/* SPDX-License-Identifier: MIT */
/* SNAP_MULTIPAGE_FAST harness (agents/sptm-locks/multipage/FAILURE-MODES.md P1-P18).
 *
 * Real code: compat/sptm-update.c's MULTIPAGE planner, compat/sptm-papt.c's
 * aperture prepare/commit, shadow/shadow.c (the canonical kernel shadow),
 * shadow/sprr-view.c (kernel views, full sync, verification and the new
 * sprr_views_sync_word) and shadow/sprr-reuse.h (the exact reuse proof and
 * snapshot). The monitor glue of probes/xnuboot.c (multipage_same_class,
 * multipage_preclean, multipage_preclean_clear, multipage_precleaned,
 * attr_clean_note, multipage_view_patch, multipage_aperture_fast,
 * multipage_close, multipage_fast and, for -DREFERENCE, the original
 * multipage_aperture) is copied verbatim below; tools/test-multipage-fast.py
 * compares every copy with probes/xnuboot.c (dc civac/dsb become model calls).
 *
 * PA == host address: one mmap holds guest RAM (frame map, guest 16K tables,
 * ops pages, target frames) and the monitor arena (4K shadow tables, copies),
 * because the monitor's identity map makes a mapped shadow pointer its PA.
 *
 * Model and checks, per MULTIPAGE call (the calling thread is the vCPU):
 *  - guest writes to the targets happen before the trap;
 *  - every frame whose AttrIndx changes across cacheability classes has a
 *    first clean after those writes and before its descriptor store (P1-P3),
 *    and a second clean after a TLBI that follows the store and before the
 *    vCPU resumes (P6, P12); same-class changes need neither (P5);
 *  - every store (canonical, guest descriptor, copy) is published before the
 *    TLBI that covers it (P10);
 *  - the 0/5 answer of every call equals an independent recomputation (P12).
 * At the end: every CPU's copies equal the translation of the canonical tables
 * (sprr_views_verify_cpu), the reuse snapshot is current, every target's
 * guest descriptor and four shadow leaves (both aliases) carry the model's
 * AttrIndx, and the fast build did no full view re-sync beyond the ones the
 * PPERM toggles and snapshot invalidations force (P7-P9).
 * Single-threaded runs print a digest of the canonical tables, copies, guest
 * tables and answers; the -DREFERENCE build (the original per-frame path)
 * must print the same digest for the same seed.
 * Six threads run under TSan/ASan with a pthread mutex as the token; pre-cleans
 * run outside it (P14, P18).
 *
 * Arguments: [calls-per-cpu] [seed] [threads]. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "sptm.h"
#include "sptm-papt.h"
#include "sprr.h"
#include "sprr-view.h"
#include "sprr-reuse.h"
#include "sprr-publish.h"
#include "sprr-variants.h"
#include "shadow.h"
#include "mmu.h"

#if !SNAP_MULTIPAGE_FAST
#error "build with -DSNAP_MULTIPAGE_FAST=1 (sprr_views_sync_word)"
#endif
#define GUEST_CPU_COUNT 6u
#define SNAP_NATIVE_WRITER_ADMISSION 0
#define SNAP_KERNEL_PPERM_VARIANTS 1
#define SNAP_KERNEL_DIRTY_PUBLISH 1
#define SPTM_FN_UPDATE_DISJOINT_MULTIPAGE 21
#define EV_UPDATE_FAILED 1
#define SPTM_SUCCESS 0
#ifndef ATTR_DEFER_MAX
#define ATTR_DEFER_MAX 16u          /* small, so most calls also take the inline overflow clean */
#endif
#define AUDIT_SAMPLE_MASK 7u

static unsigned long checks;
#define CHECK(x) do { __atomic_fetch_add(&checks,1,__ATOMIC_RELAXED); if(!(x)) { \
    fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); fflush(stderr); _exit(1); } } while(0)

/* ---- layout ------------------------------------------------------------- */
#define RAM_SIZE UINT64_C(0x2000000)        /* guest RAM, 32 MiB */
#define ARENA_SIZE UINT64_C(0x1000000)      /* monitor arena, 16 MiB */
#define NFRAMES 512u                        /* targets: 8 MiB from +4 MiB */
#define NMOVED 48u                          /* the first NMOVED targets also have a moved alias */
#define APERTURE_VA UINT64_C(0xfffffe1000000000)
#define MOVED_VA UINT64_C(0xfffffe2000000000)
#define PA16 UINT64_C(0x0000ffffffffc000)
#define LEAF_LOW (UINT64_C(0x400)|(UINT64_C(3)<<8))      /* AF, inner shareable */
#define LEAF_UPPER (PT_PXN|PT_UXN)                       /* selector 3: AP 0, PXN, UXN */
static uint64_t mem_low,mem_high,work_base,arena_end;
static uint64_t next_table;
#define FRAME(i) (mem_low+UINT64_C(0x400000)+(uint64_t)(i)*0x4000)
#define OPS(cpu) (mem_low+UINT64_C(0x200000)+(uint64_t)(cpu)*0x4000)
#define GUEST_TABLES (mem_low+UINT64_C(0x100000))
static int frame_index(uint64_t pa)
{
    if(pa<FRAME(0) || pa>=FRAME(NFRAMES) || (pa&0x3fff))return -1;
    return (int)((pa-FRAME(0))/0x4000);
}

/* ---- the monitor's state, with probes/xnuboot.c's field names ------------ */
struct params {
    uint64_t mem_low,mem_high,ttbr1_root,ram_aperture_va,frame_map_pa,frame_low,frame_high,alloc_low,alloc_high;
};
struct vcpu {uint64_t shadow_root;unsigned slot;};
struct root_ext {
    struct multipage_preclean_cpu {uint64_t count,frames;uint64_t pa[SPTM_MULTIPAGE_MAX];} multipage_preclean[GUEST_CPU_COUNT];
    struct multipage_fast_stats {
        uint64_t preclean_hits,inline_cleans,same_class,patched,unpatched,variants,closes,barrier_closes,failures;
    } multipage_fast;
    struct attr_defer_cpu {uint64_t count,deferred,overflow,flushed;uint64_t pa[ATTR_DEFER_MAX];} attr_defer[GUEST_CPU_COUNT];
};
struct attr_update_state {
    uint64_t cleans,recleans,refused,apertures,last_pa,last_before,last_after,pending;
    uint64_t pending_pa[SPTM_DISJOINT_MAX];
};
struct context {
    const struct params *params;
    struct vcpu vcpus[GUEST_CPU_COUNT];
    struct sprr_views kernel_views;
    struct sprr_reuse_state kernel_reuse_state;
    struct sprr_publish_state kernel_publish_state;
    struct sprr_view_variants kernel_variants;
    struct {struct sprr_state sprr[GUEST_CPU_COUNT];} user_roots;
    struct attr_update_state attr_updates;
    struct root_ext *root_ext;
    int kernel_view_failed;
    uint64_t shadow_tlb_syncs,multipage_calls,multipage_groups;
};
static struct params params;
static struct context ctx_storage,*C=&ctx_storage;
static struct root_ext root_ext_storage;
static struct sptm_slide_region moved_region;

/* ---- the event model ---------------------------------------------------- */
static uint64_t seq_counter;
static uint64_t next_seq(void) {return __atomic_add_fetch(&seq_counter,1,__ATOMIC_SEQ_CST);}
struct tctx {
    unsigned cpu,seed;
    struct vcpu *v;
    int in_call;
    uint64_t call_start,resume;
    uint64_t write[NFRAMES],clean1[NFRAMES],clean2[NFRAMES];
    unsigned lines[NFRAMES];
    /* every AttrIndx change of this call, per frame: its last alias store, whether it needs cleans, and the
     * latest first clean before its first store */
    unsigned changes[NFRAMES];
    uint64_t ch_store[NFRAMES][8],ch_clean1[NFRAMES][8];
    unsigned char ch_needs[NFRAMES][8];
    uint64_t publish_seq[512],tlbi_seq[512];unsigned publishes,tlbis;
    uint64_t store_last;
    uint64_t calls,records,mutated,frames_changed,class_changes;
    uint64_t answers_digest;
};
static __thread struct tctx *self;
#define vcpu_of(c) ((void)(c),self->v)
static unsigned model_attr[NFRAMES];       /* under the token */
static uint64_t expected_saves=1,invalidations,stale_entries,proof_misses,failures_seen;
static uint64_t held_ns,held_calls,held_groups,held_max;   /* host time inside the MULTIPAGE handler */
static uint64_t now_ns(void) {struct timespec ts;clock_gettime(CLOCK_MONOTONIC_RAW,&ts);return (uint64_t)ts.tv_sec*1000000000u+(uint64_t)ts.tv_nsec;}

static __attribute__((unused)) void harness_dc_civac(uint64_t line)
{
    int f=frame_index(line&~UINT64_C(0x3fff));
    if(f>=0)self->lines[f]++;
}
static void harness_dsb(void)
{
    for(unsigned f=0;f<NFRAMES;f++)
        if(self->lines[f]) {
            if(self->lines[f]>=256)self->clean1[f]=next_seq();
            self->lines[f]=0;
        }
}
static void harness_clean_frame(uint64_t pa,int second)
{
    int f=frame_index(pa);
    if(f<0)return;
    if(second)self->clean2[f]=next_seq();else self->clean1[f]=next_seq();
}
/* AttrIndx classes, independently of multipage_same_class: does changing old
 * to next require cleaning the frame? (pinned MAIR: 0/4 0xff WB, 1 NC, 2 WT,
 * 3/5/6/7 Device). Only identical write-back encodings and non-cacheable to
 * non-cacheable are free. */
static int needs_clean(unsigned old,unsigned next)
{
    int wb_old=old==0 || old==4,wb_next=next==0 || next==4;
    int nc_old=old==1 || old==3 || old>=5,nc_next=next==1 || next==3 || next>=5;
    if(wb_old && wb_next)return 0;
    if(nc_old && nc_next)return 0;
    return old!=next;
}

/* ---- callbacks the mirrored code calls (probes/xnuboot.c names) ---------- */
static volatile uint8_t *sptm_map(void *ctx,uint64_t pa,uint64_t size)
{
    const struct params *p=((struct context *)ctx)->params;
    if(pa<p->mem_low || pa>=p->mem_high || size>p->mem_high-pa)return 0;
    return (volatile uint8_t *)(uintptr_t)pa;
}
/* sptm_papt_commit publishes each alias's guest descriptor after its four
 * shadow words: that is this alias's store. */
static void sptm_publish(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;(void)size;
    uint64_t d=*(volatile uint64_t *)(uintptr_t)pa;
    int f=frame_index(d&PA16);
    if(f<0 || !self->in_call)return;
    unsigned attr=(unsigned)((d>>2)&7);
    uint64_t s=next_seq();
    if(attr!=model_attr[f]) {            /* the first alias of a change; the second sees it done */
        int n=needs_clean(model_attr[f],attr);
        CHECK(self->changes[f]<8);
        unsigned k=self->changes[f]++;
        self->ch_needs[f][k]=(unsigned char)n;self->ch_clean1[f][k]=self->clean1[f];
        self->frames_changed++;self->class_changes+=(uint64_t)n;
    }
    if(self->changes[f])self->ch_store[f][self->changes[f]-1]=s;
    model_attr[f]=attr;self->store_last=s;
}
static volatile uint8_t *sptm_shadow_map(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    if(pa<work_base || pa>=next_table || size>next_table-pa)return 0;
    return (volatile uint8_t *)(uintptr_t)pa;
}
static int native_writer_admit_high(void *ctx,uint64_t va,uint64_t pa,uint64_t size,uint64_t low,uint64_t upper)
{(void)ctx;(void)va;(void)pa;(void)size;(void)low;(void)upper;return 1;}
static uint64_t private_kernel_alloc(void *ctx)
{
    (void)ctx;
    if(next_table+4096>arena_end)return 0;
    uint64_t pa=next_table;next_table+=4096;
    memset((void *)(uintptr_t)pa,0,4096);
    return pa;
}
static int kernel_table_read(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;
    if((pa&7) || pa<work_base || pa>=next_table)return -1;
    *out=*(volatile uint64_t *)(uintptr_t)pa;return 0;
}
static int kernel_table_write(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;
    if((pa&7) || pa<work_base || pa>=next_table)return -1;
    if(*(volatile uint64_t *)(uintptr_t)pa==value)return 0;
    if(!sprr_publish_note(&C->kernel_publish_state,&C->kernel_views,pa)) {C->kernel_view_failed=1;return -1;}
    *(volatile uint64_t *)(uintptr_t)pa=value;
    if(self && self->in_call)self->store_last=next_seq();
    return 0;
}
static const volatile uint64_t *class_table_read(void *ctx,uint64_t pa)
{
    (void)ctx;
    if((pa&4095) || pa<work_base || pa>=next_table)return 0;
    return (const volatile uint64_t *)(uintptr_t)pa;
}
static struct shadow kernel_shadow(struct context *c)
{
    return (struct shadow){.txsz=17,.root=c->vcpus[0].shadow_root,
        .alloc=private_kernel_alloc,.read=kernel_table_read,.write=kernel_table_write,.ctx=c};
}
static struct sptm_memory sptm_context_memory(struct context *c)
{
    const struct params *p=c->params;
    return (struct sptm_memory){.frame_map_pa=p->frame_map_pa,.frame_low=p->frame_low,
        .frame_high=p->frame_high,.alloc_low=p->alloc_low,.alloc_high=p->alloc_high,
        .map=sptm_map,.publish=sptm_publish,.ctx=c};
}
static struct sptm_moved xnu_moved(const struct context *c)
{(void)c;return (struct sptm_moved){&moved_region,1,MOVED_VA,MOVED_VA+UINT64_C(0x1000000)};}
static uint64_t class_forgets;
static void kernel_class_proof_forget(struct context *c) {(void)c;class_forgets++;}
static void record(struct context *c,unsigned ev,uint64_t elr,uint64_t a,uint64_t b,uint64_t d)
{
    (void)c;(void)elr;
    failures_seen++;
    fprintf(stderr,"record ev %u: %#llx %#llx %#llx\n",ev,(unsigned long long)a,(unsigned long long)b,
            (unsigned long long)d);
}
/* The monitor's sptm_attr_clean: the frame cleaned to PoC before its store. */
static int sptm_attr_clean(void *ctx,uint64_t pa,uint64_t size)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct attr_update_state *s=&c->attr_updates;
    if(size!=0x4000 || (pa&0x3fff) || pa<p->mem_low || pa>=p->mem_high ||
       size>p->mem_high-pa || s->pending>=SPTM_DISJOINT_MAX) {
        s->refused++;return 0;
    }
    harness_clean_frame(pa,0);
    s->pending_pa[s->pending++]=pa;s->cleans++;
    return 1;
}
/* SNAP_ATTR_CLEAN_DEFER's attr_clean_finish: deferred past the token, inline
 * past ATTR_DEFER_MAX. */
static void attr_clean_finish(struct context *c)
{
    struct attr_update_state *s=&c->attr_updates;
    struct attr_defer_cpu *d=&c->root_ext->attr_defer[vcpu_of(c)->slot];
    for(uint64_t n=0;n<s->pending && n<SPTM_DISJOINT_MAX;n++) {
        if(d->count<ATTR_DEFER_MAX) {d->pa[d->count++]=s->pending_pa[n];d->deferred++;}
        else {harness_clean_frame(s->pending_pa[n],1);d->overflow++;}
        s->recleans++;
    }
    s->pending=0;
}
static void attr_clean_flush(struct context *c)
{
    struct attr_defer_cpu *d=&c->root_ext->attr_defer[vcpu_of(c)->slot];
    for(uint64_t n=0;n<d->count;n++)harness_clean_frame(d->pa[n],1);
    d->flushed+=d->count;d->count=0;
}
static int transaction_publish(struct context *c)
{
    (void)c;
    if(self && self->publishes<512)self->publish_seq[self->publishes++]=next_seq();
    return 1;
}
static void publish(uint64_t start,uint64_t end) {(void)start;(void)end;transaction_publish(C);}
/* probes/xnuboot.c kernel_publish_cpu (SNAP_KERNEL_DIRTY_PUBLISH). */
static int kernel_publish_cpu(struct context *c,unsigned cpu)
{
    struct sprr_publish_state *state=&c->kernel_publish_state;
    if(cpu>=GUEST_CPU_COUNT || !sprr_publish_prepare(state,&c->kernel_views)) {
        c->kernel_view_failed=1;return 0;
    }
    for(unsigned level=4;level--;)for(unsigned n=0;n<c->kernel_views.count;n++) {
        if(c->kernel_views.tables[n].level!=level)continue;
        state->pages++;
        if(!sprr_publish_needed(state,cpu,n)) {state->skipped++;continue;}
        uint64_t pa=c->kernel_views.tables[n].copy[cpu];publish(pa,pa+4096);
        if(!sprr_publish_complete(state,cpu,n)) {c->kernel_view_failed=1;return 0;}
    }
    state->publishes++;
    return 1;
}
/* kernel_refresh_impl with SNAP_KERNEL_VIEW_REUSE and SNAP_REUSE_MATCH_MAPPED. */
static int kernel_refresh(struct context *c)
{
    struct shadow s=kernel_shadow(c);
    struct sprr_reuse_state *reuse=&c->kernel_reuse_state;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
    int valid=reuse->valid;
    int match=sprr_reuse_match_mapped(reuse,&c->kernel_views,&s,pp,class_table_read,c);
    if(match<0) {c->kernel_view_failed=1;return 0;}
    if(!match && valid)proof_misses++;          /* a valid snapshot that no longer matches: P9's safety net */
    if(match) {
        if(!(reuse->hits&AUDIT_SAMPLE_MASK)) {
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
                if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,pp[cpu])) {
                    reuse->mismatches++;reuse->valid=0;c->kernel_view_failed=1;return 0;
                }
            reuse->verified++;
        }
        return 1;
    }
    reuse->valid=0;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        if(!sprr_views_sync_cpu(&c->kernel_views,&s,cpu,pp[cpu])) {c->kernel_view_failed=1;return 0;}
        if(!kernel_publish_cpu(c,cpu))return 0;
    }
    if(!sprr_reuse_save(reuse,&c->kernel_views,&s,pp)) {c->kernel_view_failed=1;return 0;}
    return 1;
}
static void shadow_tlb_sync(struct context *c)
{
    if(c->kernel_views.count && !kernel_refresh(c))return;
    if(self->tlbis<512)self->tlbi_seq[self->tlbis++]=next_seq();
    c->shadow_tlb_syncs++;
}
/* update_disjoint_call for a group with mapping records: its own transaction,
 * after resetting attr_updates.pending (the real one does both). */
static int update_disjoint_call(struct context *c,uint64_t target,uint64_t list,
    uint64_t count,uint64_t options,uint64_t scratch,uint64_t elr,uint64_t *out)
{
    (void)target;(void)list;(void)count;(void)options;(void)scratch;(void)elr;
    c->attr_updates.pending=0;
    self->records++;
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);
    attr_clean_finish(c);
    *out=SPTM_SUCCESS;
    return 1;
}

/* ===== verbatim from probes/xnuboot.c (tools/test-multipage-fast.py) ======= */
#ifdef REFERENCE
static int multipage_aperture(struct context *c,const struct sptm_multipage_group *g,
    uint64_t elr,uint64_t *out)
{
    const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    c->attr_updates.pending=0;
    uint64_t before=0,after=0;
    enum sptm_result r=SPTM_OK;
    if(g->aperture_flags&2) {
        r=sptm_papt_prepare_attr(&m,&b,&a,&moved,g->target,(unsigned)g->aperture_attr,&change);
        if(r)goto failed;
        /* Apple rewrites the alias its phystokv names: the moved one if any. */
        before=change.leaf[change.count-1].before;after=change.leaf[change.count-1].after;
        int changed=0;
        for(unsigned i=0;i<change.count;i++)changed|=change.leaf[i].before!=change.leaf[i].after;
        if(changed) {
            r=SPTM_MEMORY_UNAVAILABLE;
            if(!sptm_attr_clean(c,g->target,0x4000))goto failed;
            kernel_class_proof_forget(c);
            sptm_papt_commit(&m,&change);
            r=SPTM_SHADOW_FAILED;
            if(!transaction_publish(c))goto failed;
            shadow_tlb_sync(c);if(c->kernel_view_failed)goto failed;
            attr_clean_finish(c);
            c->attr_updates.apertures+=change.count;
        }
        c->attr_updates.last_pa=g->target;
        c->attr_updates.last_before=before;c->attr_updates.last_after=after;
    }
    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;
    return 1;
failed:
    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);
    return 0;
}
#endif
_Static_assert(SPTM_MULTIPAGE_MAX<=SPTM_DISJOINT_MAX,"one call's changed frames fit attr_updates.pending (P6)");
static int multipage_same_class(uint64_t before,uint64_t after)
{
#if MUTANT_WC_AS_WB
    static const unsigned char attr_class[8]={1,1,3,4,1,4,4,4};
#else
    static const unsigned char attr_class[8]={1,2,3,4,1,4,4,4};
#endif
    unsigned a=attr_class[(before&PT_ATTRINDX)>>2],b=attr_class[(after&PT_ATTRINDX)>>2];
    return (a==1 && b==1) || ((a==2 || a==4) && (b==2 || b==4));
}
static void multipage_preclean(struct context *c,const uint64_t *frame,uint64_t esr)
{
    struct multipage_preclean_cpu *set=&c->root_ext->multipage_preclean[vcpu_of(c)->slot];
#if MUTANT_STALE_SET
    if(0)
#endif
    set->count=0;
    if((esr>>26)!=0x20 || frame[16]!=SPTM_FN_UPDATE_DISJOINT_MULTIPAGE)return;
    const struct params *p=c->params;
    uint64_t ops=frame[0],count=frame[1];
    if(!count || count>SPTM_MULTIPAGE_MAX || (ops&7) || (ops&0x3fff)+count*24>0x4000)return;
    volatile uint8_t *in=sptm_map(c,ops,count*24);
    if(!in)return;
    for(uint64_t i=0;i<count;) {
        volatile uint8_t *h=in+i*24;
        uint64_t target=*(volatile uint64_t *)h,w=*(volatile uint64_t *)(h+16);
        uint32_t mappings=(uint32_t)w,options=(uint32_t)(w>>32);
        i++;
        if(!(options&0x200) && (options&0x20) && !(target&0x3fff) && target>=p->mem_low &&
           target<p->mem_high && p->mem_high-target>=0x4000 && set->count<SPTM_MULTIPAGE_MAX) {
            for(uint64_t line=target;line<target+0x4000;line+=64)
#if MUTANT_NO_PRECLEAN
                (void)line;
#else
                harness_dc_civac(line);
#endif
            set->pa[set->count++]=target;
        }
        if(mappings>count-i)break;
        i+=mappings;
    }
    if(set->count) {harness_dsb();set->frames+=set->count;}
}
static void multipage_preclean_clear(struct context *c)
{
#if MUTANT_STALE_SET
    (void)c;
#else
    c->root_ext->multipage_preclean[vcpu_of(c)->slot].count=0;
#endif
}
static int multipage_precleaned(struct context *c,uint64_t pa)
{
    const struct multipage_preclean_cpu *set=&c->root_ext->multipage_preclean[vcpu_of(c)->slot];
    for(uint64_t n=0;n<set->count && n<SPTM_MULTIPAGE_MAX;n++)if(set->pa[n]==pa)return 1;
    return 0;
}
static int attr_clean_note(struct context *c,uint64_t pa)
{
    const struct params *p=c->params;struct attr_update_state *s=&c->attr_updates;
    if((pa&0x3fff) || pa<p->mem_low || pa>=p->mem_high || 0x4000>p->mem_high-pa ||
       s->pending>=SPTM_DISJOINT_MAX) {
        s->refused++;return 0;
    }
    s->pending_pa[s->pending++]=pa;s->cleans++;
    return 1;
}
static int multipage_view_patch(struct context *c,uint64_t pa)
{
    if(!c->kernel_views.count)return 1;
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    int n=sprr_views_word_table(&c->kernel_views,pa);
    if(n==-1)return 1;
    struct shadow s=kernel_shadow(c);
    struct sprr_reuse_state *r=&c->kernel_reuse_state;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
    int ok=n>=0 && r->valid && r->root==s.root && r->count==c->kernel_views.count;
    if(ok) {
        const struct sprr_view_table *a=&r->tables[n],*b=&c->kernel_views.tables[n];
        ok=a->source==b->source && a->level==b->level;
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)ok=ok && a->copy[cpu]==b->copy[cpu] && r->pperm[cpu]==pp[cpu];
    }
#if MUTANT_UNPATCHED_WORD
    /* P9: the last word of every alias is neither copied nor snapshotted */
    if((pa&0x18)==0x18)return 1;
#endif
    if(!ok) {st->unpatched++;return 1;}
    uint64_t extra[GUEST_CPU_COUNT]={0},extra_pp[GUEST_CPU_COUNT]={0};
#if SNAP_KERNEL_PPERM_VARIANTS
    const struct sprr_view_variants *v=&c->kernel_variants;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
#if MUTANT_NO_VARIANT_PATCH
        if(0) {
#else
        if(v->count[cpu]==c->kernel_views.count && v->saves[cpu] && v->saves[cpu]==r->saves &&
           v->copy[n][cpu] && v->source[n][cpu]==c->kernel_views.tables[n].source) {
#endif
            extra[cpu]=v->copy[n][cpu];extra_pp[cpu]=v->pperm[cpu];st->variants++;
        }
#endif
    unsigned index=(unsigned)((pa&4095)/8);
#if MUTANT_COPY_SKIP
    /* the snapshot is patched, the copies are not */
    (void)extra;(void)extra_pp;(void)s;
#else
    if(!sprr_views_sync_word(&c->kernel_views,&s,(unsigned)n,index,pp,extra,extra_pp)) {
        c->kernel_view_failed=1;return 0;
    }
#endif
    r->words[n][index]=*(volatile uint64_t *)pa;
    st->patched++;return 1;
}
static int multipage_aperture_fast(struct context *c,const struct sptm_multipage_group *g,
    uint64_t elr,uint64_t *out,int *open)
{
    const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    uint64_t before=0,after=0;
    enum sptm_result r=SPTM_OK;
    if(g->aperture_flags&2) {
        r=sptm_papt_prepare_attr(&m,&b,&a,&moved,g->target,(unsigned)g->aperture_attr,&change);
        if(r)goto failed;
        before=change.leaf[change.count-1].before;after=change.leaf[change.count-1].after;
        int changed=0,same=1;
        for(unsigned i=0;i<change.count;i++) {
            changed|=change.leaf[i].before!=change.leaf[i].after;
            same&=multipage_same_class(change.leaf[i].before,change.leaf[i].after);
        }
        if(changed) {
            r=SPTM_MEMORY_UNAVAILABLE;
            if(same)st->same_class++;
            else if(multipage_precleaned(c,g->target)) {
                if(!attr_clean_note(c,g->target))goto failed;
                st->preclean_hits++;
            } else {
                if(!sptm_attr_clean(c,g->target,0x4000))goto failed;
                st->inline_cleans++;
            }
            kernel_class_proof_forget(c);
            sptm_papt_commit(&m,&change);
            *open=1;
            r=SPTM_SHADOW_FAILED;
            for(unsigned i=0;i<change.count;i++)for(unsigned n=0;n<4;n++)
                if(!multipage_view_patch(c,(uint64_t)(uintptr_t)change.leaf[i].shadow[n]))goto failed;
            c->attr_updates.apertures+=change.count;
        }
        c->attr_updates.last_pa=g->target;
        c->attr_updates.last_before=before;c->attr_updates.last_after=after;
    }
    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;
    return 1;
failed:
    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);
    return 0;
}
static int multipage_close(struct context *c,uint64_t elr,const struct sptm_multipage_group *g,int barrier)
{
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    st->closes++;if(barrier)st->barrier_closes++;
#if MUTANT_FINISH_FIRST
    attr_clean_finish(c);
#endif
#if !MUTANT_NO_PUBLISH
    if(!transaction_publish(c)) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
    }
#endif
#if SNAP_KERNEL_DIRTY_PUBLISH
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
#if MUTANT_PENDING_LEFT
        if(0 &&
#else
        if(!sprr_publish_row_empty(&c->kernel_publish_state,cpu) &&
#endif
           !kernel_publish_cpu(c,cpu)) {
            record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
        }
#endif
#if !MUTANT_NO_TLBI
    shadow_tlb_sync(c);
#endif
    if(c->kernel_view_failed) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
    }
    attr_clean_finish(c);
    return 1;
}
static int multipage_fast(struct context *c,const struct sptm_multipage_plan *plan,uint64_t elr,
                          uint64_t scratch,uint64_t *response)
{
    int open=0;
    c->attr_updates.pending=0;
    for(uint64_t g=0;g<plan->groups;g++) {
        const struct sptm_multipage_group *grp=&plan->group[g];
        uint64_t one;
        if(grp->aperture_flags) {
            if(!multipage_aperture_fast(c,grp,elr,&one,&open)) {
                c->root_ext->multipage_fast.failures++;
                if(open)(void)multipage_close(c,elr,grp,0);
                return 0;
            }
            if(one==5)*response=5;
        }
        if(!grp->count)continue;
#if MUTANT_NO_BARRIER
        if(0) {
#else
        if(open) {
#endif
            if(!multipage_close(c,elr,grp,1))return 0;
            open=0;
        }
        if(!update_disjoint_call(c,grp->target,grp->list,grp->count,grp->options,scratch,elr,&one))return 0;
        if(one==5)*response=5;
    }
    if(open && !multipage_close(c,elr,&plan->group[plan->groups-1],0))return 0;
    return 1;
}
/* ===== end of the verbatim copies ========================================= */

/* ---- setup ---------------------------------------------------------------- */
static uint64_t guest_l1,guest_l2,guest_l3a,guest_l3m;
static uint64_t guest_next=0;
static uint64_t guest_table(void)
{
    uint64_t pa=GUEST_TABLES+guest_next;guest_next+=0x4000;
    memset((void *)(uintptr_t)pa,0,0x4000);
    return pa;
}
static void guest_link(uint64_t table,unsigned level,uint64_t va,uint64_t next)
{((volatile uint64_t *)(uintptr_t)table)[mmu_index(14,level,va)]=next|3;}
static uint64_t guest_leaf_slot(uint64_t va)
{
    uint64_t l3=(va>=MOVED_VA) ? guest_l3m : guest_l3a;
    return l3+8UL*mmu_index(14,3,va);
}
static uint64_t frame_va(unsigned i,int moved) {return moved ? MOVED_VA+(uint64_t)i*0x4000 : APERTURE_VA+(FRAME(i)-mem_low);}
static unsigned copy_l3_count;

static void setup(unsigned seed)
{
    uint64_t total=RAM_SIZE+ARENA_SIZE,align=UINT64_C(0x2000000);
    uint8_t *raw=mmap(0,total+align,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(raw!=MAP_FAILED);
    mem_low=((uint64_t)(uintptr_t)raw+align-1)&~(align-1);
    mem_high=mem_low+RAM_SIZE;work_base=mem_high;next_table=work_base;arena_end=work_base+ARENA_SIZE;
    params=(struct params){.mem_low=mem_low,.mem_high=mem_high,.ram_aperture_va=APERTURE_VA,
        .frame_map_pa=mem_low,.frame_low=mem_low,.frame_high=mem_high,.alloc_low=mem_low,.alloc_high=mem_high};
    C->params=&params;C->root_ext=&root_ext_storage;
    /* frame map: every target DEFAULT, nothing else */
    memset((void *)(uintptr_t)mem_low,0,(RAM_SIZE/0x4000)*16);
    for(unsigned i=0;i<NFRAMES;i++)((volatile uint8_t *)(uintptr_t)(mem_low+((FRAME(i)-mem_low)>>14)*16))[2]=SPTM_MAC_DEFAULT;
    /* guest 16K tables: one root, one L2, an L3 for the linear aperture and one for the moved alias */
    guest_l1=guest_table();guest_l2=guest_table();guest_l3a=guest_table();guest_l3m=guest_table();
    params.ttbr1_root=guest_l1;
    CHECK(mmu_index(14,1,APERTURE_VA)!=mmu_index(14,1,MOVED_VA) || mmu_index(14,2,APERTURE_VA)!=mmu_index(14,2,MOVED_VA));
    uint64_t l2m=guest_table();
    guest_link(guest_l1,1,APERTURE_VA,guest_l2);guest_link(guest_l2,2,APERTURE_VA,guest_l3a);
    guest_link(guest_l1,1,MOVED_VA,l2m);guest_link(l2m,2,MOVED_VA,guest_l3m);
    moved_region=(struct sptm_slide_region){MOVED_VA,FRAME(0),NMOVED};
    /* canonical 4K kernel shadow (real shadow.c) */
    uint64_t root=private_kernel_alloc(C);
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {C->vcpus[cpu].shadow_root=root;C->vcpus[cpu].slot=cpu;}
    struct shadow s=kernel_shadow(C);
    unsigned rs=seed;
    for(unsigned i=0;i<NFRAMES;i++) {
        unsigned attr=(unsigned)(rand_r(&rs)%8);model_attr[i]=attr;
        uint64_t low=LEAF_LOW|((uint64_t)attr<<2);
        for(int moved=0;moved<=(i<NMOVED);moved++) {
            uint64_t va=frame_va(i,moved);
            *(volatile uint64_t *)(uintptr_t)guest_leaf_slot(va)=FRAME(i)|3|low|LEAF_UPPER;
            CHECK(!shadow_map(&s,va&((UINT64_C(1)<<47)-1),FRAME(i),0x4000,low,LEAF_UPPER));
        }
    }
    /* protected neighbours (selector 2, selector 4) inside some copied tables, so the copies translate */
    /* kernel views: the root, and the paths of one target in every other 2 MiB span and the moved one */
    CHECK(sprr_views_init(&C->kernel_views,&s));
    for(unsigned i=0;i<NFRAMES;i+=256)CHECK(sprr_views_prepare(&C->kernel_views,&s,frame_va(i,0)&((UINT64_C(1)<<47)-1)));
    CHECK(sprr_views_prepare(&C->kernel_views,&s,frame_va(1,1)&((UINT64_C(1)<<47)-1)));
    for(unsigned n=0;n<C->kernel_views.count;n++)copy_l3_count+=C->kernel_views.tables[n].level==3;
    /* a selector-2 and a selector-4 leaf beside the moved aliases in their copied L3 table, past its NMOVED frames */
    for(unsigned k=0;k<2;k++) {
        uint64_t va=(MOVED_VA+UINT64_C(0x100000)+(uint64_t)k*0x1000)&((UINT64_C(1)<<47)-1);
        uint64_t l3=0,t=root;
        for(unsigned level=0;level<3;level++) {uint64_t d;kernel_table_read(C,t+8UL*mmu_index(12,level,va),&d);t=d&PT_OA_MASK;}
        l3=t;
        uint64_t sel=k ? (UINT64_C(1)<<6) : PT_UXN;   /* class 4: AP bit6; class 2: UXN only */
        kernel_table_write(C,l3+8UL*mmu_index(12,3,va),(mem_low+UINT64_C(0x180000)+(uint64_t)k*0x1000)|3|LEAF_LOW|sel);
    }
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        C->user_roots.sprr[cpu].pperm=SPRR_PPERM_INITIAL|((cpu&1) ? UINT64_C(0x100):0);
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        pp[cpu]=C->user_roots.sprr[cpu].pperm;
        CHECK(sprr_views_sync_cpu(&C->kernel_views,&s,cpu,pp[cpu]));
    }
    CHECK(sprr_reuse_save(&C->kernel_reuse_state,&C->kernel_views,&s,pp));
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)CHECK(kernel_publish_cpu(C,cpu));
}

/* ---- sprr_views_sync_word against the full sync (P7) --------------------- */
static void unit_sync_word(unsigned seed)
{
    struct shadow s=kernel_shadow(C);
    uint64_t pp[GUEST_CPU_COUNT],alt[GUEST_CPU_COUNT],extra[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        pp[cpu]=C->user_roots.sprr[cpu].pperm;alt[cpu]=pp[cpu]^SPRR_KERNEL_VIEW_PPERM;
    }
    unsigned rs=seed,patched=0,refused=0,upper=0;
    static const uint64_t selector[]={LEAF_UPPER,PT_UXN,UINT64_C(1)<<6,0,UINT64_C(1)<<7,PT_PXN};  /* 3 2 4 0 8 1 */
    /* a scratch "variant column" per CPU and copied table, to check the extra translation */
    static uint64_t scratch[SPRR_VIEW_TABLES][GUEST_CPU_COUNT];
    for(unsigned n=0;n<C->kernel_views.count;n++)for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        scratch[n][cpu]=private_kernel_alloc(C);
    for(unsigned round=0;round<400;round++) {
        unsigned n=(unsigned)(rand_r(&rs)%C->kernel_views.count);
        const struct sprr_view_table *t=&C->kernel_views.tables[n];
        unsigned index=(unsigned)(rand_r(&rs)%512);
        uint64_t pa=t->source+8UL*index,old;
        CHECK(!kernel_table_read(C,pa,&old));
        int table=sprr_views_word_table(&C->kernel_views,pa);
        if(t->level!=3) {CHECK(table==-2);upper++;continue;}
        CHECK(table==(int)n);
        uint64_t value=rand_r(&rs)&1 ? 0 : (mem_low+UINT64_C(0x1c0000)+(uint64_t)(rand_r(&rs)%64)*0x1000)|3|LEAF_LOW|
                       ((uint64_t)(rand_r(&rs)%8)<<2)|selector[rand_r(&rs)%6];
        if(value && (rand_r(&rs)%9)==0)value=(value&~(PT_AP|LEAF_UPPER))|PT_PXN|PT_UXN|(UINT64_C(2)<<6); /* class 11 */
        if(value && (rand_r(&rs)%11)==0)value=(value&~(PT_AP|LEAF_UPPER))|(UINT64_C(2)<<6)|PT_PXN;      /* class 9 */
        kernel_table_write(C,pa,value);
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)extra[cpu]=rand_r(&rs)&1 ? scratch[n][cpu] : 0;
        int ok=sprr_views_sync_word(&C->kernel_views,&s,n,index,pp,extra,alt);
        if(ok) {
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
                CHECK(sprr_views_verify_cpu(&C->kernel_views,&s,cpu,pp[cpu]));   /* the copies equal a full translation */
            /* each extra word equals what that CPU's copy holds under the other PPERM */
            struct sprr_views probe=C->kernel_views;
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)if(extra[cpu]) {
                uint64_t want,got;
                CHECK(sprr_views_sync_cpu(&probe,&s,cpu,alt[cpu]));        /* rewrites the live copy under alt */
                CHECK(!kernel_table_read(C,t->copy[cpu]+8UL*index,&want));
                CHECK(!kernel_table_read(C,extra[cpu]+8UL*index,&got));
                CHECK(want==got);
                CHECK(sprr_views_sync_cpu(&probe,&s,cpu,pp[cpu]));         /* and back */
            }
            patched++;
        } else {
            refused++;
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {            /* nothing was written ... */
                uint64_t w;CHECK(!kernel_table_read(C,t->copy[cpu]+8UL*index,&w));
            }
            struct sprr_views probe=C->kernel_views;                     /* ... and a full sync refuses too */
            CHECK(!sprr_views_sync_cpu(&probe,&s,0,pp[0]) || !sprr_views_sync_cpu(&probe,&s,1,pp[1]));
        }
        kernel_table_write(C,pa,old);
        CHECK(sprr_views_sync_word(&C->kernel_views,&s,n,index,pp,0,0));
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)CHECK(sprr_views_verify_cpu(&C->kernel_views,&s,cpu,pp[cpu]));
    }
    CHECK(sprr_views_word_table(&C->kernel_views,mem_low+0x100)==-1);
    CHECK(sprr_reuse_current(&C->kernel_reuse_state,&C->kernel_views,&s,pp)==1);
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)CHECK(kernel_publish_cpu(C,cpu));
    printf("sync_word: %u patched, %u refused like a full sync, %u upper-level words left to the full sync\n",
           patched,refused,upper);
}

/* probes/xnuboot.c kernel_change_pperm_impl for a flip of SPRR_KERNEL_VIEW_PPERM, with SNAP_KERNEL_PPERM_REUSE
 * and SNAP_KERNEL_PPERM_VARIANTS (kernel_variant_swap), under the token. Every flip verifies the CPU's
 * installed column afterwards: a variant column swapped in stale (P19) fails here. */
static uint64_t flips,exact_swaps,synced_swaps;
static void pperm_flip(unsigned cpu)
{
    struct context *c=C;
    struct shadow s=kernel_shadow(c);
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned n=0;n<GUEST_CPU_COUNT;n++)pp[n]=c->user_roots.sprr[n].pperm;
    int current=c->kernel_views.count && sprr_reuse_current(&c->kernel_reuse_state,&c->kernel_views,&s,pp)==1;
    sprr_reuse_invalidate(&c->kernel_reuse_state);
    uint64_t before=pp[cpu],pperm=before^SPRR_KERNEL_VIEW_PPERM;
    int swap=0;
    if(current) {
        struct sprr_view_variants *a=&c->kernel_variants;
        int exact=sprr_variants_exact(a,&c->kernel_views,&c->kernel_reuse_state,cpu,pperm);
        int ready=exact || sprr_variants_reserve(a,&c->kernel_views,&s,cpu);
        if(ready && sprr_variants_swap(a,&c->kernel_views,&c->kernel_publish_state,cpu,before,
                                       c->kernel_reuse_state.saves))swap=exact ? 2 : 1;
        else a->fallbacks++;
        if(swap==2)exact_swaps++;else if(swap==1)synced_swaps++;
    }
    c->user_roots.sprr[cpu].pperm=pperm;
    if(swap!=2)CHECK(sprr_views_sync_cpu(&c->kernel_views,&s,cpu,pperm));
    CHECK(kernel_publish_cpu(c,cpu));
    if(current)CHECK(swap ? sprr_variants_repin(&c->kernel_reuse_state,&c->kernel_views,cpu,pperm) :
                            sprr_reuse_repin(&c->kernel_reuse_state,&c->kernel_views,cpu,pperm));
    CHECK(sprr_views_verify_cpu(&c->kernel_views,&s,cpu,pperm));
    flips++;
}

/* ---- one MULTIPAGE call --------------------------------------------------- */
static pthread_mutex_t token=PTHREAD_MUTEX_INITIALIZER;
static int threads_n=6,ref_mode;
static unsigned rnd(void) {return (unsigned)rand_r(&self->seed);}

static void build_ops(uint64_t ops,uint64_t *count_out,unsigned *targets,unsigned *ntargets)
{
    volatile uint8_t *in=(volatile uint8_t *)(uintptr_t)ops;
    uint64_t count=0;unsigned nt=0;
    unsigned headers=1+rnd()%(rnd()%4 ? 64 : 8);
    while(count<SPTM_MULTIPAGE_MAX && headers--) {
        unsigned f=rnd()%NFRAMES;
        unsigned attr=rnd()%8;
        unsigned mappings=(rnd()%10==0 && count+2<SPTM_MULTIPAGE_MAX) ? 1+rnd()%2 : 0;
        uint32_t options=0x20|(rnd()%3==0 ? 0x100u:0u);
        if(mappings)options|=0x2;          /* a valid update selector for the records */
        if(mappings && rnd()%4==0)options=0x200|0x2;   /* records only, no aperture step */
        if(count+1+mappings>SPTM_MULTIPAGE_MAX)break;
        volatile uint8_t *h=in+count*24;
        *(volatile uint64_t *)h=FRAME(f);
        *(volatile uint64_t *)(h+8)=(uint64_t)attr<<2;
        *(volatile uint64_t *)(h+16)=(uint64_t)mappings|((uint64_t)options<<32);
        count++;
        if(!(options&0x200) && nt<SPTM_MULTIPAGE_MAX)targets[nt++]=f;
        for(unsigned k=0;k<mappings;k++) {
            volatile uint8_t *r=in+count*24;
            *(volatile uint64_t *)r=FRAME(f);*(volatile uint64_t *)(r+8)=0;*(volatile uint64_t *)(r+16)=0;
            count++;
        }
    }
    *count_out=count;*ntargets=nt;
}
/* The answer of a call, recomputed from the model: 5 when any aperture header
 * with option 0x100 leaves a non-posted AttrIndx (sptm_update_leaves_posted
 * is false), or a records group answered 5 (never, here). */
static void one_call(void)
{
    struct tctx *t=self;
    uint64_t ops=OPS(t->cpu),count;
    unsigned targets[SPTM_MULTIPAGE_MAX],nt;
    build_ops(ops,&count,targets,&nt);
    for(unsigned i=0;i<nt;i++)t->write[targets[i]]=next_seq();       /* XNU's writes precede the call */
    t->call_start=next_seq();
    uint64_t frame[31]={0};
    frame[0]=ops;frame[1]=count;frame[16]=SPTM_FN_UPDATE_DISJOINT_MULTIPAGE;
    if(!ref_mode)multipage_preclean(C,frame,UINT64_C(0x20)<<26);
    /* P3: the list changes between the pre-clean and the plan (another thread's store) */
    if(nt && rnd()%7==0) {
        volatile uint8_t *in=(volatile uint8_t *)(uintptr_t)ops;
        for(uint64_t i=0;i<count;i++) {
            uint64_t w=*(volatile uint64_t *)(in+i*24+16);
            if(!((w>>32)&0x200) && ((w>>32)&0x20)) {
                unsigned f=rnd()%NFRAMES;
                *(volatile uint64_t *)(in+i*24)=FRAME(f);t->mutated++;
                break;
            }
        }
    }
    pthread_mutex_lock(&token);
    t->in_call=1;t->publishes=t->tlbis=0;
    memset(t->changes,0,sizeof t->changes);
    unsigned before[NFRAMES];memcpy(before,model_attr,sizeof before);
    struct sptm_memory memory=sptm_context_memory(C);
    struct sptm_multipage_plan plan;
    CHECK(sptm_mac_multipage_plan(&memory,frame[0],frame[1],&plan)==SPTM_OK);
    uint64_t response=SPTM_SUCCESS,expected=SPTM_SUCCESS,t0;
    for(uint64_t g=0;g<plan.groups;g++) {
        const struct sptm_multipage_group *grp=&plan.group[g];
        int f=frame_index(grp->target);
        if(grp->aperture_flags&2) {
            unsigned next=(unsigned)grp->aperture_attr;
            uint64_t b=(uint64_t)before[f]<<2,a=(uint64_t)next<<2;
            if((grp->aperture_flags&0x80) && !sptm_update_leaves_posted(b|3,a|3))expected=5;
            before[f]=next;
        }
    }
    t0=now_ns();
#ifdef REFERENCE
    for(uint64_t g=0;g<plan.groups;g++) {
        uint64_t one;
        if(plan.group[g].aperture_flags) {
            CHECK(multipage_aperture(C,&plan.group[g],0,&one));
            if(one==5)response=5;
        }
        if(!plan.group[g].count)continue;
        CHECK(update_disjoint_call(C,plan.group[g].target,plan.group[g].list,plan.group[g].count,
                                   plan.group[g].options,0,0,&one));
        if(one==5)response=5;
    }
#else
    CHECK(multipage_fast(C,&plan,0,0,&response));
#endif
    {uint64_t d=now_ns()-t0;held_ns+=d;held_calls++;held_groups+=plan.groups;if(d>held_max)held_max=d;}
    C->multipage_calls++;C->multipage_groups+=plan.groups;
    CHECK(!C->kernel_view_failed);
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)                      /* P20 */
        CHECK(!C->kernel_publish_state.pending[cpu][0] && !C->kernel_publish_state.pending[cpu][1]);
    CHECK(response==expected);
    t->answers_digest=t->answers_digest*1099511628211ULL+response+plan.groups;
    t->in_call=0;
    /* random token-held events: a PPERM toggle (refreshes, saves), a snapshot invalidation */
    for(unsigned k=rnd()%3;k--;)pperm_flip(rnd()%GUEST_CPU_COUNT);
    if(rnd()%29==0) {
        sprr_reuse_invalidate(&C->kernel_reuse_state);
        CHECK(kernel_refresh(C));
        expected_saves++;invalidations++;
    } else if(rnd()%31==0) {
        /* P8: the next call finds the snapshot invalid: nothing may be patched into it; its close saves */
        sprr_reuse_invalidate(&C->kernel_reuse_state);stale_entries++;
    }
    pthread_mutex_unlock(&token);
    attr_clean_flush(C);
    if(!ref_mode)multipage_preclean_clear(C);
    t->resume=next_seq();
    /* the ordering rules, frame by frame */
    for(unsigned f=0;f<NFRAMES;f++)for(unsigned c=0;c<t->changes[f];c++) {
        uint64_t store=t->ch_store[f][c],tlbi=0,publish=0;
        for(unsigned k=0;k<t->tlbis;k++)if(t->tlbi_seq[k]>store) {tlbi=t->tlbi_seq[k];break;}
        CHECK(tlbi && tlbi<t->resume);                                  /* P12 */
        for(unsigned k=0;k<t->publishes;k++)if(t->publish_seq[k]>store && t->publish_seq[k]<tlbi) {publish=1;break;}
        CHECK(publish);                                                 /* P10 */
        if(t->ch_needs[f][c]) {
            uint64_t clean1=t->ch_clean1[f][c];
            CHECK(clean1>t->call_start && clean1>t->write[f] && clean1<store);   /* P1 */
            CHECK(t->clean2[f]>tlbi && t->clean2[f]<t->resume);         /* P6 */
        }
    }
    t->calls++;
}

static void *cpu_main(void *arg)
{
    self=arg;
    unsigned calls=self->calls;self->calls=0;
    for(unsigned i=0;i<calls;i++)one_call();
    return 0;
}

/* Descriptors hold host addresses (PA == host address): rebase them on mem_low so runs compare. */
static uint64_t rebased(uint64_t w)
{
    uint64_t a=w&PT_OA_MASK;
    return a>=mem_low && a<arena_end ? (w&~PT_OA_MASK)|(a-mem_low) : w;
}
/* The logical state: the canonical tree (walked from the root), every CPU's active level-3 copies, the guest
 * tables and the reuse snapshot. Upper-level copies link copy pages whose addresses depend on the PPERM swap
 * history, and variant columns are not live; both are covered by the verifications instead. */
static uint64_t digest_h;
static void digest_word(uint64_t w) {digest_h^=rebased(w);digest_h*=UINT64_C(0x100000001b3);}
static void digest_table(uint64_t table,unsigned level)
{
    for(unsigned i=0;i<512;i++) {
        uint64_t d=*(volatile uint64_t *)(uintptr_t)(table+8UL*i);
        digest_word(d);
        if(level<3 && (d&3)==3)digest_table(d&PT_OA_MASK,level+1);
    }
}
static uint64_t digest(void)
{
    digest_h=UINT64_C(0xcbf29ce484222325);
    digest_table(C->vcpus[0].shadow_root,0);
    for(unsigned n=0;n<C->kernel_views.count;n++)
        if(C->kernel_views.tables[n].level==3)
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
                for(unsigned i=0;i<512;i++)digest_word(*(volatile uint64_t *)(uintptr_t)(C->kernel_views.tables[n].copy[cpu]+8UL*i));
    for(uint64_t pa=GUEST_TABLES;pa<GUEST_TABLES+guest_next;pa+=8)digest_word(*(volatile uint64_t *)(uintptr_t)pa);
    for(unsigned n=0;n<C->kernel_views.count;n++)for(unsigned i=0;i<512;i++)digest_word(C->kernel_reuse_state.words[n][i]);
    return digest_h;
}

int main(int argc,char **argv)
{
    unsigned calls=argc>1 ? (unsigned)atoi(argv[1]) : 400,seed=argc>2 ? (unsigned)atoi(argv[2]) : 5;
    threads_n=argc>3 ? atoi(argv[3]) : 6;
#ifdef REFERENCE
    ref_mode=1;
#endif
    if(threads_n<1 || threads_n>(int)GUEST_CPU_COUNT)threads_n=6;
    setup(seed);
    printf("views: %llu copied tables (%u level 3), arena %llu KiB\n",(unsigned long long)C->kernel_views.count,
           copy_l3_count,(unsigned long long)((next_table-work_base)/1024));
    if(!ref_mode)unit_sync_word(seed);
    static struct tctx t[GUEST_CPU_COUNT];
    pthread_t th[GUEST_CPU_COUNT];
    for(int i=0;i<threads_n;i++) {
        t[i].cpu=(unsigned)i;t[i].seed=seed*7919u+(unsigned)i;t[i].v=&C->vcpus[i];t[i].calls=calls;
        CHECK(!pthread_create(&th[i],0,cpu_main,&t[i]));
    }
    uint64_t total=0,records=0,mutated=0,changed=0,classes=0,answers=0;
    for(int i=0;i<threads_n;i++) {
        pthread_join(th[i],0);
        total+=t[i].calls;records+=t[i].records;mutated+=t[i].mutated;changed+=t[i].frames_changed;
        classes+=t[i].class_changes;answers=answers*31+t[i].answers_digest;
    }
    /* end state */
    struct shadow s=kernel_shadow(C);
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        pp[cpu]=C->user_roots.sprr[cpu].pperm;
        CHECK(sprr_views_verify_cpu(&C->kernel_views,&s,cpu,pp[cpu]));          /* P7, P9 */
    }
    CHECK(sprr_reuse_current(&C->kernel_reuse_state,&C->kernel_views,&s,pp)==1);  /* P8 */
    for(unsigned i=0;i<NFRAMES;i++)
        for(int moved=0;moved<=(i<NMOVED);moved++) {
            uint64_t va=frame_va(i,moved),g=*(volatile uint64_t *)(uintptr_t)guest_leaf_slot(va);
            CHECK(((g>>2)&7)==model_attr[i]);
            for(unsigned n=0;n<4;n++) {
                uint64_t a=(va+n*4096)&((UINT64_C(1)<<47)-1),tbl=C->vcpus[0].shadow_root,d=0;
                for(unsigned level=0;level<4;level++) {
                    CHECK(!kernel_table_read(C,tbl+8UL*mmu_index(12,level,a),&d));
                    if(level<3)tbl=d&PT_OA_MASK;
                }
                CHECK(d==((FRAME(i)+n*4096)|3|LEAF_LOW|((uint64_t)model_attr[i]<<2)|LEAF_UPPER));
            }
        }
    const struct multipage_fast_stats *st=&C->root_ext->multipage_fast;
    const struct sprr_reuse_state *r=&C->kernel_reuse_state;
    printf("%llu calls (%d CPUs), %llu frames changed (%llu across classes), %llu record groups, %llu lists changed "
           "after the pre-clean\n",(unsigned long long)total,threads_n,(unsigned long long)changed,
           (unsigned long long)classes,(unsigned long long)records,(unsigned long long)mutated);
    printf("refresh: %llu hits, %llu saves (%llu invalidations, %llu calls entered with an invalid snapshot), "
           "%llu proof misses, %llu verified; %llu PPERM flips (%llu exact variant swaps, %llu synced)\n",
           (unsigned long long)r->hits,(unsigned long long)r->saves,(unsigned long long)invalidations,
           (unsigned long long)stale_entries,(unsigned long long)proof_misses,(unsigned long long)r->verified,
           (unsigned long long)flips,(unsigned long long)exact_swaps,(unsigned long long)synced_swaps);
    if(!ref_mode) {
        printf("fast: %llu pre-clean hits, %llu inline cleans, %llu same-class, %llu copy words patched (%llu variant "
               "columns), %llu unpatched, %llu closes (%llu before records)\n",(unsigned long long)st->preclean_hits,
               (unsigned long long)st->inline_cleans,(unsigned long long)st->same_class,(unsigned long long)st->patched,
               (unsigned long long)st->variants,(unsigned long long)st->unpatched,(unsigned long long)st->closes,
               (unsigned long long)st->barrier_closes);
        CHECK(st->preclean_hits+st->inline_cleans+st->same_class==changed);
        CHECK(st->patched>0 && st->barrier_closes>0 && st->same_class>0 && st->variants>0 && exact_swaps>0);
        CHECK(!stale_entries || st->unpatched);
#if !MUTANT_UNPATCHED_WORD
        CHECK(!proof_misses);                     /* no MULTIPAGE change ever needed a full re-sync */
        CHECK(r->saves<=expected_saves+stale_entries);
#else
        printf("P9: unpatched words made %llu proofs miss; each re-synced in full and the copies still verify\n",
               (unsigned long long)proof_misses);
        CHECK(proof_misses>0);
#endif
    }
    CHECK(!failures_seen);
    printf("handler time (host, model cache maintenance): %.1f us per call, %.2f us per group, max %.1f us\n",
           held_calls ? held_ns/1e3/held_calls : 0.0,held_groups ? held_ns/1e3/held_groups : 0.0,held_max/1e3);
    if(threads_n==1)printf("digest %016llx answers %016llx\n",(unsigned long long)digest(),(unsigned long long)answers);
    if(getenv("MP_DUMP")) {
        FILE *o=fopen(getenv("MP_DUMP"),"w");
        for(uint64_t pa=work_base;pa<next_table;pa+=8)fprintf(o,"arena %llx %016llx\n",(unsigned long long)(pa-work_base),(unsigned long long)rebased(*(volatile uint64_t *)(uintptr_t)pa));
        for(uint64_t pa=GUEST_TABLES;pa<GUEST_TABLES+guest_next;pa+=8)fprintf(o,"guest %llx %016llx\n",(unsigned long long)(pa-GUEST_TABLES),(unsigned long long)rebased(*(volatile uint64_t *)(uintptr_t)pa));
        for(unsigned n=0;n<C->kernel_views.count;n++)for(unsigned i=0;i<512;i++)fprintf(o,"word %u %u %016llx\n",n,i,(unsigned long long)rebased(C->kernel_reuse_state.words[n][i]));
        fclose(o);
    }
    printf("PASS: %lu checks\n",checks);
    return 0;
}
