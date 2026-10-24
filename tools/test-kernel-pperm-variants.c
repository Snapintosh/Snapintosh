/* SPDX-License-Identifier: MIT */
/* SNAP_KERNEL_PPERM_VARIANTS (docs/KERNEL-PPERM-VARIANTS-20261016.md): a
 * PPERM change that flips SPRR_KERNEL_VIEW_PPERM exchanges the CPU's kernel
 * copy column with its variant column and installs the new root, instead of
 * rewriting the copy in place.
 *
 * Two machines run the same random operations. The reference is the unchanged
 * monitor (snapshot reuse, the bit-8-unchanged skip, in-place sync); the
 * candidate adds variants. After every step:
 *  - every CPU's installed translation tree (from its TTBR1) is identical on
 *    both machines, descriptor by descriptor (failure mode 1);
 *  - no page reachable from an installed root holds unpublished stores (2);
 *  - a TTBR1 change is invalidated before the step ends (3);
 *  - a valid snapshot describes all six installed columns exactly (4);
 *  - every unlinked variant page is byte-identical to when it was unlinked (5).
 * Every exact swap is also verified against the translation (the monitor
 * samples 1 in 64). -DVARIANTS_PRE_CHANGE=1 drops the snapshot-generation
 * check from the exact predicate and must fail.
 *
 * With -DSNAP_VIEW_RECLAIM=1 both machines also retire the copies of the three
 * ordinary tables now and then (sprr_views_reclaim with kernel_views_quiesce's
 * steps: snapshot invalidated, publication rows reset, refresh) and prepare one
 * again on a retired set: every check above must keep holding while table
 * positions move under the snapshot, the publication rows and the variants.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -Icompat -Ishadow tools/test-kernel-pperm-variants.c shadow/sprr-view.c \
 *    shadow/shadow.c shadow/mmu.c -o build/test-kernel-pperm-variants
 */
#define main baseline_view_tests
#include "test-sprr-view.c"
#undef main
#include "sprr-variants.h"

#ifndef VARIANTS_PRE_CHANGE
#define VARIANTS_PRE_CHANGE 0
#endif
#define PAGES (BYTES/4096)

struct machine {
    struct sprr_views views;
    struct sprr_reuse_state reuse;
    struct sprr_publish_state publish;
    struct sprr_view_variants var;
    uint64_t pp[6],ttbr1[6],next;
    unsigned budget,tlbi_due[6];
    unsigned char ram[BYTES],dirty[PAGES];
    uint64_t skipped,inplace,exact,synced,fallbacks,verified,mismatches,hits,misses;
};
static struct machine ref,cand,*active;
static uint64_t vhash[SPRR_VIEW_TABLES][6],vpage[SPRR_VIEW_TABLES][6];
static uint64_t random_state=UINT64_C(0xbb67ae8584caa73b);
static unsigned rnd(unsigned n)
{
    random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;
    return (unsigned)(random_state%n);
}
static void mark(uint64_t pa,int dirty)
{if(active && pa>=BASE && pa<BASE+BYTES)active->dirty[(pa-BASE)/4096]=(unsigned char)dirty;}
/* kernel_table_write: identical stores elided, changed stores mark the copy
 * page pending (SNAP_KERNEL_DIRTY_PUBLISH) and unpublished. */
static int kwrite(void *ctx,uint64_t pa,uint64_t value)
{
    uint64_t old;
    if(rd(ctx,pa,&old))return -1;
    if(old==value)return 0;
    if(!sprr_publish_note(&active->publish,&views,pa))return -1;
    mark(pa,1);return wr(ctx,pa,value);
}
/* table_alloc zeroes with plain stores: unpublished until a publish. */
static uint64_t kalloc(void *ctx)
{
    uint64_t pa=alloc(ctx);
    if(pa) {memset(ram+(pa-BASE),0,4096);mark(pa,1);}
    return pa;
}
/* The monitor's variant allocator: private_kernel_alloc, then the page is
 * cleaned at once. */
static uint64_t valloc(void *ctx)
{
    uint64_t pa=alloc(ctx);
    if(pa) {memset(ram+(pa-BASE),0,4096);mark(pa,0);}
    return pa;
}
static struct shadow kshadow(void)
{return (struct shadow){.txsz=17,.root=BASE,.alloc=kalloc,.read=rd,.write=kwrite};}
static struct shadow vshadow(void)
{return (struct shadow){.txsz=17,.root=BASE,.alloc=valloc,.read=rd,.write=kwrite};}
static int publish_cpu(unsigned cpu)
{
    struct sprr_publish_state *p=&active->publish;
    if(!sprr_publish_prepare(p,&views))return 0;
    for(unsigned level=4;level--;)for(unsigned n=0;n<views.count;n++) {
        if(views.tables[n].level!=level)continue;
        p->pages++;
        if(!sprr_publish_needed(p,cpu,n)) {p->skipped++;continue;}
        mark(views.tables[n].copy[cpu],0);
        if(!sprr_publish_complete(p,cpu,n))return 0;
    }
    p->publishes++;return 1;
}
static void invalidate(unsigned cpu) {active->tlbi_due[cpu]=0;}
static int refresh(void)
{
    struct shadow s=kshadow();struct machine *m=active;
    int match=sprr_reuse_match(&m->reuse,&views,&s,m->pp);
    if(match<0)return 0;
    if(match) {m->hits++;return 1;}
    m->misses++;m->reuse.valid=0;
    for(unsigned cpu=0;cpu<6;cpu++)
        if(!sprr_views_sync_cpu(&views,&s,cpu,m->pp[cpu]) || !publish_cpu(cpu))return 0;
    for(unsigned cpu=0;cpu<6;cpu++)invalidate(cpu); /* shadow_tlb_sync's ALLE1IS */
    return sprr_reuse_save(&m->reuse,&views,&s,m->pp);
}
static int reuse_skip(struct machine *m,unsigned cpu,int current,uint64_t before,uint64_t pperm)
{
    const struct sprr_publish_state *ps=&m->publish;
    return current && !((before^pperm)&SPRR_KERNEL_VIEW_PPERM) &&
        ps->root==views.canonical_root && ps->count==views.count &&
        sprr_publish_row_empty(ps,cpu);
}
/* The unchanged monitor: kernel_change_pperm_impl with SNAP_KERNEL_PPERM_REUSE. */
static int pperm_reference(unsigned cpu,uint64_t pperm)
{
    struct machine *m=active;struct shadow s=kshadow();
    int current=views.count && sprr_reuse_current(&m->reuse,&views,&s,m->pp)==1;
    sprr_reuse_invalidate(&m->reuse);
    uint64_t before=m->pp[cpu];
    int skip=reuse_skip(m,cpu,current,before,pperm);
    if(skip)m->skipped++;
    else if(!sprr_views_sync_cpu(&views,&s,cpu,pperm) || !publish_cpu(cpu))return 0;
    else {m->inplace++;invalidate(cpu);}
    m->pp[cpu]=pperm;
    return !current || sprr_reuse_repin(&m->reuse,&views,cpu,pperm);
}
static uint64_t page_hash(uint64_t pa)
{
    uint64_t h=UINT64_C(0xcbf29ce484222325);
    for(unsigned i=0;i<4096;i++)h=(h^ram[pa-BASE+i])*UINT64_C(0x100000001b3);
    return h;
}
/* A page that just became (or moved within) a variant column. */
static void record_variants(unsigned cpu)
{
    for(unsigned n=0;n<SPRR_VIEW_TABLES;n++)if(cand.var.copy[n][cpu] && vpage[n][cpu]!=cand.var.copy[n][cpu]) {
        vpage[n][cpu]=cand.var.copy[n][cpu];vhash[n][cpu]=page_hash(vpage[n][cpu]);
    }
}
static int exact_predicate(unsigned cpu,uint64_t pperm)
{
#if VARIANTS_PRE_CHANGE
    struct sprr_reuse_state r=cand.reuse;r.saves=cand.var.saves[cpu];
    return sprr_variants_exact(&cand.var,&views,&r,cpu,pperm);
#else
    return sprr_variants_exact(&cand.var,&views,&cand.reuse,cpu,pperm);
#endif
}
/* Mirrors kernel_change_pperm_impl with SNAP_KERNEL_PPERM_VARIANTS. */
static int pperm_candidate(unsigned cpu,uint64_t pperm)
{
    struct machine *m=&cand;struct shadow s=kshadow(),vs=vshadow();
    int current=views.count && sprr_reuse_current(&m->reuse,&views,&s,m->pp)==1;
    sprr_reuse_invalidate(&m->reuse);
    uint64_t before=m->pp[cpu];
    int skip=reuse_skip(m,cpu,current,before,pperm),swapped=0,exact=0;
    if(skip)m->skipped++;
    else {
        if(current && ((before^pperm)&SPRR_KERNEL_VIEW_PPERM)) {
            exact=exact_predicate(cpu,pperm);
            int reserved=exact || sprr_variants_reserve(&m->var,&views,&vs,cpu);
            record_variants(cpu);
            if(reserved)
                swapped=sprr_variants_swap(&m->var,&views,&m->publish,cpu,before,m->reuse.saves);
            if(swapped)record_variants(cpu);
            else {exact=0;m->fallbacks++;}
        }
        if(exact) {
            /* Every exact swap here; the monitor samples 1 in 64. */
            m->exact++;m->verified++;
            if(!sprr_views_verify_cpu(&views,&s,cpu,pperm)) {m->mismatches++;return 0;}
        } else if(!sprr_views_sync_cpu(&views,&s,cpu,pperm))return 0;
        else if(swapped)m->synced++;
        else m->inplace++;
        if(!publish_cpu(cpu))return 0;
        if(swapped) {m->ttbr1[cpu]=sprr_views_root(&views,cpu);m->tlbi_due[cpu]=1;}
        invalidate(cpu);
    }
    m->pp[cpu]=pperm;
    if(!current)return 1;
    return swapped ? sprr_variants_repin(&m->reuse,&views,cpu,pperm) :
                     sprr_reuse_repin(&m->reuse,&views,cpu,pperm);
}
static void enter(struct machine *m)
{
    active=m;memcpy(ram,m->ram,sizeof ram);views=m->views;next=m->next;alloc_budget=m->budget;
}
static void leave(void)
{
    struct machine *m=active;
    memcpy(m->ram,ram,sizeof ram);m->views=views;m->next=next;m->budget=alloc_budget;active=0;
}
static int word(const struct machine *m,uint64_t pa,uint64_t *out)
{
    if(pa<BASE || pa>BASE+BYTES-8 || (pa&7))return 0;
    memcpy(out,m->ram+(pa-BASE),8);return 1;
}
/* Descriptor-by-descriptor equality of two installed trees; table addresses
 * may differ, everything else may not. */
static int same_tree(uint64_t a,uint64_t b,unsigned level)
{
    for(unsigned i=0;i<512;i++) {
        uint64_t x,y;
        if(!word(&ref,a+8UL*i,&x) || !word(&cand,b+8UL*i,&y))return 0;
        if(level<3 && (x&3)==3) {
            if((y&3)!=3 || (x&~PT_OA_MASK)!=(y&~PT_OA_MASK) ||
               !same_tree(x&PT_OA_MASK,y&PT_OA_MASK,level+1))return 0;
        } else if(x!=y)return 0;
    }
    return 1;
}
/* Every page a walk from root can reach holds no unpublished store. */
static int published(const struct machine *m,uint64_t table,unsigned level)
{
    if(table<BASE || table>=BASE+BYTES || m->dirty[(table-BASE)/4096])return 0;
    for(unsigned i=0;i<512 && level<3;i++) {
        uint64_t d;if(!word(m,table+8UL*i,&d))return 0;
        if((d&3)==3 && !published(m,d&PT_OA_MASK,level+1))return 0;
    }
    return 1;
}
static void invariants(void)
{
    for(unsigned cpu=0;cpu<6;cpu++) {
        CHECK(ref.ttbr1[cpu]==sprr_views_root(&ref.views,cpu));
        CHECK(cand.ttbr1[cpu]==sprr_views_root(&cand.views,cpu));
        CHECK(same_tree(ref.ttbr1[cpu],cand.ttbr1[cpu],0));
        CHECK(published(&ref,ref.ttbr1[cpu],0) && published(&cand,cand.ttbr1[cpu],0));
        CHECK(!ref.tlbi_due[cpu] && !cand.tlbi_due[cpu]);
        CHECK(ref.pp[cpu]==cand.pp[cpu]);
    }
    enter(&cand);
    struct shadow s=kshadow();
    if(cand.reuse.valid) {
        CHECK(sprr_reuse_current(&cand.reuse,&views,&s,cand.pp)==1);
        for(unsigned cpu=0;cpu<6;cpu++)
            CHECK(sprr_views_verify_cpu(&views,&s,cpu,cand.reuse.pperm[cpu]));
    }
    for(unsigned cpu=0;cpu<6;cpu++)for(unsigned n=0;n<SPRR_VIEW_TABLES;n++)
        if(cand.var.copy[n][cpu]) {
            CHECK(vpage[n][cpu]==cand.var.copy[n][cpu]);
            CHECK(page_hash(cand.var.copy[n][cpu])==vhash[n][cpu]);
        }
    leave();
}
static void mutate(uint64_t table,unsigned index,uint64_t desc)
{
    enter(&ref);put(table,index,desc);leave();
    enter(&cand);put(table,index,desc);leave();
}
static void both_refresh(void)
{
    enter(&ref);CHECK(refresh());leave();
    enter(&cand);CHECK(refresh());leave();
    invariants();
}
static void both_pperm(unsigned cpu,uint64_t pperm)
{
    enter(&ref);CHECK(pperm_reference(cpu,pperm));leave();
    enter(&cand);CHECK(pperm_candidate(cpu,pperm));leave();
    invariants();
}
static void both_prepare(uint64_t va)
{
    struct shadow s;
    enter(&ref);s=kshadow();CHECK(sprr_views_prepare(&views,&s,va));leave();
    enter(&cand);s=kshadow();CHECK(sprr_views_prepare(&views,&s,va));leave();
}
#if SNAP_VIEW_RECLAIM
static uint64_t reclaims,retired;
/* kernel_views_quiesce on the active machine: refresh() is kernel_refresh
 * (a miss: full sync, publication, saves++) and its ALLE1IS. */
static int machine_quiesce(void *ctx)
{
    (void)ctx;
    sprr_reuse_invalidate(&active->reuse);
    sprr_publish_reset(&active->publish);
    return refresh();
}
static void both_reclaim(void)
{
    struct shadow s;int a,b;
    enter(&ref);s=kshadow();a=sprr_views_reclaim(&views,&s,machine_quiesce,0);leave();
    enter(&cand);s=kshadow();b=sprr_views_reclaim(&views,&s,machine_quiesce,0);leave();
    CHECK(a==b && a>=0 && ref.views.count==cand.views.count);
    if(a>0) {reclaims++;retired+=(unsigned)a;}
    invariants();
}
#endif
static const uint64_t deltas[4]={0,0x100,SPRR_UPERM_TPRO_WRITE,0x100|SPRR_UPERM_TPRO_WRITE};
static void canonical_change(void)
{
    unsigned which=rnd(4);
    uint64_t table=which==0 ? BASE+0x3000 : which==1 ? BASE+0x4000 :
                   which==2 ? BASE+0x2000 : BASE+0x3000;
    unsigned index=which==2 ? 5+rnd(3) : 4+rnd(8);
    uint64_t desc=rnd(3) ? DATA+0x10000+4096UL*rnd(64)+3+ATTR+PT_UXN+PT_PXN : 0;
    if(which==2)desc=rnd(2) ? DATA+0x200000UL*(1+rnd(8))+1+ATTR+PT_UXN+PT_PXN : 0;
    if(which==3)desc=rnd(2) ? DATA+0x20000+4096UL*rnd(16)+3+ATTR+PT_UXN : 0;
    mutate(table,index,desc);
}
static void unit_checks(unsigned cpu)
{
    enter(&cand);
    struct shadow s=kshadow(),vs=vshadow();
    struct sprr_view_variants a=cand.var;struct sprr_publish_state p=cand.publish;
    /* exact: each identity element alone makes it false. */
    uint64_t pperm=cand.pp[cpu]^0x100;
    if(sprr_variants_exact(&a,&views,&cand.reuse,cpu,pperm)) {
        struct sprr_view_variants b=a;b.saves[cpu]++;
        CHECK(!sprr_variants_exact(&b,&views,&cand.reuse,cpu,pperm));
        b=a;b.count[cpu]--;CHECK(!sprr_variants_exact(&b,&views,&cand.reuse,cpu,pperm));
        b=a;b.source[1][cpu]+=4096;CHECK(!sprr_variants_exact(&b,&views,&cand.reuse,cpu,pperm));
        b=a;b.copy[2][cpu]=0;CHECK(!sprr_variants_exact(&b,&views,&cand.reuse,cpu,pperm));
        CHECK(!sprr_variants_exact(&a,&views,&cand.reuse,cpu,pperm^0x100));
        CHECK(!sprr_variants_exact(&a,&views,&cand.reuse,cpu,1));
        CHECK(!sprr_variants_exact(&a,&views,&cand.reuse,6,pperm));
        CHECK(sprr_variants_exact(&a,&views,&cand.reuse,cpu,pperm^SPRR_UPERM_TPRO_WRITE));
    } else CHECK(!"no exact variant to probe");
    /* swap refuses: pending row, stale publication state, missing page, bad cpu. */
    struct sprr_views v=views;
    p.pending[cpu][1]|=UINT64_C(1)<<3;
    CHECK(!sprr_variants_swap(&a,&v,&p,cpu,cand.pp[cpu],cand.reuse.saves));
    p=cand.publish;p.count--;
    CHECK(!sprr_variants_swap(&a,&v,&p,cpu,cand.pp[cpu],cand.reuse.saves));
    p=cand.publish;a.copy[0][cpu]=0;
    CHECK(!sprr_variants_swap(&a,&v,&p,cpu,cand.pp[cpu],cand.reuse.saves));
    a=cand.var;
    CHECK(!sprr_variants_swap(&a,&v,&p,6,cand.pp[cpu],cand.reuse.saves));
    CHECK(!sprr_variants_swap(&a,&v,&p,cpu,1,cand.reuse.saves));
    CHECK(!sprr_variants_swap(&a,&v,&p,cpu,cand.pp[cpu],0));
    CHECK(!memcmp(&v,&views,sizeof v));
    /* A swap and its inverse restore both columns exactly. */
    CHECK(sprr_variants_swap(&a,&v,&p,cpu,cand.pp[cpu],cand.reuse.saves));
    CHECK(sprr_views_root(&v,cpu)!=sprr_views_root(&views,cpu));
    CHECK(sprr_variants_swap(&a,&v,&p,cpu,cand.pp[cpu],cand.reuse.saves));
    CHECK(!memcmp(v.tables,views.tables,sizeof v.tables));
    for(unsigned n=0;n<views.count;n++)CHECK(a.copy[n][cpu]==cand.var.copy[n][cpu]);
    /* reserve refuses a page that aliases a source, a copy or a variant, and
     * records nothing for it. */
    a=cand.var;a.copy[views.count-1][cpu]=0;
    const uint64_t aliases[3]={views.tables[1].source,views.tables[0].copy[(cpu+1)%6],
                               cand.var.copy[0][(cpu+2)%6]};
    for(unsigned i=0;i<3;i++) {
        forced_alloc=aliases[i];uint64_t errors=a.errors;
        CHECK(!sprr_variants_reserve(&a,&views,&vs,cpu) && a.errors==errors+1 &&
              !a.copy[views.count-1][cpu]);
    }
    forced_alloc=0;unsigned budget=alloc_budget;alloc_budget=0;
    CHECK(!sprr_variants_reserve(&a,&views,&vs,cpu) && !a.copy[views.count-1][cpu]);
    alloc_budget=budget;
    CHECK(sprr_variants_reserve(&a,&views,&vs,cpu) && a.copy[views.count-1][cpu]);
    CHECK(!sprr_variants_reserve(&a,&views,&vs,6));
    /* repin refuses mismatched identity and malformed values. */
    struct sprr_reuse_state r=cand.reuse;r.valid=0;
    CHECK(!sprr_variants_repin(&r,&views,6,SPRR_PPERM_INITIAL) && !r.valid);
    CHECK(!sprr_variants_repin(&r,&views,0,1) && !r.valid);
    r.count--;CHECK(!sprr_variants_repin(&r,&views,0,SPRR_PPERM_INITIAL) && !r.valid);r.count++;
    r.tables[1].source+=4096;CHECK(!sprr_variants_repin(&r,&views,0,SPRR_PPERM_INITIAL) && !r.valid);
    r=cand.reuse;r.valid=0;
    CHECK(sprr_variants_repin(&r,&views,2,cand.pp[2]) && r.valid);
    for(unsigned n=0;n<views.count;n++)CHECK(r.tables[n].copy[2]==views.tables[n].copy[2]);
    (void)s;leave();
}
int main(void)
{
    CHECK(!baseline_view_tests());
    struct shadow s;setup(&s);s=kshadow();
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare(&views,&s,0));
    for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,DATA+4096UL*i+3+ATTR+PT_UXN);
    for(struct machine *m=&ref;m;m=m==&ref ? &cand : 0) {
        memcpy(m->ram,ram,sizeof ram);m->views=views;m->next=next;m->budget=alloc_budget;
        for(unsigned cpu=0;cpu<6;cpu++)m->pp[cpu]=SPRR_PPERM_INITIAL;
    }
    for(unsigned cpu=0;cpu<6;cpu++)ref.ttbr1[cpu]=cand.ttbr1[cpu]=sprr_views_root(&views,cpu);
    both_refresh();
    /* Allocation failure on a CPU's first flip takes the in-place path. */
    enter(&cand);unsigned budget=alloc_budget;alloc_budget=0;leave();cand.budget=0;
    both_pperm(0,cand.pp[0]^0x100);
    cand.budget=budget;
    CHECK(cand.fallbacks==1 && !cand.synced && !cand.exact);
    unsigned prepared=0;
    /* Flips dominate, as on hardware (v6: 135,838 bit-8 flips, 208 canonical
     * re-saves), but canonical changes stay frequent enough to stale every
     * CPU's variant many times. */
    for(unsigned round=0;round<6000;round++) {
        unsigned op=rnd(40),cpu=rnd(6);
        if(op<30)both_pperm(cpu,ref.pp[cpu]^deltas[rnd(4)]);
        else if(op<32) {canonical_change();both_refresh();}
        else if(op<33) {
            /* A-B-A: a canonical change with PPERM transactions before its
             * refresh, then restored. No stale column may come back. */
            uint64_t old;CHECK(word(&ref,BASE+0x3000+8*5,&old));
            mutate(BASE+0x3000,5,DATA+0x70000+3+ATTR+PT_UXN+PT_PXN);
            enter(&ref);CHECK(pperm_reference(cpu,ref.pp[cpu]^0x100));leave();
            enter(&cand);CHECK(pperm_candidate(cpu,cand.pp[cpu]^0x100));leave();
            mutate(BASE+0x3000,5,old);both_refresh();
        } else if(op<34) {
            static const uint64_t vas[3]={0x200000,0x401000,0x600000};
#if SNAP_VIEW_RECLAIM
            if(prepared>=3) {
                /* Their leaves are ordinary: the three copies retire; the one
                 * prepared again takes the first retired set. */
                both_reclaim();both_prepare(vas[rnd(3)]);both_refresh();continue;
            }
#endif
            if(prepared>=3) {both_refresh();continue;}
            if(prepared==1) {
                mutate(BASE+0x2000,2,BASE+0x5000+3);
                mutate(BASE+0x5000,1,DATA+3+ATTR+PT_UXN+PT_PXN);
            }
            if(prepared==2) {
                mutate(BASE+0x2000,3,BASE+0x6000+3);
                mutate(BASE+0x6000,0,DATA+0x3000+3+ATTR+PT_UXN+PT_PXN);
            }
            both_prepare(vas[prepared++]);both_refresh();
        } else if(op<35) {
            /* Pending publication for this CPU: no swap, in-place sync. */
            uint64_t exact=cand.exact,synced=cand.synced,fallbacks=cand.fallbacks;
            cand.publish.pending[cpu][0]|=1;
            both_pperm(cpu,ref.pp[cpu]^0x100);
            CHECK(!cand.publish.pending[cpu][0]);
            CHECK(cand.exact==exact && cand.synced==synced && cand.fallbacks<=fallbacks+1);
        } else both_refresh();
        if(failed>20)break;
    }
    CHECK(prepared==3);
#if SNAP_VIEW_RECLAIM
    CHECK(reclaims>10 && retired>=reclaims);
#endif
    CHECK(cand.exact>800 && cand.synced>=30 && cand.fallbacks>10 && !cand.mismatches);
    /* A synced swap is a CPU's first flip after a re-save (or after an
     * in-place flip, or its first ever); every other bit-8 flip is exact. */
    CHECK(cand.synced<=6*cand.reuse.saves+cand.inplace+6);
    CHECK(cand.verified==cand.exact && cand.exact+cand.synced+cand.inplace==ref.inplace);
    CHECK(cand.skipped==ref.skipped);
    /* Two flips with no canonical change between: cpu's variant is exact. */
    unsigned cpu=rnd(6);
    both_pperm(cpu,ref.pp[cpu]^0x100);both_pperm(cpu,ref.pp[cpu]^0x100);
    unit_checks(cpu);
    printf("model: reference in-place %llu skipped %llu; candidate exact swaps %llu, synced swaps %llu, "
           "in-place %llu (fallbacks %llu), skipped %llu, variant pages %llu\n",
           (unsigned long long)ref.inplace,(unsigned long long)ref.skipped,
           (unsigned long long)cand.exact,(unsigned long long)cand.synced,
           (unsigned long long)cand.inplace,(unsigned long long)cand.fallbacks,
           (unsigned long long)cand.skipped,(unsigned long long)cand.var.reserved);
#if SNAP_VIEW_RECLAIM
    printf("reclaim: %llu reclaims retired %llu tables\n",(unsigned long long)reclaims,(unsigned long long)retired);
#endif
    printf("%s: %u kernel PPERM variant checks, %u failures\n",failed ? "FAIL" : "PASS",checks,failed);
    return failed ? 1 : 0;
}
