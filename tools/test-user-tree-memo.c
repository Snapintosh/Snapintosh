/* SPDX-License-Identifier: MIT */
/* SNAP_USER_TREE_MEMO: cross-transaction claims must be invisible.
 *
 * Every transaction runs twice from one snapshot: first the unmemoized
 * compared reference (whose callbacks never touch the witness), then the memo
 * path with the monitor's noting callbacks. RAM, view metadata, plan, every
 * existing counter, allocation cursor, epoch, write count, proof and result
 * must be identical. Deterministic cases pin hits, misses and invalidation;
 * a randomized walk mixes tree edits, CPU state/mode changes, one-CPU syncs,
 * failures, page reuse and view resets; unnoted stores prove the sampled
 * self-check catches a writer that bypasses the witness.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -Wall -Wextra -Werror -Icompat -Ishadow tools/test-user-tree-memo.c \
 *    shadow/sprr-view.c shadow/mmu.c -o build/test-user-tree-memo */
#include <stdio.h>
#include <string.h>
#include "sprr-view.h"

#define BASE UINT64_C(0x40000000)
#define DATA UINT64_C(0x94050c000)
#define PAGES 512u
#define BYTES (PAGES*4096u)
#define ATTR (PT_AF|(3UL<<8)|(1UL<<11))
static _Alignas(4096) unsigned char ram[BYTES],before[BYTES],expected[BYTES];
static uint64_t next,epoch,fail_write;
static unsigned writes,checks,failures;
static int noting;
static struct sprr_views views;
static struct sprr_table_memo memo;
static struct sprr_view_memo vmemo;
static struct sprr_user_prepare_plan plan;
static struct sprr_user_prepare_stats stats;
static struct sprr_user_zero_stats zero;
static struct sprr_store_compare_stats cmp,sync_cmp;
static struct sprr_view_proof proof;
static struct sprr_view_proof_stats proof_stats;
static uint64_t reference_words,memo_words; /* destination words decoded+compared */
#define CHECK(x) do {checks++;if(!(x)){failures++;printf("FAIL %u: %s\n",__LINE__,#x);}} while(0)

static int rd(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;if((pa&7) || pa<BASE || pa>BASE+BYTES-8)return -1;
    memcpy(out,ram+(pa-BASE),8);return 0;
}
/* The monitor's mem_write: note before a changed store, then store. */
static int wr(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;if((pa&7) || pa<BASE || pa>BASE+BYTES-8 || pa==fail_write)return -1;
    uint64_t old;memcpy(&old,ram+(pa-BASE),8);
    if(old!=value) {
        sprr_view_epoch_advance(&epoch);
        if(noting)sprr_table_memo_note(&memo,pa);
    }
    memcpy(ram+(pa-BASE),&value,8);writes++;return 0;
}
/* The monitor's table_alloc_owned: issue, note, zero. */
static uint64_t alloc(void *ctx)
{
    (void)ctx;if(next>BASE+BYTES-4096)return 0;
    uint64_t p=next;next+=4096;sprr_view_epoch_advance(&epoch);
    if(noting)sprr_table_memo_alloc(&memo,p);
    memset(ram+(p-BASE),0,4096);return p;
}
static const volatile uint64_t *tread(void *ctx,uint64_t pa)
{
    (void)ctx;if((pa&4095) || pa<BASE || pa>BASE+BYTES-4096)return 0;
    return (const volatile uint64_t *)(ram+(pa-BASE));
}
static uint64_t get(uint64_t table,unsigned slot)
{uint64_t d;memcpy(&d,ram+(table+8UL*slot-BASE),8);return d;}
/* Canonical edit between transactions: always noted, like every monitor store. */
static void put(uint64_t table,unsigned slot,uint64_t d)
{int was=noting;noting=1;CHECK(!wr(0,table+8UL*slot,d));noting=was;}
/* A deliberately broken writer that bypasses the witness. */
static void raw_put(uint64_t pa,uint64_t d){memcpy(ram+(pa-BASE),&d,8);}
static uint64_t canonical_table(void)
{int was=noting;noting=1;uint64_t p=alloc(0);noting=was;CHECK(p);return p;}
static uint64_t leaf(uint64_t pa,unsigned selector)
{return pa|3|ATTR|((uint64_t)(selector&12)<<4)|((uint64_t)(selector&3)<<53);}
static struct shadow shadow_for(uint64_t root)
{return (struct shadow){.txsz=17,.root=root,.alloc=alloc,.read=rd,.write=wr};}
static void memo_reset(void)
{
    memset(&memo,0,sizeof memo);memset(&vmemo,0,sizeof vmemo);
    memo.base=BASE;memo.pages=PAGES;
}
static void world_reset(void)
{
    memset(ram,0,sizeof ram);memset(&views,0,sizeof views);memo_reset();
    memset(&plan,0,sizeof plan);memset(&stats,0,sizeof stats);memset(&zero,0,sizeof zero);
    memset(&cmp,0,sizeof cmp);memset(&sync_cmp,0,sizeof sync_cmp);
    memset(&proof,0,sizeof proof);memset(&proof_stats,0,sizeof proof_stats);
    next=BASE+0x10000;epoch=0;fail_write=0;noting=0;
}

/* Everything a transaction may change, other than the witness itself. */
struct world {
    struct sprr_views views;struct sprr_user_prepare_plan plan;
    struct sprr_user_prepare_stats stats;struct sprr_user_zero_stats zero;
    struct sprr_store_compare_stats cmp,sync_cmp;
    struct sprr_view_proof proof;struct sprr_view_proof_stats proof_stats;
    uint64_t next,epoch;unsigned writes;
};
static struct world saved,wanted;
static void save(struct world *w)
{
    w->views=views;w->plan=plan;w->stats=stats;w->zero=zero;w->cmp=cmp;w->sync_cmp=sync_cmp;
    w->proof=proof;w->proof_stats=proof_stats;w->next=next;w->epoch=epoch;w->writes=writes;
}
static void load(const struct world *w)
{
    views=w->views;plan=w->plan;stats=w->stats;zero=w->zero;cmp=w->cmp;sync_cmp=w->sync_cmp;
    proof=w->proof;proof_stats=w->proof_stats;next=w->next;epoch=w->epoch;writes=w->writes;
}
static int same(const struct world *a,const struct world *b)
{
    return !memcmp(&a->views,&b->views,sizeof a->views) && !memcmp(&a->plan,&b->plan,sizeof a->plan) &&
        !memcmp(&a->stats,&b->stats,sizeof a->stats) && !memcmp(&a->zero,&b->zero,sizeof a->zero) &&
        !memcmp(&a->cmp,&b->cmp,sizeof a->cmp) && !memcmp(&a->sync_cmp,&b->sync_cmp,sizeof a->sync_cmp) &&
        !memcmp(&a->proof,&b->proof,sizeof a->proof) &&
        !memcmp(&a->proof_stats,&b->proof_stats,sizeof a->proof_stats) &&
        a->next==b->next && a->epoch==b->epoch && a->writes==b->writes;
}

/* One all-CPU refresh: reference, rollback, memo; everything must agree. */
static size_t used(void){return (size_t)(next-BASE);}
static int refresh(struct shadow *s,const struct sprr_state st[6],const int modes[6])
{
    save(&saved);size_t n0=used();memcpy(before,ram,n0);
    noting=0;uint64_t compared=cmp.compared;
    int reference=sprr_views_prepare_sync_user_compared(&views,s,st,modes,&plan,&stats,
        tread,&zero,tread,tread,&cmp);
    reference_words+=cmp.compared-compared;
    save(&wanted);size_t n1=used();memcpy(expected,ram,n1);
    load(&saved);memcpy(ram,before,n0);
    noting=1;uint64_t hits=memo.stats.copy_hits;
    int got=sprr_views_prepare_sync_user_memo(&views,s,st,modes,&plan,&stats,
        tread,&zero,tread,tread,&cmp,&memo,&vmemo);
    noting=0;
    memo_words+=cmp.compared-compared-512*(memo.stats.copy_hits-hits);
    struct world now;save(&now);
    CHECK(got==reference);CHECK(used()==n1 && !memcmp(ram,expected,n1));CHECK(same(&now,&wanted));
    if(!got)CHECK(!vmemo.valid);
    else if(sprr_table_memo_usable(&memo))CHECK(vmemo.valid==63 && vmemo.count==views.count);
    else CHECK(!vmemo.valid);
    return got;
}
/* One cached one-CPU sync, the same way. */
static int sync1(struct shadow *s,unsigned cpu,const struct sprr_state *st,int el0)
{
    save(&saved);size_t n0=used();memcpy(before,ram,n0);
    noting=0;uint64_t compared=sync_cmp.compared;
    int reference=sprr_views_sync_user_cached_compared(&views,s,cpu,st,el0,&epoch,&proof,
        &proof_stats,1,tread,tread,&sync_cmp);
    reference_words+=sync_cmp.compared-compared;
    save(&wanted);size_t n1=used();memcpy(expected,ram,n1);
    load(&saved);memcpy(ram,before,n0);
    noting=1;uint64_t hits=memo.stats.copy_hits;
    int got=sprr_views_sync_user_cached_memo(&views,s,cpu,st,el0,&epoch,&proof,
        &proof_stats,1,tread,tread,&sync_cmp,&memo,&vmemo);
    noting=0;
    memo_words+=sync_cmp.compared-compared-512*(memo.stats.copy_hits-hits);
    struct world now;save(&now);
    CHECK(got==reference);CHECK(used()==n1 && !memcmp(ram,expected,n1));CHECK(same(&now,&wanted));
    if(!got)CHECK(!vmemo.valid);
    else if(sprr_table_memo_usable(&memo))CHECK((vmemo.valid>>cpu)&1);
    else CHECK(!vmemo.valid);
    return got;
}
static void states_init(struct sprr_state st[6],int modes[6])
{
    memset(st,0,6*sizeof *st);
    for(unsigned cpu=0;cpu<6;cpu++){sprr_root_reset(&st[cpu],0xa);modes[cpu]=cpu&1;}
}
/* Avoid the sampled transaction in deterministic counting cases. */
static void unsampled(void)
{if(!((memo.stats.calls+1)%SPRR_TABLE_MEMO_SAMPLE))memo.stats.calls++;}

/* root -> L1 -> L2 -> L3[0..3]; L3[0] and L3[2] hold class9 leaves. */
static uint64_t root,l1,l2,l3[4];
static struct shadow fixed_tree(void)
{
    world_reset();
    root=canonical_table();l1=canonical_table();l2=canonical_table();
    put(root,1,l1|3);put(l1,2,l2|3);
    for(unsigned i=0;i<4;i++) {
        l3[i]=canonical_table();put(l2,10+i,l3[i]|3);
        for(unsigned j=0;j<24;j++)put(l3[i],j*17%512,leaf(DATA+4096UL*(64*i+j),(i==0 || i==2) && j%5==0 ? 9 : 7));
    }
    struct shadow s=shadow_for(root);
    noting=1;CHECK(sprr_views_init(&views,&s));noting=0;
    return s;
}

static void deterministic_cases(void)
{
    struct sprr_state st[6];int modes[6];states_init(st,modes);
    struct shadow s=fixed_tree();
    /* First refresh: everything scanned and compared. */
    unsampled();CHECK(refresh(&s,st,modes));
    CHECK(views.count==1+2+2);  /* root, L1, L2, two class9 L3 tables */
    CHECK(memo.stats.scan_hits==0 && memo.stats.scan_misses==4);
    CHECK(memo.stats.copy_hits==0 && memo.stats.copy_misses==6*5);
    /* Unchanged: every level3 scan and every destination is a hit. */
    struct sprr_table_memo_stats b=memo.stats;uint64_t changed=cmp.changed;
    unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.scan_hits-b.scan_hits==4 && memo.stats.scan_misses==b.scan_misses);
    CHECK(memo.stats.copy_hits-b.copy_hits==6*5 && memo.stats.copy_misses==b.copy_misses);
    CHECK(cmp.changed==changed && cmp.compared==cmp.skipped+cmp.changed);
    CHECK(zero.groups==64*stats.source_tables);
    /* Edit a non-class9 leaf of a private class9 table: one rescan, six copies. */
    put(l3[0],1,leaf(DATA+0x100000,13));b=memo.stats;
    unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.scan_misses-b.scan_misses==1 && memo.stats.scan_hits-b.scan_hits==3);
    CHECK(memo.stats.copy_misses-b.copy_misses==6 && memo.stats.copy_hits-b.copy_hits==6*4);
    /* Edit a shared (non-private) level3 table: rescan only, all copies hit. */
    put(l3[1],2,leaf(DATA+0x101000,11));b=memo.stats;
    unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.scan_misses-b.scan_misses==1 && memo.stats.copy_hits-b.copy_hits==30);
    /* CPU2 changes its write key: only its two class9 copies are recomputed. */
    modes[2]^=1;st[2].uperm^=SPRR_UPERM_TPRO_WRITE;b=memo.stats;changed=cmp.changed;
    unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.copy_misses-b.copy_misses==2 && memo.stats.copy_hits-b.copy_hits==28);
    CHECK(cmp.changed>changed);
    /* A mode change that keeps the key changes nothing and is all hits. */
    st[3].uperm=st[3].pperm&SPRR_UPERM_TPRO_WRITE ? st[3].uperm|SPRR_UPERM_TPRO_WRITE :
        st[3].uperm&~SPRR_UPERM_TPRO_WRITE;
    unsampled();CHECK(refresh(&s,st,modes));
    modes[3]^=1;b=memo.stats;changed=cmp.changed;unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.copy_hits-b.copy_hits==30 && cmp.changed==changed);
    /* One-CPU sync with a different key: CPU4's class9 copies only. */
    struct sprr_state other=st[4];other.pperm^=SPRR_UPERM_TPRO_WRITE;b=memo.stats;
    unsampled();CHECK(sync1(&s,4,&other,0));
    CHECK(memo.stats.copy_misses-b.copy_misses==2 && memo.stats.copy_hits-b.copy_hits==3);
    /* That first sync had no proof: its coverage walk replayed all four
     * current level3 summaries instead of rescanning them. */
    CHECK(memo.stats.walk_hits-b.walk_hits==4 && memo.stats.walk_misses==b.walk_misses);
    /* The same one-CPU state again: all hits. */
    b=memo.stats;unsampled();CHECK(sync1(&s,4,&other,0));
    CHECK(memo.stats.copy_hits-b.copy_hits==5 && !(memo.stats.copy_misses-b.copy_misses));
    /* Back to the refresh key for CPU4: CPU4's class9 copies recompute. */
    b=memo.stats;unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.copy_misses-b.copy_misses==2 && memo.stats.copy_hits-b.copy_hits==28);
    /* Any other noted store to a private copy (not made by a view sync of
     * that CPU) makes exactly that destination stale; the next transaction
     * recomputes and repairs it, like the reference. */
    put(views.tables[3].copy[4],7,DATA|3);b=memo.stats;changed=cmp.changed;
    unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.copy_misses-b.copy_misses==1 && cmp.changed==changed+1);
    put(views.tables[0].copy[5],9,0x1000|3);b=memo.stats;changed=sync_cmp.changed;
    unsampled();CHECK(sync1(&s,5,&st[5],modes[5]));
    CHECK(memo.stats.copy_misses-b.copy_misses==1 && sync_cmp.changed==changed+1);
    /* A new class9 table grows the view: every destination is recomputed. */
    put(l3[1],3,leaf(DATA+0x102000,9));b=memo.stats;unsigned count=(unsigned)views.count;
    unsampled();CHECK(refresh(&s,st,modes));
    CHECK(views.count==count+1 && memo.stats.copy_misses-b.copy_misses==6*views.count);
    /* A leaf reserved by prepare_user_leaf grows the view outside a refresh;
     * a one-CPU sync then keeps only its own claim. */
    put(l2,40,canonical_table()|3);
    noting=1;CHECK(sprr_views_prepare_user_leaf(&views,&s,(1UL<<39)|(2UL<<30)|(40UL<<21)));noting=0;
    b=memo.stats;unsampled();CHECK(sync1(&s,1,&st[1],modes[1]));
    CHECK(memo.stats.copy_misses-b.copy_misses==views.count && vmemo.valid==2);
    b=memo.stats;unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.copy_hits-b.copy_hits==views.count); /* CPU1 only */
    /* Privatizing an already linked table changes its unchanged parent's
     * translation (canonical child -> private child) for every CPU. */
    noting=1;CHECK(sprr_views_prepare_user_leaf(&views,&s,(1UL<<39)|(2UL<<30)|(13UL<<21)|(7UL<<12)));
    noting=0;b=memo.stats;changed=sync_cmp.changed;
    unsampled();CHECK(sync1(&s,4,&st[4],modes[4]));CHECK(vmemo.valid==16 && sync_cmp.changed>changed);
    b=memo.stats;changed=cmp.changed;unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.copy_hits-b.copy_hits==views.count && cmp.changed>changed);
    /* Page reuse: an unlinked leaf table is reissued and refilled. */
    put(l2,11,0);b=memo.stats;unsampled();CHECK(refresh(&s,st,modes));
    noting=1;sprr_table_memo_alloc(&memo,l3[1]);noting=0;memset(ram+(l3[1]-BASE),0,4096);
    put(l3[1],5,leaf(DATA+0x103000,15));put(l2,14,l3[1]|3);
    unsampled();CHECK(refresh(&s,st,modes));
    /* Failures are identical and drop every claim. */
    st[5].umprr=0;st[5].uperm&=~SPRR_UPERM_TPRO_WRITE;CHECK(!refresh(&s,st,modes));
    CHECK(!vmemo.valid);sprr_root_reset(&st[5],0xa);CHECK(refresh(&s,st,modes));
    put(l3[2],7,leaf(DATA,1));CHECK(!refresh(&s,st,modes));CHECK(!sync1(&s,0,&st[0],0));
    put(l3[2],7,0);CHECK(refresh(&s,st,modes));
    int private1=-1;
    for(unsigned n=0;n<views.count;n++)if(views.tables[n].source==l3[1])private1=(int)n;
    CHECK(private1>0);fail_write=views.tables[private1].copy[3]+8*6;
    put(l3[1],6,leaf(DATA+0x104000,9));
    CHECK(!refresh(&s,st,modes));fail_write=0;CHECK(refresh(&s,st,modes));
    /* Unusable witness: no claim is used, results unchanged. */
    uint64_t clock=memo.clock;memo.clock=SPRR_TABLE_MEMO_CLOCK_MAX;b=memo.stats;
    CHECK(refresh(&s,st,modes));CHECK(sync1(&s,2,&st[2],modes[2]));
    CHECK(memo.stats.scan_hits==b.scan_hits && memo.stats.copy_hits==b.copy_hits && !vmemo.valid);
    memo.clock=clock;memo.stats.errors=1;b=memo.stats;CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.scan_hits==b.scan_hits && memo.stats.copy_hits==b.copy_hits);
    memo.stats.errors=0;CHECK(refresh(&s,st,modes));
    b=memo.stats;unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.copy_hits-b.copy_hits==6*views.count);
    /* Tables never issued by the allocator are never summarized. */
    uint64_t carved=BASE+0x1000;memset(ram+(carved-BASE),0,4096);
    put(carved,0,leaf(DATA,7));put(l2,50,carved|3);
    CHECK(refresh(&s,st,modes));b=memo.stats;unsampled();CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.scan_misses-b.scan_misses==1); /* the carved page, every time */
    /* A view reset zeroes its claims; the next refresh rebuilds them. */
    memset(&views,0,sizeof views);memset(&vmemo,0,sizeof vmemo);
    noting=1;CHECK(sprr_views_init(&views,&s));noting=0;
    CHECK(refresh(&s,st,modes));CHECK(refresh(&s,st,modes));
    /* Sampled transactions recompute everything and check every claim. */
    b=memo.stats;memo.stats.calls=SPRR_TABLE_MEMO_SAMPLE-1;
    CHECK(refresh(&s,st,modes));
    CHECK(memo.stats.samples==b.samples+1 && memo.stats.checked>b.checked && !memo.stats.mismatches);
    CHECK(memo.stats.scan_hits==b.scan_hits && memo.stats.copy_hits==b.copy_hits);
    b=memo.stats;memo.stats.calls=2*SPRR_TABLE_MEMO_SAMPLE-1;
    CHECK(sync1(&s,0,&st[0],modes[0]));
    CHECK(memo.stats.samples==b.samples+1 && memo.stats.checked>b.checked && !memo.stats.mismatches);
    /* A forced sample (mode-skip verification) behaves the same, is counted
     * separately and is consumed by exactly one transaction. */
    b=memo.stats;memo.force=1;unsampled();CHECK(sync1(&s,3,&st[3],modes[3]));
    CHECK(memo.stats.forced==b.forced+1 && memo.stats.samples==b.samples && !memo.force);
    CHECK(memo.stats.checked>b.checked && memo.stats.copy_hits==b.copy_hits);
    b=memo.stats;unsampled();CHECK(sync1(&s,3,&st[3],modes[3]));
    CHECK(memo.stats.copy_hits-b.copy_hits==views.count);
}

/* One canonical leaf table shared by two roots (nested/shared regions) and
 * privatized in both views: one source page, two independent claim sets. */
static void shared_source_case(void)
{
    struct sprr_state st[6];int modes[6];states_init(st,modes);
    world_reset();
    uint64_t shared=canonical_table(),roots[2];
    for(unsigned j=0;j<8;j++)put(shared,j*9,leaf(DATA+4096UL*j,j%3 ? 7 : 9));
    static struct sprr_views vs[2];struct sprr_view_memo vms[2];
    for(unsigned r=0;r<2;r++) {
        uint64_t rt=canonical_table(),one=canonical_table(),two=canonical_table(),own=canonical_table();
        put(rt,r,one|3);put(one,3,two|3);put(two,5,shared|3);put(two,6,own|3);
        put(own,1,leaf(DATA+0x40000,7));roots[r]=rt;
        memset(&views,0,sizeof views);memset(&vmemo,0,sizeof vmemo);
        struct shadow s=shadow_for(rt);noting=1;CHECK(sprr_views_init(&views,&s));noting=0;
        unsampled();CHECK(refresh(&s,st,modes));CHECK(views.count==4);
        vs[r]=views;vms[r]=vmemo;
    }
    for(unsigned round=0;round<6;round++) {
        if(round==2)put(shared,100,leaf(DATA+0x50000,11));
        if(round==4)put(shared,0,0); /* drop one class9 leaf; the path stays private */
        for(unsigned r=0;r<2;r++) {
            views=vs[r];vmemo=vms[r];struct shadow s=shadow_for(roots[r]);
            struct sprr_table_memo_stats b=memo.stats;unsampled();
            CHECK(refresh(&s,st,modes));
            if(round==2 || round==4)CHECK(memo.stats.copy_misses-b.copy_misses==6);
            else CHECK(memo.stats.copy_misses==b.copy_misses && memo.stats.copy_hits-b.copy_hits==24);
            unsampled();CHECK(sync1(&s,r,&st[r],modes[r]));
            vs[r]=views;vms[r]=vmemo;
        }
    }
}

/* A writer that bypasses the witness is caught by the next sample, which
 * fails without repairing anything. */
static void unnoted_cases(void)
{
    struct sprr_state st[6];int modes[6];states_init(st,modes);
    for(unsigned kind=0;kind<5;kind++) {
        struct shadow s=fixed_tree();
        CHECK(refresh(&s,st,modes));CHECK(refresh(&s,st,modes));
        if(kind==0)raw_put(l3[1]+8*9,leaf(DATA+0x200000,9));      /* shared source */
        if(kind==1)raw_put(views.tables[3].copy[4]+8*7,1);          /* private copy */
        if(kind==2)raw_put(views.tables[4].source+8*1,leaf(DATA,7));/* private source */
        if(kind==3)raw_put(views.tables[4].copy[2]+8*3,5);
        /* A walk-only source: a native leaf in an empty group changes only the
         * zero-group summary (an unnoted class9 leaf would already fail the
         * coverage walk itself, before any claim is compared). */
        if(kind==4)raw_put(l3[3]+8*505,leaf(DATA+0x300000,7));
        memo.stats.calls=5*SPRR_TABLE_MEMO_SAMPLE-1;
        memcpy(before,ram,sizeof ram);unsigned w=writes;
        noting=1;
        int ok=kind>=3 ? sprr_views_sync_user_cached_memo(&views,&s,2,&st[2],modes[2],&epoch,&proof,
                &proof_stats,1,tread,tread,&sync_cmp,&memo,&vmemo) :
            sprr_views_prepare_sync_user_memo(&views,&s,st,modes,&plan,&stats,
                tread,&zero,tread,tread,&cmp,&memo,&vmemo);
        noting=0;
        CHECK(!ok && memo.stats.mismatches==1 && !vmemo.valid);
        CHECK(writes==w && !memcmp(ram,before,sizeof ram));
    }
}

/* -DMEMO_ROUNDS=n -DMEMO_SEED=x lengthen or vary the randomized walk. */
#ifndef MEMO_ROUNDS
#define MEMO_ROUNDS 36
#endif
#ifndef MEMO_SEED
#define MEMO_SEED 0x9e3779b97f4a7c15u
#endif
static uint64_t rng=MEMO_SEED;
static unsigned rnd(unsigned n){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}
static const unsigned native[]={3,7,10,11,13,15};
static uint64_t pool3[64],pool3_va[64];static unsigned pool3_count;
static uint64_t upper2[8],upper2_va[8];static unsigned upper2_count;
static int in_views(uint64_t pa)
{
    for(unsigned n=0;n<views.count;n++)if(views.tables[n].source==pa)return 1;
    return 0;
}
static void random_leaves(uint64_t table,int tpro)
{
    for(unsigned k=0,m=1+rnd(40);k<m;k++)
        put(table,rnd(512),leaf(DATA+4096UL*rnd(1u<<20),tpro && !rnd(6) ? 9 : native[rnd(6)]));
}
static struct shadow random_tree(void)
{
    world_reset();pool3_count=upper2_count=0;
    root=canonical_table();
    for(unsigned a=0,na=1+rnd(2);a<na;a++) {
        uint64_t one=canonical_table(),ia=a*128+rnd(128);put(root,(unsigned)ia,one|3);
        for(unsigned b=0,nb=1+rnd(3);b<nb;b++) {
            uint64_t two=canonical_table(),ib=b*128+rnd(128);put(one,(unsigned)ib,two|3);
            upper2_va[upper2_count]=(ia<<39)|(ib<<30);upper2[upper2_count++]=two;
            for(unsigned c=0,nc=1+rnd(4);c<nc;c++) {
                uint64_t three=canonical_table(),ic=c*128+rnd(128);put(two,(unsigned)ic,three|3);
                pool3_va[pool3_count]=upper2_va[upper2_count-1]|(ic<<21);
                pool3[pool3_count++]=three;random_leaves(three,!rnd(3));
            }
        }
    }
    struct shadow s=shadow_for(root);
    noting=1;CHECK(sprr_views_init(&views,&s));noting=0;
    return s;
}
static struct sprr_table_memo_stats total;
static void random_cases(unsigned rounds,unsigned steps)
{
    unsigned ok_refresh=0,ok_sync=0,failed=0,exhausted=0;
    for(unsigned round=0;round<rounds;round++) {
        struct sprr_state st[6];int modes[6];states_init(st,modes);
        struct shadow s=random_tree();
        for(unsigned step=0;step<steps;step++) {
            unsigned op=rnd(100);
            if(op<22) {             /* edit a leaf: native, empty or (rarely) TPRO */
                uint64_t t=pool3[rnd(pool3_count)];unsigned kind=rnd(10);
                put(t,rnd(512),!kind ? 0 : kind==1 && views.count<40 ?
                    leaf(DATA+4096UL*rnd(1u<<20),9) : leaf(DATA+4096UL*rnd(1u<<20),native[rnd(6)]));
            } else if(op<26 && pool3_count<64 && next<BASE+BYTES-64*4096) { /* new leaf table */
                uint64_t t=canonical_table();random_leaves(t,views.count<40 && !rnd(3));
                unsigned u=rnd(upper2_count),slot=rnd(512);put(upper2[u],slot,t|3);
                pool3_va[pool3_count]=upper2_va[u]|((uint64_t)slot<<21);pool3[pool3_count++]=t;
            } else if(op<30) {      /* unlink or relink a leaf table */
                uint64_t two=upper2[rnd(upper2_count)];unsigned slot=rnd(512);
                put(two,slot,rnd(2) ? 0 : pool3[rnd(pool3_count)]|3);
            } else if(op<33) {      /* reissue an unreachable, unprivatized page */
                uint64_t t=pool3[rnd(pool3_count)];int linked=0;
                for(unsigned u=0;u<upper2_count;u++)for(unsigned i=0;i<512;i++)
                    if((get(upper2[u],i)&PT_OA_MASK)==t)linked=1;
                if(!linked && !in_views(t)) {
                    noting=1;sprr_table_memo_alloc(&memo,t);noting=0;
                    memset(ram+(t-BASE),0,4096);random_leaves(t,0);
                }
            } else if(op<36) {      /* invalid descriptor, then repair */
                uint64_t t=pool3[rnd(pool3_count)];unsigned slot=rnd(512);uint64_t old=get(t,slot);
                put(t,slot,rnd(2) ? leaf(DATA,1) : (DATA|1));
                if(!refresh(&s,st,modes))failed++;
                put(t,slot,old);
            } else if(op<46) {      /* per-CPU key or mode */
                unsigned cpu=rnd(6),what=rnd(4);
                if(what==0)st[cpu].uperm^=SPRR_UPERM_TPRO_WRITE;
                if(what==1)st[cpu].pperm^=SPRR_UPERM_TPRO_WRITE;
                if(what==2)modes[cpu]^=1;
                if(what==3)st[cpu].pperm^=0x100;
            } else if(op<48) {      /* UMPRR refusal on one CPU, then restore */
                unsigned cpu=rnd(6);struct sprr_state keep=st[cpu];
                st[cpu].umprr=0;st[cpu].uperm&=~SPRR_UPERM_TPRO_WRITE;
                if(!refresh(&s,st,modes))failed++;
                st[cpu]=keep;
            } else if(op<52 && views.count<60 && next<BASE+BYTES-64*4096) {
                /* reserve a private path outside a refresh (user_prepare_leaf);
                 * stale VAs of relinked tables are refused without changes */
                uint64_t va=pool3_va[rnd(pool3_count)]|((uint64_t)rnd(512)<<12);
                noting=1;(void)sprr_views_prepare_user_leaf(&views,&s,va);noting=0;
            } else if(op<54 && next<BASE+BYTES-256*4096) { /* view reset */
                memset(&views,0,sizeof views);memset(&vmemo,0,sizeof vmemo);
                noting=1;CHECK(sprr_views_init(&views,&s));noting=0;
            } else if(op<77) {
                if(refresh(&s,st,modes))ok_refresh++;else failed++;
            } else {
                unsigned cpu=rnd(6);struct sprr_state one=st[cpu];
                if(rnd(3)==0)one.uperm^=SPRR_UPERM_TPRO_WRITE;
                if(rnd(3)==0)one.pperm^=SPRR_UPERM_TPRO_WRITE;
                if(sync1(&s,cpu,&one,rnd(3) ? modes[cpu] : !modes[cpu]))ok_sync++;else failed++;
            }
        }
        exhausted+=next>BASE+BYTES-8*4096;
        total.walk_hits+=memo.stats.walk_hits;total.walk_misses+=memo.stats.walk_misses;
        total.scan_hits+=memo.stats.scan_hits;total.scan_misses+=memo.stats.scan_misses;
        total.copy_hits+=memo.stats.copy_hits;total.copy_misses+=memo.stats.copy_misses;
        total.samples+=memo.stats.samples;total.checked+=memo.stats.checked;
        total.mismatches+=memo.stats.mismatches;
    }
    printf("Random memo walk: %u refreshes, %u one-CPU syncs, %u identical failures, "
           "%u/%u rounds reached allocation exhaustion\n",ok_refresh,ok_sync,failed,exhausted,rounds);
    CHECK(ok_refresh>100 && ok_sync>100 && failed>10);
}

int main(void)
{
    CHECK(sizeof(struct sprr_table_memo)==32+112+8*SPRR_TABLE_MEMO_PAGES);
    CHECK(sizeof(struct sprr_view_memo)==24+96+8*(SPRR_VIEW_TABLES/64));
    deterministic_cases();
    shared_source_case();
    unnoted_cases();
    random_cases(MEMO_ROUNDS,160);
    printf("Random memo claims: scans %llu hit / %llu run, proof walks %llu hit / %llu run, "
           "destinations %llu hit / %llu run, %llu samples checked %llu claims, %llu mismatches\n",
           (unsigned long long)total.scan_hits,(unsigned long long)total.scan_misses,
           (unsigned long long)total.walk_hits,(unsigned long long)total.walk_misses,
           (unsigned long long)total.copy_hits,(unsigned long long)total.copy_misses,
           (unsigned long long)total.samples,(unsigned long long)total.checked,
           (unsigned long long)total.mismatches);
    CHECK(total.scan_hits && total.walk_hits && total.copy_hits && total.samples &&
          total.checked && !total.mismatches);
    CHECK(memo_words<reference_words);
    printf("Memo destination words compared: %llu versus %llu reference\n",
           (unsigned long long)memo_words,(unsigned long long)reference_words);
    printf("User tree memo: %u checks, %u failures\n",checks,failures);
    return !!failures;
}
