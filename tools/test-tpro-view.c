/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "sprr-view.h"

#define BASE UINT64_C(0x40000000)
#define DATA UINT64_C(0x94050c000)
/* Room for a full pool of six-copy tables (SNAP_VIEW_RECLAIM: 256). */
#define BYTES (SPRR_VIEW_TABLES>128 ? (8u<<20) : (4u<<20))
#define ATTR (PT_AF|(3UL<<8)|(1UL<<11))
static _Alignas(4096) unsigned char ram[BYTES],before[BYTES],expected[BYTES];
static uint64_t next,fail_read;
static uint64_t reads,batch_reads,serial_reads,epoch;
static unsigned writes,budget,checks,failures;
static struct sprr_views views;
#define CHECK(x) do {checks++;if(!(x)){failures++;printf("FAIL %u: %s\n",__LINE__,#x);}} while(0)
static int rd(void *ctx,uint64_t pa,uint64_t *out)
{
    reads++;
    (void)ctx;if(pa<BASE || pa>BASE+BYTES-8 || pa==fail_read)return -1;
    memcpy(out,ram+(pa-BASE),8);return 0;
}
static int wr(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;if(pa<BASE || pa>BASE+BYTES-8)return -1;
    uint64_t old;memcpy(&old,ram+(pa-BASE),8);
    if(old!=value)sprr_view_epoch_advance(&epoch);
    memcpy(ram+(pa-BASE),&value,8);writes++;return 0;
}
static uint64_t alloc(void *ctx)
{
    (void)ctx;if(!budget || next>BASE+BYTES-4096)return 0;
    sprr_view_epoch_advance(&epoch);
    budget--;uint64_t p=next;next+=4096;return p;
}
static void put(uint64_t table,unsigned slot,uint64_t d)
{CHECK(!wr(0,table+8UL*slot,d));}
static uint64_t leaf(uint64_t pa,unsigned selector)
{return pa|3|ATTR|((uint64_t)(selector&12)<<4)|((uint64_t)(selector&3)<<53);}
static struct shadow setup(void)
{
    memset(ram,0,sizeof ram);memset(&views,0,sizeof views);
    next=BASE+0x10000;budget=BYTES/4096;fail_read=0;
    put(BASE,0,BASE+0x1000+3);put(BASE+0x1000,0,BASE+0x2000+3);
    for(unsigned i=0;i<3;i++)put(BASE+0x2000,i,BASE+0x3000+4096UL*i+3);
    for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,leaf(DATA+4096UL*i,9));
    put(BASE+0x4000,0,leaf(DATA,7)); /* same PA, ordinary writable alias */
    put(BASE+0x5000,0,leaf(DATA+0x8000,13)); /* executable ordinary page */
    writes=0;
    return (struct shadow){.txsz=17,.root=BASE,.alloc=alloc,.read=rd,.write=wr};
}
static struct mmu_leaf walk(unsigned cpu,uint64_t va)
{
    struct mmu_config config={12,17,sprr_views_root(&views,cpu)};
    struct mmu_leaf l={0};CHECK(!mmu_walk(&config,va,rd,0,&l));return l;
}
static void rights(unsigned cpu,uint64_t va,uint64_t pa,int write,int execute)
{
    struct mmu_leaf l=walk(cpu,va);CHECK(l.valid && l.pa==pa);
    CHECK(!!(l.descriptor&(1UL<<6))); /* preserves PAN-visible user access */
    CHECK(!!(l.descriptor&(2UL<<6))==!write);
    CHECK(!!(l.descriptor&PT_UXN)==!execute);
    CHECK(l.descriptor&PT_PXN);
    CHECK((l.descriptor&ATTR)==ATTR);
}
static void refused(struct shadow *s,const struct sprr_state *state,int el0)
{
    memcpy(before,ram,sizeof ram);unsigned n=writes;
    CHECK(!sprr_views_sync_user_cpu(&views,s,0,state,el0));
    CHECK(writes==n && !memcmp(before,ram,sizeof ram));
    struct sprr_state states[6];int modes[6];
    for(unsigned cpu=0;cpu<6;cpu++){states[cpu]=*state;modes[cpu]=el0;}
    CHECK(!sprr_views_sync_user_all(&views,s,states,modes));
    CHECK(writes==n && !memcmp(before,ram,sizeof ram));
}
static void differential_batch(struct shadow *s,const struct sprr_state states[6],
                                const int modes[6])
{
    struct sprr_views saved=views;
    memcpy(before,ram,sizeof ram);uint64_t start=reads;unsigned start_writes=writes;
    for(unsigned cpu=0;cpu<6;cpu++)
        CHECK(sprr_views_sync_user_cpu(&views,s,cpu,&states[cpu],modes[cpu]));
    uint64_t serial=reads-start;unsigned serial_writes=writes-start_writes;
    struct sprr_views serial_views=views;memcpy(expected,ram,sizeof ram);
    views=saved;memcpy(ram,before,sizeof ram);start=reads;start_writes=writes;
    CHECK(sprr_views_sync_user_all(&views,s,states,modes));
    uint64_t batch=reads-start;
    CHECK(!memcmp(ram,expected,sizeof ram));
    CHECK(!memcmp(&views,&serial_views,sizeof views));
    CHECK(writes-start_writes==serial_writes);
    CHECK(batch<serial);batch_reads+=batch;serial_reads+=serial;
}
static void proof_cases(void)
{
    struct shadow s=setup();struct sprr_state state[6]={0};
    struct sprr_view_proof proof={0};struct sprr_view_proof_stats stats={0};
    for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&state[cpu],0xa);
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare_user(&views,&s));
    uint64_t full_reads=0,cached_reads=0;
    for(unsigned step=0;step<256;step++) {
        unsigned cpu=step%6;int mode=(int)(step&1);
        state[cpu].uperm=SPRR_UPERM_INITIAL|((uint64_t)((step>>1)&1)<<36);
        state[cpu].pperm=SPRR_PPERM_INITIAL|((uint64_t)((step>>2)&1)<<36);
        if(!(step%17))put(BASE+0x5000,0,leaf(DATA+((uint64_t)(step&1)<<14),13));
        struct sprr_views saved=views;
        memcpy(before,ram,sizeof ram);uint64_t prior_epoch=epoch,start=reads;
        CHECK(sprr_views_sync_user_cpu(&views,&s,cpu,&state[cpu],mode));
        full_reads+=reads-start;memcpy(expected,ram,sizeof ram);
        struct sprr_views result=views;
        views=saved;epoch=prior_epoch;memcpy(ram,before,sizeof ram);start=reads;
        CHECK(sprr_views_sync_user_cached(&views,&s,cpu,&state[cpu],mode,&epoch,&proof,&stats,1));
        cached_reads+=reads-start;
        CHECK(!memcmp(ram,expected,sizeof ram));CHECK(!memcmp(&views,&result,sizeof views));
        CHECK(proof.valid==1 && proof.epoch==epoch && proof.root==s.root && proof.count==views.count);
    }
    CHECK(stats.calls==256 && stats.hits>200 && stats.verified>=4 && !stats.mismatches);
    CHECK(cached_reads<full_reads);
    printf("Versioned proof descriptor reads: %llu versus %llu full\n",
           (unsigned long long)cached_reads,(unsigned long long)full_reads);
    /* Epoch/key drift takes the full path, including uncopied source branches. */
    uint64_t old;CHECK(!rd(0,BASE+0x5000,&old));
    put(BASE+0x5000,0,leaf(DATA,2));unsigned before_writes=writes;uint64_t hits=stats.hits;
    CHECK(!sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,0));
    CHECK(writes==before_writes && stats.hits==hits && !proof.valid);
    put(BASE+0x5000,0,old);
    CHECK(sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,1));
    hits=stats.hits;proof.root^=4096;
    CHECK(sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,1));
    CHECK(stats.hits==hits);proof.count++;
    CHECK(sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,1));
    CHECK(stats.hits==hits);
    /* Diagnostic sampling catches an intentionally untracked bad mutation. */
    uint64_t bad=leaf(DATA,2);memcpy(ram+0x5000,&bad,8);
    stats.hits=(stats.hits+63)&~UINT64_C(63);before_writes=writes;
    CHECK(!sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,1));
    CHECK(stats.mismatches==1 && !proof.valid && writes==before_writes);
    put(BASE+0x5000,0,old);
    CHECK(sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,1));
    /* New private-path allocation changes the epoch before reuse. */
    CHECK(sprr_views_prepare_user_leaf(&views,&s,0x401000));hits=stats.hits;
    CHECK(sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,1));
    CHECK(stats.hits==hits);
    /* Saturation never wraps back into a retained proof. */
    epoch=UINT64_MAX-1;sprr_view_epoch_advance(&epoch);sprr_view_epoch_advance(&epoch);
    CHECK(epoch==UINT64_MAX);hits=stats.hits;
    for(unsigned i=0;i<3;i++) {
        CHECK(sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,&stats,1));
        CHECK(stats.hits==hits && !proof.valid);
    }
    CHECK(!sprr_views_sync_user_cached(&views,&s,6,&state[0],0,&epoch,&proof,&stats,1));
    CHECK(!sprr_views_sync_user_cached(&views,&s,0,&state[0],0,0,&proof,&stats,1));
    CHECK(!sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,0,&stats,1));
    CHECK(!sprr_views_sync_user_cached(&views,&s,0,&state[0],0,&epoch,&proof,0,1));
}
int main(void)
{
    struct shadow s=setup();struct sprr_state state[6]={0};
    for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&state[cpu],0xa);
    CHECK(sprr_views_init(&views,&s));
    refused(&s,&state[0],0); /* raw selector9 path has no private copies */
    CHECK(sprr_views_prepare_user(&views,&s));CHECK(views.count==4);
    for(unsigned cpu=0;cpu<6;cpu++) {
        CHECK(sprr_views_sync_user_cpu(&views,&s,cpu,&state[cpu],0));
        for(unsigned i=0;i<4;i++)rights(cpu,4096UL*i,DATA+4096UL*i,0,0);
        rights(cpu,0x200000,DATA,1,0);rights(cpu,0x400000,DATA+0x8000,0,1);
    }
    /* Same entire memory image and sync counters as six independent calls,
     * including distinct CPU permissions and mixed user/kernel regimes. */
    int modes[6];
    for(unsigned pattern=0;pattern<64;pattern++) {
        for(unsigned cpu=0;cpu<6;cpu++) {
            sprr_root_reset(&state[cpu],0xa);
            state[cpu].uperm|=(uint64_t)((pattern>>cpu)&1)<<36;
            state[cpu].pperm|=(uint64_t)((pattern>>(5-cpu))&1)<<36;
            state[cpu].pperm|=(uint64_t)(cpu&1)<<8;
            modes[cpu]=(int)((pattern+cpu)&1);
        }
        differential_batch(&s,state,modes);
    }
    /* A late CPU's invalid state/copy must fail before any CPU is written. */
    memcpy(before,ram,sizeof ram);unsigned batch_before=writes;
    state[5].uperm^=1;
    CHECK(!sprr_views_sync_user_all(&views,&s,state,modes));state[5].uperm^=1;
    CHECK(writes==batch_before && !memcmp(before,ram,sizeof ram));
    uint64_t copy=views.tables[views.count-1].copy[5];
    views.tables[views.count-1].copy[5]=0;
    CHECK(!sprr_views_sync_user_all(&views,&s,state,modes));
    CHECK(writes==batch_before && !memcmp(before,ram,sizeof ram));
    views.tables[views.count-1].copy[5]=copy;
    CHECK(!sprr_views_sync_user_all(&views,&s,0,modes));
    CHECK(!sprr_views_sync_user_all(&views,&s,state,0));
    /* Every UPERM/PPERM pair, independently on all six CPUs, in both ELs.
     * The unrelated selector2 grant must not change user permissions. */
    for(unsigned bits=0;bits<8;bits++)for(unsigned el0=0;el0<2;el0++) {
        for(unsigned cpu=0;cpu<6;cpu++) {
            sprr_root_reset(&state[cpu],0xa);
            state[cpu].uperm|=(uint64_t)(bits&1)<<36;
            state[cpu].pperm|=(uint64_t)((bits>>1)&1)<<36;
            state[cpu].pperm|=(uint64_t)((bits>>2)&1)<<8;
            CHECK(sprr_views_sync_user_cpu(&views,&s,cpu,&state[cpu],(int)el0));
            for(unsigned i=0;i<4;i++)rights(cpu,4096UL*i,DATA+4096UL*i,
                                           el0 ? bits&1 : (bits>>1)&1,0);
            rights(cpu,0x200000,DATA,1,0);
        }
    }
    for(unsigned cpu=0;cpu<6;cpu++) {
        sprr_root_reset(&state[cpu],0xa);
        CHECK(sprr_views_sync_user_cpu(&views,&s,cpu,&state[cpu],0));
    }
    state[0].uperm|=1UL<<36;
    state[1].pperm|=1UL<<36;
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],1));
    CHECK(sprr_views_sync_user_cpu(&views,&s,1,&state[1],0));
    for(unsigned cpu=0;cpu<6;cpu++)rights(cpu,0,DATA,cpu<2,0);
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],0));
    CHECK(sprr_views_sync_user_cpu(&views,&s,1,&state[1],1));
    for(unsigned cpu=0;cpu<6;cpu++)rights(cpu,0,DATA,0,0);
    /* Preparation must also cover a new shared source branch and aliases. */
    put(BASE+0x4000,1,leaf(DATA,9));
    refused(&s,&state[0],1);
    CHECK(sprr_views_prepare_user(&views,&s));CHECK(views.count==5);
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],1));
    rights(0,0x201000,DATA,1,0);rights(0,0x200000,DATA,1,0);
    put(BASE+0x2000,3,BASE+0x4000+3); /* repeated source table at another VA */
    CHECK(sprr_views_prepare_user(&views,&s));CHECK(views.count==5);
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],0));
    rights(0,0x601000,DATA,0,0);rights(0,0x600000,DATA,1,0);
    /* Unmap and replacement refresh all aliases without touching the source. */
    put(BASE+0x4000,1,0);
    CHECK(sprr_views_prepare_user(&views,&s));
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],1));
    CHECK(!walk(0,0x201000).valid && !walk(0,0x601000).valid);
    put(BASE+0x4000,1,leaf(DATA+0xc000,9));
    memcpy(before,ram,0x10000);
    CHECK(sprr_views_prepare_user(&views,&s));
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],0));
    CHECK(!memcmp(before,ram,0x10000));
    rights(0,0x201000,DATA+0xc000,0,0);rights(0,0x601000,DATA+0xc000,0,0);
    differential_batch(&s,state,modes); /* repeated table alias and replacement */
    /* Invalid control state cannot publish even a partial private view. */
    for(unsigned field=0;field<4;field++)for(unsigned bit=0;bit<64;bit++) {
        struct sprr_state bad=state[0];uint64_t *p=field==0 ? &bad.uperm :
            field==1 ? &bad.pperm : field==2 ? &bad.umprr : &bad.pmprr;
        *p^=1UL<<bit;
        if(sprr_fixed_state_valid(&bad) && (bad.umprr&0xc0000)==0x40000)continue;
        refused(&s,&bad,1);
    }
    refused(&s,&state[0],2);refused(&s,&state[0],-1);
    struct sprr_state bad=state[0];bad.resets=0;refused(&s,&bad,0);
    for(unsigned kind=0;kind<7;kind++) {
        uint64_t where=BASE+0x2000+32,old=0;
        uint64_t d=kind==0 ? leaf(DATA,2) : kind==1 ? DATA+1+ATTR :
            kind==2 ? BASE+0x1000+3 : kind==3 ? sprr_views_root(&views,0)+3 :
            kind==4 ? 2 : kind==5 ? BASE+0x4000+7 : BASE+0x1000+3;
        if(kind==0)where=BASE+0x5000;
        if(kind==6)where=BASE+8*256;
        CHECK(!rd(0,where,&old));CHECK(!wr(0,where,d));
        refused(&s,&state[0],0);
        unsigned n=writes;uint64_t count=views.count;
        CHECK(!sprr_views_prepare_user(&views,&s));
        CHECK(writes==n && views.count==count);
        CHECK(!wr(0,where,old));
    }
    fail_read=BASE+0x5000+4096-8;refused(&s,&state[0],0);fail_read=0;
    /* Partial allocation never publishes copies, and can be retried. */
    s=setup();CHECK(sprr_views_init(&views,&s));budget=7;
    unsigned n=writes;CHECK(!sprr_views_prepare_user(&views,&s));CHECK(writes==n);
    refused(&s,&state[0],0);budget=BYTES/4096;
    CHECK(sprr_views_prepare_user(&views,&s));
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],1));rights(0,0,DATA,1,0);
    /* The old kernel API must continue refusing raw selector9. */
    memcpy(before,ram,sizeof ram);n=writes;
    CHECK(!sprr_views_sync_cpu(&views,&s,0,SPRR_PPERM_INITIAL));
    CHECK(writes==n && !memcmp(before,ram,sizeof ram));
    /* A running CPU must never see a freshly published raw selector9 through
     * a shared canonical table. Detach the still-empty path on every CPU. */
    s=setup();
    for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,0);
    CHECK(sprr_views_init(&views,&s));
    for(unsigned cpu=0;cpu<6;cpu++)
        CHECK(sprr_views_sync_user_cpu(&views,&s,cpu,&state[cpu],1));
    CHECK(views.count==1);
    CHECK(sprr_views_prepare_user_leaf(&views,&s,0x201000));
    for(unsigned cpu=0;cpu<6;cpu++)
        CHECK(sprr_views_sync_user_cpu(&views,&s,cpu,&state[cpu],1));
    put(BASE+0x4000,1,leaf(DATA,9)); /* raw canonical publication */
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(!walk(cpu,0x201000).valid);
    CHECK(sprr_views_sync_user_cpu(&views,&s,0,&state[0],1));
    rights(0,0x201000,DATA,1,0);
    for(unsigned cpu=1;cpu<6;cpu++)CHECK(!walk(cpu,0x201000).valid);
    CHECK(!sprr_views_prepare_user_leaf(&views,&s,1UL<<47));
    CHECK(!sprr_views_prepare_user_leaf(&views,&s,0x201001));
    proof_cases();
    printf("TPRO private views: %u checks, %u failures\n",checks,failures);
    printf("Batch differential descriptor reads: %llu versus %llu serial\n",
           (unsigned long long)batch_reads,(unsigned long long)serial_reads);
    return !!failures;
}
