/* SPDX-License-Identifier: MIT */
#define main inherited_prepare_tests
#include "test-tpro-view.c"
#undef main

static struct sprr_user_prepare_plan plan;
static struct sprr_user_prepare_stats stats;
#if TEST_USER_ZERO_GROUP
static struct sprr_user_zero_stats zero_stats;
#endif
static uint64_t alias_once,fail_write;
static int drop_plan;
static uint64_t planned_reads,reference_reads;
#if TEST_USER_TABLE_READ
static unsigned table_maps,blank_table,bad_alignment;
static const uint64_t blank[512];
static const volatile uint64_t *table_reader(void *ctx,uint64_t pa)
{
    (void)ctx;table_maps++;
    if((pa&4095) || pa<BASE || pa>BASE+BYTES-4096 ||
       (fail_read>=pa && fail_read-pa<4096))return 0;
    if(blank_table && pa==BASE+0x3000)return blank;
    if(bad_alignment)return (const volatile uint64_t *)(ram+(pa-BASE)+1);
    return (const volatile uint64_t *)(ram+(pa-BASE));
}
#endif
static int prepare(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state state[6],const int modes[6],
    struct sprr_user_prepare_plan *p,struct sprr_user_prepare_stats *st)
{
#if TEST_USER_ZERO_GROUP
    return sprr_views_prepare_sync_user_grouped(v,s,state,modes,p,st,table_reader,&zero_stats);
#elif TEST_USER_TABLE_READ
    return sprr_views_prepare_sync_user_mapped(v,s,state,modes,p,st,table_reader);
#else
    return sprr_views_prepare_sync_user_fused(v,s,state,modes,p,st);
#endif
}
static uint64_t special_alloc(void *ctx)
{
    if(drop_plan) {plan.required_count=0;drop_plan=0;}
    if(alias_once) {uint64_t p=alias_once;alias_once=0;return p;}
    return alloc(ctx);
}
static int ordered_write(void *ctx,uint64_t pa,uint64_t value)
{
    if(pa==fail_write)return -1;
    if((value&3)==3)for(unsigned n=0;n<views.count;n++)for(unsigned cpu=0;cpu<6;cpu++)
        if((value&PT_OA_MASK)==views.tables[n].copy[cpu])
            CHECK(!memcmp(ram+(views.tables[n].copy[cpu]-BASE),
                          expected+(views.tables[n].copy[cpu]-BASE),4096));
    return wr(ctx,pa,value);
}
static int compare(struct shadow *s,const struct sprr_state state[6],const int modes[6])
{
    struct sprr_views initial=views;memcpy(before,ram,sizeof ram);
    uint64_t saved_next=next,saved_epoch=epoch,saved_alias=alias_once;
    unsigned saved_budget=budget,saved_writes=writes;uint64_t start=reads;
    s->write=wr;
    int reference=sprr_views_prepare_user(&views,s) &&
        sprr_views_sync_user_all(&views,s,state,modes);
    reference_reads+=reads-start;
    unsigned wanted_writes=writes-saved_writes;
    struct sprr_views wanted=views;uint64_t wanted_next=next,wanted_epoch=epoch;
    memcpy(expected,ram,sizeof ram);
    views=initial;memcpy(ram,before,sizeof ram);next=saved_next;epoch=saved_epoch;
    budget=saved_budget;alias_once=saved_alias;saved_writes=writes;start=reads;
    s->write=ordered_write;
    int candidate=prepare(&views,s,state,modes,&plan,&stats);
    planned_reads+=reads-start;
    CHECK(candidate==reference);
    if(candidate) {
        CHECK(!memcmp(ram,expected,sizeof ram));CHECK(!memcmp(&views,&wanted,sizeof views));
        CHECK(next==wanted_next && epoch==wanted_epoch);
        CHECK(writes-saved_writes==wanted_writes);
    } else {
        CHECK(writes==saved_writes && !memcmp(ram,before,sizeof ram));
        CHECK(!memcmp(views.syncs,initial.syncs,sizeof initial.syncs));
    }
    s->write=wr;return candidate;
}
#if TEST_USER_ZERO_GROUP
static void zero_group_cases(const struct sprr_state state[6],const int modes[6])
{
    /* Every position, including the eighth word and final group, must still
     * reject a nonzero invalid descriptor before any private write. */
    for(unsigned level=0;level<4;level++)for(unsigned slot=0;slot<512;slot++) {
        struct shadow s=setup();CHECK(sprr_views_init(&views,&s));
        put(BASE+4096UL*level,slot,2);CHECK(!compare(&s,state,modes));
    }
    struct shadow s=setup();CHECK(sprr_views_init(&views,&s));
    memset(&zero_stats,0,sizeof zero_stats);
    CHECK(compare(&s,state,modes));
    CHECK(zero_stats.groups==64*6 && zero_stats.empty_groups==63*6);
    /* One full leaf tests every nonempty group, ordinary and TPRO entries. */
    for(unsigned i=0;i<512;i++)put(BASE+0x3000,i,leaf(DATA+4096UL*i,(i&1)?7:9));
    memset(&zero_stats,0,sizeof zero_stats);CHECK(compare(&s,state,modes));
    CHECK(zero_stats.groups==64*6 && zero_stats.empty_groups==63*5);
    s=setup();CHECK(sprr_views_init(&views,&s));put(BASE,0,0);
    memset(&zero_stats,0,sizeof zero_stats);CHECK(compare(&s,state,modes));
    CHECK(zero_stats.groups==64 && zero_stats.empty_groups==64);
    /* The grouped path may never dereference an absent mapped reader. */
    unsigned saved=writes;uint64_t failures_before=stats.failures;
    CHECK(!sprr_views_prepare_sync_user_grouped(&views,&s,state,modes,
        &plan,&stats,0,&zero_stats));
    CHECK(writes==saved && stats.failures==failures_before+1);
    CHECK(zero_stats.groups==64 && zero_stats.empty_groups==64);
}
#endif
#ifndef TEST_PREPARE_ENTRY
#define TEST_PREPARE_ENTRY main
#endif
int TEST_PREPARE_ENTRY(void)
{
    CHECK(!inherited_prepare_tests());
    struct sprr_state state[6]={0};int modes[6];
    for(unsigned cpu=0;cpu<6;cpu++){sprr_root_reset(&state[cpu],0xa);modes[cpu]=cpu&1;}
    struct shadow s=setup();CHECK(sprr_views_init(&views,&s));
    CHECK(sizeof(plan)==24+16*SPRR_VIEW_TABLES+8*8192 && sizeof(stats)==56);
    CHECK(compare(&s,state,modes));CHECK(plan.source_count==6 && plan.required_count==4);
    for(unsigned pattern=0;pattern<64;pattern++) {
        for(unsigned cpu=0;cpu<6;cpu++) {
            state[cpu].uperm=SPRR_UPERM_INITIAL|((uint64_t)((pattern>>cpu)&1)<<36);
            state[cpu].pperm=SPRR_PPERM_INITIAL|((uint64_t)((pattern>>(5-cpu))&1)<<36)|
                ((uint64_t)(cpu&1)<<8);modes[cpu]=(int)((pattern+cpu)&1);
        }
        for(unsigned selector=0;selector<16;selector++) {
            put(BASE+0x3000,0,leaf(DATA,selector));compare(&s,state,modes);
        }
    }
    put(BASE+0x3000,0,leaf(DATA,9));
    for(unsigned cpu=0;cpu<6;cpu++) {
        state[cpu].uperm^=1;CHECK(!compare(&s,state,modes));state[cpu].uperm^=1;
        state[cpu].pperm^=1;CHECK(!compare(&s,state,modes));state[cpu].pperm^=1;
        state[cpu].umprr^=0x40000;CHECK(!compare(&s,state,modes));state[cpu].umprr^=0x40000;
        int mode=modes[cpu];modes[cpu]=2;CHECK(!compare(&s,state,modes));modes[cpu]=mode;
        uint64_t copy=views.tables[views.count-1].copy[cpu];
        views.tables[views.count-1].copy[cpu]=copy|8;CHECK(!compare(&s,state,modes));
        views.tables[views.count-1].copy[cpu]=copy;
    }
    for(unsigned page=0;page<6;page++)for(unsigned edge=0;edge<2;edge++) {
        fail_read=BASE+4096UL*page+(edge ? 4088 : 0);CHECK(!compare(&s,state,modes));
    }
    fail_read=0;
    /* New required paths, newly ordinary paths and retained empty copies. */
    put(BASE+0x4000,1,leaf(DATA,9));CHECK(compare(&s,state,modes));
    put(BASE+0x5000,1,leaf(DATA+0x10000,9));CHECK(compare(&s,state,modes));
    put(BASE+0x5000,0,0);put(BASE+0x5000,1,0);CHECK(compare(&s,state,modes));
    put(BASE+0x2000,2,0);CHECK(compare(&s,state,modes));
    put(BASE+0x2000,2,BASE+0x5000+3);CHECK(compare(&s,state,modes));
    CHECK(sprr_views_prepare_user_leaf(&views,&s,0x401000));CHECK(compare(&s,state,modes));
    /* An alias path is valid; a cycle, upper root entry or block is not. */
    put(BASE+0x2000,3,BASE+0x3000+3);CHECK(compare(&s,state,modes));
    put(BASE+0x1000,1,BASE+3);CHECK(!compare(&s,state,modes));put(BASE+0x1000,1,0);
    put(BASE,256,BASE+0x1000+3);CHECK(!compare(&s,state,modes));put(BASE,256,0);
    put(BASE+0x2000,4,(DATA&~0x1fffffUL)|1|ATTR);CHECK(!compare(&s,state,modes));put(BASE+0x2000,4,0);

    /* Allocation failures reserve at most terminal partial metadata and never
     * write a live private descriptor; successful allocation order agrees. */
    for(unsigned allowance=0;allowance<=18;allowance++) {
        s=setup();CHECK(sprr_views_init(&views,&s));budget=allowance;
        CHECK(compare(&s,state,modes)==(allowance==18));
    }
    /* A faulty allocator can alias a source encountered earlier or later in
     * the full scan. Both must be caught before descriptor commit. */
    for(unsigned earlier=0;earlier<2;earlier++) {
        s=setup();CHECK(sprr_views_init(&views,&s));s.alloc=special_alloc;
        if(earlier) {
            for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,leaf(DATA+i*4096UL,7));
            put(BASE+0x4000,0,leaf(DATA,9));
        }
        alias_once=BASE+(earlier ? 0x3000 : 0x4000);
        CHECK(!compare(&s,state,modes));alias_once=0;
    }
    /* Too many visited source tables must fail before plan-array overflow. */
    s=setup();CHECK(sprr_views_init(&views,&s));
    for(unsigned i=0;i<256;i++)put(BASE,i,BASE+0x1000+3);
    for(unsigned i=0;i<32;i++)put(BASE+0x1000,i,BASE+0x2000+3);
    CHECK(!compare(&s,state,modes));CHECK(plan.source_count==8192);
    /* The required-path union is independently bounded before allocations. */
    s=setup();CHECK(sprr_views_init(&views,&s));next=BASE+0x200000;
    for(unsigned i=0;i<SPRR_VIEW_TABLES;i++) {
        uint64_t table=BASE+0x80000+4096UL*i;
        put(BASE+0x2000,i,table+3);put(table,0,leaf(DATA+4096UL*i,9));
    }
    CHECK(!compare(&s,state,modes));CHECK(plan.required_count==SPRR_VIEW_TABLES);

    /* Diagnostic fault injection: a callback damages the exclusive plan.
     * The sampled coverage walk rejects it without repairing the copies. */
    s=setup();CHECK(sprr_views_init(&views,&s));s.alloc=special_alloc;
    memset(&stats,0,sizeof stats);stats.calls=63;drop_plan=1;unsigned saved=writes;
    CHECK(!prepare(&views,&s,state,modes,&plan,&stats));
    CHECK(stats.verified==1 && stats.mismatches==1 && stats.failures==1 && writes==saved);
    s=setup();CHECK(sprr_views_init(&views,&s));memset(&stats,0,sizeof stats);
    for(unsigned i=0;i<128;i++)CHECK(compare(&s,state,modes));
    CHECK(stats.calls==128 && stats.successes==128 && stats.verified==2 &&
          !stats.mismatches && !stats.failures && stats.source_tables==128*6 &&
          stats.private_tables==128*4);
    /* Write failure is terminal and does not count a successful sync. */
    struct sprr_views old=views;fail_write=views.tables[0].copy[5];s.write=ordered_write;
    CHECK(!prepare(&views,&s,state,modes,&plan,&stats));
    CHECK(!memcmp(old.syncs,views.syncs,sizeof old.syncs) && stats.successes==128);
    CHECK(planned_reads<reference_reads);
#if TEST_USER_TABLE_READ
    /* A deliberately dishonest mapping cannot hide a missing TPRO branch
     * from the independent sampled callback walk. No live write is allowed. */
    fail_write=0;s=setup();CHECK(sprr_views_init(&views,&s));
    memset(&stats,0,sizeof stats);stats.calls=63;blank_table=1;saved=writes;
    CHECK(!prepare(&views,&s,state,modes,&plan,&stats));blank_table=0;
    CHECK(stats.verified==1 && stats.mismatches==1 && stats.failures==1 && writes==saved);
    s=setup();CHECK(sprr_views_init(&views,&s));memset(&stats,0,sizeof stats);
    bad_alignment=1;saved=writes;
    CHECK(!prepare(&views,&s,state,modes,&plan,&stats));bad_alignment=0;
    CHECK(stats.failures==1 && writes==saved);
    CHECK(table_maps>0);
    printf("Bounded table mappings: %u\n",table_maps);
#endif
#if TEST_USER_ZERO_GROUP
    zero_group_cases(state,modes);
#endif
    printf("Prepared fused user views: %u checks, %u failures; reads %llu vs %llu\n",
        checks,failures,(unsigned long long)planned_reads,(unsigned long long)reference_reads);
    return failures ? 1 : 0;
}
