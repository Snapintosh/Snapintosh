/* SPDX-License-Identifier: MIT */
#define TEST_USER_TABLE_READ 1
#define TEST_USER_ZERO_GROUP 1
#define TEST_PREPARE_ENTRY inherited_grouped_tests
#include "test-user-prepare-fused.c"

static uint64_t fused_attempts,baseline_attempts,candidate_attempts;
static uint64_t fused_fail_source,fused_fail_copy;
static unsigned fused_bad_copy,fused_ordered,source_maps,copy_maps;
static const volatile uint64_t *fused_source(void *ctx,uint64_t pa)
{
    (void)ctx;source_maps++;
    if(pa==fused_fail_source || (pa&4095) || pa<BASE || pa>BASE+BYTES-4096)return 0;
    return (const volatile uint64_t *)(ram+(pa-BASE));
}
static const volatile uint64_t *fused_copy(void *ctx,uint64_t pa)
{
    (void)ctx;copy_maps++;
    if(pa==fused_fail_copy || (pa&4095) || pa<BASE || pa>BASE+BYTES-4096)return 0;
    return (const volatile uint64_t *)(ram+(pa-BASE)+!!fused_bad_copy);
}
static int fused_write(void *ctx,uint64_t pa,uint64_t value)
{
    uint64_t old;fused_attempts++;
    if(rd(ctx,pa,&old))return -1;
    if(old==value)return 0;
    if(pa==fail_write)return -1;
    return fused_ordered ? ordered_write(ctx,pa,value) : wr(ctx,pa,value);
}
static int fused_compare(struct shadow *s,const struct sprr_state state[6],const int modes[6])
{
    static struct sprr_user_prepare_plan saved_plan,wanted_plan;
    struct sprr_views saved_views=views;saved_plan=plan;
    struct sprr_user_prepare_stats saved_stats=stats;
    struct sprr_user_zero_stats saved_zero=zero_stats;
    uint64_t saved_next=next,saved_epoch=epoch,saved_alias=alias_once;
    unsigned saved_budget=budget,old_writes=writes;uint64_t start=fused_attempts;
    memcpy(before,ram,sizeof ram);s->write=fused_write;fused_ordered=0;
    int reference=sprr_views_prepare_sync_user_grouped(&views,s,state,modes,&plan,&stats,
        table_reader,&zero_stats);
    uint64_t expected_attempts=fused_attempts-start;baseline_attempts+=expected_attempts;
    struct sprr_views wanted_views=views;wanted_plan=plan;
    struct sprr_user_prepare_stats wanted_stats=stats;
    struct sprr_user_zero_stats wanted_zero=zero_stats;
    uint64_t wanted_next=next,wanted_epoch=epoch;unsigned wanted_writes=writes-old_writes;
    memcpy(expected,ram,sizeof ram);memcpy(ram,before,sizeof ram);
    views=saved_views;plan=saved_plan;stats=saved_stats;zero_stats=saved_zero;
    next=saved_next;epoch=saved_epoch;budget=saved_budget;alias_once=saved_alias;
    old_writes=writes;start=fused_attempts;fused_ordered=1;source_maps=copy_maps=0;
    struct sprr_store_compare_stats st={0};
    int candidate=sprr_views_prepare_sync_user_compared(&views,s,state,modes,&plan,&stats,
        table_reader,&zero_stats,fused_source,fused_copy,&st);
    uint64_t actual_attempts=fused_attempts-start;candidate_attempts+=actual_attempts;
    CHECK(candidate==reference);CHECK(!memcmp(ram,expected,sizeof ram));
    CHECK(!memcmp(&views,&wanted_views,sizeof views));CHECK(!memcmp(&plan,&wanted_plan,sizeof plan));
    CHECK(!memcmp(&stats,&wanted_stats,sizeof stats));CHECK(!memcmp(&zero_stats,&wanted_zero,sizeof zero_stats));
    CHECK(next==wanted_next && epoch==wanted_epoch && writes-old_writes==wanted_writes);
    if(candidate) {
        CHECK(st.calls==1 && st.complete==1 && !st.failures);
        CHECK(st.tables==6*views.count && st.compared==512*st.tables);
        CHECK(st.compared==st.skipped+st.changed && st.changed==actual_attempts);
        CHECK(expected_attempts==st.compared && source_maps==views.count && copy_maps==6*views.count);
    }
    s->write=wr;return candidate;
}
int main(void)
{
    CHECK(!inherited_grouped_tests());epoch=0;fail_read=fail_write=0;
    memset(&stats,0,sizeof stats);memset(&zero_stats,0,sizeof zero_stats);
    struct sprr_state state[6]={0};int modes[6];
    for(unsigned cpu=0;cpu<6;cpu++){sprr_root_reset(&state[cpu],0xa);modes[cpu]=cpu&1;}
    struct shadow s=setup();CHECK(sprr_views_init(&views,&s));CHECK(fused_compare(&s,state,modes));
    for(unsigned pattern=0;pattern<64;pattern++) {
        for(unsigned cpu=0;cpu<6;cpu++) {
            state[cpu].uperm=SPRR_UPERM_INITIAL|((uint64_t)((pattern>>cpu)&1)<<36);
            state[cpu].pperm=SPRR_PPERM_INITIAL|((uint64_t)((pattern>>(5-cpu))&1)<<36)|((uint64_t)(cpu&1)<<8);
            modes[cpu]=(pattern+cpu)&1;
        }
        for(unsigned selector=0;selector<16;selector++) {
            put(BASE+0x3000,0,leaf(DATA,selector));fused_compare(&s,state,modes);
        }
    }
    put(BASE+0x3000,0,leaf(DATA,9));
    for(unsigned cpu=0;cpu<6;cpu++) {
        state[cpu].uperm^=1;CHECK(!fused_compare(&s,state,modes));state[cpu].uperm^=1;
        int mode=modes[cpu];modes[cpu]=2;CHECK(!fused_compare(&s,state,modes));modes[cpu]=mode;
    }
    /* New branches, removals and retained copies keep allocation/order exact. */
    put(BASE+0x4000,1,leaf(DATA,9));CHECK(fused_compare(&s,state,modes));
    put(BASE+0x5000,1,leaf(DATA+0x10000,9));CHECK(fused_compare(&s,state,modes));
    put(BASE+0x2000,2,0);CHECK(fused_compare(&s,state,modes));
    put(BASE+0x2000,2,BASE+0x5000+3);CHECK(fused_compare(&s,state,modes));
    for(unsigned i=0;i<130;i++)CHECK(fused_compare(&s,state,modes));
    CHECK(stats.verified>=2 && !stats.mismatches);
    /* Every destination mapping, including CPU5, is checked before writes. */
    for(unsigned n=0;n<views.count;n++)for(unsigned cpu=0;cpu<6;cpu++) {
        struct sprr_store_compare_stats st={0};fused_fail_copy=views.tables[n].copy[cpu];
        memcpy(before,ram,sizeof ram);unsigned saved=writes;
        CHECK(!sprr_views_prepare_sync_user_compared(&views,&s,state,modes,&plan,&stats,
            table_reader,&zero_stats,fused_source,fused_copy,&st));
        CHECK(st.calls==1 && st.failures==1 && !st.compared && !st.complete);
        CHECK(writes==saved && !memcmp(ram,before,sizeof ram));
    }
    fused_fail_copy=0;
    for(unsigned kind=0;kind<2;kind++) {
        struct sprr_store_compare_stats st={0};unsigned saved=writes;
        fused_fail_source=kind ? 0 : views.tables[0].source;fused_bad_copy=kind;
        CHECK(!sprr_views_prepare_sync_user_compared(&views,&s,state,modes,&plan,&stats,
            table_reader,&zero_stats,fused_source,fused_copy,&st));
        CHECK(st.failures==1 && !st.compared && writes==saved);
    }
    fused_fail_source=fused_bad_copy=0;
    /* A changed-word failure preserves the reference terminal partial state. */
    put(views.tables[3].copy[5],0,0);fail_write=views.tables[3].copy[5];
    CHECK(!fused_compare(&s,state,modes));fail_write=0;
    /* A sampled independent scan still catches a dishonest full-tree map. */
    s=setup();CHECK(sprr_views_init(&views,&s));stats.calls=63;blank_table=1;
    CHECK(!fused_compare(&s,state,modes));blank_table=0;
    /* Fill both mapping arrays to their supported maximum: three upper
     * tables and SPRR_VIEW_TABLES-3 distinct TPRO leaf tables, with six
     * private destinations each. */
    s=setup();next=BASE+0x80000+4096UL*SPRR_VIEW_TABLES;
    for(unsigned i=0;i<SPRR_VIEW_TABLES-3;i++) {
        uint64_t table=BASE+0x80000+4096UL*i;
        put(BASE+0x2000,i,table+3);put(table,0,leaf(DATA+4096UL*i,9));
    }
    CHECK(sprr_views_init(&views,&s));CHECK(fused_compare(&s,state,modes));
    CHECK(views.count==SPRR_VIEW_TABLES && source_maps==SPRR_VIEW_TABLES && copy_maps==6*SPRR_VIEW_TABLES);
    CHECK(candidate_attempts<baseline_attempts);
    printf("Fused callbacks: %llu compared / %llu reference\n",
        (unsigned long long)candidate_attempts,(unsigned long long)baseline_attempts);
    printf("Fused store comparison: %u checks, %u failures\n",checks,failures);
    return !!failures;
}
