/* SPDX-License-Identifier: MIT */
/* SNAP_VIEW_RECLAIM (shadow/sprr-view.h sprr_views_reclaim; probes/xnuboot
 * kernel_views_prepare_change): kernel copies no protected leaf needs any more
 * are retired and their pages reused, in a 256-table pool.
 *
 * A canonical kernel 4K tree (one root, one level 1, four level 2 and 512
 * level-3 tables) is driven the way the monitor drives it: every protecting
 * change prepares its path, detaches it (sync, publish, TLBI), then stores the
 * selector2/4 leaves and refreshes; a release stores ordinary leaves and
 * refreshes. The quiesce callback is kernel_views_quiesce's model: publication
 * rows reset, every CPU synced and published, then an all-CPU TLBI.
 *
 * Checked after every step, independently of the library:
 *  - every CPU's walk from its own root gives, for all 16,384 leaves, the
 *    canonical descriptor, or for selector2/4 its translation under that CPU's
 *    PPERM (the only leaves that may differ);
 *  - no page reachable from a root holds an unpublished store;
 *  - every live copy page is distinct and no source; entries past count are
 *    empty, parked (source 0, level 0) or retired (level SPRR_VIEW_RETIRED);
 *  - no store reaches a retired page between its unlinking and the TLBI that
 *    follows (a walk cache may still hold it), and after the quiesce's sync no
 *    root reaches one.
 * Scenarios: fill to 256; a full pool refuses with no change; release and
 * reclaim (with the level-2 ancestor of fully released tables); reuse of the
 * retired pages before any new allocation; reclaim down to the root; a source
 * read failure, nothing to retire, an unconfigured view and a failed quiesce
 * (no partial state, retired pages never reused). Harness self-checks: a
 * quiesce without its TLBI and a protected table removed by hand must both be
 * caught.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -DSNAP_VIEW_RECLAIM=1 -Icompat -Ishadow tools/test-view-reclaim.c \
 *    shadow/sprr-view.c shadow/shadow.c shadow/mmu.c -o build/test-view-reclaim
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sprr-view.h"
#include "sprr-publish.h"
#include "sprr.h"
#if !SNAP_VIEW_RECLAIM
#error "build with -DSNAP_VIEW_RECLAIM=1"
#endif

#define BASE UINT64_C(0x40000000)
#define BYTES (32u<<20)
#define PAGES (BYTES/4096)
#define DATA UINT64_C(0x900000000)
#define ATTR (PT_AF|(3UL<<8))
#define L1 (BASE+0x1000)
#define L2(k) (BASE+0x2000+0x1000UL*(k))
#define L3(k,j) (BASE+0x10000+0x1000UL*((k)*128u+(j)))
#define COPIES (BASE+0x400000)
#define SEL3 (ATTR+PT_PXN+PT_UXN+3)     /* ordinary RW/NX page: class 3 */
#define SEL2 (ATTR+PT_UXN+3)            /* selector2 (ROZONE): class 2 */
#define SEL4 (ATTR+(1UL<<6)+3)          /* selector4 (TXM aperture): class 4 */
#define SEL11 (ATTR+(2UL<<6)+PT_UXN+PT_PXN+3)   /* fixed RO/NX: class 11 */

static unsigned char ram[BYTES],dirty[PAGES],stale[PAGES];
static struct sprr_views views;
static struct sprr_publish_state pub;
static uint64_t pp[SPRR_VIEW_CPUS],next_copy,read_fail,allocs,alloc_budget;
static unsigned checks,failed,stale_writes,tlbis,quiesces,quiesce_fails,quiesce_no_tlbi;
#define CHECK(x) do {checks++;if(!(x)){failed++;printf("FAIL %u: %s\n",__LINE__,#x);}} while(0)

static unsigned page(uint64_t pa) {return (unsigned)((pa-BASE)/4096);}
static int rd(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;if(pa<BASE || pa>BASE+BYTES-8 || (pa&7) || pa==read_fail)return -1;
    memcpy(out,ram+(pa-BASE),8);return 0;
}
/* kernel_table_write: identical stores elided; a changed one marks its copy
 * pending (SNAP_KERNEL_DIRTY_PUBLISH) and leaves the page unpublished. */
static int wr(void *ctx,uint64_t pa,uint64_t value)
{
    uint64_t old;
    if(rd(ctx,pa,&old))return -1;
    if(old==value)return 0;
    if(stale[page(pa)])stale_writes++;
    if(!sprr_publish_note(&pub,&views,pa))return -1;
    memcpy(ram+(pa-BASE),&value,8);dirty[page(pa)]=1;return 0;
}
/* private_kernel_alloc: zeroed with plain stores, unpublished. */
static uint64_t alloc(void *ctx)
{
    (void)ctx;
    if(!alloc_budget || next_copy>BASE+BYTES-4096)return 0;
    alloc_budget--;allocs++;
    uint64_t pa=next_copy;next_copy+=4096;
    memset(ram+(pa-BASE),0,4096);dirty[page(pa)]=1;return pa;
}
static struct shadow shadow_of(void)
{return (struct shadow){.txsz=17,.root=BASE,.alloc=alloc,.read=rd,.write=wr};}
static void put(uint64_t pa,uint64_t value)
{memcpy(ram+(pa-BASE),&value,8);}
static uint64_t get(uint64_t pa) {uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v;}
static uint64_t va_of(unsigned k,unsigned j,unsigned i)
{return ((uint64_t)k<<30)|((uint64_t)j<<21)|((uint64_t)i<<12);}
static uint64_t frame(unsigned k,unsigned j,unsigned i)
{return DATA+(((uint64_t)k*128+j)*512+i)*4096;}

static void tlbi(void) {memset(stale,0,sizeof stale);tlbis++;}
static int publish_cpu(unsigned cpu)
{
    if(!sprr_publish_prepare(&pub,&views))return 0;
    for(unsigned level=4;level--;)for(unsigned n=0;n<views.count;n++) {
        if(views.tables[n].level!=level || !sprr_publish_needed(&pub,cpu,n))continue;
        dirty[page(views.tables[n].copy[cpu])]=0;
        if(!sprr_publish_complete(&pub,cpu,n))return 0;
    }
    return sprr_publish_row_empty(&pub,cpu);
}
static int sync_publish(void)
{
    struct shadow s=shadow_of();
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if(!sprr_views_sync_cpu(&views,&s,cpu,pp[cpu]) || !publish_cpu(cpu))return 0;
    return 1;
}
/* shadow_tlb_sync: refresh every copy, publish, all-VMID TLBI. */
static int refresh(void) {int ok=sync_publish();if(ok)tlbi();return ok;}
static int reachable_bad(uint64_t table,unsigned level,int stale_only)
{
    if(table<BASE || table>=BASE+BYTES)return 1;
    if(stale_only ? stale[page(table)] : dirty[page(table)])return 1;
    for(unsigned i=0;i<512 && level<3;i++) {
        uint64_t d=get(table+8UL*i);
        if((d&3)==3 && reachable_bad(d&PT_OA_MASK,level+1,stale_only))return 1;
    }
    return 0;
}
/* kernel_views_quiesce's model. */
static int quiesce(void *ctx)
{
    (void)ctx;quiesces++;
    unsigned retired=0;
    for(unsigned n=views.count;n<SPRR_VIEW_TABLES;n++)if(views.tables[n].level==SPRR_VIEW_RETIRED) {
        retired++;CHECK(!views.tables[n].source);
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)stale[page(views.tables[n].copy[cpu])]=1;
    }
    CHECK(retired);
    if(quiesce_fails)return 0;
    sprr_publish_reset(&pub);
    if(!sync_publish())return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        CHECK(!reachable_bad(sprr_views_root(&views,cpu),0,1));
    if(!quiesce_no_tlbi)tlbi();
    return 1;
}
static uint64_t expected(uint64_t d,unsigned cpu)
{
    if((d&3)!=3)return d;
    unsigned c=sprr_pte_class(d);
    if(c!=2 && c!=4)return d;
    d=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN;
    return c==4 || !(pp[cpu]&0x100) ? d|(2UL<<6) : d;
}
/* An independent walk of CPU cpu's view for every leaf of the tree. */
static unsigned view_mismatches(void)
{
    unsigned bad=0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
        uint64_t root=sprr_views_root(&views,cpu);
        if(!root || root==BASE)return 1;
        for(unsigned k=0;k<4;k++)for(unsigned j=0;j<128;j++)for(unsigned i=0;i<8;i++) {
            uint64_t va=va_of(k,j,i),table=root,d=0;
            for(unsigned level=0;level<4;level++) {
                d=get(table+8UL*mmu_index(12,level,va));
                if(level<3) {if((d&3)!=3)break;table=d&PT_OA_MASK;}
            }
            bad+=d!=expected(get(L3(k,j)+8UL*i),cpu);
        }
    }
    return bad;
}
static void invariants(void)
{
    struct shadow s=shadow_of();
    CHECK(!view_mismatches());
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
        CHECK(sprr_views_verify_cpu(&views,&s,cpu,pp[cpu]));
        CHECK(!reachable_bad(sprr_views_root(&views,cpu),0,0));
    }
    CHECK(views.count && views.count<=SPRR_VIEW_TABLES && views.tables[0].source==BASE);
    static unsigned char seen[PAGES];memset(seen,0,sizeof seen);
    for(unsigned n=0;n<SPRR_VIEW_TABLES;n++) {
        const struct sprr_view_table *t=&views.tables[n];
        if(n<views.count) {CHECK(t->source>=BASE && t->source<COPIES && t->level<=3);}
        else CHECK(!t->source && (!t->level || t->level==SPRR_VIEW_RETIRED));
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
            uint64_t pa=t->copy[cpu];
            if(!pa) {CHECK(n>=views.count);continue;}
            CHECK(pa>=COPIES && pa<next_copy && !seen[page(pa)]);seen[page(pa)]=1;
        }
    }
    CHECK(!stale_writes);
}
/* sprr_views_reclaim, and what a completed one must leave: one quiesce and
 * its TLBI after the unlinking, no root reaching a retired page, and the
 * retired sets parked past count. */
static int reclaim(void)
{
    struct shadow s=shadow_of();unsigned q=quiesces,t=tlbis,count=(unsigned)views.count;
    int got=sprr_views_reclaim(&views,&s,quiesce,0);
    if(got<=0)return got;
    CHECK(quiesces==q+1 && (tlbis==t+1 || quiesce_no_tlbi) && views.count==count-(unsigned)got);
    static unsigned char tail[PAGES];memset(tail,0,sizeof tail);
    for(unsigned n=(unsigned)views.count;n<count;n++) {
        CHECK(!views.tables[n].source && !views.tables[n].level);
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)tail[page(views.tables[n].copy[cpu])]=1;
    }
    static unsigned char keep[PAGES];memcpy(keep,stale,sizeof keep);memcpy(stale,tail,sizeof stale);
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)CHECK(!reachable_bad(sprr_views_root(&views,cpu),0,1));
    memcpy(stale,keep,sizeof stale);
    return got;
}
static int find_source(uint64_t source)
{
    for(unsigned n=0;n<views.count;n++)if(views.tables[n].source==source)return (int)n;
    return -1;
}
/* kernel_views_prepare_change for a change of `leaves` frames: every path,
 * and on a refusal with the pool nearly full a reclaim and a restart from
 * the first leaf. only_failing is a deliberately wrong variant (retry the
 * refused leaf alone) the walk check must catch. */
static int only_failing;
static int prepare_change(const unsigned (*leaf)[2],unsigned leaves)
{
    struct shadow s=shadow_of();unsigned i=0;
    for(int again=0;;again=1) {
        if(!only_failing)i=0;
        while(i<leaves && sprr_views_prepare(&views,&s,va_of(leaf[i][0],leaf[i][1],0)))i++;
        if(i==leaves)return 1;
        if(again || views.count+3<=SPRR_VIEW_TABLES)return 0;
        if(reclaim()<=0)return 0;
    }
}
/* sptm_retype_rozone/txm_default: prepare, detach, commit, refresh. */
static int protect_change(const unsigned (*leaf)[2],unsigned leaves,uint64_t selector)
{
    if(!prepare_change(leaf,leaves) || !refresh())return 0;
    for(unsigned n=0;n<leaves;n++)for(unsigned i=0;i<4;i++)
        put(L3(leaf[n][0],leaf[n][1])+8UL*i,frame(leaf[n][0],leaf[n][1],i)+selector);
    return refresh();
}
static int protect(unsigned k,unsigned j,uint64_t selector)
{
    const unsigned leaf[1][2]={{k,j}};
    return protect_change(leaf,1,selector);
}
static int release(unsigned k,unsigned j)
{
    for(unsigned i=0;i<4;i++)put(L3(k,j)+8UL*i,frame(k,j,i)+SEL3);
    return refresh();
}
static void build(void)
{
    memset(ram,0,sizeof ram);memset(dirty,0,sizeof dirty);memset(stale,0,sizeof stale);
    memset(&views,0,sizeof views);memset(&pub,0,sizeof pub);
    next_copy=COPIES;allocs=0;alloc_budget=PAGES;read_fail=0;
    stale_writes=quiesce_fails=quiesce_no_tlbi=0;
    put(BASE,L1+3);
    for(unsigned k=0;k<4;k++) {
        put(L1+8UL*k,L2(k)+3);
        for(unsigned j=0;j<128;j++) {
            put(L2(k)+8UL*j,L3(k,j)+3);
            for(unsigned i=0;i<8;i++)put(L3(k,j)+8UL*i,frame(k,j,i)+SEL3);
        }
    }
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)pp[cpu]=SPRR_PPERM_INITIAL|(cpu&1 ? 0x100 : 0);
    struct shadow s=shadow_of();
    CHECK(sprr_views_init(&views,&s) && refresh());
}
static unsigned char saved_ram[BYTES];
static struct sprr_views saved_views;
static void snapshot(void) {memcpy(saved_ram,ram,sizeof ram);saved_views=views;}
static int unchanged(void)
{return !memcmp(saved_ram,ram,sizeof ram) && !memcmp(&saved_views,&views,sizeof views);}

int main(void)
{
    struct shadow s;
    build();s=shadow_of();invariants();
    /* Fill: 128 level-3 tables under level 2 #0, 64 under #1 (the first eight
     * TXM selector4), then #2 until the pool holds 256 (root, level 1, three
     * level 2, 251 level 3). */
    unsigned filled=0;
    for(unsigned k=0;k<3 && views.count<SPRR_VIEW_TABLES;k++)
        for(unsigned j=0;j<(k==1 ? 64u : 128u) && views.count<SPRR_VIEW_TABLES;j++) {
            if(views.count==SPRR_VIEW_TABLES-1) {
                /* One slot left, a path needing two: refused before any add. */
                snapshot();uint64_t allocated=allocs;
                CHECK(!sprr_views_prepare(&views,&s,va_of(3,0,0)) && unchanged() && allocs==allocated);
            }
            CHECK(protect(k,j,(k==1 && j<8) ? SEL4 : SEL2));filled++;
        }
    CHECK(views.count==SPRR_VIEW_TABLES && filled==251 && !quiesces && allocs==6u*SPRR_VIEW_TABLES);
    invariants();
    /* Full: the next path needs a level-2 and a level-3 copy. Nothing changes,
     * nothing is allocated, and a reclaim finds nothing to retire. */
    snapshot();uint64_t before=allocs;
    CHECK(!sprr_views_prepare(&views,&s,va_of(3,0,0)) && unchanged() && allocs==before);
    CHECK(sprr_views_reclaim(&views,&s,quiesce,0)==0 && unchanged() && !quiesces);
    CHECK(!protect(3,0,SEL2) && unchanged() && !quiesces);
    /* Refusals before any change: unconfigured, no quiesce, a read failure. */
    struct shadow wrong=s;wrong.root=L1;
    CHECK(sprr_views_reclaim(&views,&wrong,quiesce,0)==-1 && unchanged());
    CHECK(sprr_views_reclaim(&views,&s,0,0)==-1 && unchanged());
    CHECK(release(0,5) && release(0,6));
    snapshot();
    read_fail=L3(0,5)+8*300;   /* no protected leaf: its scan reads every word */
    CHECK(sprr_views_reclaim(&views,&s,quiesce,0)==-1 && unchanged() && !quiesces);
    read_fail=0;
    /* Release: two tables under level 2 #0, the eight TXM tables turned
     * fixed RO selector11 (an import), and every table under level 2 #2: that
     * level-2 copy goes too. */
    for(unsigned j=0;j<8;j++)for(unsigned i=0;i<4;i++)put(L3(1,j)+8UL*i,frame(1,j,i)+SEL11);
    for(unsigned j=0;j<128;j++)if(find_source(L3(2,j))>=0)CHECK(release(2,j));
    CHECK(refresh());invariants();
    uint64_t order[SPRR_VIEW_TABLES];unsigned kept=0;
    unsigned under2=0;
    for(unsigned j=0;j<128;j++)under2+=find_source(L3(2,j))>=0;
    for(unsigned n=0;n<views.count;n++) {
        uint64_t src=views.tables[n].source;
        int dead=src==L3(0,5) || src==L3(0,6) || src==L2(2) || (src>=L3(1,0) && src<L3(1,8)) ||
                 (src>=L3(2,0) && src<L3(3,0));
        if(!dead)order[kept++]=src;
    }
    unsigned count=(unsigned)views.count;
    uint64_t retired_pages[SPRR_VIEW_TABLES*SPRR_VIEW_CPUS];unsigned retired=0;
    for(unsigned n=0;n<views.count;n++)if(find_source(views.tables[n].source)>=0) {
        uint64_t src=views.tables[n].source;
        int dead=src==L3(0,5) || src==L3(0,6) || src==L2(2) || (src>=L3(1,0) && src<L3(1,8)) ||
                 (src>=L3(2,0) && src<L3(3,0));
        if(dead)for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)retired_pages[retired++]=views.tables[n].copy[cpu];
    }
    unsigned tlbis_before=tlbis;
    int got=reclaim();
    CHECK(got==(int)(2+8+under2+1) && views.count==count-(unsigned)got && quiesces==1 && tlbis==tlbis_before+1);
    CHECK(views.count==kept);
    for(unsigned n=0;n<kept;n++)CHECK(views.tables[n].source==order[n]);
    CHECK(find_source(L2(2))<0 && find_source(L2(0))>=0 && find_source(L1)>=0);
    for(unsigned n=views.count;n<count;n++)CHECK(!views.tables[n].level && !views.tables[n].source);
    invariants();
    /* Reuse: new paths take the retired pages, in position order, before the
     * allocator is asked again; their stale words are rewritten by the sync. */
    before=allocs;unsigned reused=0;
    for(unsigned j=0;j<128 && views.count<count;j++) {
        unsigned n=(unsigned)views.count;
        uint64_t want[SPRR_VIEW_CPUS];memcpy(want,views.tables[n].copy,sizeof want);
        CHECK(protect(3,j,SEL2));
        for(unsigned m=n;m<views.count;m++)for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
            int known=0;
            for(unsigned r=0;r<retired;r++)known|=retired_pages[r]==views.tables[m].copy[cpu];
            CHECK(known);reused++;
        }
        CHECK(!memcmp(want,views.tables[n].copy,sizeof want));
    }
    CHECK(allocs==before && reused==(unsigned)got*SPRR_VIEW_CPUS && views.count==count);
    invariants();
    /* Full again: a protect reclaims inside (kernel_views_prepare_change's
     * retry) and lands on the retired sets. */
    for(unsigned j=0;j<8;j++)CHECK(release(3,j));
    before=allocs;unsigned q=quiesces;
    CHECK(protect(2,0,SEL2) && quiesces==q+1 && allocs==before && views.count==SPRR_VIEW_TABLES-8+2);
    invariants();
    /* A failed quiesce: the views hold only kept tables, the retired pages are
     * never written or reused (the slot refuses), nothing is allocated. */
    CHECK(release(3,8) && release(3,9));
    quiesce_fails=1;before=allocs;count=(unsigned)views.count;
    CHECK(sprr_views_reclaim(&views,&s,quiesce,0)==-1 && views.count==count-2);
    CHECK(views.tables[views.count].level==SPRR_VIEW_RETIRED && views.tables[views.count+1].level==SPRR_VIEW_RETIRED);
    unsigned writes_before=stale_writes;
    CHECK(!sprr_views_prepare(&views,&s,va_of(3,8,0)) && allocs==before && stale_writes==writes_before);
    CHECK(views.tables[views.count].level==SPRR_VIEW_RETIRED);
    /* Everything released: the views shrink to the root. */
    build();s=shadow_of();
    for(unsigned k=0;k<4;k++)for(unsigned j=0;j<16;j++)CHECK(protect(k,j,SEL2));
    for(unsigned k=0;k<4;k++)for(unsigned j=0;j<16;j++)CHECK(release(k,j));
    CHECK(reclaim()==1+4+64 && views.count==1);
    invariants();
    CHECK(protect(1,1,SEL4) && views.count==4 && allocs==6u*(1+1+4+64));
    invariants();
    /* Past the 69 parked sets the allocator serves again. */
    for(unsigned j=0;j<71;j++)CHECK(protect(3,j,SEL2));
    CHECK(views.count==4+1+71 && allocs==6u*(1+1+4+64+6));
    invariants();
    for(unsigned j=0;j<71;j++)CHECK(release(3,j));
    CHECK(reclaim()==72 && views.count==4);
    /* Harness self-checks. A quiesce without its TLBI lets the reuse store
     * into a page a walk cache may still hold: caught. */
    CHECK(release(1,1));quiesce_no_tlbi=1;
    CHECK(reclaim()==3);
    CHECK(sprr_views_prepare(&views,&s,va_of(2,2,0)) && sync_publish() && stale_writes);
    /* A two-frame change (a SLIDE_REGION alias) at 255 tables: its first
     * path fits, its second needs two tables. The reclaim retires the first
     * one too (its leaves are not protected yet), so the whole change is
     * prepared again; retrying the refused leaf alone would leave the first
     * frame's raw selector2 leaves in a shared table. */
    for(int wrong=0;wrong<2;wrong++) {
        build();s=shadow_of();
        for(unsigned j=0;j<127;j++)CHECK(protect(0,j,SEL2));
        for(unsigned j=0;j<124;j++)CHECK(protect(1,j,SEL2));
        CHECK(views.count==SPRR_VIEW_TABLES-1 && release(1,5) && release(1,6));
        const unsigned two[2][2]={{0,127},{3,100}};
        only_failing=wrong;unsigned q2=quiesces;
        CHECK(protect_change(two,2,SEL2) && quiesces==q2+1);
        only_failing=0;
        CHECK(find_source(L2(3))>=0 && find_source(L3(3,100))>=0 && find_source(L3(1,5))<0);
        CHECK((find_source(L3(0,127))>=0)==!wrong && !view_mismatches()==!wrong);
        if(!wrong) {CHECK(views.count==SPRR_VIEW_TABLES);invariants();}
        else {
            CHECK(view_mismatches()==4*SPRR_VIEW_CPUS);
            const unsigned again[1][2]={{0,127}};
            CHECK(prepare_change(again,1) && refresh() && !view_mismatches());
        }
    }
    /* A protected table dropped from the views is visible to the walk check. */
    build();s=shadow_of();
    CHECK(protect(0,0,SEL2) && protect(0,1,SEL2) && !view_mismatches());
    struct sprr_views good=views;
    int victim=find_source(L3(0,1));CHECK(victim==(int)views.count-1);
    views.count--;sprr_publish_reset(&pub);
    CHECK(sync_publish() && view_mismatches()==4*SPRR_VIEW_CPUS);
    views=good;sprr_publish_reset(&pub);CHECK(sync_publish() && !view_mismatches());
    printf("view reclaim: %u quiesces, %u TLBIs, %llu pages allocated\n",quiesces,tlbis,
           (unsigned long long)allocs);
    printf("%s: %u view reclaim checks, %u failures\n",failed ? "FAIL" : "PASS",checks,failed);
    return failed ? 1 : 0;
}
