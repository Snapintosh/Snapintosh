/* SPDX-License-Identifier: MIT */
/* shadow/native-shared.c: shared-region 4K level-3 groups. Every check is
 * differential: after each operation, walking any root that links a group
 * must give, for every 4K address of its 32 MiB, the translation of the
 * guest 16K leaf there (shadow_map's rule), and the group must verify
 * against its guest table. Refusals leave groups, links and roots intact. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native-shared.h"
#include "../compat/sprr.h"

#define BASE UINT64_C(0x40000000)
#define SIZE (24u<<20)
/* Guest tables here read as zero: every entry invalid (no leaf, no page). */
#define EMPTY UINT64_C(0x100000000)
#define EMPTY_SIZE (UINT64_C(1)<<32)
static uint8_t *mem;
static uint64_t next_page,fail_alloc_after;
static unsigned checks,failures;
#define CHECK(x) do{checks++;if(!(x)){failures++;printf("line %d: %s\n",__LINE__,#x);}}while(0)

static int rd(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;
    if(pa>=EMPTY && pa+8<=EMPTY+EMPTY_SIZE && !(pa&7)) {*out=0;return 0;}
    if(pa<BASE || pa+8>BASE+SIZE || (pa&7))return -1;
    memcpy(out,mem+(pa-BASE),8);return 0;
}
static int wr(void *ctx,uint64_t pa,uint64_t v)
{(void)ctx;if(pa<BASE || pa+8>BASE+SIZE || (pa&7))return -1;memcpy(mem+(pa-BASE),&v,8);return 0;}
static uint64_t alloc4k(void *ctx)
{
    (void)ctx;
    if(fail_alloc_after && !--fail_alloc_after)return 0;
    if(next_page+4096>BASE+SIZE)return 0;
    uint64_t pa=next_page;next_page+=4096;memset(mem+(pa-BASE),0,4096);return pa;
}
static uint64_t no_alloc(void *ctx) {(void)ctx;return 0;}
static uint64_t word(uint64_t pa) {uint64_t v=0;rd(0,pa,&v);return v;}
static unsigned released;
static void rel(void *ctx,uint64_t pa) {(void)ctx;CHECK(pa && !(pa&4095));released++;}

/* Guest 16K level-3 tables live in the same memory (16K aligned). */
static uint64_t guest_table(void)
{
    next_page=(next_page+16383)&~UINT64_C(16383);
    uint64_t pa=next_page;next_page+=16384;memset(mem+(pa-BASE),0,16384);return pa;
}
static const uint64_t CLASSES[]={
    UINT64_C(0x0060000000000f43), /* class 7: RW NX user data */
    UINT64_C(0x0020000000000fc3), /* class 13: RO user exec */
    UINT64_C(0x0060000000000fc3), /* class 15: RO NX */
    UINT64_C(0x0060000000000f83), /* class 11 */
};
static uint64_t leaf(unsigned seed)
{return (UINT64_C(0x900000000)+UINT64_C(0x4000)*(seed%100000))|CLASSES[seed%4];}
static unsigned links(const struct native_shared *ns,int g) {return (unsigned)__builtin_popcountll(ns->group[g].slots);}
static unsigned pages_of(const struct native_shared *ns,int g)
{unsigned n=0;for(unsigned p=0;p<NATIVE_SHARED_PAGES;p++)n+=!!ns->group[g].pages[p];return n;}

static struct native_shared ns;
static struct shadow group_writer={.txsz=17,.alloc=alloc4k,.read=rd,.write=wr};
static struct shadow roots[4];
static uint64_t guest_of[8],va_of[8];
/* The trees native_shared_grow writes: the test's roots, by slot. */
static int tree(void *ctx,unsigned slot,struct shadow *out)
{(void)ctx;if(slot>=4)return -1;*out=roots[slot];out->alloc=no_alloc;return 0;}
static const struct native_shared_roots trees={tree,0};

static struct shadow new_root(void)
{
    struct shadow s={.txsz=17,.alloc=alloc4k,.read=rd,.write=wr};
    s.root=alloc4k(0);return s;
}
/* Expected 4K leaf for va in a group's range from its guest table. */
static int expect(uint64_t guest,uint64_t base,uint64_t va,uint64_t *pa,uint64_t *attrs)
{
    uint64_t d=word(guest+8UL*((va-base)>>14));
    if(!(d&1))return 0;
    *pa=(d&UINT64_C(0x0000ffffffffc000))+(va&0x3000);
    *attrs=(d&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|3;
    return 1;
}
/* Every 4K address of group g's range, walked through root s. */
static int root_matches(const struct shadow *s,int g)
{
    const struct native_shared_group *grp=&ns.group[g];
    struct mmu_config cfg={12,17,s->root};
    for(uint64_t va=grp->va;va<grp->va+NATIVE_SHARED_SPAN;va+=4096) {
        struct mmu_leaf l;uint64_t pa,attrs;
        if(mmu_walk(&cfg,va,rd,0,&l))return 0;
        int want=expect(grp->guest,grp->va,va,&pa,&attrs);
        if(l.valid!=want)return 0;
        if(want && (l.level!=3 || l.pa!=pa || (l.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER|3))!=attrs))
            return 0;
    }
    return 1;
}
static int unmapped(const struct shadow *s,uint64_t base)
{
    struct mmu_config cfg={12,17,s->root};
    for(uint64_t va=base;va<base+NATIVE_SHARED_SPAN;va+=UINT64_C(1)<<21) {
        struct mmu_leaf l;
        if(mmu_walk(&cfg,va,rd,0,&l) || l.valid)return 0;
    }
    return 1;
}

static void test_create_and_translate(void)
{
    uint64_t guest=guest_table(),va=UINT64_C(0x180000000);
    for(unsigned j=0;j<2048;j+=3)wr(0,guest+8UL*j,leaf(j*7+1));
    int g=native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest,va,rd,0,rel,0);
    CHECK(g>=0 && ns.live==1 && ns.group[g].leaves==683 && native_shared_find(&ns,guest)==g);
    CHECK(pages_of(&ns,g)==16 && native_shared_verify(&ns,&group_writer,g,rd,0));
    guest_of[0]=guest;va_of[0]=va;
    /* Two roots link it; both translate every 4K address of the range. */
    for(unsigned r=0;r<2;r++) {
        roots[r]=new_root();
        CHECK(native_shared_link(&ns,&roots[r],r,g) && native_shared_linked(&ns,&roots[r],g));
        CHECK(root_matches(&roots[r],g));
    }
    CHECK(links(&ns,g)==2 && native_shared_slot_links(&ns,0,g) && native_shared_slot_links(&ns,1,g));
    /* A second link of the same slot, or over occupied entries, is refused. */
    uint64_t errors=ns.errors;
    CHECK(!native_shared_link(&ns,&roots[0],0,g) && links(&ns,g)==2 && ns.errors==errors+1);
    CHECK(!native_shared_link(&ns,&roots[0],2,g) && links(&ns,g)==2);
    CHECK(!native_shared_slot_links(&ns,2,g));
    /* The same guest table is not mirrored twice. */
    CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest,va,rd,0,rel,0)<0 && ns.live==1);
}

static void test_stores(void)
{
    int g=native_shared_find(&ns,guest_of[0]);
    srand(7);
    for(unsigned n=0;n<3000;n++) {
        unsigned j=(unsigned)rand()%2048;
        uint64_t va=va_of[0]+UINT64_C(0x4000)*j,next=rand()%3 ? leaf((unsigned)rand()) : 0;
        uint64_t before=ns.group[g].leaves,old=word(guest_of[0]+8UL*j);
        wr(0,guest_of[0]+8UL*j,next);
        CHECK(native_shared_store(&ns,&group_writer,g,va,next));
        CHECK(ns.group[g].leaves==(before+(!old && next))-(old && !next));
    }
    CHECK(native_shared_verify(&ns,&group_writer,g,rd,0));
    CHECK(root_matches(&roots[0],g) && root_matches(&roots[1],g));
    /* holds(): exactly the guest translation, entry by entry. */
    for(unsigned j=0;j<2048;j+=97) {
        uint64_t va=va_of[0]+UINT64_C(0x4000)*j,d=word(guest_of[0]+8UL*j);
        CHECK(native_shared_holds(&ns,&group_writer,g,va,d));
        CHECK(!native_shared_holds(&ns,&group_writer,g,va,d ? 0 : leaf(j)));
        CHECK(!d || !native_shared_holds(&ns,&group_writer,g,va,d^0x4000));
    }
    /* verify() compares every entry: one flipped output address fails it. */
    {
        uint64_t slot=ns.group[g].pages[7]+8*9,saved=word(slot);
        wr(0,slot,saved^0x8000);
        CHECK(!native_shared_verify(&ns,&group_writer,g,rd,0));
        wr(0,slot,saved);
        CHECK(native_shared_verify(&ns,&group_writer,g,rd,0));
    }
    CHECK(native_shared_storable(0) && native_shared_storable(leaf(5)));
    CHECK(!native_shared_storable(UINT64_C(0x900004000)|UINT64_C(0x0020000000000e83)));
    CHECK(!native_shared_storable(UINT64_C(0x900004000)|0xf41) && !native_shared_storable(0x8000000000000000));
    /* Refused: TPRO, a block/invalid descriptor, a misaligned or foreign VA. */
    uint64_t snapshot=word(ns.group[g].pages[3]+8*20),errors=ns.errors;
    uint64_t tpro=UINT64_C(0x900004000)|UINT64_C(0x0020000000000e83);
    CHECK(sprr_pte_class(tpro)==9);
    CHECK(!native_shared_store(&ns,&group_writer,g,va_of[0]+0x4000*389,tpro));
    CHECK(!native_shared_store(&ns,&group_writer,g,va_of[0]+0x4000*389,UINT64_C(0x900004000)|0xf41));
    CHECK(!native_shared_store(&ns,&group_writer,g,va_of[0]+0x2000,leaf(3)));
    CHECK(!native_shared_store(&ns,&group_writer,g,va_of[0]+NATIVE_SHARED_SPAN,leaf(3)));
    CHECK(!native_shared_store(&ns,&group_writer,g,va_of[0]-0x4000,leaf(3)));
    CHECK(ns.errors==errors+5 && word(ns.group[g].pages[3]+8*20)==snapshot);
    CHECK(native_shared_verify(&ns,&group_writer,g,rd,0));
}

static void test_refused_create(void)
{
    uint64_t guest=guest_table(),live=ns.live;
    wr(0,guest+8*5,leaf(1));
    wr(0,guest+8*9,UINT64_C(0x900008000)|UINT64_C(0x0020000000000e83)); /* raw TPRO */
    /* A refused guest leaf is found before any page is taken. */
    uint64_t pages=next_page;
    CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest,UINT64_C(0x182000000),rd,0,rel,0)<0);
    wr(0,guest+8*9,UINT64_C(0x900008000)|0x401);                         /* a block */
    CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest,UINT64_C(0x182000000),rd,0,rel,0)<0);
    CHECK(next_page==pages && !released);
    wr(0,guest+8*9,0);
    CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest,UINT64_C(0x182001000),rd,0,rel,0)<0);
    CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest+0x1000,UINT64_C(0x182000000),rd,0,rel,0)<0);
    CHECK(native_shared_create(&ns,&group_writer,0,guest,UINT64_C(0x182000000),rd,0,rel,0)<0);
    /* An allocation failure gives back every page taken before it: leaves in
     * five 2 MiB ranges, the fifth allocation fails. */
    for(unsigned p=1;p<5;p++)wr(0,guest+8UL*(128*p+3),leaf(p));
    fail_alloc_after=5;
    CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest,UINT64_C(0x182000000),rd,0,rel,0)<0);
    CHECK(released==4);
    fail_alloc_after=0;released=0;
    for(unsigned p=1;p<5;p++)wr(0,guest+8UL*(128*p+3),0);
    CHECK(ns.live==live && native_shared_find(&ns,guest)<0);
    /* A compressed marker (software bits only) maps nothing and is no leaf;
     * only the 2 MiB that holds a leaf gets a page. */
    wr(0,guest+8*11,UINT64_C(0xa000000000000000));
    int g=native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guest,UINT64_C(0x182000000),rd,0,rel,0);
    CHECK(g>=0 && ns.group[g].leaves==1 && native_shared_verify(&ns,&group_writer,g,rd,0));
    CHECK(pages_of(&ns,g)==1 && ns.group[g].pages[0]);
    guest_of[1]=guest;va_of[1]=UINT64_C(0x182000000);
}

/* Pages exist only where leaves are; a new page reaches every linking root first. */
static void test_lazy_pages(void)
{
    int g=native_shared_find(&ns,guest_of[1]);
    uint64_t base=va_of[1],guest=guest_of[1];
    for(unsigned r=0;r<2;r++)
        CHECK(native_shared_link(&ns,&roots[r],r,g) && native_shared_linked(&ns,&roots[r],g) && root_matches(&roots[r],g));
    /* No page in 2 MiB range 9: clearing there is done, mapping needs a page. */
    uint64_t va=base+(UINT64_C(9)<<21)+0x4000*5,errors=ns.errors;
    CHECK(native_shared_store(&ns,&group_writer,g,va,0) && ns.errors==errors);
    CHECK(!native_shared_store(&ns,&group_writer,g,va,leaf(9)) && ns.errors==errors+1 && !ns.group[g].pages[9]);
    CHECK(native_shared_holds(&ns,&group_writer,g,va,0) && !native_shared_holds(&ns,&group_writer,g,va,leaf(9)));
    /* A guest leaf appearing without a page fails the audit, even with a leaf
     * count that agrees. */
    unsigned j=(unsigned)((va-base)>>14);
    wr(0,guest+8UL*j,leaf(9));
    ns.group[g].leaves++;
    CHECK(!native_shared_verify(&ns,&group_writer,g,rd,0));
    ns.group[g].leaves--;
    /* grow() refuses before any change when a linking root's entry is taken. */
    uint64_t table;
    CHECK(!shadow_table(&roots[1],2,base,&table));
    uint64_t at=table+8UL*(mmu_index(12,2,base)+9),pages=next_page;
    wr(0,at,UINT64_C(0x77000)|3);
    CHECK(!native_shared_grow(&ns,&group_writer,g,va,&trees) && !ns.group[g].pages[9] && next_page==pages);
    wr(0,at,0);
    /* grow() then store(): every linking root maps the new leaf. */
    CHECK(native_shared_grow(&ns,&group_writer,g,va,&trees) && ns.group[g].pages[9] && pages_of(&ns,g)==2);
    CHECK(native_shared_grow(&ns,&group_writer,g,va,&trees) && pages_of(&ns,g)==2);
    CHECK(native_shared_linked(&ns,&roots[0],g) && native_shared_linked(&ns,&roots[1],g));
    CHECK(native_shared_store(&ns,&group_writer,g,va,leaf(9)) && ns.group[g].leaves==2);
    CHECK(native_shared_verify(&ns,&group_writer,g,rd,0) && root_matches(&roots[0],g) && root_matches(&roots[1],g));
    /* A later link sees both pages; unlinking clears exactly those. */
    roots[2]=new_root();
    CHECK(native_shared_link(&ns,&roots[2],2,g) && root_matches(&roots[2],g));
    CHECK(native_shared_unlink(&ns,&roots[2],2,g) && unmapped(&roots[2],base) && links(&ns,g)==2);
    /* A group whose table has no leaf at all takes no page. */
    uint64_t empty=EMPTY+(((uint64_t)NATIVE_SHARED_GROUPS+8)<<14);
    int e=native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),empty,UINT64_C(0x184000000),rd,0,rel,0);
    CHECK(e>=0 && !pages_of(&ns,e) && native_shared_link(&ns,&roots[0],0,e) && native_shared_linked(&ns,&roots[0],e));
    CHECK(unmapped(&roots[0],UINT64_C(0x184000000)) && native_shared_verify(&ns,&group_writer,e,rd,0));
    CHECK(native_shared_unlink(&ns,&roots[0],0,e) && native_shared_free(&ns,e,rel,0) && !released);
}

/* More groups than the old 512 records, found through the index; the last free
 * record taken, the next creation is refused as full (not an error). */
static void test_capacity_and_index(void)
{
    /* The probe starts tools/native_shared_audit.py computes, as known answers:
     * a lone group sits at its guest's start (EMPTY+0x4000 and +0x8000 read as
     * empty tables here, so they take no page). */
    static const struct {uint64_t guest;unsigned start;} known[]={
        {UINT64_C(0x100004000),4259},{UINT64_C(0x100008000),1130}};
    for(unsigned n=0;n<2;n++) {
        int g=native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),known[n].guest,
                                   UINT64_C(0x300000000),rd,0,rel,0);
        CHECK(g>=0 && ns.index[known[n].start]==g+1 && native_shared_free(&ns,g,rel,0));
    }
    uint64_t live=ns.live,errors=ns.errors,created=ns.created;
    unsigned want=NATIVE_SHARED_GROUPS-(unsigned)live;
    int *made=calloc(want,sizeof(int));
    for(unsigned n=0;n<want;n++) {
        made[n]=native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),EMPTY+((uint64_t)n<<14),
                                     UINT64_C(0x200000000)+((uint64_t)n<<25),rd,0,rel,0);
        CHECK(made[n]>=0);
    }
    CHECK(ns.live==NATIVE_SHARED_GROUPS && ns.created==created+want && ns.errors==errors && want>512);
    CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),EMPTY+((uint64_t)want<<14),
                               UINT64_C(0x200000000)+((uint64_t)want<<25),rd,0,rel,0)<0);
    CHECK(ns.full==1 && ns.errors==errors);
    for(unsigned n=0;n<want;n++)CHECK(native_shared_find(&ns,EMPTY+((uint64_t)n<<14))==made[n]);
    /* Free a pseudo-random half; every survivor stays findable, every freed one is gone. */
    srand(11);
    unsigned *order=calloc(want,sizeof(unsigned));
    for(unsigned n=0;n<want;n++)order[n]=n;
    for(unsigned n=want-1;n>0;n--) {unsigned k=(unsigned)rand()%(n+1),t=order[n];order[n]=order[k];order[k]=t;}
    for(unsigned n=0;n<want/2;n++)CHECK(native_shared_free(&ns,made[order[n]],rel,0));
    for(unsigned n=0;n<want;n++) {
        int gone=0;
        for(unsigned m=0;m<want/2 && !gone;m++)gone=order[m]==n;
        CHECK(native_shared_find(&ns,EMPTY+((uint64_t)n<<14))==(gone ? -1 : made[n]));
    }
    /* Freed records are reused; the index keeps finding every group. */
    for(unsigned n=0;n<want/2;n++)
        CHECK(native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),EMPTY+((uint64_t)order[n]<<14),
                                   UINT64_C(0x200000000)+((uint64_t)order[n]<<25),rd,0,rel,0)>=0);
    for(unsigned n=0;n<want;n++) {
        int g=native_shared_find(&ns,EMPTY+((uint64_t)n<<14));
        CHECK(g>=0 && ns.group[g].guest==EMPTY+((uint64_t)n<<14) && native_shared_verify(&ns,&group_writer,g,rd,0));
    }
    for(unsigned n=0;n<want;n++)CHECK(native_shared_free(&ns,native_shared_find(&ns,EMPTY+((uint64_t)n<<14)),rel,0));
    CHECK(ns.live==live && !released);
    free(order);free(made);
}

/* Long probe clusters, one wrapping past the index's end: deleting from the
 * middle must keep every later member findable (backward shift). */
static void test_index_clusters(void)
{
    enum {WANT=160};
    static uint64_t guests[WANT];static int made[WANT];
    for(unsigned window=0;window<2;window++) {
        unsigned start=window ? NATIVE_SHARED_INDEX-24 : 700,n=0;
        for(uint64_t pa=EMPTY;n<WANT && pa<EMPTY+EMPTY_SIZE;pa+=16384) {
            /* The probe start, as tools/native_shared_audit.py computes it. */
            unsigned h=(unsigned)(((pa>>14)*UINT64_C(0x9e3779b97f4a7c15))>>51)&(NATIVE_SHARED_INDEX-1);
            if(((h-start)&(NATIVE_SHARED_INDEX-1))<48)guests[n++]=pa;
        }
        CHECK(n==WANT);
        uint64_t live=ns.live;
        for(unsigned i=0;i<WANT;i++) {
            made[i]=native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guests[i],
                                         UINT64_C(0x400000000)+((uint64_t)i<<25),rd,0,rel,0);
            CHECK(made[i]>=0);
        }
        for(unsigned round=0;round<3;round++) {
            for(unsigned i=round;i<WANT;i+=3)CHECK(native_shared_free(&ns,made[i],rel,0));
            for(unsigned i=0;i<WANT;i++)
                CHECK(native_shared_find(&ns,guests[i])==(i%3==round ? -1 : made[i]));
            for(unsigned i=round;i<WANT;i+=3) {
                made[i]=native_shared_create(&ns,&group_writer,UINT64_C(0x81234c000),guests[i],
                                             UINT64_C(0x400000000)+((uint64_t)i<<25),rd,0,rel,0);
                CHECK(made[i]>=0);
            }
            for(unsigned i=0;i<WANT;i++)CHECK(native_shared_find(&ns,guests[i])==made[i]);
        }
        for(unsigned i=0;i<WANT;i++)CHECK(native_shared_free(&ns,made[i],rel,0));
        CHECK(ns.live==live && !released);
    }
}

static void test_unlink_forget_free(void)
{
    int g0=native_shared_find(&ns,guest_of[0]),g1=native_shared_find(&ns,guest_of[1]);
    /* Root 2 links both; its tables beside the groups are its own. */
    roots[2]=new_root();
    CHECK(native_shared_link(&ns,&roots[2],2,g0) && native_shared_link(&ns,&roots[2],2,g1));
    CHECK(root_matches(&roots[2],g0) && root_matches(&roots[2],g1));
    /* A commit without allocation links only into existing tables. */
    struct shadow fixed=roots[3]=new_root();fixed.alloc=no_alloc;
    CHECK(!native_shared_link(&ns,&fixed,3,g0) && links(&ns,g0)==3);
    uint64_t table;
    CHECK(!shadow_table(&roots[3],2,va_of[0],&table));
    CHECK(native_shared_link(&ns,&fixed,3,g0) && links(&ns,g0)==4 && root_matches(&roots[3],g0));
    /* Unlink: only a slot that links, and only while its entries name the group. */
    CHECK(!native_shared_unlink(&ns,&roots[1],3,g1) && !native_shared_unlink(&ns,&roots[0],3,g1));
    CHECK(native_shared_unlink(&ns,&roots[1],1,g0) && links(&ns,g0)==3 && unmapped(&roots[1],va_of[0]));
    CHECK(!native_shared_slot_links(&ns,1,g0) && root_matches(&roots[0],g0));
    CHECK(!native_shared_unlink(&ns,&roots[1],1,g0));
    uint64_t saved=word(table+8*mmu_index(12,2,va_of[0]));
    wr(0,table+8*mmu_index(12,2,va_of[0]),0);
    CHECK(!native_shared_unlink(&ns,&roots[3],3,g0) && links(&ns,g0)==3);
    wr(0,table+8*mmu_index(12,2,va_of[0]),saved);
    /* Freeing waits for every link; a released slot gives its links back. */
    CHECK(!native_shared_free(&ns,g0,rel,0) && released==0);
    CHECK(native_shared_forget_slot(&ns,2) && !native_shared_slot_links(&ns,2,g0) && !native_shared_slot_links(&ns,2,g1));
    CHECK(links(&ns,g0)==2 && links(&ns,g1)==2);
    CHECK(native_shared_unlink(&ns,&roots[0],0,g1) && native_shared_unlink(&ns,&roots[1],1,g1));
    CHECK(native_shared_free(&ns,g1,rel,0) && released==2 && native_shared_find(&ns,guest_of[1])<0);
    CHECK(native_shared_unlink(&ns,&roots[0],0,g0) && native_shared_unlink(&ns,&roots[3],3,g0));
    CHECK(native_shared_free(&ns,g0,rel,0) && released==18 && ns.live==0);
    CHECK(!native_shared_verify(&ns,&group_writer,g0,rd,0) && !native_shared_store(&ns,&group_writer,g0,va_of[0],0));
}

int main(void)
{
    mem=calloc(1,SIZE);if(!mem)return 2;
    next_page=BASE;
    test_create_and_translate();test_stores();test_refused_create();test_lazy_pages();
    test_capacity_and_index();test_index_clusters();test_unlink_forget_free();
    printf("%s: %u native-shared checks, %u failures\n",failures ? "FAIL":"PASS",checks,failures);
    free(mem);return failures!=0;
}
