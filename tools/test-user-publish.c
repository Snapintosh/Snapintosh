/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shadow/user-publish.h"

static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
/* Twice the largest selection plus one: USER_PUBLISH_MAX distinct private
 * pages always fit after the three runtime pages. */
#define PAGES (2u*USER_PUBLISH_MAX+1u)
#define BASE UINT64_C(0xae1400000)
#define END (BASE+(uint64_t)PAGES*4096)
static struct root_publish_state dirty;
static struct sprr_private_pages private;
static struct user_publish_stats stats;
static unsigned char cpu[PAGES*4096],bus[PAGES*4096],reference[PAGES*4096];
static uint64_t pages[USER_PUBLISH_MAX],saved[ROOT_PUBLISH_PAGES/64];
static unsigned callbacks,fail_at;
static uint64_t seed=UINT64_C(0x546def16bc4a8e37);
static unsigned random32(void)
{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return (unsigned)seed;}
static int publish(void *ctx,uint64_t pa)
{
    (void)ctx;CHECK(!(pa&4095) && pa>=BASE && pa<END);callbacks++;
    if(fail_at && callbacks==fail_at)return 0;
    memcpy(bus+(pa-BASE),cpu+(pa-BASE),4096);return 1;
}
static void reset(void)
{
    memset(&dirty,0,sizeof(dirty));memset(&private,0,sizeof(private));
    memset(&stats,0,sizeof(stats));callbacks=fail_at=0;
    memset(cpu,0,sizeof(cpu));memset(bus,0,sizeof(bus));
    dirty.always_first=BASE;dirty.always_end=BASE+3*4096;
    for(unsigned i=3;i<PAGES-1;i++)CHECK(sprr_private_mark(&private,i));
}
static void full(void)
{
    callbacks=0;CHECK(root_publish_flush(&dirty,BASE,END,publish,0));
    CHECK(!memcmp(cpu,bus,sizeof(cpu)));
}
static void model(void)
{
    reset();memset(cpu,0x6a,sizeof(cpu));
    CHECK(root_publish_note(&dirty,BASE,END,BASE,sizeof(cpu)));full();
    for(unsigned turn=0;turn<1200;turn++) {
        for(unsigned n=0;n<19;n++) {
            unsigned offset=random32()%sizeof(cpu);
            CHECK(root_publish_note(&dirty,BASE,END,BASE+offset,1));
            cpu[offset]=(unsigned char)random32();
        }
        /* Runtime writes have no table callback and require full-root cleaning. */
        memset(cpu,(int)(turn&255),3*4096);
        unsigned count=turn%3 ? USER_PUBLISH_MAX:1;
        unsigned start=random32()%(PAGES-4);
        for(unsigned n=0;n<count;n++)pages[n]=BASE+(3+(start+n)%(PAGES-4))*4096;
        memcpy(reference,bus,sizeof(bus));
        for(unsigned n=0;n<count;n++)memcpy(reference+(pages[n]-BASE),cpu+(pages[n]-BASE),4096);
        memcpy(saved,dirty.bitmap,sizeof(saved));callbacks=0;
        CHECK(user_publish_flush(&dirty,&private,&stats,BASE,END,pages,count,publish,0));
        CHECK(!memcmp(bus,reference,sizeof(bus)));
        CHECK(stats.calls==stats.complete && !stats.errors && !dirty.errors);
        CHECK(stats.considered==stats.published+stats.skipped);
        for(unsigned n=0;n<count;n++) {
            unsigned i=(unsigned)((pages[n]-BASE)/4096);
            saved[i/64]&=~(UINT64_C(1)<<(i%64));
        }
        CHECK(!memcmp(saved,dirty.bitmap,sizeof(saved)));
        /* A second publication without stores must issue no cache operation. */
        callbacks=0;
        CHECK(user_publish_flush(&dirty,&private,&stats,BASE,END,pages,count,publish,0));
        CHECK(!callbacks);
        if(turn%7==0)full();
    }
    full();CHECK(stats.skipped>stats.published);
    /* Reuse must re-note zeroing even when this physical page was clean. */
    CHECK(sprr_private_clear(&private,9,1));CHECK(sprr_private_clear(&private,9,0));
    CHECK(root_publish_note(&dirty,BASE,END,BASE+9*4096,4096));
    memset(cpu+9*4096,0,4096);CHECK(sprr_private_mark(&private,9));
    pages[0]=BASE+9*4096;callbacks=0;
    CHECK(user_publish_flush(&dirty,&private,&stats,BASE,END,pages,1,publish,0));
    CHECK(callbacks==1 && !memcmp(cpu+9*4096,bus+9*4096,4096));
}
static void rejected(void)
{
    for(unsigned which=0;which<12;which++) {
        reset();pages[0]=BASE+3*4096;pages[1]=BASE+4*4096;
        unsigned count=2;uint64_t first=BASE,end=END;
        CHECK(root_publish_note(&dirty,BASE,END,BASE,sizeof(cpu)));
        if(which==0)pages[1]++;
        if(which==1)pages[1]=BASE-4096;
        if(which==2)pages[1]=END;
        if(which==3)pages[1]=pages[0];
        if(which==4)pages[1]=BASE+(PAGES-1)*4096; /* canonical page */
        if(which==5){private.bitmap[0]|=1;pages[1]=BASE;} /* runtime even if mislabeled */
        if(which==6)count=0;
        if(which==7)count=USER_PUBLISH_MAX+1;
        if(which==8)first++;
        if(which==9)end++;
        memcpy(saved,dirty.bitmap,sizeof(saved));
        CHECK(!user_publish_flush(&dirty,&private,&stats,first,end,
            which==10 ? 0:pages,count,which==11 ? 0:publish,0));
        CHECK(!callbacks && !stats.complete && stats.errors==1 && dirty.errors==1);
        CHECK(!memcmp(saved,dirty.bitmap,sizeof(saved)));
        CHECK(!user_publish_flush(&dirty,&private,&stats,BASE,END,pages,1,publish,0));
    }
    reset();pages[0]=BASE+3*4096;pages[1]=BASE+4*4096;
    CHECK(root_publish_note(&dirty,BASE,END,BASE+3*4096,2*4096));
    memcpy(saved,dirty.bitmap,sizeof(saved));fail_at=2;
    CHECK(!user_publish_flush(&dirty,&private,&stats,BASE,END,pages,2,publish,0));
    CHECK(callbacks==2 && !stats.complete && stats.errors==1 && dirty.errors==1);
    CHECK(!memcmp(saved,dirty.bitmap,sizeof(saved)));
    CHECK(!root_publish_flush(&dirty,BASE,END,publish,0));CHECK(callbacks==2);
    for(unsigned which=0;which<3;which++) {
        reset();pages[0]=BASE+3*4096;
        if(which==0)stats.errors=1;
        if(which==1)dirty.errors=1;
        if(which==2)private.errors=1;
        CHECK(!user_publish_flush(&dirty,&private,&stats,BASE,END,pages,1,publish,0));
        CHECK(!stats.calls && !callbacks);
    }
}
static int edge_publish(void *ctx,uint64_t pa)
{
    (void)ctx;
    CHECK(!(pa&4095) && pa>=BASE && pa<BASE+(uint64_t)ROOT_PUBLISH_PAGES*4096);
    callbacks++;return 1;
}
static void edges(void)
{
    reset();uint64_t end=BASE+(uint64_t)ROOT_PUBLISH_PAGES*4096;
    for(unsigned start=0;start<ROOT_PUBLISH_PAGES;start+=USER_PUBLISH_MAX) {
        memset(private.bitmap,0,sizeof(private.bitmap));
        dirty.always_first=dirty.always_end=0;
        for(unsigned n=0;n<USER_PUBLISH_MAX;n++) {
            unsigned i=start+n;pages[n]=BASE+(uint64_t)i*4096;
            CHECK(sprr_private_mark(&private,i));
            CHECK(root_publish_note(&dirty,BASE,end,pages[n]+4095,1));
        }
        callbacks=0;
        CHECK(user_publish_flush(&dirty,&private,&stats,BASE,end,pages,USER_PUBLISH_MAX,edge_publish,0));
        CHECK(callbacks==USER_PUBLISH_MAX);
    }
    CHECK(stats.considered==ROOT_PUBLISH_PAGES && stats.published==ROOT_PUBLISH_PAGES);
    for(unsigned w=0;w<ROOT_PUBLISH_PAGES/64;w++)CHECK(!dirty.bitmap[w]);
}
int main(void)
{
    model();rejected();edges();printf("user publication: %u checks, 0 failures\n",checks);return 0;
}
