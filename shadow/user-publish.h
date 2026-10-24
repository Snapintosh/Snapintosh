/* SPDX-License-Identifier: MIT */
#pragma once
#include "root-publish.h"
#include "sprr-private-pages.h"

/* SPRR_VIEW_TABLES: one user view's copies at most (sprr-view.h). */
#if SNAP_VIEW_RECLAIM
#define USER_PUBLISH_MAX 256u
#else
#define USER_PUBLISH_MAX 128u
#endif
struct user_publish_stats {
    uint64_t calls, complete, considered, published, skipped, errors;
};

/* Same service token and dirty bitmap as root installation. Only allocation-
 * proven private pages may be selected. Validate the entire selection before
 * cleaning any page, and retain every bit if a callback fails. Clearing after
 * successful publication is safe across root switches: later stores/reuse
 * re-note the page. Runtime pages and canonical sources are never selected.
 * This changes cache maintenance only; mapping proofs and TLBI remain required. */
static inline int user_publish_flush(struct root_publish_state *dirty,
    const struct sprr_private_pages *private,struct user_publish_stats *stats,
    uint64_t first,uint64_t allocated,const uint64_t *pages,unsigned count,
    int (*publish_page)(void *,uint64_t),void *ctx)
{
    if(stats->errors || dirty->errors || private->errors)return 0;
    stats->calls++;
    if(!pages || !count || count>USER_PUBLISH_MAX || !publish_page ||
       !root_publish_geometry(first,allocated))goto fail;
    unsigned indices[USER_PUBLISH_MAX];uint64_t selected[USER_PUBLISH_MAX/64]={0};unsigned changed=0;
    for(unsigned n=0;n<count;n++) {
        uint64_t pa=pages[n];
        if((pa&4095) || pa<first || pa>=allocated)goto fail;
        unsigned i=(unsigned)((pa-first)/4096);uint64_t bit=UINT64_C(1)<<(i%64);
        if(!(private->bitmap[i/64]&bit) ||
           (pa>=dirty->always_first && pa<dirty->always_end))goto fail;
        for(unsigned prev=0;prev<n;prev++)if(indices[prev]==i)goto fail;
        indices[n]=i;
        if(dirty->bitmap[i/64]&bit) {selected[n/64]|=UINT64_C(1)<<(n%64);changed++;}
    }
    for(unsigned n=0;n<count;n++)
        if((selected[n/64]&(UINT64_C(1)<<(n%64))) && !publish_page(ctx,pages[n]))goto fail;
    for(unsigned n=0;n<count;n++) {
        unsigned i=indices[n];
        if(selected[n/64]&(UINT64_C(1)<<(n%64)))
            dirty->bitmap[i/64]&=~(UINT64_C(1)<<(i%64));
    }
    stats->complete++;stats->considered+=count;
    stats->published+=changed;stats->skipped+=count-changed;return 1;
fail:
    stats->errors++;dirty->errors++;return 0;
}
