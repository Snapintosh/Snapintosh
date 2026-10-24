/* SPDX-License-Identifier: MIT */
#pragma once
#include "sprr-view.h"
_Static_assert((SPRR_VIEW_TABLES==128 || (SNAP_VIEW_RECLAIM && SPRR_VIEW_TABLES==256)) &&
               SPRR_VIEW_CPUS==6,"publication bitmap ABI");

/* Publication bookkeeping only: never skips descriptor validation or TLBI.
 * Caller holds the service lock, reports every changed private-copy store,
 * and completes a bit only AFTER publishing that whole page. View metadata
 * must be append-only and copies must not be recycled during this lifetime,
 * except across sprr_publish_reset (sprr_views_reclaim). */
struct sprr_publish_state {
    uint64_t root,count,pending[SPRR_VIEW_CPUS][SPRR_VIEW_TABLES/64];
    uint64_t writes,publishes,pages,flushed,skipped,errors;
};
static inline int sprr_publish_prepare(struct sprr_publish_state *p,const struct sprr_views *v)
{
    if(!v->canonical_root || (v->canonical_root&4095) || !v->count ||
       v->count>SPRR_VIEW_TABLES || p->count>v->count ||
       (p->root && p->root!=v->canonical_root) || (!p->root && p->count)) {
        p->errors++;return 0;
    }
    /* Fresh all-zero pages still contain allocator stores. Publish them even
     * if the following descriptor commit does not change a single word. */
    for(unsigned n=(unsigned)p->count;n<v->count;n++)
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
            p->pending[cpu][n/64]|=UINT64_C(1)<<(n%64);
    p->root=v->canonical_root;p->count=v->count;return 1;
}
static inline int sprr_publish_note(struct sprr_publish_state *p,const struct sprr_views *v,
                                   uint64_t address)
{
    if(address&7) {p->errors++;return 0;}
    if(!v->count)return 1;
    if(!sprr_publish_prepare(p,v))return 0;
    uint64_t page=address&~UINT64_C(4095);
    for(unsigned n=0;n<v->count;n++)for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if(v->tables[n].copy[cpu]==page) {
            p->pending[cpu][n/64]|=UINT64_C(1)<<(n%64);p->writes++;return 1;
        }
    return 1; /* A user private table or a canonical table is outside this set. */
}
static inline int sprr_publish_needed(const struct sprr_publish_state *p,unsigned cpu,unsigned n)
{
    return cpu<SPRR_VIEW_CPUS && n<p->count && n<SPRR_VIEW_TABLES &&
           !!(p->pending[cpu][n/64]&(UINT64_C(1)<<(n%64)));
}
static inline int sprr_publish_complete(struct sprr_publish_state *p,unsigned cpu,unsigned n)
{
    if(!sprr_publish_needed(p,cpu,n)) {p->errors++;return 0;}
    p->pending[cpu][n/64]&=~(UINT64_C(1)<<(n%64));p->flushed++;return 1;
}
/* No page of this CPU's copies waits for publication. */
static inline int sprr_publish_row_empty(const struct sprr_publish_state *p,unsigned cpu)
{
#if SNAP_VIEW_RECLAIM
    uint64_t any=0;
    for(unsigned w=0;w<SPRR_VIEW_TABLES/64;w++)any|=p->pending[cpu][w];
    return !any;
#else
    return !p->pending[cpu][0] && !p->pending[cpu][1];
#endif
}
#if SNAP_VIEW_RECLAIM
/* sprr_views_reclaim moved the tables: a pending bit would name another
 * page. Every row goes and the next prepare marks every remaining copy, so
 * the caller's next publication cleans all of them; a retired page is
 * rewritten and published again before any reuse links it. */
static inline void sprr_publish_reset(struct sprr_publish_state *p)
{
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        for(unsigned w=0;w<SPRR_VIEW_TABLES/64;w++)p->pending[cpu][w]=0;
    p->count=0;
}
#endif
