/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Exact change witness for the monitor's 4K table arena (SNAP_USER_TREE_MEMO).
 *
 * One word per arena page: bits 63..16 hold the page's write generation, the
 * value of the arena clock when the page was last noted; bits 15..0 hold a
 * content summary owned by the user-view walker. The owner must note a page
 * before any byte of it can change by any path (descriptor store, allocator
 * zeroing, mapped-pointer transaction), and note it as allocated whenever the
 * table allocator hands it out. Only allocator-issued pages are eligible, so
 * directly carved monitor storage is never summarized or trusted. A note never
 * makes a stale claim current: it advances the clock and clears the summary.
 * Clock saturation permanently disables every claim. The caller serializes all
 * notes, walks and syncs under one service lock; no claim survives a note. */
#include "../compat/monitor-arena.h"
#define SPRR_TABLE_MEMO_PAGES MONITOR_ARENA_PAGES
#define SPRR_TABLE_MEMO_POOL  UINT64_C(0x8000) /* issued by the table allocator */
#define SPRR_TABLE_MEMO_SCAN  UINT64_C(0x4000) /* summary describes current bytes */
#define SPRR_TABLE_MEMO_HAS9  UINT64_C(0x0004) /* at least one class9 leaf */
#define SPRR_TABLE_MEMO_LEVEL UINT64_C(0x0003) /* level the summary was taken at */
#define SPRR_TABLE_MEMO_EMPTY_SHIFT 3          /* 7 bits: empty eight-word groups */
#define SPRR_TABLE_MEMO_CLOCK_MAX ((UINT64_C(1)<<48)-1)
/* A transaction whose ordinal is a multiple of this recomputes everything and
 * checks every claim it would otherwise have used. Setting force makes the next
 * memo transaction do the same (for callers verifying their own no-op proofs). */
#define SPRR_TABLE_MEMO_SAMPLE 64u

struct sprr_table_memo_stats {
    uint64_t calls;       /* memo transactions: all-CPU refreshes and one-CPU syncs */
    uint64_t samples;     /* transactions fully recomputed against their claims */
    uint64_t checked;     /* individual claims verified by those samples */
    uint64_t mismatches;  /* claims contradicted by recomputation (must stay zero) */
    uint64_t scan_hits;   /* refresh (pass3) level3 scans replaced by a summary */
    uint64_t scan_misses; /* refresh (pass3) level3 scans performed */
    uint64_t copy_hits;   /* private destination pages proven current, not compared */
    uint64_t copy_misses; /* private destination pages decoded and compared */
    uint64_t notes;       /* page write notes (changed descriptors, mapped pages) */
    uint64_t allocations; /* allocator issues */
    uint64_t errors;      /* notes outside the arena or with a bad configuration */
    uint64_t walk_hits;   /* one-CPU proof-miss (pass2) level3 scans replaced */
    uint64_t walk_misses; /* one-CPU proof-miss (pass2) level3 scans performed */
    uint64_t forced;      /* claim-checking recomputations requested through force */
};
struct sprr_table_memo {
    uint64_t base, pages, clock, force;
    struct sprr_table_memo_stats stats;
    uint64_t page[SPRR_TABLE_MEMO_PAGES];
};

static inline int sprr_table_memo_usable(const struct sprr_table_memo *m)
{
    return m && m->pages && m->pages<=SPRR_TABLE_MEMO_PAGES && !(m->base&4095) &&
        m->clock<SPRR_TABLE_MEMO_CLOCK_MAX && !m->stats.errors;
}
static inline void sprr_table_memo_touch(struct sprr_table_memo *m,uint64_t pa,uint64_t keep)
{
    if(pa<m->base || (pa-m->base)/4096>=m->pages || m->pages>SPRR_TABLE_MEMO_PAGES) {
        /* Outside the arena nothing can be summarized, so nothing goes stale.
         * Count it: callers only note allocated table storage. */
        if(m->stats.errors!=UINT64_MAX)m->stats.errors++;
        return;
    }
    uint64_t *w=&m->page[(pa-m->base)/4096];
    if(m->clock<SPRR_TABLE_MEMO_CLOCK_MAX)m->clock++;
    *w=(m->clock<<16)|(*w&keep);
}
/* Before a changed descriptor store or a writable mapping of the page. */
static inline void sprr_table_memo_note(struct sprr_table_memo *m,uint64_t pa)
{
    sprr_table_memo_touch(m,pa,SPRR_TABLE_MEMO_POOL);
    if(m->stats.notes!=UINT64_MAX)m->stats.notes++;
}
#if SNAP_FINE_LOCKS
#include "../compat/fine-lock.h"
/* sprr_table_memo_note for a converted call: the global clock and counters
 * by atomic RMW (saturating as above); the page word belongs to the root
 * whose stripe the caller holds. */
static inline void sprr_table_memo_note_fine(struct sprr_table_memo *m,uint64_t pa)
{
    if(pa<m->base || (pa-m->base)/4096>=m->pages || m->pages>SPRR_TABLE_MEMO_PAGES) {
        fine_sat_add(&m->stats.errors,1,UINT64_MAX);
        return;
    }
    uint64_t clock=fine_sat_add(&m->clock,1,SPRR_TABLE_MEMO_CLOCK_MAX);
    uint64_t *w=&m->page[(pa-m->base)/4096];
    uint64_t old_w = __atomic_load_n(w, __ATOMIC_RELAXED), new_w;
    do {
        new_w = (clock << 16) | (old_w & SPRR_TABLE_MEMO_POOL);
    } while (!__atomic_compare_exchange_n(w, &old_w, new_w, 1, __ATOMIC_RELEASE, __ATOMIC_RELAXED));
    fine_sat_add(&m->stats.notes,1,UINT64_MAX);
}
#endif
/* Whenever the table allocator issues (and zeroes) the page. */
static inline void sprr_table_memo_alloc(struct sprr_table_memo *m,uint64_t pa)
{
    sprr_table_memo_touch(m,pa,0);
    if(pa>=m->base && (pa-m->base)/4096<m->pages && m->pages<=SPRR_TABLE_MEMO_PAGES)
        m->page[(pa-m->base)/4096]|=SPRR_TABLE_MEMO_POOL;
    if(m->stats.allocations!=UINT64_MAX)m->stats.allocations++;
}
