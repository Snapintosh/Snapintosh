/* SPDX-License-Identifier: MIT */
#pragma once
#include "shadow.h"
#include "sprr-table-memo.h"
#include "../compat/sprr.h"

/* Sparse private copies of a canonical kernel shadow. The caller prepares
 * every newly protected path, then syncs/publishes/invalidates those copies
 * before installing a selector2 leaf in the canonical tree. Ordinary
 * mappings keep sharing canonical tables; copied paths are refreshed after
 * every canonical mutation, before publication/TLBI and guest resumption.
 *
 * This is the table part of the transaction only. The caller owns the global
 * service lock, cache publication, architectural invalidation and register
 * commit. A failing write callback is terminal: never resume a partial sync.
 * alloc must return fresh, zeroed pages that cannot alias any source table. */
#define SPRR_VIEW_CPUS 6u
/* SNAP_VIEW_RECLAIM (opt-in; cycle.py installed-fresh --view-reclaim): the
 * pool holds 256 tables instead of 128, and sprr_views_reclaim gives back the
 * kernel copies no protected leaf needs any more. Off, every layout and the
 * monitor are unchanged.
 *
 * Why: installed-fresh-desktop-20261024-next1 stopped after 1,104 s (exit 7,
 * RETYPE to ROZONE refused) when its kernel views held 128 tables: 1 + 1 + 8
 * upper and 118 level-3 copies. Its context shows 114 of those 118 still held
 * selector2 leaves (122 ROZONE protects, 3 releases: each 16K RO-zone frame
 * lands in its own 2 MiB table), so the live set itself had reached the pool.
 * In the 86 preserved installed-fresh runs of 6 minutes or more, releases
 * stayed at 2 to 8 while protects reached 122 (OBSERVED, context.bin).
 * Reclaim covers released frames and TXM imports; the wider pool covers the
 * live set. */
#ifndef SNAP_VIEW_RECLAIM
#define SNAP_VIEW_RECLAIM 0
#endif
#if SNAP_VIEW_RECLAIM
#define SPRR_VIEW_TABLES 256u
#else
#define SPRR_VIEW_TABLES 128u
#endif
/* A bounded, read-only mapping of an entire canonical 4K table. The backend
 * validates the allocation span and keeps the bytes and mapping stable under
 * the service token through preflight and commit. No pointer is retained. */
typedef const volatile uint64_t *(*sprr_table_reader)(void *,uint64_t);
typedef sprr_table_reader sprr_user_table_reader;
struct sprr_view_table {
    uint64_t source, copy[SPRR_VIEW_CPUS], level;
};
/* tables[0..count) are the copied tables, the root first. With
 * SNAP_VIEW_RECLAIM, entries past count may hold the pages of retired tables
 * (source 0) or of a failed add, kept for the next add at that position. */
struct sprr_views {
    uint64_t canonical_root, count;
    uint64_t syncs[SPRR_VIEW_CPUS];
    struct sprr_view_table tables[SPRR_VIEW_TABLES];
};

/* State must initially be zero. No visible table is modified by init/prepare;
 * allocations may be retained on failure. Sync before installing the roots. */
int sprr_views_init(struct sprr_views *, const struct shadow *);
int sprr_views_prepare(struct sprr_views *, const struct shadow *, uint64_t va);
uint64_t sprr_views_root(const struct sprr_views *, unsigned cpu);
#if SNAP_VIEW_RECLAIM
/* Kernel views only: the selector2/4 decode of sprr_views_sync_cpu*, never
 * a user view, a native view or views carrying an sprr_view_memo (whose
 * claims assume append-only metadata).
 *
 * A copy is needed while some leaf under it translates differently from its
 * raw descriptor on some CPU under some PPERM: a valid selector2 or selector4
 * leaf (selector9, which a sync refuses, is kept too), or an upper-level entry
 * leading to a needed copy. Every other copied table is retired; the root
 * never is. Kept tables move to the front in their order, so positions change.
 *
 * Order: every source is read before anything changes (a read failure or an
 * unconfigured view returns -1 unchanged; nothing to retire returns 0
 * unchanged). Then the metadata is compacted: a retired table's six pages wait
 * past count with source 0 and level SPRR_VIEW_RETIRED. quiesce(ctx) must drop
 * every record kept by table position (reuse snapshot, publication rows), sync
 * every CPU's copies -- a retired table's parent entries then name its
 * canonical source again, which translates identically -- publish them and
 * complete a broadcast invalidation of every EL1&0 translation (TLBI
 * ALLE1IS, every VMID) before it returns 1. Only
 * then do the pages become reusable (level 0): the next add() at that position
 * takes them instead of allocating, and its sync rewrites every word before a
 * parent links them. Returns the number retired, or -1 after a failed quiesce
 * (terminal, as a failed sync: the views hold only kept tables and the
 * retired pages are never reused). Caller holds the service lock throughout. */
#define SPRR_VIEW_RETIRED 4u
int sprr_views_reclaim(struct sprr_views *,const struct shadow *,int (*quiesce)(void *),void *ctx);
#endif
/* Translate selector2 A/B. Selector9 2/3 state is accepted only with the
 * caller's proof that the canonical/user views contain no affected leaves;
 * mutation paths must retain that exclusion. This is not a general SPRR MMU. */
int sprr_views_sync_cpu(struct sprr_views *, const struct shadow *, unsigned cpu,
                        uint64_t pperm);
/* Same validation and child-before-parent stores. NULL uses the per-word
 * reference implementation; independent verification always uses shadow.read. */
int sprr_views_sync_cpu_mapped(struct sprr_views *,const struct shadow *,unsigned cpu,
                               uint64_t pperm,sprr_table_reader);
/* Optional destination comparison for callbacks whose equal-value stores have
 * no required side effects. Both mappings remain stable under the service
 * token. Every source descriptor is still preflighted; changed values use the
 * ordinary write callback in child-before-parent order. No cache is retained. */
struct sprr_store_compare_stats {
    uint64_t calls,complete,tables,compared,skipped,changed,failures;
};
int sprr_views_sync_cpu_compared(struct sprr_views *,const struct shadow *,unsigned cpu,
    uint64_t pperm,sprr_table_reader source,sprr_table_reader destination,
    struct sprr_store_compare_stats *);
/* Read-only differential check of every installed private descriptor. */
int sprr_views_verify_cpu(struct sprr_views *,const struct shadow *,unsigned cpu,
                          uint64_t pperm);
#if SNAP_UPDATE_DISJOINT_FAST
/* compat/update-fast.h: sprr_views_verify_cpu for every CPU, in one pass. */
int sprr_views_verify_all(struct sprr_views *,const struct shadow *,
                          const uint64_t pperm[SPRR_VIEW_CPUS]);
#endif
#if SNAP_MULTIPAGE_FAST
/* probes/xnuboot.c multipage_view_patch (agents/sptm-locks/multipage, P7):
 * the copied table holding the word at pa: its index, -1 when pa's page is no
 * copy source, -2 for a level 0-2 copy (not patched: the caller's refresh
 * must sync in full). */
int sprr_views_word_table(const struct sprr_views *,uint64_t pa);
/* Word index of copied level-3 table n, already changed in the canonical
 * table, written into every CPU's copy exactly as a full sync writes it
 * (commit_cpu's entry() under pperm[cpu]) and, where extra[cpu] is a page,
 * into that page under extra_pperm[cpu] (a PPERM variant column, P19). Every
 * store is preflighted before the first; stores go through s->write. 0 is a
 * refusal a full sync would make for the same word, or a failed store
 * (terminal, as a failed sync). */
int sprr_views_sync_word(struct sprr_views *,const struct shadow *,unsigned n,unsigned index,
                         const uint64_t pperm[SPRR_VIEW_CPUS],const uint64_t extra[SPRR_VIEW_CPUS],
                         const uint64_t extra_pperm[SPRR_VIEW_CPUS]);
#endif
/* Inspect every canonical branch, including shared paths and block mappings.
 * A successful read-only proof excludes all forbidden classes. Mutation paths
 * must preserve this exclusion until translated support for them exists. */
struct sprr_view_classes {uint64_t tables,pages,classes;};
/* The class walks' table-visit limit. SNAP_CLASS_PROOF_WIDE raises it from
 * 8,192 to the monitor arena's page count (SPRR_CLASS_PROOF_PAGES, where every
 * walked table lives): installed-fresh-20261020-v3's kernel shadow reached
 * 8,192 tables and its next TPRO class proof was refused. */
#ifndef SNAP_CLASS_PROOF_WIDE
#define SNAP_CLASS_PROOF_WIDE 0
#endif
#if SNAP_CLASS_PROOF_WIDE
#define SPRR_CLASS_WALK_TABLES 61440
#else
#define SPRR_CLASS_WALK_TABLES 8192
#endif
int sprr_views_check_classes(const struct shadow *,uint64_t forbidden,
                             struct sprr_view_classes *);
/* Identical proof and failure set, reading each table through one bounded
 * mapping (shadow.ctx is passed to read_table; shadow.read is unused). The
 * mapping must stay stable under the service token for the whole walk. walk
 * counters accumulate only for a completed proof. */
struct sprr_class_walk_stats {uint64_t tables,groups,empty_groups;};
int sprr_views_check_classes_mapped(const struct shadow *,uint64_t forbidden,
    struct sprr_view_classes *,sprr_table_reader,struct sprr_class_walk_stats *);

/* User canonical shadows retain Apple descriptors and are never installed.
 * Prepare every selector9 branch after any canonical mutation, then sync all
 * affected CPU views before releasing the service token. The sync verifies
 * complete private coverage independently, including shared source branches.
 * On an EL0/EL1 boundary, sync the requesting CPU and publish/TLBI before
 * resuming it: ordinary Arm AP cannot encode EL0 RW with EL1 RO at once.
 * el0 must describe the regime about to execute, not the trap handler's EL.
 * The caller must intercept every user-to-kernel entry before its first
 * instruction and every kernel-to-user return. Register commit follows sync.
 * Neither this API nor successful host tests install that boundary handling. */
int sprr_views_prepare_user(struct sprr_views *,const struct shadow *);
/* Reserve a private path while its canonical leaf is still absent. Sync and
 * publish every CPU copy, then invalidate, BEFORE publishing a new raw class9
 * leaf. Otherwise a running CPU could reach it through a shared branch. */
int sprr_views_prepare_user_leaf(struct sprr_views *,const struct shadow *,uint64_t va);
int sprr_views_sync_user_cpu(struct sprr_views *,const struct shadow *,unsigned cpu,
                            const struct sprr_state *,int el0);
/* Equivalent views for all CPUs with one common canonical-coverage walk.
 * The caller must hold the same service lock across the entire operation;
 * source tables and control states must remain stable. Every CPU's descriptor
 * preflight completes before any private view is written. Publication and
 * architectural invalidation remain the caller's responsibility. */
int sprr_views_sync_user_all(struct sprr_views *,const struct shadow *,
                            const struct sprr_state states[SPRR_VIEW_CPUS],
                            const int el0[SPRR_VIEW_CPUS]);
/* Same transaction and six results, with one shared source decode per entry.
 * Every CPU's state and output-copy address is checked before any write. */
int sprr_views_sync_user_fused(struct sprr_views *,const struct shadow *,
                              const struct sprr_state states[SPRR_VIEW_CPUS],
                              const int el0[SPRR_VIEW_CPUS]);
/* Transaction-local workspace, never a cross-transaction cache. One complete
 * validation walk records every source page and the union of paths needing
 * private copies. The caller owns this workspace under the service lock; it
 * must not alias sources, private copies, views or control state. Allocation
 * still returns fresh zeroed non-aliasing pages. No canonical stores or
 * callback-driven metadata changes are permitted during this transaction. */
struct sprr_user_prepare_path {uint64_t source,level;};
struct sprr_user_prepare_plan {
    uint64_t root,source_count,required_count;
    struct sprr_user_prepare_path required[SPRR_VIEW_TABLES];
    uint64_t sources[8192];
};
struct sprr_user_prepare_stats {
    uint64_t calls,successes,verified,mismatches,failures,source_tables,private_tables;
};
/* Prepare plus all-CPU synchronization, retaining whole-tree validation and
 * every private descriptor check. Every 64th call independently repeats the
 * coverage walk before commit; failed validation never repairs a view. */
int sprr_views_prepare_sync_user_fused(struct sprr_views *,const struct shadow *,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *,struct sprr_user_prepare_stats *);
/* Optional bounded, read-only mapping of one entire canonical 4K table.
 * The caller must keep those exact bytes stable under the same service token
 * throughout the walk. Every descriptor is still loaded and validated; the
 * sampled independent coverage walk always uses shadow.read instead. NULL
 * selects the original per-word callback path. No pointer survives this call. */
int sprr_views_prepare_sync_user_mapped(struct sprr_views *,const struct shadow *,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *,struct sprr_user_prepare_stats *,sprr_user_table_reader);
/* A group is empty only after all eight volatile words have been loaded and
 * their bitwise OR is zero. Nonempty groups retain the per-descriptor path.
 * Counters cover completed table scans; failed transactions remain terminal.
 * Counter storage must not alias the immutable source or transaction state. */
struct sprr_user_zero_stats {uint64_t groups,empty_groups;};
int sprr_views_prepare_sync_user_grouped(struct sprr_views *,const struct shadow *,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *,struct sprr_user_prepare_stats *,sprr_user_table_reader,
    struct sprr_user_zero_stats *);
/* Same full walk, sampled independent coverage, allocation and six-CPU
 * preflight. Map private-path sources once and compare all six destinations
 * before invoking idempotent write callbacks. tables counts destination
 * pages, i.e. six per prepared private source table. The source/destination
 * reader contract and equal-value callback restriction above still apply. */
int sprr_views_prepare_sync_user_compared(struct sprr_views *,const struct shadow *,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *,struct sprr_user_prepare_stats *,sprr_user_table_reader,
    struct sprr_user_zero_stats *,sprr_table_reader source,sprr_table_reader destination,
    struct sprr_store_compare_stats *);

/* A coverage proof is valid only while the caller's shadow-write epoch is
 * unchanged. Advance it before every canonical descriptor change, table
 * allocation and recycling; private writes may conservatively advance it too.
 * Saturation disables reuse permanently, preventing an old epoch from aliasing.
 * Hold the service lock throughout validation, sync and proof renewal. */
struct sprr_view_proof { uint64_t root,count,epoch,valid; };
struct sprr_view_proof_stats { uint64_t calls,hits,verified,mismatches; };
static inline void sprr_view_epoch_advance(uint64_t *epoch)
{ if(*epoch!=UINT64_MAX)(*epoch)++; }
#if SNAP_FINE_LOCKS
#include "../compat/fine-lock.h"
static inline void sprr_view_epoch_advance_fine(uint64_t *epoch)
{ fine_sat_add(epoch,1,UINT64_MAX); }
#endif
int sprr_views_sync_user_cached(struct sprr_views *,const struct shadow *,unsigned cpu,
    const struct sprr_state *,int el0,uint64_t *epoch,struct sprr_view_proof *,
    struct sprr_view_proof_stats *,int verify);
int sprr_views_sync_user_cached_mapped(struct sprr_views *,const struct shadow *,unsigned cpu,
    const struct sprr_state *,int el0,uint64_t *epoch,struct sprr_view_proof *,
    struct sprr_view_proof_stats *,int verify,sprr_table_reader);
int sprr_views_sync_user_cached_compared(struct sprr_views *,const struct shadow *,unsigned cpu,
    const struct sprr_state *,int el0,uint64_t *epoch,struct sprr_view_proof *,
    struct sprr_view_proof_stats *,int verify,sprr_table_reader source,
    sprr_table_reader destination,struct sprr_store_compare_stats *);

/* Exact cross-transaction claims for the two compared user paths above
 * (SNAP_USER_TREE_MEMO). The arena witness in sprr-table-memo.h must see every
 * change to every source and private page; the caller notes pages before any
 * store, allocation zeroing or writable mapping, under the same service lock.
 *
 * All-CPU transaction: a level3 source whose summary is current contributes its
 * recorded class9/zero-group result instead of being rescanned; every other
 * table (all upper levels) is scanned exactly as before, and every per-table
 * bound, alias, cycle and mapping check still runs. A private table whose
 * source and copy pages are unchanged since the CPU's stamp, under unchanged
 * view metadata and an unchanged class9 key (or with no class9 leaf), already
 * holds the translation: its preflight and equal-value compare are elided.
 * One-CPU cached sync: the same destination claim for that CPU only.
 *
 * Results, stores, failures, allocation and all existing counters are those of
 * the compared paths; elided entries count as compared and skipped. Every
 * SPRR_TABLE_MEMO_SAMPLE-th transaction uses no claim, recomputes everything,
 * and fails without repair if any claim it would have used is wrong. The view
 * memo must start zeroed and be zeroed again whenever the views are reset. */
struct sprr_view_memo {
    uint64_t root, count, valid;
    uint64_t stamp[SPRR_VIEW_CPUS], key[SPRR_VIEW_CPUS];
    uint64_t has9[SPRR_VIEW_TABLES/64];
};
int sprr_views_prepare_sync_user_memo(struct sprr_views *,const struct shadow *,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *,struct sprr_user_prepare_stats *,sprr_user_table_reader,
    struct sprr_user_zero_stats *,sprr_table_reader source,sprr_table_reader destination,
    struct sprr_store_compare_stats *,struct sprr_table_memo *,struct sprr_view_memo *);
int sprr_views_sync_user_cached_memo(struct sprr_views *,const struct shadow *,unsigned cpu,
    const struct sprr_state *,int el0,uint64_t *epoch,struct sprr_view_proof *,
    struct sprr_view_proof_stats *,int verify,sprr_table_reader source,
    sprr_table_reader destination,struct sprr_store_compare_stats *,
    struct sprr_table_memo *,struct sprr_view_memo *);
