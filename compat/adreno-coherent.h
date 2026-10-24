/* SPDX-License-Identifier: MIT */
/* IO-coherent CB0 mirror leaves (SNAP_ADRENO_COHERENT; ABI in compat/adreno-guest.h ADRENO_GUEST_COHERENT).
 *
 * Linux maps a cached-coherent Adreno buffer on glymur with AttrIndx 1 (MAIR 0xff) and SH inner shareable, and
 * then does no CPU cache maintenance for it. Whether the A16's interconnect really snoops GPU transactions is
 * disputed: the Linux DT marks the GPU SMMU dma-coherent, while the A16's ACPI IORT calls it non-coherent. So the
 * monitor proves it on this machine before the guest exists, and keeps today's leaves unless every iteration
 * passes.
 *
 * Self-test, at prepare, through the monitor-owned ring and the IB completion words every guest IB uses
 * (adreno_ib_ring_words: CACHE_CLEAN fences from BV then BR). The data moves by CP_MEMCPY of at most
 * ADRENO_COHERENT_COPY_MAX bytes per packet (a 4 MiB copy once hung the GPU) and by CP_MEM_WRITE.
 *  - CPU->GPU: the CPU writes a pattern with cacheable stores and does not clean. The GPU copies it, and the
 *    destination is read after an invalidate, so only the GPU's read of dirty CPU lines is under test. Stores write
 *    word k of every line for k = 0..15, so no line is written whole by consecutive stores (a write-streaming
 *    detector could send such lines past the caches).
 *  - GPU->CPU: the CPU primes the destination's lines (clean, holding poison), and the GPU copies a cleaned pattern
 *    over them. The CPU reads without invalidating, so only the invalidation of CPU lines by GPU writes is under
 *    test.
 *  - Detection power, from the PMU (PMU counter 0 counting L2D_CACHE_REFILL, 0x17, at EL2; Linux drives this CPU as a
 *    plain arm,armv8-pmuv3, glymur.dtsi). A case that reads back no stale word proves something only if the lines
 *    under test were in this CPU's caches when the GPU ran. Each case therefore counts three read passes:
 *      miss      a 4 KiB witness the GPU never touches, just cleaned and invalidated: at least
 *                ADRENO_COHERENT_COUNTS refills, so the counter counts this CPU's misses at EL2 at all;
 *      resident  the lines under test right after the stores (CPU->GPU) or the priming (GPU->CPU): at most
 *                ADRENO_COHERENT_SLACK refills, so the stores left dirty lines and the priming left clean ones;
 *      witness   the witness again after the job: at most ADRENO_COHERENT_SLACK, so nothing between the proof and
 *                the GPU's access (the ring, the doorbell, the poll) evicted this CPU's lines wholesale.
 *    A case with no stale word and any of the three out of bounds is INCONCLUSIVE (the eviction case, whose sweep
 *    evicts by design, only records them). DC IVAC is not used for proof: on this CPU it did not discard dirty
 *    lines (an implementation may clean them first).
 *  - Controls first, one per direction, with today's leaves. Either outcome is evidence once the counters proved
 *    power: stale words mean today's leaves are not snooped in that direction; none mean they are (detail flags
 *    ADRENO_COHERENT_TODAY_C2G, ADRENO_COHERENT_TODAY_G2C). The coherent cases decide ON either way.
 *  - Sizes keep lines in L1 (4 KiB) and L2 (256 KiB, 1 MiB). One CPU->GPU case first evicts them with a read
 *    sweep of guest RAM, so the GPU must find the data in the LLCC or DRAM.
 * Each job is polled for at most hz / 20, and the first failure ends the test.
 *
 * SNAP_ADRENO_COHERENT_FORCE (debug only, tools/cycle.py --gpu-coherent-force): no self-test. The preconditions
 * still refuse, and otherwise the state is ON with ADRENO_COHERENT_DETAIL_FORCED in the detail, which the kext
 * accepts only with its own boot-arg adreno_coherent_force=1. For an A/B rendering check, not for use.
 *
 * The scratch buffers are the q1n1 arena's Stage 4 pool region (tools/adreno_x2.py ARENA_LAYOUT 'snap_smmu'):
 * with ADRENO_VA_WIDE the pool is monitor memory, so the region is unused, and the firmware's EL2 map of it is
 * Normal write-back (PAR_EL1 ATTR 0xff, measured on the A16). They are mapped at a temporary IOVA, and unmapped and
 * invalidated afterwards. */
#pragma once
#include "adreno.h"
#if SNAP_ADRENO_COHERENT
#if !ADRENO_VA_WIDE
#error "SNAP_ADRENO_COHERENT's self-test scratch is the arena's Stage 4 pool region, unused only with ADRENO_VA_WIDE"
#endif

#define ADRENO_COHERENT_SCRATCH_OFFSET 0x1400000UL   /* q1n1 ARENA_LAYOUT['snap_smmu'] offset */
#define ADRENO_COHERENT_SCRATCH_BYTES  0x603000UL    /* and size */
#define ADRENO_COHERENT_IB_OFF   0x000000UL          /* the job's IB */
#define ADRENO_COHERENT_WIT_OFF  0x008000UL          /* the PMU passes' witness, 4 KiB the GPU never touches */
#define ADRENO_COHERENT_SRC_OFF  0x010000UL          /* 1 MiB */
#define ADRENO_COHERENT_DST_OFF  0x110000UL          /* 1 MiB */
#define ADRENO_COHERENT_SPAN     0x210000UL
#define ADRENO_COHERENT_COPY_MAX (1UL << 20)         /* bytes per CP_MEMCPY */
#define ADRENO_COHERENT_IB_DWORDS 64u                 /* the longest IB the self-test writes */
/* The temporary IOVA: 2 MiB aligned, at the window's top, far from where the guest's allocator starts. */
#define ADRENO_COHERENT_TEST_VA  (ADRENO_WINDOW_END - 0x400000UL)
#define ADRENO_COHERENT_MARKER_BASE 0x534e5000u      /* FILL32 0x534e6000, IB 0x534e7000 */
#define ADRENO_COHERENT_SWEEP_MAX (24UL << 20)       /* the eviction sweep's reads of guest RAM */
#define ADRENO_COHERENT_ROUNDS 2u                    /* every case again with other patterns */
#define ADRENO_COHERENT_MAX_PAGES (ADRENO_CACHE_MAX_BYTES >> 14)
_Static_assert(ADRENO_COHERENT_SPAN <= ADRENO_COHERENT_SCRATCH_BYTES && ADRENO_COHERENT_COPY_MAX <= ADRENO_CACHE_MAX_BYTES &&
               ADRENO_COHERENT_DST_OFF - ADRENO_COHERENT_SRC_OFF == ADRENO_COHERENT_COPY_MAX &&
               ADRENO_COHERENT_SPAN - ADRENO_COHERENT_DST_OFF == ADRENO_COHERENT_COPY_MAX &&
               !(ADRENO_COHERENT_TEST_VA & 0x1fffffUL) && ADRENO_COHERENT_TEST_VA >= ADRENO_WINDOW_BASE &&
               ADRENO_COHERENT_TEST_VA + ADRENO_COHERENT_SPAN <= ADRENO_WINDOW_END &&
               ADRENO_COHERENT_IB_OFF + 4u * ADRENO_COHERENT_IB_DWORDS <= ADRENO_COHERENT_WIT_OFF &&
               ADRENO_COHERENT_WIT_OFF + 0x1000 <= ADRENO_COHERENT_SRC_OFF,
               "self-test layout");
#if !SNAP_ADRENO_COHERENT_FORCE
#define ADRENO_COHERENT_PMU_EVENT 0x17u   /* L2D_CACHE_REFILL: misses of this CPU's L1 and L2 (common event) */
#define ADRENO_COHERENT_COUNTS 16u        /* the witness's miss pass reads 64 lines just invalidated; prefetches a
                                           * refill count may leave out can hide some, not most */
#define ADRENO_COHERENT_SLACK 16u         /* a resident pass may still count prefetches that ran past an edge */
#endif

/* root_ext.gpu_coherent (probes/xnuboot.c), under the service token. */
struct adreno_coherent_state {
    uint64_t state;              /* ADRENO_COHERENT_STATE_* */
    uint64_t leaf;               /* adreno_ops.leaf for the run: ADRENO_PTE_COHERENT_BITS when ON, else 0 */
    uint64_t detail;             /* REFUSED: the precondition; otherwise phase << 8 | round << 4 | case, | flags */
    uint64_t passed;             /* coherent iterations that passed */
    uint64_t jobs, reserved1;    /* GPU jobs rung; (the test's duration, dropped for the code budget) */
    uint64_t observed, expected, reserved0;   /* the last mismatching case's first mismatch: word seen, word wanted */
    uint64_t stale[2];           /* the controls' stale words, out of 1,024: [0] CPU->GPU, [1] GPU->CPU */
    /* The controls' PMU passes, [0] CPU->GPU, [1] GPU->CPU, and the last case's: refill counts of the witness's miss
     * pass | the resident pass << 16 | the witness pass after the job << 32. */
    uint64_t pmu[2], last_pmu;
    uint64_t reserved[6];
};
#define ADRENO_COHERENT_WORDS 20
_Static_assert(sizeof(struct adreno_coherent_state) == 8 * ADRENO_COHERENT_WORDS, "decoded word by word");

/* Phases in detail >> 8 (FAILED, TIMEOUT, GPU_ERROR, INCONCLUSIVE). 5 is retired: an earlier CPU-only DC IVAC
 * probe, which records with INCONCLUSIVE 0x500 name. */
enum { ADRENO_COHERENT_PHASE_CONTROL_C2G = 1, ADRENO_COHERENT_PHASE_CONTROL_G2C = 2, ADRENO_COHERENT_PHASE_C2G = 3,
       ADRENO_COHERENT_PHASE_G2C = 4 };
/* detail flags, set once both controls proved power: the control of that direction saw no stale word with
 * today's leaves, so the interconnect already snoops them (0x2000 is ADRENO_COHERENT_DETAIL_FORCED). */
#define ADRENO_COHERENT_TODAY_C2G 0x8000u
#define ADRENO_COHERENT_TODAY_G2C 0x4000u

/* Once, at prepare, before the guest runs: the self-test, then cs->state and cs->leaf. The caller puts cs->leaf in
 * every later adreno_ops.leaf. sweep_pa/sweep_bytes: memory the caller proved readable, read (only read) for the
 * eviction case; the monitor passes the first ADRENO_COHERENT_SWEEP_MAX bytes of guest RAM. Returns the state.
 * Bounded: at most 2 + 7 * ADRENO_COHERENT_ROUNDS jobs of hz / 20 each, ending at the first failure. The PMU state it
 * changes (MDCR_EL2, PMCR_EL0, counter 0's type, count and enable) is restored before it returns. */
unsigned adreno_coherent_selftest(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                                  struct adreno_coherent_state *cs, uint64_t sweep_pa, uint64_t sweep_bytes,
                                  uint64_t mem_low, uint64_t mem_high);

/* ADRENO_GUEST_COHERENT: regs in, reply out (compat/adreno-guest.h). epoch: the CPU attribute epoch, never 0. */
int adreno_coherent_query(const struct adreno_coherent_state *cs, uint64_t epoch, uint64_t regs[4]);

/* ADRENO_GUEST_CACHE with ADRENO_CACHE_COHERENT: adreno_guest_cache_filtered (compat/adreno.c: adreno_guest_cache's
 * validation and refusals, then maintenance only for the frames `writeback` reports as not the CPU's Normal
 * write-back), with the oracle only while the state is ON. Without it the flagged direction is not a direction,
 * so the call is refused with ADRENO_E_PARAMS before anything: no skip can happen before the self-test passed.
 * Caller: the same service lock as adreno_guest_cache. */
static inline int adreno_coherent_cache(const struct adreno_ops *o, const struct adreno_params *p,
                                        struct adreno_state *s, const struct adreno_coherent_state *cs,
                                        uint64_t regs[4], uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                                        int (*writeback)(void *ctx, uint64_t pa), void *writeback_ctx,
                                        uint64_t mem_low, uint64_t mem_high)
{
    return adreno_guest_cache_filtered(o, p, s, regs, leaf, leaf_ctx, mem_low, mem_high,
                                       cs->state == ADRENO_COHERENT_STATE_ON ? writeback : 0, writeback_ctx);
}

/* The guest's pinned MAIR_EL1 (0x0C0D00FF01A040FF; tools/test-sptm-mair.py): AttrIndx 0 and 4 are Normal
 * write-back (0xff), and nothing else is (probes/xnuboot.c multipage_same_class). */
#define ADRENO_COHERENT_CPU_WB(attrindx) ((attrindx) == 0u || (attrindx) == 4u)

/* compat/adreno.c: TLBIASID + TLBSYNC on CB0, as after a mirror change. */
int adreno_mirror_tlbi(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s);
#endif
