/* SPDX-License-Identifier: MIT */
/* See adreno-coherent.h. No libc: this links into the monitor (only with SNAP_ADRENO_COHERENT, probes/run.py
 * OPTIONAL) and into tools/test-adreno-coherent.c. Packet fields come from the generated register header. The
 * monitor image has little room below OUT_AT (probes/run.py), so the code favours size: one routine runs both
 * directions, and the cache operations are out of line. */
#include "adreno-coherent.h"
#include "adreno-ib.h"
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
#if SNAP_ADRENO_COHERENT
_Static_assert(A8XX_E_CP_MEMCPY == 0x75u && A8XX_E_CP_MEM_WRITE == 0x3du && A8XX_E_CP_WAIT_MEM_WRITES == 0x12u,
               "self-test opcodes");
_Static_assert(ADRENO_COHERENT_PHASE_CONTROL_C2G == 1 && ADRENO_COHERENT_PHASE_CONTROL_G2C == 2 &&
               ADRENO_COHERENT_TODAY_C2G == 0x10000u >> 1 && ADRENO_COHERENT_TODAY_G2C == 0x10000u >> 2 &&
               !((ADRENO_COHERENT_TODAY_C2G | ADRENO_COHERENT_TODAY_G2C) & ADRENO_COHERENT_DETAIL_FORCED),
               "control c is phase c and sets flag 0x10000 >> c");

#if ADRENO_DIRECT
#define RD(o, pa) ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa))
#define WR(o, pa, v) ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa) = (uint32_t)(v))
#define RD64(o, pa) ((void)(o), *(volatile uint64_t *)(uintptr_t)(pa))
#define WR64(o, pa, v) ((void)(o), *(volatile uint64_t *)(uintptr_t)(pa) = (v))
#else
#define RD(o, pa) ((o)->rd((o)->ctx, (pa)))
#define WR(o, pa, v) ((o)->wr((o)->ctx, (pa), (uint32_t)(v)))
#define RD64(o, pa) ((o)->rd64((o)->ctx, (pa)))
#define WR64(o, pa, v) ((o)->wr64((o)->ctx, (pa), (v)))
#endif

#if !SNAP_ADRENO_COHERENT_FORCE
#if ADRENO_DIRECT
/* DC CIVAC (clean) or DC IVAC (invalidate) over 64-byte lines, then DSB SY. */
static __attribute__((noinline)) void maintain(const struct adreno_ops *o, uint64_t pa, uint64_t size, int clean)
{
    (void)o;
    for (uint64_t line = pa & ~63UL; line < pa + size; line += 64) {
        if (clean) __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
        else __asm__ volatile("dc ivac, %0" :: "r"(line) : "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
}
static uint64_t coherent_now(const struct adreno_ops *o)
{
    uint64_t t;
    (void)o;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(t) :: "memory");
    return t;
}
#define NOW(o) coherent_now(o)
/* PMU counter 0 (adreno_coherent_selftest programs it). DSB first: the reads it follows have completed, and so have
 * the refills they caused. Zeroed at the start of the test, so the 32-bit count does not wrap. */
static uint64_t pmu_refills(void)
{
    uint64_t v;
    __asm__ volatile("dsb ish; isb; mrs %0, pmevcntr0_el0" : "=r"(v) :: "memory");
    return v;
}
#define REFILLS(o) ((void)(o), pmu_refills())
#else
static void maintain(const struct adreno_ops *o, uint64_t pa, uint64_t size, int clean)
{
    if (clean) o->clean(o->ctx, pa, size);
    else o->invalidate(o->ctx, pa, size);
}
#define NOW(o) ((o)->now((o)->ctx))
#define REFILLS(o) ((o)->refills((o)->ctx))
#endif
#define CLEAN(o, pa, size) maintain(o, pa, size, 1)
#define INVALIDATE(o, pa, size) maintain(o, pa, size, 0)
#endif

#define SLOT(p, va) ((p)->pool_pa + ADRENO_L3_OFFSET + (((va) - ADRENO_WINDOW_BASE) >> 12) * 8)
#define BR_PA(p) ((p)->fence_pa)
#define BV_PA(p) ((p)->fence_pa - ADRENO_IB_BR_FENCE_OFF + ADRENO_IB_BV_FENCE_OFF)
#define SRC(scratch) ((scratch) + ADRENO_COHERENT_SRC_OFF)
#define DST(scratch) ((scratch) + ADRENO_COHERENT_DST_OFF)
#define WIT(scratch) ((scratch) + ADRENO_COHERENT_WIT_OFF)

static int overlaps(uint64_t a, uint64_t an, uint64_t b, uint64_t bn) { return a < b + bn && b < a + an; }

/* Preconditions, in order; the number is the REFUSED detail. Nothing is written before all of them hold. Power, the
 * halt, CB0's TTBR0/TCR/SCTLR and its faults were proven by adreno_adopt just before; the ring's pointers are proven
 * by adreno_ring_reserve, and the GPU's error bits after every job. */
static unsigned refuse(const struct adreno_ops *o, const struct adreno_params *p, const struct adreno_state *s,
                       uint64_t scratch, uint64_t mem_low, uint64_t mem_high)
{
    if (s->quiesce || (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED | ADRENO_S_HIJACKED)) !=
                          (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED) ||
        (p->flags & (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING)) != (ADRENO_F_ENABLE | ADRENO_F_DART))
        return 1;   /* (hz 0 would end the first job as a timeout) */
#if !ADRENO_DIRECT
    if (!o->rd || !o->wr || !o->rd64 || !o->wr64 || !o->clean || !o->invalidate || !o->now) return 1;
#if !SNAP_ADRENO_COHERENT_FORCE
    if (!o->refills) return 9;
#endif
#else
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    if ((4UL << ((ctr >> 16) & 15)) != 64) return 2;   /* the DC loops step 64-byte lines */
#endif
    if ((p->fence_pa & 0xfff) != ADRENO_IB_BR_FENCE_OFF || (p->fence_va & 0xfff) != ADRENO_IB_BR_FENCE_OFF) return 3;
    /* The scratch must be the arena's and nothing else's. adreno_adopt proved the arena clear of guest memory and,
     * with ADRENO_VA_WIDE, of the table pool, and the ring, the fence slot and CB0's root inside the arena; q1n1 puts
     * all three below the Stage 4 region (ARENA_LAYOUT cp_rb, cp_memptrs, tables), which this re-checks. */
    if (p->arena_size < ADRENO_COHERENT_SCRATCH_OFFSET + ADRENO_COHERENT_SCRATCH_BYTES ||
        p->ring_pa + 4 * p->ring_dwords > scratch || p->fence_pa >= scratch ||
        (p->cb0_ttbr0 & ADRENO_PTE_ADDR) >= scratch || overlaps(scratch, ADRENO_COHERENT_SPAN, mem_low, mem_high - mem_low))
        return 4;
    /* No mirror check: adreno_adopt zeroed every level-3 slot just before and the guest has not run, so no guest leaf
     * can be left with the other word and the test IOVA is free. AttrIndx 1 must be write-back in CB0, and CBAR must
     * not override the leaf: Linux's weakest stage-1 bypass (arm_smmu_write_context_bank), as q1n1 writes it
     * (CBAR_S1_BYPASS_S2: type 1, BPSHCFG NSH, MEMATTR WB). */
    if (((RD(o, ADRENO_CB0 + ADRENO_CB_MAIR0) >> 8) & 0xffu) != 0xffu) return 7;
    if ((RD(o, ADRENO_SMMU_CBAR0) & 0x3f300u) != 0x1f300u) return 8;
#if ADRENO_DIRECT && !SNAP_ADRENO_COHERENT_FORCE
    /* The detection power is the PMU's: PMUv3 (ID_AA64DFR0_EL1.PMUVer 1..14; 0 is none, 15 IMPLEMENTATION DEFINED,
     * and either makes the PMU registers UNDEFINED, so this is read first), at least one event counter, and the
     * event in PMCEID0_EL0. */
    uint64_t dfr0, pmcr, ceid;
    __asm__ volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
    if (((dfr0 >> 8) & 15) - 1 > 13) return 9;
    __asm__ volatile("mrs %0, pmcr_el0; mrs %1, pmceid0_el0" : "=r"(pmcr), "=r"(ceid));
    if (!((pmcr >> 11) & 31) || !((ceid >> ADRENO_COHERENT_PMU_EVENT) & 1)) return 9;
#endif
    return 0;   /* a stopped SQE shows as the first job's timeout */
}

#if !SNAP_ADRENO_COHERENT_FORCE
static uint32_t pattern(uint32_t seed, uint64_t word) { return seed ^ (uint32_t)(word * 0x9e3779b1u); }

/* The scratch at the test VA with `leaf` (0 unmaps), cleaned, then TLBI so no translation made with the other word
 * survives. 0 or ADRENO_E_TLB. All writable: only the monitor's own IB runs there. */
static int map_scratch(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                       uint64_t scratch, uint64_t leaf)
{
    for (uint64_t off = 0; off < ADRENO_COHERENT_SPAN; off += 0x1000)
        WR64(o, SLOT(p, ADRENO_COHERENT_TEST_VA + off), leaf ? (scratch + off) | leaf : 0);
    CLEAN(o, SLOT(p, ADRENO_COHERENT_TEST_VA), (ADRENO_COHERENT_SPAN >> 12) * 8);
    return adreno_mirror_tlbi(o, p, s);
}

/* One read of every line of [pa, pa + bytes) (a power of two, at least 4 KiB), line k * 37 mod lines at step k: the
 * stride keeps changing, so a stride prefetcher does not run ahead and fill lines before they are read. Returns the
 * refills the reads caused: lines that were not in this CPU's caches. */
static __attribute__((noinline)) uint64_t touch(const struct adreno_ops *o, uint64_t pa, uint64_t bytes)
{
    const uint64_t lines = bytes / 64, before = REFILLS(o);
    for (uint64_t k = 0; k < lines; k++) (void)RD(o, pa + (k * 37 & (lines - 1)) * 64);
    return REFILLS(o) - before;
}

/* One case. The IB copies the source to the destination in CP_MEMCPY packets of at most ADRENO_COHERENT_COPY_MAX
 * bytes (a 4 MiB copy once hung the GPU), and for GPU->CPU also writes `marker` into the destination's first word
 * with CP_MEM_WRITE. It goes through the ring with a guest IB's completion words, polled with the IB path's rules
 * (both fences == marker, RPTR == WPTR, RBBM idle, no fault or error bit) within hz / 20.
 *  c2g: DRAM holds the inverted pattern in both buffers, and the source's lines are dirty with the pattern (cacheable
 *       stores, never cleaned; with a sweep they are pushed out of L1/L2 after the PMU passes). After the job the
 *       destination is invalidated before it is read: it never had a CPU line, so only the GPU's read is under test.
 *  g2c: the source is cleaned with the pattern, and the destination's lines are primed, clean, with the inverted
 *       pattern. It is read with no maintenance, so only the invalidation of CPU lines by GPU writes is under test.
 * The PMU passes (adreno-coherent.h) are recorded in cs->last_pmu. Returns 0 with *stale = the words that differ from
 * what the GPU wrote; INCONCLUSIVE when none differ but the passes did not prove the lines were in the CPU's caches
 * (never for a case with a sweep, which evicts them on purpose); or the job's ADRENO_COHERENT_STATE_*. */
static unsigned run_case(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_coherent_state *cs, uint64_t scratch, int c2g, uint64_t bytes, uint32_t seed,
                         uint64_t sweep_pa, uint64_t sweep_bytes, uint64_t *stale)
{
    const uint64_t src_va = ADRENO_COHERENT_TEST_VA + ADRENO_COHERENT_SRC_OFF, ib = scratch + ADRENO_COHERENT_IB_OFF;
    const uint64_t dst_va = ADRENO_COHERENT_TEST_VA + ADRENO_COHERENT_DST_OFF;
    /* Word 0 of the destination is always the CP_MEM_WRITE's: in GPU->CPU it lands on a primed line too. */
    const uint32_t marker = ADRENO_COHERENT_MARKER_BASE ^ seed;
    for (uint64_t i = 0; i < bytes / 4; i++) {
        WR(o, SRC(scratch) + 4 * i, c2g ? ~pattern(seed, i) : pattern(seed, i));
        WR(o, DST(scratch) + 4 * i, ~pattern(seed, i));
    }
    CLEAN(o, SRC(scratch), bytes);
    CLEAN(o, DST(scratch), bytes);
    /* The GPU's own caches first (CACHE_INVALIDATE7, CP_CCHE_INVALIDATE, as the plug-in's blit barrier): an earlier
     * case's lines there must not answer for this one, which would fail a coherent machine. */
    const uint32_t head[3] = {a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 1),
                              A8XX_PKT_CP_EVENT_WRITE7_0__EVENT(A8XX_E_CACHE_INVALIDATE7),
                              a8xx_pkt7_hdr(A8XX_E_CP_CCHE_INVALIDATE, 0)};
    unsigned n = 0;
    for (unsigned k = 0; k < 3; k++) WR(o, ib + 4 * n++, head[k]);
    for (uint64_t off = 0; off < bytes; off += ADRENO_COHERENT_COPY_MAX) {
        uint64_t chunk = bytes - off > ADRENO_COHERENT_COPY_MAX ? ADRENO_COHERENT_COPY_MAX : bytes - off;
        const uint32_t copy[6] = {a8xx_pkt7_hdr(A8XX_E_CP_MEMCPY, 5), (uint32_t)(chunk / 4), (uint32_t)(src_va + off),
                                  (uint32_t)((src_va + off) >> 32), (uint32_t)(dst_va + off),
                                  (uint32_t)((dst_va + off) >> 32)};
        for (unsigned k = 0; k < 6; k++) WR(o, ib + 4 * n++, copy[k]);
    }
    const uint32_t tail[6] = {a8xx_pkt7_hdr(A8XX_E_CP_WAIT_MEM_WRITES, 0), a8xx_pkt7_hdr(A8XX_E_CP_MEM_WRITE, 3),
                              (uint32_t)dst_va, (uint32_t)(dst_va >> 32), marker,
                              a8xx_pkt7_hdr(A8XX_E_CP_WAIT_MEM_WRITES, 0)};
    for (unsigned k = 0; k < 6; k++) WR(o, ib + 4 * n++, tail[k]);
    CLEAN(o, ib, 4ull * n);
    if (c2g) {
        /* Word k of every line, for k = 0..15: no line is written whole by consecutive stores, which a
         * write-streaming detector could send past the caches (the resident pass below would then count them). */
        for (uint64_t k = 0; k < 64; k += 4)
            for (uint64_t at = k; at < bytes; at += 64) WR(o, SRC(scratch) + at, pattern(seed, at / 4));
    } else {
        (void)touch(o, DST(scratch), bytes);
    }
    /* Detection power: the witness, just evicted, must count misses (the counter counts this CPU's refills at EL2),
     * and the lines under test must count almost none (they are in this CPU's caches: dirty after the stores, clean
     * after the priming). Read passes only: they change no line's state. */
    CLEAN(o, WIT(scratch), 0x1000);
    const uint64_t miss = touch(o, WIT(scratch), 0x1000);
    const uint64_t resident = touch(o, c2g ? SRC(scratch) : DST(scratch), bytes);
    for (uint64_t at = 0; at < sweep_bytes; at += 64) (void)RD(o, sweep_pa + at);
    uint64_t at;
    int rung;
    if (adreno_ring_reserve(o, p, s, ADRENO_IB_RING_WORDS, &at, &rung))
        return rung ? ADRENO_COHERENT_STATE_TIMEOUT : ADRENO_COHERENT_STATE_REFUSED;
    const uint32_t fence = ADRENO_COHERENT_MARKER_BASE ^ (uint32_t)++cs->jobs;
    WR(o, BR_PA(p), fence - 1);
    WR(o, BV_PA(p), fence - 1);
    CLEAN(o, BR_PA(p), BV_PA(p) + 4 - BR_PA(p));   /* both slots' lines (ADRENO_IB_BR/BV_FENCE_OFF) */
    uint32_t w[ADRENO_IB_RING_WORDS];
    unsigned words = adreno_ib_ring_words(w, ADRENO_COHERENT_TEST_VA + ADRENO_COHERENT_IB_OFF, n, p->fence_va,
                                          p->fence_va - ADRENO_IB_BR_FENCE_OFF + ADRENO_IB_BV_FENCE_OFF, fence);
    for (unsigned i = 0; i < words; i++) WR(o, p->ring_pa + 4 * (at + i), w[i]);
    if (adreno_ring_kick(o, p, s, at, words)) return ADRENO_COHERENT_STATE_TIMEOUT;
    const uint64_t start = NOW(o);
    /* A fault stalls the CP, so it ends here as a timeout; one after completion is the error check's. */
    for (unsigned reads = 0;; reads++) {
        CLEAN(o, BR_PA(p), BV_PA(p) + 4 - BR_PA(p));
        if (RD(o, BR_PA(p)) == fence && RD(o, BV_PA(p)) == fence && RD(o, ADRENO_CP_RB_RPTR) == s->wptr &&
            !(RD(o, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE)) break;
        if (reads >= 2 && NOW(o) - start > o->hz / 20) return ADRENO_COHERENT_STATE_TIMEOUT;
    }
    if ((RD(o, ADRENO_RBBM_INT_0_STATUS) & ADRENO_IB_RBBM_INT_ERRORS) ||
        (RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL) & ADRENO_IB_CP_GLOBAL_FAULTS) ||
        (RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR))
        return ADRENO_COHERENT_STATE_GPU_ERROR;
    /* The witness again: still resident, so nothing between the proof and the GPU's access (the ring, the
     * doorbell, the poll) cleaned or evicted this CPU's lines wholesale. */
    const uint64_t witness = touch(o, WIT(scratch), 0x1000);
    cs->last_pmu = miss | resident << 16 | witness << 32;
    if (c2g) INVALIDATE(o, DST(scratch), bytes);
    *stale = 0;
    for (uint64_t i = 0; i < bytes / 4; i++) {
        uint32_t want = i == 0 ? marker : pattern(seed, i), seen = RD(o, DST(scratch) + 4 * i);
        if (seen != want && !(*stale)++) { cs->observed = seen; cs->expected = want; }
    }
    /* A stale word proves its own power; none proves coherence only with the lines shown to be cached. */
    if (!*stale && !sweep_bytes &&
        (miss < ADRENO_COHERENT_COUNTS || resident > ADRENO_COHERENT_SLACK || witness > ADRENO_COHERENT_SLACK))
        return ADRENO_COHERENT_STATE_INCONCLUSIVE;
    return 0;
}
#endif

unsigned adreno_coherent_selftest(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                                  struct adreno_coherent_state *cs, uint64_t sweep_pa, uint64_t sweep_bytes,
                                  uint64_t mem_low, uint64_t mem_high)
{
    if (cs->state != ADRENO_COHERENT_STATE_NOT_RUN || cs->jobs) return (unsigned)cs->state;   /* once per boot */
    const uint64_t scratch = p->arena_base + ADRENO_COHERENT_SCRATCH_OFFSET;
    unsigned state = ADRENO_COHERENT_STATE_REFUSED, detail = refuse(o, p, s, scratch, mem_low, mem_high), flags = 0;
    if (detail) goto out;
#if SNAP_ADRENO_COHERENT_FORCE
    /* Debug only: ON with no proof, and the detail says so to the kext and the event log. */
    (void)sweep_pa;
    (void)sweep_bytes;
    state = ADRENO_COHERENT_STATE_ON;
    flags = ADRENO_COHERENT_DETAIL_FORCED;
#else
    unsigned e;
    uint64_t stale = 0;
#if ADRENO_DIRECT
    /* PMU counter 0 counts ADRENO_COHERENT_PMU_EVENT at EL2 (PMEVTYPER0 NSH set, P and U clear) from 0, in whichever
     * range MDCR_EL2.HPMN puts it: HPMD cleared lets the first range count at EL2, HPME set enables the second,
     * PMCR_EL0.E enables the first. Everything changed here is the firmware's and goes back below; the guest has
     * not run yet. */
    uint64_t mdcr, pmcr, type, count, enabled;
    __asm__ volatile("mrs %0, mdcr_el2; mrs %1, pmcr_el0; mrs %2, pmevtyper0_el0; mrs %3, pmevcntr0_el0; "
                     "mrs %4, pmcntenset_el0"
                     : "=r"(mdcr), "=r"(pmcr), "=r"(type), "=r"(count), "=r"(enabled));
    __asm__ volatile("msr mdcr_el2, %0; msr pmevtyper0_el0, %1; msr pmevcntr0_el0, xzr; msr pmcntenset_el0, %2; "
                     "msr pmcr_el0, %3; isb"
                     :: "r"((mdcr & ~(1UL << 17)) | 1UL << 7), "r"(1UL << 27 | ADRENO_COHERENT_PMU_EVENT), "r"(1UL),
                        "r"(pmcr | 1) : "memory");
#endif
    state = ADRENO_COHERENT_STATE_TIMEOUT;
    detail = 0xff;
    if (map_scratch(o, p, s, scratch, ADRENO_PTE_LEAF)) goto unmap;
    /* Controls, with today's leaves, one per direction. Either outcome is evidence: stale words mean today's leaves
     * are not snooped that way; none, with the PMU passes in bounds (run_case), mean they are. The coherent cases
     * below decide ON either way. */
    for (unsigned c = 1; c < 3; c++) {
        detail = c << 8;
        e = run_case(o, p, s, cs, scratch, c == 1, 0x1000, 0x6b6b6b6bu * c, 0, 0, &stale);
        cs->pmu[c - 1] = cs->last_pmu;
        if (e) {
            state = e;
            goto unmap;
        }
        cs->stale[c - 1] = stale;
        if (!stale) flags |= 0x10000u >> c;
    }
    detail = 0xfe;
    if (map_scratch(o, p, s, scratch, ADRENO_PTE_LEAF_COHERENT)) goto unmap;
    /* Per round, CPU->GPU then GPU->CPU, each at 4 KiB (lines in L1), 256 KiB and 1 MiB (L2), and a fourth
     * CPU->GPU 1 MiB case whose lines a read sweep first pushes towards the LLCC and DRAM. A new pattern each time. */
    for (unsigned round = 0; round < ADRENO_COHERENT_ROUNDS; round++)
        for (unsigned i = 0; i < 7; i++) {
            const int c2g = i < 4;
            const uint64_t bytes = (i % 4 == 0 || i == 4) ? 0x1000 : (i % 4 == 1 || i == 5) ? 0x40000 : 0x100000;
            detail = (c2g ? ADRENO_COHERENT_PHASE_C2G : ADRENO_COHERENT_PHASE_G2C) << 8 | round << 4 | i;
            e = run_case(o, p, s, cs, scratch, c2g, bytes, 0xa5a5a5a5u ^ 0x1b873593u * (8 * round + i + 1), sweep_pa,
                         i == 3 ? sweep_bytes : 0, &stale);
            if (e || stale) {
                state = e ? e : ADRENO_COHERENT_STATE_FAILED;
                goto unmap;
            }
            cs->passed++;
        }
    state = ADRENO_COHERENT_STATE_ON;
    detail = 0;
unmap:
    /* Whatever happened: no test leaf survives (a stuck CP faults rather than reaching the guest's future pages at
     * this IOVA), and no line of the scratch stays in a CPU cache. */
    if (map_scratch(o, p, s, scratch, 0) && state == ADRENO_COHERENT_STATE_ON) state = ADRENO_COHERENT_STATE_TIMEOUT;
    CLEAN(o, scratch, ADRENO_COHERENT_SPAN);
#if ADRENO_DIRECT
    __asm__ volatile("msr pmcr_el0, %0; msr pmcntenclr_el0, %1; msr pmevtyper0_el0, %2; msr pmevcntr0_el0, %3; "
                     "msr mdcr_el2, %4; isb"
                     :: "r"(pmcr), "r"(~enabled & 1), "r"(type), "r"(count), "r"(mdcr) : "memory");
#endif
#endif
out:
    cs->state = state;
    cs->detail = detail | flags;
    cs->leaf = state == ADRENO_COHERENT_STATE_ON ? ADRENO_PTE_COHERENT_BITS : 0;
    return state;
}

int adreno_coherent_query(const struct adreno_coherent_state *cs, uint64_t epoch, uint64_t regs[4])
{
    if (regs[0] != ADRENO_GUEST_COHERENT || regs[1] != ADRENO_COHERENT_QUERY) {   /* x2, x3 are ignored */
        regs[0] = (uint64_t)(int64_t)ADRENO_E_PARAMS;
        regs[1] = 0;
        return ADRENO_E_PARAMS;
    }
    regs[0] = 0;
    regs[1] = ADRENO_COHERENT_ABI | (cs->state & 0xff) << 8 | (cs->detail & 0xffff) << 16;
    regs[2] = epoch | !epoch;
    regs[3] = cs->passed;
    return 0;
}
#endif
