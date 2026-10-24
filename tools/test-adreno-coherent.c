/* SPDX-License-Identifier: MIT */
/* IO-coherent CB0 leaves, the monitor side (SNAP_ADRENO_COHERENT). The monitor's own entry points (adreno_adopt,
 * adreno_coherent_selftest, adreno_coherent_query, adreno_coherent_cache, adreno_mirror, adreno_guest_ib) against
 * tools/test-adreno-ring.c's model: guest RAM and the arena behind a write-back CPU cache, the CB0 walk with its TLB,
 * the CP running ring and IB packets through CB0. This file adds:
 *  - an interconnect (`hw`) that, for an access through a coherent leaf (AttrIndx 1, SH inner), may serve a GPU read
 *    from the CPU's line (dirty or clean, whatever it holds) and may write back and drop the CPU's line before a GPU
 *    write; each half can be switched off, which is a machine that is not (fully) IO-coherent, and both can apply to
 *    every leaf (`snoop_all`: an interconnect that snoops even today's non-coherent leaves);
 *  - the PMU's L2D_CACHE_REFILL: a CPU read of a line the model cache does not hold (adreno_ops.refills), which can
 *    be dead (`pmu_dead`);
 *  - CPUs the self-test must not trust: accesses that bypass the cache (`uncached_cpu`, no refills either), stores
 *    that go straight to DRAM when the line is not cached (`stream_stores`), a clean and invalidate of every CPU
 *    line just before the GPU's first access (`flush_before_gpu`), and DC IVAC that writes a dirty line back first
 *    (`ivac_cleans`, the A16's behaviour, which must not matter any more);
 *  - the eviction sweep evicting every CPU line, dirty ones written back (`sweep_evicts`, on by default);
 *  - CP_MEMCPY and CP_WAIT_MEM_WRITES in an IB; a CP_MEMCPY over 1 MiB is a violation (a 4 MiB copy hung the GPU);
 *  - CB0 MAIR0 and CBAR(0), and DC IVAC that counts a dirty line it drops (a destroyed CPU write).
 * With -DSNAP_ADRENO_COHERENT_FORCE=1 it checks the debug build instead: ON without a job, said in the detail.
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -DADRENO_VA_WIDE=1 -DSNAP_ADRENO_COHERENT=1 -DSNAP_ADRENO_IB_ASYNC=1 tools/test-adreno-coherent.c \
 *     compat/adreno-coherent.c compat/adreno-ib.c compat/adreno-fill.c compat/adreno-submit.c \
 *     compat/adreno-resource.c compat/adreno.c compat/irq-forward.c shadow/stage2.c shadow/shadow.c shadow/mmu.c \
 *     -o build/test-adreno-coherent && build/test-adreno-coherent
 * Run from the tree root. No hardware client. */
#define ADRENO_RING_NO_MAIN 1
#define ADRENO_RING_SNOOP 1
#define ADRENO_RING_IB_HOOK 1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"   /* S2 needs the draw-plan fixture: not run here */
#include "test-adreno-ring.c"
#pragma clang diagnostic pop
#include "adreno-coherent.h"
#if !SNAP_ADRENO_COHERENT || !ADRENO_VA_WIDE
#error "build with -DSNAP_ADRENO_COHERENT=1 -DADRENO_VA_WIDE=1"
#endif

#define SCRATCH (ARENA + ADRENO_COHERENT_SCRATCH_OFFSET)
#define SWEEP_PA (GUEST_PAGE + 0x200000)         /* read-only sweep target: guest pages no test writes */
#define SWEEP_BYTES 0x40000
#define C_SRC_VA 0x40800000UL                    /* this file's guest pages, clear of the ring test's fixtures */
#define C_SRC_PA (GUEST_PAGE + 0x380000)
#define C_DST_VA 0x40804000UL
#define C_DST_PA (GUEST_PAGE + 0x384000)
#define C_PKG_VA 0x40808000UL
#define C_PKG_PA (GUEST_PAGE + 0x388000)
#define OP_MEMCPY 0x75u

static struct {
    int read_snoop, write_inval, snoop_all, uncached_cpu, ivac_cleans, pmu_dead, stream_stores, flush_before_gpu;
    int sweep_evicts;
    uint32_t mair0, cbar;
    unsigned memcpys, dirty_invalidated;
    uint64_t refills;
    uint64_t memcpy_max;
} hw;
static struct adreno_coherent_state cs;
static struct adreno_ops coh;

static int coherent_leaf(uint64_t leaf)
{
    return hw.snoop_all || (((leaf >> 2) & 7) == 1 && ((leaf >> 8) & 3) == 3);
}
static int ring_snoop_read(uint64_t leaf, uint64_t pa, uint32_t *v)
{
    uint64_t off = ram_offset(pa, 4);
    if (!coherent_leaf(leaf) || !hw.read_snoop || !cached[off / 64]) return 0;
    memcpy(v, cache + off, 4);                   /* the CPU's line answers, whatever it holds */
    return 1;
}
static void ring_snoop_write(uint64_t leaf, uint64_t pa)
{
    uint64_t line = ram_offset(pa, 4) / 64;
    if (!coherent_leaf(leaf) || !hw.write_inval) return;
    if (dirty[line]) memcpy(dram + line * 64, cache + line * 64, 64);
    dirty[line] = cached[line] = 0;
}
/* Every CPU line out of the cache, dirty ones written back: what a large eviction, or a wholesale clean and
 * invalidate, does. */
static void evict_all(void)
{
    for (uint64_t line = 0; line < RAM_SIZE / 64; line++) {
        if (dirty[line]) memcpy(dram + line * 64, cache + line * 64, 64);
        dirty[line] = cached[line] = 0;
    }
}
static int ib_extra_op(uint32_t op, const uint32_t *b, uint32_t cnt)
{
    if (op == OP_WAIT_MEM_WRITES) {
        if (cnt) violation("CP_WAIT_MEM_WRITES count %u in an IB", cnt);
        return 1;
    }
    if (op != OP_MEMCPY) return 0;
    if (cnt != 5) { violation("CP_MEMCPY count %u", cnt); return 1; }
    uint64_t bytes = 4ull * b[0], src = b[1] | (uint64_t)b[2] << 32, dst = b[3] | (uint64_t)b[4] << 32;
    if (!bytes || bytes > (1u << 20)) { violation("CP_MEMCPY of %llu bytes", (unsigned long long)bytes); return 1; }
    hw.memcpys++;
    if (bytes > hw.memcpy_max) hw.memcpy_max = bytes;
    if (hw.flush_before_gpu) evict_all();
    for (uint64_t i = 0; i < bytes; i += 4) {
        uint32_t v;
        if (!gpu_rd32(src + i, &v) || !gpu_wr32(dst + i, v)) { cp.stall = 1; return 1; }
    }
    return 1;
}
static uint32_t coh_rd(void *ctx, uint64_t pa)
{
    if (pa == ADRENO_CB0 + ADRENO_CB_MAIR0) return hw.mair0;
    if (pa == ADRENO_SMMU_CBAR0) return hw.cbar;
    if (in_ram(pa, 4)) {
        /* Non-cacheable: no cache access, so no refill either. */
        if (hw.uncached_cpu) { uint32_t v; memcpy(&v, dram + ram_offset(pa, 4), 4); return v; }
        if (hw.sweep_evicts && pa == SWEEP_PA) evict_all();
        hw.refills += !cached[ram_offset(pa, 4) / 64];
    }
    return ring_rd(ctx, pa);
}
static void coh_wr(void *ctx, uint64_t pa, uint32_t v)
{
    if (in_ram(pa, 4) && (hw.uncached_cpu || (hw.stream_stores && !cached[ram_offset(pa, 4) / 64]))) {
        dev_wr32(pa, v);
        return;
    }
    ring_wr(ctx, pa, v);
}
static uint64_t coh_refills(void *ctx) { (void)ctx; return hw.pmu_dead ? 7 : hw.refills; }
static void coh_invalidate(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    uint64_t off = ram_offset(pa, size);
    for (uint64_t line = off / 64; line <= (off + size - 1) / 64; line++) {
        if (dirty[line] && hw.ivac_cleans) memcpy(dram + line * 64, cache + line * 64, 64);
        else hw.dirty_invalidated += dirty[line];
        dirty[line] = cached[line] = 0;
    }
}

/* q1n1's cp-fence and the monitor's adopt, nothing mapped yet: prepare, before the guest. */
static void setup(void)
{
    q1n1_cp_fence();
    memset(&cp, 0, sizeof cp);
    nccu = 0;
    cp.rb_cntl = r.rb_cntl;
    P.flags &= ~(uint64_t)ADRENO_F_RING;
    P.ring_wptr = r.wptr = r.rptr = 22;
    ring_ops = ops;
    ring_ops.rd = ring_rd;
    ring_ops.wr = ring_wr;
    ring_ops.clean = ring_clean;
    CHECK(adreno_adopt(&ring_ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    memset(dart, 0, sizeof(dart));
    coh = ring_ops;
    coh.rd = coh_rd;
    coh.wr = coh_wr;
    coh.invalidate = coh_invalidate;
    coh.refills = coh_refills;
    coh.leaf = 0;
    memset(&cs, 0, sizeof cs);
    memset(&hw, 0, sizeof hw);
    hw.read_snoop = hw.write_inval = hw.sweep_evicts = 1;
    hw.mair0 = 0xf404ff44u;                      /* q1n1 CB_MAIR0 */
    hw.cbar = 0x1f300u;                          /* q1n1 CBAR_S1_BYPASS_S2 */
}
static unsigned selftest(void)
{
    unsigned st = adreno_coherent_selftest(&coh, &P, &S, &cs, SWEEP_PA, SWEEP_BYTES, MEM_LOW, MEM_HIGH);
    coh.leaf = cs.leaf;                          /* what probes/xnuboot.c gpu_ops carries from now on */
    return st;
}
static int test_slots_zero(void)
{
    for (uint64_t va = ADRENO_COHERENT_TEST_VA; va < ADRENO_COHERENT_TEST_VA + ADRENO_COHERENT_SPAN; va += 0x1000)
        if (dev_rd64(P.pool_pa + ADRENO_L3_OFFSET + ((va - ADRENO_WINDOW_BASE) >> 12) * 8)) return 0;
    return 1;
}
static int scratch_lines_left(void)
{
    uint64_t first = ram_offset(SCRATCH, 1) / 64, last = ram_offset(SCRATCH + ADRENO_COHERENT_SPAN - 1, 1) / 64;
    for (uint64_t line = first; line <= last; line++) if (cached[line] || dirty[line]) return 1;
    return 0;
}
static uint64_t query(unsigned *state)
{
    uint64_t regs[4] = {ADRENO_GUEST_COHERENT, ADRENO_COHERENT_QUERY, 0, 0};
    CHECK(adreno_coherent_query(&cs, 41, regs) == 0 && regs[0] == 0 && (regs[1] & 0xff) == ADRENO_COHERENT_ABI);
    *state = (unsigned)(regs[1] >> 8 & 0xff);
    CHECK(regs[2] == 41 && regs[3] == cs.passed);
    return regs[1];
}

#define PMU_PASSES(miss, resident, witness) ((uint64_t)(miss) | (uint64_t)(resident) << 16 | (uint64_t)(witness) << 32)
#if !SNAP_ADRENO_COHERENT_FORCE
/* A machine that snoops only through coherent leaves passes every iteration. Both controls saw stale data with
 * today's leaves, and their PMU passes are exact here: 64 witness misses, nothing else. The temporary leaves are
 * gone, the TLB was invalidated, no scratch line stays cached, and the leaf word is the coherent one. */
static void test_selftest_pass(void)
{
    setup();
    uint64_t wptr = S.wptr, tlbi = S.tlbi;
    CHECK(selftest() == ADRENO_COHERENT_STATE_ON && cs.state == ADRENO_COHERENT_STATE_ON && cs.detail == 0);
    CHECK(cs.leaf == ADRENO_PTE_COHERENT_BITS && ADRENO_LEAF(&coh) == ADRENO_PTE_LEAF_COHERENT);
    CHECK(cs.passed == 7 * ADRENO_COHERENT_ROUNDS && cs.jobs == 2 + 7 * ADRENO_COHERENT_ROUNDS);
    CHECK(cs.stale[0] == 1023 && cs.stale[1] == 1024);   /* C2G: word 0 is the CP_MEM_WRITE's */
    CHECK(cs.pmu[0] == PMU_PASSES(64, 0, 0) && cs.pmu[1] == PMU_PASSES(64, 0, 0));
    CHECK(cp.violations == 0 && hw.memcpy_max == (1u << 20) && hw.dirty_invalidated == 0);
    CHECK(test_slots_zero() && !scratch_lines_left() && S.tlbi >= tlbi + 3 && S.live_pages == 0);
    CHECK(S.wptr != wptr && r.rptr == r.wptr && r.wptr == S.wptr && !cp.int0 && !r.fsr);
    unsigned state;
    query(&state);
    CHECK(state == ADRENO_COHERENT_STATE_ON);
    /* Run once per boot: a second call changes nothing. */
    uint64_t jobs = cs.jobs;
    CHECK(selftest() == ADRENO_COHERENT_STATE_ON && cs.jobs == jobs);
    /* The mirror now writes the coherent word, and the placement checks expect it. */
    dart[(C_DST_VA - ADRENO_WINDOW_BASE) >> 14] = dart_desc(C_DST_PA, 0, 0x4000, 0, 0);
    CHECK(adreno_mirror(&coh, &P, &S, C_DST_VA, 0x4000, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0);
    CHECK(smmu_walk(C_DST_VA, 0) == (C_DST_PA | ADRENO_PTE_LEAF_COHERENT));
    uint64_t regs[4] = {ADRENO_GUEST_FENCE, C_DST_VA + 0x40, 0x1234, 0};
    CHECK(adreno_guest_fence(&coh, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0);
    struct adreno_ops old = coh;
    old.leaf = 0;                                /* a placement check with today's word refuses the coherent leaf */
    uint64_t regs2[4] = {ADRENO_GUEST_FENCE, C_DST_VA + 0x40, 0x1235, 0};
    CHECK(adreno_guest_fence(&old, &P, &S, regs2, dart_leaf, 0, MEM_LOW, MEM_HIGH) == ADRENO_E_TARGET);
    printf("COHERENT pass: %llu iterations in %llu jobs, controls stale %llu/%llu, PMU %#llx/%#llx, %u CP_MEMCPYs "
           "(max %llu bytes)\n", (unsigned long long)cs.passed, (unsigned long long)cs.jobs,
           (unsigned long long)cs.stale[0], (unsigned long long)cs.stale[1], (unsigned long long)cs.pmu[0],
           (unsigned long long)cs.pmu[1], hw.memcpys, (unsigned long long)hw.memcpy_max);
}

/* Not coherent at all, or in one direction only: OFF, today's leaves, the coherent call refused. */
static void expect_off(unsigned want_state, unsigned want_detail, const char *what)
{
    unsigned state, st = selftest();
    CHECK(st == want_state && cs.state == want_state && cs.leaf == 0 && coh.leaf == 0);
    CHECK(cs.detail == want_detail);
    CHECK(test_slots_zero() && !scratch_lines_left() && hw.dirty_invalidated == 0);
    query(&state);
    CHECK(state == want_state);
    printf("COHERENT %s: state %u detail %#llx\n", what, st, (unsigned long long)cs.detail);
}
static int writeback_all(void *ctx, uint64_t pa) { (void)ctx; (void)pa; return 1; }
static void test_selftest_off(void)
{
    setup();
    hw.read_snoop = hw.write_inval = 0;
    expect_off(ADRENO_COHERENT_STATE_FAILED, ADRENO_COHERENT_PHASE_C2G << 8, "non-coherent hardware");
    /* The coherent variant is refused before anything while the state is not ON. */
    dart[(C_DST_VA - ADRENO_WINDOW_BASE) >> 14] = dart_desc(C_DST_PA, 0, 0x4000, 0, 0);
    CHECK(adreno_mirror(&coh, &P, &S, C_DST_VA, 0x4000, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0);
    CHECK(smmu_walk(C_DST_VA, 0) == (C_DST_PA | ADRENO_PTE_LEAF));
    m_wr(0, C_DST_PA, 0x5555);
    uint64_t regs[4] = {ADRENO_GUEST_CACHE, C_DST_VA, 0x4000, ADRENO_CACHE_TO_DEVICE | ADRENO_CACHE_COHERENT};
    CHECK(adreno_coherent_cache(&coh, &P, &S, &cs, regs, dart_leaf, 0, writeback_all, 0, MEM_LOW, MEM_HIGH) ==
          ADRENO_E_PARAMS && regs[0] == (uint64_t)(int64_t)ADRENO_E_PARAMS && regs[1] == 0);
    CHECK(dirty[ram_offset(C_DST_PA, 4) / 64]);  /* nothing was maintained */

    setup();
    hw.write_inval = 0;                          /* reads snoop, writes do not invalidate */
    expect_off(ADRENO_COHERENT_STATE_FAILED, ADRENO_COHERENT_PHASE_G2C << 8 | 4, "read snoop only");
    setup();
    hw.read_snoop = 0;                           /* writes invalidate, reads do not snoop */
    expect_off(ADRENO_COHERENT_STATE_FAILED, ADRENO_COHERENT_PHASE_C2G << 8, "write invalidate only");
}
/* No detection power, each caught by one PMU pass while the data alone looks coherent: INCONCLUSIVE at the first
 * control, before any coherent leaf. */
static void test_no_power(void)
{
    setup();
    hw.uncached_cpu = 1;                         /* no line is ever cached, and nothing refills */
    expect_off(ADRENO_COHERENT_STATE_INCONCLUSIVE, ADRENO_COHERENT_PHASE_CONTROL_C2G << 8, "uncached CPU");
    CHECK(cs.stale[0] == 0 && cs.pmu[0] == 0 && cs.passed == 0 && cs.jobs == 1);
    setup();
    hw.snoop_all = 1;
    hw.pmu_dead = 1;                             /* the counter does not count at EL2: the witness misses nothing */
    expect_off(ADRENO_COHERENT_STATE_INCONCLUSIVE, ADRENO_COHERENT_PHASE_CONTROL_C2G << 8, "dead PMU");
    CHECK(cs.pmu[0] == 0 && cs.jobs == 1);
    setup();
    hw.pmu_dead = 1;                             /* stale controls need no PMU; the coherent cases do */
    expect_off(ADRENO_COHERENT_STATE_INCONCLUSIVE, ADRENO_COHERENT_PHASE_C2G << 8, "dead PMU, stale controls");
    CHECK(cs.stale[0] == 1023 && cs.stale[1] == 1024 && cs.jobs == 3);
    setup();
    hw.read_snoop = hw.write_inval = 0;
    hw.stream_stores = 1;                        /* the stores never reach the cache: the resident pass refills */
    expect_off(ADRENO_COHERENT_STATE_INCONCLUSIVE, ADRENO_COHERENT_PHASE_CONTROL_C2G << 8, "streaming stores");
    CHECK(cs.stale[0] == 0 && cs.pmu[0] == PMU_PASSES(64, 64, 0));
    setup();
    hw.read_snoop = hw.write_inval = 0;
    hw.flush_before_gpu = 1;                     /* everything written back just before the GPU reads */
    expect_off(ADRENO_COHERENT_STATE_INCONCLUSIVE, ADRENO_COHERENT_PHASE_CONTROL_C2G << 8, "flush before the GPU");
    CHECK(cs.stale[0] == 0 && cs.pmu[0] == PMU_PASSES(64, 0, 64));
}
/* On the A16, DC IVAC at EL2 left no stale word behind dirty stores (an implementation may clean first). The PMU
 * passes do not depend on it, so a machine that snoops only through coherent leaves still passes. */
static void test_ivac_cleans(void)
{
    setup();
    hw.ivac_cleans = 1;
    CHECK(selftest() == ADRENO_COHERENT_STATE_ON && cs.detail == 0 && cs.stale[0] == 1023 && cs.stale[1] == 1024);
    printf("COHERENT DC IVAC that cleans: state %llu detail %#llx\n", (unsigned long long)cs.state,
           (unsigned long long)cs.detail);
}
/* An interconnect that snoops even today's leaves: the controls see nothing stale with the PMU passes in bounds,
 * which is a finding, not a lack of power. The coherent cases run and decide; with the write half broken as well
 * they still fail it. */
static void test_snoops_today(void)
{
    setup();
    hw.snoop_all = 1;
    CHECK(selftest() == ADRENO_COHERENT_STATE_ON &&
          cs.detail == (ADRENO_COHERENT_TODAY_C2G | ADRENO_COHERENT_TODAY_G2C));
    CHECK(cs.stale[0] == 0 && cs.stale[1] == 0 && cs.passed == 7 * ADRENO_COHERENT_ROUNDS);
    CHECK(cs.pmu[0] == PMU_PASSES(64, 0, 0) && cs.pmu[1] == PMU_PASSES(64, 0, 0));
    CHECK(cs.leaf == ADRENO_PTE_COHERENT_BITS && test_slots_zero() && !scratch_lines_left());
    CHECK(hw.dirty_invalidated == 0 && cp.violations == 0);
    unsigned state;
    CHECK(query(&state) >> 16 == (ADRENO_COHERENT_TODAY_C2G | ADRENO_COHERENT_TODAY_G2C) &&
          state == ADRENO_COHERENT_STATE_ON);
    printf("COHERENT snoops today's leaves: state %u detail %#llx\n", state, (unsigned long long)cs.detail);
    setup();
    hw.snoop_all = 1;
    hw.write_inval = 0;
    expect_off(ADRENO_COHERENT_STATE_FAILED, ADRENO_COHERENT_TODAY_C2G | ADRENO_COHERENT_PHASE_G2C << 8 | 4,
               "snoops today's reads only");
    CHECK(cs.stale[0] == 0 && cs.stale[1] == 1024);
}
/* A stalled CP ends the test at its first job within the budget; an error bit is GPU_ERROR. */
static void test_timeout_and_error(void)
{
    setup();
    cp.halt = 1;
    uint64_t t0 = clock_now;
    expect_off(ADRENO_COHERENT_STATE_TIMEOUT, ADRENO_COHERENT_PHASE_CONTROL_C2G << 8, "stalled CP");
    CHECK(cs.jobs == 1 && clock_now - t0 < 2 * (coh.hz / 20) + 100000);
    setup();
    cp.int0_in_ib = 1u << 24;                    /* UCHE_OOB_ACCESS during the first IB */
    expect_off(ADRENO_COHERENT_STATE_GPU_ERROR, ADRENO_COHERENT_PHASE_CONTROL_C2G << 8, "GPU error bit");
    CHECK(cs.jobs == 1);
}
#else
/* The debug build: ON with the forced flag, no GPU job, no scratch leaf, no ring word. */
static void test_forced(void)
{
    setup();
    uint64_t wptr = S.wptr;
    CHECK(selftest() == ADRENO_COHERENT_STATE_ON && cs.detail == ADRENO_COHERENT_DETAIL_FORCED);
    CHECK(cs.leaf == ADRENO_PTE_COHERENT_BITS && coh.leaf == ADRENO_PTE_COHERENT_BITS && cs.passed == 0);
    CHECK(cs.jobs == 0 && S.wptr == wptr && r.wptr == wptr && test_slots_zero() && hw.memcpys == 0);
    CHECK(!scratch_lines_left());
    unsigned state;
    CHECK(query(&state) >> 16 == ADRENO_COHERENT_DETAIL_FORCED && state == ADRENO_COHERENT_STATE_ON);
    printf("COHERENT forced: state %u detail %#llx, no job\n", state, (unsigned long long)cs.detail);
}
#endif
/* Preconditions refuse before anything is written: no ring word, no slot, no job; the forced build too. */
static void refusal(unsigned want_detail, const char *what)
{
    uint64_t wptr = S.wptr;
    unsigned st = selftest();
    CHECK(st == ADRENO_COHERENT_STATE_REFUSED && cs.detail == want_detail && cs.jobs == 0 && cs.leaf == 0);
    CHECK(S.wptr == wptr && r.wptr == wptr && test_slots_zero());
    printf("COHERENT refused (%s): detail %llu\n", what, (unsigned long long)cs.detail);
}
static void test_refusals(void)
{
    setup(); P.flags |= ADRENO_F_RING; refusal(1, "ring profile");
    setup(); P.fence_pa += 4; refusal(3, "fence slot offset");
    setup(); P.ring_pa = SCRATCH; refusal(4, "ring inside the scratch");
    setup(); P.arena_size = ADRENO_COHERENT_SCRATCH_OFFSET; refusal(4, "arena without the Stage 4 region");
    setup(); hw.mair0 = 0xf4044444u; refusal(7, "MAIR index 1 not write-back");
    setup(); hw.cbar = 0x14300u; refusal(8, "CBAR MEMATTR not write-back");
    setup(); hw.cbar = 0x1f000u; refusal(8, "CBAR BPSHCFG not NSH");
#if !SNAP_ADRENO_COHERENT_FORCE
    setup(); coh.refills = 0; refusal(9, "no PMU counter");
#endif
}

/* After ON, end to end through a guest IB (CP_MEMCPY source -> destination):
 *  - plain maintenance (an older kext) stays correct with coherent leaves;
 *  - the coherent variant skips a write-back frame (x2 = 0) and stays correct through the snoop;
 *  - it maintains a frame the CPU maps non-cacheable, which holds a stale clean line (speculation through a WB
 *    alias) under the CPU's non-cacheable store: without that clean the snooped read would return the stale line. */
static int nc_frame;                             /* the oracle: this PA's frame is not write-back */
static int writeback_oracle(void *ctx, uint64_t pa) { (void)ctx; return !(nc_frame && pa == C_SRC_PA); }
static int cache_call(uint64_t va, uint64_t direction, int coherent, uint64_t *maintained)
{
    uint64_t regs[4] = {ADRENO_GUEST_CACHE, va, 0x4000, direction | (coherent ? ADRENO_CACHE_COHERENT : 0)};
    int e = coherent ? adreno_coherent_cache(&coh, &P, &S, &cs, regs, dart_leaf, 0, writeback_oracle, 0, MEM_LOW,
                                             MEM_HIGH)
                     : adreno_guest_cache(&coh, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[1] == (e ? 0 : 0x4000) && regs[3] == S.wptr);
    *maintained = regs[2];
    return e;
}
static void map_coherent(uint64_t va, uint64_t pa, int nowrite)
{
    dart[(va - ADRENO_WINDOW_BASE) >> 14] = dart_desc(pa, 0, 0x4000, nowrite, 0);
    CHECK(adreno_mirror(&coh, &P, &S, va, 0x4000, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0);
}
static unsigned copy_round(int coherent, int nc, uint32_t seed)
{
    uint64_t maintained;
    nc_frame = nc;
    /* The CPU's view: the destination primed (clean lines), the source written. */
    for (unsigned i = 0; i < 0x1000; i++) (void)m_rd(0, C_DST_PA + 4 * i);
    if (!nc) {
        for (unsigned i = 0; i < 0x1000; i++) m_wr(0, C_SRC_PA + 4 * i, seed + i);   /* write-back: dirty lines */
    } else {
        m_clean(0, C_SRC_PA, 0x4000);            /* the WB -> NC change cleans the frame (sptm_attr_clean) */
        for (unsigned i = 0; i < 0x1000; i++) (void)m_rd(0, C_SRC_PA + 4 * i);       /* a stale clean line... */
        for (unsigned i = 0; i < 0x1000; i++) dev_wr32(C_SRC_PA + 4 * i, seed + i);  /* ...under an NC store */
    }
    CHECK(cache_call(C_SRC_VA, ADRENO_CACHE_TO_DEVICE, coherent, &maintained) == 0);
    CHECK(!coherent || maintained == (nc ? 0x4000u : 0u));
    const uint32_t words[] = {pkt7(OP_MEMCPY, 5), 0x1000, (uint32_t)C_SRC_VA, (uint32_t)(C_SRC_VA >> 32),
                              (uint32_t)C_DST_VA, (uint32_t)(C_DST_VA >> 32), pkt7(OP_WAIT_MEM_WRITES, 0)};
    put_package(C_PKG_PA, words, 7, 64);
    uint64_t regs[4] = {ADRENO_GUEST_IB, C_PKG_VA, 7, 64};
    CHECK(adreno_guest_ib(&coh, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0);
    CHECK(cache_call(C_DST_VA, ADRENO_CACHE_FROM_DEVICE, coherent, &maintained) == 0);
    CHECK(!coherent || maintained == 0);
    unsigned bad = 0;
    for (unsigned i = 0; i < 0x1000; i++) bad += m_rd(0, C_DST_PA + 4 * i) != seed + i;
    return bad;
}
static void test_cache_variant(void)
{
    const unsigned before = failures;
    setup();
    CHECK(selftest() == ADRENO_COHERENT_STATE_ON);
    map_coherent(C_SRC_VA, C_SRC_PA, 0);
    map_coherent(C_DST_VA, C_DST_PA, 0);
    map_coherent(C_PKG_VA, C_PKG_PA, 1);
    CHECK(copy_round(0, 0, 0x10000) == 0);                       /* plain maintenance, coherent leaves */
    CHECK(copy_round(1, 0, 0x20000) == 0);                       /* write-back frame: skipped, snooped */
    CHECK(copy_round(1, 1, 0x30000) == 0);                       /* NC frame maintained */
    CHECK(hw.dirty_invalidated == 0 && cp.violations == 0);
    /* With coherent leaves, a changed MAIR index 1 refuses the next IB before any ring write. */
    hw.mair0 = 0xf4044444u;
    uint64_t wptr = S.wptr, regs[4] = {ADRENO_GUEST_IB, C_PKG_VA, 7, 64};
    CHECK(adreno_guest_ib(&coh, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == ADRENO_E_CB0 && S.wptr == wptr);
    printf("COHERENT cache variant: %s\n", failures == before ? "plain, skipped write-back and maintained NC frames "
           "read back exactly; a changed MAIR refuses the next IB" : "FAILED");
}

int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    if (!dram || !cache) return 2;
#if !SNAP_ADRENO_COHERENT_FORCE
    test_selftest_pass();
    test_selftest_off();
    test_no_power();
    test_ivac_cleans();
    test_snoops_today();
    test_timeout_and_error();
#else
    test_forced();
#endif
    test_refusals();
    test_cache_variant();
    free(dram);
    free(cache);
    if (failures) { printf("FAIL: %u of %u coherent checks\n", failures, checks); return 1; }
    printf("PASS: %u coherent checks\n", checks);
    return 0;
}
