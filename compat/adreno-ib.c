/* SPDX-License-Identifier: MIT */
/* ADRENO_GUEST_IB (compat/adreno-ib.h; ABI compat/adreno-guest.h; design S2). No libc: this links into the
 * monitor and the native tests (tools/test-adreno-ring.c). Every packet field comes from the generated
 * register header (tools/gen-a8xx-regs.py, Mesa's own XML), never typed by hand. */
#include "adreno-ib.h"
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
#if SNAP_ADRENO_IB_ASYNC
#include "adreno-fill.h"                        /* ADRENO_GUEST_FILL32, a ring user refused while in flight */
#endif

/* compat/adreno.h reads these by physical address; each must be the generated A8XX offset. */
_Static_assert(ADRENO_RBBM_STATUS == ADRENO_PA + 4 * A8XX_REG_RBBM_STATUS, "RBBM_STATUS");
_Static_assert(ADRENO_RBBM_INT_0_STATUS == ADRENO_PA + 4 * A8XX_REG_RBBM_INT_0_STATUS, "RBBM_INT_0_STATUS");
_Static_assert(ADRENO_CP_RB_CNTL == ADRENO_PA + 4 * A8XX_REG_CP_RB_CNTL, "CP_RB_CNTL");
_Static_assert(ADRENO_CP_RB_RPTR == ADRENO_PA + 4 * A8XX_REG_CP_RB_RPTR, "CP_RB_RPTR");
_Static_assert(ADRENO_CP_RB_WPTR == ADRENO_PA + 4 * A8XX_REG_CP_RB_WPTR, "CP_RB_WPTR");
_Static_assert(ADRENO_CP_SQE_CNTL == ADRENO_PA + 4 * A8XX_REG_CP_SQE_CNTL, "CP_SQE_CNTL");
_Static_assert(ADRENO_CP_INTERRUPT_STATUS_GLOBAL == ADRENO_PA + 4 * A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL,
               "CP_INTERRUPT_STATUS_GLOBAL");
_Static_assert(ADRENO_CP_RB_CNTL_BUFSZ == A8XX_FIELDS_AXXX_CP_RB_CNTL__BUFSZ__MASK, "CP_RB_CNTL BUFSZ");
_Static_assert(ADRENO_RING_NOP_MAX == A8XX_PKT7_COUNT_MASK && A8XX_E_CP_NOP == 0x10u, "compat/adreno.c pkt7_nop");
_Static_assert(ADRENO_IB_MAX_DWORDS <= A8XX_PKT_A5XX_CP_INDIRECT_BUFFER_2__IB_SIZE__MASK, "IB_SIZE field");
_Static_assert(ADRENO_WINDOW_END <= 1ull << (64 - ADRENO_CB0_T0SZ) && ADRENO_IB_BV_FENCE_OFF + 4 <= 0x1000u &&
               ADRENO_IB_BR_FENCE_OFF / 64 != ADRENO_IB_BV_FENCE_OFF / 64, "slots and window");

#if ADRENO_DIRECT
#define RD(o, pa) ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa))
#define WR(o, pa, v) ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa) = (uint32_t)(v))
#define RD64(o, pa) ((void)(o), *(volatile uint64_t *)(uintptr_t)(pa))
static void ib_clean(const struct adreno_ops *o, uint64_t pa, uint64_t size)
{
    (void)o;
    for (uint64_t line = pa & ~63UL; line < pa + size; line += 64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static uint64_t ib_now(const struct adreno_ops *o)
{
    uint64_t t;
    (void)o;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(t) :: "memory");
    return t;
}
#define CLEAN(o, pa, size) ib_clean(o, pa, size)
#define NOW(o) ib_now(o)
#else
#define RD(o, pa) ((o)->rd((o)->ctx, (pa)))
#define WR(o, pa, v) ((o)->wr((o)->ctx, (pa), (uint32_t)(v)))
#define RD64(o, pa) ((o)->rd64((o)->ctx, (pa)))
#define CLEAN(o, pa, size) ((o)->clean((o)->ctx, (pa), (size)))
#define NOW(o) ((o)->now((o)->ctx))
#endif

#define L3_SLOT(p, va) ((p)->pool_pa + ADRENO_L3_OFFSET + (((va) - ADRENO_WINDOW_BASE) >> 12) * 8)

#if SNAP_ADRENO_COHERENT
/* compat/adreno-coherent.c is a second caller: one out-of-line copy keeps the monitor inside its 448 KiB of code
 * (probes/run.py OUT_AT). */
__attribute__((noinline))
#endif
unsigned adreno_ib_ring_words(uint32_t w[ADRENO_IB_RING_WORDS], uint64_t ib_va, uint32_t dwords,
                              uint64_t br_va, uint64_t bv_va, uint32_t marker)
{
    /* q1n1 a16gpu_p6p7.ring_words (Linux a7xx_submit for one context, no preemption): the BV thread commits
     * its CACHE_CLEAN fence first, BR waits for it (CP_WAIT_TIMESTAMP), then BR commits its own, so every
     * byte the IB wrote is in DRAM before either fence value is. */
#define TC(t) A8XX_PKT_CP_THREAD_CONTROL_0__THREAD(A8XX_E_CP_SET_THREAD_##t)
#define EV(e) A8XX_PKT_CP_EVENT_WRITE7_0__EVENT(A8XX_E_##e)
    const uint32_t tc = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1);
    const uint32_t ev1 = a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 1), ev4 = a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 4);
    const uint32_t clean = EV(CACHE_CLEAN) | A8XX_PKT_CP_EVENT_WRITE7_0__WRITE_ENABLED(1);
    unsigned n = 0;
    w[n++] = tc; w[n++] = TC(BR) | A8XX_PKT_CP_THREAD_CONTROL_0__SYNC_THREADS(1);
    w[n++] = tc; w[n++] = TC(BOTH);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_INDIRECT_BUFFER, 3);
    w[n++] = (uint32_t)ib_va; w[n++] = (uint32_t)(ib_va >> 32);
    w[n++] = A8XX_PKT_A5XX_CP_INDIRECT_BUFFER_2__IB_SIZE(dwords);
    w[n++] = tc; w[n++] = TC(BR);
    w[n++] = ev1; w[n++] = EV(CCU_INVALIDATE_DEPTH);
    w[n++] = ev1; w[n++] = EV(CCU_INVALIDATE_COLOR);
    w[n++] = tc; w[n++] = TC(BV);
    w[n++] = ev4; w[n++] = clean; w[n++] = (uint32_t)bv_va; w[n++] = (uint32_t)(bv_va >> 32); w[n++] = marker;
    w[n++] = tc; w[n++] = TC(BR);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_WAIT_TIMESTAMP, 4);
    w[n++] = 0; w[n++] = (uint32_t)bv_va; w[n++] = (uint32_t)(bv_va >> 32); w[n++] = marker;
    w[n++] = ev4; w[n++] = clean; w[n++] = (uint32_t)br_va; w[n++] = (uint32_t)(br_va >> 32); w[n++] = marker;
    w[n++] = tc; w[n++] = TC(BOTH);
#undef TC
#undef EV
    return n;
}

static uint64_t leaf_pa(uint64_t d) { return (d & 0x3ffffffc00UL) << 4; }

#if SNAP_ADRENO_IB_ASYNC
/* ADRENO_GUEST_IB split at its poll (compat/adreno-ib.h SNAP_ADRENO_IB_ASYNC). ib_ring is the original's checks,
 * clean, marker and doorbell, statement for statement and in its order, for request word `request`; ib_pass one
 * iteration of its poll loop; ib_retired its GPU-error verdict. adreno_guest_ib below is the original loop over
 * them; START and POLL use the same three, so the IB's semantics cannot drift between the calls. */
#define IB_BR_PA(p) ((p)->fence_pa)
#define IB_BV_PA(p) ((p)->fence_pa - ADRENO_IB_BR_FENCE_OFF + ADRENO_IB_BV_FENCE_OFF)
static int ib_ring(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                   const uint64_t regs[4], uint64_t request, uint64_t (*leaf)(void *ctx, uint64_t iova),
                   void *leaf_ctx, uint64_t mem_low, uint64_t mem_high, uint32_t *marker_out, uint64_t *start_out)
{
    const uint64_t va = regs[1], dwords = regs[2], bytes = regs[3];
    const uint64_t br_pa = IB_BR_PA(p), bv_pa = IB_BV_PA(p);
    const uint64_t br_va = p->fence_va, bv_va = p->fence_va - ADRENO_IB_BR_FENCE_OFF + ADRENO_IB_BV_FENCE_OFF;
    int e = ADRENO_E_PARAMS, rung;
    if (s->quiesce || regs[0] != request || !leaf || !o->hz ||
        (p->flags & (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING)) != (ADRENO_F_ENABLE | ADRENO_F_DART) ||
        (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED | ADRENO_S_HIJACKED)) !=
            (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED) ||
        (p->fence_pa & 0xfff) != ADRENO_IB_BR_FENCE_OFF || (p->fence_va & 0xfff) != ADRENO_IB_BR_FENCE_OFF) return e;
#if !ADRENO_DIRECT
    if (!o->rd || !o->wr || !o->rd64 || !o->clean || !o->now) return e;
#endif
    e = ADRENO_E_WINDOW;
    if (!dwords || dwords > ADRENO_IB_MAX_DWORDS || ((va | bytes) & (ADRENO_IB_ALIGN - 1)) ||
        bytes < ADRENO_IB_ALIGN_UP(4 * dwords) || bytes > ADRENO_IB_MAX_PACKAGE ||
        va < ADRENO_WINDOW_BASE || va >= ADRENO_WINDOW_END || bytes > ADRENO_WINDOW_END - va) return e;
    e = ADRENO_E_TARGET;
    for (uint64_t at = va; at < va + bytes;) {
        uint64_t offset = at & 0x3fff, chunk = 0x4000 - offset;
        if (chunk > va + bytes - at) chunk = va + bytes - at;
        uint64_t d = leaf(leaf_ctx, at & ~0x3fffUL), pa = leaf_pa(d);
        uint64_t begin = (d >> 52) * 4, stop = (((d >> 40) & 0xfff) + 1) * 4;
        if (!(d & 1) || (d & 8) || !(d & 4) || offset < begin || offset >= stop || chunk > stop - offset ||
            pa < mem_low || pa >= mem_high || mem_high - pa < 0x4000 ||
            (pa < p->arena_base + p->arena_size && p->arena_base < pa + 0x4000)) return e;
        for (uint64_t sub = at & ~0xfffUL; sub < at + chunk; sub += 0x1000)
            if (RD64(o, L3_SLOT(p, sub)) != ((pa + (sub & 0x3fff)) | ADRENO_LEAF(o) | ADRENO_PTE_RDONLY))
                return e;
        at += chunk;
    }
    e = ADRENO_E_CX;
    if (!(RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16))) return e;
    e = ADRENO_E_GX;
    if (RD(o, ADRENO_GMU_PWR_CLK_STATUS) & 3u) return e;
    e = ADRENO_E_HALT;
    if (RD(o, ADRENO_RBBM_GBIF_HALT_ACK) & 1) return e;
    e = ADRENO_E_CB0;
    uint64_t ttbr = RD(o, ADRENO_CB0 + ADRENO_CB_TTBR0) | (uint64_t)RD(o, ADRENO_CB0 + ADRENO_CB_TTBR0 + 4) << 32;
    if (ttbr != p->cb0_ttbr0 || RD(o, ADRENO_CB0 + ADRENO_CB_TCR) != p->cb0_tcr ||
        ((RD(o, ADRENO_CB0 + ADRENO_CB_SCTLR) ^ p->cb0_sctlr) & ~ADRENO_SCTLR_FIXED)) return e;
#if SNAP_ADRENO_COHERENT
    if (!ADRENO_CB0_MAIR_OK(o, RD(o, ADRENO_CB0 + ADRENO_CB_MAIR0))) return e;
#endif
    e = ADRENO_E_FAULT;
    if ((RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR)) return e;
    e = ADRENO_E_SQE;
    if (!(RD(o, ADRENO_CP_SQE_CNTL) & 1)) return e;
    e = adreno_ring_ready(o, p, s, ADRENO_IB_RING_WORDS);
    if (e) return e;
    e = ADRENO_IB_E_BUSY;
    if (RD(o, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE) return e;
    e = ADRENO_IB_E_STICKY;
    if ((RD(o, ADRENO_RBBM_INT_0_STATUS) & ADRENO_IB_RBBM_INT_ERRORS) ||
        (RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL) & ADRENO_IB_CP_GLOBAL_FAULTS)) return e;
    for (uint64_t at = va; at < va + bytes;) {
        uint64_t offset = at & 0x3fff, chunk = 0x4000 - offset;
        if (chunk > va + bytes - at) chunk = va + bytes - at;
        CLEAN(o, leaf_pa(leaf(leaf_ctx, at & ~0x3fffUL)) + offset, chunk);
        at += chunk;
    }
    uint64_t at;
    e = adreno_ring_reserve(o, p, s, ADRENO_IB_RING_WORDS, &at, &rung);
    if (e) return rung ? ADRENO_IB_E_UNCERTAIN : e;
    uint32_t marker = ADRENO_IB_MARKER_BASE ^ (uint32_t)++s->ib_submits;
    if (!marker) marker = ADRENO_IB_MARKER_BASE ^ (uint32_t)++s->ib_submits;
    WR(o, br_pa, marker - 1);
    WR(o, bv_pa, marker - 1);
    CLEAN(o, br_pa, 4);
    CLEAN(o, bv_pa, 4);
    uint32_t w[ADRENO_IB_RING_WORDS];
    unsigned n = adreno_ib_ring_words(w, va, (uint32_t)dwords, br_va, bv_va, marker);
    for (unsigned i = 0; i < n; i++) WR(o, p->ring_pa + 4 * (at + i), w[i]);
    if (adreno_ring_kick(o, p, s, at, n)) return ADRENO_IB_E_UNCERTAIN;
    *marker_out = marker;
    *start_out = NOW(o);
    return 0;
}
/* One pass of the original poll: 1 retired (both fences == marker, RPTR == WPTR, RBBM idle), 0 not yet,
 * ADRENO_IB_E_UNCERTAIN on a CB0/SMMU fault. *ticks = now - start, read where the original reads it. */
static int ib_pass(const struct adreno_ops *o, const struct adreno_params *p, const struct adreno_state *s,
                   uint32_t marker, uint64_t start, uint64_t *ticks)
{
    CLEAN(o, IB_BR_PA(p), 4);
    CLEAN(o, IB_BV_PA(p), 4);
    *ticks = NOW(o) - start;
    if ((RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR))
        return ADRENO_IB_E_UNCERTAIN;
    return RD(o, IB_BR_PA(p)) == marker && RD(o, IB_BV_PA(p)) == marker && RD(o, ADRENO_CP_RB_RPTR) == s->wptr &&
           !(RD(o, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE);
}
static int ib_retired(const struct adreno_ops *o)
{
    if ((RD(o, ADRENO_RBBM_INT_0_STATUS) & ADRENO_IB_RBBM_INT_ERRORS) ||
        (RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL) & ADRENO_IB_CP_GLOBAL_FAULTS) ||
        (RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR))
        return ADRENO_IB_E_GPU_ERROR;
    return 0;
}
static void ib_reply(uint64_t regs[4], int e, uint64_t marker, uint64_t ticks, uint64_t wptr)
{
    regs[0] = (uint64_t)(int64_t)e;
    regs[1] = marker;
    regs[2] = ticks;
    regs[3] = wptr;
}

int adreno_guest_ib(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                    uint64_t regs[4], uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                    uint64_t mem_low, uint64_t mem_high)
{
    uint64_t ticks = 0, start = 0;
    uint32_t marker = 0;
    if (!o || !p || !s || !regs) return ADRENO_E_PARAMS;
    int e = ib_ring(o, p, s, regs, ADRENO_GUEST_IB, leaf, leaf_ctx, mem_low, mem_high, &marker, &start);
    for (unsigned reads = 0; !e; reads++) {
        int k = ib_pass(o, p, s, marker, start, &ticks);
        if (k < 0) e = k;
        else if (k) { e = ib_retired(o); break; }
        else if (reads >= 2 && ticks > o->hz / ADRENO_IB_POLL_DIVISOR) e = ADRENO_IB_E_UNCERTAIN;
    }
    if (!e) s->ib_dwords += regs[2];
    if (e) s->ib_errors++;
    ib_reply(regs, e, e ? 0 : marker, ticks, s->wptr);
    return e;
}

/* A final status ends the flight: the adreno_state counters as adreno_guest_ib's, the flight's own, the stored
 * reply for a repeated POLL, and nothing left active. The one place a flight ends (A12). */
static int ib_finish(struct adreno_state *s, struct adreno_ib_flight *f, int e, uint64_t ticks)
{
    if (!e) { s->ib_dwords += f->dwords; f->ok++; }
    else { s->ib_errors++; if (e == ADRENO_IB_E_GPU_ERROR) f->gpu_errors++; else f->uncertain++; }
    f->tlbi += s->tlbi - f->tlbi_base;
    f->tlbi_timeouts += s->tlbi_timeouts - f->tlbi_timeout_base;
    f->sum_ticks += ticks;
    if (ticks > f->max_ticks) f->max_ticks = ticks;
    if (f->reads > f->max_reads) f->max_reads = f->reads;
    f->last_marker = f->marker;
    f->last_status = e;
    f->last_ticks = ticks;
    f->last_wptr = s->wptr;
    f->active = 0;
    return e;
}
/* One completion pass of the flight with the budget timed from its doorbell (A6): fault, then completion, then
 * budget, which needs two earlier passes (the original's reads >= 2). ADRENO_IB_PENDING or the final status. */
static int flight_pass(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                       struct adreno_ib_flight *f, uint64_t *ticks)
{
    if (s->wptr != f->wptr) {                /* nothing else may move the ring while in flight (A7) */
        *ticks = NOW(o) - f->start;
        return ib_finish(s, f, ADRENO_IB_E_UNCERTAIN, *ticks);
    }
    uint64_t before = f->reads++;
    int k = ib_pass(o, p, s, (uint32_t)f->marker, f->start, ticks);
    if (k < 0) return ib_finish(s, f, k, *ticks);
    if (k) return ib_finish(s, f, ib_retired(o), *ticks);
#if SNAP_ADRENO_RECOVER
    /* The budget is soft (agents/gpu-recovery R22): past it the flight is overdue (counted once) and ends early only
     * on hang evidence, an RBBM_INT_0 error bit (HANG_DETECT included) or a CP global fault; at the hard limit it ends
     * UNCERTAIN, as it did at the budget. Before the soft budget a pass reads exactly what it read without the define. */
    if (*ticks > ADRENO_IB_SOFT_TICKS(o->hz)) {
        if (!(f->active & ADRENO_IB_FLIGHT_OVERDUE)) { f->active |= ADRENO_IB_FLIGHT_OVERDUE; f->reserved[0]++; }
        if (before >= 2 && ((RD(o, ADRENO_RBBM_INT_0_STATUS) & ADRENO_IB_RBBM_INT_ERRORS) ||
                            (RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL) & ADRENO_IB_CP_GLOBAL_FAULTS))) {
            f->reserved[1]++;
            return ib_finish(s, f, ADRENO_IB_E_UNCERTAIN, *ticks);
        }
        if (before >= 2 && *ticks > ADRENO_IB_HARD_TICKS(o->hz)) return ib_finish(s, f, ADRENO_IB_E_UNCERTAIN, *ticks);
    }
#else
    if (before >= 2 && *ticks > o->hz / ADRENO_IB_POLL_DIVISOR) return ib_finish(s, f, ADRENO_IB_E_UNCERTAIN, *ticks);
#endif
    return ADRENO_IB_PENDING;
}

int adreno_guest_ib_start(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                          struct adreno_ib_flight *f, uint64_t regs[4],
                          uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                          uint64_t mem_low, uint64_t mem_high)
{
    uint64_t ticks = 0, start = 0;
    uint32_t marker = 0;
    if (!o || !p || !s || !regs) return ADRENO_E_PARAMS;
    int e = ADRENO_E_PARAMS;
    if (f) {
        f->starts++;
        e = f->active ? ADRENO_IB_E_BUSY :
            ib_ring(o, p, s, regs, ADRENO_GUEST_IB_START, leaf, leaf_ctx, mem_low, mem_high, &marker, &start);
        if (f->active) f->refused++;
    }
    const uint64_t spin = o->hz / ADRENO_IB_START_SPIN_DIVISOR;
    for (unsigned reads = 0; !e; reads++) {
        int k = ib_pass(o, p, s, marker, start, &ticks);
        if (k < 0) e = k;
        else if (k) { e = ib_retired(o); break; }
        else if (reads >= 2 && ticks > o->hz / ADRENO_IB_POLL_DIVISOR) e = ADRENO_IB_E_UNCERTAIN;
        else if (ticks > spin) {
            /* Not retired within the spin: the IB is in flight and the guest polls (FAILURE-MODES A4, A6). */
            f->active = 1;
            f->marker = marker;
            f->start = start;
            f->va = regs[1];
            f->dwords = regs[2];
            f->bytes = regs[3];
            f->wptr = s->wptr;
            f->reads = reads + 1;
            f->tlbi_base = s->tlbi;
            f->tlbi_timeout_base = s->tlbi_timeouts;
            f->flights++;
            ib_reply(regs, ADRENO_IB_PENDING, marker, ticks, s->wptr);
            return ADRENO_IB_PENDING;
        }
    }
    if (!e) s->ib_dwords += regs[2];
    if (e) s->ib_errors++;
    ib_reply(regs, e, e ? 0 : marker, ticks, s->wptr);
    return e;
}

int adreno_guest_ib_poll(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, uint64_t regs[4])
{
    if (!o || !p || !s || !regs) return ADRENO_E_PARAMS;
    const uint64_t marker = regs[1];
    uint64_t ticks = 0;
    int e = ADRENO_E_PARAMS;
    if (!f || s->quiesce || regs[0] != ADRENO_GUEST_IB_POLL || regs[2] || regs[3] || marker >> 32 || !o->hz ||
        (p->flags & (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING)) != (ADRENO_F_ENABLE | ADRENO_F_DART) ||
        (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED | ADRENO_S_HIJACKED)) !=
            (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)
#if !ADRENO_DIRECT
        || !o->rd || !o->clean || !o->now
#endif
        ) {
        if (f) { f->polls++; f->poll_refused++; }
        ib_reply(regs, e, 0, 0, s->wptr);
        return e;
    }
    f->polls++;
    if (!marker || (!f->active && marker != f->last_marker)) {   /* marker 0 never matches anything (A8) */
        f->idle++;
        ib_reply(regs, ADRENO_IB_IDLE, 0, 0, s->wptr);
        return ADRENO_IB_IDLE;
    }
    if (!f->active) {                                            /* the last flight's reply, again (A12) */
        f->idle++;
        e = (int)f->last_status;
        ib_reply(regs, e, e ? 0 : f->last_marker, f->last_ticks, f->last_wptr);
        return e;
    }
    if (marker != f->marker) {                                   /* another IB's marker: nothing changes (A4) */
        f->mismatched++;
        ib_reply(regs, ADRENO_IB_E_BUSY, 0, 0, s->wptr);
        return ADRENO_IB_E_BUSY;
    }
    e = flight_pass(o, p, s, f, &ticks);
    if (e == ADRENO_IB_PENDING) {
        f->poll_pending++;
        ib_reply(regs, e, marker, ticks, s->wptr);
        return e;
    }
    f->finished++;
    ib_reply(regs, e, e ? 0 : marker, ticks, s->wptr);
    return e;
}

int adreno_ib_flight_refuse(struct adreno_state *s, struct adreno_ib_flight *f, uint64_t regs[4])
{
    if (!s || !f || !f->active || !regs) return 0;
    int e;
    switch (regs[0]) {
    case ADRENO_GUEST_IB: case ADRENO_GUEST_IB_START:
        e = ADRENO_IB_E_BUSY;
        s->ib_errors++;                       /* as adreno_guest_ib counts a refusal */
        break;
    case ADRENO_GUEST_FENCE: case ADRENO_GUEST_FILL32:
        e = ADRENO_E_PARAMS;                  /* as their own state refusal: fence_ticks 0, fence_error set */
        s->fence_ticks = 0;
        s->fence_error = (uint64_t)(int64_t)e;
        break;
    case ADRENO_GUEST_UNMAP:                  /* A1b: never under the CP's fetch */
        if (regs[1] >= f->va + f->bytes || regs[2] > ~regs[1] || regs[1] + regs[2] <= f->va) return 0;
        e = ADRENO_IB_E_BUSY;
        break;
    default:
        return 0;
    }
    if (regs[0] == ADRENO_GUEST_IB_START) f->starts++;
    f->refused++;
    ib_reply(regs, e, 0, 0, s->wptr);
    return e;
}

/* The tick's and the stop's pass, outside any guest call: with CX off nothing behind it is read (as
 * adreno_fault_poll and adreno_quiesce); the flight cannot be proven retired, so it is UNCERTAIN. */
static int flight_pass_powered(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                               struct adreno_ib_flight *f, uint64_t *ticks)
{
    if (!(RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16))) {
        *ticks = NOW(o) - f->start;
        return ib_finish(s, f, ADRENO_IB_E_UNCERTAIN, *ticks);
    }
    return flight_pass(o, p, s, f, ticks);
}

int adreno_ib_flight_tick(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                          struct adreno_ib_flight *f, uint64_t grace, int *final)
{
    *final = ADRENO_IB_PENDING;
    if (!f || !f->active) return 1;
#if SNAP_ADRENO_RECOVER
    if (NOW(o) - f->start <= ADRENO_IB_HARD_TICKS(o->hz) + grace) return 0;     /* the guest still polls (R20) */
#else
    if (NOW(o) - f->start <= o->hz / ADRENO_IB_POLL_DIVISOR + grace) return 0;   /* the guest still polls */
#endif
    uint64_t ticks;
    int e = flight_pass_powered(o, p, s, f, &ticks);
    if (e == ADRENO_IB_PENDING) e = ib_finish(s, f, ADRENO_IB_E_UNCERTAIN, ticks);
    f->abandoned++;
    *final = e;
    return 1;
}

int adreno_ib_flight_drain(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                           struct adreno_ib_flight *f, uint64_t bound, int *final)
{
    if (!f || !f->active) return 0;
    const uint64_t from = NOW(o);
    uint64_t ticks;
    int e;
    while ((e = flight_pass_powered(o, p, s, f, &ticks)) == ADRENO_IB_PENDING)
        if (NOW(o) - from > bound) { e = ib_finish(s, f, ADRENO_IB_E_UNCERTAIN, ticks); break; }
    f->stopped++;
    *final = e;
    return 1;
}

#if SNAP_ADRENO_RECOVER
/* ---- GPU hang recovery (compat/adreno-ib.h SNAP_ADRENO_RECOVER; agents/gpu-recovery FAILURE-MODES.md) ---------- */
#include "adreno-recover-table.h"
#if ADRENO_DIRECT
static void ib_invalidate(const struct adreno_ops *o, uint64_t pa, uint64_t size)
{
    (void)o;
    for (uint64_t line = pa & ~63UL; line < pa + size; line += 64)
        __asm__ volatile("dc ivac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
#define INVALIDATE(o, pa, size) ib_invalidate(o, pa, size)
#else
#define INVALIDATE(o, pa, size) ((o)->invalidate ? (o)->invalidate((o)->ctx, (pa), (size)) : (void)0)
#endif
_Static_assert(ADRENO_RBBM_INT_CLEAR_CMD == ADRENO_PA + 4 * 0x061u && ADRENO_RBBM_SW_RESET_CMD == ADRENO_PA + 4 * 0x073u &&
               ADRENO_GBIF_HALT == ADRENO_PA + 4 * 0x3c45u && ADRENO_GBIF_HALT_ACK == ADRENO_PA + 4 * 0x3c46u &&
               ADRENO_GBIF_HALT_ACK < ADRENO_PASS0_END, "reset registers: a6xx.xml offsets, inside the passthrough");
_Static_assert(sizeof adreno_recover_me_init / sizeof adreno_recover_me_init[0] == 10, "q1n1 C4: 10 words");
_Static_assert(ADRENO_RECOVER_TABLE_PROTECT_GLOBAL == 52, "the 52 CP_PROTECT_GLOBAL entries are replayed (R9)");
_Static_assert(ADRENO_IB_RING_WORDS < 0x2000 / 2, "the ring holds the recovery's words with room to spare");
#define RECOVER_SCRUB_WORDS 10u
#define RECOVER_FENCE_WORDS 9u
#define RECOVER_FENCE_MARK 0x534e8000u               /* | epoch: never an IB marker (0x534e7...) or FILL32's */

static int recover_window(uint32_t reg)
{
    const uint64_t pa = ADRENO_PA + 4ull * reg;
    return (pa >= ADRENO_PA && pa < ADRENO_PASS0_END) || (pa >= ADRENO_PASS1_PA && pa < ADRENO_PASS1_END);
}
static int recover_table_ok(const struct adreno_recover_op *t, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        if (t[i].op > ADRENO_RT_READBACK || (t[i].op != ADRENO_RT_SMC_APERTURE && !recover_window(t[i].reg))) return 0;
    return 1;
}
#define TABLE_N(t) ((unsigned)(sizeof(t) / sizeof((t)[0])))
static int recover_power(const struct adreno_ops *o)
{
    return (RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16)) && !(RD(o, ADRENO_GMU_PWR_CLK_STATUS) & 3u);
}
static int recover_cb0(const struct adreno_ops *o, const struct adreno_params *p)
{
    uint64_t ttbr = RD(o, ADRENO_CB0 + ADRENO_CB_TTBR0) | (uint64_t)RD(o, ADRENO_CB0 + ADRENO_CB_TTBR0 + 4) << 32;
    uint32_t sctlr = RD(o, ADRENO_CB0 + ADRENO_CB_SCTLR);
    return ttbr == p->cb0_ttbr0 && RD(o, ADRENO_CB0 + ADRENO_CB_TCR) == (uint32_t)p->cb0_tcr && (sctlr & 1) &&
           !((sctlr ^ p->cb0_sctlr) & ~ADRENO_SCTLR_FIXED);
}
static int recover_faults(const struct adreno_ops *o)
{
    return (RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR);
}
static int recover_errors(const struct adreno_ops *o)
{
    return (RD(o, ADRENO_RBBM_INT_0_STATUS) & ADRENO_IB_RBBM_INT_ERRORS) ||
           (RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL) & ADRENO_IB_CP_GLOBAL_FAULTS);
}
static int recover_wait(const struct adreno_ops *o, uint64_t pa, uint32_t mask, uint32_t want, uint64_t ticks)
{
    const uint64_t start = NOW(o);
    for (unsigned reads = 0;; reads++) {
        if ((RD(o, pa) & mask) == want) return 0;
        if (reads >= 2 && NOW(o) - start > ticks) return -1;
    }
}
/* FNV-1a over q1n1's SQE image, read from memory (the lines are invalidated first: the GPU, not the CPU, reads it). */
static uint64_t recover_sqe_sum(const struct adreno_ops *o, uint64_t pa)
{
    uint64_t h = 1469598103934665603ull;
    INVALIDATE(o, pa, ADRENO_RECOVER_SQE_BYTES);
    for (uint64_t off = 0; off < ADRENO_RECOVER_SQE_BYTES; off += 4) h = (h ^ RD(o, pa + off)) * 1099511628211ull;
    return h ? h : 1;
}
/* The ring is idle at the monitor's WPTR, the SQE runs, RBBM is idle, and nothing is in error (SETTLE's proof). */
static int recover_settled(const struct adreno_ops *o, const struct adreno_params *p, const struct adreno_state *s)
{
    return recover_power(o) && (RD(o, ADRENO_CP_SQE_CNTL) & 3u) == 1u && RD(o, ADRENO_CP_RB_WPTR) == s->wptr &&
           RD(o, ADRENO_CP_RB_RPTR) == s->wptr && s->wptr < p->ring_dwords &&
           !(RD(o, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE) && !recover_errors(o) && !recover_faults(o);
}
/* n words on the monitor's ring, rung, then RPTR == WPTR and RBBM idle within hz / 20 (q1n1 cp_idle). */
static int recover_ring(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                        const uint32_t *w, unsigned n)
{
    uint64_t at;
    int rung;
    if (adreno_ring_reserve(o, p, s, n, &at, &rung)) return -1;
    for (unsigned i = 0; i < n; i++) WR(o, p->ring_pa + 4 * (at + i), w[i]);
    if (adreno_ring_kick(o, p, s, at, n)) return -1;
    return recover_wait(o, ADRENO_CP_RB_RPTR, 0xffffffffu, (uint32_t)s->wptr, o->hz / 20) ||
           recover_wait(o, ADRENO_RBBM_STATUS, ~ADRENO_IB_RBBM_IDLE_IGNORE, 0, o->hz / 20) ? -1 : 0;
}
/* One section of the generated table; -1 on a READBACK mismatch, SMC failure or an entry outside the windows. */
static int recover_replay(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                          const struct adreno_recover_op *t, unsigned n, int *step)
{
    for (unsigned i = 0; i < n; i++) {
        const uint64_t pa = ADRENO_PA + 4ull * t[i].reg;
        if (t[i].op != ADRENO_RT_SMC_APERTURE && !recover_window(t[i].reg)) { *step = ADRENO_RECOVER_STEP_TABLE; return -1; }
        switch (t[i].op) {
        case ADRENO_RT_WRITE: WR(o, pa, t[i].value); break;
        case ADRENO_RT_READ: (void)RD(o, pa); break;
        case ADRENO_RT_READBACK:
            if (RD(o, pa) != t[i].value) { *step = ADRENO_RECOVER_STEP_SECVID; return -1; }
            break;
        case ADRENO_RT_SMC_APERTURE: {
            /* q1n1 cp_aperture (adreno_hw_init's qcom_scm_set_gpu_smmu_aperture), through the allow-listed forwarder:
             * transport failure, EUNDEF or EINTR (left pending in TrustZone) fail; another answer is logged by Linux
             * and q1n1 and recovery goes on (R10). */
            uint64_t r[8] = {ADRENO_SMC_CP_APERTURE, 4, ADRENO_SMC_APERTURE_CB0, ADRENO_SMC_FILL, 0, 0, 0, 0};
            if (adreno_smc(o, p->flags, s, r) || r[0] == (uint64_t)-7 || r[0] == (uint64_t)-10) {
                *step = ADRENO_RECOVER_STEP_SMC;
                return -1;
            }
            break;
        }
        default: *step = ADRENO_RECOVER_STEP_TABLE; return -1;
        }
    }
    return 0;
}

void adreno_recover_init(const struct adreno_ops *o, const struct adreno_params *p, const struct adreno_state *s,
                         struct adreno_recover_state *rs)
{
    if (!rs) return;
    rs->level = SNAP_ADRENO_RECOVER;
    if (rs->level < 2) return;
    const uint64_t sqe = p ? p->ring_pa - ADRENO_RECOVER_SQE_BELOW_RING : 0;
    if (!o || !p || !s || (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)) != (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED) ||
        p->ring_pa < p->arena_base + ADRENO_RECOVER_SQE_BELOW_RING || sqe < p->arena_base ||
        sqe + ADRENO_RECOVER_SQE_BYTES > p->ring_pa || !(RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16)) ||
        (p->fence_pa & 0xfff) != ADRENO_IB_BR_FENCE_OFF ||
        !recover_table_ok(adreno_recover_hw_init, TABLE_N(adreno_recover_hw_init)) ||
        !recover_table_ok(adreno_recover_sqe_start, TABLE_N(adreno_recover_sqe_start)) ||
        !recover_table_ok(adreno_recover_secvid, TABLE_N(adreno_recover_secvid))
#if !ADRENO_DIRECT
        || !o->rd || !o->wr || !o->clean || !o->now || !o->smc || !o->hz
#endif
        ) {
        rs->level = 1;
        rs->init_refused = ADRENO_RECOVER_STEP_INIT;
        return;
    }
    rs->sqe_pa = sqe;
    rs->sqe_sum = recover_sqe_sum(o, sqe);
}

static int recover_fail(struct adreno_recover_state *rs, int cause, int step, uint64_t t0, const struct adreno_ops *o)
{
    rs->dead = (uint64_t)cause << 8 | (uint64_t)step;
    rs->failures++;
    rs->last_ticks = NOW(o) - t0;
    return ADRENO_RECOVER_E_DEAD;
}
int adreno_recover(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                   struct adreno_ib_flight *f, struct adreno_recover_state *rs, int cause)
{
    if (!rs) return ADRENO_E_PARAMS;
    if (rs->level < 2) return ADRENO_IB_E_UNCERTAIN;
    if (rs->dead) return ADRENO_RECOVER_E_DEAD;
    if (!o || !p || !s || s->quiesce || (f && f->active) ||
        (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED | ADRENO_S_HIJACKED)) !=
            (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)) return ADRENO_E_PARAMS;
    const uint64_t t0 = NOW(o);
    int step = 0;
    rs->attempts++;
    rs->last_cause = (uint64_t)cause;
    for (unsigned i = 0; i < 8; i++) rs->snap[i] = 0;
    if (RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16)) {
        rs->snap[5] = RD(o, ADRENO_CB0 + ADRENO_CB_FSR);
        rs->snap[6] = RD(o, ADRENO_SMMU_SGFSR);
        if (!(RD(o, ADRENO_GMU_PWR_CLK_STATUS) & 3u)) {
            rs->snap[0] = RD(o, ADRENO_RBBM_STATUS);
            rs->snap[1] = RD(o, ADRENO_RBBM_INT_0_STATUS);
            rs->snap[2] = RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL);
            rs->snap[3] = RD(o, ADRENO_CP_RB_RPTR);
            rs->snap[4] = RD(o, ADRENO_CP_RB_WPTR);
            rs->snap[7] = RD(o, ADRENO_CP_SQE_CNTL);
        }
    }
    /* R24: at most ADRENO_RECOVER_BURST resets within the window, ADRENO_RECOVER_MAX per boot. */
    if (rs->epoch >= ADRENO_RECOVER_MAX ||
        (rs->epoch >= ADRENO_RECOVER_BURST &&
         t0 - rs->times[rs->epoch % ADRENO_RECOVER_BURST] < (uint64_t)ADRENO_RECOVER_WINDOW_SECONDS * o->hz))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_POLICY, t0, o);
    /* R6, R4, R8: power, the adopted CB0 and the SQE image, before anything is written. */
    if (!recover_power(o)) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_POWER, t0, o);
    if (!recover_cb0(o, p)) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_CB0, t0, o);
    if (recover_sqe_sum(o, rs->sqe_pa) != rs->sqe_sum) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_SQE_IMAGE, t0, o);
    /* q1n1's llcc-gpu step (not part of cp-fence) programs the GPU's LLCC SCIDs in GBIF: kept across the reset. */
    const uint32_t scache0 = RD(o, ADRENO_GBIF_SCACHE_CNTL0), scache1 = RD(o, ADRENO_GBIF_SCACHE_CNTL1);
    /* R1: halt the SQE (a8xx_recover), then GPU traffic, each acknowledged (a8xx_bus_clear_pending_transactions). */
    WR(o, ADRENO_CP_SQE_CNTL, 3);
    WR(o, ADRENO_RBBM_GBIF_HALT, 1);
    if (recover_wait(o, ADRENO_RBBM_GBIF_HALT_ACK, 1, 1, o->hz / 1000))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_HALT_GX, t0, o);
    WR(o, ADRENO_GBIF_HALT, 1);
    if (recover_wait(o, ADRENO_GBIF_HALT_ACK, 1, 1, o->hz / 1000))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_HALT_CX, t0, o);
    WR(o, ADRENO_GBIF_HALT, 2);
    if (recover_wait(o, ADRENO_GBIF_HALT_ACK, 2, 2, o->hz / 1000))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_HALT_CX, t0, o);
    /* R5: a CB0 or global fault is recorded and cleared (W1C) before the reset. */
    adreno_fault_poll(o, s);
    /* The pulse (a6xx_gpu_sw_reset: write, read back, at least 100 us asserted). It must reach the CP: the SQE is off. */
    WR(o, ADRENO_RBBM_SW_RESET_CMD, 1);
    (void)RD(o, ADRENO_RBBM_SW_RESET_CMD);
    const uint64_t pulse = NOW(o);
    for (unsigned reads = 0; reads < 2 || NOW(o) - pulse <= o->hz / 10000; reads++) (void)RD(o, ADRENO_RBBM_SW_RESET_CMD);
    WR(o, ADRENO_RBBM_SW_RESET_CMD, 0);
    (void)RD(o, ADRENO_RBBM_SW_RESET_CMD);
    if (RD(o, ADRENO_CP_SQE_CNTL) & 3u) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_RESET, t0, o);
    /* R3: no word of the old ring survives (the guilty CP_INDIRECT_BUFFER included); RPTR shadows back to 0
     * (adreno_hw_init). The fence slots are written by the next IB before its doorbell. */
    for (uint64_t i = 0; i < p->ring_dwords; i++) WR(o, p->ring_pa + 4 * i, 0);
    CLEAN(o, p->ring_pa, 4 * p->ring_dwords);
    const uint64_t memptrs = p->fence_pa - ADRENO_IB_BR_FENCE_OFF;
    WR(o, memptrs + 0x0, 0);
    WR(o, memptrs + 0x8, 0);
    CLEAN(o, memptrs, 16);
    /* R9, R10: q1n1's hw_init (GBIF unhalted by its own first writes), then power and CB0 again. A write the GMU's
     * AHB fence dropped shows in the proofs below (SQE start, CP_ME_INIT, SECVID read-back), not in WRITEDROPPED,
     * which an earlier dropped doorbell can still show. */
    if (recover_replay(o, p, s, adreno_recover_hw_init, TABLE_N(adreno_recover_hw_init), &step))
        return recover_fail(rs, cause, step, t0, o);
    if (RD(o, ADRENO_GBIF_SCACHE_CNTL1) != scache1) WR(o, ADRENO_GBIF_SCACHE_CNTL1, scache1);
    if (RD(o, ADRENO_GBIF_SCACHE_CNTL0) != scache0) WR(o, ADRENO_GBIF_SCACHE_CNTL0, scache0);
    if (!recover_power(o) || !recover_cb0(o, p)) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_AFTER, t0, o);
    /* R11: the SQE starts, then CP_ME_INIT on a ring the CP reads from 0 (R12). */
    if (recover_replay(o, p, s, adreno_recover_sqe_start, TABLE_N(adreno_recover_sqe_start), &step))
        return recover_fail(rs, cause, step, t0, o);
    if (!(RD(o, ADRENO_CP_SQE_CNTL) & 1)) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_ME_INIT, t0, o);
    s->wptr = 0;
    if (adreno_ring_ready(o, p, s, sizeof adreno_recover_me_init / 4))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_RING, t0, o);
    if (recover_ring(o, p, s, adreno_recover_me_init, sizeof adreno_recover_me_init / 4))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_ME_INIT, t0, o);
    /* C5: SECVID non-secure (read back), the BR GMEM protect, the aperture clear. */
    if (recover_replay(o, p, s, adreno_recover_secvid, TABLE_N(adreno_recover_secvid), &step))
        return recover_fail(rs, cause, step, t0, o);
    /* R2: drop whatever the GPU caches still hold before any CACHE_CLEAN can write it back. */
#define TC(t) A8XX_PKT_CP_THREAD_CONTROL_0__THREAD(A8XX_E_CP_SET_THREAD_##t)
#define EV(e) A8XX_PKT_CP_EVENT_WRITE7_0__EVENT(A8XX_E_##e)
    const uint32_t tc = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1), ev1 = a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 1);
    const uint32_t scrub[RECOVER_SCRUB_WORDS] = {tc, TC(BR), ev1, EV(CCU_INVALIDATE_DEPTH), ev1, EV(CCU_INVALIDATE_COLOR),
                                                 ev1, EV(CACHE_INVALIDATE7), tc, TC(BOTH)};
    if (recover_ring(o, p, s, scrub, RECOVER_SCRUB_WORDS))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_SCRUB, t0, o);
    /* Sticky bits the hang left (RBBM_INT_CLEAR_CMD, as a8xx_irq clears them): none may remain. */
    WR(o, ADRENO_RBBM_INT_CLEAR_CMD, RD(o, ADRENO_RBBM_INT_0_STATUS));
    if (recover_errors(o)) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_STICKY, t0, o);
    if (!recover_power(o) || !recover_cb0(o, p) || recover_faults(o))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_AFTER, t0, o);
    /* R12: the proving fence: BR, after the GPU is idle, a CP_MEM_WRITE into the monitor's slot (the F7 form). */
    const uint32_t mark = RECOVER_FENCE_MARK | (uint32_t)((rs->epoch + 1) & 0xfff);
    const uint32_t fence[RECOVER_FENCE_WORDS] = {tc, TC(BR) | A8XX_PKT_CP_THREAD_CONTROL_0__SYNC_THREADS(1),
                                                 a8xx_pkt7_hdr(A8XX_E_CP_WAIT_FOR_IDLE, 0), ADRENO_PKT7_MEM_WRITE3,
                                                 (uint32_t)p->fence_va, (uint32_t)(p->fence_va >> 32), mark, tc, TC(BOTH)};
#undef TC
#undef EV
    WR(o, p->fence_pa, ~mark);
    CLEAN(o, p->fence_pa, 4);
    if (recover_ring(o, p, s, fence, RECOVER_FENCE_WORDS)) return recover_fail(rs, cause, ADRENO_RECOVER_STEP_FENCE, t0, o);
    CLEAN(o, p->fence_pa, 4);
    if (RD(o, p->fence_pa) != mark || recover_errors(o) || recover_faults(o))
        return recover_fail(rs, cause, ADRENO_RECOVER_STEP_FENCE, t0, o);
    rs->times[rs->epoch % ADRENO_RECOVER_BURST] = t0;
    rs->epoch++;
    rs->last_ticks = NOW(o) - t0;
    if (f) f->reserved[2] = rs->epoch;
    return 0;
}

int adreno_recover_final(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, struct adreno_recover_state *rs, int e, int was_flight,
                         uint64_t regs[4])
{
    if (!rs || rs->level < 2 || rs->dead || (e != ADRENO_IB_E_UNCERTAIN && e != ADRENO_IB_E_GPU_ERROR)) return e;
    int cause = ADRENO_RECOVER_UNCERTAIN, fault = 0;
    if (e == ADRENO_IB_E_GPU_ERROR) cause = ADRENO_RECOVER_GPU_ERROR;
    if (RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16)) {
        fault = recover_faults(o);
        if (fault) cause = ADRENO_RECOVER_FAULT;
        else if (cause != ADRENO_RECOVER_GPU_ERROR && !(RD(o, ADRENO_GMU_PWR_CLK_STATUS) & 3u) && recover_errors(o))
            cause = ADRENO_RECOVER_EVIDENCE;
    }
    if (cause == ADRENO_RECOVER_UNCERTAIN && was_flight && f && f->last_ticks > ADRENO_IB_HARD_TICKS(o->hz))
        cause = ADRENO_RECOVER_HARD;
    if (adreno_recover(o, p, s, f, rs, cause)) return e;   /* gave up (or could not): the answer it would have had */
    const int answer = fault ? ADRENO_IB_E_RESET_FAULT : ADRENO_IB_E_RESET;
    if (was_flight && f) { f->last_status = answer; f->last_wptr = s->wptr; }
    if (regs) { regs[0] = (uint64_t)(int64_t)answer; regs[1] = 0; regs[3] = s->wptr; }
    return answer;
}

int adreno_recover_refuse(const struct adreno_recover_state *rs, struct adreno_state *s, uint64_t regs[4])
{
    if (!rs || !rs->dead || !s || !regs) return 0;
    switch (regs[0]) {
    case ADRENO_GUEST_IB: case ADRENO_GUEST_IB_START: s->ib_errors++; break;
    case ADRENO_GUEST_FENCE: case ADRENO_GUEST_FILL32:
        s->fence_ticks = 0;
        s->fence_error = (uint64_t)(int64_t)ADRENO_E_PARAMS;
        break;
    default: return 0;
    }
    ib_reply(regs, ADRENO_E_PARAMS, 0, 0, s->wptr);
    return ADRENO_E_PARAMS;
}

int adreno_recover_start(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, struct adreno_recover_state *rs, uint64_t regs[4],
                         uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                         uint64_t mem_low, uint64_t mem_high)
{
    if (!regs) return ADRENO_E_PARAMS;
    uint64_t in[4] = {regs[0], regs[1], regs[2], regs[3]};
    int e = adreno_guest_ib_start(o, p, s, f, regs, leaf, leaf_ctx, mem_low, mem_high);
    /* Sticky bits or a ring the CP left behind refuse every START before any write: at level 2 the GPU is reset and
     * the START tried once more (both refusals are before the doorbell, so nothing ran twice). */
    if (rs && rs->level >= 2 && !rs->dead && f && !f->active && (e == ADRENO_IB_E_STICKY || e == ADRENO_E_RING) &&
        !adreno_recover(o, p, s, f, rs, ADRENO_RECOVER_STICKY)) {
        rs->start_resets++;
        for (unsigned n = 0; n < 4; n++) regs[n] = in[n];
        e = adreno_guest_ib_start(o, p, s, f, regs, leaf, leaf_ctx, mem_low, mem_high);
    }
    if (e == ADRENO_IB_E_UNCERTAIN || e == ADRENO_IB_E_GPU_ERROR) e = adreno_recover_final(o, p, s, f, rs, e, 0, regs);
    return e;
}

int adreno_guest_recover(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, struct adreno_recover_state *rs, uint64_t regs[4])
{
    if (!o || !p || !s || !f || !rs || !regs) return ADRENO_E_PARAMS;
    const uint64_t op = regs[1];
    if (regs[0] != ADRENO_GUEST_RECOVER || regs[2] || regs[3] || op > ADRENO_RECOVER_SETTLE) {
        ib_reply(regs, ADRENO_E_PARAMS, 0, 0, s->wptr);
        return ADRENO_E_PARAMS;
    }
    if (op == ADRENO_RECOVER_QUERY) {
        rs->queries++;
        ib_reply(regs, 0, ADRENO_RECOVER_ABI | rs->level << 8 | (uint64_t)ADRENO_IB_HARD_SECONDS << 16, rs->epoch,
                 rs->dead ? ADRENO_RECOVER_STATE_DEAD : f->active ? ADRENO_RECOVER_STATE_FLIGHT : ADRENO_RECOVER_STATE_READY);
        return 0;
    }
    int e;
    uint64_t reset = 0;
    if (rs->dead) e = ADRENO_RECOVER_E_DEAD;
    else if (f->active) e = ADRENO_IB_E_BUSY;
    else if (s->quiesce || (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED | ADRENO_S_HIJACKED)) !=
                               (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)) e = ADRENO_E_PARAMS;
    else if (recover_settled(o, p, s)) { rs->settles++; e = 0; }
    else if (rs->level < 2) e = ADRENO_IB_E_UNCERTAIN;
    else {
        e = adreno_recover(o, p, s, f, rs, ADRENO_RECOVER_SETTLE_BUSY);
        if (!e) { rs->settle_resets++; reset = 1; }
    }
    ib_reply(regs, e, rs->epoch, reset, s->wptr);
    return e;
}
#endif
#else
int adreno_guest_ib(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                    uint64_t regs[4], uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                    uint64_t mem_low, uint64_t mem_high)
{
    if (!o || !p || !s || !regs) return ADRENO_E_PARAMS;
    const uint64_t va = regs[1], dwords = regs[2], bytes = regs[3];
    /* The completion slots: the monitor fence (memptrs + 0x80, BR) and its neighbour line (+0xc0, BV), both
     * in q1n1 cp-fence's UNPRIV_RW memptrs page (arena; CB0 root entry 0 maps fence_va's page to it). */
    const uint64_t br_pa = p->fence_pa, bv_pa = p->fence_pa - ADRENO_IB_BR_FENCE_OFF + ADRENO_IB_BV_FENCE_OFF;
    const uint64_t br_va = p->fence_va, bv_va = p->fence_va - ADRENO_IB_BR_FENCE_OFF + ADRENO_IB_BV_FENCE_OFF;
    uint64_t ticks = 0;
    uint32_t marker = 0;
    int e = ADRENO_E_PARAMS, rung;
    if (s->quiesce || regs[0] != ADRENO_GUEST_IB || !leaf || !o->hz ||
        (p->flags & (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING)) != (ADRENO_F_ENABLE | ADRENO_F_DART) ||
        (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED | ADRENO_S_HIJACKED)) !=
            (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED) ||
        (p->fence_pa & 0xfff) != ADRENO_IB_BR_FENCE_OFF || (p->fence_va & 0xfff) != ADRENO_IB_BR_FENCE_OFF) goto out;
#if !ADRENO_DIRECT
    if (!o->rd || !o->wr || !o->rd64 || !o->clean || !o->now) goto out;
#endif
    e = ADRENO_E_WINDOW;
    if (!dwords || dwords > ADRENO_IB_MAX_DWORDS || ((va | bytes) & (ADRENO_IB_ALIGN - 1)) ||
        bytes < ADRENO_IB_ALIGN_UP(4 * dwords) || bytes > ADRENO_IB_MAX_PACKAGE ||
        va < ADRENO_WINDOW_BASE || va >= ADRENO_WINDOW_END || bytes > ADRENO_WINDOW_END - va) goto out;
    /* Placement, every page before anything else: the package cannot change under the CP. Native 16 KiB
     * leaf (valid, readable, NO-WRITE, byte bounds, guest RAM outside the arena) and every 4 KiB CB0 slot. */
    e = ADRENO_E_TARGET;
    for (uint64_t at = va; at < va + bytes;) {
        uint64_t offset = at & 0x3fff, chunk = 0x4000 - offset;
        if (chunk > va + bytes - at) chunk = va + bytes - at;
        uint64_t d = leaf(leaf_ctx, at & ~0x3fffUL), pa = leaf_pa(d);
        uint64_t begin = (d >> 52) * 4, stop = (((d >> 40) & 0xfff) + 1) * 4;
        if (!(d & 1) || (d & 8) || !(d & 4) || offset < begin || offset >= stop || chunk > stop - offset ||
            pa < mem_low || pa >= mem_high || mem_high - pa < 0x4000 ||
            (pa < p->arena_base + p->arena_size && p->arena_base < pa + 0x4000)) goto out;
        for (uint64_t sub = at & ~0xfffUL; sub < at + chunk; sub += 0x1000)
            if (RD64(o, L3_SLOT(p, sub)) != ((pa + (sub & 0x3fff)) | ADRENO_LEAF(o) | ADRENO_PTE_RDONLY))
                goto out;
        at += chunk;
    }
    /* Power, bus and SMMU as FILL32, then the ring, then what only an IB needs: an idle, error-free GPU. */
    e = ADRENO_E_CX;
    if (!(RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16))) goto out;
    e = ADRENO_E_GX;
    if (RD(o, ADRENO_GMU_PWR_CLK_STATUS) & 3u) goto out;
    e = ADRENO_E_HALT;
    if (RD(o, ADRENO_RBBM_GBIF_HALT_ACK) & 1) goto out;
    e = ADRENO_E_CB0;
    uint64_t ttbr = RD(o, ADRENO_CB0 + ADRENO_CB_TTBR0) | (uint64_t)RD(o, ADRENO_CB0 + ADRENO_CB_TTBR0 + 4) << 32;
    if (ttbr != p->cb0_ttbr0 || RD(o, ADRENO_CB0 + ADRENO_CB_TCR) != p->cb0_tcr ||
        ((RD(o, ADRENO_CB0 + ADRENO_CB_SCTLR) ^ p->cb0_sctlr) & ~ADRENO_SCTLR_FIXED)) goto out;
#if SNAP_ADRENO_COHERENT
    if (!ADRENO_CB0_MAIR_OK(o, RD(o, ADRENO_CB0 + ADRENO_CB_MAIR0))) goto out;
#endif
    e = ADRENO_E_FAULT;
    if ((RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR)) goto out;
    e = ADRENO_E_SQE;
    if (!(RD(o, ADRENO_CP_SQE_CNTL) & 1)) goto out;
    e = adreno_ring_ready(o, p, s, ADRENO_IB_RING_WORDS);
    if (e) goto out;
    e = ADRENO_IB_E_BUSY;                                /* q1n1 p67_ready: idle but the CPU's own access */
    if (RD(o, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE) goto out;
    e = ADRENO_IB_E_STICKY;                              /* q1n1 interrupt_faults: nothing clears these */
    if ((RD(o, ADRENO_RBBM_INT_0_STATUS) & ADRENO_IB_RBBM_INT_ERRORS) ||
        (RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL) & ADRENO_IB_CP_GLOBAL_FAULTS)) goto out;

    /* Nothing refused. The kext wrote the package through its cacheable mapping and neither the CP's fetch
     * nor the GPU's reads snoop (Stage 3 non-coherent attributes): every package byte goes to PoC. */
    for (uint64_t at = va; at < va + bytes;) {
        uint64_t offset = at & 0x3fff, chunk = 0x4000 - offset;
        if (chunk > va + bytes - at) chunk = va + bytes - at;
        CLEAN(o, leaf_pa(leaf(leaf_ctx, at & ~0x3fffUL)) + offset, chunk);
        at += chunk;
    }
    uint64_t at;
    e = adreno_ring_reserve(o, p, s, ADRENO_IB_RING_WORDS, &at, &rung);
    if (e) { if (rung) e = ADRENO_IB_E_UNCERTAIN; goto out; }
    /* One marker per doorbell attempt. Both slots start one below it: CP_WAIT_TIMESTAMP (TS_WAIT_GE_32B, a
     * signed >=) holds BR until the BV fence lands, and neither slot can read the marker before the GPU
     * writes it (a stale value from an earlier submission included). */
    marker = ADRENO_IB_MARKER_BASE ^ (uint32_t)++s->ib_submits;
    if (!marker) marker = ADRENO_IB_MARKER_BASE ^ (uint32_t)++s->ib_submits;   /* x1 == 0 means failure */
    WR(o, br_pa, marker - 1);
    WR(o, bv_pa, marker - 1);
    CLEAN(o, br_pa, 4);
    CLEAN(o, bv_pa, 4);
    uint32_t w[ADRENO_IB_RING_WORDS];
    unsigned n = adreno_ib_ring_words(w, va, (uint32_t)dwords, br_va, bv_va, marker);
    for (unsigned i = 0; i < n; i++) WR(o, p->ring_pa + 4 * (at + i), w[i]);
    /* From here on a failure cannot prove the IB retired: UNCERTAIN (retain everything, no more work). */
    e = ADRENO_IB_E_UNCERTAIN;
    if (adreno_ring_kick(o, p, s, at, n)) goto out;
    uint64_t start = NOW(o);
    for (unsigned reads = 0;; reads++) {
        CLEAN(o, br_pa, 4);
        CLEAN(o, bv_pa, 4);
        ticks = NOW(o) - start;
        if ((RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR)) goto out;
        /* A memory write can forge a fence value; it cannot move RPTR to WPTR or make RBBM idle. */
        if (RD(o, br_pa) == marker && RD(o, bv_pa) == marker && RD(o, ADRENO_CP_RB_RPTR) == s->wptr &&
            !(RD(o, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE)) break;
        if (reads >= 2 && ticks > o->hz / ADRENO_IB_POLL_DIVISOR) goto out;
    }
    /* Retired and idle. An error the IB raised makes its output invalid; the GPU needs recovery. */
    e = ADRENO_IB_E_GPU_ERROR;
    if ((RD(o, ADRENO_RBBM_INT_0_STATUS) & ADRENO_IB_RBBM_INT_ERRORS) ||
        (RD(o, ADRENO_CP_INTERRUPT_STATUS_GLOBAL) & ADRENO_IB_CP_GLOBAL_FAULTS) ||
        (RD(o, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR)) goto out;
    s->ib_dwords += dwords;
    e = 0;
out:
    if (e) s->ib_errors++;
    regs[0] = (uint64_t)(int64_t)e;
    regs[1] = e ? 0 : marker;
    regs[2] = ticks;
    regs[3] = s->wptr;
    return e;
}
#endif
