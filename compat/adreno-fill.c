/* SPDX-License-Identifier: MIT */
/* CP_MEM_WRITE packet format: q1n1 tools/adreno_x2.py pkt7, opcode 0x3d.
 * Additional candidate source only; no current boot input is changed. */
#include "adreno-fill.h"
#if SNAP_ADRENO_FILL_BR
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
/* F4: the words emitted below -- THREAD_CONTROL 2, MEM_WRITE header + VA 3, WAIT_MEM_WRITES 1, marker 4,
 * THREAD_CONTROL 2 -- are the count reserved and rung. */
_Static_assert(ADRENO_FILL32_BR_EXTRA == 2 + 3 + 1 + 4 + 2, "FILL32 BR words");
_Static_assert(A8XX_E_CP_MEM_WRITE == 0x3du && A8XX_E_CP_THREAD_CONTROL == 0x17u && A8XX_E_CP_WAIT_MEM_WRITES == 0x12u,
               "FILL32 BR opcodes");
#endif

#if ADRENO_DIRECT
#define READ(o, pa) ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa))
#define WRITE(o, pa, value) ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa) = (uint32_t)(value))
#define READ64(o, pa) ((void)(o), *(volatile uint64_t *)(uintptr_t)(pa))
static void clean_fill(const struct adreno_ops *ops, uint64_t pa, uint64_t size)
{
    (void)ops;
    for (uint64_t line = pa & ~63UL; line < pa + size; line += 64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static uint64_t fill_now(const struct adreno_ops *ops)
{
    uint64_t ticks;
    (void)ops;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(ticks) :: "memory");
    return ticks;
}
#define CLEAN(o, pa, size) clean_fill(o, pa, size)
#define NOW(o) fill_now(o)
#else
#define READ(o, pa) ((o)->rd((o)->ctx, pa))
#define WRITE(o, pa, value) ((o)->wr((o)->ctx, pa, (uint32_t)(value)))
#define READ64(o, pa) ((o)->rd64((o)->ctx, pa))
#define CLEAN(o, pa, size) ((o)->clean((o)->ctx, pa, size))
#define NOW(o) ((o)->now((o)->ctx))
#endif

static uint32_t odd_parity(uint32_t value)
{
    value ^= value >> 16;
    value ^= value >> 8;
    value ^= value >> 4;
    value ^= value >> 2;
    value ^= value >> 1;
    return (value ^ 1) & 1;
}

int adreno_guest_fill32(const struct adreno_ops *ops, const struct adreno_params *p,
                        struct adreno_state *s, uint64_t regs[4],
                        uint64_t (*leaf)(void *, uint64_t), void *context,
                        uint64_t mem_low, uint64_t mem_high)
{
    if (!ops || !p || !s || !regs) return ADRENO_E_PARAMS;
    uint64_t va = regs[1], size = regs[2], value = regs[3];
    int error = ADRENO_E_PARAMS, rung;
    s->fence_ticks = 0;
    if (s->quiesce || regs[0] != ADRENO_GUEST_FILL32 || value >> 32 || !leaf || !ops->hz ||
        (p->flags & (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING)) !=
            (ADRENO_F_ENABLE | ADRENO_F_DART) ||
        (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED | ADRENO_S_HIJACKED)) !=
            (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)) goto out;
#if !ADRENO_DIRECT
    if (!ops->rd || !ops->wr || !ops->rd64 || !ops->clean || !ops->now) goto out;
#endif
    error = ADRENO_E_WINDOW;
    if (!size || ((va | size) & 3) || size > ADRENO_FILL32_MAX_BYTES ||
        va < ADRENO_WINDOW_BASE || va >= ADRENO_WINDOW_END || size > ADRENO_WINDOW_END - va) goto out;
    error = ADRENO_E_TARGET;
    /* Complete every descriptor/mirror check before changing even the first
     * ring word. Native16KiB permissions/bounds are finer than mirrored4KiB.
     * The caller's service lock holds both representations stable. */
    for (uint64_t at = va; at < va + size;) {
        uint64_t offset = at & 0x3fff, bytes = 0x4000 - offset;
        if (bytes > va + size - at) bytes = va + size - at;
        uint64_t descriptor = leaf(context, at & ~0x3fffUL);
        uint64_t pa = (descriptor & 0x3ffffffc00UL) << 4;
        uint64_t begin = (descriptor >> 52) * 4;
        uint64_t end = (((descriptor >> 40) & 0xfff) + 1) * 4;
        if (!(descriptor & 1) || (descriptor & 12) || offset < begin || offset >= end || bytes > end - offset ||
            pa < mem_low || pa >= mem_high || mem_high - pa < 0x4000 ||
            (pa < p->arena_base + p->arena_size && p->arena_base < pa + 0x4000)) goto out;
        for (uint64_t sub = at & ~0xfffUL; sub < at + bytes; sub += 0x1000) {
            uint64_t slot = p->pool_pa + ADRENO_L3_OFFSET + ((sub - ADRENO_WINDOW_BASE) >> 12) * 8;
            if (READ64(ops, slot) != ((pa + (sub & 0x3fff)) | ADRENO_LEAF(ops))) goto out;
        }
        at += bytes;
    }
    error = ADRENO_E_CX;
    if (!(READ(ops, ADRENO_CX_CFG_GDSCR) & (1u << 16))) goto out;
    error = ADRENO_E_GX;
    if (READ(ops, ADRENO_GMU_PWR_CLK_STATUS) & 3u) goto out;
    error = ADRENO_E_HALT;
    if (READ(ops, ADRENO_RBBM_GBIF_HALT_ACK) & 1) goto out;
    error = ADRENO_E_CB0;
    uint64_t ttbr = READ(ops, ADRENO_CB0 + ADRENO_CB_TTBR0);
    ttbr |= (uint64_t)READ(ops, ADRENO_CB0 + ADRENO_CB_TTBR0 + 4) << 32;
    if (ttbr != p->cb0_ttbr0 || READ(ops, ADRENO_CB0 + ADRENO_CB_TCR) != p->cb0_tcr ||
        ((READ(ops, ADRENO_CB0 + ADRENO_CB_SCTLR) ^ p->cb0_sctlr) & ~ADRENO_SCTLR_FIXED)) goto out;
    error = ADRENO_E_FAULT;
    if ((READ(ops, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) ||
        READ(ops, ADRENO_SMMU_SGFSR)) goto out;
    error = ADRENO_E_SQE;
    if (!(READ(ops, ADRENO_CP_SQE_CNTL) & 1)) goto out;
#if SNAP_ADRENO_FILL_BR
    uint64_t data_words = size / 4, total_words = data_words + ADRENO_FILL32_BR_EXTRA, at;
#else
    uint64_t data_words = size / 4, total_words = data_words + 7, at;
#endif
    /* ADRENO_E_RING: pointers, CP_RB_CNTL size or room (compat/adreno.h adreno_ring_ready). */
    error = adreno_ring_ready(ops, p, s, total_words);
    if (error) goto out;
    /* The ring wraps with CP_NOP padding (design S1); a padding doorbell is a doorbell. */
    error = adreno_ring_reserve(ops, p, s, total_words, &at, &rung);
    if (error) { if (rung) error = ADRENO_FILL32_E_UNCERTAIN; goto out; }

    uint64_t ring = p->ring_pa + at * 4;
    uint32_t marker = 0x534e6000u ^ (uint32_t)(s->fences + 1);
    uint32_t count = (uint32_t)data_words + 2;
    uint32_t header = 0x703d0000u | count | (odd_parity(count) << 15);
    /* Only the private marker is primed by the CPU. Destination bytes are
     * exclusively emitted as CP payload; no CPU destination write/clean. */
    WRITE(ops, p->fence_pa, ~marker);
    CLEAN(ops, p->fence_pa, 4);
#if SNAP_ADRENO_FILL_BR
    /* BR only, after BV has caught up (SYNC_THREADS); the marker after CP_WAIT_MEM_WRITES; then BOTH again. */
    const uint32_t thread = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1);
    WRITE(ops, ring, thread);
    WRITE(ops, ring + 4, A8XX_PKT_CP_THREAD_CONTROL_0__THREAD(A8XX_E_CP_SET_THREAD_BR) |
                         A8XX_PKT_CP_THREAD_CONTROL_0__SYNC_THREADS(1));
    ring += 8;
#endif
    WRITE(ops, ring, header);
    WRITE(ops, ring + 4, (uint32_t)va);
    WRITE(ops, ring + 8, (uint32_t)(va >> 32));
    for (uint64_t n = 0; n < data_words; n++) WRITE(ops, ring + 12 + 4 * n, value);
    uint64_t completion = ring + 12 + 4 * data_words;
#if SNAP_ADRENO_FILL_BR
    WRITE(ops, completion, a8xx_pkt7_hdr(A8XX_E_CP_WAIT_MEM_WRITES, 0));
    completion += 4;
#endif
    WRITE(ops, completion, ADRENO_PKT7_MEM_WRITE3);
    WRITE(ops, completion + 4, (uint32_t)p->fence_va);
    WRITE(ops, completion + 8, (uint32_t)(p->fence_va >> 32));
    WRITE(ops, completion + 12, marker);
#if SNAP_ADRENO_FILL_BR
    WRITE(ops, completion + 16, thread);
    WRITE(ops, completion + 20, A8XX_PKT_CP_THREAD_CONTROL_0__THREAD(A8XX_E_CP_SET_THREAD_BOTH));
#endif

    /* From this point on, an unsuccessful attempt cannot prove retirement. The kick cleans the words
     * and rings WPTR with a6xx_fenced_write (one retry). */
    error = ADRENO_FILL32_E_UNCERTAIN;
    if (adreno_ring_kick(ops, p, s, at, total_words)) goto out;
    uint64_t start = NOW(ops);
    for (unsigned reads = 0;; reads++) {
        CLEAN(ops, p->fence_pa, 4);
        s->fence_ticks = NOW(ops) - start;
        if ((READ(ops, ADRENO_CB0 + ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) ||
            READ(ops, ADRENO_SMMU_SGFSR)) goto out;
#if SNAP_ADRENO_FILL_BR
        if (READ(ops, p->fence_pa) == marker && READ(ops, ADRENO_CP_RB_RPTR) == s->wptr &&
            !(READ(ops, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE)) break;
#else
        if (READ(ops, p->fence_pa) == marker && READ(ops, ADRENO_CP_RB_RPTR) == s->wptr) break;
#endif
        if (reads >= 2 && s->fence_ticks > ops->hz / 20) goto out;
    }
    s->fences++;
    s->fence_last = marker;
    error = 0;
out:
    if (error) s->fence_error = (uint64_t)(int64_t)error;
    regs[0] = (uint64_t)(int64_t)error;
    regs[1] = error ? 0 : size;
    regs[2] = s->fence_ticks;
    regs[3] = s->wptr;
    return error;
}
