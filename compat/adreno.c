/* SPDX-License-Identifier: MIT */
/* See adreno.h. No libc: this links into the monitor and the native test. */
#include "adreno.h"
#if SNAP_ADRENO_FENCE_BR
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
/* F7: THREAD_CONTROL 2, WAIT_FOR_IDLE 1, MEM_WRITE 4, THREAD_CONTROL 2 -- the count reserved and rung. */
_Static_assert(ADRENO_FENCE_BR_WORDS == 2 + 1 + 4 + 2, "fence BR words");
_Static_assert(A8XX_E_CP_THREAD_CONTROL == 0x17u && A8XX_E_CP_WAIT_FOR_IDLE == 0x26u, "fence BR opcodes");
#endif

#if ADRENO_DIRECT
/* The monitor: q1n1's EL2 identity map reaches device and DRAM words alike.
 * The host tests take the same code through struct adreno_ops. */
#define RD(o, pa)      ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa))
#define WR(o, pa, v)   ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa) = (uint32_t)(v))
#define RD64(o, pa)    ((void)(o), *(volatile uint64_t *)(uintptr_t)(pa))
#define WR64(o, pa, v) ((void)(o), *(volatile uint64_t *)(uintptr_t)(pa) = (v))
static void clean(const struct adreno_ops *o, uint64_t pa, uint64_t size)
{
    (void)o;
    for (uint64_t line = pa & ~63UL; line < pa + size; line += 64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static uint64_t now(const struct adreno_ops *o)
{
    uint64_t t;
    (void)o;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(t) :: "memory");
    return t;
}
static void invalidate(const struct adreno_ops *o, uint64_t pa, uint64_t size)
{
    (void)o;
    for (uint64_t line = pa; line < pa + size; line += 64)
        __asm__ volatile("dc ivac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
#define CLEAN(o, pa, size) clean(o, pa, size)
#define INVALIDATE(o, pa, size) invalidate(o, pa, size)
#define NOW(o) now(o)
#else
#define RD(o, pa)      ((o)->rd((o)->ctx, (pa)))
#define WR(o, pa, v)   ((o)->wr((o)->ctx, (pa), (uint32_t)(v)))
#define RD64(o, pa)    ((o)->rd64((o)->ctx, (pa)))
#define WR64(o, pa, v) ((o)->wr64((o)->ctx, (pa), (v)))
#define CLEAN(o, pa, size) ((o)->clean((o)->ctx, (pa), (size)))
#define INVALIDATE(o, pa, size) ((o)->invalidate((o)->ctx, (pa), (size)))
#define NOW(o)         ((o)->now((o)->ctx))
#endif

#define CX_ON(o)  (RD(o, ADRENO_CX_CFG_GDSCR) & (1u << 16))
#define GX_ON(o)  (!(RD(o, ADRENO_GMU_PWR_CLK_STATUS) & 3u))
#define CB(o, r)  RD(o, ADRENO_CB0 + (r))
/* The mirror's level-3 entries form one array: 2 MiB-aligned direct mapping. */
#define L3_SLOT(p, va) ((p)->pool_pa + ADRENO_L3_OFFSET + (((va) - ADRENO_WINDOW_BASE) >> 12) * 8)
_Static_assert(ADRENO_WINDOW_END <= 1ULL << (64 - ADRENO_CB0_T0SZ) && ADRENO_ROOT_SLOTS <= 512 &&
               ADRENO_L2_TABLES + 1 == ADRENO_ROOT_SLOTS && ADRENO_L2_TABLES * 512 == ADRENO_L3_TABLES,
               "the window fits CB0's VA size, one level-2 table per root entry 1.., 512 level-3 tables each");

/* One row per HWIO sub-block run (A16 UEFI GFX map), ascending, no gaps. */
static const struct { uint32_t end; uint8_t block; } map[] = {
    {0x03d37000, ADRENO_PASS},          /* RBBM, DBGC, CP, VSC, UCHE, GBIF, GRAS .. BROADCAST */
    {0x03d3b000, ADRENO_GMU_GX},        /* GPU_GMU_GX_BLK_DEC0/1 */
    {0x03d3c000, ADRENO_RDVM},          /* GPU_RDVM */
    {0x03d40000, ADRENO_PASS},          /* GPU_CP_BLK_DEC3, GPU_RBBM_BLK_DEC2 (SECVID) */
    {0x03d50000, ADRENO_GMU_AO},        /* GPU_GMU_AO_BLK_DEC0 */
    {0x03d60000, ADRENO_RSCC},          /* GPU_RSCC */
    {0x03d64000, ADRENO_SMMU_APERTURE}, /* GPU_SMMU_APERTURE_BLK_DEC0, GPU_CX_DBGC */
    {0x03d6a000, ADRENO_GXCLKCTL},      /* GPU_GXCLKCTL, GPU_ACD */
    {0x03d90000, ADRENO_GMU_CX},        /* GMU_AO_BLK_DEC1..4, GMU_CX, GDPM, MXCPR */
    {0x03d9e000, ADRENO_GPUCC},         /* GPUCC, GPU_CPR */
    {0x03da0000, ADRENO_CX_MISC},       /* GPU_CX_MISC_BLK_DEC0/1 */
    {(uint32_t)ADRENO_END, ADRENO_SMMU},/* GPU_SMMU, SMMU_SS_LOCAL, QTB */
};

unsigned adreno_block(uint64_t pa, uint64_t flags)
{
    if (pa < ADRENO_PA || pa >= ADRENO_END) return ADRENO_NONE;
    unsigned n = 0;
    while (pa >= map[n].end) n++;
    return map[n].block == ADRENO_CX_MISC && (flags & ADRENO_F_CX_MISC) ?
           ADRENO_CX_MISC_RO : map[n].block;
}

static int inside(const struct adreno_params *p, uint64_t pa, uint64_t size)
{
    return pa >= p->arena_base && size <= p->arena_size &&
           pa - p->arena_base <= p->arena_size - size;
}

static uint64_t ttbr0(const struct adreno_ops *o)
{
    return CB(o, ADRENO_CB_TTBR0) | (uint64_t)CB(o, ADRENO_CB_TTBR0 + 4) << 32;
}

static int wait_clear(const struct adreno_ops *o, uint64_t pa, uint32_t bits, uint64_t ticks)
{
    uint64_t start = NOW(o);
    for (unsigned reads = 0;; reads++) {
        if (!(RD(o, pa) & bits)) return 0;
        if (reads >= 2 && NOW(o) - start > ticks) return -1;
    }
}

static int tlbi(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s)
{
    /* arm_smmu_tlb_inv_context_s1 + arm_smmu_tlb_sync_context (q1n1 smmu_tlbi):
     * the ASID is cp-fence's (context bank index 0). */
    WR(o, ADRENO_CB0 + ADRENO_CB_TLBIASID, (uint32_t)(p->cb0_ttbr0 >> 48));
    WR(o, ADRENO_CB0 + ADRENO_CB_TLBSYNC, 0);
    if (wait_clear(o, ADRENO_CB0 + ADRENO_CB_TLBSTATUS, 1, o->hz / 1000)) {
        s->tlbi_timeouts++;
        return ADRENO_E_TLB;
    }
    s->tlbi++;
    return 0;
}
#if SNAP_ADRENO_COHERENT
/* compat/adreno-coherent.c maps and unmaps its own test leaves and needs the same invalidation as the mirror. */
int adreno_mirror_tlbi(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s)
{
    return tlbi(o, p, s);
}
#endif

int adreno_adopt(const struct adreno_ops *o, const struct adreno_params *p,
                 struct adreno_state *s, uint64_t mem_low, uint64_t mem_high)
{
    if (s->quiesce) return ADRENO_E_PARAMS; /* teardown is terminal, including failure */
    uint64_t end = p->arena_base + p->arena_size, root = p->cb0_ttbr0 & ADRENO_PTE_ADDR;
    /* probes/adreno.py and q1n1's adopt record check the layout in full; this
     * keeps what a wrong word here would turn into a stray DMA or table write:
     * an arena outside guest memory holding the pool, the ring, the fence slot
     * and CB0's root, and a root the pool does not cover. */
    const uint64_t in[4][2] = {{p->pool_pa, ADRENO_POOL_BYTES}, {p->ring_pa, p->ring_dwords * 4},
                               {p->fence_pa, 4}, {root, 0x1000}};
    int e = ADRENO_E_PARAMS;
    if ((p->flags & ~(uint64_t)ADRENO_F_ALL) || !(p->flags & ADRENO_F_ENABLE) ||
        (p->gicd & 0xffff) || !p->arena_base || ((p->arena_base | p->arena_size | p->pool_pa) & 0xfff) ||
        end < p->arena_base || (p->arena_base < mem_high && mem_low < end) ||
        (p->fence_pa & 3) || (p->fence_va >> 30) || p->ring_wptr >= p->ring_dwords || p->ring_dwords > 0x2000 ||
        (root >= p->pool_pa && root < p->pool_pa + ADRENO_POOL_BYTES))
        goto out;
#if ADRENO_VA_WIDE
    /* The wide pool is monitor memory (probes/xnuboot.py gpu_pool_reservation, FAILURE-MODES V5): never the
     * arena, never guest memory, no wrap (the root is kept out of it above). The params' TCR is the one the
     * mirror's 16 root entries need: T0SZ 30, TG0 4 KiB (V1); the live TCR must equal it below. */
    uint64_t pool_end = p->pool_pa + ADRENO_POOL_BYTES;
    if (pool_end < p->pool_pa || (p->pool_pa < end && p->arena_base < pool_end) ||
        (p->pool_pa < mem_high && mem_low < pool_end) ||
        (p->cb0_tcr & 0x3f) != ADRENO_CB0_T0SZ || ((p->cb0_tcr >> 14) & 3)) goto out;
    for (unsigned n = 1; n < 4; n++)
#else
    for (unsigned n = 0; n < 4; n++)
#endif
        if (!inside(p, in[n][0], in[n][1])) goto out;
    /* The power order q1n1 proves: CX (GPUCC status) before any CX block, the
     * GMU's word for GX before any GX register. */
    e = ADRENO_E_CX;
    if (!CX_ON(o)) goto out;
    e = ADRENO_E_GX;
    if (!GX_ON(o)) goto out;
    /* A GX-side halt a previous quiesce left (it holds until the next q1n1
     * hw_init): the CP could not fetch a fence, nor a guest ring. */
    e = ADRENO_E_HALT;
    if (RD(o, ADRENO_RBBM_GBIF_HALT_ACK) & 1) goto out;
    e = ADRENO_E_CB0;
    uint32_t sctlr = CB(o, ADRENO_CB_SCTLR);                 /* M set: never a bypassing bank */
    if (ttbr0(o) != p->cb0_ttbr0 || CB(o, ADRENO_CB_TCR) != (uint32_t)p->cb0_tcr ||
        ((sctlr ^ p->cb0_sctlr) & ~ADRENO_SCTLR_FIXED) || !(sctlr & 1)) goto out;
    e = ADRENO_E_FAULT;
    if ((CB(o, ADRENO_CB_FSR) & ADRENO_CB_FSR_FAULT) || RD(o, ADRENO_SMMU_SGFSR)) goto out;
    /* Design S1: the monitor wraps the ring where the CP does (q1n1 hw_init writes BUFSZ 12; every
     * A16 record reads CP_RB_CNTL 0x20c against the arena's 8192-dword cp_rb). */
    e = ADRENO_E_RING;
    if ((p->flags & (ADRENO_F_RING | ADRENO_F_DART)) &&
        p->ring_dwords != (uint64_t)2 << (RD(o, ADRENO_CP_RB_CNTL) & ADRENO_CP_RB_CNTL_BUFSZ)) goto out;
    if (p->flags & ADRENO_F_RING) {
        e = ADRENO_E_SQE;
        if (!(RD(o, ADRENO_CP_SQE_CNTL) & 1)) goto out;
        e = ADRENO_E_RING;
        if (RD(o, ADRENO_CP_RB_WPTR) != p->ring_wptr ||
            RD(o, ADRENO_CP_RB_RPTR) != p->ring_wptr) goto out;
    }
    s->wptr = p->ring_wptr;
    s->status |= ADRENO_S_ADOPTED | (p->flags & ADRENO_F_TZ_DONE ? ADRENO_S_TZ_DONE : 0);
    if (p->flags & ADRENO_F_DART) {
        /* cp-fence maps its buffers below 1 GiB: root entry 0 only. */
        CLEAN(o, root, 8 * ADRENO_ROOT_SLOTS);
        e = ADRENO_E_ROOT;
        for (unsigned g = 1; g < (unsigned)ADRENO_ROOT_SLOTS; g++)
            if (RD64(o, root + 8 * g)) goto out;
        /* Empty level-3 tables, then the level-2 tables that reach them, all in
         * memory before the root names them: the SMMU walks without snooping. */
        for (uint64_t a = p->pool_pa + ADRENO_L3_OFFSET; a < p->pool_pa + ADRENO_POOL_BYTES; a += 8)
            WR64(o, a, 0);
        for (uint64_t n = 0; n < ADRENO_L3_TABLES; n++)
            WR64(o, p->pool_pa + 8 * n, (p->pool_pa + ADRENO_L3_OFFSET + n * 0x1000) | 3);
        CLEAN(o, p->pool_pa, ADRENO_POOL_BYTES);
        for (unsigned g = 1; g < (unsigned)ADRENO_ROOT_SLOTS; g++)
            WR64(o, root + 8 * g, (p->pool_pa + (g - 1) * 0x1000) | 3);
        CLEAN(o, root, 8 * ADRENO_ROOT_SLOTS);
        s->status |= ADRENO_S_ATTACHED;
    }
    e = 0;
out:
    s->prepare = (uint64_t)(int64_t)e;
    return e;
}

/* PM4 type-7 header (adreno_pm4.xml pm4_parity; freedreno_pm4.h pm4_pkt7_hdr) of CP_NOP (opcode 0x10). */
static uint32_t pm4_parity(uint32_t v)
{
    return (0x9669u >> (0xfu & (v ^ (v >> 4) ^ (v >> 8) ^ (v >> 12) ^ (v >> 16) ^ (v >> 20) ^ (v >> 24) ^
                                (v >> 28)))) & 1u;
}
static uint32_t pkt7_nop(uint32_t count)
{
    return 0x70000000u | count | pm4_parity(count) << 15 | 0x10u << 16 | pm4_parity(0x10u) << 23;
}

/* a6xx_fenced_write of CP_RB_WPTR: GMU_AHB_FENCE_STATUS WRITEDROPPED must stay clear; one retry. */
static int ring_doorbell(const struct adreno_ops *o, uint64_t wptr)
{
    for (unsigned n = 0;; n++) {
        WR(o, ADRENO_CP_RB_WPTR, (uint32_t)wptr);
        if (!(RD(o, ADRENO_GMU_AHB_FENCE_STATUS) & 1)) return 0;
        if (n) return ADRENO_E_RING;
    }
}

int adreno_ring_ready(const struct adreno_ops *o, const struct adreno_params *p,
                      const struct adreno_state *s, uint64_t n)
{
    if (s->quiesce) return ADRENO_E_PARAMS;
    /* q1n1 ring_submit: the CP's own pointers decide; the size is the one CP_RB_CNTL gives the CP. */
    uint64_t w = s->wptr;
    if (RD(o, ADRENO_CP_RB_WPTR) != w || RD(o, ADRENO_CP_RB_RPTR) != w || w >= p->ring_dwords ||
        p->ring_dwords != (uint64_t)2 << (RD(o, ADRENO_CP_RB_CNTL) & ADRENO_CP_RB_CNTL_BUFSZ) ||
        !n || n > ADRENO_RING_EMIT_MAX(p->ring_dwords)) return ADRENO_E_RING;
    return 0;
}

int adreno_ring_reserve(const struct adreno_ops *o, const struct adreno_params *p,
                        struct adreno_state *s, uint64_t n, uint64_t *at, int *rung)
{
    uint64_t w = s->wptr, size = p->ring_dwords;
    *rung = 0;
    int e = adreno_ring_ready(o, p, s, n);
    if (e) return e;
    if (n < size - w) { *at = w; return 0; }
    /* KGSL adreno_ringbuffer_allocspace: no packet straddles the end, so the tail becomes CP_NOPs (each
     * header plus at most ADRENO_RING_NOP_MAX payload dwords, written as zeros) and the words go at 0. */
    for (uint64_t k = w; k < size;) {
        uint64_t count = size - k - 1 > ADRENO_RING_NOP_MAX ? ADRENO_RING_NOP_MAX : size - k - 1;
        WR(o, p->ring_pa + 4 * k, pkt7_nop((uint32_t)count));
        for (uint64_t i = 1; i <= count; i++) WR(o, p->ring_pa + 4 * (k + i), 0);
        k += count + 1;
    }
    CLEAN(o, p->ring_pa + 4 * w, 4 * (size - w));
    s->ring_wraps++;
    *at = 0;
    /* One doorbell at 0 + n then runs the padding and the words, unless the words would overwrite
     * padding the CP has not executed yet (and n == w would read as an empty ring). */
    if (n < w) return 0;
    *rung = 1;
    e = ring_doorbell(o, 0);
    if (e) return e;
    s->wptr = 0;
    uint64_t start = NOW(o);
    for (unsigned reads = 0;; reads++) {
        if (RD(o, ADRENO_CP_RB_RPTR) == 0) return 0;
        if (reads >= 2 && NOW(o) - start > o->hz / 20) return ADRENO_E_FENCE;
    }
}

int adreno_ring_kick(const struct adreno_ops *o, const struct adreno_params *p,
                     struct adreno_state *s, uint64_t at, uint64_t n)
{
    if (s->quiesce) return ADRENO_E_PARAMS;
    CLEAN(o, p->ring_pa + 4 * at, 4 * n);
    int e = ring_doorbell(o, at + n);
    if (!e) s->wptr = at + n;
    return e;
}

static int fence_at(const struct adreno_ops *o, const struct adreno_params *p,
                    struct adreno_state *s, uint64_t pa, uint64_t va, uint32_t value)
{
    int e = ADRENO_E_PARAMS, rung;
    s->fence_ticks = 0;
    if (s->quiesce || !(s->status & ADRENO_S_ADOPTED) || (s->status & ADRENO_S_QUIESCED)) goto out;
    e = ADRENO_E_CX;
    if (!CX_ON(o)) goto out;
    e = ADRENO_E_GX;
    if (!GX_ON(o)) goto out;
    e = ADRENO_E_SQE;
    if (!(RD(o, ADRENO_CP_SQE_CNTL) & 1)) goto out;
    /* ADRENO_E_RING (refused or dropped) or ADRENO_E_FENCE (the padding was not consumed). */
    uint64_t at;
#if SNAP_ADRENO_FENCE_BR
    e = adreno_ring_reserve(o, p, s, ADRENO_FENCE_BR_WORDS, &at, &rung);
    if (e) goto out;
    uint64_t word = p->ring_pa + 4 * at;
    const uint32_t thread = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1);
    WR(o, pa, ~value);
    CLEAN(o, pa, 4);
    WR(o, word, thread);
    WR(o, word + 4, A8XX_PKT_CP_THREAD_CONTROL_0__THREAD(A8XX_E_CP_SET_THREAD_BR) |
                    A8XX_PKT_CP_THREAD_CONTROL_0__SYNC_THREADS(1));
    WR(o, word + 8, a8xx_pkt7_hdr(A8XX_E_CP_WAIT_FOR_IDLE, 0));
    WR(o, word + 12, ADRENO_PKT7_MEM_WRITE3);
    WR(o, word + 16, (uint32_t)va);
    WR(o, word + 20, (uint32_t)(va >> 32));
    WR(o, word + 24, value);
    WR(o, word + 28, thread);
    WR(o, word + 32, A8XX_PKT_CP_THREAD_CONTROL_0__THREAD(A8XX_E_CP_SET_THREAD_BOTH));
    e = adreno_ring_kick(o, p, s, at, ADRENO_FENCE_BR_WORDS);
#else
    e = adreno_ring_reserve(o, p, s, 4, &at, &rung);
    if (e) goto out;
    uint64_t word = p->ring_pa + 4 * at;
    WR(o, pa, ~value);
    CLEAN(o, pa, 4);
    WR(o, word, ADRENO_PKT7_MEM_WRITE3);
    WR(o, word + 4, (uint32_t)va);
    WR(o, word + 8, (uint32_t)(va >> 32));
    WR(o, word + 12, value);
    e = adreno_ring_kick(o, p, s, at, 4);
#endif
    if (e) goto out;
    e = ADRENO_E_FENCE;
    uint64_t start = NOW(o), ticks;
    for (unsigned reads = 0;; reads++) {
        CLEAN(o, pa, 4);
        ticks = NOW(o) - start;
        s->fence_ticks = ticks;
#if SNAP_ADRENO_FENCE_BR
        if (RD(o, pa) == value && RD(o, ADRENO_CP_RB_RPTR) == s->wptr &&
            !(RD(o, ADRENO_RBBM_STATUS) & ~ADRENO_IB_RBBM_IDLE_IGNORE)) break;
#else
        if (RD(o, pa) == value &&
            RD(o, ADRENO_CP_RB_RPTR) == s->wptr) break;
#endif
        if (reads >= 2 && ticks > o->hz / 20) goto out;
    }
    s->fences++;
    s->fence_last = value;
    s->fence_ticks = ticks;
    e = 0;
out:
    if (e) s->fence_error = (uint64_t)(int64_t)e;
    return e;
}

int adreno_fence(const struct adreno_ops *o, const struct adreno_params *p,
                 struct adreno_state *s, uint32_t value)
{
    if (!(p->flags & ADRENO_F_RING)) {
        s->fence_error = (uint64_t)(int64_t)ADRENO_E_PARAMS;
        return ADRENO_E_PARAMS;
    }
    return fence_at(o, p, s, p->fence_pa, p->fence_va, value);
}

int adreno_guest_fence(const struct adreno_ops *o, const struct adreno_params *p,
                       struct adreno_state *s, uint64_t regs[4],
                       uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                       uint64_t mem_low, uint64_t mem_high)
{
    uint64_t va = regs[1], value = regs[2];
    int e = ADRENO_E_PARAMS;
    s->fence_ticks = 0;
    if (s->quiesce || regs[0] != ADRENO_GUEST_FENCE || regs[3] || value >> 32 || !leaf ||
        (p->flags & (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING)) !=
            (ADRENO_F_ENABLE | ADRENO_F_DART) ||
        (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED |
                      ADRENO_S_HIJACKED)) != (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)) goto out;
    e = ADRENO_E_TARGET;
    if ((va & 3) || va < ADRENO_WINDOW_BASE || va > ADRENO_WINDOW_END - 4) goto out;
    uint64_t d = leaf(leaf_ctx, va & ~0x3fffUL), pa = (d & 0x3ffffffc00UL) << 4;
    uint64_t begin = (d >> 52) * 4, stop = (((d >> 40) & 0xfff) + 1) * 4;
    uint64_t offset = va & 0x3fff;
    if (!(d & 1) || (d & 12) || offset < begin || offset + 4 > stop ||
        pa < mem_low || pa >= mem_high || mem_high - pa < 0x4000 ||
        (pa < p->arena_base + p->arena_size && p->arena_base < pa + 0x4000)) goto out;
    pa += offset;
    if (RD64(o, L3_SLOT(p, va)) != ((pa & ~0xfffUL) | ADRENO_LEAF(o))) goto out;
    e = fence_at(o, p, s, pa, va, (uint32_t)value);
out:
    if (e) s->fence_error = (uint64_t)(int64_t)e;
    regs[0] = (uint64_t)(int64_t)e;
    regs[1] = e ? 0 : s->fence_last;
    regs[2] = s->fence_ticks;
    regs[3] = s->wptr;
    return e;
}

#if SNAP_ADRENO_COHERENT
/* adreno_guest_cache, and with `writeback` its coherent variant (compat/adreno-coherent.c): the same validation and
 * refusals, then no maintenance for a frame writeback() reports as the CPU's Normal write-back; regs[2] is then the
 * bytes still maintained. Under the service token no attribute change runs between the passes. */
int adreno_guest_cache_filtered(const struct adreno_ops *o, const struct adreno_params *p,
                                struct adreno_state *s, uint64_t regs[4],
                                uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                                uint64_t mem_low, uint64_t mem_high,
                                int (*writeback)(void *ctx, uint64_t pa), void *writeback_ctx)
#else
int adreno_guest_cache(const struct adreno_ops *o, const struct adreno_params *p,
                       struct adreno_state *s, uint64_t regs[4],
                       uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                       uint64_t mem_low, uint64_t mem_high)
#endif
{
    uint64_t va=regs[1], size=regs[2], direction=regs[3];
#if SNAP_ADRENO_COHERENT
    uint64_t maintained=0;
    if (writeback) direction&=~(uint64_t)ADRENO_CACHE_COHERENT;
#endif
    int e=ADRENO_E_PARAMS;
    if (s->quiesce || regs[0]!=ADRENO_GUEST_CACHE || !leaf ||
        (direction!=ADRENO_CACHE_TO_DEVICE && direction!=ADRENO_CACHE_FROM_DEVICE) ||
        (p->flags & (ADRENO_F_ENABLE|ADRENO_F_DART|ADRENO_F_RING)) !=
            (ADRENO_F_ENABLE|ADRENO_F_DART) ||
        (s->status & (ADRENO_S_ADOPTED|ADRENO_S_ATTACHED|ADRENO_S_QUIESCED|ADRENO_S_HIJACKED)) !=
            (ADRENO_S_ADOPTED|ADRENO_S_ATTACHED)) goto out;
#if ADRENO_DIRECT
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    if ((4UL << ((ctr>>16)&15))!=64) goto out;
#else
    if (!o->rd64 || (direction==ADRENO_CACHE_TO_DEVICE ? !o->clean : !o->invalidate)) goto out;
#endif
    e=ADRENO_E_WINDOW;
    if (!size || ((va|size)&63) || size>ADRENO_CACHE_MAX_BYTES ||
        va<ADRENO_WINDOW_BASE || va>=ADRENO_WINDOW_END || size>ADRENO_WINDOW_END-va) goto out;
    e=ADRENO_E_TARGET;
    /* The caller's service lock prevents DART/mirror mutation across passes.
     * Reject a bad late page before performing any early-page maintenance. */
    for (unsigned pass=0;pass<2;pass++) {
        for (uint64_t at=va;at<va+size;) {
            uint64_t offset=at&0x3fff, bytes=0x4000-offset;
            if (bytes>va+size-at) bytes=va+size-at;
            uint64_t d=leaf(leaf_ctx,at&~0x3fffUL), pa=(d&0x3ffffffc00UL)<<4;
            if (!pass) {
                uint64_t begin=(d>>52)*4, stop=(((d>>40)&0xfff)+1)*4;
                if (!(d&1) || (d&8) || (direction==ADRENO_CACHE_FROM_DEVICE && (d&4)) ||
                    offset<begin || offset>=stop || bytes>stop-offset ||
                    pa<mem_low || pa>=mem_high || mem_high-pa<0x4000 ||
                    (pa<p->arena_base+p->arena_size && p->arena_base<pa+0x4000)) goto out;
                for (uint64_t sub=at&~0xfffUL;sub<at+bytes;sub+=0x1000) {
                    uint64_t want=(pa+(sub&0x3fff))|ADRENO_LEAF(o)|(d&4?ADRENO_PTE_RDONLY:0);
                    if (RD64(o,L3_SLOT(p,sub))!=want) goto out;
                }
#if SNAP_ADRENO_COHERENT
            } else if (writeback && writeback(writeback_ctx,pa)) {
            } else if ((maintained+=bytes,direction==ADRENO_CACHE_TO_DEVICE)) CLEAN(o,pa+offset,bytes);
#else
            } else if (direction==ADRENO_CACHE_TO_DEVICE) CLEAN(o,pa+offset,bytes);
#endif
            else INVALIDATE(o,pa+offset,bytes);
            at+=bytes;
        }
    }
    e=0;
out:
#if SNAP_ADRENO_COHERENT
    regs[0]=(uint64_t)(int64_t)e;regs[1]=e?0:size;regs[2]=e?0:maintained*!!writeback;regs[3]=s->wptr;
    return e;
}
int adreno_guest_cache(const struct adreno_ops *o, const struct adreno_params *p,
                       struct adreno_state *s, uint64_t regs[4],
                       uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                       uint64_t mem_low, uint64_t mem_high)
{
    return adreno_guest_cache_filtered(o,p,s,regs,leaf,leaf_ctx,mem_low,mem_high,0,0);
}
#else
    regs[0]=(uint64_t)(int64_t)e;regs[1]=e?0:size;regs[2]=0;regs[3]=s->wptr;
    return e;
}
#endif

int adreno_guest_unmap(const struct adreno_ops *o, const struct adreno_params *p,
                       struct adreno_state *s, uint64_t regs[4],
                       uint64_t (*leaf)(void *ctx, uint64_t iova),
                       int (*unmap)(void *ctx, uint64_t iova, uint64_t size), void *ctx,
                       uint64_t mem_low, uint64_t mem_high)
{
    uint64_t va = regs[1], size = regs[2];
    int e = ADRENO_E_PARAMS, native = 0;
    if (s->quiesce || regs[0] != ADRENO_GUEST_UNMAP || regs[3] || !leaf || !unmap ||
        (p->flags & (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING)) !=
            (ADRENO_F_ENABLE | ADRENO_F_DART) ||
        (s->status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED | ADRENO_S_QUIESCED |
                      ADRENO_S_HIJACKED)) != (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)) goto out;
    e = ADRENO_E_WINDOW;
    if (!size || ((va | size) & 0x3fff) || va < ADRENO_WINDOW_BASE ||
        va >= ADRENO_WINDOW_END || size > ADRENO_WINDOW_END - va ||
        size > (1UL << 25) - (va & ((1UL << 25) - 1))) goto out;
    e = ADRENO_E_CX;
    if (!CX_ON(o)) goto out;
    e = ADRENO_E_DART;
    native = unmap(ctx, va, size);
    if (native) goto out;
    s->unmaps++;
    for (uint64_t at = va; at < va + size; at += 0x4000)
        if (leaf(ctx, at)) goto out;
    e = adreno_mirror(o, p, s, va, size, leaf, ctx, mem_low, mem_high);
out:
    regs[0] = (uint64_t)(int64_t)e;
    regs[1] = e ? 0 : size;
    regs[2] = (uint64_t)(int64_t)native;
    regs[3] = s->wptr;
    return e;
}

int adreno_mirror(const struct adreno_ops *o, const struct adreno_params *p,
                  struct adreno_state *s, uint64_t iova, uint64_t size,
                  uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                  uint64_t mem_low, uint64_t mem_high)
{
    if (s->quiesce || !(s->status & ADRENO_S_ATTACHED)) return ADRENO_E_PARAMS;
    if (!size || iova < ADRENO_WINDOW_BASE || iova >= ADRENO_WINDOW_END ||
        size > ADRENO_WINDOW_END - iova) return ADRENO_E_WINDOW;
    if (!CX_ON(o)) return ADRENO_E_CX;
    uint64_t first = iova & ~0x3fffUL, end = (iova + size + 0x3fff) & ~0x3fffUL;
    uint64_t arena_end = p->arena_base + p->arena_size;
    int stale = 0;
    for (uint64_t va = first; va < end; va += 0x4000) {
        /* T8110 level-2 leaf (compat/sptm-dart.c leaf_descriptor): PA >> 4,
         * bit 2 no-write, bit 3 no-read, byte bounds [52:63] and [40:51]. */
        uint64_t d = leaf(leaf_ctx, va), pa = (d & 0x3ffffffc00UL) << 4;
        uint64_t begin = (d >> 52) * 4, stop = (((d >> 40) & 0xfff) + 1) * 4;
        int ok = (d & 1) && !(d & 8) && pa >= mem_low && pa < mem_high &&
                 mem_high - pa >= 0x4000 && !(pa < arena_end && p->arena_base < pa + 0x4000);
        if ((d & 1) && !ok) s->refused++;
        for (unsigned k = 0; k < 4; k++) {
            uint64_t slot = L3_SLOT(p, va + k * 0x1000);
            uint64_t want = ok && begin < (k + 1) * 0x1000UL && stop > k * 0x1000UL ?
                (pa + k * 0x1000) | ADRENO_LEAF(o) | (d & 4 ? ADRENO_PTE_RDONLY : 0) : 0;
            uint64_t old = RD64(o, slot);
            if (old == want) continue;
            WR64(o, slot, want);
            if (old & 1) { stale = 1; s->live_pages--; s->unmap_pages++; }
            if (want & 1) { s->live_pages++; s->map_pages++; }
        }
    }
    CLEAN(o, L3_SLOT(p, first), ((end - first) >> 12) * 8);
    return stale ? tlbi(o, p, s) : 0;
}

int adreno_fault_poll(const struct adreno_ops *o, struct adreno_state *s)
{
    if (!(s->status & ADRENO_S_ADOPTED) || !CX_ON(o)) return 0;
    uint32_t fsr = CB(o, ADRENO_CB_FSR), gfsr = RD(o, ADRENO_SMMU_SGFSR);
    if (!(fsr & ADRENO_CB_FSR_FAULT) && !gfsr) return 0;
    s->faults++;
    s->fault_fsr = fsr;
    s->fault_fsynr0 = CB(o, ADRENO_CB_FSYNR0);
    s->fault_far = CB(o, ADRENO_CB_FAR) | (uint64_t)CB(o, ADRENO_CB_FAR + 4) << 32;
    s->fault_cbfrsynra = RD(o, ADRENO_SMMU_CBFRSYNRA0);
    s->fault_gfsr = gfsr;
    if (fsr & ADRENO_CB_FSR_FAULT) WR(o, ADRENO_CB0 + ADRENO_CB_FSR, fsr);
    if (gfsr) WR(o, ADRENO_SMMU_SGFSR, gfsr);
    return 1;
}

int adreno_smc_allowed(uint64_t fid, uint64_t x1, uint64_t x2, uint64_t x3)
{
    if (fid == ADRENO_SMC_GPU_INIT) return x1 == 1 && x2 && !(x2 & ~0xfUL) && !x3;
    if (fid == ADRENO_SMC_CP_APERTURE)
        return x1 == 4 && x2 == ADRENO_SMC_APERTURE_CB0 && x3 == ADRENO_SMC_FILL;
    return 0;
}

int adreno_smc(const struct adreno_ops *o, uint64_t flags, struct adreno_state *s,
               uint64_t r[8])
{
    uint64_t fid = r[0], in[8];
    if (s->quiesce || !adreno_smc_allowed(fid, r[1], r[2], r[3])) { s->smc_refused++; return -1; }
    s->smc_fid = fid;
    /* qcom_scm_gpu_init_regs once per boot (GMU_STATUS_SECURE_INIT): q1n1 made
     * it at gmu-boot B3; TrustZone's state outlives both. */
    if (fid == ADRENO_SMC_GPU_INIT && ((flags & ADRENO_F_TZ_DONE) || (s->status & ADRENO_S_TZ_DONE))) {
        s->smc_cached++;
        r[0] = r[1] = r[2] = r[3] = 0;
        return 0;
    }
    s->smc_calls++;
    r[4] = r[5] = fid == ADRENO_SMC_CP_APERTURE ? ADRENO_SMC_FILL : 0;
    r[6] = r[7] = 0;
    for (unsigned n = 0; n < 8; n++) in[n] = r[n];
    /* INTERRUPTED is resumed here (x0 = 1, x6 = TrustZone's session: the
     * QCOM_A6 quirk), bounded as q1n1 bounds it. Every other answer, EBUSY and
     * WAITQ_SLEEP included, goes back to the guest, which may sleep and retry;
     * nothing spins at EL2 with the service lock held. */
    for (unsigned resumes = 0;; resumes++) {
        if (o->smc(o->ctx, r)) { r[0] = (uint64_t)-7; break; }        /* Q1N1_GPU_EUNDEF */
        if (r[0] != 1) break;
        if (resumes == 1024) { r[0] = (uint64_t)-10; break; }         /* Q1N1_GPU_EINTR */
        s->smc_resumes++;
        uint64_t session = r[6];
        for (unsigned n = 0; n < 8; n++) r[n] = in[n];
        r[0] = 1;
        r[6] = session;
    }
    if (!r[0] && fid == ADRENO_SMC_GPU_INIT) s->status |= ADRENO_S_TZ_DONE;
    s->smc_x0 = r[0];
    return 0;
}

static void rwp(const struct adreno_ops *o, uint64_t gicd)
{
    wait_clear(o, gicd + GICD_CTLR, 1u << 31, o->hz / 1000);
}

static void gic_off(const struct adreno_ops *o, uint64_t g)
{
    uint32_t bit = 1u << (ADRENO_INTID % 32);
    WR(o, g + GICD_ICENABLER + 4 * (ADRENO_INTID / 32), bit);
    rwp(o, g);
    WR(o, g + GICD_ICPENDR + 4 * (ADRENO_INTID / 32), bit);
}

int adreno_gic_route(const struct adreno_ops *o, const struct adreno_params *p,
                     struct adreno_state *s)
{
    uint64_t g = p->gicd, group = g + GICD_IGROUPR + 4 * (ADRENO_INTID / 32);
    uint64_t cfg = g + GICD_ICFGR + 4 * (ADRENO_INTID / 16), pri = g + GICD_IPRIORITYR + (ADRENO_INTID & ~3u);
    uint32_t bit = 1u << (ADRENO_INTID % 32), shift = (ADRENO_INTID % 4) * 8;
    gic_off(o, g);
    WR(o, group, RD(o, group) | bit);                              /* group 1 NS */
    WR(o, cfg, RD(o, cfg) & ~(2u << (2 * (ADRENO_INTID % 16))));  /* level */
    WR(o, pri, (RD(o, pri) & ~(0xffu << shift)) | ADRENO_IRQ_PRIORITY << shift);
    WR(o, g + GICD_IROUTER + 8 * ADRENO_INTID, (uint32_t)p->affinity);    /* IRM 0 */
    WR(o, g + GICD_IROUTER + 8 * ADRENO_INTID + 4, (uint32_t)(p->affinity >> 32));
    /* With GICD_CTLR.DS 0 (the A16's Non-secure view reads 0x12) GICD_IGROUPR is RAZ/WI to
     * Non-secure software for every SPI -- all 960 read 0 on the A16 -- so the group write
     * above is Linux's habit, not evidence. A Secure interrupt's priority byte is RAZ/WI to
     * Non-secure too, while a Non-secure one reads back its Non-secure view: that decides. */
    if (!((RD(o, pri) >> shift) & 0xffu)) return ADRENO_E_PARAMS;
    s->status |= ADRENO_S_ROUTED;
    return 0;
}

void adreno_gic_restore(const struct adreno_ops *o, const struct adreno_params *p,
                        struct adreno_state *s)
{
    /* Disabled and not pending, as q1n1 found it after ExitBootServices
     * ("nothing enabled"); group, trigger, priority and route stay ours. */
    if (s->status & ADRENO_S_ROUTED) gic_off(o, p->gicd);
    s->status &= ~ADRENO_S_ROUTED;
}

void adreno_quiesce(const struct adreno_ops *o, const struct adreno_params *p,
                    struct adreno_state *s)
{
    if (!(s->status & ADRENO_S_ADOPTED) || s->quiesce) return;
    /* A failed attempt is terminal too: no retry or submission may erase the
     * evidence or use this arena until external recovery. QUIESCED is proof
     * of completion, not an admission-closed flag. */
    s->quiesce = 1;
    uint64_t q = 1;
    if (!CX_ON(o)) { q |= 2; goto out; } /* cannot prove the mirror detached */
    uint32_t power = RD(o, ADRENO_GMU_PWR_CLK_STATUS) & 3u;
    if (power && power != 3) { q |= 128; goto out; }
    if (!power) {
        /* a8xx_bus_clear_pending_transactions, gx side: halt GPU-core traffic.
         * The CX side (GMU fetches) keeps running until q1n1's quiesce. */
        WR(o, ADRENO_RBBM_GBIF_HALT, 1);
        uint64_t start = NOW(o);
        for (unsigned reads = 0;; reads++) {
            s->halt_ack = RD(o, ADRENO_RBBM_GBIF_HALT_ACK);
            if (s->halt_ack & 1) break;
            if (reads >= 2 && NOW(o) - start > o->hz / 1000) { q |= 4; goto out; }
        }
        q |= 8;
    }
    /* An active bank other than the adopted one can still reach guest RAM.
     * Never mutate the old root or invalidate another owner's context. */
    s->cb0_after = ttbr0(o);
    uint32_t control = CB(o, ADRENO_CB_SCTLR);
    if ((s->status & ADRENO_S_HIJACKED) || s->cb0_after != p->cb0_ttbr0 ||
        CB(o, ADRENO_CB_TCR) != (uint32_t)p->cb0_tcr || !(control & 1) ||
        ((control ^ p->cb0_sctlr) & ~ADRENO_SCTLR_FIXED)) goto hijacked;
    if (s->status & ADRENO_S_ATTACHED) {
        uint64_t root = p->cb0_ttbr0 & ADRENO_PTE_ADDR;
        for (unsigned g = 1; g < (unsigned)ADRENO_ROOT_SLOTS; g++) WR64(o, root + 8 * g, 0);
        CLEAN(o, root, 8 * ADRENO_ROOT_SLOTS);
        if (tlbi(o, p, s)) { q |= 16; goto out; }
        s->status &= ~ADRENO_S_ATTACHED;
        q |= 32;
    }
    adreno_fault_poll(o, s);
    s->cb0_after = ttbr0(o);
    control = CB(o, ADRENO_CB_SCTLR);
    if (s->cb0_after != p->cb0_ttbr0 || CB(o, ADRENO_CB_TCR) != (uint32_t)p->cb0_tcr ||
        !(control & 1) || ((control ^ p->cb0_sctlr) & ~ADRENO_SCTLR_FIXED)) goto hijacked;
    s->status |= ADRENO_S_QUIESCED;
    goto out;
hijacked:
    s->status |= ADRENO_S_HIJACKED;
    q |= 64;
out:
    s->quiesce = q;
}
