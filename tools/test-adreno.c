/* SPDX-License-Identifier: MIT */
/* Stage 4: compat/adreno.c against a model of the A16's Adreno side.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror -Icompat -Ishadow \
 *    tools/test-adreno.c compat/adreno-submit.c compat/adreno-resource.c compat/adreno.c compat/irq-forward.c shadow/stage2.c shadow/shadow.c \
 *    shadow/mmu.c -o build/test-adreno && build/test-adreno
 *
 * The model is the part of the machine the monitor touches, written from the
 * same sources the code cites and never from the code itself:
 *  - the q1n1 GPU arena behind a write-back CPU cache the GPU does not snoop
 *    (IORT: non-coherent). CPU stores stay in the cache until a clean; device
 *    reads and writes see DRAM only; a CPU read after a device write sees the
 *    stale line until it is invalidated;
 *  - the Adreno SMMU context bank 0: an AArch64 4 KiB LPAE walk from DRAM
 *    (T0SZ 32, start level 1; built with -DADRENO_VA_WIDE=1: T0SZ 30, 16
 *    root entries, and the table pool in monitor memory above the guest's,
 *    agents/gpu-va-wide), a TLB that keeps every translation it made
 *    until TLBIASID + TLBSYNC, FSR write-one-to-clear, fixed readback bits;
 *  - the CP: CP_RB_WPTR runs the ring words from RPTR through CB0, around the
 *    ring of 2 << CP_RB_CNTL.BUFSZ dwords (CP_MEM_WRITE and the CP_NOP padding
 *    of a wrap; tools/test-adreno-ring.c models every other packet), the
 *    GMU's AHB fence, CP_SQE_CNTL, RBBM_GBIF_HALT/ACK, the power words;
 *  - the GIC distributor registers the route touches, and TrustZone's SMC
 *    replies (INTERRUPTED with a session, EBUSY, WAITQ, a trap).
 * Every register write is logged in order, which is what the quiesce and
 * route checks compare against. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "adreno.h"
#include "adreno-resource.h"
#include "adreno-submit.h"
#include "stage2.h"

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; printf("FAIL %d: %s\n", __LINE__, #x); } } while (0)

/* --- the arena, behind a non-coherent cache ------------------------------- */
#define ARENA 0xfcc00000UL
#define ARENA_SIZE (32UL << 20)
#define MEM_LOW 0x8c0000000UL
#define MEM_HIGH 0x9c0000000UL
#define GUEST_PAGE (MEM_LOW + 0x20000)
#ifndef GUEST_SIZE                               /* tools/test-adreno-ring.c needs more guest pages */
#define GUEST_SIZE 0x10000
#endif
#if ADRENO_VA_WIDE
/* The wide pool is monitor memory (probes/xnuboot.py gpu_pool_reservation): above guest memory, outside the
 * arena, behind the same non-coherent cache. */
#define POOL_BASE (MEM_HIGH + 0x10000000UL)
#define POOL_SPAN ADRENO_POOL_BYTES
#else
#define POOL_SPAN 0UL
#endif
#define RAM_SIZE (ARENA_SIZE + GUEST_SIZE + POOL_SPAN)
static uint8_t *dram, *cache;                    /* device view, CPU view */
static uint8_t dirty[RAM_SIZE / 64], cached[RAM_SIZE / 64];
static int clean_disabled;
static int in_ram(uint64_t pa, uint64_t n)
{
    return (pa >= ARENA && pa < ARENA + ARENA_SIZE && n <= ARENA + ARENA_SIZE - pa) ||
#if ADRENO_VA_WIDE
           (pa >= POOL_BASE && pa < POOL_BASE + POOL_SPAN && n <= POOL_BASE + POOL_SPAN - pa) ||
#endif
           (pa >= GUEST_PAGE && pa < GUEST_PAGE + GUEST_SIZE && n <= GUEST_PAGE + GUEST_SIZE - pa);
}
static uint64_t ram_offset(uint64_t pa, uint64_t n)
{
    if (!in_ram(pa, n)) abort();
#if ADRENO_VA_WIDE
    if (pa >= POOL_BASE) return ARENA_SIZE + GUEST_SIZE + pa - POOL_BASE;
#endif
    return pa >= GUEST_PAGE ? ARENA_SIZE + pa - GUEST_PAGE : pa - ARENA;
}
static uint8_t *line_cpu(uint64_t pa)
{
    uint64_t off = ram_offset(pa, 1), line = off / 64;
    if (!cached[line]) { memcpy(cache + line * 64, dram + line * 64, 64); cached[line] = 1; }
    return cache + off;
}
static uint64_t dev_rd64(uint64_t pa) { uint64_t v; memcpy(&v, dram + ram_offset(pa, 8), 8); return v; }
static void dev_wr32(uint64_t pa, uint32_t v) { memcpy(dram + ram_offset(pa, 4), &v, 4); }

/* --- registers ------------------------------------------------------------ */
struct regwrite { uint64_t pa; uint32_t v; };
static struct regwrite wlog[4096];
static unsigned nlog;
static struct {
    uint32_t cx, pwr, sqe, wptr, rptr, fence_status, drop_writes, halt, halt_ack, halt_stuck;
    uint32_t sctlr, tcr, ttbr_lo, ttbr_hi, fsr, far_lo, far_hi, fsynr0, gfsr, cbfrsynra;
    uint32_t tlb_stuck, tlbiasids, tlbsyncs, gic_secure, gic_ds0, rb_cntl;
    uint32_t group[32], cfg[64], pri[256], route[2048], enabled[32], pending[32], ctlr;
    unsigned mmio_reads_cx_off;          /* accesses behind CX while it was off */
} r;
/* The SMMU TLB: VA page -> leaf, filled by walks, emptied by TLBIASID + sync. */
#define TLB_SLOTS 64
static struct { uint64_t va, leaf; int valid; } tlb[TLB_SLOTS];
static unsigned tlb_next;

static uint64_t smmu_walk(uint64_t va, int use_tlb)
{
    if (use_tlb)
        for (unsigned i = 0; i < TLB_SLOTS; i++)
            if (tlb[i].valid && tlb[i].va == (va & ~0xfffUL)) return tlb[i].leaf;
    uint64_t table = ((uint64_t)r.ttbr_hi << 32 | r.ttbr_lo) & ADRENO_PTE_ADDR;
    unsigned ia = 64 - (r.tcr & 0x3f);                 /* T0SZ 32 or 30: start level 1, 4 or 16 entries */
    if (ia < 31 || ia > 39 || (va >> ia)) return 0;
    for (unsigned shift = 30; shift >= 21; shift -= 9) {
        uint64_t e = dev_rd64(table + 8 * ((va >> shift) & (shift == 30 ? (1UL << (ia - 30)) - 1 : 511)));
        if ((e & 3) != 3) return 0;
        table = e & ADRENO_PTE_ADDR;
    }
    uint64_t leaf = dev_rd64(table + 8 * ((va >> 12) & 511));
    if ((leaf & 3) != 3) return 0;
    if (use_tlb) { tlb[tlb_next] = (typeof(tlb[0])){va & ~0xfffUL, leaf, 1}; tlb_next = (tlb_next + 1) % TLB_SLOTS; }
    return leaf;
}
static void cp_run(void)
{
    /* The CP fetches the ring through CB0 and executes CP_MEM_WRITE, and the
     * CP_NOP padding before a wrap; RPTR runs modulo 2 << CP_RB_CNTL.BUFSZ. A
     * WPTR outside the ring or a packet across its end is a CP error here. */
    uint32_t size = 2u << (r.rb_cntl & 0x3f);
    while (r.rptr != r.wptr) {
        if (r.wptr >= size || r.rptr >= size) { r.fsr = 0x80; return; }
        uint64_t va = 0x10100000 + 4UL * r.rptr, leaf = smmu_walk(va, 1);
        if (!leaf) { r.fsr = 2; return; }
        uint32_t w[4];
        memcpy(&w[0], dram + ram_offset((leaf & ADRENO_PTE_ADDR) | (va & 0xfff), 4), 4);
        if ((w[0] & 0xffff0000u) == 0x70100000u) {            /* CP_NOP, count 0..0x3fff (parity bit 15) */
            uint32_t count = w[0] & 0x3fff;
            unsigned pc = (0x9669 >> (0xf & (count ^ count >> 4 ^ count >> 8 ^ count >> 12))) & 1;
            if ((w[0] & 0x8000) != pc << 15 || r.rptr + 1 + count > size) { r.fsr = 0x80; return; }
            r.rptr = (r.rptr + 1 + count) % size;
            continue;
        }
        if (w[0] != ADRENO_PKT7_MEM_WRITE3 || r.rptr + 4 > size) { r.fsr = 0x80; return; }
        for (unsigned n = 1; n < 4; n++) {
            uint64_t l = smmu_walk(va + 4 * n, 1);
            memcpy(&w[n], dram + ram_offset((l & ADRENO_PTE_ADDR) | ((va + 4 * n) & 0xfff), 4), 4);
        }
        uint64_t dst = (uint64_t)w[2] << 32 | w[1], l = smmu_walk(dst, 1);
        if (!l || (l & ADRENO_PTE_RDONLY)) { r.fsr = 2; return; }
        dev_wr32((l & ADRENO_PTE_ADDR) | (dst & 0xfff), w[3]);
        r.rptr = (r.rptr + 4) % size;
    }
}
static uint32_t *gic(uint64_t off)
{
    if (off == GICD_CTLR) return &r.ctlr;
    if (off >= GICD_IGROUPR && off < GICD_IGROUPR + 128) return &r.group[(off - GICD_IGROUPR) / 4];
    if (off >= GICD_ISENABLER && off < GICD_ISENABLER + 128) return &r.enabled[(off - GICD_ISENABLER) / 4];
    if (off >= GICD_ICENABLER && off < GICD_ICENABLER + 128) return &r.enabled[(off - GICD_ICENABLER) / 4];
    if (off >= GICD_ISPENDR && off < GICD_ISPENDR + 128) return &r.pending[(off - GICD_ISPENDR) / 4];
    if (off >= GICD_ICPENDR && off < GICD_ICPENDR + 128) return &r.pending[(off - GICD_ICPENDR) / 4];
    if (off >= GICD_IPRIORITYR && off < GICD_IPRIORITYR + 1024) return &r.pri[(off - GICD_IPRIORITYR) / 4];
    if (off >= GICD_ICFGR && off < GICD_ICFGR + 256) return &r.cfg[(off - GICD_ICFGR) / 4];
    if (off >= GICD_IROUTER && off < GICD_IROUTER + 8192) return &r.route[(off - GICD_IROUTER) / 4];
    return 0;
}
#define GICD 0x17000000UL
static int behind_cx(uint64_t pa) { return pa >= 0x03d00000 && pa < 0x03df0000 && pa != ADRENO_CX_CFG_GDSCR; }

static uint32_t m_rd(void *ctx, uint64_t pa)
{
    (void)ctx;
    if (in_ram(pa, 4)) { uint32_t v; memcpy(&v, line_cpu(pa), 4); return v; }
    if (pa >= GICD && pa < GICD + 0x10000) {
        uint64_t off = pa - GICD;
        uint32_t *g = gic(off);
        if (!g) abort();
        /* GICD_CTLR.DS 0 (the A16): IGROUPR is RAZ/WI to Non-secure; a Secure SPI's
         * priority byte is RAZ/WI too. */
        if (r.gic_ds0 && off >= GICD_IGROUPR && off < GICD_IGROUPR + 128) return 0;
        if (r.gic_secure && off == GICD_IPRIORITYR + (0x14c & ~3u)) return *g & ~0xffu;
        return *g;
    }
    if (behind_cx(pa) && !(r.cx & (1u << 16))) r.mmio_reads_cx_off++;
    switch (pa) {
    case ADRENO_CX_CFG_GDSCR: return r.cx;
    case ADRENO_GMU_PWR_CLK_STATUS: return r.pwr;
    case ADRENO_CP_SQE_CNTL: return r.sqe;
    case ADRENO_CP_RB_WPTR: return r.wptr;
    case ADRENO_CP_RB_RPTR: return r.rptr;
    case ADRENO_CP_RB_CNTL: return r.rb_cntl;
    case ADRENO_GMU_AHB_FENCE_STATUS: return r.fence_status;
    case ADRENO_RBBM_GBIF_HALT_ACK: return r.halt_ack;
    case ADRENO_SMMU_SGFSR: return r.gfsr;
    case ADRENO_SMMU_CBFRSYNRA0: return r.cbfrsynra;
    case ADRENO_CB0 + ADRENO_CB_SCTLR: return r.sctlr & ~ADRENO_SCTLR_FIXED;
    case ADRENO_CB0 + ADRENO_CB_TCR: return r.tcr;
    case ADRENO_CB0 + ADRENO_CB_TTBR0: return r.ttbr_lo;
    case ADRENO_CB0 + ADRENO_CB_TTBR0 + 4: return r.ttbr_hi;
    case ADRENO_CB0 + ADRENO_CB_FSR: return r.fsr;
    case ADRENO_CB0 + ADRENO_CB_FAR: return r.far_lo;
    case ADRENO_CB0 + ADRENO_CB_FAR + 4: return r.far_hi;
    case ADRENO_CB0 + ADRENO_CB_FSYNR0: return r.fsynr0;
    case ADRENO_CB0 + ADRENO_CB_TLBSTATUS: return r.tlb_stuck;
    }
    printf("unmodelled read %#llx\n", (unsigned long long)pa);
    abort();
}
static void m_wr(void *ctx, uint64_t pa, uint32_t v)
{
    (void)ctx;
    if (in_ram(pa, 4)) { memcpy(line_cpu(pa), &v, 4); dirty[ram_offset(pa, 4) / 64] = 1; return; }
    if (nlog < 4096) wlog[nlog++] = (struct regwrite){pa, v};
    if (pa >= GICD && pa < GICD + 0x10000) {
        uint64_t off = pa - GICD;
        uint32_t *g = gic(off);
        if (!g) abort();
        if (off >= GICD_ISENABLER && off < GICD_ISENABLER + 128) *g |= v;
        else if (off >= GICD_ICENABLER && off < GICD_ICENABLER + 128) *g &= ~v;
        else if (off >= GICD_ISPENDR && off < GICD_ISPENDR + 128) *g |= v;
        else if (off >= GICD_ICPENDR && off < GICD_ICPENDR + 128) *g &= ~v;
        else if (off >= GICD_IGROUPR && off < GICD_IGROUPR + 128 && (r.gic_secure || r.gic_ds0)) {}
        else if (r.gic_secure && off == GICD_IPRIORITYR + (0x14c & ~3u)) *g = (*g & 0xffu) | (v & ~0xffu);
        else *g = v;
        return;
    }
    if (behind_cx(pa) && !(r.cx & (1u << 16))) r.mmio_reads_cx_off++;
    switch (pa) {
    case ADRENO_CP_RB_WPTR:
        if (r.drop_writes) { r.drop_writes--; r.fence_status |= 1; return; }
        r.fence_status = 0; r.wptr = v; cp_run(); return;
    case ADRENO_RBBM_GBIF_HALT: r.halt = v; if (!r.halt_stuck) r.halt_ack = v; return;
    case ADRENO_CB0 + ADRENO_CB_FSR: r.fsr &= ~v; return;
    case ADRENO_SMMU_SGFSR: r.gfsr &= ~v; return;
    case ADRENO_CB0 + ADRENO_CB_TLBIASID: CHECK(v == r.ttbr_hi >> 16); r.tlbiasids++; return;
    case ADRENO_CB0 + ADRENO_CB_TLBSYNC:
        r.tlbsyncs++;
        if (!r.tlb_stuck && r.tlbiasids) memset(tlb, 0, sizeof(tlb));
        return;
    }
    printf("unmodelled write %#llx\n", (unsigned long long)pa);
    abort();
}
static uint64_t m_rd64(void *ctx, uint64_t pa) { (void)ctx; ram_offset(pa, 8); uint64_t v; memcpy(&v, line_cpu(pa), 8); return v; }
static void m_wr64(void *ctx, uint64_t pa, uint64_t v) { (void)ctx; uint64_t off = ram_offset(pa, 8); memcpy(line_cpu(pa), &v, 8); dirty[off / 64] = 1; }
static unsigned cleans;
static void m_clean(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    cleans++;
    if (clean_disabled || !size) return;
    uint64_t off = ram_offset(pa, size);
    for (uint64_t line = off / 64; line <= (off + size - 1) / 64; line++) {
        if (dirty[line]) memcpy(dram + line * 64, cache + line * 64, 64);
        dirty[line] = 0;
        cached[line] = 0;                 /* DC CIVAC: clean and invalidate */
    }
}
static uint64_t clock_now;
static uint64_t m_now(void *ctx) { (void)ctx; return clock_now += 50; }
/* TrustZone: `interrupts` INTERRUPTED replies with a session, then `final`. */
static struct { int trap, interrupts; uint64_t final, session, calls, last[8], resumed_x0, resumed_x6; } tz;
static int m_smc(void *ctx, uint64_t *x)
{
    (void)ctx;
    tz.calls++;
    memcpy(tz.last, x, sizeof(tz.last));
    if (tz.trap) return 1;
    if (x[0] == 1) { tz.resumed_x0 = x[0]; tz.resumed_x6 = x[6]; }
    if (tz.interrupts > 0) { tz.interrupts--; x[0] = 1; x[6] = tz.session; return 0; }
    x[0] = tz.final; x[1] = 0x11; x[2] = 0x22; x[3] = 0x33;
    return 0;
}
static const struct adreno_ops ops = {0, m_rd, m_wr, m_rd64, m_wr64, m_clean, m_now, m_smc, 1000000, 0
#if SNAP_ADRENO_COHERENT
                                     , 0   /* today's leaves until a coherency self-test passes */
                                     , 0   /* no PMU (tools/test-adreno-coherent.c models one) */
#endif
};

/* --- q1n1's state after cp-fence, as `adopt` records it -------------------- */
#define ROOT (ARENA + 0x80000)
#define RING (ARENA + 0x140000)
#define MEMPTRS (ARENA + 0x148000)
#if ADRENO_VA_WIDE
#define POOL POOL_BASE
#else
#define POOL (ARENA + 0x1400000)
#endif
#define CB0_TCR (0x802000U | ADRENO_CB0_T0SZ)   /* q1n1 CB_TCR (T0SZ 32) or CB_TCR_WIDE (30) */
static struct adreno_params P;
static struct adreno_state S;
static void q1n1_cp_fence(void)
{
    memset(dram, 0, RAM_SIZE); memset(cache, 0, RAM_SIZE);
    memset(dirty, 0, sizeof(dirty)); memset(cached, 0, sizeof(cached));
    memset(&r, 0, sizeof(r)); memset(tlb, 0, sizeof(tlb)); memset(&S, 0, sizeof(S));
    memset(&tz, 0, sizeof(tz)); nlog = 0; clean_disabled = 0;
    /* q1n1 build_tables('gpu'): root, one L2, L3s for SQE/ring/memptrs (UNPRIV). */
    uint64_t l2 = ROOT + 0x1000, l3 = ROOT + 0x2000, l3b = ROOT + 0x3000;
    uint64_t e;
    e = l2 | 3; memcpy(dram + (ROOT - ARENA), &e, 8);
    e = l3 | 3; memcpy(dram + (l2 + 8 * ((0x10100000 >> 21) & 511) - ARENA), &e, 8);
    e = l3b | 3; memcpy(dram + (l2 + 8 * ((0x10200000 >> 21) & 511) - ARENA), &e, 8);
    for (unsigned n = 0; n < 8; n++) {                 /* ring 32 KiB at VA 0x10100000 */
        e = (RING + n * 0x1000) | ADRENO_PTE_LEAF | ADRENO_PTE_RDONLY;
        memcpy(dram + (l3 + 8 * (((0x10100000 >> 12) + n) & 511) - ARENA), &e, 8);
    }
    e = MEMPTRS | ADRENO_PTE_LEAF;
    memcpy(dram + (l3b + 8 * ((0x10200000 >> 12) & 511) - ARENA), &e, 8);
    r.cx = 1u << 16; r.pwr = 0; r.sqe = 1; r.wptr = r.rptr = 22;
    r.rb_cntl = 12 | 2 << 8;                           /* q1n1 RB_CNTL_DEFAULT: 8192 dwords */
    r.sctlr = 0x1167; r.tcr = CB0_TCR; r.ttbr_lo = (uint32_t)ROOT; r.ttbr_hi = 0;
    P = (struct adreno_params){
        .flags = ADRENO_F_ENABLE | ADRENO_F_CX_MISC | ADRENO_F_DART | ADRENO_F_RING | ADRENO_F_SELF_IRQ,
        .gicd = GICD, .affinity = 0x100000002UL, .arena_base = ARENA, .arena_size = ARENA_SIZE,
        .cb0_ttbr0 = ROOT, .cb0_tcr = CB0_TCR, .cb0_sctlr = 0x1167, .pool_pa = POOL,
        .ring_pa = RING, .ring_dwords = 8192, .ring_wptr = 22,
        .fence_pa = MEMPTRS + 0x80, .fence_va = 0x10200080, .ring_at_seconds = 60};
}

/* --- the DART side: committed T8110 level-2 descriptors per 16 KiB IOVA ---- */
static uint64_t dart[(ADRENO_WINDOW_END - ADRENO_WINDOW_BASE) >> 14];
static uint64_t dart_leaf(void *ctx, uint64_t iova) { (void)ctx; return dart[(iova - ADRENO_WINDOW_BASE) >> 14]; }
/* compat/sptm-dart.c leaf_descriptor, re-derived from the T8110 fields. */
static uint64_t dart_desc(uint64_t pa, unsigned begin, unsigned end, int nowrite, int noread)
{
    return (pa >> 4) | 1 | (nowrite ? 4UL : 0) | (noread ? 8UL : 0) |
           ((uint64_t)(begin >> 2) << 52) | ((uint64_t)((end - 1) >> 2) << 40);
}
static int mirror(uint64_t iova, uint64_t size)
{
    return adreno_mirror(&ops, &P, &S, iova, size, dart_leaf, 0, MEM_LOW, MEM_HIGH);
}

static void test_blocks(void)
{
    /* The HWIO rows (adreno-hw a16-uefi-hwio-GFX-full.txt), re-listed here. */
    static const struct { uint32_t pa; unsigned block; } rows[] = {
        {0x03d00000, ADRENO_PASS}, {0x03d02000, ADRENO_PASS}, {0x03d0f114, ADRENO_PASS},
        {0x03d35ffc, ADRENO_PASS}, {0x03d36000, ADRENO_PASS}, {0x03d36ffc, ADRENO_PASS},
        {0x03d37000, ADRENO_GMU_GX}, {0x03d3affc, ADRENO_GMU_GX}, {0x03d3b000, ADRENO_RDVM},
        {0x03d3b900, ADRENO_RDVM}, {0x03d3c000, ADRENO_PASS}, {0x03d3d000, ADRENO_PASS},
        {0x03d3fffc, ADRENO_PASS}, {0x03d40000, ADRENO_GMU_AO}, {0x03d50000, ADRENO_RSCC},
        {0x03d60000, ADRENO_SMMU_APERTURE}, {0x03d61000, ADRENO_SMMU_APERTURE},
        {0x03d64000, ADRENO_GXCLKCTL}, {0x03d69000, ADRENO_GXCLKCTL}, {0x03d6c000, ADRENO_GMU_CX},
        {0x03d7dfa0, ADRENO_GMU_CX}, {0x03d8ec4c, ADRENO_GMU_CX}, {0x03d90000, ADRENO_GPUCC},
        {0x03d99084, ADRENO_GPUCC}, {0x03d9a000, ADRENO_GPUCC}, {0x03da0000, ADRENO_SMMU},
        {0x03dc0000, ADRENO_SMMU}, {0x03def3fc, ADRENO_SMMU}};
    for (unsigned n = 0; n < sizeof(rows) / sizeof(rows[0]); n++)
        CHECK(adreno_block(rows[n].pa, ADRENO_F_ALL) == rows[n].block);
    CHECK(adreno_block(0x03cffffc, ADRENO_F_ALL) == ADRENO_NONE);
    CHECK(adreno_block(0x03df0000, ADRENO_F_ALL) == ADRENO_NONE);
    CHECK(adreno_block(0x03d9e000, ADRENO_F_ALL) == ADRENO_CX_MISC_RO);
    CHECK(adreno_block(0x03d9fffc, ADRENO_F_ALL) == ADRENO_CX_MISC_RO);
    CHECK(adreno_block(0x03d9e000, ADRENO_F_ENABLE) == ADRENO_CX_MISC);   /* optional window off */
    /* Every register the monitor itself touches is outside the passthrough,
     * except the CP/RBBM words the guest also drives. */
    CHECK(adreno_block(ADRENO_GMU_PWR_CLK_STATUS, ADRENO_F_ALL) >= ADRENO_TRAPPED);
    CHECK(adreno_block(ADRENO_CX_CFG_GDSCR, ADRENO_F_ALL) >= ADRENO_TRAPPED);
    CHECK(adreno_block(ADRENO_CB0, ADRENO_F_ALL) == ADRENO_SMMU);
    CHECK(adreno_block(ADRENO_CP_RB_WPTR, ADRENO_F_ALL) == ADRENO_PASS);
}

/* The stage-2 passthrough exactly as vcpu_stage2_prepare builds it, walked. */
static uint8_t s2ram[4UL << 20];
static uint64_t s2next;
#define S2RAM 0x82500000UL
static int s2_read(void *ctx, uint64_t pa, uint64_t *out) { (void)ctx; if (pa < S2RAM || pa + 8 > S2RAM + sizeof(s2ram)) return -1; memcpy(out, s2ram + (pa - S2RAM), 8); return 0; }
static int s2_write(void *ctx, uint64_t pa, uint64_t v) { (void)ctx; if (pa < S2RAM || pa + 8 > S2RAM + sizeof(s2ram)) return -1; memcpy(s2ram + (pa - S2RAM), &v, 8); return 0; }
static uint64_t s2_alloc(void *ctx) { (void)ctx; if (s2next + 0x1000 > S2RAM + sizeof(s2ram)) return 0; uint64_t t = s2next; s2next += 0x1000; memset(s2ram + (t - S2RAM), 0, 0x1000); return t; }
static void test_stage2(void)
{
    for (int cx = 0; cx < 2; cx++) {
        memset(s2ram, 0, sizeof(s2ram)); s2next = S2RAM;
        struct shadow s = {.txsz = 28, .alloc = s2_alloc, .read = s2_read, .write = s2_write};
        s.root = s2_alloc(0);
        struct stage2_range ranges[8];
        unsigned count = 0;
        ranges[count++] = (struct stage2_range){MEM_LOW, MEM_HIGH, S2_AP_RW | S2_ATTRS, 0};
        ranges[count++] = (struct stage2_range){ADRENO_PA, ADRENO_PASS0_END, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
        ranges[count++] = (struct stage2_range){ADRENO_PASS1_PA, ADRENO_PASS1_END, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
        if (cx) ranges[count++] = (struct stage2_range){ADRENO_CX_MISC_PA, ADRENO_CX_MISC_END, S2_AP_RO | S2_ATTRS_DEVICE, S2_XN};
        CHECK(stage2_build(&s, ranges, count) == 0);
        struct mmu_config cfg = {.granule_shift = 12, .txsz = 28, .root = s.root};
        unsigned admitted = 0;
        for (uint64_t pa = ADRENO_PA - 0x4000; pa < ADRENO_END + 0x4000; pa += 0x1000) {
            struct mmu_leaf leaf;
            int ok = mmu_walk(&cfg, pa, s2_read, 0, &leaf) >= 0 && leaf.valid;
            unsigned b = adreno_block(pa, cx ? ADRENO_F_ALL : ADRENO_F_ENABLE);
            int want = b == ADRENO_PASS || b == ADRENO_CX_MISC_RO;
            CHECK(ok == want);
            if (!ok) continue;
            admitted++;
            CHECK(leaf.pa == pa);
            CHECK(((leaf.descriptor >> 2) & 0xf) == 1);                      /* Device-nGnRE */
            CHECK((leaf.descriptor & S2_XN) != 0);
            CHECK((leaf.descriptor & (3UL << 6)) == (b == ADRENO_PASS ? S2_AP_RW : S2_AP_RO));
            /* review: the exact bits tools/stage2audit.py expects (probes/adreno.py S2_DEVICE_*). */
            CHECK((leaf.descriptor & 0xffc) == (b == ADRENO_PASS ? 0x7c4UL : 0x744UL));
        }
        CHECK(admitted == (0x37000 + 0x4000 + (cx ? 0x2000 : 0)) / 0x1000);
        /* The trap-everything-else rule: nothing else of the aperture, and no
         * byte of the arena, exists at stage 2. */
        for (uint64_t pa = ARENA; pa < ARENA + ARENA_SIZE; pa += 0x100000) {
            struct mmu_leaf leaf;
            CHECK(!(mmu_walk(&cfg, pa, s2_read, 0, &leaf) >= 0 && leaf.valid));
        }
        /* Overlapping a device window with memory is refused before any write. */
        ranges[count++] = (struct stage2_range){0x03d36000, 0x03d38000, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
        CHECK(stage2_build(&s, ranges, count) == STAGE2_BAD_RANGES);
    }
}

static void test_adopt(void)
{
    q1n1_cp_fence();
    r.fsr = 0x400;       /* FSR.FORMAT, as the A16 reads it idle (stage3-run2-c3s.prestart.json) */
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    CHECK(adreno_fault_poll(&ops, &S) == 0);
    CHECK((S.status & (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED)) == (ADRENO_S_ADOPTED | ADRENO_S_ATTACHED));
    CHECK(S.wptr == 22 && S.prepare == 0);
    CHECK(nlog == 0);                                  /* read-only toward the GPU */
    CHECK(r.mmio_reads_cx_off == 0);
    /* Root entry 0 is q1n1's, 1..3 (1..15 wide) reach the pool, all in DRAM (not just in cache). */
    CHECK(dev_rd64(ROOT) == ((ROOT + 0x1000) | 3));
    for (unsigned g = 1; g < ADRENO_ROOT_SLOTS; g++) CHECK(dev_rd64(ROOT + 8 * g) == ((POOL + (g - 1) * 0x1000) | 3));
#if ADRENO_VA_WIDE
    for (unsigned g = ADRENO_ROOT_SLOTS; g < 512; g++) CHECK(dev_rd64(ROOT + 8 * g) == 0);
#endif
    CHECK(dev_rd64(POOL + 8 * (ADRENO_L3_TABLES - 1)) ==
          ((POOL + ADRENO_L3_OFFSET + (ADRENO_L3_TABLES - 1) * 0x1000) | 3));
    CHECK(smmu_walk(0x40000000, 0) == 0 && smmu_walk(ADRENO_WINDOW_END - 0x1000, 0) == 0);
    CHECK(smmu_walk(0x10200000, 0) == (MEMPTRS | ADRENO_PTE_LEAF));   /* q1n1's mapping intact */

    struct { const char *what; void (*spoil)(void); int want; } cases[] = {
        {"cx off", 0, ADRENO_E_CX}, {"gx off", 0, ADRENO_E_GX}, {"cb0 ttbr", 0, ADRENO_E_CB0},
        {"cb0 tcr", 0, ADRENO_E_CB0}, {"fault", 0, ADRENO_E_FAULT}, {"gfault", 0, ADRENO_E_FAULT},
        {"sqe", 0, ADRENO_E_SQE}, {"rptr", 0, ADRENO_E_RING}, {"root", 0, ADRENO_E_ROOT},
        {"bypass", 0, ADRENO_E_CB0},
        /* review: a GX-side GBIF halt a previous quiesce left, before any CB0/CP read. */
        {"gbif halted", 0, ADRENO_E_HALT}};
    for (unsigned n = 0; n < sizeof(cases) / sizeof(cases[0]); n++) {
        q1n1_cp_fence();
        switch (n) {
        case 0: r.cx = 0; break;
        case 1: r.pwr = 3; break;
        case 2: r.ttbr_lo += 0x1000; break;
        case 3: r.tcr = 0x802019; break;
        case 4: r.fsr = 2; break;
        case 5: r.gfsr = 1; break;
        case 6: r.sqe = 0; break;
        case 7: r.rptr = 18; break;
        case 8: { uint64_t e = 0x12345003; memcpy(dram + (ROOT + 16 - ARENA), &e, 8); } break;
        case 9: r.sctlr &= ~1u; P.cb0_sctlr &= ~1u; break;          /* both agree: still refused */
        case 10: r.halt = r.halt_ack = 1; break;
        }
        CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == cases[n].want);
        CHECK((int64_t)S.prepare == cases[n].want);
        CHECK(!(S.status & ADRENO_S_ATTACHED));
        CHECK(n != 0 || r.mmio_reads_cx_off == 0);     /* nothing behind a CX that is off */
        if (n == 8) CHECK(dev_rd64(ROOT + 16) == 0x12345003);   /* never overwritten */
    }
    /* Parameter refusals: the arena in guest memory, a pool outside the arena
     * (wide: a pool reaching into the arena), a root inside the pool, unknown
     * flags. Wide (FAILURE-MODES V1, V5): a pool in guest memory, a pool that
     * wraps, a params TCR other than T0SZ 30 or with another granule. */
#if ADRENO_VA_WIDE
#define BAD_PARAMS 9
#else
#define BAD_PARAMS 5
#endif
    struct adreno_params bad[BAD_PARAMS];
    for (unsigned n = 0; n < BAD_PARAMS; n++) { q1n1_cp_fence(); bad[n] = P; }
    bad[0].arena_base = MEM_LOW + 0x100000;
    bad[1].pool_pa = ARENA + ARENA_SIZE - 0x1000;
    bad[2].pool_pa = ROOT - 0x1000;
    bad[3].flags |= 64;
    bad[4].fence_va = ADRENO_WINDOW_BASE + 0x80;   /* review: a fence VA in the guest's mirror window */
#if ADRENO_VA_WIDE
    bad[5].pool_pa = MEM_HIGH - 0x1000;
    bad[6].pool_pa = 0xfffffffffff00000UL;
    bad[7].cb0_tcr = 0x802020;
    bad[8].cb0_tcr = CB0_TCR | 1u << 14;
#endif
    for (unsigned n = 0; n < BAD_PARAMS; n++) {
        q1n1_cp_fence();
        CHECK(adreno_adopt(&ops, &bad[n], &S, MEM_LOW, MEM_HIGH) == ADRENO_E_PARAMS);
        CHECK(!S.status && !nlog && !dirty[(ROOT - ARENA) / 64]);
    }
    /* Without the DART the CB0 tables are not touched at all. */
    q1n1_cp_fence();
    P.flags &= ~(uint64_t)ADRENO_F_DART;
    uint64_t before = dev_rd64(ROOT + 8);
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0 && !(S.status & ADRENO_S_ATTACHED));
    CHECK(dev_rd64(ROOT + 8) == before && !dirty[(ROOT - ARENA) / 64]);
    CHECK(mirror(0x40000000, 0x4000) == ADRENO_E_PARAMS);
}

static void test_fence(void)
{
    q1n1_cp_fence();
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    CHECK(adreno_fence(&ops, &P, &S, 0x534e0001) == 0);
    CHECK(S.fences == 1 && S.wptr == 26 && r.wptr == 26 && r.rptr == 26);
    uint32_t v; memcpy(&v, dram + (MEMPTRS + 0x80 - ARENA), 4);
    CHECK(v == 0x534e0001);
    /* q1n1's fence line (+0x40..0x7f) is not the monitor's. */
    CHECK(!dirty[(MEMPTRS + 0x40 - ARENA) / 64]);
    CHECK(adreno_fence(&ops, &P, &S, 0x534e0002) == 0 && S.wptr == 30);
    /* Without the invalidate before each poll the CPU keeps reading its own
     * stale ~value and never sees the GPU's write. */
    clean_disabled = 1;
    CHECK(adreno_fence(&ops, &P, &S, 0x534e0003) == ADRENO_E_FENCE);
    CHECK((int64_t)S.fence_error == ADRENO_E_FENCE);
    clean_disabled = 0;
    /* Refusals leave the ring untouched. */
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.rptr = 21;
    CHECK(adreno_fence(&ops, &P, &S, 1) == ADRENO_E_RING && r.wptr == 22);
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.pwr = 1;
    CHECK(adreno_fence(&ops, &P, &S, 1) == ADRENO_E_GX && r.wptr == 22);
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.sqe = 0;
    CHECK(adreno_fence(&ops, &P, &S, 1) == ADRENO_E_SQE);
    q1n1_cp_fence(); P.ring_wptr = r.wptr = r.rptr = 8190; adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    /* design S1: a CP_NOP pads 8190..8191, the fence runs at 0 (tools/test-adreno-ring.c covers wraps) */
    CHECK(adreno_fence(&ops, &P, &S, 1) == 0 && S.wptr == 4 && r.rptr == 4 && S.ring_wraps == 1);
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.drop_writes = 1;                                               /* one retry */
    CHECK(adreno_fence(&ops, &P, &S, 7) == 0 && r.wptr == 26);
    r.drop_writes = 2;
    CHECK(adreno_fence(&ops, &P, &S, 8) == ADRENO_E_RING);
    q1n1_cp_fence(); P.flags &= ~(uint64_t)ADRENO_F_RING; adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    CHECK(adreno_fence(&ops, &P, &S, 1) == ADRENO_E_PARAMS);
}

static int guest_fence(uint64_t va, uint64_t value)
{
    uint64_t regs[4] = {0x00010001, va, value, 0};
    int e = adreno_guest_fence(&ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[3] == S.wptr);
    CHECK(regs[1] == (e ? 0 : value));
    return e;
}
static void guest_fence_setup(void)
{
    q1n1_cp_fence();
    P.flags &= ~(uint64_t)ADRENO_F_RING;
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    memset(dart, 0, sizeof(dart));
    dart[0] = dart_desc(GUEST_PAGE, 0, 0x4000, 0, 0);
    CHECK(mirror(ADRENO_WINDOW_BASE, 0x4000) == 0);
}
static int submit_fence(void *ctx)
{
    return guest_fence(ADRENO_WINDOW_BASE + 0x200, *(uint32_t *)ctx);
}
static void test_submit_transport(void)
{
    uint32_t value = 0x534e4001;
    unsigned char bytes[13] = {0};
    /* Intentionally unaligned command storage, followed by unrelated bytes. */
    bytes[2] = 0x10; bytes[5] = 8;
    guest_fence_setup();
    CHECK(adreno_submit_command(bytes + 1, 8, submit_fence, &value) == 0);
    CHECK(S.fences == 1 && r.rptr == 26 && m_rd(0, GUEST_PAGE + 0x200) == value);
    for (unsigned bad = 0; bad < 8; bad++) {
        uint32_t wptr = r.wptr;
        CHECK(adreno_submit_command(bytes + 1, bad, submit_fence, &value) == ADRENO_SUBMIT_E_FORMAT);
        CHECK(r.wptr == wptr && S.fences == 1);
    }
    for (unsigned size = 0; size <= 12; size++) {
        if (size == 8) continue;
        bytes[5] = (unsigned char)size;
        CHECK(adreno_submit_command(bytes + 1, 12, submit_fence, &value) == ADRENO_SUBMIT_E_FORMAT);
        CHECK(S.fences == 1 && r.wptr == 26);
    }
    bytes[5] = 8;
    bytes[1] = 1; // unsupported vendor command 0x1001
    CHECK(adreno_submit_command(bytes + 1, 8, submit_fence, &value) == ADRENO_SUBMIT_E_COMMAND);
    bytes[2] = 0; // native timestamp: delegate, without executing a GPU fence here
    CHECK(adreno_submit_command(bytes + 1, 8, submit_fence, &value) == ADRENO_SUBMIT_GENERIC);
    bytes[1] = 0;
    CHECK(adreno_submit_command(bytes + 1, 8, submit_fence, &value) == ADRENO_SUBMIT_GENERIC);
    CHECK(S.fences == 1 && r.wptr == 26);
    bytes[2] = 0x10;
    CHECK(adreno_submit_command(NULL, 8, submit_fence, &value) == ADRENO_SUBMIT_E_FORMAT);
    CHECK(adreno_submit_command(bytes + 1, 8, NULL, &value) == ADRENO_SUBMIT_E_FORMAT);
    clean_disabled = 1; // CP cannot fetch the newly written command packet
    CHECK(adreno_submit_command(bytes + 1, 8, submit_fence, &value) == ADRENO_E_FENCE);
    CHECK(S.fences == 1 && r.wptr == 30 && r.rptr == 26);
    clean_disabled = 0;
}
static void test_guest_fence(void)
{
    const uint64_t va = ADRENO_WINDOW_BASE + 0x200;
    guest_fence_setup();
    CHECK(guest_fence(va, 0x534e1001) == 0);
    CHECK(S.fences == 1 && S.wptr == 26 && r.rptr == 26);
    CHECK(m_rd(0, GUEST_PAGE + 0x200) == 0x534e1001);
    CHECK(guest_fence(va, 0x534e1002) == 0);
    CHECK(S.fences == 2 && r.rptr == 30);
    /* Native byte bounds can be tighter than a 4 KiB SMMU leaf. */
    for (unsigned bad = 0; bad < 16; bad++) {
        guest_fence_setup();
        uint64_t target = va, value = 0x534e1003;
        int expected = ADRENO_E_TARGET;
        switch (bad) {
        case 0: target++; break;
        case 1: target = ADRENO_WINDOW_BASE - 4; break;
        case 2: target = ADRENO_WINDOW_END; break;
        case 3: target = ~3UL; break;
        case 4: dart[0] = 0; break;
        case 5: dart[0] |= 4; break;
        case 6: dart[0] |= 8; break;
        case 7: dart[0] = dart_desc(GUEST_PAGE, 0x204, 0x4000, 0, 0); break;
        case 8: dart[0] = dart_desc(GUEST_PAGE, 0, 0x200, 0, 0); break;
        case 9: dart[0] = dart_desc(MEM_HIGH, 0, 0x4000, 0, 0); break;
        case 10: dart[0] = dart_desc(ARENA, 0, 0x4000, 0, 0); break;
        case 11: m_wr64(0, P.pool_pa + ADRENO_L3_OFFSET, (GUEST_PAGE + 0x1000) | ADRENO_PTE_LEAF); break;
        case 12: S.status |= ADRENO_S_QUIESCED; expected = ADRENO_E_PARAMS; break;
        case 13: S.status &= ~ADRENO_S_ATTACHED; expected = ADRENO_E_PARAMS; break;
        case 14: P.flags |= ADRENO_F_RING; expected = ADRENO_E_PARAMS; break;
        case 15: value |= 1UL << 32; expected = ADRENO_E_PARAMS; break;
        }
        unsigned before = nlog;
        CHECK(guest_fence(target, value) == expected);
        CHECK(nlog == before && S.wptr == 22 && S.fences == 0);
        CHECK(m_rd(0, GUEST_PAGE + 0x200) == 0);
    }
    guest_fence_setup();
    dart[0] = dart_desc(GUEST_PAGE, 0x200, 0x204, 0, 0);
    CHECK(guest_fence(va, 0x534e1004) == 0); /* exact four-byte native bound */
    guest_fence_setup();
    uint64_t regs[4] = {0x00020001, va, 1, 0};
    CHECK(adreno_guest_fence(&ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == ADRENO_E_PARAMS);
    regs[0] = 0x00010001; regs[1] = va; regs[2] = 1; regs[3] = 1;
    CHECK(adreno_guest_fence(&ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == ADRENO_E_PARAMS);
    CHECK(S.wptr == 22 && S.fences == 0);
    guest_fence_setup();
    r.rptr--;
    CHECK(guest_fence(va, 1) == ADRENO_E_RING && r.wptr == 22);
    guest_fence_setup();
    r.drop_writes = 1;
    CHECK(guest_fence(va, 2) == 0 && r.rptr == 26);
    guest_fence_setup();
    r.drop_writes = 2;
    CHECK(guest_fence(va, 3) == ADRENO_E_RING && S.fences == 0);
    guest_fence_setup();
    clean_disabled = 1;
    CHECK(guest_fence(va, 4) == ADRENO_E_FENCE && S.fences == 0);
    clean_disabled = 0;
}

static unsigned guest_unmap_calls;
static int guest_unmap_error;
static int guest_unmap_native(void *ctx, uint64_t va, uint64_t size)
{
    (void)ctx;
    guest_unmap_calls++;
    if (guest_unmap_error) return guest_unmap_error;
    memset(&dart[(va - ADRENO_WINDOW_BASE) >> 14], 0, (size >> 14) * sizeof(dart[0]));
    return 0;
}
static int guest_unmap(uint64_t va, uint64_t size)
{
    uint64_t regs[4] = {0x00010002, va, size, 0};
    int e = adreno_guest_unmap(&ops, &P, &S, regs, dart_leaf, guest_unmap_native, 0,
                               MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[3] == S.wptr);
    CHECK(regs[1] == (e ? 0 : size));
    return e;
}
static void test_guest_mapping_lifecycle(void)
{
    const uint64_t base = ADRENO_WINDOW_BASE, va = base + 0x200;
    guest_unmap_calls = 0; guest_unmap_error = 0;
    guest_fence_setup();
    CHECK(guest_fence(va, 0x534e2001) == 0);
    CHECK(smmu_walk(va, 1) != 0); /* CP cached this translation. */
    CHECK(guest_unmap(base, 0x4000) == 0);
    CHECK(guest_unmap_calls == 1 && S.unmaps == 1 && dart[0] == 0);
    CHECK(smmu_walk(va, 1) == 0 && S.live_pages == 0);
    CHECK(guest_fence(va, 0x534e2002) == ADRENO_E_TARGET);
    CHECK(m_rd(0, GUEST_PAGE + 0x200) == 0x534e2001);
    dart[0] = dart_desc(GUEST_PAGE, 0, 0x4000, 0, 0);
    CHECK(mirror(base, 0x4000) == 0);
    CHECK(guest_fence(va, 0x534e2003) == 0);
    CHECK(m_rd(0, GUEST_PAGE + 0x200) == 0x534e2003 && S.wptr == 30);
    for (unsigned bad = 0; bad < 10; bad++) {
        guest_fence_setup(); guest_unmap_calls = 0;
        uint64_t regs[4] = {0x00010002, base, 0x4000, 0};
        int expected = ADRENO_E_WINDOW;
        switch (bad) {
        case 0: regs[0]++; expected = ADRENO_E_PARAMS; break;
        case 1: regs[3] = 1; expected = ADRENO_E_PARAMS; break;
        case 2: S.status |= ADRENO_S_QUIESCED; expected = ADRENO_E_PARAMS; break;
        case 3: P.flags |= ADRENO_F_RING; expected = ADRENO_E_PARAMS; break;
        case 4: regs[1] += 4; break;
        case 5: regs[2] = 0; break;
        case 6: regs[2] = 0x4004; break;
        case 7: regs[1] = ADRENO_WINDOW_END - 0x4000; regs[2] = 0x8000; break;
        case 8: regs[1] = base + (1UL << 25) - 0x4000; regs[2] = 0x8000; break;
        case 9: regs[2] = ~0x3fffUL; break;
        }
        unsigned before = nlog;
        CHECK(adreno_guest_unmap(&ops, &P, &S, regs, dart_leaf, guest_unmap_native, 0,
                                 MEM_LOW, MEM_HIGH) == expected);
        CHECK(guest_unmap_calls == 0 && nlog == before && S.unmaps == 0);
        CHECK(dart[0] == dart_desc(GUEST_PAGE, 0, 0x4000, 0, 0));
    }
    guest_fence_setup(); guest_unmap_error = 19;
    uint64_t regs[4] = {0x00010002, base, 0x4000, 0};
    CHECK(adreno_guest_unmap(&ops, &P, &S, regs, dart_leaf, guest_unmap_native, 0,
                             MEM_LOW, MEM_HIGH) == ADRENO_E_DART);
    CHECK(regs[2] == 19 && S.unmaps == 0 && smmu_walk(va, 1) != 0);
    guest_unmap_error = 0;
    guest_fence_setup(); r.tlb_stuck = 1;
    CHECK(guest_unmap(base, 0x4000) == ADRENO_E_TLB);
    CHECK(S.unmaps == 1 && dart[0] == 0);
}

/* Resource lifetime through a modeled mapper/descriptor, actual mirror and CP.
 * Faults are native-operation failures, including an insert which fails after
 * installing its PTE. Unwire clears before unpin; native final free requires
 * populated PTEs and pinned backing until its own strict unmap completes. */
enum { RF_RESERVE=1, RF_RANGE=2, RF_PIN=4, RF_ALIGN=8, RF_HOLE=16,
       RF_INSERT=32, RF_CLEAR=64, RF_UNPIN=128, RF_FREE=256 };
static struct {
    uint64_t logical, physical;
    unsigned faults, reserved, pins, reserve_calls, insert_calls, clear_calls, unpin_calls, free_calls;
} resource_model;
static int resource_reserve(void *ctx, uint64_t size, uint64_t *va, uint64_t *span)
{
    (void)ctx; resource_model.reserve_calls++;
    if (resource_model.faults & RF_RESERVE) return -1;
    CHECK(!resource_model.reserved);
    resource_model.reserved = 1;
    *va = resource_model.faults & RF_RANGE ? ADRENO_WINDOW_END : ADRENO_WINDOW_BASE + 0x200000;
    *span = size;
    return 0;
}
static int resource_pin(void *ctx)
{
    (void)ctx; CHECK(resource_model.reserved && !resource_model.pins);
    if (resource_model.faults & RF_PIN) return -1;
    resource_model.pins = 1; return 0;
}
static uint64_t resource_physical(void *ctx, uint64_t offset, uint64_t *length)
{
    (void)ctx; CHECK(resource_model.pins == 1);
    *length = resource_model.logical - offset;
    if (offset == 0x4000 && (resource_model.faults & RF_HOLE)) return 0;
    return resource_model.physical + offset +
        ((offset == 0x4000 && (resource_model.faults & RF_ALIGN)) ? 1 : 0);
}
static int resource_insert(void *ctx, uint64_t va, uint64_t offset, uint64_t pa, uint64_t length)
{
    (void)ctx; CHECK(resource_model.pins && resource_model.reserved && length == 0x4000);
    resource_model.insert_calls++;
    dart[(va + offset - ADRENO_WINDOW_BASE) >> 14] = dart_desc(pa, 0, 0x4000, 0, 0);
    int e = mirror(va + offset, length);
    if ((resource_model.faults & RF_INSERT) && offset == 0x4000) return -1;
    return e;
}
static int resource_clear(void *ctx, uint64_t va, uint64_t length)
{
    (void)ctx; CHECK(resource_model.pins && resource_model.reserved);
    resource_model.clear_calls++;
    if (resource_model.faults & RF_CLEAR) return -1;
    return guest_unmap(va, length);
}
static int resource_unpin(void *ctx)
{
    (void)ctx; CHECK(resource_model.pins);
    resource_model.unpin_calls++;
    CHECK(smmu_walk(ADRENO_WINDOW_BASE + 0x200000, 1) == 0);
    CHECK(smmu_walk(ADRENO_WINDOW_BASE + 0x204000, 1) == 0);
    if (resource_model.faults & RF_UNPIN) return -1;
    resource_model.pins = 0; return 0;
}
static int resource_free(void *ctx, uint64_t va, uint64_t size)
{
    (void)ctx; CHECK(resource_model.reserved && va && size == 0x8000);
    resource_model.free_calls++;
    if (resource_model.faults & RF_FREE) return -1;
    /* The native allocator's final unmap uses option0, not the HVC's holes
     * option2. Refuse the old clear-then-native-free sequence. */
    if (!resource_model.pins || va < ADRENO_WINDOW_BASE || va >= ADRENO_WINDOW_END) return -1;
    for (uint64_t off = 0; off < size; off += 0x4000)
        if (!dart[(va + off - ADRENO_WINDOW_BASE) >> 14]) return -1;
    if (guest_unmap(va, size)) return -1;
    resource_model.reserved = 0; return 0;
}
static const struct adreno_resource_ops resource_ops = {
    0, resource_reserve, resource_free, resource_pin, resource_unpin,
    resource_physical, resource_insert, resource_clear
};
static void resource_setup(unsigned faults)
{
    q1n1_cp_fence(); P.flags &= ~(uint64_t)ADRENO_F_RING;
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    memset(dart, 0, sizeof(dart));
    memset(&resource_model, 0, sizeof(resource_model));
    resource_model.logical = 0x4100; resource_model.physical = GUEST_PAGE;
    resource_model.faults = faults; guest_unmap_error = 0;
}
static void test_resource_lifetime(void)
{
    struct adreno_resource resource = {0};
    resource_setup(0);
    CHECK(adreno_resource_reserve(&resource, &resource_ops, resource_model.logical) == 0);
    uint64_t va = resource.address;
    CHECK(resource.length == 0x8000 && resource_model.reserved && !resource_model.pins);
    CHECK(adreno_resource_commit(&resource, &resource_ops) == 0);
    CHECK(guest_fence(va + 0x4080, 0x534e3001) == 0);
    CHECK(m_rd(0, GUEST_PAGE + 0x4080) == 0x534e3001);
    CHECK(adreno_resource_release(&resource, &resource_ops) == 0);
    CHECK(resource.address == va && resource_model.reserved && !resource_model.pins);
    CHECK(guest_fence(va + 0x4080, 0x534e3002) == ADRENO_E_TARGET);
    resource_model.physical += 0x8000; /* replacement backing, same published VA */
    CHECK(adreno_resource_commit(&resource, &resource_ops) == 0);
    CHECK(guest_fence(va + 0x4080, 0x534e3003) == 0);
    CHECK(m_rd(0, GUEST_PAGE + 0xc080) == 0x534e3003);
    CHECK(m_rd(0, GUEST_PAGE + 0x4080) == 0x534e3001);
    CHECK(adreno_resource_free(&resource, &resource_ops) == 0);
    CHECK(resource.flags == 0 && !resource.address && !resource_model.reserved && !resource_model.pins);
    CHECK(adreno_resource_free(&resource, &resource_ops) == 0 && resource_model.free_calls == 1);
    /* IOGPU finalize unwires before free: final deallocation must recommit
     * backing before entering the strict native allocator release. */
    resource_setup(0);
    CHECK(adreno_resource_reserve(&resource, &resource_ops, resource_model.logical) == 0);
    CHECK(adreno_resource_commit(&resource, &resource_ops) == 0);
    CHECK(adreno_resource_release(&resource, &resource_ops) == 0);
    CHECK(adreno_resource_free(&resource, &resource_ops) == 0);
    CHECK(resource_model.insert_calls == 4 && resource_model.unpin_calls == 2);
    CHECK(!resource_model.reserved && !resource_model.pins);
    for (unsigned fault = RF_RESERVE; fault <= RF_FREE; fault <<= 1) {
        resource_setup(fault); memset(&resource, 0, sizeof(resource));
        int e = adreno_resource_reserve(&resource, &resource_ops, resource_model.logical);
        if (fault <= RF_RANGE) {
            CHECK(e != 0 && resource_model.reserved == (fault == RF_RANGE) && !resource_model.pins);
            CHECK(resource_model.free_calls == 0);
            continue;
        }
        CHECK(e == 0);
        e = adreno_resource_commit(&resource, &resource_ops);
        if (fault <= RF_INSERT) {
            CHECK(e != 0 && !resource_model.pins && resource_model.reserved);
            CHECK(resource.mapped_length == 0);
            if (fault == RF_ALIGN || fault == RF_HOLE) CHECK(resource_model.insert_calls == 0);
            CHECK(adreno_resource_free(&resource, &resource_ops) != 0);
            CHECK((resource.flags & ADRENO_RESOURCE_FAILED) && resource_model.reserved);
            CHECK(resource_model.free_calls == 0 && !resource_model.pins);
        } else {
            CHECK(e == 0);
            e = fault == RF_CLEAR ? adreno_resource_release(&resource, &resource_ops) :
                                   adreno_resource_free(&resource, &resource_ops);
            CHECK(e != 0 && (resource.flags & ADRENO_RESOURCE_FAILED));
            CHECK(resource_model.reserved == (fault != RF_UNPIN) && resource_model.pins);
            unsigned before = resource_model.free_calls + resource_model.unpin_calls + resource_model.clear_calls;
            CHECK(adreno_resource_free(&resource, &resource_ops) != 0);
            CHECK(before == resource_model.free_calls + resource_model.unpin_calls + resource_model.clear_calls);
        }
    }
    resource_setup(RF_INSERT | RF_CLEAR); memset(&resource, 0, sizeof(resource));
    CHECK(adreno_resource_reserve(&resource, &resource_ops, resource_model.logical) == 0);
    CHECK(adreno_resource_commit(&resource, &resource_ops) != 0);
    CHECK((resource.flags & ADRENO_RESOURCE_FAILED) && resource_model.pins && resource_model.reserved);
    CHECK(resource.mapped_length == 0x8000 && resource_model.unpin_calls == 0);
    resource_setup(0); memset(&resource, 0, sizeof(resource));
    CHECK(adreno_resource_reserve(&resource, &resource_ops, 0) != 0);
    CHECK(adreno_resource_reserve(&resource, &resource_ops, ADRENO_WINDOW_END) != 0);
    CHECK(resource_model.reserve_calls == 0);
}

static void test_mirror(void)
{
    q1n1_cp_fence();
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    memset(dart, 0, sizeof(dart));
    /* A 32 KiB buffer: two full 16 KiB pages, one read-only. */
    uint64_t iova = 0x40200000;
    dart[(iova - ADRENO_WINDOW_BASE) >> 14] = dart_desc(0x8d0000000, 0, 0x4000, 0, 0);
    dart[(iova + 0x4000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(0x8d0010000, 0, 0x4000, 1, 0);
    unsigned syncs = r.tlbsyncs;
    CHECK(mirror(iova, 0x8000) == 0);
    CHECK(r.tlbsyncs == syncs);                   /* new entries need no invalidation */
    CHECK(S.map_pages == 8 && S.live_pages == 8);
    for (unsigned k = 0; k < 4; k++) {
        CHECK(smmu_walk(iova + k * 0x1000, 0) == ((0x8d0000000 + k * 0x1000) | ADRENO_PTE_LEAF));
        CHECK(smmu_walk(iova + 0x4000 + k * 0x1000, 0) ==
              ((0x8d0010000 + k * 0x1000) | ADRENO_PTE_LEAF | ADRENO_PTE_RDONLY));
    }
    /* Sub-page bounds: only the 4 KiB pages the DART leaf covers. */
    dart[(0x40300000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(0x8d0020000, 0x1800, 0x2804, 0, 0);
    CHECK(mirror(0x40301800, 0x1004) == 0);
    CHECK(!smmu_walk(0x40300000, 0) && smmu_walk(0x40301000, 0) && smmu_walk(0x40302000, 0) &&
          !smmu_walk(0x40303000, 0));
    /* Refused leaves: write-only, outside guest memory, the arena itself. */
    unsigned refused = (unsigned)S.refused;
    dart[(0x40400000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(0x8d0030000, 0, 0x4000, 0, 1);
    dart[(0x40404000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(0x800000000, 0, 0x4000, 0, 0);
    dart[(0x40408000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(ARENA, 0, 0x4000, 0, 0);
    dart[(0x4040c000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(MEM_HIGH - 0x2000 + 0, 0, 0x4000, 0, 0);
    CHECK(mirror(0x40400000, 0x10000) == 0);
    CHECK(S.refused == refused + 3u);                /* MEM_HIGH-0x2000 is not 16 KiB aligned: */
    for (uint64_t va = 0x40400000; va < 0x40410000; va += 0x1000)
        CHECK(!smmu_walk(va, 0) || (smmu_walk(va, 0) & ADRENO_PTE_ADDR) < MEM_HIGH);
    for (uint64_t va = 0x40408000; va < 0x4040c000; va += 0x1000) CHECK(!smmu_walk(va, 0));
    /* The GPU uses the mapping (fills the model TLB); unmap must invalidate it. */
    CHECK(smmu_walk(iova, 1) != 0);
    dart[(iova - ADRENO_WINDOW_BASE) >> 14] = 0;
    syncs = r.tlbsyncs;
    uint64_t live = S.live_pages;
    CHECK(mirror(iova, 0x4000) == 0);
    CHECK(r.tlbsyncs == syncs + 1 && S.tlbi >= 1);
    CHECK(S.live_pages == live - 4);
    CHECK(smmu_walk(iova, 1) == 0);                  /* not served from a stale TLB entry */
    /* The invalidation is what makes the unmap true: a stuck sync is reported. */
    dart[(iova + 0x4000 - ADRENO_WINDOW_BASE) >> 14] = 0;
    r.tlb_stuck = 1;
    CHECK(mirror(iova + 0x4000, 0x4000) == ADRENO_E_TLB && S.tlbi_timeouts == 1);
    r.tlb_stuck = 0;
    /* Tables reach DRAM before the call returns (the walker does not snoop). */
    clean_disabled = 1;
    dart[(0x7ff00000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(0x8d0040000, 0, 0x4000, 0, 0);
    CHECK(mirror(0x7ff00000, 0x4000) == 0 && !smmu_walk(0x7ff00000, 0));
    clean_disabled = 0;
    /* A repeat stores nothing but still cleans the range: DRAM now agrees. */
    CHECK(mirror(0x7ff00000, 0x4000) == 0 && smmu_walk(0x7ff00000, 0) != 0);
    /* Window bounds and power. */
    CHECK(mirror(0x3fffc000, 0x4000) == ADRENO_E_WINDOW);
    CHECK(mirror(ADRENO_WINDOW_END - 0x1000, 0x2000) == ADRENO_E_WINDOW);
    CHECK(mirror(0x40000000, 0) == ADRENO_E_WINDOW);
    dart[(ADRENO_WINDOW_END - 0x4000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(0x8d0050000, 0, 0x4000, 0, 0);
    CHECK(mirror(ADRENO_WINDOW_END - 0x4000, 0x4000) == 0 && smmu_walk(ADRENO_WINDOW_END - 0x1000, 0));
    r.cx = 0;
    CHECK(mirror(0x40000000, 0x4000) == ADRENO_E_CX && r.mmio_reads_cx_off == 0);
    r.cx = 1u << 16;
    /* q1n1's own translations below 1 GiB never move. */
    CHECK(smmu_walk(0x10200000, 0) == (MEMPTRS | ADRENO_PTE_LEAF));
    CHECK(S.map_pages - S.unmap_pages == S.live_pages);
}

static void test_fault(void)
{
    q1n1_cp_fence();
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    CHECK(adreno_fault_poll(&ops, &S) == 0);
    r.fsr = 0x402; r.far_lo = 0x40001000; r.fsynr0 = 0x10001; r.cbfrsynra = 1;
    CHECK(adreno_fault_poll(&ops, &S) == 1);
    CHECK(S.faults == 1 && S.fault_fsr == 0x402 && S.fault_far == 0x40001000 &&
          S.fault_fsynr0 == 0x10001 && S.fault_cbfrsynra == 1);
    CHECK((r.fsr & ADRENO_CB_FSR_FAULT) == 0);       /* cleared (W1C) */
    CHECK(adreno_fault_poll(&ops, &S) == 0 && S.faults == 1);
    r.gfsr = 2;
    CHECK(adreno_fault_poll(&ops, &S) == 1 && S.fault_gfsr == 2 && r.gfsr == 0);
    r.cx = 0;
    r.fsr = 2;
    CHECK(adreno_fault_poll(&ops, &S) == 0 && r.mmio_reads_cx_off == 0);
}

static void test_smc(void)
{
    /* The allow-list, byte for byte q1n1's q1n1_gpu_smc_allowed. */
    CHECK(adreno_smc_allowed(0x42002801, 1, 9, 0));
    CHECK(adreno_smc_allowed(0x42002801, 1, 1, 0) && adreno_smc_allowed(0x42002801, 1, 0xf, 0));
    CHECK(!adreno_smc_allowed(0x42002801, 1, 0, 0) && !adreno_smc_allowed(0x42002801, 1, 0x10, 0));
    CHECK(!adreno_smc_allowed(0x42002801, 2, 9, 0) && !adreno_smc_allowed(0x42002801, 1, 9, 1));
    CHECK(adreno_smc_allowed(0x42000c1b, 4, 0xffff0000, 0xffffffff));
    CHECK(!adreno_smc_allowed(0x42000c1b, 4, 0xffff0001, 0xffffffff));
    CHECK(!adreno_smc_allowed(0x42000c1b, 3, 0xffff0000, 0xffffffff));
    CHECK(!adreno_smc_allowed(0x42000c1b, 4, 0xffff0000, 0));
    CHECK(!adreno_smc_allowed(0x84000000, 0, 0, 0) && !adreno_smc_allowed(0xc2000001, 0, 0, 0));
    q1n1_cp_fence();
    uint64_t x[8] = {0xc4000003, 0, 0, 0};                             /* PSCI CPU_ON: refused */
    CHECK(adreno_smc(&ops, P.flags, &S, x) == -1 && tz.calls == 0 && S.smc_refused == 1);
    /* q1n1 made the init call at B3: answered without TrustZone. */
    uint64_t y[8] = {0x42002801, 1, 9, 0};
    CHECK(adreno_smc(&ops, P.flags | ADRENO_F_TZ_DONE, &S, y) == 0 && tz.calls == 0 && y[0] == 0 &&
          S.smc_cached == 1);
    /* Not made yet: forwarded once, then remembered. */
    uint64_t z[8] = {0x42002801, 1, 9, 0, 0x5555, 0x6666, 0x7777, 0x8888};
    CHECK(adreno_smc(&ops, P.flags, &S, z) == 0 && tz.calls == 1 && z[0] == 0 && z[1] == 0x11);
    CHECK(tz.last[4] == 0 && tz.last[5] == 0 && tz.last[6] == 0 && tz.last[7] == 0);
    CHECK(S.status & ADRENO_S_TZ_DONE);
    uint64_t again[8] = {0x42002801, 1, 9, 0};
    CHECK(adreno_smc(&ops, P.flags, &S, again) == 0 && tz.calls == 1 && S.smc_cached == 2);
    /* The aperture call: the payload supplies the fill words; INTERRUPTED is
     * resumed with x0 = 1 and TrustZone's session in x6 (QCOM_A6 quirk). */
    tz.interrupts = 3; tz.session = 0xabc; tz.final = 0;
    uint64_t a[8] = {0x42000c1b, 4, 0xffff0000, 0xffffffff};
    CHECK(adreno_smc(&ops, P.flags, &S, a) == 0 && a[0] == 0);
    CHECK(tz.calls == 5 && tz.resumed_x0 == 1 && tz.resumed_x6 == 0xabc && S.smc_resumes == 3);
    CHECK(tz.last[2] == 0xffff0000 && tz.last[3] == 0xffffffff && tz.last[4] == 0xffffffff &&
          tz.last[5] == 0xffffffff);
    /* A reply that never stops being INTERRUPTED is bounded (q1n1's 1024). */
    tz.interrupts = 5000; tz.calls = 0;
    uint64_t b[8] = {0x42000c1b, 4, 0xffff0000, 0xffffffff};
    CHECK(adreno_smc(&ops, P.flags, &S, b) == 0 && (int64_t)b[0] == -10 && tz.calls == 1025);
    /* EBUSY and WAITQ go back to the guest untouched; a trap is -7. */
    tz.interrupts = 0; tz.final = (uint64_t)-12;
    uint64_t c[8] = {0x42000c1b, 4, 0xffff0000, 0xffffffff};
    CHECK(adreno_smc(&ops, P.flags, &S, c) == 0 && (int64_t)c[0] == -12);
    tz.final = 2;
    uint64_t d[8] = {0x42000c1b, 4, 0xffff0000, 0xffffffff};
    CHECK(adreno_smc(&ops, P.flags, &S, d) == 0 && d[0] == 2);
    tz.trap = 1;
    uint64_t e[8] = {0x42000c1b, 4, 0xffff0000, 0xffffffff};
    CHECK(adreno_smc(&ops, P.flags, &S, e) == 0 && (int64_t)e[0] == -7);
}

static void test_gic(void)
{
    q1n1_cp_fence();
    r.group[10] = 0; r.cfg[20] = 0xffffffff; r.pri[83] = 0xa0a0a0a0; r.enabled[10] = 1u << 12;
    r.pending[10] = 1u << 12;
    CHECK(adreno_gic_route(&ops, &P, &S) == 0 && (S.status & ADRENO_S_ROUTED));
    CHECK(r.group[10] == 1u << 12);                              /* 0x14C = 10 * 32 + 12 */
    CHECK(r.cfg[20] == (0xffffffffu & ~(2u << 24)));             /* 0x14C % 16 = 12: level */
    CHECK(r.pri[83] == 0xa0a0a080);                              /* byte 0x14C % 4 = 0 */
    CHECK(r.route[2 * 0x14c] == 2 && r.route[2 * 0x14c + 1] == 1);
    CHECK(!(r.enabled[10] & (1u << 12)) && !(r.pending[10] & (1u << 12)));
    /* Disabled first, then configured: the first write is ICENABLER. */
    CHECK(wlog[0].pa == GICD + GICD_ICENABLER + 40 && wlog[0].v == 1u << 12);
    adreno_gic_restore(&ops, &P, &S);
    CHECK(!(S.status & ADRENO_S_ROUTED) && !(r.enabled[10] & (1u << 12)));
    q1n1_cp_fence();
    r.gic_secure = 1;
    CHECK(adreno_gic_route(&ops, &P, &S) == ADRENO_E_PARAMS && !(S.status & ADRENO_S_ROUTED));
    r.gic_secure = 0;
    /* The A16 (Stage 4 run 1): DS 0, every IGROUPR bit reads 0 to Non-secure. The group
     * write is ignored and the Non-secure SPI still routes; a Secure one is refused by its
     * priority byte. */
    q1n1_cp_fence();
    r.gic_ds0 = 1;
    r.group[10] = 0; r.pri[83] = 0xa0a0a0a0; nlog = 0;
    CHECK(adreno_gic_route(&ops, &P, &S) == 0 && (S.status & ADRENO_S_ROUTED));
    CHECK(r.group[10] == 0 && r.pri[83] == 0xa0a0a080);
    adreno_gic_restore(&ops, &P, &S);
    q1n1_cp_fence();
    r.gic_secure = 1; r.pri[83] = 0xa0a0a000;
    CHECK(adreno_gic_route(&ops, &P, &S) == ADRENO_E_PARAMS && !(S.status & ADRENO_S_ROUTED));
    CHECK((r.pri[83] & 0xffu) == 0);
    r.gic_secure = 0; r.gic_ds0 = 0;
}

static unsigned find(uint64_t pa, unsigned from)
{
    for (unsigned n = from; n < nlog; n++) if (wlog[n].pa == pa) return n;
    return ~0u;
}
static void test_quiesce(void)
{
    q1n1_cp_fence();
    CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    memset(dart, 0, sizeof(dart));
    dart[0] = dart_desc(0x8d0000000, 0, 0x4000, 0, 0);
    CHECK(mirror(0x40000000, 0x4000) == 0 && smmu_walk(0x40000000, 1));
    nlog = 0;
    adreno_quiesce(&ops, &P, &S);
    CHECK((S.status & ADRENO_S_QUIESCED) && !(S.status & ADRENO_S_ATTACHED));
    CHECK(S.quiesce == (1 | 8 | 32) && S.halt_ack == 1);
    /* Order: GX-side GBIF halt, then the mirror unlinked and invalidated. */
    unsigned halt = find(ADRENO_RBBM_GBIF_HALT, 0), inval = find(ADRENO_CB0 + ADRENO_CB_TLBIASID, 0);
    CHECK(halt != ~0u && inval != ~0u && halt < inval);
    CHECK(find(ADRENO_CB0 + ADRENO_CB_TLBSYNC, inval) != ~0u);
    for (unsigned g = 1; g < ADRENO_ROOT_SLOTS; g++) CHECK(dev_rd64(ROOT + 8 * g) == 0);
    CHECK(smmu_walk(0x40000000, 1) == 0 && smmu_walk(0x10200000, 1) == (MEMPTRS | ADRENO_PTE_LEAF));
    CHECK(S.cb0_after == ROOT && !(S.status & ADRENO_S_HIJACKED));
    /* Nothing the monitor writes reaches the GMU, GPUCC, RSCC or GX clocks. */
    for (unsigned n = 0; n < nlog; n++) {
        unsigned b = adreno_block(wlog[n].pa, ADRENO_F_ALL);
        CHECK(b == ADRENO_NONE || b == ADRENO_PASS || b == ADRENO_SMMU);
    }
    /* Idempotent. */
    unsigned before = nlog;
    adreno_quiesce(&ops, &P, &S);
    CHECK(nlog == before);
    /* A halt that is never acknowledged is bounded, terminal, and cannot
     * claim success or detach a root beneath potentially active DMA. */
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.halt_stuck = 1;
    adreno_quiesce(&ops, &P, &S);
    CHECK((S.quiesce & 4) && !(S.quiesce & (8 | 32)) && !(S.status & ADRENO_S_QUIESCED));
    /* GX already off: no GX register is touched. */
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.pwr = 3; nlog = 0;
    adreno_quiesce(&ops, &P, &S);
    CHECK(find(ADRENO_RBBM_GBIF_HALT, 0) == ~0u && !(S.quiesce & 8) && (S.quiesce & 32));
    /* CX off: nothing behind it is touched (not even the SMMU). */
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.cx = 0; nlog = 0;
    adreno_quiesce(&ops, &P, &S);
    CHECK(S.quiesce == (1 | 2) && nlog == 0 && r.mmio_reads_cx_off == 0);
    /* A guest ring that retargeted CB0 (CP_SMMU_TABLE_UPDATE) is reported. */
    q1n1_cp_fence(); adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH);
    r.ttbr_lo = 0x8d0000000 & 0xffffffff; r.ttbr_hi = 8;
    adreno_quiesce(&ops, &P, &S);
    CHECK((S.status & ADRENO_S_HIJACKED) && (S.quiesce & 64));
    /* Never adopted: a no-op. */
    q1n1_cp_fence(); nlog = 0;
    adreno_quiesce(&ops, &P, &S);
    CHECK(nlog == 0 && !S.status);
}

static void test_layout(void)
{
    /* tools/adreno_counters.py FIELDS and probes/adreno.py params_words. */
    CHECK(sizeof(struct adreno_params) == 8 * ADRENO_PARAMS_WORDS);
    CHECK(__builtin_offsetof(struct adreno_params, ring_at_seconds) == 14 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, irq) == 8 * ADRENO_STATE_WORDS);
    CHECK(__builtin_offsetof(struct adreno_state, prepare) == 1 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, maps) == 7 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, live_pages) == 12 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, faults) == 15 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, smc_calls) == 21 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, traps) == 27 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, self_irq) == 31 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, quiesce) == 36 * 8);
    CHECK(__builtin_offsetof(struct adreno_state, ib_submits) == 40 * 8);   /* the old gic_saved[4] words */
    CHECK(__builtin_offsetof(struct adreno_state, run_at) == 44 * 8);
    CHECK(ADRENO_POOL_BYTES == (ADRENO_VA_WIDE ? 0x1e0f000UL : 0x603000UL));
    /* The PM4 header, re-derived (adreno_pm4.xml pm4_parity). */
    unsigned count = 3, op = 61;
    unsigned pc = (0x9669 >> (0xf & (count ^ count >> 4))) & 1;
    unsigned po = (0x9669 >> (0xf & (op ^ op >> 4))) & 1;
    CHECK(ADRENO_PKT7_MEM_WRITE3 == (0x70000000u | count | pc << 15 | op << 16 | po << 23));
}

int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    if (!dram || !cache) return 2;
    test_blocks();
    test_stage2();
    test_adopt();
    test_fence();
    test_guest_fence();
    test_guest_mapping_lifecycle();
    test_resource_lifetime();
    test_submit_transport();
    test_mirror();
    test_fault();
    test_smc();
    test_gic();
    test_quiesce();
    test_layout();
    free(dram);
    free(cache);
    if (failures) { printf("FAILED: %u of %u Adreno checks\n", failures, checks); return 1; }
    printf("PASS: %u Adreno passthrough, adoption, fence, SMMU mirror, fault, SMC, GIC and quiesce checks\n", checks);
    return 0;
}
