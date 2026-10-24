/* SPDX-License-Identifier: MIT */
/* Design S1 (ring wrap) and S2 (ADRENO_GUEST_IB), end to end through the monitor's own entry points
 * (adreno_adopt, adreno_guest_fence, adreno_guest_fill32, adreno_guest_ib) against tools/test-adreno.c's
 * model of the A16's Adreno side: guest RAM behind a non-coherent CPU cache, the DART leaves, the CB0 walk
 * with its TLB, the registers. This file adds the CP the monitor rings:
 *  - the ring: CP_RB_WPTR runs packets from RPTR around 2 << CP_RB_CNTL.BUFSZ dwords, fetched through CB0
 *    from q1n1's ring mapping (DRAM, never the CPU cache). A bad PKT7 header, a packet across the ring end
 *    or a WPTR outside the ring halts it (a violation). It executes CP_NOP, CP_MEM_WRITE, CP_THREAD_CONTROL,
 *    CP_INDIRECT_BUFFER, CP_EVENT_WRITE7 (CACHE_CLEAN / CCU_CLEAN_COLOR / CACHE_FLUSH_TS drain the colour
 *    cache first; WRITE_ENABLED writes through CB0, a read-only leaf faults) and CP_WAIT_TIMESTAMP (a signed
 *    >= on memory, adreno_pm4.xml TS_WAIT_GE_32B; it stalls otherwise);
 *  - an IB1: fetched through CB0; PKT4, CP_CONTEXT_REG_BUNCH and CP_NON_CONTEXT_REG_BUNCH into a register
 *    file, CP_LOAD_STATE6 (direct UBO descriptors, indirect state fetched through CB0), the markers and
 *    flush packets q1n1's stream uses, and CP_DRAW_INDX_OFFSET, where q1n1's verify_refs rule runs: every
 *    address register and UBO descriptor of the draw lies inside a mapped reference, both ends of every
 *    reference translate to its backing with write permission where the GPU writes, and the code at
 *    SP_VS_BASE / SP_PS_BASE is the uploaded code. It cannot execute ir3: when the state is right it
 *    "paints" the window scissor into RB_MRT_BASE through CB0 and the colour cache (a model stand-in for
 *    pixels, which are the A16's experiment);
 *  - RBBM_STATUS, RBBM_INT_0_STATUS and CP_INTERRUPT_STATUS_GLOBAL, with injectable busy/error bits.
 *
 * S1: 5,000 guest fences and 20 maximum-size FILL32s (the kext's two ring users today) must all land, with
 * the ring wrapping at least three times; every wrap edge (one-dword tail, exact fit, the two-doorbell wrap,
 * a dropped padding doorbell, padding the CP never consumes, a BUFSZ mismatch). Before design S1 the monitor
 * refused the first fence that did not fit before the ring end, so this part FAILS on the pre-change code
 * (build it with -DADRENO_RING_TEST_PRE_CHANGE against HEAD's compat/ files; it uses no new symbol).
 * S2: draw-plan-v2's IB (tools/plan-adreno-native-triangle.py, 1005 dwords with q1n1's render-window
 * addresses, rebased here into the guest window by the generated register table) through adreno_guest_ib;
 * a maximum-size package; IBs mixed with fences and fills across wraps; the refusal matrix (nothing
 * written, cleaned or rung) and every post-doorbell outcome (UNCERTAIN, GPU_ERROR, forged fences, idle).
 * S3 (built with -DSNAP_ADRENO_IB_ASYNC=1; agents/async-ib/FAILURE-MODES.md): ADRENO_GUEST_IB_START / _POLL with a
 * CP that takes model time (cp.latency): START -> POLLs -> completion, GPU error, fault, budget across calls (with
 * either ADRENO_IB_POLL_DIVISOR), a POLL from another vCPU, the stop's drain and quiesce, the tick (no fault poll in
 * flight; an unpolled flight expires), in-flight refusals, an UNMAP's TLBI during a flight, POLL(0) and repeated
 * POLLs, the ring wrap. S3 needs no draw plan; tools/test-adreno-ib-async.c runs it with S1 and the kext's loop.
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     tools/test-adreno-ring.c compat/adreno-ib.c compat/adreno-fill.c compat/adreno-submit.c \
 *     compat/adreno-resource.c compat/adreno.c compat/irq-forward.c shadow/stage2.c shadow/shadow.c \
 *     shadow/mmu.c -o build/test-adreno-ring && build/test-adreno-ring
 * Run from the tree root. SNAP_DRAW_PLAN names the draw-plan directory (default
 * build/adreno-pipeline-compiler-20260927/draw-plan-v2); SNAP_RING_ARTIFACT_DIR, when set, receives the
 * evidence (ring words, rebased IB, readback, walk report) that tools/qualify-adreno-ring-ib.py checks
 * against q1n1's own ring_words and register database. No hardware client. */
#include <stdarg.h>
#ifndef ADRENO_RING_TEST_PRE_CHANGE
#define GUEST_SIZE 0x400000                     /* S2 needs code, target, zero page and a 2 MiB package */
#endif
#define main adreno_existing_main
#include "test-adreno.c"
#undef main
#include "adreno-fill.h"
#ifndef ADRENO_RING_TEST_PRE_CHANGE
#include "adreno-ib.h"
#define A8XX_REGS_TABLES
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
#endif
/* HEAD's compat/adreno.h names none of these; the values are a6xx.xml's (the post build asserts them). */
#ifndef ADRENO_CP_RB_CNTL
#define ADRENO_CP_RB_CNTL 0x03d02008UL
#define ADRENO_RBBM_INT_0_STATUS 0x03d001a8UL
#define ADRENO_CP_INTERRUPT_STATUS_GLOBAL 0x03d022d4UL
#endif

enum { OP_NOP = 0x10, OP_WAIT_MEM_WRITES = 0x12, OP_WAIT_TS = 0x14, OP_THREAD = 0x17, OP_SKIP_IB2_GLOBAL = 0x1d, OP_SKIP_IB2_LOCAL = 0x23,
       OP_WFI = 0x26, OP_BLIT = 0x2c, OP_LOAD_GEOM = 0x32, OP_LOAD_FRAG = 0x34, OP_DRAW = 0x38,
       OP_CCHE_INVALIDATE = 0x3a, OP_MEM_WRITE = 0x3d, OP_IB = 0x3f, OP_SET_DRAW_STATE = 0x43, OP_EVENT7 = 0x46,
       OP_CRB = 0x5c, OP_NCRB = 0x5d, OP_SET_MODE = 0x63, OP_VIS_OVERRIDE = 0x64, OP_SET_MARKER = 0x65 };
enum { EV_CACHE_FLUSH_TS = 0x04, EV_CCU_CLEAN_COLOR = 0x21, EV_CACHE_CLEAN = 0x31 };
#ifndef ADRENO_RING_TEST_PRE_CHANGE
_Static_assert(OP_NOP == A8XX_E_CP_NOP && OP_WAIT_MEM_WRITES == A8XX_E_CP_WAIT_MEM_WRITES &&
               OP_WAIT_TS == A8XX_E_CP_WAIT_TIMESTAMP &&
               OP_THREAD == A8XX_E_CP_THREAD_CONTROL && OP_SKIP_IB2_GLOBAL == A8XX_E_CP_SKIP_IB2_ENABLE_GLOBAL &&
               OP_SKIP_IB2_LOCAL == A8XX_E_CP_SKIP_IB2_ENABLE_LOCAL && OP_WFI == A8XX_E_CP_WAIT_FOR_IDLE &&
               OP_BLIT == A8XX_E_CP_BLIT && OP_LOAD_GEOM == A8XX_E_CP_LOAD_STATE6_GEOM &&
               OP_LOAD_FRAG == A8XX_E_CP_LOAD_STATE6_FRAG && OP_DRAW == A8XX_E_CP_DRAW_INDX_OFFSET &&
               OP_CCHE_INVALIDATE == A8XX_E_CP_CCHE_INVALIDATE && OP_MEM_WRITE == A8XX_E_CP_MEM_WRITE &&
               OP_IB == A8XX_E_CP_INDIRECT_BUFFER && OP_SET_DRAW_STATE == A8XX_E_CP_SET_DRAW_STATE &&
               OP_EVENT7 == A8XX_E_CP_EVENT_WRITE7 && OP_CRB == A8XX_E_CP_CONTEXT_REG_BUNCH &&
               OP_NCRB == A8XX_E_CP_NON_CONTEXT_REG_BUNCH && OP_SET_MODE == A8XX_E_CP_SET_MODE &&
               OP_VIS_OVERRIDE == A8XX_E_CP_SET_VISIBILITY_OVERRIDE && OP_SET_MARKER == A8XX_E_CP_SET_MARKER,
               "opcodes");
_Static_assert(EV_CACHE_FLUSH_TS == A8XX_E_CACHE_FLUSH_TS && EV_CCU_CLEAN_COLOR == A8XX_E_CCU_CLEAN_COLOR &&
               EV_CACHE_CLEAN == A8XX_E_CACHE_CLEAN, "events");
_Static_assert(ADRENO_CP_RB_CNTL == ADRENO_PA + 4 * A8XX_REG_CP_RB_CNTL &&
               ADRENO_RBBM_INT_0_STATUS == ADRENO_PA + 4 * A8XX_REG_RBBM_INT_0_STATUS &&
               ADRENO_CP_INTERRUPT_STATUS_GLOBAL == ADRENO_PA + 4 * A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL, "regs");
#endif

/* adreno_pm4.xml pm4_parity, re-derived here (not the monitor's copy). */
static uint32_t parity(uint32_t v)
{
    return (0x9669u >> (0xfu & (v ^ v >> 4 ^ v >> 8 ^ v >> 12 ^ v >> 16 ^ v >> 20 ^ v >> 24 ^ v >> 28))) & 1u;
}
static uint32_t pkt7(uint32_t op, uint32_t count)
{
    return 0x70000000u | count | parity(count) << 15 | op << 16 | parity(op) << 23;
}
static int pkt7_ok(uint32_t h) { return h >> 28 == 7 && !(h & 0x0f000000u) && h == pkt7(h >> 16 & 0x7f, h & 0x3fff); }

/* --- the CP ------------------------------------------------------------------------------------------ */
#define RING_VA 0x10100000UL                     /* q1n1 CP_RB_VA, the fixture's 8 read-only pages */
#define MEMPTRS_VA 0x10200000UL                  /* q1n1 CP_MEMPTRS_VA, read-write */
#define PAINT 0xc0ffee42u                        /* what the model's draw writes: not a pixel value */
struct ref { char what[48], window[16]; uint64_t va, pa, size; int write; };
static struct {
    uint32_t rb_cntl, rbbm_status, int0, cp_global;
    unsigned busy_polls, busy_after_doorbell, busy_forever;
    int halt, stall, drop_bv_fence, fault_in_ib;
    uint32_t int0_in_ib, cp_global_in_ib;
    unsigned thread, violations, packets, nops, mem_writes, mem_write_words, ibs, draws, wraps, doorbells;
    /* agents/gpu-x290: the CP thread mode each ring CP_MEM_WRITE executed in (0 = never set since cp-fence,
     * 1 BR, 2 BV, 3 BOTH), CP_THREAD_CONTROL(BR | SYNC_THREADS) seen, the waits, and the ring's packets in order
     * (opcode | thread << 8 | SYNC_THREADS << 16; CP_NOPs left out) */
    unsigned mw_thread[4], sync_br, wait_mem_writes, ring_wfis, nlog_ops;
    uint32_t ops_log[64];
    char first[200];
    uint32_t wptr_log[16]; unsigned nwptr;
    uint64_t skip_clean_lo, skip_clean_hi; unsigned skipped_cleans;
    /* the IB side */
    uint32_t reg[0x40000]; uint8_t set[0x40000];
    struct { uint64_t base; uint32_t vec4; } ubo[2][16]; unsigned nubo[2];
    struct ref refs[16]; unsigned nrefs;
    const uint8_t *vs_code, *fs_code; size_t vs_bytes, fs_bytes;
    unsigned refs_walked, address_registers, ubo_descriptors, painted, code_checked;
    /* S3: with latency, a doorbell's work runs only once the model clock is `latency` ticks past it (the GPU's
     * execution time), when the monitor next reads a register: the asynchronous IB's world. 0: at the doorbell. */
    uint64_t latency, due;
    int pending;
} cp;
static struct { uint64_t pa; uint32_t v; } ccu[1 << 16];
static unsigned nccu;

static void violation(const char *fmt, ...)
{
    if (!cp.violations++) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(cp.first, sizeof cp.first, fmt, ap);
        va_end(ap);
    }
    cp.stall = 1;                                /* the CP halts: CP_HW_ERROR, as the A16 reports it */
    cp.int0 |= 1u << 9;
}
#ifdef ADRENO_RING_SNOOP
/* tools/test-adreno-coherent.c: the includer models an interconnect that may snoop the CPU's
 * cache for a GPU access through a coherent leaf. ring_snoop_read answers a read (1) or leaves it to DRAM (0);
 * ring_snoop_write runs before a GPU write reaches DRAM. gpu_leaf is the leaf of the access being made. */
static uint64_t gpu_leaf;
static int ring_snoop_read(uint64_t leaf, uint64_t pa, uint32_t *v);
static void ring_snoop_write(uint64_t leaf, uint64_t pa);
#endif
/* CB0 as the GPU sees it: a missing leaf is a translation fault, a write to a read-only leaf a permission
 * fault; both are recorded in FSR and stop the access. */
static int gpu_pa(uint64_t va, int write, uint64_t *pa)
{
    uint64_t leaf = smmu_walk(va, 1);           /* the walk refuses VAs past CB0's T0SZ (32, or 30 wide) */
#ifdef ADRENO_RING_SNOOP
    gpu_leaf = leaf;
#endif
    if (!leaf) { r.fsr |= 2; r.far_lo = (uint32_t)va; r.far_hi = (uint32_t)(va >> 32); return 0; }
    if (write && (leaf & ADRENO_PTE_RDONLY)) {
        r.fsr |= 8; r.far_lo = (uint32_t)va; r.far_hi = (uint32_t)(va >> 32); return 0;
    }
    *pa = (leaf & ADRENO_PTE_ADDR) | (va & 0xfff);
    return 1;
}
static int gpu_rd32(uint64_t va, uint32_t *v)
{
    uint64_t pa;
    if (!gpu_pa(va, 0, &pa)) return 0;
#ifdef ADRENO_RING_SNOOP
    if (ring_snoop_read(gpu_leaf, pa, v)) return 1;
#endif
    memcpy(v, dram + ram_offset(pa, 4), 4);
    return 1;
}
static int gpu_wr32(uint64_t va, uint32_t v)
{
    uint64_t pa;
    if (!gpu_pa(va, 1, &pa)) return 0;
#ifdef ADRENO_RING_SNOOP
    ring_snoop_write(gpu_leaf, pa);
#endif
    dev_wr32(pa, v);
    return 1;
}
static void ccu_clean(void)
{
    for (unsigned i = 0; i < nccu; i++) dev_wr32(ccu[i].pa, ccu[i].v);
    nccu = 0;
}
#ifdef ADRENO_RING_IB_HOOK
static int ib_extra_op(uint32_t op, const uint32_t *b, uint32_t count);
#endif
#ifdef ADRENO_RING_HOOKS
/* agents/gpu-recovery (tools/test-adreno-recover.c): the includer models more of the GPU. ring_event_hook sees every
 * CP_EVENT_WRITE7 event (its own caches); ring_extra_op runs a ring opcode this model does not know (1: handled). */
static void ring_event_hook(uint32_t ev);
static int ring_extra_op(uint32_t op, const uint32_t *b, uint32_t count);
#endif
static void event(const uint32_t *b, uint32_t count, int in_ib)
{
    uint32_t ev = b[0] & 0xff;                  /* CP_EVENT_WRITE7_0 EVENT [7:0] */
#ifdef ADRENO_RING_HOOKS
    ring_event_hook(ev);
#endif
    if (ev == EV_CCU_CLEAN_COLOR || ev == EV_CACHE_CLEAN || ev == EV_CACHE_FLUSH_TS) ccu_clean();
    if (!(b[0] >> 27 & 1)) return;
    if (count < 4) { violation("CP_EVENT_WRITE7 WRITE_ENABLED without an address and value"); return; }
    if (cp.drop_bv_fence && cp.thread == 2 && !in_ib) return;      /* injected: the BV fence never lands */
    if (!gpu_wr32(b[1] | (uint64_t)b[2] << 32, b[3])) cp.stall = 1;
}
static int wait_ts(const uint32_t *b, uint32_t count)
{
    uint32_t v;
    if (count != 4 || b[0]) { violation("CP_WAIT_TIMESTAMP form %#x", b[0]); return 0; }
    if (!gpu_rd32(b[1] | (uint64_t)b[2] << 32, &v)) { cp.stall = 1; return 0; }
    if ((int32_t)v < (int32_t)b[3]) { cp.stall = 1; return 0; }    /* TS_WAIT_GE_32B: signed */
    return 1;
}
#ifdef ADRENO_RING_TEST_PRE_CHANGE
static void run_ib(uint64_t va, uint32_t dwords) { violation("an IB (%#llx, %u) before design S2", (unsigned long long)va, dwords); }
#else
static void run_ib(uint64_t va, uint32_t dwords);
#endif

static void cp_ring(void)
{
    uint32_t size = 2u << (cp.rb_cntl & 0x3f);
    if (cp.halt) return;                                           /* injected: no progress */
    while (r.rptr != r.wptr && !cp.stall) {
        if (r.wptr >= size || r.rptr >= size) { violation("WPTR %u outside a %u-dword ring", r.wptr, size); return; }
        uint32_t h;
        if (!gpu_rd32(RING_VA + 4UL * r.rptr, &h)) { cp.stall = 1; return; }
        uint32_t count = h & 0x3fff, op = h >> 16 & 0x7f, b[8];
        if (!pkt7_ok(h)) { violation("bad PKT7 header %#x on the ring at %u", h, r.rptr); return; }
        if (r.rptr + 1 + count > size) { violation("packet %#x across the ring end at %u", h, r.rptr); return; }
        cp.packets++;
        if (op != OP_NOP && cp.nlog_ops < 64) cp.ops_log[cp.nlog_ops++] = op | cp.thread << 8;
        if (op == OP_NOP) {
            cp.nops++;
        } else if (op == OP_MEM_WRITE) {
            cp.mw_thread[cp.thread & 3]++;
            uint32_t lo, hi;
            if (count < 3 || !gpu_rd32(RING_VA + 4UL * (r.rptr + 1), &lo) ||
                !gpu_rd32(RING_VA + 4UL * (r.rptr + 2), &hi)) { violation("CP_MEM_WRITE form"); return; }
            for (uint32_t i = 0; i + 2 < count; i++) {
                uint32_t v;
                if (!gpu_rd32(RING_VA + 4UL * (r.rptr + 3 + i), &v) ||
                    !gpu_wr32(((uint64_t)hi << 32 | lo) + 4UL * i, v)) { cp.stall = 1; return; }
            }
            cp.mem_writes++;
            cp.mem_write_words += count - 2;
        } else {
            if (count > 8) { violation("ring packet %#x longer than the monitor emits", h); return; }
            for (uint32_t i = 0; i < count; i++)
                if (!gpu_rd32(RING_VA + 4UL * (r.rptr + 1 + i), &b[i])) { cp.stall = 1; return; }
            switch (op) {
            case OP_THREAD:
                if (count != 1) { violation("CP_THREAD_CONTROL count %u", count); return; }
                cp.thread = b[0] & 3;
                if ((b[0] & 3) == 1 && b[0] >> 31) cp.sync_br++;
                if (cp.nlog_ops) cp.ops_log[cp.nlog_ops - 1] = op | cp.thread << 8 | (b[0] >> 31) << 16;
                break;
            case OP_WAIT_MEM_WRITES:            /* the model's CP_MEM_WRITEs land at once: nothing to drain */
                if (count) { violation("CP_WAIT_MEM_WRITES count %u", count); return; }
                cp.wait_mem_writes++;
                break;
            case OP_WFI:                        /* the ring model runs one packet at a time: idle here */
                if (count) { violation("CP_WAIT_FOR_IDLE count %u", count); return; }
                cp.ring_wfis++;
                break;
            case OP_IB:
                if (count != 3) { violation("CP_INDIRECT_BUFFER count %u", count); return; }
                run_ib(b[0] | (uint64_t)b[1] << 32, b[2] & 0xfffff);
                if (cp.stall) return;
                break;
            case OP_EVENT7: event(b, count, 0); if (cp.stall) return; break;
            case OP_WAIT_TS: if (!wait_ts(b, count)) return; break;
            default:
#ifdef ADRENO_RING_HOOKS
                if (ring_extra_op(op, b, count)) { if (cp.stall) return; break; }
#endif
                violation("opcode %#x on the ring", op); return;
            }
        }
        uint32_t next = (r.rptr + 1 + count) % size;
        if (next < r.rptr) cp.wraps++;
        r.rptr = next;
    }
}

static void cp_catch_up(void)
{
    if (cp.pending && (int64_t)(clock_now - cp.due) >= 0) { cp.pending = 0; cp_ring(); }
}
static uint32_t ring_rd(void *ctx, uint64_t pa)
{
    cp_catch_up();
    int gx = pa == ADRENO_CP_RB_CNTL || pa == ADRENO_RBBM_STATUS || pa == ADRENO_RBBM_INT_0_STATUS ||
             pa == ADRENO_CP_INTERRUPT_STATUS_GLOBAL;
    if (gx && !(r.cx & (1u << 16))) r.mmio_reads_cx_off++;
    switch (pa) {
    case ADRENO_CP_RB_CNTL: return cp.rb_cntl;
    case ADRENO_RBBM_STATUS:
        if (cp.busy_forever || cp.pending) return 3;     /* S3: still executing what a doorbell published */
        if (cp.busy_polls) { cp.busy_polls--; return 3; }
        return cp.rbbm_status;
    case ADRENO_RBBM_INT_0_STATUS: return cp.int0;
    case ADRENO_CP_INTERRUPT_STATUS_GLOBAL: return cp.cp_global;
    }
    return m_rd(ctx, pa);
}
static void ring_wr(void *ctx, uint64_t pa, uint32_t v)
{
    if (pa != ADRENO_CP_RB_WPTR) { m_wr(ctx, pa, v); return; }
    if (nlog < 4096) wlog[nlog++] = (struct regwrite){pa, v};
    if (r.drop_writes) { r.drop_writes--; r.fence_status |= 1; return; }
    r.fence_status = 0;
    r.wptr = v;
    cp.doorbells++;
    if (cp.nwptr < 16) cp.wptr_log[cp.nwptr++] = v;
    cp.busy_polls = cp.busy_after_doorbell;
    if (cp.latency) { cp.pending = 1; cp.due = clock_now + cp.latency; return; }
    cp_ring();
}
static void ring_clean(void *ctx, uint64_t pa, uint64_t size)
{
    if (pa < cp.skip_clean_hi && cp.skip_clean_lo < pa + size) { cleans++; cp.skipped_cleans++; return; }
    m_clean(ctx, pa, size);
}
static struct adreno_ops ring_ops;

/* --- fixtures ------------------------------------------------------------------------------------------- */
#define FENCE_VA ADRENO_WINDOW_BASE              /* dart[0]: the kext's stamp page stand-in */
#define FENCE_PA GUEST_PAGE
#define FILL_A_VA (ADRENO_WINDOW_BASE + 0x4000)
#define FILL_A_PA (GUEST_PAGE + 0x4000)
#define FILL_B_VA (ADRENO_WINDOW_BASE + 0x8000)
#define FILL_B_PA (GUEST_PAGE + 0x8000)
static void map(uint64_t va, uint64_t pa, uint64_t bytes, int nowrite)
{
    for (uint64_t off = 0; off < bytes; off += 0x4000)
        dart[(va + off - ADRENO_WINDOW_BASE) >> 14] = dart_desc(pa + off, 0, 0x4000, nowrite, 0);
    CHECK(mirror(va, bytes) == 0);
}
static void ring_setup(uint64_t wptr)
{
    q1n1_cp_fence();
    memset(&cp, 0, sizeof cp);
    nccu = 0;
    cp.rb_cntl = 12 | 2 << 8;                    /* q1n1 RB_CNTL_DEFAULT: what every A16 record reads */
    P.flags &= ~(uint64_t)ADRENO_F_RING;         /* the guest profile: ENABLE | DART (| CX_MISC | SELF_IRQ) */
    P.ring_wptr = r.wptr = r.rptr = (uint32_t)wptr;
    ring_ops = ops;
    ring_ops.rd = ring_rd;
    ring_ops.wr = ring_wr;
    ring_ops.clean = ring_clean;
    CHECK(adreno_adopt(&ring_ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    memset(dart, 0, sizeof(dart));
    map(FENCE_VA, FENCE_PA, 0x4000, 0);
    map(FILL_A_VA, FILL_A_PA, 0x4000, 0);
    map(FILL_B_VA, FILL_B_PA, 0x4000, 0);
    nlog = 0;
}
static int fence(uint64_t va, uint32_t value)
{
    uint64_t regs[4] = {0x00010001, va, value, 0};
    int e = adreno_guest_fence(&ring_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[3] == S.wptr && regs[1] == (e ? 0 : value));
    return e;
}
static int fill(uint64_t va, uint64_t bytes, uint32_t value)
{
    uint64_t regs[4] = {ADRENO_GUEST_FILL32, va, bytes, value};
    int e = adreno_guest_fill32(&ring_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[3] == S.wptr && regs[1] == (e ? 0 : bytes));
    return e;
}
static uint32_t dev_rd32(uint64_t pa) { uint32_t v; memcpy(&v, dram + ram_offset(pa, 4), 4); return v; }
static unsigned words_not(uint64_t pa, uint64_t bytes, uint32_t value)
{
    unsigned bad = 0;
    for (uint64_t off = 0; off < bytes; off += 4) bad += dev_rd32(pa + off) != value;
    return bad;
}

/* --- S1: 5,000 fences and 20 maximum-size fills through the wrapping ring --------------------------------- */
static struct { unsigned fences, fills, wraps, first_failure_at, first_failure_kind; int first_error; } s1;
static void test_s1_capacity(void)
{
    ring_setup(22);
    for (uint64_t off = 0; off < 0x4000; off += 4) { dev_wr32(FILL_A_PA + off, 0xa55aa55a); dev_wr32(FILL_B_PA + off, 0xa55aa55a); }
    unsigned bad_values = 0, bad_fills = 0, bad_pointers = 0, submissions = 0;
    s1.first_failure_at = ~0u;
    for (unsigned i = 0; i < 5000; i++) {
        uint32_t value = 0x5a000000u + i;
        int e = fence(FENCE_VA + 0x200, value);
        submissions++;
        if (!e) s1.fences++;
        if ((e || dev_rd32(FENCE_PA + 0x200) != value) && s1.first_failure_at == ~0u) {
            s1.first_failure_at = submissions; s1.first_failure_kind = 0; s1.first_error = e;
        }
        bad_values += e || dev_rd32(FENCE_PA + 0x200) != value;
        bad_pointers += S.wptr != r.wptr || r.wptr != r.rptr || S.wptr >= P.ring_dwords;
        if (i % 250 == 125) {                    /* 20 fills of 4,096 words (4,103 ring dwords each) */
            unsigned k = i / 250;
            uint64_t va = k & 1 ? FILL_B_VA : FILL_A_VA, pa = k & 1 ? FILL_B_PA : FILL_A_PA;
            uint32_t pattern = 0xf1000000u + k;
            e = fill(va, ADRENO_FILL32_MAX_BYTES, pattern);
            submissions++;
            if (!e) s1.fills++;
            if ((e || words_not(pa, 0x4000, pattern)) && s1.first_failure_at == ~0u) {
                s1.first_failure_at = submissions; s1.first_failure_kind = 1; s1.first_error = e;
            }
            bad_fills += e || words_not(pa, 0x4000, pattern);
        }
    }
    s1.wraps = cp.wraps;
    printf("RING_S1 fences=%u/5000 fills=%u/20 model_wraps=%u doorbells=%u words=%u first_failure=%d kind=%s error=%d violations=%u\n",
           s1.fences, s1.fills, cp.wraps, cp.doorbells, cp.mem_write_words,
           s1.first_failure_at == ~0u ? -1 : (int)s1.first_failure_at, s1.first_failure_kind ? "fill" : "fence",
           s1.first_error, cp.violations);
    CHECK(s1.fences == 5000 && bad_values == 0);                   /* every fence value landed */
    CHECK(s1.fills == 20 && bad_fills == 0);                       /* every filled byte landed */
    CHECK(bad_pointers == 0);                                      /* RPTR == WPTR == monitor, inside the ring */
    CHECK(cp.wraps >= 3 && cp.violations == 0 && !r.fsr);          /* wrapped, no bad packet, no fault */
    CHECK(cp.mem_writes == 5000 + 2 * 20);                         /* each fill: payload + completion */
#ifndef ADRENO_RING_TEST_PRE_CHANGE
    CHECK(S.ring_wraps == cp.wraps && S.fences == 5020);
#endif
    /* Neighbours of the fence word never change. */
    CHECK(dev_rd32(FENCE_PA + 0x1fc) == 0 && dev_rd32(FENCE_PA + 0x204) == 0);
}

/* --- S1: the wrap edges ------------------------------------------------------------------------------------ */
/* The ring words of one fence and of one FILL32 of d data dwords, and where the fill's marker packet starts:
 * 4 / d + 7 / d + 3 by default; with agents/gpu-x290's opt-in thread selection (compat/adreno.h
 * SNAP_ADRENO_FENCE_BR, compat/adreno-fill.h SNAP_ADRENO_FILL_BR) 9 / d + 12 / d + 6. Every edge below is the
 * same edge in both builds; with the defines off the numbers are the original ones (8187, 8188, 4099, 4103). */
#if SNAP_ADRENO_FENCE_BR
#define FENCE_WORDS ADRENO_FENCE_BR_WORDS
#define FENCE_HEAD pkt7(OP_THREAD, 1)
#else
#define FENCE_WORDS 4u
#define FENCE_HEAD ADRENO_PKT7_MEM_WRITE3
#endif
#if SNAP_ADRENO_FILL_BR
#define FILL_WORDS(d) ((d) + ADRENO_FILL32_BR_EXTRA)
#define FILL_MARKER_AT(d) ((d) + 6u)
#else
#define FILL_WORDS(d) ((d) + 7u)
#define FILL_MARKER_AT(d) ((d) + 3u)
#endif
static uint32_t ring_word(uint32_t i) { return dev_rd32(RING + 4UL * i); }
static void test_s1_edges(void)
{
    const uint32_t fw = FILL_WORDS(0x1000);
    /* A one-dword tail: pkt7(CP_NOP, 0), then the fence at 0 with one doorbell. */
    ring_setup(8191);
    CHECK(fence(FENCE_VA + 0x200, 0x51000001) == 0 && dev_rd32(FENCE_PA + 0x200) == 0x51000001);
    CHECK(ring_word(8191) == pkt7(OP_NOP, 0) && ring_word(0) == FENCE_HEAD);
    CHECK(S.wptr == FENCE_WORDS && r.rptr == FENCE_WORDS && cp.doorbells == 1 && cp.wptr_log[0] == FENCE_WORDS &&
          cp.nops == 1);
    /* Exact fit leaves one dword (WPTR 8191, never 8192); the next fence pads that dword. */
    ring_setup(8191 - FENCE_WORDS);
    CHECK(fence(FENCE_VA + 0x200, 0x51000002) == 0 && S.wptr == 8191 && cp.nops == 0);
    CHECK(fence(FENCE_VA + 0x200, 0x51000003) == 0 && S.wptr == FENCE_WORDS && cp.nops == 1 && cp.wraps == 1);
    /* n == ring_dwords - w: the whole tail becomes one CP_NOP carrying n - 1 dwords. */
    ring_setup(8192 - FENCE_WORDS);
    CHECK(fence(FENCE_VA + 0x200, 0x51000004) == 0 && ring_word(8192 - FENCE_WORDS) == pkt7(OP_NOP, FENCE_WORDS - 1) &&
          S.wptr == FENCE_WORDS);
    /* The two-doorbell wrap: a 4,103-dword fill at w = 4100 would overwrite padding the CP has not run,
     * so the padding is rung alone (WPTR 0), consumed, then the fill at 0 (WPTR 4103). */
    ring_setup(4100);
    CHECK(fill(FILL_A_VA, 0x4000, 0x0f0f0f0f) == 0 && words_not(FILL_A_PA, 0x4000, 0x0f0f0f0f) == 0);
    CHECK(cp.nwptr == 2 && cp.wptr_log[0] == 0 && cp.wptr_log[1] == fw && S.wptr == fw && r.rptr == fw);
    /* The padding ran (one CP_NOP) before the fill's words at 0 reused 4100..4102: its completion packet
     * now starts at 4099 (header, VA, 4,096 words, then CP_MEM_WRITE of the marker). */
    CHECK(cp.nops == 1 && cp.wraps == 1 && cp.violations == 0 &&
          ring_word(FILL_MARKER_AT(0x1000)) == ADRENO_PKT7_MEM_WRITE3);
    /* n == w exactly: one doorbell at WPTR n would equal RPTR, which the CP reads as an empty ring, so this
     * too takes the two-doorbell path; one dword later (w = 4104, n < w) a single doorbell runs pad + words. */
    ring_setup(fw);
    CHECK(fill(FILL_A_VA, 0x4000, 0x69696969) == 0 && words_not(FILL_A_PA, 0x4000, 0x69696969) == 0);
    CHECK(cp.nwptr == 2 && cp.wptr_log[0] == 0 && cp.wptr_log[1] == fw && S.wptr == fw && r.rptr == fw);
    ring_setup(fw + 1);
    CHECK(fill(FILL_A_VA, 0x4000, 0x78787878) == 0 && words_not(FILL_A_PA, 0x4000, 0x78787878) == 0);
    CHECK(cp.nwptr == 1 && cp.wptr_log[0] == fw && S.wptr == fw && r.rptr == fw && cp.violations == 0);
    /* The same with a padding doorbell dropped once (a6xx_fenced_write retries) ... */
    ring_setup(4100);
    r.drop_writes = 1;
    CHECK(fill(FILL_A_VA, 0x4000, 0x1e1e1e1e) == 0 && words_not(FILL_A_PA, 0x4000, 0x1e1e1e1e) == 0);
    /* ... and dropped twice: FILL32 reports UNCERTAIN (a doorbell may have reached the CP); a fence reports
     * the dropped doorbell (ADRENO_E_RING) and keeps its WPTR, and the next fence pads again and lands. */
    ring_setup(4100);
    r.drop_writes = 2;
    CHECK(fill(FILL_A_VA, 0x4000, 0x2d2d2d2d) == ADRENO_FILL32_E_UNCERTAIN && S.fences == 0);
    CHECK(S.wptr == 4100 && r.wptr == 4100 && words_not(FILL_A_PA, 0x4000, 0) == 0);
    ring_setup(8190);
    r.drop_writes = 2;
    CHECK(fence(FENCE_VA + 0x200, 0x51000005) == ADRENO_E_RING && S.wptr == 8190 && r.wptr == 8190);
    CHECK(fence(FENCE_VA + 0x200, 0x51000006) == 0 && dev_rd32(FENCE_PA + 0x200) == 0x51000006 &&
          S.wptr == FENCE_WORDS);
    /* Padding the CP never consumes (no progress): FILL32 is UNCERTAIN; the monitor's WPTR is the CP's (0). */
    ring_setup(4100);
    cp.halt = 1;
    CHECK(fill(FILL_A_VA, 0x4000, 0x3c3c3c3c) == ADRENO_FILL32_E_UNCERTAIN && S.wptr == 0 && r.wptr == 0);
    /* The ring's size must be the CP's: refused at adoption and at every emission, before any write. */
    ring_setup(22);
    cp.rb_cntl = 13 | 2 << 8;
    unsigned before = nlog;
    CHECK(fence(FENCE_VA + 0x200, 0x51000007) == ADRENO_E_RING && nlog == before && S.wptr == 22);
    CHECK(fill(FILL_A_VA, 0x4000, 0x4b4b4b4b) == ADRENO_E_RING && nlog == before && S.wptr == 22);
    q1n1_cp_fence(); P.flags &= ~(uint64_t)ADRENO_F_RING;
    CHECK(adreno_adopt(&ring_ops, &P, &S, MEM_LOW, MEM_HIGH) == ADRENO_E_RING && !(S.status & ADRENO_S_ATTACHED));
    /* A fill that cannot fit even an empty ring (BUFSZ 11: 4,096 dwords) is refused, not wrapped. */
    q1n1_cp_fence(); P.flags &= ~(uint64_t)ADRENO_F_RING; P.ring_dwords = 4096; cp.rb_cntl = 11 | 2 << 8;
    P.ring_wptr = r.wptr = r.rptr = 0;
    CHECK(adreno_adopt(&ring_ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
    memset(dart, 0, sizeof(dart)); map(FILL_A_VA, FILL_A_PA, 0x4000, 0); nlog = 0;
    CHECK(fill(FILL_A_VA, 0x4000, 0x5a5a5a5a) == ADRENO_E_RING && nlog == 0 && S.wptr == 0);
    CHECK(fill(FILL_A_VA, 0x3000, 0x5a5a5a5a) == 0 && words_not(FILL_A_PA, 0x3000, 0x5a5a5a5a) == 0);
    CHECK(cp.violations == 0);
}

#ifndef ADRENO_RING_TEST_PRE_CHANGE
/* --- S1: CP_NOP padding longer than one packet (a ring above ADRENO_RING_NOP_MAX dwords) ------------------ */
static void test_s1_nop_split(void)
{
    /* adopt caps the ring at 8,192 dwords, so one CP_NOP always suffices on the A16; the splitting rule is
     * checked on the helper itself: a 0x10000-dword ring (BUFSZ 15) at an unused arena offset, w = 0xb000,
     * n = 0x6000 (no room before the end, n < w: one later doorbell, so nothing is rung here). */
    ring_setup(22);
    struct adreno_params big = P;
    big.ring_pa = ARENA + 0x800000;
    big.ring_dwords = 0x10000;
    cp.rb_cntl = 15 | 2 << 8;
    S.wptr = r.wptr = r.rptr = 0xb000;
    uint64_t at = 99;
    int rung = 7;
    unsigned wraps = (unsigned)S.ring_wraps, doorbells = cp.doorbells;
    CHECK(adreno_ring_reserve(&ring_ops, &big, &S, 0x6000, &at, &rung) == 0 && at == 0 && rung == 0);
    CHECK(S.ring_wraps == wraps + 1 && cp.doorbells == doorbells && S.wptr == 0xb000);
    unsigned packets = 0, bad = 0;
    uint64_t k = 0xb000;
    while (k < 0x10000) {
        uint32_t h = dev_rd32(big.ring_pa + 4 * k), count = h & 0x3fff;
        bad += !pkt7_ok(h) || (h >> 16 & 0x7f) != OP_NOP;
        for (uint32_t i = 1; i <= count && k + i < 0x10000; i++) bad += dev_rd32(big.ring_pa + 4 * (k + i)) != 0;
        k += 1 + count;
        packets++;
    }
    CHECK(k == 0x10000 && packets == 2 && bad == 0);                /* 16,384 + 4,096 dwords, exactly */
    CHECK(dev_rd32(big.ring_pa + 4 * 0xb000) == pkt7(OP_NOP, 0x3fff) &&
          dev_rd32(big.ring_pa + 4 * 0xf000) == pkt7(OP_NOP, 0xfff));
    /* Every emission is at most ring_dwords - 1 and at least one word. */
    CHECK(adreno_ring_ready(&ring_ops, &big, &S, 0) == ADRENO_E_RING);
    CHECK(adreno_ring_ready(&ring_ops, &big, &S, 0x10000) == ADRENO_E_RING);
    CHECK(adreno_ring_ready(&ring_ops, &big, &S, 0xffff) == 0);
}

/* --- agents/gpu-x290 F1-F3, F7, F10: the CP thread mode of the ring writes outside IBs ---------------------------
 * adreno_ib_ring_words leaves the ring in CP_THREAD_CONTROL(BOTH), so a fence or FILL32 after an IB runs on both CP
 * threads by default (this model executes a BOTH-mode packet once and records the mode). With SNAP_ADRENO_FENCE_BR /
 * SNAP_ADRENO_FILL_BR the words select BR with SYNC_THREADS (adreno-ib.c, Linux a7xx_submit), wait (CP_WAIT_FOR_IDLE
 * before a fence, CP_WAIT_MEM_WRITES between the fill and its marker), write from BR only and end in BOTH; completion
 * also needs RBBM idle. Both builds run this test: the default half documents what the defines change. */
static void thread_log_reset(void)
{
    cp.nlog_ops = 0;
    memset(cp.mw_thread, 0, sizeof cp.mw_thread);
    cp.sync_br = cp.wait_mem_writes = cp.ring_wfis = 0;
}
static void test_thread_modes(void)
{
    const uint32_t tc = pkt7(OP_THREAD, 1), br_sync = 1u << 31 | 1u;
    (void)tc; (void)br_sync;                     /* used by the define-on halves only */
    ring_setup(22);
    cp.thread = 3;                               /* as an IB leaves it */
    thread_log_reset();
    CHECK(fence(FENCE_VA + 0x200, 0x61000001) == 0 && dev_rd32(FENCE_PA + 0x200) == 0x61000001);
#if SNAP_ADRENO_FENCE_BR
    CHECK(ring_word(22) == tc && ring_word(23) == br_sync && ring_word(24) == pkt7(OP_WFI, 0) &&
          ring_word(25) == ADRENO_PKT7_MEM_WRITE3 && ring_word(29) == tc && ring_word(30) == 3u &&
          S.wptr == 22 + ADRENO_FENCE_BR_WORDS);
    CHECK(cp.mw_thread[1] == 1 && cp.mw_thread[3] == 0 && cp.sync_br == 1 && cp.ring_wfis == 1 && cp.thread == 3);
    CHECK(cp.nlog_ops == 4 && cp.ops_log[0] == (OP_THREAD | 1u << 8 | 1u << 16) && cp.ops_log[1] == (OP_WFI | 1u << 8) &&
          cp.ops_log[2] == (OP_MEM_WRITE | 1u << 8) && cp.ops_log[3] == (OP_THREAD | 3u << 8));
#else
    CHECK(ring_word(22) == ADRENO_PKT7_MEM_WRITE3 && S.wptr == 26 && cp.mw_thread[3] == 1 && cp.sync_br == 0);
#endif
    thread_log_reset();
    for (uint64_t off = 0; off < 64; off += 4) dev_wr32(FILL_A_PA + off, 0xa55aa55a);
    const uint64_t at = S.wptr;
    CHECK(fill(FILL_A_VA, 64, 0x0badf00d) == 0 && words_not(FILL_A_PA, 64, 0x0badf00d) == 0);
    CHECK(S.wptr == at + FILL_WORDS(16) && cp.violations == 0);
#if SNAP_ADRENO_FILL_BR
    CHECK(ring_word((uint32_t)at) == tc && ring_word((uint32_t)at + 1) == br_sync &&
          ring_word((uint32_t)at + 2) == pkt7(OP_MEM_WRITE, 16 + 2) &&
          ring_word((uint32_t)at + 21) == pkt7(OP_WAIT_MEM_WRITES, 0) &&
          ring_word((uint32_t)at + FILL_MARKER_AT(16)) == ADRENO_PKT7_MEM_WRITE3 &&
          ring_word((uint32_t)at + 26) == tc && ring_word((uint32_t)at + 27) == 3u);
    CHECK(cp.mw_thread[1] == 2 && cp.mw_thread[3] == 0 && cp.sync_br == 1 && cp.wait_mem_writes == 1 && cp.thread == 3);
    CHECK(cp.nlog_ops == 5 && cp.ops_log[0] == (OP_THREAD | 1u << 8 | 1u << 16) &&
          cp.ops_log[1] == (OP_MEM_WRITE | 1u << 8) && cp.ops_log[2] == (OP_WAIT_MEM_WRITES | 1u << 8) &&
          cp.ops_log[3] == (OP_MEM_WRITE | 1u << 8) && cp.ops_log[4] == (OP_THREAD | 3u << 8));
#else
    CHECK(ring_word((uint32_t)at) == pkt7(OP_MEM_WRITE, 16 + 2) && cp.mw_thread[3] == 2 && cp.sync_br == 0);
#endif
    /* F2: RBBM busy after the doorbell. With the defines the call completes only once RBBM reads idle, and a GPU
     * that stays busy is not complete (UNCERTAIN / ADRENO_E_FENCE); the default never reads RBBM. */
    ring_setup(22);
    cp.busy_after_doorbell = 40;
    CHECK(fill(FILL_A_VA, 64, 0x22222222) == 0 && words_not(FILL_A_PA, 64, 0x22222222) == 0);
#if SNAP_ADRENO_FILL_BR
    CHECK(cp.busy_polls == 0);
#else
    CHECK(cp.busy_polls == 40);
#endif
    ring_setup(22);
    cp.busy_after_doorbell = 40;
    CHECK(fence(FENCE_VA + 0x200, 0x61000002) == 0 && dev_rd32(FENCE_PA + 0x200) == 0x61000002);
#if SNAP_ADRENO_FENCE_BR
    CHECK(cp.busy_polls == 0);
#else
    CHECK(cp.busy_polls == 40);
#endif
    ring_setup(22);
    cp.busy_forever = 1;
    int e = fill(FILL_A_VA, 64, 0x33333333);
#if SNAP_ADRENO_FILL_BR
    CHECK(e == ADRENO_FILL32_E_UNCERTAIN && S.fences == 0 && words_not(FILL_A_PA, 64, 0x33333333) == 0);
#else
    CHECK(e == 0);
#endif
    ring_setup(22);
    cp.busy_forever = 1;
    e = fence(FENCE_VA + 0x200, 0x61000003);
#if SNAP_ADRENO_FENCE_BR
    CHECK(e == ADRENO_E_FENCE && S.fences == 0);
#else
    CHECK(e == 0);
#endif
    /* F10: no progress at all (SYNC_THREADS never satisfied looks the same): bounded, nothing else touched. */
    ring_setup(22);
    cp.halt = 1;
    CHECK(fill(FILL_A_VA, 64, 0x44444444) == ADRENO_FILL32_E_UNCERTAIN && S.fences == 0);
    ring_setup(22);
    cp.halt = 1;
    CHECK(fence(FENCE_VA + 0x200, 0x61000004) == ADRENO_E_FENCE && S.fences == 0);
    printf("RING_THREADS fence %s, fill %s: modes, waits, idle and no-progress checked\n",
#if SNAP_ADRENO_FENCE_BR
           "BR+SYNC/WFI/BOTH",
#else
           "default (ring mode)",
#endif
#if SNAP_ADRENO_FILL_BR
           "BR+SYNC/WAIT_MEM_WRITES/BOTH");
#else
           "default (ring mode)");
#endif
}

/* --- S2: the IB fixtures ----------------------------------------------------------------------------------- */
#define ZERO_VA 0x40100000UL                     /* the kext arena's zero page (read-only)       */
#define ZERO_PA (GUEST_PAGE + 0x10000)
#define PKG_VA 0x40104000UL                      /* the kext arena's package area (read-only)    */
#define PKG_PA (GUEST_PAGE + 0x14000)
#define CODE_VA 0x40200000UL                     /* the pipeline's code buffer (a Metal buffer)  */
#define CODE_PA (GUEST_PAGE + 0x20000)
#define RT_VA 0x40300000UL                       /* the render target's allocation, guards incl. */
#define RT_PA (GUEST_PAGE + 0x28000)
#define RT_BYTES 0xa000UL
#define BIG_VA 0x40400000UL                      /* a 2 MiB package across 129 pages             */
#define BIG_PA (GUEST_PAGE + 0x100000)
/* q1n1's render window (adreno_x2.RENDER_VA + ARENA_LAYOUT r_* - RENDER_ARENA_WINDOW[0]): the symbolic
 * addresses tools/plan-adreno-native-triangle.py wrote into draw-plan-v2. */
static const struct { const char *window; uint64_t q1n1_va, size, model_va, model_pa; } WINDOWS[] = {
    {"r_misc", 0x120a0000, 0x1000, ZERO_VA, ZERO_PA},
    {"r_code", 0x120b0000, 0x4000, CODE_VA, CODE_PA},
    {"r_rt", 0x122a0000, RT_BYTES, RT_VA, RT_PA},
};
#define RENDER_LO 0x12000000u
#define RENDER_HI 0x125a0000u

struct plan {
    uint32_t *ib, *original; unsigned dwords, rebased, left_in_render_window;
    uint8_t *vs, *fs, *rt; size_t vs_bytes, fs_bytes, rt_bytes;
    struct ref refs[16]; unsigned nrefs;
};
static struct plan plan;
static uint8_t *slurp(const char *dir, const char *name, size_t *bytes)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = n > 0 ? malloc((size_t)n + 1) : 0;
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = 0; }
    fclose(f);
    if (b) { b[n] = 0; *bytes = (size_t)n; }
    return b;
}
static int rebase(uint64_t va, uint64_t *out)
{
    for (unsigned w = 0; w < sizeof WINDOWS / sizeof WINDOWS[0]; w++)
        if (va >= WINDOWS[w].q1n1_va && va < WINDOWS[w].q1n1_va + WINDOWS[w].size) {
            *out = WINDOWS[w].model_va + (va - WINDOWS[w].q1n1_va);
            return 1;
        }
    return 0;
}
/* Is `off` the low dword of a 64-bit address register (generated a8xx_ib_regs, flag ADDRESS)? */
static const struct a8xx_reg_info *address_register(uint32_t off)
{
    for (unsigned i = 0; i < sizeof a8xx_ib_regs / sizeof a8xx_ib_regs[0]; i++) {
        const struct a8xx_reg_info *g = &a8xx_ib_regs[i];
        if (!(g->flags & A8XX_REG_FLAG_ADDRESS) || off < g->offset) continue;
        uint32_t d = off - g->offset;
        if (g->count == 1 ? d == 0 : (g->stride && d % g->stride == 0 && d / g->stride < g->count)) return g;
    }
    return 0;
}
static void rebase_dword(uint32_t *w, uint64_t mask_low)
{
    uint64_t moved;
    if ((*w & ~mask_low) >= RENDER_LO && (*w & ~mask_low) < RENDER_HI && rebase(*w & ~mask_low, &moved)) {
        *w = (uint32_t)moved | (*w & (uint32_t)mask_low);
        plan.rebased++;
    }
}
static int load_plan(const char *dir)
{
    size_t n = 0, refs_bytes = 0;
    memset(&plan, 0, sizeof plan);
    uint8_t *ib = slurp(dir, "draw.ib.bin", &n);
    char *json = (char *)slurp(dir, "references.json", &refs_bytes);
    plan.vs = slurp(dir, "upload-0.bin", &plan.vs_bytes);
    plan.fs = slurp(dir, "upload-1.bin", &plan.fs_bytes);
    plan.rt = slurp(dir, "target.before.bin", &plan.rt_bytes);
    if (!ib || !json || !plan.vs || !plan.fs || !plan.rt || n % 4 || !n) return -1;
    plan.dwords = (unsigned)(n / 4);
    plan.ib = (uint32_t *)ib;
    plan.original = malloc(n);
    memcpy(plan.original, ib, n);
    /* references.json: one object per reference, one key per line (json.dumps indent=2). */
    struct ref *cur = 0;
    for (char *line = strtok(json, "\n"); line; line = strtok(0, "\n")) {
        char text[64];
        unsigned long long v;
        if (strchr(line, '{') && plan.nrefs < 16) cur = &plan.refs[plan.nrefs++];
        if (!cur) continue;
        if (sscanf(line, " \"what\": \"%47[^\"]\"", text) == 1) snprintf(cur->what, sizeof cur->what, "%s", text);
        else if (sscanf(line, " \"window\": \"%15[^\"]\"", text) == 1) snprintf(cur->window, sizeof cur->window, "%s", text);
        else if (sscanf(line, " \"va\": %llu", &v) == 1) cur->va = v;
        else if (sscanf(line, " \"size\": %llu", &v) == 1) cur->size = v;
        else if (strstr(line, "\"write\": true")) cur->write = 1;
    }
    free(json);
    for (unsigned i = 0; i < plan.nrefs; i++) {
        struct ref *f = &plan.refs[i];
        if (!strcmp(f->window, "memptrs")) { f->pa = MEMPTRS + (f->va - MEMPTRS_VA); continue; }
        int found = 0;
        for (unsigned w = 0; w < sizeof WINDOWS / sizeof WINDOWS[0]; w++)
            if (!strcmp(f->window, WINDOWS[w].window) && f->va >= WINDOWS[w].q1n1_va &&
                f->va + f->size <= WINDOWS[w].q1n1_va + WINDOWS[w].size) {
                f->pa = WINDOWS[w].model_pa + (f->va - WINDOWS[w].q1n1_va);
                f->va = WINDOWS[w].model_va + (f->va - WINDOWS[w].q1n1_va);
                found = 1;
            }
        if (!found) return -2;
    }
    /* Rebase the IB's address fields only: PKT4 / CRB / NCRB writes of an address register's low dword,
     * the SP_GFX_BINDLESS_BASE_DESCRIPTOR low bits (DESC_SIZE) kept, LOAD_STATE6 UBO descriptors and
     * indirect sources. The high dwords stay 0: every address is below 4 GiB on both sides. */
    uint32_t *w = plan.ib;
    for (unsigned i = 0; i < plan.dwords;) {
        uint32_t h = w[i];
        if (h >> 28 == 4) {
            uint32_t cnt = h & 0x7f, off = h >> 8 & 0x3ffff;
            for (uint32_t k = 0; k < cnt && i + 1 + k < plan.dwords; k++)
                if (address_register(off + k)) rebase_dword(&w[i + 1 + k], 3);
            i += 1 + cnt;
            continue;
        }
        uint32_t cnt = h & 0x3fff, op = h >> 16 & 0x7f;
        if (h >> 28 != 7 || i + 1 + cnt > plan.dwords) return -3;
        uint32_t *b = &w[i + 1];
        if (op == OP_CRB || op == OP_NCRB)
            for (uint32_t k = op == OP_NCRB ? 2 : 0; k + 1 < cnt; k += 2) {
                if (address_register(b[k])) rebase_dword(&b[k + 1], 3);
            }
        if ((op == OP_LOAD_GEOM || op == OP_LOAD_FRAG) && cnt >= 3) {
            uint32_t src = b[0] >> 16 & 3, type = b[0] >> 14 & 3, units = b[0] >> 22;
            if (src == A8XX_E_SS6_INDIRECT) rebase_dword(&b[1], 3);
            if (src == A8XX_E_SS6_DIRECT && type == A8XX_E_ST6_UBO)
                for (uint32_t u = 0; u < units && 3 + 2 * u < cnt; u++) rebase_dword(&b[3 + 2 * u], 0x3f);
        }
        i += 1 + cnt;
    }
    for (unsigned i = 0; i < plan.dwords; i++)
        plan.left_in_render_window += w[i] >= RENDER_LO && w[i] < RENDER_HI;
    return 0;
}

/* The CP's IB side. */
static int pkt4_ok(uint32_t h)
{
    uint32_t count = h & 0x7f, reg = h >> 8 & 0x3ffff;
    return h >> 28 == 4 && h == (0x40000000u | count | parity(count) << 7 | reg << 8 | parity(reg) << 27);
}
static void write_reg(uint32_t off, uint32_t v)
{
    if (off >= 0x40000) { violation("register %#x out of range", off); return; }
    cp.reg[off] = v;
    cp.set[off] = 1;
}
static uint64_t reg64(uint32_t off) { return cp.reg[off] | (uint64_t)cp.reg[off + 1] << 32; }
static const struct ref *ref_of(uint64_t va, uint64_t bytes)
{
    for (unsigned i = 0; i < cp.nrefs; i++)
        if (va >= cp.refs[i].va && bytes <= cp.refs[i].size && va - cp.refs[i].va <= cp.refs[i].size - bytes)
            return &cp.refs[i];
    return 0;
}
static int bytes_equal_through_cb0(uint64_t va, const uint8_t *want, size_t n)
{
    for (size_t i = 0; i < n; i += 4) {
        uint32_t v, w = 0;
        if (!gpu_rd32(va + i, &v)) return 0;
        memcpy(&w, want + i, n - i < 4 ? n - i : 4);
        if (n - i < 4) v &= (1u << 8 * (n - i)) - 1;
        if (v != w) return 0;
    }
    return 1;
}
static void load_state(uint32_t op, const uint32_t *b, uint32_t cnt)
{
    uint32_t type = b[0] >> 14 & 3, src = b[0] >> 16 & 3, block = b[0] >> 18 & 0xf, n = b[0] >> 22;
    unsigned stage = op == OP_LOAD_FRAG;
    if (src == A8XX_E_SS6_DIRECT && type == A8XX_E_ST6_UBO) {
        if (cnt != 3 + 2 * n) { violation("UBO state count"); return; }
        uint32_t first = b[0] & 0x3fff;                             /* DST_OFF */
        for (uint32_t u = 0; u < n; u++) {
            if (first + u >= 16) { violation("UBO index %u", first + u); return; }
            cp.ubo[stage][first + u].base = b[3 + 2 * u] | (uint64_t)(b[4 + 2 * u] & 0x1ffff) << 32;
            cp.ubo[stage][first + u].vec4 = b[4 + 2 * u] >> 17;
            if (first + u + 1 > cp.nubo[stage]) cp.nubo[stage] = first + u + 1;
        }
    } else if (src == A8XX_E_SS6_INDIRECT) {
        uint64_t va = b[1] | (uint64_t)b[2] << 32, bytes = (uint64_t)n * (type == A8XX_E_ST6_SHADER ? 16 : 64);
        for (uint64_t off = 0; off < bytes; off += 4) {
            uint32_t v;
            if (!gpu_rd32(va + off, &v)) { cp.stall = 1; return; }
        }
    } else {
        violation("CP_LOAD_STATE6 form %#x (block %u)", b[0], block);
    }
}
static void draw(const uint32_t *b, uint32_t cnt)
{
    cp.draws++;
    if (cnt != 3 || (b[0] & 0x3f) != A8XX_E_DI_PT_TRILIST) { violation("draw form %#x", b[0]); return; }
    /* verify_refs: both ends of every reference, as the SMMU walks them now. */
    for (unsigned i = 0; i < cp.nrefs; i++) {
        const struct ref *f = &cp.refs[i];
        for (unsigned end = 0; end < 2; end++) {
            uint64_t off = end ? f->size - 1 : 0, pa;
            if (!gpu_pa(f->va + off, f->write, &pa) || pa != f->pa + off) {
                violation("reference %s does not walk to its backing at +%#llx", f->what, (unsigned long long)off);
                return;
            }
        }
        cp.refs_walked++;
    }
    /* Every address the draw can reach through a register or a UBO descriptor lies inside a reference. */
    for (unsigned i = 0; i < sizeof a8xx_ib_regs / sizeof a8xx_ib_regs[0]; i++) {
        const struct a8xx_reg_info *g = &a8xx_ib_regs[i];
        if (!(g->flags & A8XX_REG_FLAG_ADDRESS)) continue;
        for (unsigned e = 0; e < g->count; e++) {
            uint32_t off = g->offset + e * g->stride;
            if (!cp.set[off]) continue;
            uint64_t va = reg64(off) & (g->offset == A8XX_REG_SP_GFX_BINDLESS_BASE_DESCRIPTOR ? ~3ull : ~0ull);
            if (!va) continue;
            cp.address_registers++;
            const struct ref *f = ref_of(va, 1);
            if (!f) { violation("%s[%u] = %#llx outside every reference", g->name, e, (unsigned long long)va); return; }
            if ((g->flags & A8XX_REG_FLAG_WADDRESS) && !f->write) { violation("%s is written but read-only", g->name); return; }
        }
    }
    for (unsigned st = 0; st < 2; st++)
        for (unsigned u = 0; u < cp.nubo[st]; u++) {
            if (!cp.ubo[st][u].base) continue;
            cp.ubo_descriptors++;
            if (!ref_of(cp.ubo[st][u].base, 16ull * cp.ubo[st][u].vec4)) {
                violation("UBO %u of stage %u outside every reference", u, st);
                return;
            }
        }
    /* The code the SP fetches is the code that was uploaded. */
    if (cp.vs_code && (!bytes_equal_through_cb0(reg64(A8XX_REG_SP_VS_BASE), cp.vs_code, cp.vs_bytes) ||
                       !bytes_equal_through_cb0(reg64(A8XX_REG_SP_PS_BASE), cp.fs_code, cp.fs_bytes))) {
        violation("SP_VS_BASE / SP_PS_BASE do not hold the uploaded code");
        return;
    }
    cp.code_checked += cp.vs_code != 0;
    /* The model's stand-in for pixels: the window scissor, through CB0 and the colour cache. */
    uint32_t tl = cp.reg[A8XX_REG_GRAS_SC_WINDOW_SCISSOR_TL], br = cp.reg[A8XX_REG_GRAS_SC_WINDOW_SCISSOR_BR];
    uint64_t base = reg64(A8XX_REG_RB_MRT_BASE), pitch = (uint64_t)cp.reg[A8XX_REG_RB_MRT_PITCH] << 6;
    for (uint32_t y = tl >> 16 & 0x3fff; y <= (br >> 16 & 0x3fff); y++)
        for (uint32_t x = tl & 0x3fff; x <= (br & 0x3fff); x++) {
            uint64_t pa;
            if (!gpu_pa(base + y * pitch + 4 * x, 1, &pa)) { cp.stall = 1; return; }
            if (nccu == sizeof ccu / sizeof ccu[0]) { violation("colour cache overflow"); return; }
            ccu[nccu].pa = pa;
            ccu[nccu++].v = PAINT;
            cp.painted++;
        }
}
static void ib_packet(uint32_t op, const uint32_t *b, uint32_t cnt)
{
    switch (op) {
    case OP_CRB:
        for (uint32_t k = 0; k + 1 < cnt; k += 2) write_reg(b[k], b[k + 1]);
        break;
    case OP_NCRB:
        if (cnt < 2 || b[0] != 1 || b[1]) { violation("CP_NON_CONTEXT_REG_BUNCH without its 1, 0"); return; }
        for (uint32_t k = 2; k + 1 < cnt; k += 2) write_reg(b[k], b[k + 1]);
        break;
    case OP_EVENT7: event(b, cnt, 1); break;
    case OP_SET_MARKER: case OP_SET_MODE: case OP_WFI: case OP_CCHE_INVALIDATE: case OP_SKIP_IB2_GLOBAL:
    case OP_SKIP_IB2_LOCAL: case OP_VIS_OVERRIDE: case OP_NOP:
        break;
    case OP_THREAD: cp.thread = cnt ? b[0] & 3 : cp.thread; break;
    case OP_SET_DRAW_STATE:
        if (cnt != 3 || !(b[0] & A8XX_PKT_CP_SET_DRAW_STATE__0__DISABLE_ALL_GROUPS(1))) violation("draw-state groups");
        break;
    case OP_LOAD_GEOM: case OP_LOAD_FRAG: load_state(op, b, cnt); break;
    case OP_DRAW: draw(b, cnt); break;
    case OP_WAIT_TS: wait_ts(b, cnt); break;
    case OP_MEM_WRITE:
        for (uint32_t i = 2; i < cnt; i++)
            if (!gpu_wr32((b[0] | (uint64_t)b[1] << 32) + 4ull * (i - 2), b[i])) { cp.stall = 1; return; }
        break;
    default:
#ifdef ADRENO_RING_IB_HOOK
        if (ib_extra_op(op, b, cnt)) break;        /* the includer models more IB packets (CP_MEMCPY) */
#endif
        violation("opcode %#x in an IB is not modeled", op);
    }
}
static void run_ib(uint64_t va, uint32_t dwords)
{
    cp.ibs++;
    cp.int0 |= cp.int0_in_ib;
    cp.cp_global |= cp.cp_global_in_ib;
    if (cp.fault_in_ib) { r.fsr |= 2; cp.stall = 1; return; }
    uint32_t *w = malloc(4ull * dwords + 4);
    for (uint32_t i = 0; i < dwords; i++)
        if (!gpu_rd32(va + 4ull * i, &w[i])) { cp.stall = 1; free(w); return; }
    for (uint32_t i = 0; i < dwords && !cp.stall;) {
        uint32_t h = w[i];
        if (h >> 28 == 4) {
            uint32_t cnt = h & 0x7f, off = h >> 8 & 0x3ffff;
            if (!pkt4_ok(h) || i + 1 + cnt > dwords) { violation("bad PKT4 %#x in the IB at %u", h, i); break; }
            for (uint32_t k = 0; k < cnt; k++) write_reg(off + k, w[i + 1 + k]);
            i += 1 + cnt;
            continue;
        }
        uint32_t cnt = h & 0x3fff;
        if (!pkt7_ok(h) || i + 1 + cnt > dwords) { violation("bad packet %#x in the IB at %u", h, i); break; }
        ib_packet(h >> 16 & 0x7f, &w[i + 1], cnt);
        i += 1 + cnt;
    }
    free(w);
}

/* A fresh S2 world: the fixture, the arena zero page, the code buffer, the target (guards included) and a
 * package written by the "kext" through its cacheable view (dirty lines; only the monitor cleans them). */
static void ib_setup(uint64_t wptr)
{
    ring_setup(wptr);
    map(ZERO_VA, ZERO_PA, 0x4000, 1);
    map(PKG_VA, PKG_PA, 0x4000, 1);
    map(CODE_VA, CODE_PA, 0x4000, 0);
    map(RT_VA, RT_PA, 0xc000, 0);
    memcpy(dram + ram_offset(CODE_PA, plan.vs_bytes), plan.vs, plan.vs_bytes);
    memcpy(dram + ram_offset(CODE_PA + 0x1000, plan.fs_bytes), plan.fs, plan.fs_bytes);
    memcpy(dram + ram_offset(RT_PA, plan.rt_bytes), plan.rt, plan.rt_bytes);
    memcpy(cp.refs, plan.refs, sizeof plan.refs);
    cp.nrefs = plan.nrefs;
    cp.vs_code = plan.vs; cp.vs_bytes = plan.vs_bytes;
    cp.fs_code = plan.fs; cp.fs_bytes = plan.fs_bytes;
    nlog = 0;
}
static void put_package(uint64_t pa, const uint32_t *words, unsigned dwords, uint64_t bytes)
{
    for (uint64_t off = 0; off < bytes; off += 4) m_wr(0, pa + off, off / 4 < dwords ? words[off / 4] : 0);
}
static int ib(uint64_t va, uint64_t dwords, uint64_t bytes)
{
    uint64_t regs[4] = {ADRENO_GUEST_IB, va, dwords, bytes};
    uint64_t submits = S.ib_submits;
    int e = adreno_guest_ib(&ring_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[3] == S.wptr);
    CHECK(regs[1] == (e ? 0 : (ADRENO_IB_MARKER_BASE ^ (uint32_t)S.ib_submits)) && (e || S.ib_submits == submits + 1));
    return e;
}
static void save(const char *name, const void *data, size_t bytes)
{
    const char *dir = getenv("SNAP_RING_ARTIFACT_DIR");
    if (!dir) return;
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    CHECK(f != 0);
    if (!f) return;
    CHECK(fwrite(data, 1, bytes, f) == bytes);
    CHECK(fclose(f) == 0);
}

/* --- S2: draw-plan-v2's IB through ADRENO_GUEST_IB ---------------------------------------------------------- */
static void test_s2_draw_plan(void)
{
    CHECK(plan.dwords == 1005 && plan.nrefs == 7);
    CHECK(plan.rebased == 12 && plan.left_in_render_window == 0);   /* every address field, nothing else */
    ib_setup(22);
    uint64_t bytes = ADRENO_IB_ALIGN_UP(4ull * plan.dwords);
    put_package(PKG_PA, plan.ib, plan.dwords, bytes);
    CHECK(dev_rd32(PKG_PA) == 0 && m_rd(0, PKG_PA) == plan.ib[0]);  /* the package is only in the CPU cache */
    unsigned walks = 0;
    CHECK(ib(PKG_VA, plan.dwords, bytes) == 0);
    uint32_t marker = ADRENO_IB_MARKER_BASE ^ 1u;
    CHECK(cp.violations == 0 && !r.fsr && cp.ibs == 1 && cp.draws == 1);
    CHECK(cp.refs_walked == 7 && cp.address_registers == 11 && cp.ubo_descriptors == 1 && cp.code_checked == 1);
    CHECK(dev_rd32(MEMPTRS + 0x80) == marker && dev_rd32(MEMPTRS + 0xc0) == marker);    /* BR and BV fences */
    CHECK(dev_rd32(MEMPTRS + 0x60) == 0x534e7001);                  /* the IB's own last packet ran */
    CHECK(S.wptr == 22 + ADRENO_IB_RING_WORDS && r.rptr == S.wptr && S.ib_submits == 1);
    CHECK(S.ib_dwords == 1005 && S.ib_errors == 0);
    /* The monitor cleaned the package: the CP fetched it from DRAM. */
    CHECK(dev_rd32(PKG_PA) == plan.ib[0] && dev_rd32(PKG_PA + 4 * 1004) == plan.ib[1004]);
    /* The ring words (the oracle comparison with q1n1's ring_words is tools/qualify-adreno-ring-ib.py's). */
    uint32_t words[ADRENO_IB_RING_WORDS];
    for (unsigned i = 0; i < ADRENO_IB_RING_WORDS; i++) words[i] = ring_word(22 + i);
    CHECK(words[4] == pkt7(OP_IB, 3) && words[5] == PKG_VA && words[6] == 0 && words[7] == 1005);
    CHECK(words[16] == pkt7(OP_EVENT7, 4) && words[18] == 0x102000c0 && words[20] == marker);
    CHECK(words[23] == pkt7(OP_WAIT_TS, 4) && words[25] == 0x102000c0 && words[27] == marker);
    CHECK(words[28] == pkt7(OP_EVENT7, 4) && words[30] == 0x10200080 && words[32] == marker);
    /* The target: the scissor painted, every other byte (row padding, guards) as seeded. */
    unsigned painted_wrong = 0, other_wrong = 0;
    for (uint64_t off = 0; off < plan.rt_bytes; off += 4) {
        uint64_t image = off >= 0x1000 ? off - 0x1000 : ~0ull;
        int inside = image != ~0ull && image / 1024 < 23 && image % 1024 < 37 * 4;
        uint32_t seed;
        memcpy(&seed, plan.rt + off, 4);
        if (inside) painted_wrong += dev_rd32(RT_PA + off) != PAINT;
        else other_wrong += dev_rd32(RT_PA + off) != seed;
    }
    CHECK(cp.painted == 37 * 23 && painted_wrong == 0 && other_wrong == 0 && nccu == 0);
    walks = cp.refs_walked;
    save("ib-ring-words.bin", words, sizeof words);
    save("ib-rebased.bin", plan.ib, 4ull * plan.dwords);
    uint8_t *rt = malloc(plan.rt_bytes);
    memcpy(rt, dram + ram_offset(RT_PA, plan.rt_bytes), plan.rt_bytes);
    save("rt-readback.bin", rt, plan.rt_bytes);
    free(rt);
    char report[4096];
    int n = snprintf(report, sizeof report,
        "{\"ib_va\": %lu, \"ib_dwords\": %u, \"package_bytes\": %llu, \"br_va\": %u, \"bv_va\": %u, "
        "\"marker\": %u, \"br\": %u, \"bv\": %u, \"ib_fence\": %u, \"wptr_before\": 22, \"wptr_after\": %llu, "
        "\"refs_walked\": %u, \"address_registers\": %u, \"ubo_descriptors\": %u, \"painted\": %u, "
        "\"violations\": %u, \"rebased\": %u, \"windows\": {\"r_misc\": [%lu, %lu], \"r_code\": [%lu, %lu], "
        "\"r_rt\": [%lu, %lu]}}\n",
        PKG_VA, plan.dwords, (unsigned long long)bytes, 0x10200080u, 0x102000c0u, marker,
        dev_rd32(MEMPTRS + 0x80), dev_rd32(MEMPTRS + 0xc0), dev_rd32(MEMPTRS + 0x60),
        (unsigned long long)S.wptr, walks, cp.address_registers, cp.ubo_descriptors, cp.painted, cp.violations,
        plan.rebased, 0x120a0000UL, ZERO_VA, 0x120b0000UL, CODE_VA, 0x122a0000UL, RT_VA);
    CHECK(n > 0 && (size_t)n < sizeof report);
    save("ib-walk.json", report, (size_t)n);
    /* A second submission of the same package: a new marker, the ring moves on. */
    CHECK(ib(PKG_VA, plan.dwords, bytes) == 0 && dev_rd32(MEMPTRS + 0x80) == (ADRENO_IB_MARKER_BASE ^ 2u));
    CHECK(cp.draws == 2 && cp.violations == 0 && S.wptr == 22 + 2 * ADRENO_IB_RING_WORDS);
}

/* The kext's start probe IB (design 3.6): one pkt7(CP_NOP, 0), a 64-byte package. */
static const uint32_t NOP_IB[1] = {0x70108000u};
static void test_s2_probe_and_wrap(void)
{
    CHECK(NOP_IB[0] == pkt7(OP_NOP, 0));
    ib_setup(22);
    put_package(PKG_PA, NOP_IB, 1, 64);
    CHECK(ib(PKG_VA, 1, 64) == 0 && cp.ibs == 1 && cp.violations == 0);
    /* The ring boundary: 35 words at w = 8190 pad two dwords and run at 0 with one doorbell. */
    ib_setup(8190);
    put_package(PKG_PA, NOP_IB, 1, 64);
    CHECK(ib(PKG_VA, 1, 64) == 0 && S.wptr == ADRENO_IB_RING_WORDS && cp.nwptr == 1 && S.ring_wraps == 1);
    CHECK(ring_word(8190) == pkt7(OP_NOP, 1) && ring_word(0) == pkt7(OP_THREAD, 1) && cp.violations == 0);
    /* Every user of the ring, mixed, for more than four ring capacities: 600 IBs (every 40th the draw),
     * 1,200 fences and 12 maximum fills. */
    ib_setup(22);
    uint64_t draw_bytes = ADRENO_IB_ALIGN_UP(4ull * plan.dwords);
    unsigned bad = 0, draws = 0, fills = 0;
    for (unsigned i = 0; i < 600; i++) {
        int drawn = i % 40 == 39;
        put_package(PKG_PA, drawn ? plan.ib : NOP_IB, drawn ? plan.dwords : 1, drawn ? draw_bytes : 64);
        if (drawn) memcpy(dram + ram_offset(RT_PA, plan.rt_bytes), plan.rt, plan.rt_bytes);
        bad += ib(PKG_VA, drawn ? plan.dwords : 1, drawn ? draw_bytes : 64) != 0;
        draws += drawn;
        bad += fence(FENCE_VA + 0x200, 0x77000000u + i) || dev_rd32(FENCE_PA + 0x200) != 0x77000000u + i;
        bad += fence(FENCE_VA + 0x300, 0x78000000u + i) || dev_rd32(FENCE_PA + 0x300) != 0x78000000u + i;
        if (i % 50 == 25) {
            bad += fill(FILL_B_VA, 0x4000, 0x99000000u + i) || words_not(FILL_B_PA, 0x4000, 0x99000000u + i);
            fills++;
        }
    }
    uint64_t ring_dwords_used = 600ull * ADRENO_IB_RING_WORDS + 1200ull * 4 + fills * 4103ull;
    printf("RING_S2_MIX ibs=%u draws=%u fences=1200 fills=%u ring_dwords=%llu wraps=%u violations=%u bad=%u\n",
           cp.ibs, cp.draws, fills, (unsigned long long)ring_dwords_used, cp.wraps, cp.violations, bad);
    CHECK(bad == 0 && cp.violations == 0 && cp.ibs == 600 && cp.draws == draws && draws == 15);
    CHECK(ring_dwords_used > 4 * 8192ull && cp.wraps >= 4 && S.ring_wraps == cp.wraps);
    CHECK(S.ib_submits == 600 && S.ib_errors == 0 && S.ib_dwords == 585 + 15ull * 1005);
}

/* A maximum package: 2 MiB across 129 pages, the IB 0x40000 dwords of CP_NOPs. */
static void test_s2_max_package(void)
{
    ib_setup(22);
    uint64_t va = BIG_VA + 0x40, pa = BIG_PA + 0x40;
    map(BIG_VA, BIG_PA, 129 * 0x4000ull, 1);
    uint32_t *nops = malloc(4ull * ADRENO_IB_MAX_DWORDS);
    for (unsigned i = 0; i < ADRENO_IB_MAX_DWORDS; i += 0x4000) {
        nops[i] = pkt7(OP_NOP, 0x3fff);
        for (unsigned k = 1; k < 0x4000; k++) nops[i + k] = 0xdead0000u + k;
    }
    put_package(pa, nops, ADRENO_IB_MAX_DWORDS, ADRENO_IB_MAX_PACKAGE);
    CHECK(ib(va, ADRENO_IB_MAX_DWORDS, ADRENO_IB_MAX_PACKAGE) == 0 && cp.ibs == 1 && cp.violations == 0);
    CHECK(dev_rd32(pa + 4ull * (ADRENO_IB_MAX_DWORDS - 1)) == nops[ADRENO_IB_MAX_DWORDS - 1]);
    free(nops);
}

/* --- S2: refusals before any doorbell: nothing written, cleaned or rung, nothing latched ------------------- */
enum { K_REQUEST, K_RING_FLAG, K_QUIESCED, K_HIJACKED, K_DETACHED, K_SLOTS, K_NO_LEAF_FN, K_NO_CLEAN,
       K_DWORDS0, K_DWORDS_MAX, K_MISALIGNED, K_ALIGN32, K_BYTES_ODD, K_BYTES_SHORT, K_BYTES_MAX, K_BELOW, K_PAST_END,
       K_OVERFLOW, K_WRITABLE, K_NOREAD, K_UNMAPPED, K_MIDDLE_PAGE, K_LEAF_SHORT, K_LEAF_BEGIN, K_OUTSIDE_RAM,
       K_ARENA, K_SLOT_RW, K_SLOT_ZERO, K_CX, K_GX, K_HALT, K_TTBR, K_TCR, K_FSR, K_SGFSR, K_SQE, K_RPTR, K_BUFSZ,
       K_BUSY, K_STICKY_INT0, K_CP_FAULT, K_COUNT };
static const int K_EXPECT[K_COUNT] = {
    [K_REQUEST] = ADRENO_E_PARAMS, [K_RING_FLAG] = ADRENO_E_PARAMS, [K_QUIESCED] = ADRENO_E_PARAMS,
    [K_HIJACKED] = ADRENO_E_PARAMS, [K_DETACHED] = ADRENO_E_PARAMS, [K_SLOTS] = ADRENO_E_PARAMS,
    [K_NO_LEAF_FN] = ADRENO_E_PARAMS, [K_NO_CLEAN] = ADRENO_E_PARAMS,
    [K_DWORDS0] = ADRENO_E_WINDOW, [K_DWORDS_MAX] = ADRENO_E_WINDOW, [K_MISALIGNED] = ADRENO_E_WINDOW,
    [K_ALIGN32] = ADRENO_E_WINDOW, [K_BYTES_ODD] = ADRENO_E_WINDOW, [K_BYTES_SHORT] = ADRENO_E_WINDOW,
    [K_BYTES_MAX] = ADRENO_E_WINDOW, [K_BELOW] = ADRENO_E_WINDOW, [K_PAST_END] = ADRENO_E_WINDOW,
    [K_OVERFLOW] = ADRENO_E_WINDOW,
    [K_WRITABLE] = ADRENO_E_TARGET, [K_NOREAD] = ADRENO_E_TARGET, [K_UNMAPPED] = ADRENO_E_TARGET,
    [K_MIDDLE_PAGE] = ADRENO_E_TARGET, [K_LEAF_SHORT] = ADRENO_E_TARGET, [K_LEAF_BEGIN] = ADRENO_E_TARGET,
    [K_OUTSIDE_RAM] = ADRENO_E_TARGET, [K_ARENA] = ADRENO_E_TARGET, [K_SLOT_RW] = ADRENO_E_TARGET,
    [K_SLOT_ZERO] = ADRENO_E_TARGET,
    [K_CX] = ADRENO_E_CX, [K_GX] = ADRENO_E_GX, [K_HALT] = ADRENO_E_HALT, [K_TTBR] = ADRENO_E_CB0,
    [K_TCR] = ADRENO_E_CB0, [K_FSR] = ADRENO_E_FAULT, [K_SGFSR] = ADRENO_E_FAULT, [K_SQE] = ADRENO_E_SQE,
    [K_RPTR] = ADRENO_E_RING, [K_BUFSZ] = ADRENO_E_RING,
    [K_BUSY] = ADRENO_IB_E_BUSY, [K_STICKY_INT0] = ADRENO_IB_E_STICKY, [K_CP_FAULT] = ADRENO_IB_E_STICKY};
static void test_s2_refusals(void)
{
    unsigned refused_right = 0;
    for (unsigned k = 0; k < K_COUNT; k++) {
        ib_setup(22);
        /* Three pages of package (the middle-page case needs them): 0x40104000.. read-only. */
        map(PKG_VA, PKG_PA, 0xc000, 1);
        put_package(PKG_PA, plan.ib, plan.dwords, 0xc000);
        uint64_t regs[4] = {ADRENO_GUEST_IB, PKG_VA, plan.dwords, ADRENO_IB_ALIGN_UP(4ull * plan.dwords)};
        uint64_t (*leaf)(void *, uint64_t) = dart_leaf;
        struct adreno_params saved = P;
        uint64_t slot = P.pool_pa + ADRENO_L3_OFFSET + ((PKG_VA - ADRENO_WINDOW_BASE) >> 12) * 8;
        switch (k) {
        case K_REQUEST: regs[0] = ADRENO_GUEST_IB + 1; break;
        case K_RING_FLAG: P.flags |= ADRENO_F_RING; break;
        case K_QUIESCED: S.status |= ADRENO_S_QUIESCED; break;
        case K_HIJACKED: S.status |= ADRENO_S_HIJACKED; break;
        case K_DETACHED: S.status &= ~(uint64_t)ADRENO_S_ATTACHED; break;
        case K_SLOTS: P.fence_pa += 0x40; P.fence_va += 0x40; break;
        case K_NO_LEAF_FN: leaf = 0; break;
        case K_NO_CLEAN: ring_ops.clean = 0; break;
        case K_DWORDS0: regs[2] = 0; break;
        case K_DWORDS_MAX: regs[2] = ADRENO_IB_MAX_DWORDS + 1; regs[3] = ADRENO_IB_MAX_PACKAGE; break;
        case K_MISALIGNED: regs[1] += 4; break;
        case K_ALIGN32: regs[1] += 32; break;
        case K_BYTES_ODD: regs[3] += 4; break;
        case K_BYTES_SHORT: regs[3] = ADRENO_IB_ALIGN_UP(4ull * plan.dwords) - 64; break;
        case K_BYTES_MAX: regs[3] = ADRENO_IB_MAX_PACKAGE + 64; break;
        case K_BELOW: regs[1] = ADRENO_WINDOW_BASE - 0x1000; break;
        case K_PAST_END: regs[1] = ADRENO_WINDOW_END - 0x40; break;
        case K_OVERFLOW: regs[1] = ~0x3fULL; break;
        case K_WRITABLE: dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] &= ~4ull; break;   /* GPU-writable page */
        case K_NOREAD: dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] |= 8; break;
        case K_UNMAPPED: dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] = 0; break;
        case K_MIDDLE_PAGE: regs[3] = 0xc000; dart[(PKG_VA + 0x4000 - ADRENO_WINDOW_BASE) >> 14] = 0; break;
        case K_LEAF_SHORT: dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] = dart_desc(PKG_PA, 0, 0xf00, 1, 0); break;
        case K_LEAF_BEGIN: dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] = dart_desc(PKG_PA, 0x40, 0x4000, 1, 0); break;
        case K_OUTSIDE_RAM: dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] = dart_desc(MEM_HIGH, 0, 0x4000, 1, 0); break;
        case K_ARENA: dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] = dart_desc(ARENA + 0x800000, 0, 0x4000, 1, 0); break;
        case K_SLOT_RW: m_wr64(0, slot, PKG_PA | ADRENO_PTE_LEAF); break;       /* mirror lost RDONLY */
        case K_SLOT_ZERO: m_wr64(0, slot, 0); break;
        case K_CX: r.cx = 0; break;
        case K_GX: r.pwr = 1; break;
        case K_HALT: r.halt_ack = 1; break;
        case K_TTBR: r.ttbr_lo ^= 0x1000; break;
        case K_TCR: r.tcr ^= 1; break;
        case K_FSR: r.fsr = 2; break;
        case K_SGFSR: r.gfsr = 2; break;
        case K_SQE: r.sqe = 0; break;
        case K_RPTR: r.rptr--; break;
        case K_BUFSZ: cp.rb_cntl = 11 | 2 << 8; break;
        case K_BUSY: cp.rbbm_status = 1u << 1; break;
        case K_STICKY_INT0: cp.int0 = 1u << 9; break;                 /* CP_HW_ERROR */
        case K_CP_FAULT: cp.cp_global = 1u << 16; break;              /* SWFAULT BR */
        }
        unsigned writes = nlog, cleans_before = cleans;
        uint64_t wptr = S.wptr;
        int e = adreno_guest_ib(&ring_ops, &P, &S, regs, leaf, 0, MEM_LOW, MEM_HIGH);
        int ok = e == K_EXPECT[k] && (int64_t)regs[0] == e && regs[1] == 0 && regs[3] == S.wptr &&
                 nlog == writes && cleans == cleans_before && S.wptr == wptr && r.wptr == wptr &&
                 !cp.doorbells && !cp.ibs && S.ib_submits == 0 && dev_rd32(PKG_PA) == 0 &&
                 dev_rd32(MEMPTRS + 0x80) == 0 && r.mmio_reads_cx_off == 0;
        if (!ok) printf("FAIL refusal case %u: got %d want %d (writes %u, cleans %u)\n", k, e, K_EXPECT[k],
                        nlog - writes, cleans - cleans_before);
        CHECK(ok);
        refused_right += ok;
        P = saved;
    }
    printf("RING_S2_REFUSALS %u/%u\n", refused_right, (unsigned)K_COUNT);
    /* Not refusals: the CPU's own register access (CP_AHB_BUSY_CX_MASTER) and a non-error interrupt bit. */
    ib_setup(22);
    put_package(PKG_PA, NOP_IB, 1, 64);
    cp.rbbm_status = 1;
    cp.int0 = 1u << 20;                                                  /* CP_CACHE_FLUSH_TS */
    CHECK(ib(PKG_VA, 1, 64) == 0);
    /* An old monitor routes 0x00010005 to the fence handler, which refuses it (the ADT gate suffices). */
    ib_setup(22);
    uint64_t old[4] = {ADRENO_GUEST_IB, PKG_VA, 1, 64};
    CHECK(adreno_guest_fence(&ring_ops, &P, &S, old, dart_leaf, 0, MEM_LOW, MEM_HIGH) == ADRENO_E_PARAMS);
}

/* --- S2: after the doorbell ----------------------------------------------------------------------------------- */
static void test_s2_after_doorbell(void)
{
    uint64_t bytes = ADRENO_IB_ALIGN_UP(4ull * plan.dwords);
    /* WRITEDROPPED once: retried. Twice: UNCERTAIN, WPTR kept, the attempt counted (its marker is spent). */
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64); r.drop_writes = 1;
    CHECK(ib(PKG_VA, 1, 64) == 0);
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64); r.drop_writes = 2;
    CHECK(ib(PKG_VA, 1, 64) == ADRENO_IB_E_UNCERTAIN && S.wptr == 22 && S.ib_submits == 1 && S.ib_errors == 1);
    CHECK(ib(PKG_VA, 1, 64) == 0 && dev_rd32(MEMPTRS + 0x80) == (ADRENO_IB_MARKER_BASE ^ 2u));
    /* The attempt count that would make the marker 0 (x1 == 0 reads as failure to the kext) is skipped. */
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64);
    S.ib_submits = ADRENO_IB_MARKER_BASE - 1;
    uint64_t skip[4] = {ADRENO_GUEST_IB, PKG_VA, 1, 64};
    CHECK(adreno_guest_ib(&ring_ops, &P, &S, skip, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0 && skip[1] == 1);
    CHECK(S.ib_submits == ADRENO_IB_MARKER_BASE + 1 && dev_rd32(MEMPTRS + 0x80) == 1 && dev_rd32(MEMPTRS + 0xc0) == 1);
    /* The CP makes no progress: UNCERTAIN after the hz / 10 budget. */
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64); cp.halt = 1;
    uint64_t regs[4] = {ADRENO_GUEST_IB, PKG_VA, 1, 64};
    CHECK(adreno_guest_ib(&ring_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == ADRENO_IB_E_UNCERTAIN);
    CHECK(regs[2] > ring_ops.hz / ADRENO_IB_POLL_DIVISOR && regs[1] == 0 && S.wptr == 22 + ADRENO_IB_RING_WORDS);
    /* A CB0 fault while the IB runs: UNCERTAIN at once. */
    ib_setup(22); put_package(PKG_PA, plan.ib, plan.dwords, bytes); cp.fault_in_ib = 1;
    CHECK(ib(PKG_VA, plan.dwords, bytes) == ADRENO_IB_E_UNCERTAIN && r.fsr);
    /* The BV fence never lands: BR waits in CP_WAIT_TIMESTAMP, RPTR never reaches WPTR. */
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64); cp.drop_bv_fence = 1;
    CHECK(ib(PKG_VA, 1, 64) == ADRENO_IB_E_UNCERTAIN && dev_rd32(MEMPTRS + 0x80) != (ADRENO_IB_MARKER_BASE ^ 1u));
    CHECK(r.rptr != S.wptr && cp.stall);
    /* A forged completion: the IB writes this submission's marker into both slots, then stalls. Neither
     * value is accepted: RPTR never reaches WPTR. */
    ib_setup(22);
    uint32_t forge_marker = ADRENO_IB_MARKER_BASE ^ 1u;
    const uint32_t forge[] = {
        pkt7(OP_EVENT7, 4), EV_CACHE_CLEAN | 1u << 27, 0x10200080, 0, forge_marker,
        pkt7(OP_EVENT7, 4), EV_CACHE_CLEAN | 1u << 27, 0x102000c0, 0, forge_marker,
        pkt7(OP_WAIT_TS, 4), 0, 0x10200100, 0, 0x7fffffff};
    put_package(PKG_PA, forge, 15, 64);
    CHECK(ib(PKG_VA, 15, 64) == ADRENO_IB_E_UNCERTAIN);
    CHECK(dev_rd32(MEMPTRS + 0x80) == forge_marker && dev_rd32(MEMPTRS + 0xc0) == forge_marker && cp.stall);
    /* RBBM busy after the fences: accepted only once idle ... */
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64); cp.busy_after_doorbell = 40;
    regs[0] = ADRENO_GUEST_IB; regs[1] = PKG_VA; regs[2] = 1; regs[3] = 64;
    CHECK(adreno_guest_ib(&ring_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0 && cp.busy_polls == 0);
    CHECK(regs[2] >= 40 * 50);                                          /* 40 busy polls, 50 ticks per clock */
    /* ... and never, if it never is. */
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64);
    cp.busy_after_doorbell = 1u << 30;
    CHECK(ib(PKG_VA, 1, 64) == ADRENO_IB_E_UNCERTAIN && dev_rd32(MEMPTRS + 0x80) == (ADRENO_IB_MARKER_BASE ^ 1u));
    /* Retired, idle, but the IB raised an error: GPU_ERROR (the ring is consistent, the output is not). */
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64); cp.int0_in_ib = 1u << 24;          /* UCHE_OOB_ACCESS */
    CHECK(ib(PKG_VA, 1, 64) == ADRENO_IB_E_GPU_ERROR && r.rptr == S.wptr && S.ib_errors == 1);
    ib_setup(22); put_package(PKG_PA, NOP_IB, 1, 64); cp.cp_global_in_ib = 1u << 1;     /* HWFAULT BV */
    CHECK(ib(PKG_VA, 1, 64) == ADRENO_IB_E_GPU_ERROR);
    /* The monitor's package clean is what the CP fetches: without it the CP reads zeros and halts. */
    ib_setup(22); put_package(PKG_PA, plan.ib, plan.dwords, bytes);
    cp.skip_clean_lo = PKG_PA; cp.skip_clean_hi = PKG_PA + 0x4000;
    CHECK(ib(PKG_VA, plan.dwords, bytes) == ADRENO_IB_E_UNCERTAIN && cp.skipped_cleans == 1 && cp.violations == 1);
    /* A read-only package cannot be written by the IB it carries (the SMMU refuses; UNCERTAIN). */
    ib_setup(22);
    const uint32_t self[] = {pkt7(OP_MEM_WRITE, 3), (uint32_t)PKG_VA, 0, 0x12345678};
    put_package(PKG_PA, self, 4, 64);
    CHECK(ib(PKG_VA, 4, 64) == ADRENO_IB_E_UNCERTAIN && (r.fsr & 8) && dev_rd32(PKG_PA) == self[0]);
}
#endif

#if SNAP_ADRENO_IB_ASYNC && !defined(ADRENO_RING_TEST_PRE_CHANGE)
/* --- S3: asynchronous completion, ADRENO_GUEST_IB_START / _POLL (SNAP_ADRENO_IB_ASYNC) ---------------------------
 * The monitor's own entry points (adreno_guest_ib_start/_poll, adreno_ib_flight_refuse/_tick/_drain, in the order
 * probes/xnuboot.c calls them) against the same CP, now with execution time (cp.latency: the work a doorbell
 * publishes runs once the model clock is that many ticks later; hz is 1 MHz, a tick is a microsecond). The
 * failure modes and their guards are agents/async-ib/FAILURE-MODES.md (A-numbers below). Plan-free: NOP and
 * CP_MEM_WRITE IBs only, so S3 runs without the draw-plan fixture. */
static struct adreno_ib_flight F;
#define WORK_VA RT_VA                            /* a GPU-writable page the work IB writes */
#define WORK_PA RT_PA
#define BUDGET (ring_ops.hz / ADRENO_IB_POLL_DIVISOR)
#define GRACE (ADRENO_IB_FLIGHT_GRACE_SECONDS * ring_ops.hz)
static void s3_setup(uint64_t wptr, uint64_t latency)
{
    ring_setup(wptr);
    map(PKG_VA, PKG_PA, 0xc000, 1);
    map(WORK_VA, WORK_PA, 0x4000, 0);
    memset(&F, 0, sizeof F);
    cp.latency = latency;
    nlog = 0;
}
/* The work IB: one CP_MEM_WRITE of `value` into the work page. */
static void s3_package(uint32_t value)
{
    const uint32_t w[4] = {pkt7(OP_MEM_WRITE, 3), (uint32_t)WORK_VA, 0, value};
    put_package(PKG_PA, w, 4, 64);
}
/* probes/xnuboot.c's dispatch for one request: the in-flight admission first, then the call. */
static int s3_native_unmap(void *ctx, uint64_t iova, uint64_t size)
{
    (void)ctx;
    for (uint64_t at = iova; at < iova + size; at += 0x4000) dart[(at - ADRENO_WINDOW_BASE) >> 14] = 0;
    return 0;
}
static int s3_call(uint64_t x[4])
{
    int e = adreno_ib_flight_refuse(&S, &F, x);
    if (e) return e;
    switch (x[0]) {
    case ADRENO_GUEST_IB_START:
        return adreno_guest_ib_start(&ring_ops, &P, &S, &F, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    case ADRENO_GUEST_IB: return adreno_guest_ib(&ring_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    case ADRENO_GUEST_FILL32: return adreno_guest_fill32(&ring_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    case ADRENO_GUEST_UNMAP:
        return adreno_guest_unmap(&ring_ops, &P, &S, x, dart_leaf, s3_native_unmap, 0, MEM_LOW, MEM_HIGH);
    }
    return adreno_guest_fence(&ring_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
}
static int s3_start(uint64_t x[4])
{
    x[0] = ADRENO_GUEST_IB_START; x[1] = PKG_VA; x[2] = 4; x[3] = 64;
    return s3_call(x);
}
static int s3_poll(const struct adreno_ops *o, uint64_t marker, uint64_t x[4])
{
    x[0] = ADRENO_GUEST_IB_POLL; x[1] = marker; x[2] = x[3] = 0;
    return adreno_guest_ib_poll(o, &P, &S, &F, x);
}
/* The guest polls with the kext's backoff until a final status; *polls counts the PENDING answers. */
static int s3_poll_until_final(const struct adreno_ops *o, uint64_t marker, uint64_t x[4], unsigned *polls,
                               uint64_t *max_pending_ticks)
{
    uint64_t delay = 10;
    int e;
    *polls = 0;
    while ((e = s3_poll(o, marker, x)) == ADRENO_IB_PENDING) {
        CHECK(x[1] == marker && x[3] == S.wptr);
        if (max_pending_ticks && x[2] > *max_pending_ticks) *max_pending_ticks = x[2];
        if (++*polls > 100000) break;
        clock_now += delay;
        delay = delay * 2 > 200 ? 200 : delay * 2;
    }
    return e;
}
/* probes/xnuboot.c gpu_tick's order: the flight first, then (only without one) the CB0 fault poll. */
static int s3_tick(void)
{
    int final;
    if (adreno_ib_flight_tick(&ring_ops, &P, &S, &F, GRACE, &final)) adreno_fault_poll(&ring_ops, &S);
    return final;
}
static unsigned s3_reads;
static uint32_t s3_counted_rd(void *ctx, uint64_t pa) { s3_reads++; return ring_rd(ctx, pa); }
static struct adreno_ops cpu_b;                  /* A4: the other vCPU's view of the same machine */
static unsigned cpu_b_reads;
static uint32_t cpu_b_rd(void *ctx, uint64_t pa) { cpu_b_reads++; return ring_rd(ctx, pa); }

/* START -> several POLLs -> completion; and an IB that retires within START's spin. */
static void test_s3_complete(void)
{
    uint64_t x[4], before = clock_now;
    unsigned polls;
    s3_setup(22, 1500);
    s3_package(0xa5a50001);
    CHECK(s3_start(x) == ADRENO_IB_PENDING && x[1] == (ADRENO_IB_MARKER_BASE ^ 1u) && F.active && S.ib_submits == 1);
    const uint32_t m = (uint32_t)x[1];
    CHECK(x[2] > ring_ops.hz / ADRENO_IB_START_SPIN_DIVISOR && x[2] < 1500 && x[3] == 22 + ADRENO_IB_RING_WORDS);
    CHECK(cp.ibs == 0 && dev_rd32(WORK_PA) != 0xa5a50001 && F.starts == 1 && F.flights == 1 && F.va == PKG_VA);
    int e = s3_poll_until_final(&ring_ops, m, x, &polls, 0);
    CHECK(e == 0 && x[1] == m && x[3] == S.wptr && polls >= 3 && x[2] >= 1500 && clock_now - before >= 1500);
    CHECK(!F.active && F.finished == 1 && F.ok == 1 && F.poll_pending == polls && F.polls == polls + 1);
    CHECK(dev_rd32(WORK_PA) == 0xa5a50001 && cp.ibs == 1 && cp.violations == 0 && !r.fsr);
    CHECK(S.ib_dwords == 4 && S.ib_errors == 0 && dev_rd32(MEMPTRS + 0x80) == m && dev_rd32(MEMPTRS + 0xc0) == m);
    CHECK(F.max_ticks == x[2] && F.sum_ticks == x[2] && F.last_marker == m && F.last_status == 0);
    printf("RING_S3_COMPLETE polls=%u ticks=%llu reads=%llu\n", polls, (unsigned long long)x[2],
           (unsigned long long)F.max_reads);
    /* No execution time: START's spin sees it retire and answers like ADRENO_GUEST_IB (no flight). */
    s3_setup(22, 0);
    s3_package(0xa5a50002);
    CHECK(s3_start(x) == 0 && x[1] == (ADRENO_IB_MARKER_BASE ^ 1u) && !F.active && F.flights == 0 && F.starts == 1);
    CHECK(dev_rd32(WORK_PA) == 0xa5a50002 && S.ib_dwords == 4);
}

/* Final outcomes after the doorbell: GPU error, a fault while running, the budget (A6). */
static void test_s3_outcomes(void)
{
    uint64_t x[4], max_pending = 0;
    unsigned polls;
    s3_setup(22, 800);                                         /* retired and idle, but UCHE_OOB_ACCESS */
    s3_package(1);
    cp.int0_in_ib = 1u << 24;
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    CHECK(s3_poll_until_final(&ring_ops, x[1], x, &polls, 0) == ADRENO_IB_E_GPU_ERROR && x[1] == 0 && polls >= 1);
    CHECK(F.gpu_errors == 1 && S.ib_errors == 1 && r.rptr == S.wptr);
    s3_setup(22, 800);                                         /* a CB0 fault while it runs */
    s3_package(1);
    cp.fault_in_ib = 1;
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    CHECK(s3_poll_until_final(&ring_ops, x[1], x, &polls, 0) == ADRENO_IB_E_UNCERTAIN && x[1] == 0 && r.fsr);
    CHECK(F.uncertain == 1 && !F.active);
    /* A6: the CP never finishes. PENDING up to the budget timed from START's doorbell, across calls, then
     * UNCERTAIN, never earlier. */
    s3_setup(22, 1);
    s3_package(1);
    cp.halt = 1;
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    CHECK(s3_poll_until_final(&ring_ops, x[1], x, &polls, &max_pending) == ADRENO_IB_E_UNCERTAIN && x[1] == 0);
    /* each POLL is the guest's delay (at most 200 us) plus one pass of model time (50 ticks) */
    CHECK(x[2] > BUDGET && max_pending <= BUDGET && polls >= BUDGET / 250 && polls <= BUDGET / 200 + 8);
    CHECK(F.uncertain == 1 && F.finished == 1 && S.wptr == 22 + ADRENO_IB_RING_WORDS);
    printf("RING_S3_BUDGET divisor=%u budget=%llu polls=%u last_pending=%llu final=%llu\n",
           (unsigned)ADRENO_IB_POLL_DIVISOR, (unsigned long long)BUDGET, polls, (unsigned long long)max_pending,
           (unsigned long long)x[2]);
    /* A6: retired, then the guest is away for three budgets: completion is checked before the budget. */
    s3_setup(22, 1000);
    s3_package(0xa5a50003);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    uint64_t m = x[1];
    CHECK(s3_poll(&ring_ops, m, x) == ADRENO_IB_PENDING && F.reads >= 2);  /* the timeout's two earlier passes */
    clock_now += 3 * BUDGET;
    CHECK(s3_poll(&ring_ops, m, x) == 0 && x[1] == m && x[2] > 3 * BUDGET && dev_rd32(WORK_PA) == 0xa5a50003);
    /* A19: after UNCERTAIN with the CP still stalled, a START is refused before any ring write. */
    s3_setup(22, 1);
    s3_package(1);
    cp.halt = 1;
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    CHECK(s3_poll_until_final(&ring_ops, x[1], x, &polls, 0) == ADRENO_IB_E_UNCERTAIN);
    unsigned writes = nlog, cleans_before = cleans, doorbells = cp.doorbells;
    CHECK(s3_start(x) == ADRENO_E_RING && x[1] == 0 && nlog == writes && cleans == cleans_before &&
          cp.doorbells == doorbells && !F.active && F.flights == 1);
    /* A20: the doorbell dropped twice: UNCERTAIN from START, no flight; the next START is admitted. */
    s3_setup(22, 500);
    s3_package(1);
    r.drop_writes = 2;
    CHECK(s3_start(x) == ADRENO_IB_E_UNCERTAIN && x[1] == 0 && !F.active && F.flights == 0 && S.ib_errors == 1);
    CHECK(s3_start(x) == ADRENO_IB_PENDING && F.active && x[1] == (ADRENO_IB_MARKER_BASE ^ 2u));
    CHECK(s3_poll_until_final(&ring_ops, x[1], x, &polls, 0) == 0);
}

/* A4: START on one vCPU, every POLL on another; a POLL of another marker changes nothing. */
static void test_s3_migration(void)
{
    uint64_t x[4];
    unsigned polls;
    s3_setup(22, 1200);
    s3_package(0xa5a50004);
    cpu_b = ring_ops;
    cpu_b.ctx = &cpu_b;
    cpu_b.rd = cpu_b_rd;
    cpu_b_reads = 0;
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1];
    const struct adreno_ib_flight saved = F;
    CHECK(s3_poll(&cpu_b, m ^ 0x10, x) == ADRENO_IB_E_BUSY && x[1] == 0 && x[2] == 0);
    CHECK(F.active && F.marker == saved.marker && F.reads == saved.reads && F.start == saved.start &&
          F.mismatched == 1 && cpu_b_reads == 0);
    CHECK(s3_poll_until_final(&cpu_b, m, x, &polls, 0) == 0 && x[1] == m && cpu_b_reads > 0);
    CHECK(dev_rd32(WORK_PA) == 0xa5a50004 && F.finished == 1);
    uint64_t again[4];
    CHECK(s3_poll(&cpu_b, m, again) == 0 && !memcmp(again, x, sizeof x));        /* the stored reply */
}

/* A5: the stop drains an IB in flight before quiesce. */
static void test_s3_stop(void)
{
    uint64_t x[4];
    int final = 1;
    s3_setup(22, 3000);                                        /* finishes within the drain's bound */
    s3_package(0xa5a50005);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    CHECK(adreno_ib_flight_drain(&ring_ops, &P, &S, &F, ring_ops.hz / 10, &final) == 1 && final == 0);
    CHECK(!F.active && F.stopped == 1 && F.ok == 1 && dev_rd32(WORK_PA) == 0xa5a50005);
    adreno_quiesce(&ring_ops, &P, &S);
    CHECK((S.status & ADRENO_S_QUIESCED) && r.halt == 1);
    CHECK(adreno_ib_flight_drain(&ring_ops, &P, &S, &F, ring_ops.hz / 10, &final) == 0);  /* nothing left */
    s3_setup(22, 1);                                           /* never finishes: UNCERTAIN within the bound */
    s3_package(1);
    cp.halt = 1;
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    uint64_t from = clock_now;
    CHECK(adreno_ib_flight_drain(&ring_ops, &P, &S, &F, ring_ops.hz / 100, &final) == 1 &&
          final == ADRENO_IB_E_UNCERTAIN);
    CHECK(clock_now - from > ring_ops.hz / 100 && clock_now - from < ring_ops.hz / 100 + 1000);
    CHECK(!F.active && F.stopped == 1 && F.uncertain == 1);
    adreno_quiesce(&ring_ops, &P, &S);
    CHECK((S.status & ADRENO_S_QUIESCED) && r.halt == 1 && S.quiesce);
    s3_setup(22, 3000);                                        /* CX off at the stop: nothing behind it is read */
    s3_package(1);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    r.cx = 0;
    r.mmio_reads_cx_off = 0;
    CHECK(adreno_ib_flight_drain(&ring_ops, &P, &S, &F, ring_ops.hz / 10, &final) == 1 &&
          final == ADRENO_IB_E_UNCERTAIN && !F.active && r.mmio_reads_cx_off == 0);
}

/* A2, A3: the tick leaves FSR to the IB's own POLL; an unpolled flight ends at budget + grace. */
static void test_s3_tick(void)
{
    uint64_t x[4];
    unsigned polls;
    s3_setup(22, 1000);                                        /* A2 */
    s3_package(1);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1];
    r.fsr = 2;                                                 /* a CB0 fault while it runs */
    CHECK(s3_tick() == ADRENO_IB_PENDING && r.fsr == 2 && S.faults == 0 && F.active);
    clock_now += 2000;
    CHECK(s3_poll(&ring_ops, m, x) == ADRENO_IB_E_UNCERTAIN && r.fsr == 2);
    CHECK(s3_tick() == ADRENO_IB_PENDING && S.faults == 1 && r.fsr == 0);     /* now polled, recorded, cleared */
    s3_setup(22, 1);                                           /* A3: never polled, CP stalled */
    s3_package(1);
    cp.halt = 1;
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    uint64_t m3 = x[1];
    clock_now += BUDGET;
    CHECK(s3_tick() == ADRENO_IB_PENDING && F.active && F.abandoned == 0);   /* within budget + grace */
    clock_now += GRACE;
    CHECK(s3_tick() == ADRENO_IB_E_UNCERTAIN && !F.active && F.abandoned == 1 && F.uncertain == 1);
    CHECK(s3_poll(&ring_ops, m3, x) == ADRENO_IB_E_UNCERTAIN && x[1] == 0 && F.idle == 1);   /* the stored reply */
    s3_setup(22, 700);                                         /* A3: never polled, CP finished */
    s3_package(0xa5a50006);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    m3 = x[1];
    clock_now += BUDGET + GRACE + 1;
    CHECK(s3_tick() == 0 && F.abandoned == 1 && F.ok == 1 && dev_rd32(WORK_PA) == 0xa5a50006);
    CHECK(s3_poll(&ring_ops, m3, x) == 0 && x[1] == m3);
    uint64_t f[4] = {ADRENO_GUEST_FENCE, FENCE_VA + 0x200, 0x5a5a0003, 0};    /* ring users admitted again */
    CHECK(s3_call(f) == 0 && dev_rd32(FENCE_PA + 0x200) == 0x5a5a0003);
    (void)polls;
}

/* A7, A1b: ring users and an UNMAP of the package refused before any write while in flight; A1: another UNMAP
 * runs, its TLBI (and a TLBI timeout) counted against the flight; A16: reads per POLL. */
static void test_s3_refusals(void)
{
    uint64_t x[4];
    unsigned polls;
    s3_setup(22, 5000);
    s3_package(0xa5a50007);
    map(FILL_A_VA, FILL_A_PA, 0x4000, 0);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1], wptr = S.wptr;
    struct { uint64_t req[4]; int want; } cases[] = {
        {{ADRENO_GUEST_FENCE, FENCE_VA + 0x200, 0x5a5a0004, 0}, ADRENO_E_PARAMS},
        {{ADRENO_GUEST_FILL32, FILL_A_VA, 0x40, 0x11223344}, ADRENO_E_PARAMS},
        {{ADRENO_GUEST_IB, PKG_VA, 4, 64}, ADRENO_IB_E_BUSY},
        {{ADRENO_GUEST_IB_START, PKG_VA, 4, 64}, ADRENO_IB_E_BUSY},
        {{ADRENO_GUEST_UNMAP, PKG_VA, 0x4000, 0}, ADRENO_IB_E_BUSY},             /* A1b */
        {{ADRENO_GUEST_UNMAP, PKG_VA - 0x4000, 0x8000, 0}, ADRENO_IB_E_BUSY},    /* overlapping */
    };
    unsigned right = 0;
    const uint64_t pkg_leaf = dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14];
    for (unsigned k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        unsigned writes = nlog, cleans_before = cleans, doorbells = cp.doorbells, tlbi = r.tlbiasids;
        uint64_t refused = F.refused;
        int e = s3_call(cases[k].req);
        int ok = e == cases[k].want && (int64_t)cases[k].req[0] == e && cases[k].req[1] == 0 &&
                 cases[k].req[3] == wptr && nlog == writes && cleans == cleans_before && cp.doorbells == doorbells &&
                 r.tlbiasids == tlbi && S.wptr == wptr && F.refused == refused + 1 && F.active && F.marker == m;
        if (!ok) printf("FAIL S3 refusal case %u: got %d want %d\n", k, e, cases[k].want);
        CHECK(ok);
        right += ok;
    }
    CHECK(dart[(PKG_VA - ADRENO_WINDOW_BASE) >> 14] == pkg_leaf && dev_rd32(FENCE_PA + 0x200) == 0);
    /* A1: an UNMAP elsewhere runs during the flight; its TLBI is the flight's. */
    uint64_t u[4] = {ADRENO_GUEST_UNMAP, FILL_A_VA, 0x4000, 0};
    unsigned tlbi = r.tlbiasids;
    CHECK(s3_call(u) == 0 && u[1] == 0x4000 && r.tlbiasids == tlbi + 1 && !dart[(FILL_A_VA - ADRENO_WINDOW_BASE) >> 14]);
    /* A16: one PENDING POLL is one pass: at most 8 register/memory reads. */
    ring_ops.rd = s3_counted_rd;
    s3_reads = 0;
    CHECK(s3_poll(&ring_ops, m, x) == ADRENO_IB_PENDING && s3_reads >= 3 && s3_reads <= 8);
    ring_ops.rd = ring_rd;
    CHECK(s3_poll_until_final(&ring_ops, m, x, &polls, 0) == 0 && dev_rd32(WORK_PA) == 0xa5a50007);
    CHECK(F.tlbi == 1 && F.tlbi_timeouts == 0);
    printf("RING_S3_REFUSALS %u/%u, reads per pending POLL %u\n", right, (unsigned)(sizeof cases / sizeof cases[0]),
           s3_reads);
    /* A1: the SMMU's sync stuck while the GPU runs: the UNMAP fails (the caller keeps its backing), the IB is
     * unaffected, the timeout is counted against the flight. */
    map(FILL_B_VA, FILL_B_PA, 0x4000, 0);
    s3_package(0xa5a50008);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    r.tlb_stuck = 1;
    uint64_t v[4] = {ADRENO_GUEST_UNMAP, FILL_B_VA, 0x4000, 0};
    CHECK(s3_call(v) == ADRENO_E_TLB && v[1] == 0);
    r.tlb_stuck = 0;
    CHECK(s3_poll_until_final(&ring_ops, x[1], x, &polls, 0) == 0 && dev_rd32(WORK_PA) == 0xa5a50008);
    CHECK(F.tlbi == 1 && F.tlbi_timeouts == 1 && F.ok == 2);
}

/* A8, A12: POLL(0) is never anything but IDLE; a repeated POLL gets the stored reply and counts nothing again. */
static void test_s3_idle_and_repeats(void)
{
    uint64_t x[4];
    unsigned polls;
    s3_setup(22, 600);
    CHECK(s3_poll(&ring_ops, 0, x) == ADRENO_IB_IDLE && x[1] == 0 && x[2] == 0 && x[3] == 22);
    CHECK(s3_poll(&ring_ops, ADRENO_IB_MARKER_BASE ^ 1u, x) == ADRENO_IB_IDLE && F.idle == 2);
    x[0] = ADRENO_GUEST_IB_POLL; x[1] = 0; x[2] = 1; x[3] = 0;               /* malformed: refused */
    CHECK(adreno_guest_ib_poll(&ring_ops, &P, &S, &F, x) == ADRENO_E_PARAMS && F.poll_refused == 1);
    s3_package(0xa5a50009);
    CHECK(s3_start(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1];
    const struct adreno_ib_flight live = F;
    CHECK(s3_poll(&ring_ops, 0, x) == ADRENO_IB_IDLE && F.active && F.reads == live.reads);
    CHECK(s3_poll_until_final(&ring_ops, m, x, &polls, 0) == 0);
    const uint64_t dwords = S.ib_dwords, errors = S.ib_errors, finished = F.finished;
    uint64_t first[4];
    memcpy(first, x, sizeof first);
    for (unsigned n = 0; n < 3; n++) CHECK(s3_poll(&ring_ops, m, x) == 0 && !memcmp(x, first, sizeof x));
    CHECK(S.ib_dwords == dwords && S.ib_errors == errors && F.finished == finished);
    CHECK(s3_poll(&ring_ops, 0, x) == ADRENO_IB_IDLE && x[1] == 0);
    /* The counters' identities (tools/perf_counters.py decode_ib_async checks them on the report). */
    CHECK(F.polls == F.poll_pending + F.finished + F.idle + F.mismatched + F.poll_refused);
    CHECK(F.flights == F.finished + F.abandoned + F.stopped && F.ok + F.gpu_errors + F.uncertain == F.flights);
}

/* A16: START across the ring end (CP_NOP padding, one doorbell) goes asynchronous and completes. */
static void test_s3_wrap(void)
{
    uint64_t x[4];
    unsigned polls;
    s3_setup(8190, 900);
    s3_package(0xa5a5000a);
    CHECK(s3_start(x) == ADRENO_IB_PENDING && S.wptr == ADRENO_IB_RING_WORDS && S.ring_wraps == 1 && cp.nwptr == 1);
    CHECK(s3_poll_until_final(&ring_ops, x[1], x, &polls, 0) == 0 && dev_rd32(WORK_PA) == 0xa5a5000a);
    CHECK(cp.wraps == 1 && cp.violations == 0 && r.rptr == ADRENO_IB_RING_WORDS);
}

static void test_s3(void)
{
    unsigned before = failures;
    test_s3_complete();
    test_s3_outcomes();
    test_s3_migration();
    test_s3_stop();
    test_s3_tick();
    test_s3_refusals();
    test_s3_idle_and_repeats();
    test_s3_wrap();
    printf("RING_S3 %s: asynchronous IB (START/POLL) completion, outcomes, budget, migration, stop, tick, refusals, "
           "repeats, wrap\n", failures == before ? "ok" : "FAILED");
}
#endif

#ifndef ADRENO_RING_NO_MAIN
int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    if (!dram || !cache) return 2;
    test_s1_capacity();
    test_s1_edges();
#ifndef ADRENO_RING_TEST_PRE_CHANGE
    test_s1_nop_split();
    test_thread_modes();
    const char *dir = getenv("SNAP_DRAW_PLAN");
    int loaded = load_plan(dir ? dir : "build/adreno-pipeline-compiler-20260927/draw-plan-v2");
    CHECK(loaded == 0);
    if (!loaded) {
        test_s2_draw_plan();
        test_s2_probe_and_wrap();
        test_s2_max_package();
        test_s2_refusals();
        test_s2_after_doorbell();
    }
#endif
#if SNAP_ADRENO_IB_ASYNC && !defined(ADRENO_RING_TEST_PRE_CHANGE)
    test_s3();                                   /* plan-free: runs with or without the draw-plan fixture */
#endif
    free(dram);
    free(cache);
    if (failures) { printf("FAIL: %u of %u ring/IB checks\n", failures, checks); return 1; }
    printf("PASS: %u ring/IB checks; 5,000 fences + 20 maximum fills across %u wraps%s\n", checks, s1.wraps,
#ifndef ADRENO_RING_TEST_PRE_CHANGE
           "; draw-plan-v2 through ADRENO_GUEST_IB, mixed users, 2 MiB package, refusal matrix, post-doorbell outcomes"
#else
           " (pre-change build: S1 only)"
#endif
           );
    return 0;
}
#endif
