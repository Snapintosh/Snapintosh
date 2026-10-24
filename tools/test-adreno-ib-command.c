/* SPDX-License-Identifier: MIT */
/* The kext's draw submission (design S3 kext side, sections 3.1-3.6) through production code only:
 *   compat/adreno-ib-command.c   kernel-command dispatch, staging, relocation, allowlist, reply mapping, fail-fast
 *   compat/adreno-resource-list.c retain/prepare and per-resource cache ownership (FROM_DEVICE on Write only)
 *   compat/adreno.c, adreno-fill.c the monitor's FENCE/FILL32/CACHE with ring wrap (design S1)
 *   compat/adreno-ib.c           the monitor's ADRENO_GUEST_IB (design S2), when present (MONITOR_IB)
 * against tools/test-adreno.c's noncoherent RAM + SMMU model, extended here with a CP that runs the IB ring words
 * (CP_INDIRECT_BUFFER fetched through CB0, EVENT_WRITE7 fences, CP_WAIT_TIMESTAMP, CP_MEM_WRITE, the wrap NOPs).
 * The explicit copy extension executes only CP_MEMCPY inside the fetched IB. Shader/draw packets are observed,
 * not executed. Its preimplementation failure inventory is docs/ADRENO-COPY-MODEL-20261019.md.
 * Native IOGPU retain/prepare and the kext's map range check are fixtures (the latter calls the production rule).
 *
 *   test-adreno-ib-command                 built-in E2E checks (below)
 *   test-adreno-ib-command --replay DIR    one captured segment: DIR/list.bin (IOGPU segment resource list),
 *                                          DIR/commands.bin (the kernel commands), DIR/resources.txt ("id va
 *                                          length" per fixture resource); optional DIR/expect.txt ("index code").
 *                                          Writes DIR/result.txt, DIR/package.bin, DIR/fetched.bin, DIR/refs.txt.
 *
 * Failure inventory this was written against (the code under test came after it):
 *  F1 the package is parsed in place (TOCTOU) or a size overflows: only the copy is parsed, sizes are exact;
 *  F2 a relocation patches the wrong dword, the wrong half, twice, or with address bits in the placeholder;
 *  F3 an address reaches the GPU without a relocation, or a relocation lands on a non-address dword;
 *  F4 a RESOURCE relocation escapes its list entry (unknown ID, WRITE on a Read-usage entry, range, alignment);
 *  F5 an opcode/register/event outside the allowlist runs (nested IB, memory write, protected register);
 *  F6 the monitor reply is misread: a refusal treated as retired, UNCERTAIN not latched, GPU_ERROR freezing
 *     (or not disabling IB), an inconsistent reply (success without marker) trusted;
 *  F7 after UNCERTAIN another HVC or cache maintenance runs, or the arena/backing of the uncertain IB is reused;
 *  F8 cache ownership: TO_DEVICE missed on a read-only entry before the doorbell, FROM_DEVICE run on a read-only
 *     entry after it, or run at all after a refusal;
 *  F9 the fence mapping assumes a monotonic WPTR (ring wrap) or treats a post-doorbell RING/FENCE as clean;
 *  F10 the zero page is not at PoC before the first IB (R1); the package is not what the CP fetches.
 * Built with -DSNAP_ADRENO_IB_ASYNC=1 every IB goes through the kext's START/POLL loop (compat/adreno-ib-async.h)
 * and a CP that takes model time, so the list keeps its preparation across the POLLs (agents/async-ib
 * FAILURE-MODES.md A17); SNAP_IB_PATH=sync runs the same suite through that build's synchronous ADRENO_GUEST_IB.
 * Built with -DADRENO_IB_CS_SAMPLERS=1 the CS sampler checks also cover the count a kext opts into; adding
 * -DIB_REPLAY_CS_SAMPLER_UNITS=N makes --replay validate as a kext booted with adreno_cs_samplers=1 (N = 8). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef GUEST_SIZE
#define GUEST_SIZE 0x100000                /* 64 guest pages: fence/fill pages, fixtures, the IB arena */
#endif
#define ADRENO_FILL_COMMAND_TEST_ENTRY fill_command_main
#include "test-adreno-fill-command.c"
#include "adreno-ib-command.h"
#include "adreno-ib-tables.h"
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
#if __has_include("adreno-ib.h")
#include "adreno-ib.h"
#define MONITOR_IB 1
#else
#define MONITOR_IB 0
#endif

/* ---- model extension: the registers the IB path reads, and a CP for the IB ring words -------------------- */
static struct {
    uint32_t rbbm_status, int0, cp_global;
    int stall, error_after_ib;
    unsigned ibs, ib_writable, events, event_writes, waits, mem_writes, wptr_writes;
    uint32_t fetched[ADRENO_IB_MAX_DWORDS], fetched_dwords;   /* the production IB limit (1 MiB of packets) */
    uint64_t fetched_va;
    uint64_t copy_bytes;
    unsigned copies, observed_draws, observed_dispatches;
    /* SNAP_ADRENO_IB_ASYNC: with latency, a doorbell's work runs once the model clock is that many ticks later,
     * when the monitor next reads a register, so an IB needs several POLLs (FAILURE-MODES A17). 0: at once. */
    uint64_t latency, due;
    int pending;
} cpm;

static uint32_t cp_load(uint64_t va, int *ok)
{
    uint64_t leaf = smmu_walk(va, 1);
    if (!leaf) { r.fsr = 2; *ok = 0; return 0; }
    uint32_t value;
    memcpy(&value, dram + ram_offset((leaf & ADRENO_PTE_ADDR) | (va & 0xfff), 4), 4);
    return value;
}
static int cp_store(uint64_t va, uint32_t value)
{
    uint64_t leaf = smmu_walk(va, 1);
    if (!leaf || (leaf & ADRENO_PTE_RDONLY)) { r.fsr = 2; return -1; }
    dev_wr32((leaf & ADRENO_PTE_ADDR) | (va & 0xfff), value);
    return 0;
}
/* Interpret only the copy effects of actual CP-fetched words. No shader, raster or GPU-cache model is implied. */
static int ib_cp_copy_effects(void)
{
    const uint32_t *words = cpm.fetched;
    const uint32_t n = cpm.fetched_dwords;
    if (n > sizeof cpm.fetched / sizeof cpm.fetched[0]) return -1;
    for (uint32_t at = 0; at < n;) {
        uint32_t h = words[at], count, op = 0;
        if ((h & 0xf0000000u) == A8XX_E_CP_TYPE4_PKT) {
            count = h & A8XX_PKT4_COUNT_MASK;
            const uint32_t reg = (h >> 8) & A8XX_PKT4_REG_MASK;
            if (!count || h != a8xx_pkt4_hdr(reg, count)) return -1;
        } else if ((h & 0xf0000000u) == A8XX_E_CP_TYPE7_PKT) {
            count = h & A8XX_PKT7_COUNT_MASK;
            op = (h >> 16) & A8XX_PKT7_OPCODE_MASK;
            if (h != a8xx_pkt7_hdr(op, count)) return -1;
        } else return -1;
        if (count > n - at - 1) return -1;
        if (op == A8XX_E_CP_EXEC_CS) cpm.observed_dispatches++;
        if (op == A8XX_E_CP_DRAW_INDX_OFFSET) cpm.observed_draws++;
        if (op == A8XX_E_CP_MEMCPY) {
            if (count != 5) return -1;
            const uint32_t *p = words + at + 1;
            const uint64_t bytes = 4ull * p[0];
            const uint64_t src = (uint64_t)p[2] << 32 | p[1];
            const uint64_t dst = (uint64_t)p[4] << 32 | p[3];
            const uint64_t budget = 64ull << 20;   /* bounded host replay, not an advertised GPU limit */
            if (!bytes || ((src | dst) & 3) || bytes > budget - cpm.copy_bytes ||
                src > UINT64_MAX - bytes || dst > UINT64_MAX - bytes ||
                (src < dst + bytes && dst < src + bytes)) return -1;
            for (uint64_t off = 0; off < bytes; off += 4) {
                int ok = 1;
                uint32_t value = cp_load(src + off, &ok);
                if (!ok || cp_store(dst + off, value)) return -1;
            }
            cpm.copy_bytes += bytes;
            cpm.copies++;
        }
        at += 1 + count;
    }
    return 0;
}
static void ib_cp_run(void)
{
    const uint32_t size = 2u << (r.rb_cntl & 0x3f);
    if (cpm.stall) return;
    while (r.rptr != r.wptr) {
        int ok = 1;
        if (r.wptr >= size || r.rptr >= size) { r.fsr = 0x80; return; }
        const uint64_t at = 0x10100000 + 4ull * r.rptr;
        const uint32_t h = cp_load(at, &ok), count = h & 0x3fff, op = (h >> 16) & 0x7f;
        if (!ok) return;
        if (h != a8xx_pkt7_hdr(op, count) || r.rptr + 1 + count > size) { r.fsr = 0x80; return; }
        uint32_t p[4] = {0};
        for (uint32_t i = 0; i < count && i < 4; i++) p[i] = cp_load(at + 4 + 4 * i, &ok);
        if (!ok) return;
        switch (op) {
        case A8XX_E_CP_NOP: case A8XX_E_CP_THREAD_CONTROL: break;
        case A8XX_E_CP_MEM_WRITE:
            for (uint32_t i = 2; i < count; i++) {
                uint32_t v = cp_load(at + 4 + 4 * i, &ok);
                if (!ok || cp_store(((uint64_t)p[1] << 32 | p[0]) + 4 * (i - 2), v)) return;
                cpm.mem_writes++;
            }
            break;
        case A8XX_E_CP_INDIRECT_BUFFER: {
            const uint64_t va = (uint64_t)p[1] << 32 | p[0];
            const uint32_t dwords = p[2] & A8XX_PKT_A5XX_CP_INDIRECT_BUFFER_2__IB_SIZE__MASK;
            cpm.ibs++;
            cpm.fetched_va = va;
            cpm.fetched_dwords = dwords;
            for (uint32_t i = 0; i < dwords; i++) {
                uint64_t leaf = smmu_walk(va + 4ull * i, 1);
                if (!leaf) { r.fsr = 2; return; }
                if (!(leaf & ADRENO_PTE_RDONLY)) cpm.ib_writable++;
                uint32_t v = cp_load(va + 4ull * i, &ok);
                if (i < sizeof cpm.fetched / 4) cpm.fetched[i] = v;
            }
            if (!ok || ib_cp_copy_effects()) { r.fsr |= 0x80; return; }
            if (cpm.error_after_ib) cpm.int0 |= 1u << 22;   /* RBBM_HANG_DETECT, one of ADRENO_IB_RBBM_INT_ERRORS */
            break;
        }
        case A8XX_E_CP_EVENT_WRITE7:
            cpm.events++;
            if (p[0] & A8XX_PKT_CP_EVENT_WRITE7_0__WRITE_ENABLED__MASK) {
                if (count != 4 || cp_store((uint64_t)p[2] << 32 | p[1], p[3])) { r.fsr |= 0x80; return; }
                cpm.event_writes++;
            }
            break;
        case A8XX_E_CP_WAIT_TIMESTAMP: {
            uint32_t v = cp_load((uint64_t)p[2] << 32 | p[1], &ok);
            cpm.waits++;
            if (!ok || (int32_t)(v - p[3]) < 0) return;      /* TS_WAIT_GE_32B: stall until it lands */
            break;
        }
        default: r.fsr = 0x80; return;
        }
        r.rptr = (r.rptr + 1 + count) % size;
    }
}
static uint32_t ib_rd(void *ctx, uint64_t pa)
{
    if (cpm.pending && (int64_t)(clock_now - cpm.due) >= 0) { cpm.pending = 0; ib_cp_run(); }
    switch (pa) {
    case ADRENO_RBBM_STATUS: return cpm.pending ? 3 : cpm.rbbm_status;
    case ADRENO_RBBM_INT_0_STATUS: return cpm.int0;
    case ADRENO_CP_INTERRUPT_STATUS_GLOBAL: return cpm.cp_global;
    }
    return m_rd(ctx, pa);
}
static void ib_wr(void *ctx, uint64_t pa, uint32_t value)
{
    if (pa != ADRENO_CP_RB_WPTR) { m_wr(ctx, pa, value); return; }
    if (nlog < 4096) wlog[nlog++] = (struct regwrite){pa, value};
    cpm.wptr_writes++;
    if (r.drop_writes) { r.drop_writes--; r.fence_status |= 1; return; }
    r.fence_status = 0; r.wptr = value;
    if (cpm.latency) { cpm.pending = 1; cpm.due = clock_now + cpm.latency; return; }
    ib_cp_run();
}
static struct adreno_ops ib_ops;

/* ---- the kext side: fixtures for IOGPU retain/prepare, the arena, the HVC callbacks ------------------------ */
#define IB_ARENA_VA (ADRENO_WINDOW_BASE + 0x4000000)
#ifndef IB_ARENA_OFFSET
#define IB_ARENA_OFFSET 0x80000
#endif
#define IB_ARENA_PA (GUEST_PAGE + IB_ARENA_OFFSET)   /* zero page + 16 package pages (256 KiB packages) */
#ifndef IB_ARENA_PAGES
#define IB_ARENA_PAGES 17u                             /* larger captures (icon rendering) map up to ADRENO_IB_MAX_PACKAGE */
#endif
#define IB_FIXTURE_PA (GUEST_PAGE + 0x10000)          /* fixture resources from here, 28 pages */
#define IB_FIXTURE_END IB_ARENA_PA
#ifndef IB_FIXTURES
#define IB_FIXTURES 24u
#endif
#ifndef IB_REPLAY_CAPACITY
#define IB_REPLAY_CAPACITY 48u
#endif
struct ib_fixture { uint32_t id; struct adreno_resource res; uint64_t pa; unsigned retained, prepared; };
static struct ib_fixture ibfx[IB_FIXTURES];
static unsigned ibfx_count;
static uint64_t ibfx_next;
static struct adreno_ib_tables ib_tables;
static struct adreno_ib_work ib_work;
static uint8_t *ib_arena;
static struct adreno_ib_reloc ib_relocs[ADRENO_IB_MAX_RELOCS];
static uint16_t ib_order[ADRENO_IB_MAX_RELOCS];
static uint8_t ib_used[ADRENO_IB_MAX_RELOCS];
static uint64_t ib_targets[ADRENO_IB_TARGET_WORDS];
static uint8_t ib_latch;                               /* the kext's fStampCleanupFailed */
static unsigned ib_cache_calls[3], ib_ring_calls, ib_sync_log_n;
static struct { unsigned direction; uint64_t address; } ib_sync_log[64];
static struct { int active; struct adreno_ib_reply reply; } ib_fake;

static int ib_cache_range(void *ctx, uint64_t address, uint64_t bytes, unsigned direction)
{
    (void)ctx;
    ib_cache_calls[direction]++;
    uint64_t regs[] = {ADRENO_GUEST_CACHE, address, bytes, direction};
    return adreno_guest_cache(&ib_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
}
static void *ibfx_retain(void *ctx, uint32_t id)
{
    (void)ctx;
    for (unsigned i = 0; i < ibfx_count; i++)
        if (ibfx[i].id == id) { ibfx[i].retained++; return &ibfx[i].res; }
    return 0;
}
static struct ib_fixture *ibfx_of(void *resource)
{
    for (unsigned i = 0; i < ibfx_count; i++) if (&ibfx[i].res == resource) return &ibfx[i];
    return 0;
}
static void ibfx_release(void *ctx, void *resource) { (void)ctx; struct ib_fixture *f = ibfx_of(resource); CHECK(f && f->retained); if (f) f->retained--; }
static int ibfx_prepare(void *ctx, void *resource, void **token)
{
    (void)ctx; struct ib_fixture *f = ibfx_of(resource);
    CHECK(f != 0); if (!f) { *token = 0; return -1; }
    f->prepared++; *token = resource; return 0;
}
static void ibfx_complete(void *ctx, void *token) { (void)ctx; struct ib_fixture *f = ibfx_of(token); CHECK(f && f->prepared); if (f) f->prepared--; }
static int ibfx_sync(void *ctx, void *token, unsigned direction)
{
    (void)ctx;
    if (direction && ib_sync_log_n < 64) ib_sync_log[ib_sync_log_n++] = (typeof(ib_sync_log[0])){direction, ((struct adreno_resource *)token)->address};
    return adreno_resource_cache(token, direction, ib_cache_range, 0);
}
static const struct adreno_resource_list_ops ibfx_ops = {0, ibfx_retain, ibfx_release, ibfx_prepare, ibfx_complete, ibfx_sync};
/* AdrenoSegmentList::resolveRange -> AdrenoMemoryMap::resolveRange: the production range rule. */
static int ibfx_resolve(void *ctx, void *resource, void *token, uint64_t offset, uint64_t bytes, uint64_t *address)
{
    (void)ctx;
    if (resource != token) return ADRENO_LIST_E_RESOURCE;
    return adreno_ib_resource_range(resource, offset, bytes, address);
}
static uint32_t ib_marker_seen;
#if MONITOR_IB && SNAP_ADRENO_IB_ASYNC
/* SNAP_ADRENO_IB_ASYNC: the kext's ibRing built with ADRENO_IB_ASYNC is the START/POLL loop (compat/adreno-ib-async.h)
 * against the monitor's dispatch (probes/xnuboot.c order: POLL, then the in-flight admission, then the call), and the
 * CP takes IB_ASYNC_LATENCY ticks per doorbell, so every submission below waits through several POLLs while the
 * resource list holds its preparation (FAILURE-MODES A17). SNAP_IB_PATH=sync runs the suite through the define's
 * synchronous ADRENO_GUEST_IB instead (the same refactored core). */
#include "adreno-ib-async.h"
#define IB_ASYNC_LATENCY 700u
static struct adreno_ib_flight ib_flight;
static int ib_async_path = 1;
static unsigned ib_async_starts, ib_async_polls;
static void ib_monitor_hvc(void *ctx, uint64_t x[4])
{
    (void)ctx;
    if (x[0] == ADRENO_GUEST_IB_POLL) { ib_async_polls++; adreno_guest_ib_poll(&ib_ops, &P, &S, &ib_flight, x); return; }
    if (adreno_ib_flight_refuse(&S, &ib_flight, x)) return;
    CHECK(x[0] == ADRENO_GUEST_IB_START);
    ib_async_starts++;
    adreno_guest_ib_start(&ib_ops, &P, &S, &ib_flight, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
}
static void ib_monitor_delay(void *ctx, uint32_t us) { (void)ctx; clock_now += us; }   /* IODelay: hz is 1 MHz */
#endif
/* The kext's ibRing: ADRENO_GUEST_IB. The kext's arena stores sit in the CPU cache, not DRAM (non-coherent), so
 * the package is written through the CPU model; only the monitor's clean makes it visible to the CP. */
static int ib_ring(void *ctx, uint64_t va, uint64_t dwords, uint64_t bytes, struct adreno_ib_reply *reply)
{
    (void)ctx;
    ib_ring_calls++;
    if (ib_fake.active) { *reply = ib_fake.reply; return 0; }
#if MONITOR_IB
    if (va >= IB_ARENA_VA && bytes <= (IB_ARENA_PAGES - 1) * 0x4000ull && va - IB_ARENA_VA + bytes <= IB_ARENA_PAGES * 0x4000ull)
        for (uint64_t o = 0; o < bytes; o += 4) {
            uint32_t v;
            memcpy(&v, ib_arena + (va - IB_ARENA_VA) + o, 4);
            m_wr(0, IB_ARENA_PA + (va - IB_ARENA_VA) + o, v);
        }
#if SNAP_ADRENO_IB_ASYNC
    if (ib_async_path) {
        const struct adreno_ib_async_ops ops = {0, ib_monitor_hvc, ib_monitor_delay};
        uint64_t out[4];
        adreno_ib_async_run(&ops, va, dwords, bytes, out, 0);
        *reply = (struct adreno_ib_reply){(int64_t)out[0], out[1], out[2], out[3]};
        ib_marker_seen = (uint32_t)reply->marker;
        return 0;
    }
#endif
    uint64_t regs[] = {ADRENO_GUEST_IB, va, dwords, bytes};
    adreno_guest_ib(&ib_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    *reply = (struct adreno_ib_reply){(int64_t)regs[0], regs[1], regs[2], regs[3]};
#else
    /* No monitor source in this tree: the adreno-guest.h argument contract, then a retired reply. */
    if ((va | bytes) % ADRENO_IB_ALIGN || !dwords || dwords > ADRENO_IB_MAX_DWORDS || bytes < ADRENO_IB_ALIGN_UP(4 * dwords) ||
        bytes > ADRENO_IB_MAX_PACKAGE || va < IB_ARENA_VA + ADRENO_IB_PACKAGE_AT || va + bytes > IB_ARENA_VA + ADRENO_IB_ARENA_BYTES)
        *reply = (struct adreno_ib_reply){ADRENO_E_WINDOW, 0, 0, 22};
    else
        *reply = (struct adreno_ib_reply){0, 0x534e7001u, 1, 35};
#endif
    ib_marker_seen = (uint32_t)reply->marker;
    return 0;
}
/* The kext's probeGuestFence against the model's stamp slot (window page 0, offset 0x200). */
static int ib_fence_work(void *ctx)
{
    (void)ctx;
    const uint32_t value = 0x534e5001;
    m_wr(0, GUEST_PAGE + 0x200, ~value);
    uint64_t regs[] = {ADRENO_GUEST_FENCE, ADRENO_WINDOW_BASE + 0x200, value, 0};
    adreno_guest_fence(&ib_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    return adreno_fence_classify((int64_t)regs[0], regs[1], value, m_rd(0, GUEST_PAGE + 0x200));
}
static int ib_fill_transfer(void *ctx, uint64_t address, uint64_t bytes, uint32_t pattern)
{
    (void)ctx;
    uint64_t regs[] = {ADRENO_GUEST_FILL32, address, bytes, pattern};
    int result = adreno_guest_fill32(&ib_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    if (!result && regs[1] != bytes) return ADRENO_FILL32_E_UNCERTAIN;
    return result;
}
static int ibfx_resolve_fill(void *ctx, void *resource, void *token, uint64_t offset, uint64_t bytes, uint64_t *address)
{
    (void)ctx;
    if (resource != token) return ADRENO_LIST_E_RESOURCE;
    return adreno_fill32_resource_range(resource, offset, bytes, address);
}

/* AdrenoCommandQueue::processSegmentKernelCommand's callbacks, gated exactly as AdrenoAcceleratorX2 gates them. */
struct ib_submission { struct adreno_resource_list *list; const struct adreno_fill32_request *fill; const void *command; uint64_t bytes; };
static int ib_gated_fence(void *c) { struct ib_submission *s = c; return adreno_resource_list_submit(s->list, &ibfx_ops, ib_fence_work, 0); }
static int ib_gated_fill(void *c) { struct ib_submission *s = c; return adreno_fill32_submit(s->list, &ibfx_ops, s->fill, ibfx_resolve_fill, ib_fill_transfer, 0); }
static int ib_gated_ib(void *c) { struct ib_submission *s = c; return adreno_ib_submit(&ib_work, s->list, &ibfx_ops, s->command, s->bytes, ibfx_resolve, ib_ring, 0); }
static int ib_k_fence(void *c) { struct ib_submission s = {c, 0, 0, 0}; return adreno_submit_gated(&ib_latch, ib_gated_fence, &s); }
static int ib_k_fill(void *c, const struct adreno_fill32_request *request) { struct ib_submission s = {c, request, 0, 0}; return adreno_submit_gated(&ib_latch, ib_gated_fill, &s); }
static int ib_k_ib(void *c, const void *command, uint64_t bytes) { struct ib_submission s = {c, 0, command, bytes}; return adreno_submit_gated(&ib_latch, ib_gated_ib, &s); }
/* The whole kernel command, and the retain AdrenoCommandQueue adds on UNCERTAIN/VISIBILITY. */
static int ib_command(struct adreno_resource_list *list, const void *command, uint64_t bytes)
{
    const struct adreno_kernel_ops kops = {list, ib_k_fence, ib_k_fill, ib_k_ib};
    int result = adreno_kernel_command(command, bytes, &kops);
    if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY) adreno_resource_list_freeze(list);
    return result;
}

static void ib_map(uint64_t va, uint64_t pa, unsigned pages, int nowrite)
{
    for (unsigned i = 0; i < pages; i++)
        dart[(va - ADRENO_WINDOW_BASE) / 0x4000 + i] = dart_desc(pa + 0x4000ull * i, 0, 0x4000, nowrite, 0);
    CHECK(mirror(va, 0x4000ull * pages) == 0);
}
static struct ib_fixture *ibfx_add(uint32_t id, uint64_t va, uint64_t length)
{
    const unsigned pages = (unsigned)((length + 0x3fff) / 0x4000);
    if (ibfx_count >= IB_FIXTURES || !length || (va & 0x3fff) || ibfx_next + 0x4000ull * pages > IB_FIXTURE_END) return 0;
    struct ib_fixture *f = &ibfx[ibfx_count++];
    *f = (struct ib_fixture){id, {va, 0x4000ull * pages, length, 0x4000ull * pages,
                                  ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED}, ibfx_next, 0, 0};
    for (uint64_t o = 0; o < 0x4000ull * pages; o += 4) dev_wr32(ibfx_next + o, 0x69696969);   /* seed */
    ib_map(va, ibfx_next, pages, 0);
    ibfx_next += 0x4000ull * pages;
    return f;
}
/* A fresh monitor (adopted, attached, ring at 22), kext IB work bound to a GPU-read-only arena whose zero page
 * reached PoC (R1), no fixtures. */
static void ib_setup(void)
{
    setup_fill();
    fill_ops.invalidate = invalidate_cpu;
    ib_ops = fill_ops;
    ib_ops.rd = ib_rd;
    ib_ops.wr = ib_wr;
    memset(&cpm, 0, sizeof cpm);
#if MONITOR_IB && SNAP_ADRENO_IB_ASYNC
    memset(&ib_flight, 0, sizeof ib_flight);
    cpm.latency = ib_async_path ? IB_ASYNC_LATENCY : 0;
#endif
    memset(ibfx, 0, sizeof ibfx);
    ibfx_count = 0; ibfx_next = IB_FIXTURE_PA;
    ib_latch = 0; ib_ring_calls = 0; ib_sync_log_n = 0; ib_marker_seen = 0;
    memset(ib_cache_calls, 0, sizeof ib_cache_calls);
    memset(&ib_fake, 0, sizeof ib_fake);
    for (uint64_t o = 0; o < 0x4000ull * IB_ARENA_PAGES; o += 4) dev_wr32(IB_ARENA_PA + o, 0xdeadbeef);  /* stale DRAM */
    ib_map(IB_ARENA_VA, IB_ARENA_PA, IB_ARENA_PAGES, 1);
    memset(ib_arena, 0xa5, ADRENO_IB_ARENA_BYTES);
    CHECK(adreno_ib_work_init(&ib_work, &ib_tables, ib_arena, IB_ARENA_VA, ADRENO_IB_ARENA_BYTES, ib_relocs, ib_order,
                              ib_used, ADRENO_IB_MAX_RELOCS, ib_targets) == 0);
    /* R1 as AdrenoAcceleratorX2::configureGuestIB does it: the kext's zero stores, then one TO_DEVICE clean. */
    for (uint64_t o = 0; o < ADRENO_IB_ZERO_BYTES; o += 4) m_wr(0, IB_ARENA_PA + o, 0);
    uint64_t regs[] = {ADRENO_GUEST_CACHE, IB_ARENA_VA, ADRENO_IB_ZERO_BYTES, ADRENO_CACHE_TO_DEVICE};
    CHECK(adreno_guest_cache(&ib_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH) == 0);
    unsigned stale = 0;
    for (uint64_t o = 0; o < ADRENO_IB_ZERO_BYTES; o += 4) { uint32_t v; memcpy(&v, dram + ram_offset(IB_ARENA_PA + o, 4), 4); stale += v != 0; }
    CHECK(stale == 0);
}

/* ---- a minimal package builder (the plug-in's wire format, adreno-submit.h) -------------------------------- */
struct ib_pkg {
    uint32_t words[512], n;
    uint8_t data[512];
    uint32_t data_bytes, nrelocs;
    struct adreno_ib_reloc relocs[32];
};
static void pk_word(struct ib_pkg *k, uint32_t w) { k->words[k->n++] = w; }
static void pk_pkt7(struct ib_pkg *k, uint32_t op, uint32_t count) { pk_word(k, a8xx_pkt7_hdr(op, count)); }
static uint32_t pk_data_at(const struct ib_pkg *k) { return (uint32_t)adreno_ib_data_offset(k->n); }
/* lo/hi: IB word indices (hi ~0u: none); data relocations are added after the IB is final (pk_data_reloc). */
static void pk_reloc(struct ib_pkg *k, uint32_t lo, uint32_t hi, uint8_t kind, uint8_t access, uint8_t align,
                     uint8_t hi_bits, uint32_t id, uint64_t offset, uint64_t length)
{
    k->relocs[k->nrelocs++] = (struct adreno_ib_reloc){lo * 4, hi == ~0u ? ADRENO_IB_RELOC_NO_HI : hi * 4, kind, access,
                                                        align, hi_bits, id, offset, length};
}
static size_t pk_serialize(const struct ib_pkg *k, uint8_t *out)
{
    const uint64_t package = adreno_ib_package_bytes(k->n, k->data_bytes);
    const uint64_t total = adreno_ib_command_bytes(k->n, k->data_bytes, k->nrelocs);
    struct adreno_ib_command c = {{ADRENO_KCMD_IB, (uint32_t)total}, ADRENO_IB_COMMAND_VERSION, 0, k->n, k->data_bytes,
                                  k->nrelocs, 0, {0, 0}};
    memset(out, 0, total);
    memcpy(out, &c, sizeof c);
    memcpy(out + sizeof c, k->words, 4ull * k->n);
    memcpy(out + sizeof c + adreno_ib_data_offset(k->n), k->data, k->data_bytes);
    memcpy(out + sizeof c + package, k->relocs, sizeof(struct adreno_ib_reloc) * k->nrelocs);
    return (size_t)total;
}
#define RT_ID 0x11u
#define RO_ID 0x12u
#define RT_VA (ADRENO_WINDOW_BASE + 0x100000)
#define RO_VA (ADRENO_WINDOW_BASE + 0x200000)
/* A small valid draw: every relocation kind, a UBO, S# from the package, one auto-index draw. */
static void pk_draw(struct ib_pkg *k)
{
    memset(k, 0, sizeof *k);
    pk_pkt7(k, A8XX_E_CP_SET_MARKER, 1); pk_word(k, A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_DIRECT_RENDER));
    pk_pkt7(k, A8XX_E_CP_CONTEXT_REG_BUNCH, 4);
    pk_word(k, A8XX_REG_RB_MRT_BASE); pk_word(k, 0); pk_word(k, A8XX_REG_RB_MRT_BASE + 1); pk_word(k, 0);
    pk_reloc(k, 4, 6, ADRENO_IB_RELOC_RESOURCE, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE, 6, 32, RT_ID, 0, 0x5c00);
    pk_pkt7(k, A8XX_E_CP_CONTEXT_REG_BUNCH, 4);
    pk_word(k, A8XX_REG_SP_GFX_BINDLESS_BASE_DESCRIPTOR); pk_word(k, 3);
    pk_word(k, A8XX_REG_SP_GFX_BINDLESS_BASE_DESCRIPTOR + 1); pk_word(k, 0);
    pk_reloc(k, 9, 11, ADRENO_IB_RELOC_ZERO, ADRENO_IB_ACCESS_READ, 6, 32, 0, 0, 0x1000);
    pk_pkt7(k, A8XX_E_CP_LOAD_STATE6_GEOM, 5);                                     /* UBO 0 = RO buffer */
    pk_word(k, A8XX_PKT_CP_LOAD_STATE6_0__STATE_TYPE(A8XX_E_ST6_UBO) | A8XX_PKT_CP_LOAD_STATE6_0__STATE_SRC(A8XX_E_SS6_DIRECT) |
               A8XX_PKT_CP_LOAD_STATE6_0__STATE_BLOCK(A8XX_E_SB6_VS_SHADER) | A8XX_PKT_CP_LOAD_STATE6_0__NUM_UNIT(1));
    pk_word(k, 0); pk_word(k, 0); pk_word(k, 0); pk_word(k, A8XX_DESC_A6XX_UBO_1__SIZE(4));
    pk_reloc(k, 16, 17, ADRENO_IB_RELOC_RESOURCE, ADRENO_IB_ACCESS_READ, 6, 17, RO_ID, 0x40, 64);
    pk_pkt7(k, A8XX_E_CP_LOAD_STATE6_FRAG, 3);                                     /* S# from the package */
    pk_word(k, A8XX_PKT_CP_LOAD_STATE6_0__STATE_TYPE(A8XX_E_ST6_SHADER) | A8XX_PKT_CP_LOAD_STATE6_0__STATE_SRC(A8XX_E_SS6_INDIRECT) |
               A8XX_PKT_CP_LOAD_STATE6_0__STATE_BLOCK(A8XX_E_SB6_FS_TEX) | A8XX_PKT_CP_LOAD_STATE6_0__NUM_UNIT(1));
    pk_word(k, 0); pk_word(k, 0);
    const uint32_t sampler_ext = k->n - 2;
    pk_pkt7(k, A8XX_E_CP_DRAW_INDX_OFFSET, 3);
    pk_word(k, A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE(A8XX_E_DI_PT_TRILIST) |
               A8XX_PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT(A8XX_E_DI_SRC_SEL_AUTO_INDEX) |
               A8XX_PKT_CP_DRAW_INDX_OFFSET_0__VIS_CULL(A8XX_E_USE_VISIBILITY));
    pk_word(k, 1); pk_word(k, 3);
    pk_pkt7(k, A8XX_E_CP_EVENT_WRITE7, 1); pk_word(k, A8XX_PKT_CP_EVENT_WRITE7_0__EVENT(A8XX_E_CACHE_CLEAN));
    k->data_bytes = 64;                                                              /* one S#, zero */
    pk_reloc(k, sampler_ext, sampler_ext + 1, ADRENO_IB_RELOC_PACKAGE, ADRENO_IB_ACCESS_READ, 4, 32, 0,
             pk_data_at(k), 16);
}
static struct adreno_resource_list ib_list;
static struct adreno_resource_entry ib_entries[IB_REPLAY_CAPACITY];
static unsigned char ib_wire[32 + 64 * 8], ib_wire_copy[32 + 64 * 8];
/* An IOGPU segment resource list with (id, usage) pairs, acquired and prepared by the production code. */
static int ib_list_make(struct adreno_resource_list *list, struct adreno_resource_entry *slots, const uint32_t *ids,
                        const uint16_t *usages, unsigned n)
{
    memset(ib_wire, 0, sizeof ib_wire);
    unsigned groups = (n + 5) / 6;
    put32(ib_wire + 28, groups);
    for (unsigned i = 0; i < n; i++) {
        unsigned char *group = ib_wire + 32 + 64 * (i / 6);
        put32(group + 4 * (i % 6), ids[i]);
        group[48 + 2 * (i % 6)] = (unsigned char)usages[i];
        group[48 + 2 * (i % 6) + 1] = (unsigned char)(usages[i] >> 8);
        group[62] = (unsigned char)(i % 6 + 1);
    }
    *list = (struct adreno_resource_list){0};
    int e = adreno_resource_list_acquire(list, ib_wire, 32 + 64 * groups, ib_wire_copy, sizeof ib_wire_copy, slots, 48, &ibfx_ops);
    return e ? e : adreno_resource_list_prepare(list, &ibfx_ops);
}
static void ib_standard_fixtures(void)
{
    CHECK(ibfx_add(RT_ID, RT_VA, 0x8000) != 0);
    CHECK(ibfx_add(RO_ID, RO_VA, 0x4000) != 0);
}
static int ib_standard_list(struct adreno_resource_list *list, struct adreno_resource_entry *slots)
{
    static const uint32_t ids[] = {RT_ID, RO_ID};
    static const uint16_t usages[] = {ADRENO_USAGE_READ | ADRENO_USAGE_WRITE, ADRENO_USAGE_READ};
    return ib_list_make(list, slots, ids, usages, 2);
}
static uint8_t ib_command_bytes[0x10000];

/* ---- built-in checks --------------------------------------------------------------------------------------- */
static void test_ib_tables(void)
{
    CHECK(ib_tables.allowed_offsets == ADRENO_IB_KNOWN_OFFSETS - ADRENO_IB_KNOWN_PROTECTED);
    CHECK(ib_tables.address_rows == 23); /* exact draw baseline18 plus five explicit CS address registers */
    unsigned allowed = 0;
    for (uint32_t o = 0; o < ADRENO_IB_REG_LIMIT; o++) allowed += (unsigned)((ib_tables.allowed[o / 64] >> (o % 64)) & 1);
    CHECK(allowed == ib_tables.allowed_offsets);
    for (uint32_t p = 0; p < ADRENO_IB_PROTECT_COUNT; p++) {       /* no protected offset survives */
        uint32_t first = ADRENO_IB_PROTECT_REG(adreno_ib_protect[p]), last = first + ADRENO_IB_PROTECT_LEN(adreno_ib_protect[p]);
        for (uint32_t o = first; o <= last && o < ADRENO_IB_REG_LIMIT; o++) CHECK(!((ib_tables.allowed[o / 64] >> (o % 64)) & 1));
    }
}
static void test_ib_probe(void)
{
    ib_setup();
    uint64_t va, dwords, bytes;
    CHECK(adreno_ib_probe(&ib_work, &va, &dwords, &bytes) == 0);
    CHECK(va == IB_ARENA_VA + ADRENO_IB_PACKAGE_AT && dwords == 1 && bytes == ADRENO_IB_ALIGN);
    struct adreno_ib_reply reply;
    ib_ring(0, va, dwords, bytes, &reply);
    CHECK(adreno_ib_classify(&reply) == 0);
#if MONITOR_IB
    CHECK(cpm.ibs == 1 && cpm.fetched_dwords == 1 && cpm.fetched[0] == a8xx_pkt7_hdr(A8XX_E_CP_NOP, 0));
    CHECK(cpm.ib_writable == 0 && cpm.event_writes == 2 && cpm.waits == 1);
    /* A writable arena (no no-write DART bit) is refused before any ring write: IB off, nothing latched. */
    ib_setup();
    ib_map(IB_ARENA_VA, IB_ARENA_PA, IB_ARENA_PAGES, 0);
    CHECK(adreno_ib_probe(&ib_work, &va, &dwords, &bytes) == 0);
    unsigned writes = cpm.wptr_writes;
    ib_ring(0, va, dwords, bytes, &reply);
    CHECK(reply.status == ADRENO_E_TARGET && !reply.marker);
    CHECK(adreno_ib_classify(&reply) == ADRENO_SUBMIT_E_INACTIVE && cpm.wptr_writes == writes && cpm.ibs == 0);
#endif
}
static void test_ib_draw(void)
{
    ib_setup();
    ib_standard_fixtures();
    struct ib_pkg k;
    pk_draw(&k);
    size_t n = pk_serialize(&k, ib_command_bytes);
    CHECK(ib_standard_list(&ib_list, ib_entries) == 0);
    CHECK(ib_command(&ib_list, ib_command_bytes, n) == 0);
    CHECK(ib_ring_calls == 1 && ib_work.submitted == 1 && !ib_latch && !(ib_list.ready & ADRENO_LIST_FROZEN));
    /* F8: TO_DEVICE on both entries before the doorbell, FROM_DEVICE on the Write entry only, after it. */
    CHECK(ib_sync_log_n == 3 && ib_sync_log[0].direction == ADRENO_CACHE_TO_DEVICE &&
          ib_sync_log[1].direction == ADRENO_CACHE_TO_DEVICE && ib_sync_log[2].direction == ADRENO_CACHE_FROM_DEVICE &&
          ib_sync_log[2].address == RT_VA);
    /* F2/F3: the relocated package. */
    const uint8_t *p = ib_arena + ADRENO_IB_PACKAGE_AT;
    uint32_t w[32];
    memcpy(w, p, sizeof w);
    CHECK(w[4] == (uint32_t)RT_VA && w[6] == 0);
    CHECK(w[9] == ((uint32_t)IB_ARENA_VA | 3u) && w[11] == 0);
    CHECK(w[16] == (uint32_t)(RO_VA + 0x40) && w[17] == A8XX_DESC_A6XX_UBO_1__SIZE(4));
    CHECK(w[20] == (uint32_t)(IB_ARENA_VA + ADRENO_IB_PACKAGE_AT + pk_data_at(&k)) && w[21] == 0);
#if MONITOR_IB
    /* F10: the CP fetched exactly the validated words, from read-only mappings, after the monitor's clean. */
    CHECK(cpm.ibs == 1 && cpm.fetched_va == IB_ARENA_VA + ADRENO_IB_PACKAGE_AT && cpm.fetched_dwords == k.n);
    CHECK(!memcmp(cpm.fetched, p, 4ull * k.n) && cpm.ib_writable == 0);
    CHECK(S.ib_submits == 1 && S.ib_errors == 0);
    /* The relocated addresses walk through CB0 to the right pages with the right permission. */
    uint64_t rt = smmu_walk(RT_VA, 0), zero = smmu_walk(IB_ARENA_VA, 0);
    CHECK(rt && !(rt & ADRENO_PTE_RDONLY) && (rt & ADRENO_PTE_ADDR) == ibfx[0].pa);
    CHECK(zero && (zero & ADRENO_PTE_RDONLY) && (zero & ADRENO_PTE_ADDR) == IB_ARENA_PA);
#endif
    CHECK(adreno_resource_list_release(&ib_list, &ibfx_ops) == 0);
    CHECK(ibfx[0].retained == 0 && ibfx[1].retained == 0 && ibfx[0].prepared == 0);
}
/* One CS sampler load (CP_LOAD_STATE6_FRAG SB6_CS_TEX ST6_SHADER, indirect) of `units` S#s from a package table of
 * `table` zero S#s, DST_OFF `dst`, through the whole kext path: the submission's result. */
static int ib_cs_sampler_load(uint32_t units, uint32_t table, uint32_t dst)
{
    ib_setup();
    ib_standard_fixtures();
    struct ib_pkg k;
    memset(&k, 0, sizeof k);
    pk_pkt7(&k, A8XX_E_CP_SET_MARKER, 1); pk_word(&k, A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_COMPUTE));
    pk_pkt7(&k, A8XX_E_CP_LOAD_STATE6_FRAG, 3);
    pk_word(&k, A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF(dst) | A8XX_PKT_CP_LOAD_STATE6_0__STATE_TYPE(A8XX_E_ST6_SHADER) |
                A8XX_PKT_CP_LOAD_STATE6_0__STATE_SRC(A8XX_E_SS6_INDIRECT) |
                A8XX_PKT_CP_LOAD_STATE6_0__STATE_BLOCK(A8XX_E_SB6_CS_TEX) | A8XX_PKT_CP_LOAD_STATE6_0__NUM_UNIT(units));
    pk_word(&k, 0); pk_word(&k, 0);
    const uint32_t ext = k.n - 2;
    pk_pkt7(&k, A8XX_E_CP_EVENT_WRITE7, 1); pk_word(&k, A8XX_PKT_CP_EVENT_WRITE7_0__EVENT(A8XX_E_CACHE_CLEAN));
    k.data_bytes = 192;                                                              /* room for 12 S#s, zero */
    pk_reloc(&k, ext, ext + 1, ADRENO_IB_RELOC_PACKAGE, ADRENO_IB_ACCESS_READ, 4, 32, 0, pk_data_at(&k), 16ull * table);
    size_t n = pk_serialize(&k, ib_command_bytes);
    CHECK(ib_standard_list(&ib_list, ib_entries) == 0);
    int result = ib_command(&ib_list, ib_command_bytes, n);
    CHECK(adreno_resource_list_release(&ib_list, &ibfx_ops) == 0);
    return result;
}
/* CS sampler loads: one S# unit, the limit the validator has always had; with ADRENO_IB_CS_SAMPLERS, up to the count
 * the kext opts into (the boot-arg adreno_cs_samplers=1: ADRENO_IB_CS_SAMPLER_UNITS_MAX), still bounded by the table's
 * relocation and refused with a DST_OFF, and back to one unit for a count outside 1..MAX. */
static void test_ib_cs_samplers(void)
{
    CHECK(ib_cs_sampler_load(1, 1, 0) == 0);
    CHECK(ib_cs_sampler_load(2, 2, 0) == ADRENO_IB_E_PACKET);
    CHECK(ib_cs_sampler_load(1, 1, 1) == ADRENO_IB_E_PACKET);
#if ADRENO_IB_CS_SAMPLERS
    adreno_ib_set_cs_sampler_units(ADRENO_IB_CS_SAMPLER_UNITS_MAX);
    CHECK(ib_cs_sampler_load(1, 1, 0) == 0);
    CHECK(ib_cs_sampler_load(2, 2, 0) == 0);
    CHECK(ib_cs_sampler_load(ADRENO_IB_CS_SAMPLER_UNITS_MAX, ADRENO_IB_CS_SAMPLER_UNITS_MAX, 0) == 0);
    CHECK(ib_cs_sampler_load(ADRENO_IB_CS_SAMPLER_UNITS_MAX + 1, ADRENO_IB_CS_SAMPLER_UNITS_MAX + 1, 0) == ADRENO_IB_E_PACKET);
    CHECK(ib_cs_sampler_load(3, 2, 0) == ADRENO_IB_E_BOUNDS);           /* more S#s than the relocated table holds */
    CHECK(ib_cs_sampler_load(2, 2, 1) == ADRENO_IB_E_PACKET);
    adreno_ib_set_cs_sampler_units(0);
    CHECK(ib_cs_sampler_load(2, 2, 0) == ADRENO_IB_E_PACKET);
    adreno_ib_set_cs_sampler_units(ADRENO_IB_CS_SAMPLER_UNITS_MAX + 1);
    CHECK(ib_cs_sampler_load(2, 2, 0) == ADRENO_IB_E_PACKET);
    adreno_ib_set_cs_sampler_units(1);
#endif
}
/* F6: every reply the monitor can give, through the whole kext path (fake monitor replies). */
static void test_ib_replies(void)
{
    static const struct { int64_t status; uint64_t marker, wptr; int result, frozen, latched, from_device; uint32_t state; } cases[] = {
        {0, 0x534e7001u, 35, 0, 0, 0, 1, 0},
        {0, 0, 35, ADRENO_SUBMIT_E_UNCERTAIN, 1, 1, 0, ADRENO_IB_STATE_UNCERTAIN},            /* no marker */
        {0, 1, 8192, ADRENO_SUBMIT_E_UNCERTAIN, 1, 1, 0, ADRENO_IB_STATE_UNCERTAIN},          /* WPTR off the ring */
        {ADRENO_E_PARAMS, 0, 22, ADRENO_E_PARAMS, 0, 0, 0, 0},
        {ADRENO_E_WINDOW, 0, 22, ADRENO_E_WINDOW, 0, 0, 0, 0},
        {ADRENO_E_TARGET, 0, 22, ADRENO_E_TARGET, 0, 0, 0, 0},
        {ADRENO_E_CX, 0, 22, ADRENO_E_CX, 0, 0, 0, 0},
        {ADRENO_E_GX, 0, 22, ADRENO_E_GX, 0, 0, 0, 0},
        {ADRENO_E_HALT, 0, 22, ADRENO_E_HALT, 0, 0, 0, 0},
        {ADRENO_E_CB0, 0, 22, ADRENO_E_CB0, 0, 0, 0, 0},
        {ADRENO_E_FAULT, 0, 22, ADRENO_E_FAULT, 0, 0, 0, 0},
        {ADRENO_E_SQE, 0, 22, ADRENO_E_SQE, 0, 0, 0, 0},
        {ADRENO_E_RING, 0, 22, ADRENO_E_RING, 0, 0, 0, 0},
        {ADRENO_IB_E_BUSY, 0, 22, ADRENO_IB_E_BUSY, 0, 0, 0, 0},
        {ADRENO_IB_E_STICKY, 0, 22, ADRENO_IB_E_STICKY, 0, 0, 0, ADRENO_IB_STATE_DISABLED},
        {ADRENO_E_TARGET, 5, 22, ADRENO_SUBMIT_E_UNCERTAIN, 1, 1, 0, ADRENO_IB_STATE_UNCERTAIN},  /* refusal + marker */
        {ADRENO_IB_E_UNCERTAIN, 0, 57, ADRENO_SUBMIT_E_UNCERTAIN, 1, 1, 0, ADRENO_IB_STATE_UNCERTAIN},
        {ADRENO_IB_E_GPU_ERROR, 0, 57, ADRENO_IB_E_GPU_ERROR, 0, 0, 1, ADRENO_IB_STATE_DISABLED},
        {ADRENO_IB_E_GPU_ERROR, 9, 57, ADRENO_SUBMIT_E_UNCERTAIN, 1, 1, 0, ADRENO_IB_STATE_UNCERTAIN},
        {ADRENO_E_FENCE, 0, 22, ADRENO_SUBMIT_E_UNCERTAIN, 1, 1, 0, ADRENO_IB_STATE_UNCERTAIN},   /* not an IB refusal */
        {-1, 0, 22, ADRENO_SUBMIT_E_UNCERTAIN, 1, 1, 0, ADRENO_IB_STATE_UNCERTAIN},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ib_setup();
        ib_standard_fixtures();
        struct ib_pkg k;
        pk_draw(&k);
        size_t n = pk_serialize(&k, ib_command_bytes);
        CHECK(ib_standard_list(&ib_list, ib_entries) == 0);
        ib_fake.active = 1;
        ib_fake.reply = (struct adreno_ib_reply){cases[i].status, cases[i].marker, 7, cases[i].wptr};
        int result = ib_command(&ib_list, ib_command_bytes, n);
        CHECK(result == cases[i].result);
        CHECK(!!(ib_list.ready & ADRENO_LIST_FROZEN) == cases[i].frozen && ib_latch == cases[i].latched);
        CHECK(ib_cache_calls[ADRENO_CACHE_FROM_DEVICE] == (unsigned)cases[i].from_device &&
              ib_cache_calls[ADRENO_CACHE_TO_DEVICE] == 2);
        CHECK((ib_work.state & ~ADRENO_IB_STATE_READY) == cases[i].state && (ib_work.state & ADRENO_IB_STATE_READY));
        if (!cases[i].frozen) {
            CHECK(adreno_resource_list_release(&ib_list, &ibfx_ops) == 0);
        } else {   /* F7: an uncertain list keeps every reference and preparation */
            CHECK(adreno_resource_list_release(&ib_list, &ibfx_ops) == ADRENO_LIST_E_BUSY);
            CHECK(ib_list.prepared_count == 2 && ibfx[0].retained == 1 && ibfx[0].prepared == 1);
        }
        if (cases[i].state == ADRENO_IB_STATE_DISABLED) {   /* IB off, nothing latched: no more IB HVCs, FENCE goes on */
            unsigned rings = ib_ring_calls;
            CHECK(ib_standard_list(&ib_list, ib_entries) == 0);
            CHECK(ib_command(&ib_list, ib_command_bytes, n) == ADRENO_SUBMIT_E_INACTIVE && ib_ring_calls == rings);
            static const uint8_t fence[8] = {0x00, 0x10, 0, 0, 8, 0, 0, 0};
            CHECK(ib_command(&ib_list, fence, sizeof fence) == 0);
            CHECK(adreno_resource_list_release(&ib_list, &ibfx_ops) == 0);
        }
    }
}
/* F7: fail-fast after UNCERTAIN, the plan's M7 test: 10 later submissions, 10 error completions, 0 HVCs, 0 cache
 * maintenance, the uncertain submission's list and arena retained untouched. */
static void test_ib_fail_fast(void)
{
    ib_setup();
    ib_standard_fixtures();
    struct ib_pkg k;
    pk_draw(&k);
    size_t n = pk_serialize(&k, ib_command_bytes);
    struct adreno_resource_list uncertain;
    struct adreno_resource_entry uncertain_entries[48];
    CHECK(ib_standard_list(&uncertain, uncertain_entries) == 0);
#if MONITOR_IB
    cpm.stall = 1;                          /* the CP never consumes the ring: the monitor's poll times out */
#else
    ib_fake.active = 1;
    ib_fake.reply = (struct adreno_ib_reply){ADRENO_IB_E_UNCERTAIN, 0, 0, 57};
#endif
    CHECK(ib_command(&uncertain, ib_command_bytes, n) == ADRENO_SUBMIT_E_UNCERTAIN);
    CHECK(ib_latch == 1 && (uncertain.ready & ADRENO_LIST_FROZEN) && (ib_work.state & ADRENO_IB_STATE_UNCERTAIN));
#if MONITOR_IB
    CHECK(ib_work.reply.status == ADRENO_IB_E_UNCERTAIN && S.ib_submits == 1);
#endif
    static uint8_t snapshot[ADRENO_IB_ARENA_BYTES];
    memcpy(snapshot, ib_arena, sizeof snapshot);
    const unsigned rings = ib_ring_calls, writes = cpm.wptr_writes, fences = (unsigned)S.fences;
    const unsigned to_device = ib_cache_calls[1], from_device = ib_cache_calls[2];
    const uint64_t ib_submits = S.ib_submits;
    static const uint8_t fence[8] = {0x00, 0x10, 0, 0, 8, 0, 0, 0};
    uint8_t fill[32] = {0};
    put32(fill, ADRENO_KCMD_FILL32); put32(fill + 4, 32); put32(fill + 8, RT_ID); put32(fill + 12, 0x3c3c3c3c);
    put64(fill + 16, 0); put64(fill + 24, 0x100);
    unsigned errors = 0;
    for (unsigned i = 0; i < 10; i++) {
        struct adreno_resource_list later;
        struct adreno_resource_entry later_entries[48];
        CHECK(ib_standard_list(&later, later_entries) == 0);
        int result = i % 3 == 0 ? ib_command(&later, fence, sizeof fence) :
                     i % 3 == 1 ? ib_command(&later, fill, sizeof fill) : ib_command(&later, ib_command_bytes, n);
        errors += result == ADRENO_SUBMIT_E_INACTIVE;   /* AdrenoCommandQueue: setSubmissionError(0xa) */
        CHECK(!(later.ready & ADRENO_LIST_FROZEN));
        CHECK(adreno_resource_list_release(&later, &ibfx_ops) == 0);
    }
    CHECK(errors == 10);
    CHECK(ib_ring_calls == rings && cpm.wptr_writes == writes && S.fences == fences && S.ib_submits == ib_submits);
    CHECK(ib_cache_calls[1] == to_device && ib_cache_calls[2] == from_device);
    CHECK(!memcmp(snapshot, ib_arena, sizeof snapshot));
    CHECK(adreno_resource_list_release(&uncertain, &ibfx_ops) == ADRENO_LIST_E_BUSY);
    CHECK(uncertain.prepared_count == 2 && ibfx[0].retained == 1 && ibfx[1].retained == 1 && ibfx[0].prepared == 1);
    /* The kext's probe and stage refuse too: the arena is never written again. */
    uint64_t va, dwords, bytes;
    CHECK(adreno_ib_probe(&ib_work, &va, &dwords, &bytes) == ADRENO_SUBMIT_E_INACTIVE);
    CHECK(adreno_ib_stage(&ib_work, ib_command_bytes, n) == ADRENO_SUBMIT_E_INACTIVE);
    CHECK(!memcmp(snapshot, ib_arena, sizeof snapshot));
}
/* F9: the fence reply through the monitor's wrapping ring. */
static void test_fence_ring_wrap(void)
{
    struct adreno_resource_list list;
    struct adreno_resource_entry slots[48];
    for (unsigned c = 0; c < 8; c++) {
        ib_setup();
        ib_standard_fixtures();
        if (c == 1 || c >= 5) {             /* adopt with the CP idle two dwords before the end of the ring */
            q1n1_cp_fence(); P.flags &= ~(uint64_t)ADRENO_F_RING;
            P.ring_wptr = r.wptr = r.rptr = 8190;
            CHECK(adreno_adopt(&ib_ops, &P, &S, MEM_LOW, MEM_HIGH) == 0);
            memset(dart, 0, sizeof dart);
            ib_map(ADRENO_WINDOW_BASE, GUEST_PAGE, 1, 0);
            ib_map(RT_VA, ibfx[0].pa, 2, 0);
            ib_map(RO_VA, ibfx[1].pa, 1, 0);
        }
        int expect = 0;
        switch (c) {
        case 2: r.cx = 0; expect = ADRENO_SUBMIT_E_INACTIVE; break;
        case 3: r.pwr = 1; expect = ADRENO_SUBMIT_E_INACTIVE; break;
        case 4: r.sqe = 0; expect = ADRENO_SUBMIT_E_INACTIVE; break;
        case 5: r.drop_writes = 2; expect = ADRENO_SUBMIT_E_UNCERTAIN; break;   /* the wrap padding's doorbell dropped */
        case 6: cpm.stall = 1; expect = ADRENO_SUBMIT_E_UNCERTAIN; break;      /* rung, never retired: FENCE */
        case 7: r.drop_writes = 1; break;                                     /* one retry after the wrap */
        }
        uint64_t wptr_before = S.wptr;
        CHECK(ib_standard_list(&list, slots) == 0);
        static const uint8_t fence[8] = {0x00, 0x10, 0, 0, 8, 0, 0, 0};
        int result = ib_command(&list, fence, sizeof fence);
        CHECK(result == expect);
        CHECK(ib_latch == (expect == ADRENO_SUBMIT_E_UNCERTAIN));
        if (!expect && (c == 1 || c == 7)) CHECK(S.ring_wraps == 1 && S.wptr < wptr_before);   /* WPTR moved back */
        if (expect == ADRENO_SUBMIT_E_INACTIVE) CHECK(!(list.ready & ADRENO_LIST_FROZEN) && ib_cache_calls[2] == 0);
        if (expect != ADRENO_SUBMIT_E_UNCERTAIN) CHECK(adreno_resource_list_release(&list, &ibfx_ops) == 0);
        else CHECK(adreno_resource_list_release(&list, &ibfx_ops) == ADRENO_LIST_E_BUSY);
    }
}
#if MONITOR_IB
/* F6 through the real monitor: BUSY and STICKY before the doorbell, GPU_ERROR after it (IB off, list released). */
static void test_ib_monitor_states(void)
{
    for (unsigned c = 0; c < 3; c++) {
        ib_setup();
        ib_standard_fixtures();
        struct ib_pkg k;
        pk_draw(&k);
        size_t n = pk_serialize(&k, ib_command_bytes);
        CHECK(ib_standard_list(&ib_list, ib_entries) == 0);
        int expect = ADRENO_IB_E_BUSY;
        if (c == 0) cpm.rbbm_status = 1u << 30;
        if (c == 1) { cpm.int0 = 1u << 22; expect = ADRENO_IB_E_STICKY; }
        if (c == 2) { cpm.error_after_ib = 1; expect = ADRENO_IB_E_GPU_ERROR; }
        CHECK(ib_command(&ib_list, ib_command_bytes, n) == expect && !ib_latch);
        CHECK(!(ib_list.ready & ADRENO_LIST_FROZEN));
        CHECK(ib_cache_calls[2] == (c == 2) && cpm.ibs == (c == 2));
        CHECK(!!(ib_work.state & ADRENO_IB_STATE_DISABLED) == (c != 0));
        CHECK(adreno_resource_list_release(&ib_list, &ibfx_ops) == 0);
    }
}
#endif

/* ---- replay of a captured segment ---------------------------------------------------------------------------- */
static uint8_t *read_all(const char *dir, const char *name, size_t *length, int required)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { if (required) { fprintf(stderr, "missing %s\n", path); exit(2); } *length = 0; return 0; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *bytes = malloc(n > 0 ? (size_t)n + 1 : 1);
    if (!bytes || (n > 0 && fread(bytes, 1, (size_t)n, f) != (size_t)n)) exit(2);
    fclose(f);
    bytes[n > 0 ? n : 0] = 0;
    *length = (size_t)(n > 0 ? n : 0);
    return bytes;
}
static void write_all(const char *dir, const char *name, const void *bytes, size_t length)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(bytes, 1, length, f) != length || fclose(f)) { fprintf(stderr, "cannot write %s\n", path); exit(2); }
}
static int replay(const char *dir)
{
    size_t list_bytes, command_bytes, fixtures_bytes, expect_bytes;
    uint8_t *wire = read_all(dir, "list.bin", &list_bytes, 1);
    uint8_t *commands = read_all(dir, "commands.bin", &command_bytes, 1);
    char *fixtures = (char *)read_all(dir, "resources.txt", &fixtures_bytes, 1);
    char *expect = (char *)read_all(dir, "expect.txt", &expect_bytes, 0);
    ib_setup();
    for (char *line = strtok(fixtures, "\n"); line; line = strtok(0, "\n")) {
        unsigned long long id, va, length;
        if (sscanf(line, "%llx %llx %llx", &id, &va, &length) != 3 || !ibfx_add((uint32_t)id, va, length)) {
            fprintf(stderr, "bad fixture line: %s\n", line); exit(2);
        }
    }
    unsigned has_blob[IB_FIXTURES] = {0};
    for (unsigned i = 0; i < ibfx_count; i++) {
        char name[80]; size_t bytes;
        snprintf(name, sizeof name, "resource-%x.initial.bin", ibfx[i].id);
        uint8_t *blob = read_all(dir, name, &bytes, 0);
        if (!blob) continue;
        if (bytes != ibfx[i].res.logical_length || (bytes & 3)) {
            fprintf(stderr, "bad initial resource blob: %s\n", name); exit(2);
        }
        for (size_t off = 0; off < bytes; off += 4) {
            uint32_t value; memcpy(&value, blob + off, 4);
            m_wr(0, ibfx[i].pa + off, value);
        }
        has_blob[i] = 1;
        free(blob);
    }
    uint64_t snapshot_bytes = 0, capacity = 0;
    CHECK(adreno_resource_list_measure(wire, list_bytes, &snapshot_bytes, &capacity) == 0 && capacity <= IB_REPLAY_CAPACITY);
    uint8_t *copy = malloc(snapshot_bytes ? snapshot_bytes : 1);
    struct adreno_resource_list list = {0};
    CHECK(copy && adreno_resource_list_acquire(&list, wire, list_bytes, copy, snapshot_bytes, ib_entries, IB_REPLAY_CAPACITY, &ibfx_ops) == 0);
    CHECK(adreno_resource_list_prepare(&list, &ibfx_ops) == 0);
    char path[4096];
    snprintf(path, sizeof path, "%s/result.txt", dir);
    FILE *out = fopen(path, "w");
    if (!out) exit(2);
    fprintf(out, "monitor_ib %d\narena_gpu 0x%llx\npackage_gpu 0x%llx\nzero_gpu 0x%llx\n", MONITOR_IB,
            (unsigned long long)IB_ARENA_VA, (unsigned long long)(IB_ARENA_VA + ADRENO_IB_PACKAGE_AT),
            (unsigned long long)IB_ARENA_VA);
    int results[64], ncommands = 0;
    for (size_t at = 0; at + 8 <= command_bytes && ncommands < 64;) {
        uint32_t type, size;
        memcpy(&type, commands + at, 4);
        memcpy(&size, commands + at + 4, 4);
        if (size < 8 || size % 4 || size > command_bytes - at) { results[ncommands++] = ADRENO_SUBMIT_E_FORMAT; break; }
        const unsigned rings = ib_ring_calls, to_device = ib_cache_calls[1], from_device = ib_cache_calls[2];
#ifdef ADRENO_REPLAY_HEAD_DISPATCH
        /* HEAD 2cdbae5's AdrenoCommandQueue::processSegmentKernelCommand: FENCE, then FILL32, nothing else. */
        const struct adreno_kernel_ops kops = {&list, ib_k_fence, ib_k_fill, 0};
        int result = adreno_submit_command(commands + at, size, ib_k_fence, &list);
        if (result == ADRENO_SUBMIT_E_COMMAND) {
            struct adreno_fill32_request request;
            result = adreno_fill32_decode(commands + at, size, &request);
            if (!result) result = kops.fill(kops.context, &request);
        }
        if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY) adreno_resource_list_freeze(&list);
#else
        int result = ib_command(&list, commands + at, size);
#endif
        results[ncommands] = result;
        fprintf(out, "command %d type 0x%x size %u result %d rings %u to_device %u from_device %u frozen %d latched %u"
                     " error_at 0x%x reply %lld marker 0x%llx wptr %llu\n",
                ncommands, type, size, result, ib_ring_calls - rings, ib_cache_calls[1] - to_device,
                ib_cache_calls[2] - from_device, !!(list.ready & ADRENO_LIST_FROZEN), ib_latch, ib_work.error_at,
                (long long)ib_work.reply.status, (unsigned long long)ib_work.reply.marker,
                (unsigned long long)ib_work.reply.wptr);
        ncommands++;
        if (type == ADRENO_KCMD_IB && !result) {
            write_all(dir, "package.bin", ib_arena + ADRENO_IB_PACKAGE_AT, ib_work.package_bytes);
            snprintf(path, sizeof path, "%s/refs.txt", dir);
            FILE *refs = fopen(path, "w");
            if (!refs) exit(2);
            for (uint32_t i = 0; i < ib_work.command.reloc_count; i++) {
                const struct adreno_ib_reloc *x = &ib_relocs[i];
                uint32_t lo, hi = 0;
                memcpy(&lo, ib_arena + ADRENO_IB_PACKAGE_AT + x->lo, 4);
                if (x->hi != ADRENO_IB_RELOC_NO_HI) memcpy(&hi, ib_arena + ADRENO_IB_PACKAGE_AT + x->hi, 4);
                const uint32_t align = (1u << x->align_log2) - 1u;
                const uint64_t mask = x->hi == ADRENO_IB_RELOC_NO_HI ? 0 : x->hi_bits == 32 ? 0xffffffffu : (1u << x->hi_bits) - 1u;
                const uint64_t va = ((uint64_t)(hi & mask) << 32) | (lo & ~align);
                const uint64_t first = smmu_walk(va, 0), last = smmu_walk(va + x->length - 1, 0);
                fprintf(refs, "%u kind %u access %u id 0x%x lo 0x%x hi 0x%x va 0x%llx length 0x%llx first 0x%llx last 0x%llx"
                              " rdonly %d %d used %u\n", i, x->kind, x->access, x->resource_id, x->lo, x->hi,
                        (unsigned long long)va, (unsigned long long)x->length,
                        (unsigned long long)(first & ADRENO_PTE_ADDR), (unsigned long long)(last & ADRENO_PTE_ADDR),
                        !!(first & ADRENO_PTE_RDONLY), !!(last & ADRENO_PTE_RDONLY), ib_used[i]);
                CHECK(first && last);
                if (x->access & ADRENO_IB_ACCESS_WRITE) CHECK(!(first & ADRENO_PTE_RDONLY) && !(last & ADRENO_PTE_RDONLY));
                if (x->kind != ADRENO_IB_RELOC_RESOURCE) CHECK((first & ADRENO_PTE_RDONLY) && (last & ADRENO_PTE_RDONLY));
            }
            fclose(refs);
#if MONITOR_IB
            write_all(dir, "fetched.bin", cpm.fetched, 4ull * cpm.fetched_dwords);
            CHECK(cpm.fetched_dwords == ib_work.command.ib_dwords && cpm.fetched_dwords <= sizeof cpm.fetched / 4 &&
                  cpm.ib_writable == 0 &&
                  !memcmp(cpm.fetched, ib_arena + ADRENO_IB_PACKAGE_AT, 4ull * cpm.fetched_dwords));
#endif
        }
        if (result && result != ADRENO_SUBMIT_GENERIC) break;   /* IOGPU stops at the queue's error word */
        at += size;
    }
    fprintf(out, "list_frozen %d\n", !!(list.ready & ADRENO_LIST_FROZEN));
    fprintf(out, "copy_model packets %u bytes %llu observed_draws %u observed_dispatches %u\n",
            cpm.copies, (unsigned long long)cpm.copy_bytes, cpm.observed_draws, cpm.observed_dispatches);
    for (unsigned i = 0; i < ibfx_count; i++) {
        if (!has_blob[i]) continue;
        size_t bytes = (size_t)ibfx[i].res.logical_length;
        uint8_t *cpu = malloc(bytes);
        if (!cpu) exit(2);
        for (size_t off = 0; off < bytes; off += 4) {
            uint32_t value = m_rd(0, ibfx[i].pa + off);
            memcpy(cpu + off, &value, 4);
        }
        char name[80];
        snprintf(name, sizeof name, "resource-%x.final.bin", ibfx[i].id);
        write_all(dir, name, cpu, bytes);
        snprintf(name, sizeof name, "resource-%x.device.bin", ibfx[i].id);
        write_all(dir, name, dram + ram_offset(ibfx[i].pa, bytes), bytes);
        free(cpu);
    }
    if (expect)
        for (char *line = strtok(expect, "\n"); line; line = strtok(0, "\n")) {
            int index, code;
            if (sscanf(line, "%d %d", &index, &code) != 2) continue;
            CHECK(index < ncommands && results[index] == code);
            if (index < ncommands && results[index] != code)
                fprintf(stderr, "command %d: result %d, expected %d\n", index, results[index], code);
        }
    int frozen = !!(list.ready & ADRENO_LIST_FROZEN);
    if (!frozen) CHECK(adreno_resource_list_release(&list, &ibfx_ops) == 0);
    fprintf(out, "checks %u failures %u\n", checks, failures);
    fclose(out);
    free(wire); free(commands); free(fixtures); free(expect); free(copy);
    printf("%s: replay %s, %d commands, monitor_ib %d, %u checks\n", failures ? "FAIL" : "PASS", dir, ncommands, MONITOR_IB, checks);
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
#if MONITOR_IB && SNAP_ADRENO_IB_ASYNC
    const char *path = getenv("SNAP_IB_PATH");
    ib_async_path = !(path && !strcmp(path, "sync"));
#endif
    if (argc == 3 && !strcmp(argv[1], "--replay")) {
        dram = calloc(1, RAM_SIZE); cache = calloc(1, RAM_SIZE);
        ib_arena = aligned_alloc(0x4000, ADRENO_IB_ARENA_BYTES);
        if (!dram || !cache || !ib_arena || adreno_ib_tables_init(&ib_tables)) return 2;
#if ADRENO_IB_CS_SAMPLERS && defined(IB_REPLAY_CS_SAMPLER_UNITS)
        adreno_ib_set_cs_sampler_units(IB_REPLAY_CS_SAMPLER_UNITS);   /* as a kext booted with adreno_cs_samplers=1 */
#endif
        return replay(argv[2]);
    }
    if (argc != 1) return 64;
    if (fill_command_main()) return 1;
    checks = failures = 0;
    dram = calloc(1, RAM_SIZE); cache = calloc(1, RAM_SIZE);
    ib_arena = aligned_alloc(0x4000, ADRENO_IB_ARENA_BYTES);
    if (!dram || !cache || !ib_arena) return 2;
    CHECK(adreno_ib_tables_init(&ib_tables) == 0);
    test_ib_tables(); test_ib_probe(); test_ib_draw(); test_ib_cs_samplers(); test_ib_replies(); test_ib_fail_fast();
    test_fence_ring_wrap();
#if MONITOR_IB
    test_ib_monitor_states();
#endif
#if MONITOR_IB && SNAP_ADRENO_IB_ASYNC
    if (ib_async_path) CHECK(ib_async_starts > 0 && ib_async_polls > ib_async_starts);   /* the loop really waited */
#endif
    printf("%s: %u IB command checks; monitor_ib %d; allowlist, probe, relocated draw through CB0, %u monitor replies, "
           "fail-fast (10 later submissions, 0 HVCs), fence ring-wrap classification\n",
           failures ? "FAIL" : "PASS", checks, MONITOR_IB, 21u);
#if MONITOR_IB && SNAP_ADRENO_IB_ASYNC
    printf("IB path: %s (%u STARTs, %u POLLs)\n", ib_async_path ? "asynchronous START/POLL through the kext loop" :
           "synchronous ADRENO_GUEST_IB (SNAP_ADRENO_IB_ASYNC core)", ib_async_starts, ib_async_polls);
#endif
    free(dram); free(cache); free(ib_arena);
    return failures ? 1 : 0;
}
