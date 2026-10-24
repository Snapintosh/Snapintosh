/* SPDX-License-Identifier: MIT */
/* The Adreno virtual DART (dart-id 31): XNU's table-3 calls, the monitor's
 * admission of the model, and what the mirror makes of the committed leaves.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror -Icompat -Ishadow \
 *    tools/test-sptm-dart-adreno.c compat/sptm-dart.c compat/sptm-refs.c compat/sptm.c \
 *    compat/dart.c compat/device.c compat/adreno.c compat/irq-forward.c compat/aes.c \
 *    compat/aic.c compat/sep-pnon.c compat/sep-xars.c compat/watchdog.c \
 *    -o build/test-sptm-dart-adreno && build/test-sptm-dart-adreno
 *
 * The sequence is the one XNU's DART driver makes for dart-sio at boot and a
 * GPU client makes later: table 3 endpoint 6 (INIT) and 5 (POWERUP) on the
 * model, endpoint 0 (MAP_TABLE) for the level-1 root and a level-2 table,
 * endpoint 2 (MAP) from a page list, endpoint 8 (ENABLE), endpoint 3 (UNMAP).
 * The window is [1 GiB, 4 GiB): below the 0x4400000-page threshold, so TCR 1
 * and a two-level table, like SEP's streams 0/1 (compat/device.c POWERUP).
 * Built with -DADRENO_VA_WIDE=1 (agents/gpu-va-wide) the window is [1 GiB,
 * 16 GiB), still below the threshold (TCR 1, root level 1, slots 32..511):
 * the same calls run just below 4 GiB, at 4 GiB, above it and at the top,
 * and test_boundary maps, mirrors and unmaps across 4 GiB, which needs two
 * level-2 tables (slots 127 and 128) and SMMU root entries 3 and 4. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm-dart.h"
#include "sptm-refs.h"
#include "device.h"
#include "adreno.h"

#define BASE 0x8c0000000UL
#define SIZE 0x200000UL
#define FM (BASE + 0x4000)
#define ROOT (BASE + 0x140000)
#define LEAF (BASE + 0x144000)
#define LIST (BASE + 0x148000)
#define DATA (BASE + 0x14c000)
#define LEAF2 (BASE + 0x170000)                  /* test_boundary's second level-2 table */
#define ID 31u
static uint8_t ram[SIZE];
static struct dart_state state;
static struct sptm_ref_batch refs;
static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; printf("FAIL %d: %s\n", __LINE__, #x); } } while (0)
static uint8_t *meta(uint64_t pa) { return ram + (FM - BASE) + ((pa - BASE) >> 14) * 16; }
static uint64_t get(uint64_t pa) { uint64_t v; memcpy(&v, ram + (pa - BASE), 8); return v; }
static void put(uint64_t pa, uint64_t v) { memcpy(ram + (pa - BASE), &v, 8); }
static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t n)
{ return ctx == ram && pa >= BASE && pa < BASE + SIZE && n && n <= BASE + SIZE - pa ? ram + (pa - BASE) : 0; }
static void publish(void *ctx, uint64_t pa, uint64_t n) { CHECK(map(ctx, pa, n) != 0); }

static struct sptm_memory memory(void)
{
    memset(ram, 0, SIZE); memset(&refs, 0, sizeof(refs));
    for (unsigned level = 1; level < 3; level++) {
        uint8_t e[16] = {0, 0, 24, 0, 0, 0, 5, 0, ID, 0, (uint8_t)level, 0, 0, 0, 0, 0};
        memcpy(meta(level == 1 ? ROOT : LEAF), e, 16);
        if (level == 2) memcpy(meta(LEAF2), e, 16);
    }
    for (unsigned i = 0; i < 8; i++) { meta(DATA + i * 0x4000)[2] = 11; put(LIST + 8 * i, DATA + i * 0x4000); }
    meta(LIST)[2] = 11;
    return (struct sptm_memory){.frame_map_pa = FM, .frame_low = BASE, .frame_high = BASE + SIZE,
        .alloc_low = ROOT, .alloc_high = BASE + SIZE, .map = map, .publish = publish, .ctx = ram, .refs = &refs};
}

/* The model as probes/devicemodel.py dart_models binds dart-adreno. */
static const struct device_model adreno_dart = {DEVICE_DART_T8110_V1, 0x710000000UL, 0x20000,
    {16, DEVICE_DART_ADRENO_BOOT_V1, 976, 36, 1UL << 31}};

static void test_admission(void)
{
    struct device_model models[1] = {adreno_dart};
    static struct device_state states[1];
    memset(states, 0, sizeof(states));
    CHECK(device_models_valid(models, 1, 0, 0));
    CHECK(device_models_start(models, states, 1, 0, 24000000) == DEVICE_OK);
    unsigned index = 9;
    CHECK(device_dart_admit_frame(models, states, 1, 5, ID, 0, 1, &index) == DEVICE_BAD_VALUE);
    CHECK(device_dart_monitor_init(models, states, 1, ID) == DEVICE_OK);
    CHECK(device_dart_monitor_init(models, states, 1, ID) == DEVICE_BAD_VALUE);   /* once */
    CHECK(device_dart_monitor_powerup(models, states, 1, ID) == DEVICE_OK);
    CHECK(states[0].dart.tcr[0] == 1 && states[0].dart.tcr[1] == 1 && !states[0].dart.tcr[2]);
    CHECK(states[0].dart.powered_ids == 1U << ID && !states[0].dart.ttbr[0]);
    CHECK(device_dart_admit_frame(models, states, 1, 5, ID, 0, 1, &index) == DEVICE_OK && index == 0);
    CHECK(device_dart_admit_frame(models, states, 1, 5, ID, 1, 2, &index) == DEVICE_OK);
    CHECK(device_dart_admit_frame(models, states, 1, 5, ID, 2, 1, &index) == DEVICE_BAD_VALUE);
    CHECK(device_dart_admit_frame(models, states, 1, 5, 21, 0, 1, &index) == DEVICE_NOT_FOUND);
    CHECK(device_dart_admit_frame(models, states, 1, 4, ID, 0, 1, &index) == DEVICE_BAD_VALUE);
    /* The policy is exact: another id, stream count or span is not admitted. */
    struct device_model bad = adreno_dart;
    bad.config[4] = 1UL << 30; CHECK(!device_models_valid(&bad, 1, 0, 0));
    bad = adreno_dart; bad.config[0] = 3; CHECK(!device_models_valid(&bad, 1, 0, 0));
    bad = adreno_dart; bad.span = 0xc000; CHECK(!device_models_valid(&bad, 1, 0, 0));
    /* It must not sit on guest memory or the GPU aperture it stands for. */
    struct device_range keep[2] = {{BASE, SIZE}, {ADRENO_PA, ADRENO_END - ADRENO_PA}};
    CHECK(device_models_valid(models, 1, keep, 2));
    bad = adreno_dart; bad.base = ADRENO_PA; CHECK(!device_models_valid(&bad, 1, keep, 2));
}

static void powered(void)
{
    dart_init(&state);
    state.initialized_ids = state.powered_ids = 1U << ID;
    state.tcr[0] = state.tcr[1] = 1;
}

static void attach(struct sptm_memory *m, uint64_t va)
{
    CHECK(sptm_dart_map_table(m, &state, ID, 0, va, 0, ROOT) == SPTM_UNSUPPORTED_OPTIONS);
    CHECK(sptm_dart_map_table(m, &state, ID, 0, va, 1, ROOT) == SPTM_OK);
    CHECK(state.ttbr[0] == (ROOT >> 12 | 1));
    CHECK(sptm_dart_map_table(m, &state, ID, 0, va, 2, LEAF) == SPTM_OK);
    CHECK(get(ROOT + 8 * ((va >> 25) & 2047)) == (LEAF >> 4 | 1));
}

/* --- a flat arena and the SMMU registers adreno_mirror touches ------------- */
#define ARENA 0xfcc00000UL
#define POOL_AT 0x1400000UL                      /* the default pool's arena offset; wide: the same model place */
#define ARENA_MODEL (POOL_AT + ADRENO_POOL_BYTES > (32UL << 20) ? POOL_AT + ADRENO_POOL_BYTES : 32UL << 20)
static uint8_t *arena;
static unsigned tlbi_syncs;
static uint32_t o_rd(void *c, uint64_t pa)
{
    (void)c;
    if (pa == ADRENO_CX_CFG_GDSCR) return 1u << 16;
    if (pa == ADRENO_CB0 + ADRENO_CB_TLBSTATUS) return 0;
    abort();
}
static void o_wr(void *c, uint64_t pa, uint32_t v)
{
    (void)c; (void)v;
    if (pa == ADRENO_CB0 + ADRENO_CB_TLBSYNC) tlbi_syncs++;
    else if (pa != ADRENO_CB0 + ADRENO_CB_TLBIASID) abort();
}
static uint64_t o_rd64(void *c, uint64_t pa) { (void)c; uint64_t v; memcpy(&v, arena + (pa - ARENA), 8); return v; }
static void o_wr64(void *c, uint64_t pa, uint64_t v) { (void)c; memcpy(arena + (pa - ARENA), &v, 8); }
static void o_clean(void *c, uint64_t pa, uint64_t n) { (void)c; (void)pa; (void)n; }
static uint64_t t;
static uint64_t o_now(void *c) { (void)c; return t += 10; }
static const struct adreno_ops ops = {0, o_rd, o_wr, o_rd64, o_wr64, o_clean, o_now, 0, 1000000, 0
#if SNAP_ADRENO_COHERENT
                                     , 0   /* today's leaves (SNAP_ADRENO_COHERENT) */
                                     , 0   /* no PMU */
#endif
};
struct leaf_ctx { const struct sptm_memory *m; };
static uint64_t leaf(void *ctx, uint64_t iova)
{
    return sptm_dart_leaf(((struct leaf_ctx *)ctx)->m, &state, ID, 0, iova);
}
static uint64_t l3(const struct adreno_params *p, uint64_t va)
{
    return o_rd64(0, p->pool_pa + ADRENO_L3_OFFSET + ((va - ADRENO_WINDOW_BASE) >> 12) * 8);
}

static void test_calls(void)
{
#if ADRENO_VA_WIDE
    uint64_t addresses[] = {ADRENO_WINDOW_BASE, 0x7e000000, 0xffff8000, 0x100000000, 0x200000000,
                            ADRENO_WINDOW_END - 0x8000};
#else
    uint64_t addresses[] = {ADRENO_WINDOW_BASE, 0x7e000000, ADRENO_WINDOW_END - 0x8000};
#endif
    arena = calloc(1, ARENA_MODEL);
    for (unsigned n = 0; n < sizeof(addresses) / sizeof(addresses[0]); n++) for (unsigned flags = 0; flags < 4; flags++) {
        struct sptm_memory m = memory();
        powered();
        uint64_t va = addresses[n], pa = 0;
        attach(&m, va);
        CHECK(sptm_dart_map(&m, &state, ID, 0, va, LIST, 0x8000, flags) == SPTM_OK);
        CHECK(sptm_dart_enable(&m, &state, ID, 0) == SPTM_OK);
        for (int write = 0; write < 2; write++) {
            int permitted = !(flags & (write ? 2 : 1));
            CHECK(sptm_dart_dma_translate(&m, &state, ID, 0, va + 0x4008, 16, write, &pa) ==
                  (permitted ? SPTM_OK : SPTM_UNSUPPORTED_OPTIONS));
            if (permitted) CHECK(pa == DATA + 0x4008);
        }
        /* The descriptor the mirror reads is the committed one. */
        uint64_t d = sptm_dart_leaf(&m, &state, ID, 0, va + 0x4000);
        CHECK((d & 1) && ((d & 0x3ffffffc00UL) << 4) == DATA + 0x4000 && ((d >> 2) & 3) == (flags & 2 ? 1 : 0) + (flags & 1 ? 2 : 0));
        CHECK(sptm_dart_leaf(&m, &state, ID, 0, va + 0x8000) == 0);
        CHECK(sptm_dart_leaf(&m, &state, ID, 1, va) == 0);          /* stream 1: no table */
        /* MAP -> CB0: the monitor's hook after a successful endpoint 2. */
        memset(arena, 0, ARENA_MODEL);
        struct adreno_params p = {.flags = ADRENO_F_ENABLE | ADRENO_F_DART, .arena_base = ARENA,
            .arena_size = 32 << 20, .pool_pa = ARENA + POOL_AT};
        struct adreno_state s = {.status = ADRENO_S_ADOPTED | ADRENO_S_ATTACHED};
        struct leaf_ctx lc = {&m};
        CHECK(adreno_mirror(&ops, &p, &s, va, 0x8000, leaf, &lc, BASE, BASE + SIZE) == 0);
        uint64_t perm = flags & 2 ? ADRENO_PTE_RDONLY : 0;
        for (unsigned k = 0; k < 8; k++) {
            uint64_t want = flags & 1 ? 0 : (DATA + k * 0x1000) | ADRENO_PTE_LEAF | perm;
            CHECK(l3(&p, va + k * 0x1000) == want);
        }
        CHECK(s.refused == (flags & 1 ? 2u : 0u));                  /* write-only: not expressible */
        /* UNMAP -> invalidate before the call returns. */
        unsigned syncs = tlbi_syncs;
        CHECK(sptm_dart_unmap(&m, &state, ID, 0, va, 0x8000, 0) == SPTM_OK);
        CHECK(sptm_dart_leaf(&m, &state, ID, 0, va) == 0);
        CHECK(adreno_mirror(&ops, &p, &s, va, 0x8000, leaf, &lc, BASE, BASE + SIZE) == 0);
        CHECK(tlbi_syncs == syncs + (flags & 1 ? 0u : 1u));
        for (unsigned k = 0; k < 8; k++) CHECK(l3(&p, va + k * 0x1000) == 0);
        CHECK(s.live_pages == 0);
        /* Outside the Adreno window: refused before anything is written. */
        uint64_t invalid[] = {ADRENO_WINDOW_BASE - 0x4000, ADRENO_WINDOW_END, 1UL << 40, 0};
        for (unsigned i = 0; i < 4; i++)
            CHECK(sptm_dart_map(&m, &state, ID, 0, invalid[i], LIST, 0x4000, flags) == SPTM_BAD_ADDRESS);
        CHECK(sptm_dart_map(&m, &state, ID, 0, ADRENO_WINDOW_END - 4, LIST, 8, flags) == SPTM_BAD_ADDRESS);
    }
    /* A root entry outside slots 32..127 (32..511 wide) is a malformed table. */
    struct sptm_memory m = memory();
    powered();
    attach(&m, ADRENO_WINDOW_BASE);
    put(ROOT + 8 * 31, (LEAF >> 4) | 1);
    CHECK(sptm_dart_map(&m, &state, ID, 0, ADRENO_WINDOW_BASE, LIST, 0x4000, 0) != SPTM_OK);
    m = memory();
    powered();
    attach(&m, ADRENO_WINDOW_BASE);
    put(ROOT + 8 * (ADRENO_WINDOW_END >> 25), (LEAF >> 4) | 1);
    CHECK(sptm_dart_map(&m, &state, ID, 0, ADRENO_WINDOW_BASE, LIST, 0x4000, 0) != SPTM_OK);
    m = memory();
    powered();
    CHECK(sptm_dart_map_table(&m, &state, ID, 0, ADRENO_WINDOW_END, 1, ROOT) == SPTM_BAD_ADDRESS);
    /* SIO and SEP keep their own geometry. */
    m = memory();
    dart_init(&state);
    state.initialized_ids = state.powered_ids = 1U << 21;
    state.tcr[0] = 9;
    CHECK(sptm_dart_map_table(&m, &state, 21, 0, ADRENO_WINDOW_BASE, 0, ROOT) == SPTM_BAD_ADDRESS);
    free(arena);
}

/* Across 4 GiB (ADRENO_VA_WIDE): two level-2 tables, MAP below and above, one mirror over both, UNMAP of each
 * half (a single UNMAP may not cross a 32 MiB table), and the CB0 slots on both sides of root entries 3/4. */
static void test_boundary(void)
{
    struct sptm_memory m = memory();
    powered();
    const uint64_t below = 0x100000000UL - 0x8000, above = 0x100000000UL;
#if ADRENO_VA_WIDE
    attach(&m, below);
    CHECK(sptm_dart_map_table(&m, &state, ID, 0, above, 2, LEAF2) == SPTM_OK);
    CHECK(get(ROOT + 8 * 127) == (LEAF >> 4 | 1) && get(ROOT + 8 * 128) == (LEAF2 >> 4 | 1));
    CHECK(sptm_dart_map(&m, &state, ID, 0, below, LIST, 0x8000, 0) == SPTM_OK);
    CHECK(sptm_dart_map(&m, &state, ID, 0, above, LIST + 16, 0x8000, 2) == SPTM_OK);
    CHECK(sptm_dart_map(&m, &state, ID, 0, below, LIST, 0x10000, 0) != SPTM_OK);   /* one call, one table */
    uint64_t pa = 0;
    CHECK(sptm_dart_enable(&m, &state, ID, 0) == SPTM_OK);
    CHECK(sptm_dart_dma_translate(&m, &state, ID, 0, above + 0x4010, 8, 0, &pa) == SPTM_OK && pa == DATA + 0xc010);
    arena = calloc(1, ARENA_MODEL);
    struct adreno_params p = {.flags = ADRENO_F_ENABLE | ADRENO_F_DART, .arena_base = ARENA,
        .arena_size = 32 << 20, .pool_pa = ARENA + POOL_AT};
    struct adreno_state s = {.status = ADRENO_S_ADOPTED | ADRENO_S_ATTACHED};
    struct leaf_ctx lc = {&m};
    CHECK(adreno_mirror(&ops, &p, &s, below, 0x10000, leaf, &lc, BASE, BASE + SIZE) == 0);
    for (unsigned k = 0; k < 16; k++) {
        uint64_t want = (DATA + k * 0x1000) | ADRENO_PTE_LEAF | (k >= 8 ? ADRENO_PTE_RDONLY : 0);
        CHECK(l3(&p, below + k * 0x1000) == want);
    }
    /* Slots on both sides of 4 GiB sit in level-3 tables 1535 and 1536: the L2 tables of root entries 3 and 4. */
    CHECK(((below - ADRENO_WINDOW_BASE) >> 21) == 1535 && ((above - ADRENO_WINDOW_BASE) >> 21) == 1536);
    CHECK(s.live_pages == 16 && s.refused == 0);
    unsigned syncs = tlbi_syncs;
    CHECK(sptm_dart_unmap(&m, &state, ID, 0, below, 0x10000, 0) != SPTM_OK);      /* crosses the table */
    CHECK(sptm_dart_unmap(&m, &state, ID, 0, below, 0x8000, 0) == SPTM_OK);
    CHECK(sptm_dart_unmap(&m, &state, ID, 0, above, 0x8000, 0) == SPTM_OK);
    CHECK(adreno_mirror(&ops, &p, &s, below, 0x10000, leaf, &lc, BASE, BASE + SIZE) == 0);
    CHECK(tlbi_syncs == syncs + 1 && s.live_pages == 0);
    for (unsigned k = 0; k < 16; k++) CHECK(l3(&p, below + k * 0x1000) == 0);
    free(arena);
#else
    /* The default window ends at 4 GiB: nothing at or above it is mapped or mirrored. */
    attach(&m, below);
    CHECK(sptm_dart_map_table(&m, &state, ID, 0, above, 2, LEAF2) == SPTM_BAD_ADDRESS);
    CHECK(sptm_dart_map(&m, &state, ID, 0, above, LIST, 0x4000, 0) == SPTM_BAD_ADDRESS);
#endif
}

int main(void)
{
    test_admission();
    test_calls();
    test_boundary();
    if (failures) { printf("FAILED: %u of %u Adreno DART checks\n", failures, checks); return 1; }
    printf("PASS: %u Adreno virtual-DART admission, table-3 and mirror checks\n", checks);
    return 0;
}
