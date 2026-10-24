/* SPDX-License-Identifier: MIT
 * Benchmark and verification for shadow MMU mapping optimizations.
 * Measures translation descent overhead and memory read reductions.
 *
 * cc -std=gnu11 -O2 -Wall -Wextra -Werror -fsanitize=address,undefined -Ishadow \
 *    tools/test-shadow-perf.c shadow/mmu.c shadow/shadow.c -o build/test-shadow-perf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "shadow.h"

#define RAM_BASE 0x40000000UL
#define RAM_SIZE (32UL << 20)
static uint8_t ram[RAM_SIZE];
static uint64_t next_table;
static uint64_t g_reads = 0;
static uint64_t g_writes = 0;

static int ram_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(out, &ram[pa - RAM_BASE], 8);
    g_reads++;
    return 0;
}

static int ram_write(void *ctx, uint64_t pa, uint64_t value)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(&ram[pa - RAM_BASE], &value, 8);
    g_writes++;
    return 0;
}

static uint64_t ram_alloc(void *ctx)
{
    (void)ctx;
    uint64_t p = next_table;
    next_table += 4096;
    if (p + 4096 > RAM_BASE + RAM_SIZE) return 0;
    memset(&ram[p - RAM_BASE], 0, 4096);
    return p;
}

static void reset_ram(void)
{
    memset(ram, 0, sizeof(ram));
    next_table = RAM_BASE + 0x100000;
    g_reads = 0;
    g_writes = 0;
}

int main(void)
{
    printf("=== Shadow MMU Optimization & Performance Verification ===\n");

    /* Test 1: Map 1024 distinct 16 KiB pages (macOS standard 16K kernel granule) */
    reset_ram();
    struct shadow s = {
        .txsz = 28, /* 36-bit VA */
        .root = ram_alloc(NULL),
        .alloc = ram_alloc,
        .read = ram_read,
        .write = ram_write,
        .ctx = NULL
    };

    clock_t t0 = clock();
    const unsigned count = 1024;
    for (unsigned i = 0; i < count; i++) {
        uint64_t va = 0x10000000UL + (uint64_t)i * 0x4000;
        uint64_t pa = 0x80000000UL + (uint64_t)i * 0x4000;
        if (shadow_map(&s, va, pa, 0x4000, PT_AF, PT_PXN | PT_UXN) < 0) {
            fprintf(stderr, "FAIL: shadow_map failed at index %u\n", i);
            return 1;
        }
    }
    clock_t t1 = clock();
    double elapsed_ms = (double)(t1 - t0) * 1000.0 / CLOCKS_PER_SEC;

    printf("Mapped %u 16 KiB pages (total %u KiB):\n", count, count * 16);
    printf("  Memory reads performed:  %llu\n", (unsigned long long)g_reads);
    printf("  Memory writes performed: %llu\n", (unsigned long long)g_writes);
    printf("  Elapsed time:            %.2f ms\n", elapsed_ms);

    /* Verify each mapped page with software mmu_walk */
    struct mmu_config cfg = {.granule_shift = 12, .txsz = s.txsz, .root = s.root};
    for (unsigned i = 0; i < count; i++) {
        for (unsigned page = 0; page < 4; page++) {
            uint64_t va = 0x10000000UL + (uint64_t)i * 0x4000 + page * 0x1000;
            uint64_t expected_pa = 0x80000000UL + (uint64_t)i * 0x4000 + page * 0x1000;
            struct mmu_leaf leaf;
            if (mmu_walk(&cfg, va, ram_read, NULL, &leaf) < 0 || !leaf.valid) {
                fprintf(stderr, "FAIL: translation missing for VA 0x%llx\n", (unsigned long long)va);
                return 1;
            }
            uint64_t resolved_pa = (leaf.descriptor & PT_OA_MASK) + (va - leaf.base);
            if (resolved_pa != expected_pa) {
                fprintf(stderr, "FAIL: mismatch PA for VA 0x%llx (got 0x%llx, expected 0x%llx)\n",
                        (unsigned long long)va, (unsigned long long)resolved_pa, (unsigned long long)expected_pa);
                return 1;
            }
        }
    }

    /* Test 2: Error handling & robustness */
    if (shadow_map(NULL, 0x1000, 0x1000, 0x1000, 0, 0) != -1) {
        fprintf(stderr, "FAIL: shadow_map accepted NULL s\n");
        return 1;
    }
    if (shadow_map(&s, 0x1001, 0x1000, 0x1000, 0, 0) != -1) {
        fprintf(stderr, "FAIL: shadow_map accepted misaligned VA\n");
        return 1;
    }
    if (shadow_map(&s, 0x1000, 0x1001, 0x1000, 0, 0) != -1) {
        fprintf(stderr, "FAIL: shadow_map accepted misaligned PA\n");
        return 1;
    }
    if (shadow_map(&s, 0x1000, 0x1000, 0x1001, 0, 0) != -1) {
        fprintf(stderr, "FAIL: shadow_map accepted misaligned size\n");
        return 1;
    }
    if (shadow_map(&s, 0x1000, 0x1000, 0, 0, 0) != 0) {
        fprintf(stderr, "FAIL: shadow_map non-zero on size 0\n");
        return 1;
    }

    printf("PASS: 100%% verified with mmu_walk across all %u pages, robust error handling validated\n", count * 4);
    return 0;
}
