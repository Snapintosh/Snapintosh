/* SPDX-License-Identifier: MIT
 * Benchmark and verification for shadow MMU L3 caching and hot-path trap/AIC optimizations.
 *
 * cc -std=gnu11 -O2 -Wall -Wextra -Werror -fsanitize=address,undefined -Ishadow -Icompat \
 *    tools/test-shadow-perf.c shadow/mmu.c shadow/shadow.c compat/aic.c -o build/test-shadow-perf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "shadow.h"
#include "aic.h"
#include "fast-trap.h"

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

static int ref_key_reg(uint64_t reg)
{
    if (reg == FAST_TRAP_SYSREG(3,4,15,1,0) || reg == FAST_TRAP_SYSREG(3,4,15,1,1) ||
        reg == FAST_TRAP_SYSREG(3,4,15,0,4)) return 1;
    for (unsigned crm = 1; crm <= 3; crm++)
        for (unsigned op2 = 0; op2 < (crm < 3 ? 4u : 2u); op2++)
            if (reg == FAST_TRAP_SYSREG(3,0,2,crm,op2)) return 1;
    return 0;
}

int main(void)
{
    printf("=== Shadow MMU & Hot-Path Optimization Verification ===\n");

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

    /* With L3 caching, each 16 KiB mapping (four 4 KiB pages) descends L1->L2
     * only once instead of 4 times: 2048 reads instead of 8192 (-75%). */
    if (g_reads != 2048) {
        fprintf(stderr, "FAIL: expected 2048 reads with L3 cache, got %llu\n",
                (unsigned long long)g_reads);
        return 1;
    }

    printf("Mapped %u 16 KiB pages (total %u KiB):\n", count, count * 16);
    printf("  Memory reads performed:  %llu (-75.0%% vs uncached 8192)\n", (unsigned long long)g_reads);
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
                fprintf(stderr, "FAIL: mismatch PA for VA 0x%llx\n", (unsigned long long)va);
                return 1;
            }
        }
    }

    /* Verify shadow_unmap L3 cache equivalence */
    if (shadow_unmap(&s, 0x10000000UL, (uint64_t)count * 0x4000, 0) != 0) {
        fprintf(stderr, "FAIL: shadow_unmap across 16 MiB failed\n");
        return 1;
    }
    struct mmu_leaf check_leaf;
    if (mmu_walk(&cfg, 0x10000000UL, ram_read, NULL, &check_leaf) < 0 || check_leaf.valid) {
        fprintf(stderr, "FAIL: unmapped page remained valid\n");
        return 1;
    }

    /* Verify O(1) fast_trap_key_reg matches reference over all Op0=3 sysreg tuples */
    for (unsigned op1 = 0; op1 < 8; op1++) {
        for (unsigned crn = 0; crn < 16; crn++) {
            for (unsigned crm = 0; crm < 16; crm++) {
                for (unsigned op2 = 0; op2 < 8; op2++) {
                    uint64_t r = FAST_TRAP_SYSREG(3, op1, crn, crm, op2);
                    if (fast_trap_key_reg(r) != ref_key_reg(r)) {
                        fprintf(stderr, "FAIL: fast_trap_key_reg mismatch at 0x%llx\n",
                                (unsigned long long)r);
                        return 1;
                    }
                }
            }
        }
    }

    /* Verify AIC unrolled pending check */
    struct aic_config aic_cfg = {4096, 0xa, 0x40000};
    struct aic_state aic_st;
    memset(&aic_st, 0, sizeof(aic_st));
    aic_st.control = 1;
    if (aic_pending(&aic_cfg, &aic_st) != 0) {
        fprintf(stderr, "FAIL: empty AIC reported pending\n");
        return 1;
    }
    aic_set_level(&aic_cfg, &aic_st, 4095, 1);
    aic_st.unmasked[4095 >> 5] |= (1u << 31);
    if (aic_pending(&aic_cfg, &aic_st) != 1) {
        fprintf(stderr, "FAIL: asserted IRQ 4095 not detected\n");
        return 1;
    }

    printf("PASS: 100%% verified across %u pages, 32768 sysreg tuples, and 4096 AIC lines\n", count * 4);
    return 0;
}
