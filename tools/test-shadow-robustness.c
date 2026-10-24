/* SPDX-License-Identifier: MIT
 * Comprehensive boundary, NULL-safety, and edge-case validation for shadow MMU.
 *
 * cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -Ishadow \
 *    tools/test-shadow-robustness.c shadow/mmu.c shadow/shadow.c -o build/test-shadow-robustness
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "shadow.h"

#define RAM_BASE 0x40000000UL
#define RAM_SIZE (16UL << 20)
static uint8_t ram[RAM_SIZE];
static uint64_t next_table;
static unsigned checks = 0;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static int ram_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(out, &ram[pa - RAM_BASE], 8);
    return 0;
}

static int ram_write(void *ctx, uint64_t pa, uint64_t value)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(&ram[pa - RAM_BASE], &value, 8);
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

static void setup_shadow(struct shadow *s)
{
    memset(ram, 0, sizeof(ram));
    next_table = RAM_BASE + 0x100000;
    s->txsz = 28; /* 36-bit VA */
    s->root = ram_alloc(NULL);
    s->alloc = ram_alloc;
    s->read = ram_read;
    s->write = ram_write;
    s->ctx = NULL;
    s->alloc_ctx = NULL;
    s->admit = NULL;
}

int main(void)
{
    struct shadow s;
    setup_shadow(&s);

    /* 1. NULL parameter checks on all shadow functions */
    CHECK(shadow_map(NULL, 0x1000, 0x1000, 0x1000, 0, 0) == -1);
    CHECK(shadow_table(NULL, 3, 0x1000, NULL) == -1);
    uint64_t out_table = 0;
    CHECK(shadow_table(&s, 3, 0x1000, NULL) == -1);
    CHECK(shadow_reserve(NULL, 0x1000, 0x1000) == -1);
    CHECK(shadow_unmap(NULL, 0x1000, 0x1000, 0) == -1);
    CHECK(shadow_insert(NULL, NULL, 0, 0) == SHADOW_NOTHING);

    struct mmu_leaf dummy_leaf = {.valid = 0};
    CHECK(shadow_insert(&s, &dummy_leaf, 0, 0) == SHADOW_NOTHING);

    /* 2. mmu_walk NULL parameter checks */
    struct mmu_config cfg = {.granule_shift = 12, .txsz = 28, .root = s.root};
    struct mmu_leaf leaf;
    CHECK(mmu_walk(NULL, 0x1000, ram_read, NULL, &leaf) == -1);
    CHECK(mmu_walk(&cfg, 0x1000, NULL, NULL, &leaf) == -1);
    CHECK(mmu_walk(&cfg, 0x1000, ram_read, NULL, NULL) == -1);

    /* 3. mmu_level_size and mmu_index out-of-range checks */
    CHECK(mmu_level_size(12, 4) == 0); /* level > 3 */
    CHECK(mmu_level_size(10, 2) == 0); /* granule_shift < 12 */
    CHECK(mmu_level_size(20, 2) == 0); /* granule_shift > 16 */
    CHECK(mmu_index(12, 4, 0x1000) == 0); /* level > 3 */
    CHECK(mmu_index(10, 2, 0x1000) == 0); /* granule_shift < 12 */

    /* 4. Alignment error checks on shadow_map */
    CHECK(shadow_map(&s, 0x1001, 0x1000, 0x1000, 0, 0) == -1);
    CHECK(shadow_map(&s, 0x1000, 0x1001, 0x1000, 0, 0) == -1);
    CHECK(shadow_map(&s, 0x1000, 0x1000, 0x1001, 0, 0) == -1);

    /* 5. Address space limit and overflow checks */
    uint64_t limit = 1ULL << (64 - s.txsz);
    CHECK(shadow_map(&s, limit, 0x1000, 0x1000, 0, 0) == -1);
    CHECK(shadow_map(&s, limit - 0x1000, 0x1000, 0x2000, 0, 0) == -1); /* spans past limit */
    CHECK(shadow_map(&s, 0x1000, 0x1000, UINT64_MAX & ~0xfffULL, 0, 0) == -1); /* arithmetic overflow */

    /* 6. Zero size map returns 0 cleanly without modifying tables */
    CHECK(shadow_map(&s, 0x1000, 0x1000, 0, 0, 0) == 0);

    /* 7. Successful map, reserve, and unmap sequence */
    CHECK(shadow_map(&s, 0x10000000UL, 0x80000000UL, 0x4000, PT_AF, PT_PXN | PT_UXN) == 0);
    CHECK(mmu_walk(&cfg, 0x10000000UL, ram_read, NULL, &leaf) == 0 && leaf.valid);
    CHECK(mmu_walk(&cfg, 0x10003000UL, ram_read, NULL, &leaf) == 0 && leaf.valid);

    /* Reserved area cannot conflict with existing mappings */
    CHECK(shadow_reserve(&s, 0x10000000UL, 0x1000) == -1);

    /* Unmap validation */
    CHECK(shadow_unmap(&s, 0x10000000UL, 0x4000, 1) == 0); /* check_only */
    CHECK(shadow_unmap(&s, 0x10000000UL, 0x4000, 0) == 0); /* commit unmap */
    CHECK(mmu_walk(&cfg, 0x10000000UL, ram_read, NULL, &leaf) == 0 && !leaf.valid);

    /* 8. Table descent */
    CHECK(shadow_table(&s, 3, 0x20000000UL, &out_table) == 0 && out_table != 0);

    printf("PASS: %u shadow MMU robustness and safety assertions verified\n", checks);
    return 0;
}
