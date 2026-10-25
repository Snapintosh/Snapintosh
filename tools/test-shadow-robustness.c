/* SPDX-License-Identifier: MIT
 * Robustness, boundary, overflow, and NULL-safety regression tests for MMU,
 * Shadow MMU, Stage-2, DockChannel, MMIO decoder, and IRQ forwarding.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *    -Ishadow -Icompat tools/test-shadow-robustness.c shadow/mmu.c shadow/shadow.c \
 *    shadow/stage2.c shadow/dockchannel.c compat/mmio.c compat/irq-forward.c -o build/test-shadow-robustness
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mmu.h"
#include "shadow.h"
#include "stage2.h"
#include "dockchannel.h"
#include "mmio.h"
#include "irq-forward.h"

static unsigned g_checks = 0;

#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

#define RAM_BASE 0x40000000UL
#define RAM_SIZE (4UL << 20)
static uint8_t ram[RAM_SIZE];
static uint64_t next_table;

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

int main(void)
{
    memset(ram, 0, sizeof(ram));
    next_table = RAM_BASE + 0x10000;

    /* 1. MMU walker bounds & NULL safety */
    struct mmu_leaf leaf;
    struct mmu_config cfg = {.granule_shift = 12, .txsz = 28, .root = RAM_BASE};
    CHECK(mmu_walk(NULL, 0x1000, ram_read, NULL, &leaf) == -1);
    CHECK(mmu_walk(&cfg, 0x1000, NULL, NULL, &leaf) == -1);
    CHECK(mmu_walk(&cfg, 0x1000, ram_read, NULL, NULL) == -1);
    CHECK(mmu_level_size(11, 2) == 0);
    CHECK(mmu_level_size(12, 4) == 0);
    CHECK(mmu_index(11, 2, 0x1000) == 0);
    CHECK(mmu_index(12, 4, 0x1000) == 0);

    /* 2. Shadow MMU NULL & range boundary checks */
    struct shadow s = {
        .txsz = 28,
        .root = ram_alloc(NULL),
        .alloc = ram_alloc,
        .read = ram_read,
        .write = ram_write
    };
    CHECK(shadow_map(NULL, 0x1000, 0x1000, 0x1000, 0, 0) == -1);
    CHECK(shadow_insert(NULL, &leaf, 0, 0x1000) == SHADOW_NOTHING);
    CHECK(shadow_insert(&s, NULL, 0, 0x1000) == SHADOW_NOTHING);
    CHECK(shadow_reserve(NULL, 0x1000, 0x1000) == -1);
    CHECK(shadow_unmap(NULL, 0x1000, 0x1000, 0) == -1);

    /* Address space limit overflow rejection */
    uint64_t limit = 1ULL << (64 - s.txsz);
    CHECK(shadow_map(&s, limit, 0x1000, 0x1000, 0, 0) == -1);
    CHECK(shadow_map(&s, limit - 0x1000, 0x1000, 0x2000, 0, 0) == -1);

    /* 3. Stage-2 NULL & invalid parameter safety */
    struct stage2_range r = {.lo = 0x1000, .hi = 0x2000, .low = S2_AP_RW | S2_ATTRS, .upper = 0};
    CHECK(stage2_build(NULL, &r, 1) == STAGE2_BAD_RANGES);
    CHECK(stage2_build(&s, NULL, 1) == STAGE2_BAD_RANGES);
    CHECK(stage2_split(NULL, 0x1000) == 0);

    /* 4. DockChannel NULL & ring buffer underflow safety */
    struct dockchannel dc = {0};
    struct dc_rx rx = {0};
    uint64_t val = 0;
    uint8_t tx[4] = {0};
    unsigned tx_len = 99;
    CHECK(dc_narrow(NULL, 0x1234) == 0);
    CHECK(dc_extend(NULL, 0x1234) == 0);
    CHECK(dc_shape(NULL, 2) == 0);
    CHECK(dc_window(NULL, NULL, 2, 0, &val) == -1);
    CHECK(dc_read(NULL, 0, 0, &val) == DC_UNMODELLED);
    CHECK(dc_read(&dc, 0, 0, NULL) == DC_UNMODELLED);
    CHECK(dc_write(NULL, 0, 0, 0, tx, &tx_len) == DC_UNMODELLED && tx_len == 0);
    CHECK(dc_write(&dc, 0, 0, 0, NULL, &tx_len) == DC_UNMODELLED);
    CHECK(dc_write(&dc, 0, 0, 0, tx, NULL) == DC_UNMODELLED);
    CHECK(dc_rx_free(NULL) == 0);
    rx.count = DC_RX_RING + 10; /* Corrupted count > ring size must not underflow */
    CHECK(dc_rx_free(&rx) == 0);
    CHECK(dc_rx_push(NULL, 0x41) == -1);
    CHECK(dc_read_rx(&dc, &rx, 0, 0, NULL) == DC_UNMODELLED);

    /* 5. MMIO LDP64 signed immediate underflow/overflow & NULL completion guards */
    uint64_t regs[31] = {0};
    struct mmio_pair pair;
    const uint64_t esr = (0x24UL << 26) | (1UL << 25) | 4UL;
    /* ldp x0, x1, [x2, #-8] when x2 == 0 must be rejected, not wrap around UINT64_MAX */
    uint32_t ldp_neg8 = 0xa9400440U | (127u << 15);
    regs[2] = 0;
    CHECK(mmio_ldp64_decode(ldp_neg8, esr, regs, 0, &pair) == 0);
    /* ldp x0, x1, [sp] with unaligned SP must be rejected */
    CHECK(mmio_ldp64_decode(0xa94007e0U, esr, regs, 0x1008, &pair) == 0);
    mmio_ldp64_complete(NULL, regs, regs);
    mmio_ldr32_pre_complete(NULL, 0, regs, &val);

    /* 6. IRQ Forwarding NULL safety */
    struct irqfwd fwd = {0};
    struct irqfwd_ops empty_ops = {0};
    CHECK(irqfwd_physical(NULL, &empty_ops, 100) == IRQFWD_BAD);
    CHECK(irqfwd_physical(&fwd, NULL, 100) == IRQFWD_BAD);
    CHECK(irqfwd_physical(&fwd, &empty_ops, 100) == IRQFWD_BAD);
    irqfwd_unmasked(NULL, &empty_ops, 0, 1);
    irqfwd_unmasked(&fwd, NULL, 0, 1);
    irqfwd_quiesce(NULL, &empty_ops);
    irqfwd_quiesce(&fwd, NULL);

    printf("PASS: %u robustness, overflow, and NULL-safety assertions verified\n", g_checks);
    return 0;
}
