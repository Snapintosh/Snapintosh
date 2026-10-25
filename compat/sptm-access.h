/* SPDX-License-Identifier: MIT */
/* The SPTM model's 8-byte accesses to guest memory (compat/sptm*.c,
 * compat/txm-copy.c): one single-copy-atomic load or store for every
 * naturally aligned 8-byte field, page-table descriptors above all.
 *
 * Why (installed-fresh-20261018-v67, docs/USER-HW-WALK-20261017.md "v67").
 * Every model file had its own get64/put64 that moved the value byte by byte
 * through a volatile uint8_t pointer, so -Os emitted eight STRBs, lowest byte
 * first (sptm_mac_map_user_page: an lsr/strb loop that even spilled its
 * pointer between bytes). With SNAP_USER_HW_WALK the hardware walks XNU's own
 * user tables while the model writes them, and another CPU running a thread
 * of the same process walked a new leaf after its low four bytes (valid bit,
 * attributes, OA[31:12]) and before its high ones: v67's HPFAR named IPA
 * 0x60e3f030 for a leaf whose OA is 0x960e3f000. Every stage-2 stop since
 * v62 is that IPA with OA[47:32] cleared: 0x2fdde030 and 0x36f0f200 fall in
 * level-1 entry 0, whose level-2 table has no entry there (level-2 faults),
 * 0xa5ce3000 and 0x60e3f030 in level-1 entries 2 and 1, which are invalid
 * (level-1 faults).
 *
 * A misaligned field (never a descriptor: table slots are 8-aligned by
 * construction) keeps the byte copy, out of line in sptm_get_bytes /
 * sptm_put_bytes, the only functions tools/test-descriptor-stores.py lets
 * hold a byte-wise 8-byte access. */
#pragma once
#include <stdint.h>

__attribute__((noinline)) static uint64_t sptm_get_bytes(const volatile uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
__attribute__((noinline)) static void sptm_put_bytes(volatile uint8_t *p, uint64_t v, unsigned n)
{
    for (unsigned i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static inline uint64_t sptm_get64(const volatile uint8_t *p)
{
    if (!((uintptr_t)p & 7)) return *(const volatile uint64_t *)(const volatile void *)p;
    return sptm_get_bytes(p, 8);
}
static inline void sptm_put64(volatile uint8_t *p, uint64_t v)
{
    if (!((uintptr_t)p & 7)) {*(volatile uint64_t *)(volatile void *)p = v; return;}
    sptm_put_bytes(p, v, 8);
}
