/* SPDX-License-Identifier: MIT */
#pragma once
/* SNAP_SPTM_FINE_KERNEL (compat/fine-lock.h; agents/sptm-locks/FAILURE-MODES.md
 * S5-S9, S12, S19): the kernel root's MAP_PAGE and UNMAP_REGION as converted
 * calls. probes/xnuboot.c runs these with the gate shared and the kernel lock
 * held, on this CPU's fine memory (atomic reference deltas). Header-only so the
 * host harness (tools/test-sptm-fine.c) runs the same code.
 *
 * What makes the token path's kernel_refresh unnecessary here: the call writes
 * only level-3 entries of canonical 4K kernel shadow tables that no kernel view
 * copies (copied() is 0 for each, checked before any store), and it allocates
 * nothing (the path must already exist; the shadow's allocator refuses). Every
 * view therefore still reaches each written table through an unchanged
 * descriptor, the views' reuse snapshot still describes them exactly, and the
 * next token-path refresh proves reuse as before.
 *
 * TLB: a leaf whose four 4K shadow descriptors were all invalid needs no
 * invalidation (no TLB holds a faulting entry: hw_walk_after_add's rule);
 * otherwise tlbi() invalidates the 16K by VA in every guest VMID before the
 * references commit. UNMAP_REGION invalidates its whole range before the call
 * returns (its references commit inside sptm_mac_unmap_region; the frames stay
 * pinned by the gate and, with SNAP_SPTM_FINE_RETYPE, by their frame locks,
 * until after that TLBI: S5).
 *
 * Every refusal before the first store is DECLINE (the token path repeats the
 * call and makes its own report, failure or answer) or COPIED; a failure after
 * a store is FATAL with the token path's map_page_failed reason in fail. */
#include "sptm.h"
#include "sptm-refs.h"
#include "mmu.h"
#include "shadow.h"

enum sptm_fine_kernel_end {
    SPTM_FINE_K_DONE, SPTM_FINE_K_DECLINE, SPTM_FINE_K_COPIED, SPTM_FINE_K_FATAL
};
/* MAP_PAGE's failure reasons after the store (probes/xnuboot.c MAP_FAIL_*). */
#define SPTM_FINE_K_FAIL_WRITE_LEAF 4u
#define SPTM_FINE_K_FAIL_REREAD 5u
#define SPTM_FINE_K_FAIL_SHADOW_INSERT 6u
#define SPTM_FINE_K_FAIL_SHADOW_ABSENT 7u
#define SPTM_FINE_K_FAIL_SHADOW_WRONG 8u
#define SPTM_FINE_K_FAIL_LEAF_INVALID 9u
#define SPTM_FINE_K_FAIL_SHADOW_EMPTY 10u

struct sptm_fine_kernel {
    const struct sptm_memory *m;      /* this CPU's fine memory (batch, snapshots, publish) */
    struct shadow *shadow;            /* the canonical kernel 4K shadow: refusing alloc, converted writer */
    mmu_read_fn guest_read;           /* the guest's 16K tables (mem_read) */
    int (*guest_write)(void *ctx, uint64_t pa, uint64_t value);   /* the converted mem_write */
    int (*copied)(void *ctx, uint64_t table);                     /* 1: a kernel-view copy source */
    void (*tlbi)(void *ctx, uint64_t va, uint64_t size);          /* every VMID, completed */
    void (*clean_out)(void *ctx, volatile uint64_t *out);         /* the output words to the PoU */
    void *ctx;
    const struct sptm_aperture *aperture;
    const struct sptm_moved *moved;
    uint32_t t1sz;
    /* Out. */
    uint64_t status, old, fail, fail_va, fail_detail, invalidated;
    int moved_pointer;
};

/* The level-3 shadow table holding va (4K regime): 1 and *table when every
 * level above is a table descriptor; 0 when a level is invalid (an insert
 * would allocate; nothing is mapped below it); -1 for a block or a read
 * failure. */
static inline int sptm_fine_kernel_l3(const struct shadow *s, uint64_t va, uint64_t *table)
{
    int start = mmu_start_level(12, s->txsz);
    if (start < 0 || !s->read) return -1;
    uint64_t t = s->root & PT_OA_MASK;
    for (unsigned level = (unsigned)start; level < 3; level++) {
        uint64_t d;
        if (s->read(s->ctx, t + 8UL * mmu_index(12, level, va), &d)) return -1;
        if (!(d & PT_VALID)) return 0;
        if (!(d & PT_TABLE)) return -1;
        t = d & PT_OA_MASK;
    }
    *table = t;
    return 1;
}

/* MAP_PAGE on the kernel root, after the caller refused SPRR classes 2, 4 and
 * 9, a root outside guest RAM and a PTE outside it (the token path's logged
 * cases). out: this CPU's output words, or 0. The token path's order: walk,
 * slot, plan, references, guest store, outputs, guest re-read, shadow insert,
 * shadow read-back, invalidation, commit. */
static inline enum sptm_fine_kernel_end sptm_fine_kernel_map(struct sptm_fine_kernel *k,
    uint64_t root, uint64_t va, uint64_t new_pte, volatile uint64_t *out)
{
    const struct sptm_memory *m = k->m;
    struct shadow *s = k->shadow;
    int start = mmu_start_level(14, k->t1sz);
    if (start < 0 || !m || !s || !k->copied || !k->tlbi || !k->guest_read || !k->guest_write)
        return SPTM_FINE_K_DECLINE;
    uint64_t table = root;
    for (int level = start; level < 3; level++) {
        uint64_t entry;
        if (k->guest_read(k->ctx, table + 8UL * mmu_index(14, (uint32_t)level, va), &entry) ||
            (entry & 3) != 3 || (entry & 0x3000UL)) return SPTM_FINE_K_DECLINE;        /* the token path answers TABLE_NOT_PRESENT */
        table = entry & 0x0000ffffffffc000UL;
        if (m->frame_low && (table < m->frame_low || table > m->frame_high - 0x4000UL))
            return SPTM_FINE_K_DECLINE;
    }
    uint64_t slot = table + 8UL * mmu_index(14, 3, va), existing = 0;
    if (m->frame_low && (slot < m->frame_low || slot > m->frame_high - 8UL))
        return SPTM_FINE_K_DECLINE;
    if (k->guest_read(k->ctx, slot, &existing) || (new_pte & 3) != 3) return SPTM_FINE_K_DECLINE;
    k->old = existing;
    struct sptm_kernel_leaf plan;
    if (sptm_mac_kernel_map_leaf(k->aperture, k->moved, slot, existing, new_pte, &plan) || !plan.install)
        return SPTM_FINE_K_DECLINE;                              /* a conflict reports on the token path */
    /* The shadow side, before any store: an existing path to a level-3 table
     * no view copies (S8, S9), and whether any of its four leaves is valid. */
    uint64_t va_off = va & ((UINT64_C(1) << (64 - k->t1sz)) - 1), l3 = 0;
    if ((va_off & 0x3fff) || sptm_fine_kernel_l3(s, va_off, &l3) != 1 || k->copied(k->ctx, l3))
        return SPTM_FINE_K_COPIED;
    int fresh = 1;
    for (unsigned j = 0; j < 4; j++) {
        uint64_t d;
        if (s->read(s->ctx, l3 + 8UL * mmu_index(12, 3, va_off + j * 0x1000), &d)) return SPTM_FINE_K_DECLINE;
        if (d & PT_VALID) fresh = 0;
    }
    sptm_refs_begin(m->refs);
    if (sptm_refs_leaf(m, table, va, existing, new_pte) || sptm_refs_validate(m)) return SPTM_FINE_K_DECLINE;
    k->fail_va = va;
    if (k->guest_write(k->ctx, slot, new_pte)) {
        k->fail = SPTM_FINE_K_FAIL_WRITE_LEAF; k->fail_detail = slot; return SPTM_FINE_K_FATAL;
    }
    k->moved_pointer = plan.pointer != sptm_aperture_pointer(k->aperture, slot, 8);
    if (out) {
        out[0] = existing;
        out[1] = plan.pointer;
        if (k->clean_out) k->clean_out(k->ctx, out);
    }
    struct mmu_config guest = {.granule_shift = 14, .txsz = k->t1sz, .root = root};
    struct mmu_leaf leaf;
    if (mmu_walk(&guest, va, k->guest_read, k->ctx, &leaf) < 0) {
        k->fail = SPTM_FINE_K_FAIL_REREAD; k->fail_detail = new_pte; return SPTM_FINE_K_FATAL;
    }
    if (!leaf.valid) {
        k->fail = SPTM_FINE_K_FAIL_LEAF_INVALID; k->fail_detail = new_pte; return SPTM_FINE_K_FATAL;
    }
    int put = shadow_insert(s, &leaf, va_off, va_off + (UINT64_C(1) << 14));
    if (put < 0) {k->fail = SPTM_FINE_K_FAIL_SHADOW_INSERT; k->fail_detail = 0; return SPTM_FINE_K_FATAL;}
    if (put == SHADOW_NOTHING) {
        k->fail = SPTM_FINE_K_FAIL_SHADOW_EMPTY; k->fail_detail = leaf.base; return SPTM_FINE_K_FATAL;
    }
    struct mmu_config view = {.granule_shift = 12, .txsz = k->t1sz, .root = s->root};
    struct mmu_leaf got;
    uint64_t want = leaf.descriptor & PT_OA_MASK & ~(leaf.size - 1);
    if (mmu_walk(&view, va_off, s->read, s->ctx, &got) < 0 || !got.valid) {
        k->fail = SPTM_FINE_K_FAIL_SHADOW_ABSENT; k->fail_detail = s->root; return SPTM_FINE_K_FATAL;
    }
    uint64_t resolved = (got.descriptor & PT_OA_MASK & ~(got.size - 1)) + (va_off - got.base);
    if (resolved != want) {
        k->fail = SPTM_FINE_K_FAIL_SHADOW_WRONG; k->fail_detail = resolved; return SPTM_FINE_K_FATAL;
    }
    k->invalidated = 0;
    if (!fresh) {k->tlbi(k->ctx, va, UINT64_C(1) << 14); k->invalidated = 1;}
    sptm_refs_commit(m);
    k->status = plan.status;
    return SPTM_FINE_K_DONE;
}

/* UNMAP_REGION on the kernel root: sptm_mac_unmap_region on the converted
 * memory and shadow, after checking that every shadow leaf it could remove is
 * a level-3 entry of a table no view copies (a block, or a copied table:
 * COPIED), then the range's invalidation in every VMID. */
static inline enum sptm_fine_kernel_end sptm_fine_kernel_unmap(struct sptm_fine_kernel *k,
    uint64_t root, uint64_t va, uint64_t count, uint64_t options, uint64_t scratch, enum sptm_result *result)
{
    struct shadow *s = k->shadow;
    *result = SPTM_OK;
    if (!k->m || !s || !k->copied || !k->tlbi || (va & 0x3fff) || va < UINT64_C(0xffff800000000000) ||
        !count || count > 2048 || count > (UINT64_MAX - va) / 0x4000 || s->txsz != 17)
        return SPTM_FINE_K_DECLINE;                              /* the engine refuses: token path */
    uint64_t off = va & ((UINT64_C(1) << 47) - 1), end = off + count * 0x4000;
    for (uint64_t at = off; at < end;) {
        uint64_t l3 = 0, next = (at | (UINT64_C(0x200000) - 1)) + 1;
        int path = sptm_fine_kernel_l3(s, at, &l3);
        if (path < 0 || (path > 0 && k->copied(k->ctx, l3))) return SPTM_FINE_K_COPIED;
        at = next;
    }
    enum sptm_result r = sptm_mac_unmap_region(k->m, s, root, va, count, options, scratch);
    if (r) {*result = r; return SPTM_FINE_K_DECLINE;}           /* the caller decides by its store count */
    k->tlbi(k->ctx, va, count * 0x4000);
    k->invalidated = 1;
    return SPTM_FINE_K_DONE;
}
