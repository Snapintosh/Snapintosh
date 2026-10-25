/* SPDX-License-Identifier: MIT */
/* See shadow.h. */
#include "shadow.h"

#define G 12u                       /* the shadow is always a 4K regime */

/* Descend to `level`, creating tables on the way. Returns the table PA that
 * contains the entry for `va` at that level. */
static int descend(struct shadow *s, uint32_t level, uint64_t va, uint64_t *table)
{
    int start = mmu_start_level(G, s->txsz);
    if (start < 0 || level < (uint32_t)start || level > 3) return -1;

    uint64_t current = s->root & PT_OA_MASK;
    for (uint32_t l = (uint32_t)start; l < level; l++) {
        uint64_t slot = current + 8UL * mmu_index(G, l, va);
        uint64_t descriptor;
        if (s->read(s->ctx, slot, &descriptor)) return -1;

        if (descriptor & PT_VALID) {
            /* A block already covering this range means an earlier insert used
             * a larger descriptor. Splitting it is a different operation than
             * mapping, and silently overwriting it would lose the mapping it
             * carries, so refuse rather than corrupt. */
            if (!(descriptor & PT_TABLE)) return -1;
            current = descriptor & PT_OA_MASK;
            continue;
        }

        uint64_t fresh = shadow_alloc_page(s);
        if (!fresh) return -1;
        if (s->write(s->ctx, slot, (fresh & PT_OA_MASK) | PT_VALID | PT_TABLE)) return -1;
        current = fresh;
    }
    *table = current;
    return 0;
}

int shadow_table(struct shadow *s, uint32_t level, uint64_t va, uint64_t *table)
{
    if (!s || !table || !s->read || !s->write || !s->alloc || s->txsz < 16 ||
        s->txsz > 39 || va >= (1UL << (64 - s->txsz))) return -1;
    return descend(s, level, va, table);
}

static int put(struct shadow *s, uint32_t level, uint64_t va, uint64_t descriptor)
{
    uint64_t table;
    if (descend(s, level, va, &table)) return -1;
    return s->write(s->ctx, table + 8UL * mmu_index(G, level, va), descriptor);
}

int shadow_reserve(struct shadow *s, uint64_t va, uint64_t size)
{
    if (!s || !s->alloc || !s->read || !s->write || s->txsz < 16 || s->txsz > 39 ||
        !size || ((va | size) & 0xfff) || va >= (1UL << (64-s->txsz)) ||
        size > (1UL << (64-s->txsz))-va) return -1;
    uint64_t cached_l3_table = 0, cached_l3_base = UINT64_MAX;
    for (uint64_t at=va; at<va+size; at+=0x1000) {
        uint64_t value, l3_base = at & ~((1ULL << 21) - 1);
        if (!cached_l3_table || cached_l3_base != l3_base) {
            if (descend(s,3,at,&cached_l3_table)) return -1;
            cached_l3_base = l3_base;
        }
        if (s->read(s->ctx,cached_l3_table+8UL*mmu_index(12,3,at),&value) || value) return -1;
    }
    return 0;
}

int shadow_map(struct shadow *s, uint64_t va, uint64_t pa, uint64_t size,
               uint64_t low, uint64_t upper)
{
    if (!s || !s->read || !s->write || !s->alloc || s->txsz < 16 || s->txsz > 39) return -1;
    if ((va | pa | size) & 0xfff) return -1;
    if (!size) return 0;

    uint64_t limit = 1ULL << (64 - s->txsz);
    if (va >= limit || size > limit - va) return -1;

    /* The contiguous hint describes a run of 16 entries in the granule that
     * declared it. Carrying it across granules would promise the TLB a
     * contiguity the shadow does not have, so it is dropped. */
    low &= PT_LEAF_ATTRS;
    upper &= PT_LEAF_UPPER;
    if (s->admit && !s->admit(s->ctx,va,pa,size,low,upper)) return -1;

    /* Cache resolved level-3 table PA within each 2 MiB VA span so consecutive
     * 4 KiB page insertions bypass repeated L0->L2 root descents. */
    uint64_t cached_l3_table = 0;
    uint64_t cached_l3_base = UINT64_MAX;

    while (size) {
        uint32_t level = 3;
        uint64_t step = 1UL << 12;

        /* Largest descriptor whose alignment and remaining size both fit. */
        for (uint32_t candidate = 1; candidate <= 2; candidate++) {
            if (!mmu_block_allowed(G, candidate)) continue;
            uint64_t span = mmu_level_size(G, candidate);
            if (size >= span && !((va | pa) & (span - 1))) {
                level = candidate;
                step = span;
                break;
            }
        }

        /* Level 3 leaves set bit 1; blocks at levels 1 and 2 clear it. */
        uint64_t descriptor = (pa & PT_OA_MASK) | low | upper | PT_VALID;
        if (level == 3) {
            descriptor |= PT_TABLE;
            uint64_t l3_base = va & ~((1ULL << 21) - 1);
            if (!cached_l3_table || cached_l3_base != l3_base) {
                if (descend(s, 3, va, &cached_l3_table)) return -1;
                cached_l3_base = l3_base;
            }
            if (s->write(s->ctx, cached_l3_table + 8UL * mmu_index(G, 3, va), descriptor))
                return -1;
        } else {
            cached_l3_base = UINT64_MAX;
            cached_l3_table = 0;
            if (put(s, level, va, descriptor)) return -1;
        }

        va += step;
        pa += step;
        size -= step;
    }
    return 0;
}

int shadow_insert(struct shadow *s, const struct mmu_leaf *leaf,
                  uint64_t clip_start, uint64_t clip_end)
{
    if (!s || !leaf || !leaf->valid) return SHADOW_NOTHING;

    uint64_t start = leaf->base, end = leaf->base + leaf->size;
    if (start < clip_start) start = clip_start;
    if (end > clip_end) end = clip_end;
    /* An empty range after clipping. Usually the clip and the leaf are in
     * different address spaces, which is not a thing this can detect from here
     * -- but it is a thing the caller must not mistake for a mapping. */
    if (start >= end) return SHADOW_NOTHING;

    /* The leaf's output address for its own base, then offset to the clip. */
    uint64_t pa = (leaf->descriptor & PT_OA_MASK & ~(leaf->size - 1)) + (start - leaf->base);
    return shadow_map(s, start, pa, end - start,
                      leaf->descriptor & PT_LEAF_ATTRS, leaf->descriptor & PT_LEAF_UPPER);
}

int shadow_unmap(struct shadow *s, uint64_t va, uint64_t size, int check_only)
{
    if (!s || s->txsz < 16 || s->txsz > 39 || !s->read || !s->write ||
        ((va | size) & 0xfff) || va >= (1UL << (64-s->txsz)) ||
        size > (1UL << (64-s->txsz)) - va) return -1;
    struct mmu_config cfg = {.granule_shift=12, .txsz=s->txsz, .root=s->root};
    /* Validate every removal before touching the first descriptor. */
    for (unsigned pass=0; pass<(check_only ? 1u : 2u); pass++) {
        uint64_t at=va, end=va+size;
        uint64_t cached_l3_table = 0, cached_l3_base = UINT64_MAX;
        while (at<end) {
            struct mmu_leaf leaf;
            if (mmu_walk(&cfg,at,s->read,s->ctx,&leaf)) return -1;
            uint64_t span=mmu_level_size(12,leaf.level);
            uint64_t next=(at & ~(span-1))+span;
            if (leaf.valid) {
                if (at!=leaf.base || next>end) return -1;
                if (pass) {
                    uint64_t table;
                    if (leaf.level == 3) {
                        uint64_t l3_base = at & ~((1ULL << 21) - 1);
                        if (!cached_l3_table || cached_l3_base != l3_base) {
                            if (descend(s, 3, at, &cached_l3_table)) return -1;
                            cached_l3_base = l3_base;
                        }
                        table = cached_l3_table;
                    } else {
                        cached_l3_table = 0;
                        cached_l3_base = UINT64_MAX;
                        if (descend(s,leaf.level,at,&table)) return -1;
                    }
                    if (s->write(s->ctx,table+8UL*mmu_index(12,leaf.level,at),0)) return -1;
                }
            }
            at=next;
        }
    }
    return 0;
}

#if SNAP_DETACH_FAST
int shadow_range_empty(const struct shadow *s, uint64_t va, uint64_t size)
{
    if (!s || s->txsz < 16 || s->txsz > 39 || !s->read || !s->write ||
        ((va | size) & 0xfff) || va >= (1UL << (64-s->txsz)) ||
        size > (1UL << (64-s->txsz)) - va) return -1;
    int start = mmu_start_level(G, s->txsz);
    if (start < 0) return -1;
    uint64_t at = va, end = va + size;
    while (at < end) {
        uint64_t table = s->root & PT_OA_MASK, d = 0;
        uint32_t level = (uint32_t)start;
        for (;; level++) {
            if (s->read(s->ctx, table + 8UL * mmu_index(G, level, at), &d)) return -1;
            if (!(d & PT_VALID)) break;
            if (!(d & PT_TABLE) || level >= 3) return -1;
            if (level == 2) break;
            table = d & PT_OA_MASK;
        }
        uint64_t span = mmu_level_size(G, level), next = (at & ~(span - 1)) + span;
        if (d & PT_VALID) {
            /* The level-3 table of this 2 MiB: as mmu_walk, a leaf is bits1:0 = 3. */
            uint64_t l3 = d & PT_OA_MASK, stop = next < end ? next : end;
            for (uint64_t x = at; x < stop; x += 0x1000) {
                uint64_t e;
                if (s->read(s->ctx, l3 + 8UL * mmu_index(G, 3, x), &e)) return -1;
                if ((e & 3) == 3) return 0;
            }
        }
        if (next <= at) return -1;
        at = next;
    }
    return 1;
}
#endif

long shadow_build(struct shadow *s, const struct mmu_config *guest,
                  uint64_t start, uint64_t end, mmu_read_fn guest_read, void *guest_ctx)
{
    long inserted = 0;
    uint64_t va = start;

    while (va < end) {
        struct mmu_leaf leaf;
        if (mmu_walk(guest, va, guest_read, guest_ctx, &leaf) < 0) return -1;

        if (!leaf.valid) {
            /* Skip the whole region the failed level covers, not one page: a
             * missing level-1 entry means nothing below it is mapped either,
             * and stepping by 4K through a 64GB hole does not terminate in any
             * useful time. */
            uint64_t span = mmu_level_size(guest->granule_shift, leaf.level);
            va = (va & ~(span - 1)) + span;
            continue;
        }

        int put_leaf = shadow_insert(s, &leaf, start, end);
        if (put_leaf < 0) return -1;
        if (put_leaf == 0) inserted++;
        va = leaf.base + leaf.size;
    }
    return inserted;
}
