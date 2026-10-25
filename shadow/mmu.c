/* SPDX-License-Identifier: MIT */
/* See mmu.h. */
#include "mmu.h"
#include <string.h>

/* Index bits per level. A table is one granule of 8-byte entries, so a 16K
 * granule indexes 11 bits per level and a 4K granule 9 -- which is why the 16K
 * and 4K level boundaries do not line up and a shadow is a re-translation
 * rather than a structural rewrite of the guest's tables. */
static uint32_t index_bits(uint32_t granule_shift)
{
    return granule_shift - 3;
}

/* Lowest VA bit resolved by `level`. Level 3 resolves the granule offset. */
static uint32_t level_shift(uint32_t granule_shift, uint32_t level)
{
    return granule_shift + (3 - level) * index_bits(granule_shift);
}

uint64_t mmu_level_size(uint32_t granule_shift, uint32_t level)
{
    return 1UL << level_shift(granule_shift, level);
}

uint32_t mmu_index(uint32_t granule_shift, uint32_t level, uint64_t va)
{
    uint32_t bits = index_bits(granule_shift);
    return (uint32_t)((va >> level_shift(granule_shift, level)) & ((1UL << bits) - 1));
}

int mmu_block_allowed(uint32_t granule_shift, uint32_t level)
{
    /* 4K permits 1GB blocks at L1 and 2MB at L2. 16K and 64K permit blocks only
     * at L2 -- an L1 block would span 64GB and 4TB respectively, which the
     * architecture does not encode. Getting this wrong turns a table descriptor
     * into a huge bogus mapping, so it is checked rather than assumed. */
    if (granule_shift == 12) return level == 1 || level == 2;
    return level == 2;
}

int mmu_start_level(uint32_t granule_shift, uint32_t txsz)
{
    if (txsz > 39 || txsz < 16) return -1;
    uint32_t va_bits = 64 - txsz;
    if (va_bits <= granule_shift) return -1;
    uint32_t bits = index_bits(granule_shift);
    /* The first level whose index reaches the top VA bit. */
    uint32_t levels = (va_bits - granule_shift + bits - 1) / bits;
    if (levels < 1 || levels > 4) return -1;
    return (int)(4 - levels);
}

int mmu_walk(const struct mmu_config *cfg, uint64_t va, mmu_read_fn read, void *ctx,
             struct mmu_leaf *out)
{
    if (!cfg || !read || !out) return -1;
    memset(out, 0, sizeof(*out));

    if (cfg->granule_shift != 12 && cfg->granule_shift != 14 && cfg->granule_shift != 16)
        return -1;
    int level = mmu_start_level(cfg->granule_shift, cfg->txsz);
    if (level < 0) return -1;

    uint64_t table = cfg->root & PT_OA_MASK;
    uint32_t va_bits = 64 - cfg->txsz;
    /* Only the bits this regime translates; the caller is responsible for
     * having picked the right root for the top bits. */
    uint64_t address = va & (va_bits >= 64 ? ~0UL : ((1UL << va_bits) - 1));

    for (; level <= 3; level++) {
        uint64_t descriptor;
        uint64_t slot = table + 8UL * mmu_index(cfg->granule_shift, (uint32_t)level, address);
        if (read(ctx, slot, &descriptor)) return -1;

        if (!(descriptor & PT_VALID)) {
            out->level = (uint32_t)level;
            out->valid = 0;
            return 0;
        }

        int is_table = (descriptor & PT_TABLE) && level < 3;
        if (is_table) {
            table = descriptor & PT_OA_MASK;
            continue;
        }

        /* A level-3 leaf sets bit 1; a block at levels 0-2 clears it. Anything
         * else is a malformed descriptor, not a mapping. */
        if (level == 3) {
            if (!(descriptor & PT_TABLE)) {
                out->level = 3;
                out->valid = 0;
                return 0;
            }
        } else if (!mmu_block_allowed(cfg->granule_shift, (uint32_t)level)) {
            return -1;
        }

        uint64_t size = mmu_level_size(cfg->granule_shift, (uint32_t)level);
        out->descriptor = descriptor;
        out->base = address & ~(size - 1);
        out->size = size;
        out->pa = (descriptor & PT_OA_MASK & ~(size - 1)) | (address & (size - 1));
        out->level = (uint32_t)level;
        out->valid = 1;
        return 0;
    }
    return -1;
}
