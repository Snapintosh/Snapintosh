/* SPDX-License-Identifier: MIT */
/* See stage2.h. */
#include "stage2.h"

#define G 12u                       /* stage 2 here is always a 4K regime */

static int readonly_walk(struct shadow *s, uint64_t lo, uint64_t hi, int commit)
{
    int start=mmu_start_level(G,s->txsz);
    for(uint64_t at=lo;at<hi;) {
        uint64_t table=s->root,desc=0,slot=0,span=0;
        unsigned level;
        for(level=(unsigned)start;level<=3;level++) {
            slot=table+8UL*mmu_index(G,level,at);
            if(s->read(s->ctx,slot,&desc) || !(desc&PT_VALID))return -1;
            if(level<3 && (desc&PT_TABLE)) {
                if(desc!=((desc&PT_OA_MASK)|3))return -1;
                table=desc&PT_OA_MASK;
                continue;
            }
            if(level==3 ? !(desc&PT_TABLE) : !mmu_block_allowed(G,level))return -1;
            span=mmu_level_size(G,level);
            break;
        }
        if(!span || (at&(span-1)) || span>hi-at ||
           (desc&PT_OA_MASK)!=at ||
           ((desc&PT_AP)!=S2_AP_RO && (desc&PT_AP)!=S2_AP_RW) ||
           (desc&~(PT_OA_MASK|PT_AP|S2_XN|3UL))!=S2_ATTRS)return -1;
        if(commit && (desc&(1UL<<7)) &&
           s->write(s->ctx,slot,desc&~(1UL<<7)))return -1;
        at+=span;
    }
    return 0;
}

int stage2_readonly(struct shadow *s, uint64_t lo, uint64_t hi, int validate_only)
{
    if(!s || !s->read || !s->write || s->txsz<16 || s->txsz>39 ||
       !s->root || (s->root&~PT_OA_MASK) ||
       lo>=hi || ((lo|hi)&0xfff) || hi>(1UL<<(64-s->txsz)))
        return STAGE2_BAD_RANGES;
    if(readonly_walk(s,lo,hi,0))return -1;
    return validate_only ? 0 : readonly_walk(s,lo,hi,1);
}

int stage2_build(struct shadow *s, const struct stage2_range *ranges, unsigned count)
{
    if (!s || !ranges || !count || s->txsz < 16 || s->txsz > 39) return STAGE2_BAD_RANGES;
    uint64_t limit = 1UL << (64 - s->txsz);
    for (unsigned n = 0; n < count; n++) {
        const struct stage2_range *r = &ranges[n];
        if (r->lo >= r->hi || ((r->lo | r->hi) & 0xfff) || r->hi > limit)
            return STAGE2_BAD_RANGES;
        /* Disjoint from every earlier range. Where two ranges meet at the same
         * level shadow_map writes the later leaf over the earlier one, and
         * where they meet at different levels it refuses; neither is a map of
         * both, so the list is checked before a descriptor is written. */
        for (unsigned m = 0; m < n; m++)
            if (r->lo < ranges[m].hi && ranges[m].lo < r->hi) return STAGE2_BAD_RANGES;
    }
    for (unsigned n = 0; n < count; n++) {
        const struct stage2_range *r = &ranges[n];
        if (shadow_map(s, r->lo, r->lo, r->hi - r->lo, r->low, r->upper)) return -1;
    }
    return 0;
}

/* Replace the block at `slot` with a table of 512 pieces that together say
 * exactly what the block said. `span` is the block's size. Level-3 pieces are
 * pages and carry bit 1; a block clears it. */
static int split_block(struct shadow *s, uint64_t slot, uint64_t block, uint64_t span,
                       int pieces_are_pages, uint64_t *table_out)
{
    uint64_t table = shadow_alloc_page(s);
    if (!table) return -1;
    uint64_t piece = span / 512;
    uint64_t base = block & PT_OA_MASK & ~(span - 1);
    /* Everything but the address: the valid bit, the low attributes and the
     * upper attributes, carried onto every piece unchanged. */
    uint64_t attrs = block & ~PT_OA_MASK;
    if (pieces_are_pages) attrs |= PT_TABLE;
    for (unsigned n = 0; n < 512; n++)
        if (s->write(s->ctx, table + 8UL * n, (base + n * piece) | attrs)) return -1;
    if (s->write(s->ctx, slot, (table & PT_OA_MASK) | PT_VALID | PT_TABLE)) return -1;
    *table_out = table;
    return 0;
}

uint64_t stage2_split(struct shadow *s, uint64_t ipa)
{
    if (!s || !s->read || !s->write || !s->alloc) return 0;
    int start = mmu_start_level(G, s->txsz);
    if (start < 0 || start > 2) return 0;
    uint64_t address = ipa & ((1UL << (64 - s->txsz)) - 1);
    uint64_t table = s->root & PT_OA_MASK;
    for (uint32_t level = (uint32_t)start; level <= 2; level++) {
        uint64_t slot = table + 8UL * mmu_index(G, level, address);
        uint64_t descriptor;
        if (s->read(s->ctx, slot, &descriptor)) return 0;
        if (!(descriptor & PT_VALID)) return 0;
        if (descriptor & PT_TABLE) {
            table = descriptor & PT_OA_MASK;
            continue;
        }
        if (!mmu_block_allowed(G, level)) return 0;
        if (split_block(s, slot, descriptor, mmu_level_size(G, level), level == 2, &table))
            return 0;
    }
    return table;
}
