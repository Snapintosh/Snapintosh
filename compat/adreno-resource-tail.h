/* SPDX-License-Identifier: MIT */
/* compat/adreno-resource-tail.h - agents/resident-evict (-DADRENO_RESIDENT_REPIN=1, AdrenoMemoryMap.cpp and
 * tools/test-adreno-residency.c): a backing descriptor shorter than its GPU map by less than one page.
 *
 * Why: IOGPU's memory length, which IOGPUMemoryMap::getLength returns and the kext binds as the map's logical length, is
 * the descriptor's DMA-map length in whole 16 KiB pages, while the descriptor holds exactly the client's bytes:
 *   IOGPUSysMemory::withClientBuffer (IOGPUFamily 26A428 0x56280): descriptor = withAddressRange(address, length, task)
 *     (memoryDescriptorWithClientBuffer 0x5621c); memory length (+0x38) = round_page(page offset + length) (0x56338-0x5636c).
 *   IOGPUSysMemory::withMemoryDescriptor (0x56d64): memory length = IOMemoryDescriptor::getDMAMapLength (0x56d8c).
 * The plug-in's newTextureWithBytesNoCopy passes the caller's length unrounded (AdrenoResources.m
 * AdrenoNewTextureNoCopy: sysMemSize = len). AdrenoMemoryMap::pinBacking refused every such descriptor
 * (getLength() < logical length: kIOReturnBadArgument, "map failed -83 native=0xe00002c2") on its first commit and
 * on every later one, and IOGPUMemory::commit_mappings (0x1323c) then failed every map of that memory
 * (kIOReturnNoMemory, "submission prepare failed 0xe00002bd"; the list: "preparation failed -115").
 *
 * The rules here, header-only so the host model runs exactly this arithmetic:
 *   admission  the shortfall lies inside the descriptor's last page (the descriptor starts page-aligned: the core's
 *              physical_page refuses an unaligned first page, so an unaligned client address stays refused);
 *   segments   a physically contiguous run that reaches the descriptor's end goes on to that page's end: the wire
 *              holds the whole page, and native DMA maps whole pages too;
 *   cache      nothing past the line that holds the descriptor's last byte; that line, when partial, is cleaned and
 *              invalidated (TO_DEVICE, dc civac) instead of invalidated (FROM_DEVICE, dc ivac), which would discard
 *              CPU data the client keeps beside the buffer in the same line. */
#pragma once
#include <stdint.h>
#include "adreno-resource.h"
#include "adreno-guest.h"

#define ADRENO_TAIL_PAGE 0x4000ull
#define ADRENO_TAIL_LINE 64ull

static inline uint64_t adreno_tail_round_page(uint64_t bytes)
{
    return (bytes + ADRENO_TAIL_PAGE - 1) & ~(ADRENO_TAIL_PAGE - 1);
}
/* A descriptor of `bytes` under a map of `logical` bytes: 1 when the map ends inside the descriptor's last page. */
static inline int adreno_tail_admit(uint64_t bytes, uint64_t logical)
{
    return bytes && bytes < logical && !(logical & (ADRENO_TAIL_PAGE - 1)) &&
           bytes <= UINT64_MAX - ADRENO_TAIL_PAGE && logical <= adreno_tail_round_page(bytes);
}
/* The contiguous bytes the core's physical callback reports at page offset `offset` of a descriptor of `bytes`, from
 * the descriptor's own run `span`: a run that ends exactly at the descriptor's end goes on to the end of that page. */
static inline uint64_t adreno_tail_span(uint64_t offset, uint64_t span, uint64_t bytes)
{
    if (!span || offset >= bytes || span != bytes - offset) return span;
    return adreno_tail_round_page(bytes) - offset;
}
/* Cache maintenance of [offset, offset + len) of the map for a descriptor of `bytes` (offset and len 64-byte aligned):
 * at most two ranges, in order, each with its direction; 0 when nothing of the descriptor is inside. */
struct adreno_tail_range { uint64_t offset, bytes; unsigned direction; };
static inline unsigned adreno_tail_cache_plan(uint64_t offset, uint64_t len, uint64_t bytes, unsigned direction,
                                              struct adreno_tail_range out[2])
{
    const uint64_t whole = bytes & ~(ADRENO_TAIL_LINE - 1);                       /* lines wholly the descriptor's */
    const uint64_t touched = (bytes + ADRENO_TAIL_LINE - 1) & ~(ADRENO_TAIL_LINE - 1);
    const uint64_t stop = len > touched || offset > touched - len ? touched : offset + len;
    unsigned n = 0;
    if (offset >= stop) return 0;
    if (direction == ADRENO_CACHE_FROM_DEVICE && whole < touched) {
        if (offset < whole) out[n++] = (struct adreno_tail_range){offset, (stop < whole ? stop : whole) - offset, direction};
        const uint64_t partial = offset > whole ? offset : whole;
        if (partial < stop) out[n++] = (struct adreno_tail_range){partial, stop - partial, ADRENO_CACHE_TO_DEVICE};
        return n;
    }
    out[n++] = (struct adreno_tail_range){offset, stop - offset, direction};
    return n;
}
/* adreno_resource_cache (whole map: offset 0, len logical_length) or its sparse form (any range of the logical extent,
 * rounded out to lines) for a map whose descriptor holds only `bytes`: the core's state, window and range rules first
 * (validation only), then the plan in chunks of at most ADRENO_CACHE_MAX_BYTES. */
static inline int adreno_tail_cache(const struct adreno_resource *r, uint64_t bytes, unsigned direction,
                                    uint64_t offset, uint64_t len,
                                    int (*maintain)(void *, uint64_t, uint64_t, unsigned), void *context)
{
    int e = adreno_resource_cache(r, 0, 0, 0);
    if (e) return e;
    if (direction > ADRENO_CACHE_FROM_DEVICE || (direction && !maintain)) return ADRENO_RESOURCE_E_STATE;
    if (!len || offset >= r->logical_length || len > r->logical_length - offset) return ADRENO_RESOURCE_E_RANGE;
    if (!direction) return 0;
    const uint64_t start = offset & ~(ADRENO_TAIL_LINE - 1);
    const uint64_t end = (offset + len + ADRENO_TAIL_LINE - 1) & ~(ADRENO_TAIL_LINE - 1);   /* <= logical_length */
    struct adreno_tail_range plan[2];
    const unsigned n = adreno_tail_cache_plan(start, end - start, bytes, direction, plan);
    for (unsigned i = 0; i < n; i++)
        for (uint64_t at = plan[i].offset; at < plan[i].offset + plan[i].bytes;) {
            uint64_t chunk = plan[i].offset + plan[i].bytes - at;
            if (chunk > ADRENO_CACHE_MAX_BYTES) chunk = ADRENO_CACHE_MAX_BYTES;
            if (maintain(context, r->address + at, chunk, plan[i].direction)) return ADRENO_RESOURCE_E_CACHE;
            at += chunk;
        }
    return 0;
}
