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
 *              CPU data the client keeps beside the buffer in the same line.
 *
 * The head rule (-DADRENO_RESIDENT_HEAD_OFFSET=1 with ADRENO_RESIDENT_REPIN, below): the same arithmetic for a
 * descriptor that starts `head` bytes into its first page, which the tail rule leaves refused. */
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

/* ---- the head rule: a descriptor that starts inside its first page (-DADRENO_RESIDENT_HEAD_OFFSET=1) ----
 *
 * Why: withClientBuffer sizes the memory as round_page(page offset + length) (above), so a client buffer at a
 * page-unaligned address gets a map that reaches one page past round_page(length). The tail rule refuses it: the
 * shortfall is more than a page, and the first segment does not start a page. OBSERVED twice on the A16 (b12v23 and
 * org2, 26A428), at the onset of the glitch the owner ties to opening System Settings > Displays: a WindowServer
 * buffer with a 16 KiB descriptor under a 32 KiB map is refused -83 (kIOReturnBadArgument), and every later
 * WindowServer submission that lists it fails its preparation (-115, about one per frame to the end of both runs),
 * so stale framebuffers alternate on the panel (89% of scanout rows rewritten per present instead of 2-5%).
 *
 * Map offset m holds descriptor byte m - head. The map covers the whole pages the descriptor touches: the descriptor
 * is [head, head + bytes) of the map; the bytes before head and after head + bytes are the same task's bytes in the
 * same wired pages, reachable by the GPU exactly as native DMA reaches them (a DART maps whole pages too).
 *   admission  head + bytes fits the map, and the map is exactly the pages that range touches;
 *   segments   the first run is moved back to its page's start; a run that reaches the descriptor's end goes on to
 *              that page's end; a segment that does not sit where the head says is refused (0);
 *   cache      only the lines the descriptor touches; a partial first or last line is cleaned and invalidated;
 *   ranges     a client's buffer offset (IB relocation, FILL32) is inside the descriptor's bytes and lands at
 *              head + offset of the map.
 * head 0 is the tail rule: the functions below give exactly the tail rule's answers (tools/test-adreno-residency.c). */
static inline int adreno_head_admit(uint64_t head, uint64_t bytes, uint64_t logical)
{
    if (head >= ADRENO_TAIL_PAGE || !bytes || bytes > UINT64_MAX - 2 * ADRENO_TAIL_PAGE) return 0;
    if (!head) return adreno_tail_admit(bytes, logical);
    return !(logical & (ADRENO_TAIL_PAGE - 1)) && head + bytes <= logical &&
           logical <= adreno_tail_round_page(head + bytes);
}
/* Before the wire, when the head is not known yet: 1 when some head could make `bytes` fit `logical`. */
static inline int adreno_head_fit(uint64_t bytes, uint64_t logical)
{
    return bytes && bytes < logical && !(logical & (ADRENO_TAIL_PAGE - 1)) &&
           bytes <= UINT64_MAX - 2 * ADRENO_TAIL_PAGE && logical <= adreno_tail_round_page(bytes) + ADRENO_TAIL_PAGE;
}
/* The descriptor offset the physical callback asks for at page-aligned map offset `offset`. */
static inline uint64_t adreno_head_descriptor_offset(uint64_t offset, uint64_t head)
{
    return offset ? offset - head : 0;
}
/* The run the core's physical callback reports at page-aligned map offset `offset`, from the descriptor's own segment
 * (pa, span) at adreno_head_descriptor_offset(offset, head): its physical start and, in *length, its bytes. 0 refuses. */
static inline uint64_t adreno_head_run(uint64_t offset, uint64_t head, uint64_t bytes, uint64_t pa, uint64_t span,
                                       uint64_t *length)
{
    const uint64_t at = adreno_head_descriptor_offset(offset, head), lead = offset ? 0 : head;
    *length = 0;
    if (!pa || !span || head >= ADRENO_TAIL_PAGE || (offset & (ADRENO_TAIL_PAGE - 1)) || (offset && offset < head) ||
        at >= bytes || span > bytes - at || pa < lead || ((pa - lead) & (ADRENO_TAIL_PAGE - 1)))
        return 0;
    *length = span == bytes - at ? adreno_tail_round_page(head + bytes) - offset : span + lead;
    return pa - lead;
}
/* Cache maintenance of [offset, offset + len) of the map (64-byte aligned) for a descriptor of `bytes` at `head`: at
 * most three ranges, in order. 0 when nothing of the descriptor is inside. */
static inline unsigned adreno_head_cache_plan(uint64_t offset, uint64_t len, uint64_t head, uint64_t bytes,
                                              unsigned direction, struct adreno_tail_range out[3])
{
    const uint64_t first = head & ~(ADRENO_TAIL_LINE - 1);                         /* the line of the first byte */
    const uint64_t lead = (head + ADRENO_TAIL_LINE - 1) & ~(ADRENO_TAIL_LINE - 1); /* the first whole line */
    const uint64_t whole = (head + bytes) & ~(ADRENO_TAIL_LINE - 1);               /* the end of the whole lines */
    const uint64_t touched = (head + bytes + ADRENO_TAIL_LINE - 1) & ~(ADRENO_TAIL_LINE - 1);
    const uint64_t start = offset > first ? offset : first;
    const uint64_t stop = len > touched || offset > touched - len ? touched : offset + len;
    unsigned n = 0;
    if (start >= stop) return 0;
    if (direction != ADRENO_CACHE_FROM_DEVICE || (lead == first && whole == touched)) {
        out[n++] = (struct adreno_tail_range){start, stop - start, direction};
        return n;
    }
    if (lead >= whole) {                                  /* no line is wholly the descriptor's */
        out[n++] = (struct adreno_tail_range){start, stop - start, ADRENO_CACHE_TO_DEVICE};
        return n;
    }
    if (start < lead) out[n++] = (struct adreno_tail_range){start, (stop < lead ? stop : lead) - start, ADRENO_CACHE_TO_DEVICE};
    const uint64_t a = start > lead ? start : lead, b = stop < whole ? stop : whole;
    if (a < b) out[n++] = (struct adreno_tail_range){a, b - a, direction};
    const uint64_t c = start > whole ? start : whole;
    if (c < stop) out[n++] = (struct adreno_tail_range){c, stop - c, ADRENO_CACHE_TO_DEVICE};
    return n;
}
/* adreno_tail_cache with the head: validation first, then the plan in chunks of at most ADRENO_CACHE_MAX_BYTES. */
static inline int adreno_head_cache(const struct adreno_resource *r, uint64_t head, uint64_t bytes, unsigned direction,
                                    uint64_t offset, uint64_t len,
                                    int (*maintain)(void *, uint64_t, uint64_t, unsigned), void *context)
{
    int e = adreno_resource_cache(r, 0, 0, 0);
    if (e) return e;
    if (direction > ADRENO_CACHE_FROM_DEVICE || (direction && !maintain)) return ADRENO_RESOURCE_E_STATE;
    if (!len || offset >= r->logical_length || len > r->logical_length - offset) return ADRENO_RESOURCE_E_RANGE;
    if (head >= ADRENO_TAIL_PAGE || !bytes || bytes > r->logical_length || head > r->logical_length - bytes)
        return ADRENO_RESOURCE_E_RANGE;
    if (!direction) return 0;
    const uint64_t start = offset & ~(ADRENO_TAIL_LINE - 1);
    const uint64_t end = (offset + len + ADRENO_TAIL_LINE - 1) & ~(ADRENO_TAIL_LINE - 1);   /* <= logical_length */
    struct adreno_tail_range plan[3];
    const unsigned n = adreno_head_cache_plan(start, end - start, head, bytes, direction, plan);
    for (unsigned i = 0; i < n; i++)
        for (uint64_t at = plan[i].offset; at < plan[i].offset + plan[i].bytes;) {
            uint64_t chunk = plan[i].offset + plan[i].bytes - at;
            if (chunk > ADRENO_CACHE_MAX_BYTES) chunk = ADRENO_CACHE_MAX_BYTES;
            if (maintain(context, r->address + at, chunk, plan[i].direction)) return ADRENO_RESOURCE_E_CACHE;
            at += chunk;
        }
    return 0;
}
/* A client's range [offset, offset + len) of a head-offset buffer: 1 and its map offset when it lies inside the
 * descriptor's bytes; 0 otherwise (the caller refuses the IB or FILL32 that names it). */
static inline int adreno_head_range(uint64_t head, uint64_t bytes, uint64_t offset, uint64_t len, uint64_t *map_offset)
{
    *map_offset = 0;
    if (!len || head >= ADRENO_TAIL_PAGE || offset > bytes || len > bytes - offset) return 0;
    *map_offset = head + offset;
    return 1;
}
