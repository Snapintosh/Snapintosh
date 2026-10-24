/* SPDX-License-Identifier: MIT */
/* Adreno GPU mappings resident across native unwire, and contiguous-run insertion
 * (docs/ADRENO-GPU-MAP-RESIDENCY-20261017.md).
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Werror \
 *    -Icompat tools/test-adreno-residency.c compat/adreno-resource.c -o build/test-adreno-residency
 * build/test-adreno-residency [all|scenarios|workload]
 *
 * The real compat/adreno-resource.c, driven by the same glue AdrenoMemoryMap.cpp uses, against a
 * model written from the native code the document cites, never from the core:
 *  - IODARTMapper::iovmInsert maps page i of an insert to pa + i * 16 KiB. Each insert is one
 *    SPTM call per page on the per-page path, or one call per 64 pages (t8110dart_map's list) on
 *    the batch path; both counts are reported. Inserting over a different live leaf is the SPTM
 *    model's TABLE_EXISTS, which stops the guest: fatal here.
 *  - ADRENO_GUEST_UNMAP clears up to one 32 MiB leaf table, admits holes, subtracts the cleared
 *    leaves from XNU's per-table wiredcnt (SNAP_DART_WIREDCNT) and invalidates the SMMU TLB when
 *    a valid entry went away (adreno_mirror).
 *  - Strict native free (iovmUnmapMemory, option 0) requires every leaf present and the backing
 *    pinned; anything else stops the guest: fatal here.
 *  - IOMemoryDescriptor::prepare/complete per direction: a read/write prepare fails NotWritable
 *    while another client holds a read-only wire. A VM moves or reuses the pages of any
 *    descriptor nobody wires (pageout, purge, compaction), so a translation to an unpinned page is
 *    caught as soon as the page changes owner.
 *  - Native IOGPU: prepareMemory wires (IOGPUSysMemory::wire, then commit_pte per map) when the
 *    memory is unwired; completeMemory retires; the scheduler unwires idle memory later (release_pte
 *    per map); finalize unwires before free; descriptors are replaced while unwired.
 * After every step: every valid leaf maps the page its own map holds pinned, read-only backing has
 * no-write leaves, no leaf survives outside a reservation, wiredcnt equals the valid leaves, the
 * residency charge equals the RESIDENT lengths and stays within the budget; during a submission
 * every prepared map agrees with the native descriptor.
 *
 * Kext batch 8 (FAILURES-AND-DESIGN.md, V1-V7 and D1-D12), modelled before the code:
 *  - IOGPU's fixed bind: IOGPUMemoryMap::reserveGPUVirtualAddress -> IOGPUTask::allocate ->
 *    IORangeAllocator::allocateRange(address, round16K(length)) on the one CB0 allocator every task
 *    shares (refused when any page is taken), then add_mapping (commit when the memory is wired);
 *    freeGPUVirtualAddress deallocates it. Invariant: every CB0 page a map holds lies in its own DART
 *    reservation.
 *  - The DART reuses a just-freed range first (prefer_va), as a LIFO/first-fit allocator would.
 *  - A hook between the two halves of a release, where another thread creates a map of the same size:
 *    the v8 order (DART first, then CB0) makes that bind collide ("native VA bind failed").
 *  - The patched glue (policy 2): adreno_resource_bind/retire with the empty-reservation pool; pooled
 *    ranges hold no leaf, are free in CB0 and belong to no map.
 *  - The arena workload: fresh 64-page buffers per submission (the plug-in's 1 MiB UBO staging).
 * Build against the base core with -DRESOURCE_BASE (no pool policy, no pool scenarios).
 *
 * Batch 9 (batch9/dart FAILURES-AND-DESIGN.md K1-K12), modelled before the code:
 *  - The burst workload (both pool builds): spans whose maps are never re-created fill the general byte budget
 *    first, as installed-fresh-20261020-v9's did (put - take = 224 = live from window 8 on); then command
 *    buffers keep their fresh 1 MiB arenas in flight for 1-16 submissions and complete together every 200.
 *    Under batch 8's rules the arenas are refused and strict-freed (v9: 13,257 refusals, 65.9 pages each).
 *  - -DADRENO_POOL_ARENA=1 (both translation units): the arena class with the kext's values, its invariants
 *    (K7) after every step, and scenario 25.
 *
 * agents/gpu-va (FAILURE-MODES.md G0-G17), modelled before the code, with -DADRENO_VA_RECLAIM=1 (both units):
 *  - The kext's filler: 64 pages outside the VM's pages, inserted read-only (G4) in the run contract; its strict free
 *    requires every leaf of the reservation to map the filler (G2) and stops on an insert over a live leaf (G3).
 *  - Every mapper callback asserts that the pool lock is not held (G8, G14).
 *  - DART occupancy: the IODART allocator may be limited to the first window_pages pages (a scaled window), and the
 *    gauge the kext keeps (+ reserve, - native free) is mirrored and compared with the allocator (G10).
 *  - Scenarios 26-29 and the pressure workload (PRESSURE rows): pool parking while reserves fail, reclaim, pressure,
 *    genuine overcommit, residency on and off (G0). Without the filler (use_filler 0) every path is the base's (G12). */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "adreno.h"
#include "adreno-resource.h"
#if ADRENO_RESIDENT_REPIN
#include "adreno-resource-tail.h"
#endif
#if ADRENO_RESIDENT_HEAD_OFFSET && !ADRENO_RESIDENT_REPIN
#error "ADRENO_RESIDENT_HEAD_OFFSET needs ADRENO_RESIDENT_REPIN, as in the kext"
#endif
#if !defined(RESOURCE_BASE) && !ADRENO_RESOURCE_POOL
#error "build with -DADRENO_RESOURCE_POOL=1 (both translation units), or -DRESOURCE_BASE against the base core"
#endif

#define PAGE 0x4000ULL
#define LEAF_PAGES 2048u
#define WINDOW_PAGES ((unsigned)((ADRENO_WINDOW_END - ADRENO_WINDOW_BASE) / PAGE))
#define TABLES (WINDOW_PAGES / LEAF_PAGES)
#define PHYS_PAGES 65536u
#define PA_BASE 0x800000000ULL
#define BATCH 64u
#define MAX_DESCS 80000
#define MAX_MEMS 40000
#define MAX_MAPS 40000
#define MAX_RESV (1 << 17)
#define NO_WRITE 4ULL
enum { DIR_OUT = 1, DIR_INOUT = 3 };

static void fatal(int line, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    printf("!line %d: ", line); vprintf(fmt, ap); printf("\n");
    va_end(ap); exit(1);
}
#define CHECK(c) do { if (!(c)) fatal(__LINE__, "%s", #c); } while (0)

struct desc {
    int live;
    unsigned refs, npages, dir, ro_other, wires_ro, wires_rw, our_pins, native;
    uint64_t logical;
    uint64_t head;                     /* display-modeset: the first byte's offset in pages[0] (a page-unaligned client) */
    uint32_t *pages;
};
struct mem { int live, desc, wired, fb; unsigned prep, idle, nmaps; int maps[3];
             uint64_t maplen; };                 /* IOGPU's memory length when not the descriptor's (resident-evict) */
struct map {
    int live, leaked, mem, backing, committed;
    unsigned backing_dir;
    struct adreno_resource r;
    int native;                        /* map+0x10 bit 0: CB0 range held */
    int refuse_pin, refusal;           /* resident-evict: this map's pins fail; the kext's fRefusal */
    uint64_t tail;                     /* resident-evict: the kext's fBackingBytes */
    uint64_t head;                     /* display-modeset: the kext's fBackingHead */
    uint64_t native_addr, native_len;
};
struct counts {
    uint64_t submissions, refused, write_refused, inserts, sptm_perpage, sptm_batch, map_pages,
             clears, unmap_pages, tlbi, native_frees, native_unmap_calls, pins, unpins, moves,
             peak_resident, frozen;
    uint64_t reserves, binds, bind_busy, bind_commit, alloc_failed, race_failed;
};
static struct {
    uint64_t leaves[WINDOW_PAGES];
    int va_owner[WINDOW_PAGES];        /* DART reservation id (resv_*) of a live reservation */
    int native_owner[WINDOW_PAGES];    /* map index + 1 holding the page in the shared CB0 allocator */
    uint64_t resv_addr[MAX_RESV], resv_len[MAX_RESV];
    int nresv;
    uint64_t prefer_va;                /* the DART hands this range out first when it is free */
    struct { int armed; uint64_t addr, len; } race;
#ifndef RESOURCE_BASE
    struct adreno_va_pool pool;
#endif
    unsigned table_count[TABLES];      /* XNU's per-table wiredcnt, leaf part */
    int page_owner[PHYS_PAGES];
    struct desc descs[MAX_DESCS];
    struct mem mems[MAX_MEMS];
    struct map maps[MAX_MAPS];
    int ndescs, nmems, nmaps;
    unsigned va_cursor;
    uint64_t arng, erng, force_va;
    struct counts c;
    struct adreno_residency res;
    int policy;                        /* 0 old kext (v8), 1 resident kext, 2 pool (batch 8) */
    unsigned options;
    /* faults: insert number (1-based) and how many of its pages install first; one-shot others */
    unsigned fault_insert_at, fault_insert_partial, fault_clear, fault_unpin, fault_free, fault_pin;
    unsigned window_pages;             /* the IODART allocator's pages from the window base (0: all of it) */
    int head_off;                      /* display-modeset: boot-arg adreno_head_offset=0 */
    uint64_t head_admitted, head_refused;
#if ADRENO_VA_RECLAIM
    struct adreno_va_filler filler;
    int use_filler, pool_locked;
    unsigned fault_fill_insert, fault_fill_free;   /* one-shot: the nth filler insert (1-based) / the next filler free */
    uint64_t fill_inserts, filled_frees, held, lost_pages;   /* held: the kext's gauge (G10) */
#endif
} M;

static uint64_t rnd(uint64_t *s)
{
    uint64_t x = *s; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; *s = x;
    return x * 0x2545f4914f6cdd1dULL;
}
static unsigned below(uint64_t *s, unsigned n) { return (unsigned)(rnd(s) % n); }
static uint64_t pa_of(uint32_t page) { return PA_BASE + (uint64_t)page * PAGE; }
#if ADRENO_VA_RECLAIM
#define FILLER_PAGES 64u
#define FILLER_PA pa_of(PHYS_PAGES)          /* outside every descriptor's pages */
static int filler_leaf(uint64_t leaf)
{
    uint64_t pa = leaf & ~(NO_WRITE | 1ULL);
    return (leaf & 1) && (leaf & NO_WRITE) && pa >= FILLER_PA && pa < FILLER_PA + (uint64_t)FILLER_PAGES * PAGE;
}
#endif
static unsigned leaf_index(uint64_t va)
{
    CHECK(va >= ADRENO_WINDOW_BASE && va < ADRENO_WINDOW_END && !(va % PAGE));
    return (unsigned)((va - ADRENO_WINDOW_BASE) / PAGE);
}

/* ---- descriptors, wiring and the VM ---- */
static void alloc_pages(struct desc *d, int id)
{
    for (unsigned i = 0; i < d->npages;) {
        unsigned run = 1;
        while (below(&M.arng, 100) < 66) run++;
        if (run > d->npages - i) run = d->npages - i;
        uint32_t p = below(&M.arng, PHYS_PAGES);
        for (unsigned scan = 0; M.page_owner[p] >= 0; scan++) { CHECK(scan < PHYS_PAGES); p = (p + 1) % PHYS_PAGES; }
        for (unsigned k = 0; k < run && i < d->npages && M.page_owner[p] < 0; k++, i++, p = (p + 1) % PHYS_PAGES) {
            if (p == 0 && k) break;                      /* never wrap a run */
            M.page_owner[p] = id; d->pages[i] = p;
        }
    }
}
static void free_pages(struct desc *d)
{
    for (unsigned i = 0; i < d->npages; i++) { CHECK(M.page_owner[d->pages[i]] == d - M.descs); M.page_owner[d->pages[i]] = -1; }
}
/* A descriptor of `logical` bytes whose first byte is `head` bytes into its first page (0: page-aligned). */
static int new_desc_at(uint64_t logical, unsigned dir, uint64_t head)
{
    CHECK(M.ndescs < MAX_DESCS && head < PAGE);
    int id = M.ndescs++;
    struct desc *d = &M.descs[id];
    memset(d, 0, sizeof(*d));
    d->live = 1; d->logical = logical; d->dir = dir; d->head = head;
    d->npages = (unsigned)((head + logical + PAGE - 1) / PAGE);
    d->pages = calloc(d->npages, sizeof(*d->pages));
    CHECK(d->pages);
    alloc_pages(d, id);
    return id;
}
static int new_desc(uint64_t logical, unsigned dir) { return new_desc_at(logical, dir, 0); }
#if ADRENO_RESIDENT_HEAD_OFFSET
/* IOMemoryDescriptor::getPhysicalSegment(at): the physical address of descriptor byte `at` and the bytes physically
 * contiguous from it, up to the descriptor's end. */
static uint64_t segment(const struct desc *d, uint64_t at, uint64_t *length)
{
    CHECK(at < d->logical);
    const uint64_t p = d->head + at;
    unsigned i = (unsigned)(p / PAGE), run = 1;
    CHECK(i < d->npages);
    while (i + run < d->npages && d->pages[i + run] == d->pages[i] + run) run++;
    uint64_t bytes = (uint64_t)(i + run) * PAGE - p;
    if (bytes > d->logical - at) bytes = d->logical - at;
    *length = bytes;
    return pa_of(d->pages[i]) + p % PAGE;
}
#endif
static int wired(const struct desc *d) { return d->our_pins || d->native || d->wires_ro || d->wires_rw || d->ro_other; }
static void put_desc(int id)
{
    struct desc *d = &M.descs[id];
    CHECK(d->live && d->refs);
    if (--d->refs) return;
    d->ro_other = 0;
    CHECK(!wired(d));
    free_pages(d); free(d->pages); d->pages = NULL; d->live = 0;
}
static int prepare(struct desc *d, unsigned dir)
{
    if (dir == DIR_INOUT && (d->wires_ro || d->ro_other)) return -1;   /* kIOReturnNotWritable */
    if (dir == DIR_INOUT) d->wires_rw++; else d->wires_ro++;
    return 0;
}
static void complete(struct desc *d, unsigned dir)
{
    if (dir == DIR_INOUT) { CHECK(d->wires_rw); d->wires_rw--; } else { CHECK(d->wires_ro); d->wires_ro--; }
}
/* Pageout, purge or compaction of anything nobody wires: new pages, old ones free for reuse. */
static void vm_move(int id)
{
    struct desc *d = &M.descs[id];
    if (!d->live || wired(d)) return;
    uint32_t *old = d->pages;
    d->pages = calloc(d->npages, sizeof(*d->pages));
    CHECK(d->pages);
    alloc_pages(d, id);                                    /* old pages still owned: disjoint */
    for (unsigned i = 0; i < d->npages; i++) { CHECK(M.page_owner[old[i]] == id); M.page_owner[old[i]] = -1; }
    free(old);
    M.c.moves++;
}

/* ---- native mapper callbacks (ctx = struct map) ---- */
static unsigned window_pages(void) { return M.window_pages ? M.window_pages : WINDOW_PAGES; }
static int range_free(unsigned start, unsigned n)
{
    if (start + n > window_pages()) return 0;
    for (unsigned k = 0; k < n; k++) if (M.va_owner[start + k]) return 0;
    return 1;
}
static int cb_reserve(void *ctx, uint64_t length, uint64_t *address, uint64_t *span)
{
    (void)ctx;
    CHECK(length && !(length % PAGE));
    unsigned n = (unsigned)(length / PAGE), start = M.va_cursor, window = window_pages();
    M.c.reserves++;
#if ADRENO_VA_RECLAIM
    CHECK(!M.pool_locked);                                /* G8: no mapper call under the pool lock */
#endif
    if (start >= window) start = 0;
    if (M.force_va) start = leaf_index(M.force_va);
    else if (M.prefer_va && range_free(leaf_index(M.prefer_va), n)) start = leaf_index(M.prefer_va);
    M.prefer_va = 0;
    for (unsigned tries = 0; tries < window; tries++, start = (start + 1) % window) {
        if (start + n > window) { start = window - 1; continue; }
        unsigned k = 0;
        while (k < n && !M.va_owner[start + k]) k++;
        if (k < n) { if (M.force_va) return -1; start += k; continue; }
        CHECK(M.nresv + 1 < MAX_RESV);
        int id = ++M.nresv;
        M.resv_addr[id] = ADRENO_WINDOW_BASE + (uint64_t)start * PAGE; M.resv_len[id] = length;
        for (k = 0; k < n; k++) { M.va_owner[start + k] = id; CHECK(!M.leaves[start + k]); }
        M.va_cursor = (start + n) % window; M.force_va = 0;
        *address = ADRENO_WINDOW_BASE + (uint64_t)start * PAGE; *span = length;
#if ADRENO_VA_RECLAIM
        M.held += length;                                 /* G10: the kext's reservePages */
#endif
        return 0;
    }
    return -1;
}
/* The reservation id covering exactly [address, address + length), or 0. */
static int reservation(uint64_t address, uint64_t length)
{
    if (address < ADRENO_WINDOW_BASE || address >= ADRENO_WINDOW_END || (address % PAGE) || !length) return 0;
    int id = M.va_owner[leaf_index(address)];
    if (!id || M.resv_addr[id] != address || M.resv_len[id] != length) return 0;
    for (uint64_t off = 0; off < length; off += PAGE) if (M.va_owner[leaf_index(address + off)] != id) return 0;
    return id;
}
static int strict_free(void *ctx, uint64_t address, uint64_t length)
{
    struct map *m = ctx;
    CHECK(address == m->r.address && length == m->r.length);
#if ADRENO_VA_RECLAIM
    CHECK(!M.pool_locked);
#endif
    if (!reservation(address, length)) fatal(__LINE__, "native free of a range that is not one DART reservation");
    if (M.fault_free) { M.fault_free = 0; return -1; }
    if (m->backing < 0) fatal(__LINE__, "strict native free without pinned backing");
    struct desc *d = &M.descs[m->backing];
    for (uint64_t off = 0; off < length; off += PAGE) {
        uint64_t leaf = M.leaves[leaf_index(address + off)];
        if (!(leaf & 1) || (leaf & ~(NO_WRITE | 1ULL)) != pa_of(d->pages[off / PAGE]))
            fatal(__LINE__, "strict native free over a missing or foreign leaf at 0x%llx", (unsigned long long)(address + off));
    }
    uint64_t last_table = ~0ULL;
    for (uint64_t off = 0; off < length; off += PAGE) {
        unsigned i = leaf_index(address + off);
        if (i / LEAF_PAGES != last_table) { last_table = i / LEAF_PAGES; M.c.native_unmap_calls++; M.c.tlbi++; }
        M.leaves[i] = 0; CHECK(M.table_count[i / LEAF_PAGES]); M.table_count[i / LEAF_PAGES]--;
        M.c.unmap_pages++;
        M.va_owner[i] = 0;
    }
    M.c.native_frees++;
#if ADRENO_VA_RECLAIM
    M.held -= length;                                     /* G10: the kext's freePages */
#endif
    return 0;
}
#if ADRENO_VA_RECLAIM
/* The kext's fillerInsert: read-only leaves to the filler (G4), the run contract, never over a live leaf (G3). */
static int filler_insert(void *ctx, uint64_t address, uint64_t offset, uint64_t pa, uint64_t size)
{
    CHECK(ctx == &M.filler && !M.pool_locked);
    CHECK(size && !(size % PAGE) && !(pa % PAGE) && !(offset % PAGE));
    CHECK(pa >= FILLER_PA && pa + size <= FILLER_PA + (uint64_t)FILLER_PAGES * PAGE);
    int id = M.va_owner[leaf_index(address)];
    CHECK(id && M.resv_addr[id] == address && offset + size <= M.resv_len[id]);   /* inside one reservation */
    unsigned n = (unsigned)(size / PAGE), first = leaf_index(address + offset);
    CHECK(n <= BATCH && first / LEAF_PAGES == (first + n - 1) / LEAF_PAGES);
    M.c.inserts++; M.c.sptm_perpage += n; M.c.sptm_batch += (n + BATCH - 1) / BATCH; M.fill_inserts++;
    if (M.fault_fill_insert && M.fill_inserts == M.fault_fill_insert) { M.fault_fill_insert = 0; return -1; }
    for (unsigned i = 0; i < n; i++) {
        if (M.leaves[first + i]) fatal(__LINE__, "TABLE_EXISTS: filler insert over a live leaf (G3)");
        M.leaves[first + i] = (pa + i * PAGE) | 1 | NO_WRITE;
        M.table_count[(first + i) / LEAF_PAGES]++; M.c.map_pages++;
    }
    return 0;
}
/* The kext's fillerFree: the strict native free; every leaf must be present and map the filler (G2). */
static int filler_free(void *ctx, uint64_t address, uint64_t length)
{
    CHECK(ctx == &M.filler && !M.pool_locked);
    if (!reservation(address, length)) fatal(__LINE__, "filled free of a range that is not one DART reservation");
    if (M.fault_fill_free) { M.fault_fill_free = 0; return -1; }
    for (uint64_t off = 0; off < length; off += PAGE)
        if (!filler_leaf(M.leaves[leaf_index(address + off)]))
            fatal(__LINE__, "strict native free over a missing or non-filler leaf at 0x%llx (G2)", (unsigned long long)(address + off));
    uint64_t last_table = ~0ULL;
    for (uint64_t off = 0; off < length; off += PAGE) {
        unsigned i = leaf_index(address + off);
        if (i / LEAF_PAGES != last_table) { last_table = i / LEAF_PAGES; M.c.native_unmap_calls++; M.c.tlbi++; }
        M.leaves[i] = 0; CHECK(M.table_count[i / LEAF_PAGES]); M.table_count[i / LEAF_PAGES]--;
        M.c.unmap_pages++; M.va_owner[i] = 0;
    }
    M.c.native_frees++; M.filled_frees++;
    M.held -= length;
    return 0;
}
static void model_lock(void *ctx) { CHECK(ctx == &M && !M.pool_locked); M.pool_locked = 1; }
static void model_unlock(void *ctx) { CHECK(ctx == &M && M.pool_locked); M.pool_locked = 0; }
#endif
static int cb_pin(void *ctx)
{
    struct map *m = ctx;
    if (m->backing >= 0) return -1;                       /* pinBacking: kIOReturnBadArgument */
    if (M.fault_pin) { M.fault_pin = 0; return -1; }
    int id = M.mems[m->mem].desc;
    if (id < 0) return -1;
    struct desc *d = &M.descs[id];
    if (m->refuse_pin) return -1;
#if ADRENO_RESIDENT_HEAD_OFFSET
    /* the kext's pinBacking: the head is read from the wired descriptor's first segment */
    const int tail = d->logical < m->r.logical_length && adreno_tail_admit(d->logical, m->r.logical_length);
    const int headed = d->logical < m->r.logical_length && !M.head_off && adreno_head_fit(d->logical, m->r.logical_length);
    if (d->logical < m->r.logical_length && !tail && !headed) return -1;
#elif ADRENO_RESIDENT_REPIN
    const int tail = d->logical < m->r.logical_length && adreno_tail_admit(d->logical, m->r.logical_length);
    if (d->logical < m->r.logical_length && !tail) return -1;
#else
    if (d->logical < m->r.logical_length) return -1;
#endif
    unsigned dir = d->dir == DIR_OUT ? DIR_OUT : DIR_INOUT;
    if (prepare(d, dir)) {
        if (dir == DIR_OUT) return -1;
        dir = DIR_OUT;
        if (prepare(d, dir)) return -1;
    }
#if ADRENO_RESIDENT_HEAD_OFFSET
    uint64_t head = 0;
    if (headed) {
        uint64_t span = 0;
        head = segment(d, 0, &span) & (PAGE - 1);
        if (!adreno_head_admit(head, d->logical, m->r.logical_length)) { complete(d, dir); M.head_refused++; return -1; }
        if (head) M.head_admitted++;
    }
#endif
    d->refs++; d->our_pins++;
    m->backing = id; m->backing_dir = dir;
#if ADRENO_RESIDENT_HEAD_OFFSET
    m->tail = tail || headed ? d->logical : 0;
    m->head = head;
#elif ADRENO_RESIDENT_REPIN
    m->tail = tail ? d->logical : 0;
#endif
    M.c.pins++;
    return 0;
}
static int cb_unpin(void *ctx)
{
    struct map *m = ctx;
    CHECK(m->backing >= 0);
    if (M.fault_unpin) { M.fault_unpin = 0; return -1; }
    struct desc *d = &M.descs[m->backing];
    /* complete() only after every translation to it is gone */
    for (uint64_t off = 0; off < m->r.length; off += PAGE)
        if (M.leaves[leaf_index(m->r.address + off)]) fatal(__LINE__, "unpin with a live leaf at offset 0x%llx", (unsigned long long)off);
    complete(d, m->backing_dir);
    CHECK(d->our_pins); d->our_pins--;
    int id = m->backing;
    m->backing = -1; m->tail = 0; m->head = 0;
    put_desc(id);
    M.c.unpins++;
    return 0;
}
static uint64_t cb_physical(void *ctx, uint64_t offset, uint64_t *length)
{
    struct map *m = ctx;
    CHECK(m->backing >= 0);                               /* only while prepared */
    struct desc *d = &M.descs[m->backing];
    CHECK(!(offset % PAGE) && offset < (uint64_t)d->npages * PAGE);
#if ADRENO_RESIDENT_HEAD_OFFSET
    if (m->head) {                                        /* the kext's physicalPage, head rule */
        uint64_t span = 0;
        const uint64_t pa = segment(d, adreno_head_descriptor_offset(offset, m->head), &span);
        return adreno_head_run(offset, m->head, m->tail, pa, span, length);
    }
#endif
    unsigned i = (unsigned)(offset / PAGE), run = 1;
    while (i + run < d->npages && d->pages[i + run] == d->pages[i] + run) run++;
    uint64_t bytes = (uint64_t)run * PAGE;
    if (bytes > d->logical - offset) bytes = d->logical - offset;   /* getPhysicalSegment stops at the end */
#if ADRENO_RESIDENT_REPIN
    if (m->tail) bytes = adreno_tail_span(offset, bytes, m->tail);  /* the kext's physicalPage */
#endif
    *length = bytes;
    return pa_of(d->pages[i]);
}
static int cb_insert(void *ctx, uint64_t address, uint64_t offset, uint64_t pa, uint64_t size)
{
    struct map *m = ctx;
#if ADRENO_VA_RECLAIM
    CHECK(!M.pool_locked);
#endif
    CHECK(m->backing >= 0 && address == m->r.address);
    CHECK(size && !(size % PAGE) && !(pa % PAGE) && !(offset % PAGE));
    uint64_t va = address + offset;
    CHECK(offset + size <= m->r.length);
    unsigned n = (unsigned)(size / PAGE), first = leaf_index(va);
    CHECK(n <= BATCH && first / LEAF_PAGES == (first + n - 1) / LEAF_PAGES);   /* the run contract */
    M.c.inserts++; M.c.sptm_perpage += n; M.c.sptm_batch += (n + BATCH - 1) / BATCH;
    int failing = M.fault_insert_at && M.c.inserts == M.fault_insert_at;
    for (unsigned i = 0; i < n; i++) {
        if (failing && i == M.fault_insert_partial) return -1;
        uint64_t want = (pa + i * PAGE) | 1 | (m->backing_dir == DIR_OUT ? NO_WRITE : 0);
        uint64_t old = M.leaves[first + i];
        if (old && old != want) fatal(__LINE__, "TABLE_EXISTS: insert over a live leaf");
        if (!old) { M.leaves[first + i] = want; M.table_count[(first + i) / LEAF_PAGES]++; M.c.map_pages++; }
    }
    return failing ? -1 : 0;
}
static int cb_clear(void *ctx, uint64_t va, uint64_t size)
{
    struct map *m = ctx;
    CHECK(size && !((va | size) % PAGE));
    unsigned first = leaf_index(va), n = (unsigned)(size / PAGE);
    CHECK(first / LEAF_PAGES == (first + n - 1) / LEAF_PAGES);
    CHECK(va >= m->r.address && va + size <= m->r.address + m->r.length);
    if (M.fault_clear) { M.fault_clear = 0; return -1; }
    CHECK(m->backing >= 0);                               /* clear strictly before unpin */
    unsigned cleared = 0;
    for (unsigned i = 0; i < n; i++)
        if (M.leaves[first + i]) { M.leaves[first + i] = 0; cleared++; }
    CHECK(M.table_count[first / LEAF_PAGES] >= cleared);
    M.table_count[first / LEAF_PAGES] -= cleared;
    M.c.clears++; M.c.unmap_pages += cleared;
    if (cleared) M.c.tlbi++;
    return 0;
}
static struct adreno_resource_ops ops_for(struct map *m)
{
    return (struct adreno_resource_ops){m, cb_reserve, strict_free, cb_pin, cb_unpin, cb_physical, cb_insert, cb_clear};
}

/* ---- the kext's glue (AdrenoMemoryMap.cpp), old and resident ---- */
static int glue_commit(struct map *m)
{
    struct adreno_resource_ops o = ops_for(m);
    int same = m->backing < 0 || m->backing == M.mems[m->mem].desc;
    if (!M.policy) return same ? adreno_resource_commit(&m->r, &o) : ADRENO_RESOURCE_E_STATE;
    return adreno_resource_rewire(&m->r, &o, &M.res, same, M.options);
}
/* commitIntoGPUPageTable's answer to IOGPU: with ADRENO_RESIDENT_REPIN a clean refusal is reported committed and
 * remembered; the map stays unadmitted (resident-evict). */
#if ADRENO_RESIDENT_REPIN
static int clean_refusal(const struct map *m)
{
    return m->r.flags == ADRENO_RESOURCE_RESERVED && m->r.length && !m->r.mapped_length && m->backing < 0;
}
#endif
static int glue_native_commit(struct map *m)
{
    int e = glue_commit(m);
#if ADRENO_RESIDENT_REPIN
    if (!e) m->refusal = 0;
    else if (M.policy && clean_refusal(m)) { m->refusal = e; return 0; }
#endif
    return e;
}
static int keep_verdict(const struct map *m)
{
    return m->backing >= 0 && m->backing == M.mems[m->mem].desc &&
           !(m->backing_dir == DIR_OUT && M.descs[m->backing].dir != DIR_OUT);
}
static int glue_release(struct map *m)
{
    struct adreno_resource_ops o = ops_for(m);
    if (!M.policy) return adreno_resource_release(&m->r, &o);
    return adreno_resource_unwire(&m->r, &o, &M.res, keep_verdict(m));
}
/* ---- IOGPU's fixed bind on the CB0 allocator every task shares (reserveGPUVirtualAddress) ---- */
static int native_bind(struct map *m, uint64_t address, uint64_t length)
{
    uint64_t span = (length + PAGE - 1) & ~(PAGE - 1);
    unsigned first = leaf_index(address), n = (unsigned)(span / PAGE);
    CHECK(!m->native && m->live);
    M.c.binds++;
    for (unsigned k = 0; k < n; k++)
        if (M.native_owner[first + k]) { M.c.bind_busy++; return 1; }   /* allocateRange refuses: bit 0 stays clear */
    for (unsigned k = 0; k < n; k++) M.native_owner[first + k] = (int)(m - M.maps) + 1;
    m->native = 1; m->native_addr = address; m->native_len = span;
    if (M.mems[m->mem].wired) {                                      /* add_mapping -> commit_pte */
        if (glue_native_commit(m)) { M.c.bind_commit++; return 2; }
        m->committed = 1;
    }
    return 0;
}
static void native_unbind(struct map *m)                             /* IOGPUMemoryMap::freeGPUVirtualAddress */
{
    if (!m->native) return;
    unsigned first = leaf_index(m->native_addr), n = (unsigned)(m->native_len / PAGE);
    for (unsigned k = 0; k < n; k++) {
        CHECK(M.native_owner[first + k] == (int)(m - M.maps) + 1);
        M.native_owner[first + k] = 0;
    }
    m->native = 0;
}
static int new_mem_try(uint64_t logical, unsigned dir);
/* Another thread creates a map of the dying map's size between the two halves of its release; the DART
 * hands the most recently freed range out first. */
static void race_hook(void)
{
    if (!M.race.armed) return;
    M.race.armed = 0;
    M.prefer_va = M.race.addr;
    if (new_mem_try(M.race.len, DIR_INOUT) < 0) M.c.race_failed++;
    M.prefer_va = 0;
}
#ifndef RESOURCE_BASE
static int h_bind(void *ctx, uint64_t address, uint64_t length) { return native_bind(ctx, address, length); }
/* The racing thread runs just before the CB0 release: whatever has already happened to the DART reservation
 * (nothing, in the batch-8 order) is visible to it while CB0 still holds the range. */
static void h_unbind(void *ctx) { race_hook(); native_unbind(ctx); }
#endif
/* releaseAddress: v8 (and today's base) free the DART reservation first, then the CB0 range; batch 8
 * frees the CB0 range first and keeps an empty reservation in the pool (adreno_resource_retire). */
static int glue_free(struct map *m)
{
    struct adreno_resource_ops o = ops_for(m);
    M.race.addr = m->r.address; M.race.len = m->r.logical_length;
#ifndef RESOURCE_BASE
    if (M.policy == 2) return adreno_resource_retire(&m->r, &o, &M.res, M.options, &M.pool, h_unbind, m);
#endif
    int e = !M.policy ? adreno_resource_free(&m->r, &o) : adreno_resource_free_with(&m->r, &o, &M.res, M.options);
    if (e) return e;
    race_hook();
    native_unbind(m);
    return 0;
}
/* allocGPUVirtualAddress: reserve (or, batch 8, take from the pool), then bind at that exact address. */
static int glue_alloc(struct map *m, uint64_t length)
{
    struct adreno_resource_ops o = ops_for(m);
#ifndef RESOURCE_BASE
    if (M.policy == 2) {
        int e = adreno_resource_bind(&m->r, &o, length, &M.pool, h_bind, h_unbind, m, &M.res, M.options);
        if (e) M.c.alloc_failed++;
        return e;
    }
#endif
    int e = adreno_resource_reserve(&m->r, &o, length);
    if (e) { M.c.alloc_failed++; return e; }
    if (!native_bind(m, m->r.address, length)) return 0;
    M.c.alloc_failed++;                                              /* "native VA bind failed" */
    int f = glue_free(m);
    return f ? f : -1;
}
static int admitted(const struct map *m)       /* prepareForSubmission's check */
{
    return m->r.flags == (ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED) && m->r.length &&
           m->r.mapped_length == m->r.length && m->backing >= 0 && m->backing == M.mems[m->mem].desc;
}
/* prepareForSubmission: with ADRENO_RESIDENT_REPIN a cleanly refused map retries its pin under the native preparation. */
static int glue_prepare(struct map *m)
{
#if ADRENO_RESIDENT_REPIN
    if (m->refusal && clean_refusal(m)) {
        int e = glue_commit(m);
        if (!e) m->refusal = 0;
        else if (clean_refusal(m)) m->refusal = e;
    }
#endif
    return admitted(m);
}

/* ---- invariants ---- */
static void check_map(const struct map *m)
{
    if (!m->live && !m->leaked) return;
    if (!(m->r.flags & ADRENO_RESOURCE_RESERVED)) return;
    int pinned = !!(m->r.flags & ADRENO_RESOURCE_PINNED);
    if (m->r.flags & ADRENO_RESOURCE_RESIDENT) {
        CHECK(pinned && m->backing >= 0);                 /* charged while possibly wired */
        CHECK((m->r.flags & ADRENO_RESOURCE_FAILED) || m->r.mapped_length == m->r.length);
        CHECK(!m->committed || m->leaked);                /* native view: unwired */
    }
    for (uint64_t off = 0; off < m->r.length; off += PAGE) {
        unsigned i = leaf_index(m->r.address + off);
        uint64_t leaf = M.leaves[i];
#if ADRENO_VA_RECLAIM
        /* G2: a reservation lost to a failed fill keeps what was filled (filler leaves only), frozen */
        if (!pinned && leaf && (m->r.flags & ADRENO_RESOURCE_FAILED) && filler_leaf(leaf)) continue;
#endif
        if (!pinned) { if (leaf) fatal(__LINE__, "leaf without pin, map %d offset 0x%llx", (int)(m - M.maps), (unsigned long long)off); continue; }
        if (!(m->r.flags & ADRENO_RESOURCE_FAILED) && off < m->r.mapped_length && !leaf) fatal(__LINE__, "hole in a complete mapping");
        if (!leaf) continue;
        if (m->backing < 0) fatal(__LINE__, "leaf after unpin");
        const struct desc *d = &M.descs[m->backing];
        CHECK(d->live && d->our_pins && off / PAGE < d->npages);
        uint32_t page = d->pages[off / PAGE];
        if ((leaf & ~(NO_WRITE | 1ULL)) != pa_of(page)) fatal(__LINE__, "leaf maps a page its descriptor does not hold (map %d offset 0x%llx)", (int)(m - M.maps), (unsigned long long)off);
        if (M.page_owner[page] != m->backing) fatal(__LINE__, "leaf maps a reclaimed page");
        if (!!(leaf & NO_WRITE) != (m->backing_dir == DIR_OUT)) fatal(__LINE__, "leaf write permission differs from the prepared direction");
    }
}
static void check_all(int full)
{
    uint64_t charge = 0;
    for (int i = 0; i < M.nmaps; i++) {
        const struct map *m = &M.maps[i];
        check_map(m);
        if ((m->live || m->leaked) && (m->r.flags & ADRENO_RESOURCE_RESIDENT)) charge += m->r.length;
    }
    if (M.res.bytes != charge) fatal(__LINE__, "residency charge %llu, RESIDENT bytes %llu", (unsigned long long)M.res.bytes, (unsigned long long)charge);
#if ADRENO_VA_RECLAIM
    if (full) {                                           /* G10: the gauge equals the DART's view */
        uint64_t owned = 0;
        for (unsigned p = 0; p < WINDOW_PAGES; p++) owned += !!M.va_owner[p];
        if (owned * PAGE != M.held) fatal(__LINE__, "VA gauge %llu, DART-held bytes %llu", (unsigned long long)M.held, (unsigned long long)(owned * PAGE));
    }
#endif
    CHECK(charge <= M.res.budget);
    if (charge > M.c.peak_resident) M.c.peak_resident = charge;
    if (!full) return;
    for (int i = 0; i < M.ndescs; i++) {
        const struct desc *d = &M.descs[i];
        if (!d->live) continue;
        unsigned pins = 0;
        for (int k = 0; k < M.nmaps; k++) pins += (M.maps[k].live || M.maps[k].leaked) && M.maps[k].backing == i;
        CHECK(pins == d->our_pins);
    }
    for (unsigned t = 0; t < TABLES; t++) {
        unsigned valid = 0;
        for (unsigned k = 0; k < LEAF_PAGES; k++) {
            unsigned i = t * LEAF_PAGES + k;
            if (!M.leaves[i]) continue;
            valid++;
            if (!M.va_owner[i]) fatal(__LINE__, "leaf outside any reservation");
        }
        if (valid != M.table_count[t]) fatal(__LINE__, "wiredcnt %u, valid leaves %u in table %u", M.table_count[t], valid, t);
        CHECK(M.table_count[t] <= 32767);
    }
    /* Every reserved map and every pooled entry is exactly one DART reservation, and none is shared (D10). */
    unsigned char *users = calloc((size_t)M.nresv + 1, 1);
    CHECK(users);
    for (int i = 0; i < M.nmaps; i++) {
        const struct map *m = &M.maps[i];
        if ((!m->live && !m->leaked) || !(m->r.flags & ADRENO_RESOURCE_RESERVED)) continue;
        int id = reservation(m->r.address, m->r.length);
        if (!id) fatal(__LINE__, "map %d is not one DART reservation", i);
        if (users[id]++) fatal(__LINE__, "DART reservation %d used twice", id);
    }
#ifndef RESOURCE_BASE
    uint64_t pooled = 0;
#if ADRENO_POOL_ARENA
    uint64_t arena = 0, general = 0;
#endif
    for (unsigned e = 0; e < M.pool.count; e++) {
        int id = reservation(M.pool.address[e], M.pool.span[e]);
        if (!id) fatal(__LINE__, "pooled entry %u is not one DART reservation", e);
        if (users[id]++) fatal(__LINE__, "pooled reservation %d is also in use", id);
        for (uint64_t off = 0; off < M.pool.span[e]; off += PAGE) {
            unsigned p = leaf_index(M.pool.address[e] + off);
            if (M.leaves[p]) fatal(__LINE__, "valid leaf in a pooled reservation (D1)");
            /* D3: none of our maps holds a pooled range in CB0; only a parked collision (V3) may still be
             * held by a foreign CB0 user, and it is never handed out. */
            if (M.native_owner[p] > 0 ||
                (M.native_owner[p] && !(M.pool.flags[e] & ADRENO_VA_POOL_SUSPECT)))
                fatal(__LINE__, "pooled range still held in CB0 (D3)");
        }
        CHECK(M.pool.span[e] <= M.pool.max_span);
        pooled += M.pool.span[e];
#if ADRENO_POOL_ARENA
        /* K6, K7: the class holds the takeable entries of exactly arena_span; everything else (other spans and
         * parked collisions of any span) is general and keeps batch 8's per-span cap. */
        if (M.pool.arena_span && M.pool.span[e] == M.pool.arena_span && !(M.pool.flags[e] & ADRENO_VA_POOL_SUSPECT)) {
            arena++;
        } else {
            general += M.pool.span[e];
            unsigned same = 0;
            for (unsigned f = 0; f < M.pool.count; f++)
                same += M.pool.span[f] == M.pool.span[e] &&
                        !(M.pool.span[f] == M.pool.arena_span && !(M.pool.flags[f] & ADRENO_VA_POOL_SUSPECT));
            CHECK(same <= ADRENO_VA_POOL_PER_SPAN);
        }
#endif
    }
#if ADRENO_POOL_ARENA
    CHECK(arena == M.pool.arena_count && arena <= M.pool.arena_limit);
    CHECK(pooled == M.pool.bytes && general == pooled - arena * M.pool.arena_span && general <= M.pool.limit_bytes &&
          M.pool.count <= ADRENO_VA_POOL_SLOTS);
#else
    CHECK(pooled == M.pool.bytes && pooled <= M.pool.limit_bytes && M.pool.count <= ADRENO_VA_POOL_SLOTS);
#endif
#endif
    free(users);
    /* V1: every CB0 page a map holds lies inside that map's own DART reservation. */
    for (unsigned p = 0; p < WINDOW_PAGES; p++) {
        int owner = M.native_owner[p];
        if (owner <= 0) continue;                                  /* -1: a foreign CB0 user (scenario 21) */
        const struct map *m = &M.maps[owner - 1];
        uint64_t va = ADRENO_WINDOW_BASE + (uint64_t)p * PAGE;
        CHECK(m->native);
        if (!(m->r.flags & ADRENO_RESOURCE_RESERVED) || va < m->r.address || va >= m->r.address + m->r.length)
            fatal(__LINE__, "CB0 page 0x%llx held by map %d outside its DART reservation", (unsigned long long)va, owner - 1);
    }
}
static void check_gpu_view(const struct map *m, int write)
{
    const struct desc *d = &M.descs[M.mems[m->mem].desc];
    for (uint64_t off = 0; off < m->r.length; off += PAGE) {
        uint64_t leaf = M.leaves[leaf_index(m->r.address + off)];
        if (!(leaf & 1) || (leaf & ~(NO_WRITE | 1ULL)) != pa_of(d->pages[off / PAGE]))
            fatal(__LINE__, "GPU sees memory other than the native descriptor (map %d offset 0x%llx)", (int)(m - M.maps), (unsigned long long)off);
    }
    if (write && (M.leaves[leaf_index(m->r.address)] & NO_WRITE)) M.c.write_refused++;
}

/* ---- native IOGPU ---- */
static void reset(int policy, unsigned options, uint64_t budget, uint64_t seed)
{
    for (int i = 0; i < M.ndescs; i++) free(M.descs[i].pages);
    memset(&M, 0, sizeof(M));
    memset(M.page_owner, 0xff, sizeof(M.page_owner));
    M.policy = policy; M.options = options; M.res.budget = budget;
    M.arng = seed * 0x9e3779b97f4a7c15ULL + 1; M.erng = seed ^ 0x5bd1e995ULL;
#ifndef RESOURCE_BASE
    M.pool.limit_bytes = 128ULL << 20; M.pool.max_span = 4ULL << 20;  /* the kext's limits (D5) */
#if ADRENO_POOL_ARENA
    M.pool.arena_span = 64 * PAGE; M.pool.arena_limit = ADRENO_VA_POOL_ARENA_ENTRIES;  /* the kext's class (K5) */
#endif
#if ADRENO_VA_RECLAIM
    M.filler = (struct adreno_va_filler){&M.filler, filler_insert, filler_free, FILLER_PA, (uint64_t)FILLER_PAGES * PAGE};
    M.use_filler = 1;
    M.pool.filler = &M.filler;
    M.pool.lock = model_lock; M.pool.unlock = model_unlock; M.pool.lock_ctx = &M;
#endif
#endif
}
#if ADRENO_VA_RECLAIM
/* G12: no filler, as the kext when neither filler buffer could be pinned. */
static void no_filler(void) { M.use_filler = 0; M.pool.filler = NULL; }
#endif
/* createGPUMappingInTask -> allocGPUVirtualAddress; -1 when the allocation fails (IOGPU drops the map). */
static int new_map_try(int mem)
{
    CHECK(M.nmaps < MAX_MAPS);
    int id = M.nmaps++;
    struct map *m = &M.maps[id];
    memset(m, 0, sizeof(*m));
    m->live = 1; m->mem = mem; m->backing = -1;
    struct mem *me = &M.mems[mem];
    CHECK(me->nmaps < 3);
    if (glue_alloc(m, me->maplen ? me->maplen : M.descs[me->desc].logical)) {
        m->live = 0;
        if (m->r.flags) { m->leaked = 1; M.c.frozen++; }          /* a frozen failure path keeps its state */
        return -1;
    }
    me->maps[me->nmaps++] = id;
    return id;
}
static int new_map(int mem)
{
    int id = new_map_try(mem);
    CHECK(id >= 0);
    return id;
}
static int new_mem_try(uint64_t logical, unsigned dir)
{
    CHECK(M.nmems < MAX_MEMS);
    int id = M.nmems++;
    struct mem *me = &M.mems[id];
    memset(me, 0, sizeof(*me));
    me->live = 1;
    me->desc = new_desc(logical, dir);
    M.descs[me->desc].refs = 1;
    if (new_map_try(id) < 0) {
        if (!M.descs[me->desc].our_pins) put_desc(me->desc);
        me->live = 0; me->desc = -1;
        return -1;
    }
    return id;
}
static int new_mem(uint64_t logical, unsigned dir, int fb)
{
    int id = new_mem_try(logical, dir);
    CHECK(id >= 0);
    M.mems[id].fb = fb;
    return id;
}
static int native_wire(struct mem *me)
{
    CHECK(!me->wired && me->live);
    M.descs[me->desc].native++;
    for (unsigned k = 0; k < me->nmaps; k++) {
        struct map *m = &M.maps[me->maps[k]];
        if (glue_native_commit(m)) {
            for (unsigned j = 0; j < k; j++) {
                struct map *done = &M.maps[me->maps[j]];
                glue_release(done); done->committed = 0;
            }
            M.descs[me->desc].native--;
            return 0;
        }
        m->committed = 1;
    }
    me->wired = 1;
    return 1;
}
static void native_unwire(struct mem *me)
{
    CHECK(me->wired && !me->prep);
    for (unsigned k = 0; k < me->nmaps; k++) {
        struct map *m = &M.maps[me->maps[k]];
        if (m->committed) { glue_release(m); m->committed = 0; }
    }
    CHECK(M.descs[me->desc].native); M.descs[me->desc].native--;
    me->wired = 0; me->idle = 0;
}
static void drop_map(struct mem *me, unsigned k)
{
    struct map *m = &M.maps[me->maps[k]];
    if (m->committed) { glue_release(m); m->committed = 0; }   /* remove_mapping: release_pte */
    if (glue_free(m)) { m->leaked = 1; M.c.frozen++; }       /* the kext keeps it until reset */
    m->live = 0;
    me->maps[k] = me->maps[--me->nmaps];
}
static void free_mem(int id)
{
    struct mem *me = &M.mems[id];
    CHECK(me->live && !me->prep);
    if (me->wired) native_unwire(me);                          /* finalize */
    while (me->nmaps) drop_map(me, me->nmaps - 1);
    put_desc(me->desc);
    me->live = 0; me->desc = -1;
}
static void replace_backing(struct mem *me)
{
    if (!me->live || me->wired || me->prep) return;
    const struct desc *old = &M.descs[me->desc];
    int fresh = new_desc_at(old->logical, old->dir, old->head);   /* the client's address keeps its page offset */
    M.descs[fresh].refs = 1;
    int previous = me->desc;
    me->desc = fresh;
    put_desc(previous);
}
static int submit(const int *mems, const int *writes, unsigned n)
{
    int prepared[16] = {0};
    int ok = 1;
    M.c.submissions++;
    for (unsigned i = 0; i < n; i++) {
        struct mem *me = &M.mems[mems[i]];
        me->prep++;
        if (!me->wired && !native_wire(me)) { me->prep--; ok = 0; break; }
        prepared[i] = 1;
        for (unsigned k = 0; k < me->nmaps; k++) {
            struct map *m = &M.maps[me->maps[k]];
            if (!glue_prepare(m)) { ok = 0; continue; }
            check_gpu_view(m, writes[i]);
        }
    }
    if (!ok) M.c.refused++;
    for (unsigned i = n; i-- > 0;) {
        if (!prepared[i]) continue;
        struct mem *me = &M.mems[mems[i]];
        me->prep--; me->idle = 0;
    }
    return ok;
}
static int pick_live(int exclude_fb)
{
    for (int tries = 0; tries < 10000; tries++) {
        int id = (int)below(&M.erng, (unsigned)M.nmems);
        if (M.mems[id].live && !(exclude_fb && M.mems[id].fb)) return id;
    }
    return -1;
}
static uint64_t small_size(void)
{
    static const uint64_t sizes[] = {0x100, 0x4000, 0x4100, 0x8000, 0xc040, 0x10000, 0x1c000, 0x20000};
    return sizes[below(&M.erng, 8)];
}
/* Free everything, check that nothing is left but empty pooled reservations, print the counts. */
static void finish(const char *name, uint64_t budget, uint64_t arenas)
{
    for (int i = 0; i < M.nmems; i++) if (M.mems[i].live) free_mem(i);
    check_all(1);
    uint64_t pooled_pages = 0, puts = 0, takes = 0, refused = 0, live = 0, collisions = 0, retried = 0, gave_up = 0;
#ifndef RESOURCE_BASE
    pooled_pages = M.pool.bytes / PAGE; puts = M.pool.puts; takes = M.pool.takes; refused = M.pool.refused;
    live = M.pool.count; collisions = M.pool.collisions; retried = M.pool.retried; gave_up = M.pool.gave_up;
#endif
    uint64_t held = 0;
    for (unsigned i = 0; i < WINDOW_PAGES; i++) { CHECK(!M.leaves[i] && !M.native_owner[i]); held += !!M.va_owner[i]; }
    CHECK(held == pooled_pages);                                    /* only the pool keeps DART ranges */
    for (int i = 0; i < M.ndescs; i++) CHECK(!M.descs[i].live);
    CHECK(M.res.bytes == 0 && !M.c.frozen && !M.c.refused && !M.c.alloc_failed);
    printf("COUNTS {\"policy\": \"%s\", \"budget\": %llu, \"submissions\": %llu, \"inserts\": %llu, "
           "\"sptm_map_perpage\": %llu, \"sptm_map_batch\": %llu, \"map_pages\": %llu, \"clears\": %llu, "
           "\"unmap_pages\": %llu, \"tlbi\": %llu, \"native_frees\": %llu, \"native_unmap_calls\": %llu, "
           "\"pins\": %llu, \"unpins\": %llu, \"moves\": %llu, \"write_refused\": %llu, \"peak_resident\": %llu, "
           "\"retained\": %llu, \"reused\": %llu, \"evicted\": %llu, \"refused_budget\": %llu, "
           "\"arenas\": %llu, \"reserves\": %llu, \"binds\": %llu, \"bind_busy\": %llu, \"pool_puts\": %llu, "
           "\"pool_takes\": %llu, \"pool_refused\": %llu, \"pool_live\": %llu, \"collisions\": %llu, "
           "\"retried\": %llu, \"gave_up\": %llu}\n",
           name, (unsigned long long)budget, (unsigned long long)M.c.submissions, (unsigned long long)M.c.inserts,
           (unsigned long long)M.c.sptm_perpage, (unsigned long long)M.c.sptm_batch, (unsigned long long)M.c.map_pages,
           (unsigned long long)M.c.clears, (unsigned long long)M.c.unmap_pages, (unsigned long long)M.c.tlbi,
           (unsigned long long)M.c.native_frees, (unsigned long long)M.c.native_unmap_calls,
           (unsigned long long)M.c.pins, (unsigned long long)M.c.unpins, (unsigned long long)M.c.moves,
           (unsigned long long)M.c.write_refused, (unsigned long long)M.c.peak_resident,
           (unsigned long long)M.res.retained, (unsigned long long)M.res.reused,
           (unsigned long long)M.res.evicted, (unsigned long long)M.res.refused, (unsigned long long)arenas,
           (unsigned long long)M.c.reserves, (unsigned long long)M.c.binds, (unsigned long long)M.c.bind_busy,
           (unsigned long long)puts, (unsigned long long)takes, (unsigned long long)refused, (unsigned long long)live,
           (unsigned long long)collisions, (unsigned long long)retried, (unsigned long long)gave_up);
}
static void workload(const char *name, int policy, unsigned options, uint64_t budget, unsigned steps)
{
    reset(policy, options, budget, 39);
    int fbs[4];
    for (int i = 0; i < 4; i++) fbs[i] = new_mem(4096ULL * 2160 * 4, DIR_INOUT, 1);   /* 2160 pages */
    for (int i = 0; i < 24; i++) new_mem(64 * PAGE, below(&M.erng, 4) ? DIR_INOUT : DIR_OUT, 0);
    for (int i = 0; i < 160; i++) new_mem(small_size(), below(&M.erng, 4) ? DIR_INOUT : DIR_OUT, 0);
    check_all(1);
    for (unsigned step = 0; step < steps; step++) {
        int list[8], writes[8];
        unsigned n = 0;
        list[n] = fbs[step % 2]; writes[n++] = 1;
        if (below(&M.erng, 8) == 0) { list[n] = fbs[2 + below(&M.erng, 2)]; writes[n++] = 0; }
        while (n < 7) {
            int id = pick_live(1);
            int dup = 0;
            for (unsigned k = 0; k < n; k++) dup |= list[k] == id;
            if (id < 0 || dup) continue;
            list[n] = id; writes[n++] = M.descs[M.mems[id].desc].dir == DIR_INOUT && below(&M.erng, 2);
        }
        if (!submit(list, writes, n)) fatal(__LINE__, "submission refused in a fault-free workload");
        /* The scheduler unwires memory idle for two submissions. */
        for (int i = 0; i < M.nmems; i++) {
            struct mem *me = &M.mems[i];
            if (me->live && me->wired && !me->prep && ++me->idle >= 2) native_unwire(me);
        }
        unsigned roll = below(&M.erng, 1000);
        if (roll < 50) {                                    /* alloc/free churn */
            int id = pick_live(1);
            if (id >= 0) free_mem(id);
            new_mem(small_size(), below(&M.erng, 4) ? DIR_INOUT : DIR_OUT, 0);
        } else if (roll < 60) {
            int id = pick_live(0);
            if (id >= 0) replace_backing(&M.mems[id]);
        } else if (roll < 80) {                             /* another client's read-only wire */
            int id = pick_live(0);
            if (id >= 0 && M.descs[M.mems[id].desc].dir == DIR_INOUT)
                M.descs[M.mems[id].desc].ro_other ^= 1;
        } else if (roll < 90) {                             /* alias maps come and go */
            int id = pick_live(1);
            if (id >= 0 && M.mems[id].nmaps < 3) new_map(id);
            else if (id >= 0 && M.mems[id].nmaps > 1) drop_map(&M.mems[id], M.mems[id].nmaps - 1);
        }
        if (below(&M.erng, 5) == 0)                          /* memory pressure, purges */
            for (int k = 0; k < 8; k++) vm_move((int)below(&M.erng, (unsigned)M.ndescs));
        check_all(step % 25 == 0);
    }
    finish(name, budget, 0);
}
/* The arena workload (FAILURES-AND-DESIGN.md 1.2): every submission draws into one of three framebuffers
 * with 6-14 fresh 1 MiB (64-page) UBO staging arenas, which the command buffer frees after completion:
 * some after the scheduler's unwire, some still wired (finalize unwires them). */
static void arena_workload(const char *name, int policy, unsigned options, uint64_t budget, unsigned steps)
{
    reset(policy, options, budget, 41);
    int fbs[3];
    for (int i = 0; i < 3; i++) fbs[i] = new_mem(4096ULL * 2160 * 4, DIR_INOUT, 1);
    for (int i = 0; i < 16; i++) new_mem(small_size(), DIR_INOUT, 0);
    check_all(1);
    uint64_t arenas = 0;
    for (unsigned step = 0; step < steps; step++) {
        int list[16], writes[16], fresh[16];
        unsigned n = 0, k = 6 + below(&M.erng, 9);
        list[n] = fbs[step % 3]; writes[n++] = 1;
        for (unsigned a = 0; a < k; a++) {
            fresh[a] = new_mem(64 * PAGE, DIR_INOUT, 0);
            list[n] = fresh[a]; writes[n++] = 1; arenas++;
        }
        if (!submit(list, writes, n)) fatal(__LINE__, "submission refused in a fault-free workload");
        for (unsigned a = 0; a < k; a++) {
            struct mem *me = &M.mems[fresh[a]];
            if (below(&M.erng, 2) && me->wired) native_unwire(me);
            free_mem(fresh[a]);
        }
        /* Long-lived memory in use every frame stays wired (v8: about 10.5K clears outside the arenas); the
         * scheduler unwires what was idle for four submissions. */
        for (int i = 0; i < M.nmems; i++) {
            struct mem *me = &M.mems[i];
            if (me->live && me->wired && !me->prep && ++me->idle >= 4) native_unwire(me);
        }
        if (below(&M.erng, 5) == 0)
            for (int q = 0; q < 8; q++) vm_move((int)below(&M.erng, (unsigned)M.ndescs));
        check_all(step % 25 == 0);
    }
    finish(name, budget, arenas);
}
#ifndef RESOURCE_BASE
/* Batch 9 (FAILURES-AND-DESIGN.md 1): installed-fresh-20261020-v9's pool. First, spans whose maps are never
 * created again fill the general byte budget (34 maps of each of eight odd spans, freed together: the per-span cap
 * and then the byte limit refuse the rest). Then every submission draws into a framebuffer with 6-14 fresh 1 MiB
 * arenas; its command buffer completes after the next `depth` submissions (1-16, redrawn every 50), and every 200th
 * submission all of them complete together (bursts of up to ~240 arenas). The BURST row separates the two phases. */
static void burst_workload(const char *name, unsigned steps)
{
    reset(2, ADRENO_COMMIT_RUNS, 0, 43);
    int fbs[3];
    for (int i = 0; i < 3; i++) {
        int w = 1;
        fbs[i] = new_mem(4096ULL * 2160 * 4, DIR_INOUT, 1);
        if (!submit(&fbs[i], &w, 1)) fatal(__LINE__, "framebuffer submission refused");   /* wired before the burst */
    }
    static const unsigned odd[] = {9, 17, 25, 33, 41, 49, 57, 65};
    int fill[8 * (ADRENO_VA_POOL_PER_SPAN + 2)];
    unsigned nfill = 0;
    for (unsigned s = 0; s < 8; s++)
        for (unsigned k = 0; k < ADRENO_VA_POOL_PER_SPAN + 2; k++) {
            int m = new_mem(odd[s] * PAGE - 0x100, DIR_INOUT, 0);
            if (k & 1) { int w = 1; if (!submit(&m, &w, 1)) fatal(__LINE__, "fill submission refused"); }
            fill[nfill++] = m;
        }
    for (unsigned i = 0; i < nfill; i++) free_mem(fill[i]);
    check_all(1);
    uint64_t fill_puts = M.pool.puts, fill_refused = M.pool.refused, fill_frees = M.c.native_frees;
    uint64_t fill_maps = M.c.map_pages, fill_takes = M.pool.takes, fill_bytes = M.pool.bytes, fill_count = M.pool.count;
    int ring[24][16];
    unsigned rk[24], head = 0, len = 0, depth = 8, inflight = 0, peak = 0;
    uint64_t arenas = 0;
    for (unsigned step = 0; step < steps; step++) {
        if (step % 50 == 0) depth = 1 + below(&M.erng, 16);
        if (step % 200 == 199) depth = 0;
        int list[16], writes[16];
        unsigned n = 0, k = 6 + below(&M.erng, 9), slot = (head + len) % 24;
        list[n] = fbs[step % 3]; writes[n++] = 1;
        for (unsigned a = 0; a < k; a++) {
            ring[slot][a] = new_mem(64 * PAGE, DIR_INOUT, 0);
            list[n] = ring[slot][a]; writes[n++] = 1; arenas++;
        }
        rk[slot] = k; len++; inflight += k;
        if (inflight > peak) peak = inflight;
        if (!submit(list, writes, n)) fatal(__LINE__, "submission refused in a fault-free workload");
        while (len > depth) {
            for (unsigned a = 0; a < rk[head]; a++) {
                struct mem *me = &M.mems[ring[head][a]];
                if (below(&M.erng, 2) && me->wired) native_unwire(me);
                free_mem(ring[head][a]);
            }
            inflight -= rk[head]; head = (head + 1) % 24; len--;
        }
        for (int i = 0; i < M.nmems; i++) {
            struct mem *me = &M.mems[i];
            if (me->live && me->wired && !me->prep && ++me->idle >= 4) native_unwire(me);
        }
        if (below(&M.erng, 5) == 0)
            for (int q = 0; q < 8; q++) vm_move((int)below(&M.erng, (unsigned)M.ndescs));
        check_all(step % 25 == 0);
    }
    printf("BURST {\"policy\": \"%s\", \"arenas\": %llu, \"peak_inflight\": %u, \"fill_puts\": %llu, "
           "\"fill_refused\": %llu, \"fill_native_frees\": %llu, \"fill_bytes\": %llu, \"fill_count\": %llu, "
           "\"burst_puts\": %llu, \"burst_takes\": %llu, \"burst_refused\": %llu, \"burst_native_frees\": %llu, "
           "\"burst_map_pages\": %llu, \"pool_count\": %llu}\n",
           name, (unsigned long long)arenas, peak, (unsigned long long)fill_puts, (unsigned long long)fill_refused,
           (unsigned long long)fill_frees, (unsigned long long)fill_bytes, (unsigned long long)fill_count,
           (unsigned long long)(M.pool.puts - fill_puts), (unsigned long long)(M.pool.takes - fill_takes),
           (unsigned long long)(M.pool.refused - fill_refused), (unsigned long long)(M.c.native_frees - fill_frees),
           (unsigned long long)(M.c.map_pages - fill_maps), (unsigned long long)M.pool.count);
    finish(name, 0, arenas);
}
/* Pacing work 2026-10-21 (failure modes R1-R13, written before this code): the deployed collection's kext
 * (pool + arena class, budget 0) against the same kext with residency (budget > 0), under the load
 * installed-fresh-neon-20261021-v2 showed: WindowServer frames that draw into one of three framebuffers and sample
 * layer surfaces, with the drag-speed plug-in's recycled 1 MiB staging arenas (PLUGIN-DRAG-SPEED C3: an arena goes back
 * to the plug-in's own pool when its command buffer completes and is taken again by a later frame; the IOGPU map
 * persists), fence-only command buffers that wire without an IB, and IOGPU's scheduler unwiring memory as soon as no
 * submission references it (v2's s=6: 2,632 clears and 182K inserts in 600 presents). Also, at random: a layer resized
 * (new descriptor, R1), memory pressure moving unwired pages (R2), an app's surface freed and another created, the
 * plug-in pool trimmed (arena freed into the empty-reservation pool, R7), another client's read-only wire (R6). The RECYCLE
 * row reports the steady state (after warm-up) per frame. Every step runs the full invariant check every 25 frames
 * and the cheap one otherwise (check_all). */
static void recycled_workload(const char *name, unsigned options, uint64_t budget, unsigned frames)
{
    reset(2, options, budget, 47);
    enum { FBS = 3, LAYERS = 10, SMALL = 24, ARENA_POOL = 128, DEPTH = 2, WARM = 100 };
    int fbs[FBS], layers[LAYERS], small[SMALL];
    for (int i = 0; i < FBS; i++) fbs[i] = new_mem(4096ULL * 2160 * 4, DIR_INOUT, 1);
    for (int i = 0; i < LAYERS; i++) layers[i] = new_mem((64 + 32 * below(&M.erng, 16)) * PAGE, DIR_INOUT, 0);
    for (int i = 0; i < SMALL; i++) small[i] = new_mem(small_size(), below(&M.erng, 3) ? DIR_OUT : DIR_INOUT, 0);
    int free_arena[ARENA_POOL], nfree = 0, held[DEPTH + 1][16];
    unsigned nheld[DEPTH + 1] = {0};
    unsigned head = 0;
    uint64_t arenas_made = 0, at_warm[6] = {0};
    check_all(1);
    for (unsigned frame = 0; frame < frames; frame++) {
        if (frame == WARM) {
            at_warm[0] = M.c.inserts; at_warm[1] = M.c.clears; at_warm[2] = M.c.map_pages; at_warm[3] = M.c.pins;
            at_warm[4] = M.c.tlbi; at_warm[5] = M.c.submissions;
        }
        int list[16], writes[16];
        unsigned n = 0, slot = head % (DEPTH + 1), k = 3 + below(&M.erng, 6);
        list[n] = fbs[frame % FBS]; writes[n++] = 1;
        for (unsigned l = 0, want = 2 + below(&M.erng, 3); l < want; l++) {
            int id = layers[below(&M.erng, LAYERS)], dup = 0;
            for (unsigned j = 0; j < n; j++) dup |= list[j] == id;
            if (!dup) { list[n] = id; writes[n++] = 0; }
        }
        list[n] = small[below(&M.erng, SMALL)]; writes[n++] = 0;
        nheld[slot] = 0;
        for (unsigned a = 0; a < k && n < 16; a++) {
            int id = nfree ? free_arena[--nfree] : (arenas_made++, new_mem(64 * PAGE, DIR_INOUT, 0));
            held[slot][nheld[slot]++] = id;
            list[n] = id; writes[n++] = 1;
        }
        if (!submit(list, writes, n)) fatal(__LINE__, "submission refused in a fault-free workload");
        if (below(&M.erng, 4) == 0) {                       /* a fence-only command buffer: it wires, no IB */
            int fence[2] = {layers[below(&M.erng, LAYERS)], small[below(&M.erng, SMALL)]}, w[2] = {0, 0};
            if (fence[0] != fence[1] && !submit(fence, w, 2)) fatal(__LINE__, "fence submission refused");
        }
        head++;
        /* The command buffer DEPTH frames back completes: its arenas return to the plug-in's pool (C3). */
        unsigned done = head % (DEPTH + 1);
        if (head > DEPTH) {
            for (unsigned a = 0; a < nheld[done]; a++) {
                if (nfree < ARENA_POOL) free_arena[nfree++] = held[done][a];
                else free_mem(held[done][a]);              /* over the plug-in's cap: released (pool put, R7) */
            }
            nheld[done] = 0;
        }
        /* IOGPU's scheduler: memory no submission references any more is unwired (release_pte per map). */
        for (int i = 0; i < M.nmems; i++) {
            struct mem *me = &M.mems[i];
            if (me->live && me->wired && !me->prep && ++me->idle >= 1) native_unwire(me);
        }
        unsigned roll = below(&M.erng, 1000);
        if (roll < 20) {                                    /* a window resized: new backing (R1) */
            struct mem *me = &M.mems[layers[below(&M.erng, LAYERS)]];
            replace_backing(me);
        } else if (roll < 30) {                             /* an app closes a surface, another opens one */
            unsigned i = below(&M.erng, LAYERS);
            free_mem(layers[i]);
            layers[i] = new_mem((64 + 32 * below(&M.erng, 16)) * PAGE, DIR_INOUT, 0);
        } else if (roll < 40 && nfree > 8) {                /* the plug-in trims idle arenas (R7) */
            for (int t = 0; t < 8; t++) free_mem(free_arena[--nfree]);
        } else if (roll < 50) {                             /* another client's read-only wire (R6) */
            struct desc *d = &M.descs[M.mems[layers[below(&M.erng, LAYERS)]].desc];
            d->ro_other ^= 1;
        }
        if (below(&M.erng, 5) == 0)                          /* memory pressure (R2) */
            for (int q = 0; q < 8; q++) vm_move((int)below(&M.erng, (unsigned)M.ndescs));
        check_all(frame % 25 == 0);
    }
    for (unsigned s = 0; s <= DEPTH; s++) nheld[s] = 0;
    uint64_t steady = frames - WARM, subs = M.c.submissions - at_warm[5];
    printf("RECYCLE {\"policy\": \"%s\", \"budget\": %llu, \"frames\": %llu, \"submissions\": %llu, \"arenas_made\": %llu, "
           "\"inserts_per_frame\": %.2f, \"clears_per_frame\": %.2f, \"map_pages_per_frame\": %.2f, \"pins_per_frame\": %.2f, "
           "\"tlbi_per_frame\": %.2f, \"retained\": %llu, \"reused\": %llu, \"evicted\": %llu, \"refused_budget\": %llu, "
           "\"peak_resident\": %llu, \"write_refused\": %llu}\n",
           name, (unsigned long long)budget, (unsigned long long)steady, (unsigned long long)subs,
           (unsigned long long)arenas_made,
           (double)(M.c.inserts - at_warm[0]) / steady, (double)(M.c.clears - at_warm[1]) / steady,
           (double)(M.c.map_pages - at_warm[2]) / steady, (double)(M.c.pins - at_warm[3]) / steady,
           (double)(M.c.tlbi - at_warm[4]) / steady, (unsigned long long)M.res.retained,
           (unsigned long long)M.res.reused, (unsigned long long)M.res.evicted, (unsigned long long)M.res.refused,
           (unsigned long long)M.c.peak_resident, (unsigned long long)M.c.write_refused);
    finish(name, budget, arenas_made);
}
#endif

#ifndef RESOURCE_BASE
#if ADRENO_POOL_ARENA
/* agents/gpu-va (G0, G6, G7, G9, G12): b12v5's pattern on a DART scaled to 448 MiB with the pool scaled alike (16 MiB
 * general, 32 arenas; the kext: 128 MiB, 256 of 3 GiB). Phases:
 *  A  three framebuffers, wired;
 *  B  spans never created again fill the general class, and 40 arenas freed together fill the arena class;
 *  C  long-lived surfaces until 20 MiB of the DART is free (the pool still parks 48 MiB);
 *  D  10 bursts of 56 arenas in flight together (WindowServer's busy windows), freed after their submission;
 *  F  4,200 single arena allocate/free cycles (pressure ends; the pool admits again);
 *  E  surfaces until the DART is genuinely full (live maps alone), then 8 more attempts.
 * Phase D has failures in the base (and without the filler) while the pool parks bytes; none with reclaim. PRESSURE row
 * per policy; held_trace lists the DART-held pages after each phase (G0: residency changes none of them). */
static unsigned dart_free_pages(void)
{
    unsigned n = 0;
    for (unsigned p = 0; p < window_pages(); p++) n += !M.va_owner[p];
    return n;
}
static unsigned dart_held_pages(void)
{
    unsigned n = 0;
    for (unsigned p = 0; p < WINDOW_PAGES; p++) n += !!M.va_owner[p];
    return n;
}
static void pressure_workload(const char *name, uint64_t budget, int filler)
{
    reset(2, ADRENO_COMMIT_RUNS, budget, 53);
#if ADRENO_VA_RECLAIM
    if (!filler) no_filler();
#endif
    M.window_pages = 448 * 64;
    M.pool.limit_bytes = 16ULL << 20; M.pool.arena_limit = 32;
    unsigned trace[6], nt = 0;
    uint64_t first_pool = 0, first_free = 0, d_fail = 0, e_fail = 0;
    int fbs[3];
    for (int i = 0; i < 3; i++) {
        int w = 1;
        fbs[i] = new_mem(4096ULL * 2160 * 4, DIR_INOUT, 1);
        if (!submit(&fbs[i], &w, 1)) fatal(__LINE__, "framebuffer submission refused");
    }
    trace[nt++] = dart_held_pages();
    static const unsigned odd[] = {9, 17, 25, 33, 41, 49, 57, 65};
    int fill[8 * (ADRENO_VA_POOL_PER_SPAN + 2)], arenas[64];
    unsigned nfill = 0;
    for (unsigned s2 = 0; s2 < 8; s2++)
        for (unsigned k = 0; k < ADRENO_VA_POOL_PER_SPAN + 2; k++) fill[nfill++] = new_mem(odd[s2] * PAGE - 0x100, DIR_INOUT, 0);
    for (unsigned i = 0; i < nfill; i++) free_mem(fill[i]);
    for (int i = 0; i < 40; i++) arenas[i] = new_mem(64 * PAGE, DIR_INOUT, 0);
    for (int i = 0; i < 40; i++) free_mem(arenas[i]);
    check_all(1);
    CHECK(M.pool.arena_count == 32 && M.pool.bytes > (16ULL << 20) + 32 * 64 * PAGE - 64 * PAGE);
    trace[nt++] = dart_held_pages();
    while (dart_free_pages() > 1280 + 512) new_mem(512 * PAGE - 0x40, DIR_INOUT, 0);
    while (dart_free_pages() > 1280) new_mem(64 * PAGE - 0x4000, DIR_INOUT, 0);   /* 63 pages: not an arena */
    check_all(1);
    trace[nt++] = dart_held_pages();
    for (unsigned round = 0; round < 10; round++) {
        int list[16], writes[16], live[56];
        unsigned n = 0, nl = 0;
        for (unsigned a = 0; a < 56; a++) {
            int id = new_mem_try(64 * PAGE, DIR_INOUT);
            if (id < 0) {
                if (!d_fail++) { first_pool = M.pool.bytes; first_free = (uint64_t)dart_free_pages() * PAGE; }
                continue;
            }
            live[nl++] = id;
        }
        list[n] = fbs[round % 3]; writes[n++] = 1;
        for (unsigned a = 0; a < nl && n < 16; a++) { list[n] = live[a]; writes[n++] = 1; }
        if (!submit(list, writes, n)) fatal(__LINE__, "burst submission refused");
        for (unsigned a = 0; a < nl; a++) free_mem(live[a]);
        check_all(round % 3 == 0);
    }
    check_all(1);
    trace[nt++] = dart_held_pages();
    uint64_t puts_before_f = M.pool.puts;
    for (unsigned i = 0; i < 4200; i++) {
        int id = new_mem_try(64 * PAGE, DIR_INOUT);
        CHECK(id >= 0);
        free_mem(id);
        if (i % 500 == 0) check_all(1);
    }
    uint64_t f_puts = M.pool.puts - puts_before_f;
    check_all(1);
    trace[nt++] = dart_held_pages();
    for (unsigned misses = 0; misses < 8;)
        if (new_mem_try(512 * PAGE, DIR_INOUT) < 0) { misses++; e_fail++; }
    check_all(1);
    trace[nt++] = dart_held_pages();
    uint64_t exhausted = 0, reclaimed = 0, reclaim_failed = 0, drained = 0, drained_bytes = 0, filled = 0, pressure = 0;
    uint64_t lost = 0;
#if ADRENO_VA_RECLAIM
    exhausted = M.pool.exhausted; reclaimed = M.pool.reclaimed; reclaim_failed = M.pool.reclaim_failed;
    drained = M.pool.drained; drained_bytes = M.pool.drained_bytes; filled = M.filled_frees;
    pressure = M.pool.pressure_refused; lost = M.pool.lost;
    if (M.pool.filler) {
        CHECK(!d_fail);                                     /* G6: no failure that only parking caused */
        CHECK(reclaim_failed && e_fail);                    /* G7: genuine overcommit still fails, cleanly */
        CHECK(f_puts > 0);                                  /* G9: pressure ends, the pool admits again */
    } else CHECK(d_fail);                                   /* G12: the base's failures */
#else
    CHECK(d_fail);
#endif
    CHECK(!M.c.frozen && !lost && first_pool * (d_fail ? 1 : 0) == first_pool);
    for (int i = 0; i < M.nmems; i++) if (M.mems[i].live) free_mem(i);
    check_all(1);
    CHECK(dart_held_pages() == M.pool.bytes / PAGE);         /* only the pool keeps DART ranges */
    printf("PRESSURE {\"policy\": \"%s\", \"budget\": %llu, \"filler\": %d, \"d_failures\": %llu, \"e_failures\": %llu, "
           "\"first_fail_pool_bytes\": %llu, \"first_fail_free_bytes\": %llu, \"held_trace\": [%u, %u, %u, %u, %u, %u], "
           "\"exhausted\": %llu, \"reclaimed\": %llu, \"reclaim_failed\": %llu, \"drained\": %llu, \"drained_bytes\": %llu, "
           "\"filled_frees\": %llu, \"pressure_refused\": %llu, \"lost\": %llu, \"f_puts\": %llu, \"native_frees\": %llu, "
           "\"map_pages\": %llu, \"inserts\": %llu, \"pins\": %llu, \"alloc_failed\": %llu}\n",
           name, (unsigned long long)budget, filler, (unsigned long long)d_fail, (unsigned long long)e_fail,
           (unsigned long long)first_pool, (unsigned long long)first_free, trace[0], trace[1], trace[2], trace[3],
           trace[4], trace[5], (unsigned long long)exhausted, (unsigned long long)reclaimed,
           (unsigned long long)reclaim_failed, (unsigned long long)drained, (unsigned long long)drained_bytes,
           (unsigned long long)filled, (unsigned long long)pressure, (unsigned long long)lost, (unsigned long long)f_puts,
           (unsigned long long)M.c.native_frees, (unsigned long long)M.c.map_pages, (unsigned long long)M.c.inserts,
           (unsigned long long)M.c.pins, (unsigned long long)M.c.alloc_failed);
}
#endif
#endif

/* ---- targeted scenarios ---- */
static int scenario_mem(const uint32_t *pages, unsigned npages, uint64_t logical, unsigned dir)
{
    CHECK(M.nmems < MAX_MEMS && M.ndescs < MAX_DESCS);
    int id = M.ndescs++;
    struct desc *d = &M.descs[id];
    memset(d, 0, sizeof(*d));
    d->live = 1; d->logical = logical; d->dir = dir; d->refs = 1;
    d->npages = npages; d->pages = calloc(npages, sizeof(*d->pages));
    CHECK(d->pages);
    for (unsigned i = 0; i < npages; i++) { CHECK(M.page_owner[pages[i]] < 0); M.page_owner[pages[i]] = id; d->pages[i] = pages[i]; }
    int mem = M.nmems++;
    struct mem *me = &M.mems[mem];
    memset(me, 0, sizeof(*me));
    me->live = 1; me->desc = id;
    new_map(mem);
    return mem;
}
static struct map *map_of(int mem) { return &M.maps[M.mems[mem].maps[0]]; }
static void wire_check(int mem)
{
    struct mem *me = &M.mems[mem];
    me->prep++;
    CHECK(me->wired || native_wire(me));
    CHECK(glue_prepare(map_of(mem)));
    check_gpu_view(map_of(mem), 0);
    me->prep--;
    check_all(1);
}
static void scenarios(void)
{
    const unsigned RUNS = ADRENO_COMMIT_RUNS;
    uint64_t MiB = 1ULL << 20;
    /* 1. Runs: [P,P+1,P+2][Q,Q+1][R] then 70 contiguous: 3,2,1,64,6 with runs; 76 page by page. */
    for (int policy = 0; policy < 2; policy++) {
        reset(policy, RUNS, 512 * MiB, 1);
        uint32_t pages[76] = {100, 101, 102, 200, 201, 300};
        for (unsigned i = 6; i < 76; i++) pages[i] = 400 + i;
        int mem = scenario_mem(pages, 76, 76 * PAGE - 0x40, DIR_INOUT);
        wire_check(mem);
        CHECK(M.c.inserts == (policy ? 5u : 76u) && M.c.map_pages == 76 && M.c.sptm_perpage == 76);
        CHECK(M.c.sptm_batch == (policy ? 5u : 76u));
        native_unwire(&M.mems[mem]);
        CHECK(policy ? (map_of(mem)->r.flags & ADRENO_RESOURCE_RESIDENT) && !M.c.clears : M.c.clears == 1 && M.c.unpins == 1);
        wire_check(mem);
        CHECK(M.c.inserts == (policy ? 5u : 152u) && M.c.pins == (policy ? 1u : 2u));
        free_mem(mem);
        CHECK(M.c.native_frees == 1 && M.res.bytes == 0);
        check_all(1);
    }
    /* 2. Short tail page mapped whole, inside its run. */
    reset(1, RUNS, 512 * MiB, 2);
    { uint32_t pages[2] = {500, 501}; int mem = scenario_mem(pages, 2, 0x4100, DIR_INOUT);
      wire_check(mem); CHECK(M.c.inserts == 1 && M.c.map_pages == 2); free_mem(mem); check_all(1); }
    /* 3. A run never crosses a 32 MiB leaf table. */
    reset(1, RUNS, 512 * MiB, 3);
    { uint32_t pages[4] = {600, 601, 602, 603};
      M.force_va = ADRENO_WINDOW_BASE + 32 * MiB - 2 * PAGE;
      int mem = scenario_mem(pages, 4, 4 * PAGE, DIR_INOUT);
      wire_check(mem); CHECK(M.c.inserts == 2 && M.c.map_pages == 4); free_mem(mem); check_all(1); }
#if ADRENO_VA_WIDE
    /* agents/gpu-va-wide V10, V14: across 4 GiB (a 32 MiB leaf-table boundary, so two runs) and at the top of the
     * 16 GiB window, wired, unwired, rewired and freed through the kext's resource core like any other map. */
    for (unsigned w = 0; w < 2; w++) {
        reset(1, RUNS, 512 * MiB, 30 + w);
        uint32_t pages[4] = {640, 641, 642, 643};
        M.force_va = w ? ADRENO_WINDOW_END - 4 * PAGE : 0x100000000ULL - 2 * PAGE;
        int mem = scenario_mem(pages, 4, 4 * PAGE, DIR_INOUT);
        CHECK(map_of(mem)->r.address == (w ? ADRENO_WINDOW_END - 4 * PAGE : 0x100000000ULL - 2 * PAGE));
        wire_check(mem);
        CHECK(M.c.inserts == (w ? 1u : 2u) && M.c.map_pages == 4);
        native_unwire(&M.mems[mem]);
        wire_check(mem);
        free_mem(mem);
        CHECK(M.res.bytes == 0);
        check_all(1);
    }
#endif
    /* 4. A run fails after installing part of itself: rollback clears all of it. */
    reset(1, RUNS, 512 * MiB, 4);
    { uint32_t pages[6] = {700, 701, 702, 800, 801, 802};
      int mem = scenario_mem(pages, 6, 6 * PAGE, DIR_INOUT);
      M.fault_insert_at = 2; M.fault_insert_partial = 1;
#if ADRENO_RESIDENT_REPIN
      /* resident-evict: the clean refusal is reported committed; the map stays unadmitted until its next preparation */
      M.mems[mem].prep++; CHECK(native_wire(&M.mems[mem]) && !admitted(map_of(mem)) &&
                                map_of(mem)->refusal == ADRENO_RESOURCE_E_INSERT); M.mems[mem].prep--;
      native_unwire(&M.mems[mem]);
#else
      M.mems[mem].prep++; CHECK(!native_wire(&M.mems[mem])); M.mems[mem].prep--;
#endif
      struct map *m = map_of(mem);
      CHECK(!(m->r.flags & (ADRENO_RESOURCE_PINNED | ADRENO_RESOURCE_FAILED)) && m->backing < 0);
      check_all(1);
      M.fault_insert_at = 0;
      wire_check(mem); free_mem(mem); check_all(1); }
    /* 5. ...and when that rollback's clear fails too, everything stays pinned and frozen. */
    reset(1, RUNS, 512 * MiB, 5);
    { uint32_t pages[6] = {700, 701, 702, 800, 801, 802};
      int mem = scenario_mem(pages, 6, 6 * PAGE, DIR_INOUT);
      M.fault_insert_at = 2; M.fault_insert_partial = 1; M.fault_clear = 1;
      M.mems[mem].prep++; CHECK(!native_wire(&M.mems[mem])); M.mems[mem].prep--;
      struct map *m = map_of(mem);
      CHECK((m->r.flags & ADRENO_RESOURCE_FAILED) && (m->r.flags & ADRENO_RESOURCE_PINNED) && m->backing >= 0);
      check_all(1);
      struct adreno_resource_ops o = ops_for(m);
      struct counts before = M.c;
      CHECK(adreno_resource_unwire(&m->r, &o, &M.res, 1) != 0 && !(m->r.flags & ADRENO_RESOURCE_RESIDENT));
      CHECK(adreno_resource_free_with(&m->r, &o, &M.res, RUNS) != 0);
      CHECK(!memcmp(&before, &M.c, sizeof(before)) && M.res.bytes == 0);
      m->leaked = 1; m->live = 0; check_all(1); }
    /* 6. Budget: three one-page maps fit, the fourth releases; a rewire uncharges. */
    reset(1, RUNS, 3 * PAGE, 6);
    { int mems[4];
      for (int i = 0; i < 4; i++) { uint32_t p = 900 + 10 * (uint32_t)i; mems[i] = scenario_mem(&p, 1, PAGE, DIR_INOUT); wire_check(mems[i]); }
      for (int i = 0; i < 4; i++) native_unwire(&M.mems[mems[i]]);
      check_all(1);
      CHECK(M.res.bytes == 3 * PAGE && M.res.retained == 3 && M.res.refused == 1 && M.c.clears == 1 && M.c.unpins == 1);
      CHECK(!(map_of(mems[3])->r.flags & ADRENO_RESOURCE_RESIDENT));
      wire_check(mems[0]);
      CHECK(M.res.bytes == 2 * PAGE && M.res.reused == 1 && M.c.inserts == 4);
      wire_check(mems[3]); native_unwire(&M.mems[mems[3]]);
      CHECK(M.res.bytes == 3 * PAGE && M.c.inserts == 5);
      for (int i = 0; i < 4; i++) free_mem(mems[i]);
      CHECK(M.res.bytes == 0 && M.c.native_frees == 4); check_all(1); }
    /* 7. Replaced descriptor: the stale resident mapping is released before the new one is pinned;
     *    the old pages cannot move while resident. */
    reset(1, RUNS, 512 * MiB, 7);
    { uint32_t pages[3] = {1000, 1001, 1002};
      int mem = scenario_mem(pages, 3, 3 * PAGE, DIR_INOUT);
      wire_check(mem); native_unwire(&M.mems[mem]);
      int old = M.mems[mem].desc;
      replace_backing(&M.mems[mem]);
      CHECK(M.descs[old].live && M.descs[old].our_pins == 1);
      vm_move(old); CHECK(M.descs[old].pages[0] == 1000);
      check_all(1);
      wire_check(mem);
      CHECK(M.res.evicted == 1 && M.c.clears == 1 && M.c.unpins == 1 && M.c.pins == 2 && !M.descs[old].live);
      free_mem(mem); check_all(1); }
    /* 8. ...and if releasing the stale mapping fails: frozen, still pinned and charged, nothing new pinned. */
    reset(1, RUNS, 512 * MiB, 8);
    { uint32_t pages[3] = {1000, 1001, 1002};
      int mem = scenario_mem(pages, 3, 3 * PAGE, DIR_INOUT);
      wire_check(mem); native_unwire(&M.mems[mem]);
      replace_backing(&M.mems[mem]);
      int fresh = M.mems[mem].desc;
      M.fault_clear = 1;
      M.mems[mem].prep++; CHECK(!native_wire(&M.mems[mem])); M.mems[mem].prep--;
      struct map *m = map_of(mem);
      CHECK((m->r.flags & ADRENO_RESOURCE_FAILED) && (m->r.flags & ADRENO_RESOURCE_RESIDENT));
      CHECK(M.res.bytes == 3 * PAGE && M.descs[fresh].our_pins == 0 && M.c.inserts == 1);
      check_all(1);
      m->leaked = 1; m->live = 0; M.mems[mem].nmaps = 0; check_all(1); }
    /* 9. Read-only fallback is never retained; a read-only descriptor is, with no-write leaves. */
    reset(1, RUNS, 512 * MiB, 9);
    { uint32_t a[2] = {1100, 1101}, b[2] = {1200, 1201};
      int rw = scenario_mem(a, 2, 2 * PAGE, DIR_INOUT), ro = scenario_mem(b, 2, 2 * PAGE, DIR_OUT);
      M.descs[M.mems[rw].desc].ro_other = 1;
      wire_check(rw); wire_check(ro);
      CHECK(map_of(rw)->backing_dir == DIR_OUT && map_of(ro)->backing_dir == DIR_OUT);
      native_unwire(&M.mems[rw]); native_unwire(&M.mems[ro]);
      CHECK(!(map_of(rw)->r.flags & ADRENO_RESOURCE_RESIDENT) && (map_of(ro)->r.flags & ADRENO_RESOURCE_RESIDENT));
      M.descs[M.mems[rw].desc].ro_other = 0;
      wire_check(rw);
      CHECK(map_of(rw)->backing_dir == DIR_INOUT && !(M.leaves[leaf_index(map_of(rw)->r.address)] & NO_WRITE));
      free_mem(rw); free_mem(ro); check_all(1); }
    /* 10. Unwire of a resident mapping is a real release, charged once. */
    reset(1, RUNS, 512 * MiB, 10);
    { uint32_t p = 1300; int mem = scenario_mem(&p, 1, PAGE, DIR_INOUT);
      wire_check(mem); native_unwire(&M.mems[mem]);
      struct map *m = map_of(mem); struct adreno_resource_ops o = ops_for(m);
      CHECK(adreno_resource_unwire(&m->r, &o, &M.res, 1) == 0);
      CHECK(!(m->r.flags & (ADRENO_RESOURCE_RESIDENT | ADRENO_RESOURCE_PINNED)) && M.res.bytes == 0 && M.c.clears == 1);
      check_all(1); free_mem(mem); check_all(1); }
    /* 11. Final free of a resident mapping: no recommit; native free sees it complete. */
    reset(1, RUNS, 512 * MiB, 11);
    { uint32_t pages[3] = {1400, 1402, 1404}; int mem = scenario_mem(pages, 3, 3 * PAGE, DIR_INOUT);
      wire_check(mem); native_unwire(&M.mems[mem]);
      uint64_t inserts = M.c.inserts;
      free_mem(mem);
      CHECK(M.c.inserts == inserts && M.c.native_frees == 1 && M.c.clears == 0 && M.res.bytes == 0); check_all(1); }
    /* 12. Final free fails in native free, or in the unpin: frozen, charge kept. */
    for (int which = 0; which < 2; which++) {
        reset(1, RUNS, 512 * MiB, 12);
        uint32_t p = 1500; int mem = scenario_mem(&p, 1, PAGE, DIR_INOUT);
        wire_check(mem); native_unwire(&M.mems[mem]);
        struct map *m = map_of(mem); struct adreno_resource_ops o = ops_for(m);
        if (which) M.fault_unpin = 1; else M.fault_free = 1;
        CHECK(adreno_resource_free_with(&m->r, &o, &M.res, RUNS) != 0);
        CHECK((m->r.flags & ADRENO_RESOURCE_FAILED) && (m->r.flags & ADRENO_RESOURCE_RESIDENT) && M.res.bytes == PAGE);
        CHECK(!!(m->r.flags & ADRENO_RESOURCE_RESERVED) == !which && m->backing >= 0);
        struct counts before = M.c;
        CHECK(adreno_resource_free_with(&m->r, &o, &M.res, RUNS) != 0 && !memcmp(&before, &M.c, sizeof(before)));
        if (which) { for (unsigned i = 0; i < WINDOW_PAGES; i++) CHECK(!M.leaves[i]); }
        /* The DART range is gone (which == 1) while CB0 would still hold it under the v8 glue order: the V1
         * hazard race() shows. Batch 8 frees CB0 first (adreno_resource_retire); model that here. */
        native_unbind(m);
        m->leaked = 1; m->live = 0; M.mems[mem].nmaps = 0;
        check_all(1);
    }
    /* 13. A resident (natively unwired) mapping is refused for submissions and cache maintenance. */
    reset(1, RUNS, 512 * MiB, 13);
    { uint32_t p = 1600; int mem = scenario_mem(&p, 1, PAGE, DIR_INOUT);
      wire_check(mem); native_unwire(&M.mems[mem]);
      struct map *m = map_of(mem);
      CHECK(!admitted(m) && adreno_resource_cache(&m->r, 0, NULL, NULL) == ADRENO_RESOURCE_E_STATE);
      free_mem(mem); check_all(1); }
    /* 14. Budget 0 and the old entry points never retain; the old commit stays page by page. */
    reset(1, RUNS, 0, 14);
    { uint32_t pages[3] = {1700, 1701, 1702}; int mem = scenario_mem(pages, 3, 3 * PAGE, DIR_INOUT);
      wire_check(mem); native_unwire(&M.mems[mem]);
      CHECK(!(map_of(mem)->r.flags & ADRENO_RESOURCE_RESIDENT) && M.c.clears == 1 && M.c.unpins == 1 && M.c.inserts == 1);
      free_mem(mem); check_all(1); }
    reset(0, 0, 512 * MiB, 15);
    { uint32_t pages[3] = {1700, 1701, 1702}; int mem = scenario_mem(pages, 3, 3 * PAGE, DIR_INOUT);
      wire_check(mem); native_unwire(&M.mems[mem]); free_mem(mem);
      CHECK(M.c.inserts == 6 && M.c.clears == 1 && M.c.unpins == 2 && M.res.bytes == 0 && !M.res.retained); check_all(1); }
    printf("PASS scenarios\n");
}

/* 16. V1 (FAILURES-AND-DESIGN.md 1.3): another thread creates a map of the same size between the two halves
 * of a release, and the DART hands the just-freed range out first. Reported, not asserted, so the base runs
 * through: the v8 order (DART first, CB0 second) must show the collisions, the batch-8 order none. */
static void race(void)
{
    static const char *names[] = {"old", "resident", "pool"};
#ifdef RESOURCE_BASE
    const int policies = 2;
#else
    const int policies = 3;
#endif
    for (int policy = 0; policy < policies; policy++) {
        reset(policy, policy ? ADRENO_COMMIT_RUNS : 0, policy == 1 ? 512ULL << 20 : 0, 16);
        unsigned attempts = 0;
        for (int wired = 0; wired < 2; wired++) {
            for (int round = 0; round < 4; round++) {
                int victim = new_mem(64 * PAGE, DIR_INOUT, 0);
                struct mem *me = &M.mems[victim];
                me->prep++; CHECK(native_wire(me)); me->prep--;
                if (!wired) native_unwire(me);              /* freed after the scheduler's unwire, or still wired */
                M.race.armed = 1; attempts++;
                free_mem(victim);
                CHECK(!M.race.armed);
                check_all(1);
            }
        }
        printf("RACE {\"policy\": \"%s\", \"attempts\": %u, \"bind_failed\": %llu, \"bind_busy\": %llu, "
               "\"race_failed\": %llu}\n", names[policy], attempts, (unsigned long long)M.c.alloc_failed,
               (unsigned long long)M.c.bind_busy, (unsigned long long)M.c.race_failed);
#ifndef RESOURCE_BASE
        /* The batch-8 order: the racing map never meets the dying map's range, not even as a retried collision. */
        if (policy == 2) CHECK(!M.c.alloc_failed && !M.c.bind_busy && !M.pool.collisions);
#endif
        for (int i = 0; i < M.nmems; i++) if (M.mems[i].live) free_mem(i);
        check_all(1);
    }
    printf("PASS race\n");
}

#ifndef RESOURCE_BASE
/* The pool (D1-D10) and the bind retry (V2-V6). */
static void pool_scenarios(void)
{
    const unsigned RUNS = ADRENO_COMMIT_RUNS;
    /* 17. D2: a buffer freed after its unwire is retired without a recommit or a native free; the next buffer
     *     of its span reuses the reservation; one freed while wired is cleared by finalize, then pooled. */
    reset(2, RUNS, 0, 17);
    { int a = new_mem(64 * PAGE, DIR_INOUT, 0);
      wire_check(a); native_unwire(&M.mems[a]);
      uint64_t inserts = M.c.inserts, reserves = M.c.reserves, clears = M.c.clears;
      free_mem(a);
      CHECK(M.c.inserts == inserts && M.c.native_frees == 0 && M.c.clears == clears && M.pool.count == 1 &&
            M.pool.puts == 1 && M.c.pins == 1 && M.c.unpins == 1);
      check_all(1);
      int b = new_mem(64 * PAGE, DIR_INOUT, 0);
      CHECK(M.c.reserves == reserves && M.pool.takes == 1 && M.pool.count == 0);
      wire_check(b);
      CHECK(M.c.map_pages == 128);
      free_mem(b);
      CHECK(M.c.native_frees == 0 && M.pool.count == 1 && M.c.map_pages == 128);
      check_all(1); }
    /* 18. D4: no reuse across spans. */
    reset(2, RUNS, 0, 18);
    { int a = new_mem(64 * PAGE, DIR_INOUT, 0); free_mem(a);
      uint64_t reserves = M.c.reserves;
      int b = new_mem(65 * PAGE - 0x100, DIR_INOUT, 0);
      CHECK(M.c.reserves == reserves + 1 && M.pool.count == 1 && M.pool.takes == 0);
      free_mem(b); CHECK(M.pool.count == 2); check_all(1); }
    /* 19. D5, D2: a full pool sends the reservation down the strict path: recommit, native free, unpin. */
    reset(2, RUNS, 0, 19);
    { M.pool.limit_bytes = 2 * 64 * PAGE;
#if ADRENO_POOL_ARENA
      M.pool.arena_span = 0;      /* batch 8's general rules alone; scenario 25 checks the class */
#endif
      int m[3];
      for (int i = 0; i < 3; i++) m[i] = new_mem(64 * PAGE, DIR_INOUT, 0);
      for (int i = 0; i < 3; i++) free_mem(m[i]);
      CHECK(M.pool.count == 2 && M.pool.refused == 1 && M.c.native_frees == 1 && M.c.map_pages == 64);
      check_all(1); }
    /* ...and one span never holds more than ADRENO_VA_POOL_PER_SPAN entries. */
    reset(2, RUNS, 0, 19);
    { int m[ADRENO_VA_POOL_PER_SPAN + 1];
      for (unsigned i = 0; i <= ADRENO_VA_POOL_PER_SPAN; i++) m[i] = new_mem(PAGE, DIR_INOUT, 0);
      for (unsigned i = 0; i <= ADRENO_VA_POOL_PER_SPAN; i++) free_mem(m[i]);
      CHECK(M.pool.count == ADRENO_VA_POOL_PER_SPAN && M.pool.refused == 1 && M.c.native_frees == 1);
      int other = new_mem(2 * PAGE, DIR_INOUT, 0); free_mem(other);
      CHECK(M.pool.count == ADRENO_VA_POOL_PER_SPAN + 1);
      check_all(1); }
    /* 20. D5: spans above 4 MiB are never pooled. */
    reset(2, RUNS, 0, 20);
    { int a = new_mem(257 * PAGE, DIR_INOUT, 0); free_mem(a);
      CHECK(M.pool.count == 0 && M.pool.refused == 0 && M.c.native_frees == 1 && M.c.map_pages == 257);
      check_all(1); }
    /* 21. V3: a CB0 collision (a foreign holder) retries with a fresh DART reservation; the colliding one is
     *     parked in the pool (suspect: never handed out), never returned to the DART. Three collisions fail. */
    reset(2, RUNS, 0, 21);
    { for (unsigned k = 0; k < 64; k++) M.native_owner[k] = -1;
      int a = new_mem(64 * PAGE, DIR_INOUT, 0);
      CHECK(M.pool.collisions == 1 && M.pool.retried == 1 && M.c.alloc_failed == 0 && M.pool.count == 1 &&
            M.pool.suspects == 1 && map_of(a)->r.address != ADRENO_WINDOW_BASE);
      check_all(1);
      int b = new_mem(64 * PAGE, DIR_INOUT, 0);                 /* a suspect entry is never taken */
      CHECK(M.pool.takes == 0 && map_of(b)->r.address != ADRENO_WINDOW_BASE);
      unsigned next = leaf_index(map_of(b)->r.address) + 64;
      for (unsigned k = 0; k < 3 * 64; k++) M.native_owner[next + k] = -1;
      CHECK(new_mem_try(64 * PAGE, DIR_INOUT) < 0);
      CHECK(M.pool.gave_up == 1 && M.pool.collisions == 4 && M.pool.count == 4 && M.c.alloc_failed == 1 &&
            M.c.native_frees == 0);
      check_all(1);
      free_mem(a); free_mem(b);
      CHECK(M.pool.count == 6);
      check_all(1); }
    /* 22. V4, V6: the native allocation succeeds but add_mapping's commit fails: no retry, the CB0 range is
     *     freed first, the unwound reservation is pooled. */
    reset(2, RUNS, 0, 22);
    { uint32_t pages[4] = {2000, 2001, 2002, 2003};
      int mem = scenario_mem(pages, 4, 4 * PAGE, DIR_INOUT);
      wire_check(mem);
      M.mems[mem].prep++;
      M.fault_insert_at = (unsigned)M.c.inserts + 1; M.fault_insert_partial = 1;
#if ADRENO_RESIDENT_REPIN
      /* resident-evict: the cleanly refused commit is reported committed: the map is bound, unadmitted, and its next
       * preparation pins and maps it at the same address. */
      int alias = new_map_try(mem);
      M.fault_insert_at = 0;
      CHECK(alias >= 0 && !admitted(&M.maps[alias]) && M.maps[alias].refusal == ADRENO_RESOURCE_E_INSERT &&
            M.pool.unbound == 0 && M.c.alloc_failed == 0);
      const uint64_t va = M.maps[alias].r.address;
      CHECK(glue_prepare(&M.maps[alias]) && M.maps[alias].r.address == va);
      check_gpu_view(&M.maps[alias], 1);
      M.mems[mem].prep--;
      check_all(1);
      drop_map(&M.mems[mem], M.mems[mem].nmaps - 1);
      CHECK(M.pool.count == 1 && M.c.native_frees == 0);
#else
      CHECK(new_map_try(mem) < 0);
      M.fault_insert_at = 0;
      M.mems[mem].prep--;
      CHECK(M.pool.unbound == 1 && M.pool.retried == 0 && M.pool.collisions == 0 && M.pool.count == 1 &&
            M.c.alloc_failed == 1 && M.c.native_frees == 0);
#endif
      check_all(1);
      free_mem(mem); check_all(1); }
    /* 23. V2, D7: a clear that fails during retire freezes the resource: CB0 already freed, nothing pooled,
     *     the DART reservation, leaves, pin and charge kept. */
    reset(2, RUNS, 512ULL << 20, 23);
    { int a = new_mem(8 * PAGE, DIR_INOUT, 0);
      wire_check(a); native_unwire(&M.mems[a]);
      struct map *m = map_of(a);
      CHECK(m->r.flags & ADRENO_RESOURCE_RESIDENT);
      M.fault_clear = 1;
      free_mem(a);
      CHECK(m->leaked && (m->r.flags & ADRENO_RESOURCE_FAILED) && !m->native && M.pool.count == 0 &&
            M.res.bytes == 8 * PAGE && m->backing >= 0);
      check_all(1); }
    /* 24. D1: a resident buffer (budget > 0) is cleared and unpinned by retire before it is pooled. */
    reset(2, RUNS, 512ULL << 20, 24);
    { int a = new_mem(8 * PAGE, DIR_INOUT, 0);
      wire_check(a); native_unwire(&M.mems[a]);
      CHECK(map_of(a)->r.flags & ADRENO_RESOURCE_RESIDENT);
      free_mem(a);
      CHECK(M.pool.count == 1 && M.c.native_frees == 0 && M.res.bytes == 0 && M.c.clears == 1 && M.res.evicted == 1);
      check_all(1); }
#if ADRENO_POOL_ARENA
    /* 25. Batch 9 K2, K4, K7: the arena class. Other spans fill the general budget, and arenas are still pooled,
     *     past the per-span cap, up to arena_limit; the next one takes the strict path; a take is exact-span and
     *     leaves the class one entry smaller. */
    reset(2, RUNS, 0, 25);
    { M.pool.limit_bytes = 4 * 64 * PAGE; M.pool.arena_limit = ADRENO_VA_POOL_PER_SPAN + 8;
      int g[4];
      for (int i = 0; i < 4; i++) g[i] = new_mem(63 * PAGE, DIR_INOUT, 0);
      for (int i = 0; i < 4; i++) free_mem(g[i]);
      int y = new_mem(62 * PAGE, DIR_INOUT, 0); free_mem(y);           /* 252 + 62 pages > 256: refused */
      CHECK(M.pool.count == 4 && M.pool.refused == 1 && M.c.native_frees == 1 && M.pool.arena_count == 0);
      check_all(1);
      int a[ADRENO_VA_POOL_PER_SPAN + 9];
      for (unsigned i = 0; i < ADRENO_VA_POOL_PER_SPAN + 9; i++) {
          a[i] = new_mem(64 * PAGE, DIR_INOUT, 0);
          if (i & 1) wire_check(a[i]);
      }
      for (unsigned i = 0; i < ADRENO_VA_POOL_PER_SPAN + 9; i++) free_mem(a[i]);
      CHECK(M.pool.arena_count == ADRENO_VA_POOL_PER_SPAN + 8 && M.pool.count == ADRENO_VA_POOL_PER_SPAN + 12 &&
            M.pool.refused == 2 && M.c.native_frees == 2);
      check_all(1);
      uint64_t reserves = M.c.reserves;
      int b = new_mem(64 * PAGE, DIR_INOUT, 0);
      CHECK(M.pool.takes == 1 && M.pool.arena_count == ADRENO_VA_POOL_PER_SPAN + 7 && M.c.reserves == reserves);
      int c2 = new_mem(64 * PAGE - 0x4000, DIR_INOUT, 0);              /* 63 pages: a general entry, not an arena */
      CHECK(M.pool.takes == 2 && M.pool.arena_count == ADRENO_VA_POOL_PER_SPAN + 7);
      free_mem(b); free_mem(c2);
      CHECK(M.pool.arena_count == ADRENO_VA_POOL_PER_SPAN + 8 && M.pool.refused == 2);
      check_all(1); }
    /* ...K6: a collision of the arena span is parked under the general rules and never taken. */
    reset(2, RUNS, 0, 25);
    { for (unsigned k = 0; k < 64; k++) M.native_owner[k] = -1;
      int a = new_mem(64 * PAGE, DIR_INOUT, 0);
      CHECK(M.pool.collisions == 1 && M.pool.suspects == 1 && M.pool.count == 1 && M.pool.arena_count == 0);
      check_all(1);
      int b = new_mem(64 * PAGE, DIR_INOUT, 0);
      CHECK(M.pool.takes == 0);
      free_mem(a); free_mem(b);
      CHECK(M.pool.arena_count == 2 && M.pool.count == 3);
      int c2 = new_mem(64 * PAGE, DIR_INOUT, 0);
      CHECK(M.pool.takes == 1 && M.pool.arena_count == 1 && map_of(c2)->r.address != ADRENO_WINDOW_BASE);
      free_mem(c2);
      check_all(1); }
#endif
#if ADRENO_VA_RECLAIM
    /* 26. G1, G6, G7, G9: a refused reserve drains the pool, never a parked collision, and retries; a drain that leaves
     *     no hole of the span fails cleanly (bounded); pressure then sends a freed reservation back to the DART, filled,
     *     and the next reserve fits without a reclaim. A 4 MiB DART: [0,64) collides in CB0, [128,160) is pooled. */
    reset(2, RUNS, 0, 26);
    { M.window_pages = 4 * 64;
      for (unsigned k = 0; k < 64; k++) M.native_owner[k] = -1;          /* a foreign CB0 user */
      int a = new_mem(64 * PAGE, DIR_INOUT, 0);                          /* [0,64) parked suspect, lands at [64,128) */
      CHECK(M.pool.suspects == 1 && M.pool.count == 1 && map_of(a)->r.address == ADRENO_WINDOW_BASE + 64 * PAGE);
      int b = new_mem(32 * PAGE, DIR_INOUT, 0); free_mem(b);             /* [128,160) pooled */
      int c = new_mem(64 * PAGE, DIR_INOUT, 0);                          /* [160,224) */
      CHECK(M.pool.count == 2 && map_of(c)->r.address == ADRENO_WINDOW_BASE + 160 * PAGE);
      check_all(1);
      CHECK(new_mem_try(64 * PAGE, DIR_INOUT) < 0);                      /* 32 + 32 free pages, never 64 in a row */
      CHECK(M.pool.exhausted == 1 && M.pool.reclaim_failed == 1 && M.pool.reclaimed == 0 && M.pool.drained == 1 &&
            M.pool.drained_bytes == 32 * PAGE && M.pool.count == 1 && (M.pool.flags[0] & ADRENO_VA_POOL_SUSPECT) &&
            M.pool.pressure == ADRENO_VA_PRESSURE_PUTS && M.c.alloc_failed == 1 && M.filled_frees == 1);
      check_all(1);
      free_mem(c);                                                       /* refused for pressure: filled strict free */
      CHECK(M.pool.pressure_refused == 1 && M.pool.filled == 1 && M.filled_frees == 2 && M.pool.count == 1 &&
            M.pool.pressure == ADRENO_VA_PRESSURE_PUTS - 1 && M.c.pins == 0);
      int d = new_mem(64 * PAGE, DIR_INOUT, 0);                          /* [128,192): no reclaim needed */
      CHECK(M.pool.exhausted == 1 && map_of(d)->r.address == ADRENO_WINDOW_BASE + 128 * PAGE);
      check_all(1);
      /* Under pressure a new collision is still parked (G1), not handed back to the DART to collide again. */
      for (unsigned k = 192; k < 256; k++) M.native_owner[k] = -1;
      CHECK(new_mem_try(64 * PAGE, DIR_INOUT) < 0);
      CHECK(M.pool.suspects == 2 && M.pool.count == 2 && M.pool.collisions == 2 && M.pool.exhausted == 2 &&
            M.pool.drained == 1 && M.pool.reclaim_failed == 2);
      check_all(1);
      free_mem(a); free_mem(d);
      CHECK(M.pool.count == 2 && (M.pool.flags[0] & ADRENO_VA_POOL_SUSPECT) && (M.pool.flags[1] & ADRENO_VA_POOL_SUSPECT));
      check_all(1); }
    /* 27. G2: a filler insert that fails never reaches the native free: the reservation is lost (frozen, counted) with
     *     the filler leaves it got; a failed filled free keeps every leaf. Both are what a frozen resource is today. */
    reset(2, RUNS, 0, 27);
    { int a = new_mem(64 * PAGE, DIR_INOUT, 0), b = new_mem(300 * PAGE, DIR_INOUT, 0);   /* b: above max_span */
      M.fault_fill_insert = (unsigned)M.fill_inserts + 2;
      free_mem(b);
      CHECK(M.pool.lost == 1 && M.pool.lost_bytes == 300 * PAGE && M.c.native_frees == 0 && M.c.frozen == 1 &&
            M.fill_inserts == 2);
      check_all(1);
      M.pool.pressure = 1; M.fault_fill_free = 1;
      free_mem(a);
      CHECK(M.pool.lost == 2 && M.c.native_frees == 0 && M.c.frozen == 2 && M.pool.count == 0);
      for (uint64_t off = 0; off < 64 * PAGE; off += PAGE) CHECK(filler_leaf(M.leaves[leaf_index(map_of(a)->r.address + off)]));
      check_all(1); }
    /* 28. G5, G12: the final free of a released map whose backing cannot be pinned again (b11v1: 47 x "address
     *     release failed -83 native=0xe00002c2"): the filler stands in, nothing is frozen, no pin is tried; without
     *     the filler it freezes as today. */
    for (int with = 1; with >= 0; with--) {
        reset(2, RUNS, 0, 28);
        if (!with) no_filler();
        int a = new_mem(300 * PAGE, DIR_INOUT, 0);
        wire_check(a); native_unwire(&M.mems[a]);
        uint64_t pins = M.c.pins;
        M.fault_pin = 1;
        free_mem(a);
        if (with) CHECK(!M.c.frozen && M.filled_frees == 1 && M.c.native_frees == 1 && M.fault_pin == 1 && M.c.pins == pins);
        else CHECK(M.c.frozen == 1 && M.c.native_frees == 0 && !M.fault_pin && !M.filled_frees);
        M.fault_pin = 0;
        check_all(1);
    }
    /* 29. G3: a pinned (resident) reservation keeps the old strict path: its own complete leaves, never the filler. */
    reset(2, RUNS, 512ULL << 20, 29);
    { int a = new_mem(300 * PAGE, DIR_INOUT, 0);
      wire_check(a); native_unwire(&M.mems[a]);
      CHECK(map_of(a)->r.flags & ADRENO_RESOURCE_RESIDENT);
      free_mem(a);
      CHECK(!M.fill_inserts && !M.filled_frees && M.c.native_frees == 1 && !M.c.frozen && M.res.bytes == 0);
      check_all(1); }
#endif
    printf("PASS pool\n");
}
#endif

#ifndef RESOURCE_BASE
/* ---- agents/resident-evict (REPORT.md): b12v17's "map failed -83" ---- */
/* A client buffer: the descriptor holds `bytes`, IOGPU's memory (and map) length is its page-rounded DMA length
 * (IOGPUSysMemory::withClientBuffer 0x56338-0x5636c). */
static int tail_mem(uint64_t bytes)
{
    CHECK(M.nmems < MAX_MEMS);
    int id = M.nmems++;
    struct mem *me = &M.mems[id];
    memset(me, 0, sizeof(*me));
    me->live = 1; me->maplen = (bytes + PAGE - 1) & ~(PAGE - 1);
    me->desc = new_desc(bytes, DIR_INOUT);
    M.descs[me->desc].refs = 1;
    new_map(id);
    return id;
}
/* display-modeset: a client buffer of `bytes` at a page-unaligned address: its first byte `head` bytes into its first
 * page, IOGPU's memory (and map) length round_page(page offset + length). */
static int head_mem(uint64_t bytes, uint64_t head)
{
    CHECK(M.nmems < MAX_MEMS);
    int id = M.nmems++;
    struct mem *me = &M.mems[id];
    memset(me, 0, sizeof(*me));
    me->live = 1; me->maplen = (head + bytes + PAGE - 1) & ~(PAGE - 1);
    me->desc = new_desc_at(bytes, DIR_INOUT, head);
    M.descs[me->desc].refs = 1;
    new_map(id);
    return id;
}
#if ADRENO_RESIDENT_REPIN
struct cache_call { uint64_t va, bytes; unsigned direction; };
static struct cache_call calls[8];
static unsigned ncalls;
static int record_cache(void *ctx, uint64_t va, uint64_t bytes, unsigned direction)
{
    (void)ctx; CHECK(ncalls < 8); calls[ncalls++] = (struct cache_call){va, bytes, direction};
    return 0;
}
#endif
static void repin_scenarios(void)
{
    const unsigned RUNS = ADRENO_COMMIT_RUNS;
    /* 30. Evict -> re-prepare -> submit (the deployed pool, arena and reclaim build): two 64-page maps fit the budget,
     *     the third unwire is refused and released; a replaced descriptor evicts a resident map. Both re-prepare at
     *     their own reserved address, pin and map again, and a submission of both is admitted with the GPU seeing the
     *     current descriptor. With and without the define: eviction was never the fault. */
    reset(2, RUNS, 2 * 64 * PAGE, 30);
    { int a = new_mem(64 * PAGE, DIR_INOUT, 0), b = new_mem(64 * PAGE, DIR_INOUT, 0), c = new_mem(64 * PAGE, DIR_INOUT, 0);
      wire_check(a); wire_check(b); wire_check(c);
      const uint64_t va = map_of(a)->r.address, vc = map_of(c)->r.address;
      native_unwire(&M.mems[a]); native_unwire(&M.mems[b]); native_unwire(&M.mems[c]);
      CHECK(M.res.retained == 2 && M.res.refused == 1 && map_of(c)->backing < 0 &&
            map_of(c)->r.flags == ADRENO_RESOURCE_RESERVED);                     /* budget eviction */
      replace_backing(&M.mems[a]);
      check_all(1);
      uint64_t pins = M.c.pins;
      int list[2] = {a, c}, writes[2] = {1, 1};
      CHECK(submit(list, writes, 2));                                             /* re-prepare both, then use them */
      CHECK(M.res.evicted == 1 && M.c.pins == pins + 2 && map_of(a)->r.address == va && map_of(c)->r.address == vc);
      CHECK(admitted(map_of(a)) && admitted(map_of(c)) && map_of(a)->backing == M.mems[a].desc);
      for (int i = 0; i < M.nmems; i++) if (M.mems[i].live) free_mem(i);
      CHECK(M.res.bytes == 0); check_all(1); }
    /* 31. b12v17: a buffer of 3 pages + 0x1010 bytes under IOGPU's 4-page map. The base refuses the pin on every wire
     *     (E_PIN, kIOReturnBadArgument), before and after any eviction; with the define it pins, maps the last page
     *     whole, survives unwire, budget eviction and a replaced descriptor, and its cache maintenance stops at the
     *     descriptor's last line, the partial one cleaned rather than invalidated. */
    reset(2, RUNS, 512ULL << 20, 31);
    { const uint64_t bytes = 3 * PAGE + 0x1010;
      int t = tail_mem(bytes);
      struct mem *me = &M.mems[t];
      CHECK(map_of(t)->r.logical_length == 4 * PAGE);
      for (int round = 0; round < 3; round++) {
          me->prep++;
#if ADRENO_RESIDENT_REPIN
          CHECK(me->wired || native_wire(me));
          CHECK(admitted(map_of(t)) && map_of(t)->tail == bytes && map_of(t)->r.mapped_length == 4 * PAGE);
          check_gpu_view(map_of(t), 1);
          me->prep--;
          check_all(1);
          if (round == 0) native_unwire(me);                                      /* resident */
          if (round == 1) { native_unwire(me); replace_backing(me); }             /* stale: evicted, re-pinned */
          if (round == 2) { M.res.budget = 0; native_unwire(me); }                /* released: re-pinned at free */
#else
          const uint64_t pins = M.c.pins;
          CHECK(!native_wire(me) && !admitted(map_of(t)) && map_of(t)->backing < 0 && M.c.pins == pins);
          me->prep--;
          check_all(1);
#endif
      }
#if ADRENO_RESIDENT_REPIN
      CHECK(M.res.evicted == 1);
      me->prep++; CHECK(native_wire(me)); me->prep--;
      for (unsigned dir = ADRENO_CACHE_TO_DEVICE; dir <= ADRENO_CACHE_FROM_DEVICE; dir++) {
          ncalls = 0;
          const struct map *m = map_of(t);
          CHECK(!adreno_tail_cache(&m->r, m->tail, dir, 0, m->r.logical_length, record_cache, NULL));
          const uint64_t end = m->r.address + ((bytes + 63) & ~63ULL), whole = m->r.address + (bytes & ~63ULL);
          CHECK(ncalls == (dir == ADRENO_CACHE_FROM_DEVICE ? 2u : 1u) && calls[0].va == m->r.address);
          CHECK(calls[ncalls - 1].va + calls[ncalls - 1].bytes == end);
          if (dir == ADRENO_CACHE_FROM_DEVICE)
              CHECK(calls[0].bytes == whole - m->r.address && calls[0].direction == dir &&
                    calls[1].va == whole && calls[1].direction == ADRENO_CACHE_TO_DEVICE);
      }
      native_unwire(me);
#endif
      free_mem(t); check_all(1); }
    /* 32. A map that cannot be pinned (here: its own refusal) among the maps of one memory. The base fails the native
     *     wire of the whole memory, so the other task's submission fails too; with the define the memory wires, the
     *     other map is admitted, the refused map stays unadmitted and retries at its own preparation. */
    reset(2, RUNS, 512ULL << 20, 32);
    { int s = new_mem(4 * PAGE, DIR_INOUT, 0);
      new_map(s);
      struct mem *me = &M.mems[s];
      struct map *own = &M.maps[me->maps[0]], *other = &M.maps[me->maps[1]];
      other->refuse_pin = 1;
      me->prep++;
#if ADRENO_RESIDENT_REPIN
      CHECK(native_wire(me));
      CHECK(admitted(own) && !admitted(other) && other->committed && other->refusal == ADRENO_RESOURCE_E_PIN);
      check_gpu_view(own, 1);
      CHECK(!glue_prepare(other));
      other->refuse_pin = 0;
      CHECK(glue_prepare(other) && !other->refusal);
      check_gpu_view(other, 1);
      me->prep--;
      check_all(1);
      native_unwire(me);
#else
      CHECK(!native_wire(me) && !admitted(own) && !admitted(other));
      me->prep--;
      other->refuse_pin = 0;
#endif
      check_all(1);
      free_mem(s); check_all(1); }
    /* 33. org2 and b12v23: WindowServer's 16 KiB buffer at a page-unaligned address under IOGPU's 32 KiB map. Without the
     *     head rule every wire reports it committed (clean refusal, E_PIN) and every submission that lists it is refused,
     *     round after round, as the -115 lines of both runs; with it the pin is admitted, the map's two pages are the
     *     descriptor's two pages, every client byte the GPU reaches through the head-moved offset is the CPU's byte, the
     *     cache passes touch only the descriptor's lines, and it survives unwire, eviction and a replaced descriptor. */
    {   static const uint64_t heads[] = {0x10, 0x40, 0x200, 0x1000, 0x2a0c, 0x3fc0, 0x3ff0};
        const uint64_t bytes = 0x4000;
        for (unsigned h = 0; h < sizeof heads / sizeof heads[0]; h++) {
            const uint64_t head = heads[h];
            reset(2, RUNS, 512ULL << 20, 33 + h);
            int t = head_mem(bytes, head);
            struct mem *me = &M.mems[t];
            CHECK(map_of(t)->r.logical_length == 2 * PAGE && M.descs[me->desc].npages == 2);
            int list[1] = {t}, writes[1] = {1};
            for (int round = 0; round < 3; round++) {
#if ADRENO_RESIDENT_HEAD_OFFSET
                CHECK(submit(list, writes, 1));
                const struct map *m = map_of(t);
                CHECK(admitted(m) && m->head == head && m->tail == bytes && m->r.mapped_length == 2 * PAGE);
                me->prep++; check_gpu_view(m, 1);
                for (uint64_t k = 0; k < bytes; k += (k < 256 || k > bytes - 256) ? 1 : 61) {
                    uint64_t at = 0;
                    CHECK(adreno_head_range(m->head, m->tail, k, 1, &at) && at == head + k);   /* resolveRange */
                    const uint64_t va = m->r.address + at, leaf = M.leaves[leaf_index(va & ~(PAGE - 1))];
                    const struct desc *d = &M.descs[me->desc];
                    CHECK((leaf & 1) && (leaf & ~(NO_WRITE | 1ULL)) + va % PAGE ==
                          pa_of(d->pages[(head + k) / PAGE]) + (head + k) % PAGE);           /* GPU byte == CPU byte */
                }
                uint64_t at = 0;
                CHECK(adreno_head_range(head, bytes, bytes - 4, 4, &at) && at == head + bytes - 4);
                CHECK(!adreno_head_range(head, bytes, bytes, 4, &at) && !adreno_head_range(head, bytes, bytes - 4, 8, &at) &&
                      !adreno_head_range(head, bytes, 0, bytes + 1, &at) && !adreno_head_range(head, bytes, 0, 0, &at));
                for (unsigned dir = ADRENO_CACHE_TO_DEVICE; dir <= ADRENO_CACHE_FROM_DEVICE; dir++) {
                    ncalls = 0;
                    CHECK(!adreno_head_cache(&m->r, m->head, m->tail, dir, 0, m->r.logical_length, record_cache, NULL));
                    const uint64_t first = m->r.address + (head & ~63ULL), end = m->r.address + ((head + bytes + 63) & ~63ULL);
                    CHECK(ncalls && calls[0].va == first && calls[ncalls - 1].va + calls[ncalls - 1].bytes == end);
                    for (unsigned i = 1; i < ncalls; i++) CHECK(calls[i].va == calls[i - 1].va + calls[i - 1].bytes);
                    for (unsigned i = 0; i < ncalls; i++) {
                        const uint64_t a = calls[i].va - m->r.address, b = a + calls[i].bytes;
                        /* invalidate only lines wholly the descriptor's; partial lines are cleaned and invalidated */
                        if (calls[i].direction == ADRENO_CACHE_FROM_DEVICE) CHECK(a >= head && b <= head + bytes);
                        else CHECK(calls[i].direction == ADRENO_CACHE_TO_DEVICE);
                    }
                    if (dir == ADRENO_CACHE_FROM_DEVICE)
                        CHECK(ncalls == 1u + !!(head & 63) + !!((head + bytes) & 63) &&
                              calls[!!(head & 63)].direction == ADRENO_CACHE_FROM_DEVICE);
                    else CHECK(ncalls == 1 && calls[0].direction == ADRENO_CACHE_TO_DEVICE);
                }
                me->prep--;
                check_all(1);
                if (round == 0) native_unwire(me);                                      /* resident */
                if (round == 1) { native_unwire(me); replace_backing(me); }             /* stale: evicted, re-pinned */
                if (round == 2) { M.res.budget = 0; native_unwire(me); }                /* released: re-pinned at free */
#elif ADRENO_RESIDENT_REPIN
                const uint64_t pins = M.c.pins;
                CHECK(!submit(list, writes, 1) && me->wired);           /* the memory wires; the map stays unadmitted */
                CHECK(!admitted(map_of(t)) && map_of(t)->refusal == ADRENO_RESOURCE_E_PIN && M.c.pins == pins);
                check_all(1);
                native_unwire(me);
#else
                CHECK(!submit(list, writes, 1) && !me->wired && !admitted(map_of(t)));
                check_all(1);
#endif
            }
#if ADRENO_RESIDENT_HEAD_OFFSET
            if (!(M.res.evicted == 1 && M.head_admitted == 2 && !M.head_refused))
                fatal(__LINE__, "head %llx: evicted %llu admitted %llu refused %llu", (unsigned long long)head,
                      (unsigned long long)M.res.evicted, (unsigned long long)M.head_admitted, (unsigned long long)M.head_refused);
#endif
            free_mem(t); check_all(1);
        }
    }
#if ADRENO_RESIDENT_HEAD_OFFSET
    /* 34. What the head rule still refuses, and its head-0 equivalence to the tail rule. A map a page longer than the
     *     pages the descriptor touches, a map too short for head + bytes, and boot-arg adreno_head_offset=0 are refused
     *     cleanly (nothing pinned, wired once and completed); every submission of them stays refused. */
    reset(2, RUNS, 512ULL << 20, 40);
    {   const uint64_t bytes = 0x4000, head = 0x1000;
        int longer = head_mem(bytes, head), shorter = head_mem(bytes + 0x3000, 0x1100);
        M.mems[longer].maplen = 0;                                /* the model's map length is fixed at creation: */
        CHECK(map_of(longer)->r.logical_length == 2 * PAGE);
        struct map *lm = map_of(longer);
        /* stretch the refused map by one page the way a wrong IOGPU length would: refuse, never map past the pages */
        lm->r.logical_length = 3 * PAGE;
        int a[1] = {longer}, w[1] = {0};
        CHECK(!submit(a, w, 1) && !admitted(lm) && lm->refusal == ADRENO_RESOURCE_E_PIN && lm->backing < 0);
        lm->r.logical_length = 2 * PAGE;                          /* restored: admitted */
        CHECK(submit(a, w, 1) && admitted(lm) && lm->head == head);
        struct map *sm = map_of(shorter);
        sm->r.logical_length = 2 * PAGE;                          /* 0x1100 + 0x7000 needs 3 pages */
        int b[1] = {shorter};
        CHECK(!submit(b, w, 1) && !admitted(sm) && sm->backing < 0);
        sm->r.logical_length = 3 * PAGE;
        CHECK(submit(b, w, 1) && admitted(sm));
        check_all(1);
        native_unwire(&M.mems[longer]); native_unwire(&M.mems[shorter]);
        free_mem(longer); free_mem(shorter); check_all(1);
        M.head_off = 1;                                           /* boot-arg adreno_head_offset=0 */
        int off = head_mem(bytes, head), c[1] = {off};
        CHECK(!submit(c, w, 1) && !admitted(map_of(off)) && map_of(off)->refusal == ADRENO_RESOURCE_E_PIN);
        native_unwire(&M.mems[off]); free_mem(off); check_all(1);
        M.head_off = 0;
        CHECK(M.head_refused == 2); }
    /* head 0: admission, runs and cache plans are the tail rule's, over every byte count of a few pages. */
    for (uint64_t bytes = 1; bytes <= 3 * PAGE; bytes += bytes < 300 ? 1 : 251)
        for (uint64_t logical = PAGE; logical <= 5 * PAGE; logical += PAGE) {
            CHECK(adreno_head_admit(0, bytes, logical) == adreno_tail_admit(bytes, logical));
            if (!adreno_tail_admit(bytes, logical)) continue;
            for (uint64_t off = 0; off < logical; off += PAGE) {
                if (off >= bytes) continue;
                const uint64_t span = bytes - off < 2 * PAGE ? bytes - off : 2 * PAGE;
                uint64_t len = 0;
                CHECK(adreno_head_run(off, 0, bytes, PA_BASE + off, span, &len) == PA_BASE + off &&
                      len == adreno_tail_span(off, span, bytes));
            }
            for (unsigned dir = 0; dir <= ADRENO_CACHE_FROM_DEVICE; dir++)
                for (uint64_t o = 0; o < logical; o += 64 * 37)
                    for (uint64_t l = 64; o + l <= logical; l += 64 * 53) {
                        struct adreno_tail_range t[2], h[3];
                        const unsigned nt = adreno_tail_cache_plan(o, l, bytes, dir, t);
                        const unsigned nh = adreno_head_cache_plan(o, l, 0, bytes, dir, h);
                        CHECK(nt == nh);
                        for (unsigned i = 0; i < nt; i++)
                            CHECK(t[i].offset == h[i].offset && t[i].bytes == h[i].bytes && t[i].direction == h[i].direction);
                    }
        }
    /* A segment that does not sit where the head says is refused page by page (the core then unwinds). */
    {   uint64_t len = 1;
        CHECK(!adreno_head_run(0, 0x200, 0x4000, PA_BASE + 0x300, 0x3d00, &len) && !len);       /* not the head */
        CHECK(!adreno_head_run(PAGE, 0x200, 0x4000, PA_BASE + 0x10, 0x210, &len) && !len);     /* unaligned page */
        CHECK(adreno_head_run(0, 0x200, 0x4000, PA_BASE + 0x200, 0x3e00, &len) == PA_BASE && len == PAGE);
        CHECK(adreno_head_run(PAGE, 0x200, 0x4000, PA_BASE + 7 * PAGE, 0x200, &len) == PA_BASE + 7 * PAGE &&
              len == PAGE);                                                                  /* the last page, whole */
        CHECK(!adreno_head_admit(0x200, 0x4000, 3 * PAGE) && !adreno_head_admit(0x200, 0x4000, PAGE) &&
              adreno_head_admit(0x200, 0x4000, 2 * PAGE) && !adreno_head_admit(PAGE, 0x4000, 2 * PAGE)); }
    printf("PASS head\n");
#endif
    printf("PASS repin\n");
}
#endif

int main(int argc, char **argv)
{
    const char *what = argc > 1 ? argv[1] : "all";
    uint64_t MiB = 1ULL << 20;
    int all = !strcmp(what, "all");
    if (all || !strcmp(what, "scenarios")) scenarios();
    if (all || !strcmp(what, "race")) race();
#ifndef RESOURCE_BASE
    if (all || !strcmp(what, "pool")) pool_scenarios();
    if (all || !strcmp(what, "repin")) repin_scenarios();
#endif
    if (all || !strcmp(what, "workload")) {
        workload("old", 0, 0, 512 * MiB, 4000);
        workload("resident", 1, 0, 512 * MiB, 4000);
        workload("resident+runs", 1, ADRENO_COMMIT_RUNS, 512 * MiB, 4000);
        workload("runs, budget 0", 1, ADRENO_COMMIT_RUNS, 0, 4000);
        workload("resident+runs, 64 MiB", 1, ADRENO_COMMIT_RUNS, 64 * MiB, 4000);
#ifndef RESOURCE_BASE
        workload("pool+runs, budget 0", 2, ADRENO_COMMIT_RUNS, 0, 4000);
        workload("pool+runs, resident", 2, ADRENO_COMMIT_RUNS, 512 * MiB, 4000);   /* pacing work R1-R13 */
#endif
        printf("PASS workload\n");
    }
    if (all || !strcmp(what, "arena")) {
        arena_workload("arena old", 0, 0, 0, 1500);
        arena_workload("arena runs, budget 0", 1, ADRENO_COMMIT_RUNS, 0, 1500);
        arena_workload("arena resident+runs", 1, ADRENO_COMMIT_RUNS, 512 * MiB, 1500);
#ifndef RESOURCE_BASE
        arena_workload("arena pool+runs, budget 0", 2, ADRENO_COMMIT_RUNS, 0, 1500);
        arena_workload("arena pool+runs, resident", 2, ADRENO_COMMIT_RUNS, 512 * MiB, 1500);
#endif
        printf("PASS arena\n");
    }
#ifndef RESOURCE_BASE
    if (all || !strcmp(what, "recycled")) {
        /* Pacing work 2026-10-21: the deployed kext (pool, budget 0) against residency on the plug-in's recycled
         * arenas, and a budget smaller than the working set (R5). */
        recycled_workload("recycled pool+runs, budget 0", ADRENO_COMMIT_RUNS, 0, 1500);
        recycled_workload("recycled pool+runs, resident", ADRENO_COMMIT_RUNS, 512 * MiB, 1500);
        recycled_workload("recycled pool+runs, resident 64 MiB", ADRENO_COMMIT_RUNS, 64 * MiB, 1500);
        printf("PASS recycled\n");
    }
#endif
#ifndef RESOURCE_BASE
    if (all || !strcmp(what, "burst")) {
        burst_workload("burst pool+runs, budget 0", 1500);
        printf("PASS burst\n");
    }
#endif
#if !defined(RESOURCE_BASE) && ADRENO_POOL_ARENA
    if (all || !strcmp(what, "pressure")) {
        /* agents/gpu-va: the base (or no filler) against reclaim, residency off and on (G0). */
        pressure_workload("pressure, budget 0", 0, 1);
        pressure_workload("pressure, resident", 512 * MiB, 1);
#if ADRENO_VA_RECLAIM
        pressure_workload("pressure no filler, budget 0", 0, 0);
        pressure_workload("pressure no filler, resident", 512 * MiB, 0);
#endif
        printf("PASS pressure\n");
    }
#endif
    printf("PASS: %s\n", what);
    return 0;
}
