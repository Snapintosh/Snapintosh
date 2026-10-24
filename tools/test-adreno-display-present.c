/* SPDX-License-Identifier: MIT */
/* Host E2E of AdrenoDisplay's present copy (gpu/adreno-kext/kext/src/AdrenoDisplayCopy.h),
 * the exact header the kext compiles. Driven by tools/test-adreno-display.py.
 *
 * Failure inventory, written before the copy routine (each has a case below):
 *   F1  last source row ends past the surface allocation -> kernel over-read
 *   F2  destination rows past the scanout mapping -> write past the GOP aperture
 *   F3  y * row_bytes or offset arithmetic wraps -> out-of-bounds access
 *   F4  zero width/height/row_bytes -> degenerate loops
 *   F5  unsupported FourCC copied as if BGRA -> garbage on the panel
 *   F6  BGRA byte order changed (R/B swap) -> wrong colours
 *   F7  l10r bit positions or rounding wrong -> wrong colours
 *   F8  RGhA half-float edge cases (negative, NaN, inf, >1, subnormal) -> wrong/unstable
 *   F9  stale CPU cache lines of a GPU-written surface -> old pixels (no FROM_DEVICE)
 *   F10 maintenance outside the row being read (or after it) -> faults / stale data
 *   F11 surface smaller than the panel -> pixels outside the overlap rewritten
 *   F12 surface larger than the panel -> writes past a row or the aperture
 *   F13 row padding copied, base offset ignored -> sheared image
 *   F14 a refused copy partially writes the panel or maintains memory
 *
 * Memory model: every source and destination buffer ends exactly at a PROT_NONE guard
 * page, so any over-read or over-write faults the process. The source buffer is the
 * CPU's view; it starts STALE. A separate DRAM buffer holds the fresh (device-written)
 * bytes, and the maintain callback copies DRAM into the CPU view for exactly the lines it
 * is given, i.e. invalidate + refetch. A row read without prior maintenance is stale.
 *
 * Build with -DADRENO_DISPLAY_PRECHANGE to run the same cases against a model of the
 * HEAD 2cdbae5 AdrenoDisplay::presentGated (BGRA only, readBytes per row with its length
 * clamp, no cache maintenance); that build must fail.
 *
 * `cursor` runs the cursor-layer cases (gpu/adreno-kext/kext/src/AdrenoDisplayCursor.h,
 * failure inventory C1-C14 there) through present_under_test, which calls the header in
 * AdrenoDisplay::presentGated's order: cursor_begin, the layer-0 copy, cursor_layer for each
 * of layers 1..3 whose mask bit is set, cursor_finish. Expected panels come from an
 * independent float reference (layer 0 copied, then each cursor pixel blended as
 * min(255, s + round(u * (255 - a) / 255)) per byte). The PRECHANGE build models the
 * 7ec040b4 presentGated, which drops layers 1..3; its cursor run must fail.
 *
 * `geometry` runs adreno_display_swap_geometry (AdrenoDisplayCopy.h): what a layer-0 swap asks that the 1:1, top-left
 * copy does not do, as the kext's -DADRENO_DISPLAY_TRACE_MODES logs it (agents/display-modeset). The cases are the
 * panel's own mode, macOS's scaled resolutions of a 2880x1800 panel (1280x800 to 1920x1200 points at 2x: the
 * framebuffer is the points' size twice, presented to the full panel), a placed destination, a cropped source,
 * negative rectangles and an unknown surface.
 *
 *   test-adreno-display-present selftest
 *   test-adreno-display-present geometry                       (prints a JSON line)
 *   test-adreno-display-present cursor                         (prints a JSON line)
 *   test-adreno-display-present surface DUMP.adsf PANEL.bin   (prints a JSON line)
 */
#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayCopy.h"
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayCursor.h"

static unsigned failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

/* ---------------------------------------------------------------- guarded memory */
struct guarded { uint8_t *base; size_t length, mapped; };
static struct guarded guarded_alloc(size_t length)
{
    size_t page = (size_t)getpagesize(), span = (length + page - 1) / page * page;
    uint8_t *m = mmap(NULL, span + page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); exit(2); }
    if (mprotect(m + span, page, PROT_NONE)) { perror("mprotect"); exit(2); }
    struct guarded g = { m + span - length, length, span + page };   /* ends at the guard */
    return g;
}
static void guarded_free(struct guarded g)
{
    size_t page = (size_t)getpagesize(), span = g.mapped - page;
    munmap(g.base + g.length - span, g.mapped);
}

/* ---------------------------------------------------------------- stale-cache model */
struct cache_model {
    uint8_t *cpu; const uint8_t *dram; uint64_t length;
    uint64_t calls, bytes;
    uint64_t row_start, row_stride, row_bytes, rows_seen; int order_ok, range_ok;
};
static void maintain_model(void *ctx, const void *address, uint64_t bytes)
{
    struct cache_model *m = ctx;
    uint64_t off = (uint64_t)((const uint8_t *)address - m->cpu);
    m->calls++; m->bytes += bytes;
    /* F10: exactly the next row's bytes, in order. */
    uint64_t want = m->row_start + m->rows_seen * m->row_stride;
    if (off != want || bytes != m->row_bytes) m->order_ok = 0;
    if (off > m->length || bytes > m->length - off) m->range_ok = 0;
    m->rows_seen++;
    uint64_t first = off & ~63ull, end = off + bytes;
    for (uint64_t line = first; line < end; line += 64) {
        uint64_t n = line + 64 <= m->length ? 64 : m->length - line;
        memcpy(m->cpu + line, m->dram + line, n);
    }
}

/* ---------------------------------------------------------------- copy under test */
#ifdef ADRENO_DISPLAY_PRECHANGE
/* HEAD 2cdbae5 AdrenoDisplay.cpp:420-437: format != 'BGRA' -> nothing; w/h clamped to the
 * scanout; bytes = w*4 must fit both row strides; md->readBytes(base + y*row) which copies
 * min(bytes, length - offset) and nothing at or past the end. No maintenance. */
static int copy_under_test(const struct adreno_display_surface *s, const struct adreno_display_scanout *d,
                           adreno_display_maintain_fn maintain, void *ctx, struct adreno_display_copy_result *r)
{
    (void)maintain; (void)ctx;
    if (r) r->width = r->height = r->bytes_read = 0;
    if (!s || !d || !s->base || !d->base) return ADRENO_DISPLAY_E_ARGS;
    if (s->format != ADRENO_DISPLAY_FORMAT_BGRA) return ADRENO_DISPLAY_E_FORMAT;
    uint64_t w = s->width < d->width ? s->width : d->width, h = s->height < d->height ? s->height : d->height;
    uint64_t bytes = w * 4;
    if (!s->row_bytes || bytes > s->row_bytes || bytes > d->row_bytes) return ADRENO_DISPLAY_E_SOURCE;
    for (uint64_t y = 0; y < h; y++) {
        uint64_t at = s->offset + y * s->row_bytes;
        if (at >= s->length) break;
        uint64_t n = bytes < s->length - at ? bytes : s->length - at;
        memcpy(d->base + y * d->row_bytes, s->base + at, n);
    }
    if (r) { r->width = w; r->height = h; r->bytes_read = bytes * h; }
    return ADRENO_DISPLAY_OK;
}
#define VARIANT "prechange-head-2cdbae5"
#else
#define copy_under_test adreno_display_copy
#define VARIANT "adreno-display-copy"
#endif

/* ---------------------------------------------------------------- helpers */
/* Fresh pixels for every row that lies wholly inside the allocation. */
static void fill_bgra(uint8_t *base, uint64_t length, uint64_t offset, uint64_t row_bytes, uint64_t w, uint64_t h,
                      uint32_t seed)
{
    for (uint64_t y = 0; y < h; y++) {
        if (offset > length || (length - offset) / row_bytes < y || length - offset - y * row_bytes < w * 4)
            break;
        for (uint64_t x = 0; x < w; x++) {
            uint8_t *q = base + offset + y * row_bytes + x * 4;
            q[0] = (uint8_t)(x * 3 + y + seed); q[1] = (uint8_t)(x ^ (y * 7) ^ seed);
            q[2] = (uint8_t)((x + y * 5) >> 1); q[3] = (uint8_t)(0xa0 + seed);
        }
    }
}

struct scene {
    struct guarded dram, cpu, dst;
    struct adreno_display_surface s;
    struct adreno_display_scanout d;
    struct cache_model model;
};

/* A surface of w x h (bpp 4) at `offset` with `row_bytes`, allocation `length`; a scanout
 * of dw x dh with drow; CPU view stale (0x5a), DRAM fresh, destination sentinel 0xc3. */
static void scene_make(struct scene *sc, uint32_t format, uint64_t w, uint64_t h, uint64_t row_bytes,
                       uint64_t offset, uint64_t length, uint64_t dw, uint64_t dh, uint64_t drow)
{
    memset(sc, 0, sizeof *sc);
    sc->dram = guarded_alloc(length);
    sc->cpu = guarded_alloc(length);
    sc->dst = guarded_alloc(drow * dh);
    memset(sc->dram.base, 0x77, length);
    memset(sc->cpu.base, 0x5a, length);
    memset(sc->dst.base, 0xc3, drow * dh);
    if (format == ADRENO_DISPLAY_FORMAT_BGRA)
        fill_bgra(sc->dram.base, length, offset, row_bytes, w, h, 1);
    sc->s = (struct adreno_display_surface){ sc->cpu.base, length, offset, row_bytes, w, h, format };
    sc->d = (struct adreno_display_scanout){ sc->dst.base, drow * dh, drow, dw, dh };
    uint64_t cw = w < dw ? w : dw;
    sc->model = (struct cache_model){ sc->cpu.base, sc->dram.base, length, 0, 0, offset, row_bytes,
                                      cw * adreno_display_bytes_per_pixel(format), 0, 1, 1 };
}
static void scene_free(struct scene *sc)
{
    guarded_free(sc->dram); guarded_free(sc->cpu); guarded_free(sc->dst);
}
static int dst_untouched(const struct scene *sc)
{
    for (uint64_t i = 0; i < sc->d.length; i++) if (sc->dst.base[i] != 0xc3) return 0;
    return 1;
}
/* The overlap equals fresh DRAM pixels; everything outside it keeps the sentinel. */
static int dst_matches(const struct scene *sc, uint64_t w, uint64_t h)
{
    for (uint64_t y = 0; y < sc->d.height; y++)
        for (uint64_t x = 0; x < sc->d.width; x++) {
            const uint8_t *q = sc->dst.base + y * sc->d.row_bytes + x * 4;
            if (y < h && x < w) {
                if (memcmp(q, sc->dram.base + sc->s.offset + y * sc->s.row_bytes + x * 4, 4)) return 0;
            } else if (q[0] != 0xc3 || q[1] != 0xc3 || q[2] != 0xc3 || q[3] != 0xc3) {
                return 0;
            }
        }
    /* Row padding beyond width*4 in the destination is never written. */
    for (uint64_t y = 0; y < sc->d.height; y++)
        for (uint64_t i = sc->d.width * 4; i < sc->d.row_bytes; i++)
            if (sc->dst.base[y * sc->d.row_bytes + i] != 0xc3) return 0;
    return 1;
}

/* ---------------------------------------------------------------- cases */
static void case_full_panel_stale_cache(void)   /* F9 F10 F13(offset 0) F6 */
{
    struct scene sc; struct adreno_display_copy_result r;
    scene_make(&sc, ADRENO_DISPLAY_FORMAT_BGRA, 2880, 1800, 11520, 0, 11520ull * 1800 + 6144, 2880, 1800, 11520);
    int e = copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, &r);
    CHECK(e == ADRENO_DISPLAY_OK);
    CHECK(dst_matches(&sc, 2880, 1800));                         /* fresh, not stale 0x5a */
    CHECK(sc.model.order_ok && sc.model.range_ok);
    CHECK(sc.model.rows_seen == 1800 && sc.model.bytes == 11520ull * 1800 && r.bytes_read == sc.model.bytes);
    CHECK(r.width == 2880 && r.height == 1800);
    scene_free(&sc);
}
static void case_padding_and_offset(void)        /* F13 */
{
    struct scene sc; struct adreno_display_copy_result r;
    uint64_t row = 12288, off = 4096, len = off + row * 599 + 1000 * 4;   /* last row exactly fits */
    scene_make(&sc, ADRENO_DISPLAY_FORMAT_BGRA, 1000, 600, row, off, len, 1024, 640, 4096 + 64);
    int e = copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, &r);
    CHECK(e == ADRENO_DISPLAY_OK);
    CHECK(dst_matches(&sc, 1000, 600));
    CHECK(sc.model.order_ok && sc.model.range_ok && sc.model.rows_seen == 600);
    scene_free(&sc);
}
static void case_smaller_surface(void)           /* F11 */
{
    struct scene sc; struct adreno_display_copy_result r;
    scene_make(&sc, ADRENO_DISPLAY_FORMAT_BGRA, 1440, 900, 5760, 0, 5760ull * 900, 2880, 1800, 11520);
    CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, &r) == ADRENO_DISPLAY_OK);
    CHECK(dst_matches(&sc, 1440, 900));
    scene_free(&sc);
}
static void case_larger_surface(void)            /* F12 */
{
    struct scene sc; struct adreno_display_copy_result r;
    scene_make(&sc, ADRENO_DISPLAY_FORMAT_BGRA, 4096, 2304, 16384, 0, 16384ull * 2304, 2880, 1800, 11520);
    CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, &r) == ADRENO_DISPLAY_OK);
    CHECK(dst_matches(&sc, 2880, 1800));
    CHECK(sc.model.bytes == 11520ull * 1800);                   /* only the clipped part is read */
    scene_free(&sc);
}
static void refused(uint32_t format, uint64_t w, uint64_t h, uint64_t row, uint64_t off, uint64_t len,
                    uint64_t dw, uint64_t dh, uint64_t drow, int dst_short, int want)   /* F14 */
{
    struct scene sc; struct adreno_display_copy_result r;
    scene_make(&sc, format, w, h, row, off, len, dw, dh, drow);
    if (dst_short) sc.d.length -= 1;
    int e = copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, &r);
    CHECK(e == want);
    if (e != want) fprintf(stderr, "  got %d want %d (w=%llu h=%llu row=%llu off=%llu len=%llu)\n", e, want,
                           (unsigned long long)w, (unsigned long long)h, (unsigned long long)row,
                           (unsigned long long)off, (unsigned long long)len);
    CHECK(dst_untouched(&sc));
    CHECK(sc.model.calls == 0);
    scene_free(&sc);
}
static void case_refusals(void)
{
    const uint32_t B = ADRENO_DISPLAY_FORMAT_BGRA;
    refused(B, 2880, 1800, 11520, 0, 11520ull * 1800 - 1, 2880, 1800, 11520, 0, ADRENO_DISPLAY_E_SOURCE);  /* F1 */
    refused(B, 64, 4, 256, 257, 257 + 256 * 3 + 255, 64, 4, 256, 0, ADRENO_DISPLAY_E_SOURCE);              /* F1 offset */
    refused(B, 64, 4, 256, 4096, 1024, 64, 4, 256, 0, ADRENO_DISPLAY_E_SOURCE);                           /* F3 offset > length */
    refused(B, 64, 4, 200, 0, 4096, 64, 4, 256, 0, ADRENO_DISPLAY_E_SOURCE);                              /* row < w*4 */
    refused(B, 64, 4, 256, 0, 1024, 64, 4, 256, 1, ADRENO_DISPLAY_E_DEST);                                /* F2 */
    refused(B, 64, 4, 256, 0, 1024, 64, 4, 200, 0, ADRENO_DISPLAY_E_DEST);                                /* F2 row */
    refused(0x78343230u, 64, 4, 256, 0, 1024, 64, 4, 256, 0, ADRENO_DISPLAY_E_FORMAT);                    /* F5 'x420' */
    /* F3: huge stride whose (h-1)*row wraps 64 bits. */
    {
        struct scene sc;
        scene_make(&sc, B, 16, 3, 64, 0, 4096, 16, 3, 64);
        sc.s.row_bytes = 1ull << 63;
        CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, NULL) == ADRENO_DISPLAY_E_SOURCE);
        CHECK(dst_untouched(&sc) && sc.model.calls == 0);
        sc.s.row_bytes = 64; sc.s.offset = UINT64_MAX - 8;
        CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, NULL) == ADRENO_DISPLAY_E_SOURCE);
        CHECK(dst_untouched(&sc) && sc.model.calls == 0);
        scene_free(&sc);
    }
    /* F4 */
    {
        struct scene sc;
        scene_make(&sc, B, 16, 3, 64, 0, 4096, 16, 3, 64);
        sc.s.height = 0;
        CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, NULL) == ADRENO_DISPLAY_E_ARGS);
        sc.s.height = 3; sc.s.row_bytes = 0;
        CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, NULL) == ADRENO_DISPLAY_E_ARGS);
        sc.s.row_bytes = 64; sc.d.width = 0;
        CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, NULL) == ADRENO_DISPLAY_E_ARGS);
        CHECK(dst_untouched(&sc) && sc.model.calls == 0);
        scene_free(&sc);
    }
}
static void case_l10r(void)                      /* F7 */
{
    struct scene sc; struct adreno_display_copy_result r;
    const uint32_t L = ADRENO_DISPLAY_FORMAT_L10R;
    scene_make(&sc, L, 4, 1, 16, 0, 64, 4, 1, 16);
    /* B in bits 0-9, G 10-19, R 20-29, A 30-31. */
    uint32_t px[4] = { (3u << 30) | (1023u << 20) | (512u << 10) | 0u,       /* R max, G mid, B 0 */
                       (0u << 20) | (0u << 10) | 1023u,                     /* pure blue */
                       (1u << 20) | (2u << 10) | 3u,                        /* tiny values */
                       (511u << 20) | (1022u << 10) | 4u };
    memcpy(sc.dram.base, px, sizeof px);
    CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, &r) == ADRENO_DISPLAY_OK);
    /* round(v * 255 / 1023): 512 -> 128, 3 -> 1, 2 -> 0, 1 -> 0, 4 -> 1, 1022 -> 255, 511 -> 127. */
    static const uint8_t want[16] = { 0, 128, 255, 0xff,   255, 0, 0, 0xff,   1, 0, 0, 0xff,   1, 255, 127, 0xff };
    CHECK(!memcmp(sc.dst.base, want, 16));
    if (memcmp(sc.dst.base, want, 16)) {
        for (int i = 0; i < 16; i++) fprintf(stderr, "%d ", sc.dst.base[i]);
        fprintf(stderr, "\n");
    }
    scene_free(&sc);
}
static void case_rgha(void)                      /* F8 */
{
    struct scene sc; struct adreno_display_copy_result r;
    const uint32_t H = ADRENO_DISPLAY_FORMAT_RGHA;
    scene_make(&sc, H, 4, 1, 32, 0, 64, 4, 1, 16);
    /* half: 1.0 0x3c00, 0.5 0x3800, 2.0 0x4000, -1 0xbc00, +inf 0x7c00, NaN 0x7e00,
     * subnormal 0x0200, 1/255 ~ 0x1c04 (0.0039215), 0.25 0x3400 -> 64 (63.75). */
    uint16_t v[16] = { 0x3c00, 0x3800, 0x0000, 0x3c00,     /* R 1.0 -> 255, G 0.5 -> 128, B 0 */
                       0xbc00, 0x7c00, 0x7e00, 0x3c00,     /* R -1 -> 0, G inf -> 255, B NaN -> 0 */
                       0x0200, 0x1c04, 0x4000, 0x3c00,     /* R subnormal -> 0, G 1/255 -> 1, B 2.0 -> 255 */
                       0x3400, 0x3bff, 0x0400, 0x0000 };   /* R .25 -> 64, G .99951 -> 255, B 2^-14 -> 0 */
    memcpy(sc.dram.base, v, sizeof v);
    CHECK(copy_under_test(&sc.s, &sc.d, maintain_model, &sc.model, &r) == ADRENO_DISPLAY_OK);
    static const uint8_t want[16] = { 0, 128, 255, 0xff,   0, 255, 0, 0xff,   255, 1, 0, 0xff,   0, 255, 64, 0xff };
    CHECK(!memcmp(sc.dst.base, want, 16));
    if (memcmp(sc.dst.base, want, 16)) {
        for (int i = 0; i < 16; i++) fprintf(stderr, "%d ", sc.dst.base[i]);
        fprintf(stderr, "\n");
    }
    /* Exhaustive half sweep: monotone over non-negative finite values, bounded. */
    uint8_t last = 0; int monotone = 1;
    for (uint32_t h = 0; h < 0x7c00; h++) {
        uint8_t o = adreno_display_half_to_8((uint16_t)h);
        if (o < last) monotone = 0;
        last = o;
    }
    CHECK(monotone && last == 255);
    scene_free(&sc);
}

/* ---------------------------------------------------------------- cursor layer */
/* A surface as the kext sees it: DRAM holds the fresh bytes, the CPU view is stale (0x5a)
 * until the copy maintains a row, unless `coherent` (layer 0 of the cursor cases, so the
 * PRECHANGE copy model is not failed for its missing maintenance). Guard-paged. */
struct hsurf {
    struct guarded dram, cpu;
    struct adreno_display_surface s;
    struct cache_model model;
};
static void hsurf_make(struct hsurf *h, uint32_t format, uint64_t w, uint64_t hgt, uint64_t row, uint64_t off,
                       uint64_t len)
{
    memset(h, 0, sizeof *h);
    h->dram = guarded_alloc(len);
    h->cpu = guarded_alloc(len);
    memset(h->dram.base, 0x77, len);
    memset(h->cpu.base, 0x5a, len);
    h->s = (struct adreno_display_surface){ h->cpu.base, len, off, row, w, hgt, format };
}
static void hsurf_free(struct hsurf *h) { guarded_free(h->dram); guarded_free(h->cpu); }
static void hsurf_coherent(struct hsurf *h) { memcpy(h->cpu.base, h->dram.base, h->s.length); }
/* The maintenance this present must do on h: rows of `bytes` from (x, y), `rows` of them. */
static void hsurf_expect(struct hsurf *h, uint64_t x, uint64_t y, uint64_t bytes)
{
    h->model = (struct cache_model){ h->cpu.base, h->dram.base, h->s.length, 0, 0,
                                     h->s.offset + y * h->s.row_bytes + x * 4, h->s.row_bytes, bytes, 0, 1, 1 };
}
/* Premultiplied cursor pixels: alphas 0, 255 and between, colour <= alpha, plus the
 * diagonal as an additive (a = 0, colour 40) pixel to reach the 255 clamp. */
static void cursor_fill(struct hsurf *h, uint32_t seed)
{
    static const uint8_t alphas[8] = { 0, 255, 128, 1, 254, 64, 200, 17 };
    for (uint64_t y = 0; y < h->s.height; y++)
        for (uint64_t x = 0; x < h->s.width; x++) {
            uint64_t at = h->s.offset + y * h->s.row_bytes + x * 4;
            if (at + 4 > h->s.length) continue;             /* rows past a short allocation */
            uint8_t *q = h->dram.base + at;
            uint32_t a = alphas[(x + 3 * y + seed) & 7];
            for (int c = 0; c < 3; c++)
                q[c] = (uint8_t)(a * ((x * 37 + y * 11 + (uint64_t)c * 53 + seed) & 255) / 255);
            q[3] = (uint8_t)a;
            if (x == y) { q[0] = q[1] = q[2] = 40; q[3] = 0; }
        }
}

/* Independent reference (float rounding, no shared helper). */
static void ref_blend(const uint8_t *s, uint8_t *u)
{
    for (int c = 0; c < 4; c++) {
        double v = s[c] + (double)(uint64_t)(u[c] * (255.0 - s[3]) / 255.0 + 0.5);
        u[c] = v > 255.0 ? 255 : (uint8_t)v;
    }
}
static void ref_layer0(uint8_t *panel, const struct adreno_display_scanout *d, const struct hsurf *l0)
{
    uint64_t w = l0->s.width < d->width ? l0->s.width : d->width, h = l0->s.height < d->height ? l0->s.height : d->height;
    for (uint64_t y = 0; y < h; y++)
        memcpy(panel + y * d->row_bytes, l0->dram.base + l0->s.offset + y * l0->s.row_bytes, (size_t)(w * 4));
}
static void ref_cursor(uint8_t *panel, const struct adreno_display_scanout *d, const struct hsurf *cs,
                       struct adreno_display_rect src, int32_t cx, int32_t cy)
{
    if (!src.w || !src.h) { src.x = src.y = 0; src.w = (int32_t)cs->s.width; src.h = (int32_t)cs->s.height; }
    for (int64_t j = 0; j < src.h; j++)
        for (int64_t i = 0; i < src.w; i++) {
            int64_t X = (int64_t)cx + i, Y = (int64_t)cy + j;
            if (X < 0 || Y < 0 || X >= (int64_t)d->width || Y >= (int64_t)d->height) continue;
            const uint8_t *s = cs->dram.base + cs->s.offset + (uint64_t)(src.y + j) * cs->s.row_bytes + (uint64_t)(src.x + i) * 4;
            ref_blend(s, panel + (uint64_t)Y * d->row_bytes + (uint64_t)X * 4);
        }
}

/* Maintenance of either surface of a present, routed by address. */
struct models { struct cache_model *m[2]; uint64_t stray; };
static void maintain_multi(void *ctx, const void *address, uint64_t bytes)
{
    struct models *ms = ctx;
    for (int i = 0; i < 2; i++) {
        struct cache_model *m = ms->m[i];
        if (m && (const uint8_t *)address >= m->cpu && (const uint8_t *)address < m->cpu + m->length) {
            maintain_model(m, address, bytes);
            return;
        }
    }
    ms->stray++;
}

struct tlayer { int on; struct hsurf *surf; struct adreno_display_rect src, dst; };
struct tstats { uint64_t blank, copy_errors, draws, cursor_errors, format_skips, stray; int last_error; };
/* AdrenoDisplay::presentGated's order (fConsoleDisabled taken as true). */
static void present_under_test(struct adreno_display_cursor *c, const struct adreno_display_scanout *d,
                               struct tlayer L[4], struct tstats *st)
{
    struct models ms = { { L[0].on && L[0].surf ? &L[0].surf->model : NULL, NULL }, 0 };
    for (int l = 1; l < 4; l++)
        if (L[l].on && L[l].surf) ms.m[1] = &L[l].surf->model;
#ifndef ADRENO_DISPLAY_PRECHANGE
    adreno_display_cursor_begin(c, d);
#else
    (void)c;
#endif
    if (L[0].on && L[0].surf) {
        if (copy_under_test(&L[0].surf->s, d, maintain_multi, &ms, NULL)) st->copy_errors++;
    } else {
        st->blank++;
    }
#ifndef ADRENO_DISPLAY_PRECHANGE
    for (uint32_t l = 1; l < 4; l++) {
        if (!L[l].on) continue;
        int e = adreno_display_cursor_layer(c, l, L[l].surf ? &L[l].surf->s : NULL, L[l].src, L[l].dst.x,
                                            L[l].dst.y, maintain_multi, &ms);
        if (e == ADRENO_DISPLAY_E_FORMAT) st->format_skips++;
        else if (e) st->cursor_errors++;
        if (e) st->last_error = e;
    }
    if (adreno_display_cursor_finish(c, d)) st->draws++;
#endif
    st->stray += ms.stray;
}

struct cpanel { struct guarded buf; struct adreno_display_scanout d; uint8_t *ref; };
static void cpanel_make(struct cpanel *p, uint64_t w, uint64_t h, uint64_t row)
{
    p->buf = guarded_alloc(row * h);
    memset(p->buf.base, 0xc3, row * h);
    p->d = (struct adreno_display_scanout){ p->buf.base, row * h, row, w, h };
    p->ref = malloc(row * h);
    memset(p->ref, 0xc3, row * h);
}
static void cpanel_free(struct cpanel *p) { guarded_free(p->buf); free(p->ref); }
static int cpanel_ok(const struct cpanel *p) { return !memcmp(p->buf.base, p->ref, p->d.length); }
static void cpanel_diff(const struct cpanel *p, const char *what)
{
    for (uint64_t i = 0; i < p->d.length; i++)
        if (p->buf.base[i] != p->ref[i]) {
            fprintf(stderr, "  %s: first difference at byte %llu (x=%llu y=%llu c=%llu): got %u want %u\n", what,
                    (unsigned long long)i, (unsigned long long)(i % p->d.row_bytes / 4),
                    (unsigned long long)(i / p->d.row_bytes), (unsigned long long)(i % 4), p->buf.base[i], p->ref[i]);
            return;
        }
}
#define PANEL_CHECK(p, what) do { int ok_ = cpanel_ok(p); CHECK(ok_ && what[0]); if (!ok_) cpanel_diff(p, what); } while (0)

static struct adreno_display_cursor cursor_new(struct guarded *gi, struct guarded *gs)
{
    *gi = guarded_alloc(ADRENO_DISPLAY_CURSOR_BYTES);
    *gs = guarded_alloc(ADRENO_DISPLAY_CURSOR_BYTES);
    struct adreno_display_cursor c;
    memset(&c, 0, sizeof c);
    c.image = gi->base;
    c.save = gs->base;
    return c;
}
static struct tlayer L0(struct hsurf *s) { return (struct tlayer){ 1, s, { 0, 0, 0, 0 }, { 0, 0, 0, 0 } }; }
static struct tlayer LC(struct hsurf *s, int32_t x, int32_t y)
{
    return (struct tlayer){ 1, s, { 0, 0, (int32_t)(s ? s->s.width : 0), (int32_t)(s ? s->s.height : 0) },
                            { x, y, (int32_t)(s ? s->s.width : 0), (int32_t)(s ? s->s.height : 0) } };
}
static const struct tlayer OFF = { 0, NULL, { 0, 0, 0, 0 }, { 0, 0, 0, 0 } };

static unsigned case_failures(unsigned before) { return failures - before; }

static void case_cursor_none_identical(void)     /* C11 */
{
    struct cpanel a, b;
    cpanel_make(&a, 130, 70, 130 * 4 + 48);
    cpanel_make(&b, 130, 70, 130 * 4 + 48);
    struct hsurf f1, f2;
    hsurf_make(&f1, ADRENO_DISPLAY_FORMAT_BGRA, 130, 70, 600, 64, 64 + 600 * 70);
    hsurf_make(&f2, ADRENO_DISPLAY_FORMAT_BGRA, 100, 60, 512, 0, 512 * 60);
    fill_bgra(f1.dram.base, f1.s.length, f1.s.offset, f1.s.row_bytes, 130, 70, 3);
    fill_bgra(f2.dram.base, f2.s.length, f2.s.offset, f2.s.row_bytes, 100, 60, 9);
    hsurf_coherent(&f1); hsurf_coherent(&f2);
    struct guarded gi, gs; struct adreno_display_cursor c = cursor_new(&gi, &gs);
    struct tstats st = { 0 };
    struct hsurf *frames[4] = { &f1, NULL, &f2, NULL };
    int on[4] = { 1, 1, 1, 0 };          /* f1, layer 0 on without a surface, f2, no layer bit */
    for (int i = 0; i < 4; i++) {
        struct tlayer L[4] = { { on[i], frames[i], { 0, 0, 0, 0 }, { 0, 0, 0, 0 } }, OFF, OFF, OFF };
        if (frames[i]) hsurf_expect(frames[i], 0, 0, frames[i]->s.width * 4);
        present_under_test(&c, &a.d, L, &st);
        if (frames[i]) {
            hsurf_expect(frames[i], 0, 0, frames[i]->s.width * 4);
            CHECK(adreno_display_copy(&frames[i]->s, &b.d, NULL, NULL, NULL) == ADRENO_DISPLAY_OK);
        }
        CHECK(!memcmp(a.buf.base, b.buf.base, a.d.length));     /* every byte, padding included */
    }
    CHECK(st.blank == 2 && st.draws == 0 && !c.drawn && !c.visible && st.stray == 0);
    hsurf_free(&f1); hsurf_free(&f2); cpanel_free(&a); cpanel_free(&b);
    guarded_free(gi); guarded_free(gs);
}

static void case_cursor_positions(uint64_t W, uint64_t H, uint64_t row, uint64_t cw, uint64_t ch)  /* C1 C6 C12 C13 */
{
    struct cpanel p;
    cpanel_make(&p, W, H, row);
    struct hsurf f1, cs;
    hsurf_make(&f1, ADRENO_DISPLAY_FORMAT_BGRA, W, H, W * 4 + 64, 0, (W * 4 + 64) * H);
    fill_bgra(f1.dram.base, f1.s.length, 0, f1.s.row_bytes, W, H, 5);
    hsurf_coherent(&f1);
    hsurf_make(&cs, ADRENO_DISPLAY_FORMAT_BGRA, cw, ch, cw * 4 + 16, 32, 32 + (cw * 4 + 16) * ch);
    cursor_fill(&cs, 1);
    struct guarded gi, gs; struct adreno_display_cursor c = cursor_new(&gi, &gs);
    const int64_t w = (int64_t)cw, h = (int64_t)ch, sw = (int64_t)W, sh = (int64_t)H;
    const int64_t pos[][2] = { { 10, 10 }, { 0, 0 }, { -5, -7 }, { sw - 8, 5 }, { 5, sh - 6 }, { sw - 3, sh - 2 },
                               { -w + 1, -h + 1 }, { sw - w, sh - h }, { -w, 0 }, { 0, -h }, { sw, 10 }, { 10, sh },
                               { -1, sh - 1 }, { sw - 1, -1 }, { INT32_MIN, INT32_MIN }, { INT32_MAX, INT32_MAX },
                               { INT32_MIN, 3 }, { 3, INT32_MAX } };
    for (size_t k = 0; k < sizeof pos / sizeof pos[0]; k++) {
        int32_t x = (int32_t)pos[k][0], y = (int32_t)pos[k][1];
        struct tstats st = { 0 };
        hsurf_expect(&f1, 0, 0, W * 4);
        memset(cs.cpu.base, 0x5a, cs.s.length);                 /* stale again: C12 */
        hsurf_expect(&cs, 0, 0, cw * 4);
        struct tlayer L[4] = { L0(&f1), LC(&cs, x, y), OFF, OFF };
        present_under_test(&c, &p.d, L, &st);
        memset(p.ref, 0xc3, p.d.length);
        ref_layer0(p.ref, &p.d, &f1);
        ref_cursor(p.ref, &p.d, &cs, L[1].src, x, y);
        PANEL_CHECK(&p, "cursor composite");
        if (!cpanel_ok(&p)) fprintf(stderr, "  at (%d,%d) on %llux%llu\n", x, y, (unsigned long long)W, (unsigned long long)H);
        CHECK(cs.model.rows_seen == ch && cs.model.order_ok && cs.model.range_ok && st.stray == 0);
        int onscreen = (int64_t)x + w > 0 && (int64_t)y + h > 0 && x < sw && y < sh;
        CHECK(st.draws == (uint64_t)onscreen && c.drawn == onscreen);     /* C13: nothing saved off screen */
        /* The cursor comes off again: a cursor-only swap that switches the layer off. */
        struct tlayer H_[4] = { OFF, LC(NULL, 0, 0), OFF, OFF };
        H_[1].on = 1;
        present_under_test(&c, &p.d, H_, &st);
        memset(p.ref, 0xc3, p.d.length);
        ref_layer0(p.ref, &p.d, &f1);
        PANEL_CHECK(&p, "save-under restore at the edge");
        CHECK(!c.visible && !c.drawn);
    }
    hsurf_free(&f1); hsurf_free(&cs); cpanel_free(&p);
    guarded_free(gi); guarded_free(gs);
}

static void case_cursor_alpha(void)              /* C6 */
{
    int div_ok = 1, blend_ok = 1;
    for (uint32_t v = 0; v <= 65535; v++) {
        uint32_t want = (uint32_t)((double)v / 255.0 + 0.5);
        if (adreno_display_div255(v) != want) div_ok = 0;
    }
    for (uint32_t a = 0; a < 256 && blend_ok; a++)
        for (uint32_t s = 0; s < 256; s++) {
            uint8_t src[256 * 4], under[256 * 4], out[256 * 4];
            for (uint32_t u = 0; u < 256; u++) {
                src[u * 4 + 0] = (uint8_t)s; src[u * 4 + 1] = (uint8_t)(255 - s); src[u * 4 + 2] = (uint8_t)(s ^ 0x5a);
                src[u * 4 + 3] = (uint8_t)a;
                under[u * 4 + 0] = (uint8_t)u; under[u * 4 + 1] = (uint8_t)(255 - u); under[u * 4 + 2] = (uint8_t)(u * 7);
                under[u * 4 + 3] = (uint8_t)(u ^ 0xa5);
            }
            adreno_display_blend_row(src, under, out, 256);
            for (uint32_t u = 0; u < 256; u++) {
                uint8_t want[4];
                memcpy(want, under + u * 4, 4);
                ref_blend(src + u * 4, want);
                if (memcmp(want, out + u * 4, 4)) {
                    if (blend_ok)
                        fprintf(stderr, "  blend s=%u a=%u u=%u: got %u %u %u %u want %u %u %u %u\n", s, a, u,
                                out[u * 4], out[u * 4 + 1], out[u * 4 + 2], out[u * 4 + 3], want[0], want[1], want[2], want[3]);
                    blend_ok = 0;
                }
            }
        }
    CHECK(div_ok);
    CHECK(blend_ok);
    /* In place (out aliases under), as the kext does not, but the header allows. */
    uint8_t s4[4] = { 10, 20, 30, 128 }, u4[4] = { 200, 100, 50, 255 }, r4[4];
    memcpy(r4, u4, 4); ref_blend(s4, r4);
    adreno_display_blend_row(s4, u4, u4, 1);
    CHECK(!memcmp(u4, r4, 4));
}

static void case_cursor_moves(void)              /* C4 C5 C9 C10, cursor-only swaps */
{
    const uint64_t W = 160, H = 90, row = 160 * 4 + 32;
    struct cpanel p;
    cpanel_make(&p, W, H, row);
    struct hsurf f[3], cs, cs3;
    for (int i = 0; i < 3; i++) {
        hsurf_make(&f[i], ADRENO_DISPLAY_FORMAT_BGRA, W, H, W * 4, 0, W * 4 * H);
        fill_bgra(f[i].dram.base, f[i].s.length, 0, W * 4, W, H, (uint32_t)(11 * i + 2));
        hsurf_coherent(&f[i]);
    }
    hsurf_make(&cs, ADRENO_DISPLAY_FORMAT_BGRA, 32, 28, 32 * 4, 0, 32 * 4 * 28);
    cursor_fill(&cs, 4);
    hsurf_make(&cs3, ADRENO_DISPLAY_FORMAT_BGRA, 20, 12, 20 * 4 + 8, 8, 8 + (20 * 4 + 8) * 12);
    cursor_fill(&cs3, 6);
    struct guarded gi, gs; struct adreno_display_cursor c = cursor_new(&gi, &gs);
    struct tstats st = { 0 };
    uint8_t *before = malloc(p.d.length);
    struct step { int l0; int lc; int x, y; int hide; struct adreno_display_rect src; int layer; };
    /* l0: frame index or -1; lc: cursor surface 1 = cs, 3 = cs3 (on layer `layer`), 0 = none. */
    const struct step steps[] = {
        { 0, 0, 0, 0, 0, { 0, 0, 0, 0 }, 1 },          /* a: frame 0 */
        { -1, 1, 20, 15, 0, { 0, 0, 0, 0 }, 1 },       /* b: cursor-only at P1 */
        { -1, 1, 30, 22, 0, { 0, 0, 0, 0 }, 1 },       /* c: overlapping move */
        { -1, 1, 120, 70, 0, { 0, 0, 0, 0 }, 1 },      /* d: far, clipped right/bottom */
        { 1, 0, 0, 0, 0, { 0, 0, 0, 0 }, 1 },          /* e: new frame, no cursor bit: cursor stays (C10) */
        { 2, 1, -10, 40, 0, { 0, 0, 0, 0 }, 1 },       /* f: frame and cursor in one swap */
        { -1, 0, 0, 0, 1, { 0, 0, 0, 0 }, 1 },         /* g: layer switched off (C9) */
        { 0, 0, 0, 0, 0, { 0, 0, 0, 0 }, 1 },          /* h: frame 0, no cursor */
        { -1, 1, 50, 30, 0, { 3, 2, 10, 9 }, 1 },      /* i: source sub-rectangle */
        { -1, 3, 70, 10, 0, { 0, 0, 0, 0 }, 3 },       /* j: cursor on layer 3 (IOMFBSupportsGPLite plane) */
        { -1, 3, 71, 11, 0, { 0, 0, 0, 0 }, 3 },       /* k: one-pixel move */
        { -1, 0, 0, 0, 1, { 0, 0, 0, 0 }, 1 },         /* l: layer 1 off: the layer-3 cursor stays */
        { -1, 0, 0, 0, 1, { 0, 0, 0, 0 }, 3 },         /* m: layer 3 off */
    };
    int frame = -1, cur_vis = 0, cur_x = 0, cur_y = 0;
    struct hsurf *cur_s = NULL; struct adreno_display_rect cur_src = { 0, 0, 0, 0 };
    int prev_vis = 0; int64_t prev_rect[4] = { 0, 0, 0, 0 };
    for (size_t k = 0; k < sizeof steps / sizeof steps[0]; k++) {
        const struct step *s = &steps[k];
        struct tlayer L[4] = { OFF, OFF, OFF, OFF };
        if (s->l0 >= 0) { L[0] = L0(&f[s->l0]); hsurf_expect(&f[s->l0], 0, 0, W * 4); }
        for (int i = 0; i < 3; i++) if (i != s->l0) hsurf_expect(&f[i], 0, 0, W * 4);
        struct hsurf *cur = s->lc == 1 ? &cs : s->lc == 3 ? &cs3 : NULL;
        if (cur) {
            L[s->layer] = LC(cur, s->x, s->y);
            if (s->src.w) L[s->layer].src = s->src;
            struct adreno_display_rect r = L[s->layer].src;
            memset(cur->cpu.base, 0x5a, cur->s.length);
            hsurf_expect(cur, (uint64_t)r.x, (uint64_t)r.y, (uint64_t)r.w * 4);
        }
        if (s->hide) { L[s->layer] = OFF; L[s->layer].on = 1; }
        memcpy(before, p.buf.base, p.d.length);
        present_under_test(&c, &p.d, L, &st);
        /* Expected state. */
        if (s->l0 >= 0) frame = s->l0;
        if (cur) { cur_vis = 1; cur_s = cur; cur_x = s->x; cur_y = s->y; cur_src = L[s->layer].src; }
        if (s->hide && ((s->layer == 1 && cur_s == &cs) || (s->layer == 3 && cur_s == &cs3))) cur_vis = 0;
        memset(p.ref, 0xc3, p.d.length);
        if (frame >= 0) ref_layer0(p.ref, &p.d, &f[frame]);
        if (cur_vis) ref_cursor(p.ref, &p.d, cur_s, cur_src, cur_x, cur_y);
        char what[64];
        snprintf(what, sizeof what, "move step %c", (char)('a' + k));
        PANEL_CHECK(&p, what);
        /* A cursor-only swap reads no layer-0 byte and changes nothing outside the old and
         * new cursor rectangles. */
        if (s->l0 < 0) {
            for (int i = 0; i < 3; i++) CHECK(f[i].model.rows_seen == 0);
            int64_t nr[4] = { cur_x, cur_y, cur_src.w ? cur_src.w : 0, cur_src.h ? cur_src.h : 0 };
            int outside_ok = 1;
            for (uint64_t y = 0; y < H; y++)
                for (uint64_t x = 0; x < W; x++) {
                    int in_old = prev_vis && (int64_t)x >= prev_rect[0] && (int64_t)x < prev_rect[0] + prev_rect[2] &&
                                 (int64_t)y >= prev_rect[1] && (int64_t)y < prev_rect[1] + prev_rect[3];
                    int in_new = cur_vis && (int64_t)x >= nr[0] && (int64_t)x < nr[0] + nr[2] &&
                                 (int64_t)y >= nr[1] && (int64_t)y < nr[1] + nr[3];
                    if (!in_old && !in_new && memcmp(p.buf.base + y * row + x * 4, before + y * row + x * 4, 4))
                        outside_ok = 0;
                }
            CHECK(outside_ok);
        }
        if (cur) CHECK(cur->model.rows_seen == (uint64_t)L[s->layer].src.h && cur->model.order_ok);
        prev_vis = cur_vis;
        prev_rect[0] = cur_x; prev_rect[1] = cur_y; prev_rect[2] = cur_src.w; prev_rect[3] = cur_src.h;
    }
    CHECK(st.stray == 0 && st.cursor_errors == 0 && st.format_skips == 0);
    free(before);
    for (int i = 0; i < 3; i++) hsurf_free(&f[i]);
    hsurf_free(&cs); hsurf_free(&cs3); cpanel_free(&p);
    guarded_free(gi); guarded_free(gs);
}

/* A visible cursor, then a refused one: hidden (neither old nor new place), the cached
 * image and geometry unchanged, nothing read or maintained. */
static void refused_cursor(uint32_t format, uint64_t w, uint64_t h, uint64_t row, uint64_t off, uint64_t len,
                           struct adreno_display_rect src, int want)
{
    struct cpanel p;
    cpanel_make(&p, 96, 64, 96 * 4);
    struct hsurf f1, good, bad;
    hsurf_make(&f1, ADRENO_DISPLAY_FORMAT_BGRA, 96, 64, 96 * 4, 0, 96 * 4 * 64);
    fill_bgra(f1.dram.base, f1.s.length, 0, 96 * 4, 96, 64, 7);
    hsurf_coherent(&f1);
    hsurf_make(&good, ADRENO_DISPLAY_FORMAT_BGRA, 16, 16, 64, 0, 64 * 16);
    cursor_fill(&good, 2);
    hsurf_make(&bad, format, w, h, row, off, len);
    memset(bad.dram.base, 0xee, len);
    struct guarded gi, gs; struct adreno_display_cursor c = cursor_new(&gi, &gs);
    struct tstats st = { 0 };
    hsurf_expect(&f1, 0, 0, 96 * 4); hsurf_expect(&good, 0, 0, 64);
    struct tlayer A[4] = { L0(&f1), LC(&good, 30, 20), OFF, OFF };
    present_under_test(&c, &p.d, A, &st);
    uint32_t cw = c.width, ch = c.height;
    uint8_t *image = malloc(ADRENO_DISPLAY_CURSOR_BYTES);
    memcpy(image, c.image, ADRENO_DISPLAY_CURSOR_BYTES);
    bad.model = (struct cache_model){ bad.cpu.base, bad.dram.base, len, 0, 0, 0, 0, 0, 0, 1, 1 };
    struct tlayer B[4] = { OFF, LC(&bad, 50, 40), OFF, OFF };
    B[1].src = src;
    present_under_test(&c, &p.d, B, &st);
    CHECK(st.last_error == want);
    if (st.last_error != want) fprintf(stderr, "  refused cursor: got %d want %d\n", st.last_error, want);
    CHECK(bad.model.calls == 0 && st.stray == 0);
    CHECK(c.width == cw && c.height == ch && !memcmp(image, c.image, ADRENO_DISPLAY_CURSOR_BYTES));
    CHECK(!c.visible && !c.drawn);
    memset(p.ref, 0xc3, p.d.length);
    ref_layer0(p.ref, &p.d, &f1);
    PANEL_CHECK(&p, "refused cursor hidden");
    CHECK((want == ADRENO_DISPLAY_E_FORMAT) == (st.format_skips == 1));
    free(image);
    hsurf_free(&f1); hsurf_free(&good); hsurf_free(&bad); cpanel_free(&p);
    guarded_free(gi); guarded_free(gs);
}
static void case_cursor_refusals(void)           /* C2 C3 C7 C8 C14 */
{
    const struct adreno_display_rect whole = { 0, 0, 0, 0 };
    refused_cursor(ADRENO_DISPLAY_FORMAT_L10R, 16, 16, 64, 0, 1024, whole, ADRENO_DISPLAY_E_FORMAT);   /* C7 */
    refused_cursor(ADRENO_DISPLAY_FORMAT_RGHA, 16, 16, 128, 0, 2048, whole, ADRENO_DISPLAY_E_FORMAT);
    refused_cursor(0x78343230u, 16, 16, 64, 0, 1024, whole, ADRENO_DISPLAY_E_FORMAT);                  /* 'x420' */
    refused_cursor(0, 16, 16, 64, 0, 1024, whole, ADRENO_DISPLAY_E_FORMAT);
    const uint32_t B = ADRENO_DISPLAY_FORMAT_BGRA;
    refused_cursor(B, 16, 16, 64, 0, 1024, (struct adreno_display_rect){ -1, 0, 8, 8 }, ADRENO_DISPLAY_E_RECT);  /* C3 */
    refused_cursor(B, 16, 16, 64, 0, 1024, (struct adreno_display_rect){ 0, -3, 8, 8 }, ADRENO_DISPLAY_E_RECT);
    refused_cursor(B, 16, 16, 64, 0, 1024, (struct adreno_display_rect){ 0, 0, -8, 8 }, ADRENO_DISPLAY_E_RECT);
    refused_cursor(B, 16, 16, 64, 0, 1024, (struct adreno_display_rect){ 9, 0, 8, 8 }, ADRENO_DISPLAY_E_RECT);   /* C2 */
    refused_cursor(B, 16, 16, 64, 0, 1024, (struct adreno_display_rect){ 0, 9, 8, 8 }, ADRENO_DISPLAY_E_RECT);
    refused_cursor(B, 16, 16, 64, 0, 1024,
                   (struct adreno_display_rect){ INT32_MAX, INT32_MAX, INT32_MAX, INT32_MAX }, ADRENO_DISPLAY_E_RECT);
    refused_cursor(B, 600, 8, 2400, 0, 2400 * 8, whole, ADRENO_DISPLAY_E_SIZE);                       /* C8 */
    refused_cursor(B, 8, 513, 32, 0, 32 * 513, whole, ADRENO_DISPLAY_E_SIZE);
    refused_cursor(B, 16, 16, 64, 0, 1023, whole, ADRENO_DISPLAY_E_SOURCE);                           /* C2 short */
    refused_cursor(B, 16, 16, 64, 1, 1024, whole, ADRENO_DISPLAY_E_SOURCE);                           /* offset */
    refused_cursor(B, 16, 16, 60, 0, 1024, whole, ADRENO_DISPLAY_E_SOURCE);                           /* row < w*4 */
    refused_cursor(B, 16, 16, 64, 4096, 1024, whole, ADRENO_DISPLAY_E_SOURCE);                        /* offset > length */
    refused_cursor(B, 16, 16, 0, 0, 1024, whole, ADRENO_DISPLAY_E_ARGS);                              /* row 0 */
    /* A legal sub-rectangle of a surface whose other rows lie past the allocation is fine:
     * only the rows read must fit. */
    {
        struct cpanel p;
        cpanel_make(&p, 64, 64, 256);
        struct hsurf cs;
        hsurf_make(&cs, B, 16, 16, 64, 0, 64 * 4 + 32);       /* rows 0-4 fully present, row 5 half */
        cursor_fill(&cs, 3);
        struct guarded gi, gs; struct adreno_display_cursor c = cursor_new(&gi, &gs);
        struct tstats st = { 0 };
        hsurf_expect(&cs, 0, 1, 32);
        struct tlayer L[4] = { OFF, LC(&cs, 5, 5), OFF, OFF };
        L[1].src = (struct adreno_display_rect){ 0, 1, 8, 4 };
        present_under_test(&c, &p.d, L, &st);
        memset(p.ref, 0xc3, p.d.length);
        ref_cursor(p.ref, &p.d, &cs, L[1].src, 5, 5);
        PANEL_CHECK(&p, "sub-rectangle at the end of the allocation");
        CHECK(st.cursor_errors == 0 && cs.model.rows_seen == 4 && cs.model.order_ok);
        hsurf_free(&cs); cpanel_free(&p); guarded_free(gi); guarded_free(gs);
    }
}

static int cursor_mode(void)
{
    struct case_result { const char *name; unsigned failures; } cases[6];
    unsigned n = 0, before;
    before = failures; case_cursor_none_identical(); cases[n++] = (struct case_result){ "no_cursor_layer_identical", case_failures(before) };
    before = failures; case_cursor_alpha(); cases[n++] = (struct case_result){ "premultiplied_alpha_exhaustive", case_failures(before) };
    before = failures;
    case_cursor_positions(130, 70, 130 * 4 + 48, 24, 20);           /* padded rows, every edge */
    case_cursor_positions(2880, 1800, 11520, 64, 64);               /* the A16 GOP, a 64x64 cursor */
    cases[n++] = (struct case_result){ "positions_and_edge_clipping", case_failures(before) };
    before = failures; case_cursor_moves(); cases[n++] = (struct case_result){ "moves_hide_persist_cursor_only", case_failures(before) };
    before = failures; case_cursor_refusals(); cases[n++] = (struct case_result){ "refusals_and_unknown_formats", case_failures(before) };
    printf("{\"variant\":\"%s\",\"mode\":\"cursor\",\"checks\":%u,\"failures\":%u,\"cases\":{", VARIANT, checks, failures);
    for (unsigned i = 0; i < n; i++) printf("%s\"%s\":%u", i ? "," : "", cases[i].name, cases[i].failures);
    printf("}}\n");
    return failures ? 1 : 0;
}

/* ---------------------------------------------------------------- probe surface mode */
static void hex(const unsigned char *h, char *out)
{
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) sprintf(out + 2 * i, "%02x", h[i]);
}
static int surface_mode(const char *dump_path, const char *panel_path)
{
    FILE *f = fopen(dump_path, "rb");
    if (!f) { perror(dump_path); return 2; }
    uint32_t h32[4]; uint64_t h64[3];
    if (fread(h32, 4, 4, f) != 4 || fread(h64, 8, 3, f) != 3 || h32[0] != 0x46534441u) { fclose(f); return 2; }
    uint64_t length = h64[2];
    /* The dump is DRAM; the CPU view starts stale, as for a GPU-written surface. */
    struct guarded dram = guarded_alloc(length), cpu = guarded_alloc(length);
    if (fread(dram.base, 1, length, f) != length) { fclose(f); return 2; }
    fclose(f);
    memset(cpu.base, 0x5a, length);
    /* The A16 GOP: 2880x1800, pitch 11520 (q1n1 docs/A16-ADRENO-STAGE3.md D0), BGRX. */
    const uint64_t pw = 2880, ph = 1800, pitch = 11520;
    struct guarded panel = guarded_alloc(pitch * ph);
    memset(panel.base, 0, pitch * ph);
    struct adreno_display_surface s = { cpu.base, length, h64[1], h64[0], h32[1], h32[2], h32[3] };
    struct adreno_display_scanout d = { panel.base, pitch * ph, pitch, pw, ph };
    struct cache_model m = { cpu.base, dram.base, length, 0, 0, h64[1], h64[0],
                             (h32[1] < pw ? h32[1] : pw) * adreno_display_bytes_per_pixel(h32[3]), 0, 1, 1 };
    struct adreno_display_copy_result r;
    int e = copy_under_test(&s, &d, maintain_model, &m, &r);
    unsigned char hraw[CC_SHA256_DIGEST_LENGTH], hrgb[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(panel.base, (CC_LONG)(pitch * ph), hraw);
    CC_SHA256_CTX c; CC_SHA256_Init(&c);
    uint8_t *line = malloc(pw * 3);
    for (uint64_t y = 0; y < ph; y++) {
        for (uint64_t x = 0; x < pw; x++) {
            const uint8_t *p = panel.base + y * pitch + x * 4;
            line[x * 3] = p[2]; line[x * 3 + 1] = p[1]; line[x * 3 + 2] = p[0];
        }
        CC_SHA256_Update(&c, line, (CC_LONG)(pw * 3));
    }
    CC_SHA256_Final(hrgb, &c);
    free(line);
    if (panel_path) {
        FILE *o = fopen(panel_path, "wb");
        if (!o || fwrite(panel.base, 1, pitch * ph, o) != pitch * ph) return 2;
        fclose(o);
    }
    char sraw[65], srgb[65];
    hex(hraw, sraw); hex(hrgb, srgb);
    printf("{\"variant\":\"%s\",\"error\":%d,\"width\":%llu,\"height\":%llu,\"bytes_read\":%llu,"
           "\"maintained_rows\":%llu,\"maintain_order_ok\":%d,\"panel_raw_sha256\":\"%s\",\"panel_rgb_sha256\":\"%s\"}\n",
           VARIANT, e, (unsigned long long)r.width, (unsigned long long)r.height, (unsigned long long)r.bytes_read,
           (unsigned long long)m.rows_seen, m.order_ok && m.range_ok, sraw, srgb);
    return e ? 1 : 0;
}

static int geometry_mode(void)
{
    enum { S = ADRENO_DISPLAY_GEOMETRY_SCALED, P = ADRENO_DISPLAY_GEOMETRY_PLACED, C = ADRENO_DISPLAY_GEOMETRY_CROPPED,
           Z = ADRENO_DISPLAY_GEOMETRY_SIZED };
    static const struct { int32_t sx, sy, sw, sh, dx, dy, dw, dh; uint64_t w, h; unsigned want; const char *what; } k[] = {
        {0, 0, 2880, 1800, 0, 0, 2880, 1800, 2880, 1800, 0, "native 1440x900 at 2x"},
        {0, 0, 2880, 1800, 0, 0, 2880, 1800, 0, 0, 0, "native, surface unknown"},
        {0, 0, 2560, 1600, 0, 0, 2880, 1800, 2560, 1600, S | Z, "1280x800 at 2x (larger text)"},
        {0, 0, 3360, 2100, 0, 0, 2880, 1800, 3360, 2100, S | Z, "1680x1050 at 2x (more space)"},
        {0, 0, 3840, 2400, 0, 0, 2880, 1800, 3840, 2400, S | Z, "1920x1200 at 2x"},
        {0, 0, 2048, 1280, 0, 0, 2880, 1800, 2048, 1280, S | Z, "1024x640 at 2x"},
        {0, 0, 2880, 1800, 0, 0, 2880, 1800, 3360, 2100, C | Z, "a panel-sized source inside a larger surface"},
        {0, 0, 1440, 900, 0, 0, 2880, 1800, 1440, 900, S | Z, "1440x900 at 1x, scaled up by the display"},
        {0, 0, 1440, 900, 720, 450, 1440, 900, 1440, 900, P | Z, "unscaled, centred"},
        {16, 8, 2880, 1800, 0, 0, 2880, 1800, 2896, 1808, C | Z, "source offset"},
        {16, 8, 2880, 1800, 0, 0, 2880, 1800, 2880, 1800, C, "source origin past the surface's top-left"},
        {0, 0, -1, 1800, 0, 0, -1, 1800, 2880, 1800, P | C, "negative width"},
        {0, 0, 2880, 1800, 0, 0, 2880, 1800, 2880, 1792, C | Z, "surface one row short of its source"},
    };
    unsigned bad = 0;
    for (unsigned i = 0; i < sizeof k / sizeof k[0]; i++) {
        const unsigned got = adreno_display_swap_geometry(k[i].sx, k[i].sy, k[i].sw, k[i].sh, k[i].dx, k[i].dy, k[i].dw,
                                                          k[i].dh, k[i].w, k[i].h, 2880, 1800);
        CHECK(got == k[i].want);
        if (got != k[i].want) { bad++; fprintf(stderr, "geometry %s: 0x%x, want 0x%x\n", k[i].what, got, k[i].want); }
    }
    printf("{\"variant\":\"%s\",\"geometry_cases\":%u,\"failures\":%u}\n", VARIANT,
           (unsigned)(sizeof k / sizeof k[0]), bad);
    return bad ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "geometry"))
        return geometry_mode();
    if (argc >= 3 && !strcmp(argv[1], "surface"))
        return surface_mode(argv[2], argc > 3 ? argv[3] : NULL);
    if (argc == 2 && !strcmp(argv[1], "cursor"))
        return cursor_mode();
    if (argc != 2 || strcmp(argv[1], "selftest")) {
        fprintf(stderr, "usage: %s selftest | geometry | cursor | surface DUMP [PANEL]\n", argv[0]);
        return 64;
    }
    case_full_panel_stale_cache();
    case_padding_and_offset();
    case_smaller_surface();
    case_larger_surface();
    case_refusals();
    case_l10r();
    case_rgha();
    printf("{\"variant\":\"%s\",\"checks\":%u,\"failures\":%u}\n", VARIANT, checks, failures);
    return failures ? 1 : 0;
}
