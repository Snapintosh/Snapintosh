/* SPDX-License-Identifier: MIT */
/* Failure inventory: docs/GRAPHICS-CORRECTNESS-20261018.md (publication), and the present-cost
 * batch's P1-P24 (FAILURES-AND-DESIGN.md, 2026-10-20): row signatures, the maintenance pass
 * with one barrier, the rolling refresh, forget, format/size changes, cursor rows.
 * Replay the production presentation path; inspect every published region as well
 * as the final frame. No target, GPU, kernel load or display changes.
 *
 *   presentation OUTDIR    writes OUTDIR/presentation.json, OUTDIR/damage.json, OUTDIR/final.bgra
 *
 * Build against the current header (the default) or, with -DADRENO_DISPLAY_BASE
 * -DPRESENT_HEADER='"<base>/AdrenoDisplayPresent.h"', against the pre-change one: the base
 * writes every source row and maintains each row with its own barrier, so its correctness
 * cases must pass and its cost cases must fail. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef PRESENT_HEADER
#define PRESENT_HEADER "../gpu/adreno-kext/kext/src/AdrenoDisplayPresent.h"
#endif
#if defined(ADRENO_PRESENT_CURSOR_STAGE) && ADRENO_PRESENT_CURSOR_STAGE
/* bytes the present reads back from the live (write-combined) scanout under the cursor */
static unsigned long long live_read_bytes;
#define ADRENO_DISPLAY_LIVE_READ(d, s, n) (live_read_bytes += (unsigned long long)(n), memcpy((d), (s), (n)))
#endif
#include PRESENT_HEADER
#ifdef ADRENO_DISPLAY_BASE
#define VARIANT "base"
/* The patched header's constants, so the same expectations apply to the base. */
#define ADRENO_DISPLAY_REFRESH_PERIOD 64u
#define ADRENO_DISPLAY_STAGE_ROWS 16u
#else
#define VARIANT "patched"
#endif

/* ---------------------------------------------------------------- source model (P6 P7)
 * dram holds what the producer wrote; cpu is what CPU loads return. Maintenance marks lines
 * pending; only the barrier makes them visible (Normal-NC: DC CIVAC is not ordered against
 * later loads without a DMB/DSB). The base callback completed every row itself (DSB SY), so
 * under ADRENO_DISPLAY_BASE maintenance is visible at once. */
struct srcmodel {
    uint8_t *cpu; const uint8_t *dram; uint64_t length; uint8_t *pending;
    uint64_t maintained, calls; int range_ok; unsigned barriers; int maintained_after_barrier;
    unsigned barrier_mark;      /* barriers before this present */
};
struct harness { struct srcmodel *m; uint64_t clocks; };
static struct harness HX;
static void commit_line(struct srcmodel *m, uint64_t line) {
    uint64_t n = line + 64 <= m->length ? 64 : m->length - line;
    if (m->cpu != m->dram) memcpy(m->cpu + line, m->dram + line, n);
}
static void m_maintain(void *ctx, const void *p, uint64_t n) {
    struct harness *h = ctx; struct srcmodel *m = h ? h->m : NULL;
    if (!m) return;
    uint64_t off = (uint64_t)((const uint8_t *)p - m->cpu);
    m->calls++; m->maintained += n;
    if (off > m->length || n > m->length - off) { m->range_ok = 0; return; }
    if (m->barriers > m->barrier_mark) m->maintained_after_barrier = 1;
    for (uint64_t line = off & ~63ull; line < off + n; line += 64) {
#ifdef ADRENO_DISPLAY_BASE
        commit_line(m, line);
#else
        m->pending[line / 64] = 1;
#endif
    }
}
#ifndef ADRENO_DISPLAY_BASE
static void m_barrier(void *ctx) {
    struct harness *h = ctx; struct srcmodel *m = h ? h->m : NULL;
    if (!m) return;
    m->barriers++;
    for (uint64_t line = 0; line < m->length; line += 64)
        if (m->pending[line / 64]) { commit_line(m, line); m->pending[line / 64] = 0; }
}
static uint64_t m_clock(void *ctx) { struct harness *h = ctx; return ++h->clocks; }
#endif

/* ---------------------------------------------------------------- present adapter */
struct outcome {
    int error; uint64_t bytes_read, bytes_written, regions, rows_written, rows_skipped, rows_compared,
        rows_refreshed; int forgot; uint64_t clocks; unsigned barriers;
};
static struct adreno_display_present_workspace WS;
#ifndef ADRENO_DISPLAY_BASE
static struct adreno_display_damage DMG;
#endif
static struct outcome present(struct adreno_display_cursor *c, const struct adreno_display_scanout *d,
                              const struct adreno_display_surface *s, struct srcmodel *m,
                              adreno_display_publish_fn observe)
{
    struct outcome o; memset(&o, 0, sizeof o);
    HX.m = m; HX.clocks = 0;
    unsigned barriers0 = m ? m->barriers : 0;
#ifdef ADRENO_DISPLAY_BASE
    uint64_t calls0 = m ? m->calls : 0;
#endif
    if (m) { m->maintained_after_barrier = 0; m->barrier_mark = m->barriers; }
#ifdef ADRENO_DISPLAY_BASE
    struct adreno_display_present_result r;
    o.error = adreno_display_present(c, d, s, &WS, m_maintain, &HX, observe, NULL, &r);
    struct adreno_display_plan plan = {0, 0, 0};
    if (!o.error && s) adreno_display_plan(s, d, &plan);
    o.bytes_read = r.bytes_read; o.bytes_written = r.bytes_written; o.regions = r.regions;
    o.rows_written = o.error ? 0 : plan.height;
    /* Kernel counter reads per copy: AdrenoDisplay's own start/end pair, and the base kext's
     * maintainSourceRow timed every row (two more per maintained row). */
    o.clocks = 2 + (m ? 2 * (m->calls - calls0) : 0);
#else
#if ADRENO_BEAM
    struct adreno_display_present_ops ops = { m_maintain, m_barrier, m_clock, &HX, observe, NULL, NULL, NULL };
#else
    struct adreno_display_present_ops ops = { m_maintain, m_barrier, m_clock, &HX, observe, NULL };
#endif
    struct adreno_display_present_result r;
    o.error = adreno_display_present(c, d, s, &WS, &ops, &r);
    o.bytes_read = r.bytes_read; o.bytes_written = r.bytes_written; o.regions = r.regions;
    o.rows_written = r.rows_written; o.rows_skipped = r.rows_skipped; o.rows_compared = r.rows_compared;
    o.rows_refreshed = r.rows_refreshed; o.forgot = (int)r.forgot; o.clocks = 2 + HX.clocks;
#endif
    o.barriers = m ? m->barriers - barriers0 : 0;
    return o;
}
static void forget(void)
{
#ifndef ADRENO_DISPLAY_BASE
    adreno_display_damage_forget(&DMG);
#endif
}

/* ---------------------------------------------------------------- the 2026-10-18 publication replay */
enum { W=2880,H=1800,ROW=W*4+32,SIZE=ROW*H,G=64 };
static uint8_t *background, *expected, *scan;
static unsigned publications, absent, stationary;
static uint64_t maintained;
static void observe(void *ctx,uint64_t x,uint64_t y,uint64_t w) {
    (void)ctx; publications++;
    assert(!memcmp(scan+y*ROW+x*4,expected+y*ROW+x*4,w*4));
    if(stationary) {
        for(unsigned yy=100;yy<132;yy++) for(unsigned xx=100;xx<132;xx++)
            if(scan[yy*ROW+xx*4]!=240) { absent++;return; }
    }
}
/* Independent oracle: explicit integer source-over, no production blending/copy helpers. */
static void reference(struct adreno_display_cursor *c) {
    memcpy(expected,background,SIZE);
    if(!c->visible)return;
    for(unsigned y=0;y<c->height;y++)for(unsigned x=0;x<c->width;x++) {
        int dx=c->x+(int)x,dy=c->y+(int)y;
        if(dx<0||dy<0||dx>=W||dy>=H)continue;
        const uint8_t *s=c->image+(y*c->width+x)*4;uint8_t *d=expected+dy*ROW+dx*4;
        for(unsigned k=0;k<4;k++){unsigned v=s[k]+(d[k]*(255-s[3])+127)/255;d[k]=v>255?255:v;}
    }
}
/* A coherent source (cpu == dram): this replay is about publication, not maintenance. */
static struct srcmodel coherent(uint8_t *bytes, uint64_t length) {
    struct srcmodel m = { bytes, bytes, length, calloc(length / 64 + 1, 1), 0, 0, 1, 0, 0, 0 };
    return m;
}
static unsigned stationaryPublications; static uint64_t maxCursorBytes;
static void publication_replay(const char *dir) {
    uint8_t *allocation=malloc(SIZE+2*G);memset(allocation,0xa5,SIZE+2*G);scan=allocation+G;
    background=malloc(SIZE);expected=malloc(SIZE);memset(background,0xa5,SIZE);
    for(unsigned y=0;y<H;y++)for(unsigned x=0;x<W;x++) {
        uint8_t *d=background+y*ROW+x*4;d[0]=x%127;d[1]=y%127;d[2]=33;d[3]=255;
    }
    memcpy(scan,background,SIZE);
    struct adreno_display_cursor c={0};c.image=malloc(ADRENO_DISPLAY_CURSOR_BYTES);c.save=malloc(ADRENO_DISPLAY_CURSOR_BYTES);
    c.width=c.height=32;c.x=c.y=100;c.visible=1;
    for(unsigned i=0;i<32*32;i++){c.image[i*4]=240;c.image[i*4+1]=12;c.image[i*4+2]=4;c.image[i*4+3]=255;}
    memset(&WS,0,sizeof WS);
    WS.row=malloc(W*4);WS.row_bytes=W*4;WS.next_save=malloc(ADRENO_DISPLAY_CURSOR_BYTES);
#ifndef ADRENO_DISPLAY_BASE
    WS.stage=malloc((size_t)ADRENO_DISPLAY_STAGE_ROWS*W*4);WS.stage_row_bytes=W*4;
    DMG=(struct adreno_display_damage){calloc(2*H,8),calloc(H,1),H,0,0,ADRENO_DISPLAY_REFRESH_PERIOD};
    WS.damage=&DMG;
#endif
    struct adreno_display_scanout d={scan,SIZE,ROW,W,H};
    struct adreno_display_surface s={background,SIZE,0,ROW,W,H,ADRENO_DISPLAY_FORMAT_BGRA};
    struct srcmodel m=coherent(background,SIZE);
    struct outcome out;
    reference(&c);out=present(&c,&d,NULL,NULL,observe);assert(!out.error);
    assert(!memcmp(scan,expected,SIZE));
    stationary=1;
    for(unsigned frame=0;frame<5;frame++) {
        for(unsigned y=0;y<H;y++)for(unsigned x=0;x<W;x++)background[y*ROW+x*4+2]=40+frame;
        reference(&c);m.maintained=0;
        out=present(&c,&d,&s,&m,observe);assert(!out.error);
        assert(!memcmp(scan,expected,SIZE));assert(m.maintained==(uint64_t)W*H*4);
        assert(out.bytes_written==(uint64_t)W*H*4);assert(!absent);
    }
    stationaryPublications=publications-32;stationary=0;
    const int pos[][2]={{104,104},{2400,1600},{-16,-12},{W-8,H-5},{W+8,0},{0,0}};
    for(unsigned i=0;i<sizeof(pos)/sizeof(pos[0]);i++) {
        c.x=pos[i][0];c.y=pos[i][1];reference(&c);m.maintained=0;
        out=present(&c,&d,NULL,&m,observe);assert(!out.error);
        assert(!memcmp(scan,expected,SIZE));assert(!m.maintained);
        assert(out.bytes_written<=2*32*32*4);if(out.bytes_written>maxCursorBytes)maxCursorBytes=out.bytes_written;
    }
    /* Partial layer copy must preserve background outside it and erase the old cursor there. */
    c.x=2700;c.y=1700;reference(&c);out=present(&c,&d,NULL,&m,observe);assert(!out.error);
    s.width=200;s.height=150;c.x=180;c.y=140;
    for(unsigned y=0;y<150;y++)for(unsigned x=0;x<200;x++)background[y*ROW+x*4+1]=99;
    reference(&c);out=present(&c,&d,&s,&m,observe);assert(!out.error);assert(!memcmp(scan,expected,SIZE));
    /* Semi-transparent glyph, then hide: saved background must never contain a cursor. */
    for(unsigned i=0;i<32*32;i++){c.image[i*4]=30;c.image[i*4+3]=128;}
    reference(&c);out=present(&c,&d,NULL,&m,observe);assert(!out.error);assert(!memcmp(scan,expected,SIZE));
    c.visible=0;reference(&c);out=present(&c,&d,NULL,&m,observe);assert(!out.error);assert(!memcmp(scan,background,SIZE));
    /* Refusals occur before maintenance, publication, cursor state or pixel mutation. */
    unsigned before=publications;uint64_t reads=m.maintained;
    struct adreno_display_cursor saved=c;s.format=0;
    assert(present(&c,&d,&s,&m,observe).error==ADRENO_DISPLAY_E_FORMAT);
    s.format=ADRENO_DISPLAY_FORMAT_BGRA;s.length=8;
    assert(present(&c,&d,&s,&m,observe).error==ADRENO_DISPLAY_E_SOURCE);
    c.visible=1;saved=c;WS.row_bytes=1;
    assert(present(&c,&d,NULL,&m,observe).error!=0);
    assert(!memcmp(&c,&saved,sizeof c));assert(publications==before&&m.maintained==reads);assert(!memcmp(scan,background,SIZE));
    for(unsigned i=0;i<G;i++)assert(allocation[i]==0xa5&&allocation[SIZE+G+i]==0xa5);
    char path[4096];snprintf(path,sizeof path,"%s/final.bgra",dir);FILE *f=fopen(path,"wb");assert(f);assert(fwrite(scan,1,SIZE,f)==SIZE);fclose(f);
    free(c.image);free(c.save);free(WS.next_save);free(WS.row);free(background);free(expected);free(allocation);free(m.pending);
#ifndef ADRENO_DISPLAY_BASE
    free(WS.stage);free(DMG.sig);free(DMG.known);
#endif
    (void)maintained;
}

/* ---------------------------------------------------------------- damage scenarios (P1-P24) */
/* CHECK: correctness (both variants must pass). COST: what the change is for (the base must fail). */
static unsigned failures, checks, cost_failures, cost_checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
#define COST(c) do { cost_checks++; if (!(c)) { cost_failures++; fprintf(stderr, "COST %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

struct guarded { uint8_t *base; size_t length, mapped; };
static struct guarded guarded_alloc(size_t length) {
    size_t page = (size_t)getpagesize(), span = (length + page - 1) / page * page;
    uint8_t *m = mmap(NULL, span + page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); exit(2); }
    if (mprotect(m + span, page, PROT_NONE)) { perror("mprotect"); exit(2); }
    struct guarded g = { m + span - length, length, span + page };
    return g;
}
static void guarded_free(struct guarded g) {
    size_t page = (size_t)getpagesize(), span = g.mapped - page;
    munmap(g.base + g.length - span, g.mapped);
}

/* A test display: scanout (guarded), its expected bytes, a per-row write log. */
struct tdisp { uint64_t w, h, row; struct guarded scan; uint8_t *ref; uint64_t *writes;
               struct adreno_display_scanout d; struct adreno_display_cursor c; struct guarded ci, cs, ns;
               int track_cursor; int64_t cx, cy; uint64_t cursor_absent; };
static struct tdisp *TD;
static void tobserve(void *ctx, uint64_t x, uint64_t y, uint64_t w) {
    (void)ctx; (void)x; (void)w;
    TD->writes[y]++;
    /* P4: a publication touching a visible stationary cursor's rows shows the cursor. */
    if (TD->track_cursor && TD->c.visible && (int64_t)y >= TD->cy && (int64_t)y < TD->cy + (int64_t)TD->c.height) {
        int64_t px = TD->cx + 1;
        if (px >= 0 && px < (int64_t)TD->w && (int64_t)x <= px && px < (int64_t)(x + w)) {
            const uint8_t *p = TD->scan.base + y * TD->row + (uint64_t)px * 4;
            if (p[0] != 250 || p[1] != 3) TD->cursor_absent++;
        }
    }
}
static void tdisp_make(struct tdisp *t, uint64_t w, uint64_t h, uint64_t row) {
    memset(t, 0, sizeof *t);
    t->w = w; t->h = h; t->row = row;
    t->scan = guarded_alloc(row * h); memset(t->scan.base, 0xc3, row * h);
    t->ref = malloc(row * h); memset(t->ref, 0xc3, row * h);
    t->writes = calloc(h, 8);
    t->d = (struct adreno_display_scanout){ t->scan.base, row * h, row, w, h };
    t->ci = guarded_alloc(ADRENO_DISPLAY_CURSOR_BYTES); t->cs = guarded_alloc(ADRENO_DISPLAY_CURSOR_BYTES);
    t->ns = guarded_alloc(ADRENO_DISPLAY_CURSOR_BYTES);
    t->c.image = t->ci.base; t->c.save = t->cs.base;
    memset(&WS, 0, sizeof WS);
    /* The present swaps c.save and WS.next_save: both are freed by identity, not by pointer. */
    WS.row = malloc(w * 4); WS.row_bytes = w * 4; WS.next_save = t->ns.base;
#ifndef ADRENO_DISPLAY_BASE
    WS.stage = malloc((size_t)ADRENO_DISPLAY_STAGE_ROWS * w * 4); WS.stage_row_bytes = w * 4;
    DMG = (struct adreno_display_damage){ calloc(2 * h, 8), calloc(h, 1), h, 0, 0, ADRENO_DISPLAY_REFRESH_PERIOD };
    WS.damage = &DMG;
#endif
    TD = t;
}
static void tdisp_free(struct tdisp *t) {
    guarded_free(t->scan); free(t->ref); free(t->writes); guarded_free(t->ci); guarded_free(t->cs); guarded_free(t->ns);
    free(WS.row);
#ifndef ADRENO_DISPLAY_BASE
    free(WS.stage); free(DMG.sig); free(DMG.known); memset(&DMG, 0, sizeof DMG);
#endif
    memset(&WS, 0, sizeof WS);
}
static int tdisp_ok(const struct tdisp *t) { return !memcmp(t->scan.base, t->ref, t->row * t->h); }
static uint64_t tdisp_bad_rows(const struct tdisp *t) {
    uint64_t n = 0;
    for (uint64_t y = 0; y < t->h; y++) if (memcmp(t->scan.base + y * t->row, t->ref + y * t->row, t->row)) n++;
    return n;
}

/* A test surface: dram (truth) and the CPU view, which goes stale before every present (P6). */
struct tsurf { struct guarded dram, cpu; struct srcmodel m; struct adreno_display_surface s; };
static void tsurf_make(struct tsurf *t, uint32_t format, uint64_t w, uint64_t h, uint64_t row, uint64_t offset) {
    uint64_t length = offset + row * h;
    t->dram = guarded_alloc(length); t->cpu = guarded_alloc(length);
    memset(t->dram.base, 0x77, length); memset(t->cpu.base, 0x5a, length);
    t->m = (struct srcmodel){ t->cpu.base, t->dram.base, length, calloc(length / 64 + 1, 1), 0, 0, 1, 0, 0, 0 };
    t->s = (struct adreno_display_surface){ t->cpu.base, length, offset, row, w, h, format };
}
static void tsurf_free(struct tsurf *t) { guarded_free(t->dram); guarded_free(t->cpu); free(t->m.pending); }
static void tsurf_stale(struct tsurf *t) { memset(t->cpu.base, 0x5a, t->m.length); memset(t->m.pending, 0, t->m.length / 64 + 1); }

/* Frame k of a desktop: a fixed background with a clock rectangle, a spinner and a line of text
 * that change with k. pixel(x, y, k) is BGRX. */
static void frame_pixel(uint64_t x, uint64_t y, unsigned k, uint8_t p[4]) {
    p[0] = (uint8_t)(x * 7 + y); p[1] = (uint8_t)(y * 3 ^ x); p[2] = (uint8_t)((x + y) >> 2); p[3] = 0xff;
    if (y >= 8 && y < 40 && x >= 40 && x < 160) { p[0] = (uint8_t)(k * 13 + x); p[1] = (uint8_t)k; }      /* clock */
    uint64_t sy = 100 + (k % 7) * 9;                                                                   /* spinner */
    if (y >= sy && y < sy + 12 && x >= 200 && x < 230) { p[0] = 1; p[1] = (uint8_t)(200 + k); p[2] = 7; }
    if (k >= 3 && y == 150 + k && x < 64) { p[2] = (uint8_t)(255 - k); }                                 /* text */
}
static void render(struct tsurf *t, uint64_t w, uint64_t h, unsigned k) {
    for (uint64_t y = 0; y < h; y++) for (uint64_t x = 0; x < w; x++)
        frame_pixel(x, y, k, t->dram.base + t->s.offset + y * t->s.row_bytes + x * 4);
}
static void ref_frame(struct tdisp *d, uint64_t w, uint64_t h, unsigned k) {
    for (uint64_t y = 0; y < h && y < d->h; y++) for (uint64_t x = 0; x < w && x < d->w; x++)
        frame_pixel(x, y, k, d->ref + y * d->row + x * 4);
}
static void ref_cursor(struct tdisp *d) {
    if (!d->c.visible) return;
    for (uint64_t j = 0; j < d->c.height; j++) for (uint64_t i = 0; i < d->c.width; i++) {
        int64_t x = d->c.x + (int64_t)i, y = d->c.y + (int64_t)j;
        if (x < 0 || y < 0 || x >= (int64_t)d->w || y >= (int64_t)d->h) continue;
        const uint8_t *s = d->c.image + (j * d->c.width + i) * 4; uint8_t *q = d->ref + (uint64_t)y * d->row + (uint64_t)x * 4;
        for (int c = 0; c < 4; c++) { unsigned v = s[c] + (q[c] * (255u - s[3]) + 127) / 255; q[c] = (uint8_t)(v > 255 ? 255 : v); }
    }
}
static uint64_t changed_rows(uint64_t w, uint64_t h, unsigned a, unsigned b) {
    uint64_t n = 0; uint8_t p[4], q[4];
    for (uint64_t y = 0; y < h; y++) for (uint64_t x = 0; x < w; x++) {
        frame_pixel(x, y, a, p); frame_pixel(x, y, b, q);
        if (memcmp(p, q, 4)) { n++; break; }
    }
    return n;
}

struct scen { const char *name; unsigned failures, cost_failures; uint64_t rows_written, rows_total, bytes_written; };
static struct scen S[16]; static unsigned NS, cost_before;
static unsigned scen_begin(void) { cost_before = cost_failures; return failures; }
static void scen_end(const char *name, unsigned before, uint64_t rows_written, uint64_t rows_total, uint64_t bytes) {
    S[NS++] = (struct scen){ name, failures - before, cost_failures - cost_before, rows_written, rows_total, bytes };
}

/* S1 (P1 P6 P13 P16): three rotating buffers at the A16 size, small damage per frame. */
static void s_rotation(void) {
    unsigned before = scen_begin();
    const uint64_t w = 2880, h = 1800, row = 11520;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf b[3]; for (int i = 0; i < 3; i++) tsurf_make(&b[i], ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    uint64_t written = 0, total = 0, bytes = 0, extra = 0, maxclocks = 0; int read_ok = 1, barrier_ok = 1;
    for (unsigned k = 0; k < 12; k++) {
        struct tsurf *t = &b[k % 3];
        render(t, w, h, k); tsurf_stale(t);
        ref_frame(&d, w, h, k);
        memset(d.writes, 0, h * 8);
        struct outcome o = present(&d.c, &d.d, &t->s, &t->m, tobserve);
        CHECK(o.error == 0);
        CHECK(tdisp_ok(&d));                               /* P1 P6: right bytes despite a stale CPU view */
        if (!tdisp_ok(&d)) fprintf(stderr, "  rotation frame %u: %llu bad rows\n", k, (unsigned long long)tdisp_bad_rows(&d));
        read_ok &= t->m.maintained == o.bytes_read && t->m.range_ok;
#ifndef ADRENO_DISPLAY_BASE
        barrier_ok &= o.barriers == 1 && !t->m.maintained_after_barrier;
#endif
        t->m.maintained = 0;
        if (k) {
            uint64_t need = changed_rows(w, h, k - 1, k);
            uint64_t refresh = (h + ADRENO_DISPLAY_REFRESH_PERIOD - 1) / ADRENO_DISPLAY_REFRESH_PERIOD;
            CHECK(o.rows_written >= need);                 /* sound */
            COST(o.rows_written <= need + refresh);        /* P16: cost follows the damage (base: every row) */
            extra += o.rows_written - need;
            written += o.rows_written; total += h; bytes += o.bytes_written;
        }
        if (o.clocks > maxclocks) maxclocks = o.clocks;
    }
    CHECK(read_ok); CHECK(barrier_ok);
    COST(maxclocks <= 6 + 3 * ((h + ADRENO_DISPLAY_STAGE_ROWS - 1) / ADRENO_DISPLAY_STAGE_ROWS));    /* P13 */
    fprintf(stderr, "  rotation: %llu of %llu rows written after frame 0, %llu beyond the damage; %llu kernel counter reads per copy at most\n",
            (unsigned long long)written, (unsigned long long)total, (unsigned long long)extra, (unsigned long long)maxclocks);
    for (int i = 0; i < 3; i++) tsurf_free(&b[i]);
    tdisp_free(&d);
    scen_end("rotation_small_damage_a16", before, written, total, bytes);
}

/* S2 (P1 P22): single-pixel changes at the corners and edges; padded rows, base offset. */
static void s_corners(void) {
    unsigned before = scen_begin();
    const uint64_t w = 301, h = 203, row = 301 * 4 + 52;
    struct tdisp d; tdisp_make(&d, w, h, row + 12);
    struct tsurf t; tsurf_make(&t, ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 128);
    render(&t, w, h, 0); ref_frame(&d, w, h, 0);
    tsurf_stale(&t); CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == 0); CHECK(tdisp_ok(&d));
    const uint64_t at[][2] = { { 0, 0 }, { w - 1, h - 1 }, { w - 1, 0 }, { 0, h - 1 }, { 150, 101 }, { 1, 1 } };
    uint64_t written = 0;
    for (unsigned i = 0; i < sizeof at / sizeof at[0]; i++) {
        uint8_t *p = t.dram.base + t.s.offset + at[i][1] * row + at[i][0] * 4, *q = d.ref + at[i][1] * d.row + at[i][0] * 4;
        p[i % 3] ^= 0x01; memcpy(q, p, 4);                 /* one bit of one channel */
        tsurf_stale(&t); memset(d.writes, 0, h * 8);
        struct outcome o = present(&d.c, &d.d, &t.s, &t.m, tobserve);
        CHECK(o.error == 0 && tdisp_ok(&d));
        CHECK(d.writes[at[i][1]] >= 1);
        COST(o.rows_written <= 1 + (h + ADRENO_DISPLAY_REFRESH_PERIOD - 1) / ADRENO_DISPLAY_REFRESH_PERIOD);
        written += o.rows_written;
    }
    /* Row padding of the scanout is never written (P22). */
    int pad_ok = 1;
    for (uint64_t y = 0; y < h; y++) for (uint64_t x = w * 4; x < d.row; x++) if (d.scan.base[y * d.row + x] != 0xc3) pad_ok = 0;
    CHECK(pad_ok);
    tsurf_free(&t); tdisp_free(&d);
    scen_end("single_pixel_edges", before, written, 6 * h, 0);
}

/* S3 (P3 P21): foreign scanout writes and a corrupted signature are repaired within one refresh period,
 * and every row is rewritten at least once per period. */
static void s_refresh(void) {
    unsigned before = scen_begin();
    const uint64_t w = 200, h = 130, row = 800;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf t; tsurf_make(&t, ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    render(&t, w, h, 1); ref_frame(&d, w, h, 1);
    tsurf_stale(&t); CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == 0); CHECK(tdisp_ok(&d));
    memset(d.scan.base + 17 * row, 0x11, row);             /* a console line nobody told us about */
    memset(d.scan.base + 129 * row + 40, 0x22, 64);
#ifndef ADRENO_DISPLAY_BASE
    /* A signature collision (P1): row 64 changes, but its recorded signature already equals the new
     * content's, so the comparison alone would never rewrite it. */
    uint8_t *r64 = t.dram.base + 64 * row;
    for (uint64_t x = 10; x < 20; x++) r64[x * 4 + 1] ^= 0x40;
    memcpy(d.ref + 64 * row, r64, w * 4);
    adreno_display_row_signature(r64, w * 4, DMG.sig + 2 * 64);
#endif
    memset(d.writes, 0, h * 8);
    unsigned repaired_at = 0; uint64_t written = 0;
    for (unsigned n = 1; n <= ADRENO_DISPLAY_REFRESH_PERIOD; n++) {
        tsurf_stale(&t);
        struct outcome o = present(&d.c, &d.d, &t.s, &t.m, tobserve);
        CHECK(o.error == 0);
        written += o.rows_written;
        if (!repaired_at && tdisp_ok(&d)) repaired_at = n;
    }
    CHECK(repaired_at && repaired_at <= ADRENO_DISPLAY_REFRESH_PERIOD);
    uint64_t never = 0; for (uint64_t y = 0; y < h; y++) if (!d.writes[y]) never++;
    CHECK(never == 0);                                      /* P21 */
    COST(written <= (uint64_t)ADRENO_DISPLAY_REFRESH_PERIOD * ((h + ADRENO_DISPLAY_REFRESH_PERIOD - 1) / ADRENO_DISPLAY_REFRESH_PERIOD) + 4);
    fprintf(stderr, "  refresh: repaired after %u presents; %llu rows over %u presents\n", repaired_at,
            (unsigned long long)written, ADRENO_DISPLAY_REFRESH_PERIOD);
    tsurf_free(&t); tdisp_free(&d);
    scen_end("foreign_write_refresh_bound", before, written, (uint64_t)h * ADRENO_DISPLAY_REFRESH_PERIOD, 0);
}

/* S4 (P2 P11): a mode set that clears the GOP; forget makes the next frame complete. Without forget
 * (patched only) the clear shows until the refresh repairs it: the hook is load-bearing. */
static void s_forget(void) {
    unsigned before = scen_begin();
    const uint64_t w = 160, h = 96, row = 640;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf t; tsurf_make(&t, ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    render(&t, w, h, 2); ref_frame(&d, w, h, 2);
    tsurf_stale(&t); CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == 0); CHECK(tdisp_ok(&d));
    memset(d.scan.base, 0, row * h); forget();
    tsurf_stale(&t);
    struct outcome o = present(&d.c, &d.d, &t.s, &t.m, tobserve);
    CHECK(o.error == 0 && tdisp_ok(&d) && o.rows_written == h);
#ifndef ADRENO_DISPLAY_BASE
    memset(d.scan.base, 0, row * h);                         /* the same clear, nobody calls forget */
    tsurf_stale(&t); o = present(&d.c, &d.d, &t.s, &t.m, tobserve);
    CHECK(o.error == 0 && !tdisp_ok(&d));                    /* expected hazard, bounded by S3 */
    for (unsigned n = 0; n < ADRENO_DISPLAY_REFRESH_PERIOD; n++) { tsurf_stale(&t); present(&d.c, &d.d, &t.s, &t.m, tobserve); }
    CHECK(tdisp_ok(&d));
#endif
    tsurf_free(&t); tdisp_free(&d);
    scen_end("forget_after_mode_set", before, 0, 0, 0);
}

/* S5 (P9): the same image as l10r (identical output), a different one as RGhA, then an unknown format. */
static void s_formats(void) {
    unsigned before = scen_begin();
    const uint64_t w = 128, h = 80, row = 512;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf a, l, r;
    tsurf_make(&a, ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    tsurf_make(&l, ADRENO_DISPLAY_FORMAT_L10R, w, h, row, 0);
    tsurf_make(&r, ADRENO_DISPLAY_FORMAT_RGHA, w, h, w * 8, 0);
    /* l10r image whose conversion is exactly the BGRA image: 8-bit values v8 -> v10 = v8 * 4 + v8 / 64. */
    for (uint64_t y = 0; y < h; y++) for (uint64_t x = 0; x < w; x++) {
        uint8_t p[4]; frame_pixel(x, y, 4, p);
        uint32_t v[3]; for (int c = 0; c < 3; c++) v[c] = (uint32_t)p[c] * 4u + p[c] / 64u;
        uint32_t word = v[0] | v[1] << 10 | v[2] << 20 | 3u << 30;
        memcpy(l.dram.base + y * row + x * 4, &word, 4);
        uint8_t conv[4]; adreno_display_convert_row(ADRENO_DISPLAY_FORMAT_L10R, (const uint8_t *)&word, conv, 1);
        memcpy(a.dram.base + y * row + x * 4, conv, 4);      /* the BGRA twin is the converter's output */
        memcpy(d.ref + y * row + x * 4, conv, 4);
    }
    tsurf_stale(&a); CHECK(present(&d.c, &d.d, &a.s, &a.m, tobserve).error == 0); CHECK(tdisp_ok(&d));
    tsurf_stale(&l); struct outcome o = present(&d.c, &d.d, &l.s, &l.m, tobserve);
    CHECK(o.error == 0 && tdisp_ok(&d));
    COST(o.rows_written <= (h + ADRENO_DISPLAY_REFRESH_PERIOD - 1) / ADRENO_DISPLAY_REFRESH_PERIOD);    /* same pixels */
    uint64_t written = o.rows_written;
    /* RGhA, a different image: 1.0 or 0.5 per channel. */
    for (uint64_t y = 0; y < h; y++) for (uint64_t x = 0; x < w; x++) {
        uint16_t one = 0x3c00, half = 0x3800, ch[4] = { (uint16_t)((x + y) & 1 ? one : half), half, one, one };
        memcpy(r.dram.base + y * w * 8 + x * 8, ch, 8);
        uint8_t out[4]; adreno_display_convert_row(ADRENO_DISPLAY_FORMAT_RGHA, r.dram.base + y * w * 8 + x * 8, out, 1);
        memcpy(d.ref + y * row + x * 4, out, 4);
    }
    tsurf_stale(&r); o = present(&d.c, &d.d, &r.s, &r.m, tobserve);
    CHECK(o.error == 0 && tdisp_ok(&d) && o.rows_written == h);
    written += o.rows_written;
    /* Unknown format: refused, nothing read, pixels and signatures untouched. */
#ifndef ADRENO_DISPLAY_BASE
    uint64_t *sig0 = malloc(2 * h * 8); memcpy(sig0, DMG.sig, 2 * h * 8); uint8_t *known0 = malloc(h); memcpy(known0, DMG.known, h);
#endif
    struct adreno_display_surface bad = r.s; bad.format = 0x78343230u;
    uint64_t m0 = r.m.maintained;
    CHECK(present(&d.c, &d.d, &bad, &r.m, tobserve).error == ADRENO_DISPLAY_E_FORMAT);
    CHECK(r.m.maintained == m0 && tdisp_ok(&d));
#ifndef ADRENO_DISPLAY_BASE
    CHECK(!memcmp(sig0, DMG.sig, 2 * h * 8) && !memcmp(known0, DMG.known, h)); free(sig0); free(known0);
#endif
    tsurf_free(&a); tsurf_free(&l); tsurf_free(&r); tdisp_free(&d);
    scen_end("format_changes", before, written, 2 * h, 0);
}

/* S6 (P10): narrower (forget, columns beyond untouched), shorter (rows below untouched), back to full. */
static void s_sizes(void) {
    unsigned before = scen_begin();
    const uint64_t w = 180, h = 120, row = 720;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf t; tsurf_make(&t, ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    render(&t, w, h, 5); ref_frame(&d, w, h, 5);
    tsurf_stale(&t); CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == 0); CHECK(tdisp_ok(&d));
    render(&t, w, h, 6);
    struct adreno_display_surface narrow = t.s; narrow.width = w - 37;
    ref_frame(&d, w - 37, h, 6);                             /* columns >= w-37 keep frame 5 */
    tsurf_stale(&t); struct outcome o = present(&d.c, &d.d, &narrow, &t.m, tobserve);
    CHECK(o.error == 0 && tdisp_ok(&d) && o.rows_written == h);
#ifndef ADRENO_DISPLAY_BASE
    CHECK(o.forgot == 1);
#endif
    struct adreno_display_surface shorter = narrow; shorter.height = h - 50;
    render(&t, w, h, 7); ref_frame(&d, w - 37, h - 50, 7);   /* rows >= h-50 keep frame 6 */
    tsurf_stale(&t); o = present(&d.c, &d.d, &shorter, &t.m, tobserve);
    CHECK(o.error == 0 && tdisp_ok(&d));
    CHECK(o.rows_written >= changed_rows(w - 37, h - 50, 6, 7));
    COST(o.rows_written <= changed_rows(w - 37, h - 50, 6, 7) + (h - 50 + ADRENO_DISPLAY_REFRESH_PERIOD - 1) / ADRENO_DISPLAY_REFRESH_PERIOD);
    /* Back to the full surface (frame 7): the tall rows and the right columns are rewritten. */
    ref_frame(&d, w, h, 7);
    tsurf_stale(&t); o = present(&d.c, &d.d, &t.s, &t.m, tobserve);
    CHECK(o.error == 0 && tdisp_ok(&d) && o.rows_written == h);   /* width changed again: forgot */
    tsurf_free(&t); tdisp_free(&d);
    scen_end("size_changes", before, 0, 0, 0);
}

/* S7 (P4 P5 P24): a cursor over changed and unchanged rows: stationary, moved, hidden. */
static void cursor_fill(struct tdisp *d, uint32_t cw, uint32_t ch) {
    d->c.width = cw; d->c.height = ch;
    for (uint32_t i = 0; i < cw * ch; i++) {
        uint8_t *p = d->c.image + i * 4;
        if ((i % cw) < 3) { p[0] = 250; p[1] = 3; p[2] = 9; p[3] = 255; }   /* opaque left edge: the probe column */
        else { p[0] = 40; p[1] = 50; p[2] = 60; p[3] = 128; }
    }
}
static void s_cursor(void) {
    unsigned before = scen_begin();
    const uint64_t w = 400, h = 260, row = 1600;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf b[2]; for (int i = 0; i < 2; i++) tsurf_make(&b[i], ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    cursor_fill(&d, 24, 30);
    struct { unsigned k; int x, y, vis; } steps[] = {
        { 0, 20, 10, 1 },     /* over the changing clock */
        { 1, 20, 10, 1 },     /* stationary, clock changes under it */
        { 2, 20, 10, 1 },
        { 3, 300, 200, 1 },   /* moved over rows that do not change */
        { 4, 300, 200, 1 },   /* stationary over unchanged rows, damage elsewhere */
        { 5, 301, 205, 1 },   /* small move over unchanged rows */
        { 6, 205, 100, 1 },   /* onto the spinner */
        { 7, 205, 100, 1 },
        { 8, 205, 100, 0 },   /* hidden over changing rows */
        { 9, 390, 250, 1 },   /* clipped at the corner */
        { 10, 390, 250, 0 },  /* hidden over unchanged rows */
    };
    d.track_cursor = 1;
    for (unsigned i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        struct tsurf *t = &b[i % 2];
        render(t, w, h, steps[i].k); tsurf_stale(t);
        d.c.x = steps[i].x; d.c.y = steps[i].y; d.c.visible = steps[i].vis; d.cx = steps[i].x; d.cy = steps[i].y;
        memset(d.ref, 0xc3, row * h); ref_frame(&d, w, h, steps[i].k); ref_cursor(&d);
        struct outcome o = present(&d.c, &d.d, &t->s, &t->m, tobserve);
        CHECK(o.error == 0);
        CHECK(tdisp_ok(&d));
        if (!tdisp_ok(&d)) fprintf(stderr, "  cursor step %u: %llu bad rows\n", i, (unsigned long long)tdisp_bad_rows(&d));
    }
    CHECK(d.cursor_absent == 0);                             /* P4: never published cursor-free */
    /* After the last hide the scanout is pure layer 0: no save-under carried a cursor (P5). */
    tsurf_free(&b[0]); tsurf_free(&b[1]); tdisp_free(&d);
    scen_end("cursor_over_damage", before, 0, 0, 0);
}

/* S8 (P2 P14 P15): refusals touch nothing; tracking off writes every row. */
static void s_refusals(void) {
    unsigned before = scen_begin();
    const uint64_t w = 64, h = 40, row = 256;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf t; tsurf_make(&t, ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    render(&t, w, h, 3); ref_frame(&d, w, h, 3);
    tsurf_stale(&t); CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == 0); CHECK(tdisp_ok(&d));
    render(&t, w, h, 4);
    uint64_t m0 = t.m.maintained;
    struct adreno_display_surface shortlen = t.s; shortlen.length -= 1;
    CHECK(present(&d.c, &d.d, &shortlen, &t.m, tobserve).error == ADRENO_DISPLAY_E_SOURCE);
    CHECK(t.m.maintained == m0 && tdisp_ok(&d));
#ifndef ADRENO_DISPLAY_BASE
    uint64_t rows = DMG.rows; DMG.rows = h - 1;               /* P15: table smaller than the scanout */
    CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == ADRENO_DISPLAY_E_SIZE);
    CHECK(t.m.maintained == m0 && tdisp_ok(&d));
    DMG.rows = rows;
    uint8_t *stage = WS.stage; WS.stage = NULL;               /* P14: no stage */
    CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == ADRENO_DISPLAY_E_SIZE);
    CHECK(t.m.maintained == m0 && tdisp_ok(&d));
    WS.stage = stage;
    WS.damage = NULL;                                         /* P14: no signature table: every row */
    ref_frame(&d, w, h, 4); tsurf_stale(&t);
    struct outcome o = present(&d.c, &d.d, &t.s, &t.m, tobserve);
    CHECK(o.error == 0 && tdisp_ok(&d) && o.rows_written == h && o.rows_compared == 0);
    WS.damage = &DMG;
#endif
    tsurf_free(&t); tdisp_free(&d);
    scen_end("refusals_and_fallback", before, 0, 0, 0);
}

#if ADRENO_PRESENT_CURSOR_STAGE
/* agents/tear-free, the dvfs finding (b11v1: cursor rows read the live write-combined scanout at 313 MB/s): a layer-0
 * present reads nothing back under the cursor, a cursor-only move reads only the new strip outside the old save-under,
 * and every frame equals the reference. */
static void s_cursor_stage(void) {
    unsigned before = scen_begin();
    const uint64_t w = 400, h = 260, row = 1600;
    struct tdisp d; tdisp_make(&d, w, h, row);
    struct tsurf t; tsurf_make(&t, ADRENO_DISPLAY_FORMAT_BGRA, w, h, row, 0);
    cursor_fill(&d, 64, 64);
    render(&t, w, h, 0); tsurf_stale(&t); d.c.x = 250; d.c.y = 170; d.c.visible = 1;
    memset(d.ref, 0xc3, row * h); ref_frame(&d, w, h, 0); ref_cursor(&d);
    CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == 0 && tdisp_ok(&d));
    /* layer 0 changes elsewhere (clock, spinner), the cursor moves 5 right and 3 down over unchanged rows */
    live_read_bytes = 0;
    render(&t, w, h, 1); tsurf_stale(&t); d.c.x = 255; d.c.y = 173;
    memset(d.ref, 0xc3, row * h); ref_frame(&d, w, h, 1); ref_cursor(&d);
    CHECK(present(&d.c, &d.d, &t.s, &t.m, tobserve).error == 0 && tdisp_ok(&d));
    const unsigned long long layer0 = live_read_bytes;
    COST(layer0 == 0);
    /* a cursor-only move, 5 right and 3 down: 61 rows of a 5-pixel strip and 3 rows of 64 pixels */
    live_read_bytes = 0; d.c.x = 260; d.c.y = 176;
    memset(d.ref, 0xc3, row * h); ref_frame(&d, w, h, 1); ref_cursor(&d);
    CHECK(present(&d.c, &d.d, NULL, NULL, tobserve).error == 0 && tdisp_ok(&d));
    const unsigned long long only = live_read_bytes;
    COST(only == (64 - 3) * 5 * 4 + 3 * 64 * 4);
    /* hidden: the save-under restores it, nothing read */
    live_read_bytes = 0; d.c.visible = 0;
    memset(d.ref, 0xc3, row * h); ref_frame(&d, w, h, 1);
    CHECK(present(&d.c, &d.d, NULL, NULL, tobserve).error == 0 && tdisp_ok(&d) && live_read_bytes == 0);
    printf("cursor stage: live readback %llu bytes in a layer-0 present, %llu in a cursor-only move\n", layer0, only);
    tsurf_free(&t); tdisp_free(&d);
    scen_end("cursor_stage_readback", before, 0, 0, 0);
}
#endif
static void damage_scenarios(const char *dir) {
    s_rotation(); s_corners(); s_refresh(); s_forget(); s_formats(); s_sizes(); s_cursor(); s_refusals();
#if ADRENO_PRESENT_CURSOR_STAGE
    s_cursor_stage();
#endif
    char path[4096]; snprintf(path, sizeof path, "%s/damage.json", dir);
    FILE *f = fopen(path, "w"); assert(f);
    fprintf(f, "{\"variant\":\"%s\",\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u,\"scenarios\":{",
            VARIANT, checks, failures, cost_checks, cost_failures);
    for (unsigned i = 0; i < NS; i++)
        fprintf(f, "%s\"%s\":{\"failures\":%u,\"cost_failures\":%u,\"rows_written\":%llu,\"rows_total\":%llu,\"bytes_written\":%llu}",
                i ? "," : "", S[i].name, S[i].failures, S[i].cost_failures, (unsigned long long)S[i].rows_written,
                (unsigned long long)S[i].rows_total, (unsigned long long)S[i].bytes_written);
    fprintf(f, "}}\n"); fclose(f);
    printf("{\"variant\":\"%s\",\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", VARIANT, checks,
           failures, cost_checks, cost_failures);
}

#ifndef ADRENO_DISPLAY_BASE
/* ---------------------------------------------------------------- frame pacing (kext batch 8, F1-F11)
 * FAILURES-AND-DESIGN.md (batch 8) section 2, written before AdrenoDisplayPacing.h: synthetic timelines of
 * layer-0 copies and frame ticks in nanoseconds, the five perf lines' worst-case length (the v8 console
 * kept 255 bytes of a line) and a parse-back of what they print. */
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayPacing.h"
#define MS 1000000ull
static unsigned pacing_checks0;
static void pacing_summary(const struct adreno_pacing *p, struct adreno_pacing_summary *s) {
    memset(s, 0xa5, sizeof *s);                       /* every field must be written */
    adreno_pacing_summarize(p, s);
    CHECK(s->ready + s->missed + s->idle == s->ticks);          /* F6 */
    uint64_t b = 0; for (int i = 0; i < 5; i++) b += s->buckets[i];
    CHECK(b == p->intervals);                                   /* F4: one interval per copy after the first */
}
/* A frame-timer world: the producer delivers swap n at times[n]; the tick completes the shown swap and copies
 * the next pending one; with nothing pending the timer stops and the next swap is copied on arrival. */
static void pacing_world(struct adreno_pacing *p, const uint64_t *arrive, unsigned n, uint64_t period, uint64_t lateness) {
    uint64_t t = arrive[0], armed = t; unsigned next = 1; int shown = 1, timer = 1;
    adreno_pacing_copy(p, t, 0, arrive[0], 0, 0);      /* the first swap finds the timer idle */
    while (next < n) {
        if (timer) {                                   /* the tick: complete the shown swap, copy a pending one */
            t = armed + period + lateness;
            int completed = shown, ready = arrive[next] <= t;
            shown = 0;
            if (ready) { adreno_pacing_copy(p, t, 1, arrive[next], 0, 0); next++; shown = 1; }
            adreno_pacing_tick(p, t, armed, period, completed, ready);
            armed = t; timer = shown;                  /* nothing pending: the timer stops */
        } else {                                       /* off tick: copied when the swap arrives */
            t = arrive[next];
            adreno_pacing_copy(p, t, 0, arrive[next], 0, 0); next++; shown = 1; armed = t; timer = 1;
        }
    }
}
static unsigned field(const char *line, const char *key, unsigned long long *v, unsigned max) {
    const char *at = strstr(line, key); if (!at) return 0;
    at += strlen(key); unsigned k = 0;
    while (k < max) { char *end; v[k++] = strtoull(at, &end, 10); if (end == at) return 0; at = end; if (*at != '/' && *at != '.') break; at++; }
    return k;
}
static void pacing_scenarios(const char *dir) {
    pacing_checks0 = checks;
    unsigned before = failures;
    struct adreno_pacing p; struct adreno_pacing_summary s;
    static uint64_t arrive[2000];
    const uint64_t period = 16 * MS + 666667;          /* a 60 Hz world; the kext's own tick is 16 ms */

    /* F4 F5 F6: steady 60 Hz, every swap ready at its tick. */
    adreno_pacing_init(&p);
    for (unsigned i = 0; i < 600; i++) arrive[i] = 1000 * MS + i * period - 2 * MS;
    pacing_world(&p, arrive, 600, period, 0);
    pacing_summary(&p, &s);
    CHECK(p.copies == 600 && p.intervals == 599 && s.buckets[0] == 599);
    CHECK(s.mean_us >= 16666 && s.mean_us <= 16667 && s.p95_ms == 17 && s.pps_x10 == 599);
    CHECK(s.ready == 599 && s.missed == 0 && s.off == 1 && s.ticks == 599 && s.idle == 0);

    /* F7: 30 Hz producer: every tick completes a frame and finds nothing; the next swap is copied off tick. */
    adreno_pacing_init(&p);
    for (unsigned i = 0; i < 300; i++) arrive[i] = 1000 * MS + i * 2 * period;
    pacing_world(&p, arrive, 300, period, 0);
    pacing_summary(&p, &s);
    CHECK(s.buckets[2] == 299 && s.buckets[0] == 0 && s.missed == 299 && s.ready == 0 && s.off == 300);
    CHECK(s.pps_x10 >= 299 && s.pps_x10 <= 300 && s.p95_ms == 34);

    /* F5: jitter across every bucket; p95 from 1 ms bins; exact mean. */
    adreno_pacing_init(&p);
    static const uint64_t gaps[5] = {16 * MS, 19 * MS, 30 * MS, 45 * MS, 75 * MS};
    uint64_t t = 1000 * MS, sum = 0;
    adreno_pacing_copy(&p, t, 1, 0, 0, 0);
    for (unsigned i = 0; i < 100; i++) { t += gaps[i % 5]; sum += gaps[i % 5]; adreno_pacing_copy(&p, t, 1, 0, 0, 0); }
    pacing_summary(&p, &s);
    for (int b = 0; b < 5; b++) CHECK(s.buckets[b] == 20);
    CHECK(s.mean_us == sum / 100 / 1000 && s.p95_ms == 76 && s.off == 0);
    /* boundaries are inclusive upper bounds */
    adreno_pacing_init(&p); t = 1000 * MS; adreno_pacing_copy(&p, t, 1, 0, 0, 0);
    static const uint64_t edge[5] = {17 * MS, 20 * MS, 34 * MS, 50 * MS, 50 * MS + 1};
    for (int i = 0; i < 5; i++) { t += edge[i]; adreno_pacing_copy(&p, t, 1, 0, 0, 0); }
    pacing_summary(&p, &s);
    for (int b = 0; b < 5; b++) CHECK(s.buckets[b] == 1);

    /* F4 F5: an idle gap of 10 s is one interval in >50, does not move p95 of 600 intervals, enters the mean. */
    adreno_pacing_init(&p); t = 1000 * MS; adreno_pacing_copy(&p, t, 1, 0, 0, 0);
    for (unsigned i = 0; i < 600; i++) { t += i == 300 ? 10000 * MS : period; adreno_pacing_copy(&p, t, 1, 0, 0, 0); }
    pacing_summary(&p, &s);
    CHECK(s.buckets[4] == 1 && s.buckets[0] == 599 && s.p95_ms == 17 && s.mean_us > 33000 && s.pps_x10 < 600);
    /* ...and a window that is mostly idle reports overflow as 101 */
    adreno_pacing_init(&p); t = 1000 * MS; adreno_pacing_copy(&p, t, 1, 0, 0, 0);
    for (unsigned i = 0; i < 10; i++) { t += 200 * MS; adreno_pacing_copy(&p, t, 1, 0, 0, 0); }
    pacing_summary(&p, &s);
    CHECK(s.p95_ms == 101 && s.buckets[4] == 10 && s.pps_x10 == 50);

    /* F4: the interval across a window edge belongs to the new window; the first copy ever has none. */
    adreno_pacing_init(&p);
    adreno_pacing_copy(&p, 1000 * MS, 1, 0, 0, 0); adreno_pacing_copy(&p, 1000 * MS + period, 1, 0, 0, 0);
    adreno_pacing_next_window(&p);
    pacing_summary(&p, &s);
    CHECK(p.copies == 0 && p.intervals == 0 && s.mean_us == 0 && s.pps_x10 == 0 && s.p95_ms == 0);   /* F5: empty */
    adreno_pacing_copy(&p, 1000 * MS + 2 * period, 1, 0, 0, 0);
    pacing_summary(&p, &s);
    CHECK(p.intervals == 1 && s.buckets[0] == 1);

    /* F8: GPU latency only after a new IB, never negative; F9 lateness; F5 queue wait. */
    adreno_pacing_init(&p); t = 1000 * MS;
    for (unsigned i = 0; i < 100; i++) {
        t += period;
        uint64_t ibs = i / 2 + 1;                       /* a new IB before every second copy, 3 ms before it */
        uint64_t ib_at = (i % 2 == 0) ? t - 3 * MS : t - 3 * MS - period;
        if (i == 50) ib_at = t + MS;                    /* stamped after the copy start on another CPU: skipped */
        adreno_pacing_copy(&p, t, 1, t - 5 * MS, ibs, ib_at);
        adreno_pacing_tick(&p, t, t - 16 * MS - 1500000, 16 * MS, 1, 1);
    }
    pacing_summary(&p, &s);
    CHECK(s.gpu_n == 49 && s.gpu_us == 3000 && s.q_us == 5000 && s.late_us == 1500);
    adreno_pacing_tick(&p, t + 10 * MS, t, 16 * MS, 0, 0);        /* early or unarmed: lateness 0, idle tick */
    adreno_pacing_tick(&p, t + 20 * MS, 0, 16 * MS, 1, 0);
    pacing_summary(&p, &s);
    CHECK(s.idle == 1 && s.missed == 1 && s.ready == 100 && s.late_us == 1500 * 100 / 101);

    /* F2 F3: every line within 250 bytes at the caps; the pace line parses back. */
    char line[512]; int n;
    struct adreno_pacing_summary big; memset(&big, 0xff, sizeof big);
    n = adreno_perf_line_pace(line, sizeof line, ~0ull, &big);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX && (size_t)n == strlen(line));
    CHECK(strstr(line, "s=999999999 ") && !strstr(line, "18446744073709551615"));
    uint64_t v[ADRENO_PERF_MAP_FIELDS]; memset(v, 0xff, sizeof v);
    n = adreno_perf_line_map(line, sizeof line, ~0ull, v);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    uint64_t head[ADRENO_PERF_HEAD_FIELDS]; memset(head, 0xff, sizeof head);
    n = adreno_perf_line_head(line, sizeof line, "periodic", ~0ull, head);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX && strstr(line, "AdrenoDisplay: perf why=periodic s=999999999 presents="));
    uint64_t split[ADRENO_PERF_SPLIT_FIELDS]; memset(split, 0xff, sizeof split);
    n = adreno_perf_line_split(line, sizeof line, ~0ull, split);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    uint64_t conv[5]; memset(conv, 0xff, sizeof conv);
    n = adreno_perf_line_src(line, sizeof line, ~0ull, 0xffffffffu, ~0ull, 1, 1, conv, ~0ull, -2147483647 - 1);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    n = adreno_perf_line_head(line, 8, "periodic", 1, head);               /* a short buffer truncates, never overruns */
    CHECK(n > 0 && strlen(line) == 7);
    /* Pacing work 2026-10-21, P1 P7: the perf gpu line within 250 bytes at every cap, and it parses back. */
    uint64_t gv[ADRENO_PERF_GPU_FIELDS]; memset(gv, 0xff, sizeof gv);
    n = adreno_perf_line_gpu(line, sizeof line, ~0ull, gv);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX && (size_t)n == strlen(line) && !strstr(line, "18446744073709551615"));
    for (unsigned i = 0; i < ADRENO_PERF_GPU_FIELDS; i++) gv[i] = 100 + i;
    n = adreno_perf_line_gpu(line, sizeof line, 57, gv);
    {
        unsigned long long g[4];
        CHECK(!strncmp(line, "AdrenoDisplay: perf gpu s=57 ", 29));
        CHECK(field(line, " gtk=", g, 2) == 2 && g[0] == 100 + ADRENO_GPU_IB_TICKS && g[1] == 100 + ADRENO_GPU_IB_TICKS_MAX);
        CHECK(field(line, " sub_us=", g, 2) == 2 && g[0] == 100 + ADRENO_GPU_SUBMIT_TICKS && g[1] == 100 + ADRENO_GPU_LOCK_TICKS);
        CHECK(field(line, " prep=", g, 2) == 2 && g[0] == 100 + ADRENO_GPU_PREPARES && g[1] == 100 + ADRENO_GPU_PREPARE_TICKS);
        CHECK(field(line, " unw=", g, 2) == 2 && g[0] == 100 + ADRENO_GPU_UNWIRES && g[1] == 100 + ADRENO_GPU_UNWIRE_TICKS);
        CHECK(field(line, " cache=", g, 3) == 3 && g[0] == 100 + ADRENO_GPU_CACHE_CALLS && g[2] == 100 + ADRENO_GPU_CACHE_TICKS);
        CHECK(field(line, " res=", g, 4) == 4 && g[0] == 100 + ADRENO_GPU_RES_RETAINED && g[3] == 100 + ADRENO_GPU_RES_REFUSED);
        CHECK(field(line, " mib=", g, 2) == 2 && g[0] == 100 + ADRENO_GPU_RES_BYTES && g[1] == 100 + ADRENO_GPU_RES_BUDGET);
    }
    printf("%s\n", line);
    /* parse back the 60 Hz window */
    adreno_pacing_init(&p);
    for (unsigned i = 0; i < 600; i++) arrive[i] = 1000 * MS + i * period - 2 * MS;
    pacing_world(&p, arrive, 600, period, 0);
    pacing_summary(&p, &s);
    n = adreno_perf_line_pace(line, sizeof line, 57, &s);
    unsigned long long f[6];
    CHECK(!strncmp(line, "AdrenoDisplay: perf pace s=57 ", 30));
    CHECK(field(line, " pps=", f, 2) == 2 && f[0] == 59 && f[1] == 9);
    CHECK(field(line, " pp=", f, 5) == 5 && f[0] == 599 && f[1] == 0 && f[4] == 0);
    CHECK(field(line, " tk=", f, 4) == 4 && f[0] == 599 && f[1] == 599 && f[2] == 0 && f[3] == 0);
    CHECK(field(line, " p95=", f, 1) == 1 && f[0] == 17);
    printf("%s\n", line);
    v[0] = 3; for (unsigned i = 1; i < ADRENO_PERF_MAP_FIELDS; i++) v[i] = i * 10;
    n = adreno_perf_line_map(line, sizeof line, 57, v);
    CHECK(!strncmp(line, "AdrenoDisplay: perf map s=57 ", 29));
    printf("%s\n", line);

    char path[4096]; snprintf(path, sizeof path, "%s/pacing.json", dir);
    FILE *jf = fopen(path, "w"); assert(jf);
    fprintf(jf, "{\"checks\":%u,\"failures\":%u}\n", checks - pacing_checks0, failures - before);
    fclose(jf);
    printf("{\"pacing_checks\":%u,\"pacing_failures\":%u}\n", checks - pacing_checks0, failures - before);
}

/* ---------------------------------------------------------------- phase-locked tick (--present-vsync60, S1-S11)
 * FAILURES-AND-DESIGN-VSYNC.md, written before the code. A model of the frame path and of 26A428's thread-call
 * timer (1.2): a timer armed at `armed` for x fires at x + slop, slop = min((x - armed) >> 3, cap); with
 * kIOTimeOptionsWithLeeway the slop is max(leeway, slop); a share of fires are serviced early, between x and
 * x + slop; plus scheduling noise. The work loop is busy during a copy and during stalls, so a tick never runs
 * inside a copy (S3). The producer has the next swap ready `render` after each copy (CoreAnimation renders ahead).
 * Two policies: VREL, the v9 code (setTimeoutMS(16) relative to the arm), and VGRID, AdrenoDisplayPacing.h's grid.
 * Rate and drift are COST checks the relative policy must fail. Times are ns unless a scenario says ticks. */
enum { VREL, VGRID };
struct ktimer { unsigned shift; uint64_t cap, leeway, noise; int leeway_opt; unsigned early_pct; };
struct vworld {
    int policy; struct ktimer k; struct adreno_vsync v; struct adreno_pacing p;
    uint64_t rng, now, busy_until, copy_ns, render_min, render_max, rel_period;
    uint64_t stall_at, stall_ns, idle_at, idle_ns, slow_at, slow_ns, long_copy_at, long_copy_ns, long_copy_until, reset_at,
             watch_from;
    uint64_t (*to_ns)(uint64_t);
    int current, armed, idle_done, slow_done, reset_done;
    uint64_t ready_at, ready_queued, fire_at, armed_at, armed_for;
    /* results */
    uint64_t copies, fires, last_fire, min_gap, grid0, off_grid, resume_copy, resume_target, late_copy, short_shown;
};
static uint64_t vrnd(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }
static uint64_t ns_identity(uint64_t t) { return t; }
static uint64_t ns_24mhz(uint64_t t) { return t / 3 * 125 + t % 3 * 125 / 3; }      /* 24 MHz ticks, no overflow */
static uint64_t kfire(struct vworld *w, uint64_t armed, uint64_t x) {
    uint64_t slop = x > armed ? (x - armed) >> w->k.shift : 0;
    if (slop > w->k.cap) slop = w->k.cap;
    if (w->k.leeway_opt && w->k.leeway > slop) slop = w->k.leeway;
    uint64_t fire = x + slop;
    if (w->k.early_pct && slop && vrnd(&w->rng) % 100 < w->k.early_pct) fire = x + vrnd(&w->rng) % slop;
    if (w->k.noise) fire += vrnd(&w->rng) % w->k.noise;
    return fire < armed ? armed : fire;
}
static void w_arm(struct vworld *w, int in_tick) {          /* armFrameTimerGated */
    if (w->armed || (!w->current && !w->ready_queued)) return;
    uint64_t x;
    if (w->policy == VREL) { x = w->now + w->rel_period; w->armed_for = 0; }
    else { w->armed_for = adreno_vsync_target(&w->v, w->now, in_tick); x = adreno_vsync_arm_time(&w->v, w->now, w->armed_for); }
    w->armed = 1; w->armed_at = w->now; w->fire_at = kfire(w, w->now, x);
    if (w->policy == VGRID && w->grid0 && w->armed_for != UINT64_MAX &&
        w->armed_for > w->grid0 && (w->armed_for - w->grid0) % w->v.period) w->off_grid++;
}
static void w_copy(struct vworld *w, int in_tick) {         /* swap_begin_gated: dequeue, arm, copy */
    w->current = 1;
    uint64_t queued = w->ready_queued;
    w->ready_queued = 0;
    w_arm(w, in_tick);
    w->copies++;
    adreno_pacing_copy(&w->p, w->to_ns(w->now), in_tick, w->to_ns(queued), 0, 0);
    if (w->slow_done == 2) { w->short_shown = w->now - w->late_copy; w->slow_done = 3; }    /* how long the late frame showed */
    if (w->slow_done == 1 && !in_tick) { w->late_copy = w->now; w->slow_done = 2; }        /* the late frame, off tick */
    uint64_t c = w->copy_ns;
    if (w->long_copy_at && w->now >= w->long_copy_at && w->now < w->long_copy_until) c = w->long_copy_ns;
    w->busy_until = w->now + c;
    /* the producer has the next swap ready `render` after this one is shown */
    uint64_t r = w->render_min + vrnd(&w->rng) % (w->render_max - w->render_min + 1);
    if (w->slow_at && !w->slow_done && w->now >= w->slow_at) { r = w->slow_ns; w->slow_done = 1; }
    w->ready_at = w->now + r;
    if (w->idle_at && !w->idle_done && w->ready_at >= w->idle_at) { w->ready_at += w->idle_ns; w->idle_done = 1; w->resume_copy = w->ready_at; }
}
static void w_run(struct vworld *w, uint64_t start, unsigned copies) {
    w->now = start; w->ready_at = start; w->min_gap = UINT64_MAX;
    while (w->copies < copies) {
        uint64_t t_tick = w->armed ? w->fire_at : UINT64_MAX, t_swap = UINT64_MAX;
        if (w->ready_at && !w->ready_queued) t_swap = w->ready_at;           /* the swap reaches the queue */
        uint64_t t = t_tick < t_swap ? t_tick : t_swap;
        if (t == UINT64_MAX) { CHECK(!"the world stopped with copies left"); return; }
        if (t < w->busy_until) t = w->busy_until;                              /* the work loop is busy (S3) */
        if (w->stall_at && t >= w->stall_at && t < w->stall_at + w->stall_ns) t = w->stall_at + w->stall_ns;
        if (t < w->now) t = w->now;
        w->now = t;
        if (w->reset_at && !w->reset_done && t >= w->reset_at && w->policy == VGRID) {   /* teardown + restart (S4) */
            adreno_vsync_reset(&w->v); w->reset_done = 1;
        }
        if (t_tick < t_swap) {                                                 /* vsyncGated */
            w->armed = 0; w->fires++;
            uint64_t grid = w->policy == VGRID ? adreno_vsync_fired(&w->v, t) : 0;
            if (w->policy == VGRID && !w->grid0 && grid) w->grid0 = grid;
            if (w->watch_from && w->last_fire >= w->watch_from && t - w->last_fire < w->min_gap) w->min_gap = t - w->last_fire;
            w->last_fire = t;
            int completed = w->current; w->current = 0;
            uint64_t before = w->copies;
            if (w->ready_queued) w_copy(w, 1); else w_arm(w, 1);
            uint64_t period = w->policy == VGRID ? w->v.period : w->rel_period;
            uint64_t armed = w->policy == VGRID ? (grid ? grid - w->v.period : 0) : w->armed_at;
            adreno_pacing_tick(&w->p, w->to_ns(t), armed ? w->to_ns(armed) : 0, w->to_ns(period), completed, w->copies != before);
        } else {                                                               /* the family's swap_submit */
            w->ready_queued = w->ready_at; w->ready_at = 0;
            if (!w->current) {
                if (w->resume_copy && w->resume_copy <= t && !w->resume_target) { w_copy(w, 0); w->resume_target = w->armed_for; w->resume_copy = t; }
                else w_copy(w, 0);
            }
        }
    }
}
static void vworld_init(struct vworld *w, int policy, uint64_t seed) {
    memset(w, 0, sizeof *w);
    w->policy = policy; w->rng = seed * 0x9e3779b97f4a7c15ull | 1; w->to_ns = ns_identity;
    w->k = (struct ktimer){3, 1000000, 0, 300000, 0, 0};
    w->copy_ns = 2700000; w->render_min = 3000000; w->render_max = 12000000; w->rel_period = 16000000;
    adreno_pacing_init(&w->p);
    adreno_vsync_init(&w->v, 16666667, 1000000, 4 * 16666667ull);
}
struct vres { struct adreno_pacing_summary s; struct adreno_vsync_summary v; };
static struct vres vsummary(struct vworld *w) {
    struct vres r; adreno_pacing_summarize(&w->p, &r.s); adreno_vsync_summarize(&w->v, w->to_ns, &r.v); return r;
}
static void vsync_scenarios(const char *dir) {
    unsigned c0 = checks, f0 = failures, cc0 = cost_checks, cf0 = cost_failures;
    const uint64_t P = 16666667;
    struct vworld w; struct vres r;
    char path[4096]; snprintf(path, sizeof path, "%s/vsync.json", dir);
    FILE *jf = fopen(path, "w"); assert(jf);
    fprintf(jf, "{\"scenarios\":{");
#define VREPORT(name) fprintf(jf, "%s\"%s\":{\"pps_x10\":%llu,\"mean_us\":%llu,\"p95_ms\":%llu,\"le17\":%llu,\"le20\":%llu,\"ticks\":%llu,\"ready\":%llu,\"missed\":%llu,\"late_us\":%llu,\"grid_late_us\":%llu,\"grid_late_max_us\":%llu,\"early\":%llu,\"skip\":%llu,\"rs_first\":%llu,\"rs_idle\":%llu,\"lead_us\":%llu}", \
        first++ ? "," : "", name, (unsigned long long)r.s.pps_x10, (unsigned long long)r.s.mean_us, (unsigned long long)r.s.p95_ms, \
        (unsigned long long)r.s.buckets[0], (unsigned long long)r.s.buckets[1], (unsigned long long)r.s.ticks, (unsigned long long)r.s.ready, \
        (unsigned long long)r.s.missed, (unsigned long long)r.s.late_us, (unsigned long long)r.v.late_us, (unsigned long long)r.v.late_max_us, \
        (unsigned long long)r.v.early, (unsigned long long)r.v.skipped, (unsigned long long)r.v.resync_first, (unsigned long long)r.v.resync_idle, \
        (unsigned long long)r.v.lead_us)
    int first = 0;

    /* Steady producer (render 3-12 ms < P), copy 2.7 ms: the v9 shape. Both policies are reported; the rate checks
     * (COST) apply to the policy under test: the grid, or with -DVSYNC_RELATIVE the v9 timer, which must fail them. */
#ifdef VSYNC_RELATIVE
    const int under_test = VREL;
#else
    const int under_test = VGRID;
#endif
    for (int policy = VREL; policy <= VGRID; policy++) {
        vworld_init(&w, policy, 1);
        w_run(&w, 1000 * MS, 3000);
        r = vsummary(&w);
        VREPORT(policy == VREL ? "steady_relative_v9" : "steady_grid");
        CHECK(r.s.ready + r.s.missed + r.s.idle == r.s.ticks && r.s.missed == 0);
        /* the rate fix: exactly 60 Hz on average, every interval within a jitter of the grid */
        if (policy == under_test) {
            COST(r.s.pps_x10 >= 599 && r.s.pps_x10 <= 601);
            COST(r.s.buckets[0] * 100 >= w.p.intervals * 97);
        }
        if (policy == VGRID) {
            CHECK(r.v.resync_first == 1 && r.v.resync_idle == 0 && r.v.skipped == 0 && w.off_grid == 0);
            CHECK(r.v.late_us <= 300 && r.v.lead_us >= 990);             /* S6: the early arm absorbs the 1 ms slop */
            CHECK(r.s.late_us == r.v.late_us);                          /* S8: pace late is on the grid */
        } else {
            CHECK(r.s.mean_us >= 16900);                                 /* v9: 16 ms + the slop, never recovered */
        }
    }
    /* S6: no early arm: still exactly 60 Hz, a millisecond later; an explicit leeway changes nothing below the slop
     * and makes ticks later above it. */
    {   uint64_t late[3];
        for (int c = 0; c < 3; c++) {
            vworld_init(&w, VGRID, 2);
            w.v.lead_max = 0;
            if (c) { w.k.leeway_opt = 1; w.k.leeway = c == 1 ? 200000 : 2500000; }
            w_run(&w, 1000 * MS, 2000);
            r = vsummary(&w);
            VREPORT(c == 0 ? "grid_no_lead" : c == 1 ? "grid_no_lead_leeway_200us" : "grid_no_lead_leeway_2500us");
            CHECK(r.s.pps_x10 >= 599 && r.s.pps_x10 <= 601);
            late[c] = r.v.late_us;
        }
        CHECK(late[0] >= 1000 && late[0] <= 1300 && late[1] == late[0] && late[2] >= 2500);
    }
    /* S1 S3: a 200 ms stall of the work loop, and copies of 25 ms: one late tick, skipped grid points, never a
     * burst (no two fires within P/4), the phase kept. */
    for (int c = 0; c < 2; c++) {
        vworld_init(&w, VGRID, 3);
        w.watch_from = 3000 * MS;
        if (c == 0) { w.stall_at = 3000 * MS; w.stall_ns = 200 * MS; }
        else { w.long_copy_at = 3000 * MS; w.long_copy_until = 3200 * MS; w.long_copy_ns = 25 * MS; }
        w_run(&w, 1000 * MS, 600);
        r = vsummary(&w);
        VREPORT(c == 0 ? "stall_200ms" : "copies_25ms");
        CHECK(r.v.skipped >= (c == 0 ? 11u : 1u) && w.off_grid == 0);
        CHECK(w.min_gap >= P / 5);                                       /* never a burst */
        CHECK(r.v.resync_idle == 0 && r.v.resync_first == 1);
    }
    /* S2: a 1 s idle re-syncs to now + P once; a single slow frame (P + 3 ms) keeps the grid and still shows for at
     * least P/2; the average rate of a window with one slow frame stays at 60. */
    vworld_init(&w, VGRID, 4);
    w.idle_at = 3000 * MS; w.idle_ns = 1000 * MS;
    w_run(&w, 1000 * MS, 600);
    r = vsummary(&w);
    VREPORT("idle_1s");
    CHECK(r.v.resync_idle == 1 && w.resume_copy && w.resume_target == w.resume_copy + P);
    vworld_init(&w, VGRID, 5);
    w.slow_at = 3000 * MS; w.slow_ns = P + 3 * MS;
    w_run(&w, 1000 * MS, 600);
    r = vsummary(&w);
    VREPORT("one_slow_frame");
    CHECK(r.v.resync_idle == 0 && w.off_grid == 0 && r.s.missed == 1 && r.s.off == 2 && w.slow_done == 3);
    CHECK(w.short_shown >= P / 2 && w.short_shown <= P);
    /* S4: teardown and restart mid-run: the grid is forgotten, the next arm starts a new one. */
    vworld_init(&w, VGRID, 6);
    w.reset_at = 3000 * MS;
    w_run(&w, 1000 * MS, 600);
    r = vsummary(&w);
    VREPORT("reset");
    CHECK(r.v.resync_first == 2 && r.v.unarmed == 1 && r.s.pps_x10 >= 597);
    /* S7: a third of the fires serviced early (between the armed time and the grid point): counted, no drift. */
    vworld_init(&w, VGRID, 7);
    w.k.early_pct = 33;
    w_run(&w, 1000 * MS, 2000);
    r = vsummary(&w);
    VREPORT("early_fires");
    CHECK(r.v.early > 100 && w.off_grid == 0 && r.s.pps_x10 >= 599 && r.s.pps_x10 <= 601);
    /* S5 S10: clocks near 2^63 and a 24 MHz timebase (P = 400,000 ticks = 16,666,666.67 ns). */
    vworld_init(&w, VGRID, 8);
    w_run(&w, (1ull << 63) - 1000 * MS, 1200);
    r = vsummary(&w);
    VREPORT("clock_2e63");
    CHECK(r.s.pps_x10 >= 599 && r.s.pps_x10 <= 601 && w.off_grid == 0);
    vworld_init(&w, VGRID, 9);
    w.to_ns = ns_24mhz;
    w.k = (struct ktimer){3, 24000, 0, 7200, 0, 0};
    w.copy_ns = 64800; w.render_min = 72000; w.render_max = 288000; w.rel_period = 384000;
    adreno_vsync_init(&w.v, 400000, 24000, 4 * 400000ull);
    w_run(&w, 24000000ull * 3600 * 24 * 365 * 100, 2000);                /* a century of uptime in ticks */
    r = vsummary(&w);
    VREPORT("timebase_24mhz");
    CHECK(r.s.pps_x10 >= 599 && r.s.pps_x10 <= 601 && w.off_grid == 0 && r.v.period_ns == 16666666);
    {   struct adreno_vsync v; adreno_vsync_init(&v, P, 1000000, 4 * P);   /* saturation, never a wrap */
        uint64_t now = UINT64_MAX - P / 2, t = adreno_vsync_target(&v, now, 0);
        CHECK(t >= now && adreno_vsync_arm_time(&v, now, t) >= now);
        v.last = UINT64_MAX - 3 * P; t = adreno_vsync_target(&v, UINT64_MAX - P, 1);
        CHECK(t >= UINT64_MAX - P);
        /* S1: a tick 10 minutes late skips by division: one target, 36,000 points skipped */
        adreno_vsync_init(&v, P, 1000000, 4 * P);
        v.last = 1000 * MS; t = adreno_vsync_target(&v, 1000 * MS + 600000 * MS, 1);
        CHECK(t > 1000 * MS + 600000 * MS && t <= 1000 * MS + 600000 * MS + P + P / 4 && (t - 1000 * MS) % P == 0 &&
              v.skipped >= 35999 && v.skipped <= 36001);
        /* S4: a failed wakeAtTime leaves nothing armed; a later fire without a deadline is unarmed, the grid kept */
        adreno_vsync_arm_failed(&v);
        uint64_t last = v.last;
        CHECK(!v.deadline && v.arm_failed == 1 && adreno_vsync_fired(&v, 2000 * MS) == 0 && v.unarmed == 1 && v.last == last);
        /* S11-style: the arm time is never in the past, and equals the target without a lead cap */
        v.lead_max = 0; CHECK(adreno_vsync_arm_time(&v, 5, 5 + P) == 5 + P && adreno_vsync_arm_time(&v, 9, 3) == 9);
    }
    /* S8: the vsync line within 250 bytes at the caps; and it parses back. */
    {   char line[512]; struct adreno_vsync_summary big; memset(&big, 0xff, sizeof big);
        int n = adreno_perf_line_vsync(line, sizeof line, ~0ull, &big);
        CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
        vworld_init(&w, VGRID, 1); w_run(&w, 1000 * MS, 600); r = vsummary(&w);
        n = adreno_perf_line_vsync(line, sizeof line, 7, &r.v);
        static const char head[] = "AdrenoDisplay: perf vsync s=7 period_ns=16666667 grid=";
        CHECK(!strncmp(line, head, sizeof head - 1) && strstr(line, " rs=1/0 ") && strstr(line, " skip=0 "));
        printf("%s\n", line);
    }
    fprintf(jf, "},\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", checks - c0, failures - f0,
            cost_checks - cc0, cost_failures - cf0);
    fclose(jf);
    printf("{\"vsync_checks\":%u,\"vsync_failures\":%u,\"vsync_cost_checks\":%u,\"vsync_cost_failures\":%u}\n", checks - c0,
           failures - f0, cost_checks - cc0, cost_failures - cf0);
}
#if ADRENO_BEAM
/* ---------------------------------------------------------------- --present-beam (agents/tear-free FAILURE-MODES.md) */
#include "replay-adreno-beam.c"
/* ---------------------------------------------------------------- latency (agents/input-latency FAILURE-MODES.md) */
#include "replay-adreno-latency.c"
#endif
#endif

int main(int argc,char **argv) {
    if(argc!=2)return 64;
    publication_replay(argv[1]);
    char path[4096];snprintf(path,sizeof path,"%s/presentation.json",argv[1]);FILE *f=fopen(path,"w");assert(f);
    fprintf(f,"{\"status\":\"PASS\",\"variant\":\"%s\",\"width\":%d,\"height\":%d,\"row_bytes\":%d,\"stationary_publications\":%u,\"cursor_absent_publications\":%u,\"max_cursor_only_bytes\":%llu,\"full_frame_bytes\":%u,\"physical_scanout_tested\":false}\n",VARIANT,W,H,ROW,stationaryPublications,absent,(unsigned long long)maxCursorBytes,W*H*4);fclose(f);
    puts("PASS publication");
    damage_scenarios(argv[1]);
#ifndef ADRENO_DISPLAY_BASE
    pacing_scenarios(argv[1]);
    vsync_scenarios(argv[1]);
#if ADRENO_BEAM
    beam_scenarios(argv[1]);
    latency_scenarios(argv[1]);
#if ADRENO_PRESENT_SYNC
    presentsync_scenarios(argv[1]);
#if ADRENO_PIPELINE
    pipeline_scenarios(argv[1]);
#endif
#if ADRENO_PRESENT_RELATCH
    relatch_scenarios(argv[1]);
#if ADRENO_PRESENT_EARLY_DONE
    early_done_scenarios(argv[1]);
#endif
#endif
#endif
#endif
#endif
    return failures ? 1 : cost_failures ? 3 : 0;
}
