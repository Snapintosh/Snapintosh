/* SPDX-License-Identifier: MIT
 * compat/edp-backlight.{h,c} against a model of the eDP controller's AUX FIFO and a DPCD panel; no hardware.
 *
 *   clang -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=all \
 *     -Icompat tools/test-edp-backlight.c compat/edp-backlight.c -o build/test-edp-backlight
 *
 * The model is written from the same facts as the engine (Linux dp_aux.c's FIFO sequence, drm_dp.h's DPCD layout)
 * but checks them independently: every MMIO access against its own list of the controller registers the backlight
 * may touch, every DPCD write against {0x721, 0x722, 0x723}, every INTR_STATUS write for kept mask bits and
 * AUX-only acks, and the PHY clear sequence before every GO. tools/test-edp-backlight.py also compiles weakened
 * copies of the engine that this program must reject. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "edp-backlight.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define HZ UINT64_C(19200000)

/* The model's own register list (not the header's allow-list). */
#define M_DISPCC 0x0AF00000u
#define M_AHB 0x0AF6C000u
#define M_AUX 0x0AF6C200u
enum { R_AHB_CBCR, R_GDSCR, R_AUX_CBCR, R_INTR, R_AUX_CTRL, R_AUX_DATA, R_TRANS, R_PHY_STATUS, R_PHY_CLEAR, R_N };
static const uint32_t reg_pa[R_N] = {M_DISPCC + 0x80B0, M_DISPCC + 0x9000, M_DISPCC + 0x80A8, M_AHB + 0x20,
                                     M_AUX + 0x30, M_AUX + 0x34, M_AUX + 0x38, M_AUX + 0xBC, M_AUX + 0x4C};
static const int reg_readable[R_N] = {1, 1, 1, 1, 1, 1, 1, 1, 0};
static const int reg_writable[R_N] = {0, 0, 0, 1, 0, 1, 1, 0, 1};
#define ST_DONE (1u << 3)
#define ST_NACK (1u << 12)
#define AUX_STATUSES 0x08249248u   /* bits 3, 6, 9, 12, 15, 18, 21, 27 */

struct model {
    uint32_t reg[R_N];
    uint32_t status, mask;          /* INTR_STATUS: statuses and mask bits, kept apart */
    uint8_t fifo[32];
    uint32_t widx, ridx, reads_left;
    int read_mode;
    uint8_t reply[20];
    uint32_t reply_len;
    unsigned phy_step;              /* 0 -> 0x1f -> 0x9f -> 0 seen since the last GO */
    int trans_zeroed;
    uint8_t dpcd[0x800];
    int silent;                     /* the sink never answers: no status at all */
    int nack;                       /* answer the next n transactions with NACK */
    int ignore_level;               /* the panel drops writes to 0x722/0x723 */
    int ignore_mode;                /* ... and to 0x721 */
    uint64_t now;
    unsigned violations, gos, dpcd_writes, mmio_reads, mmio_writes, dp_reads;
    uint32_t last_write_addr, last_write_len;
    uint8_t last_write[16];
};
static struct model M;
static struct edp_backlight_state S;

static int reg_of(uint64_t pa)
{
    for (int i = 0; i < R_N; i++) if (pa == reg_pa[i]) return i;
    return -1;
}
static void violation(const char *what, uint64_t pa)
{
    fprintf(stderr, "violation: %s %#llx\n", what, (unsigned long long)pa);
    M.violations++;
}

static void transaction(void)
{
    M.gos++;
    if (!M.trans_zeroed || M.phy_step != 3) violation("GO without TRANS_CTRL=0 and the PHY clear sequence", 0);
    if (M.status & AUX_STATUSES) violation("GO with an unacknowledged AUX status", M.status);
    M.trans_zeroed = 0;
    M.phy_step = 0;
    if (M.widx < 4) { violation("GO with a short header", M.widx); return; }
    uint32_t addr = (uint32_t)(M.fifo[0] & 0x0f) << 16 | (uint32_t)M.fifo[1] << 8 | M.fifo[2], len = M.fifo[3] + 1u;
    int read = M.fifo[0] & 0x10;
    if (M.silent) return;
    if (M.nack) { M.nack--; M.status |= ST_NACK | ST_DONE; return; }
    if (addr + len > sizeof M.dpcd) { violation("DPCD beyond the model", addr); return; }
    if (read) {
        if (M.widx != 4) violation("read with data bytes", M.widx);
        M.reply[0] = 0;   /* ACK */
        memcpy(M.reply + 1, M.dpcd + addr, len);
        M.reply_len = len + 1;
    } else {
        if (M.widx != 4 + len) violation("write length differs from the header", M.widx);
        M.dpcd_writes++;
        M.last_write_addr = addr;
        M.last_write_len = len;
        memcpy(M.last_write, M.fifo + 4, len);
        for (uint32_t i = 0; i < len; i++) {
            uint32_t a = addr + i;
            if (a != 0x721 && a != 0x722 && a != 0x723) violation("DPCD write outside 0x721..0x723", a);
            if ((a == 0x722 || a == 0x723) && M.ignore_level) continue;
            if (a == 0x721 && M.ignore_mode) continue;
            M.dpcd[a] = M.fifo[4 + i];
        }
    }
    M.status |= ST_DONE;
}

static int read32(void *ctx, uint64_t pa, uint32_t *v)
{
    (void)ctx;
    int r = reg_of(pa);
    M.mmio_reads++;
    if (r < 0 || !reg_readable[r]) { violation("read outside the backlight registers", pa); return -1; }
    if (r > R_AUX_CBCR) M.dp_reads++;
    switch (r) {
    case R_INTR: *v = M.status | M.mask; break;
    case R_AUX_DATA:
        if (!M.read_mode || M.ridx >= M.reply_len) { violation("FIFO read past the reply", pa); *v = 0; break; }
        /* the reply command first, then data byte i with index i (dp_aux.c cmd_fifo_rx) */
        *v = (uint32_t)M.reply[M.ridx] << 8 | (M.ridx ? (M.ridx - 1) << 16 : 0);
        M.ridx++;
        break;
    default: *v = M.reg[r];
    }
    return 0;
}

static int write32(void *ctx, uint64_t pa, uint32_t v)
{
    (void)ctx;
    int r = reg_of(pa);
    M.mmio_writes++;
    if (r < 0 || !reg_writable[r]) { violation("write outside the backlight registers", pa); return -1; }
    switch (r) {
    case R_INTR: {
        uint32_t ack = (v >> 1) & EDP_INTR_STATUS_BITS, mask = v & (EDP_INTR_STATUS_BITS << 2);
        if (ack & ~AUX_STATUSES) violation("ack of a non-AUX status", v);
        if (mask != M.mask) violation("INTR_STATUS mask bits changed", v);
        if (v & ~(EDP_INTR_STATUS_BITS << 1 | EDP_INTR_STATUS_BITS << 2)) violation("status bits written", v);
        M.status &= ~ack;
        break;
    }
    case R_AUX_DATA:
        if (v & EDP_AUX_DATA_INDEX_WRITE) {
            M.read_mode = v & EDP_AUX_DATA_READ;
            M.widx = M.ridx = 0;
            if (M.read_mode) break;
        } else if (M.read_mode) { violation("FIFO byte written in read mode", v); break; }
        if (M.widx >= sizeof M.fifo) { violation("FIFO overflow", v); break; }
        if (v & ~0x0000ff00u & ~EDP_AUX_DATA_INDEX_WRITE) violation("FIFO word with stray bits", v);
        M.fifo[M.widx++] = (uint8_t)(v >> 8);
        break;
    case R_TRANS:
        M.reg[R_TRANS] = v;
        if (v == 0) { M.trans_zeroed = 1; M.phy_step = 0; }
        else if (v == EDP_AUX_TRANS_GO) transaction();
        else if (v & EDP_AUX_TRANS_GO) violation("GO with I2C or other bits", v);
        break;
    case R_PHY_CLEAR:
        if ((M.phy_step == 0 && v == 0x1f) || (M.phy_step == 1 && v == 0x9f) || (M.phy_step == 2 && v == 0)) M.phy_step++;
        else violation("PHY clear out of sequence", v);
        break;
    }
    return 0;
}
static uint64_t counter(void *ctx) { (void)ctx; return M.now += 1000; }
static const struct edp_backlight_io IO = {0, read32, write32, counter, HZ};

/* A healthy A16-like panel: display control capable, AUX-settable 11-bit brightness, DPCD mode, level 768. */
static void reset(void)
{
    memset(&M, 0, sizeof M);
    memset(&S, 0, sizeof S);
    M.reg[R_AHB_CBCR] = 0x1;            /* CLK_OFF clear */
    M.reg[R_GDSCR] = 0x80000000u;       /* PWR_ON */
    M.reg[R_AUX_CBCR] = 0x1;
    M.reg[R_AUX_CTRL] = 0x1;            /* enabled by the firmware */
    M.mask = 0x00000004u | 0x00000020u; /* HPD and AUX-done interrupts unmasked by the firmware */
    M.dpcd[0x00D] = 0x0B;
    M.dpcd[0x700] = 0x03; M.dpcd[0x701] = 0x07; M.dpcd[0x702] = 0x06; M.dpcd[0x703] = 0x00;
    M.dpcd[0x721] = 0x12;               /* DPCD mode, dynamic backlight bit kept */
    M.dpcd[0x722] = 0x03; M.dpcd[0x723] = 0x00;
    M.dpcd[0x724] = 11; M.dpcd[0x725] = 11; M.dpcd[0x726] = 11;
}
static int64_t call(uint64_t op, uint64_t arg, uint64_t flags, uint64_t out[4])
{
    uint64_t r[4] = {0x0001000C, op, arg, flags};
    CHECK(edp_backlight_call(&S, &IO, r) == 0);
    memcpy(out, r, sizeof r);
    return (int64_t)r[0];
}
static uint32_t level_of(const uint64_t r[4]) { return (uint32_t)r[3]; }
static uint32_t state_of(const uint64_t r[4]) { return edp_bl_reply_state(r[1]); }
static uint32_t panel_level(void) { return (uint32_t)M.dpcd[0x722] << 8 | M.dpcd[0x723]; }

/* The kext's nits -> level curve (luminance proportional to level, the top level = max_nits), on the A16's 11-bit
 * panel with the default 5..500 nits: the bottom of CoreBrightness's range is the floor, the top is the panel's
 * maximum, and everything between is proportional, so the slider's lower half is genuinely dim. */
#define Q(n) ((uint64_t)(n) << 16)
static void test_curve(void)
{
    const uint32_t max = 2047, floor = edp_bl_floor_level(max), maxn = EDP_BL_NITS_MAX_DEFAULT;
    CHECK(floor == 41 && maxn == 500);
    uint32_t prev = 0;
    for (uint64_t q = 0; q <= Q(600); q += 1u << 12) {          /* monotonic, inside [floor, max] */
        uint32_t l = edp_bl_nits_to_level(q, maxn, floor, max);
        CHECK(l >= floor && l <= max && l >= prev);
        prev = l;
    }
    CHECK(edp_bl_nits_to_level(0, maxn, floor, max) == floor);
    CHECK(edp_bl_nits_to_level(Q(5), maxn, floor, max) == floor);       /* Windows' minimum is below the floor */
    CHECK(edp_bl_nits_to_level(Q(10), maxn, floor, max) == floor);      /* the table's low offset is the floor */
    CHECK(edp_bl_nits_to_level(Q(11), maxn, floor, max) == 45);
    CHECK(edp_bl_nits_to_level(Q(250), maxn, floor, max) == 1024);      /* half the luminance, half the levels */
    CHECK(edp_bl_nits_to_level(Q(140), maxn, floor, max) == 573);       /* CoreBrightness's default, 28% */
    CHECK(edp_bl_nits_to_level(Q(500), maxn, floor, max) == max);
    CHECK(edp_bl_nits_to_level(Q(500) - 1, maxn, floor, max) == max);
    CHECK(edp_bl_nits_to_level(Q(1000), maxn, floor, max) == max);
    CHECK(edp_bl_nits_to_level(UINT64_MAX, maxn, floor, max) == max);
    CHECK(edp_bl_nits_to_level(Q(100), 0, floor, max) == floor);        /* degenerate: the floor */
    CHECK(edp_bl_nits_to_level(Q(100), maxn, max, max) == max && edp_bl_nits_to_level(Q(100), maxn, 9, 9) == 9);
    /* The configured top moves the scale: with 400 nits as full scale, 200 nits is half. */
    CHECK(edp_bl_nits_to_level(Q(200), 400, floor, max) == 1024 && edp_bl_nits_to_level(Q(400), 400, floor, max) == max);
    /* Level -> nits is the same line; every level from the floor up survives the round trip. */
    CHECK(edp_bl_level_to_nits(0, maxn, max) == 0 && edp_bl_level_to_nits(max, maxn, max) == Q(500) &&
          edp_bl_level_to_nits(max + 100, maxn, max) == Q(500) && edp_bl_level_to_nits(5, maxn, 0) == 0);
    CHECK(edp_bl_level_to_nits(716, maxn, max) >> 16 == 174);           /* where Windows left the panel */
    for (uint32_t l = floor; l <= max; l++) {
        uint64_t n = edp_bl_level_to_nits(l, maxn, max), exact = (uint64_t)l * Q(maxn);
        CHECK(n * max + max >= exact && n * max <= exact + max);           /* within half a q16 step of the line */
        CHECK(edp_bl_nits_to_level(n, maxn, floor, max) == l);
    }
    /* The darkest offer: the configured minimum, never below what the floor shows. */
    uint64_t lo = edp_bl_min_nits_q16(EDP_BL_NITS_MIN_DEFAULT, maxn, floor, max);
    CHECK(lo == edp_bl_level_to_nits(floor, maxn, max) && lo >> 16 == 10 && edp_bl_nits_to_level(lo, maxn, floor, max) == floor);
    CHECK(edp_bl_min_nits_q16(20, maxn, floor, max) == Q(20) && edp_bl_nits_to_level(Q(20), maxn, floor, max) == 82);
    /* The slider scale between the published ends. */
    CHECK(edp_bl_slider_to_nits(0, lo, Q(500)) == lo && edp_bl_slider_to_nits(65536, lo, Q(500)) == Q(500) &&
          edp_bl_slider_to_nits(1u << 20, lo, Q(500)) == Q(500) && edp_bl_slider_to_nits(77, Q(9), Q(9)) == Q(9));
    CHECK(edp_bl_nits_to_slider(lo, lo, Q(500)) == 0 && edp_bl_nits_to_slider(Q(500), lo, Q(500)) == 65536 &&
          edp_bl_nits_to_slider(Q(3), lo, Q(500)) == 0 && edp_bl_nits_to_slider(Q(9), Q(9), Q(9)) == 0);
    for (uint32_t v = 0; v <= 65536; v += 512) {
        uint32_t back = edp_bl_nits_to_slider(edp_bl_slider_to_nits(v, lo, Q(500)), lo, Q(500));
        CHECK(back + 1 >= v && back <= v + 1);
    }
    /* The bottom of the slider is the floor, its top the panel's maximum. */
    CHECK(edp_bl_nits_to_level(edp_bl_slider_to_nits(0, lo, Q(500)), maxn, floor, max) == floor);
    CHECK(edp_bl_nits_to_level(edp_bl_slider_to_nits(65536, lo, Q(500)), maxn, floor, max) == max);
}

/* A swap record's brightness double as 16.16 nits: bit-exact against the host's own double arithmetic, refusing what
 * names no brightness, capped, and never trusting the bits to be a sensible number. */
static uint64_t bits_of(double d) { uint64_t b; memcpy(&b, &d, sizeof b); return b; }
static void test_swap_double(void)
{
    const uint64_t cap = (uint64_t)EDP_BL_NITS_LIMIT_MAX << 16;
    uint64_t q = 12345;
    static const double exact[] = {0.0, 1.0, 5.0, 10.015, 140.0, 174.89, 384.615, 499.999, 500.0, 0.5, 1.0 / 65536,
                                   1.5 / 65536, 0.49 / 65536, 1e-300, 999.99998};
    for (unsigned i = 0; i < sizeof exact / sizeof exact[0]; i++) {
        double diff;
        CHECK(edp_bl_double_to_q16(bits_of(exact[i]), cap, &q) == 0);
        diff = (double)q - exact[i] * 65536.0;
        CHECK(diff <= 0.5 && diff >= -0.5);
    }
    CHECK(edp_bl_double_to_q16(bits_of(140.0), cap, &q) == 0 && q == 140ull << 16);
    CHECK(edp_bl_double_to_q16(bits_of(-0.0), cap, &q) == 0 && q == 0);
    CHECK(edp_bl_double_to_q16(bits_of(4.9e-324), cap, &q) == 0 && q == 0);           /* subnormal */
    CHECK(edp_bl_double_to_q16(bits_of(1000.5), cap, &q) == 0 && q == cap);
    CHECK(edp_bl_double_to_q16(bits_of(1e300), cap, &q) == 0 && q == cap);
    CHECK(edp_bl_double_to_q16(bits_of(68719476736.0), cap, &q) == 0 && q == cap);   /* 2^36: the shifted branch */
    CHECK(edp_bl_double_to_q16(bits_of(1e300), UINT64_MAX, &q) == 0 && q == UINT64_MAX);
    CHECK(edp_bl_double_to_q16(bits_of(68719476736.0), UINT64_MAX, &q) == 0 && q == 1ull << 52);
    q = 777;
    CHECK(edp_bl_double_to_q16(0x7ff8000000000000ull, cap, &q) == -1 && q == 777);    /* the NaN CoreAnimation logs */
    CHECK(edp_bl_double_to_q16(0x7ff0000000000001ull, cap, &q) == -1);                /* signalling NaN */
    CHECK(edp_bl_double_to_q16(0x7ff0000000000000ull, cap, &q) == -1);                /* +inf */
    CHECK(edp_bl_double_to_q16(0xfff0000000000000ull, cap, &q) == -1);                /* -inf */
    CHECK(edp_bl_double_to_q16(bits_of(-1.0), cap, &q) == -1 && edp_bl_double_to_q16(bits_of(-1e-300), cap, &q) == -1);
    /* Every exponent and a spread of mantissas: monotonic in the value, never above the cap, rounding within half a
     * step of the host's arithmetic. */
    uint64_t seed = 0x9e3779b97f4a7c15ull, prev = 0;
    for (uint32_t e = 0; e < 0x7ff; e++) {
        for (unsigned k = 0; k < 8; k++) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            uint64_t frac = k == 0 ? 0 : k == 1 ? (1ull << 52) - 1 : seed >> 12;
            uint64_t b = (uint64_t)e << 52 | frac;
            double d;
            memcpy(&d, &b, sizeof d);
            CHECK(edp_bl_double_to_q16(b, cap, &q) == 0 && q <= cap);
            double want = d * 65536.0;
            if (want < (double)cap) CHECK((double)q >= want - 0.5 && (double)q <= want + 0.5);
            else CHECK(q == cap);
            if (k == 0) { CHECK(q >= prev); prev = q; }
        }
    }
}

static void test_helpers(void)
{
    uint32_t bits = 0;
    uint8_t h[4], b[2];
    edp_aux_header(0x722, 2, 0, h);
    CHECK(h[0] == 0x00 && h[1] == 0x07 && h[2] == 0x22 && h[3] == 0x01);
    edp_aux_header(0xF0123, 16, 1, h);
    CHECK(h[0] == 0x1F && h[1] == 0x01 && h[2] == 0x23 && h[3] == 0x0F);
    CHECK(!edp_bl_bits(11, 11, 11, 1, &bits) && bits == 11);
    CHECK(!edp_bl_bits(4, 8, 16, 1, &bits) && bits == 8);     /* below min: the min */
    CHECK(!edp_bl_bits(20, 1, 12, 1, &bits) && bits == 12);   /* above max: the max */
    CHECK(edp_bl_bits(8, 9, 8, 1, &bits));                     /* min > max */
    CHECK(edp_bl_bits(0, 0, 0, 1, &bits));                     /* no count */
    CHECK(edp_bl_bits(17, 17, 17, 1, &bits));                  /* above 16 */
    CHECK(edp_bl_bits(10, 10, 10, 0, &bits));                  /* above 8 without the LSB register */
    CHECK(!edp_bl_bits(8, 8, 8, 0, &bits) && bits == 8);
    CHECK(edp_bl_max_level(11) == 2047 && edp_bl_max_level(8) == 255 && edp_bl_max_level(16) == 65535);
    /* The floor is 2% of full scale, rounded up (EDP_BL_FLOOR_PERMILLE): level 41 of the A16's 2047. */
    CHECK(edp_bl_floor_level(2047) == 41 && edp_bl_floor_level(255) == 6 && edp_bl_floor_level(1) == 1);
    for (uint32_t n = 1; n <= 16; n++) {
        uint32_t max = edp_bl_max_level(n), floor = edp_bl_floor_level(max);
        CHECK(floor >= 1 && floor <= max);
        CHECK((uint64_t)floor * 1000 >= (uint64_t)max * EDP_BL_FLOOR_PERMILLE);
        CHECK(floor == 1 || (uint64_t)(floor - 1) * 1000 < (uint64_t)max * 20);   /* the first level at 2%, no more */
    }
    CHECK(edp_bl_clamp(0, 41, 2047) == 41 && edp_bl_clamp(5000, 41, 2047) == 2047 &&
          edp_bl_clamp(1000, 41, 2047) == 1000 && edp_bl_clamp(UINT64_MAX, 41, 2047) == 2047);
    CHECK(edp_bl_encode(0x5A3, 1, b) == 2 && b[0] == 0x05 && b[1] == 0xA3 && edp_bl_decode(b, 1) == 0x5A3);
    CHECK(edp_bl_encode(0xC8, 0, b) == 1 && b[0] == 0xC8 && edp_bl_decode(b, 0) == 0xC8);
    test_curve();
    test_swap_double();
    uint8_t caps[4] = {0x03, 0x07, 0x06, 0x10};
    uint64_t x1 = edp_bl_reply_x1(EDP_BL_STATE_MODE, EDP_BL_DETAIL_BITS, caps, 0x12);
    CHECK(edp_bl_reply_abi(x1) == EDP_BL_ABI && edp_bl_reply_state(x1) == EDP_BL_STATE_MODE &&
          edp_bl_reply_detail(x1) == EDP_BL_DETAIL_BITS && (x1 >> 40 & 0xff) == 0x06 && x1 >> 56 == 0x12);
    /* the header's allow-lists */
    CHECK(edp_bl_dpcd_write_ok(0x722, 2) && edp_bl_dpcd_write_ok(0x722, 1) && edp_bl_dpcd_write_ok(0x721, 1));
    CHECK(!edp_bl_dpcd_write_ok(0x720, 1) && !edp_bl_dpcd_write_ok(0x721, 2) && !edp_bl_dpcd_write_ok(0x723, 1) &&
          !edp_bl_dpcd_write_ok(0x600, 1) && !edp_bl_dpcd_write_ok(0x734, 3) && !edp_bl_dpcd_write_ok(0x722, 3) &&
          !edp_bl_dpcd_write_ok(0x700, 4) && !edp_bl_dpcd_write_ok(0x00D, 1) && !edp_bl_dpcd_write_ok(0x721, 6));
    CHECK(edp_bl_dpcd_read_ok(0x00D, 1) && edp_bl_dpcd_read_ok(0x700, 4) && edp_bl_dpcd_read_ok(0x721, 6) &&
          !edp_bl_dpcd_read_ok(0x000, 16) && !edp_bl_dpcd_read_ok(0x700, 5));
    for (int i = 0; i < R_N; i++) {
        CHECK(edp_bl_mmio_read_ok(reg_pa[i]) == reg_readable[i]);
        CHECK(edp_bl_mmio_write_ok(reg_pa[i]) == reg_writable[i]);
    }
    CHECK(!edp_bl_mmio_write_ok(M_AUX + 0x30) && !edp_bl_mmio_write_ok(M_AUX + 0x00) && !edp_bl_mmio_read_ok(0));
}

static void test_probe_and_set(void)
{
    uint64_t r[4];
    reset();
    M.status = ST_DONE;                           /* a status the firmware left behind */
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0);
    CHECK(edp_bl_reply_abi(r[1]) == EDP_BL_ABI && state_of(r) == EDP_BL_STATE_READY);
    CHECK((uint32_t)r[2] == 41 && r[2] >> 32 == 2047 && level_of(r) == 768 && (r[3] >> 32 & 0xff) == 11 &&
          (r[3] >> 40 & 1) == 1);
    CHECK(M.dpcd_writes == 0 && M.gos == 3 && M.violations == 0);
    CHECK(call(EDP_BL_SET, 1500, 0, r) == 0 && level_of(r) == 1500 && panel_level() == 1500 && !(r[3] >> 41 & 1));
    CHECK(M.last_write_addr == 0x722 && M.last_write_len == 2 && M.last_write[0] == 0x05 && M.last_write[1] == 0xDC);
    unsigned gos = M.gos;
    CHECK(call(EDP_BL_SET, 1500, 0, r) == 0 && M.gos == gos);   /* unchanged: no traffic */
    CHECK(call(EDP_BL_SET, 0, 0, r) == 0 && panel_level() == 41 && (r[3] >> 41 & 1));      /* never black */
    CHECK(call(EDP_BL_SET, 70000, 0, r) == 0 && panel_level() == 2047 && (r[3] >> 41 & 1)); /* never past max */
    CHECK(M.dpcd[0x721] == 0x12 && M.violations == 0);
}

static void test_byte_panel(void)
{
    uint64_t r[4];
    reset();
    M.dpcd[0x702] = 0x02;                          /* no BYTE_COUNT: 0x722 only */
    M.dpcd[0x722] = 0x80; M.dpcd[0x723] = 0x55;
    M.dpcd[0x724] = 8; M.dpcd[0x725] = 8; M.dpcd[0x726] = 8;
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0 && state_of(r) == EDP_BL_STATE_READY && level_of(r) == 0x80 &&
          r[2] >> 32 == 255 && (uint32_t)r[2] == 6);
    CHECK(call(EDP_BL_SET, 200, 0, r) == 0 && M.dpcd[0x722] == 200 && M.dpcd[0x723] == 0x55 && M.last_write_len == 1);
    CHECK(M.violations == 0);
}

static void test_mode_switch(void)
{
    uint64_t r[4];
    reset();
    M.dpcd[0x721] = 0x10;                          /* PWM pin mode, dynamic backlight bit set */
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0 && state_of(r) == EDP_BL_STATE_MODE && r[1] >> 56 == 0x10);
    unsigned gos = M.gos;
    CHECK(call(EDP_BL_SET, 900, 0, r) == EDP_BL_E_STATE && M.gos == gos && M.dpcd_writes == 0);
    CHECK(call(EDP_BL_SET, 900, EDP_BL_SET_MODE, r) == 0 && state_of(r) == EDP_BL_STATE_READY);
    CHECK(panel_level() == 900 && M.dpcd[0x721] == 0x12 && M.dpcd_writes == 2 && M.violations == 0);
    /* the level was written before the mode */
    CHECK(M.last_write_addr == 0x721);
    reset();
    M.dpcd[0x721] = 0x10;
    M.ignore_mode = 1;                             /* the panel refuses the switch */
    CHECK(call(EDP_BL_SET, 900, EDP_BL_SET_MODE, r) == EDP_BL_E_VERIFY && state_of(r) == EDP_BL_STATE_FAILED &&
          edp_bl_reply_detail(r[1]) == EDP_BL_DETAIL_MODE);
    CHECK(M.last_write_addr == 0x721 && M.last_write[0] == 0x10);   /* the original mode written back */
    gos = M.gos;
    CHECK(call(EDP_BL_SET, 900, EDP_BL_SET_MODE, r) == EDP_BL_E_STATE && M.gos == gos);
    CHECK(M.violations == 0);
}

static void test_refusals(void)
{
    uint64_t r[4];
    struct { int reg; uint32_t value; uint32_t detail; } off[] = {
        {R_AHB_CBCR, 0x80000001u, EDP_BL_DETAIL_CLOCK}, {R_GDSCR, 0, EDP_BL_DETAIL_POWER},
        {R_AUX_CBCR, 0x80000001u, EDP_BL_DETAIL_AUX_CLOCK}, {R_AUX_CTRL, 0, EDP_BL_DETAIL_AUX_OFF}};
    for (unsigned i = 0; i < sizeof off / sizeof off[0]; i++) {
        reset();
        M.reg[off[i].reg] = off[i].value;
        CHECK(call(EDP_BL_SET, 1000, 0, r) == EDP_BL_E_STATE && state_of(r) == EDP_BL_STATE_FAILED &&
              edp_bl_reply_detail(r[1]) == off[i].detail);
        CHECK(M.mmio_writes == 0 && M.gos == 0 && M.violations == 0);
        if (off[i].reg <= R_AUX_CBCR) CHECK(M.dp_reads == 0);   /* nothing in the DP block read unclocked */
    }
    reset();
    M.dpcd[0x00D] = 0x03;                          /* not display-control capable */
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0 && state_of(r) == EDP_BL_STATE_UNSUPPORTED &&
          edp_bl_reply_detail(r[1]) == EDP_BL_DETAIL_NO_CONTROL && M.gos == 1 && M.dpcd_writes == 0);
    reset();
    M.dpcd[0x702] = 0x01;                          /* PWM pin only */
    CHECK(call(EDP_BL_SET, 1000, 0, r) == EDP_BL_E_STATE && edp_bl_reply_detail(r[1]) == EDP_BL_DETAIL_NO_AUX_SET &&
          M.dpcd_writes == 0);
    reset();
    M.dpcd[0x725] = 12; M.dpcd[0x726] = 8;         /* min > max */
    CHECK(call(EDP_BL_SET, 1000, 0, r) == EDP_BL_E_STATE && edp_bl_reply_detail(r[1]) == EDP_BL_DETAIL_BITS &&
          M.dpcd_writes == 0);
    reset();
    unsigned gos = M.gos;
    CHECK(call(7, 0, 0, r) == EDP_BL_E_OP && M.gos == gos && M.mmio_reads == 0);
    CHECK(call(EDP_BL_QUERY, 1, 0, r) == EDP_BL_E_OP && M.mmio_reads == 0);
    CHECK(call(EDP_BL_SET, 1000, 2, r) == EDP_BL_E_OP && M.mmio_reads == 0);
    CHECK(M.violations == 0);
}

static void test_io_failures(void)
{
    uint64_t r[4];
    reset();
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0);
    M.nack = 1;                                    /* one NACK: refused, level unchanged, then recovers */
    CHECK(call(EDP_BL_SET, 1200, 0, r) == EDP_BL_E_IO && level_of(r) == 768 && (r[3] >> 48) == 1 &&
          state_of(r) == EDP_BL_STATE_READY);
    CHECK(call(EDP_BL_SET, 1200, 0, r) == 0 && level_of(r) == 1200 && (r[3] >> 48) == 0);
    M.nack = 100;                                  /* three failures in a row: stopped */
    for (unsigned i = 0; i < EDP_BL_MAX_FAILURES; i++) CHECK(call(EDP_BL_SET, 300 + i, 0, r) == EDP_BL_E_IO);
    CHECK(state_of(r) == EDP_BL_STATE_FAILED && level_of(r) == 1200);
    unsigned gos = M.gos;
    CHECK(call(EDP_BL_SET, 700, 0, r) == EDP_BL_E_STATE && M.gos == gos);
    CHECK(M.violations == 0);
    reset();
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0);
    M.silent = 1;                                  /* no completion: stopped at once, nothing follows into the FIFO */
    uint64_t before = M.now;
    CHECK(call(EDP_BL_SET, 1200, 0, r) == EDP_BL_E_IO && state_of(r) == EDP_BL_STATE_FAILED);
    CHECK(M.now - before <= HZ / EDP_BL_AUX_BUDGET_DIV + 4000);   /* one budget, not unbounded */
    gos = M.gos;
    M.silent = 0;
    CHECK(call(EDP_BL_SET, 1300, 0, r) == EDP_BL_E_STATE && M.gos == gos);
    reset();
    M.silent = 1;                                  /* silent at the probe */
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0 && state_of(r) == EDP_BL_STATE_FAILED &&
          edp_bl_reply_detail(r[1]) == EDP_BL_DETAIL_AUX_IO && M.gos == 1);
    reset();
    CHECK(call(EDP_BL_QUERY, 0, 0, r) == 0);
    M.ignore_level = 1;                            /* the read-back differs: stopped */
    CHECK(call(EDP_BL_SET, 1600, 0, r) == EDP_BL_E_VERIFY && state_of(r) == EDP_BL_STATE_FAILED &&
          edp_bl_reply_detail(r[1]) == EDP_BL_DETAIL_VERIFY && level_of(r) == 768);
    CHECK(M.violations == 0);
}

/* The engine's own allow-list: a monitor callback refusing an access stops it for the boot. */
static int refuse_dp(void *ctx, uint64_t pa, uint32_t *v)
{
    if (pa == reg_pa[R_AUX_CTRL]) return -1;
    return read32(ctx, pa, v);
}
static void test_callback_refusal(void)
{
    uint64_t r[4] = {0x0001000C, EDP_BL_QUERY, 0, 0};
    const struct edp_backlight_io io = {0, refuse_dp, write32, counter, HZ};
    reset();
    CHECK(edp_backlight_call(&S, &io, r) == 0 && edp_bl_reply_state(r[1]) == EDP_BL_STATE_FAILED &&
          edp_bl_reply_detail(r[1]) == EDP_BL_DETAIL_MMIO && M.mmio_writes == 0);
    const struct edp_backlight_io slow = {0, read32, write32, counter, 10};   /* a clock that cannot time anything */
    reset();
    uint64_t q[4] = {0x0001000C, EDP_BL_QUERY, 0, 0};
    CHECK(edp_backlight_call(&S, &slow, q) == 0 && edp_bl_reply_state(q[1]) == EDP_BL_STATE_FAILED &&
          M.mmio_reads == 0);
}

int main(void)
{
    test_helpers();
    test_probe_and_set();
    test_byte_panel();
    test_mode_switch();
    test_refusals();
    test_io_failures();
    test_callback_refusal();
    printf("edp-backlight: PASS\n");
    return 0;
}
