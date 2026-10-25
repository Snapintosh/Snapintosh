/* SPDX-License-Identifier: MIT */
/*
 * The A16 panel's brightness: VESA eDP DPCD backlight registers written over the eDP controller's AUX channel. The
 * EL2 monitor owns the AUX channel (-DSNAP_EDP_BACKLIGHT=1, compat/edp-backlight.c); the AdrenoX2 kext's
 * AdrenoBacklight (-DADRENO_BACKLIGHT=1) asks it for a level with ADRENO_GUEST_BACKLIGHT. The guest never maps any
 * of these registers. Header-only and freestanding: constants, the call ABI, and the pure helpers the monitor, the
 * kext (C++) and the host test (tools/test-edp-backlight.c) share. Nothing here touches hardware.
 *
 * Evidence (AGENTS.md labels; the captures stay private, only facts are cited):
 *  - VERIFIED, Windows capture pnp-present.json: the internal panel enumerates as DISPLAY\SDC422C (Samsung, 0x422C).
 *  - VERIFIED, the A16 DSDT's \_SB.GPU0._ROM panel table for ManufactureID 0x834C / ProductCode 0x422C: eDP
 *    (InterfaceType 18), BacklightType 8, no BacklightPmic* key, a DPCD caps override whose byte 0x00D is 0x0B
 *    (bit 3: DPCD display control capable), BrightnessRangeLevel0 "5000 500000 1000 2" (INFERRED: millinits min,
 *    max and step). The DSDT has no _BCM, _BCL or _BQC anywhere.
 *  - VERIFIED, Linux glymur.dtsi: the eDP controller is mdss_dp3, regions "ahb" 0x0af6c000 + 0x200 and "aux"
 *    0x0af6c200 + 0x200, clocked by DISP_CC_MDSS_AHB_CLK and DISP_CC_MDSS_DPTX3_AUX_CLK (dispcc-glymur.c CBCRs
 *    0x80b0 and 0x80a8). glymur-crd.dts's Samsung OLED (samsung,atna33xc20) has no backlight node: panel drivers
 *    of that kind control it with drm_panel_dp_aux_backlight (DPCD). No glymur PMIC node has a WLED or LPG.
 *  - INFERRED: BacklightType 8 is that DPCD control. The monitor does not assume it: it reads the panel's own
 *    capability bytes first and refuses unless they say the brightness is AUX-settable.
 * Register offsets and bit meanings are facts from Linux drivers/gpu/drm/msm/dp/dp_reg.h, dp_aux.c, dp_ctrl.c and
 * include/drm/display/drm_dp.h (VESA eDP 1.4b section 3.3.10); no Linux code is reused.
 */
#ifndef SNAP_EDP_BACKLIGHT_H
#define SNAP_EDP_BACKLIGHT_H
#include <stdint.h>
#include "dpu-intf.h"       /* DPU_DISPCC_PA, DPU_DISPCC_MDSS_AHB_CBCR, DPU_DISPCC_MDSS_CORE_GDSCR, DPU_CBCR_CLK_OFF */

/* ---- The eDP controller (mdss_dp3) ---------------------------------------------------------------------------- */
#define EDP_DP3_AHB_PA              0x0AF6C000ULL   /* glymur.dtsi mdss_dp3 reg[0] "ahb", 0x200 */
#define EDP_DP3_AUX_PA              0x0AF6C200ULL   /* glymur.dtsi mdss_dp3 reg[1] "aux", 0x200 */
#define EDP_DISPCC_DPTX3_AUX_CBCR   0x80A8u         /* dispcc-glymur.c disp_cc_mdss_dptx3_aux_clk */
#define EDP_GDSC_PWR_ON             (1u << 31)

#define EDP_AHB_INTR_STATUS         0x020u  /* status at bits 0,3..27; its ack at status << 1, its mask at << 2 */
#define EDP_AUX_HPD_INT_STATUS      0x004u  /* bits 31:29 HPD state (read only by the survey) */
#define EDP_AUX_CTRL                0x030u  /* bit 0 enable: the monitor never writes it */
#define EDP_AUX_DATA                0x034u  /* FIFO: byte at 15:8, index at 23:16, bit 31 index write, bit 0 read */
#define EDP_AUX_TRANS_CTRL          0x038u  /* bit 9 GO */
#define EDP_AUX_PHY_INTR_CLEAR      0x04Cu
#define EDP_AUX_PHY_INTR_STATUS     0x0BCu

#define EDP_AUX_CTRL_ENABLE         (1u << 0)
#define EDP_AUX_DATA_READ           (1u << 0)
#define EDP_AUX_DATA_INDEX_WRITE    (1u << 31)
#define EDP_AUX_TRANS_GO            (1u << 9)
#define EDP_INTR_AUX_DONE           (1u << 3)
#define EDP_INTR_AUX_ERRORS         ((1u << 6) | (1u << 9) | (1u << 12) | (1u << 15) | (1u << 18) | (1u << 21) | \
                                     (1u << 27))   /* wrong address, timeout, NACK/DEFER, data count, I2C x2, PHY */
#define EDP_INTR_AUX_ALL            (EDP_INTR_AUX_DONE | EDP_INTR_AUX_ERRORS)
#define EDP_INTR_STATUS_BITS        0x09249249u      /* every status position, 0..27 step 3 */
#define EDP_INTR_MASK_BITS          (EDP_INTR_STATUS_BITS << 2)
/* The PHY AUX interrupt clear sequence the controller expects before every GO (dp_aux.c clear_hw_interrupts). */
#define EDP_AUX_PHY_CLEAR_A         0x1Fu
#define EDP_AUX_PHY_CLEAR_B         0x9Fu
#define EDP_AUX_MAX_BYTES           16u     /* one native AUX transaction */

/* ---- DPCD (drm_dp.h; eDP display control registers, VESA eDP 1.4b 3.3.10) ------------------------------------- */
#define DPCD_EDP_CONFIGURATION_CAP  0x00Du
#define DPCD_DISPLAY_CONTROL_CAPABLE (1u << 3)
#define DPCD_EDP_DPCD_REV           0x700u  /* read as four bytes: rev, general cap 1, adjustment cap, general cap 2 */
#define DPCD_EDP_BL_AUX_SET_CAP     (1u << 1)   /* 0x702 */
#define DPCD_EDP_BL_BYTE_COUNT      (1u << 2)   /* 0x702: 0x723 (LSB) is used */
#define DPCD_EDP_BL_MODE_SET        0x721u  /* read as six bytes: mode, MSB, LSB, bit count, its min and max */
#define DPCD_EDP_BL_MODE_MASK       0x03u
#define DPCD_EDP_BL_MODE_DPCD       0x02u
#define DPCD_EDP_BL_BRIGHTNESS_MSB  0x722u
#define DPCD_EDP_PWMGEN_BITS_MASK   0x1Fu

/* ---- Policy ------------------------------------------------------------------------------------------------------ */
/* The lowest level the monitor writes, in thousandths of full scale (at least level 1); the guest cannot go below it
 * and the top is the panel's own maximum. What is known (run next1b and the A16 DSDT, AGENTS.md labels):
 *  - OBSERVED: 11-bit levels 0..2047; the firmware/Windows left level 716 (35% of full scale).
 *  - VERIFIED: the DSDT panel table for 0x834C/0x422C names it "Generic OLED Panel HDR" and gives Windows' nits-based
 *    brightness BrightnessRangeLevel0 "5000 500000 1000 2" and BrightnessRangeLowOffset 10000 (INFERRED: millinits,
 *    so 5..500 nits with a 10-nit low offset).
 *  - Nothing measures the panel's luminance per level. If it is linear in luminance (INFERRED: the table describes
 *    the panel to Windows only by a nits range; edp_bl_nits_to_level uses this model), the previous 10% floor
 *    (level 205) was ~50 nits, ten times Windows' minimum, so the bottom of the macOS slider could not be dim.
 * 2% is level 41 on this panel: ~10 nits under the linear model, the table's low offset and twice Windows' minimum,
 * so the bottom of the slider is dim but readable. If the TCON instead followed a 2.2 power law it would be ~0.02% of
 * peak (very dark, never off); the hardware run must look at the bottom of the slider before this is relied on, and
 * the kext's boot-arg adreno_backlight_min_nits raises the darkest request without rebuilding the monitor. */
#define EDP_BL_FLOOR_PERMILLE       20u
#define EDP_BL_MAX_FAILURES         3u      /* consecutive failed SETs before the monitor stops for the boot */
#define EDP_BL_AUX_BUDGET_DIV       200u    /* one transaction's completion budget: hz / 200 = 5 ms */
/* The kext's nominal range for CoreBrightness, from the panel table's millinit range (INFERRED). MAX is the luminance
 * the model assigns to the top level; MIN is the darkest request, raised to the floor's luminance when below it.
 * Boot-args adreno_backlight_min_nits / _max_nits may set either within [EDP_BL_NITS_LIMIT_MIN, EDP_BL_NITS_LIMIT_MAX]. */
#define EDP_BL_NITS_MIN_DEFAULT     5u
#define EDP_BL_NITS_MAX_DEFAULT     500u
#define EDP_BL_NITS_LIMIT_MIN       1u
#define EDP_BL_NITS_LIMIT_MAX       1000u
#define EDP_BL_SLIDER_MAX           65536u  /* IODisplayParameters "brightness" scale (AppleARMBacklight's, OBSERVED) */

/* ---- ADRENO_GUEST_BACKLIGHT (HVC #ADRENO_GUEST_HVC, compat/adreno-guest.h) --------------------------------------
 * Admitted only at EL1 for an HVC in the loaded AuxKC's bytes (early_stop_guest_caller), under the service lock. No
 * ADT property: discovery is QUERY, which a monitor without SNAP_EDP_BACKLIGHT refuses (its fence handler:
 * ADRENO_E_PARAMS), so an older monitor leaves the kext without a backlight service.
 *  QUERY  In: x1 = EDP_BL_QUERY, x2 = x3 = 0. The first QUERY or SET probes: clocks and power (reads), AUX enable
 *         (read), then AUX reads of DPCD 0x00D, 0x700..0x703 and 0x721..0x726. No DPCD write.
 *  SET    In: x1 = EDP_BL_SET, x2 = level, x3 = flags (EDP_BL_SET_MODE or 0). The level is clamped into
 *         [floor, max] and written to 0x722 (and 0x723 when the panel uses it) in one AUX write, then read back.
 *         In state MODE the call also needs EDP_BL_SET_MODE: the level is written first (a panel in another mode
 *         ignores it), then 0x721's two mode bits become DPCD with every other bit kept, and both are read back.
 *  Out (both): x0 = 0 or EDP_BL_E_*; x1 = edp_bl_reply_x1() (ABI, state, detail, DPCD 0x700..0x703, mode byte);
 *         x2 = floor | max << 32; x3 = the panel's level (unchanged by a failed SET) | bits << 32 | lsb << 40 |
 *         clamped << 41 | consecutive failures << 48.
 * DPCD writes are only 0x721 (mode bits), 0x722 and 0x723; MMIO writes only AUX_DATA, AUX_TRANS_CTRL,
 * PHY_AUX_INTERRUPT_CLEAR and INTR_STATUS (AUX acks, every mask bit written back as read). */
#define EDP_BL_ABI                  1u
#define EDP_BL_QUERY                0u
#define EDP_BL_SET                  1u
#define EDP_BL_SET_MODE             1u      /* SET flag: allow the DPCD mode switch */

#define EDP_BL_STATE_UNPROBED       0u
#define EDP_BL_STATE_READY          1u      /* DPCD mode: SET writes the level */
#define EDP_BL_STATE_MODE           2u      /* capable but in another mode: SET needs EDP_BL_SET_MODE */
#define EDP_BL_STATE_FAILED         3u      /* stopped for this boot: nothing more is sent to the panel */
#define EDP_BL_STATE_UNSUPPORTED    4u      /* the hardware does not offer AUX brightness: nothing is sent */

#define EDP_BL_DETAIL_NONE          0u
#define EDP_BL_DETAIL_CLOCK         1u      /* MDSS AHB clock off */
#define EDP_BL_DETAIL_POWER         2u      /* MDSS core GDSC off */
#define EDP_BL_DETAIL_AUX_CLOCK     3u      /* DPTX3 AUX clock off */
#define EDP_BL_DETAIL_AUX_OFF       4u      /* AUX controller disabled */
#define EDP_BL_DETAIL_AUX_IO        5u      /* a transaction failed or timed out */
#define EDP_BL_DETAIL_NO_CONTROL    6u      /* DPCD 0x00D: not display-control capable */
#define EDP_BL_DETAIL_NO_AUX_SET    7u      /* DPCD 0x702: brightness not AUX-settable */
#define EDP_BL_DETAIL_BITS          8u      /* DPCD 0x724..0x726 or byte count inconsistent */
#define EDP_BL_DETAIL_VERIFY        9u      /* a read-back differs from what was written */
#define EDP_BL_DETAIL_MODE          10u     /* the mode switch did not take */
#define EDP_BL_DETAIL_MMIO          11u     /* an access outside the allow-list was refused */

#define EDP_BL_E_OP                 (-101)  /* unknown sub-op, or reserved bits set: nothing done */
#define EDP_BL_E_ORIGIN             (-102)  /* not EL1, or the HVC is not in the AuxKC */
#define EDP_BL_E_STATE              (-103)  /* FAILED, UNSUPPORTED, or MODE without EDP_BL_SET_MODE */
#define EDP_BL_E_IO                 (-104)  /* an AUX transaction failed; the level is the one before */
#define EDP_BL_E_VERIFY             (-105)  /* a read-back differed: the monitor stopped (FAILED) */

static inline uint64_t edp_bl_reply_x1(uint32_t state, uint32_t detail, const uint8_t caps[4], uint8_t mode_reg)
{
    return (uint64_t)EDP_BL_ABI | (uint64_t)(state & 0xff) << 8 | (uint64_t)(detail & 0xff) << 16 |
           (uint64_t)caps[0] << 24 | (uint64_t)caps[1] << 32 | (uint64_t)caps[2] << 40 | (uint64_t)caps[3] << 48 |
           (uint64_t)mode_reg << 56;
}
static inline uint32_t edp_bl_reply_abi(uint64_t x1) { return (uint32_t)(x1 & 0xff); }
static inline uint32_t edp_bl_reply_state(uint64_t x1) { return (uint32_t)((x1 >> 8) & 0xff); }
static inline uint32_t edp_bl_reply_detail(uint64_t x1) { return (uint32_t)((x1 >> 16) & 0xff); }

/* ---- Pure helpers ------------------------------------------------------------------------------------------------ */

/* The four AUX request header bytes (DP 1.4 2.7.1): command and address 19:16, address 15:8, 7:0, length - 1. */
static inline void edp_aux_header(uint32_t addr, uint32_t len, int read, uint8_t hdr[4])
{
    hdr[0] = (uint8_t)(((addr >> 16) & 0x0f) | (read ? 0x10 : 0x00));
    hdr[1] = (uint8_t)(addr >> 8);
    hdr[2] = (uint8_t)addr;
    hdr[3] = (uint8_t)(len - 1);
}

/* The effective PWMGEN bit count (eDP 1.4b 3.3.10.2: a count outside [min, max] is taken as the nearer bound).
 * 0 with *bits set, or -1: no usable count (min > max, 0, above 16, or above 8 without the LSB register). */
static inline int edp_bl_bits(uint8_t count, uint8_t cap_min, uint8_t cap_max, int lsb, uint32_t *bits)
{
    uint32_t n = count & DPCD_EDP_PWMGEN_BITS_MASK, lo = cap_min & DPCD_EDP_PWMGEN_BITS_MASK,
             hi = cap_max & DPCD_EDP_PWMGEN_BITS_MASK;
    if (lo > hi) return -1;
    if (n < lo) n = lo;
    if (n > hi) n = hi;
    if (!n || n > 16 || (!lsb && n > 8)) return -1;
    *bits = n;
    return 0;
}
static inline uint32_t edp_bl_max_level(uint32_t bits) { return (1u << bits) - 1u; }
static inline uint32_t edp_bl_floor_level(uint32_t max)
{
    uint32_t f = (uint32_t)(((uint64_t)max * EDP_BL_FLOOR_PERMILLE + 999u) / 1000u);
    return f ? f : 1u;
}
static inline uint32_t edp_bl_clamp(uint64_t level, uint32_t floor, uint32_t max)
{
    return level < floor ? floor : level > max ? max : (uint32_t)level;
}
/* 0x722 holds the MSB, 0x723 the LSB when the panel uses it (BYTE_COUNT); otherwise the level is one byte. */
static inline uint32_t edp_bl_encode(uint32_t level, int lsb, uint8_t out[2])
{
    if (!lsb) { out[0] = (uint8_t)level; out[1] = 0; return 1; }
    out[0] = (uint8_t)(level >> 8);
    out[1] = (uint8_t)level;
    return 2;
}
static inline uint32_t edp_bl_decode(const uint8_t in[2], int lsb)
{
    return lsb ? (uint32_t)in[0] << 8 | in[1] : in[0];
}

/* The luminance model the kext maps CoreBrightness's requests with: luminance proportional to the level, the top
 * level being max_nits (INFERRED, see EDP_BL_FLOOR_PERMILLE). Nits are 16.16 fixed point throughout, the unit of
 * BrightnessControl's "brightness-nits". A request maps to the nearest level, clamped into [floor, max]: the bottom
 * of the slider lands on (or near) the floor and the top on the panel's maximum. Callers keep max_nits within
 * EDP_BL_NITS_LIMIT_MAX and max within 16 bits, so no product below exceeds 2^42. */
static inline uint32_t edp_bl_nits_to_level(uint64_t nits_q16, uint32_t max_nits, uint32_t floor, uint32_t max)
{
    uint64_t full = (uint64_t)max_nits << 16;
    if (!full || max <= floor) return floor;
    if (nits_q16 >= full) return max;
    return edp_bl_clamp((nits_q16 * max + full / 2) / full, floor, max);
}
/* A level's luminance under the same model (levels above max count as max). */
static inline uint64_t edp_bl_level_to_nits(uint32_t level, uint32_t max_nits, uint32_t max)
{
    if (!max) return 0;
    if (level > max) level = max;
    return ((uint64_t)level * ((uint64_t)max_nits << 16) + max / 2) / max;
}
/* The darkest luminance the kext offers CoreBrightness (BrightnessMilliNits "min"): the configured minimum, raised to
 * the floor's luminance, since nothing below the floor can be shown. */
static inline uint64_t edp_bl_min_nits_q16(uint32_t min_nits, uint32_t max_nits, uint32_t floor, uint32_t max)
{
    uint64_t at_floor = edp_bl_level_to_nits(floor, max_nits, max), configured = (uint64_t)min_nits << 16;
    return configured > at_floor ? configured : at_floor;
}
/* IODisplayParameters "brightness" (0..EDP_BL_SLIDER_MAX) as nits, linear between lo and hi (16.16), and back. */
static inline uint64_t edp_bl_slider_to_nits(uint64_t slider, uint64_t lo_q16, uint64_t hi_q16)
{
    if (slider > EDP_BL_SLIDER_MAX) slider = EDP_BL_SLIDER_MAX;
    return hi_q16 <= lo_q16 ? lo_q16 : lo_q16 + ((hi_q16 - lo_q16) * slider + EDP_BL_SLIDER_MAX / 2) / EDP_BL_SLIDER_MAX;
}
static inline uint32_t edp_bl_nits_to_slider(uint64_t nits_q16, uint64_t lo_q16, uint64_t hi_q16)
{
    if (hi_q16 <= lo_q16 || nits_q16 <= lo_q16) return 0;
    if (nits_q16 >= hi_q16) return EDP_BL_SLIDER_MAX;
    return (uint32_t)(((nits_q16 - lo_q16) * EDP_BL_SLIDER_MAX + (hi_q16 - lo_q16) / 2) / (hi_q16 - lo_q16));
}
/* A swap record's brightness (an IEEE 754 binary64 in nits, as IOMobileFramebufferSwapSetBrightness stores it) as
 * 16.16 nits, rounded to nearest and capped at cap_q16, in integer arithmetic only: the bits come straight from a
 * client's record. 0 with *q16 set; -1 for a NaN, an infinity or a negative value, which name no brightness. Zero and
 * subnormals are 0 nits (the darkest request). */
static inline int edp_bl_double_to_q16(uint64_t bits, uint64_t cap_q16, uint64_t *q16)
{
    /* A normal value is mantissa * 2^(exponent - 1075), so value * 2^16 = mantissa * 2^(exponent - 1059). */
    uint32_t exponent = (uint32_t)(bits >> 52) & 0x7ffu;
    uint64_t mantissa = (bits & ((1ull << 52) - 1)) | 1ull << 52, v;
    if (exponent == 0x7ffu || (bits >> 63 && bits << 1)) return -1;
    if (exponent == 0)
        v = 0;
    else if (exponent >= 1059)   /* 2^36 nits or more; a mantissa below 2^53 shifted by up to 10 stays below 2^63 */
        v = exponent - 1059 > 10 ? UINT64_MAX : mantissa << (exponent - 1059);
    else if (1059 - exponent > 63)
        v = 0;
    else
        v = (mantissa + (1ull << (1059 - exponent - 1))) >> (1059 - exponent);
    *q16 = v > cap_q16 ? cap_q16 : v;
    return 0;
}

/* ---- Allow-lists: every MMIO access and every DPCD transaction the monitor makes passes one of these ----------- */
static inline int edp_bl_mmio_read_ok(uint64_t pa)
{
    static const uint32_t ok[] = {
        (uint32_t)(DPU_DISPCC_PA + DPU_DISPCC_MDSS_AHB_CBCR), (uint32_t)(DPU_DISPCC_PA + DPU_DISPCC_MDSS_CORE_GDSCR),
        (uint32_t)(DPU_DISPCC_PA + EDP_DISPCC_DPTX3_AUX_CBCR), (uint32_t)(EDP_DP3_AHB_PA + EDP_AHB_INTR_STATUS),
        (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_CTRL), (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_DATA),
        (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_TRANS_CTRL), (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_PHY_INTR_STATUS)};
    for (uint32_t i = 0; i < sizeof ok / sizeof ok[0]; i++)
        if (pa == ok[i]) return 1;
    return 0;
}
static inline int edp_bl_mmio_write_ok(uint64_t pa)
{
    static const uint32_t ok[] = {
        (uint32_t)(EDP_DP3_AHB_PA + EDP_AHB_INTR_STATUS), (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_DATA),
        (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_TRANS_CTRL), (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_PHY_INTR_CLEAR)};
    for (uint32_t i = 0; i < sizeof ok / sizeof ok[0]; i++)
        if (pa == ok[i]) return 1;
    return 0;
}
static inline int edp_bl_dpcd_ok(uint32_t addr, uint32_t len, int read)
{
    /* addr << 8 | len; the writes are the first three */
    static const uint32_t ok[] = {
        DPCD_EDP_BL_MODE_SET << 8 | 1, DPCD_EDP_BL_BRIGHTNESS_MSB << 8 | 1, DPCD_EDP_BL_BRIGHTNESS_MSB << 8 | 2,
        DPCD_EDP_BL_MODE_SET << 8 | 6, DPCD_EDP_DPCD_REV << 8 | 4, DPCD_EDP_CONFIGURATION_CAP << 8 | 1};
    for (uint32_t i = 0; i < (read ? sizeof ok / sizeof ok[0] : 3u); i++)
        if (addr << 8 == (ok[i] & ~0xffu) && len == (ok[i] & 0xffu)) return 1;
    return 0;
}
static inline int edp_bl_dpcd_read_ok(uint32_t addr, uint32_t len) { return edp_bl_dpcd_ok(addr, len, 1); }
static inline int edp_bl_dpcd_write_ok(uint32_t addr, uint32_t len) { return edp_bl_dpcd_ok(addr, len, 0); }

/* ---- The monitor's engine (compat/edp-backlight.c) --------------------------------------------------------------- */
struct edp_backlight_io {
    void *ctx;
    int (*read32)(void *ctx, uint64_t pa, uint32_t *value);    /* nonzero: refused, nothing read */
    int (*write32)(void *ctx, uint64_t pa, uint32_t value);    /* nonzero: refused, nothing written */
    uint64_t (*counter)(void *ctx);
    uint64_t hz;
};
/* One zeroed monitor page (setup.c); the state is also the record a report can read. */
struct edp_backlight_state {
    uint32_t state, detail;
    uint8_t caps[4];                    /* DPCD 0x700..0x703 */
    uint8_t mode_reg, bits, lsb, config_cap;
    uint32_t floor, max, current, failures;
    uint32_t refused;                   /* an access outside the allow-list was attempted (sticky) */
    uint32_t timed_out;                 /* a transaction never completed (sticky) */
    uint64_t calls, sets, transactions, errors, last_intr;
    const struct edp_backlight_io *io;  /* during edp_backlight_call only */
};
_Static_assert(sizeof(struct edp_backlight_state) <= 4096, "one monitor page");
/* regs = the HVC's x0..x3 (x0 = ADRENO_GUEST_BACKLIGHT), replaced by the reply. Always returns 0. */
int edp_backlight_call(struct edp_backlight_state *s, const struct edp_backlight_io *io, uint64_t regs[4]);
#endif
