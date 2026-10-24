/* SPDX-License-Identifier: MIT */
/*
 * ADRENO_GUEST_BACKLIGHT's engine (compat/edp-backlight.h): one native AUX transaction at a time on the eDP
 * controller the firmware left running, under the monitor's service lock. Linked only into a -DSNAP_EDP_BACKLIGHT=1
 * monitor (probes/run.py OPTIONAL) and into tools/test-edp-backlight.c. Written for size: the monitor has about 3 KiB
 * of code budget left with the desktop flags (probes/run.py OUT_AT - CODE_AT).
 *
 * Failure behaviour: every refusal leaves the panel as it was. A probe that finds the clocks, the power domain or
 * the AUX controller off reads nothing else and never enables anything; a panel that does not report AUX-settable
 * brightness is never written. The state becomes FAILED, and nothing more reaches the AUX channel this boot, after
 * EDP_BL_MAX_FAILURES failed SETs in a row, one read-back that differs from what was written, one transaction that
 * never completes (it may still be in flight: nothing may follow it into the FIFO), or one access outside the
 * allow-list. The controller is never reset or re-enabled from here: that would be a write outside the backlight set.
 */
#include "edp-backlight.h"

#define AHB(off) (EDP_DP3_AHB_PA + (off))
#define AUX(off) (EDP_DP3_AUX_PA + (off))

/* MMIO through the allow-list. A refusal is sticky (s->refused): every later access in the call is skipped, the
 * transaction in progress fails, and edp_backlight_call stops the engine for the boot. Reads that did not happen
 * return 0. */
__attribute__((noinline)) static uint32_t rd(struct edp_backlight_state *s, uint64_t pa)
{
    uint32_t v = 0;
    if (!s->refused && (!edp_bl_mmio_read_ok(pa) || s->io->read32(s->io->ctx, pa, &v))) s->refused = 1;
    return s->refused ? 0 : v;
}
__attribute__((noinline)) static void wr(struct edp_backlight_state *s, uint64_t pa, uint32_t v)
{
    if (!s->refused && (!edp_bl_mmio_write_ok(pa) || s->io->write32(s->io->ctx, pa, v))) s->refused = 1;
}

/* Acknowledge the AUX statuses in status. INTR_STATUS also holds the HPD and PLL statuses (left alone) and every
 * interrupt's mask bit: a 0 written to a mask bit would mask that interrupt, so each is written back as read. */
static void aux_ack(struct edp_backlight_state *s, uint32_t status)
{
    if (status & EDP_INTR_AUX_ALL)
        wr(s, AHB(EDP_AHB_INTR_STATUS), (status & EDP_INTR_AUX_ALL) << 1 | (status & EDP_INTR_MASK_BITS));
}

/* One native DPCD transaction from the allow-list (Linux dp_aux.c's register sequence): 0, or -1 with
 * s->detail = EDP_BL_DETAIL_AUX_IO. A transaction that never completes sets s->timed_out. Not retried. */
__attribute__((noinline)) static int aux(struct edp_backlight_state *s, int read, uint32_t addr, uint8_t *buf,
                                         uint32_t len)
{
    uint8_t hdr[4];
    uint32_t st, v;
    if (!edp_bl_dpcd_ok(addr, len, read)) s->refused = 1;
    edp_aux_header(addr, len, read, hdr);
    for (uint32_t i = 0; i < 4 + (read ? 0 : len); i++)
        wr(s, AUX(EDP_AUX_DATA), (uint32_t)(i < 4 ? hdr[i] : buf[i - 4]) << 8 | (i ? 0 : EDP_AUX_DATA_INDEX_WRITE));
    wr(s, AUX(EDP_AUX_TRANS_CTRL), 0);
    rd(s, AUX(EDP_AUX_PHY_INTR_STATUS));
    wr(s, AUX(EDP_AUX_PHY_INTR_CLEAR), EDP_AUX_PHY_CLEAR_A);
    wr(s, AUX(EDP_AUX_PHY_INTR_CLEAR), EDP_AUX_PHY_CLEAR_B);
    wr(s, AUX(EDP_AUX_PHY_INTR_CLEAR), 0);
    wr(s, AUX(EDP_AUX_TRANS_CTRL), EDP_AUX_TRANS_GO);
    if (s->refused) goto fail;
    s->transactions++;
    uint64_t start = s->io->counter(s->io->ctx), budget = s->io->hz / EDP_BL_AUX_BUDGET_DIV;
    do st = rd(s, AHB(EDP_AHB_INTR_STATUS));
    while (!(st & EDP_INTR_AUX_ALL) && !s->refused && s->io->counter(s->io->ctx) - start < budget);
    s->last_intr = st;
    if (!(st & EDP_INTR_AUX_ALL)) { s->timed_out = 1; goto fail; }
    aux_ack(s, st);
    if ((st & EDP_INTR_AUX_ERRORS) || !(st & EDP_INTR_AUX_DONE)) goto fail;
    if (read) {
        /* The reply: GO cleared, the FIFO index reset for reading; its first byte is the reply command, then one byte
         * per read address, each carrying its index (dp_aux.c cmd_fifo_rx). A short reply fails the transaction. */
        wr(s, AUX(EDP_AUX_TRANS_CTRL), rd(s, AUX(EDP_AUX_TRANS_CTRL)) & ~EDP_AUX_TRANS_GO);
        wr(s, AUX(EDP_AUX_DATA), EDP_AUX_DATA_INDEX_WRITE | EDP_AUX_DATA_READ);
        rd(s, AUX(EDP_AUX_DATA));
        for (uint32_t i = 0; i < len; i++) {
            v = rd(s, AUX(EDP_AUX_DATA));
            if (((v >> 16) & 0xff) != i) goto fail;
            buf[i] = (uint8_t)(v >> 8);
        }
    }
    if (!s->refused) return 0;
fail:
    s->errors++;
    s->detail = EDP_BL_DETAIL_AUX_IO;
    return -1;
}

__attribute__((noinline)) static int stop(struct edp_backlight_state *s, uint32_t state, uint32_t detail)
{
    s->state = state;
    s->detail = detail;
    return 0;
}

/* Reads only: dispcc and the AUX controller's enable bit (each must already be on: nothing is enabled from here),
 * then three DPCD reads. */
static int probe(struct edp_backlight_state *s)
{
    static const struct { uint32_t pa, mask, want, detail; } on[] = {
        {(uint32_t)(DPU_DISPCC_PA + DPU_DISPCC_MDSS_AHB_CBCR), DPU_CBCR_CLK_OFF, 0, EDP_BL_DETAIL_CLOCK},
        {(uint32_t)(DPU_DISPCC_PA + DPU_DISPCC_MDSS_CORE_GDSCR), EDP_GDSC_PWR_ON, EDP_GDSC_PWR_ON, EDP_BL_DETAIL_POWER},
        {(uint32_t)(DPU_DISPCC_PA + EDP_DISPCC_DPTX3_AUX_CBCR), DPU_CBCR_CLK_OFF, 0, EDP_BL_DETAIL_AUX_CLOCK},
        {(uint32_t)AUX(EDP_AUX_CTRL), EDP_AUX_CTRL_ENABLE, EDP_AUX_CTRL_ENABLE, EDP_BL_DETAIL_AUX_OFF}};
    uint32_t bits;
    uint8_t b[6];
    if (!s->io->counter || s->io->hz < 1000) return stop(s, EDP_BL_STATE_FAILED, EDP_BL_DETAIL_MMIO);
    for (uint32_t i = 0; i < sizeof on / sizeof on[0]; i++)
        if ((rd(s, on[i].pa) & on[i].mask) != on[i].want || s->refused)
            return stop(s, EDP_BL_STATE_FAILED, on[i].detail);
    aux_ack(s, rd(s, AHB(EDP_AHB_INTR_STATUS)));    /* statuses the firmware left behind */
    if (aux(s, 1, DPCD_EDP_CONFIGURATION_CAP, b, 1)) return stop(s, EDP_BL_STATE_FAILED, s->detail);
    s->config_cap = b[0];
    if (!(b[0] & DPCD_DISPLAY_CONTROL_CAPABLE)) return stop(s, EDP_BL_STATE_UNSUPPORTED, EDP_BL_DETAIL_NO_CONTROL);
    if (aux(s, 1, DPCD_EDP_DPCD_REV, s->caps, 4)) return stop(s, EDP_BL_STATE_FAILED, s->detail);
    if (!(s->caps[2] & DPCD_EDP_BL_AUX_SET_CAP)) return stop(s, EDP_BL_STATE_UNSUPPORTED, EDP_BL_DETAIL_NO_AUX_SET);
    if (aux(s, 1, DPCD_EDP_BL_MODE_SET, b, 6)) return stop(s, EDP_BL_STATE_FAILED, s->detail);
    s->mode_reg = b[0];
    s->lsb = (s->caps[2] & DPCD_EDP_BL_BYTE_COUNT) ? 1 : 0;
    if (edp_bl_bits(b[3], b[4], b[5], s->lsb, &bits)) return stop(s, EDP_BL_STATE_UNSUPPORTED, EDP_BL_DETAIL_BITS);
    s->bits = (uint8_t)bits;
    s->max = edp_bl_max_level(bits);
    s->floor = edp_bl_floor_level(s->max);
    s->current = edp_bl_decode(b + 1, s->lsb);
    return stop(s, (b[0] & DPCD_EDP_BL_MODE_MASK) == DPCD_EDP_BL_MODE_DPCD ? EDP_BL_STATE_READY : EDP_BL_STATE_MODE,
                EDP_BL_DETAIL_NONE);
}

/* Write len bytes at addr and read them back. 0, or EDP_BL_E_IO / EDP_BL_E_VERIFY. */
static int write_verified(struct edp_backlight_state *s, uint32_t addr, uint8_t *bytes, uint32_t len)
{
    uint8_t back[2] = {0, 0};
    if (aux(s, 0, addr, bytes, len) || aux(s, 1, addr, back, len)) return EDP_BL_E_IO;
    return back[0] == bytes[0] && (len < 2 || back[1] == bytes[1]) ? 0 : EDP_BL_E_VERIFY;
}

static int set(struct edp_backlight_state *s, uint64_t request, uint64_t flags, uint32_t *clamped)
{
    uint8_t bytes[2];
    if (s->state != EDP_BL_STATE_READY &&
        (s->state != EDP_BL_STATE_MODE || !(flags & EDP_BL_SET_MODE))) return EDP_BL_E_STATE;
    uint32_t level = edp_bl_clamp(request, s->floor, s->max);
    *clamped = level != request;
    s->sets++;
    if (s->state == EDP_BL_STATE_READY && level == s->current) return 0;
    int e = write_verified(s, DPCD_EDP_BL_BRIGHTNESS_MSB, bytes, edp_bl_encode(level, s->lsb, bytes));
    if (!e && s->state == EDP_BL_STATE_MODE) {
        /* Level first, then the mode: a panel still in PWM mode ignores 0x722, so the switch lands on this level.
         * Only the two mode bits change. On failure the original mode goes back once (not after a timeout), and
         * whatever happens nothing more is sent. */
        uint8_t mode = (uint8_t)((s->mode_reg & ~DPCD_EDP_BL_MODE_MASK) | DPCD_EDP_BL_MODE_DPCD);
        e = write_verified(s, DPCD_EDP_BL_MODE_SET, &mode, 1);
        if (e) {
            if (!s->timed_out) aux(s, 0, DPCD_EDP_BL_MODE_SET, &s->mode_reg, 1);
            stop(s, EDP_BL_STATE_FAILED, EDP_BL_DETAIL_MODE);
            return e;
        }
        s->mode_reg = mode;
        s->state = EDP_BL_STATE_READY;
    }
    if (e == EDP_BL_E_VERIFY) stop(s, EDP_BL_STATE_FAILED, EDP_BL_DETAIL_VERIFY);
    else if (e && (++s->failures >= EDP_BL_MAX_FAILURES || s->timed_out)) stop(s, EDP_BL_STATE_FAILED, s->detail);
    if (e) return e;
    s->failures = 0;
    s->detail = EDP_BL_DETAIL_NONE;
    s->current = level;
    return 0;
}

int edp_backlight_call(struct edp_backlight_state *s, const struct edp_backlight_io *io, uint64_t r[4])
{
    uint64_t op = r[1], arg = r[2], flags = r[3];
    uint32_t clamped = 0;
    int e = 0;
    s->io = io;
    s->calls++;
    if ((op == EDP_BL_QUERY && (arg || flags)) || (op == EDP_BL_SET && (flags & ~(uint64_t)EDP_BL_SET_MODE)) ||
        op > EDP_BL_SET)
        e = EDP_BL_E_OP;
    else {
        if (s->state == EDP_BL_STATE_UNPROBED) probe(s);
        if (op == EDP_BL_SET) e = set(s, arg, flags, &clamped);
    }
    if (s->refused) {   /* an access outside the allow-list was attempted: stop for the boot */
        stop(s, EDP_BL_STATE_FAILED, EDP_BL_DETAIL_MMIO);
        if (op == EDP_BL_SET && !e) e = EDP_BL_E_IO;
    }
    s->io = 0;
    r[0] = (uint64_t)(int64_t)e;
    r[1] = edp_bl_reply_x1(s->state, s->detail, s->caps, s->mode_reg);
    r[2] = s->floor | (uint64_t)s->max << 32;
    r[3] = s->current | (uint64_t)s->bits << 32 | (uint64_t)s->lsb << 40 | (uint64_t)clamped << 41 |
           (uint64_t)s->failures << 48;
    return 0;
}
