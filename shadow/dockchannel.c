/* SPDX-License-Identifier: MIT */
/* The dock-channel UART's registers, and what each one answers.
 *
 * *The story.* Fifteen monitor calls into every boot, XNU stops asking us to
 * print for it and goes to drive its own serial line. It looks
 * `/arm-io/dockchannel-uart` up in the tree we handed it, maps the two windows
 * that node declares, masks off the interrupts it does not want yet, sets a
 * transmit threshold and a divider, and then writes its first byte. On this
 * laptop there is nothing at those addresses, so every one of those accesses
 * arrives at EL2 as a stage-2 fault instead. This file is the other half of
 * the conversation: the transmit register swallows a byte and hands it to the
 * console buffer the host already reads, the "how much room is left" register
 * says "plenty", and the receive side says "nothing waiting", because we have
 * no input to give it and answering otherwise would invent bytes the kernel
 * never received.
 *
 * Everything else stops the run and names itself. That is deliberate. A device
 * model that quietly returns zero for a register it does not understand is the
 * exact shape of the failure this project has paid for most often: a run that
 * reports success having done nothing. The permissive mode belongs to step F,
 * where it is labelled, counted and asked for by name.
 *
 * WHERE EACH OFFSET COMES FROM, per register, since the two available sources
 * are different consumers of the same hardware and do not agree:
 *
 *   window 1 +0x0 +0x4 +0x8 +0xc   kernelcache 0xfffffe000c1f0b08..0b94:
 *                                  four read-modify-writes of bits 0-1, clear
 *                                  on +0x0/+0x8 and set on +0x4/+0xc, plus a
 *                                  separate enable path at 0xfffffe000c1f0980
 *                                  that writes 1 to +0x4 and clears bit 0 of
 *                                  +0x0. Read as two (mask, flag) pairs, which
 *                                  is q1n1's DockChannelIRQRegs at a 0x8 stride
 *                                  -- that reading is INFERRED; the accesses
 *                                  themselves are recovered.
 *   window 0 +0x0                  kernelcache 0xfffffe000c1f0a08: writes 0xff.
 *                                  q1n1 calls it TX_THRESH.
 *   window 0 +0x8                  kernelcache 0xfffffe000c1f0bb0: writes a
 *                                  value computed by dividing the tree's
 *                                  max-aop-clk. q1n1 names nothing here.
 *   window 0 +0x4004  TX_8         kernelcache 0xfffffe000c2533f0 -- putc:
 *                                  ml_io_write(window0 + 0x4004, byte, 4).
 *   window 0 +0x4014  TX_FREE      kernelcache 0xfffffe000c253448: read, then
 *                                  masked with 0xfff from a global (the tree's
 *                                  dock-wstat-mask).
 *   window 0 +0x4018  RX_COUNT     kernelcache 0xfffffe000c1f0a80: read, then
 *                                  `and w0, w0, #0x7f`. q1n1 NAMES NOTHING AT
 *                                  0x18 and calls 0x2c RX_COUNT. The kernel is
 *                                  the authority on which register its own
 *                                  driver polls, and it polls this one.
 *   window 0 +0x401c  RX_8         kernelcache 0xfffffe000c1f0a50: read, then
 *                                  `ubfx w0, w0, #8, #8` -- the byte is in bits
 *                                  15:8, which is exactly q1n1's R_RX_DATA.
 *                                  Both sources agree.
 *   window 0 +0xc01c               kernelcache 0xfffffe000c1f0bd0: the serial
 *                                  init's tail call reads it and returns it.
 *                                  Block 3's RX_8 by the stride; INFERRED.
 *   window 0 +0x4008/0x400c/0x4010 TX_16/TX_24/TX_32: q1n1 only. XNU's boot
 *                                  console does not use them. Modelled because
 *                                  the widths are unambiguous and swallowing a
 *                                  byte is the one thing this device does.
 *   window 0 +0x4020/0x4024/0x402c q1n1 only. Modelled as "nothing waiting".
 *   window 0 +0x4028  RX_32        q1n1 only, and DELIBERATELY NOT MODELLED --
 *                                  see the comment at the read switch.
 */
#include "dockchannel.h"

/* -------------------------------------------------------------------------
 * The syndrome.
 */
struct dc_access dc_decode(uint64_t esr)
{
    struct dc_access a = {0, 0, 0, 0, 0, 0};
    uint64_t iss = esr & 0x1ffffff;

    /* EC 0x24 is a data abort from a lower exception level. On anything else
     * these bit positions carry other meanings entirely, and a plausible
     * answer built out of them would be worse than no answer. */
    if ((esr >> 26) != 0x24)
        return a;
    if (!((iss >> 24) & 1))          /* ISV: the syndrome describes the access */
        return a;

    a.valid = 1;
    a.write = (uint8_t)((iss >> 6) & 1);          /* WnR */
    a.size  = (uint8_t)(1u << ((iss >> 22) & 3)); /* SAS: 0,1,2,3 -> 1,2,4,8 */
    a.reg   = (uint8_t)((iss >> 16) & 0x1f);      /* SRT */
    a.sign  = (uint8_t)((iss >> 21) & 1);         /* SSE */
    a.wide  = (uint8_t)((iss >> 15) & 1);         /* SF */
    return a;
}

uint64_t dc_narrow(const struct dc_access *a, uint64_t value)
{
    if (!a) return 0;
    if (a->size >= 8)
        return value;
    if (a->size == 0)
        return 0;
    return value & (((uint64_t)1 << (a->size * 8)) - 1);
}

uint64_t dc_extend(const struct dc_access *a, uint64_t value)
{
    if (!a) return 0;
    value = dc_narrow(a, value);
    if (a->sign && a->size < 8 && a->size > 0) {
        uint64_t sign = (uint64_t)1 << (a->size * 8 - 1);
        if (value & sign)
            value |= ~((((uint64_t)1 << (a->size * 8)) - 1));
    }
    /* A W destination zeroes bits 63:32, which is also what truncates a
     * sign-extension that ran past 32 bits. Applied last, and to the
     * sign-extended value, because that is the order the hardware uses. */
    if (!a->wide)
        value &= 0xffffffffu;
    return value;
}

/* -------------------------------------------------------------------------
 * The device.
 */
int dc_shape(const uint64_t *span, uint64_t count)
{
    if (!span || count < 2)
        return 0;
    if (span[DC_WINDOW_DATA] < DC_DATA_SPAN_MIN)
        return 0;
    if (span[DC_WINDOW_IRQ] < DC_IRQ_SPAN_MIN)
        return 0;
    return 1;
}

int dc_window(const uint64_t *pa, const uint64_t *span, uint64_t count,
              uint64_t ipa, uint64_t *off)
{
    if (!pa || !span || !off) return -1;
    /* No separate test for an empty entry. The loader pads device_pa[] and
     * device_span[] with zeros, and a zero span cannot match anything: the
     * comparison below is `ipa >= base && ipa < base`, which is a
     * contradiction for every address including zero. A guard here would read
     * like care and never once fire, which is a thing this project has
     * shipped before and would rather not ship again. */
    for (uint64_t n = 0; n < count && n < 4; n++) {
        if (ipa >= pa[n] && ipa < pa[n] + span[n]) {
            *off = ipa - pa[n];
            return (int)n;
        }
    }
    return -1;
}

/* Which 0x4000 block of window 0, and where inside it. */
static uint64_t dc_block(uint64_t off) { return off / DC_BLOCK; }
static uint64_t dc_within(uint64_t off) { return off % DC_BLOCK; }

int dc_read(const struct dockchannel *d, int window, uint64_t off,
            uint64_t *value)
{
    if (!d || !value) return DC_UNMODELLED;
    if (window == DC_WINDOW_IRQ) {
        switch (off) {
        case 0x0: *value = d->irq_mask[0]; return DC_OK;
        case 0x8: *value = d->irq_mask[1]; return DC_OK;
        /* The flag registers. Nothing in this monitor ever raises a
         * dock-channel interrupt, so nothing is ever pending, and zero is the
         * true state rather than a convenient one. XNU reads +0x4 and tests
         * bit 13 at 0xfffffe000c1f0c04; zero takes the branch that has nothing
         * to acknowledge, which is correct. */
        case 0x4:
        case 0xc: *value = 0; return DC_OK;
        default:  return DC_UNMODELLED;
        }
    }

    if (window != DC_WINDOW_DATA)
        return DC_UNMODELLED;

    {
        uint64_t block = dc_block(off), reg = dc_within(off);

        /* The config blocks remember what was written to them. Only block 0 is
         * modelled: XNU writes +0x0 and +0x8 of it and nothing touches block
         * 2, so answering for block 2 would be a register invented to look
         * complete. */
        if (block == 0) {
            switch (reg) {
            case DC_CFG_TX_THRESH: *value = d->cfg[0]; return DC_OK;
            case DC_CFG_RX_THRESH: *value = d->cfg[1]; return DC_OK;
            case DC_CFG_DIVIDER:   *value = d->cfg[2]; return DC_OK;
            default: return DC_UNMODELLED;
            }
        }

        /* Block 1 is the console's data block; block 3 is the other
         * direction's, and XNU's serial init reads its RX_8 once. Only the
         * receive side of block 3 is modelled -- nothing transmits there, and
         * if something does we would rather stop than silently eat the byte
         * into the transcript under the wrong channel. */
        if (block == 1 || block == 3) {
            switch (reg) {
            /* "How much room is left in the transmit FIFO." Always plenty:
             * every byte we are handed goes straight into the console buffer,
             * so the FIFO is never the thing that fills. */
            case DC_DATA_TX_FREE:
                if (block != 1) return DC_UNMODELLED;
                *value = DC_TX_FREE_ANSWER;
                return DC_OK;
            /* "How many bytes are waiting." None here: host input exists only
             * when a launch enables the console link, and then dc_read_rx
             * answers these registers from its ring. A non-zero count here
             * would send the kernel to the data register for a byte nobody
             * sent. */
            case DC_DATA_RX_COUNT:
            case DC_DATA_RX_COUNT2:
                *value = 0;
                return DC_OK;
            /* The receive data registers. The byte sits in bits 15:8 and the
             * low byte is a count (q1n1's R_RX_DATA; XNU's own getc does
             * `ubfx w0, w0, #8, #8`). Zero therefore says "no byte, and none
             * waiting" -- it is the same answer as the count register, not an
             * invented NUL. A driver that reads these while the count is zero
             * gets a consistent nothing. */
            case DC_DATA_RX8:
            case DC_DATA_RX16:
            case DC_DATA_RX24:
                *value = 0;
                return DC_OK;
            /* RX_32 is the one receive register with no count field: its whole
             * 32 bits are data. Answering zero there would hand the kernel four
             * bytes it never received, which is the one thing this model must
             * not do. Left unmodelled on purpose, so it stops and says so. */
            case DC_DATA_RX32:
            default:
                return DC_UNMODELLED;
            }
        }
        return DC_UNMODELLED;
    }
}

int dc_write(struct dockchannel *d, int window, uint64_t off, uint64_t value,
             uint8_t *tx, unsigned *tx_len)
{
    if (!tx_len) return DC_UNMODELLED;
    *tx_len = 0;
    if (!d || !tx) return DC_UNMODELLED;

    if (window == DC_WINDOW_IRQ) {
        switch (off) {
        case 0x0: d->irq_mask[0] = (uint32_t)value; return DC_OK;
        case 0x8: d->irq_mask[1] = (uint32_t)value; return DC_OK;
        /* Acknowledging an interrupt that was never raised. Accepted and
         * dropped: there is no pending set for a write-one-to-clear to act
         * on, which is why the flag registers read back zero. */
        case 0x4:
        case 0xc: return DC_OK;
        default:  return DC_UNMODELLED;
        }
    }

    if (window != DC_WINDOW_DATA)
        return DC_UNMODELLED;

    {
        uint64_t block = dc_block(off), reg = dc_within(off);
        unsigned n;

        if (block == 0) {
            switch (reg) {
            case DC_CFG_TX_THRESH: d->cfg[0] = (uint32_t)value; return DC_OK;
            case DC_CFG_RX_THRESH: d->cfg[1] = (uint32_t)value; return DC_OK;
            case DC_CFG_DIVIDER:   d->cfg[2] = (uint32_t)value; return DC_OK;
            default: return DC_UNMODELLED;
            }
        }

        /* The transmit registers, and the whole point of this file. TX_8 puts
         * one byte on the wire, TX_16 two, TX_24 three and TX_32 four, low
         * order first -- q1n1's tracer decodes them exactly that way. Only
         * block 1 transmits: the console's putc writes block 1's TX_8 and
         * nothing in the kernelcache writes block 3's. */
        if (block == 1) {
            switch (reg) {
            case DC_DATA_TX8:  n = 1; break;
            case DC_DATA_TX16: n = 2; break;
            case DC_DATA_TX24: n = 3; break;
            case DC_DATA_TX32: n = 4; break;
            default: return DC_UNMODELLED;
            }
            for (unsigned i = 0; i < n; i++)
                tx[i] = (uint8_t)((value >> (8 * i)) & 0xff);
            *tx_len = n;
            return DC_OK;
        }
        return DC_UNMODELLED;
    }
}

/* -------------------------------------------------------------------------
 * Receive (dockchannel.h). Only the launch's console link fills the ring.
 */
unsigned dc_rx_free(const struct dc_rx *r)
{
    if (!r || r->count >= DC_RX_RING) return 0;
    return DC_RX_RING - r->count;
}

int dc_rx_push(struct dc_rx *r, uint8_t byte)
{
    if (!r) return -1;
    if (r->count >= DC_RX_RING) {
        r->refused++;
        return -1;
    }
    r->buf[(r->head + r->count) % DC_RX_RING] = byte;
    r->count++;
    r->pushed++;
    return 0;
}

int dc_read_rx(const struct dockchannel *d, struct dc_rx *rx, int window,
               uint64_t off, uint64_t *value)
{
    if (!value) return DC_UNMODELLED;
    if (!rx || !rx->count || window != DC_WINDOW_DATA || dc_block(off) != 1)
        return dc_read(d, window, off, value);
    switch (dc_within(off)) {
    case DC_DATA_RX_COUNT:
    case DC_DATA_RX_COUNT2:
        *value = rx->count < 0x7f ? rx->count : 0x7f;
        return DC_OK;
    case DC_DATA_RX8:
        *value = (uint64_t)rx->buf[rx->head] << 8 | 1;
        rx->head = (rx->head + 1) % DC_RX_RING;
        rx->count--;
        rx->popped++;
        return DC_OK;
    case DC_DATA_RX16:
    case DC_DATA_RX24:
    case DC_DATA_RX32:
        return DC_UNMODELLED;
    default:
        return dc_read(d, window, off, value);
    }
}
