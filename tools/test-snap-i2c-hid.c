/* SPDX-License-Identifier: MIT */
/*
 * Host test of drivers/snap-i2c-hid/src (GENI I2C master, HID report
 * descriptor scan, I2C-HID transport and state machine) against a simulated
 * GENI serial engine and simulated I2C-HID devices. The keyboard device
 * serves the physically captured A16 bytes (tools/test-snap-i2c-hid-fixture.h);
 * the engine starts from the generation57 IC20 register snapshot.
 *
 * Build and run from the repository root (tools/test-snap-i2c-hid.py also
 * verifies the fixture against the retained evidence first):
 *   mkdir -p build && cc -std=gnu11 -O1 -g -fsanitize=address,undefined \
 *     -Wall -Wextra -Werror -Idrivers/snap-i2c-hid/src tools/test-snap-i2c-hid.c \
 *     drivers/snap-i2c-hid/src/geni-i2c.c drivers/snap-i2c-hid/src/hid-rdesc.c \
 *     drivers/snap-i2c-hid/src/i2c-hid.c drivers/snap-i2c-hid/src/hid-keyboard.c \
 *     drivers/snap-i2c-hid/src/hid-pointer.c drivers/snap-i2c-hid/src/hid-ptp.c \
 *     -o build/test-snap-i2c-hid && build/test-snap-i2c-hid
 *
 * Built with -DSNAP_I2C_HID_FNKEYS=1 it also runs the keyboard's Fn-key layer
 * (test-snap-i2c-hid/fnkeys.c, against hid-keyboard.c built with the same define);
 * tools/test-snap-i2c-hid-kext.py runs both builds.
 *
 * The Precision Touchpad groups (test_ptp_*) cover failure modes F1-F22 of
 * docs/A16-INPUT-PTP-20261020.md, written before src/hid-ptp.c: the real A16
 * descriptor, frames encoded by hand from its decoded offsets (not from the
 * parser's), and the mode switch end to end through the GENI model against a
 * touchpad model that answers feature reports and switches what it sends.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geni-i2c.h"
#include "hid-rdesc.h"
#include "i2c-hid.h"
#include "hid-keyboard.h"
#include "hid-pointer.h"
#include "hid-ptp.h"
#include "hid-mt2.h"
#include "test-snap-i2c-hid-fixture.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #x); exit(1); } } while (0)
/* Model and harness invariants: abort, but are not counted as test checks. */
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "MODEL %s:%d: %s\n", __func__, __LINE__, #x); exit(2); } } while (0)

/* ---------------------------------------------------------------- model -- */

#define FIFO_WORDS 32u
#define MAX_LOG    256u

struct dev {
    uint8_t addr;
    const uint8_t *desc;                 /* 30 bytes */
    const uint8_t *desc_after_reset;     /* identity change after a RESET */
    const uint8_t *rdesc;
    uint32_t rdesc_len;
    uint16_t reg_desc, reg_rdesc, reg_output, reg_cmd, reg_data;
    int powered;
    int resetting;
    uint64_t reset_done_ns, reset_ns;
    int sentinel;
    uint8_t q[32][64];
    uint32_t qlen[32], qhead, qcount;
    uint8_t ctx[16];
    uint32_t ctxn;
    uint8_t get_report[64];
    uint32_t get_report_len;
    uint8_t last[64];
    uint32_t last_len;
    uint8_t leds;
    uint32_t power_on, power_sleep, resets, get_reports, set_reports, outputs;
    uint32_t plain_reads, register_reads, dropped;
    /* faults */
    uint32_t nack_next, nack_next_write, nack_until_ns_valid;
    uint64_t nack_until_ns;
    int nack_while_resetting;
    int bogus_when_empty, repeat_when_empty;
    int never_back;                      /* NACK forever after RESET */
    /* Feature reports (the Precision Touchpad model, features != 0): SET_REPORT stores the report,
     * GET_REPORT answers it with its length prefix; Input Mode and the Surface/Button Switch report
     * take effect; RESET restores the power-on mode (mouse). */
    int features;
    uint8_t feat[256][264];
    uint16_t feat_len[256];              /* report bytes, ID included; 0 = not a feature */
    uint8_t mode_id, mode, selective_id, selective;
    uint32_t feature_gets[256], feature_sets[256];
    uint8_t req_op[64], req_id[64];      /* the order of feature requests: op 2 GET, 3 SET */
    uint32_t nreq;
    int nack_set_id;                     /* NACK the data of a SET_REPORT for this feature */
    int ignore_mode;                     /* acknowledge Input Mode writes, keep the old mode */
    int no_get;                          /* every GET_REPORT is answered empty */
};

struct xfer {
    uint8_t addr, op, stretch, nacked;
    uint32_t len;
    uint8_t data[160];
    uint64_t at_ns;
};

struct model {
    uint32_t regs[0x1000 / 4];
    uint64_t now_ns;
    uint32_t byte_ns, delay_scale;
    uint32_t irq_status, irq_en, tx_len, rx_len;
    uint32_t txq[FIFO_WORDS], txn, tx_byte;
    uint32_t rxq[FIFO_WORDS + 8], rxn;
    int active, hung;
    uint32_t op, addr, stretch, phase, done_bytes;
    uint64_t next_ns;
    uint8_t wbuf[256];
    uint8_t rbuf[4096];
    uint32_t partial, partial_n;
    int push_pending, final_in_fifo;
    uint32_t last_bytes;
    int held;
    uint32_t held_addr;
    struct dev *devs[128];
    /* faults */
    uint32_t nack_addr_next;
    int nack_without_done, tx_retained_after_nack, cancel_clears_tx;
    int cancel_works, abort_works, stall_forever;
    uint32_t short_read_at, excess_words, bad_last_bytes;
    int short_without_last;                /* early DONE that never flags LAST */
    uint32_t inject_on_done, inject_late, late_pending, done_reads;
    int status_requires_enable;
    uint32_t zero_last_mode;
    /* accounting */
    uint32_t mmio_reads, mmio_writes, illegal_writes, outside_reads, underflows, overflows;
    uint32_t idle_ctrl, cancels, aborts, rfr_stalls, commands;
    struct xfer log[MAX_LOG];
    uint32_t nlog;
};

static struct model M;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

static void raise_irq(struct model *m, uint32_t bits)
{
    m->irq_status |= bits;
    if (bits & GENI_IRQ_DONE) {
        m->done_reads = 0;
        m->late_pending = m->inject_late;
    }
}

/* -- device ---------------------------------------------------------------- */

static void dev_init(struct dev *d, uint8_t addr, const uint8_t *desc, const uint8_t *rdesc,
                     uint32_t rdesc_len)
{
    memset(d, 0, sizeof(*d));
    d->addr = addr;
    d->desc = desc;
    d->rdesc = rdesc;
    d->rdesc_len = rdesc_len;
    d->reg_desc = 1;
    d->reg_rdesc = le16(desc + 6);
    d->reg_output = le16(desc + 12);
    d->reg_cmd = le16(desc + 16);
    d->reg_data = le16(desc + 18);
    d->powered = 1;              /* firmware left it on (its last write was 6 bytes) */
    d->reset_ns = 30000000ull;   /* 30 ms */
}

static int dev_attention(struct dev *d, uint64_t now)
{
    if (d->resetting && now < d->reset_done_ns)
        return 0;
    return (d->sentinel && !d->never_back) || d->qcount;
}

static void dev_push(struct dev *d, const uint8_t *report, uint32_t n)
{
    uint32_t slot;
    if (!d->powered || d->qcount == 32 || n + 2 > 64) {
        d->dropped++;
        return;
    }
    slot = (d->qhead + d->qcount) % 32;
    d->q[slot][0] = (uint8_t)(n + 2);
    d->q[slot][1] = 0;
    memcpy(d->q[slot] + 2, report, n);
    d->qlen[slot] = n + 2;
    d->qcount++;
}

/* Raw input-register content, length prefix included (for malformed cases). */
static void dev_push_raw(struct dev *d, const uint8_t *raw, uint32_t n)
{
    uint32_t slot = (d->qhead + d->qcount) % 32;
    memcpy(d->q[slot], raw, n);
    d->qlen[slot] = n;
    d->qcount++;
}

static int dev_nacks(struct dev *d, uint32_t op, uint64_t now)
{
    if (d->nack_next) {
        d->nack_next--;
        return 1;
    }
    if (op == GENI_I2C_OP_WRITE && d->nack_next_write) {
        d->nack_next_write--;
        return 1;
    }
    if (d->nack_until_ns_valid && now < d->nack_until_ns)
        return 1;
    if (d->resetting && d->never_back)
        return 1;
    if (d->resetting && d->nack_while_resetting && now < d->reset_done_ns)
        return 1;
    return 0;
}

/* The report ID a command addresses: the low nibble of byte 2, or byte 4 when that nibble is 15. */
static uint32_t command_id(const uint8_t *b, uint32_t *at)
{
    if ((b[2] & 0x0f) == 0x0f) {
        *at = 5;
        return b[4];
    }
    *at = 4;
    return b[2] & 0x0fu;
}

static void dev_note_request(struct dev *d, uint8_t op, uint8_t id)
{
    if (d->nreq < 64) {
        d->req_op[d->nreq] = op;
        d->req_id[d->nreq] = id;
    }
    d->nreq++;
}

/* Returns 1 when the device NACKs the data (a refused SET_REPORT). */
static int dev_write(struct dev *d, const uint8_t *b, uint32_t n, int stretch, uint64_t now)
{
    uint16_t reg;
    if (stretch) {
        REQUIRE(n <= sizeof(d->ctx));
        memcpy(d->ctx, b, n);
        d->ctxn = n;
        return 0;
    }
    d->ctxn = 0;
    REQUIRE(n >= 2);
    reg = le16(b);
    if (reg == d->reg_cmd && n >= 4) {
        uint8_t op = b[3] & 0x0f;
        if (op == I2C_HID_OP_SET_POWER) {
            d->powered = !(b[2] & 1);
            if (d->powered)
                d->power_on++;
            else
                d->power_sleep++;
        } else if (op == I2C_HID_OP_RESET) {
            d->resets++;
            d->qcount = 0;
            d->qhead = 0;
            d->resetting = 1;
            d->reset_done_ns = now + d->reset_ns;
            d->sentinel = 1;
            d->powered = 1;
            if (d->desc_after_reset)
                d->desc = d->desc_after_reset;
            if (d->features) {               /* power-on defaults: mouse mode, surface and buttons on */
                d->mode = 0;
                d->selective = 3;
                if (d->mode_id)
                    d->feat[d->mode_id][1] = 0;
            }
        } else if (op == I2C_HID_OP_SET_REPORT) {
            d->set_reports++;
            if (d->features && ((b[2] >> 4) & 3u) == I2C_HID_TYPE_FEATURE) {
                uint32_t at, id = command_id(b, &at), len;
                REQUIRE(n >= at + 4 && le16(b + at) == d->reg_data);
                len = le16(b + at + 2);
                REQUIRE(len >= 3 && at + 2 + len == n && b[at + 4] == id && d->feat_len[id] == len - 2);
                dev_note_request(d, I2C_HID_OP_SET_REPORT, (uint8_t)id);
                d->feature_sets[id]++;
                if ((int)id == d->nack_set_id)
                    return 1;
                if (id == d->mode_id && d->ignore_mode)
                    return 0;
                memcpy(d->feat[id], b + at + 4, len - 2);
                if (id == d->mode_id)
                    d->mode = d->feat[id][1];
                if (id == d->selective_id)
                    d->selective = d->feat[id][1] & 3u;
            }
        }
    } else if (reg == d->reg_output && n >= 5) {
        d->outputs++;
        REQUIRE(le16(b + 2) == n - 2);
        if (b[4] == 0x36)
            d->leds = b[5];
    }
    return 0;
}

static void dev_read(struct dev *d, int selected, uint8_t *out, uint32_t n, uint64_t now)
{
    memset(out, 0, n);
    if (selected && d->ctxn) {
        uint16_t reg = le16(d->ctx);
        d->register_reads++;
        if (d->ctxn == 2 && reg == d->reg_desc)
            memcpy(out, d->desc, n < 30 ? n : 30);
        else if (d->ctxn == 2 && reg == d->reg_rdesc)
            memcpy(out, d->rdesc, n < d->rdesc_len ? n : d->rdesc_len);
        else if (reg == d->reg_cmd && d->ctxn >= 6 && (d->ctx[3] & 0x0f) == I2C_HID_OP_GET_REPORT) {
            d->get_reports++;
            if (d->features && ((d->ctx[2] >> 4) & 3u) == I2C_HID_TYPE_FEATURE) {
                uint32_t at, id = command_id(d->ctx, &at), len = d->feat_len[id];
                dev_note_request(d, I2C_HID_OP_GET_REPORT, (uint8_t)id);
                d->feature_gets[id]++;
                if (len && !d->no_get) {
                    uint8_t resp[266];
                    resp[0] = (uint8_t)(len + 2);
                    resp[1] = (uint8_t)((len + 2) >> 8);
                    memcpy(resp + 2, d->feat[id], len);
                    memcpy(out, resp, n < len + 2 ? n : len + 2);
                }
            } else {
                memcpy(out, d->get_report, n < d->get_report_len ? n : d->get_report_len);
            }
        }
        d->ctxn = 0;
        return;
    }
    d->ctxn = 0;
    d->plain_reads++;
    if (d->resetting && now >= d->reset_done_ns)
        d->resetting = 0;
    if (d->resetting)
        return;                              /* answers before it is ready: zeros */
    if (d->sentinel) {
        d->sentinel = 0;                     /* 0x00 0x00: reset complete */
        return;
    }
    if (d->qcount) {
        uint32_t len = d->qlen[d->qhead];
        memcpy(out, d->q[d->qhead], n < len ? n : len);
        memcpy(d->last, d->q[d->qhead], len);
        d->last_len = len;
        d->qhead = (d->qhead + 1) % 32;
        d->qcount--;
        return;
    }
    if (d->bogus_when_empty)
        memset(out, 0xff, n);
    else if (d->repeat_when_empty && d->last_len)
        memcpy(out, d->last, n < d->last_len ? n : d->last_len);
}

/* -- engine ---------------------------------------------------------------- */

static void log_xfer(struct model *m, int nacked, const uint8_t *data, uint32_t len)
{
    struct xfer *x;
    REQUIRE(m->nlog < MAX_LOG);
    x = &m->log[m->nlog++];
    x->addr = (uint8_t)m->addr;
    x->op = (uint8_t)m->op;
    x->stretch = (uint8_t)m->stretch;
    x->nacked = (uint8_t)nacked;
    x->len = len;
    x->at_ns = m->now_ns;
    if (data)
        memcpy(x->data, data, len < sizeof(x->data) ? len : sizeof(x->data));
}

static void complete_read(struct model *m)
{
    m->final_in_fifo = !(m->short_read_at && m->short_without_last);
    m->last_bytes = (m->done_bytes & 3u) ? (m->done_bytes & 3u) : m->zero_last_mode;
    if (m->bad_last_bytes)
        m->last_bytes = m->bad_last_bytes;
    for (uint32_t i = 0; i < m->excess_words; i++)
        m->rxq[m->rxn++] = 0xeeeeeeeeu;
    log_xfer(m, 0, m->rbuf, m->done_bytes);
    raise_irq(m, GENI_IRQ_DONE | GENI_IRQ_RX_LAST | m->inject_on_done);
    m->active = 0;
}

static int push_word(struct model *m)
{
    if (m->rxn >= FIFO_WORDS) {
        m->push_pending = 1;
        m->rfr_stalls++;
        return 0;
    }
    m->rxq[m->rxn++] = m->partial;
    m->partial = 0;
    m->partial_n = 0;
    m->push_pending = 0;
    if (m->rxn >= m->regs[GENI_RX_WATERMARK / 4])
        raise_irq(m, GENI_IRQ_RX_WM);
    return 1;
}

static void model_run(struct model *m)
{
    for (unsigned guard = 0; m->active && !m->hung && !m->stall_forever &&
                             m->next_ns <= m->now_ns; guard++) {
        REQUIRE(guard < 200000);
        if (m->phase == 0) {                     /* address byte */
            struct dev *d = m->devs[m->addr];
            int nack = 0;
            if (m->nack_addr_next) {
                m->nack_addr_next--;
                nack = 1;
            } else if (!d || dev_nacks(d, m->op, m->now_ns)) {
                nack = 1;
            }
            if (nack) {
                log_xfer(m, 1, NULL, 0);
                if (!m->tx_retained_after_nack)
                    m->txn = 0;
                m->held = 0;
                if (m->nack_without_done) {
                    raise_irq(m, GENI_IRQ_NACK | GENI_IRQ_FAILURE);
                    m->hung = 1;                 /* stays active until cancel/abort */
                } else {
                    raise_irq(m, GENI_IRQ_NACK | GENI_IRQ_FAILURE | GENI_IRQ_DONE);
                    m->active = 0;
                }
                return;
            }
            if (m->op == GENI_I2C_OP_READ) {
                REQUIRE(m->rx_len <= sizeof(m->rbuf));
                dev_read(d, m->held && m->held_addr == m->addr, m->rbuf, m->rx_len, m->now_ns);
                m->held = 0;
            }
            m->phase = 1;
            m->next_ns += m->byte_ns;
            continue;
        }
        if (m->op == GENI_I2C_OP_WRITE) {
            uint8_t byte;
            if (!m->txn) {                       /* starved: hold the clock */
                m->next_ns = m->now_ns + m->byte_ns;
                return;
            }
            byte = (uint8_t)(m->txq[0] >> (8 * m->tx_byte));
            m->wbuf[m->done_bytes++] = byte;
            if (++m->tx_byte == 4 || m->done_bytes == m->tx_len) {
                memmove(m->txq, m->txq + 1, (m->txn - 1) * sizeof(uint32_t));
                m->txn--;
                m->tx_byte = 0;
            }
            if (m->done_bytes == m->tx_len) {
                struct dev *d = m->devs[m->addr];
                int refused;
                log_xfer(m, 0, m->wbuf, m->tx_len);
                refused = dev_write(d, m->wbuf, m->tx_len, (int)m->stretch, m->now_ns);
                if (refused) {                   /* the device NACKs the data */
                    m->held = 0;
                    raise_irq(m, GENI_IRQ_NACK | GENI_IRQ_FAILURE | GENI_IRQ_DONE);
                    m->active = 0;
                    return;
                }
                m->held = m->stretch != 0;
                m->held_addr = m->addr;
                raise_irq(m, GENI_IRQ_DONE | m->inject_on_done);
                m->active = 0;
                return;
            }
            m->next_ns += m->byte_ns;
            continue;
        }
        /* READ */
        if (m->push_pending) {
            if (!push_word(m)) {
                m->next_ns = m->now_ns + m->byte_ns;
                return;
            }
            if (m->done_bytes == m->rx_len) {
                complete_read(m);
                return;
            }
        }
        if (m->short_read_at && m->done_bytes == m->short_read_at) {
            if (m->partial_n)
                (void)push_word(m);
            complete_read(m);
            return;
        }
        m->partial |= (uint32_t)m->rbuf[m->done_bytes] << (8 * m->partial_n);
        m->partial_n++;
        m->done_bytes++;
        if (m->partial_n == 4 || m->done_bytes == m->rx_len) {
            if (!push_word(m)) {
                m->next_ns = m->now_ns + m->byte_ns;
                return;
            }
            if (m->done_bytes == m->rx_len) {
                complete_read(m);
                return;
            }
        }
        m->next_ns += m->byte_ns;
    }
}

static uint32_t model_read(struct model *m, uint32_t off)
{
    switch (off) {
    case GENI_STATUS:
        return m->active ? GENI_M_ACTIVE : 0;
    case GENI_M_IRQ_STATUS: {
        uint32_t s;
        if (m->late_pending && m->done_reads++ >= 1) {
            m->irq_status |= m->late_pending;
            m->late_pending = 0;
        }
        s = m->irq_status;
        return m->status_requires_enable ? s & m->irq_en : s;
    }
    case GENI_M_IRQ_EN: return m->irq_en;
    case GENI_I2C_TX_TRANS_LEN: return m->tx_len;
    case GENI_I2C_RX_TRANS_LEN: return m->rx_len;
    case GENI_TX_FIFO_STATUS: return m->txn;
    case GENI_RX_FIFO_STATUS: {
        uint32_t v = m->rxn;
        if (m->final_in_fifo && m->rxn)
            v |= GENI_RX_LAST | (m->last_bytes << GENI_RX_LAST_BYTES_SHIFT);
        return v;
    }
    case GENI_RX_FIFO: {
        uint32_t w;
        if (!m->rxn) {
            m->underflows++;
            raise_irq(m, GENI_IRQ_RX_RD_ERR);
            return 0xdeadbeefu;
        }
        w = m->rxq[0];
        memmove(m->rxq, m->rxq + 1, (m->rxn - 1) * sizeof(uint32_t));
        if (!--m->rxn)
            m->final_in_fifo = 0;
        return w;
    }
    default:
        return m->regs[off / 4];
    }
}

static void model_write(struct model *m, uint32_t off, uint32_t v)
{
    switch (off) {
    case GENI_I2C_TX_TRANS_LEN: m->tx_len = v; return;
    case GENI_I2C_RX_TRANS_LEN: m->rx_len = v; return;
    case GENI_M_IRQ_EN: m->irq_en = v; return;
    case GENI_M_IRQ_CLEAR: m->irq_status &= ~v; return;
    case GENI_TX_FIFO:
        if (m->txn == FIFO_WORDS) {
            m->overflows++;
            raise_irq(m, GENI_IRQ_TX_WR_ERR);
            return;
        }
        m->txq[m->txn++] = v;
        return;
    case GENI_M_CMD0: {
        uint32_t op = v >> GENI_OPCODE_SHIFT;
        m->commands++;
        if (m->active || (op != GENI_I2C_OP_WRITE && op != GENI_I2C_OP_READ)) {
            raise_irq(m, GENI_IRQ_ILLEGAL_CMD);
            return;
        }
        m->op = op;
        m->addr = (v >> GENI_I2C_ADDR_SHIFT) & 0x7f;
        m->stretch = (v & GENI_I2C_STOP_STRETCH) != 0;
        m->phase = 0;
        m->done_bytes = 0;
        m->tx_byte = 0;
        m->partial = 0;
        m->partial_n = 0;
        m->push_pending = 0;
        m->final_in_fifo = 0;
        m->active = 1;
        m->hung = 0;
        m->next_ns = m->now_ns + m->byte_ns;
        return;
    }
    case GENI_M_CMD_CTRL:
        if (!m->active) {
            m->idle_ctrl++;
            return;
        }
        if (v & GENI_CMD_CANCEL) {
            m->cancels++;
            if (m->cancel_works) {
                m->active = 0;
                m->hung = 0;
                raise_irq(m, GENI_IRQ_CANCEL);
                if (m->cancel_clears_tx)
                    m->txn = 0;
            }
        }
        if (v & GENI_CMD_ABORT) {
            m->aborts++;
            if (m->abort_works) {
                m->active = 0;
                m->hung = 0;
                raise_irq(m, GENI_IRQ_ABORT);
                m->txn = 0;
            }
        }
        m->held = 0;
        return;
    default:
        m->illegal_writes++;
        return;
    }
}

static uint32_t io_read32(void *ctx, uint32_t off)
{
    struct model *m = ctx;
    uint32_t v;
    m->mmio_reads++;
    m->now_ns += 200;
    model_run(m);
    if (off >= 0x1000u || (off & 3u)) {
        m->outside_reads++;
        return 0;
    }
    v = model_read(m, off);
    model_run(m);
    return v;
}

static void io_write32(void *ctx, uint32_t off, uint32_t v)
{
    struct model *m = ctx;
    m->mmio_writes++;
    m->now_ns += 200;
    model_run(m);
    model_write(m, off, v);
    model_run(m);
}

static uint64_t io_now_us(void *ctx)
{
    return ((struct model *)ctx)->now_ns / 1000u;
}

static void io_delay_us(void *ctx, uint32_t us)
{
    struct model *m = ctx;
    m->now_ns += (uint64_t)us * 1000u * m->delay_scale;
    model_run(m);
}

static const struct geni_i2c_io IO = { &M, io_read32, io_write32, io_now_us, io_delay_us };

static struct dev KBD, TPAD;
static uint8_t tpad_desc[30];

static void model_reset(void)
{
    memset(&M, 0, sizeof(M));
    for (size_t i = 0; i < sizeof(a16_ic20_registers) / sizeof(a16_ic20_registers[0]); i++)
        M.regs[a16_ic20_registers[i].offset / 4] = a16_ic20_registers[i].value;
    M.irq_status = M.regs[GENI_M_IRQ_STATUS / 4];
    M.irq_en = M.regs[GENI_M_IRQ_EN / 4];
    M.tx_len = M.regs[GENI_I2C_TX_TRANS_LEN / 4];
    M.rx_len = M.regs[GENI_I2C_RX_TRANS_LEN / 4];
    M.byte_ns = 22500;                       /* nine clocks at 400 kHz */
    M.delay_scale = 1;
    M.cancel_works = 1;
    M.abort_works = 1;
    M.cancel_clears_tx = 1;
    M.now_ns = 1000000000ull;
    dev_init(&KBD, 0x15, a16_eckb_hid_desc, a16_eckb_report_desc, sizeof(a16_eckb_report_desc));
    memcpy(KBD.get_report, a16_eckb_get_report_54, sizeof(a16_eckb_get_report_54));
    KBD.get_report_len = sizeof(a16_eckb_get_report_54);
    M.devs[0x15] = &KBD;
}

static void add_touchpad(uint8_t addr)
{
    static const uint8_t base[30] = {
        0x1e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0e, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0,
    };
    memcpy(tpad_desc, base, sizeof(base));
    tpad_desc[4] = (uint8_t)sizeof(synthetic_tpad_report_desc);
    tpad_desc[5] = (uint8_t)(sizeof(synthetic_tpad_report_desc) >> 8);
    dev_init(&TPAD, addr, tpad_desc, synthetic_tpad_report_desc,
             sizeof(synthetic_tpad_report_desc));
    M.devs[addr] = &TPAD;
}

static void advance_us(uint64_t us)
{
    M.now_ns += us * 1000u;
    model_run(&M);
}

/* Invariants every test ends with. model_write counts any write outside the
 * tools' writable set: TX/RX length, M_CMD0, M_CMD_CTRL, M_IRQ_EN/CLEAR, TX FIFO. */
static void check_clean(void)
{
    CHECK(M.illegal_writes == 0);
    CHECK(M.outside_reads == 0);             /* only the first 4 KiB page */
    CHECK(M.underflows == 0);                /* never pop an empty FIFO */
    CHECK(M.overflows == 0);
}

static struct geni_i2c BUS;

static void start_bus(uint32_t policy)
{
    CHECK(geni_i2c_start(&BUS, &IO, 400000, policy) == GENI_I2C_OK);
}

/* ---------------------------------------------------------------- tests -- */

static void test_start_and_stop(void)
{
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    CHECK(BUS.tx_fifo_words == 32 && BUS.rx_fifo_words == 32);
    CHECK(BUS.saved_irq_en == 0x33c0007eu && BUS.saved_tx_len == 6 && BUS.saved_rx_len == 0x40);
    CHECK(M.irq_en == 0x7fc0367fu);          /* the value the physical tools wrote */
    CHECK(M.mmio_writes == 1);               /* 0x80 is not an event: nothing acknowledged */
    CHECK(BUS.initial_status == 0x80u && BUS.initial_ios == 7u && BUS.scl_counters == 0x503018u);
    CHECK(geni_i2c_stop(&BUS) == GENI_I2C_OK);
    CHECK(M.irq_en == 0x33c0007eu && M.tx_len == 6 && M.rx_len == 0x40);
    CHECK(geni_i2c_write(&BUS, 0x15, (const uint8_t *)"\1\0", 2, 1) == GENI_I2C_INVALID);
    model_reset();
    start_bus(GENI_I2C_IRQ_MASKED);
    CHECK(M.irq_en == 0);
    check_clean();
}

static void test_start_refusals(void)
{
    struct { uint32_t off, value; int expect; } cases[] = {
        {GENI_FW_REVISION_RO, 0x204, GENI_I2C_CONFIG},   /* SPI firmware */
        {GENI_IF_DISABLE_RO, 1, GENI_I2C_CONFIG},
        {GENI_DMA_MODE_EN, 1, GENI_I2C_CONFIG},
        {GENI_SER_M_CLK_CFG, 0x20, GENI_I2C_CONFIG},     /* clock off */
        {GENI_SER_M_CLK_CFG, 0x01, GENI_I2C_CONFIG},     /* no divider */
        {GENI_BYTE_GRAN, 1, GENI_I2C_CONFIG},
        {GENI_TX_PACKING_CFG0, 0x7f8ff, GENI_I2C_CONFIG},
        {GENI_RX_PACKING_CFG1, 0xffeff, GENI_I2C_CONFIG},
        {GENI_HW_PARAM_0, 0x10202a68, GENI_I2C_CONFIG},  /* 16-bit words */
        {GENI_HW_PARAM_1, 0x20044802, GENI_I2C_CONFIG},  /* 4-word FIFO */
    };
    struct geni_i2c c;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        model_reset();
        M.regs[cases[i].off / 4] = cases[i].value;
        CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_EVENTS) == cases[i].expect);
        CHECK(M.mmio_writes == 0);
        CHECK(!c.started);
    }
    model_reset();
    M.active = 1;
    M.hung = 1;                              /* engine busy */
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_EVENTS) == GENI_I2C_BUSY);
    CHECK(M.mmio_writes == 0);
    model_reset();
    M.rxq[0] = 0x12345678u;
    M.rxn = 1;                               /* someone else's data: never consumed */
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_EVENTS) == GENI_I2C_BUSY);
    CHECK(M.mmio_writes == 0 && M.rxn == 1);
    model_reset();
    M.irq_status |= GENI_IRQ_NACK;           /* firmware left an error */
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_EVENTS) == GENI_I2C_BUSY);
    CHECK(M.mmio_writes == 0);
    CHECK(geni_i2c_start(&c, &IO, 5000, GENI_I2C_IRQ_EVENTS) == GENI_I2C_INVALID);
    CHECK(geni_i2c_start(&c, &IO, 400000, 7) == GENI_I2C_INVALID);
}

/* A previous run stopped without geni_i2c_stop (a panic or a monitor stop
 * mid-run), then a chainload: the QUP keeps M_IRQ_EN = 0, the lengths it was
 * given and whatever its last transfer left. v39 refused exactly this. The
 * previous run is played through the real transport, then abandoned. */
static void leftover_read(const uint8_t *select, uint32_t len, uint32_t run_us)
{
    model_reset();
    start_bus(GENI_I2C_IRQ_MASKED);
    if (select)
        CHECK(geni_i2c_write(&BUS, 0x15, select, 2, 1) == GENI_I2C_OK);
    io_write32(&M, GENI_I2C_RX_TRANS_LEN, len);
    io_write32(&M, GENI_M_CMD0, (GENI_I2C_OP_READ << GENI_OPCODE_SHIFT) | (0x15u << GENI_I2C_ADDR_SHIFT));
    io_delay_us(&M, run_us);                 /* nobody services it: the guest stopped */
    M.mmio_writes = M.mmio_reads = 0;
}

static void after_recovery_works(struct geni_i2c *c)
{
    uint8_t sel[2] = {1, 0}, buf[30];
    CHECK(c->recovered && !c->wedged && c->started);
    CHECK(!M.active && M.rxn == 0 && M.txn == 0 && !(M.irq_status & GENI_IRQ_ERRORS));
    CHECK(M.underflows == 0 && M.illegal_writes == 0 && M.outside_reads == 0);
    CHECK(M.irq_en == 0);                    /* the masked policy, and the signature kept */
    CHECK(geni_i2c_write(c, 0x15, sel, 2, 1) == GENI_I2C_OK);
    CHECK(geni_i2c_read(c, 0x15, buf, 30) == GENI_I2C_OK);
    CHECK(!memcmp(buf, a16_eckb_hid_desc, 30));
}

static void test_own_leftover(void)
{
    static const uint8_t rdesc_sel[2] = {2, 0};
    struct geni_i2c c;

    /* A finished poll nobody drained: 16 words, DONE and RX_LAST latched. */
    leftover_read(NULL, 64, 5000);
    CHECK(!M.active && M.rxn == 16 && (M.irq_status & GENI_IRQ_DONE));
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_OK);
    CHECK(c.stats.recovered_words == 16 && c.stats.cancels == 0 && c.stats.aborts == 0);
    CHECK(c.found_irq_en == 0 && (c.found_rx_fifo & GENI_RX_FIFO_WC_MASK) == 16);
    after_recovery_works(&c);
    /* The same leftover under the events policy, or with firmware's enables
     * back (someone else's state): refused untouched, as before. */
    leftover_read(NULL, 64, 5000);
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_EVENTS) == GENI_I2C_BUSY);
    CHECK(M.mmio_writes == 0 && M.rxn == 16 && !c.started);
    leftover_read(NULL, 64, 5000);
    M.irq_en = 0x33c0007eu;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_BUSY);
    CHECK(M.mmio_writes == 0 && M.rxn == 16 && !c.started);

    /* Mid-transaction: the 144-byte report-descriptor read stalled on a full
     * FIFO when the guest stopped. Servicing the FIFO lets it finish. */
    leftover_read(rdesc_sel, 144, 10000);
    CHECK(M.active && M.rxn == FIFO_WORDS);
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_OK);
    CHECK(c.stats.recovered_words == 36 && c.stats.cancels == 0);
    after_recovery_works(&c);

    /* An engine that never finishes: cancel, else abort; both bounded. */
    leftover_read(NULL, 64, 5000);
    (void)geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED);   /* drain it first */
    M.active = 1;
    M.hung = 1;
    M.mmio_writes = 0;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_OK);
    CHECK(c.stats.cancels == 1 && c.stats.aborts == 0 && M.cancels == 1);
    after_recovery_works(&c);
    model_reset();
    M.irq_en = 0;
    M.active = 1;
    M.hung = 1;
    M.cancel_works = 0;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_OK);
    CHECK(c.stats.cancels == 1 && c.stats.aborts == 1);
    after_recovery_works(&c);
    model_reset();
    M.irq_en = 0;
    M.active = 1;
    M.hung = 1;
    M.cancel_works = 0;
    M.abort_works = 0;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_WEDGED);
    CHECK(c.wedged && !c.started && M.cancels == 1 && M.aborts == 1);
    {
        uint32_t reads = M.mmio_reads, writes = M.mmio_writes;
        uint8_t buf[4];
        CHECK(geni_i2c_read(&c, 0x15, buf, 4) != GENI_I2C_OK);
        CHECK(M.mmio_reads == reads && M.mmio_writes == writes);   /* nothing more */
    }

    /* A latched error with the engine idle and empty: cleared, then used. */
    model_reset();
    M.irq_en = 0;
    M.irq_status |= GENI_IRQ_NACK | GENI_IRQ_DONE;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_OK);
    CHECK(c.stats.recovered_words == 0 && (c.found_irq & GENI_IRQ_NACK));
    after_recovery_works(&c);

    /* Leftover transmit words cannot be discarded without sending them, and
     * an impossible receive count is not ours: refused, nothing popped. */
    model_reset();
    M.irq_en = 0;
    M.txq[0] = 0x00080005u;
    M.txn = 1;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_BUSY);
    CHECK(M.mmio_writes == 0 && M.txn == 1);
    model_reset();
    M.irq_en = 0;
    M.rxn = FIFO_WORDS + 4;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_WEDGED);
    CHECK(M.rxn == FIFO_WORDS + 4 && M.underflows == 0 && M.mmio_writes == 0);

    /* Our own clean leftover (stop never ran, nothing pending): as before. */
    model_reset();
    M.irq_en = 0;
    CHECK(geni_i2c_start(&c, &IO, 400000, GENI_I2C_IRQ_MASKED) == GENI_I2C_OK && !c.recovered);
}

/* Report 54/55 to key transitions (src/hid-keyboard.c), as SnapI2CHIDKeyboard dispatches them. */
static uint32_t kev[64][3], nkev;
static void kbd_emit(void *ctx, uint32_t page, uint32_t usage, uint32_t down)
{
    (void)ctx;
    if (nkev < 64) { kev[nkev][0] = page; kev[nkev][1] = usage; kev[nkev][2] = down; }
    nkev++;
}
static int kbd_report(struct hid_kbd_state *st, uint8_t mods, const uint8_t *k, unsigned nk)
{
    uint8_t r[9] = {0x36, mods, 0, 0, 0, 0, 0, 0, 0};
    memcpy(r + 3, k, nk);
    return hid_kbd_translate(st, r, 9, kbd_emit, NULL);
}
static int kev_is(unsigned i, uint32_t page, uint32_t usage, uint32_t down)
{
    return i < nkev && kev[i][0] == page && kev[i][1] == usage && kev[i][2] == down;
}

static void test_keyboard_translation(void)
{
    struct hid_kbd_state st = {0};
    static const uint8_t a[1] = {0x04}, ab[2] = {0x04, 0x05}, b[1] = {0x05}, dup[3] = {0x04, 0x04, 0x05};
    static const uint8_t roll[6] = {1, 1, 1, 1, 1, 1}, wild[2] = {0x66, 0xdd}, err[2] = {0x02, 0x03};

    nkev = 0;
    CHECK(kbd_report(&st, 0, a, 1) == HID_KBD_EVENTS && nkev == 1 && kev_is(0, 7, 4, 1));
    CHECK(kbd_report(&st, 0, a, 1) == HID_KBD_EVENTS && nkev == 1);          /* unchanged: nothing */
    CHECK(kbd_report(&st, 0, ab, 2) == HID_KBD_EVENTS && nkev == 2 && kev_is(1, 7, 5, 1));
    CHECK(kbd_report(&st, 0, b, 1) == HID_KBD_EVENTS && nkev == 3 && kev_is(2, 7, 4, 0));
    CHECK(kbd_report(&st, 0, NULL, 0) == HID_KBD_EVENTS && nkev == 4 && kev_is(3, 7, 5, 0));
    /* Modifiers: releases before key releases, presses before key presses. */
    nkev = 0;
    CHECK(kbd_report(&st, 0x22, a, 1) == HID_KBD_EVENTS && nkev == 3);
    CHECK(kev_is(0, 7, 0xe1, 1) && kev_is(1, 7, 0xe5, 1) && kev_is(2, 7, 4, 1));
    CHECK(kbd_report(&st, 0x02, NULL, 0) == HID_KBD_EVENTS && nkev == 5 && kev_is(3, 7, 0xe5, 0) && kev_is(4, 7, 4, 0));
    /* ErrorRollOver keeps the last good state; out-of-range and error usages are no keys. */
    nkev = 0;
    CHECK(kbd_report(&st, 0x02, roll, 6) == HID_KBD_ROLLOVER_REPORT && nkev == 0 && st.modifiers == 0x02);
    CHECK(kbd_report(&st, 0x02, wild, 2) == HID_KBD_EVENTS && nkev == 0);
    CHECK(kbd_report(&st, 0x02, err, 2) == HID_KBD_EVENTS && nkev == 0);
    /* A usage listed twice is one key, released once. */
    CHECK(kbd_report(&st, 0x02, dup, 3) == HID_KBD_EVENTS && nkev == 2 && kev_is(0, 7, 4, 1) && kev_is(1, 7, 5, 1));
    CHECK(kbd_report(&st, 0x02, NULL, 0) == HID_KBD_EVENTS && nkev == 4 && kev_is(2, 7, 4, 0) && kev_is(3, 7, 5, 0));
    /* Consumer report 55: one usage at a time. */
    {
        static const uint8_t up[3] = {0x37, 0xe9, 0x00}, down[3] = {0x37, 0xea, 0x00}, none[3] = {0x37, 0, 0};
        nkev = 0;
        CHECK(hid_kbd_translate(&st, up, 3, kbd_emit, NULL) == HID_KBD_EVENTS && nkev == 1 && kev_is(0, 12, 0xe9, 1));
        CHECK(hid_kbd_translate(&st, up, 3, kbd_emit, NULL) == HID_KBD_EVENTS && nkev == 1);
        CHECK(hid_kbd_translate(&st, down, 3, kbd_emit, NULL) == HID_KBD_EVENTS && nkev == 3 &&
              kev_is(1, 12, 0xe9, 0) && kev_is(2, 12, 0xea, 1));
        CHECK(hid_kbd_translate(&st, none, 3, kbd_emit, NULL) == HID_KBD_EVENTS && nkev == 4 && kev_is(3, 12, 0xea, 0));
    }
    /* Vendor report 90, wrong lengths: nothing, state kept. */
    {
        static const uint8_t vendor[6] = {0x5a, 1, 2, 3, 4, 5}, short54[4] = {0x36, 0, 0, 4}, long55[4] = {0x37, 1, 0, 0};
        nkev = 0;
        CHECK(hid_kbd_translate(&st, vendor, 6, kbd_emit, NULL) == HID_KBD_IGNORED);
        CHECK(hid_kbd_translate(&st, short54, 4, kbd_emit, NULL) == HID_KBD_BAD_LENGTH);
        CHECK(hid_kbd_translate(&st, long55, 4, kbd_emit, NULL) == HID_KBD_BAD_LENGTH);
        CHECK(hid_kbd_translate(&st, vendor, 0, kbd_emit, NULL) == HID_KBD_BAD_LENGTH && nkev == 0);
    }
    /* Release everything held, once. */
    {
        static const uint8_t vol[3] = {0x37, 0xe9, 0};
        CHECK(kbd_report(&st, 0x81, ab, 2) == HID_KBD_EVENTS);
        CHECK(hid_kbd_translate(&st, vol, 3, kbd_emit, NULL) == HID_KBD_EVENTS);
        nkev = 0;
        hid_kbd_release_all(&st, kbd_emit, NULL);
        CHECK(nkev == 5 && kev_is(0, 7, 0xe0, 0) && kev_is(1, 7, 0xe7, 0));
        CHECK(kev_is(2, 7, 4, 0) && kev_is(3, 7, 5, 0) && kev_is(4, 12, 0xe9, 0));
        nkev = 0;
        hid_kbd_release_all(&st, kbd_emit, NULL);
        CHECK(nkev == 0);
    }
}

/* The touchpad's mouse-mode layout from a report descriptor, and its reports to pointer events
 * (src/hid-pointer.c), as SnapI2CHIDPointer dispatches them. */
static int32_t pmove[32][3], pscroll[32][2];
static uint32_t npmove, npscroll;
static void p_move(void *ctx, int32_t dx, int32_t dy, uint32_t buttons)
{
    (void)ctx;
    if (npmove < 32) { pmove[npmove][0] = dx; pmove[npmove][1] = dy; pmove[npmove][2] = (int32_t)buttons; }
    npmove++;
}
static void p_scroll(void *ctx, int32_t v, int32_t h)
{
    (void)ctx;
    if (npscroll < 32) { pscroll[npscroll][0] = v; pscroll[npscroll][1] = h; }
    npscroll++;
}

static void test_pointer(void)
{
    struct hid_pointer_layout l;
    struct hid_pointer_state st = {0};
    /* A Precision-Touchpad-style mouse collection with a wheel and AC Pan, 12-bit X/Y, report 2,
     * after a vendor collection with report 9 and a constant pad. */
    static const uint8_t rich[] = {
        0x06, 0x00, 0xff, 0x09, 0x01, 0xa1, 0x01, 0x85, 0x09, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
        0x95, 0x04, 0x09, 0x02, 0x81, 0x02, 0xc0,
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xa1, 0x00,
        0x05, 0x09, 0x19, 0x01, 0x29, 0x02, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x02, 0x81, 0x02,
        0x95, 0x06, 0x81, 0x03,
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x16, 0x01, 0xf8, 0x26, 0xff, 0x07, 0x75, 0x0c, 0x95, 0x02, 0x81, 0x06,
        0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x01, 0x81, 0x06,
        0x05, 0x0c, 0x0a, 0x38, 0x02, 0x81, 0x06,
        0xc0, 0xc0,
    };
    /* Absolute X/Y only (a digitizer-style mouse): no relative pointer. */
    static const uint8_t absolute[] = {
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x05, 0x09, 0x19, 0x01, 0x29, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
        0x95, 0x07, 0x81, 0x03, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x26, 0xff, 0x0f, 0x75, 0x10, 0x95, 0x02,
        0x81, 0x02, 0xc0,
    };

    /* The fixture's synthetic touchpad: report 1, three buttons, 8-bit relative X/Y. */
    CHECK(hid_pointer_layout(synthetic_tpad_report_desc, sizeof(synthetic_tpad_report_desc), &l) == HID_POINTER_OK);
    CHECK(l.report_id == 1 && l.report_bytes == 4 && l.buttons == 3 && l.buttons_offset == 0);
    CHECK(l.x.offset == 8 && l.x.size == 8 && l.x.is_signed && l.y.offset == 16 && l.y.size == 8);
    CHECK(!l.wheel.size && !l.pan.size);
    {
        static const uint8_t r1[4] = {1, 0x00, 0x05, 0xfd}, r2[4] = {1, 0x01, 0x00, 0x00}, r3[4] = {1, 0x01, 0x00, 0x00},
                             r4[4] = {1, 0x00, 0x00, 0x00}, other[5] = {3, 1, 2, 3, 4}, bad[3] = {1, 0, 0};
        CHECK(hid_pointer_translate(&l, &st, r1, 4, p_move, p_scroll, NULL) == HID_POINTER_EVENTS);
        CHECK(npmove == 1 && pmove[0][0] == 5 && pmove[0][1] == -3 && pmove[0][2] == 0);
        CHECK(hid_pointer_translate(&l, &st, r2, 4, p_move, p_scroll, NULL) == HID_POINTER_EVENTS &&
              npmove == 2 && pmove[1][2] == 1);                     /* button 1 down */
        CHECK(hid_pointer_translate(&l, &st, r3, 4, p_move, p_scroll, NULL) == HID_POINTER_EVENTS && npmove == 2);
        CHECK(hid_pointer_translate(&l, &st, r4, 4, p_move, p_scroll, NULL) == HID_POINTER_EVENTS &&
              npmove == 3 && pmove[2][2] == 0);                     /* and up */
        CHECK(hid_pointer_translate(&l, &st, other, 5, p_move, p_scroll, NULL) == HID_POINTER_OTHER_REPORT);
        CHECK(hid_pointer_translate(&l, &st, bad, 3, p_move, p_scroll, NULL) == HID_POINTER_BAD_LENGTH);
        CHECK(npmove == 3 && npscroll == 0);
    }
    CHECK(hid_pointer_layout(rich, sizeof(rich), &l) == HID_POINTER_OK);
    CHECK(l.report_id == 2 && l.report_bytes == 1 + 1 + 3 + 1 + 1 && l.buttons == 2);
    CHECK(l.x.offset == 8 && l.x.size == 12 && l.y.offset == 20 && l.y.size == 12 && l.x.is_signed);
    CHECK(l.wheel.offset == 32 && l.wheel.size == 8 && l.pan.offset == 40 && l.pan.size == 8);
    {
        /* buttons 2, x = -2 (0xffe), y = +3, wheel -1, pan +2 */
        uint8_t r[7] = {2, 0x02, 0xfe, 0x3f, 0x00, 0xff, 0x02};
        npmove = npscroll = 0;
        st.buttons = 0;
        CHECK(hid_pointer_translate(&l, &st, r, 7, p_move, p_scroll, NULL) == HID_POINTER_EVENTS);
        CHECK(npmove == 1 && pmove[0][0] == -2 && pmove[0][1] == 3 && pmove[0][2] == 2);
        CHECK(npscroll == 1 && pscroll[0][0] == -1 && pscroll[0][1] == 2);
        r[0] = 9;
        CHECK(hid_pointer_translate(&l, &st, r, 5, p_move, p_scroll, NULL) == HID_POINTER_OTHER_REPORT);
    }
    CHECK(hid_pointer_layout(absolute, sizeof(absolute), &l) == HID_POINTER_NO_MOUSE);
    CHECK(hid_pointer_layout(a16_eckb_report_desc, sizeof(a16_eckb_report_desc), &l) == HID_POINTER_NO_MOUSE);
    CHECK(hid_pointer_layout(rich, sizeof(rich) - 1, &l) == HID_POINTER_MALFORMED);    /* collection open */
    CHECK(hid_pointer_layout(rich, 30, &l) == HID_POINTER_MALFORMED);                  /* truncated item */
    {
        uint8_t big[] = {0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x75, 0x20, 0x96, 0xff, 0x7f, 0x81, 0x02, 0xc0};
        CHECK(hid_pointer_layout(big, sizeof(big), &l) == HID_POINTER_MALFORMED);    /* oversize report */
    }
}

static void test_descriptor_reads(void)
{
    uint8_t sel[2] = {1, 0}, buf[144];
    for (uint32_t scale = 1; scale <= 40; scale += 39) {
        model_reset();
        M.delay_scale = scale;               /* 40: coarse sleeps overfill the FIFO */
        start_bus(GENI_I2C_IRQ_EVENTS);
        CHECK(geni_i2c_write(&BUS, 0x15, sel, 2, 1) == GENI_I2C_OK);
        CHECK(geni_i2c_read(&BUS, 0x15, buf, 30) == GENI_I2C_OK);
        CHECK(!memcmp(buf, a16_eckb_hid_desc, 30));
        sel[0] = 2;
        CHECK(geni_i2c_write(&BUS, 0x15, sel, 2, 1) == GENI_I2C_OK);
        CHECK(geni_i2c_read(&BUS, 0x15, buf, 144) == GENI_I2C_OK);
        CHECK(!memcmp(buf, a16_eckb_report_desc, 144));
        CHECK(scale == 1 ? M.rfr_stalls == 0 : M.rfr_stalls > 0);
        CHECK(M.nlog == 4);
        CHECK(M.log[0].op == GENI_I2C_OP_WRITE && M.log[0].stretch && M.log[0].len == 2 &&
              M.log[0].data[0] == 1 && M.log[0].data[1] == 0);
        CHECK(M.log[1].op == GENI_I2C_OP_READ && M.log[1].len == 30);
        CHECK(M.log[3].op == GENI_I2C_OP_READ && M.log[3].len == 144);
        CHECK(KBD.register_reads == 2 && KBD.plain_reads == 0);
        CHECK(!M.active && M.rxn == 0 && M.txn == 0);
        CHECK(BUS.stats.ok == 4 && BUS.stats.cancels == 0);
        CHECK(M.tx_len == 2 && M.rx_len == 144);
        check_clean();
        sel[0] = 1;
    }
}

static void test_report_descriptor_scan(void)
{
    struct hid_rdesc_info info;
    struct { uint8_t type, id; uint32_t bits, bytes; } want[] = {
        {HID_REPORT_INPUT, 54, 64, 9}, {HID_REPORT_OUTPUT, 54, 8, 2},
        {HID_REPORT_INPUT, 90, 40, 6}, {HID_REPORT_FEATURE, 90, 504, 64},
        {HID_REPORT_INPUT, 55, 16, 3},
    };
    CHECK(hid_rdesc_parse(a16_eckb_report_desc, 144, &info) == HID_RDESC_OK);
    CHECK(info.numbered && info.nreports == 5 && info.napps == 3);
    for (size_t i = 0; i < 5; i++) {
        CHECK(info.reports[i].type == want[i].type && info.reports[i].id == want[i].id);
        CHECK(info.reports[i].bits == want[i].bits);
        /* The generation57 Python decoder's payload_bytes, then +2 on the wire. */
        CHECK(hid_rdesc_report_bytes(&info, want[i].type, want[i].id) == want[i].bytes);
    }
    CHECK(hid_rdesc_max_report_bytes(&info, HID_REPORT_INPUT) + 2 == 11);
    CHECK(info.apps[0].page == 0x01 && info.apps[0].usage == 0x06);    /* keyboard */
    CHECK(info.apps[1].page == 0xff31 && info.apps[1].usage == 0x76);  /* ASUS vendor */
    CHECK(info.apps[2].page == 0x0c && info.apps[2].usage == 0x01);    /* consumer */
    CHECK(hid_rdesc_report_bytes(&info, HID_REPORT_INPUT, 1) == 0);

    CHECK(hid_rdesc_parse(synthetic_tpad_report_desc, sizeof(synthetic_tpad_report_desc),
                          &info) == HID_RDESC_OK);
    CHECK(hid_rdesc_report_bytes(&info, HID_REPORT_INPUT, 1) == 4);
    CHECK(hid_rdesc_report_bytes(&info, HID_REPORT_INPUT, 3) == 10);
    CHECK(info.apps[0].page == 1 && info.apps[0].usage == 2 &&
          info.apps[1].page == 0x0d && info.apps[1].usage == 5);

    {   /* Push/Pop: a 16-bit field inside, the saved 8-bit size after Pop. */
        static const uint8_t pushed[] = {0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x75, 0x08, 0x95,
                                         0x01, 0xa4, 0x75, 0x10, 0x81, 0x02, 0xb4, 0x81, 0x02,
                                         0xc0};
        CHECK(hid_rdesc_parse(pushed, sizeof(pushed), &info) == HID_RDESC_OK);
        CHECK(info.nreports == 1 && info.reports[0].bits == 24 && !info.numbered);
    }
    {   /* refusals */
        static const uint8_t truncated[] = {0x05, 0x01, 0x09};
        static const uint8_t unbalanced[] = {0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x75, 0x08,
                                             0x95, 0x01, 0x81, 0x02};
        static const uint8_t extra_end[] = {0xc0};
        static const uint8_t id_zero[] = {0x85, 0x00};
        static const uint8_t id_wide[] = {0x86, 0x36, 0x00};
        static const uint8_t pop[] = {0xb4};
        static const uint8_t outside[] = {0x75, 0x08, 0x95, 0x01, 0x81, 0x02};
        static const uint8_t no_count[] = {0xa1, 0x01, 0x75, 0x08, 0x81, 0x02, 0xc0};
        static const uint8_t reserved[] = {0x0c};
        static const uint8_t mixed[] = {0xa1, 0x01, 0x75, 0x08, 0x95, 0x01, 0x81, 0x02,
                                        0x85, 0x02, 0x81, 0x02, 0xc0};
        static const uint8_t long_item[] = {0xfe, 0x04, 0x10, 1, 2};
        CHECK(hid_rdesc_parse(truncated, sizeof(truncated), &info) == HID_RDESC_TRUNCATED);
        CHECK(hid_rdesc_parse(unbalanced, sizeof(unbalanced), &info) == HID_RDESC_COLLECTION);
        CHECK(hid_rdesc_parse(extra_end, sizeof(extra_end), &info) == HID_RDESC_COLLECTION);
        CHECK(hid_rdesc_parse(id_zero, sizeof(id_zero), &info) == HID_RDESC_REPORT_ID);
        CHECK(hid_rdesc_parse(id_wide, sizeof(id_wide), &info) == HID_RDESC_REPORT_ID);
        CHECK(hid_rdesc_parse(pop, sizeof(pop), &info) == HID_RDESC_STACK);
        CHECK(hid_rdesc_parse(outside, sizeof(outside), &info) == HID_RDESC_FIELD);
        CHECK(hid_rdesc_parse(no_count, sizeof(no_count), &info) == HID_RDESC_FIELD);
        CHECK(hid_rdesc_parse(reserved, sizeof(reserved), &info) == HID_RDESC_BAD_ITEM);
        CHECK(hid_rdesc_parse(mixed, sizeof(mixed), &info) == HID_RDESC_MIXED_IDS);
        CHECK(hid_rdesc_parse(long_item, sizeof(long_item), &info) == HID_RDESC_TRUNCATED);
        CHECK(hid_rdesc_parse(a16_eckb_report_desc, 143, &info) != HID_RDESC_OK);
        /* Every prefix is bounded. The only complete ones end a top-level
         * collection (keyboard at 77, vendor at 119), optionally followed by
         * the next collection's Usage Page/Usage items. */
        static const uint32_t ok_at[] = {77, 80, 82, 119, 121, 123};
        uint32_t complete = 0;
        for (uint32_t n = 0; n < 144; n++) {
            if (hid_rdesc_parse(a16_eckb_report_desc, n, &info) != HID_RDESC_OK)
                continue;
            CHECK(complete < 6 && n == ok_at[complete]);
            CHECK(info.napps == (n < 119 ? 1u : 2u));
            complete++;
        }
        CHECK(complete == 6);
    }
}

static void test_hid_descriptor_parse(void)
{
    struct i2c_hid_desc d;
    uint8_t raw[30];
    CHECK(i2c_hid_parse_desc(a16_eckb_hid_desc, 30, &d) == I2C_HID_DESC_OK);
    CHECK(d.version == 0x100 && d.rdesc_length == 144 && d.rdesc_register == 2);
    CHECK(d.input_register == 3 && d.max_input == 64 && d.output_register == 4);
    CHECK(d.max_output == 32 && d.command_register == 5 && d.data_register == 6);
    CHECK(d.vendor_id == 0x0b05 && d.product_id == 0x4b42 && d.device_version == 0);
    CHECK(i2c_hid_parse_desc(a16_eckb_hid_desc, 29, &d) == I2C_HID_DESC_LENGTH);
    memcpy(raw, a16_eckb_hid_desc, 30);
    raw[2] = 1;
    CHECK(i2c_hid_parse_desc(raw, 30, &d) == I2C_HID_DESC_VERSION);
    memcpy(raw, a16_eckb_hid_desc, 30);
    raw[4] = raw[5] = 0;
    CHECK(i2c_hid_parse_desc(raw, 30, &d) == I2C_HID_DESC_BOUNDS);
    memcpy(raw, a16_eckb_hid_desc, 30);
    raw[10] = 2;
    CHECK(i2c_hid_parse_desc(raw, 30, &d) == I2C_HID_DESC_BOUNDS);
    memcpy(raw, a16_eckb_hid_desc, 30);
    raw[29] = 1;
    CHECK(i2c_hid_parse_desc(raw, 30, &d) == I2C_HID_DESC_RESERVED);
    memcpy(raw, a16_eckb_hid_desc, 30);
    raw[0] = 0x1f;
    CHECK(i2c_hid_parse_desc(raw, 30, &d) == I2C_HID_DESC_LENGTH);
}

static void test_encoders(void)
{
    struct i2c_hid_desc d;
    uint8_t out[128], feature[63];
    CHECK(i2c_hid_parse_desc(a16_eckb_hid_desc, 30, &d) == I2C_HID_DESC_OK);
    CHECK(i2c_hid_encode_set_power(&d, I2C_HID_POWER_ON, out, sizeof(out)) == 4 &&
          !memcmp(out, "\x05\x00\x00\x08", 4));
    CHECK(i2c_hid_encode_set_power(&d, I2C_HID_POWER_SLEEP, out, sizeof(out)) == 4 &&
          !memcmp(out, "\x05\x00\x01\x08", 4));
    CHECK(i2c_hid_encode_set_power(&d, 2, out, sizeof(out)) == 0);
    CHECK(i2c_hid_encode_reset(&d, out, sizeof(out)) == 4 && !memcmp(out, "\x05\x00\x00\x01", 4));
    /* The exact generation59 command packet. */
    CHECK(i2c_hid_encode_get_report(&d, I2C_HID_TYPE_INPUT, 54, out, sizeof(out)) == 7 &&
          !memcmp(out, "\x05\x00\x1f\x02\x36\x06\x00", 7));
    CHECK(i2c_hid_encode_get_report(&d, I2C_HID_TYPE_FEATURE, 5, out, sizeof(out)) == 6 &&
          !memcmp(out, "\x05\x00\x35\x02\x06\x00", 6));
    CHECK(i2c_hid_encode_get_report(&d, I2C_HID_TYPE_INPUT, 54, out, 6) == 0);
    CHECK(i2c_hid_encode_output(&d, 0x36, (const uint8_t *)"\x02", 1, out, sizeof(out)) == 6 &&
          !memcmp(out, "\x04\x00\x04\x00\x36\x02", 6));
    memset(feature, 0xa5, sizeof(feature));
    CHECK(i2c_hid_encode_set_report(&d, I2C_HID_TYPE_FEATURE, 0x5a, feature, 63, out,
                                    sizeof(out)) == 5 + 2 + 66);
    CHECK(!memcmp(out, "\x05\x00\x3f\x03\x5a\x06\x00\x42\x00\x5a", 10) && out[72] == 0xa5);
    CHECK(i2c_hid_encode_set_report(&d, I2C_HID_TYPE_FEATURE, 0x5a, feature, 63, out, 72) == 0);
}

static void test_classification(void)
{
    struct hid_rdesc_info r;
    struct i2c_hid_input in;
    uint8_t buf[64];
    CHECK(hid_rdesc_parse(a16_eckb_report_desc, 144, &r) == HID_RDESC_OK);
    /* Task 1: the physical GET_REPORT answer is an empty report, not an error. */
    CHECK(i2c_hid_classify_response(&r, I2C_HID_TYPE_INPUT, 54, a16_eckb_get_report_54, 11,
                                    &in) == I2C_HID_IN_EMPTY);
    CHECK(in.length == 0);
    memcpy(buf, "\x0b\x00\x36\x02\x00\x04\x00\x00\x00\x00\x00", 11);
    CHECK(i2c_hid_classify_response(&r, I2C_HID_TYPE_INPUT, 54, buf, 11, &in) ==
          I2C_HID_IN_REPORT && in.report_bytes == 9 && in.report[0] == 0x36);
    CHECK(i2c_hid_classify_response(&r, I2C_HID_TYPE_INPUT, 55, buf, 11, &in) ==
          I2C_HID_IN_UNKNOWN_ID);
    buf[0] = 0x0c;
    CHECK(i2c_hid_classify_response(&r, I2C_HID_TYPE_INPUT, 54, buf, 11, &in) ==
          I2C_HID_IN_BAD_LENGTH);

    memset(buf, 0, sizeof(buf));
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_EMPTY);
    buf[0] = 2;
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_EMPTY);
    buf[0] = 1;
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_BAD_LENGTH);
    buf[0] = 65;
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_BAD_LENGTH);
    buf[0] = buf[1] = 0xff;
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_BOGUS);
    memcpy(buf, "\x0b\x00\x36\x02\x00\x04\x00\x00\x00\x00\x00", 11);
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_REPORT);
    CHECK(in.id == 54 && in.report_bytes == 9 && in.report == buf + 2);
    memcpy(buf, "\x05\x00\x37\xe9\x00", 5);
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_REPORT && in.id == 55);
    memcpy(buf, "\x08\x00\x5a\x01\x02\x03\x04\x05", 8);
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_REPORT && in.id == 90);
    memcpy(buf, "\x0a\x00\x36\x00\x00\x04\x00\x00\x00\x00", 10);
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_WRONG_SIZE);
    memcpy(buf, "\x05\x00\x40\x00\x00", 5);
    CHECK(i2c_hid_classify_input(&r, buf, 64, &in) == I2C_HID_IN_UNKNOWN_ID);
    CHECK(i2c_hid_classify_input(&r, buf, 1, &in) == I2C_HID_IN_BAD_LENGTH);
}

/* -- state machine ----------------------------------------------------------- */

static uint8_t delivered[64][64];
static uint32_t delivered_len[64], ndelivered;

static void deliver(void *ctx, const uint8_t *report, uint32_t len)
{
    (void)ctx;
    REQUIRE(ndelivered < 64 && len <= 64);
    memcpy(delivered[ndelivered], report, len);
    delivered_len[ndelivered++] = len;
}

static int attention(void *ctx)
{
    return dev_attention(ctx, M.now_ns);
}

static struct i2c_hid_dev DEV;

/* Run the timer loop until the device reaches `until` or stops asking. */
static uint32_t run_until(struct i2c_hid_dev *d, uint32_t until, uint32_t max_steps)
{
    uint32_t steps = 0;
    while (d->state != until && steps++ < max_steps) {
        uint32_t wake = i2c_hid_step(d);
        if (wake == I2C_HID_NO_WAKE)
            break;
        advance_us(wake);
    }
    return steps;
}

static void poll_ticks(struct i2c_hid_dev *d, uint32_t ticks)
{
    for (uint32_t i = 0; i < ticks; i++) {
        uint32_t wake = i2c_hid_step(d);
        if (wake == I2C_HID_NO_WAKE)
            return;
        advance_us(wake);
    }
}

static void begin_keyboard(uint32_t policy)
{
    struct i2c_hid_config cfg;
    model_reset();
    ndelivered = 0;
    start_bus(policy);
    i2c_hid_default_config(&cfg, 0x15, 1);
    cfg.expect_vendor = 0x0b05;
    cfg.expect_product = 0x4b42;
    CHECK(i2c_hid_begin(&DEV, &BUS, &cfg, deliver, NULL) == I2C_HID_R_OK);
}

static void test_initialisation(void)
{
    static const uint8_t pwr[] = {5, 0, 0, 8}, rst[] = {5, 0, 0, 1};
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY);
    CHECK(M.nlog == 8);
    CHECK(M.log[0].op == GENI_I2C_OP_WRITE && M.log[0].stretch && !memcmp(M.log[0].data, "\1\0", 2));
    CHECK(M.log[1].op == GENI_I2C_OP_READ && M.log[1].len == 30);
    CHECK(M.log[2].op == GENI_I2C_OP_WRITE && !M.log[2].stretch && M.log[2].len == 4 &&
          !memcmp(M.log[2].data, pwr, 4));
    CHECK(M.log[3].len == 4 && !memcmp(M.log[3].data, rst, 4));
    CHECK(M.log[4].op == GENI_I2C_OP_READ && M.log[4].len == 64 && !M.log[4].data[0] &&
          !M.log[4].data[1]);                        /* the reset sentinel */
    CHECK(M.log[5].len == 4 && !memcmp(M.log[5].data, pwr, 4));
    CHECK(M.log[6].stretch && !memcmp(M.log[6].data, "\2\0", 2));
    CHECK(M.log[7].op == GENI_I2C_OP_READ && M.log[7].len == 144);
    CHECK(M.log[3].at_ns - M.log[2].at_ns >= 60000000ull);   /* PWR_ON settles 60 ms */
    CHECK(M.log[4].at_ns - M.log[3].at_ns >= 100000000ull);  /* reset given 100 ms */
    CHECK(M.log[6].at_ns - M.log[5].at_ns >= 60000000ull);
    CHECK(KBD.power_on == 2 && KBD.resets == 1 && !KBD.sentinel && !KBD.resetting);
    CHECK(DEV.rdesc_len == 144 && !memcmp(DEV.rdesc, a16_eckb_report_desc, 144));
    CHECK(DEV.stats.transfer_errors == 0 && BUS.stats.cancels == 0);
    CHECK(i2c_hid_step(&DEV) == I2C_HID_NO_WAKE);    /* READY waits for publication */
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK && DEV.state == I2C_HID_S_RUNNING);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_NOT_READY);
    check_clean();

    /* Identity: a different product is refused before any command is sent. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    DEV.cfg.expect_product = 0x4b43;
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_IDENTITY);
    CHECK(M.nlog == 2 && KBD.power_on == 0 && KBD.resets == 0);
}

static void test_keyboard_input(void)
{
    static const uint8_t press_a[] = {0x36, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0};
    static const uint8_t shift_a[] = {0x36, 0x02, 0x00, 0x04, 0, 0, 0, 0, 0};
    static const uint8_t release[] = {0x36, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0};
    static const uint8_t volume_up[] = {0x37, 0xe9, 0x00};
    static const uint8_t vendor[] = {0x5a, 0xc4, 0, 0, 0, 0};
    uint32_t reads;

    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    poll_ticks(&DEV, 5);                             /* idle: empty reads */
    CHECK(ndelivered == 0 && DEV.stats.empty == 5 && DEV.stats.polls == 5);
    reads = KBD.plain_reads;
    dev_push(&KBD, press_a, sizeof(press_a));
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 1 && delivered_len[0] == 9 && !memcmp(delivered[0], press_a, 9));
    CHECK(KBD.plain_reads == reads + 2);             /* the report, then empty */
    dev_push(&KBD, shift_a, sizeof(shift_a));
    dev_push(&KBD, release, sizeof(release));
    dev_push(&KBD, volume_up, sizeof(volume_up));
    poll_ticks(&DEV, 1);                             /* drained in one tick */
    CHECK(ndelivered == 4);
    CHECK(!memcmp(delivered[1], shift_a, 9) && !memcmp(delivered[2], release, 9));
    CHECK(delivered_len[3] == 3 && !memcmp(delivered[3], volume_up, 3));
    for (int i = 0; i < 6; i++)
        dev_push(&KBD, release, sizeof(release));
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 8 && DEV.stats.identical >= 3);   /* four per tick, repeats counted */
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 10);
    dev_push(&KBD, vendor, sizeof(vendor));
    poll_ticks(&DEV, 2);
    CHECK(ndelivered == 11 && delivered_len[10] == 6 && delivered[10][0] == 0x5a);
    CHECK(DEV.stats.reports == 11 && DEV.stats.transfer_errors == 0);
    CHECK(BUS.stats.cancels == 0 && BUS.stats.aborts == 0);
    check_clean();

    /* Keys pressed during reset are not reported before RDESC; reports queued
     * after the device returns are. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_RESET_WAIT, 64);
    advance_us(50000);
    dev_push(&KBD, press_a, sizeof(press_a));        /* while the sentinel is pending */
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY && DEV.stats.early_reports == 0);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 1 && !memcmp(delivered[0], press_a, 9));
    check_clean();
}

static void test_input_rejects(void)
{
    static const uint8_t bad_id[] = {0x05, 0x00, 0x40, 0x00, 0x00};
    static const uint8_t short_kbd[] = {0x0a, 0x00, 0x36, 0, 0, 4, 0, 0, 0, 0};
    static const uint8_t one[] = {0x01, 0x00};
    static const uint8_t huge[] = {0x41, 0x00};
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    dev_push_raw(&KBD, bad_id, sizeof(bad_id));
    poll_ticks(&DEV, 1);
    dev_push_raw(&KBD, short_kbd, sizeof(short_kbd));
    poll_ticks(&DEV, 1);
    dev_push_raw(&KBD, one, sizeof(one));
    poll_ticks(&DEV, 1);
    dev_push_raw(&KBD, huge, sizeof(huge));
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 0);
    CHECK(DEV.stats.unknown_id == 1 && DEV.stats.wrong_size == 1 && DEV.stats.bad_length == 2);
    CHECK(DEV.rejected_len == 64 && DEV.rejected[0] == 0x41);
    KBD.bogus_when_empty = 1;
    poll_ticks(&DEV, 3);
    CHECK(DEV.stats.bogus == 3 && ndelivered == 0);
    /* A device that repeats its last report when idle is visible in stats. */
    KBD.bogus_when_empty = 0;
    KBD.repeat_when_empty = 1;
    dev_push(&KBD, (const uint8_t *)"\x36\x00\x00\x04\x00\x00\x00\x00\x00", 9);
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 4 && DEV.stats.identical == 3);
    check_clean();
}

static void test_touchpad(void)
{
    static const uint8_t mouse[] = {0x01, 0x01, 0x05, 0xfb};
    static const uint8_t contact[] = {0x03, 0x03, 0x00, 0x34, 0x02, 0x10, 0x01, 0x20, 0x4e, 0x01};
    struct i2c_hid_config cfg;
    model_reset();
    ndelivered = 0;
    M.devs[0x15] = NULL;
    add_touchpad(0x15);
    start_bus(GENI_I2C_IRQ_EVENTS);
    i2c_hid_default_config(&cfg, 0x15, 1);
    CHECK(i2c_hid_begin(&DEV, &BUS, &cfg, deliver, NULL) == I2C_HID_R_OK);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY && DEV.desc.max_input == 14);
    CHECK(DEV.rinfo.napps == 2 && DEV.rinfo.apps[1].page == 0x0d);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    dev_push(&TPAD, mouse, sizeof(mouse));
    dev_push(&TPAD, contact, sizeof(contact));
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 2 && delivered_len[0] == 4 && delivered_len[1] == 10);
    CHECK(!memcmp(delivered[0], mouse, 4) && !memcmp(delivered[1], contact, 10));
    CHECK(M.log[M.nlog - 1].len == 14);              /* reads wMaxInputLength */
    check_clean();
}

static void test_nack_paths(void)
{
    uint8_t buf[64];
    /* Address NACK that completes: no cancel, clean engine. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    KBD.nack_next = 1;
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_NACK);
    CHECK(!M.active && M.rxn == 0 && BUS.stats.cancels == 0 && M.idle_ctrl == 0);
    CHECK(!(M.irq_status & GENI_IRQ_ERRORS));
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_OK);
    CHECK(geni_i2c_read(&BUS, 0x16, buf, 4) == GENI_I2C_NACK);  /* nobody there */
    check_clean();

    /* NACK leaving the engine active: cancel returns it to idle. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    M.nack_without_done = 1;
    KBD.nack_next = 1;
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 11) == GENI_I2C_NACK);
    CHECK(!M.active && M.cancels == 1 && M.aborts == 0 && BUS.stats.cancels == 1);
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 11) == GENI_I2C_OK);
    check_clean();

    /* Write NACK, engine idle, hardware discards unsent words: usable. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    KBD.nack_next_write = 1;
    CHECK(geni_i2c_write(&BUS, 0x15, (const uint8_t *)"\5\0\0\x08", 4, 0) == GENI_I2C_NACK);
    CHECK(!BUS.wedged && M.txn == 0);
    CHECK(geni_i2c_write(&BUS, 0x15, (const uint8_t *)"\5\0\0\x08", 4, 0) == GENI_I2C_OK);
    check_clean();

    /* Write NACK, engine idle, words retained: wedge, never write again. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    M.tx_retained_after_nack = 1;
    KBD.nack_next_write = 1;
    CHECK(geni_i2c_write(&BUS, 0x15, (const uint8_t *)"\5\0\0\x08", 4, 0) == GENI_I2C_WEDGED);
    CHECK(BUS.wedged && M.txn == 1 && M.idle_ctrl == 0);
    {
        uint32_t writes = M.mmio_writes;
        CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_WEDGED);
        CHECK(geni_i2c_stop(&BUS) == GENI_I2C_WEDGED);
        CHECK(M.mmio_writes == writes);
    }

    /* Same, but the NACK leaves the engine active and cancel flushes it. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    M.tx_retained_after_nack = 1;
    M.nack_without_done = 1;
    KBD.nack_next_write = 1;
    CHECK(geni_i2c_write(&BUS, 0x15, (const uint8_t *)"\5\0\0\x08", 4, 0) == GENI_I2C_NACK);
    CHECK(!BUS.wedged && M.txn == 0 && M.cancels == 1);
    check_clean();
}

static void test_timeouts(void)
{
    uint8_t buf[64];
    uint64_t t0;
    /* Cancel suffices. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    M.stall_forever = 1;
    t0 = M.now_ns;
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_TIMEOUT);
    CHECK(M.now_ns - t0 >= 100000000ull && M.now_ns - t0 < 200000000ull);
    CHECK(!M.active && M.cancels == 1 && M.aborts == 0);
    M.stall_forever = 0;
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_OK);
    check_clean();
    /* Cancel ignored, abort works. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    M.stall_forever = 1;
    M.cancel_works = 0;
    CHECK(geni_i2c_write(&BUS, 0x15, (const uint8_t *)"\5\0\0\1", 4, 0) == GENI_I2C_TIMEOUT);
    CHECK(!M.active && M.cancels == 1 && M.aborts == 1 && !BUS.wedged && M.txn == 0);
    check_clean();
    /* Neither works: wedged, and no further MMIO writes. */
    model_reset();
    start_bus(GENI_I2C_IRQ_EVENTS);
    M.stall_forever = 1;
    M.cancel_works = 0;
    M.abort_works = 0;
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_WEDGED);
    CHECK(BUS.wedged && M.active);
    {
        uint32_t writes = M.mmio_writes;
        CHECK(geni_i2c_write(&BUS, 0x15, (const uint8_t *)"\1\0", 2, 1) == GENI_I2C_WEDGED);
        CHECK(M.mmio_writes == writes);
    }
}

static void test_short_excess_errors(void)
{
    uint8_t sel[2] = {1, 0}, buf[64];
    struct { uint32_t short_at, nolast, excess, bad_last, on_done, late; int expect; } cases[] = {
        {5, 0, 0, 0, 0, 0, GENI_I2C_SHORT},        /* early LAST */
        {8, 1, 0, 0, 0, 0, GENI_I2C_SHORT},        /* early DONE, no LAST flag */
        {0, 0, 1, 0, 0, 0, GENI_I2C_EXCESS},
        {0, 0, 0, 3, 0, 0, GENI_I2C_EXCESS},       /* 30 bytes end with 2, not 3 */
        {0, 0, 0, 0, GENI_IRQ_BUS_PROTO, 0, GENI_I2C_BUS_ERROR},
        {0, 0, 0, 0, GENI_IRQ_ARB_LOST, 0, GENI_I2C_BUS_ERROR},
        {0, 0, 0, 0, GENI_IRQ_RX_WR_ERR, 0, GENI_I2C_CONTROLLER},
        {0, 0, 0, 0, GENI_IRQ_OVERRUN, 0, GENI_I2C_CONTROLLER},
        {0, 0, 0, 0, 0, GENI_IRQ_FAILURE, GENI_I2C_CONTROLLER},   /* after DONE */
        {0, 0, 0, 0, 0, GENI_IRQ_NACK, GENI_I2C_NACK},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        model_reset();
        start_bus(GENI_I2C_IRQ_EVENTS);
        CHECK(geni_i2c_write(&BUS, 0x15, sel, 2, 1) == GENI_I2C_OK);
        M.short_read_at = cases[i].short_at;
        M.short_without_last = cases[i].nolast;
        M.excess_words = cases[i].excess;
        M.bad_last_bytes = cases[i].bad_last;
        M.inject_on_done = cases[i].on_done;
        M.inject_late = cases[i].late;
        CHECK(geni_i2c_read(&BUS, 0x15, buf, 30) == cases[i].expect);
        CHECK(!M.active && M.rxn == 0 && !BUS.wedged);   /* failed words discarded */
        CHECK(!(M.irq_status & GENI_IRQ_ERRORS));
        if (cases[i].late)
            CHECK(BUS.stats.late_errors == 1);
        M.short_read_at = 0;
        M.short_without_last = 0;
        M.excess_words = 0;
        M.bad_last_bytes = 0;
        M.inject_on_done = 0;
        M.inject_late = 0;
        CHECK(geni_i2c_write(&BUS, 0x15, sel, 2, 1) == GENI_I2C_OK);
        CHECK(geni_i2c_read(&BUS, 0x15, buf, 30) == GENI_I2C_OK &&
              !memcmp(buf, a16_eckb_hid_desc, 30));
        check_clean();
    }
    /* An aligned final word may report 0 or 4 valid bytes. */
    for (uint32_t mode = 0; mode <= 4; mode += 4) {
        model_reset();
        M.zero_last_mode = mode;
        start_bus(GENI_I2C_IRQ_EVENTS);
        CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_OK);
    }
    /* Arguments. */
    CHECK(geni_i2c_read(&BUS, 0x80, buf, 4) == GENI_I2C_INVALID);
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 0) == GENI_I2C_INVALID);
    CHECK(geni_i2c_write(&BUS, 0x15, buf, 129, 0) == GENI_I2C_INVALID);
}

static void test_irq_policy(void)
{
    uint8_t buf[64];
    /* Masked enables work when status latches regardless of enables. */
    begin_keyboard(GENI_I2C_IRQ_MASKED);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY && M.irq_en == 0);
    /* If status only shows enabled bits, masked transfers time out cleanly
     * (the command still finished on the bus, so nothing is wedged). */
    model_reset();
    M.status_requires_enable = 1;
    start_bus(GENI_I2C_IRQ_MASKED);
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_TIMEOUT);
    CHECK(!BUS.wedged && !M.active && M.rxn == 0 && M.cancels == 0);
    /* With EVENTS the same engine works. */
    model_reset();
    M.status_requires_enable = 1;
    start_bus(GENI_I2C_IRQ_EVENTS);
    CHECK(geni_i2c_read(&BUS, 0x15, buf, 64) == GENI_I2C_OK);
    check_clean();
}

static void test_reset_and_power_quirks(void)
{
    /* The device NACKs while resetting for longer than the settle time. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    KBD.reset_ns = 250000000ull;
    KBD.nack_while_resetting = 1;
    run_until(&DEV, I2C_HID_S_READY, 256);
    CHECK(DEV.state == I2C_HID_S_READY && DEV.stats.reset_retries >= 10);
    check_clean();
    /* It never comes back: FAILED(reset) after about one second. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    KBD.never_back = 1;
    run_until(&DEV, I2C_HID_S_READY, 512);
    CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_RESET);
    CHECK(DEV.failed_in == I2C_HID_S_RESET_WAIT);
    check_clean();
    /* First SET_POWER NACKed (a sleeping device): one retry after 500 us. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_POWER_ON, 64);
    KBD.nack_next_write = 1;
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY && KBD.power_on == 2 && DEV.stats.nacks == 1);
    CHECK(DEV.stats.transfer_errors == 0 && DEV.init_errors == 0);
    CHECK(M.log[2].nacked && M.log[3].at_ns - M.log[2].at_ns >= 500000u);
    check_clean();
    /* Persistent init failure: bounded retries, then FAILED. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    KBD.nack_until_ns_valid = 1;
    KBD.nack_until_ns = ~0ull;
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_INIT_ERRORS);
    CHECK(DEV.stats.transfer_errors == 4);
    check_clean();
    /* A device whose descriptor is not the HID 1.00 layout. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    {
        static uint8_t broken[30];
        memcpy(broken, a16_eckb_hid_desc, 30);
        broken[3] = 0;                               /* bcdVersion 0x0000 */
        KBD.desc = broken;
        run_until(&DEV, I2C_HID_S_READY, 64);
        CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_DESCRIPTOR);
    }
}

static void test_reinitialisation(void)
{
    static const uint8_t press_a[] = {0x36, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0};
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    /* Eight consecutive failed polls: re-initialise, then keep running. */
    KBD.nack_next = 8;
    poll_ticks(&DEV, 8);
    CHECK(DEV.state == I2C_HID_S_DESC && DEV.stats.reinits == 1);
    run_until(&DEV, I2C_HID_S_RUNNING, 64);
    CHECK(DEV.state == I2C_HID_S_RUNNING && KBD.resets == 2);
    dev_push(&KBD, press_a, sizeof(press_a));
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 1);
    check_clean();
    /* A different device answers after re-initialisation: refuse it. */
    {
        static uint8_t other[30];
        memcpy(other, a16_eckb_hid_desc, 30);
        other[22] = 0x43;                            /* product 0x4b43 */
        KBD.nack_next = 8;
        KBD.desc = other;
        poll_ticks(&DEV, 8);
        run_until(&DEV, I2C_HID_S_RUNNING, 64);
        CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_IDENTITY);
    }
    /* Same product, changed report descriptor: refused, published copy kept. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    DEV.cfg.expect_product = 0;
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    {
        static uint8_t changed[144];
        memcpy(changed, a16_eckb_report_desc, 144);
        changed[143 - 3] = 0x02;
        KBD.rdesc = changed;
        KBD.nack_next = 8;
        poll_ticks(&DEV, 8);
        run_until(&DEV, I2C_HID_S_RUNNING, 64);
        CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_IDENTITY);
        CHECK(!memcmp(DEV.rdesc, a16_eckb_report_desc, 144));
    }
    /* Too many re-initialisations. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    DEV.cfg.max_reinit = 1;
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    for (int round = 0; round < 2; round++) {
        KBD.nack_next = 8;
        poll_ticks(&DEV, 8);
        run_until(&DEV, I2C_HID_S_RUNNING, 64);
    }
    CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_REINIT);
    check_clean();
    /* A wedged controller fails the device with no further MMIO writes. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    M.stall_forever = 1;
    M.cancel_works = 0;
    M.abort_works = 0;
    poll_ticks(&DEV, 1);
    CHECK(DEV.state == I2C_HID_S_FAILED && DEV.failure == I2C_HID_F_BUS);
    {
        uint32_t writes = M.mmio_writes;
        CHECK(i2c_hid_step(&DEV) == I2C_HID_NO_WAKE);
        CHECK(i2c_hid_send_output(&DEV, (const uint8_t *)"\x36\x02", 2) == I2C_HID_R_NOT_READY);
        CHECK(M.mmio_writes == writes);
    }
}

static void test_attention(void)
{
    static const uint8_t press_a[] = {0x36, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0};
    uint32_t reads;
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    i2c_hid_set_attention(&DEV, attention, &KBD);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY && DEV.stats.reset_acks == 1);
    CHECK(DEV.stats.reset_without_attention == 0);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    reads = KBD.plain_reads;
    poll_ticks(&DEV, 20);
    CHECK(KBD.plain_reads == reads && DEV.stats.attention_skips == 20);   /* no bus traffic */
    dev_push(&KBD, press_a, sizeof(press_a));
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 1 && KBD.plain_reads == reads + 1);
    check_clean();
    /* A line that never asserts: proceed after the deadline, like Linux. */
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    KBD.reset_ns = 5000000000ull;
    i2c_hid_set_attention(&DEV, attention, &KBD);
    run_until(&DEV, I2C_HID_S_READY, 256);
    CHECK(DEV.state == I2C_HID_S_READY && DEV.stats.reset_without_attention == 1);
    check_clean();
}

static void test_requests(void)
{
    uint8_t buf[64];
    uint32_t got = 99;
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    CHECK(i2c_hid_send_output(&DEV, (const uint8_t *)"\x36\x02", 2) == I2C_HID_R_NOT_READY);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    /* Caps Lock LED through the output register, the 6-byte write UEFI left. */
    CHECK(i2c_hid_send_output(&DEV, (const uint8_t *)"\x36\x02", 2) == I2C_HID_R_OK);
    CHECK(KBD.leds == 2 && KBD.outputs == 1 && M.tx_len == 6);
    CHECK(!memcmp(M.log[M.nlog - 1].data, "\x04\x00\x04\x00\x36\x02", 6));
    CHECK(i2c_hid_send_output(&DEV, (const uint8_t *)"\x36\x02\x00", 3) == I2C_HID_R_INVALID);
    CHECK(i2c_hid_send_output(&DEV, (const uint8_t *)"\x37\x02", 2) == I2C_HID_R_INVALID);
    /* GET_REPORT(input 54) as generation59 ran it: the device's empty answer. */
    CHECK(i2c_hid_get_report(&DEV, I2C_HID_TYPE_INPUT, 54, buf, sizeof(buf), &got) ==
          I2C_HID_R_EMPTY && got == 0);
    CHECK(!memcmp(M.log[M.nlog - 2].data, "\x05\x00\x1f\x02\x36\x06\x00", 7));
    CHECK(M.log[M.nlog - 2].stretch && M.log[M.nlog - 1].len == 11);
    CHECK(!memcmp(M.log[M.nlog - 1].data, a16_eckb_get_report_54, 11));
    /* A device that does return its state. */
    memcpy(KBD.get_report, "\x0b\x00\x36\x02\x00\x04\x00\x00\x00\x00\x00", 11);
    CHECK(i2c_hid_get_report(&DEV, I2C_HID_TYPE_INPUT, 54, buf, sizeof(buf), &got) ==
          I2C_HID_R_OK && got == 9 && buf[1] == 2 && buf[3] == 4);
    memcpy(KBD.get_report, "\x0b\x00\x37\x02\x00\x04\x00\x00\x00\x00\x00", 11);
    CHECK(i2c_hid_get_report(&DEV, I2C_HID_TYPE_INPUT, 54, buf, sizeof(buf), &got) ==
          I2C_HID_R_BAD_RESPONSE);
    /* Feature 90 is 64 bytes; SET_REPORT through the command register. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x5a;
    CHECK(i2c_hid_set_report(&DEV, I2C_HID_TYPE_FEATURE, buf, 64) == I2C_HID_R_OK);
    CHECK(KBD.set_reports == 1 && M.log[M.nlog - 1].len == 5 + 2 + 66);
    CHECK(i2c_hid_get_report(&DEV, I2C_HID_TYPE_FEATURE, 91, buf, sizeof(buf), &got) ==
          I2C_HID_R_INVALID);
    CHECK(DEV.state == I2C_HID_S_RUNNING);
    check_clean();
}

/* The real A16 touchpad (2808:0219, generation 33): its report descriptor declares a 64-byte vendor
 * input report 6 beside wMaxInputLength 52. The old rule (every declared input report must fit)
 * failed it in report-descriptor; now it initialises, counts the one oversize report, reads 52-byte
 * input, and its mouse collection (report 1: two buttons, 8-bit X/Y, 8-bit wheel) drives the pointer. */
static void test_a16_touchpad(void)
{
    struct i2c_hid_desc d;
    struct i2c_hid_config cfg;
    struct hid_pointer_layout l;
    struct hid_pointer_state st = {0};
    static const uint8_t mouse[5] = {0x01, 0x01, 0x05, 0xfb, 0xff};
    CHECK(i2c_hid_parse_desc(a16_tpad_hid_desc, 30, &d) == I2C_HID_DESC_OK);
    CHECK(d.vendor_id == 0x2808 && d.product_id == 0x0219 && d.max_input == 52 && d.rdesc_length == 764 &&
          d.rdesc_register == 2 && d.input_register == 3 && d.max_output == 66 && d.device_version == 0x501);
    CHECK(hid_pointer_layout(a16_tpad_report_desc, sizeof(a16_tpad_report_desc), &l) == HID_POINTER_OK);
    CHECK(l.report_id == 1 && l.report_bytes == 5 && l.buttons == 2 && l.buttons_offset == 0);
    CHECK(l.x.offset == 8 && l.x.size == 8 && l.x.is_signed && l.y.offset == 16 && l.y.size == 8);
    CHECK(l.wheel.offset == 24 && l.wheel.size == 8 && l.wheel.is_signed && !l.pan.size);
    model_reset();
    ndelivered = 0;
    M.devs[0x15] = NULL;
    dev_init(&TPAD, 0x15, a16_tpad_hid_desc, a16_tpad_report_desc, sizeof(a16_tpad_report_desc));
    M.devs[0x15] = &TPAD;
    start_bus(GENI_I2C_IRQ_MASKED);
    i2c_hid_default_config(&cfg, 0x15, 1);
    cfg.expect_vendor = 0x2808;
    cfg.expect_product = 0x0219;
    CHECK(i2c_hid_begin(&DEV, &BUS, &cfg, deliver, NULL) == I2C_HID_R_OK);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY && DEV.rdesc_len == 764 && DEV.stats.oversize_inputs == 1);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    dev_push(&TPAD, mouse, sizeof(mouse));
    poll_ticks(&DEV, 1);
    CHECK(ndelivered == 1 && delivered_len[0] == 5 && !memcmp(delivered[0], mouse, 5));
    CHECK(M.log[M.nlog - 1].len == 52);                /* reads wMaxInputLength */
    npmove = npscroll = 0;
    CHECK(hid_pointer_translate(&l, &st, delivered[0], delivered_len[0], p_move, p_scroll, NULL) == HID_POINTER_EVENTS);
    CHECK(npmove == 1 && pmove[0][0] == 5 && pmove[0][1] == -5 && pmove[0][2] == 1);
    CHECK(npscroll == 1 && pscroll[0][0] == -1 && pscroll[0][1] == 0);
    check_clean();
}

/* -- Precision Touchpad (failure modes F1-F22, docs/A16-INPUT-PTP-20261020.md) ------------------ */

/* The A16's input report 4, encoded from its decoded descriptor (work/touchpad-rdesc.txt), not from
 * the parser: five 40-bit fingers from bit 0 (Confidence bit 0, Tip Switch bit 1, Contact ID bits
 * 4-7, X bits 8-23, Y bits 24-39), Scan Time at bit 200, Contact Count at 216, Button 1 at 224. */
struct tc { uint8_t conf, tip, id; uint16_t x, y; };
#define A16_PTP_BYTES 50u

static uint32_t a16_frame(uint8_t *r, const struct tc *c, unsigned n, unsigned count, unsigned scan,
                          unsigned button)
{
    REQUIRE(n <= 5);
    memset(r, 0, A16_PTP_BYTES);
    r[0] = 4;
    for (unsigned i = 0; i < n; i++) {
        uint8_t *f = r + 1 + 5 * i;
        f[0] = (uint8_t)((c[i].conf ? 1u : 0u) | (c[i].tip ? 2u : 0u) | (uint8_t)(c[i].id << 4));
        f[1] = (uint8_t)c[i].x;
        f[2] = (uint8_t)(c[i].x >> 8);
        f[3] = (uint8_t)c[i].y;
        f[4] = (uint8_t)(c[i].y >> 8);
    }
    r[26] = (uint8_t)scan;
    r[27] = (uint8_t)(scan >> 8);
    r[28] = (uint8_t)count;
    r[29] = (uint8_t)(button & 1u);
    return A16_PTP_BYTES;
}

struct pev { char kind; int32_t a, b; uint32_t c; };
static struct pev pev[8192];
static unsigned npev;

static void ptp_ptr(void *ctx, int32_t dx, int32_t dy, uint32_t buttons)
{
    (void)ctx;
    REQUIRE(npev < 8192);
    pev[npev++] = (struct pev){'p', dx, dy, buttons};
}

static void ptp_scr(void *ctx, int32_t v, int32_t h, uint32_t options)
{
    (void)ctx;
    REQUIRE(npev < 8192);
    pev[npev++] = (struct pev){'s', v, h, options};
}

static const struct hid_ptp_sink PSINK = {NULL, ptp_ptr, ptp_scr, NULL};
static struct hid_ptp_layout PL;
static struct hid_ptp_engine PE;
static uint64_t pnow, plast_key;
static unsigned pscan;

static void ptp_begin_layout(const struct hid_ptp_layout *l)
{
    hid_ptp_engine_init(&PE, l);
    npev = 0;
    pnow = 5000000;
    pscan = 1000;
    plast_key = 0;
}

static void ptp_begin(void)
{
    CHECK(hid_ptp_layout(a16_tpad_report_desc, sizeof(a16_tpad_report_desc), &PL) == HID_PTP_OK);
    ptp_begin_layout(&PL);
}

/* One A16 frame 8 ms (and 80 scan units) after the last. Contact Count = slots used. */
static int frame(const struct tc *c, unsigned n, unsigned button)
{
    uint8_t r[64];
    pnow += 8000;
    pscan = (pscan + 80u) & 0xffffu;
    a16_frame(r, c, n, n, pscan, button);
    return hid_ptp_engine_report(&PE, r, A16_PTP_BYTES, pnow, plast_key, &PSINK);
}

static void tick(uint64_t us)
{
    pnow += us;
    hid_ptp_engine_tick(&PE, pnow, &PSINK);
}

/* Q16 output units per count, from the descriptor's physical extents (147.5 x 96.0 mm). */
static int64_t q16(int64_t counts, int y)
{
    double um = y ? 96000.0 / 3099.0 : 147500.0 / 4762.0;
    return (int64_t)(counts * um * 400.0 / 25400.0 * 65536.0);
}

static int near(int64_t got, int64_t want, int64_t tolerance)
{
    return got - want <= tolerance && want - got <= tolerance;
}

static unsigned n_kind(char kind, unsigned from)
{
    unsigned n = 0;
    for (unsigned i = from; i < npev; i++)
        n += pev[i].kind == kind;
    return n;
}

static int64_t sum_of(char kind, int second, unsigned from)
{
    int64_t s = 0;
    for (unsigned i = from; i < npev; i++)
        if (pev[i].kind == kind)
            s += second ? pev[i].b : pev[i].a;
    return s;
}

static unsigned n_opt(uint32_t option, unsigned from)
{
    unsigned n = 0;
    for (unsigned i = from; i < npev; i++)
        n += pev[i].kind == 's' && (pev[i].c & option);
    return n;
}

static int last_is(char kind, int32_t a, int32_t b, uint32_t c)
{
    return npev && pev[npev - 1].kind == kind && pev[npev - 1].a == a && pev[npev - 1].b == b &&
           pev[npev - 1].c == c;
}

/* -- synthetic descriptors: the same collections, one property changed at a time -- */
struct rd { uint8_t b[2048]; uint32_t n; };

static void rd(struct rd *r, uint8_t prefix, uint32_t v, unsigned size)
{
    static const uint8_t code[5] = {0, 1, 2, 0, 3};
    REQUIRE((size <= 2 || size == 4) && r->n + 1 + size <= sizeof(r->b));
    r->b[r->n++] = (uint8_t)(prefix | code[size]);
    for (unsigned i = 0; i < size; i++)
        r->b[r->n++] = (uint8_t)(v >> (8 * i));
}

struct syn { unsigned fingers; int conf, tip, mode, rel, units, count, drop_end; };

/* Report 4: per finger a byte (bit 0 Tip Switch, bit 1 Confidence, else padding), an 8-bit Contact
 * ID, 16-bit X (0..1000 over 100 mm) and Y (0..600 over 60 mm); then 16-bit Scan Time, an 8-bit
 * Contact Count (when count), Button 1 and 7 padding bits. Features 2 (caps), 3 (Input Mode) and 5
 * (Surface/Button Switch) when mode. */
static void syn_ptp(struct rd *r, const struct syn *o)
{
    r->n = 0;
    rd(r, 0x04, 0x0d, 1); rd(r, 0x08, 0x05, 1); rd(r, 0xa0, 1, 1);
    rd(r, 0x84, 4, 1);
    for (unsigned f = 0; f < o->fingers; f++) {
        rd(r, 0x04, 0x0d, 1); rd(r, 0x08, 0x22, 1); rd(r, 0xa0, 2, 1);
        rd(r, 0x14, 0, 1); rd(r, 0x24, 1, 1); rd(r, 0x74, 1, 1); rd(r, 0x94, 1, 1);
        if (o->tip) { rd(r, 0x08, 0x42, 1); rd(r, 0x80, 0x02, 1); } else rd(r, 0x80, 0x03, 1);
        if (o->conf) { rd(r, 0x08, 0x47, 1); rd(r, 0x80, 0x02, 1); } else rd(r, 0x80, 0x03, 1);
        rd(r, 0x94, 6, 1); rd(r, 0x80, 0x03, 1);
        rd(r, 0x08, 0x51, 1); rd(r, 0x24, 15, 1); rd(r, 0x74, 8, 1); rd(r, 0x94, 1, 1); rd(r, 0x80, 0x02, 1);
        rd(r, 0xa4, 0, 0);                                   /* Push: units only for X and Y */
        rd(r, 0x04, 0x01, 1); rd(r, 0x74, 16, 1);
        if (o->units) { rd(r, 0x54, 0x0e, 1); rd(r, 0x64, 0x11, 1); rd(r, 0x34, 0, 1); }
        rd(r, 0x08, 0x30, 1); rd(r, 0x24, 1000, 2);
        if (o->units) rd(r, 0x44, 1000, 2);
        rd(r, 0x80, o->rel ? 0x06 : 0x02, 1);
        rd(r, 0x08, 0x31, 1); rd(r, 0x24, 600, 2);
        if (o->units) rd(r, 0x44, 600, 2);
        rd(r, 0x80, o->rel ? 0x06 : 0x02, 1);
        rd(r, 0xb4, 0, 0);                                   /* Pop */
        rd(r, 0xc0, 0, 0);
    }
    rd(r, 0x04, 0x0d, 1); rd(r, 0x08, 0x56, 1); rd(r, 0x14, 0, 1); rd(r, 0x24, 65535, 4);
    rd(r, 0x74, 16, 1); rd(r, 0x94, 1, 1); rd(r, 0x80, 0x02, 1);
    if (o->count) { rd(r, 0x08, 0x54, 1); rd(r, 0x24, 10, 1); rd(r, 0x74, 8, 1); rd(r, 0x80, 0x02, 1); }
    rd(r, 0x04, 0x09, 1); rd(r, 0x08, 0x01, 1); rd(r, 0x24, 1, 1); rd(r, 0x74, 1, 1); rd(r, 0x80, 0x02, 1);
    rd(r, 0x94, 7, 1); rd(r, 0x80, 0x03, 1);
    rd(r, 0x84, 2, 1); rd(r, 0x04, 0x0d, 1); rd(r, 0x08, 0x55, 1); rd(r, 0x08, 0x59, 1);
    rd(r, 0x24, 15, 1); rd(r, 0x74, 4, 1); rd(r, 0x94, 2, 1); rd(r, 0xb0, 0x02, 1);
    rd(r, 0xc0, 0, 0);
    if (o->mode) {
        rd(r, 0x04, 0x0d, 1); rd(r, 0x08, 0x0e, 1); rd(r, 0xa0, 1, 1);
        rd(r, 0x84, 3, 1); rd(r, 0x08, 0x52, 1); rd(r, 0x24, 10, 1); rd(r, 0x74, 8, 1); rd(r, 0x94, 1, 1);
        rd(r, 0xb0, 0x02, 1);
        rd(r, 0x84, 5, 1); rd(r, 0x08, 0x57, 1); rd(r, 0x08, 0x58, 1); rd(r, 0x24, 1, 1); rd(r, 0x74, 1, 1);
        rd(r, 0x94, 2, 1); rd(r, 0xb0, 0x02, 1); rd(r, 0x94, 6, 1); rd(r, 0xb0, 0x03, 1);
        rd(r, 0xc0, 0, 0);
    }
    if (o->drop_end)
        r->n--;                                              /* the last End Collection */
}

static const struct syn SYN = {2, 1, 1, 1, 0, 1, 1, 0};

/* A frame of the synthetic layout; conf is ignored when the layout has no Confidence. */
static int syn_frame(const struct syn *o, const struct tc *c, unsigned n, unsigned count, unsigned button)
{
    uint8_t r[128];
    uint32_t at = 1;
    REQUIRE(n <= o->fingers);
    memset(r, 0, sizeof(r));
    r[0] = 4;
    for (unsigned i = 0; i < o->fingers; i++, at += 6) {
        if (i >= n)
            continue;
        r[at] = (uint8_t)((c[i].tip ? 1u : 0u) | (c[i].conf ? 2u : 0u));
        r[at + 1] = c[i].id;
        r[at + 2] = (uint8_t)c[i].x;
        r[at + 3] = (uint8_t)(c[i].x >> 8);
        r[at + 4] = (uint8_t)c[i].y;
        r[at + 5] = (uint8_t)(c[i].y >> 8);
    }
    pnow += 8000;
    pscan = (pscan + 80u) & 0xffffu;
    r[at++] = (uint8_t)pscan;
    r[at++] = (uint8_t)(pscan >> 8);
    if (o->count)
        r[at++] = (uint8_t)count;
    r[at++] = (uint8_t)(button & 1u);
    return hid_ptp_engine_report(&PE, r, at, pnow, plast_key, &PSINK);
}

/* F14: the layout from the device's own descriptor, and every refusal by name. */
static void test_ptp_layout(void)
{
    struct hid_ptp_layout l;
    struct rd r;
    struct syn o;
    CHECK(hid_ptp_layout(a16_tpad_report_desc, sizeof(a16_tpad_report_desc), &l) == HID_PTP_OK);
    CHECK(l.report_id == 4 && l.report_bytes == 50 && l.fingers == 5 && l.has_confidence);
    for (unsigned i = 0; i < 5; i++) {
        const struct hid_ptp_finger *f = &l.finger[i];
        CHECK(f->confidence.offset == 40 * i && f->confidence.size == 1);
        CHECK(f->tip.offset == 40 * i + 1 && f->tip.size == 1);
        CHECK(f->id.offset == 40 * i + 4 && f->id.size == 4 && f->id.max == 5);
        CHECK(f->x.offset == 40 * i + 8 && f->x.size == 16 && f->x.min == 0 && f->x.max == 4762);
        CHECK(f->y.offset == 40 * i + 24 && f->y.size == 16 && f->y.min == 0 && f->y.max == 3099);
    }
    CHECK(l.scan_time.offset == 200 && l.scan_time.size == 16);
    CHECK(l.contact_count.offset == 216 && l.contact_count.size == 8 && l.contact_count.max == 5);
    CHECK(l.buttons == 1 && l.button[0].offset == 224 && l.button[0].size == 1);
    CHECK(l.width_um == 147500 && l.height_um == 96000);
    CHECK(l.x_min == 0 && l.x_max == 4762 && l.y_min == 0 && l.y_max == 3099);
    CHECK(l.input_mode.report_id == 3 && l.input_mode.report_bytes == 2 && l.input_mode.field.offset == 0 &&
          l.input_mode.field.size == 8 && l.input_mode.field.max == 10);
    CHECK(l.surface_switch.report_id == 5 && l.surface_switch.field.offset == 0 && l.surface_switch.field.size == 1);
    CHECK(l.button_switch.report_id == 5 && l.button_switch.field.offset == 1 && l.button_switch.field.size == 1);
    CHECK(l.contact_max.report_id == 2 && l.contact_max.field.offset == 0 && l.contact_max.field.size == 4);
    CHECK(l.pad_type.report_id == 2 && l.pad_type.field.offset == 4 && l.pad_type.field.size == 4);
    CHECK(l.blob.report_id == 8 && l.blob.report_bytes == 257);
    /* F15: the keyboard's descriptor has no touch pad, and neither has a mouse-only one. */
    CHECK(hid_ptp_layout(a16_eckb_report_desc, sizeof(a16_eckb_report_desc), &l) == HID_PTP_NO_TOUCHPAD);
    /* The older synthetic touchpad: one finger, no Device Configuration collection. */
    CHECK(hid_ptp_layout(synthetic_tpad_report_desc, sizeof(synthetic_tpad_report_desc), &l) ==
          HID_PTP_NO_INPUT_MODE);
    /* Truncated anywhere: malformed, never a partial layout. */
    for (uint32_t cut = 1; cut < sizeof(a16_tpad_report_desc); cut += 37)
        CHECK(hid_ptp_layout(a16_tpad_report_desc, cut, &l) != HID_PTP_OK);
    CHECK(hid_ptp_layout(a16_tpad_report_desc, 0x283, &l) == HID_PTP_MALFORMED);
    CHECK(hid_ptp_layout(NULL, 10, &l) == HID_PTP_MALFORMED);
    o = SYN; syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_OK && l.fingers == 2 && l.has_confidence &&
          l.width_um == 100000 && l.height_um == 60000 && l.report_bytes == 1 + 12 + 2 + 1 + 1);
    o = SYN; o.conf = 0; syn_ptp(&r, &o);                    /* F4 */
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_OK && !l.has_confidence && !l.finger[0].confidence.size);
    o = SYN; o.mode = 0; syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_NO_INPUT_MODE);
    o = SYN; o.rel = 1; syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_NO_FINGERS);
    o = SYN; o.tip = 0; syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_NO_FINGERS);
    o = SYN; o.units = 0; syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_NO_UNITS);
    o = SYN; o.fingers = 11; syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_UNSUPPORTED);
    o = SYN; o.drop_end = 1; syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_MALFORMED);
    CHECK(!strcmp(hid_ptp_layout_name(HID_PTP_NO_UNITS), "no physical units"));
}

/* -- the mode switch, end to end through the GENI model ------------------------------------ */

static void tpad_features(struct dev *d)
{
    static const struct { uint8_t id; uint16_t len; } sizes[] = {
        {2, 2}, {3, 2}, {5, 2}, {7, 2}, {8, 257}, {11, 129}, {12, 34}, {13, 5}, {14, 5},
    };
    d->features = 1;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        d->feat_len[sizes[i].id] = sizes[i].len;
        d->feat[sizes[i].id][0] = sizes[i].id;
    }
    d->feat[2][1] = 0x05;                    /* Contact Count Maximum 5, Pad Type 0 (clickpad) */
    for (uint32_t i = 1; i < 257; i++)
        d->feat[8][i] = (uint8_t)(i * 7u);
    d->mode_id = 3;
    d->selective_id = 5;
    d->feat[5][1] = 3;
    d->selective = 3;
    d->nack_set_id = -1;
}

static void begin_a16_touchpad(void)
{
    struct i2c_hid_config cfg;
    model_reset();
    ndelivered = 0;
    M.devs[0x15] = NULL;
    dev_init(&TPAD, 0x15, a16_tpad_hid_desc, a16_tpad_report_desc, sizeof(a16_tpad_report_desc));
    tpad_features(&TPAD);
    M.devs[0x15] = &TPAD;
    start_bus(GENI_I2C_IRQ_MASKED);
    i2c_hid_default_config(&cfg, 0x15, 1);
    cfg.expect_vendor = 0x2808;
    cfg.expect_product = 0x0219;
    CHECK(i2c_hid_begin(&DEV, &BUS, &cfg, deliver, NULL) == I2C_HID_R_OK);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(DEV.state == I2C_HID_S_READY);
    CHECK(hid_ptp_layout(DEV.rdesc, DEV.rdesc_len, &PL) == HID_PTP_OK);
}

static int f_get(void *ctx, uint8_t id, uint8_t *buf, uint32_t cap, uint32_t *got)
{
    return i2c_hid_get_report(ctx, I2C_HID_TYPE_FEATURE, id, buf, cap, got) != I2C_HID_R_OK;
}

static int f_set(void *ctx, const uint8_t *report, uint32_t len)
{
    return i2c_hid_set_report(ctx, I2C_HID_TYPE_FEATURE, report, len) != I2C_HID_R_OK;
}

static const struct hid_ptp_io FIO = {&DEV, f_get, f_set};
static uint8_t fscratch[300];

/* What the firmware sends for one finger: report 4 in touchpad mode, else mouse report 1. */
static uint16_t tlx, tly;
static unsigned tscan;
static void tpad_touch(uint16_t x, uint16_t y, int tip)
{
    uint8_t r[64];
    if (TPAD.mode == HID_PTP_MODE_TOUCHPAD) {
        struct tc c = {1, (uint8_t)tip, 0, x, y};
        tscan += 80;
        dev_push(&TPAD, r, a16_frame(r, &c, 1, 1, tscan & 0xffffu, 0));
    } else {
        uint8_t m[5] = {1, 0, (uint8_t)(x - tlx), (uint8_t)(y - tly), 0};
        dev_push(&TPAD, m, 5);
    }
    tlx = x;
    tly = y;
}

/* As SnapI2CHIDPointer routes them: report 4 to the engine, report 1 to the mouse translator. */
static struct hid_pointer_layout ML;
static struct hid_pointer_state MS;
static void route(void)
{
    for (uint32_t i = 0; i < ndelivered; i++) {
        if (delivered[i][0] == 4)
            hid_ptp_engine_report(&PE, delivered[i], delivered_len[i], M.now_ns / 1000u, 0, &PSINK);
        else if (delivered[i][0] == 1)
            hid_pointer_translate(&ML, &MS, delivered[i], delivered_len[i], p_move, p_scroll, NULL);
    }
    ndelivered = 0;
}

static void touch_and_route(unsigned frames)
{
    for (unsigned i = 0; i < frames; i++) {
        tpad_touch((uint16_t)(2000 + 32 * i), 1500, 1);
        poll_ticks(&DEV, 1);
        route();
    }
}

/* F1, F2, F3, F9, F10, F15, F16. */
static void test_ptp_enable(void)
{
    struct hid_ptp_setup s;
    static const uint8_t order_op[6] = {2, 2, 2, 3, 3, 2}, order_id[6] = {8, 2, 3, 3, 5, 3};

    CHECK(hid_pointer_layout(a16_tpad_report_desc, sizeof(a16_tpad_report_desc), &ML) == HID_POINTER_OK);
    /* The switch: blob once, capabilities, Input Mode 3 (it was 0), Surface/Button on, readback 3. */
    begin_a16_touchpad();
    CHECK(hid_ptp_enable(&PL, &FIO, fscratch, sizeof(fscratch), &s) == HID_PTP_ENABLED && s.result == HID_PTP_ENABLED);
    CHECK(TPAD.mode == HID_PTP_MODE_TOUCHPAD && TPAD.selective == 3);
    CHECK(s.mode_before_read && s.mode_before == 0 && s.mode_after_read && s.mode_after == 3);
    CHECK(s.blob_read && s.blob_bytes == 257 && TPAD.feature_gets[8] == 1);
    CHECK(s.caps_read && s.max_contacts == 5 && s.pad_type == 0 && s.selective_written);
    CHECK(TPAD.nreq == 6 && s.requests == 6);
    for (unsigned i = 0; i < 6; i++)
        CHECK(TPAD.req_op[i] == order_op[i] && TPAD.req_id[i] == order_id[i]);
    CHECK(DEV.state == I2C_HID_S_READY && i2c_hid_run(&DEV) == I2C_HID_R_OK);
    /* The device now sends report 4 (52-byte reads), and one finger moves the pointer. */
    ptp_begin_layout(&PL);
    npmove = 0;
    touch_and_route(6);
    CHECK(PE.stats.frames == 6 && n_kind('p', 0) == 5 && npmove == 0);
    CHECK(near(sum_of('p', 0, 0), q16(5 * 32, 0), 8) && sum_of('p', 1, 0) == 0);
    CHECK(M.log[M.nlog - 1].len == 52);
    check_clean();

    /* F10: eight failed polls re-initialise the device; its RESET restores mouse mode, which the
     * mouse path still handles (F9), and re-applying the switch restores report 4. */
    TPAD.nack_next = 8;
    poll_ticks(&DEV, 8);
    CHECK(DEV.stats.reinits == 1);
    run_until(&DEV, I2C_HID_S_RUNNING, 64);
    CHECK(DEV.state == I2C_HID_S_RUNNING && TPAD.resets == 2 && TPAD.mode == 0);
    npmove = 0;
    touch_and_route(3);
    CHECK(npmove == 3 && PE.stats.frames == 6);              /* mouse reports, mouse path */
    CHECK(hid_ptp_enable(&PL, &FIO, fscratch, sizeof(fscratch), &s) == HID_PTP_ENABLED && TPAD.mode == 3);
    touch_and_route(2);
    CHECK(PE.stats.frames == 8 && npmove == 3);
    check_clean();

    /* F1: the Input Mode write is NACKed. Nothing after it is sent; the device stays a mouse. */
    begin_a16_touchpad();
    TPAD.nack_set_id = 3;
    CHECK(hid_ptp_enable(&PL, &FIO, fscratch, sizeof(fscratch), &s) == HID_PTP_REFUSED_WRITE);
    CHECK(TPAD.mode == 0 && TPAD.feature_sets[3] == 1 && TPAD.feature_sets[5] == 0 && TPAD.nreq == 4);
    CHECK(DEV.state == I2C_HID_S_READY && i2c_hid_run(&DEV) == I2C_HID_R_OK);
    npmove = 0;
    ptp_begin_layout(&PL);
    touch_and_route(3);
    CHECK(npmove == 3 && PE.stats.frames == 0);              /* F16: today's mouse mode */
    check_clean();

    /* F2: written and acknowledged, but the device keeps mouse mode: the readback says so. */
    begin_a16_touchpad();
    TPAD.ignore_mode = 1;
    CHECK(hid_ptp_enable(&PL, &FIO, fscratch, sizeof(fscratch), &s) == HID_PTP_REFUSED_READBACK);
    CHECK(TPAD.mode == 0 && s.mode_after_read && s.mode_after == 0);
    check_clean();

    /* A device that answers no GET_REPORT: the write goes through, unverified (F9 covers it). */
    begin_a16_touchpad();
    TPAD.no_get = 1;
    CHECK(hid_ptp_enable(&PL, &FIO, fscratch, sizeof(fscratch), &s) == HID_PTP_ENABLED_UNVERIFIED);
    CHECK(TPAD.mode == 3 && !s.blob_read && !s.caps_read && !s.mode_before_read && !s.mode_after_read);
    CHECK(TPAD.feature_sets[3] == 1 && TPAD.feature_sets[5] == 1);
    check_clean();

    /* No buffer for the blob: it is skipped, the rest proceeds. No Input Mode: nothing is sent. */
    begin_a16_touchpad();
    CHECK(hid_ptp_enable(&PL, &FIO, fscratch, 64, &s) == HID_PTP_ENABLED && !s.blob_read &&
          TPAD.feature_gets[8] == 0);
    {
        struct hid_ptp_layout none = PL;
        uint32_t before = TPAD.nreq;
        none.input_mode.report_id = 0;
        CHECK(hid_ptp_enable(&none, &FIO, fscratch, sizeof(fscratch), &s) == HID_PTP_ENABLE_INVALID &&
              TPAD.nreq == before);
    }
    CHECK(!strcmp(hid_ptp_enable_name(HID_PTP_ENABLED_UNVERIFIED), "enabled, unverified"));
    check_clean();
}

/* One finger moves the pointer; a lift with travel is no tap. */
static void test_ptp_pointer(void)
{
    struct tc a = {1, 1, 1, 2000, 1500};
    unsigned at;
    ptp_begin();
    CHECK(frame(&a, 1, 0) == HID_PTP_FRAME && npev == 0);  /* landing: no motion yet */
    for (unsigned i = 0; i < 10; i++) {
        a.x += 32;
        frame(&a, 1, 0);
        CHECK(near(pev[npev - 1].a, q16(32, 0), 2) && pev[npev - 1].b == 0 && pev[npev - 1].c == 0);
    }
    CHECK(n_kind('p', 0) == 10 && near(sum_of('p', 0, 0), q16(320, 0), 12) && n_kind('s', 0) == 0);
    at = npev;
    a.y -= 64;
    frame(&a, 1, 0);
    CHECK(npev == at + 1 && near(pev[at].b, q16(-64, 1), 2) && pev[at].a == 0);
    a.tip = 0;
    at = npev;
    frame(&a, 1, 0);
    frame(NULL, 0, 0);
    CHECK(npev == at && PE.stats.taps == 0 && !hid_ptp_engine_busy(&PE));
}

/* F18, F19: a physical click, its wobble, and two-finger secondary click. */
static void test_ptp_click(void)
{
    struct tc ab[2] = {{1, 1, 1, 2000, 1500}, {1, 1, 2, 2700, 1600}};
    unsigned at;
    ptp_begin();
    frame(ab, 1, 0);
    frame(ab, 1, 1);
    CHECK(last_is('p', 0, 0, 1) && PE.stats.button_edges == 1);
    at = npev;
    for (unsigned i = 0; i < 4; i++) {                       /* the pad tilts for 32 ms: no motion */
        ab[0].x += 5;
        frame(ab, 1, 1);
    }
    CHECK(npev == at);
    ab[0].x += 32;
    frame(ab, 1, 1);                                         /* 40 ms after the edge: a drag */
    CHECK(npev == at + 1 && pev[at].c == 1 && near(pev[at].a, q16(32, 0), 2));
    frame(ab, 1, 0);
    CHECK(last_is('p', 0, 0, 0));
    ab[0].tip = 0;
    frame(ab, 1, 0);
    frame(NULL, 0, 0);
    CHECK(PE.stats.taps == 0);                               /* a session with a press is no tap */
    ab[0].tip = 1;
    frame(ab, 2, 0);
    frame(ab, 2, 1);
    CHECK(last_is('p', 0, 0, 2));                            /* two fingers: secondary */
    ab[1].tip = 0;
    frame(ab, 2, 1);                                         /* one lifts, still held: secondary */
    CHECK(last_is('p', 0, 0, 2));
    frame(ab, 1, 0);
    CHECK(last_is('p', 0, 0, 0));
    ab[0].tip = 0;
    frame(ab, 1, 0);
    frame(NULL, 0, 0);
    CHECK(n_kind('s', 0) == 0 && PE.stats.taps == 0);
}

/* F17, F21: taps, their release on the tick, and the typing guard. */
static void test_ptp_tap(void)
{
    struct tc ab[2] = {{1, 1, 1, 2000, 1500}, {1, 1, 2, 2700, 1600}};
    unsigned at;
    ptp_begin();
    for (unsigned i = 0; i < 10; i++)
        frame(ab, 1, 0);                                     /* 80 ms, still */
    ab[0].tip = 0;
    frame(ab, 1, 0);
    CHECK(last_is('p', 0, 0, 1) && PE.stats.taps == 1 && hid_ptp_engine_busy(&PE));
    at = npev;
    tick(4000);
    CHECK(npev == at);
    tick(8000);
    CHECK(last_is('p', 0, 0, 0) && npev == at + 1 && !hid_ptp_engine_busy(&PE));
    frame(NULL, 0, 0);
    /* Two fingers: secondary. */
    ab[0].tip = ab[1].tip = 1;
    frame(ab, 2, 0);
    frame(ab, 2, 0);
    ab[0].tip = ab[1].tip = 0;
    frame(ab, 2, 0);
    CHECK(last_is('p', 0, 0, 2) && PE.stats.secondary_taps == 1);
    tick(16000);
    CHECK(last_is('p', 0, 0, 0));
    frame(NULL, 0, 0);
    /* Held too long: no tap. Moved 2 mm: pointer motion, no tap. */
    at = npev;
    ab[0].tip = 1;
    for (unsigned i = 0; i < 30; i++)
        frame(ab, 1, 0);
    ab[0].tip = 0;
    frame(ab, 1, 0);
    CHECK(npev == at && PE.stats.taps == 2);
    ab[0].tip = 1;
    for (unsigned i = 0; i < 4; i++) {
        frame(ab, 1, 0);
        ab[0].x += 24;                                       /* 3 x 0.74 mm: over 1.5 mm */
    }
    ab[0].tip = 0;
    frame(ab, 1, 0);
    CHECK(n_kind('p', at) == 3 && PE.stats.taps == 2);
    for (unsigned i = at; i < npev; i++)
        CHECK(pev[i].c == 0);
    /* Typing: a key-down 100 ms before the touch blocks the tap; one 400 ms before does not. */
    frame(NULL, 0, 0);
    plast_key = pnow - 100000 + 8000;
    ab[0].tip = 1;
    frame(ab, 1, 0);
    ab[0].tip = 0;
    frame(ab, 1, 0);
    CHECK(PE.stats.taps == 2 && PE.stats.typing_blocked_taps == 1);
    plast_key = pnow - 400000;
    ab[0].tip = 1;
    frame(ab, 1, 0);
    ab[0].tip = 0;
    frame(ab, 1, 0);
    CHECK(PE.stats.taps == 3 && last_is('p', 0, 0, 1));
    /* A new touch before the release tick releases first. */
    ab[0].tip = 1;
    frame(ab, 1, 0);
    CHECK(last_is('p', 0, 0, 0) && !hid_ptp_engine_busy(&PE));
}

/* Two-finger scroll, momentum, and F7 / F20 / F8. */
static unsigned scroll_two(struct tc *ab, int dy, int dx, unsigned frames)
{
    unsigned at = npev;
    for (unsigned i = 0; i < frames; i++) {
        ab[0].y = (uint16_t)(ab[0].y + dy);
        ab[1].y = (uint16_t)(ab[1].y + dy);
        ab[0].x = (uint16_t)(ab[0].x + dx);
        ab[1].x = (uint16_t)(ab[1].x + dx);
        frame(ab, 2, 0);
    }
    return at;
}

static void run_momentum(unsigned max_ticks)
{
    for (unsigned i = 0; i < max_ticks && hid_ptp_engine_busy(&PE); i++)
        tick(8000);
}

static void test_ptp_scroll(void)
{
    struct tc ab[3] = {{1, 1, 1, 2000, 2000}, {1, 1, 2, 2600, 2000}, {1, 1, 3, 3200, 2000}};
    unsigned at, ended;
    int32_t prev;
    ptp_begin();
    frame(ab, 2, 0);
    at = scroll_two(ab, -16, 0, 2);                          /* 1.0 mm: not yet */
    CHECK(npev == at);
    at = scroll_two(ab, -16, 0, 1);                          /* 1.5 mm: began */
    CHECK(npev == at + 1 && pev[at].kind == 's' && pev[at].c == HID_PTP_SCROLL_PHASE_BEGAN);
    CHECK(near(pev[at].a, q16(16, 1), 2) && pev[at].b == 0);  /* fingers up: positive (wheel up) */
    at = scroll_two(ab, -16, 0, 10);
    CHECK(n_opt(HID_PTP_SCROLL_PHASE_CHANGED, at) == 10 && n_kind('p', 0) == 0);
    CHECK(near(sum_of('s', 0, at), q16(160, 1), 20));
    ab[0].tip = ab[1].tip = 0;                               /* both lift together */
    frame(ab, 2, 0);
    CHECK(last_is('s', 0, 0, HID_PTP_SCROLL_PHASE_ENDED) && hid_ptp_engine_busy(&PE));
    ended = npev;
    run_momentum(1000);
    CHECK(!hid_ptp_engine_busy(&PE) && PE.stats.momentum == 1);
    CHECK(pev[ended].c == HID_PTP_SCROLL_MOMENTUM_START && pev[ended].a > 0);
    CHECK(last_is('s', 0, 0, HID_PTP_SCROLL_MOMENTUM_END));
    CHECK(n_opt(HID_PTP_SCROLL_MOMENTUM_CONTINUE, ended) > 20 && npev - ended < 3000u / 8u + 2u);
    prev = pev[ended].a;
    for (unsigned i = ended + 1; i < npev - 1; i++) {
        CHECK(pev[i].a > 0 && pev[i].a <= prev + 1 && pev[i].b == 0);
        prev = pev[i].a;
    }
    /* 16 counts per 8 ms, about 2.4 in/s: about 0.4 s worth of travel, a few hundred units. */
    CHECK(sum_of('s', 0, ended) > (150 << 16) && sum_of('s', 0, ended) < (500 << 16));
    frame(NULL, 0, 0);

    /* Horizontal: fingers right is negative (wheel convention). */
    ab[0].tip = ab[1].tip = 1;
    frame(ab, 2, 0);
    at = scroll_two(ab, 0, 16, 4);
    CHECK(n_opt(HID_PTP_SCROLL_PHASE_BEGAN, at) == 1 && sum_of('s', 1, at) < 0 && sum_of('s', 0, at) == 0);
    /* F20: a touch during momentum ends it at once. */
    ab[0].tip = ab[1].tip = 0;
    frame(ab, 2, 0);
    tick(8000);
    tick(8000);
    CHECK(n_opt(HID_PTP_SCROLL_MOMENTUM_START, at) == 1);
    ab[0].tip = 1;
    at = npev;
    frame(ab, 1, 0);
    CHECK(npev == at + 1 && pev[at].c == HID_PTP_SCROLL_MOMENTUM_END && !hid_ptp_engine_busy(&PE));
    tick(8000);
    CHECK(npev == at + 1);
    ab[0].tip = 0;
    frame(ab, 1, 0);
    frame(NULL, 0, 0);

    /* F7: one finger lifts mid-scroll and the other keeps moving: Ended without momentum after the
     * lift window, then the remaining finger moves the pointer from where it is (F8: no jump). */
    ab[0].tip = ab[1].tip = 1;
    frame(ab, 2, 0);
    at = scroll_two(ab, -16, 0, 5);
    CHECK(n_opt(HID_PTP_SCROLL_PHASE_BEGAN, at) == 1);
    ab[1].tip = 0;
    frame(ab, 2, 0);
    at = npev;
    for (unsigned i = 0; i < 7; i++) {                       /* 56 ms of the 60 ms window */
        ab[0].x += 32;
        frame(ab, 1, 0);
    }
    CHECK(npev == at);
    ab[0].x += 32;
    frame(ab, 1, 0);                                         /* 64 ms: the window closes */
    CHECK(npev == at + 1 && last_is('s', 0, 0, HID_PTP_SCROLL_PHASE_ENDED));
    ab[0].x += 32;
    frame(ab, 1, 0);
    CHECK(last_is('p', (int32_t)pev[npev - 1].a, 0, 0) && near(pev[npev - 1].a, q16(32, 0), 2));
    run_momentum(10);
    CHECK(n_opt(HID_PTP_SCROLL_MOMENTUM_START, at) == 0);
    ab[0].tip = 0;
    frame(ab, 1, 0);
    frame(NULL, 0, 0);

    /* F7: a staggered lift inside the window is a flick: Ended, then momentum. */
    ab[0].tip = ab[1].tip = 1;
    frame(ab, 2, 0);
    scroll_two(ab, -16, 0, 6);
    ab[1].tip = 0;
    frame(ab, 2, 0);
    at = npev;
    ab[0].tip = 0;
    frame(ab, 1, 0);                                         /* 8 ms later */
    CHECK(npev == at + 1 && pev[at].c == HID_PTP_SCROLL_PHASE_ENDED);
    tick(8000);
    CHECK(pev[npev - 1].c == HID_PTP_SCROLL_MOMENTUM_START);
    run_momentum(1000);
    frame(NULL, 0, 0);

    /* A third finger ends the scroll; three fingers do nothing (phase 2); back to two scrolls again. */
    ab[0].tip = ab[1].tip = ab[2].tip = 1;
    frame(ab, 2, 0);
    scroll_two(ab, -16, 0, 5);
    at = npev;
    frame(ab, 3, 0);
    CHECK(npev == at + 1 && last_is('s', 0, 0, HID_PTP_SCROLL_PHASE_ENDED));
    for (unsigned i = 0; i < 5; i++) {
        ab[0].y -= 16; ab[1].y -= 16; ab[2].y -= 16;
        frame(ab, 3, 0);
    }
    CHECK(npev == at + 1 && PE.stats.max_fingers == 3);
    ab[2].tip = 0;
    frame(ab, 3, 0);
    at = scroll_two(ab, -16, 0, 8);
    CHECK(n_opt(HID_PTP_SCROLL_PHASE_BEGAN, at) == 1 && n_kind('p', at) == 0);
    ab[0].tip = ab[1].tip = 0;
    frame(ab, 2, 0);
    run_momentum(1000);
    frame(NULL, 0, 0);

    /* F23: a resting thumb: one finger still, the other moving: the pointer follows the moving one
     * and nothing scrolls. */
    ab[0] = (struct tc){1, 1, 1, 2000, 2000};
    ab[1] = (struct tc){1, 1, 2, 2600, 2900};
    frame(ab, 2, 0);
    at = npev;
    for (unsigned i = 0; i < 8; i++) {
        ab[0].x += 32;
        frame(ab, 2, 0);
    }
    CHECK(n_kind('s', at) == 0 && n_kind('p', at) >= 4 && sum_of('p', 0, at) > 0 && sum_of('p', 1, at) == 0);
    CHECK(PE.mode == HID_PTP_REST);
}

/* F5, F6, F4, F13: palms, ID reuse, a descriptor without Confidence, hybrid frames. */
static void test_ptp_contacts(void)
{
    struct tc c[3] = {{1, 1, 1, 2000, 2000}, {0, 1, 2, 3500, 2900}, {1, 1, 3, 2600, 2000}};
    struct hid_ptp_layout l;
    struct rd r;
    struct syn o;
    unsigned at;
    ptp_begin();
    /* F5: a palm (Confidence 0) lands beside the pointer finger and moves: the pointer follows the
     * finger only, nothing scrolls, and the session makes no tap. */
    frame(c, 1, 0);
    frame(c, 2, 0);
    at = npev;
    for (unsigned i = 0; i < 5; i++) {
        c[0].x += 32;
        c[1].x -= 50;
        c[1].y -= 50;
        frame(c, 2, 0);
    }
    CHECK(n_kind('s', at) == 0 && n_kind('p', at) >= 4 && sum_of('p', 1, at) == 0 && sum_of('p', 0, at) > 0);
    CHECK(PE.stats.palms == 1);
    c[0].tip = c[1].tip = 0;
    frame(c, 2, 0);
    frame(NULL, 0, 0);
    CHECK(PE.stats.taps == 0);
    /* A palm alone, short and still: no tap. */
    c[1].tip = 1;
    frame(c + 1, 1, 0);
    c[1].tip = 0;
    frame(c + 1, 1, 0);
    CHECK(PE.stats.taps == 0 && npev == at + n_kind('p', at));
    frame(NULL, 0, 0);
    /* A finger that becomes a palm mid-scroll ends the scroll, without momentum. */
    c[0].tip = c[2].tip = 1;
    c[2].conf = 1;
    {
        struct tc ab[2] = {c[0], c[2]};
        frame(ab, 2, 0);
        at = scroll_two(ab, -16, 0, 5);
        CHECK(n_opt(HID_PTP_SCROLL_PHASE_BEGAN, at) == 1);
        ab[1].conf = 0;
        for (unsigned i = 0; i < 10; i++)
            frame(ab, 2, 0);
        CHECK(n_opt(HID_PTP_SCROLL_PHASE_ENDED, at) == 1 && n_opt(HID_PTP_SCROLL_MOMENTUM_START, at) == 0);
        ab[0].tip = ab[1].tip = 0;
        frame(ab, 2, 0);
        frame(NULL, 0, 0);
    }
    /* F6: ID 1 lifts and lands again far away: a new contact, no jump; a slot that vanishes is a
     * lift; duplicate IDs in one frame take the first; a teleport is a new contact too. */
    c[0] = (struct tc){1, 1, 1, 1000, 1000};
    frame(c, 1, 0);
    c[0].x += 64;                                            /* 2 mm: a stroke, not a tap */
    frame(c, 1, 0);
    c[0].tip = 0;
    frame(c, 1, 0);
    c[0] = (struct tc){1, 1, 1, 4000, 2800};
    at = npev;
    frame(c, 1, 0);
    c[0].x += 32;
    frame(c, 1, 0);
    CHECK(npev == at + 1 && near(pev[at].a, q16(32, 0), 2));
    c[2] = (struct tc){1, 1, 2, 2000, 2000};
    {
        struct tc two[2] = {c[0], c[2]}, one[1] = {c[2]};
        frame(two, 2, 0);
        frame(one, 1, 0);                                    /* ID 1 vanished: lifted */
        two[0].x = 300;
        two[0].y = 300;
        frame(two, 2, 0);                                    /* ID 1 again, far away: new */
        CHECK(PE.stats.reused_ids >= 1);
        two[0].tip = two[1].tip = 0;
        frame(two, 2, 0);
        frame(NULL, 0, 0);
    }
    {
        struct tc dup[2] = {{1, 1, 4, 2000, 2000}, {1, 1, 4, 3000, 2500}};
        frame(dup, 2, 0);
        at = npev;
        dup[0].x += 32;
        dup[1].x += 32;
        frame(dup, 2, 0);
        CHECK(PE.stats.duplicate_ids >= 1 && n_kind('p', at) == 1 && n_kind('s', at) == 0);
        dup[0].tip = 0;
        frame(dup, 1, 0);
        frame(NULL, 0, 0);
    }
    {
        struct tc t = {1, 1, 5, 1000, 1000};
        frame(&t, 1, 0);
        t.x += 32;
        frame(&t, 1, 0);
        at = npev;
        t.x += 1000;                                         /* 31 mm in 8 ms */
        frame(&t, 1, 0);
        CHECK(PE.stats.jumps == 1 && npev == at);
        t.x += 32;
        frame(&t, 1, 0);
        CHECK(npev == at + 1 && near(pev[at].a, q16(32, 0), 2));
        t.tip = 0;
        frame(&t, 1, 0);
        frame(NULL, 0, 0);
    }
    /* F4: no Confidence in the descriptor: every contact is a finger, so two scroll. */
    o = SYN;
    o.conf = 0;
    syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_OK);
    ptp_begin_layout(&l);
    {
        struct tc ab[2] = {{0, 1, 1, 300, 300}, {0, 1, 2, 500, 300}};
        syn_frame(&o, ab, 1, 1, 0);
        ab[0].x += 20;
        syn_frame(&o, ab, 1, 1, 0);
        CHECK(n_kind('p', 0) == 1);
        at = npev;
        syn_frame(&o, ab, 2, 2, 0);
        for (unsigned i = 0; i < 4; i++) {
            ab[0].y -= 10;
            ab[1].y -= 10;
            syn_frame(&o, ab, 2, 2, 0);
        }
        CHECK(n_opt(HID_PTP_SCROLL_PHASE_BEGAN, at) == 1);
    }
    /* F13: two slots, three contacts: the frame completes over two reports; a new nonzero count
     * drops a partial frame. */
    o = SYN;
    syn_ptp(&r, &o);
    CHECK(hid_ptp_layout(r.b, r.n, &l) == HID_PTP_OK);
    ptp_begin_layout(&l);
    {
        struct tc three[2] = {{1, 1, 1, 100, 100}, {1, 1, 2, 300, 100}}, last[1] = {{1, 1, 3, 500, 100}};
        syn_frame(&o, three, 2, 3, 0);
        CHECK(PE.stats.frames == 0 && PE.stats.hybrid_partial == 1);
        syn_frame(&o, last, 1, 0, 0);
        CHECK(PE.stats.frames == 1 && PE.stats.max_fingers == 3);
        syn_frame(&o, three, 2, 3, 0);
        syn_frame(&o, three, 1, 1, 0);
        CHECK(PE.stats.hybrid_dropped == 1 && PE.stats.frames == 2);
    }
}

/* F11, F12: Scan Time wrap, duplicates, implausible gaps and bunched host timestamps give the same
 * release velocity as evenly timed frames. */
static int32_t flick(unsigned scan_start, int bunched, int duplicates, int gap)
{
    struct tc ab[2] = {{1, 1, 1, 2000, 2500}, {1, 1, 2, 2600, 2500}};
    uint8_t r[64];
    unsigned at;
    ptp_begin();
    pscan = scan_start;
    for (unsigned i = 0; i < 12; i++) {
        if (i) {
            ab[0].y -= 16;
            ab[1].y -= 16;
        }
        pscan = (pscan + 80u) & 0xffffu;
        if (gap && i == 1)
            pscan = (pscan + 30000u) & 0xffffu;              /* 3 s: implausible, use the host clock */
        if (!bunched || i % 4 == 0)
            pnow += bunched ? 32000 : 8000;
        a16_frame(r, ab, 2, 2, pscan, 0);
        hid_ptp_engine_report(&PE, r, A16_PTP_BYTES, pnow, 0, &PSINK);
        if (duplicates && i == 8)
            hid_ptp_engine_report(&PE, r, A16_PTP_BYTES, pnow, 0, &PSINK);   /* the same frame again */
    }
    ab[0].tip = ab[1].tip = 0;
    pnow += 8000;
    pscan = (pscan + 80u) & 0xffffu;
    a16_frame(r, ab, 2, 2, pscan, 0);
    hid_ptp_engine_report(&PE, r, A16_PTP_BYTES, pnow, 0, &PSINK);
    at = npev;
    tick(8000);
    CHECK(npev == at + 1 && pev[at].c == HID_PTP_SCROLL_MOMENTUM_START);
    return pev[at].a;
}

static void test_ptp_timing(void)
{
    int32_t even = flick(1000, 0, 0, 0);
    CHECK(even > 0);
    CHECK(near(flick(65536u - 400u, 0, 0, 0), even, 2));           /* wraps mid-flick */
    CHECK(near(flick(1000, 1, 0, 0), even, even / 50 + 2));         /* four frames per host tick */
    CHECK(near(flick(1000, 0, 1, 0), even, 2));                     /* a duplicate frame */
    CHECK(PE.stats.frames == 14);
    flick(1000, 0, 0, 1);
    CHECK(PE.stats.scan_fallbacks >= 1);
}

/* F22, and report validation. */
static void test_ptp_reset_and_reports(void)
{
    struct tc ab[2] = {{1, 1, 1, 2000, 2000}, {1, 1, 2, 2600, 2000}};
    uint8_t r[64];
    unsigned at;
    ptp_begin();
    frame(ab, 2, 0);
    scroll_two(ab, -16, 0, 5);
    at = npev;
    hid_ptp_engine_reset(&PE, pnow, &PSINK);
    CHECK(npev == at + 1 && last_is('s', 0, 0, HID_PTP_SCROLL_PHASE_ENDED) && !hid_ptp_engine_busy(&PE));
    frame(ab, 2, 0);
    scroll_two(ab, -16, 0, 5);
    ab[0].tip = ab[1].tip = 0;
    frame(ab, 2, 0);
    tick(8000);
    at = npev;
    hid_ptp_engine_reset(&PE, pnow, &PSINK);
    CHECK(npev == at + 1 && last_is('s', 0, 0, HID_PTP_SCROLL_MOMENTUM_END));
    ab[0].tip = 1;
    frame(ab, 1, 0);
    frame(ab, 1, 1);
    at = npev;
    hid_ptp_engine_reset(&PE, pnow, &PSINK);
    CHECK(npev == at + 1 && last_is('p', 0, 0, 0));
    frame(ab, 1, 0);
    ab[0].tip = 0;
    frame(ab, 1, 0);
    CHECK(last_is('p', 0, 0, 1));
    hid_ptp_engine_reset(&PE, pnow, &PSINK);
    CHECK(last_is('p', 0, 0, 0) && !hid_ptp_engine_busy(&PE));
    at = npev;
    hid_ptp_engine_reset(&PE, pnow, &PSINK);
    CHECK(npev == at);                                       /* nothing held: nothing sent */
    a16_frame(r, ab, 1, 1, 0, 0);
    CHECK(hid_ptp_engine_report(&PE, r, 49, pnow, 0, &PSINK) == HID_PTP_BAD_LENGTH && PE.stats.bad_length == 1);
    r[0] = 1;
    CHECK(hid_ptp_engine_report(&PE, r, 5, pnow, 0, &PSINK) == HID_PTP_OTHER_REPORT);
    CHECK(npev == at);
}

/* --------------------------------------------- multitouch frames (hid-mt2.c, M4-M16) ---- */
/* The receiving side restated from the 26A428 binaries (gestures agent FAILURE-MODES.md; the same
 * bytes also go through Apple's own parsers on a 26A428 host in tools/test-mt2-apple-parser.c):
 *  - AppleMultitouchTrackpadHIDEventDriver::handleInterruptReport takes report 2 longer than 8 bytes,
 *    reads byte 7 bit 1 as "tracking" (the 8-byte header is then not dispatched) and strips 8 bytes;
 *  - MTCompactV7HeaderUnpack / MTCompactV7BinaryContactUnpack (MultitouchSupport) and
 *    -[HSTFrameParser unpackFrame31Header:/unpackFrame31Contact:] (HSTouchHIDService) unpack the 0x31
 *    frame: (len - 4) % 9 == 0; X = 2 * x13, Y = 2 * y13 + 5000; finger 7 becomes 12;
 *  - HSTPipeline::SurfaceCoordinates::fromService: position = (10X - 10 xmin, 10Y - 10 ymin) um;
 *  - AppleMultitouchDevice::_cacheDeviceProperties / decodeDeviceProperty: the 0xDB walk and the
 *    payload layouts; any of D1 D3 D0 A1 D9 7F missing from it is fetched alone. */
struct mtc { int x, y; uint8_t finger, stage, id, flag, angle, major, minor, size, pressure; };
struct mtf { uint8_t outer[8], button, flagb, host_click; uint32_t ts; unsigned n; struct mtc c[32]; };

static int mt_decode(const uint8_t *r, uint32_t len, struct mtf *f)
{
    const uint8_t *p = r + 8;
    uint32_t n;
    if (len <= 8 || r[0] != HID_MT2_REPORT_ID)
        return 0;
    memcpy(f->outer, r, 8);
    n = len - 8;
    if (n < 4 || p[0] != 0x31 || (n - 4) % 9)
        return 0;
    f->button = p[1] & 1u;
    f->flagb = (p[1] >> 1) & 1u;
    f->host_click = (p[1] >> 2) & 1u;
    f->ts = (uint32_t)(p[1] >> 3) | (uint32_t)p[2] << 5 | (uint32_t)p[3] << 13;
    f->n = (n - 4) / 9;
    for (unsigned i = 0; i < f->n && i < 32; i++) {
        const uint8_t *q = p + 4 + 9 * i;
        int x = q[0] | (q[1] & 0x1f) << 8, y = (q[1] >> 5) | q[2] << 3 | (q[3] & 3) << 11;
        if (x & 0x1000)
            x -= 0x2000;
        if (y & 0x1000)
            y -= 0x2000;
        f->c[i] = (struct mtc){2 * x, 2 * y + 5000, (uint8_t)((q[3] >> 2) & 7), (uint8_t)(q[3] >> 5),
                               (uint8_t)(q[8] & 15), (uint8_t)((q[8] >> 4) & 1), (uint8_t)(q[8] >> 5), q[4], q[5], q[6], q[7]};
        if (f->c[i].finger == 7)
            f->c[i].finger = 12;
    }
    return 1;
}

struct amd_props {
    unsigned family, endian, rows, cols, bcd, maxpkt, status, decoded, fetched, errors;
    uint8_t region[32], param[8], surface[16];
    uint32_t nregion, nparam, nsurface, width, height;
};

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static int16_t le16s(const uint8_t *p) { return (int16_t)(p[0] | p[1] << 8); }

static void amd_decode(struct amd_props *a, uint8_t id, const uint8_t *d, uint32_t len)
{
    a->decoded++;
    if (!len) { a->errors++; return; }
    switch (id) {
    case 0xd1: a->family = d[0]; break;
    case 0xd3:
        if (len < 5) { a->errors++; return; }
        a->endian = d[0]; a->rows = d[1]; a->cols = d[2]; a->bcd = (unsigned)d[3] << 8 | d[4];
        if (len >= 12) a->maxpkt = le32(d + 8);
        break;
    case 0xd0: memcpy(a->region, d, len < 32 ? len : 32); a->nregion = len; break;
    case 0xa1: memcpy(a->param, d, len < 8 ? len : 8); a->nparam = len; break;
    case 0xd9:
        if (len < 8) return;
        a->width = le32(d); a->height = le32(d + 4);
        if (len >= 16) { memcpy(a->surface, d, 16); a->nsurface = len; }
        break;
    case 0x7f: a->status = len == 4 ? le32(d) : len == 2 ? (unsigned)(d[0] | d[1] << 8) : 0; break;
    default: a->errors++;
    }
}

static void amd_cache(const struct hid_mt2 *m, struct amd_props *a)
{
    uint8_t buf[0x201], wanted[6] = {0xd1, 0xd3, 0xd0, 0xa1, 0xd9, 0x7f};
    uint32_t n = hid_mt2_feature(m, 0xdb, 0, buf, sizeof(buf)), len, at, rem;
    memset(a, 0, sizeof(*a));
    if (n > 1 && buf[0] == 0xdb && buf[1] == 1 && (rem = (len = n - 1) - 1) > 2) {
        at = 1;                                  /* payload offset of the first entry */
        while (rem > 2) {
            const uint8_t *e = buf + 1 + at;
            uint32_t l = (uint32_t)(e[0] | e[1] << 8), dlen;
            if (!l) { a->errors++; break; }
            dlen = l - 1;
            if (rem - 3 < dlen) { a->errors++; break; }
            amd_decode(a, e[2], e + 3, dlen);
            for (unsigned i = 0; i < 6; i++)
                if (wanted[i] == e[2]) wanted[i] = 0;
            rem -= 3 + dlen;
            at += 3 + dlen;
        }
        REQUIRE(at <= len);
    }
    for (unsigned i = 0; i < 6; i++)
        if (wanted[i] && (n = hid_mt2_feature(m, wanted[i], 0, buf, sizeof(buf))) > 1) {
            a->fetched++;
            amd_decode(a, buf[0], buf + 1, n - 1);
        }
}

static struct hid_mt2 MT;
static struct mtf MF[512];
static unsigned nmf;

static void mt_keep(uint32_t len, const uint8_t *r)
{
    REQUIRE(nmf < 512);
    CHECK(len <= HID_MT2_MAX_REPORT && mt_decode(r, len, &MF[nmf]));
    nmf++;
}

static void mt_hook(void *ctx, const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons, uint32_t scan,
                    int has_scan)
{
    uint8_t r[HID_MT2_MAX_REPORT];
    uint32_t len;
    (void)ctx;
    len = hid_mt2_frame(&MT, c, n, buttons, scan, has_scan, pnow, r, sizeof(r));
    if (len)
        mt_keep(len, r);
}

static const struct hid_ptp_sink MSINK = {NULL, ptp_ptr, ptp_scr, mt_hook};

static void mt_begin(void)
{
    ptp_begin();
    CHECK(hid_mt2_init(&MT, &PL) == HID_MT2_OK);
    nmf = 0;
}

/* One A16 frame through the engine, the multitouch encoder on its frame hook. */
static void mt_frame(const struct tc *c, unsigned n, unsigned button)
{
    uint8_t r[64];
    pnow += 8000;
    pscan = (pscan + 80u) & 0xffffu;
    a16_frame(r, c, n, n, pscan, button);
    CHECK(hid_ptp_engine_report(&PE, r, A16_PTP_BYTES, pnow, plast_key, &MSINK) == HID_PTP_FRAME);
}

static unsigned mt_tick(uint64_t us)
{
    uint8_t r[HID_MT2_MAX_REPORT];
    uint32_t len;
    pnow += us;
    len = hid_mt2_tick(&MT, pnow, r, sizeof(r));
    if (len)
        mt_keep(len, r);
    return len;
}

static const struct mtc *mt_find(const struct mtf *f, unsigned id)
{
    for (unsigned i = 0; i < f->n; i++)
        if (f->c[i].id == id)
            return &f->c[i];
    return NULL;
}

/* Micrometres from the surface origin as HSTouch computes them, against the touchpad's own. */
static int mt_at(const struct mtc *c, uint16_t x, uint16_t y)
{
    int64_t xum = (int64_t)c->x * 10 - (int64_t)(-2 * MT.wq) * 10;
    int64_t yum = (int64_t)c->y * 10 - (int64_t)(5000 - 2 * MT.hq) * 10;
    int64_t want_x = (int64_t)x * 147500 / 4762, want_y = 96000 - (int64_t)y * 96000 / 3099;
    return near(xum, want_x, 50) && near(yum, want_y, 50);
}

/* M4, M12, M14: geometry, refusals, the handshake replies, the descriptor. */
static void test_mt_features(void)
{
    struct hid_ptp_layout l;
    struct amd_props a;
    struct hid_rdesc_info info;
    uint8_t buf[HID_MT2_MAX_FEATURE], small[8];
    uint32_t dlen;
    const uint8_t *d;
    ptp_begin();
    CHECK(hid_mt2_init(&MT, &PL) == HID_MT2_OK && MT.wq == 3687 && MT.hq == 2400);
    CHECK(hid_mt2_init(&MT, NULL) == HID_MT2_NO_LAYOUT);
    l = PL; l.width_um = 200000;
    CHECK(hid_mt2_init(&MT, &l) == HID_MT2_BAD_SIZE);                 /* 13 bits hold 163.8 mm */
    l = PL; l.height_um = 20000;
    CHECK(hid_mt2_init(&MT, &l) == HID_MT2_BAD_SIZE);
    l = PL; l.x_max = l.x_min;
    CHECK(hid_mt2_init(&MT, &l) == HID_MT2_BAD_RANGE);
    CHECK(hid_mt2_feature(&MT, 0xd1, 0, buf, sizeof(buf)) == 0);       /* refused geometry: no replies */
    CHECK(hid_mt2_init(&MT, &PL) == HID_MT2_OK);
    /* AMD's cache: every report from the one 0xDB reply, exactly to its end, nothing fetched alone. */
    amd_cache(&MT, &a);
    CHECK(a.errors == 0 && a.decoded == 6 && a.fetched == 0);
    CHECK(a.family == 0x81 && a.endian == 1 && a.rows == 22 && a.cols == 30 && a.bcd == 0x0100 && a.maxpkt == 0x400);
    CHECK(a.nregion == 15 && a.region[0] == 2 && a.nparam == 6 && a.status == 0);
    CHECK(a.width == 14748 && a.height == 9600 && a.nsurface == 16);
    CHECK(le32(a.surface) == a.width && le16s(a.surface + 8) == -7374 && le16s(a.surface + 10) == 200 &&
          le16s(a.surface + 12) == 7374 && le16s(a.surface + 14) == 9800);
    /* Each report alone equals its 0xDB entry; report 1 answers the length query. */
    CHECK(hid_mt2_feature(&MT, 0xd9, 0, buf, sizeof(buf)) == 17 && buf[0] == 0xd9 && !memcmp(buf + 1, a.surface, 16));
    CHECK(hid_mt2_feature(&MT, 0xd1, 0, buf, sizeof(buf)) == 2 && buf[1] == 0x81);
    CHECK(hid_mt2_feature(&MT, 0xd3, 0, buf, sizeof(buf)) == 13 && hid_mt2_feature(&MT, 0xd0, 0, buf, sizeof(buf)) == 16 &&
          hid_mt2_feature(&MT, 0xa1, 0, buf, sizeof(buf)) == 7 && hid_mt2_feature(&MT, 0x7f, 0, buf, sizeof(buf)) == 5);
    CHECK(hid_mt2_feature(&MT, 0xdb, 0, buf, sizeof(buf)) == 74);
    CHECK(hid_mt2_feature(&MT, 0x01, 0xd9, buf, sizeof(buf)) == 5 && buf[0] == 1 && buf[1] == 0xd9 && buf[2] == 0 &&
          buf[3] == 16 && buf[4] == 0);
    CHECK(hid_mt2_feature(&MT, 0x01, 0xdb, buf, sizeof(buf)) == 5 && buf[3] == 73);
    CHECK(hid_mt2_feature(&MT, 0x01, 0x42, buf, sizeof(buf)) == 0 && hid_mt2_feature(&MT, 0x01, 0x01, buf, sizeof(buf)) == 0);
    CHECK(hid_mt2_feature(&MT, 0xc8, 0, buf, sizeof(buf)) == 0 && hid_mt2_feature(&MT, 0x02, 0, buf, sizeof(buf)) == 0);
    CHECK(hid_mt2_feature(&MT, 0xd9, 0, small, sizeof(small)) == 0 && hid_mt2_feature(&MT, 0xdb, 0, small, sizeof(small)) == 0);
    /* The descriptor: report 2 is the 8-byte header, MaxInputReportSize covers a full frame, pairs 1/2 and 13/5. */
    d = hid_mt2_report_descriptor(&dlen);
    CHECK(hid_rdesc_parse(d, dlen, &info) == HID_RDESC_OK);
    CHECK(hid_rdesc_report_bytes(&info, HID_REPORT_INPUT, HID_MT2_REPORT_ID) == HID_MT2_HEADER_BYTES);
    CHECK(hid_rdesc_max_report_bytes(&info, HID_REPORT_INPUT) == HID_MT2_DECLARED_INPUT &&
          HID_MT2_DECLARED_INPUT >= HID_MT2_MAX_REPORT);
    CHECK(info.napps == 2 && info.apps[0].page == 1 && info.apps[0].usage == 2 && info.apps[1].page == 13 &&
          info.apps[1].usage == 5);
}

/* M5, M8-M11, M13, M15, M16: frames from real A16 reports through the engine's hook. */
static void test_mt_frames(void)
{
    struct tc a = {1, 1, 1, 0, 0}, ab[2];
    struct tc many[5];
    struct hid_ptp_contact ten[10];
    uint8_t r[HID_MT2_MAX_REPORT];
    const struct mtc *c;
    unsigned at, id;
    mt_begin();
    /* One finger: MakeTouch, Touching, BreakTouch with the lift report, OutOfRange and the empty frame on ticks. */
    a = (struct tc){1, 1, 1, 0, 0};
    mt_frame(&a, 1, 0);
    CHECK(nmf == 1 && MF[0].n == 1 && MF[0].c[0].stage == 3 && MF[0].c[0].finger == 2 && MF[0].c[0].id >= 1);
    CHECK(mt_at(&MF[0].c[0], 0, 0) && MF[0].host_click == 0 && MF[0].button == 0 && MF[0].flagb == 0);
    CHECK(MF[0].outer[7] == 3 && !MF[0].outer[1] && !MF[0].outer[2] && !MF[0].outer[3] && !MF[0].outer[4] &&
          !MF[0].outer[5] && !MF[0].outer[6]);                                   /* M2 */
    CHECK(MF[0].c[0].major == HID_MT2_CODE_MAJOR && MF[0].c[0].pressure == HID_MT2_CODE_PRESSURE && MF[0].c[0].flag == 0);
    id = MF[0].c[0].id;
    a.x = 30; a.y = 30;
    mt_frame(&a, 1, 0);
    CHECK(MF[1].n == 1 && MF[1].c[0].stage == 4 && MF[1].c[0].id == id && mt_at(&MF[1].c[0], 30, 30));
    a.x = 60; a.y = 60;
    mt_frame(&a, 1, 0);
    CHECK(mt_at(&MF[2].c[0], 60, 60) && MF[2].c[0].stage == 4);
    CHECK(MF[1].ts - MF[0].ts == 8 && MF[2].ts - MF[1].ts == 8);                  /* scan time: 80 x 100 us */
    CHECK(mt_tick(4000) == 0);                                                     /* M8: nothing to end */
    a.tip = 0;
    mt_frame(&a, 1, 0);
    at = nmf - 1;
    CHECK(MF[at].n == 1 && MF[at].c[0].stage == 5 && MF[at].c[0].id == id && MF[at].c[0].major == 0 &&
          MF[at].c[0].pressure == 0 && MF[at].outer[7] == 2);
    CHECK(mt_tick(4000) == 0);                                                     /* within a poll: wait */
    CHECK(mt_tick(4000) > 0 && MF[nmf - 1].n == 1 && MF[nmf - 1].c[0].stage == 7 && MF[nmf - 1].c[0].id == id);
    CHECK(mt_tick(8000) == HID_MT2_HEADER_BYTES + HID_MT2_FRAME_HEADER && MF[nmf - 1].n == 0);
    CHECK(mt_tick(8000) == 0 && !hid_mt2_busy(&MT) && MT.stats.lifts == 1 && MT.stats.empty_frames == 1);
    for (unsigned i = 1; i < nmf; i++)
        CHECK(MF[i].ts > MF[i - 1].ts);                                            /* M11 */
    /* M9: the same PTP ID touching again is a new touch with a new MT ID. */
    a = (struct tc){1, 1, 1, 1000, 1000};
    mt_frame(&a, 1, 0);
    CHECK(MF[nmf - 1].c[0].stage == 3 && MF[nmf - 1].c[0].id != id);
    /* Two fingers, the second a palm for life (M10); a vanished contact (no lift report) is broken. */
    ab[0] = a; ab[1] = (struct tc){0, 1, 2, 3000, 1000};
    mt_frame(ab, 2, 0);
    c = mt_find(&MF[nmf - 1], MF[nmf - 1].c[1].id);
    CHECK(MF[nmf - 1].n == 2 && MF[nmf - 1].c[0].finger == 2 && c && c->finger == 12 && c->stage == 3);
    ab[1].conf = 1;
    mt_frame(ab, 2, 0);
    CHECK(MF[nmf - 1].c[1].finger == 12 && MF[nmf - 1].c[1].stage == 4 && MT.stats.palms == 1);
    mt_frame(ab, 1, 0);                                                            /* the palm vanished */
    CHECK(MF[nmf - 1].n == 2 && MF[nmf - 1].c[1].stage == 5 && MT.stats.vanished == 1);
    mt_frame(ab, 1, 0);
    CHECK(MF[nmf - 1].n == 2 && MF[nmf - 1].c[1].stage == 7);
    mt_frame(ab, 1, 0);
    CHECK(MF[nmf - 1].n == 1 && MF[nmf - 1].c[0].stage == 4);
    /* A 30 mm jump under one PTP ID: the old touch breaks and a new one makes, in the same frame (M9). */
    ab[0].x = (uint16_t)(ab[0].x + 1000);
    mt_frame(ab, 1, 0);
    CHECK(MF[nmf - 1].n == 2 && MT.stats.jumps == 1 &&
          ((MF[nmf - 1].c[0].stage == 5 && MF[nmf - 1].c[1].stage == 3) ||
           (MF[nmf - 1].c[0].stage == 3 && MF[nmf - 1].c[1].stage == 5)) && MF[nmf - 1].c[0].id != MF[nmf - 1].c[1].id);
    /* A physical click: the device button bit (host click off), never the mouse header (M15). */
    mt_frame(ab, 1, 1);
    CHECK(MF[nmf - 1].button == 1 && MF[nmf - 1].host_click == 0 && MF[nmf - 1].outer[1] == 0);
    mt_frame(ab, 1, 0);
    CHECK(MF[nmf - 1].button == 0);
    /* Five fingers: index, middle, ring, little, thumb; distinct IDs. */
    for (unsigned i = 0; i < 5; i++)
        many[i] = (struct tc){1, 1, (uint8_t)(i + 1), (uint16_t)(800 + 700 * i), 2000};
    ab[0].tip = 0;
    mt_frame(ab, 1, 0);
    mt_frame(many, 5, 0);
    mt_frame(many, 5, 0);
    {
        unsigned fingers = 0, ids = 0, down = 0;
        const struct mtf *f = &MF[nmf - 1];
        for (unsigned i = 0; i < f->n; i++)
            if (f->c[i].stage == 4) {
                down++;
                fingers |= 1u << f->c[i].finger;
                ids |= 1u << f->c[i].id;
            }
        CHECK(down == 5 && fingers == 0x3e && __builtin_popcount(ids) == 5);
    }
    /* M16: re-applied switch: every touch ends on the ticks. */
    hid_mt2_reset(&MT);
    CHECK(mt_tick(8000) > 0 && MF[nmf - 1].n >= 5);
    {
        unsigned breaking = 0;
        for (unsigned i = 0; i < MF[nmf - 1].n; i++)
            breaking += MF[nmf - 1].c[i].stage == 5;
        CHECK(breaking == 5 && MT.stats.resets == 1);
    }
    CHECK(mt_tick(8000) > 0 && mt_tick(8000) == HID_MT2_HEADER_BYTES + HID_MT2_FRAME_HEADER && !hid_mt2_busy(&MT));
    /* M13: ten touches replaced at once by ten others: at most 16 contacts and 15 live IDs, the rest dropped. */
    for (unsigned i = 0; i < 10; i++)
        ten[i] = (struct hid_ptp_contact){i + 1, 1, 1, (int32_t)(400 * i + 100), 1500};
    pnow += 8000;
    CHECK(hid_mt2_frame(&MT, ten, 10, 0, 0, 0, pnow, r, sizeof(r)) == 8 + 4 + 10 * 9);
    for (unsigned i = 0; i < 10; i++)
        ten[i].id = i + 20;
    pnow += 8000;
    {
        uint32_t len = hid_mt2_frame(&MT, ten, 10, 0, 0, 0, pnow, r, sizeof(r));
        struct mtf f;
        unsigned seen = 0;
        CHECK(len <= HID_MT2_MAX_REPORT && mt_decode(r, len, &f) && f.n <= HID_MT2_MAX_TRACKS && MT.stats.dropped >= 4);
        for (unsigned i = 0; i < f.n; i++) {
            CHECK(!(seen & (1u << f.c[i].id)) && f.c[i].id >= 1 && f.c[i].id <= 15);
            seen |= 1u << f.c[i].id;
        }
    }
    CHECK(hid_mt2_frame(&MT, ten, 10, 0, 0, 0, pnow, r, HID_MT2_MAX_REPORT - 1) == 0);   /* a short buffer: nothing */
    /* M11: duplicate scan time and a scan wrap; the kick only when idle. */
    mt_begin();
    a = (struct tc){1, 1, 1, 1000, 1000};
    mt_frame(&a, 1, 0);
    pscan = (pscan - 80u) & 0xffffu;                 /* the next frame repeats the scan time */
    mt_frame(&a, 1, 0);
    CHECK(MF[1].ts == MF[0].ts + 8 && MT.stats.time_fallbacks == 1);   /* host clock: 8 ms */
    pnow -= 8000;                                    /* bunched in one poll, same scan: still 1 ms later */
    pscan = (pscan - 80u) & 0xffffu;
    mt_frame(&a, 1, 0);
    CHECK(MF[2].ts == MF[1].ts + 1);
    pscan = 0xffffu - 30u;
    mt_frame(&a, 1, 0);
    mt_frame(&a, 1, 0);                              /* wraps: 80 units */
    CHECK(MF[4].ts == MF[3].ts + 8);
    CHECK(hid_mt2_empty(&MT, pnow, r, sizeof(r)) == 0);                  /* a touch is down */
    a.tip = 0;
    mt_frame(&a, 1, 0);
    mt_tick(8000);
    mt_tick(8000);
    CHECK(!hid_mt2_busy(&MT) && hid_mt2_empty(&MT, pnow + 1000, r, sizeof(r)) == 12 && mt_decode(r, 12, &MF[0]) &&
          MF[0].n == 0 && MF[0].outer[7] == 2);
    /* M5: the far corner and the centre, each a first touch: Y grows upwards, centred on 5000. */
    mt_begin();
    a = (struct tc){1, 1, 1, 4762, 3099};
    mt_frame(&a, 1, 0);
    CHECK(mt_at(&MF[0].c[0], 4762, 3099) && MF[0].c[0].x == 2 * MT.wq && MF[0].c[0].y == 5000 - 2 * MT.hq);
    mt_begin();
    a = (struct tc){1, 1, 1, 2381, 1550};
    mt_frame(&a, 1, 0);
    CHECK(mt_at(&MF[0].c[0], 2381, 1550) && near(MF[0].c[0].x, 0, 2) && near(MF[0].c[0].y, 5000, 2));
}

#if SNAP_I2C_HID_FNKEYS
#include "test-snap-i2c-hid/fnkeys.c"
#endif

int main(void)
{
    test_start_and_stop();
    test_start_refusals();
    test_own_leftover();
    test_keyboard_translation();
    test_pointer();
    test_a16_touchpad();
    test_descriptor_reads();
    test_report_descriptor_scan();
    test_hid_descriptor_parse();
    test_encoders();
    test_classification();
    test_initialisation();
    test_keyboard_input();
    test_input_rejects();
    test_touchpad();
    test_nack_paths();
    test_timeouts();
    test_short_excess_errors();
    test_irq_policy();
    test_reset_and_power_quirks();
    test_reinitialisation();
    test_attention();
    test_requests();
    test_ptp_layout();
    test_ptp_enable();
    test_ptp_pointer();
    test_ptp_click();
    test_ptp_tap();
    test_ptp_scroll();
    test_ptp_contacts();
    test_ptp_timing();
    test_ptp_reset_and_reports();
    test_mt_features();
    test_mt_frames();
#if SNAP_I2C_HID_FNKEYS
    test_fnkeys();
    printf("test-snap-i2c-hid: %u checks passed (34 groups and the Fn-key layer's 8)\n", checks);
#else
    printf("test-snap-i2c-hid: %u checks passed (34 groups)\n", checks);
#endif
    return 0;
}
