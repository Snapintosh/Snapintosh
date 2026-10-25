/* SPDX-License-Identifier: MIT */
/* See nvme-host.h. No libc: this links into the monitor and the native test. */
#include "nvme-host.h"

#if NVMEH_DIRECT
/* The monitor: q1n1's EL2 identity map reaches the BAR and DRAM words alike. */
#define RD(o, pa)    ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa))
#define WR(o, pa, v) ((void)(o), *(volatile uint32_t *)(uintptr_t)(pa) = (uint32_t)(v))
static void clean(const struct nvmeh_ops *o, uint64_t pa, uint64_t size)
{
    (void)o;
    for (uint64_t line = pa & ~63UL; line < pa + size; line += 64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static uint64_t now(const struct nvmeh_ops *o)
{
    uint64_t t;
    (void)o;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(t) :: "memory");
    return t;
}
#define CLEAN(o, pa, size) clean(o, pa, size)
#define NOW(o) now(o)
#else
#define RD(o, pa)    ((o)->rd((o)->ctx, (pa)))
#define WR(o, pa, v) ((o)->wr((o)->ctx, (pa), (uint32_t)(v)))
#define CLEAN(o, pa, size) ((o)->clean((o)->ctx, (pa), (size)))
#define NOW(o) ((o)->now((o)->ctx))
#endif

#define PAGE 4096u
#define CSTS_RDY 1u
#define CSTS_CFS 2u

static uint64_t rd64(const struct nvmeh_ops *o, uint64_t pa)
{
    return RD(o, pa) | (uint64_t)RD(o, pa + 4) << 32;
}

int nvmeh_adopt(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
                uint64_t mem_low, uint64_t mem_high)
{
    if (!o || !p || !s) return NVMEH_E_PARAMS;
    uint64_t end = p->dma_base + NVMEH_WINDOW_BYTES;
    int e = NVMEH_E_PARAMS;
    /* What a wrong word would turn into a stray DMA or a read outside the window. */
    if ((p->flags & ~(uint64_t)NVMEH_F_ALL) || !(p->flags & NVMEH_F_ENABLE) || !p->bar || (p->bar & 0x3fff) ||
        p->stride > 4 || !p->dma_base || (p->dma_base & 0xfffff) || end < p->dma_base ||
        p->io_tail >= NVMEH_IO_ENTRIES || p->io_head >= NVMEH_IO_ENTRIES || p->io_phase > 1 ||
        !p->io_next_cid || p->io_next_cid > 0xffff || p->lba_bytes != 512 ||
        p->first_lba > p->last_lba || p->last_lba == UINT64_MAX ||
        p->max_transfer < PAGE || !p->timeout_ticks || p->reserved ||
        ((p->flags & NVMEH_F_WRITE) ?
            (p->write_first_lba < p->first_lba || p->write_last_lba > p->last_lba ||
             p->write_first_lba > p->write_last_lba) :
            (p->write_first_lba || p->write_last_lba)))
        goto out;
    e = NVMEH_E_GUEST;
    if (p->dma_base < mem_high && mem_low < end) goto out;
    e = NVMEH_E_CTRL;
    uint32_t cc = RD(o, p->bar + NVMEH_CC), csts = RD(o, p->bar + NVMEH_CSTS);
    s->csts = csts;
    if (!(cc & 1) || !(csts & CSTS_RDY) || (csts & CSTS_CFS)) goto out;
    e = NVMEH_E_QUEUES;
    if (RD(o, p->bar + NVMEH_AQA) != ((NVMEH_ADMIN_ENTRIES - 1) << 16 | (NVMEH_ADMIN_ENTRIES - 1)) ||
        rd64(o, p->bar + NVMEH_ASQ_REG) != p->dma_base + NVMEH_ASQ ||
        rd64(o, p->bar + NVMEH_ACQ_REG) != p->dma_base + NVMEH_ACQ) goto out;
    s->tail = p->io_tail; s->head = p->io_head; s->phase = p->io_phase; s->next_cid = p->io_next_cid;
    s->status |= NVMEH_S_ADOPTED;
    e = 0;
out:
    s->prepare = (uint64_t)(int64_t)e;
    return e;
}

static uint64_t doorbell(const struct nvmeh_params *p, unsigned index)
{
    return p->bar + 0x1000 + (uint64_t)index * (4u << p->stride);
}

static int command(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
                    unsigned op, uint64_t wlba, uint32_t count, uint32_t at)
{
    if (!(s->status & NVMEH_S_ADOPTED) || (s->status & NVMEH_S_FAILED)) return NVMEH_E_DEAD;
    if (op == 1 && !(p->flags & NVMEH_F_WRITE)) { s->refused++; return NVMEH_E_READONLY; }
    uint64_t bytes = (uint64_t)count * p->lba_bytes, span = p->last_lba - p->first_lba + 1;
    if (op && (!count || wlba >= span || count > span - wlba || (at & (PAGE - 1)) ||
        bytes > p->max_transfer || at > NVMEH_DATA_BYTES || bytes > NVMEH_DATA_BYTES - at)) {
        s->refused++;
        return NVMEH_E_RANGE;
    }
    uint64_t lba = op ? p->first_lba + wlba : 0;
    if (op == 1 && (lba < p->write_first_lba || lba > p->write_last_lba ||
                    count - 1 > p->write_last_lba - lba)) {
        s->refused++;
        return NVMEH_E_RANGE;
    }
    s->csts = RD(o, p->bar + NVMEH_CSTS);
    if (!(s->csts & CSTS_RDY) || (s->csts & CSTS_CFS)) {
        s->errors++; s->status |= NVMEH_S_FAILED;
        return NVMEH_E_CTRL;
    }
    uint64_t data = op ? p->dma_base + NVMEH_DATA + at : 0;
    uint64_t pages = (bytes + PAGE - 1) / PAGE, prp2 = 0;
    if (pages == 2) prp2 = data + PAGE;
    else if (pages > 2) {
        uint64_t list = p->dma_base + NVMEH_PRP;
        for (uint64_t i = 1; i < pages; i++) {
            WR(o, list + 8 * (i - 1), (uint32_t)(data + PAGE * i));
            WR(o, list + 8 * (i - 1) + 4, (uint32_t)((data + PAGE * i) >> 32));
        }
        CLEAN(o, list, 8 * (pages - 1));
        prp2 = list;
    }
    /* Publish writes; leave no dirty line over a pending SSD read DMA. */
    if (op) CLEAN(o, data, bytes);
    uint32_t cid = (uint32_t)s->next_cid;
    s->next_cid = s->next_cid % 0xffff + 1;
    uint64_t sqe = p->dma_base + NVMEH_IOSQ + s->tail * 64;
    const uint32_t w[16] = {
        op | cid << 16, 1, 0, 0, 0, 0, (uint32_t)data, (uint32_t)(data >> 32),
        (uint32_t)prp2, (uint32_t)(prp2 >> 32), (uint32_t)lba, (uint32_t)(lba >> 32),
        op ? (count - 1) | (op == 1 ? 1u << 30 : 0) : 0, 0, 0, 0,
    };
    for (unsigned i = 0; i < 16; i++) WR(o, sqe + 4 * i, w[i]);
    CLEAN(o, sqe, 64);
    s->tail = (s->tail + 1) % NVMEH_IO_ENTRIES;
    s->last_opcode = op;
    WR(o, doorbell(p, 2), (uint32_t)s->tail);                 /* SQ 1 tail */
    uint64_t cqe = p->dma_base + NVMEH_IOCQ + s->head * 16, start = NOW(o), ticks;
    uint32_t dw3;
    for (;;) {
        CLEAN(o, cqe, 16);
        dw3 = RD(o, cqe + 12);
        ticks = NOW(o) - start;
        if (((dw3 >> 16) & 1) == s->phase) break;
        if (ticks > p->timeout_ticks) {
            s->timeouts++;
            s->csts = RD(o, p->bar + NVMEH_CSTS);
            s->status |= NVMEH_S_FAILED;
            return NVMEH_E_TIMEOUT;
        }
    }
    s->head = (s->head + 1) % NVMEH_IO_ENTRIES;
    if (!s->head) s->phase ^= 1;
    WR(o, doorbell(p, 3), (uint32_t)s->head);                 /* CQ 1 head */
    s->total_ticks += ticks;
    if (ticks > s->max_ticks) s->max_ticks = ticks;
    uint32_t status = (dw3 >> 17) & 0x7fff, dw2 = RD(o, cqe + 8);
    int identity_bad = (dw3 & 0xffff) != cid || (dw2 >> 16) != 1 ||
                       (dw2 & 0xffff) >= NVMEH_IO_ENTRIES;
    if (identity_bad || status) {
        s->errors++;
        s->last_status = (uint64_t)status << 16 | (dw3 & 0xffff);
        s->last_lba = lba;
        if (identity_bad) s->status |= NVMEH_S_FAILED;   /* out of step: stop using the queue */
        return NVMEH_E_STATUS;
    }
    if (op == 2) {
        CLEAN(o, data, bytes);                /* drop lines fetched before the DMA landed */
        s->reads++; s->read_bytes += bytes;
    } else if (op == 1) { s->writes++; s->write_bytes += bytes; }
    else s->flushes++;
    s->last_lba = lba;
    return 0;
}

int nvmeh_read(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
               uint64_t wlba, uint32_t count, uint32_t at)
{
    return command(o, p, s, 2, wlba, count, at);
}

int nvmeh_write(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
                uint64_t wlba, uint32_t count, uint32_t at)
{
    return command(o, p, s, 1, wlba, count, at);
}

int nvmeh_flush(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s)
{
    return command(o, p, s, 0, 0, 0, 0);
}

void nvmeh_stop(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s)
{
    if (s->status & NVMEH_S_ADOPTED) s->csts = RD(o, p->bar + NVMEH_CSTS);
}

#if SNAP_ANS_ASYNC
/* command() above, split at the doorbell (nvme-host.h). Statement for statement the same up to the SQ tail
 * doorbell; the flight keeps what the completion half needs. */
int nvmeh_submit(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
                 struct nvmeh_flight *f, unsigned op, uint64_t wlba, uint32_t count, uint32_t at)
{
    if (f->active) return NVMEH_E_BUSY;
    if (!(s->status & NVMEH_S_ADOPTED) || (s->status & NVMEH_S_FAILED)) return NVMEH_E_DEAD;
    if (op == 1 && !(p->flags & NVMEH_F_WRITE)) { s->refused++; return NVMEH_E_READONLY; }
    uint64_t bytes = (uint64_t)count * p->lba_bytes, span = p->last_lba - p->first_lba + 1;
    if (op && (!count || wlba >= span || count > span - wlba || (at & (PAGE - 1)) ||
        bytes > p->max_transfer || at > NVMEH_DATA_BYTES || bytes > NVMEH_DATA_BYTES - at)) {
        s->refused++;
        return NVMEH_E_RANGE;
    }
    uint64_t lba = op ? p->first_lba + wlba : 0;
    if (op == 1 && (lba < p->write_first_lba || lba > p->write_last_lba ||
                    count - 1 > p->write_last_lba - lba)) {
        s->refused++;
        return NVMEH_E_RANGE;
    }
    s->csts = RD(o, p->bar + NVMEH_CSTS);
    if (!(s->csts & CSTS_RDY) || (s->csts & CSTS_CFS)) {
        s->errors++; s->status |= NVMEH_S_FAILED;
        return NVMEH_E_CTRL;
    }
    uint64_t data = op ? p->dma_base + NVMEH_DATA + at : 0;
    uint64_t pages = (bytes + PAGE - 1) / PAGE, prp2 = 0;
    if (pages == 2) prp2 = data + PAGE;
    else if (pages > 2) {
        uint64_t list = p->dma_base + NVMEH_PRP;
        for (uint64_t i = 1; i < pages; i++) {
            WR(o, list + 8 * (i - 1), (uint32_t)(data + PAGE * i));
            WR(o, list + 8 * (i - 1) + 4, (uint32_t)((data + PAGE * i) >> 32));
        }
        CLEAN(o, list, 8 * (pages - 1));
        prp2 = list;
    }
    /* Publish writes; leave no dirty line over a pending SSD read DMA. */
    if (op) CLEAN(o, data, bytes);
    uint32_t cid = (uint32_t)s->next_cid;
    s->next_cid = s->next_cid % 0xffff + 1;
    uint64_t sqe = p->dma_base + NVMEH_IOSQ + s->tail * 64;
    const uint32_t w[16] = {
        op | cid << 16, 1, 0, 0, 0, 0, (uint32_t)data, (uint32_t)(data >> 32),
        (uint32_t)prp2, (uint32_t)(prp2 >> 32), (uint32_t)lba, (uint32_t)(lba >> 32),
        op ? (count - 1) | (op == 1 ? 1u << 30 : 0) : 0, 0, 0, 0,
    };
    for (unsigned i = 0; i < 16; i++) WR(o, sqe + 4 * i, w[i]);
    CLEAN(o, sqe, 64);
    s->tail = (s->tail + 1) % NVMEH_IO_ENTRIES;
    s->last_opcode = op;
    WR(o, doorbell(p, 2), (uint32_t)s->tail);                 /* SQ 1 tail */
    f->op = op; f->lba = lba; f->bytes = bytes; f->data = data; f->cid = cid;
    f->start = NOW(o);
    f->active = 1;
    return 0;
}

/* One pass of command()'s wait loop; past it, command()'s tail unchanged. */
int nvmeh_reap(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
               struct nvmeh_flight *f)
{
    if (!o || !p || !s || !f) return NVMEH_E_PARAMS;
    if (!f->active) return NVMEH_E_BUSY;
    uint64_t cqe = p->dma_base + NVMEH_IOCQ + s->head * 16, ticks;
    CLEAN(o, cqe, 16);
    uint32_t dw3 = RD(o, cqe + 12);
    ticks = NOW(o) - f->start;
    if (((dw3 >> 16) & 1) != s->phase) {
        if (ticks <= p->timeout_ticks) return NVMEH_PENDING;
        f->active = 0;
        s->timeouts++;
        s->csts = RD(o, p->bar + NVMEH_CSTS);
        s->status |= NVMEH_S_FAILED;
        return NVMEH_E_TIMEOUT;
    }
    f->active = 0;
    s->head = (s->head + 1) % NVMEH_IO_ENTRIES;
    if (!s->head) s->phase ^= 1;
    WR(o, doorbell(p, 3), (uint32_t)s->head);                 /* CQ 1 head */
    s->total_ticks += ticks;
    if (ticks > s->max_ticks) s->max_ticks = ticks;
    uint32_t status = (dw3 >> 17) & 0x7fff, dw2 = RD(o, cqe + 8);
    int identity_bad = (dw3 & 0xffff) != f->cid || (dw2 >> 16) != 1 ||
                       (dw2 & 0xffff) >= NVMEH_IO_ENTRIES;
    if (identity_bad || status) {
        s->errors++;
        s->last_status = (uint64_t)status << 16 | (dw3 & 0xffff);
        s->last_lba = f->lba;
        if (identity_bad) s->status |= NVMEH_S_FAILED;   /* out of step: stop using the queue */
        return NVMEH_E_STATUS;
    }
    if (f->op == 2) {
        CLEAN(o, f->data, f->bytes);          /* drop lines fetched before the DMA landed */
        s->reads++; s->read_bytes += f->bytes;
    } else if (f->op == 1) { s->writes++; s->write_bytes += f->bytes; }
    else s->flushes++;
    s->last_lba = f->lba;
    return 0;
}

int nvmeh_ready(const struct nvmeh_ops *o, const struct nvmeh_params *p, const struct nvmeh_state *s)
{
    if (!o || !p || !s) return 0;
    uint64_t cqe = p->dma_base + NVMEH_IOCQ + (s->head % NVMEH_IO_ENTRIES) * 16;
    CLEAN(o, cqe, 16);
    return (int)((RD(o, cqe + 12) >> 16) & 1) == (int)(s->phase & 1);
}
#endif
