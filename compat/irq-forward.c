/* SPDX-License-Identifier: MIT */
#include "irq-forward.h"

static struct irqfwd_line *by_intid(struct irqfwd *f, uint32_t intid)
{
    for (unsigned n = 0; n < f->count; n++)
        if (f->line[n].intid == intid) return &f->line[n];
    return 0;
}

enum irqfwd_result irqfwd_add(struct irqfwd *f, uint32_t intid, uint32_t aic_irq)
{
    if (!f || f->count >= IRQFWD_MAX || intid < 32 || intid > 1019) return IRQFWD_BAD;
    for (unsigned n = 0; n < f->count; n++)
        if (f->line[n].intid == intid || f->line[n].aic_irq == aic_irq) return IRQFWD_BAD;
    f->line[f->count++] = (struct irqfwd_line){.intid = intid, .aic_irq = aic_irq};
    return IRQFWD_OK;
}

enum irqfwd_result irqfwd_physical(struct irqfwd *f, const struct irqfwd_ops *ops,
                                   uint32_t intid)
{
    if (!f || !ops || !ops->gic_disable || !ops->gic_complete || !ops->aic_level)
        return IRQFWD_BAD;
    struct irqfwd_line *l = by_intid(f, intid);
    if (!l) return IRQFWD_NOT_OURS;
    /* Mask before completing: a level input still high would otherwise be
     * re-delivered to EL2 the moment the priority drops. */
    ops->gic_disable(ops->ctx, intid);
    ops->gic_complete(ops->ctx, intid);
    if (l->state == IRQFWD_ASSERTED) {  /* masked already: a late, stale delivery */
        l->spurious++;
        return IRQFWD_OK;
    }
    if (ops->aic_level(ops->ctx, l->aic_irq, 1)) {
        /* No virtual source: leave the SPI masked rather than storm EL2. */
        l->spurious++;
        return IRQFWD_BAD;
    }
    l->state = IRQFWD_ASSERTED;
    l->fired++;
    return IRQFWD_OK;
}

void irqfwd_unmasked(struct irqfwd *f, const struct irqfwd_ops *ops,
                     unsigned word, uint32_t bits)
{
    if (!f || !ops || !ops->gic_pending || !ops->aic_level || !ops->gic_enable) return;
    for (unsigned n = 0; n < f->count; n++) {
        struct irqfwd_line *l = &f->line[n];
        if (l->aic_irq / 32 != word || !(bits & (UINT32_C(1) << (l->aic_irq % 32))) ||
            l->state != IRQFWD_ASSERTED) continue;
        if (ops->gic_pending(ops->ctx, l->intid)) {
            l->kept++;                  /* device still asserting: level stays up */
            continue;
        }
        ops->aic_level(ops->ctx, l->aic_irq, 0);
        l->state = IRQFWD_IDLE;
        l->resampled++;
        ops->gic_enable(ops->ctx, l->intid);
    }
}

void irqfwd_quiesce(struct irqfwd *f, const struct irqfwd_ops *ops)
{
    if (!f || !ops || !ops->gic_disable || !ops->aic_level) return;
    for (unsigned n = 0; n < f->count; n++) {
        ops->gic_disable(ops->ctx, f->line[n].intid);
        ops->aic_level(ops->ctx, f->line[n].aic_irq, 0);
        f->line[n].state = IRQFWD_IDLE;
    }
}
