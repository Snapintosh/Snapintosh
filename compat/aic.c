/* SPDX-License-Identifier: MIT */
#include "aic.h"

int aic_config_valid(const struct aic_config *config)
{
    return config && config->irqs && config->irqs <= AIC_MAX_IRQS &&
           !(config->irqs & 31) && config->revision == 0xa &&
           config->event >= 0x14a00 && !(config->event & 3);
}

int aic_pending(const struct aic_config *config, const struct aic_state *state)
{
    if (!aic_config_valid(config) || !state || !(state->control & 1)) return 0;
    unsigned words = config->irqs >> 5;
    unsigned i = 0;
    for (; i + 4 <= words; i += 4) {
        uint32_t p0 = state->unmasked[i] & (state->software[i] | state->level[i]);
        uint32_t p1 = state->unmasked[i + 1] & (state->software[i + 1] | state->level[i + 1]);
        uint32_t p2 = state->unmasked[i + 2] & (state->software[i + 2] | state->level[i + 2]);
        uint32_t p3 = state->unmasked[i + 3] & (state->software[i + 3] | state->level[i + 3]);
        if (p0 | p1 | p2 | p3) return 1;
    }
    for (; i < words; i++)
        if (state->unmasked[i] & (state->software[i] | state->level[i])) return 1;
    return 0;
}

enum aic_result aic_set_level(const struct aic_config *config,
    struct aic_state *state, unsigned irq, int level)
{
    if (!aic_config_valid(config) || !state) return AIC_BAD_CONFIG;
    if (irq >= config->irqs || (level != 0 && level != 1)) return AIC_BAD_VALUE;
    uint32_t bit = UINT32_C(1) << (irq & 31);
    if (level) state->level[irq >> 5] |= bit;
    else state->level[irq >> 5] &= ~bit;
    return AIC_OK;
}

static uint32_t acknowledge(const struct aic_config *config, struct aic_state *state)
{
    if (!(state->control & 1)) return 0;
    unsigned words = config->irqs >> 5;
    for (unsigned i=0; i<words; i++) {
        uint32_t pending = state->unmasked[i] & (state->software[i] | state->level[i]);
        if (!pending) continue;
        unsigned bit = (unsigned)__builtin_ctz(pending);
        uint32_t mask = UINT32_C(1) << bit;
        /* EVENT auto-masks the source and consumes its software request.
         * A physical/virtual producer's level remains until it deasserts.
         * Darwin completes delivery with MASK_CLR, not a separate EOI token. */
        state->unmasked[i] &= ~mask;
        state->software[i] &= ~mask;
        state->events++;
        return UINT32_C(0x10000) | ((i << 5) + bit); /* die 0, hardware type 1 */
    }
    return 0;
}

enum aic_result aic_access(const struct aic_config *config,
    struct aic_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value)
{
    if (!aic_config_valid(config) || !value) return AIC_BAD_CONFIG;
    if (width != 4 || (offset & 3)) return AIC_BAD_WIDTH;
    if (offset == 0 || offset == 4 || offset == 12) {
        if (write) return AIC_READ_ONLY;
        *value = offset == 0 ? config->revision : offset == 4 ? config->irqs :
                 UINT32_C(0x01001000); /* capacity: one die, 4096 IRQ slots */
        return AIC_OK;
    }
    if (!state) return AIC_BAD_CONFIG;
    if (offset == config->event) {
        if (write) return AIC_READ_ONLY;
        *value = acknowledge(config, state);
        return AIC_OK;
    }
    if (offset == 0x14) {
        if (write) {
            if (*value & ~UINT64_C(1)) return AIC_BAD_VALUE;
            state->control = (uint32_t)*value;
        } else *value = state->control;
        return AIC_OK;
    }
    if (offset >= 0x10000 && offset < 0x14000) {
        unsigned irq = (unsigned)((offset-0x10000) >> 2);
        if (irq >= config->irqs) return AIC_UNKNOWN_REGISTER;
        /* This virtual controller routes to its single cluster. Delayed
         * delivery groups, other targets and reserved bits need new backends. */
        if (write && *value) return AIC_BAD_VALUE;
        if (!write) *value = 0;
        return AIC_OK;
    }
    if (offset >= 0x14000 && offset < 0x14a00) {
        unsigned bank = (unsigned)((offset-0x14000) >> 9);
        unsigned word = (unsigned)((offset & 0x1ff) >> 2);
        uint32_t valid = word < (config->irqs >> 5) ? UINT32_MAX : 0;
        if (write) {
            if (bank == 4) return AIC_READ_ONLY;
            if (*value > UINT32_MAX) return AIC_BAD_VALUE;
            uint32_t bits = (uint32_t)*value & valid;
            if (bank == 0) state->software[word] |= bits;
            else if (bank == 1) state->software[word] &= ~bits;
            else if (bank == 2) state->unmasked[word] &= ~bits;
            else state->unmasked[word] |= bits;
        } else {
            if (bank < 2) *value = state->software[word] & valid;
            else if (bank < 4) *value = ~state->unmasked[word];
            else *value = state->level[word] & valid;
        }
        return AIC_OK;
    }
    return AIC_UNKNOWN_REGISTER;
}
