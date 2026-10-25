/* SPDX-License-Identifier: MIT */
#include "mmio.h"

int mmio_ldp64_decode(uint32_t instruction, uint64_t esr,
    const uint64_t regs[31], uint64_t sp, struct mmio_pair *out)
{
    const uint64_t syndrome_mask = (0x3fUL << 26) | (1UL << 25) |
        (1UL << 24) | (0x1fUL << 6); /* ISV, FnV, EA, CM, S1PTW, WnR */
    if (!regs || !out ||
        (esr & syndrome_mask) != ((0x24UL << 26) | (1UL << 25)) ||
        ((esr & 0x3c) != 4 && (esr & 0x3c) != 12) ||
        (instruction & 0xffc00000U) != 0xa9400000U) return 0;
    unsigned first=instruction & 31, second=(instruction >> 10) & 31;
    unsigned base=(instruction >> 5) & 31;
    if (first == second) return 0; /* Constrained-unpredictable overlap. */
    if (base == 31 && (sp & 15)) return 0;
    int immediate=(int)((instruction >> 15) & 127);
    if (immediate & 64) immediate -= 128;
    immediate *= 8;
    uint64_t original=(base == 31 ? sp : regs[base]);
    if ((immediate < 0 && original < (uint64_t)-immediate) ||
        (immediate > 0 && original > UINT64_MAX - (uint64_t)immediate)) return 0;
    uint64_t address=original + (uint64_t)immediate;
    /* A pair crossing the address-space boundary cannot be one device entry. */
    if ((address & 7) || address > UINT64_MAX-15) return 0;
    *out=(struct mmio_pair){address, {first, second}};
    return 1;
}

void mmio_ldp64_complete(const struct mmio_pair *pair,
    const uint64_t values[2], uint64_t regs[31])
{
    if (!pair || !values || !regs) return;
    if (pair->reg[0] < 31) regs[pair->reg[0]]=values[0];
    if (pair->reg[1] < 31) regs[pair->reg[1]]=values[1];
}

int mmio_stp64_decode(uint32_t instruction, uint64_t esr,
    const uint64_t regs[31], uint64_t sp, struct mmio_pair *out)
{
    const uint64_t syndrome_mask=(0x3fUL<<26)|(1UL<<25)|(1UL<<24)|(0x1fUL<<6);
    if (!regs || !out ||
        (esr&syndrome_mask)!=((0x24UL<<26)|(1UL<<25)|(1UL<<6)) ||
        ((esr&0x3c)!=4 && (esr&0x3c)!=12) ||
        (instruction&0xffc00000U)!=0xa9000000U) return 0;
    unsigned base=(instruction>>5)&31;
    if (base==31 && (sp&15)) return 0;
    int immediate=(instruction>>15)&127;
    if (immediate&64) immediate-=128;
    immediate*=8;
    uint64_t original=base==31 ? sp : regs[base];
    if ((immediate<0 && original<(uint64_t)-immediate) ||
        (immediate>0 && original>UINT64_MAX-(uint64_t)immediate)) return 0;
    uint64_t address=original+(uint64_t)immediate;
    if ((address&7) || address>UINT64_MAX-15) return 0;
    *out=(struct mmio_pair){address,{instruction&31,(instruction>>10)&31}};
    return 1;
}

int mmio_ldr32_pre_decode(uint32_t instruction, uint64_t esr,
    const uint64_t regs[31], uint64_t sp, struct mmio_preload *out)
{
    const uint64_t syndrome_mask=(0x3fUL<<26)|(1UL<<25)|(1UL<<24)|(0x1fUL<<6);
    if (!regs || !out ||
        (esr&syndrome_mask)!=((0x24UL<<26)|(1UL<<25)) ||
        ((esr&0x3c)!=4 && (esr&0x3c)!=12) ||
        (instruction&0xffe00c00U)!=0xb8400c00U) return 0;
    unsigned reg=instruction&31, base=(instruction>>5)&31;
    if (reg==base && base!=31) return 0;
    if (base==31 && (sp&15)) return 0;
    int immediate=(instruction>>12)&511;
    if (immediate&256) immediate-=512;
    uint64_t original=base==31 ? sp : regs[base];
    if ((immediate<0 && original<(uint64_t)-immediate) ||
        (immediate>0 && original>UINT64_MAX-(uint64_t)immediate)) return 0;
    uint64_t address=original+(uint64_t)immediate;
    if ((address&3) || address>UINT64_MAX-3) return 0;
    *out=(struct mmio_preload){address,reg,base};
    return 1;
}

void mmio_ldr32_pre_complete(const struct mmio_preload *load, uint32_t value,
    uint64_t regs[31], uint64_t *sp)
{
    if (!load || !regs || !sp) return;
    if (load->reg < 31) regs[load->reg]=value;
    if (load->base == 31) *sp=load->address;
    else if (load->base < 31) regs[load->base]=load->address;
}
