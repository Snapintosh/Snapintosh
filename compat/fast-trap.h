/* SPDX-License-Identifier: MIT */
/* Lock-free handling of traps that touch only the trapping vCPU
 * (SNAP_FAST_VCPU_TRAPS, probes/xnuboot.c), and a per-vCPU census of trapped
 * system registers (SNAP_SYSREG_CENSUS). Nothing here touches hardware: the
 * monitor supplies the per-CPU operations (AT S1E1R, the native PACGA with the
 * guest GA key, ESR/FAR/SP reads, the guest counter) through fast_trap_hw,
 * so tools/test-fast-trap.c runs the same emulation natively.
 *
 * Why these classes need no service lock. The locked handler for each one
 * (xnuboot_trap_locked, EC 0x09 and EC 0x18) reads or writes only:
 *   - the trapping CPU's registers and its own exception frame;
 *   - that vCPU's user_pauth[slot], guest_apga_lo/hi, pacga_calls, clock,
 *     clock_rate/clock_* samples and arch_counter_reads. Each is written only
 *     by its own CPU; the only reader on another CPU is the final report, which
 *     runs after every executor has quiesced through the lifecycle atomics;
 *   - that vCPU's timer (CNTV_CTL/CNTV_TVAL reads: no timer state changes, so
 *     the locked path's timer_sync is not needed; the EL2 timer armed at the
 *     last write still delivers the interrupt) and its SPRR state (reads only;
 *     a root reset by another CPU leaves either value whole, and a state that
 *     fails sprr_fixed_state_valid declines);
 *   - immutable configuration (params->mem_low/mem_high, ID registers);
 *   - guest kernel text, which is const-sealed read-only at stage 2.
 * The shared parts of the locked handler are exactly what this path drops or
 * defers: c->traps (folded into report word 2 from the per-vCPU count), and
 * record() into the shared event log (the first trap of each class and each
 * ignored register per vCPU still takes the locked path, so the log keeps its
 * first-occurrence evidence). A pending stop, a latched view/install failure,
 * a monitor single-step, an open guard, a user-entry probe or CPU0's pending
 * secondary launch all decline here and take the unchanged locked path. */
#pragma once
#include <stdint.h>
#include "pauth.h"
#include "pauth-user.h"
#include "clock.h"
#include "sprr.h"

/* SNAP_LEAN_TRAPS (compat/lean-trap.h) calls the classifier and the emulation
 * from a second site (the run-ahead); keep them inlined, with the monitor's
 * operations direct, as with one caller. */
#ifndef SNAP_LEAN_TRAPS
#define SNAP_LEAN_TRAPS 0
#endif
#if SNAP_LEAN_TRAPS
#define FAST_TRAP_HOT static inline __attribute__((always_inline))
#else
#define FAST_TRAP_HOT static inline
#endif

enum fast_trap_class {
    FAST_TRAP_NONE, FAST_TRAP_PACGA, FAST_TRAP_KEY, FAST_TRAP_COUNTER,
    FAST_TRAP_ESR, FAST_TRAP_FAR, FAST_TRAP_IGNORE,
    FAST_TRAP_TIMER,  /* CNTV_CTL/CNTV_TVAL reads */
    FAST_TRAP_SPRR,   /* SPRR UPERM/PPERM/UMPRR/PMPRR reads */
    FAST_TRAP_ZERO,   /* claimed registers whose locked case reads zero, no record */
    FAST_TRAP_TIMER_WRITE, /* CNTV_TVAL writes that keep the synced timer line
                            * (probes/xnuboot.c rearms the EL2 timer, SNAP_FAST_TIMER_WRITE) */
    FAST_TRAP_IDLE_POLL,   /* data abort: the ACC idle poll (compat/fast-mmio.h,
                            * SNAP_FAST_IDLE_POLL); never a system-register class */
    FAST_TRAP_CLASSES
};

/* ESR_EL2 EC 0x18 ISS register tuple, Rt and direction removed. */
#define FAST_TRAP_SYSREG(op0,op1,crn,crm,op2) \
    (((uint64_t)(op0)<<20)|((uint64_t)(op2)<<17)|((uint64_t)(op1)<<14)| \
     ((uint64_t)(crn)<<10)|((uint64_t)(crm)<<1))
#define FAST_TRAP_ESR_EL1 FAST_TRAP_SYSREG(3,0,5,2,0)
#define FAST_TRAP_FAR_EL1 FAST_TRAP_SYSREG(3,0,6,0,0)

/* Registers whose locked handling is the provisional ignore default of
 * xnuboot_trap_locked (writes dropped, reads zero, one EV_SYSREG record).
 * Only registers the pinned kernel reaches per context switch, per recount
 * snapshot or per FIQ entry are listed; tools/test-fast-trap.py proves that
 * no locked handler or switch case claims any of them. Order is the log-bit
 * order: entries 0..6 take bits 1..7, entries 7.. take bits 14.. (compat/
 * fast-vector.h's boundary owns 8..13). Entries 7..19 are the unclaimed
 * registers the 2026-10-16 census found on the lock (docs/
 * FAST-TRAP-BATCH-20261016.md): 26.3M of a 600 s boot's traps. */
#define FAST_TRAP_IGNORED 20u
static const uint64_t fast_trap_ignored[FAST_TRAP_IGNORED] = {
    FAST_TRAP_SYSREG(3,0,13,0,1),  /* CONTEXTIDR_EL1: TVM/TRVM, every thread switch */
    FAST_TRAP_SYSREG(3,4,15,13,6), /* JAPIBKeyLo: thread switch with new keys */
    FAST_TRAP_SYSREG(3,4,15,13,7), /* JAPIBKeyHi */
    FAST_TRAP_SYSREG(3,2,15,0,0),  /* PMC0 (cycles): recount snapshot ...b920404 */
    FAST_TRAP_SYSREG(3,2,15,1,0),  /* PMC1 (instructions): recount ...b920408 */
    FAST_TRAP_SYSREG(3,1,15,0,0),  /* PMCR0: read at every FIQ entry (sleh_fiq) */
    FAST_TRAP_SYSREG(3,7,15,6,4),  /* UPMSR (uncore PMU status): read by sleh_fiq */
    FAST_TRAP_SYSREG(3,2,15,2,0),  /* PMC2..PMC7: read as a group with PMC8/PMC9 */
    FAST_TRAP_SYSREG(3,2,15,3,0),
    FAST_TRAP_SYSREG(3,2,15,4,0),
    FAST_TRAP_SYSREG(3,2,15,5,0),
    FAST_TRAP_SYSREG(3,2,15,6,0),
    FAST_TRAP_SYSREG(3,2,15,7,0),
    FAST_TRAP_SYSREG(3,2,15,9,0),  /* PMC8 */
    FAST_TRAP_SYSREG(3,2,15,10,0), /* PMC9 */
    FAST_TRAP_SYSREG(3,4,15,15,6), /* read and written per context switch */
    FAST_TRAP_SYSREG(3,4,15,10,4),
    FAST_TRAP_SYSREG(3,1,15,1,5),
    FAST_TRAP_SYSREG(3,4,15,1,4),
    FAST_TRAP_SYSREG(3,4,15,1,3),  /* AMX_STATE_T_EL1: per context switch */
};

/* Claimed registers whose xnuboot_trap_locked case is exactly "reads zero",
 * with no record (tools/test-fast-trap.py checks the case body). */
static inline int fast_trap_zero_reg(uint64_t reg)
{
    return reg==FAST_TRAP_SYSREG(3,6,15,8,0);   /* GXF_STATUS_EL1: no guarded world */
}

/* The key registers pauth_user_reg models: IA/IB/DA/DB/GA lo/hi, KERNKey
 * (Apple EXTRA) lo/hi and APCTL. tools/test-fast-trap.c checks this predicate
 * against pauth_user_reg over every Op0=3 register tuple. O(1) bitmask check
 * replaces the 10-iteration nested crm/op2 loop on every EC 0x18 trap. */
FAST_TRAP_HOT int fast_trap_key_reg(uint64_t reg)
{
    if(reg==FAST_TRAP_SYSREG(3,4,15,1,0) || reg==FAST_TRAP_SYSREG(3,4,15,1,1) ||
       reg==FAST_TRAP_SYSREG(3,4,15,0,4))return 1;
    if((reg & ~((UINT64_C(7) << 17) | (UINT64_C(15) << 1))) == FAST_TRAP_SYSREG(3,0,2,0,0)) {
        unsigned crm = (unsigned)((reg >> 1) & 15u);
        unsigned op2 = (unsigned)((reg >> 17) & 7u);
        return (crm == 1u || crm == 2u) ? (op2 < 4u) : (crm == 3u && op2 < 2u);
    }
    return 0;
}

/* The counter reads guest_clock_access answers from the per-vCPU clock alone.
 * CNTKCTL (which also programs hardware) and every timer stay locked. */
static inline int fast_trap_counter_reg(uint64_t reg)
{
    return reg==CLOCK_CNTVCT || reg==CLOCK_CNTVCTSS ||
           reg==CLOCK_ARCH_CNTVCT || reg==CLOCK_ARCH_CNTVCTSS;
}

static inline int fast_trap_ignored_index(uint64_t reg)
{
    for(unsigned i=0;i<FAST_TRAP_IGNORED;i++)if(fast_trap_ignored[i]==reg)return (int)i;
    return -1;
}

FAST_TRAP_HOT unsigned fast_trap_sysreg_class(uint64_t reg,int is_read)
{
#if SNAP_LEAN_TRAPS
    /* The hot reads first (compat/lean-trap.h). The classes are disjoint, so
     * the order changes no result. */
    if(is_read) {
        if(fast_trap_counter_reg(reg))return FAST_TRAP_COUNTER;
        if(reg==FAST_TRAP_ESR_EL1)return FAST_TRAP_ESR;
        if(reg==FAST_TRAP_FAR_EL1)return FAST_TRAP_FAR;
        if(reg==SPRR_UPERM || reg==SPRR_PPERM || reg==SPRR_UMPRR || reg==SPRR_PMPRR)
            return FAST_TRAP_SPRR;
    }
#endif
    if(fast_trap_key_reg(reg))return FAST_TRAP_KEY;
    if(is_read && fast_trap_counter_reg(reg))return FAST_TRAP_COUNTER;
    if(is_read && reg==FAST_TRAP_ESR_EL1)return FAST_TRAP_ESR;
    if(is_read && reg==FAST_TRAP_FAR_EL1)return FAST_TRAP_FAR;
    if(fast_trap_ignored_index(reg)>=0)return FAST_TRAP_IGNORE;
    if(is_read && (reg==CLOCK_CNTV_CTL || reg==CLOCK_CNTV_TVAL))return FAST_TRAP_TIMER;
    if(!is_read && reg==CLOCK_CNTV_TVAL)return FAST_TRAP_TIMER_WRITE;
    if(is_read && (reg==SPRR_UPERM || reg==SPRR_PPERM || reg==SPRR_UMPRR || reg==SPRR_PMPRR))
        return FAST_TRAP_SPRR;
    if(fast_trap_zero_reg(reg))return FAST_TRAP_ZERO;
    return FAST_TRAP_NONE;
}

/* One bit per class whose locked handler records into the shared log (PACGA)
 * and one per ignored register; zero for classes that never record. */
static inline uint64_t fast_trap_log_bit(unsigned cls,uint64_t reg)
{
    if(cls==FAST_TRAP_PACGA)return 1;
    if(cls==FAST_TRAP_IGNORE) {
        int i=fast_trap_ignored_index(reg);
        return i<0 ? 0 : i<7 ? UINT64_C(2)<<i : UINT64_C(1)<<(14+i-7);
    }
    return 0;
}

/* Per-vCPU counters, one cache line group per CPU (written without the lock).
 * The exception boundary (compat/fast-vector.h: SNAP_VECTOR_BRANCH,
 * SNAP_FAST_CROSSINGS) shares declined, first and logged (its log bits are
 * 8..13; this file uses 0..7 and 14..26) and owns the next three words. */
struct fast_trap_cpu {
    uint64_t handled[FAST_TRAP_CLASSES]; /* emulated here, by class */
    uint64_t sysreg;    /* EC 0x18 traps emulated here: report word 2 adds these */
    uint64_t declined;  /* classified candidates sent to the locked path */
    uint64_t first;     /* ...of which first occurrences kept for the shared log */
    uint64_t logged;    /* fast_trap_log_bit bits already recorded by the locked path */
    uint64_t branches;  /* vector slots performed instead of stepped, locked and fast */
    uint64_t entries;   /* vector entries handled without the lock */
    uint64_t returns;   /* ERETs handled without the lock */
    uint64_t reserved;  /* zero */
    /* SNAP_WFI_RESUME (compat/wfi-resume.h): EL2 timer ticks by
     * enum wfi_resume_result -- [0] re-entered the guest's WFI, [1..7] decline
     * reasons. Written by this CPU only, under the service lock or in its
     * lock-free tick (SNAP_FAST_TIMER_IRQ); zero otherwise.
     * In the former tail padding, so the size and every older offset hold. */
    uint32_t wfi[8];
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct fast_trap_cpu)==192,"three cache lines per CPU");

/* Everything the emulation needs from the CPU, supplied by the monitor. */
struct fast_trap_hw {
    void *ctx;
    uint64_t mem_low,mem_high;  /* owned guest RAM: the only instruction source */
    int pac_supported;          /* generic_pauth_supported() */
    uint64_t (*guest_pa)(void *ctx,uint64_t va);          /* AT S1E1R, 0 = fault */
    uint32_t (*fetch)(void *ctx,uint64_t pa);             /* instruction word at pa */
    uint64_t (*stack)(void *ctx,uint64_t spsr);           /* SP_EL1 or SP_EL0 */
    uint64_t (*sign)(void *ctx,uint64_t data,uint64_t modifier); /* guest GA key */
    uint64_t (*esr)(void *ctx);
    uint64_t (*far)(void *ctx);
    const struct clock_backend *clock;  /* the vCPU's counter backend */
};
/* The trapping vCPU's private state, exactly the fields the locked path uses. */
struct fast_trap_vcpu {
    struct pauth_user_state *pauth;
    uint64_t *apga_lo,*apga_hi,*pacga_calls;
    struct guest_clock *clock;
    uint64_t *arch_counter_reads;
    struct guest_timer *timer;
    struct sprr_state *sprr;
    const uint64_t *timer_pending;      /* the timer line timer_sync last synced */
};

/* Emulate one EC 0x09 PACGA or EC 0x18 system-register trap from AArch64 EL1
 * exactly as xnuboot_trap_locked would, minus c->traps and record(). Returns
 * the class emulated (frame, *elr and the vCPU state updated) or
 * FAST_TRAP_NONE with nothing changed, in which case the caller must take the
 * locked path. Never decides a stop: every failure declines. */
FAST_TRAP_HOT unsigned fast_trap_emulate(const struct fast_trap_hw *hw,
    const struct fast_trap_vcpu *v,uint64_t esr,uint64_t spsr,uint64_t *frame,uint64_t *elr)
{
    uint64_t ec=esr>>26,iss=esr&0x1ffffff;
    unsigned mode=(unsigned)(spsr&31);
    if(mode!=4 && mode!=5)return FAST_TRAP_NONE;     /* AArch64 EL1t/EL1h only */
    if(ec==0x09) {
        if(!hw->pac_supported)return FAST_TRAP_NONE;
        uint64_t pa=hw->guest_pa(hw->ctx,*elr);
        if(pa<hw->mem_low || pa>hw->mem_high-4)return FAST_TRAP_NONE;
        uint32_t word=hw->fetch(hw->ctx,pa);
        /* pauth_pacga changes nothing unless the word is PACGA. */
        if(!pauth_pacga(word,frame,hw->stack(hw->ctx,spsr),hw->sign,hw->ctx))
            return FAST_TRAP_NONE;
        (*v->pacga_calls)++;*elr+=4;return FAST_TRAP_PACGA;
    }
    if(ec!=0x18)return FAST_TRAP_NONE;
    uint64_t reg=iss&~((UINT64_C(0x1f)<<5)|1),rt=(iss>>5)&0x1f;
    int is_read=(int)(iss&1);
    unsigned cls=fast_trap_sysreg_class(reg,is_read);
    uint64_t value=rt==31 ? 0 : frame[rt];
    switch(cls) {
    case FAST_TRAP_KEY:
        if(!pauth_user_reg(v->pauth,reg,is_read,&value))return FAST_TRAP_NONE;
        *v->apga_lo=v->pauth->key[PAUTH_GA].lo;
        *v->apga_hi=v->pauth->key[PAUTH_GA].hi;
        break;
    case FAST_TRAP_COUNTER:
        /* A counter read has no failing branch with a configured backend; a
         * failure would leave the clock untouched and take the locked path. */
        if(guest_clock_access(v->clock,hw->clock,reg,1,&value)!=CLOCK_OK)return FAST_TRAP_NONE;
        if(reg==CLOCK_ARCH_CNTVCT || reg==CLOCK_ARCH_CNTVCTSS)(*v->arch_counter_reads)++;
        break;
    case FAST_TRAP_ESR: value=hw->esr(hw->ctx);break;
    case FAST_TRAP_FAR: value=hw->far(hw->ctx);break;
    case FAST_TRAP_IGNORE: if(is_read)value=0;break;
    case FAST_TRAP_TIMER:
        /* guest_timer_access as the locked path calls it: one counter sample. */
        if(!v->timer)return FAST_TRAP_NONE;
        if(guest_timer_access(v->timer,reg,1,&value,hw->clock->counter(hw->clock->ctx))!=CLOCK_OK)
            return FAST_TRAP_NONE;
        break;
    case FAST_TRAP_SPRR:
        /* A read changes only readback bookkeeping; an invalid state declines first. */
        if(!v->sprr || !sprr_fixed_state_valid(v->sprr) ||
           sprr_access_with(v->sprr,reg,1,&value,0,0)!=SPRR_OK)return FAST_TRAP_NONE;
        break;
    case FAST_TRAP_ZERO: if(is_read)value=0;break;
    case FAST_TRAP_TIMER_WRITE: {
        /* Only a write that leaves the timer line as last synced: with
         * cval=now+(int32)TVAL, guest_timer_control's (int64)(cval-now)<=0 is
         * (int32)TVAL<=0, so the line after is known before the clock sample.
         * Anything else needs guest_interrupt_sync: the locked path. */
        if(!v->timer || !v->timer_pending)return FAST_TRAP_NONE;
        int line=v->timer->ctl==1 && (int32_t)(uint32_t)value<=0;
        if(line!=!!*v->timer_pending)return FAST_TRAP_NONE;
        if(guest_timer_access(v->timer,reg,0,&value,hw->clock->counter(hw->clock->ctx))!=CLOCK_OK)
            return FAST_TRAP_NONE;
        break;
    }
    default: return FAST_TRAP_NONE;
    }
    if(is_read && rt!=31)frame[rt]=value;
    *elr+=4;return cls;
}

/* Diagnostic census of EC 0x18 traps by register and direction, per vCPU.
 * Counts every trapped access, locked or fast. Open-addressed: the key's hash
 * picks a home slot and a linear probe finds it or the first empty slot, so
 * an encoding first trapped late in boot is still named, at about one compare
 * per trap. `other` counts only keys that found the whole table taken; it must
 * stay 0 for a complete census (docs/SYSREG-CENSUS-20261016.md). The 48-slot
 * first-come list this replaces lost 31% of a boot's traps that way. */
#define SYSREG_CENSUS_BITS 8u
#define SYSREG_CENSUS_SLOTS (1u<<SYSREG_CENSUS_BITS)
struct sysreg_census_cpu {
    uint64_t key[SYSREG_CENSUS_SLOTS];   /* reg|is_read, plus 1 so zero is empty */
    uint64_t count[SYSREG_CENSUS_SLOTS];
    uint64_t total,other,pacga,keys;     /* keys: distinct encodings stored */
} __attribute__((aligned(64)));
static inline unsigned sysreg_census_home(uint64_t key)
{
    return (unsigned)((key*UINT64_C(0x9e3779b97f4a7c15))>>(64-SYSREG_CENSUS_BITS));
}
static inline void sysreg_census_note(struct sysreg_census_cpu *s,uint64_t esr)
{
    uint64_t ec=esr>>26;
    if(ec==0x09) {s->pacga++;return;}
    if(ec!=0x18)return;
    uint64_t iss=esr&0x1ffffff,key=(iss&~(UINT64_C(0x1f)<<5))+1;
    s->total++;
    for(unsigned n=0,i=sysreg_census_home(key);n<SYSREG_CENSUS_SLOTS;n++,i=(i+1)&(SYSREG_CENSUS_SLOTS-1)) {
        if(s->key[i]==key) {s->count[i]++;return;}
        if(!s->key[i]) {s->key[i]=key;s->count[i]=1;s->keys++;return;}
    }
    s->other++;
}
