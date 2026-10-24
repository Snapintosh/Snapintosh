/* SPDX-License-Identifier: MIT */
#pragma once
#define PAUTH_BANK_STRIDE 256
/* struct context's pauth_bank (asserted in probes/xnuboot/context.c). With
 * SNAP_VIEW_RECLAIM, 65 struct sprr_views before it (kernel_views and the 64
 * define-free user_views) are 8,192 bytes wider each (sprr-view.h). */
#if SNAP_VIEW_RECLAIM
#define PAUTH_BANK_CONTEXT 3172736
#else
#define PAUTH_BANK_CONTEXT 2640256
#endif
#define PAUTH_BANK_ENABLES 176
#define PAUTH_BANK_ACTIVE 184
#define PAUTH_BANK_ENTRIES 192
#define PAUTH_BANK_EXITS 200
#define PAUTH_BANK_FAILURES 208
#define PAUTH_BANK_RESTORED 216
#ifndef __ASSEMBLER__
#include "pauth-user.h"
struct pauth_switch {
    struct pauth_key_pair guest[PAUTH_KEYS],host[PAUTH_KEYS];
    uint64_t saved_hcr,saved_sctlr,enables,active,entries,exits,failures,restored;
#if defined(SNAP_NATIVE_PACGA) && SNAP_NATIVE_PACGA
    /* SNAP_NATIVE_PACGA (probes/xnuboot.c): the APGAKey this CPU had before
     * the guest kernel's GA key was loaded for EL1, the MPIDR_EL1 of the CPU
     * that saved it (0: nothing saved), and how often the guest GA key was
     * loaded. Private like the rest of the bank; in the former tail padding,
     * so the stride and every offset above are unchanged. */
    uint64_t ga_host_lo,ga_host_hi,ga_owner,ga_loads;
#endif
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct pauth_switch)==PAUTH_BANK_STRIDE,"PA bank stride");
_Static_assert(__builtin_offsetof(struct pauth_switch,enables)==PAUTH_BANK_ENABLES,"PA enable offset");
_Static_assert(__builtin_offsetof(struct pauth_switch,restored)==PAUTH_BANK_RESTORED,"PA result offset");
/* Only EL2 with all DAIF masks set. Enter installs keys for the immediate
 * guest return; leave restores before monitor C runs. No PAC or C calls here.
 * Saved host keys stay private and are cleared after verified restoration. */
int pauth_switch_enter(struct pauth_switch *);
int pauth_switch_leave(struct pauth_switch *);
#if defined(SNAP_PAUTH_EL0_LIVE) && SNAP_PAUTH_EL0_LIVE
/* SNAP_PAUTH_EL0_LIVE (probes/xnuboot.S sync_lower only): 0 with the EL0 bank
 * left installed for an entry that may be an EL0 read xnuboot_trap answers
 * live; otherwise exactly pauth_switch_leave. */
int pauth_switch_live(struct pauth_switch *);
#endif
#endif
