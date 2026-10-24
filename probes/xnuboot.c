/* SPDX-License-Identifier: MIT */
/* SPTM endpoint numbers and return codes: from m1n1, https://github.com/AsahiLinux/m1n1:
 * Copyright The Asahi Linux Contributors, MIT. */
/* Enter a stock XNU kernelcache at EL1 on silicon that has none of what it
 * expects, and report what it asks for first.
 *
 * Everything the host prepared is already in memory: the rebased image, 16K
 * page tables mapping it at 0xfffffe00_........, and the two handoff structures
 * the entry stub validates (probes/xnuboot.py). This does the parts that can
 * only be done at EL2:
 *
 *   - walk those 16K tables and emit an equivalent 4K translation, because the
 *     hardware cannot walk a 16K granule (docs/FEASIBILITY.md)
 *   - build a stage-2 map covering only what actually exists, so a touch of
 *     anything else is a fault at EL2 with the address in it, rather than a
 *     silent wander
 *   - mark the monitor-call pages and XNU's own exception vectors execute-never
 *     at stage 2, so both a `genter` and a fault XNU takes arrive here
 *   - ERET to the entry point with x0 = 0, x1 and x2 pointing at the handoff
 *
 * The first thing XNU does after setting its vectors is one monitor call with
 * x16 = 0xf. Reaching that is the milestone; everything before it is the boot
 * stub, and everything after is a new endpoint to implement.
 */
#include "shadow.h"
#include "sprr-view.h"
#include "sprr-publish.h"
#include "sprr-reuse.h"
#include "sprr-variants.h"
#include "sprr-class-proof.h"
#include "sprr-private-pages.h"
#include "stage2.h"
#include "dockchannel.h"
#include "idregs.h"
#include "../compat/pauth.h"
#include "../compat/pauth-user.h"
#include "../compat/pauth-domain.h"
#include "../compat/pauth-switch.h"
#include "../compat/pauth-native.h"
#include "../compat/pauth-batch.h"
#include "../compat/pauth-pointer.h"
#include "secondary.h"
#include "../compat/cpu-release.h"
#include "../compat/exception.h"
#include "../compat/panic-state.h"
#include "../compat/clock.h"
#include "../compat/ipi.h"
#include "../compat/cpu.h"
#include "../compat/service-lock.h"
#include "../compat/service-profile.h"
#include "../compat/service-detail.h"
#include "../compat/step-translation.h"
#include "../compat/step-alu.h"
#include "../compat/native-call.h"
#include "../compat/native-writer.h"
#include "../compat/native-writer-debug.h"
#include "xnuboot/feature_flags.c"
#include "../compat/device.h"
#include "../compat/mmio.h"

/* What the host puts in memory for us. Laid out by probes/xnuboot.py; the two
 * sides are checked against each other by the size assertion below. */
#include "../compat/sptm.h"
#include "../compat/sptm-refs.h"
#include "../compat/sptm-dart.h"
#include "../compat/sptm-slide.h"
#include "../compat/sptm-user.h"
#include "../compat/sptm-root.h"
#include "../compat/sptm-root-memo.h"
#include "../compat/sptm-root-policy.h"
#include "../compat/inactive-mirror.h"
#include "../compat/native-select.h"
#include "../shadow/native-view.h"
#include "../shadow/native-shared.h"
#include "../compat/sptm-papt.h"
#include "../compat/txm.h"
#include "../compat/uat.h"
#include "../compat/cputrace.h"
#include "../compat/cpu-runtime.h"
#include "../compat/table-pool.h"
#include "../shadow/root-publish.h"
#ifndef SNAP_ROOT_DIRTY_PUBLISH
#define SNAP_ROOT_DIRTY_PUBLISH 0
#endif
#include "../shadow/user-publish.h"
#ifndef SNAP_USER_DIRTY_PUBLISH
#define SNAP_USER_DIRTY_PUBLISH 0
#endif
_Static_assert(!SNAP_USER_DIRTY_PUBLISH ||
    (SNAP_ROOT_DIRTY_PUBLISH && SNAP_PRIVATE_VIEW_EPOCH && SNAP_USER_VIEW_BATCH),
    "user publication requires tracked writes, private ownership and batch views");
#include "../shadow/txn-publish.h"
/* Transaction-end cache publication from the root dirty bitmap instead of a
 * clean of the whole allocated arena (UPDATE_DISJOINT/REGION, kernel
 * UNMAP_REGION, SLIDE_REGION, aperture retypes). Sentinel-checked. */
#ifndef SNAP_TXN_DIRTY_PUBLISH
#define SNAP_TXN_DIRTY_PUBLISH 0
#endif
_Static_assert(!SNAP_TXN_DIRTY_PUBLISH || SNAP_ROOT_DIRTY_PUBLISH,
    "transaction publication shares the audited root dirty bitmap");
/* Keep the exact kernel-view snapshot valid across a PPERM transaction that
 * began current; skip that CPU's kernel sync when the new value cannot change
 * a kernel descriptor. Sampled read-only verification of every skipped view. */
#ifndef SNAP_KERNEL_PPERM_REUSE
#define SNAP_KERNEL_PPERM_REUSE 0
#endif
_Static_assert(!SNAP_KERNEL_PPERM_REUSE || (SNAP_KERNEL_VIEW_REUSE && SNAP_KERNEL_DIRTY_PUBLISH),
    "PPERM reuse extends the exact kernel snapshot and needs publication bits");
/* User-root UPDATE_DISJOINT touches no kernel canonical table, kernel copy or
 * PPERM: skip its redundant kernel refresh (publication and the all-VMID TLBI
 * are kept). Sampled read-only verification of all six kernel views. */
#ifndef SNAP_USER_UPDATE_KERNEL_SKIP
#define SNAP_USER_UPDATE_KERNEL_SKIP 0
#endif
_Static_assert(!SNAP_USER_UPDATE_KERNEL_SKIP || SNAP_USER_ONLY_TLBI,
    "user-update kernel skip extends the qualified user-only invalidation contract");
/* SNAP_UPDATE_CHECK_SPARSE: the skip's read-only re-derivation of all six
 * kernel copies runs 1 in 1024 skips instead of 1 in 64. A weaker audit
 * (opt-in): a stale copy is found later, never repaired; the skip itself is
 * unchanged. tools/kernel_ops_perf.py checks verified == skipped // 1024. */
#ifndef SNAP_UPDATE_CHECK_SPARSE
#define SNAP_UPDATE_CHECK_SPARSE 0
#endif
_Static_assert(!SNAP_UPDATE_CHECK_SPARSE || SNAP_USER_UPDATE_KERNEL_SKIP,
    "the sparse check samples the user-update kernel skip");
/* Root installation ends with its own all-VMID TLBI before the CPU can run
 * EL1/EL0 again; earlier invalidations of this CPU's private copies inside the
 * same installation are folded into it (issued anyway on any failure path). */
#ifndef SNAP_INSTALL_TLBI_DEFER
#define SNAP_INSTALL_TLBI_DEFER 0
#endif
/* Class-proof walks map each canonical table once (bounded span check) and
 * test eight-word zero groups; every descriptor is still loaded and decided
 * identically. Sampled hits still re-walk through the original word reader. */
#ifndef SNAP_CLASS_PROOF_MAPPED
#define SNAP_CLASS_PROOF_MAPPED 0
#endif
/* Reuse unchanged L3 class summaries using the existing table write clock.
 * Whole-tree coverage, structure checks and sampled word re-walks remain. */
#ifndef SNAP_CLASS_LEAF_MEMO
#define SNAP_CLASS_LEAF_MEMO 0
#endif
_Static_assert(!SNAP_CLASS_LEAF_MEMO ||
    (SNAP_CLASS_PROOF_MAPPED && SNAP_KERNEL_CLASS_PROOF && SNAP_USER_TREE_MEMO),
    "class leaf reuse requires mapped whole proofs and table write generations");
/* The TPRO preflight's kernel class proof made incremental: a miss reuses the
 * L3 summaries of tables whose write generation is unchanged and rescans the
 * rest; a sampled hit re-walks every table through one refusing mapping
 * instead of one callback per word (shadow/sprr-class-fast.h, which lists
 * the measurement and failure modes; tools/test-kernel-pperm-fast.py). */
#ifndef SNAP_KERNEL_PPERM_FAST
#define SNAP_KERNEL_PPERM_FAST 0
#endif
_Static_assert(!SNAP_KERNEL_PPERM_FAST ||
    (SNAP_CLASS_PROOF_MAPPED && SNAP_KERNEL_CLASS_PROOF && SNAP_USER_TREE_MEMO &&
     !SNAP_CLASS_LEAF_MEMO),
    "the fast class proof needs mapped whole proofs and table write generations, "
    "and replaces the leaf-memo option");
#if SNAP_KERNEL_PPERM_FAST
#include "sprr-class-fast.h"
#endif
/* SWITCH_ROOT validates the incoming user tree with aligned 64-bit descriptor
 * loads instead of eight volatile byte loads each; 1 in 64 validations repeats
 * the byte walk and must agree (compat/sptm-root.c). */
#ifndef SNAP_ROOT_VALIDATE_WORDS
#define SNAP_ROOT_VALIDATE_WORDS 0
#endif
/* A cache-hit SWITCH_ROOT reuses level-3 verdicts retained since their table
 * page, its frame record and every referenced mapped frame's type last
 * changed (compat/sptm-root-memo.h). Root, level-2, child records and links
 * are still checked on every switch; builds validate everything; the sampled
 * byte walk above runs without the memo and must agree. */
#ifndef SNAP_ROOT_VALIDATE_MEMO
#define SNAP_ROOT_VALIDATE_MEMO 0
#endif
_Static_assert(!SNAP_ROOT_VALIDATE_MEMO || SNAP_ROOT_VALIDATE_WORDS,
    "retained root verdicts require the sampled reference walk");
/* DART table verdicts (compat/sptm-dart-memo.h, docs/DART-MEMO-20261019.md):
 * MAP, UNMAP, MAP_TABLE and DMA translation skip the per-table scan for a
 * table that passed it with the same refs and no published store since;
 * sptm_publish is the write witness, every 64th hit is re-scanned. Kept in
 * root_ext, reported below the thermal block (OUT_DART_MEMO). */
#ifndef SNAP_DART_MEMO
#define SNAP_DART_MEMO 0
#endif
#if SNAP_DART_MEMO
#include "../compat/sptm-dart-memo.h"
_Static_assert(SNAP_ROOT_CACHE_WIDE, "the DART memo lives in the wide cache's arena pages");
#endif
/* MAP_PAGE and MAP_TABLE on a cached user root that no CPU has installed keep
 * its shadow in step with the guest tree instead of discarding it for a
 * rebuild on the next switch (compat/inactive-mirror.h). Fresh leaves use the
 * active root's prepare/commit pair, bounded per slot; TPRO leaves, a spent
 * budget, uncached roots and CONFIGURE_ROOT still invalidate. */
#ifndef SNAP_INACTIVE_MIRROR
#define SNAP_INACTIVE_MIRROR 0
#endif
/* Native page tables, phase 1 (docs/NATIVE-TABLES-DESIGN-20260929.md): a user
 * root runs on two permission-variant trees (TPRO read-only / writable) that
 * every CPU shares, each with its own hardware ASID, kept exact per canonical
 * store (shadow/native-view.h). SWITCH_ROOT, UPERM and TPRO PPERM writes and
 * EL0/EL1 boundaries select a variant (compat/native-select.h); user commits
 * invalidate exactly their 4K entries in every VMID. Proofs run sampled, 1 in
 * 2^SNAP_NATIVE_AUDIT_SHIFT (0: every time). */
#ifndef SNAP_NATIVE_TABLES
#define SNAP_NATIVE_TABLES 0
#endif
#ifndef SNAP_NATIVE_AUDIT_SHIFT
#define SNAP_NATIVE_AUDIT_SHIFT 6
#endif
_Static_assert(SNAP_NATIVE_AUDIT_SHIFT<32,"native audit sample");
/* Native page tables, phase 3 (SNAP_NATIVE_SHARED): a 16K user root links
 * each nested shared-region level-3 table to one shared set of 4K level-3
 * tables (shadow/native-shared.h) instead of copying its leaves into every
 * cached root. Builds, NEST and UNNEST link and unlink; a shared-region leaf
 * change is written once, for every nesting root and variant. */
#ifndef SNAP_NATIVE_SHARED
#define SNAP_NATIVE_SHARED 0
#endif
_Static_assert(!SNAP_NATIVE_SHARED || SNAP_NATIVE_TABLES,"shared groups need native page tables");
/* The table-pool allocation domain of every shared group page. */
#define NATIVE_SHARED_OWNER 200u
/* SNAP_NATIVE_LIVE: a new 16K user root is cached from its constructor with an
 * empty tree, so every SPTM call keeps it exact from its first mapping and its
 * first SWITCH_ROOT needs no build; an inactive root mirrors every MAP_PAGE
 * (no per-install budget, TPRO included: variant copies are kept per store). */
#ifndef SNAP_NATIVE_LIVE
#define SNAP_NATIVE_LIVE 0
#endif
_Static_assert(!SNAP_NATIVE_LIVE || SNAP_NATIVE_SHARED,"live roots need shared groups");
/* SNAP_ROOT_MISS_FAST (compat/root-miss.h): a full user-root cache gives up
 * the least recently installed inactive root (root_stamp) instead of the next
 * one round robin, and a miss's two walks answer the nested SHARED level-3
 * tables a linked build links from the retained verdicts above, as a hit
 * does; every copied table is still scanned in full. */
#ifndef SNAP_ROOT_MISS_FAST
#define SNAP_ROOT_MISS_FAST 0
#endif
_Static_assert(!SNAP_ROOT_MISS_FAST || (SNAP_ROOT_VALIDATE_MEMO && SNAP_ROOT_VALIDATE_WORDS &&
               SNAP_NATIVE_SHARED),
    "miss-path verdicts need their write witness, the sampled walk and linked builds");
/* SNAP_UPDATE_DISJOINT_FAST (compat/update-fast.h): a user leaf update whose
 * old leaf has AF clear (never cacheable: user regimes run with TCR.HA clear)
 * skips its TLBI; the sampled kernel-copy verifications check all six CPUs in
 * one pass with sprr_views_verify_cpu's exact verdict. */
#ifndef SNAP_UPDATE_DISJOINT_FAST
#define SNAP_UPDATE_DISJOINT_FAST 0
#endif
_Static_assert(!SNAP_UPDATE_DISJOINT_FAST || SNAP_NATIVE_TABLES,
    "the skipped invalidation is native_tlbi_range's");
#if SNAP_UPDATE_DISJOINT_FAST
#include "../compat/update-fast.h"
#endif
/* SNAP_ROOT_CACHE_WIDE (compat/root-wide.h): 192 cached user roots instead of
 * 64. Every slot's state lives in monitor arena pages taken at setup
 * (struct root_ext); struct context keeps its define-free 64-slot fields,
 * refreshed from the live state when the run stops (root_ext_mirror). */
#ifndef SNAP_ROOT_CACHE_WIDE
#define SNAP_ROOT_CACHE_WIDE 0
#endif
_Static_assert(!SNAP_ROOT_CACHE_WIDE || SNAP_NATIVE_SHARED,
    "wide link bits are the native-shared groups'");
#if SNAP_ROOT_CACHE_WIDE
#include "../compat/root-wide.h"
#endif
/* SNAP_USER_HW_WALK (compat/user-hw-walk.h, docs/USER-HW-WALK-20261017.md):
 * a 4K (format 1, SNAP_KERNEL_USER_4K) user root runs on its own guest
 * tables -- an UMPRR18 root on two monitor copies of the paths to its TPRO
 * leaves -- with its own hardware ASIDs: SWITCH_ROOT builds, caches and walks
 * nothing, and every SPTM call keeps the copies exact and invalidates what it
 * changed. 16K roots keep the shadow path unchanged. SNAP_USER_HW_WALK_S2RO
 * (on with it unless set to 0) keeps every SPTM page-table frame read-only at
 * stage 2 while typed, so the guest cannot edit a hardware-walked tree behind
 * the SPTM's validation. */
#ifndef SNAP_USER_HW_WALK
#define SNAP_USER_HW_WALK 0
#endif
#ifndef SNAP_USER_HW_WALK_S2RO
#define SNAP_USER_HW_WALK_S2RO SNAP_USER_HW_WALK
#endif
_Static_assert(!SNAP_USER_HW_WALK || (SNAP_NATIVE_TABLES && SNAP_ROOT_DIRTY_PUBLISH),
    "hardware-walk roots use the native per-CPU variant selection, TLBI and dirty-page flush");
_Static_assert(!SNAP_USER_HW_WALK_S2RO || SNAP_USER_HW_WALK,
    "stage-2 table protection is part of the hardware walk");
#if SNAP_USER_HW_WALK
#include "../compat/user-hw-walk.h"
_Static_assert(HW_WALK_OWNER!=NATIVE_SHARED_OWNER && HW_WALK_OWNER>SPTM_ROOT_CACHE &&
               HW_WALK_OWNER<TABLE_POOL_FREE,"copy pages have their own table-pool domain");
#define HW_WALK_PAGES ((sizeof(struct hw_walk_state)+4095)/4096)
#endif
/* SNAP_S2_FAULT_RETRY (compat/s2-fault-retry.h): a stage-2 translation fault
 * whose hardware IPA (HPFAR) is guest RAM this CPU's tree maps is snapshotted
 * and retried, bounded, instead of stopping the run; every stage-2 stop
 * carries HPFAR_EL2 in its terminal event. SNAP_S2_FAULT_RETRY_STAGE1 also
 * retries one whose HPFAR IPA is not mapped but whose stage-1 re-walk's is.
 * Off: nothing changes. */
#ifndef SNAP_S2_FAULT_RETRY
#define SNAP_S2_FAULT_RETRY 0
#endif
#ifndef SNAP_S2_FAULT_RETRY_STAGE1
#define SNAP_S2_FAULT_RETRY_STAGE1 0
#endif
_Static_assert(!SNAP_S2_FAULT_RETRY_STAGE1 || SNAP_S2_FAULT_RETRY,
    "the STAGE1 retry is part of the stage-2 fault retry");
#if SNAP_S2_FAULT_RETRY
#include "../compat/s2-fault-retry.h"
_Static_assert(S2_RETRY_CPUS==GUEST_CPU_COUNT,"one retry bound per vCPU");
#endif
/* SNAP_IDREG_MMFR3: every vCPU also records ID_AA64MMFR3_EL1 (S1PIE [11:8],
 * S1POE [19:16]) and ID_AA64MMFR1_EL1 at setup, one EV_OTHER event each
 * (probes/run.py "permission features"). Off: nothing changes. */
#ifndef SNAP_IDREG_MMFR3
#define SNAP_IDREG_MMFR3 0
#endif
/* Root installation cleans its noted pages with one barrier for the whole
 * flush (the installation sequence's own leading dsb ish) instead of one
 * dsb ish per page. */
#ifndef SNAP_ROOT_PUBLISH_BATCH_DSB
#define SNAP_ROOT_PUBLISH_BATCH_DSB 0
#endif
_Static_assert(!SNAP_ROOT_PUBLISH_BATCH_DSB || SNAP_ROOT_DIRTY_PUBLISH,
    "batched root publication applies to the dirty root flush");
_Static_assert(!SNAP_CLASS_PROOF_MAPPED || SNAP_KERNEL_CLASS_PROOF,
    "mapped class walks replace only the cached proof's full walk");
/* Emulate traps that touch only the trapping vCPU without the service lock:
 * PACGA, the modeled PAC key registers, guest counter reads, ESR/FAR reads and
 * the ignored context-switch/recount registers (compat/fast-trap.h has the
 * per-class shared-state proof). Declines to the locked path on any stop,
 * failure, step, guard, probe or pending secondary launch. */
#ifndef SNAP_FAST_VCPU_TRAPS
#define SNAP_FAST_VCPU_TRAPS 0
#endif
/* Diagnostic: per-vCPU counts of trapped system registers by encoding and
 * direction (locked and fast alike), for profiling the remaining traps. */
#ifndef SNAP_SYSREG_CENSUS
#define SNAP_SYSREG_CENSUS 0
#endif
/* CNTV_TVAL writes that keep the timer's synced interrupt line, applied without
 * the lock and rearmed by timer_arm; and the ACC idle-poll read
 * (compat/fast-mmio.h) answered without it (docs/FAST-TRAP-BATCH2-20261016.md). */
#ifndef SNAP_FAST_TIMER_WRITE
#define SNAP_FAST_TIMER_WRITE 0
#endif
#ifndef SNAP_FAST_IDLE_POLL
#define SNAP_FAST_IDLE_POLL 0
#endif
_Static_assert(!(SNAP_FAST_TIMER_WRITE || SNAP_FAST_IDLE_POLL) || SNAP_FAST_VCPU_TRAPS,
               "the timer-write and idle-poll paths use the fast-trap admission and counters");
/* A bit-8 PPERM flip exchanges this CPU's kernel copy column with its variant
 * column and installs the new root in TTBR1 (shadow/sprr-variants.h,
 * docs/KERNEL-PPERM-VARIANTS-20261016.md). */
#ifndef SNAP_KERNEL_PPERM_VARIANTS
#define SNAP_KERNEL_PPERM_VARIANTS 0
#endif
_Static_assert(!SNAP_KERNEL_PPERM_VARIANTS || (SNAP_NATIVE_TABLES && SNAP_KERNEL_PPERM_REUSE &&
               SNAP_KERNEL_VIEW_REUSE && SNAP_KERNEL_DIRTY_PUBLISH),
               "variants need the native local flush, the snapshot proof and dirty publication");
/* SNAP_AUDIT_SPARSE (compat/audit-sparse.h, which lists the measurement and
 * the failure modes): the TPRO class-proof hit verification, the kernel
 * refresh's reuse-hit verification, the exact kernel-variant swap
 * verification and the PPERM-reuse skip verification sample 1 in 1024 events
 * instead of 1 in 64 (AUDIT_SAMPLE_MASK). A weaker audit, accepted for speed;
 * every audited mechanism is unchanged (tools/test-audit-sparse.py). */
#include "../compat/audit-sparse.h"
_Static_assert(!SNAP_AUDIT_SPARSE ||
    (SNAP_KERNEL_PPERM_FAST && SNAP_KERNEL_VIEW_REUSE && SNAP_KERNEL_PPERM_REUSE &&
     SNAP_KERNEL_PPERM_VARIANTS),
    "the sparse audits sample the fast class proof, the kernel view reuse proof, "
    "the PPERM reuse skip and the kernel PPERM variants");
/* XNU's vector slot starts with an unconditional B out of its page: perform
 * it instead of opening the execute-never vector page for one single step, so
 * a guest exception costs no step exit, stage-2 write or broadcast TLBI
 * (compat/fast-vector.h). A slot holding anything else keeps the step. */
#ifndef SNAP_VECTOR_BRANCH
#define SNAP_VECTOR_BRANCH 0
#endif
/* Take the native-call exception snapshot at the ERET exit instead of at the
 * hardware breakpoint on exception_return's SPSR write (native writer site 5),
 * whose comparator is left unarmed. Prepare proves that the code from that
 * write to the kernel's only ERET is straight-line, forward-only, call-free
 * and exception-free (native_writer_return_window), so no native call can
 * restore a stale snapshot in between. The other five groups keep theirs. */
#ifndef SNAP_ERET_SNAPSHOT
#define SNAP_ERET_SNAPSHOT 0
#endif
_Static_assert(!SNAP_ERET_SNAPSHOT || SNAP_NATIVE_WRITER_BREAKPOINTS,
               "the ERET snapshot replaces one of the writer breakpoints");
/* The vector entry and the ERET of the common exception classes without the
 * service lock (compat/fast-vector.h has the per-class shared-state proof):
 * kernel page faults, EL0 SVCs and page faults and the virtual timer/device
 * interrupts on entry; kernel returns and user returns on exit. A crossing
 * between EL0 and EL1 is lock-free only under SNAP_NATIVE_TABLES, through
 * native_cross; otherwise it keeps the locked view switch. Declines to the
 * locked path on any stop, failure, step, guard, probe, pending secondary
 * launch, SPTM call or other class. */
#ifndef SNAP_FAST_CROSSINGS
#define SNAP_FAST_CROSSINGS 0
#endif
_Static_assert(!SNAP_FAST_CROSSINGS || (SNAP_FAST_VCPU_TRAPS && SNAP_VECTOR_BRANCH),
               "lock-free crossings share the fast-trap admission and never open the vector page");
/* The two EL0 IMPDEF reads this silicon cannot execute (SPRR_UPERM and the
 * ordered counter alias) emulated in the lock-free crossing path, exactly as
 * user_sysreg_access does under the lock; every other EL0 EC 0 entry, the
 * UPERM write included, stays locked (compat/fast-vector.h fast_el0_sysreg).
 * exit_profile.cpu[].el0 counts the outcomes. */
#ifndef SNAP_FAST_EL0_SYSREG
#define SNAP_FAST_EL0_SYSREG 0
#endif
_Static_assert(!SNAP_FAST_EL0_SYSREG || (SNAP_FAST_CROSSINGS && SNAP_NATIVE_TABLES),
               "the EL0 emulation is a lock-free crossing class; without native tables EL0 entries decline");
#define FAST_CROSS_EL0_SYSREG SNAP_FAST_EL0_SYSREG
/* The kernel's PACGA without a trap (docs/SPEED-BATCH4-20261020.md): each
 * vCPU keeps the guest kernel's GA key (guest_apga, the modeled APGAKey
 * writes) in APGAKey while EL1 runs and sets HCR_EL2.API for EL1, so PACGA
 * runs natively under exactly the key generic_sign would load. The kernel's
 * address-key enables stay masked, so every other PAC instruction still
 * returns its input; EL0 keeps its per-process bank (compat/pauth-switch.S).
 * The host APGAKey is saved in the private PAC bank and restored on each
 * CPU's terminal path. */
#ifndef SNAP_NATIVE_PACGA
#define SNAP_NATIVE_PACGA 0
#endif
/* The EL0 reads fast_el0_sysreg answers (SPRR_UPERM, the ordered counter
 * alias) return to EL0 with the process's PAC bank still installed: no
 * pauth_switch_leave on the entry, no pauth_switch_enter on the return, since
 * no EL1 instruction runs in between and the answer needs no other bank.
 * sync_lower's pauth_switch_live leaves the bank live only for that entry's
 * syndrome; el0_live_trap re-checks the exact slot, runs fast_crossing, and
 * restores the bank (pauth_switch_leave) before any other C when it declines;
 * xnuboot_pauth_resume refuses to reach EL1 with the bank live. */
#ifndef SNAP_PAUTH_EL0_LIVE
#define SNAP_PAUTH_EL0_LIVE 0
#endif
#if SNAP_PAUTH_EL0_LIVE && !(SNAP_FAST_CROSSINGS && SNAP_FAST_EL0_SYSREG)
#error "SNAP_PAUTH_EL0_LIVE keeps the bank live only for SNAP_FAST_EL0_SYSREG's lock-free EL0 reads"
#endif
#if SNAP_PAUTH_EL0_LIVE && defined(SNAP_PAUTH_FIXED_KEYS) && SNAP_PAUTH_FIXED_KEYS
#error "SNAP_PAUTH_FIXED_KEYS removes the bank switch; review before combining it with SNAP_PAUTH_EL0_LIVE"
#endif
/* Batch 6 (compat/el0-memo.h): fast_el0_word answers the EL0 read's fetch from
 * a per-vCPU memo of the PC page's translation, kept only from an agreeing
 * double read and trusted for addresses only: each hit re-reads every
 * descriptor both walks read, the code frame's type and the word, and
 * fast_el0_sysreg then skips its repeat read (FAST_EL0_FETCH_PROVEN). Every
 * root install on a vCPU makes its memo stale. The user return derives its
 * PAC bank through a 128-entry second level behind the 8-entry memo, which
 * reuses each key's constant first block (compat/pauth-domain.h); both levels
 * belong to the domain epoch xnuboot_prepare bumps. State in root_ext. */
#ifndef SNAP_EL0_MEMO
#define SNAP_EL0_MEMO 0
#endif
#if SNAP_EL0_MEMO && !(SNAP_PAUTH_EL0_LIVE && SNAP_ROOT_CACHE_WIDE)
#error "SNAP_EL0_MEMO memoizes SNAP_PAUTH_EL0_LIVE's lock-free EL0 reads and keeps its state in SNAP_ROOT_CACHE_WIDE's arena pages"
#endif
#if SNAP_EL0_MEMO
#include "../compat/el0-memo.h"
#endif
#define FAST_CROSS_EL0_MEMO SNAP_EL0_MEMO
/* Instrumentation (rides along, no trap removed): lock wait and hold of the
 * locked instruction aborts by sub-class (vector entry, each EL0 emulation,
 * each SPTM endpoint; compat/service-profile.h service_sub_*), and the
 * CNTPCT round trip of every lock-free exit by class (compat/perf-state.h
 * fast_exit_charge). Both live in exit_profile. */
#ifndef SNAP_SERVICE_SUBCLASS
#define SNAP_SERVICE_SUBCLASS 0
#endif
_Static_assert(!SNAP_SERVICE_SUBCLASS || SNAP_SERVICE_PROFILE,
               "sub-classes refine the service profile's EC 0x20 bucket");
/* Clear HCR_EL2.TWE: the guest's WFE runs natively and the hardware event
 * stream wakes it (CNTKCTL_EL1.EVNTEN as the guest sets it, EVNTI rescaled
 * from the guest to the host counter rate, clock_event_host_control),
 * instead of a trap that polls for the emulated event under the lock. */
#ifndef SNAP_NATIVE_WFE
#define SNAP_NATIVE_WFE 0
#endif
/* SNAP_EL0_WFE: SCTLR_EL1.nTWE (bit 18) in the SCTLR_EL1 this monitor
 * installs, as 26A428's SPTM installs it for XNU's regime (sptm.t8140 boot:
 * MOVK x0 = 0x12001010fc14793d, MSR SCTLR_EL1). Without it every EL0 WFE or
 * WFET traps to EL1, where XNU's handle_wf_trap (sleh.c:2474) raises
 * EXC_BAD_INSTRUCTION, a SIGILL. libdispatch waits for a racing enqueuer with
 * LDXR/WFE (_dispatch_wait_for_enqueuer+12), so any dispatch process can die
 * of it; launchd did in installed-fresh-20261017-v41, -20261019-v88,
 * -20261020-v16 and -desktop-20261021-v1 (initproc exited, subcode 0x4).
 * With SNAP_NATIVE_WFE (HCR_EL2.TWE clear) EL0 WFE then waits natively like
 * EL1's: SEV, a cleared exclusive monitor, the rescaled event stream or any
 * interrupt (the EL2 tick included) wakes it. Without it the WFE traps to EL2,
 * where the trapped-WFE branch answers every origin (clock_wfe, ELR+4) and
 * resume_lower reloads the EL0 PAC bank. nTWI stays clear: XNU traps EL0 WFI
 * on Apple silicon too. The readback refuses at preparation (-26). */
#ifndef SNAP_EL0_WFE
#define SNAP_EL0_WFE 0
#endif
/* SNAP_EL0_CACHE_MAINT: SCTLR_EL1.UCI (bit 26), the other EL0 permission
 * SPTM's value grants and the installed one lacks. Without it EL0 DC CVAU,
 * DC CVAC, DC CIVAC, DC CVAP, DC CVADP and IC IVAU trap to EL1 as EC 0x18,
 * which XNU's handle_msr_trap also turns into SIGILL. 26A428's shared cache
 * has one such EL0 instruction: IC IVAU in sys_icache_invalidate
 * (libsystem_platform), which JITs and code loaders call. Native: the
 * hardware checks translation and permission and reports faults to XNU as
 * ordinary EL0 data aborts with CM set. Separate from SNAP_EL0_WFE so either
 * can be withdrawn alone. */
#ifndef SNAP_EL0_CACHE_MAINT
#define SNAP_EL0_CACHE_MAINT 0
#endif
#define EL0_SCTLR_GRANTS ((SNAP_EL0_WFE ? (1UL << 18) : 0UL) | \
                          (SNAP_EL0_CACHE_MAINT ? (1UL << 26) : 0UL))
/* A monitor-only EL2 timer tick (the 1 ms IPI poll, the run budget, the host
 * stop poll) that interrupted an idle guest WFI in const-sealed kernel text,
 * with nothing to deliver and the next tick armed within the poll, returns to
 * the WFI instead of WFI+4: XNU's idle exit and re-entry do not run for a wake
 * that brought nothing (compat/wfi-resume.h). perf.fast[cpu].wfi counts it. */
#ifndef SNAP_WFI_RESUME
#define SNAP_WFI_RESUME 0
#endif
#if SNAP_WFI_RESUME
#include "../compat/wfi-resume.h"
#endif
/* vCPU 0's tick, too, without the token while none of its own duties (the
 * host poll, the thermal sample, the GPU tick) is due, with a locked tick at
 * least every FAST_IRQ_CPU0_LOCKED_MS (SNAP_FAST_TIMER_IRQ below;
 * docs/SPEED-BATCH4-20261020.md). */
#ifndef SNAP_FAST_TIMER_IRQ_CPU0
#define SNAP_FAST_TIMER_IRQ_CPU0 0
#endif
#define FAST_IRQ_CPU0 SNAP_FAST_TIMER_IRQ_CPU0
/* The EL2 timer tick of vCPUs 1-5 (the 1 ms IPI poll, the guest timer) without
 * the service token: this vCPU's timer, lines, re-arm, EOI and WFI decision.
 * vCPU 0, any other interrupt, a due or unsynced device deadline, a latched
 * reset, a due budget or early stop and every fast-trap admission decline take
 * the locked tick (compat/fast-timer-irq.h). root_ext->fast_irq[cpu] counts
 * the outcomes (the context's last page has no room), reported after the
 * exit-profile records (OUT_FAST_IRQ). */
#ifndef SNAP_FAST_TIMER_IRQ
#define SNAP_FAST_TIMER_IRQ 0
#endif
#if SNAP_FAST_TIMER_IRQ
#include "../compat/fast-timer-irq.h"
_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE && SNAP_SERVICE_SUBCLASS,
               "the lock-free tick uses the fast-trap admission, counts in the wide cache's arena pages "
               "and reports after the exit profile");
/* wfi_resume also runs in the lock-free tick: words other CPUs write under
 * the token are read atomically there. */
#define WFI_SHARED(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#else
#define WFI_SHARED(x) (x)
#endif
_Static_assert(!SNAP_FAST_TIMER_IRQ_CPU0 || SNAP_FAST_TIMER_IRQ,
               "vCPU 0's quiet tick is the secondaries' lock-free tick");
/* The Apple IPI registers (IPI_RR_LOCAL/GLOBAL, IPI_SR) without the service
 * token: guest_ipi_route's decision with atomic posts and acknowledgements
 * (compat/fast-ipi.h; compat/ipi.c's locked ones match under the define), for
 * a CPU the fast-trap admission accepts. root_ext->fast_ipi[cpu] counts the
 * outcomes, reported just below the thermal block (OUT_FAST_IPI). */
#ifndef SNAP_FAST_IPI
#define SNAP_FAST_IPI 0
#endif
#if SNAP_FAST_IPI
#include "../compat/fast-ipi.h"
_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE,
               "the lock-free IPI registers use the fast-trap admission and count in the wide cache's arena pages");
#endif
/* Fewer and cheaper lock-free system-register exits (compat/lean-trap.h).
 * 1: after an ESR/FAR/PMC read the lock-free path also emulates the adjacent
 * MRS it answers (one trap per FAR/ESR or PMC0/PMC1 pair), the counter
 * conversion has no division, and only PACGA reads the PAC ID registers.
 * 2: also FEAT_FGT in place of HCR_EL2.TVM/TRVM on each CPU whose FGT
 * registers read back, so ESR_EL1/FAR_EL1 reads and CONTEXTIDR_EL1 writes run
 * natively (needs SCR_EL3.FGTEn; unrecorded). root_ext->lean[cpu] holds the
 * saved host values; one EV_OTHER record (pc 3) per vCPU gives the outcome. */
#ifndef SNAP_LEAN_TRAPS
#define SNAP_LEAN_TRAPS 0
#endif
#if SNAP_LEAN_TRAPS
#include "../compat/lean-trap.h"
_Static_assert(SNAP_LEAN_TRAPS == 1 || SNAP_LEAN_TRAPS == 2, "SNAP_LEAN_TRAPS is 1 or 2");
_Static_assert(SNAP_FAST_VCPU_TRAPS && SNAP_ROOT_CACHE_WIDE,
               "lean traps extend the fast-trap path and keep their state in the wide cache's arena pages");
#endif
/* vCPU 0 on a physical CPU other than q1n1's, chosen by the host (secondary
 * configuration mask bit 0), so all six vCPUs share one cluster that is not
 * q1n1's: the A16's Prime cluster 1 (compat/boot-relocate.h). Off, the code is
 * absent and bit 0 is refused as before. */
#ifndef SNAP_BOOT_RELOCATE
#define SNAP_BOOT_RELOCATE 0
#endif
#if SNAP_BOOT_RELOCATE
#include "../compat/boot-relocate.h"
#endif
/* ADRENO_GUEST_UNMAP also subtracts the leaves it clears from XNU's IOMMU
 * table count, as t8110dart_unmap would (compat/dart-wiredcnt.h): the kext's
 * unwire/rewire otherwise overflows it (installed-fresh-20261017-v29). */
#ifndef SNAP_DART_WIREDCNT
#define SNAP_DART_WIREDCNT 0
#endif
#if SNAP_DART_WIREDCNT
#include "../compat/dart-wiredcnt.h"
#endif
/* The built-in keyboard's GENI I2C page as Device-nGnRE passthrough for the
 * SnapI2CHID kext, from struct i2c_input_params appended to struct params
 * (compat/i2c-input.h, probes/i2cinput.py; cycle.py installed-fresh --input). */
#ifndef SNAP_I2C_INPUT
#define SNAP_I2C_INPUT 0
#endif
#if SNAP_I2C_INPUT
#include "../compat/i2c-input.h"
#endif
/* The QCC2072 Wi-Fi endpoint (BAR0, BAR2, its ECAM page read-only) and its
 * 64 MiB DMA arena and read-only control page for the SnapintoshQCC2072 kext,
 * from struct qcc2072_wifi_params appended after struct params
 * (compat/qcc2072-wifi.h, probes/qcc2072wifi.py; installed-fresh --qcc2072-wifi). */
#ifndef SNAP_QCC2072_WIFI
#define SNAP_QCC2072_WIFI 0
#endif
#if SNAP_QCC2072_WIFI
#include "../compat/qcc2072-wifi.h"
#endif
/* The eDP interface's timing engine page (DPU INTF_5) as read-only Device-nGnRE passthrough for the AdrenoDisplay
 * kext's beam (-DADRENO_BEAM=1), from struct display_timing_params appended after struct params and, when built in,
 * the QCC2072 block (compat/display-timing.h, probes/displaytiming.py; installed-fresh --present-beam). */
#ifndef SNAP_DISPLAY_TIMING
#define SNAP_DISPLAY_TIMING 0
#endif
#if SNAP_DISPLAY_TIMING
#include "../compat/display-timing.h"
#define SNAP_DISPLAY_TIMING_ROWS DISPLAY_TIMING_STAGE2_MAX
#else
#define SNAP_DISPLAY_TIMING_ROWS 0
#endif
/* NEST_REGION and UNNEST_REGION answer nested shared level-3 tables from the
 * SWITCH_ROOT memo's retained verdicts (or scan each once), and UNMAP_TABLE of
 * an empty level-3 table proves both trees empty table by table
 * (compat/nest-fast.h, docs/TOKEN-COSTS-20261018.md). */
#ifndef SNAP_NEST_FAST
#define SNAP_NEST_FAST 0
#endif
#ifndef SNAP_DETACH_FAST
#define SNAP_DETACH_FAST 0
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "../compat/nest-fast.h"
_Static_assert(!SNAP_NEST_FAST || (SNAP_ROOT_VALIDATE_MEMO && SNAP_ROOT_VALIDATE_WORDS && SNAP_NATIVE_SHARED),
    "nest verdicts are the SWITCH_ROOT memo's: its write witness, its sampled walk, linked groups");
_Static_assert(SNAP_ROOT_CACHE_WIDE,"the nest-fast counters live in the wide cache's arena pages");
#endif
/* UNNEST_REGION on 4K (format 1) user roots, the kernel-user-4k route's,
 * answers nested shared tables and their leaf counts from the same memo
 * (compat/nest-fast.h 3, docs/UNNEST-4K-FAST-20261020.md). */
#ifndef SNAP_UNNEST_4K_FAST
#define SNAP_UNNEST_4K_FAST 0
#endif
#if SNAP_UNNEST_4K_FAST && !SNAP_NEST_FAST
#error "SNAP_UNNEST_4K_FAST extends SNAP_NEST_FAST's UNNEST answer: build with SNAP_NEST_FAST"
#endif
/* TXM35/36/37 and USER_ROOT constructors find root records through an index
 * kept at every frame-type commit instead of scanning the whole frame map
 * (compat/root-index.h, docs/TOKEN-COSTS-20261018.md). */
#ifndef SNAP_ROOT_INDEX
#define SNAP_ROOT_INDEX 0
#endif
#if SNAP_ROOT_INDEX
#include "../compat/root-index.h"
_Static_assert(SNAP_ROOT_CACHE_WIDE,"the root index lives in the wide cache's arena pages");
#endif
/* call_other split by what the native call was, and a converted call that
 * waits out a long token hold on the gate instead of declining after 2^16
 * yields (compat/token-costs.h, docs/TOKEN-COSTS-20261018.md). */
#ifndef SNAP_OTHER_PROFILE
#define SNAP_OTHER_PROFILE 0
#endif
#ifndef SNAP_GATE_WAIT
#define SNAP_GATE_WAIT 0
#endif
/* compat/service-lock.h SNAP_PHASE_FAIR_GATE (batch 6): its announced wait is
 * bounded, and withdrawn at the bound, in SNAP_GATE_WAIT's loop. */
#if SNAP_PHASE_FAIR_GATE && !SNAP_GATE_WAIT
#error "SNAP_PHASE_FAIR_GATE bounds and withdraws a converted call's announced wait in SNAP_GATE_WAIT's loop"
#endif
#define SNAP_TOKEN_COSTS (SNAP_NEST_FAST || SNAP_DETACH_FAST || SNAP_ROOT_INDEX || SNAP_OTHER_PROFILE || \
                          SNAP_GATE_WAIT)
#if SNAP_TOKEN_COSTS
#include "../compat/token-costs.h"
_Static_assert(SNAP_ROOT_CACHE_WIDE && SNAP_SERVICE_SUBCLASS,
    "the token-cost counters live in the wide cache's arena pages and report after the exit profile");
#endif
/* SIGN/AUTH/BATCH_SIGN_USER_POINTER off the service token: converted calls
 * of the fine-lock dispatcher. Their header, which also defaults this
 * define, is included only with the fine locks, so the default and the
 * refusal of a build without them are here too. */
#ifndef SNAP_FAST_PAUTH_CALLS
#define SNAP_FAST_PAUTH_CALLS 0
#endif
#if SNAP_FAST_PAUTH_CALLS && !SNAP_FINE_LOCKS
#error "SNAP_FAST_PAUTH_CALLS converts calls in the fine locks' dispatcher: build with SNAP_FINE_LOCKS"
#endif
/* The kernel refresh's reuse proof from the table memo's write witness, and the
 * Adreno DART's MAP/UNMAP as converted calls (compat/token-trim.h, batch 5). */
#ifndef SNAP_TOKEN_TRIM
#define SNAP_TOKEN_TRIM 0
#endif
#if SNAP_TOKEN_TRIM
#include "../compat/token-trim.h"
#if !SNAP_KERNEL_VIEW_REUSE || !SNAP_USER_TREE_MEMO || !SNAP_ROOT_CACHE_WIDE || !SNAP_SERVICE_SUBCLASS
#error "SNAP_TOKEN_TRIM needs SNAP_KERNEL_VIEW_REUSE and SNAP_USER_TREE_MEMO (the witness), SNAP_ROOT_CACHE_WIDE (its state) and SNAP_SERVICE_SUBCLASS (its report)"
#endif
#endif
/* The Adreno DART's MAP/UNMAP as converted calls on their own: SNAP_TOKEN_TRIM's
 * part B without its kernel-view witness (compat/dart-converted.h, batch 9). The
 * fine-lock header refuses it without the fine locks and the pointer calls, and
 * beside SNAP_TOKEN_TRIM. */
#ifndef SNAP_DART_CONVERTED
#define SNAP_DART_CONVERTED 0
#endif
#if SNAP_DART_CONVERTED
#include "../compat/dart-converted.h"
#if !SNAP_FINE_LOCKS || !SNAP_ROOT_CACHE_WIDE
#error "SNAP_DART_CONVERTED needs SNAP_FINE_LOCKS (the converted-call dispatcher) and SNAP_ROOT_CACHE_WIDE (its state)"
#endif
#endif
/* SNAP_SPTM_FINE, SNAP_SPTM_FINE_RETYPE, SNAP_SPTM_FINE_KERNEL (compat/fine-lock.h,
 * agents/sptm-locks/FAILURE-MODES.md): more converted SPTM calls. The fine-lock
 * header refuses them without the fine locks and the hardware-walk events;
 * here, without what their converted bodies assume. */
#if SNAP_SPTM_FINE && (!SNAP_USER_HW_WALK || !SNAP_UPDATE_DISJOINT_FAST)
#error "SNAP_SPTM_FINE needs SNAP_USER_HW_WALK (its update events) and SNAP_UPDATE_DISJOINT_FAST (update_fast_uncached)"
#endif
#if SNAP_SPTM_FINE_KERNEL
#include "../compat/sptm-fine.h"
#endif
/* SNAP_REUSE_MATCH_MAPPED (shadow/sprr-reuse.h lists the measurement and the
 * failure modes): kernel_refresh_impl's exact reuse proof reads each copied
 * source table through class_table_read instead of one kernel_table_read
 * callback per word. Same verdict, counters and state. */
#if SNAP_REUSE_MATCH_MAPPED && (!SNAP_KERNEL_VIEW_REUSE || !SNAP_CLASS_PROOF_MAPPED || SNAP_TOKEN_TRIM)
#error "SNAP_REUSE_MATCH_MAPPED needs SNAP_KERNEL_VIEW_REUSE and SNAP_CLASS_PROOF_MAPPED (class_table_read), and not SNAP_TOKEN_TRIM (its witness answers the same proof)"
#endif
/* Root installation and transaction-end publication enumerate an index of
 * pages noted since the last publish instead of every bitmap word; same
 * callback sequence and counters (shadow/root-publish-index.h). _VERIFY also
 * enumerates the bitmap on every listed flush and must agree. */
#ifndef SNAP_INCREMENTAL_PUBLISH
#define SNAP_INCREMENTAL_PUBLISH 0
#endif
#ifndef SNAP_INCREMENTAL_PUBLISH_VERIFY
#define SNAP_INCREMENTAL_PUBLISH_VERIFY 0
#endif
_Static_assert(!SNAP_INCREMENTAL_PUBLISH || (SNAP_ROOT_DIRTY_PUBLISH && SNAP_TXN_DIRTY_PUBLISH),
    "the index lists pages of the root dirty bitmap both flushes consume");
_Static_assert(!SNAP_INCREMENTAL_PUBLISH_VERIFY || SNAP_INCREMENTAL_PUBLISH,
    "verification compares the index with the bitmap it indexes");
/* UPERM writes and TPRO PPERM transactions prove the canonical user view with
 * whole-table shadow reads and one source walk per source page
 * (sptm_root_view_mapped); every 64th proof also runs the reference walk and
 * any difference is terminal. */
#ifndef SNAP_CANONICAL_VIEW_FAST
#define SNAP_CANONICAL_VIEW_FAST 0
#endif
/* Appended last to struct context in every build, like the other appended
 * state, so host layout readers (which compute layouts without build defines)
 * agree with every monitor on the context size and the table-arena base. */
#include "../compat/perf-state.h"
#include "../compat/fast-mmio.h"
/* Keep the last EL0 crash-class events per vCPU (abort()'s self-SIGABRT,
 * kill with a core signal, payload aborts, fatal EL0 exception classes and
 * wild-address aborts) with registers, four frame records and any reason
 * string, read at XNU's vector entry. Diagnostic only; delivery unchanged.
 * The context field is present in every build (compat/user-crash.h). */
#ifndef SNAP_USER_CRASH_RING
#define SNAP_USER_CRASH_RING 0
#endif
#include "../compat/user-crash.h"
#include "../compat/auxkc-observe.h"
#include "../compat/adreno.h"
#include "../compat/adreno-fill.h"
#include "../compat/adreno-ib.h"
#if SNAP_ADRENO_COHERENT
/* SNAP_ADRENO_COHERENT: the boot self-test that may make CB0's mirror leaves IO-coherent, the
 * ADRENO_GUEST_COHERENT query and the coherent ADRENO_GUEST_CACHE variant. Its state is in root_ext. */
#include "../compat/adreno-coherent.h"
#if !SNAP_ROOT_CACHE_WIDE
#error "SNAP_ADRENO_COHERENT keeps its state in root_ext: it needs SNAP_ROOT_CACHE_WIDE"
#endif
#endif
#include "../compat/ans.h"
#include "../compat/ans-window.h"
#include "../compat/nvme-host.h"
/* agents/nvme-async (FAILURE-MODES.md): SNAP_ANS_ASYNC serves the virtual ANS2's I/O queue without waiting for
 * the SSD (compat/ans.h); SNAP_ANS_CONVERTED runs its I/O doorbells and table-6 MAP/UNMAP_PAGES as converted
 * calls under the ANS device lock; SNAP_ATTR_CLEAN_DEFER moves attr_clean_finish's second clean past the token. */
#if SNAP_ANS_ASYNC && !SNAP_ROOT_CACHE_WIDE
#error "SNAP_ANS_ASYNC keeps its schedule pointer in root_ext: it needs SNAP_ROOT_CACHE_WIDE"
#endif
#if SNAP_ANS_CONVERTED && (!SNAP_FINE_LOCKS || !SNAP_ROOT_CACHE_WIDE)
#error "SNAP_ANS_CONVERTED needs SNAP_FINE_LOCKS (the gate and the converted-call dispatcher) and SNAP_ROOT_CACHE_WIDE"
#endif
#ifndef SNAP_ATTR_CLEAN_DEFER
#define SNAP_ATTR_CLEAN_DEFER 0
#endif
#if SNAP_ATTR_CLEAN_DEFER
#if !SNAP_ROOT_CACHE_WIDE
#error "SNAP_ATTR_CLEAN_DEFER keeps each CPU's deferred list in root_ext: it needs SNAP_ROOT_CACHE_WIDE"
#endif
#define ATTR_DEFER_MAX 1024u        /* frames per call; past it attr_clean_finish cleans inline (D2) */
#endif
/* agents/sptm-locks/multipage (FAILURE-MODES.md P1-P18): SNAP_MULTIPAGE_FAST. UPDATE_DISJOINT_MULTIPAGE's
 * aperture steps are pre-cleaned before the token is taken, skip both cleans when the AttrIndx keeps its
 * cacheability class, patch a changed word of a kernel-view copy source into the six copies and the reuse
 * snapshot instead of a full re-sync, and are published, refreshed and invalidated once per run of headers
 * (b12v16: 7.79 ms per call, 82 % of it full view re-syncs, 12 % reuse proofs). */
#ifndef SNAP_MULTIPAGE_FAST
#define SNAP_MULTIPAGE_FAST 0
#endif
#if SNAP_MULTIPAGE_FAST && (!SNAP_ATTR_CLEAN_DEFER || !SNAP_KERNEL_VIEW_REUSE || !SNAP_ROOT_CACHE_WIDE || \
                            SNAP_TOKEN_TRIM)
#error "SNAP_MULTIPAGE_FAST needs SNAP_ATTR_CLEAN_DEFER, SNAP_KERNEL_VIEW_REUSE and SNAP_ROOT_CACHE_WIDE, not SNAP_TOKEN_TRIM"
#endif
#include "../compat/early-stop.h"
#include "../compat/a16-thermal.h"
#include "../compat/console-link.h"
#if SNAP_ADRENO_IB_ASYNC
/* SNAP_ADRENO_IB_ASYNC (compat/adreno-ib.h, agents/async-ib/FAILURE-MODES.md): ADRENO_GUEST_IB_START and _POLL,
 * so an IB's GPU execution no longer holds the service token. The flight lives in root_ext's arena pages (the
 * context's last page is full). The pacing report's 0x00010007 is ADRENO_GUEST_NET, which the dispatch answers
 * first (A0). */
#if !SNAP_ROOT_CACHE_WIDE
#error "SNAP_ADRENO_IB_ASYNC keeps its flight in root_ext's monitor arena pages: it needs SNAP_ROOT_CACHE_WIDE"
#endif
#include "../compat/guest-net.h"
_Static_assert(ADRENO_GUEST_IB_START != ADRENO_GUEST_NET && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_NET &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_STOP && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_STOP &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_FILL32 && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_FILL32 &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_IB && ADRENO_GUEST_IB_POLL != ADRENO_GUEST_IB &&
               ADRENO_GUEST_IB_START > ADRENO_GUEST_CACHE && ADRENO_GUEST_IB_POLL > ADRENO_GUEST_CACHE &&
               ADRENO_GUEST_IB_START != ADRENO_GUEST_IB_POLL, "IB_START/IB_POLL request words are unique");
#endif
#ifndef SNAP_CPU_DVFS
#define SNAP_CPU_DVFS 0
#endif
#ifndef SNAP_GPU_DVFS
#define SNAP_GPU_DVFS 0
#endif
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
/* agents/dvfs (FAILURE-MODES.md): opt-in CPU and GPU frequency governors on vCPU 0's locked tick, restored at the
 * stop. Their state is the last member of root_ext (the context's last page is full; agents/async-ib A14), and
 * they run only with the thermal guard (EARLY_STOP_F_THERMAL). */
#if !SNAP_ROOT_CACHE_WIDE
#error "SNAP_CPU_DVFS/SNAP_GPU_DVFS keep their state in root_ext's monitor arena pages: they need SNAP_ROOT_CACHE_WIDE"
#endif
#if SNAP_CPU_DVFS && !SNAP_WFI_RESUME
#error "SNAP_CPU_DVFS reads the EL2 tick's WFI classification (perf.fast[].wfi): it needs SNAP_WFI_RESUME"
#endif
#if SNAP_CPU_DVFS
#include "../compat/cpu-dvfs.h"
#endif
#if SNAP_GPU_DVFS
#include "../compat/gpu-dvfs.h"
#endif
#endif
/* SNAP_GUEST_NET (compat/guest-net-link.h, docs/GUEST-NETWORK-20261019.md): the
 * guest's paravirtual NIC rides on the host poll. ADRENO_GUEST_NET attaches the
 * kext's ring, admitted like ADRENO_GUEST_STOP; a launch with EARLY_STOP_F_NET
 * then polls q1n1 with POLL2 and a net view. Off, the code is absent. */
#if SNAP_GUEST_NET
#include "../compat/guest-net-link.h"
struct guest_net_state {
    struct guest_net_link link;
    struct guest_net_view view;
    struct guest_net_poll_views views;
};
#define GUEST_NET_STATE_PAGES ((sizeof(struct guest_net_state)+4095)/4096)
#define GUEST_NET_POLL2 4u                     /* q1n1 Q1N1_CALL_POLL2 */
#define GUEST_NET_CALL_E_OP UINT64_C(0xffffffffffffffff)   /* Q1N1_CALL_E_OP: an older q1n1 */
#endif
/* SNAP_EDP_BACKLIGHT (compat/edp-backlight.h, agents/brightness): ADRENO_GUEST_BACKLIGHT sets the panel's DPCD
 * brightness over the eDP controller's AUX channel for the kext's AdrenoBacklight, admitted like ADRENO_GUEST_STOP.
 * Its state is one zeroed monitor page (setup.c). Off, the code is absent and compat/edp-backlight.c is not linked. */
#ifndef SNAP_EDP_BACKLIGHT
#define SNAP_EDP_BACKLIGHT 0
#endif
#if SNAP_EDP_BACKLIGHT
#include "../compat/edp-backlight.h"
#endif
#include "../compat/fast-vector.h"
_Static_assert(FAST_EXIT_CLASSES==FAST_TRAP_CLASSES-1+FAST_CROSS_CLASSES &&
               FAST_EXIT_CROSS_SLOT(1)==FAST_TRAP_CLASSES-1,
               "one exit-timing slot per lock-free class, the EL0 emulation last");
/* Table-arena reserve, in 4K pages. The arena (the240MiB work region less
 * this context) holds every shadow and private copy; each cached user root
 * owns ~365 pages at 61 processes and the kernel ~5.7k, so the 64-slot cache
 * alone left 2.8k of 31.9k free. Every monitor call first restores this many
 * free pages by giving back inactive cached roots (cheapest first), so no
 * transaction starts short of tables. 2048 pages (8 MiB) covers the largest
 * single non-build call (a shared-leaf insertion across 64 aliasing roots,
 * or a 48-descriptor nest). Zero disables the call-entry reserve; an
 * exhausted SWITCH_ROOT build still reclaims and retries once. */
#ifndef SNAP_ARENA_RESERVE_PAGES
#define SNAP_ARENA_RESERVE_PAGES 2048u
#endif
/* A root build that ran the arena dry retries after freeing this many. */
#define ARENA_RETRY_PAGES 8192u

#include "xnuboot/report_layout.c"
#include "xnuboot/context.c"
#include "xnuboot/mmu_access.c"
#include "xnuboot/kernel_views.c"
#include "xnuboot/ans_glue.c"
#include "xnuboot/sptm_retype.c"
#include "xnuboot/telemetry.c"
#include "xnuboot/stage2.c"
#include "xnuboot/setup.c"
#include "xnuboot/clock_timer.c"
#include "xnuboot/gpu_glue.c"
#include "xnuboot/early_stop_thermal.c"

#include "../compat/dvfs-glue.h"

#include "xnuboot/async.c"
#include "xnuboot/prepare.c"
#include "xnuboot/cpu_boot.c"
#include "xnuboot/sysreg_clock.c"
#include "xnuboot/pauth.c"
#include "xnuboot/user_native.c"
#include "xnuboot/user_hw_walk.c"
#include "xnuboot/user_views.c"
#include "xnuboot/user_backend.c"
#include "xnuboot/multipage.c"
#include "xnuboot/sptm_dispatch.c"
#include "xnuboot/mmio_dispatch.c"
#include "xnuboot/trap_dispatch.c"
#include "xnuboot/fast_traps.c"
#include "xnuboot/fine_locks_backend.c"
#include "xnuboot/fine_locks_calls.c"
#include "xnuboot/fine_locks_dispatch.c"
#include "xnuboot/trap_entry.c"
#include "xnuboot-terminal.h"
#include "xnuboot/report.c"
