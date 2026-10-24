/* SPDX-License-Identifier: MIT */
/* SPTM endpoint numbers and return codes: from m1n1, https://github.com/AsahiLinux/m1n1:
 * Copyright The Asahi Linux Contributors, MIT. */
/* The boot parameter block, event codes, SPTM endpoint numbers and the report
 * layout that probes/run.py decodes.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
struct params {
    uint64_t ttbr1_root;      /* the guest's own 16K root */
    uint64_t tcr;             /* the guest's TCR_EL1, 16K granules and all */
    uint64_t mair;
    uint64_t entry;           /* where to ERET to */
    uint64_t x1, x2;          /* the two handoff pointers */
    uint64_t vbar;            /* XNU's exception vectors, so faults come here */
    uint64_t stub_count;      /* NATIVE_CALL_FLAG opts into call/writer closure */
    uint64_t stub_pa[8];      /* legacy call guards, or five call + two writer pages */
    uint64_t vbar_va;         /* XNU's vectors, as a virtual address */
    uint64_t watch_pa;        /* handoff pages to observe, 4K each */
    uint64_t watch_count;
    uint64_t watch_va;        /* the same pages as XNU sees them */
    uint64_t vncr_va;         /* loader VNCR seed, copied into private CPU pages */
    uint64_t permissive;      /* acknowledge endpoints we have not implemented */
    uint64_t vmpidr;          /* MPIDR_EL1 as the guest's own cpu node describes it */
    uint64_t let_panic;       /* let XNU run its own exception handler and print */
    uint64_t watchdog_seconds;/* how long the guest may run before we take it back */
    uint64_t low_base, low_span;/* the range to shadow under TTBR0 */
    uint64_t scratch_pa;      /* per-CPU pages the monitor leaves results in */
    uint64_t skip_undef;      /* step over unimplemented encodings, and count them */
    uint64_t scratch_va;      /* the same pages as XNU sees them: what OUTPUT_AREA
                               * returns, because XNU dereferences the answer */
    uint64_t mem_low, mem_high;/* the physical memory we declared: the DRAM and
                                * the reserve above it. Stage 2 covers exactly
                                * this, so MAP_PAGE reports a PTE that points
                                * outside it and a touch outside it faults. */
    uint64_t fb_pa, fb_span;  /* the panel, when it is handed over: the one
                               * range outside mem_low..mem_high the guest may
                               * touch. A zero span means no panel. */
    /* Device register windows the guest's own device tree names, derived from
     * it at build time. Physical addresses on the machine the tree describes,
     * which is not this one -- nothing is there. They are listed so MAP_PAGE
     * can tell a device the kernel legitimately asked for from an address we
     * cannot account for, and install the first while still withholding the
     * second. Stage 2 leaves them absent, so the guest's access traps here
     * with the IPA instead of reaching the bus. */
    uint64_t device_count;
    uint64_t device_pa[4], device_span[4];
    uint64_t frame_map_pa, frame_low, frame_high, alloc_low, alloc_high;
    uint64_t ram_aperture_va;
    uint64_t write_watch_pa;  /* optional 4K page: stop before any guest write */
    uint64_t txm_stacks_pa, txm_stack_count, txm_log_pa;
    uint64_t txm_rw_pa, txm_ro_pa, txm_aspace_pa;
    struct uat_config uat;
    struct sptm_slide_config slide;
    uint64_t model_count;
    struct device_model models[DEVICE_MODEL_MAX];
    uint64_t clock_host_hz, clock_guest_hz;
    uint64_t const_begin, const_end; /* exclusive end, immutable KC prefix */
    struct txm_trust_cache trust_cache;
    uint64_t sep_firmware_pa, sep_firmware_size;
    /* A kmutil-linked AuxKC's VA and PA extents, or zeros. Observed by the
     * compat/auxkc-observe.h counters; nothing is gated on them. */
    struct auxkc_range auxkc;
    /* The Adreno behind the monitor (compat/adreno.h), from q1n1's adoption
     * record (probes/adreno.py). flags 0 leaves every Stage-4 path off. */
    struct adreno_params gpu;
    struct txm_native_params txm_native;
    /* Appended: opt-in early stop (compat/early-stop.h); all zero unless the
     * launch set SNAP_EARLY_STOP, which leaves every early-stop path off. */
    struct early_stop_params early_stop;
#if SNAP_I2C_INPUT
    /* Appended in -DSNAP_I2C_INPUT=1 builds only; the loader appends the six
     * words only for a profile with i2c_input (compat/i2c-input.h). */
    struct i2c_input_params i2c_input;
#endif
};

/* The two sides of this structure are written in different languages and there
 * is nothing but this line holding them together: probes/xnuboot.py builds it
 * as a flat list of u64s, in field order, and a field added on one side and not
 * the other shifts everything after it. That does not fault -- it hands the
 * guest a plausible address from the wrong field -- so the count is stated
 * here, asserted there, and a mismatch is a build error rather than a run. */
#define PARAMS_WORDS 1154
#if SNAP_I2C_INPUT
#undef PARAMS_WORDS
#define PARAMS_WORDS (1154 + I2C_INPUT_PARAMS_WORDS)
#endif
_Static_assert(sizeof(struct params) == PARAMS_WORDS * 8,
               "probes/xnuboot.py builds this structure word by word; "
               "update PARAMS_WORDS on both sides");
#if SNAP_QCC2072_WIFI
/* -DSNAP_QCC2072_WIFI=1 builds read QCC2072_WIFI_PARAMS_WORDS more words right
 * after struct params (after the i2c-input block when that is built in too);
 * the loader appends them only for --qcc2072-wifi. struct params itself, and
 * so every offset the host tools read, is unchanged. */
static inline const struct qcc2072_wifi_params *qcc2072_wifi_block(const struct params *p)
{
    return (const struct qcc2072_wifi_params *)(const void *)(p + 1);
}
#endif
#if SNAP_DISPLAY_TIMING
/* -DSNAP_DISPLAY_TIMING=1 builds read DISPLAY_TIMING_PARAMS_WORDS more words after struct params and, when it is built
 * in, the QCC2072 block; the loader appends them only for --present-beam. struct params itself is unchanged. */
static inline const struct display_timing_params *display_timing_block(const struct params *p)
{
    const uint64_t *after = (const uint64_t *)(const void *)(p + 1);
#if SNAP_QCC2072_WIFI
    after += QCC2072_WIFI_PARAMS_WORDS;
#endif
    return (const struct display_timing_params *)(const void *)after;
}
#endif

/* Events, in the order they happened. A first run is an exploration, so the
 * report is a log rather than a verdict.
 *
 * 512, not 64. The last run recorded 180 events and kept 64 of them, and 36 of
 * those 64 were sysreg traps -- so the log was three quarters full of one kind
 * of thing before the boot had finished starting. Growing it is not a fix for
 * a report that cannot name its ending; the terminal word above is that, and
 * it stays whatever this number is. This is a fix for a different loss: the
 * MIDDLE of the run, the sequence of what XNU asked for, which is most of the
 * evidence about what it is doing. Eight times the room costs 21 KiB in a
 * buffer with 960 KiB of slack before the work area. */
#define EVENT_MAX 512
struct event {
    uint64_t kind;            /* see EV_* */
    uint64_t pc, a, b, c;
    uint64_t repeats;         /* how many identical ones followed */
};
#define EV_MONITOR   1        /* a monitor call: a = x16, b = x0, c = x1 */
#define EV_S2_FAULT  2        /* a stage-2 fault, and the run stops on it:
                               * a = IPA (0 when neither the stage-1 walk nor
                               * HPFAR could name it), b = ESR_EL2 (the ISS:
                               * ISV, size, register, direction, S1PTW, FSC),
                               * c = the guest VA (FAR_EL2); pc = the guest PC.
                               * a is the stage-1 re-walk's IPA when it has one;
                               * with SNAP_S2_FAULT_RETRY the terminal word's
                               * sixth word is HPFAR_EL2, the hardware's. */
#define EV_GUEST_EXC 3        /* XNU took its own exception: a/b/c = ESR/FAR/ELR */
#define EV_SYSREG    4        /* a trapped MSR/MRS: a = ISS */
/* Which bits of that ISS name the register rather than the access.
 *
 * ESR_EL2 EC 0x18 lays the ISS out as Op0 [21:20], Op2 [19:17], Op1 [16:14],
 * CRn [13:10], Rt [9:5], CRm [4:1], Direction [0]. The first four fields and
 * CRm are the register's encoding; Rt and the direction are what this
 * particular instruction did with it. Keeping the first set and dropping the
 * second is what makes "the kernel is reading CNTFRQ" one log entry instead of
 * one per call site per destination register. */
#define SYSREG_ID    0x3FFC1EUL
#define EV_OTHER     5
#define EV_RETYPE    17       /* a = PA, b = old << 32 | new, c = options */
#define EV_RETYPE_FAILED 18   /* a = sptm_result, b = PA, c = new type */
#define EV_MAP_TABLE 19       /* a = VA, b = parent level, c = new TTE */
#define EV_TABLE_FAILED 20    /* a = sptm_result, b = VA, c = new TTE */
#define EV_UNMAP_REGION 21    /* a = VA, b = count, c = options */
#define EV_UNMAP_FAILED 22    /* a = sptm_result, b = VA, c = count */
#define EV_MAP_NEEDS_TABLE 23 /* recoverable TABLE_NOT_PRESENT; a = level, b = VA */
#define EV_EXCEPTION_RETURN 24 /* a = target PC, b = virtual SPSR, c = physical SPSR */
#define EV_RETURN_REFUSED 25   /* a = target PC, b = virtual SPSR, c = instruction */
#define EV_UPDATE_FAILED 26   /* a = sptm_result, b = target PA, c = options */
#define EV_REGION_FAILED 27   /* a = sptm_result, b = VA, c = options */
#define EV_REFERENCE_FAILED 28 /* a = sptm_result, b = VA, c = PTE */
#define EV_SLIDE_FAILED 29     /* a = sptm_result, b = VA, c = count */
#define EV_TXM_FAILED 30       /* a = sptm_result, b = object/argument, c = selector */
#define EV_SLIDE_REGION 31     /* a = source VA, b = new VA, c = count */
#define EV_CLOCK_FAILED 32     /* a = clock_result, b = ISS, c = value */
#define EV_TIMER_FIQ 33        /* a = interrupted PC, b = timer ctl, c = deadline */
#define EV_DEVICE_FAILED 34    /* a = kind << 32 | device_result, b = IPA, c = ESR */
#define EV_DEVICE_IRQ 35       /* a = interrupted PC; asserted virtual AIC IRQ */
#define EV_DEVICE_RESET 36     /* a = PC; b = model bitmap requesting guest reset */
#define EV_IPI_FAILED 37       /* a = ipi_result, b = ISS, c = requested value */
#define EV_CPU_FAILED 38       /* a = cpu_result, b = endpoint, c = argument */
#define EV_SPRR_FAILED 39      /* a = sprr_result, b = ISS, c = requested value */
#define EV_USER_RETURN 40      /* a = target, b = SPSR, c = active source root */
#define EV_USER_EXECUTED 41    /* a = entry PC, b = X0, c = physical SPSR */
#define EV_USER_STEP_FAILED 42 /* a = entry PC, b = X0, c = physical SPSR */
#define EV_PANIC_STATE_FAILED 43 /* a = x16, b = panic owner, c = CPU */
#define EV_NATIVE_WRITER_FAILED 44 /* a = ESR, b = instruction PA, c = word */
#define EV_AUXKC_EXEC 45       /* a = VA, b = old PTE, c = new PTE: a kernel-root
                                * leaf in the linked AuxKC gained EL1 execute */
/* Stage 4 (compat/adreno.h). A trapped GPU block and a refused HVC stop the run;
 * an SMMU fault and a test fence are recorded and the guest continues. */
#define EV_GPU_TRAP 46         /* a = IPA, b = ESR_EL2, c = block class */
#define EV_GPU_SMMU 47         /* a = FSYNR0 << 32 | FSR, b = FAR, c = sGFSR << 32 | CBFRSYNRA0 */
#define EV_GPU_SMC 48          /* a = x0 (fid), b = x1, c = TrustZone x0, or ~0 refused */
#define EV_GPU_RING 49         /* a = fence value, b = result (0 or ADRENO_E_*), c = ticks */
#define EV_GPU_IB 51           /* ADRENO_GUEST_IB: a = package VA, b = IB dwords << 32 | (u32)result, c = ticks */
/* Virtual ANS2 (compat/ans.h): a refused MMIO, mailbox or SPTM table 5/6 access
 * stops the run. a = ANS_E_* << 32 | window/kind (MMIO) or table << 8 | endpoint,
 * b = IPA or x0, c = ESR or x1. The first refusal is also kept in the state. */
#define EV_ANS 50
/* Early stop (compat/early-stop.h). A request is recorded and the guest
 * continues; the stop happens when its deadline expires on some CPU's timer. */
#define EV_EARLY_STOP 52         /* fired: a = source << 32 | reason, b = detail, c = accepted delay */
#define EV_NATIVE_SHARED_FULL 54 /* a call needed a shared-region group and none was free:
                                  * a = native_shared.full, b = root or shared root,
                                  * c = NATIVE_SHARED_GROUPS (SNAP_NATIVE_SHARED) */
#define EV_S2_RETRY 55           /* SNAP_S2_FAULT_RETRY: a stage-2 translation fault retried:
                                  * a = HPFAR's IPA, b = ESR_EL2, c = FAR_EL2; pc = the guest PC */
#define EV_EARLY_STOP_REQUEST 53 /* a = source << 32 | reason, b = requested delay << 32 | (u32)detail,
                                  * c = result (EARLY_STOP_ACCEPTED/_DUPLICATE or EARLY_STOP_E_*) */
#define EV_GUEST_NET 56          /* SNAP_GUEST_NET: ADRENO_GUEST_NET: a = sub-op, b = ring IPA,
                                  * c = result << 32 | (u32)generation; pc = the HVC */
#if SNAP_QCC2072_WIFI
#define EV_QCC2072_COMMAND 57    /* the monitor wrote the QCC2072 command register for the guest:
                                  * a = value, b = read back, c = ESR_EL2; pc = the store */
#endif
#if SNAP_ADRENO_RECOVER
#define EV_GPU_RECOVER 58        /* compat/adreno-ib.h adreno_recover ran: a = cause << 56 | (dead & 0xffff) << 32 |
                                  * (u32)epoch, b = RBBM_STATUS << 32 | RBBM_INT_0_STATUS, c = CP_INTERRUPT_STATUS_GLOBAL
                                  * << 32 | (u32)its own ticks (the snapshot before the reset); pc = the HVC, 0 the tick */
#endif
#if SNAP_ADRENO_COHERENT
#define EV_GPU_COHERENT 59       /* compat/adreno-coherent.h self-test, once at prepare, whatever its outcome:
                                  * pc = the CPU->GPU control's PMU passes (miss | resident << 16 | witness
                                  * << 32), a = state << 32 | detail, b = iterations passed | the GPU->CPU
                                  * control's PMU passes << 16, c = stale[0] << 32 | stale[1] (the controls'
                                  * stale words, each at most 1,024); probes/run.py decodes it */
#endif
#if SNAP_EDP_BACKLIGHT
#define EV_EDP_BACKLIGHT 60      /* ADRENO_GUEST_BACKLIGHT (compat/edp-backlight.h): a = sub-op << 32 | (u32)level asked,
                                  * b = (u32)result << 32 | the panel's level after the call, c = the reply's x1 (ABI |
                                  * state << 8 | detail << 16 | DPCD 0x700..0x703 << 24 | mode << 56); pc = the HVC */
#endif
#define EV_HANDOFF   7        /* a field of the handoff was read: a = offset */
#define EV_WATCHDOG  6        /* the guest ran too long and was taken back */
#define EV_DISPATCH_CMD 8     /* a call that is not an endpoint call:
                               * a = command, b = domain, c = the raw x16 */
#define EV_PANIC_ENTRY 9      /* XNU announced a fatal exception:
                               * a = x30 (which caller), b = ELR_EL1, c = ESR_EL1 */
#define EV_MAP_FAILED 10      /* a MAP_PAGE that returned an error:
                               * a = reason (MAP_FAIL_*), b = the VA, c = detail */
#define EV_MAP_DEVICE 15      /* a MAP_PAGE onto a device window the guest's own
                               * tree names: installed, so the access traps at
                               * stage 2 rather than faulting at stage 1 */
/* 14 was EV_MAP_WITHHELD: a mapping outside our memory that we wrote into the
 * guest's table and kept out of the hardware's. Nothing withholds any more --
 * under the narrowed stage-2 map installing is the loud option, because the
 * access then traps to EL2 with its address instead of faulting inside XNU's
 * own handler. The number is left unused rather than reassigned, so an old
 * transcript keeps its meaning. */
#define EV_MAP_OUTSIDE 11     /* a MAP_PAGE we COMPLETED whose PTE points outside
                               * the memory we declared: a = PA, b = VA, c = PTE */
#define EV_SERROR 12          /* the guest took an SError -- an access the
                               * interconnect refused, which is a bus error and
                               * not a timeout: a = ESR_EL2 (EC 0x2f),
                               * b = ESR_EL1, c = ELR_EL1, pc = ELR_EL2 */
#define EV_ASYNC 13           /* an IRQ or FIQ that was not our timer:
                               * a = which vector (ASYNC_*), b = ESR_EL1,
                               * c = ELR_EL1, pc = ELR_EL2 */
#define EV_MMIO_STOP 16       /* an access to a device window we model, that the
                               * model does not answer -- and the run stops on
                               * it: a = (reason << 48) | (window << 32) |
                               * offset, b = ESR_EL2 (which carries the size and
                               * the direction), c = the IPA; pc = the guest PC.
                               *
                               * A modelled access records nothing. There is one
                               * per character of the kernel's output and the log
                               * holds 64 entries, so the counters carry them
                               * (mmio_reads, mmio_writes, uart_tx) and the log
                               * stays free for the thing that ends the run --
                               * exactly the rule SPTM_FN_SERIAL_PUTC follows. */
/* Why a device access stopped the run. Each one is a thing to go and model, and
 * the transcript names which. */
#define MMIO_STOP_OFFSET 1    /* the window is ours; this offset is not modelled */
#define MMIO_STOP_NO_ISV 2    /* ISS.ISV clear: a pair or writeback form, so the
                               * syndrome does not say which registers moved and
                               * emulating it would be a guess */
#define MMIO_STOP_FETCH  3    /* an instruction fetch from a device page */
#define MMIO_STOP_S1PTW  4    /* the stage-1 walk faulted into a device page: the
                               * fault is the walker's, not the access's */
#define MMIO_STOP_SHAPE  5    /* the tree's windows are not the shape the model
                               * was written against */
#define MAP_OUTSIDE_LOGGED 6  /* how many to record before the counter alone */

/* Which asynchronous vector an exception arrived at. The three values are
 * mirrored in probes/xnuboot.S, which is where they are chosen. */
#define ASYNC_IRQ    0
#define ASYNC_FIQ    1
#define ASYNC_SERROR 2
#if SNAP_FAST_TIMER_IRQ
/* Never chosen by a vector: an IRQ whose acknowledge on the lock-free tick
 * (fast_timer_irq) returned, and completed, another INTID than HPPIR's 26.
 * xnuboot_async_locked passes over its GPU and timer cases for it, so it
 * records and stops as after the same acknowledge of its own (probes/run.py
 * ASYNC_KINDS names it). */
#define ASYNC_IRQ_OTHER 3
#endif

/* CNTHP_CTL_EL2.ISTATUS -- the timer condition is met. This is the only thing
 * that entitles anything to print the word "watchdog": the register says the
 * comparator fired, rather than us assuming it because something asynchronous
 * happened while the guest was running. */
#define CNTHP_ISTATUS (1UL << 2)

/* Why a MAP_PAGE failed. Six branches returned one status and recorded nothing,
 * so a failed map was indistinguishable from a working one in the transcript.
 * The level a walk stopped at is packed into bits 15:8 of the reason. */
#define MAP_FAIL_START_LEVEL   1   /* T1SZ gives no valid starting level */
#define MAP_FAIL_LEVEL_MISSING 2   /* a table in the walk is absent: MAP_TABLE's job */
#define MAP_FAIL_READ_LEAF     3   /* the level-3 entry could not be read */
#define MAP_FAIL_WRITE_LEAF    4   /* ...or written */
#define MAP_FAIL_REREAD        5   /* written, but reading it back disagreed */
#define MAP_FAIL_SHADOW_INSERT 6   /* the 4K shadow refused it, usually no arena */
#define MAP_FAIL_SHADOW_ABSENT 7   /* inserted, but the shadow does not resolve it */
#define MAP_FAIL_SHADOW_WRONG  8   /* the shadow resolves it, to the wrong page */
#define MAP_FAIL_LEAF_INVALID  9   /* the guest says unmapped; we would no-op */
#define MAP_FAIL_SHADOW_EMPTY 10   /* shadow_insert accepted it and did nothing */
#define MAP_FAIL_ROOT_OUTSIDE 11   /* the root handed to us is not our memory */
#define MAP_FAIL_SPRR_CLASS   12   /* needs a prepared private permission path */

/* The monitor call ABI, from the stubs themselves: x16 packs the routing and
 * x0..x7 carry the arguments. Endpoint numbering matches
 * m1n1 (AsahiLinux) and the author's J700 research fork (sptm/private.h), reverse-engineered on this same
 * SoC -- see docs/BOOT-CHAIN.md section 5.
 *
 * Every name below is now Apple's own rather than a reconstruction. SPTM's
 * dispatch table is in its `__DATA_CONST` at 0xfffffff027022350 -- 51 entries
 * of `{void *handler; uint64_t flags; const char *name;}`, indexed by endpoint,
 * pointers stored as chained fixups -- and it carries the
 * `SPTM_FUNCTIONID_*` string for each one. `tools/sptm-dispatch.py` prints it.
 * Eight endpoints this file already implemented land exactly where they were
 * guessed, which is what makes the table trustworthy for the ones that were
 * not. */
/* x16 is four fields, not three:
 *
 *   dispatch command  [63:56]     domain  [55:48]
 *   table             [39:32]     endpoint [31:0]
 *
 * The command names which *kind* of call this is; only command 0 is an endpoint
 * call, where the other three fields mean anything. See monitor_call(). */
#define SPTM_CMD_ENDPOINT       0
#define SPTM_CMD_PANIC_ENTRY    2      /* XNU is taking a fatal exception */
#define SPTM_CMD_MAX            6      /* dispatch_cmd_handler rejects >= 7 */
#define SPTM_SUCCESS            0
/* Return codes, from m1n1-j700/src/sptm/private.h. */
#define SPTM_TABLE_NOT_PRESENT  7
#define SPTM_FN_RETYPE          1
#define SPTM_FN_MAP_TABLE       3
#define SPTM_FN_UNMAP_TABLE     4
#define SPTM_FN_CONDEMN_LEAF_TABLE 43
#define SPTM_FN_UNCONDEMN_LEAF_TABLE 44
#define SPTM_FN_UPDATE_DISJOINT 6
#define SPTM_FN_UPDATE_REGION   5
#define SPTM_FN_UPDATE_DISJOINT_MULTIPAGE 21
#define SPTM_FN_UNMAP_REGION    7
#define SPTM_FN_UNMAP_DISJOINT  8
#define SPTM_FN_CONFIGURE_SHAREDREGION 9
#define SPTM_FN_NEST_REGION 10
#define SPTM_FN_UNNEST_REGION 11
#define SPTM_FN_SET_SHARED_REGION 39
#define SPTM_FN_BATCH_SIGN_USER_POINTER 40
#define SPTM_FN_SIGN_USER_POINTER 16
#define SPTM_FN_AUTH_USER_POINTER 17
#define SPTM_FN_CONFIGURE_ROOT 12
#define SPTM_FN_SWITCH_ROOT     13
#define SPTM_FN_SLIDE_REGION    20
#define SPTM_FN_MAP_PAGE        2      /* SPTM_FUNCTIONID_MAP_PAGE */
#define SPTM_FN_SERIAL_DISABLE  46     /* SPTM_FUNCTIONID_SPTM_SERIAL_DISABLE */
#define SPTM_FN_LOCKDOWN        0      /* SPTM_FUNCTIONID_LOCKDOWN */
#define SPTM_FN_FIXUPS_COMPLETE 15     /* SPTM_FUNCTIONID_FIXUPS_COMPLETE */
#define SPTM_FN_REGISTER_CPU        14 /* SPTM_FUNCTIONID_REGISTER_CPU */
#define SPTM_FN_REGISTER_EXC_RETURN 18 /* SPTM_FUNCTIONID_REGISTER_EXC_RETURN */
#define SPTM_FN_SERIAL_PUTC     45     /* SPTM_FUNCTIONID_SPTM_SERIAL_PUTC */
#define SPTM_FN_CPU_ID          0x13   /* SPTM_FUNCTIONID_CPU_ID: which slot am I */
#define SPTM_FN_OUTPUT_AREA     0x32   /* SPTM_FUNCTIONID_OUTPUT_AREA: where that
                                        * slot's results are left */
#define CONSOLE_MAX           1024
#define CONSOLE_TAIL_MAX     65536
#define CONSOLE_LOG_MAX      (4u << 20)

/* A page the guest is not allowed to touch unobserved.
 *
 * Two kinds, one mechanism. EXEC pages are execute-never, so a call into a
 * monitor stub arrives at EL2; DATA pages are invalid outright, so *any* access
 * does. Both open the page and observe the next instruction with single-step.
 * DATA then closes; EXEC can remain open while each instruction on that page
 * is still stepped. Neither needs the faulting instruction decoded. That
 * matters: the alternative is decoding every load/store form XNU might use,
 * and being wrong about one of them silently. */
#define GUARD_EXEC 0
#define GUARD_DATA 1
struct guard {
    uint64_t pa, slot;        /* the page, and the level-3 entry that maps it */
    uint64_t descriptor;      /* what that entry says when the page is open */
    uint64_t mode;
};

/* The guest's register file at the moment it took an exception.
 *
 * Three values were not enough. ESR/FAR/ELR say what faulted and where; they do
 * not say what the kernel had in its hands, and the difference decides what the
 * fault means. A walk that lands on a null table base and a walk that lands on
 * a plausible one are the same syndrome and different problems, and telling
 * them apart by reading the disassembly backwards is guesswork the machine can
 * simply answer.
 *
 * These are the guest's own values, with no qualification needed: `sync_lower`
 * in probes/xnuboot.S pushes x0..x30 as the first thing it does, before any
 * call, so nothing at EL2 has run between the exception and the save. The
 * frame is what this copies from. */
struct guest_regs {
    uint64_t x[31];           /* x0 .. x30 */
    uint64_t sp_el1;          /* selected guest SP; historical wire field name */
    uint64_t spsr;            /* SPSR_EL2: the guest's PSTATE as it faulted */
    uint64_t pc;              /* ELR_EL1: the instruction that faulted */
    uint64_t esr;             /* ESR_EL1, the syndrome XNU's own handler sees */
    uint64_t far;             /* FAR_EL1, the address it faulted on */
};
#define GUEST_REGS_WORDS (sizeof(struct guest_regs) / 8)
_Static_assert(GUEST_REGS_WORDS == 36, "probes/run.py unpacks 36 words per snapshot");

/* Where the snapshots sit in the out buffer, in 64-bit words from the start of
 * the report area. Past the console, so every offset the host already reads
 * stays where it was:
 *
 *   0                          8 report words
 *   8                          EVENT_MAX events of 6 words
 *   8 + 6*EVENT_MAX            CONSOLE_MAX bytes
 *   OUT_GUEST_REGS             count, then two snapshots of GUEST_REGS_WORDS
 *   OUT_PANIC_REGS             count, then the frame at XNU's panic-entry call
 *   OUT_COUNTERS               OUT_COUNTERS_N counters
 *   OUT_EXC_RETURN             the trampoline XNU registered
 *   OUT_BAD_REGS               ELR_EL2 and FAR_EL2 at an EL2 fault
 *
 * The host's `out` is 16 bytes below this one (probes/xnuboot.S, OUT_REPORT),
 * so in its terms this area starts at out + 16 + OUT_GUEST_REGS * 8. */
#define OUT_GUEST_REGS (8 + 6 * EVENT_MAX + CONSOLE_MAX / 8)
/* And after the two exception snapshots: the frame at XNU's panic-entry call.
 * Appended rather than inserted, so every offset above keeps its address. */
#define OUT_PANIC_REGS (OUT_GUEST_REGS + 1 + 2 * GUEST_REGS_WORDS)
/* Counters the report otherwise loses. The event log holds 64 entries and
 * collapses repeats, so "how many maps failed" cannot be recovered by counting
 * lines in it -- these survive a log that overflowed. */
#define OUT_COUNTERS   (OUT_PANIC_REGS + 1 + GUEST_REGS_WORDS)
#define OUT_COUNTERS_N 13
/* The exception-return trampoline XNU registers, in a word of its own.
 *
 * It used to be written over the fault syndrome at report word 6, so once XNU
 * had answered REGISTER_EXC_RETURN -- which it does early in every boot -- that
 * slot held a code address. The host reads word 6 as an ESR: it printed the
 * trampoline under the label "ESR", and its "was a fault recorded?" test, which
 * is just "is that word non-zero", became permanently true. One word each, and
 * neither can be mistaken for the other. */
#define OUT_EXC_RETURN (OUT_COUNTERS + OUT_COUNTERS_N)
/* ELR_EL2 and FAR_EL2 as the `bad` vector found them. ESR_EL2 alone says an
 * EL2 fault happened and what kind; these say where in this file it happened
 * and what address it was reaching for, which is the difference between "the
 * monitor faulted" and a line number. */
#define OUT_BAD_REGS   (OUT_EXC_RETURN + 1)
/* The last event recorded, whatever the log did with it.
 *
 * Six words in the shape of a log entry, so the host parses it with the same
 * code. It exists because the log is a ring with a fixed size and the boot is
 * now longer than it: a run that drops events has no readable tail, and every
 * verdict that asks "what was the last thing that happened" was therefore
 * unavailable exactly when the run got far enough to be interesting. This slot
 * is written on every record() and never dropped, so the question always has
 * an answer. `repeats` is always zero here -- it is the ring's bookkeeping,
 * not this slot's -- and `kind` zero means nothing was ever recorded. */
#define OUT_LAST_EVENT (OUT_BAD_REGS + 2)
/* How many calls each endpoint took, and how many went somewhere else.
 *
 * The log collapses repeats and then drops what does not fit, so "which
 * endpoints did this run actually call, and how often" is not recoverable from
 * it. The last run made 390 monitor calls and the transcript could account for
 * 385; the missing five were not a mystery the log could solve, because the
 * log had already thrown them away. Sixty-four buckets covers SPTM's whole
 * dispatch table -- 51 entries, highest endpoint 0x32 -- so no two endpoints
 * share a bucket, and the sixty-fifth counts everything that is not an
 * XNU_BOOTSTRAP endpoint call. The two together must equal the number of calls
 * that reached the dispatcher, which is what makes the arithmetic checkable. */
#define OUT_ENDPOINTS  (OUT_LAST_EVENT + 6)
#define ENDPOINT_BUCKETS 64
/* The out-of-memory mappings, coalesced into spans.
 *
 * 379 of them arrived in the last run and the log kept five, because five
 * identical lines say what 379 say and the rest would push out everything
 * else. But "five examples and a count" loses the shape: which device, how
 * many pages of it, mapped once or twice. Spans keep the shape at a fixed
 * cost -- a run of consecutive pages of one device is one row however many
 * pages it is -- and the host turns each physical base back into the node of
 * the guest's own tree that named it.
 *
 * Twenty-four slots, a count, and a count of the spans that did not fit. The
 * overflow counter is not decoration: a table that silently stopped recording
 * would read as a device surface smaller than it is, which is the same lie
 * the 64-entry log was telling. */
#define OUT_RANGES     (OUT_ENDPOINTS + ENDPOINT_BUCKETS + 1)
#define MAP_RANGES     128
#define MAP_RANGE_WORDS 4
/* The guest's translation registers as the probe last saw them.
 *
 * TTBR0, TTBR1, TCR, MAIR, SCTLR -- five words, in that order. The probe has
 * tracked these since it started trapping them and has never shown them, so
 * "did XNU change one" has only ever been answerable by reading the log for a
 * sysreg event that may have been collapsed or dropped.
 *
 * MAIR is the one with a question attached. The loader publishes the value
 * SPTM's common start leaves for XNU (0x0c0d00ff01a040ff) on the strength of
 * there being no `msr MAIR_EL1` anywhere in this kernelcache; if that reading
 * is wrong, this word comes back as something else and says so. A static
 * claim about 120 MiB of image, measured for the cost of five words. */
#define OUT_GUEST_SYSREGS (OUT_RANGES + 2 + MAP_RANGES * MAP_RANGE_WORDS)
#define OUT_FRAMEBUFFER (OUT_GUEST_SYSREGS + 5)
#define OUT_ASYNC_REGS (OUT_FRAMEBUFFER + 3)
#define OUT_EXCEPTION_FLOW (OUT_ASYNC_REGS + 1 + GUEST_REGS_WORDS)
#define OUT_UPDATE_FLOW (OUT_EXCEPTION_FLOW + 3)
#define OUT_SLIDE_FLOW (OUT_UPDATE_FLOW + 4)
#define OUT_CLOCK_FLOW (OUT_SLIDE_FLOW + 3)
#define OUT_TIMER_FLOW (OUT_CLOCK_FLOW + 8)
#define OUT_DEVICE_FLOW (OUT_TIMER_FLOW + 11)
#define OUT_CLOCK_ADAPTER (OUT_DEVICE_FLOW + 1 + 2*DEVICE_MODEL_MAX)
#define OUT_AIC_FLOW (OUT_CLOCK_ADAPTER + 12)
#define OUT_WATCHDOG_FLOW (OUT_AIC_FLOW + 5)
#define OUT_OPTIONAL_FLOW (OUT_WATCHDOG_FLOW + DEVICE_RESET_WORDS + 3*DEVICE_MODEL_MAX)
#define OUT_IPI_FLOW (OUT_OPTIONAL_FLOW + 2)
#define OUT_CPU_FLOW (OUT_IPI_FLOW + 8)
#define OUT_VCPU_FLOW (OUT_CPU_FLOW + 8)
#define OUT_SHARED_FLOW (OUT_VCPU_FLOW + GUEST_CPU_COUNT*12)
#define OUT_SERVICE_FLOW (OUT_SHARED_FLOW + 3)
#define OUT_RUNTIME_STORAGE (OUT_SERVICE_FLOW + 4 + GUEST_CPU_COUNT*2)
_Static_assert(DEVICE_RESET_WORDS==2, "reset events record two bitmap words");
_Static_assert(OUT_RUNTIME_STORAGE + GUEST_CPU_COUNT*5 + 1 <= 0x10000/8,
               "device metrics must fit the report reservation");
/* Stage 4: struct adreno_state's counter words (compat/adreno.h), appended. */
#define OUT_GPU_FLOW (OUT_RUNTIME_STORAGE + GUEST_CPU_COUNT*5 + 1)
_Static_assert(OUT_GPU_FLOW + ADRENO_STATE_WORDS <= 0x10000/8,
               "the Adreno counters must fit the report reservation");
_Static_assert(__builtin_offsetof(struct adreno_state, irq) == 8*ADRENO_STATE_WORDS,
               "tools/adreno_counters.py decodes every word before irq");
/* Early stop (compat/early-stop.h): the whole record, appended after the GPU
 * words; probes/run.py EARLY_STOP_OFFSET and tools/early_stop.py read it. */
#define OUT_EARLY_STOP (OUT_GPU_FLOW + ADRENO_STATE_WORDS)
_Static_assert(OUT_EARLY_STOP + EARLY_STOP_STATE_WORDS <= 0x10000/8,
               "the early-stop record must fit the report reservation");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
/* The exit profile (compat/perf-state.h), copied whole behind a magic word
 * and a word of build bits | size << 32, after the early-stop record: the
 * cycle tools capture context.bin at the define-free context size, which
 * ends before it, and report.bin whole. tools/perf_counters.py
 * decode_exit_profile reads it at probes/run.py EARLY_STOP_OFFSET + 8*30. */
#define OUT_EXIT_PROFILE (OUT_EARLY_STOP + EARLY_STOP_STATE_WORDS)
#define EXIT_PROFILE_MAGIC UINT64_C(0x31464f5250544958)   /* "XITPROF1" */
#define EXIT_PROFILE_WORDS (sizeof(struct exit_profile)/8)
_Static_assert(OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS <= 0x10000/8,
               "the exit profile must fit the report reservation");
#endif
#if SNAP_FINE_LOCKS
#if !SNAP_SERVICE_SUBCLASS
#error "SNAP_FINE_LOCKS reports after the exit profile: build with SNAP_SERVICE_SUBCLASS"
#endif
/* Each CPU's converted-call profile (compat/fine-lock.h struct fine_profile)
 * behind a magic word and a word of SNAP_FINE_SWITCH | SNAP_FAST_PAUTH_CALLS
 * << 1 | profile bytes << 32, after the exit profile; tools/perf_counters.py
 * decodes it. */
#define OUT_FINE_PROFILE (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#define FINE_PROFILE_WORDS (sizeof(struct fine_profile)/8)
_Static_assert(OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS <= 0x10000/8,
               "the fine profile must fit the report reservation");
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST || SNAP_ROOT_INDEX || SNAP_OTHER_PROFILE || SNAP_GATE_WAIT
/* compat/token-costs.h struct token_costs_report behind "TOKCOST1" and a word
 * of define bits | bytes << 32, after the fine profile (or the exit profile);
 * tools/perf_counters.py decode_token_costs reads it. */
#if SNAP_FINE_LOCKS
#define OUT_TOKEN_COSTS (OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS)
#else
#define OUT_TOKEN_COSTS (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#endif
#define TOKEN_COSTS_WORDS 96u
_Static_assert(OUT_TOKEN_COSTS + 2 + TOKEN_COSTS_WORDS <= 0x10000/8,
               "the token-cost record must fit the report reservation");
#endif
/* Fixed unused report tail: do not move any existing decoder offset. */
#define OUT_THERMAL (A16_THERMAL_REPORT_OFFSET/8)
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_THERMAL,"thermal report overlap");
#elif SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_THERMAL,"thermal report overlap");
#elif SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_THERMAL,"thermal report overlap");
#else
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_THERMAL,"thermal report overlap");
#endif
_Static_assert(OUT_THERMAL+A16_THERMAL_REPORT_WORDS <= (0x10000-16)/8,"thermal report reservation");
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
/* agents/dvfs: "DVFSREP1", a word of SNAP_CPU_DVFS | SNAP_GPU_DVFS << 1 | CPU words << 16 | GPU words << 32,
 * then the reported prefix of struct cpu_dvfs_state and of struct gpu_dvfs_state (each header's ABI word says
 * its layout; their private tails are not written), word by word (absent ones are not written), in the
 * otherwise unused words after the thermal report. */
#define OUT_DVFS (OUT_THERMAL + A16_THERMAL_REPORT_WORDS)
#define DVFS_REPORT_MAGIC UINT64_C(0x3150455253465644)   /* "DVFSREP1" */
#if SNAP_CPU_DVFS
#define DVFS_CPU_WORDS CPU_DVFS_REPORT_WORDS
#else
#define DVFS_CPU_WORDS 0
#endif
#if SNAP_GPU_DVFS
#define DVFS_GPU_WORDS GPU_DVFS_REPORT_WORDS
#else
#define DVFS_GPU_WORDS 0
#endif
_Static_assert(OUT_DVFS + 2 + DVFS_CPU_WORDS + DVFS_GPU_WORDS <= (0x10000-16)/8, "DVFS report reservation");
#endif
#if SNAP_FAST_TIMER_IRQ
/* root_ext->fast_irq (compat/fast-timer-irq.h struct fast_irq_cpu, per CPU)
 * behind "FASTIRQ1" and a word of SNAP_WFI_RESUME | per-CPU bytes << 32, after
 * the last exit-profile record; tools/perf_counters.py decode_fast_irq. */
#if SNAP_TOKEN_COSTS
#define OUT_FAST_IRQ (OUT_TOKEN_COSTS + 2 + TOKEN_COSTS_WORDS)
#elif SNAP_FINE_LOCKS
#define OUT_FAST_IRQ (OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS)
#else
#define OUT_FAST_IRQ (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#endif
#define FAST_IRQ_MAGIC UINT64_C(0x3151524954534146)   /* "FASTIRQ1" */
#define FAST_IRQ_WORDS (sizeof(struct fast_irq_cpu)/8)
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_THERMAL,"thermal report overlap");
#endif
#if SNAP_GUEST_NET
/* The guest network (compat/guest-net-link.h): the link's words, then the net
 * view's (q1n1's counters included), behind "GUESTNT1" and a word of
 * EARLY_STOP_F_NET-enabled | link bytes << 32, after the last record before it;
 * tools/guest_net_report.py decodes it. */
#if SNAP_FAST_TIMER_IRQ
#define OUT_GUEST_NET (OUT_FAST_IRQ + 2 + GUEST_CPU_COUNT*FAST_IRQ_WORDS)
#elif SNAP_TOKEN_COSTS
#define OUT_GUEST_NET (OUT_TOKEN_COSTS + 2 + TOKEN_COSTS_WORDS)
#elif SNAP_FINE_LOCKS
#define OUT_GUEST_NET (OUT_FINE_PROFILE + 2 + GUEST_CPU_COUNT*FINE_PROFILE_WORDS)
#elif SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
#define OUT_GUEST_NET (OUT_EXIT_PROFILE + 2 + EXIT_PROFILE_WORDS)
#else
#define OUT_GUEST_NET (OUT_EARLY_STOP + EARLY_STOP_STATE_WORDS)
#endif
#define GUEST_NET_REPORT_MAGIC UINT64_C(0x31544e5453455547)   /* "GUESTNT1" */
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_THERMAL,"thermal report overlap");
#endif
#if SNAP_FAST_IPI
/* root_ext->fast_ipi (compat/fast-ipi.h struct fast_ipi_cpu, per CPU) behind
 * "FASTIPI1" and a word of per-CPU bytes << 32, at a fixed place just below the
 * thermal block, so it does not move with the records chained above; each of
 * them must end before it. tools/perf_counters.py decode_fast_ipi. */
#define FAST_IPI_WORDS (sizeof(struct fast_ipi_cpu)/8)
#define OUT_FAST_IPI (OUT_THERMAL - 2 - GUEST_CPU_COUNT*FAST_IPI_WORDS)
#define FAST_IPI_MAGIC UINT64_C(0x3149504954534146)   /* "FASTIPI1" */
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_FAST_IPI,"fast IPI report overlap");
#endif
#endif
_Static_assert(EARLY_STOP_E_DISABLED == ADRENO_E_PARAMS,
               "a disabled early stop answers like an older monitor's fence handler");
_Static_assert(sizeof(struct adreno_params) == 8*ADRENO_PARAMS_WORDS,
               "probes/adreno.py builds params.gpu word by word");
_Static_assert(ADRENO_DART_ID == SPTM_DART_ADRENO, "one virtual DART id");
_Static_assert(SPTM_DART_ADRENO_BASE == ADRENO_WINDOW_BASE && SPTM_DART_ADRENO_END == ADRENO_WINDOW_END,
               "one Adreno window (ADRENO_VA_WIDE)");
#if SNAP_DART_WIREDCNT
_Static_assert((ADRENO_WINDOW_END >> 25) <= 64 * DWC_PIN_WORDS, "the pin bitmap covers every Adreno level-1 slot");
#if ADRENO_VA_WIDE && !SNAP_ROOT_CACHE_WIDE
#error "ADRENO_VA_WIDE with SNAP_DART_WIREDCNT keeps its 8-word pin bitmap in struct root_ext (SNAP_ROOT_CACHE_WIDE)"
#endif
#endif
#if SNAP_DART_MEMO
/* root_ext->dart_memo's counters (compat/sptm-dart-memo.h struct
 * sptm_dart_memo_stats, then live) behind "DARTMEM1" and a word of stats
 * bytes << 32, at a fixed place: below the 98 words just under the thermal
 * block that SNAP_FAST_IPI's record (compat/fast-ipi.h) takes when it is on.
 * Every chained record must end before it. tools/perf_counters.py decode_dart_memo. */
#define DART_MEMO_STATS_WORDS (sizeof(struct sptm_dart_memo_stats)/8)
#define OUT_DART_MEMO (OUT_THERMAL - 98 - 3 - DART_MEMO_STATS_WORDS)
#define DART_MEMO_MAGIC UINT64_C(0x314d454d54524144)   /* "DARTMEM1" */
#if SNAP_FAST_IPI
_Static_assert(OUT_FAST_IPI == OUT_THERMAL - 98, "the fast IPI record's slot");
#endif
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_DART_MEMO,"DART memo report overlap");
#endif
#endif
#if SNAP_TOKEN_TRIM
/* root_ext->trim.stats (compat/token-trim.h struct token_trim_stats) behind
 * "TOKTRIM1" and a word of stats bytes << 32, at a fixed place just below the
 * DART memo's slot (used or not), so it does not move with the records chained
 * above; each of them must end before it. tools/perf_counters.py
 * decode_token_trim. */
#define TOKEN_TRIM_WORDS (sizeof(struct token_trim_stats)/8)
#define OUT_TOKEN_TRIM (OUT_THERMAL - 98 - 3 - 8 - 2 - TOKEN_TRIM_WORDS)
#define TOKEN_TRIM_MAGIC UINT64_C(0x314d4952544b4f54)   /* "TOKTRIM1" */
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_TOKEN_TRIM,"token-trim report overlap");
#endif
#if SNAP_DART_MEMO
_Static_assert(OUT_TOKEN_TRIM+2+TOKEN_TRIM_WORDS==OUT_DART_MEMO,"the token-trim record ends at the DART memo's slot");
#endif
#endif
#if SNAP_ADRENO_IB_ASYNC
/* root_ext->ib_flight (compat/adreno-ib.h struct adreno_ib_flight) as the stop leaves it, behind "IBASYNC1" and a word of
 * flight bytes << 32 | ADRENO_IB_POLL_DIVISOR, at a fixed place just below the token-trim slot (its 18 words, used
 * or not), so it does not move with the records chained above; each of them must end before it.
 * tools/perf_counters.py decode_ib_async. */
#define OUT_IB_ASYNC (OUT_THERMAL - 98 - 3 - 8 - 2 - 16 - 2 - ADRENO_IB_FLIGHT_WORDS)
#define IB_ASYNC_MAGIC UINT64_C(0x31434e5953414249)   /* "IBASYNC1" */
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_IB_ASYNC,"IB async report overlap");
#endif
#if SNAP_TOKEN_TRIM
_Static_assert(OUT_IB_ASYNC+2+ADRENO_IB_FLIGHT_WORDS==OUT_TOKEN_TRIM,"the IB async record ends at the token-trim slot");
#endif
#if SNAP_DART_MEMO
_Static_assert(OUT_IB_ASYNC+2+ADRENO_IB_FLIGHT_WORDS+2+16==OUT_DART_MEMO,"the IB async record's slot");
#endif
#endif
#if SNAP_VIEW_RECLAIM
/* The kernel views' pool (shadow/sprr-view.h): count and high-water mark, the
 * reclaims that retired tables and how many, refusals that found nothing to
 * retire, and the capacity, behind "VIEWRCL1" and a word of value bytes << 32,
 * at a fixed place just below the IB async slot (used or not); each chained
 * record must end before it. tools/perf_counters.py decode_view_reclaim. */
#define VIEW_RECLAIM_WORDS 6u
#define OUT_VIEW_RECLAIM (OUT_THERMAL - 98 - 3 - 8 - 2 - 16 - 2 - 36 - 2 - VIEW_RECLAIM_WORDS)
#define VIEW_RECLAIM_MAGIC UINT64_C(0x314c435257454956)   /* "VIEWRCL1" */
_Static_assert(OUT_EARLY_STOP+EARLY_STOP_STATE_WORDS<=OUT_VIEW_RECLAIM,"view reclaim report overlap");
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert(OUT_EXIT_PROFILE+2+EXIT_PROFILE_WORDS<=OUT_VIEW_RECLAIM,"view reclaim report overlap");
#endif
#if SNAP_FINE_LOCKS
_Static_assert(OUT_FINE_PROFILE+2+GUEST_CPU_COUNT*FINE_PROFILE_WORDS<=OUT_VIEW_RECLAIM,"view reclaim report overlap");
#endif
#if SNAP_TOKEN_COSTS
_Static_assert(OUT_TOKEN_COSTS+2+TOKEN_COSTS_WORDS<=OUT_VIEW_RECLAIM,"view reclaim report overlap");
#endif
#if SNAP_FAST_TIMER_IRQ
_Static_assert(OUT_FAST_IRQ+2+GUEST_CPU_COUNT*FAST_IRQ_WORDS<=OUT_VIEW_RECLAIM,"view reclaim report overlap");
#endif
#if SNAP_GUEST_NET
_Static_assert(OUT_GUEST_NET+2+GUEST_NET_LINK_WORDS+GUEST_NET_VIEW_WORDS<=OUT_VIEW_RECLAIM,"view reclaim report overlap");
#endif
#if SNAP_ADRENO_IB_ASYNC
_Static_assert(OUT_VIEW_RECLAIM+2+VIEW_RECLAIM_WORDS==OUT_IB_ASYNC,"the view reclaim record ends at the IB async slot");
#endif
#endif
