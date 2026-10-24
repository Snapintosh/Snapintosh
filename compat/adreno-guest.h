/* SPDX-License-Identifier: MIT */
#ifndef SNAP_ADRENO_GUEST_H
#define SNAP_ADRENO_GUEST_H

/* Private monitor-owned-ring probe, advertised by the GPU ADT node.
 * x0=request, x1=IOVA, x2=u32 value, x3=0; results: signed status, observed
 * value (zero on failure), poll ticks, ring WPTR. ELR already follows HVC. */
#define ADRENO_GUEST_HVC 0xad16
#define ADRENO_GUEST_ABI 1
#define ADRENO_GUEST_FENCE 0x00010001
#define ADRENO_GUEST_PROPERTY "snapintosh,guest-fence-abi"
/* Clear PTEs while retaining the native mapper's address reservation.
 * x1=16 KiB-aligned IOVA, x2=aligned bytes within one 32 MiB leaf span.
 * Results: status, cleared bytes (zero on error), native status, ring WPTR. */
#define ADRENO_GUEST_UNMAP 0x00010002
#define ADRENO_GUEST_UNMAP_PROPERTY "snapintosh,guest-unmap-abi"
/* CPU cache maintenance for exclusively owned 64-byte lines. Caller retains
 * prepared backing and proves GPU retirement before FROM_DEVICE. x1=IOVA,
 * x2=bytes (both aligned); x3=direction. Results: status, bytes, 0, WPTR.
 * This does not submit commands or flush GPU-internal caches. */
#define ADRENO_GUEST_CACHE 0x00010003
#define ADRENO_GUEST_CACHE_PROPERTY "snapintosh,guest-cache-abi"
#define ADRENO_CACHE_TO_DEVICE 1
#define ADRENO_CACHE_FROM_DEVICE 2
#define ADRENO_CACHE_MAX_BYTES (1UL << 20)

/* Early stop (compat/early-stop.h): end this run through the watchdog's own stop x2 seconds from now,
 * for reason x1 (EARLY_STOP_REASON_*), recording detail x3. Advertised only by ADT property
 * ADRENO_GUEST_STOP_PROPERTY = <ADRENO_GUEST_STOP_ABI>, with the launch's default delay (seconds) in
 * ADRENO_GUEST_STOP_DELAY_PROPERTY. A launch that did not enable it, like an older monitor's fence
 * handler, refuses with ADRENO_E_PARAMS and the run continues. Admitted only from EL1, for an HVC whose
 * bytes are the loaded AuxKC's. The run keeps going until the deadline; the first request wins.
 * Out: x0 = 0 accepted, 1 an earlier request already won, negative refused (EARLY_STOP_E_*);
 *      x1 = accepted delay (0 on refusal), x2 = monitor phase, x3 = the launch's maximum delay. */
#define ADRENO_GUEST_STOP 0x00010006
#define ADRENO_GUEST_STOP_ABI 1
#define ADRENO_GUEST_STOP_PROPERTY "snapintosh,guest-stop-abi"
#define ADRENO_GUEST_STOP_DELAY_PROPERTY "snapintosh,guest-stop-delay"

/* ---- Draw submission: ADRENO_GUEST_IB (ABI 1, design S0/4.3) -------------------------------------------
 * The monitor rings one kext-validated indirect buffer (IB1) through the monitor-owned ring and returns after
 * GPU completion (synchronous, like FENCE/FILL32). Advertised only by ADT property ADRENO_GUEST_IB_PROPERTY
 * = <ADRENO_GUEST_IB_ABI> on the GPU node; an older monitor routes the request to the fence handler, which
 * refuses it (ADRENO_E_PARAMS). The monitor never parses IB content.
 * In:  x0 = ADRENO_GUEST_IB
 *      x1 = package GPU VA, ADRENO_IB_ALIGN-aligned; [x1, x1 + x3) inside the shared window
 *           [ADRENO_WINDOW_BASE, ADRENO_WINDOW_END) (compat/adreno.h); the IB is package bytes [0, 4 * x2)
 *      x2 = IB dwords, 1..ADRENO_IB_MAX_DWORDS
 *      x3 = package bytes: multiple of ADRENO_IB_ALIGN, >= ADRENO_IB_ALIGN_UP(4 * x2), <= ADRENO_IB_MAX_PACKAGE
 * Out: x0 = status (0 or negative), x1 = completion marker (0 on failure), x2 = poll ticks, x3 = ring WPTR.
 * Placement (checked for every 16 KiB page of the package): DART leaf valid, readable, NO-WRITE (leaf bit 2),
 * byte bounds cover the used bytes, PA in guest RAM and outside the monitor arena, and every 4 KiB mirror
 * slot == pa | ADRENO_PTE_LEAF | ADRENO_PTE_RDONLY. The monitor cleans the package to PoC before ringing.
 * Refusals before any ring write, in check order (no GPU state changed, nothing latched):
 *   ADRENO_E_PARAMS   request word; flags not ENABLE|DART or RING set; state not ADOPTED|ATTACHED, or
 *                     QUIESCED/HIJACKED
 *   ADRENO_E_WINDOW   x1/x2/x3 alignment, limits or window
 *   ADRENO_E_TARGET   a package page fails the placement rule above
 *   ADRENO_E_CX, ADRENO_E_GX, ADRENO_E_HALT, ADRENO_E_CB0, ADRENO_E_FAULT, ADRENO_E_SQE   as FILL32
 *   ADRENO_E_RING     CP_RB_WPTR/CP_RB_RPTR != the monitor's WPTR, or ring_dwords != ADRENO_RING_DWORDS(BUFSZ)
 *   ADRENO_IB_E_BUSY  RBBM_STATUS & ~ADRENO_IB_RBBM_IDLE_IGNORE != 0 before submission
 *   ADRENO_IB_E_STICKY RBBM_INT_0_STATUS & ADRENO_IB_RBBM_INT_ERRORS or CP_INTERRUPT_STATUS_GLOBAL &
 *                     ADRENO_IB_CP_GLOBAL_FAULTS already set (nothing clears them: the GPU needs recovery)
 * After a doorbell may have reached the CP:
 *   ADRENO_IB_E_UNCERTAIN  WRITEDROPPED twice, CB0/SMMU fault while polling, or no completion within
 *                     hz / ADRENO_IB_POLL_DIVISOR: retain every backing page, submit nothing more until reset
 *   ADRENO_IB_E_GPU_ERROR  both fences landed, RPTR == WPTR and RBBM idle (the IB is retired), but an error
 *                     bit or CB0 fault is now set: the output is invalid; stop IB submission, GPU is idle
 * Success requires BR fence == marker, BV fence == marker, CP_RB_RPTR == new WPTR and RBBM idle; a shader or
 * IB write to memptrs cannot fake the last two. marker = ADRENO_IB_MARKER_BASE ^ (submission count). */
#define ADRENO_GUEST_IB 0x00010005
#define ADRENO_GUEST_IB_PROPERTY "snapintosh,guest-ib-abi"
/* agents/gpu-va-wide: the GPU node's u32 GPU VA width, 34, only in a tree for an ADRENO_VA_WIDE monitor
 * (probes/adreno.py GPU_VA_BITS_PROPERTY). A kext built with ADRENO_VA_WIDE refuses to start without it. */
#define ADRENO_GPU_VA_BITS_PROPERTY "snapintosh,gpu-va-bits"
#define ADRENO_GUEST_IB_ABI 1
#define ADRENO_IB_ALIGN 64u
#define ADRENO_IB_ALIGN_UP(bytes) (((bytes) + (ADRENO_IB_ALIGN - 1ull)) & ~(ADRENO_IB_ALIGN - 1ull))
#define ADRENO_IB_MAX_DWORDS 0x40000u     /* 1 MiB of packets; CP IB_SIZE is 20 bits */
#define ADRENO_IB_MAX_DATA 0x100000u      /* 1 MiB of descriptors/uniforms/driver tables per package */
#define ADRENO_IB_MAX_PACKAGE 0x200000u   /* = IB max + data max; bytes validated/cleaned per call */
#define ADRENO_IB_E_UNCERTAIN (-75)
#define ADRENO_IB_E_GPU_ERROR (-76)
#define ADRENO_IB_E_BUSY (-77)
#define ADRENO_IB_E_STICKY (-78)
#define ADRENO_IB_MARKER_BASE 0x534e7000u /* FILL32 uses 0x534e6000 */
#ifndef ADRENO_IB_POLL_DIVISOR            /* opt-in override: installed-fresh --ib-budget-1s (v38 timed out once) */
#define ADRENO_IB_POLL_DIVISOR 10u        /* completion budget hz / 10 (FILL32: hz / 20) */
#endif
/* Completion slots, byte offsets in q1n1's CP memptrs page (the BR slot is the monitor fence, q1n1
 * MONITOR_FENCE_OFF; q1n1 itself uses 0x0, 0x8, 0x40, 0x50, 0x60). Both on their own 64-byte line. */
#define ADRENO_IB_BR_FENCE_OFF 0x80u
#define ADRENO_IB_BV_FENCE_OFF 0xc0u
/* Ring words per IB: q1n1 a16gpu_p6p7.ring_words (a7xx_submit): THREAD_CONTROL(BR,sync), (BOTH),
 * CP_INDIRECT_BUFFER, (BR), CCU_INVALIDATE_DEPTH, CCU_INVALIDATE_COLOR, (BV), CACHE_CLEAN->BV slot, (BR),
 * CP_WAIT_TIMESTAMP(BV slot), CACHE_CLEAN->BR slot, (BOTH). */
#define ADRENO_IB_RING_WORDS 35u
/* Error bits (a6xx.xml A8XX fields; tools/test-draw-contract.sh proves them against the generated header and
 * q1n1 RBBM_INT_ERRORS / CP_GLOBAL_FAULTS): RBBM_INT_0_STATUS CP_AHB_ERROR, RBBM_ATB_ASYNCFIFO_OVERFLOW,
 * RBBM_GPC_ERROR, CP_HW_ERROR, RBBM_ATB_BUS_OVERFLOW, RBBM_HANG_DETECT, UCHE_OOB_ACCESS, UCHE_TRAP_INTR,
 * TSBWRITEERROR, SWFUSEVIOLATION; CP_INTERRUPT_STATUS_GLOBAL HWFAULT{BR..DDEBV} | SWFAULT{BR..DDEBV};
 * RBBM_STATUS CP_AHB_BUSY_CX_MASTER (the CPU's own register access, ignored for idle). */
#define ADRENO_IB_RBBM_INT_ERRORS 0x33c002c2u
#define ADRENO_IB_CP_GLOBAL_FAULTS 0x007f007fu
#define ADRENO_IB_RBBM_IDLE_IGNORE 0x00000001u

/* ---- Asynchronous completion: ADRENO_GUEST_IB_START / ADRENO_GUEST_IB_POLL (monitor SNAP_ADRENO_IB_ASYNC) ------
 * ADRENO_GUEST_IB holds the monitor's global service token while the GPU runs (every HVC is taken under it). These
 * two split one IB into short token holds; the guest waits between them (agents/async-ib/FAILURE-MODES.md).
 * No ADT property: discovery is IB_POLL with x1 = 0, answered ADRENO_IB_IDLE by a monitor that has them and
 * ADRENO_E_PARAMS by any other (its fence handler refuses the request word).
 *  IB_START  In: as ADRENO_GUEST_IB (x0 = ADRENO_GUEST_IB_START). The same checks and refusals in the same order,
 *            the same package clean and ring words, then a completion poll of at most hz / ADRENO_IB_START_SPIN_DIVISOR.
 *            Out: a final status exactly as ADRENO_GUEST_IB's, or x0 = ADRENO_IB_PENDING with x1 = the marker (the
 *            IB is in flight), x2 = ticks since the doorbell, x3 = WPTR. Refused with ADRENO_IB_E_BUSY (before any
 *            ring write) while another IB is in flight.
 *  IB_POLL   In: x1 = the marker START returned, x2 = x3 = 0. One completion pass with ADRENO_GUEST_IB's rules (fault,
 *            then completion, then GPU error), the budget hz / ADRENO_IB_POLL_DIVISOR timed from START's doorbell.
 *            Out: x0 = ADRENO_IB_PENDING (x1 = marker), or the final 0 (x1 = marker), ADRENO_IB_E_GPU_ERROR or
 *            ADRENO_IB_E_UNCERTAIN (x1 = 0); x2 = ticks since the doorbell, x3 = WPTR. A final status ends the
 *            flight; a later POLL of the same marker gets the same reply again. ADRENO_IB_IDLE (x1 = 0): no flight
 *            and not the last one's marker (marker 0 always). ADRENO_IB_E_BUSY: another marker is in flight.
 * While an IB is in flight the monitor refuses ADRENO_GUEST_IB and IB_START (ADRENO_IB_E_BUSY), FENCE and FILL32
 * (ADRENO_E_PARAMS), an UNMAP overlapping the in-flight package (ADRENO_IB_E_BUSY), all before any write; its tick
 * skips the CB0 fault poll (the IB's own POLL must see a fault) and the run fence. A flight nobody polls for
 * budget + 1 s is finalized by the tick; a stop drains it before the GPU is quiesced.
 * After START answered PENDING the doorbell has been rung: any POLL reply other than 0, GPU_ERROR, UNCERTAIN or
 * PENDING with the same marker means UNCERTAIN to the caller (compat/adreno-ib-async.h). */
#define ADRENO_GUEST_IB_START 0x00010008      /* 0x00010007 is ADRENO_GUEST_NET (compat/guest-net.h) */
#define ADRENO_GUEST_IB_POLL 0x00010009
#define ADRENO_IB_PENDING (-79)
#define ADRENO_IB_IDLE (-80)
#ifndef ADRENO_IB_START_SPIN_DIVISOR
#define ADRENO_IB_START_SPIN_DIVISOR 50000u   /* START polls at most hz / 50000 = 20 us */
#endif

/* ---- GPU hang recovery: ADRENO_GUEST_RECOVER (monitor SNAP_ADRENO_RECOVER; agents/gpu-recovery FAILURE-MODES.md) ---
 * No ADT property: discovery is QUERY, which a monitor without it refuses (its fence handler: ADRENO_E_PARAMS).
 *  QUERY   In: x1 = ADRENO_RECOVER_QUERY, x2 = x3 = 0.
 *          Out: x0 = 0, x1 = ADRENO_RECOVER_ABI | level << 8 | hard limit in seconds << 16, x2 = epoch (resets so far),
 *               x3 = ADRENO_RECOVER_STATE_*.
 *  SETTLE  In: x1 = ADRENO_RECOVER_SETTLE, x2 = x3 = 0. Everything the guest rang before this call has retired or was
 *          reset: 0 only once the CP is proven idle (CP_RB_RPTR == CP_RB_WPTR == the monitor's WPTR, SQE running, RBBM
 *          idle, no error bit, no CB0 or global fault, no flight), after a CP soft reset at level 2 when it was not.
 *          Out: x0 = 0, ADRENO_IB_E_BUSY (an IB is in flight: POLL it first), ADRENO_RECOVER_E_DEAD (the monitor gave
 *               up for this boot) or ADRENO_IB_E_UNCERTAIN (level 1: not idle, and no reset allowed); x1 = epoch,
 *               x2 = 1 when this call reset the GPU, x3 = WPTR.
 * Level 2 ends a flight with ADRENO_IB_E_RESET or ADRENO_IB_E_RESET_FAULT (x1 = 0, like any failure) instead of
 * UNCERTAIN or GPU_ERROR: the IB hung (hard limit, hang evidence) or faulted, the monitor drained GPU DMA and reset the
 * CP; the IB's outputs are undefined, the GPU no longer accesses anything it referenced, and ring users are admitted
 * again. An older kext reads either as UNCERTAIN (adreno-ib-async.h A9). */
#define ADRENO_GUEST_RECOVER 0x0001000A
#define ADRENO_RECOVER_ABI 1u
#define ADRENO_RECOVER_QUERY 0u
#define ADRENO_RECOVER_SETTLE 1u
#define ADRENO_RECOVER_STATE_READY 0u
#define ADRENO_RECOVER_STATE_FLIGHT 1u
#define ADRENO_RECOVER_STATE_DEAD 2u
#define ADRENO_IB_E_RESET_FAULT (-94)
#define ADRENO_IB_E_RESET (-95)
#define ADRENO_RECOVER_E_DEAD (-96)
#define ADRENO_IB_HARD_SECONDS_MAX 4u      /* IOGPU waitForGPUTimeoutSeconds is 5 (AdrenoContract.h) */

/* ---- IO-coherent GPU mappings: ADRENO_GUEST_COHERENT (monitor SNAP_ADRENO_COHERENT) -----------------------------
 * The monitor's boot self-test decides whether CB0's mirror leaves are cache-coherent with the CPU (AttrIndx 1 =
 * MAIR 0xff, SH inner shareable). No ADT property: discovery is QUERY, which a monitor without it refuses (its fence
 * handler: ADRENO_E_PARAMS), so an older monitor leaves the kext on today's maintenance.
 *  QUERY   In: x1 = ADRENO_COHERENT_QUERY (x2, x3 ignored; pass 0).
 *          Out: x0 = 0; x1 = ADRENO_COHERENT_ABI | state << 8 | (u16)detail << 16 (ADRENO_COHERENT_STATE_*);
 *               x2 = the CPU attribute epoch (never 0): it moves whenever an SPTM call changes any frame's SH/AttrIndx,
 *               so a "every frame of this map is CPU write-back" verdict holds only at the epoch it was made at;
 *               x3 = self-test iterations passed.
 * ADRENO_GUEST_CACHE with x3 = direction | ADRENO_CACHE_COHERENT, accepted only while the state is ON (else
 * ADRENO_E_PARAMS before anything): the same arguments, validation and refusals as the plain call, then only the
 * frames whose live CPU attribute is not Normal write-back are maintained. Out: x0 = 0, x1 = bytes, x2 = the bytes
 * still maintained (0: every frame was write-back), x3 = WPTR. */
#define ADRENO_GUEST_COHERENT 0x0001000B
#define ADRENO_COHERENT_ABI 1u
#define ADRENO_COHERENT_QUERY 0u
#define ADRENO_COHERENT_STATE_NOT_RUN 0u      /* no self-test (no GPU, or prepare refused earlier) */
#define ADRENO_COHERENT_STATE_ON 1u           /* passed every iteration: coherent leaves, coherent calls accepted */
#define ADRENO_COHERENT_STATE_FAILED 2u       /* a direction saw stale data with coherent leaves */
#define ADRENO_COHERENT_STATE_TIMEOUT 3u      /* a GPU job did not complete within its budget */
#define ADRENO_COHERENT_STATE_REFUSED 4u      /* a precondition (CB0 MAIR/CBAR, scratch, ring, mirror) did not hold */
#define ADRENO_COHERENT_STATE_INCONCLUSIVE 5u /* the test had no detection power (the PMU did not prove it) */
#define ADRENO_COHERENT_STATE_GPU_ERROR 6u    /* a job retired with an error bit or a CB0/SMMU fault */
#define ADRENO_CACHE_COHERENT 0x100u          /* ADRENO_GUEST_CACHE direction flag */
/* In QUERY's detail with state ON: a debug monitor (SNAP_ADRENO_COHERENT_FORCE) set ON without the self-test. The
 * kext takes it as ON only with its own boot-arg adreno_coherent_force=1, and says so loudly either way. */
#define ADRENO_COHERENT_DETAIL_FORCED 0x2000u

/* ---- Panel brightness: ADRENO_GUEST_BACKLIGHT (monitor SNAP_EDP_BACKLIGHT) ------------------------------------------
 * QUERY and SET of the panel's DPCD backlight level over the eDP AUX channel; ABI, states and errors in
 * compat/edp-backlight.h. No ADT property: discovery is QUERY, which a monitor without it refuses (ADRENO_E_PARAMS). */
#define ADRENO_GUEST_BACKLIGHT 0x0001000C

/* ---- Ring wrap (design S1; shared by FENCE, FILL32 and IB) ----------------------------------------------
 * The ring is ADRENO_RING_DWORDS(CP_RB_CNTL.BUFSZ) dwords (q1n1 writes BUFSZ ADRENO_RING_BUFSZ = 8192 dwords);
 * the monitor adopts it only when p->ring_dwords matches. Submissions stay synchronous: an emit starts with
 * CP_RB_RPTR == CP_RB_WPTR == w. n words fit at w when n < ring_dwords - w. Otherwise [w, ring_dwords) is
 * padded with CP_NOP packets (payload count <= ADRENO_RING_NOP_MAX each; a one-dword tail is CP_NOP count 0)
 * and the words start at 0. The new WPTR must never equal RPTR (the CP would see an empty ring): with the
 * words at 0 that needs n < w, so an emit of n >= w first rings the pad alone (WPTR = 0), waits for
 * RPTR == 0, then writes at 0. Every emit needs n <= ADRENO_RING_EMIT_MAX(ring_dwords). */
#define ADRENO_RING_BUFSZ 12u
#define ADRENO_RING_DWORDS(bufsz) (2u << (bufsz))     /* CP_RB_CNTL BUFSZ = log2(ring bytes / 8) */
#define ADRENO_RING_NOP_MAX 0x3fffu                    /* pkt7 count field (freedreno_pm4.h type7_pkt_size) */
#define ADRENO_RING_EMIT_MAX(ring_dwords) ((ring_dwords) - 1u)

#endif
