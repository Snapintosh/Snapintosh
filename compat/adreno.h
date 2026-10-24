/* SPDX-License-Identifier: MIT */
/* The Adreno X2-90 behind the monitor (Stage 4; docs/ADRENO-STAGE4-20260925.md).
 *
 * Power stays with q1n1. Its host tool (tools/a16gpu.py: gmu-smmu .. cp-fence)
 * brings the GPU to "CP idle after cp-fence": GMU booted from the q1n1 GPU
 * arena, OOB GPU_SET held (GX on), SQE running, one ring whose read and write
 * pointers agree. `a16gpu.py adopt` proves that state read-only just before the
 * launch and writes the record the loader turns into struct adreno_params. The
 * monitor adopts it: it never writes the GMU, GPUCC, RSCC or GX clock
 * controller, and reads two power words (CX GDSC, GMU_PWR_CLK_STATUS) before
 * every access that needs them.
 *
 * What the guest gets:
 *  - two stage-2 passthrough windows of GPU registers (Device-nGnRE, XN) and,
 *    optionally, CX_MISC read-only; every other block of the GPU aperture
 *    stays absent and a touch stops the run as EV_GPU_TRAP with its IPA;
 *  - INTID 0x14C (glymur.dtsi GIC_SPI 300; A16 ACPI GFX_INTERRUPT) as AIC 975,
 *    level, through compat/irq-forward.c;
 *  - SMMU context bank 0 (SIDs 0 and 1) as a virtual DART: stream 0 of
 *    /arm-io/dart-adreno is mirrored from the SPTM table-3 descriptors into
 *    CB0's LPAE tables over GPU VA [1 GiB, 4 GiB); q1n1's own CP buffers keep
 *    root entry 0 ([0, 1 GiB));
 *  - HVC #0 as the two allow-listed TrustZone GPU calls q1n1 forwards;
 *  - HVC #0xad16 for a guest-requested fence, FILL32 or IB (compat/adreno-ib.h)
 *    on the monitor-owned ring, which wraps with CP_NOP padding (design S1).
 *
 * Everything reaches hardware through struct adreno_ops, so the whole file
 * runs natively under sanitizers in tools/test-adreno.c against a model of
 * the SMMU walk, the CP ring, the GIC and a non-coherent cache. */
#pragma once
#include <stdint.h>
#include "irq-forward.h"
#include "adreno-guest.h"

/* The GPU aperture, A16 UEFI HWIO GFX map (adreno-hw a16-uefi-hwio-GFX-full.txt).
 * Passthrough: RBBM..BROADCAST (0x03d00000..0x03d35fff, plus the unlisted 4 KiB
 * at 0x03d36000 the plan admits) and CP_BLK_DEC3 + RBBM_BLK_DEC2 (SECVID). */
#define ADRENO_PA            0x03d00000UL
#define ADRENO_PASS0_END     0x03d37000UL
#define ADRENO_PASS1_PA      0x03d3c000UL
#define ADRENO_PASS1_END     0x03d40000UL
#define ADRENO_CX_MISC_PA    0x03d9e000UL   /* GPU_CX_MISC_BLK_DEC0/1 */
#define ADRENO_CX_MISC_END   0x03da0000UL
#define ADRENO_END           0x03df0000UL   /* GPU_SMMU .. GPU_QTB end at 0x03def400 */

/* Block classes (adreno_block). Anything >= ADRENO_TRAPPED stops the run. */
enum {
    ADRENO_NONE, ADRENO_PASS, ADRENO_CX_MISC_RO, ADRENO_TRAPPED,
    ADRENO_GMU_GX = ADRENO_TRAPPED, ADRENO_RDVM, ADRENO_GMU_AO, ADRENO_RSCC,
    ADRENO_SMMU_APERTURE, ADRENO_GXCLKCTL, ADRENO_GMU_CX, ADRENO_GPUCC,
    ADRENO_CX_MISC, ADRENO_SMMU, ADRENO_HOLE
};

/* Registers the monitor reads or writes: absolute PAs. GPU dwords from the
 * freedreno XML via q1n1 tools/adreno_x2.py (register x at 0x03d00000 + 4x). */
#define ADRENO_RBBM_GBIF_HALT      0x03d00028UL  /* A8XX_RBBM_GBIF_HALT 0x00a */
#define ADRENO_RBBM_GBIF_HALT_ACK  0x03d0002cUL  /* 0x00b */
#define ADRENO_RBBM_STATUS         0x03d00048UL  /* 0x012 */
#define ADRENO_RBBM_INT_0_STATUS   0x03d001a8UL  /* A8XX_RBBM_INT_0_STATUS 0x06a: sticky, nothing clears it */
#define ADRENO_CP_RB_CNTL          0x03d02008UL  /* A6XX_CP_RB_CNTL 0x802: BUFSZ [5:0] = log2(ring bytes / 8) */
#define ADRENO_CP_RB_CNTL_BUFSZ    0x3fU         /* the A16 reads 0x20c (BUFSZ 12) in every q1n1 record */
#define ADRENO_CP_RB_RPTR          0x03d02018UL  /* A6XX_CP_RB_RPTR 0x806 */
#define ADRENO_CP_RB_WPTR          0x03d0201cUL  /* 0x807 */
#define ADRENO_CP_SQE_CNTL         0x03d02054UL  /* A8XX_CP_SQE_CNTL 0x815 */
#define ADRENO_CP_INTERRUPT_STATUS_GLOBAL 0x03d022d4UL /* A8XX_CP_INTERRUPT_STATUS_GLOBAL 0x8b5: HW/SWFAULT */
#define ADRENO_GMU_PWR_CLK_STATUS  0x03d7dfa0UL  /* bits 0/1: GX GDSC off / clock off */
#define ADRENO_GMU_AHB_FENCE_STATUS 0x03d8ec4cUL /* 0x23b13, bit 0 WRITEDROPPED */
#define ADRENO_CX_CFG_GDSCR        0x03d99084UL  /* GPU_CC_CX_CFG_GDSCR bit 16 POWER_UP_COMPLETE */
#define ADRENO_SMMU_PA             0x03da0000UL
#define ADRENO_SMMU_SGFSR          (ADRENO_SMMU_PA + 0x48)
#define ADRENO_SMMU_CBFRSYNRA0     (ADRENO_SMMU_PA + 0x1400)
#define ADRENO_CB0                 (ADRENO_SMMU_PA + 32 * 0x1000)  /* A16 IDR1 NUMPAGENDXB 4 */
#define ADRENO_CB_SCTLR    0x000
#define ADRENO_CB_TTBR0    0x020
#define ADRENO_CB_TCR      0x030
#define ADRENO_CB_FSR      0x058
#define ADRENO_CB_FAR      0x060
#define ADRENO_CB_FSYNR0   0x068
#define ADRENO_CB_TLBIASID 0x610
#define ADRENO_CB_TLBSYNC  0x7f0
#define ADRENO_CB_TLBSTATUS 0x7f4
#define ADRENO_CB_FSR_FAULT 0xc00001feU          /* q1n1 CB_FSR_FAULT */
#define ADRENO_SCTLR_FIXED  0x1000U              /* ASIDPNE reads 0 on the A16 */

/* GIC distributor registers (Arm GICv3). */
#define GICD_CTLR 0x0
#define GICD_IGROUPR 0x80
#define GICD_ISENABLER 0x100
#define GICD_ICENABLER 0x180
#define GICD_ISPENDR 0x200
#define GICD_ICPENDR 0x280
#define GICD_IPRIORITYR 0x400
#define GICD_ICFGR 0xc00
#define GICD_IROUTER 0x6000
#define ADRENO_INTID 0x14cU
#define ADRENO_AIC_IRQ 975U
#define ADRENO_IRQ_PRIORITY 0x80U               /* q1n1's tick priority, under PMR 0xf0 */

/* The mirrored GPU VA window and the monitor's table pool: one level-2 table
 * per GiB of window (root entries 1..), then one level-3 table per 2 MiB,
 * direct-mapped. Default: [1 GiB, 4 GiB), CB0 T0SZ 32, the pool inside the
 * arena. ADRENO_VA_WIDE=1 (agents/gpu-va-wide FAILURE-MODES.md): [1 GiB,
 * 16 GiB), CB0 T0SZ 30 (q1n1 cp-fence --va-wide), and the pool in monitor
 * memory outside the arena (probes/xnuboot.py gpu_pool_reservation). */
#ifndef ADRENO_VA_WIDE
#define ADRENO_VA_WIDE 0
#endif
#if ADRENO_VA_WIDE != 0 && ADRENO_VA_WIDE != 1
#error "ADRENO_VA_WIDE is 0 or 1"
#endif
#define ADRENO_WINDOW_BASE  0x40000000UL
#if !ADRENO_VA_WIDE
#define ADRENO_CB0_T0SZ     32U
#define ADRENO_WINDOW_END   0x100000000UL
#else
#define ADRENO_CB0_T0SZ     30U
#define ADRENO_WINDOW_END   0x400000000UL
#endif
#define ADRENO_LOW_WINDOW_END 0x100000000UL     /* fixed kernel buffers (the IB arena) stay below it */
#define ADRENO_ROOT_SLOTS   (ADRENO_WINDOW_END >> 30)   /* CB0 root entries: 4 or 16; entry 0 is q1n1's */
#define ADRENO_L2_TABLES    ((ADRENO_WINDOW_END - ADRENO_WINDOW_BASE) >> 30)
#define ADRENO_L3_OFFSET    (ADRENO_L2_TABLES * 0x1000UL)  /* the level-3 array, from the pool start */
#define ADRENO_L3_TABLES    ((ADRENO_WINDOW_END - ADRENO_WINDOW_BASE) >> 21)
#define ADRENO_POOL_BYTES   ((ADRENO_L2_TABLES + ADRENO_L3_TABLES) * 0x1000UL)
#define ADRENO_DART_ID      31U                 /* /arm-io/dart-adreno dart-id */

/* LPAE stage-1 leaf bits (q1n1 a16gpu_stage3 PRIV_RW/UNPRIV_*; io-pgtable-arm.c). */
#define ADRENO_PTE_ADDR   0x0000fffffffff000UL
#define ADRENO_PTE_LEAF   (3UL | (1UL << 6) | (2UL << 8) | (1UL << 10) | (1UL << 11))
#define ADRENO_PTE_RDONLY (1UL << 7)
#ifndef SNAP_ADRENO_COHERENT
#define SNAP_ADRENO_COHERENT 0
#endif
#ifndef SNAP_ADRENO_COHERENT_FORCE
#define SNAP_ADRENO_COHERENT_FORCE 0   /* debug: ON without the self-test (compat/adreno-coherent.h) */
#endif
#if SNAP_ADRENO_COHERENT_FORCE && !SNAP_ADRENO_COHERENT
#error "SNAP_ADRENO_COHERENT_FORCE forces SNAP_ADRENO_COHERENT's state: build with both"
#endif
#if SNAP_ADRENO_COHERENT
/* IO-coherent leaves: the leaf Linux uses for a cached-coherent buffer on glymur (io-pgtable-arm.c IOMMU_CACHE:
 * AttrIndx 1 and SH inner shareable), with ADRENO_PTE_LEAF's permission, AF and nG bits. AttrIndx 1 is MAIR 0xff
 * only because q1n1 programs CB0 MAIR0 0xf404ff44 (tools/adreno_x2.py CB_MAIR0); the monitor re-reads it before
 * using this word (compat/adreno-coherent.c) and before every IB (compat/adreno-ib.c). The word is chosen once, at
 * prepare, while the mirror holds no guest leaf, and carried to every placement check in adreno_ops.leaf. */
#define ADRENO_PTE_LEAF_COHERENT ((ADRENO_PTE_LEAF & ~(3UL << 8)) | (1UL << 2) | (3UL << 8))
/* adreno_ops.leaf holds the bits that turn ADRENO_PTE_LEAF into the run's word: 0, or ADRENO_PTE_COHERENT_BITS
 * (AttrIndx 0 -> 1, SH outer -> inner: both only add bits), so the check is one OR at every placement site. */
#define ADRENO_PTE_COHERENT_BITS (ADRENO_PTE_LEAF_COHERENT ^ ADRENO_PTE_LEAF)
_Static_assert((ADRENO_PTE_LEAF | ADRENO_PTE_COHERENT_BITS) == ADRENO_PTE_LEAF_COHERENT, "coherent bits only add");
#define ADRENO_LEAF(o) (ADRENO_PTE_LEAF | (o)->leaf)
#define ADRENO_CB_MAIR0     0x038                       /* arm-smmu.h ARM_SMMU_CB_S1_MAIR0 */
#define ADRENO_SMMU_CBAR0   (ADRENO_SMMU_PA + 0x1000)   /* GR1 page, ARM_SMMU_GR1_CBAR(0) (q1n1 adreno_x2.py SMMU_CBAR) */
/* A ring user's CB0 check: coherent leaves are only coherent while MAIR index 1 is still write-back. `mair` is a
 * register read, evaluated only with coherent leaves, so today's leaves cost no extra MMIO. */
#define ADRENO_CB0_MAIR_OK(o, mair) (!(o)->leaf || (((mair) >> 8) & 0xffu) == 0xffu)
#else
#define ADRENO_LEAF(o) ADRENO_PTE_LEAF
#endif

/* PM4 (adreno_pm4.xml): CP_MEM_WRITE, type-7 header with odd parity. */
#define ADRENO_PKT7_MEM_WRITE3 0x703d8003U

/* HVC-forwarded TrustZone calls (q1n1 gpu-el2.h; qcom_scm.c). */
#define ADRENO_SMC_GPU_INIT     0x42002801UL
#define ADRENO_SMC_CP_APERTURE  0x42000c1bUL
#define ADRENO_SMC_APERTURE_CB0 0xffff0000UL
#define ADRENO_SMC_FILL         0xffffffffUL

/* params.gpu flags. Zero leaves the monitor exactly as it was. */
#define ADRENO_F_ENABLE   1u   /* passthrough, IRQ forward, HVC forwarder */
#define ADRENO_F_CX_MISC  2u   /* CX_MISC read-only passthrough */
#define ADRENO_F_DART     4u   /* mirror dart-adreno stream 0 into CB0 */
#define ADRENO_F_RING     8u   /* monitor test fence at prepare and in the run */
#define ADRENO_F_TZ_DONE 16u   /* q1n1 already made 0x42002801 on this boot */
#define ADRENO_F_SELF_IRQ 32u  /* one GICD_ISPENDR self-test of the IRQ path */
#define ADRENO_F_ALL     63u

/* probes/adreno.py builds this word by word (ADRENO_PARAMS_WORDS). */
struct adreno_params {
    uint64_t flags, gicd, affinity;          /* GIC distributor; IROUTER for the SPI */
    uint64_t arena_base, arena_size;         /* q1n1 bootinfo gpu_arena_* */
    uint64_t cb0_ttbr0, cb0_tcr, cb0_sctlr;  /* as cp-fence programmed and adopt read */
    uint64_t pool_pa;                        /* ADRENO_POOL_BYTES: inside the arena, or (ADRENO_VA_WIDE)
                                              * monitor memory outside it and outside guest memory */
    uint64_t ring_pa, ring_dwords, ring_wptr;/* the adopted ring, idle at ring_wptr */
    uint64_t fence_pa, fence_va;             /* monitor fence slot (memptrs + 0x80), VA < 1 GiB */
    uint64_t ring_at_seconds;                /* in-run fence after this much guest time */
    uint64_t reserved;
};
#define ADRENO_PARAMS_WORDS 16

/* context.gpu: tools/adreno_counters.py decodes it word by word in this order
 * (and the report copies it to OUT_GPU_FLOW); tools/test-adreno.c pins it. */
struct adreno_state {
    uint64_t status;                          /* ADRENO_S_* */
    uint64_t prepare;                         /* 0 or the adopt/attach refusal */
    uint64_t wptr, fences, fence_last, fence_ticks, fence_error;
    uint64_t maps, map_pages, unmaps, unmap_pages, refused, live_pages;
    uint64_t tlbi, tlbi_timeouts;
    uint64_t faults, fault_fsr, fault_far, fault_fsynr0, fault_cbfrsynra, fault_gfsr;
    uint64_t smc_calls, smc_refused, smc_cached, smc_fid, smc_x0, smc_resumes;
    uint64_t traps, trap_ipa, trap_esr, trap_block;
    uint64_t self_irq, irq_fired, irq_kept, irq_resampled, irq_spurious;
    uint64_t quiesce, halt_ack, cb0_after, serrors; /* nonzero quiesce closes submissions, even on failure */
    /* Were gic_saved[4] (reserved, same words): ADRENO_GUEST_IB calls that reached a doorbell (the marker
     * source), IB dwords completed, ring wraps of every ring user, IB calls that returned an error. */
    uint64_t ib_submits, ib_dwords, ring_wraps, ib_errors;
    uint64_t run_at;                          /* counter value for the in-run fence */
    struct irqfwd irq;
};
#define ADRENO_STATE_WORDS 45   /* words before `irq` */

#define ADRENO_S_ADOPTED   1u
#define ADRENO_S_ATTACHED  2u
#define ADRENO_S_ROUTED    4u
#define ADRENO_S_RUN_FENCE 8u
#define ADRENO_S_QUIESCED 16u   /* successful halt/off + owned mirror detach/TLBI only */
#define ADRENO_S_TZ_DONE  32u
#define ADRENO_S_HIJACKED 64u   /* CB0 TTBR0/TCR/SCTLR no longer what was adopted */

/* Refusals (negative, in state.prepare and returned to xnuboot_prepare). */
enum {
    ADRENO_E_PARAMS = -60, ADRENO_E_CX = -61, ADRENO_E_GX = -62, ADRENO_E_CB0 = -63,
    ADRENO_E_ROOT = -64, ADRENO_E_SQE = -65, ADRENO_E_RING = -66, ADRENO_E_FAULT = -67,
    ADRENO_E_FENCE = -68, ADRENO_E_TLB = -69, ADRENO_E_WINDOW = -70,
    ADRENO_E_HALT = -71,    /* GX-side GBIF already halted (RBBM_GBIF_HALT_ACK bit 0) */
    ADRENO_E_TARGET = -72,  /* guest fence target absent, bounded or mirror mismatch */
    ADRENO_E_DART = -73    /* native unmap failed or left a live leaf */
};

/* The monitor build (aarch64 ELF, freestanding) reaches hardware directly and
 * uses only ctx, smc and hz; the native tests supply every member. */
#ifndef ADRENO_DIRECT
#if defined(__aarch64__) && defined(__ELF__) && !defined(__APPLE__) && !defined(__linux__)
#define ADRENO_DIRECT 1
#else
#define ADRENO_DIRECT 0
#endif
#endif
struct adreno_ops {
    void *ctx;
    uint32_t (*rd)(void *ctx, uint64_t pa);              /* 32-bit, device or DRAM word */
    void (*wr)(void *ctx, uint64_t pa, uint32_t value);
    uint64_t (*rd64)(void *ctx, uint64_t pa);            /* DRAM table word */
    void (*wr64)(void *ctx, uint64_t pa, uint64_t value);
    void (*clean)(void *ctx, uint64_t pa, uint64_t size);/* DC CIVAC to PoC, then DSB */
    uint64_t (*now)(void *ctx);                          /* CNTPCT */
    int (*smc)(void *ctx, uint64_t regs[8]);             /* nonzero: did not reach EL3 */
    uint64_t hz;
    void (*invalidate)(void *ctx, uint64_t pa, uint64_t size); /* aligned DC IVAC + DSB */
#if SNAP_ADRENO_COHERENT
    uint64_t leaf;   /* 0 or ADRENO_PTE_COHERENT_BITS: the run's mirror leaf is ADRENO_LEAF(o) */
#if !ADRENO_DIRECT
    uint64_t (*refills)(void *ctx);   /* the self-test's PMU counter (L2D_CACHE_REFILL); the monitor reads it itself */
#endif
#endif
};

/* Which block of the GPU aperture holds `pa` (ADRENO_NONE outside it). */
unsigned adreno_block(uint64_t pa, uint64_t flags);

/* Validate params against guest memory [mem_low, mem_high), re-prove the
 * adopted state from the hardware (read-only), then build the empty mirror
 * and link it into CB0's root entries 1..ADRENO_ROOT_SLOTS-1 (1..3, or 1..15
 * with ADRENO_VA_WIDE, which also requires CB0 T0SZ 30 and a 4 KiB TG0).
 * 0 or ADRENO_E_*. */
int adreno_adopt(const struct adreno_ops *o, const struct adreno_params *p,
                 struct adreno_state *s, uint64_t mem_low, uint64_t mem_high);

/* One CP_MEM_WRITE of `value` to the fence slot, bounded poll. 0 or ADRENO_E_*. */
#if SNAP_ADRENO_FENCE_BR
/* Opt-in (agents/gpu-x290 FAILURE-MODES.md F7): the fence words (this and ADRENO_GUEST_FENCE) are
 * CP_THREAD_CONTROL(BR | SYNC_THREADS), CP_WAIT_FOR_IDLE, the CP_MEM_WRITE, CP_THREAD_CONTROL(BOTH): written by
 * BR once, after the GPU is idle, instead of by both CP threads in the ring's BOTH mode; completion also needs
 * RBBM_STATUS idle (ADRENO_IB_RBBM_IDLE_IGNORE). */
#define ADRENO_FENCE_BR_WORDS 9u
#endif
int adreno_fence(const struct adreno_ops *o, const struct adreno_params *p,
                 struct adreno_state *s, uint32_t value);

/* The monitor-owned ring, shared by the fences, FILL32 and IB (design S1, compat/adreno-guest.h "Ring wrap").
 * Submissions are synchronous, so every emission starts on an idle ring at w = s->wptr.
 *  - ready: read-only. 0 when CP_RB_WPTR == CP_RB_RPTR == w < ring_dwords, CP_RB_CNTL.BUFSZ describes
 *    exactly ring_dwords (the CP's wrap point is the monitor's) and 1 <= n <= ring_dwords - 1; else
 *    ADRENO_E_RING.
 *  - reserve: ready, then room for n contiguous words at *at. When n < ring_dwords - w they go at w. Else
 *    [w, ring_dwords) becomes CP_NOP packets (cleaned to PoC), ring_wraps counts it and *at = 0. When the
 *    words would also cover that unexecuted padding (n >= w) the padding is rung alone first (WPTR 0, fenced
 *    write, one retry) and the CP must reach RPTR 0 within hz/20; *rung then reports that a doorbell was
 *    attempted: ADRENO_E_RING (dropped twice; s->wptr unchanged) or ADRENO_E_FENCE (not consumed in time;
 *    s->wptr = 0) may leave work queued, and FILL32/IB treat both as UNCERTAIN.
 *  - kick: clean the n words at `at` and ring CP_RB_WPTR = at + n (never ring_dwords) with
 *    a6xx_fenced_write (one retry). 0 and s->wptr = at + n, or ADRENO_E_RING with s->wptr unchanged. */
int adreno_ring_ready(const struct adreno_ops *o, const struct adreno_params *p,
                      const struct adreno_state *s, uint64_t n);
int adreno_ring_reserve(const struct adreno_ops *o, const struct adreno_params *p,
                        struct adreno_state *s, uint64_t n, uint64_t *at, int *rung);
int adreno_ring_kick(const struct adreno_ops *o, const struct adreno_params *p,
                     struct adreno_state *s, uint64_t at, uint64_t n);

/* Private guest request (compat/adreno-guest.h). Caller serializes with DART
 * changes. Validate native byte bounds and writable SMMU mirror before DMA.
 * Failed submitted work may remain outstanding: retain its buffer until reset. */
int adreno_guest_fence(const struct adreno_ops *o, const struct adreno_params *p,
                       struct adreno_state *s, uint64_t regs[4],
                       uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                       uint64_t mem_low, uint64_t mem_high);

/* Same service lock as native SPTM/DART: clear native leaves/references, then
 * synchronously invalidate their SMMU mirror. The mapper VMSpace survives.
 * On ANY failure the caller must retain backing and its address reservation. */
int adreno_guest_unmap(const struct adreno_ops *o, const struct adreno_params *p,
                       struct adreno_state *s, uint64_t regs[4],
                       uint64_t (*leaf)(void *ctx, uint64_t iova),
                       int (*unmap)(void *ctx, uint64_t iova, uint64_t size), void *ctx,
                       uint64_t mem_low, uint64_t mem_high);

/* Service lock must cover both full-range preflight and maintenance. TO_DEVICE
 * cleans+invalidates; FROM_DEVICE invalidates only, after caller-proven GPU
 * retirement. Native byte bounds and every mirror leaf must agree. */
int adreno_guest_cache(const struct adreno_ops *o, const struct adreno_params *p,
                       struct adreno_state *s, uint64_t regs[4],
                       uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                       uint64_t mem_low, uint64_t mem_high);
#if SNAP_ADRENO_COHERENT
int adreno_guest_cache_filtered(const struct adreno_ops *o, const struct adreno_params *p,
                                struct adreno_state *s, uint64_t regs[4],
                                uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                                uint64_t mem_low, uint64_t mem_high,
                                int (*writeback)(void *ctx, uint64_t pa), void *writeback_ctx);
#endif

/* Mirror DART stream 0 over [iova, iova + size): `leaf` returns the committed
 * T8110 level-2 descriptor of a 16 KiB IOVA page (0: none). Leaves that point
 * outside [mem_low, mem_high), inside the arena, or are write-only are left
 * unmapped and counted. Unmapped or changed entries are invalidated
 * (TLBIASID + TLBSYNC) before the call returns. 0 or ADRENO_E_*. */
int adreno_mirror(const struct adreno_ops *o, const struct adreno_params *p,
                  struct adreno_state *s, uint64_t iova, uint64_t size,
                  uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                  uint64_t mem_low, uint64_t mem_high);

/* A CB0 context fault, recorded and cleared (W1C). 1 when one was new. */
int adreno_fault_poll(const struct adreno_ops *o, struct adreno_state *s);

/* The SMC allow-list (q1n1 q1n1_gpu_smc_allowed, byte for byte). */
int adreno_smc_allowed(uint64_t fid, uint64_t x1, uint64_t x2, uint64_t x3);
/* Forward guest x0..x3 in regs[0..3]; TrustZone's x0..x3 come back there.
 * -1: refused (not allow-listed); 0: answered (regs[0] is TrustZone's own,
 * EBUSY and WAITQ_SLEEP included, or q1n1's -7 UNDEF / -10 EINTR). */
int adreno_smc(const struct adreno_ops *o, uint64_t flags, struct adreno_state *s,
               uint64_t regs[8]);

/* Route the SPI to p->affinity (group 1 NS, level, priority), disabled and
 * not pending; ADRENO_E_PARAMS when the priority byte reads 0 (Secure: RAZ/WI).
 * Restore leaves it disabled and not pending. */
int adreno_gic_route(const struct adreno_ops *o, const struct adreno_params *p,
                     struct adreno_state *s);
void adreno_gic_restore(const struct adreno_ops *o, const struct adreno_params *p,
                        struct adreno_state *s);

/* Before the guest stops (and so before any chainload): halt GX-side GPU
 * DMA (RBBM_GBIF_HALT), unlink the mirror from CB0 and invalidate, record
 * any fault and whether CB0 still holds the adopted TTBR0/TCR. The caller
 * has already drained every guest executor/service owner and dropped the IRQ
 * line (irqfwd_quiesce, adreno_gic_restore). Nonzero state.quiesce is sticky and
 * closes submissions. Only ADRENO_S_QUIESCED proves successful completion;
 * without it the caller must quarantine RAM, not publish/reclaim or retry.
 * Polls are bounded by the physical counter (MMIO itself must still return). */
void adreno_quiesce(const struct adreno_ops *o, const struct adreno_params *p,
                    struct adreno_state *s);
