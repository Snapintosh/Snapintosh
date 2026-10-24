/* SPDX-License-Identifier: MIT */
/* Kext side of draw submission (design 3.1-3.6): ADRENO_KCMD_IB staging, relocation and validation, the
 * submission's per-resource cache ownership and monitor-reply mapping, the IOGPU kernel-command dispatch, and the
 * fail-fast gate every GPU submission (FENCE, FILL32, IB) passes through. Pure C, no allocation: the kext
 * (AdrenoX2.cpp, -mkernel) and the host tests (tools/test-adreno-ib-command.c) own every buffer.
 * Wire format and relocation rules: adreno-submit.h. Monitor call and its result codes: adreno-guest.h.
 *
 * Validator policy (allowlist, design 3.3), applied to the kernel copy after relocation:
 *  - packets: PKT4 (count >= 1) and PKT7 only, header == a8xx_pkt4_hdr/a8xx_pkt7_hdr of its own fields, every
 *    packet inside the IB; 17 opcodes: CP_NOP, CP_WAIT_FOR_IDLE, CP_CCHE_INVALIDATE, CP_SET_MODE(0),
 *    CP_THREAD_CONTROL (THREAD 1..3, CONCURRENT_BIN_DISABLE, SYNC_THREADS), CP_SET_MARKER (RM6_DIRECT_RENDER,
 *    RM6_BLIT2DSCALE), CP_SKIP_IB2_ENABLE_GLOBAL/LOCAL (0/1), CP_SET_VISIBILITY_OVERRIDE (0/1), CP_EVENT_WRITE7
 *    (count 1, event only: CCU clean/invalidate colour/depth, CACHE_CLEAN, CACHE_INVALIDATE7, LRZ_CACHE_FLUSH,
 *    DUMMY_EVENT, SUBPASS_FENCE, DEBUG_LABEL), CP_CONTEXT_REG_BUNCH, CP_NON_CONTEXT_REG_BUNCH (1, 0, pairs),
 *    CP_SET_DRAW_STATE (DISABLE_ALL_GROUPS, 0, 0), CP_LOAD_STATE6_GEOM/FRAG (UBO direct for SB6_VS_SHADER/
 *    SB6_FS_SHADER; S#/T# indirect for SB6_FS_TEX from the package), CP_BLIT (BLIT_OP_SCALE), CP_DRAW_INDX_OFFSET
 *    (3 dwords auto-index, or 7 dwords DMA 16/32-bit; TRI/LINE/POINT lists and strips, TRIFAN; no GS/tess).
 *    Everything else (nested IBs, memory writes, CP_SMMU_TABLE_UPDATE, ...) is ADRENO_IB_E_PACKET.
 *  - registers: KNOWN (AdrenoA8xxRegs.h a8xx_ib_regs, expanded) minus PROTECTED (adreno-ib-tables.h), by the full
 *    dword offset; otherwise ADRENO_IB_E_REGISTER.
 *  - address fields: every 64-bit register (the 18 address registers), UBO descriptor, LOAD_STATE6 external
 *    address, DMA index base and T# base (dwords 0/1, 4/5, 8/9 of each T# in a package T# array) holds either a
 *    null address (address bits zero) or exactly one relocation whose lo/hi targets are that field's two dwords,
 *    hi_bits 32 (registers, packets) or 17 (UBO/T# BASE_HI). Kinds: RB_MRT_BASE, RB_A2D_DEST_BUFFER_BASE, depth,
 *    LRZ and private-memory bases need a RESOURCE relocation with WRITE access; RB_COLOR_FLAG_BUFFER_ADDR and the
 *    2D source bases RESOURCE; vertex buffers and shader code RESOURCE or PACKAGE; SP_PS_SAMPLER_BASE,
 *    SP_PS_TEXMEMOBJ_BASE and indirect S#/T# loads PACKAGE (T# arrays in the data area, checked descriptor by
 *    descriptor); border colour tables ZERO or PACKAGE; bindless sets ZERO (empty). Minimum alignments: 6 for
 *    RT/2D/depth/LRZ/pvtmem/bindless/border/T#/UBO, 8 shader code, 4 S#, 2 vertex/LOAD_STATE6, 1/2 index 16/32.
 *    A relocation half inside the IB that no such field consumes is ADRENO_IB_E_RELOC; relocations in the data
 *    area are opaque (driver tables, uniforms) except inside validated T# arrays.
 *  - bounds: UBO SIZE * 16, NUM_UNIT * 16 (S#) or 64 (T#), MAX_INDICES * index size must fit the relocation.
 * Not enforced here (INFERRED to need register tracking, design S6): VFD_VERTEX_BUFFER_SIZE, SP_xS_INSTR_SIZE,
 * RB_MRT_PITCH * rows and T# extents against their relocation lengths; driver-table slots inside UBO data.
 * Shaders can still form arbitrary CB0 addresses (design 4.4/4.5): this is defence in depth, not isolation. */
#pragma once
#include <stdint.h>
#include "adreno-submit.h"
#include "adreno-resource-list.h"
#include "adreno-fill-command.h"

/* MTLResourceUsage bits exactly as the plug-in records them (AdrenoResourceUsage.m; 4 is legacy Sample, a read). */
#define ADRENO_USAGE_READ 1u
#define ADRENO_USAGE_WRITE 2u
#define ADRENO_USAGE_SAMPLE 4u

/* Arena layout (design 3.4): [0, ADRENO_IB_ZERO_BYTES) zero page, then the one package being submitted. */
#define ADRENO_IB_PACKAGE_AT ADRENO_IB_ZERO_BYTES
#define ADRENO_IB_TARGET_WORDS (ADRENO_IB_MAX_PACKAGE / 4u / 64u)   /* one bit per package dword */
#define ADRENO_IB_REG_LIMIT 0x10000u                                /* dword offsets the allowlist covers */
#define ADRENO_IB_ADDRESS_ROWS 32u

struct adreno_ib_tables {
    uint64_t allowed[ADRENO_IB_REG_LIMIT / 64];   /* KNOWN - PROTECTED */
    uint64_t address[ADRENO_IB_REG_LIMIT / 64];   /* either half of an address register */
    uint16_t address_row[ADRENO_IB_ADDRESS_ROWS]; /* indices into a8xx_ib_regs */
    uint32_t address_rows, allowed_offsets;
};

/* x0..x3 of an ADRENO_GUEST_IB reply (adreno-guest.h). */
struct adreno_ib_reply { int64_t status; uint64_t marker, ticks, wptr; };

#define ADRENO_IB_STATE_READY 1u
#define ADRENO_IB_STATE_DISABLED 2u   /* no IB ABI, probe refused, GPU_ERROR or STICKY: IB off, FENCE/FILL32 go on */
#define ADRENO_IB_STATE_UNCERTAIN 4u  /* a doorbell may be outstanding: the arena is never written or freed again */

struct adreno_ib_work {
    /* Caller storage, bound by adreno_ib_work_init. */
    uint8_t *arena;                   /* CPU view of the GPU-read-only arena */
    uint64_t arena_gpu, arena_bytes;
    struct adreno_ib_reloc *relocs;   /* private copies */
    uint16_t *order;                  /* relocation indices sorted by lo */
    uint8_t *used;                    /* bit 0/1: lo/hi consumed by a validated address field */
    uint32_t reloc_capacity, state;
    uint64_t *targets;                /* ADRENO_IB_TARGET_WORDS: the package dword is a relocation half */
    const struct adreno_ib_tables *tables;
    /* The staged package (after adreno_ib_stage). */
    struct adreno_ib_command command;
    uint8_t *package;
    uint64_t package_gpu, package_bytes, data_offset;
    /* Compute geometry observed in this IB only; reset on every validation. */
    uint32_t cs_ndrange[8], cs_groups[3], cs_seen;
    /* The last monitor reply, the last refusal and counters (logs, tests). */
    struct adreno_ib_reply reply;
    int last_error;
    uint32_t error_at;                /* package byte offset (packet/field) or relocation index of that refusal */
    uint64_t submitted, refused, gpu_errors, uncertain;
#if ADRENO_GPU_RECOVER
    uint64_t resets;                  /* agents/gpu-recovery: IBs the monitor reset (ADRENO_IB_E_RESET(_FAULT)) */
#endif
};

/* The IOGPU kernel-command callbacks (AdrenoCommandQueue): each returns 0, a pre-DMA error, ADRENO_SUBMIT_E_INACTIVE
 * (nothing reached the GPU), or ADRENO_SUBMIT_E_UNCERTAIN / ADRENO_LIST_E_VISIBILITY (retain the list). */
struct adreno_kernel_ops {
    void *context;
    int (*fence)(void *context);
    int (*fill)(void *context, const struct adreno_fill32_request *);
    int (*ib)(void *context, const void *command, uint64_t bytes);
};

#ifdef __cplusplus
extern "C" {
#endif
/* Build the register allowlist from AdrenoA8xxRegs.h and adreno-ib-tables.h. 0, or ADRENO_IB_E_FORMAT when the
 * two generated tables disagree (KNOWN size, a KNOWN offset past ADRENO_IB_REG_LIMIT). */
int adreno_ib_tables_init(struct adreno_ib_tables *);
/* Bind storage: arena of arena_bytes (>= ADRENO_IB_PACKAGE_AT + ADRENO_IB_MAX_PACKAGE, 64-byte aligned GPU VA in
 * the window), relocs/order/used of reloc_capacity entries (<= ADRENO_IB_MAX_RELOCS), targets of
 * ADRENO_IB_TARGET_WORDS. Zeroes the zero page; the caller cleans it to PoC before the first IB (design R1). */
int adreno_ib_work_init(struct adreno_ib_work *, const struct adreno_ib_tables *, uint8_t *arena, uint64_t arena_gpu,
                        uint64_t arena_bytes, struct adreno_ib_reloc *relocs, uint16_t *order, uint8_t *used,
                        uint32_t reloc_capacity, uint64_t *targets);
/* Copy one ADRENO_KCMD_IB command (volatile loads; the header is read once) into the arena's package area and the
 * private relocation array. `available` is IOGPU's extent for this command. */
int adreno_ib_stage(struct adreno_ib_work *, const void *command, uint64_t available);
/* Resolve and patch every relocation of the staged package. resolve maps a RESOURCE (id, access, offset, length)
 * to a window address after admitting it; PACKAGE and ZERO resolve inside the arena. */
int adreno_ib_relocate(struct adreno_ib_work *,
                       int (*resolve)(void *, uint32_t id, unsigned access, uint64_t offset, uint64_t length,
                                      uint64_t *address), void *context);
/* Allowlist validation of the relocated copy (policy above). Compute adds direct CP_EXEC_CS, exact CS
 * UBO/S#/T#/UAV loads, consistent local/global/group geometry, and resource-WRITE linear 2D RGBA32Float
 * storage descriptors with a checked row extent. See docs/ADRENO-COMPUTE-PACKETS-20261019.md. */
int adreno_ib_validate(struct adreno_ib_work *);
#if ADRENO_IB_CS_SAMPLERS
/* The S# units one CS sampler load (CP_LOAD_STATE6_FRAG, SB6_CS_TEX, ST6_SHADER) may carry in the IBs validated after
 * the call: 1 (the fixed limit without ADRENO_IB_CS_SAMPLERS, and the default) up to ADRENO_IB_CS_SAMPLER_UNITS_MAX;
 * any other value sets 1. CoreImage's multi-input kernels sample T#1..N with samplers 0..N-1. An S# holds no address,
 * and the load stays bounded by its package relocation (NUM_UNIT * 16 bytes), as an FS sampler load is. Process-wide;
 * the kext sets it once, before it publishes ADRENO_IB_REGISTRY_PROPERTY, so no validation runs concurrently. */
#define ADRENO_IB_CS_SAMPLER_UNITS_MAX 8u
void adreno_ib_set_cs_sampler_units(uint32_t units);
#endif
/* The RESOURCE relocation range rule (design 3.2; AdrenoMemoryMap::resolveRange calls it under the map lock):
 * a reserved, pinned, fully mapped window resource and [offset, offset + bytes) inside its logical length, with
 * no FILL32-style size or dword limits. 0 and *address = resource VA + offset, or ADRENO_RESOURCE_E_*. */
int adreno_ib_resource_range(const struct adreno_resource *, uint64_t offset, uint64_t bytes, uint64_t *address);
/* Map a monitor reply: 0 (retired), ADRENO_SUBMIT_E_INACTIVE (documented refusal before any ring write),
 * ADRENO_IB_E_GPU_ERROR (retired and idle, error bits set), ADRENO_SUBMIT_E_UNCERTAIN (everything else, including
 * inconsistent replies: a refusal with a marker, success without one, a WPTR outside the ring). With
 * ADRENO_GPU_RECOVER also ADRENO_IB_E_RESET / ADRENO_IB_E_RESET_FAULT (the monitor reset the GPU under this IB:
 * nothing it referenced is accessed any more; its list completes with FROM_DEVICE, unfrozen, and IB stays ready;
 * agents/gpu-recovery R14). */
int adreno_ib_classify(const struct adreno_ib_reply *);
/* The whole submission (design 3.5), caller-serialized: refuses without touching the arena while the work is
 * DISABLED or UNCERTAIN; stages, relocates against the list's prepared entries (resolve: the kext's map range
 * check), validates, then runs adreno_resource_list_submit (TO_DEVICE on every entry, the ring callback, then
 * FROM_DEVICE on WRITE entries only). Returns 0, a kext refusal (ADRENO_IB_E_*, ADRENO_LIST_E_*), the monitor's
 * refusal status (nothing latched; STICKY also disables IB), ADRENO_IB_E_GPU_ERROR (IB disabled, list not frozen),
 * or ADRENO_SUBMIT_E_UNCERTAIN / ADRENO_LIST_E_VISIBILITY (list frozen, work UNCERTAIN: arena retained). */
int adreno_ib_submit(struct adreno_ib_work *, struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                     const void *command, uint64_t available,
                     int (*resolve)(void *, void *resource, void *preparation, uint64_t offset, uint64_t length,
                                    uint64_t *address),
                     int (*ring)(void *, uint64_t package_gpu, uint64_t ib_dwords, uint64_t package_bytes,
                                 struct adreno_ib_reply *),
                     void *context);
#if ADRENO_PIPELINE
/* --pipeline (agents/gpu-pipeline FAILURE-MODES.md Q, R1, C4): adreno_ib_submit split at the doorbell, so an IB can
 * stay on the GPU after its submission returns. begin: every check, stage, relocation and validation of
 * adreno_ib_submit, then the list's TO_DEVICE (adreno_resource_list_begin); nothing is rung. ring: the ring callback
 * once; a reply of ADRENO_IB_PENDING with a usable marker (IB_START: the IB is in flight) returns ADRENO_IB_IN_FLIGHT
 * and leaves `pending` armed with the marker; any other reply is final and goes through finish at once. finish: the
 * final reply mapped exactly as adreno_ib_submit maps it (FROM_DEVICE through adreno_resource_list_end, the work's
 * state and counters), returning what adreno_ib_submit would have. adreno_ib_submit is begin, ring, and (for a ring
 * callback that is always final) nothing more. */
#define ADRENO_IB_IN_FLIGHT 1
struct adreno_ib_pending {
    struct adreno_list_pending list;
    uint64_t marker;                  /* IB_START's marker while in flight */
    uint32_t armed, reserved;
};
int adreno_ib_submit_begin(struct adreno_ib_work *, struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                           const void *command, uint64_t available,
                           int (*resolve)(void *, void *resource, void *preparation, uint64_t offset, uint64_t length,
                                          uint64_t *address),
                           void *context, struct adreno_ib_pending *);
int adreno_ib_submit_ring(struct adreno_ib_work *, struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                          struct adreno_ib_pending *,
                          int (*ring)(void *, uint64_t package_gpu, uint64_t ib_dwords, uint64_t package_bytes,
                                      struct adreno_ib_reply *),
                          void *context);
int adreno_ib_submit_finish(struct adreno_ib_work *, struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                            struct adreno_ib_pending *, const struct adreno_ib_reply *final, int transport_error);
#endif
/* The start-time probe package (design 3.6): one CP_NOP, validated like any IB. Outputs the HVC arguments. */
int adreno_ib_probe(struct adreno_ib_work *, uint64_t *package_gpu, uint64_t *ib_dwords, uint64_t *package_bytes);
/* Fence reply (ADRENO_GUEST_FENCE; ring-wrap aware: the reply WPTR is never compared, it may move backwards):
 * 0 only for status 0 with reply == observed == value; ADRENO_SUBMIT_E_INACTIVE for PARAMS/TARGET/CX/GX/SQE with
 * reply 0 and the slot still ~value (refused before any ring write); otherwise ADRENO_SUBMIT_E_UNCERTAIN
 * (ADRENO_E_RING included: today's fence_at also reports a twice-dropped doorbell as RING after writing the ring). */
int adreno_fence_classify(int64_t status, uint64_t reply, uint32_t value, uint32_t observed);
/* Fail-fast gate (plan M7): while *latch is set, work is never called (no HVC, no cache maintenance) and the
 * result is ADRENO_SUBMIT_E_INACTIVE; an UNCERTAIN or VISIBILITY result sets it until reset. */
int adreno_submit_gated(uint8_t *latch, int (*work)(void *), void *context);
/* One IOGPU kernel command (processSegmentKernelCommand's extent): ADRENO_SUBMIT_GENERIC for IOGPU's own types,
 * FENCE through adreno_submit_command, FILL32 through adreno_fill32_decode, ADRENO_KCMD_IB to ops->ib, anything
 * else ADRENO_SUBMIT_E_COMMAND. Nonzero other than GENERIC means IOGPU submission error 0xa for the caller. */
int adreno_kernel_command(const void *command, uint64_t available, const struct adreno_kernel_ops *);
#ifdef __cplusplus
}
#endif
