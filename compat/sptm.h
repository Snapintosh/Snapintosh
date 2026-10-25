/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* The measured sptm-mac-v1 ABI, independent of the host CPU and transport.
 * Other monitor ABIs must have their own adapter; these are not Arm enums. */
#define SPTM_MAC_FRAME_SIZE 0x4000UL
#define SPTM_MAC_ENTRY_SIZE 16UL
#define SPTM_MAC_DEFAULT 11u
#define SPTM_MAC_USER_EXEC 14u
#define SPTM_MAC_USER_TPRO 17u
#define SPTM_MAC_USER_ROOT_TABLE 18u
#define SPTM_MAC_SHARED_ROOT_TABLE 19u
#define SPTM_MAC_SHARED_ROOT_LIMIT 255u
#define SPTM_MAC_PAGE_TABLE 20u
#define SPTM_MAC_PAGE_TABLE_SHARED 21u
#define SPTM_MAC_PAGE_TABLE_ROZONE 22u
#define SPTM_MAC_PAGE_TABLE_COMMPAGE 23u
#define SPTM_MAC_IOMMU 24u
#define SPTM_MAC_ROZONE 25u
#define SPTM_MAC_COMMPAGE_RW 29u
#define SPTM_MAC_COMMPAGE_RO 30u
#define SPTM_MAC_COMMPAGE_RX 31u
#define SPTM_MAC_KERNEL_RESTRICTED 35u
#define SPTM_MAC_TXM_DEFAULT 42u
#define SPTM_MAC_TXM_OWNED 60u /* Internal TXM load input; privileged RO aperture. */
/* Apple XNU_IO: out-of-DRAM data without frame-table state. Here only the
 * loader-declared user_io window (the panel) may carry this type. */
#define SPTM_MAC_IO 26u
/* Each frame type's descriptor +4 mapping policy (4-bit permission classes)
 * in the pinned image (table ...2709e230, stride 144; pinned by
 * tools/replay-sptm-matrix.py). Types absent here have no mapping policy. */
static inline unsigned sptm_mac_type_policy(unsigned type)
{
    switch(type) {
    case 0: case SPTM_MAC_DEFAULT: case SPTM_MAC_IO: case 40: return 0x8888u;
    case 7: case 13: return 0x0008u;
    case SPTM_MAC_USER_EXEC: return 0xa800u;
    case 15: return 0xa888u;
    case 16: return 0x8828u;
    case SPTM_MAC_USER_TPRO: return 0x8a88u;
    case SPTM_MAC_ROZONE: case 27: return 0x0800u;
    case 28: case 39: return 0x8800u;
    case SPTM_MAC_COMMPAGE_RW: case SPTM_MAC_COMMPAGE_RO: return 0x8000u;
    case SPTM_MAC_COMMPAGE_RX: return 0xa000u;
    case SPTM_MAC_KERNEL_RESTRICTED: return 0x0808u;
    case 36: return 0x8008u;
    case 37: return 0x8808u;
    default: return 0;
    }
}
#define SPTM_MAC_ROOT_FLAGS_USER 0x2u
/* May be clear at construction or changed with CONFIGURE_ROOT.
 * SWITCH_ROOT uses bit1 to select the address-authentication SCTLR enables. */
#define SPTM_MAC_ROOT_FLAG_ADDRESS_PAUTH 0x2u
/* SWITCH_ROOT maps bit0 to UMPRR bit11 (selector5's control field).
 * Current shadows reject selector5 and UPERM writes affecting it. Retaining
 * this control does not authorize JIT mappings or guess their permissions. */
#define SPTM_MAC_ROOT_FLAG_UMPRR11 0x1u
#define SPTM_MAC_ROOT_FLAG_X86_COMMPAGE 0x4u
#define SPTM_MAC_ROOT_FLAG_ARM64_32 0x20u
/* CONFIGURE_ROOT's reached flag. SWITCH_ROOT maps this bit to bit18 of
 * Apple S3_6_C15_C3_0. Activation retains it and enables the measured TPRO
 * private-view contract. Unreached JIT permission modes remain unsupported. */
#define SPTM_MAC_ROOT_FLAG_UMPRR18 0x8u
/* MAP_PAGE's guest status once the leaf has been accepted (not CONFLICT 6 or
 * TABLE_NOT_PRESENT 7). Shipped 26A428 handler, common to kernel, user and
 * shared roots: an identical request returns 1 at ...f9378 without a store;
 * otherwise, after the CAS at ...f92b4 succeeds, ...f9490 tests the old
 * descriptor (x16 = old&3): a valid page descriptor is invalidated and
 * returns 1 at ...f95d4, and only an empty slot returns 0 at ...f9574.
 * XNU's pmap_enter (0xfffffe000ba61544) enters a new PV entry and counts a
 * new mapping for 0 and treats 1 as "mapping already present", so a
 * same-PA permission change that reports 0 duplicates the PV entry.
 * Confirmed by a qemu-sptm run of the real SPTM with this kernelcache:
 * 251 kernel and 3 user same-PA replacements, all returned 1. */
static inline uint64_t sptm_mac_map_page_status(uint64_t old,uint64_t requested)
{return (old&3)==3 || (old && old==requested) ? 1 : 0;}
static inline int sptm_mac_user_base_flags_valid(uint64_t flags)
{
    return flags==SPTM_MAC_ROOT_FLAGS_USER ||
           flags==(SPTM_MAC_ROOT_FLAGS_USER|SPTM_MAC_ROOT_FLAG_X86_COMMPAGE) ||
           flags==(SPTM_MAC_ROOT_FLAGS_USER|SPTM_MAC_ROOT_FLAG_ARM64_32);
}
static inline uint64_t sptm_mac_user_va_limit(unsigned flags)
{ return 1UL<<((flags&SPTM_MAC_ROOT_FLAG_ARM64_32) ? 32 : 47); }
static inline int sptm_mac_user_runtime_flags_valid(uint64_t flags)
{return sptm_mac_user_base_flags_valid((flags|SPTM_MAC_ROOT_FLAG_ADDRESS_PAUTH)&
        ~(uint64_t)(SPTM_MAC_ROOT_FLAG_UMPRR18|SPTM_MAC_ROOT_FLAG_UMPRR11));}
/* mac-v1 MAP_TABLE ...facfc: the commpage table must fall wholly within
 * the top 32 MiB of 32-bit VA or the last 1 GiB below 64 GiB for arm64. */
static inline int sptm_mac_commpage_va(unsigned flags,uint64_t va)
{
    if(flags&SPTM_MAC_ROOT_FLAG_X86_COMMPAGE)
        return va>=0x7fffffe00000UL && va<0x800000000000UL;
    uint64_t end=1UL<<((flags&SPTM_MAC_ROOT_FLAG_ARM64_32) ? 32 : 36);
    uint64_t span=(flags&SPTM_MAC_ROOT_FLAG_ARM64_32) ? 0x2000000UL : 0x40000000UL;
    return va>=end-span && va<end;
}
struct sptm_user_geometry {
    unsigned shift, start, group, root_groups;
    uint64_t page_size, pa_mask, va_limit;
};
/* Audited format selectors in mac-v1, not host CPU page-size choices. */
static inline int sptm_mac_user_geometry(unsigned format,unsigned flags,
                                        struct sptm_user_geometry *g)
{
    if(format>1 || !sptm_mac_user_runtime_flags_valid(flags) ||
       ((flags&SPTM_MAC_ROOT_FLAG_X86_COMMPAGE) && format!=1)) return 0;
    g->shift=format ? 12 : 14;g->start=format ? 0 : 1;g->group=format ? 4 : 1;
    g->page_size=1UL<<g->shift;
    g->pa_mask=0x0000ffffffffffffUL&~(g->page_size-1);
    g->va_limit=sptm_mac_user_va_limit(flags);
    g->root_groups=(unsigned)(((g->va_limit-1)>>(g->shift+(3-g->start)*(g->shift-3)))/g->group+1);
    return 1;
}
/* MAP_TABLE ...fad20..5c aligns the x86 commpage window to the containing
 * four-subtable group. Its leaves remain confined to the last 2 MiB below
 * 2^47; the other three 4K subtables must not admit commpage leaves. */
static inline int sptm_mac_commpage_table_va(unsigned flags,uint64_t va)
{
    if(flags&SPTM_MAC_ROOT_FLAG_X86_COMMPAGE)
        return va>=0x7fffff800000UL && va<0x800000000000UL;
    return sptm_mac_commpage_va(flags,va);
}
static inline unsigned sptm_mac_user_index(const struct sptm_user_geometry *g,
                                          unsigned level,uint64_t va)
{ return (unsigned)((va>>(g->shift+(3-level)*(g->shift-3)))&(g->page_size/8-1)); }

struct sptm_ref_batch;
struct sptm_root_memo;
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
struct sptm_nest_fast_stats;
#endif
#if SNAP_ROOT_INDEX
struct sptm_root_index;
#endif
/* Disposable image storage and its privileged bootstrap aliases. The same
 * geometry is used by SLIDE_REGION; relocation changes VA, not ownership. */
struct sptm_slide_region { uint64_t va, pa, pages; };
/* Private counterpart of mac-v1 shared slots. State0 is free, state1 is
 * allocated, state3 is configured. State2 is a native lock transition;
 * our global service token excludes concurrent observers during commit. */
struct sptm_shared_slot { uint64_t state,start,size,root; };
int sptm_mac_shared_slot_valid(const struct sptm_shared_slot *,unsigned format);
struct sptm_shared_registry {
    struct sptm_shared_slot slots[SPTM_MAC_SHARED_ROOT_LIMIT];
    uint64_t configurations;
};
struct sptm_root_configuration {
    uint64_t calls,changes,root,value,mask,before,after,reserved;
};
/* Self-checks on the answers XNU's PV bookkeeping is built from. Counting
 * only: nothing here changes a result, and a NULL audit counts nothing.
 * moved_pointers: PTE pointers MAP_PAGE handed back through a SLIDE_REGION
 *   alias instead of the linear aperture (see sptm_published_pointer).
 * remaps: committed leaf changes valid -> valid with a different output PA.
 *   Apple's MAP_PAGE refuses these with CONFLICT 6 (...f92e8/...f95dc) and
 *   XNU then removes the old mapping (pmap_enter ...ba61ad0 -> ...ba62ff8);
 *   an accepted one leaves the old frame's PV entry naming this PTE.
 * duplicate_records: UPDATE/UNMAP_DISJOINT records naming an earlier record's
 *   (root, VA) in the same engine call, counted where detected (including
 *   ones the monitor then refuses). Apple's engine (...270fdc44) accepts them
 *   and applies them in order (tools/replay-disjoint-duplicates.py).
 * The last remap and duplicate are kept as witnesses. pending_* is the
 * current reference batch's share, published by sptm_refs_commit; the
 * dispatcher clears it at each call so an abandoned batch is never counted. */
struct sptm_pv_audit {
    uint64_t moved_pointers, remaps, duplicate_records;
    uint64_t remap_va, remap_old, remap_next, duplicate_root, duplicate_va;
    uint64_t pending, pending_va, pending_old, pending_next;
};
_Static_assert(sizeof(struct sptm_pv_audit)==96,"pv audit stride");
static inline void sptm_audit_duplicate(struct sptm_pv_audit *a,uint64_t root,uint64_t va)
{
    if(a) {a->duplicate_records++;a->duplicate_root=root;a->duplicate_va=va;}
}
_Static_assert(sizeof(struct sptm_root_configuration)==64,"root configuration audit stride");
_Static_assert(sizeof(struct sptm_shared_slot)==32,"shared slot audit stride");
struct sptm_memory {
    uint64_t frame_map_pa, frame_low, frame_high;
    /* Original contiguous allocator arena. Reservations below it remain
     * excluded except for the explicitly declared disposable boot ranges. */
    uint64_t alloc_low, alloc_high;
    /* Map a complete physical range or return NULL without side effects.
     * Keep it valid until the operation returns. publish makes stores visible
     * to the guest and its translation observers before publishing the type. */
    volatile uint8_t *(*map)(void *ctx, uint64_t pa, uint64_t size);
    void (*publish)(void *ctx, uint64_t pa, uint64_t size);
    void *ctx;
    /* Required only for USER_ROOT -> DEFAULT. Confirm no CPU/TXM user and
     * retire stale translations before reuse. Called after all other checks;
     * return nonzero only when retirement is complete. */
    int (*retire_user_root)(void *ctx, uint64_t pa, uint16_t asid);
    /* Serialized USER_ROOT -> SHARED_ROOT transaction: validate and rekey
     * the existing TXM object, retire private shadows, and flush every VMID.
     * Failure must leave TXM identity unchanged. Shared teardown requires
     * the TXM object to have been unregistered before releasing its slot. */
    int (*share_user_root)(void *ctx,uint64_t pa,uint16_t asid,uint8_t slot);
    int (*retire_shared_root)(void *ctx,uint64_t pa,uint8_t slot);
    /* SET_SHARED_REGION internal TXM transaction, after all metadata checks.
     * Failure is read-only; success leaves no fallible work before commit. */
    int (*bind_shared_root)(void *ctx,uint64_t user,uint16_t asid,
                           uint64_t shared,uint8_t slot,uint64_t start,uint64_t size);
    /* Preflight/retire an inactive root's cached permission regime. No
     * failure may change metadata or cache state. Active changes are not
     * admitted until the Apple permission modifier is modeled in hardware. */
    int (*configure_user_root)(void *ctx,uint64_t root,uint16_t before,uint16_t after);
    struct sptm_root_configuration *root_configuration;
    struct sptm_shared_registry *shared_regions;
    /* The monitor's physical aperture is an uncounted privileged alias.
     * Ordinary mappings of allocator and disposable image frames are counted. */
    uint64_t aperture_va, aperture_size;
    struct sptm_ref_batch *refs;
    /* Read-only admission for class-specific IOMMU ownership. Return nonzero
     * only for an initialized device, declared stream and supported level.
     * Allocation does not install a descriptor or authorize DMA. */
    int (*admit_iommu)(void *ctx, unsigned iommu_class, unsigned device_id,
                       unsigned sid, unsigned level);
    const struct sptm_slide_region *boot_ranges, *boot_aliases;
    uint64_t boot_count, boot_alias_count;
    /* Required for DEFAULT <-> ROZONE. After metadata preflight, change the
     * privileged aperture and complete private-view publication/TLBI before
     * the new type is visible. A backend failure must stop guest execution. */
    int (*retype_rozone)(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type);
    /* USER_EXEC seals the privileged aperture and synchronizes instructions
     * before publishing the type. Release restores ordinary aperture rights. */
    int (*retype_user_exec)(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type);
    /* Type17 requires the host's aperture/permission contract. The callback
     * must complete before publishing the type; absence keeps it unsupported.
     * Supplying it also promises that raw canonical selector9 user leaves
     * will be translated into private CPU views at every privilege boundary. */
    int (*retype_user_tpro)(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type);
    /* DEFAULT -> TXM_DEFAULT retains existing privileged RO references.
     * Prepare selector4's private RO/NX aperture before publishing ownership. */
    int (*retype_txm_default)(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type);
    /* Optional, after a USER_ROOT constructor published the new (empty) root:
     * the host may begin mirroring it at once. It never fails the call. */
    void (*created_user_root)(void *ctx,uint64_t pa,uint16_t asid,unsigned format,unsigned flags);
    /* Internal domain2 import42->60 / release60->11 only. Complete aperture
     * publication and all-CPU invalidation before publishing the new type. */
    int (*retype_txm_owned)(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type);
    /* Loader-reserved payload, owned only as data by normal SEP firmware DMA.
     * Never include this in bootstrap aliases, nor in managed frames until
     * released: after the SEP boots, AppleSEPFirmware::releaseFirmware hands
     * the SEPFW extent to ml_static_mfree, which retypes only frames that are
     * not XNU_DEFAULT and then gives every frame to the VM. Nonzero released
     * admits the whole extent as ordinary allocator memory from then on. */
    uint64_t sep_firmware_pa, sep_firmware_size, sep_firmware_released;
    /* Optional loader-declared device window user roots may map, as Apple's
     * MAP_PAGE admits XNU_IO (26) leaves in ordinary user tables. It must be
     * plain memory behind stage 2 (the panel), never an emulated MMIO range,
     * and lie wholly outside frame metadata: it is never typed or counted. */
    uint64_t user_io_pa, user_io_size;
    /* Optional self-check counters; see struct sptm_pv_audit. */
    struct sptm_pv_audit *audit;
    /* Optional SWITCH_ROOT level-3 memo (sptm-root-memo.h). Every frame-type
     * store reports the record it replaces, so a mapped frame's retype
     * retires all retained verdicts. */
    struct sptm_root_memo *root_memo;
    /* Data-cache maintenance for a memory-attribute change (UPDATE options
     * 0x10/0x20, MULTIPAGE aperture AttrIndx): clean and invalidate the whole
     * physical range to PoC and complete it; zero if it cannot. Called once
     * per changed frame after preflight and before the first descriptor
     * store, so no line cached under the old attributes survives into the
     * new ones. The host repeats it once its TLBI has retired the old
     * translations. Absent, SH/AttrIndx changes are refused. Apple's own
     * multipage path never passes its cache flag (...dfb1c flag 0x40);
     * XNU cleans after the call, which this does not rely on. */
    int (*clean_frame)(void *ctx,uint64_t pa,uint64_t size);
#if SNAP_FINE_LOCKS
    /* Non-NULL only inside a converted call (compat/fine-lock.h): this CPU's
     * reference snapshots (compat/sptm-refs.h struct sptm_ref_fine). Counts
     * then load atomically and commit as atomic deltas; NULL on the token
     * path keeps the absolute stores. */
    struct sptm_ref_fine *fine;
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
    /* Optional counters of compat/nest-fast.h; NULL counts nothing. */
    struct sptm_nest_fast_stats *nest_fast;
#endif
#if SNAP_ROOT_INDEX
    /* Optional index of root records (compat/root-index.h); NULL scans. */
    struct sptm_root_index *root_index;
#endif
#if SNAP_DART_MEMO
    /* Optional DART table verdicts (compat/sptm-dart-memo.h), only on the
     * service-token path; NULL scans every table. */
    struct sptm_dart_memo *dart_memo;
#endif
};

/* A complete user leaf page inside the declared device window. */
static inline int sptm_user_io_frame(const struct sptm_memory *m,uint64_t pa,uint64_t size)
{
    if(!m || !m->user_io_size || !size || ((m->user_io_pa|m->user_io_size)&0x3fff) ||
       m->user_io_size>UINT64_MAX-m->user_io_pa || m->user_io_pa+m->user_io_size>(1UL<<48) ||
       (m->user_io_pa<m->frame_high && m->frame_low<m->user_io_pa+m->user_io_size) ||
       (pa&(size-1)) || pa<m->user_io_pa || pa-m->user_io_pa>=m->user_io_size ||
       size>m->user_io_size-(pa-m->user_io_pa))return 0;
    return 1;
}

/* A complete 16K frame, never a broad lower bound encompassing reservations. */
static inline int sptm_managed_frame(const struct sptm_memory *m,uint64_t pa)
{
    if (!m || (pa&0x3fff) || pa<m->frame_low || pa>=m->frame_high) return 0;
    if (pa>=m->alloc_low && pa<m->alloc_high) return 1;
    if (m->sep_firmware_released && m->sep_firmware_size &&
        pa>=m->sep_firmware_pa && pa-m->sep_firmware_pa<m->sep_firmware_size) return 1;
    if (m->boot_count>8 || (m->boot_count && !m->boot_ranges)) return 0;
    for (unsigned i=0;i<m->boot_count;i++) {
        const struct sptm_slide_region *r=&m->boot_ranges[i];
        if (pa>=r->pa && (pa-r->pa)/0x4000<r->pages) return 1;
    }
    return 0;
}
static inline int sptm_boot_alias(const struct sptm_memory *m,uint64_t va,uint64_t pa)
{
    for (unsigned i=0;i<m->boot_alias_count;i++) {
        const struct sptm_slide_region *r=&m->boot_aliases[i];
        if (va>=r->va && va-r->va<r->pages*0x4000 &&
            pa>=r->pa && va-r->va==pa-r->pa) return 1;
    }
    return 0;
}
/* Call before admitting extra ownership or dereferencing aliases. No metadata
 * or allocator overlap; alias coverage must partition exactly those frames. */
static inline int sptm_boot_memory_valid(const struct sptm_memory *m)
{
    if (!m || m->boot_count>8 || m->boot_alias_count>50 ||
        (m->boot_count && (!m->boot_ranges || !m->boot_aliases)) ||
        (!!m->boot_count!=!!m->boot_alias_count)) return 0;
    uint64_t total=0,aliased=0;
    if (m->frame_high<m->frame_low || m->frame_high>(1ULL<<48) || (m->frame_high-m->frame_low)>(1ULL<<48)) return 0;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if (map_size>UINT64_MAX-m->frame_map_pa) return 0;
    for (unsigned pass=0;pass<2;pass++) {
        unsigned count=pass ? m->boot_alias_count : m->boot_count;
        const struct sptm_slide_region *ranges=pass ? m->boot_aliases : m->boot_ranges;
        for (unsigned i=0;i<count;i++) {
            const struct sptm_slide_region *r=&ranges[i];
            if (!r->pages || r->pages>0x1000 || ((r->pa|r->va)&0x3fff) ||
                r->va<0xffff800000000000UL || r->va>UINT64_MAX-r->pages*0x4000 ||
                r->pa<m->frame_low || r->pa>=m->alloc_low ||
                r->pages*0x4000>m->alloc_low-r->pa ||
                (r->pa<m->frame_map_pa+map_size &&
                 r->pa+r->pages*0x4000>m->frame_map_pa)) return 0;
            for (unsigned j=0;j<i;j++) {
                const struct sptm_slide_region *q=&ranges[j];
                if ((r->pa<q->pa+q->pages*0x4000 && q->pa<r->pa+r->pages*0x4000) ||
                    (r->va<q->va+q->pages*0x4000 && q->va<r->va+r->pages*0x4000)) return 0;
            }
            if (pass) {
                unsigned found=0;
                for (unsigned j=0;j<m->boot_count;j++) {
                    const struct sptm_slide_region *q=&m->boot_ranges[j];
                    if (r->pa>=q->pa && r->pa-q->pa<q->pages*0x4000 &&
                        r->pages*0x4000<=q->pages*0x4000-(r->pa-q->pa)) found++;
                }
                if (found!=1) return 0;
                aliased+=r->pages;
            } else total+=r->pages;
        }
    }
    return total==aliased;
}
/* Enumerate disjoint managed ranges without scanning physical holes. */
static inline uint64_t sptm_next_frame(const struct sptm_memory *m,uint64_t from)
{
    uint64_t next=from<m->alloc_low ? m->alloc_low : from;
    if (next>m->alloc_high) next=m->alloc_high;
    for (unsigned i=0;i<m->boot_count;i++) {
        const struct sptm_slide_region *r=&m->boot_ranges[i];
        uint64_t candidate=from<r->pa ? r->pa : from;
        if (candidate<r->pa+r->pages*0x4000 && candidate<next) next=candidate;
    }
    if (m->sep_firmware_released && m->sep_firmware_size) {
        uint64_t candidate=from<m->sep_firmware_pa ? m->sep_firmware_pa : from;
        if (candidate<m->sep_firmware_pa+m->sep_firmware_size && candidate<next) next=candidate;
    }
    return next;
}

static inline int sptm_sep_firmware_valid(const struct sptm_memory *m)
{
    if (!m || !sptm_boot_memory_valid(m)) return 0;
    uint64_t pa=m->sep_firmware_pa,size=m->sep_firmware_size;
    if (!pa && !size) return 1;
    if (!pa || !size || size>0x1000000 || ((pa|size)&0x3fff) ||
        pa<m->frame_low || pa>=m->alloc_low || size>m->alloc_low-pa ||
        m->alloc_low>m->frame_high || m->frame_high>(1UL<<36)) return 0;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if (pa<m->frame_map_pa+map_size && m->frame_map_pa<pa+size) return 0;
    for (unsigned i=0;i<m->boot_count;i++) {
        const struct sptm_slide_region *r=&m->boot_ranges[i];
        if (pa<r->pa+r->pages*0x4000 && r->pa<pa+size) return 0;
    }
    return 1;
}
static inline int sptm_sep_firmware_frame(const struct sptm_memory *m,uint64_t pa)
{
    return m && !(pa&0x3fff) && m->sep_firmware_size &&
        pa>=m->sep_firmware_pa && pa-m->sep_firmware_pa<m->sep_firmware_size;
}
static inline int sptm_dart_data_frame(const struct sptm_memory *m,
    uint64_t id,uint64_t sid,uint64_t pa)
{
    return sptm_managed_frame(m,pa) ||
        (id==20 && sid==0 && sptm_sep_firmware_frame(m,pa));
}

/* A guest-visible linear mapping, independent of EL2's physical access.
 * MAP_PAGE returns a dereferenceable PTE pointer through this aperture. */
struct sptm_aperture { uint64_t pa, va, size; };
/* SLIDE_REGION moves bootstrap frames to a new alias and republishes the
 * physical-to-virtual table XNU's phystokv reads (0xfffffe000c22aa40); the
 * linear alias stays mapped. A PTE pointer handed to XNU must be the one its
 * phystokv would compute, because pmap_remove_pv finds the PV entry to drop by
 * comparing pointers: a linear pointer for a table on a moved frame is never
 * matched and outlives the mapping (the madvise PV-walk panic). regions is the
 * monitor's slide state; entries whose va lies in [low, high) are moved. */
struct sptm_moved {
    const struct sptm_slide_region *regions;
    uint64_t count, low, high;
};
/* The moved alias when pa lies in a moved range, else the linear aperture. */
uint64_t sptm_published_pointer(const struct sptm_aperture *a,
                                const struct sptm_moved *moved, uint64_t pa,
                                uint64_t size);
uint64_t sptm_aperture_pointer(const struct sptm_aperture *a, uint64_t pa,
                               uint64_t size);

/* Kernel-root MAP_PAGE once the level-3 slot has been found and the request
 * is a valid leaf (probes/xnuboot.c). The shipped handler treats the kernel
 * root (SPTM_KERNEL_ROOT_TABLE, type 8) like a user root at the old leaf:
 * ...f92e8/92ec compare the old and new PA and ...f92f0 returns CONFLICT(6)
 * at ...f95dc with no CAS, TLBI or reference move; ...f9530 still reports the
 * old PTE and the slot pointer (tools/replay-kernel-map-conflict.py). XNU's
 * pmap_enter (ba615e4) answers 6 by removing [VA,VA+16K) and retrying, which
 * drops the old page's PV entry. Replacing the leaf and returning 0 instead
 * makes it add a PV entry for the new page and keep the old one, which then
 * names a slot mapping another page.
 * install is 0 for a conflict. Otherwise status is what the accepted leaf
 * returns: sptm_mac_map_page_status for a valid same-PA leaf, else 0.
 * pointer is XNU's phystokv of the slot (SLIDE_REGION alias when moved). */
#define SPTM_MAC_MAP_CONFLICT 6u
struct sptm_kernel_leaf { uint64_t status, old, pointer; int install; };
enum sptm_result sptm_mac_kernel_map_leaf(const struct sptm_aperture *a,
    const struct sptm_moved *moved, uint64_t slot_pa, uint64_t old,
    uint64_t requested, struct sptm_kernel_leaf *out);

/* Internal diagnostic results, never invented SPTM guest return values.
 * On failure the dispatcher stops without acknowledging the call. */
enum sptm_result {
    SPTM_OK = 0,
    SPTM_BAD_CONFIG,
    SPTM_BAD_ADDRESS,
    SPTM_UNSUPPORTED_RETYPE,
    SPTM_UNSUPPORTED_OPTIONS,
    SPTM_MEMORY_UNAVAILABLE,
    SPTM_TYPE_MISMATCH,
    SPTM_FRAME_BUSY,
    SPTM_BAD_TABLE,
    SPTM_TABLE_MISSING,
    SPTM_TABLE_EXISTS,
    SPTM_SHADOW_FAILED,
    SPTM_BAD_REFERENCE,
};

/* Implements DEFAULT -> PAGE_TABLE (level 0..3) / data types 25,29..31,35
 * (options 0). Commpage allocation preserves the already initialized payload;
 * COMMPAGE tables support the reached leaf level 3. Recycling commpage frames
 * or tables requires their separate shared-mapping lifecycle
 * and is not covered by the ordinary data release below.
 * An unreferenced supported data frame may return to DEFAULT without clearing.
 * An empty, unreferenced PAGE_TABLE may also return to DEFAULT.
 * USER_ROOT allocation supports formats 0/1, the modeled PA/UMPRR controls,
 * arm64/arm64_32 (also x86 commpage geometry for format1) and a unique nonzero ASID;
 * recycling additionally requires an empty root and host retirement callback.
 * Commpage/general user mappings are in sptm-user.h; activation is in sptm-root.h.
 * DEFAULT -> IOMMU supports class 5 with validated device/SID/level ownership
 * and preserves the payload. Its release and ordinary CPU mappings remain
 * unsupported until their separate lifecycle is implemented.
 * Alternate types and attached-table recycling need contracts (geometry,
 * cache attributes, mapping counts/invalidation); fail explicitly until then.
 * Only quiescent, unreferenced default frames are accepted. All validation
 * and mapping completes before the first memory write. */
enum sptm_result sptm_mac_retype(const struct sptm_memory *m, uint64_t pa,
                               uint64_t old_type, uint64_t new_type,
                               uint64_t options);
/* Called only by the monitor's TXM implementation under the service lock.
 * This is deliberately separate from XNU's public RETYPE dispatch. */
enum sptm_result sptm_txm_retype(const struct sptm_memory *m,uint64_t pa,
                               uint64_t old_type,uint64_t new_type);
enum sptm_result sptm_txm_retype_check(const struct sptm_memory *m,uint64_t pa,
                                     uint64_t old_type,uint64_t new_type);
/* Apple's post-lockdown transition matrix (old descriptor +0x40 bitmap).
 * The monitor's supported transitions are always a subset of it. */
int sptm_mac_apple_retype(uint64_t old_type,uint64_t new_type);
/* The transitions sptm_mac_retype can admit (before its per-type checks). */
int sptm_mac_retype_supported(uint64_t old_type,uint64_t new_type);
/* CONFIGURE_SHAREDREGION endpoint9. Count is normalized to uint32 by the
 * shipped handler; ranges are virtual. Does not insert PTEs or grant trust. */
enum sptm_result sptm_mac_configure_sharedregion(const struct sptm_memory *,
    uint64_t root,uint64_t start,uint64_t page_count);
/* SET_SHARED_REGION endpoint39 establishes identity only. NEST performs the
 * later PTE attachment; this operation neither maps pages nor grants trust. */
enum sptm_result sptm_mac_set_shared_region(const struct sptm_memory *,
    uint64_t user_root,uint64_t shared_root);
/* Validate a user root's optional binding without admitting nested PTEs. */
int sptm_mac_user_binding_valid(const struct sptm_memory *,volatile uint8_t *meta);
enum sptm_result sptm_mac_configure_root(const struct sptm_memory *,
    uint64_t root,uint64_t value,uint64_t mask);

/* Install a fresh, empty 16K child under the current kernel root (47-bit VA,
 * L1 start). No translations are added by an empty table: the 4K shadow
 * remains unchanged until MAP_PAGE populates a leaf. Reject nonempty children,
 * aliases and geometry not yet supported by this backend. */
enum sptm_result sptm_mac_map_table(const struct sptm_memory *m, uint64_t root,
                                  uint64_t va, uint64_t level, uint64_t tte);
/* Empty table construction under an inactive USER_ROOT (format 0: 16K/L1;
 * format 1: 4K/L0, four subtables per 16K frame). Both admit 47-bit user VA,
 * limited to 32 bits with ARM64_32. Root and every ancestor must have matching allocator-owned
 * frame metadata. No leaf or hardware translation is installed. The host must
 * refuse use on a root currently installed in a guest translation register. */
enum sptm_result sptm_mac_map_user_table(const struct sptm_memory *m,uint64_t root,
                                      uint64_t va,uint64_t level,uint64_t tte);
struct shadow;
struct sptm_shared_update_state;
enum sptm_result sptm_mac_unmap_kernel_disjoint(const struct sptm_memory *,
    struct shadow *,uint64_t root,uint64_t target,uint64_t list,uint64_t count,
    uint64_t scratch,struct sptm_shared_update_state *);
enum sptm_result sptm_mac_unmap_region(const struct sptm_memory *m, struct shadow *s,
    uint64_t root, uint64_t va, uint64_t count, uint64_t options, uint64_t scratch);

/* mac17p UPDATE_DISJOINT has 1..64 {root, VA, template} records of 24 bytes.
 * Handles AF/WIRED, SH/AttrIndx (options 0x10/0x20, any value, on managed
 * frames: memory.clean_frame cleans each changed frame before the first
 * store) and the shipped kernel NX/write-history matrix on counted allocator
 * leaves. Other permission domains, nG and user roots fail closed.
 * UPDATE_REGION uses the same update engine,
 * with 1..64 templates confined to a single L3 table (audited mac17p ABI).
 * The caller quiesces the guest, publishes shadow writes and invalidates its
 * TLB before resuming. Result5 requires option100 and a hardware-visible
 * change, and no changed leaf leaving AttrIndx 5/7 (sptm_update_leaves_posted);
 * the host completes invalidation synchronously. No Apple MMIO or host PA is accepted.
 * map_shadow has the same lifetime/no-side-effects contract as memory.map. */
#define SPTM_DISJOINT_MAX 64u
struct sptm_update_backend {
    uint64_t kernel_root, shadow_root;
    volatile uint8_t *(*map_shadow)(void *ctx, uint64_t pa, uint64_t size);
    void *ctx;
    /* Optional mapping admission before direct descriptor changes. VA is
     * normalized to the 47-bit shadow regime; nonzero admits the whole range. */
    int (*admit)(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
                 uint64_t low,uint64_t upper);
};
struct sptm_update_entry {
    volatile uint8_t *guest, *shadow[4];
    uint64_t slot_pa, old, next;
};
struct sptm_update_workspace { struct sptm_update_entry entries[SPTM_DISJOINT_MAX]; };
/* Single kernel record for a mixed transaction. Prepare stages references but
 * publishes nothing; the owner begins/validates/commits one reference batch
 * around every user and kernel record. Commit runs only after all prepare
 * calls succeed. The owner refreshes private kernel views and broadcasts TLBI. */
enum sptm_result sptm_kernel_update_prepare(const struct sptm_memory *,
    const struct sptm_update_backend *,uint64_t target,uint64_t va,
    uint64_t requested,uint64_t options,uint64_t scratch,uint64_t scratch_bytes,
    struct sptm_update_entry *);
void sptm_kernel_update_commit(const struct sptm_memory *,struct sptm_update_entry *);
/* Call only after a successful update with the same workspace/count. */
uint64_t sptm_update_result(const struct sptm_update_workspace *w,
    uint64_t count,uint64_t options);
/* ...fdea0..fdec4 (UPDATE_REGION's engine ...fcaf4 alike; both skip it for
 * stage-2 roots): a changed leaf leaving a posted AttrIndx (5 or 7: bits 0x14
 * both set) clears 0x100/0x400 for the rest of the call, which then
 * invalidates at once and returns 0; ...dfd7c applies the same test to the
 * MULTIPAGE aperture leaf. "Changed" is the helper's ...fd8d4 flag: any bit
 * but 58/59. */
static inline int sptm_update_leaves_posted(uint64_t old,uint64_t next)
{return ((old^next)&~(3UL<<58)) && (old&0x14)==0x14 && (next&0x14)!=0x14;}
enum sptm_result sptm_mac_update_disjoint(const struct sptm_memory *m,
    const struct sptm_update_backend *b, struct sptm_update_workspace *w,
    uint64_t target, uint64_t list, uint64_t count, uint64_t options,
    uint64_t scratch);
/* UPDATE_DISJOINT_MULTIPAGE (endpoint 0x15, ...270fe4e4): 1..64 24-byte
 * records inside one 16K page. Each header {frame PA, aperture attributes,
 * u32 mapping count, u32 options} is followed by that many UPDATE_DISJOINT
 * records {root, VA, template}; each group runs the UPDATE_DISJOINT engine
 * (...270fdc44) with target = frame and options without 0x200, and the call
 * returns 5 if any group did. XNU issues it from phys_attribute_clear's
 * flush-range path (header options 0xa/0x10a|0x200: no aperture change) and
 * pmap_batch_set_cache_attributes (0x130 for a frame's first header, 0x330
 * for its continuations). A header without 0x200 first rewrites the frame's
 * physical-aperture leaf through ...270dfb1c, even with no mappings: flag 2
 * (option 0x20) sets its AttrIndx to bits4:2 of the attribute word, never
 * SH; flag 0x80 (option 0x100, types deferring at descriptor +0x34) defers
 * that TLBI and reports 5. No flag at all is refused (...dfe40). Apple's
 * cache flag 0x40 is never passed. The aperture step is modeled for DEFAULT
 * frames only (selector3 aperture). The plan snapshots/validates every header
 * before any group executes; aperture_flags is 0 for a 0x200 header. */
#define SPTM_MULTIPAGE_MAX 64u
struct sptm_multipage_group {
    uint64_t target, list, count, options;
    uint64_t aperture_flags, aperture_attr;
};
struct sptm_multipage_plan {
    uint64_t groups;
    struct sptm_multipage_group group[SPTM_MULTIPAGE_MAX];
};
enum sptm_result sptm_mac_multipage_plan(const struct sptm_memory *m,uint64_t ops,
    uint64_t count,struct sptm_multipage_plan *p);
enum sptm_result sptm_mac_update_region(const struct sptm_memory *m,
    const struct sptm_update_backend *b, struct sptm_update_workspace *w,
    uint64_t root, uint64_t va, uint64_t count, uint64_t templates,
    uint64_t options, uint64_t scratch);
