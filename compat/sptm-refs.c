/* SPDX-License-Identifier: MIT */
#include "sptm-refs.h"
#define PA_MASK 0x0000ffffffffc000UL

static uint32_t load(volatile uint8_t *p,unsigned bytes)
{
    /* Reference fields are naturally aligned u16/u32. Keep the byte path for
     * backends that map guest memory at an unaligned host address. No change
     * to reference policy, publication ranges or the fine-lock atomic path. */
    if(bytes==2 && !((uintptr_t)p&1))return *(const volatile uint16_t *)(const volatile void *)p;
    if(bytes==4 && !((uintptr_t)p&3))return *(const volatile uint32_t *)(const volatile void *)p;
    uint32_t v=0;for (unsigned i=0;i<bytes;i++) v|=(uint32_t)p[i]<<(8*i);return v;
}
static void store(volatile uint8_t *p,uint32_t v,unsigned bytes)
{
    if(bytes==2 && !((uintptr_t)p&1)){*(volatile uint16_t *)(volatile void *)p=(uint16_t)v;return;}
    if(bytes==4 && !((uintptr_t)p&3)){*(volatile uint32_t *)(volatile void *)p=v;return;}
    for (unsigned i=0;i<bytes;i++) p[i]=(uint8_t)(v>>(8*i));
}
void sptm_refs_begin(struct sptm_ref_batch *b) { if (b) b->count=0; }
static int table_type(unsigned type) { return type==20 || type==21 || type==22 || type==23; }
static int commpage_type(unsigned type) { return type>=29 && type<=31; }
static enum sptm_result delta(const struct sptm_memory *m,uint64_t pa,
                             int table,int ro,int other,int aliases,int sep_resource)
{
    if (!ro && !other) return SPTM_OK;
    if (!m || !m->refs || !m->map || !m->publish || (pa&0x3fff))
        return SPTM_BAD_CONFIG;
    if (!sptm_boot_memory_valid(m)) return SPTM_BAD_CONFIG;
    /* Monitor reservations, permanent image and devices remain outside the
     * allocator lifecycle. Disposable image frames participate normally. */
    if (!sptm_managed_frame(m,pa) && !sep_resource) return SPTM_OK;
    if (sep_resource && (table || !sptm_sep_firmware_valid(m) ||
                         !sptm_sep_firmware_frame(m,pa))) return SPTM_BAD_CONFIG;
    if (pa<m->frame_low || pa>=m->frame_high || (m->frame_map_pa&15))
        return SPTM_BAD_ADDRESS;
    struct sptm_ref_batch *b=m->refs;
    struct sptm_ref_entry *e=0;
    for (unsigned i=0;i<b->count;i++) if (b->entries[i].pa==pa) { e=&b->entries[i];break; }
    if (!e) {
        if (b->count>=SPTM_REF_MAX) return SPTM_BAD_REFERENCE;
        uint64_t index=(pa-m->frame_low)>>14;
        if (index>(UINT64_MAX-m->frame_map_pa-15)/16) return SPTM_BAD_CONFIG;
        volatile uint8_t *p=m->map(m->ctx,m->frame_map_pa+index*16,16);
        if (!p) return SPTM_MEMORY_UNAVAILABLE;
#if SNAP_SPTM_FINE_RETYPE
        /* sptm-refs.h: the frame shared before its type is read; held
         * exclusive by a converted RETYPE: refuse (the call declines). */
        if (m->fine && !sptm_frame_share(m->fine->held,pa)) return SPTM_FRAME_BUSY;
#endif
        unsigned type=p[2];
        if (sep_resource && (type!=11 || p[3] || p[4] || p[5] || p[6] || p[7]))
            return SPTM_TYPE_MISMATCH;
        if (table ? (!table_type(type) || p[4]!=3) :
            (type!=11 && type!=14 && type!=17 && type!=25 && type!=35 && !commpage_type(type)))
            return SPTM_TYPE_MISMATCH;
        if (p[0] || p[1]) return SPTM_FRAME_BUSY;
#if SNAP_FINE_LOCKS
        if (m->fine) {
            if (sep_resource || (table ? type!=20 : (type!=11 && type!=14)))
                return SPTM_FRAME_BUSY;
            e=&b->entries[b->count++];e->pa=pa;e->entry=p;e->type=type;
            e->ro=table ? __atomic_load_n((volatile uint16_t *)(p+8),__ATOMIC_RELAXED) :
                          __atomic_load_n((volatile uint32_t *)(p+8),__ATOMIC_RELAXED);
            e->other=table ? 0 : __atomic_load_n((volatile uint32_t *)(p+12),__ATOMIC_RELAXED);
            m->fine->ro[e-b->entries]=e->ro;m->fine->other[e-b->entries]=e->other;
            if (e->ro>(table ? 2048 : INT32_MAX-(int64_t)SPTM_REF_FINE_MARGIN) ||
                e->other>INT32_MAX-(int64_t)SPTM_REF_FINE_MARGIN)
                return SPTM_BAD_REFERENCE;
        } else {
#endif
        e=&b->entries[b->count++];e->pa=pa;e->entry=p;e->type=type;
        e->ro=load(p+8,table ? 2 : 4);e->other=table ? 0 : load(p+12,4);
        if (e->ro>(table ? 2048 : INT32_MAX) || e->other>INT32_MAX)
            return SPTM_BAD_REFERENCE;
#if SNAP_FINE_LOCKS
        }
#endif
    }
    if (!!table!=!!table_type(e->type)) return SPTM_TYPE_MISMATCH;
    if(e->type==SPTM_MAC_USER_EXEC && !(aliases&1))return SPTM_TYPE_MISMATCH;
    if(e->type==SPTM_MAC_USER_TPRO && !(aliases&2))return SPTM_TYPE_MISMATCH;
    e->ro+=ro;e->other+=other;
    if (e->ro<0 || e->other<0) return SPTM_BAD_REFERENCE;
    return SPTM_OK;
}
/* SPTM ...ecba8..eccfc: readonly counts permission classes 11/15 only when
 * software WAS_WRITABLE (bit 59) is clear; other valid leaves count at +12.
 * Both classes count toward a table's u16 +8, independent of AF or WIRED,
 * as does an invalid leaf with any of software bits63:61 (...ecbe8/ecbf4
 * test 0xe000000000000000, so bit61 alone counts like the compressed markers). */
static int readonly(uint64_t pte)
{
    unsigned perm=(unsigned)(((pte>>4)&12)|((pte>>53)&3));
    return (perm&~4u)==11 && !(pte&(1UL<<59));
}
static int counted(uint64_t pte)
{
    return (pte&3)==3 || (pte&0xe000000000000000UL);
}
enum sptm_result sptm_refs_leaf(const struct sptm_memory *m,uint64_t table,
                               uint64_t va,uint64_t old,uint64_t next)
{
    if (!m || !m->refs || !sptm_boot_memory_valid(m) || (table & 0x3fff)) return SPTM_BAD_CONFIG;
    if (m->frame_low && (table < m->frame_low || table >= m->frame_high)) return SPTM_BAD_ADDRESS;
    if (sptm_managed_frame(m, table)) {
        uint64_t index = (table - m->frame_low) >> 14;
        volatile uint8_t *p = m->map(m->ctx, m->frame_map_pa + index * 16, 16);
        if (!p) return SPTM_MEMORY_UNAVAILABLE;
        if (!table_type(p[2])) return SPTM_TYPE_MISMATCH;
    }
    /* Every CPU leaf transition passes here; 4K is the finer user granule. */
    if (m->audit && (old&3)==3 && (next&3)==3 && ((old^next)&0x0000fffffffff000UL)) {
        struct sptm_pv_audit *a=m->audit;
        a->pending++;a->pending_va=va;a->pending_old=old;a->pending_next=next;
    }
    if (m->aperture_size && va>=m->aperture_va && va-m->aperture_va<m->aperture_size)
        return SPTM_OK;
    enum sptm_result r=delta(m,table,1,counted(next)-counted(old),0,0,0);
    if (r) return r;
    uint64_t states[2]={old,next};
    for (unsigned i=0;i<2;i++) if ((states[i]&3)==3) {
        if (sptm_boot_alias(m,va,states[i]&PA_MASK)) continue;
        int sign=i ? 1 : -1,ro=readonly(states[i]);
        unsigned perm=(unsigned)(((states[i]>>4)&12)|((states[i]>>53)&3));
        int exec_alias=(perm==11 || perm==13 || perm==15) && !(states[i]&(1UL<<59));
        /* Type17's 0x8a88 policy is on the 4-bit class. WAS_WRITABLE is the
         * software half of Apple's rows 7->23/31 and 9->25 on this type. */
        int tpro_alias=!!(0x8a88u&(1u<<perm));
        r=delta(m,states[i]&PA_MASK,0,ro*sign,(!ro)*sign,exec_alias|(tpro_alias<<1),0);
        if (r) return r;
    }
    return SPTM_OK;
}
enum sptm_result sptm_refs_validate(const struct sptm_memory *m)
{
    if (!m || !m->refs || m->refs->count>SPTM_REF_MAX) return SPTM_BAD_CONFIG;
    for (unsigned i=0;i<m->refs->count;i++) {
        struct sptm_ref_entry *e=&m->refs->entries[i];
        int table=table_type(e->type);
        if (e->ro<0 || e->other<0 || e->ro>(table ? 2048 : INT32_MAX) ||
            e->other>INT32_MAX) return SPTM_BAD_REFERENCE;
        /* The audited type descriptors' +0x33 flag allows mixed aliases for
         * DEFAULT and COMMPAGE data, but not ROZONE/KERNEL_RESTRICTED. */
        if (!table && e->type!=11 && e->type!=14 && e->type!=17 &&
            !commpage_type(e->type) && e->ro && e->other)
            return SPTM_FRAME_BUSY;
    }
    return SPTM_OK;
}
enum sptm_result sptm_refs_dart(const struct sptm_memory *m,uint64_t pa,int ro)
{
    if (!m || !sptm_managed_frame(m,pa) || (ro!=0 && ro!=1))
        return SPTM_BAD_ADDRESS;
    return delta(m,pa,0,ro,!ro,0,0);
}
enum sptm_result sptm_refs_dart_remove(const struct sptm_memory *m,uint64_t pa,int ro)
{
    if (!m || !sptm_managed_frame(m,pa) || (ro!=0 && ro!=1))
        return SPTM_BAD_ADDRESS;
    return delta(m,pa,0,-ro,-!ro,0,0);
}
enum sptm_result sptm_refs_dart_stream(const struct sptm_memory *m,
    uint64_t id,uint64_t sid,uint64_t pa,int ro,int remove)
{
    if (!sptm_sep_firmware_valid(m)) return SPTM_BAD_CONFIG;
    if (!sptm_dart_data_frame(m,id,sid,pa) || (ro!=0 && ro!=1) ||
        (remove!=0 && remove!=1)) return SPTM_BAD_ADDRESS;
    int sign=remove ? -1 : 1;
    /* Once released the extent is allocator memory and counts like it. */
    return delta(m,pa,0,sign*ro,sign*!ro,0,
                 sptm_sep_firmware_frame(m,pa) && !m->sep_firmware_released);
}
void sptm_refs_commit(const struct sptm_memory *m)
{
    struct sptm_pv_audit *a=m->audit;
    if (a && a->pending) {
        a->remaps+=a->pending;a->pending=0;
        a->remap_va=a->pending_va;a->remap_old=a->pending_old;a->remap_next=a->pending_next;
    }
    for (unsigned i=0;i<m->refs->count;i++) {
        struct sptm_ref_entry *e=&m->refs->entries[i];int table=table_type(e->type);
#if SNAP_FINE_LOCKS
        if (m->fine) {
            int64_t ro=e->ro-m->fine->ro[i],other=e->other-m->fine->other[i];
            if (table && ro)
                __atomic_fetch_add((volatile uint16_t *)(e->entry+8),(uint16_t)ro,__ATOMIC_RELAXED);
            if (!table && ro)
                __atomic_fetch_add((volatile uint32_t *)(e->entry+8),(uint32_t)ro,__ATOMIC_RELAXED);
            if (!table && other)
                __atomic_fetch_add((volatile uint32_t *)(e->entry+12),(uint32_t)other,__ATOMIC_RELAXED);
            m->publish(m->ctx,m->frame_map_pa+((e->pa-m->frame_low)>>14)*16,16);
            continue;
        }
#endif
        store(e->entry+8,(uint32_t)e->ro,table ? 2 : 4);
        if (!table) store(e->entry+12,(uint32_t)e->other,4);
        m->publish(m->ctx,m->frame_map_pa+((e->pa-m->frame_low)>>14)*16,16);
    }
}
