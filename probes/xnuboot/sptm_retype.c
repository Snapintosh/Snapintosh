/* SPDX-License-Identifier: MIT */
/* SPTM retype callbacks, TXM image load and the user-root share, retire, bind
 * and configure calls.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
static int sptm_retype_rozone(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    /* A SLIDE_REGION-moved frame also has the alias XNU's phystokv uses;
     * both leaves need private paths before either becomes selector2. */
#if SNAP_VIEW_RECLAIM
    for(unsigned i=0;i<change.count;i++)if(sprr_pte_class(change.leaf[i].after)==9)return 0;
    if(!kernel_views_prepare_change(c,&change))return 0;
#else
    struct shadow s=kernel_shadow(c);
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)==9 ||
           !sprr_views_prepare(&c->kernel_views,&s,change.leaf[i].va))return 0;
#endif
    /* Detach copied paths while canonical descriptors still have their old
     * permissions. No guest CPU may see an untranslated raw selector2 leaf. */
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    kernel_class_proof_forget(c);
    sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    if(new_type==SPTM_MAC_ROZONE)c->papt_protects++;else c->papt_releases++;
    return 1;
}

static int sptm_retype_txm_default(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    if(old_type!=SPTM_MAC_DEFAULT || new_type!=SPTM_MAC_TXM_DEFAULT)return 0;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
#if SNAP_VIEW_RECLAIM
    for(unsigned i=0;i<change.count;i++)if(sprr_pte_class(change.leaf[i].after)!=4)return 0;
    if(!kernel_views_prepare_change(c,&change))return 0;
#else
    struct shadow s=kernel_shadow(c);
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)!=4 ||
           !sprr_views_prepare(&c->kernel_views,&s,change.leaf[i].va))return 0;
#endif
    /* Detach every CPU's path while the canonical aperture is still class3.
     * After commit, private class4 is always EL1 RO/NX, with no EL0 access. */
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    kernel_class_proof_forget(c);sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    c->txm_donations++;return 1;
}

static int sptm_retype_txm_owned(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    if(!((old_type==SPTM_MAC_TXM_DEFAULT && new_type==SPTM_MAC_TXM_OWNED) ||
         (old_type==SPTM_MAC_TXM_OWNED && new_type==SPTM_MAC_DEFAULT)))return 0;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    unsigned selector=new_type==SPTM_MAC_TXM_OWNED ? 11:3;
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)!=selector)return 0;
    /* Donation already detached selector4's paths on every CPU. Import uses
     * fixed RO/NX selector11; release restores ordinary RW/NX selector3.
     * Keep the counted, separately mapped read-only kernel alias intact. */
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    kernel_class_proof_forget(c);sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    if(new_type==SPTM_MAC_TXM_OWNED)c->txm_imports++;else c->txm_releases++;
    return 1;
}

static enum sptm_result txm_load_prepare(void *ctx,const uint64_t args[8],uint64_t pa[2])
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);m.retype_txm_owned=sptm_retype_txm_owned;
    struct txm_kernel_memory kernel={&m,vcpu_of(c)->guest_ttbr1&0x0000ffffffffc000UL,
                                    vcpu_of(c)->guest_tcr};
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    for(unsigned i=0;i<2;i++) {
        if(!txm_resolve_kernel_page(&kernel,args[2+i*2],args[3+i*2],&pa[i]))return SPTM_BAD_ADDRESS;
        enum sptm_result r=sptm_txm_retype_check(&m,pa[i],42,60);
        if(r)return r;
        struct sptm_papt_change change;
        r=sptm_papt_prepare(&m,&b,&a,&moved,pa[i],42,60,&change);
        if(r)return r;
    }
    return pa[0]!=pa[1] ? SPTM_OK:SPTM_BAD_ADDRESS;
}
static int txm_load_stage(void *ctx,const uint8_t *payload,uint64_t size,
                           const uint8_t *manifest,uint64_t manifest_size)
{
    struct context *c=ctx;
    return txm_native_stage(&c->params->txm_native,&c->txm_native,payload,size,manifest,manifest_size);
}
static int txm_load_authenticate(void *ctx,uint64_t type,const struct txm_native_cache *boot,
    const struct txm_native_cache *dynamic,unsigned count,struct txm_native_result *result)
{
    struct context *c=ctx;
    return txm_native_load_caches(&c->params->txm_native,&c->txm_native,type,boot,dynamic,count,result);
}

static int sptm_retype_user_exec(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    for(unsigned i=0;i<change.count;i++)
        if(sprr_pte_class(change.leaf[i].after)==9)return 0;
    /* Class11 uses fixed ARM permissions on all CPUs, so no new private
     * branches are needed. Existing private paths still receive the update. */
    kernel_class_proof_forget(c);
    sptm_papt_commit(&m,&change);
    if(!transaction_publish(c))return 0;
    shadow_tlb_sync(c);if(c->kernel_view_failed)return 0;
    if(new_type==SPTM_MAC_USER_EXEC) {
        /* Publish data to PoC, then invalidate instruction caches in the
         * inner-shareable domain across all guest VMIDs and VA aliases. */
        publish(pa,pa+SPTM_MAC_FRAME_SIZE);
        __asm__ volatile("ic ialluis; dsb ish; isb" ::: "memory");
        c->user_exec_cache_syncs++;c->user_exec_protects++;
    } else c->user_exec_releases++;
    return 1;
}

static int sptm_retype_user_tpro(void *ctx,uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);
    struct sptm_papt_change change;
    if(sptm_papt_prepare(&m,&b,&a,&moved,pa,old_type,new_type,&change)!=SPTM_OK)return 0;
    for(unsigned i=0;i<change.count;i++)
        if(change.leaf[i].before!=change.leaf[i].after ||
           sprr_pte_class(change.leaf[i].after)!=3)return 0;
#if SNAP_ROOT_VALIDATE_MEMO
    /* A mapped frame's TPRO retype changes canonical_leaf's verdict for its
     * leaves. sptm_mac_retype admits this transition only with zero
     * references and reports every type store itself; retire retained
     * SWITCH_ROOT verdicts here too if that ever changes. */
    sptm_root_memo_retype(&c->root_memo,
        m.map(m.ctx,m.frame_map_pa+((pa-m.frame_low)>>14)*16,16));
#endif
    /* Both types keep the same RW/NX physical aperture. Preflight verifies
     * the source and all four canonical hardware leaves; there is no page
     * data or descriptor mutation before the lifecycle publishes metadata. */
    if(new_type==SPTM_MAC_USER_TPRO)c->user_tpro_protects++;
    else c->user_tpro_releases++;
    return 1;
}

static int sptm_retire_user_root(void *ctx, uint64_t pa, uint16_t asid)
{
    struct context *c = ctx;
    if (vcpu_root_busy(c, pa)) return 0;
    for (unsigned n = 0; n < TXM_REG(c)->count; n++)
        if (TXM_REG(c)->root[n] == pa ||
            (!TXM_REG(c)->shared[n] && TXM_REG(c)->asid[n] == asid))
            return 0;
    /* No CPU holds this root. Remove translations in every guest VMID before
     * allowing the retired ASID/frame to recur. */
    if(!sptm_root_invalidate(&c->user_roots,pa,1))return 0;
    shadow_tlb_sync(c);
#if SNAP_USER_HW_WALK
    /* After that flush its hardware ASIDs and copy pages may recur too. */
    struct hw_walk_root *hr=hw_root(c,pa);
    if(hr) {struct hw_walk_ops o=hw_ops(c);hw_walk_detach(c->hw_walk,&o,hr);}
#endif
    return 1;
}

static int sptm_share_user_root(void *ctx,uint64_t pa,uint16_t asid,uint8_t slot)
{
    struct context *c=ctx;
    if(vcpu_root_busy(c,pa))return 0;
    const struct params *p=c->params;
    struct sptm_memory memory=sptm_context_memory(c);
    struct sptm_aperture ap={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct txm_arena arena={p->txm_aspace_pa,sptm_aperture_pointer(&ap,p->txm_aspace_pa,TXM_ASPACE_SIZE)};
    struct txm_share_plan plan;
    if(txm_share_prepare(&memory,&arena,TXM_REG(c),pa,asid,slot,&plan))return 0;
    if(!sptm_root_invalidate(&c->user_roots,pa,1))return 0;
    shadow_tlb_sync(c);
#if SNAP_USER_HW_WALK
    /* A shared root is never switched to: its user-root record goes. */
    struct hw_walk_root *hr=hw_root(c,pa);
    if(hr) {struct hw_walk_ops o=hw_ops(c);hw_walk_detach(c->hw_walk,&o,hr);}
#endif
    txm_share_commit(&memory,TXM_REG(c),&plan);
    c->shared_root_converts++;
    return 1;
}

static int sptm_retire_shared_root(void *ctx,uint64_t pa,uint8_t slot)
{
    struct context *c=ctx;
    if(vcpu_root_busy(c,pa))return 0;
    for(unsigned i=0;i<TXM_REG(c)->count;i++)
        if(TXM_REG(c)->root[i]==pa || (TXM_REG(c)->root[i] &&
           TXM_REG(c)->shared[i] && TXM_REG(c)->asid[i]==slot))return 0;
    if(!sptm_root_invalidate(&c->user_roots,pa,1))return 0;
#if SNAP_NATIVE_SHARED
    for(unsigned g=0;g<NATIVE_SHARED_GROUPS;g++)if(UNS(c).group[g].guest &&
                                                   UNS(c).group[g].shared==pa) {
        if(!native_group_unlinked(c,(int)g) ||
           !native_shared_free(&UNS(c),(int)g,native_group_release,c) || c->user_view_failed)
            return 0;
    }
#endif
    shadow_tlb_sync(c);
    c->shared_root_releases++;
    return 1;
}

static int sptm_bind_shared_root(void *ctx,uint64_t user,uint16_t asid,
    uint64_t shared,uint8_t slot,uint64_t start,uint64_t size)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct sptm_memory memory=sptm_context_memory(c);
    struct sptm_aperture ap={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct txm_arena arena={p->txm_aspace_pa,sptm_aperture_pointer(&ap,p->txm_aspace_pa,TXM_ASPACE_SIZE)};
    return txm_bind_shared(&memory,&arena,TXM_REG(c),user,asid,shared,slot,start,size)==SPTM_OK;
}

static int sptm_configure_user_root(void *ctx,uint64_t root,uint16_t before,uint16_t after)
{
    struct context *c=ctx;
    unsigned active=0;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)active+=c->user_roots.active[cpu]==root;
    if(active) {
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
            if(!sptm_root_recorded_matches(&c->user_roots,cpu,c->vcpus[cpu].guest_ttbr0,
                                          c->params->ttbr1_root) ||
               (c->vcpus[cpu].guest_ttbr1&UINT64_C(0x0000ffffffffc000))==root)return 0;
#if SNAP_USER_HW_WALK
        /* As for a cached root: UMPRR11 only, which no user leaf class (and so
         * no copy) depends on; UMPRR18 never changes under a running CPU. */
        struct hw_walk_root *hr=hw_root(c,root);
        if(hr) {
            if((before^after)!=SPTM_MAC_ROOT_FLAG_UMPRR11 || hr->entry.flags!=before)return 0;
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
                if(!hw_walk_loaded_valid(&c->user_roots,c->hw_walk,c->root_loaded,cpu))return 0;
            hr->entry.flags=after;
            hr->umprr=((uint64_t)(after&8)<<15)|((uint64_t)(after&1)<<11);
            return 1;
        }
        /* A cached root, with hardware-walk roots possibly active elsewhere. */
        return hw_walk_configure_active(&c->user_roots,c->hw_walk,c->root_loaded,root,before,after);
#else
        return sptm_root_configure_active(&c->user_roots,c->root_loaded,root,before,after);
#endif
    }
#if SNAP_INACTIVE_MIRROR
    unsigned cached=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
        cached|=c->user_roots.cache[i].root==root && c->user_roots.cache[i].valid;
#endif
    if(vcpu_root_busy(c,root) || !sptm_root_invalidate(&c->user_roots,root,0))return 0;
#if SNAP_INACTIVE_MIRROR
    c->inactive_mirror.stats.configured+=cached;
#endif
    shadow_tlb_sync(c);
#if SNAP_USER_HW_WALK
    /* Inactive and flushed: the record goes; the next install attaches the
     * root again under its new flags (copies and discovery included). */
    struct hw_walk_root *hr=hw_root(c,root);
    if(hr) {struct hw_walk_ops o=hw_ops(c);hw_walk_detach(c->hw_walk,&o,hr);}
#endif
    return 1;
}

