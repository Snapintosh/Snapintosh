/* SPDX-License-Identifier: MIT */
/* UPDATE_DISJOINT_MULTIPAGE planning, aperture steps and attribute-clean batching.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
/* UPDATE_DISJOINT_MULTIPAGE's aperture step for a header without 0x200
 * (...270dfb1c): flag 2 gives both aperture aliases of the DEFAULT frame the
 * header's AttrIndx (SH and permissions unchanged). The frame is cleaned to
 * PoC before the store; publication, the private-view refresh and the
 * all-VMID TLBI complete before the group's own records, then the frame is
 * cleaned again. Apple defers that TLBI under flag 0x80 and answers 5,
 * except when the leaf leaves a posted AttrIndx (...dfd7c); the answer is
 * reproduced although the invalidation here is always synchronous. */
#if !SNAP_MULTIPAGE_FAST
static int multipage_aperture(struct context *c,const struct sptm_multipage_group *g,
    uint64_t elr,uint64_t *out)
{
    const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    c->attr_updates.pending=0;
    uint64_t before=0,after=0;
    enum sptm_result r=SPTM_OK;
    if(g->aperture_flags&2) {
        r=sptm_papt_prepare_attr(&m,&b,&a,&moved,g->target,(unsigned)g->aperture_attr,&change);
        if(r)goto failed;
        /* Apple rewrites the alias its phystokv names: the moved one if any. */
        before=change.leaf[change.count-1].before;after=change.leaf[change.count-1].after;
        int changed=0;
        for(unsigned i=0;i<change.count;i++)changed|=change.leaf[i].before!=change.leaf[i].after;
        if(changed) {
            r=SPTM_MEMORY_UNAVAILABLE;
            if(!sptm_attr_clean(c,g->target,0x4000))goto failed;
            kernel_class_proof_forget(c);
            sptm_papt_commit(&m,&change);
            r=SPTM_SHADOW_FAILED;
            if(!transaction_publish(c))goto failed;
            shadow_tlb_sync(c);if(c->kernel_view_failed)goto failed;
            attr_clean_finish(c);
            c->attr_updates.apertures+=change.count;
        }
        c->attr_updates.last_pa=g->target;
        c->attr_updates.last_before=before;c->attr_updates.last_after=after;
    }
    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;
    return 1;
failed:
    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);
    return 0;
}
#else
_Static_assert(SPTM_MULTIPAGE_MAX<=SPTM_DISJOINT_MAX,"one call's changed frames fit attr_updates.pending (P6)");
/* P5: the cacheability class of an AttrIndx under the pinned MAIR (tools/test-sptm-mair.py): 1 Normal
 * write-back 0xff (0 WRITEBACK, 4 INNERWRITEBACK), 2 Normal-NC (1 WRITECOMB), 3 WRITETHRU (2), 4 Device (3, 5,
 * 6, 7). Both cleans are skipped only when no cache can hold anything different for the frame afterwards: the
 * same write-back encoding, or non-cacheable before and after. */
static int multipage_same_class(uint64_t before,uint64_t after)
{
    static const unsigned char attr_class[8]={1,2,3,4,1,4,4,4};
    unsigned a=attr_class[(before&PT_ATTRINDX)>>2],b=attr_class[(after&PT_ATTRINDX)>>2];
    return (a==1 && b==1) || ((a==2 || a==4) && (b==2 || b==4));
}
/* P1-P3: xnuboot_trap, before runtime_enter, without the token. The ops page is read with the planner's bounds
 * and every aperture-step target (a header without 0x200, with option 0x20) is cleaned to PoC by VA through
 * EL2's identity map of guest RAM; the set is this vCPU's, armed for this trap only. The plan read under the
 * token decides; a target not in the set is cleaned inline. Data-preserving, so a stale or hostile list only
 * costs cleans. */
static void multipage_preclean(struct context *c,const uint64_t *frame,uint64_t esr)
{
    struct multipage_preclean_cpu *set=&c->root_ext->multipage_preclean[vcpu_of(c)->slot];
    set->count=0;
    if((esr>>26)!=0x20 || frame[16]!=SPTM_FN_UPDATE_DISJOINT_MULTIPAGE)return;
    const struct params *p=c->params;
    uint64_t ops=frame[0],count=frame[1];
    if(!count || count>SPTM_MULTIPAGE_MAX || (ops&7) || (ops&0x3fff)+count*24>0x4000)return;
    volatile uint8_t *in=sptm_map(c,ops,count*24);
    if(!in)return;
    for(uint64_t i=0;i<count;) {
        volatile uint8_t *h=in+i*24;
        uint64_t target=*(volatile uint64_t *)h,w=*(volatile uint64_t *)(h+16);
        uint32_t mappings=(uint32_t)w,options=(uint32_t)(w>>32);
        i++;
        if(!(options&0x200) && (options&0x20) && !(target&0x3fff) && target>=p->mem_low &&
           target<p->mem_high && p->mem_high-target>=0x4000 && set->count<SPTM_MULTIPAGE_MAX) {
            for(uint64_t line=target;line<target+0x4000;line+=64)
                __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
            set->pa[set->count++]=target;
        }
        if(mappings>count-i)break;
        i+=mappings;
    }
    if(set->count) {__asm__ volatile("dsb ish" ::: "memory");set->frames+=set->count;}
}
static void multipage_preclean_clear(struct context *c)
{c->root_ext->multipage_preclean[vcpu_of(c)->slot].count=0;}
static int multipage_precleaned(struct context *c,uint64_t pa)
{
    const struct multipage_preclean_cpu *set=&c->root_ext->multipage_preclean[vcpu_of(c)->slot];
    for(uint64_t n=0;n<set->count && n<SPTM_MULTIPAGE_MAX;n++)if(set->pa[n]==pa)return 1;
    return 0;
}
/* sptm_attr_clean for a frame already cleaned to PoC before the token: the same refusals, the same pending
 * entry for attr_clean_finish's second clean, the same count. */
static int attr_clean_note(struct context *c,uint64_t pa)
{
    const struct params *p=c->params;struct attr_update_state *s=&c->attr_updates;
    if((pa&0x3fff) || pa<p->mem_low || pa>=p->mem_high || 0x4000>p->mem_high-pa ||
       s->pending>=SPTM_DISJOINT_MAX) {
        s->refused++;return 0;
    }
    s->pending_pa[s->pending++]=pa;s->cleans++;
    return 1;
}
/* P7-P9, P19: a changed canonical shadow word. In a level-3 kernel-view copy source, while the reuse snapshot is
 * valid for these views and PPERMs, it is written into the six copies (sprr_views_sync_word: a full sync's own
 * translation), into every PPERM variant column still exact for this snapshot generation (sprr_variants_exact's
 * test: an unchanged saves means unchanged canonical words, which must stay true), and into the snapshot. Otherwise
 * nothing is written: the run's refresh then misses its proof and syncs and saves in full. */
static int multipage_view_patch(struct context *c,uint64_t pa)
{
    if(!c->kernel_views.count)return 1;
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    int n=sprr_views_word_table(&c->kernel_views,pa);
    if(n==-1)return 1;
    struct shadow s=kernel_shadow(c);
    struct sprr_reuse_state *r=&c->kernel_reuse_state;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
    int ok=n>=0 && r->valid && r->root==s.root && r->count==c->kernel_views.count;
    if(ok) {
        const struct sprr_view_table *a=&r->tables[n],*b=&c->kernel_views.tables[n];
        ok=a->source==b->source && a->level==b->level;
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)ok=ok && a->copy[cpu]==b->copy[cpu] && r->pperm[cpu]==pp[cpu];
    }
    if(!ok) {st->unpatched++;return 1;}
    uint64_t extra[GUEST_CPU_COUNT]={0},extra_pp[GUEST_CPU_COUNT]={0};
#if SNAP_KERNEL_PPERM_VARIANTS
    const struct sprr_view_variants *v=&c->kernel_variants;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if(v->count[cpu]==c->kernel_views.count && v->saves[cpu] && v->saves[cpu]==r->saves &&
           v->copy[n][cpu] && v->source[n][cpu]==c->kernel_views.tables[n].source) {
            extra[cpu]=v->copy[n][cpu];extra_pp[cpu]=v->pperm[cpu];st->variants++;
        }
#endif
    unsigned index=(unsigned)((pa&4095)/8);
    if(!sprr_views_sync_word(&c->kernel_views,&s,(unsigned)n,index,pp,extra,extra_pp)) {
        c->kernel_view_failed=1;return 0;
    }
    r->words[n][index]=*(volatile uint64_t *)pa;
    st->patched++;return 1;
}
/* multipage_aperture without its own publication, refresh, TLBI and second clean: the open run is closed by
 * multipage_close (P12). The first clean is the pre-clean's when this trap made one (P1), none for a
 * same-class change (P5), else inline as before. The answer is computed exactly as before. */
static int multipage_aperture_fast(struct context *c,const struct sptm_multipage_group *g,
    uint64_t elr,uint64_t *out,int *open)
{
    const struct params *p=c->params;
    struct sptm_memory m=sptm_context_memory(c);
    struct sptm_update_backend b={.kernel_root=p->ttbr1_root,
        .shadow_root=c->vcpus[0].shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    struct sptm_aperture a={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_moved moved=xnu_moved(c);struct sptm_papt_change change;
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    uint64_t before=0,after=0;
    enum sptm_result r=SPTM_OK;
    if(g->aperture_flags&2) {
        r=sptm_papt_prepare_attr(&m,&b,&a,&moved,g->target,(unsigned)g->aperture_attr,&change);
        if(r)goto failed;
        before=change.leaf[change.count-1].before;after=change.leaf[change.count-1].after;
        int changed=0,same=1;
        for(unsigned i=0;i<change.count;i++) {
            changed|=change.leaf[i].before!=change.leaf[i].after;
            same&=multipage_same_class(change.leaf[i].before,change.leaf[i].after);
        }
        if(changed) {
            r=SPTM_MEMORY_UNAVAILABLE;
            if(same)st->same_class++;
            else if(multipage_precleaned(c,g->target)) {
                if(!attr_clean_note(c,g->target))goto failed;
                st->preclean_hits++;
            } else {
                if(!sptm_attr_clean(c,g->target,0x4000))goto failed;
                st->inline_cleans++;
            }
            kernel_class_proof_forget(c);
            sptm_papt_commit(&m,&change);
            *open=1;
            r=SPTM_SHADOW_FAILED;
            for(unsigned i=0;i<change.count;i++)for(unsigned n=0;n<4;n++)
                if(!multipage_view_patch(c,(uint64_t)(uintptr_t)change.leaf[i].shadow[n]))goto failed;
            c->attr_updates.apertures+=change.count;
        }
        c->attr_updates.last_pa=g->target;
        c->attr_updates.last_before=before;c->attr_updates.last_after=after;
    }
    *out=(g->aperture_flags&0x80) && !sptm_update_leaves_posted(before,after) ? 5:0;
    return 1;
failed:
    record(c,EV_UPDATE_FAILED,elr,r,g->target,g->aperture_flags);
    return 0;
}
/* P10/P12/P6: the open run's publication (copies included: their stores were noted), then the exact reuse
 * proof and the all-VMID TLBI, then the second cleans (deferred past the token by SNAP_ATTR_CLEAN_DEFER). */
static int multipage_close(struct context *c,uint64_t elr,const struct sptm_multipage_group *g,int barrier)
{
    struct multipage_fast_stats *st=&c->root_ext->multipage_fast;
    st->closes++;if(barrier)st->barrier_closes++;
    if(!transaction_publish(c)) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
    }
#if SNAP_KERNEL_DIRTY_PUBLISH
    /* P20: the patched copy pages through their own publication, so every pending row is empty again (the PPERM
     * skip and the variant swap require it). */
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if(!sprr_publish_row_empty(&c->kernel_publish_state,cpu) &&
           !kernel_publish_cpu(c,cpu)) {
            record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
        }
#endif
    shadow_tlb_sync(c);
    if(c->kernel_view_failed) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,g->target,g->aperture_flags);return 0;
    }
    attr_clean_finish(c);
    return 1;
}
/* The MULTIPAGE loop: a run of aperture steps is closed before any group with records (update_disjoint_call
 * resets attr_updates.pending and does its own transaction, P6) and at the end; a failure closes an open run
 * best-effort before the guest is stopped (P13). */
static int multipage_fast(struct context *c,const struct sptm_multipage_plan *plan,uint64_t elr,
                          uint64_t scratch,uint64_t *response)
{
    int open=0;
    c->attr_updates.pending=0;
    for(uint64_t g=0;g<plan->groups;g++) {
        const struct sptm_multipage_group *grp=&plan->group[g];
        uint64_t one;
        if(grp->aperture_flags) {
            if(!multipage_aperture_fast(c,grp,elr,&one,&open)) {
                c->root_ext->multipage_fast.failures++;
                if(open)(void)multipage_close(c,elr,grp,0);
                return 0;
            }
            if(one==5)*response=5;
        }
        if(!grp->count)continue;
        if(open) {
            if(!multipage_close(c,elr,grp,1))return 0;
            open=0;
        }
        if(!update_disjoint_call(c,grp->target,grp->list,grp->count,grp->options,scratch,elr,&one))return 0;
        if(one==5)*response=5;
    }
    if(open && !multipage_close(c,elr,&plan->group[plan->groups-1],0))return 0;
    return 1;
}
#endif
