/* SPDX-License-Identifier: MIT */
/* Kernel shadow views: sync, publication, refresh and permission changes; the
 * SPTM map/publish/attribute-clean helpers and the SPTM memory description.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
static struct shadow kernel_shadow(struct context *c)
{
    return (struct shadow){.txsz=17,.root=c->vcpus[0].shadow_root,
        .alloc=private_kernel_alloc,.read=kernel_table_read,.write=kernel_table_write,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
}
#if SNAP_VIEW_TABLE_READ
static const volatile uint64_t *view_table_read(struct context *c,uint64_t pa,unsigned kind)
{
    struct view_table_read_stats *st=&c->view_table_reads[kind];
    if(st->errors)return 0;
    sprr_count(&st->map_calls);
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096) {
        sprr_count(&st->errors);return 0;
    }
    sprr_count(&st->map_complete);
    return (const volatile uint64_t *)pa;
}
static const volatile uint64_t *kernel_view_table_read(void *ctx,uint64_t pa)
{return view_table_read(ctx,pa,0);}
static const volatile uint64_t *user_view_table_read(void *ctx,uint64_t pa)
{return view_table_read(ctx,pa,1);}
#endif
#if SNAP_VIEW_STORE_COMPARE
static const volatile uint64_t *private_copy_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if(c->private_pages.errors || (pa&4095) || pa<c->work_base ||
       pa>=c->next_table || c->next_table-pa<4096)return 0;
    uint64_t index=(pa-c->work_base)/4096;
    if(index>=SPRR_PRIVATE_PAGES ||
       !(c->private_pages.bitmap[index/64]&(UINT64_C(1)<<(index%64))))return 0;
    /* Read-only comparison of allocated private storage. Changed words still
     * go through kernel_table_write/user_private_write and their publication,
     * ownership, break-before-make and epoch accounting. */
    return (const volatile uint64_t *)pa;
}
#endif
static int kernel_sync_view(struct context *c,const struct shadow *s,unsigned cpu,uint64_t pperm)
{
#if SNAP_VIEW_TABLE_READ
    struct view_table_read_stats *st=&c->view_table_reads[0];
    if(st->errors)return 0;
    sprr_count(&st->calls);st->tables+=c->kernel_views.count;
#if SNAP_VIEW_STORE_COMPARE
    int ok=sprr_views_sync_cpu_compared(&c->kernel_views,s,cpu,pperm,
        kernel_view_table_read,private_copy_table_read,&c->view_store_compare[0]);
#else
    int ok=sprr_views_sync_cpu_mapped(&c->kernel_views,s,cpu,pperm,kernel_view_table_read);
#endif
    if(!ok) {
        sprr_count(&st->errors);return 0;
    }
    sprr_count(&st->complete);return 1;
#else
    return sprr_views_sync_cpu(&c->kernel_views,s,cpu,pperm);
#endif
}
static int kernel_publish_cpu(struct context *c,unsigned cpu)
{
#if SNAP_KERNEL_DIRTY_PUBLISH
    struct sprr_publish_state *state=&c->kernel_publish_state;
    if(cpu>=GUEST_CPU_COUNT || !sprr_publish_prepare(state,&c->kernel_views)) {
        c->kernel_view_failed=1;return 0;
    }
    /* Publish children before parents, including newly allocated zero pages,
     * so a visible copied parent cannot expose an unpublished copied child. */
    for(unsigned level=4;level--;)for(unsigned n=0;n<c->kernel_views.count;n++) {
        if(c->kernel_views.tables[n].level!=level)continue;
        state->pages++;
        if(!sprr_publish_needed(state,cpu,n)) {state->skipped++;continue;}
        uint64_t pa=c->kernel_views.tables[n].copy[cpu];publish(pa,pa+4096);
        if(!sprr_publish_complete(state,cpu,n)) {c->kernel_view_failed=1;return 0;}
    }
    state->publishes++;
#else
    for(unsigned n=0;n<c->kernel_views.count;n++) {
        uint64_t pa=c->kernel_views.tables[n].copy[cpu];publish(pa,pa+4096);
    }
#endif
    return 1;
}
#if SNAP_TOKEN_TRIM
/* compat/token-trim.h part A, under the token. The words were just proven
 * equal to the snapshot (an exact hit or a completed save): every later note
 * of a copied source page stamps it with a clock above this one. */
static void token_trim_prove(struct context *c)
{
    struct token_trim_state *t=&c->root_ext->trim;
    t->proof=c->table_memo.clock;t->proven=1;
    if(t->stats.proofs!=UINT64_MAX)t->stats.proofs++;
}
/* sprr_reuse_match's answer: from the witness when it holds (counted as the
 * same hit), else exactly; every TOKEN_TRIM_SAMPLE-th witnessed answer is
 * also compared exactly and a disagreement is terminal (-1: the caller
 * latches kernel_view_failed). */
static int token_trim_match(struct context *c,struct sprr_reuse_state *reuse,
                            const struct shadow *s,const uint64_t *pp)
{
    struct token_trim_state *t=&c->root_ext->trim;
    t->stats.asks++;
    int w=token_trim_witness(reuse,&c->kernel_views,s,pp,&c->table_memo,t->proof,t->proven);
    if(w==1 && (++t->stats.witnessed&(TOKEN_TRIM_SAMPLE-1))) {
        reuse->calls++;reuse->hits++;return 1;
    }
    if(w==1)t->stats.sampled++;
    else if(w==-2)t->stats.stale++;
    else t->stats.unproven++;
    int match=sprr_reuse_match(reuse,&c->kernel_views,s,pp);
    if(w==1 && match!=1) {t->stats.mismatches++;t->proven=0;return -1;}
    if(match==1)token_trim_prove(c);
    return match;
}
#endif
static int kernel_refresh_impl(struct context *c)
{
    struct shadow s=kernel_shadow(c);
#if SNAP_KERNEL_VIEW_REUSE
    struct sprr_reuse_state *reuse=&c->kernel_reuse_state;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
#if SNAP_TOKEN_TRIM
    int match=token_trim_match(c,reuse,&s,pp);
#elif SNAP_REUSE_MATCH_MAPPED
    /* shadow/sprr-reuse.h: the same exact proof, each copied source table
     * read once through class_table_read (kernel_table_read's bound for the
     * whole page) instead of one callback per word. */
    int match=sprr_reuse_match_mapped(reuse,&c->kernel_views,&s,pp,class_table_read,c);
#else
    int match=sprr_reuse_match(reuse,&c->kernel_views,&s,pp);
#endif
    if(match<0) {c->kernel_view_failed=1;return 0;}
    if(match) {
        /* Differential read-only verification of one in 64 cache hits (one
         * in 1024 with SNAP_AUDIT_SPARSE). No bad copy is silently repaired by
         * the verification pass. */
        if(!(reuse->hits&AUDIT_SAMPLE_MASK)) {
#if SNAP_UPDATE_DISJOINT_FAST
            if(!sprr_views_verify_all(&c->kernel_views,&s,pp)) {
                reuse->mismatches++;reuse->valid=0;c->kernel_view_failed=1;return 0;
            }
#else
            for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
                if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,pp[cpu])) {
                    reuse->mismatches++;reuse->valid=0;c->kernel_view_failed=1;return 0;
                }
#endif
            reuse->verified++;
        }
        return 1;
    }
    reuse->valid=0;
#endif
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        if(!kernel_sync_view(c,&s,cpu,c->user_roots.sprr[cpu].pperm)) {
            c->kernel_view_failed=1;return 0;
        }
        if(!kernel_publish_cpu(c,cpu))return 0;
    }
#if SNAP_KERNEL_VIEW_REUSE
#if SNAP_TOKEN_TRIM
    /* The save overwrites the words: no proof until it completes. */
    c->root_ext->trim.proven=0;
#endif
    if(!sprr_reuse_save(reuse,&c->kernel_views,&s,pp)) {
        c->kernel_view_failed=1;return 0;
    }
#if SNAP_TOKEN_TRIM
    token_trim_prove(c);
#endif
#endif
    return 1;
}
static int kernel_refresh(struct context *c)
{
    int started=detail_begin(c,DETAIL_KERNEL_REFRESH);
    int result=kernel_refresh_impl(c);
    detail_end(c,DETAIL_KERNEL_REFRESH,started,result);return result;
}
static void shadow_tlb_sync(struct context *c)
{
    /* The canonical tree is never installed directly. Refresh every copied
     * kernel path before invalidating, including ordinary updates that land
     * beside a protected aperture leaf. */
    if(c->kernel_views.count && !kernel_refresh(c))return;
    /* Shared stage-1 updates affect every guest VMID. ALLE1IS broadcasts to
     * all EL1 regimes; VMALLE1IS would leave the other CPUs' VMIDs stale.
     * Stage-2 guard changes retain their current-VMID invalidation below.
     * Callers still require shared-service serialization before SMP entry. */
    __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
    c->shadow_tlb_syncs++;
}
#if SNAP_VIEW_RECLAIM
/* sprr_views_reclaim's quiesce. The reuse snapshot and the publication rows
 * name tables by position, which just moved: drop both, then shadow_tlb_sync
 * syncs all six views in full (a retired table's parent entries name its
 * canonical source again), publishes every remaining copy and completes the
 * all-VMID TLBI. After that no walk, cached or new, reaches a retired page.
 * The variant columns need nothing: the refresh's save makes them inexact. */
static int kernel_views_quiesce(void *ctx)
{
    struct context *c=ctx;
#if SNAP_KERNEL_VIEW_REUSE
    sprr_reuse_invalidate(&c->kernel_reuse_state);
#endif
#if SNAP_KERNEL_DIRTY_PUBLISH
    sprr_publish_reset(&c->kernel_publish_state);
#endif
    shadow_tlb_sync(c);
    return !c->kernel_view_failed;
}
/* The private paths of every leaf a protecting retype changes, before its
 * first detach (the callers' shadow_tlb_sync). A full pool refuses with no
 * change; then the copies no protected leaf needs are retired and the whole
 * change is prepared again from its first leaf: the reclaim retires any path
 * an earlier leaf of this change prepared, since that leaf is not protected
 * until the commit. A second refusal (nothing to retire) fails the retype as
 * before. */
static int kernel_views_prepare_change(struct context *c,const struct sptm_papt_change *change)
{
    struct sprr_views *v=&c->kernel_views;struct kernel_view_reclaim *r=&c->kernel_view_reclaim;
    struct shadow s=kernel_shadow(c);
    for(int again=0;;again=1) {
        unsigned i=0;
        while(i<change->count && sprr_views_prepare(v,&s,change->leaf[i].va))i++;
        if(i==change->count) {
            if(r->high_water<v->count)r->high_water=v->count;
            return 1;
        }
        if(again || v->count+3<=SPRR_VIEW_TABLES)return 0;
        int retired=sprr_views_reclaim(v,&s,kernel_views_quiesce,c);
        if(retired<=0) {r->full+=!retired;return 0;}
        r->reclaims++;r->retired+=(unsigned)retired;
    }
}
#endif
#if SNAP_USER_UPDATE_KERNEL_SKIP
/* User-root UPDATE_DISJOINT: sptm_mac_update_user_disjoint reaches only the
 * user backend (user canonical shadow, user private copies, guest PTE memory
 * and SPTM metadata) and never PPERM or a kernel canonical table. The kernel
 * sources and all six kernel copies are exactly as the previous transaction
 * left them (current: every kernel/PPERM mutation refreshes before returning,
 * the contract the qualified user-only TLBI commits already rely on), so the
 * refresh would store nothing. Publication and the all-VMID TLBI remain. Every
 * 64th skip regenerates all six kernel views read-only; a stale copy is
 * terminal, exactly like a failed refresh, and is never repaired. */
static void user_update_kernel_skip(struct context *c)
{
    struct user_update_skip_stats *k=&c->user_update_skip;
#if SNAP_UPDATE_CHECK_SPARSE
    if(!(++k->skipped&1023) && c->kernel_views.count) {
#else
    if(!(++k->skipped&63) && c->kernel_views.count) {
#endif
        struct shadow s=kernel_shadow(c);
#if SNAP_UPDATE_DISJOINT_FAST
        uint64_t pp[GUEST_CPU_COUNT];
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)pp[cpu]=c->user_roots.sprr[cpu].pperm;
        if(!sprr_views_verify_all(&c->kernel_views,&s,pp)) {
            k->mismatches++;c->kernel_view_failed=1;return;
        }
#else
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
            if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,c->user_roots.sprr[cpu].pperm)) {
                k->mismatches++;c->kernel_view_failed=1;return;
            }
#endif
        k->verified++;
    }
#if SNAP_NATIVE_TABLES
    /* Each changed leaf's user_commit_update already invalidated its own 4K
     * entries in every VMID, after both its canonical and variant stores were
     * cleaned; no other hardware-walked table changed. */
#else
    __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
    c->shadow_tlb_syncs++;
#endif
}
#endif

static int pperm_tpro_preflight(struct context *,struct sprr_pperm_update_state *,int);
static int user_refresh_pperm(struct context *,uint64_t);
#if SNAP_KERNEL_PPERM_VARIANTS
/* Cleaned when allocated: an exact swap installs a variant page without a
 * store, and a synced swap may leave words of it zero. */
static uint64_t kernel_variant_alloc(void *ctx)
{
    uint64_t pa=private_kernel_alloc(ctx);
    if(pa)publish(pa,pa+4096);
    return pa;
}
/* A bit-8 flip that began with the snapshot current: exchange this CPU's
 * kernel column with its variant column. 2: swapped, and the new column is
 * already its translation under pperm; 1: swapped, the new column still needs
 * its sync; 0: not swapped (the in-place path runs); -1: terminal. */
static int kernel_variant_swap(struct context *c,const struct shadow *s,unsigned cpu,
                               uint64_t before,uint64_t pperm)
{
    struct sprr_view_variants *a=&c->kernel_variants;
    int exact=sprr_variants_exact(a,&c->kernel_views,&c->kernel_reuse_state,cpu,pperm);
    if(!exact) {
        struct shadow vs=*s;vs.alloc=kernel_variant_alloc;
        if(!sprr_variants_reserve(a,&c->kernel_views,&vs,cpu)) {a->fallbacks++;return 0;}
    }
    if(!sprr_variants_swap(a,&c->kernel_views,&c->kernel_publish_state,cpu,before,
                           c->kernel_reuse_state.saves)) {a->fallbacks++;return 0;}
    if(!exact) {a->synced++;return 1;}
    /* The first and then one in 64 exact swaps (one in 1024 with
     * SNAP_AUDIT_SPARSE) regenerate the new column read-only and compare it;
     * a discrepancy is terminal, never repaired. */
    if(!(a->exact++&AUDIT_SAMPLE_MASK)) {
        if(!sprr_views_verify_cpu(&c->kernel_views,s,cpu,pperm)) {
            a->mismatches++;c->kernel_view_failed=1;return -1;
        }
        a->verified++;
    }
    return 2;
}
#endif
/* invalidate=0 only from root installation, whose final all-VMID TLBI follows
 * every store made here (this CPU's own kernel/user copies) before the CPU can
 * execute EL1/EL0 again; see user_root_install. */
static int kernel_change_pperm_impl(struct context *c,uint64_t pperm,int invalidate)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
#if SNAP_KERNEL_VIEW_REUSE
#if SNAP_KERNEL_PPERM_REUSE
    /* Exact pre-transaction proof, taken before any private write: every copied
     * kernel view equals the saved translation of the CURRENT canonical words
     * under the current six PPERMs. Anything else (including a read failure)
     * takes the unchanged path below, which repeats the same reads. */
    struct kernel_pperm_reuse_stats *kr=&c->kernel_pperm_reuse;
    uint64_t pp[GUEST_CPU_COUNT];
    for(unsigned n=0;n<GUEST_CPU_COUNT;n++)pp[n]=c->user_roots.sprr[n].pperm;
    struct shadow ks=kernel_shadow(c);
#if SNAP_NATIVE_TABLES
    int current=c->kernel_views.count && native_reuse_current(c,&ks,pp);
    if(c->kernel_view_failed)return 0;
#else
    int current=c->kernel_views.count &&
        sprr_reuse_current(&c->kernel_reuse_state,&c->kernel_views,&ks,pp)==1;
#endif
    kr->calls++;if(current)kr->current++;
#endif
    /* The only writer outside full refresh; invalidate before changing even
     * one private copy, including transactions whose later user sync fails. */
    sprr_reuse_invalidate(&c->kernel_reuse_state);
#endif
    uint64_t before=c->user_roots.sprr[cpu].pperm;
    int tpro=!!((before^pperm)&SPRR_UPERM_TPRO_WRITE);
    struct sprr_pperm_update_state proof={0};
#if SNAP_NATIVE_TABLES
    /* Audit mode: the canonical user-view proof runs on a CPU's first TPRO
     * change and then sampled, the record keeping the last one. The kernel
     * class proof (cached; hits are cheap) still runs on every change. */
    if(tpro) {
        const struct sprr_pperm_update_state *last=&c->sprr_pperm_update[cpu];
        int user_proof=!last->user_root || native_due(&c->native_stats.proof_asks);
        if(!user_proof) {proof=*last;c->native_stats.proof_skips++;}
        if(!pperm_tpro_preflight(c,&proof,user_proof))return 0;
    }
#else
    if(tpro && !pperm_tpro_preflight(c,&proof,1))return 0;
#endif
    struct shadow s=kernel_shadow(c);
    int skip=0,swap=0;
#if SNAP_KERNEL_PPERM_REUSE
    /* A kernel copy decodes PPERM only through SPRR_KERNEL_VIEW_PPERM
     * (entry_decode, user==NULL). With the snapshot current and that bit
     * unchanged, this CPU's copy already equals its translation under pperm:
     * the compared sync would pass the same preflight and store nothing, and
     * with no pending bit for this CPU the publish loop would clean nothing. */
    const struct sprr_publish_state *ps=&c->kernel_publish_state;
    skip=current && !((before^pperm)&SPRR_KERNEL_VIEW_PPERM) &&
        ps->root==c->kernel_views.canonical_root && ps->count==c->kernel_views.count &&
        sprr_publish_row_empty(ps,cpu);
#if SNAP_KERNEL_PPERM_VARIANTS
    if(!skip && current && ((before^pperm)&SPRR_KERNEL_VIEW_PPERM) &&
       (swap=kernel_variant_swap(c,&s,cpu,before,pperm))<0)return 0;
#endif
    if(skip) {
        /* One in 64 skipped views (one in 1024 with SNAP_AUDIT_SPARSE) is
         * regenerated and compared read-only; a discrepancy is terminal and
         * never repaired. */
        if(!(++kr->skipped&AUDIT_SAMPLE_MASK)) {
            if(!sprr_views_verify_cpu(&c->kernel_views,&s,cpu,pperm)) {
                kr->mismatches++;c->kernel_view_failed=1;return 0;
            }
            kr->verified++;
        }
    } else
#endif
    if(swap!=2 && !kernel_sync_view(c,&s,cpu,pperm)) {
        c->kernel_view_failed=1;return 0;
    }
    if(!user_refresh_pperm(c,pperm))return 0;
    if(!skip && !kernel_publish_cpu(c,cpu))return 0;
#if SNAP_KERNEL_PPERM_VARIANTS
    /* The new column is published; its root is installed before the
     * invalidation below (or, for invalidate=0, the root installation's
     * all-VMID TLBI). Kernel entries are global: the TLBI is what removes
     * the old column's. */
    if(swap) {
        uint64_t root=sprr_views_root(&c->kernel_views,cpu);
        __asm__ volatile("msr ttbr1_el1, %0; isb" :: "r"(root) : "memory");
        c->kernel_installed[cpu]=root;
    }
#endif
    if(invalidate) {
#if SNAP_NATIVE_TABLES
        /* Only this CPU walks its private kernel copy, and a user variant
         * changes by TTBR0 alone: nothing to invalidate when the copy is
         * provably unchanged (skip), else this CPU's own TLB, locally. */
        if(!skip) {
            __asm__ volatile("dsb ishst; tlbi vmalle1; dsb nsh; isb" ::: "memory");
            c->native_stats.pperm_flushes++;c->shadow_tlb_syncs++;
        }
#else
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        c->shadow_tlb_syncs++;
#endif
    }
    if(before!=pperm)c->kernel_permission_changes++;
    if(tpro) {
        struct sprr_pperm_update_state *u=&c->sprr_pperm_update[cpu];
        proof.transactions=u->transactions+1;
        proof.grants=u->grants+!!(pperm&SPRR_UPERM_TPRO_WRITE);
        proof.restores=u->restores+!(pperm&SPRR_UPERM_TPRO_WRITE);
        proof.before=before;proof.after=pperm;
        __asm__ volatile("mrs %0, elr_el2":"=r"(proof.pc));
        *u=proof;
    }
#if SNAP_KERNEL_PPERM_REUSE
    /* Neither the TPRO preflight (read-only) nor the user sync (user copies and
     * fresh user-owned pages only) changed a canonical kernel word or view
     * identity; only this CPU's copy was (re)written for pperm. The snapshot
     * describes all six copies exactly again. */
    if(current) {
        if(!skip)kr->synced++;
        if(!(swap ? sprr_variants_repin(&c->kernel_reuse_state,&c->kernel_views,cpu,pperm) :
                    sprr_reuse_repin(&c->kernel_reuse_state,&c->kernel_views,cpu,pperm))) {
            kr->errors++;c->kernel_view_failed=1;return 0;
        }
        kr->repinned++;
    }
#endif
    return 1;
}
static int kernel_change_pperm_timed(struct context *c,uint64_t pperm,int invalidate)
{
    int started=detail_begin(c,DETAIL_KERNEL_PPERM);
    int result=kernel_change_pperm_impl(c,pperm,invalidate);
    detail_end(c,DETAIL_KERNEL_PPERM,started,result);return result;
}
static int kernel_change_pperm(void *ctx,uint64_t pperm)
{return kernel_change_pperm_timed(ctx,pperm,1);}

static int vcpu_root_busy(struct context *c, uint64_t root)
{
    struct guest_cpu_address_space spaces[GUEST_CPU_COUNT];
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        spaces[cpu] = (struct guest_cpu_address_space){c->vcpus[cpu].guest_ttbr0,
                                                     c->vcpus[cpu].guest_ttbr1};
    c->root_checks++;
    int busy = guest_cpu_root_busy(spaces, root);
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)busy|=c->user_roots.active[cpu]==root;
    if (busy) c->root_busy_refusals++;
    return busy;
}

static volatile uint8_t *sptm_map(void *ctx, uint64_t pa, uint64_t size)
{
    const struct params *p = ((struct context *)ctx)->params;
    if (pa < p->mem_low || pa >= p->mem_high || size > p->mem_high - pa)
        return 0;
    return (volatile uint8_t *)pa;
}

static void sptm_publish(void *ctx, uint64_t pa, uint64_t size)
{
#if SNAP_DART_MEMO
    /* The DART memo's write witness (compat/sptm-dart-memo.h). */
    if (((struct context *)ctx)->root_ext)
        sptm_dart_memo_publish(&((struct context *)ctx)->root_ext->dart_memo, pa, size);
#endif
#if SNAP_ROOT_VALIDATE_MEMO
    /* Every SPTM store to guest tables or frame records is published here
     * (compat/sptm.h map/publish contract): the memo's write witness. */
    struct context *c=ctx;const struct params *p=c->params;
    sptm_root_memo_publish(&c->root_memo,p->frame_map_pa,p->frame_low,p->frame_high,
                           sptm_map,c,pa,size);
#else
    (void)ctx;
#endif
    publish(pa, pa + size);
}

/* memory.clean_frame (compat/sptm.h): a frame whose SH/AttrIndx is about to
 * change is cleaned and invalidated to PoC through EL2's identity map of guest
 * RAM before any new descriptor is stored, and again by attr_clean_finish
 * once the transaction's TLBI has retired every translation that could still
 * allocate its lines with the old attributes. Maintenance by address reaches
 * the physical lines whichever alias allocated them. */
static int sptm_attr_clean(void *ctx,uint64_t pa,uint64_t size)
{
    struct context *c=ctx;const struct params *p=c->params;
    struct attr_update_state *s=&c->attr_updates;
    if(size!=0x4000 || (pa&0x3fff) || pa<p->mem_low || pa>=p->mem_high ||
       size>p->mem_high-pa || s->pending>=SPTM_DISJOINT_MAX) {
        s->refused++;return 0;
    }
    publish(pa,pa+size);
    s->pending_pa[s->pending++]=pa;s->cleans++;
    return 1;
}
static void attr_clean_finish(struct context *c)
{
    struct attr_update_state *s=&c->attr_updates;
#if SNAP_ATTR_CLEAN_DEFER
    /* agents/nvme-async D1-D6: this second clean (after the TLBI) moves to
     * attr_clean_flush, after the token is released and before this vCPU
     * resumes; the first one, before the store, stays. Counted here, under the
     * token, as before; past ATTR_DEFER_MAX it cleans inline. */
    struct attr_defer_cpu *d=&c->root_ext->attr_defer[vcpu_of(c)->slot];
    for(uint64_t n=0;n<s->pending && n<SPTM_DISJOINT_MAX;n++) {
        if(d->count<ATTR_DEFER_MAX) {d->pa[d->count++]=s->pending_pa[n];d->deferred++;}
        else {publish(s->pending_pa[n],s->pending_pa[n]+0x4000);d->overflow++;}
        s->recleans++;
    }
    s->pending=0;
    return;
#endif
    for(uint64_t n=0;n<s->pending && n<SPTM_DISJOINT_MAX;n++) {
        publish(s->pending_pa[n],s->pending_pa[n]+0x4000);s->recleans++;
    }
    s->pending=0;
}
#if SNAP_ATTR_CLEAN_DEFER
/* xnuboot_trap, after runtime_leave: this vCPU's deferred second cleans, by VA
 * through EL2's identity map of guest RAM (data-preserving: no lock), one
 * barrier at the end, before the guest resumes (D1, D3). */
static void attr_clean_flush(struct context *c)
{
    struct attr_defer_cpu *d=&c->root_ext->attr_defer[vcpu_of(c)->slot];
    if(!d->count)return;
    for(uint64_t n=0;n<d->count;n++)
        for(uint64_t line=d->pa[n];line<d->pa[n]+0x4000;line+=64)
            __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    d->flushed+=d->count;d->count=0;
}
#endif

static volatile uint8_t *sptm_shadow_map(void *ctx,uint64_t pa,uint64_t size)
{
    struct context *c=ctx;
    if (pa<c->work_base || pa>=c->next_table || size>c->next_table-pa) return 0;
#if SNAP_INCREMENTAL_PUBLISH
    if(size && !root_index_note(&c->root_publish,&c->perf.root_index,c->work_base,
                                c->next_table,pa,size))return 0;
#elif SNAP_ROOT_DIRTY_PUBLISH
    if(size && !root_publish_note(&c->root_publish,c->work_base,c->next_table,pa,size))return 0;
#endif
#if SNAP_TXN_DIRTY_PUBLISH
    txn_publish_observe(&c->txn_publish,pa,size);
#endif
#if SNAP_USER_TREE_MEMO
    /* The caller may store through this pointer without mem_write. Kernel
     * update backends never reach a user view refresh before those stores,
     * so noting every mapped page now is conservative and complete. */
    for(uint64_t page=pa&~4095UL;size && page<pa+size;page+=4096)
        sprr_table_memo_note(&c->table_memo,page);
#endif
    return (volatile uint8_t *)pa;
}

/* UPDATE_REGION/DISJOINT, SLIDE_REGION and the two aperture commits hold
 * mapped canonical pointers and write bytes directly. Invalidate before
 * entering those transactions; no class proof is renewed before commit.
 * Their existing publication, private-view refresh and TLBI remain intact. */
static void kernel_class_proof_forget(struct context *c)
{
#if SNAP_KERNEL_CLASS_PROOF
    sprr_class_proof_forget(&c->kernel_class_proof);
#else
    (void)c;
#endif
}

#if SNAP_TXN_DIRTY_PUBLISH
/* guard_write stores and cleans stage-2 guard descriptors directly, without a
 * dirty note. Such pages are published by that path and are never armed as a
 * coverage sentinel. Guards are only added while building stage 2. */
static int txn_publish_exclude(void *ctx,uint64_t page)
{
    struct context *c=ctx;
    if(c->thermal && page==(uint64_t)c->thermal)return 1;
#if SNAP_ROOT_CACHE_WIDE
    /* Monitor-only state stored without a note: no translation table, never
     * published, never a coverage sentinel (compat/root-wide.h W6). */
    if(page>=(uint64_t)c->root_ext && page-(uint64_t)c->root_ext<ROOT_EXT_PAGES*4096)return 1;
#endif
#if SNAP_TXM_ASPACE_WIDE
    /* The TXM registry, stored the same way (compat/txm.h A4). */
    if(page>=(uint64_t)TXM_REG(c) && page-(uint64_t)TXM_REG(c)<TXM_EXT_PAGES*4096)return 1;
#endif
#if SNAP_USER_HW_WALK
    /* The hardware-walk records, index and counters, stored the same way
     * (compat/user-hw-walk.h). Its copy pages are pool tables: noted. */
    if(page>=(uint64_t)c->hw_walk && page-(uint64_t)c->hw_walk<HW_WALK_PAGES*4096)return 1;
#endif
#if SNAP_S2_FAULT_RETRY
    /* The retry snapshot page, stored the same way (compat/s2-fault-retry.h). */
    if(page>=(uint64_t)c->s2_retry && page-(uint64_t)c->s2_retry<S2_RETRY_PAGES*4096)return 1;
#endif
#if SNAP_GUEST_NET
    /* The guest-network state, stored the same way (compat/guest-net-link.h). */
    if(page>=(uint64_t)c->guest_net && page-(uint64_t)c->guest_net<GUEST_NET_STATE_PAGES*4096)return 1;
#endif
#if SNAP_EDP_BACKLIGHT
    /* ADRENO_GUEST_BACKLIGHT's state page, stored the same way (compat/edp-backlight.h). */
    if(page==(uint64_t)c->edp_backlight)return 1;
#endif
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        for(uint64_t g=0;g<c->vcpus[cpu].guard_count;g++)
            if((c->vcpus[cpu].guards[g].slot&~UINT64_C(4095))==page)return 1;
    return 0;
}
#endif
/* Runtime transaction end: previously dc civac over every allocated arena
 * line. Called after the transaction's last table store and before its TLBI.
 * Failure (tracking error or a sentinel store the bitmap missed) is terminal. */
static int transaction_publish(struct context *c)
{
#if SNAP_TXN_DIRTY_PUBLISH
#if SNAP_INCREMENTAL_PUBLISH
    int ok=txn_index_flush(&c->root_publish,&c->perf.root_index,&c->txn_publish,
                           c->work_base,c->next_table,publish_page_lines,txn_publish_exclude,c);
#else
    int ok=txn_publish_flush(&c->root_publish,&c->txn_publish,c->work_base,c->next_table,
                             publish_page_lines,txn_publish_exclude,c);
#endif
    __asm__ volatile("dsb ish" ::: "memory");
    return ok;
#else
    publish(c->work_base,c->next_table);return 1;
#endif
}

static int sptm_admit_iommu(void *ctx, unsigned iommu_class, unsigned device_id,
                           unsigned sid, unsigned level)
{
    struct context *c=ctx;
    return device_dart_admit_frame(c->params->models,c->model_state,
        c->params->model_count,iommu_class,device_id,sid,level,0)==DEVICE_OK;
}

static int gfx_power_idle(void *ctx)
{
    struct context *c=ctx;
    const struct params *p=c->params;
    struct sptm_aperture aperture={p->mem_low,p->ram_aperture_va,p->mem_high-p->mem_low};
    struct sptm_memory memory={.map=sptm_map,.ctx=c};
    /* Only UAT information queries are accepted by table 7. Graphics
     * mappings, commands and ASC execution remain unsupported. Preserve
     * the reserved pages; the runtime service lock holds them stable. */
    return uat_power_idle(&p->uat,&aperture,&memory)==SPTM_OK;
}

static int sptm_retype_user_tpro(void *,uint64_t,uint64_t,uint64_t);
static struct sptm_moved xnu_moved(const struct context *);
/* AppleSEPFirmware::releaseFirmware (0xfffffe00099c3904) frees the SEPFW
 * extent through ml_static_mfree (0xfffffe000ba89dd0) once the SEP is up.
 * That routine retypes only frames whose type is not XNU_DEFAULT, and every
 * frame here is 0x0b, so the release makes no monitor call: the first sign of
 * it is an ordinary MAP_PAGE or RETYPE of one of those frames. The firmware is
 * dead from the ROM's bootstrap handoff on, so that is when XNU owns it. */
static uint64_t sep_firmware_released(const struct context *c)
{
    const struct params *p=c->params;
    if (!p->sep_firmware_size) return 0;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 && p->models[i].config[4])
            return c->model_state[i].sep_asc.service_ready!=0;
    return 0;
}

static struct sptm_memory sptm_context_memory(struct context *c)
{
    const struct params *p=c->params;
    return (struct sptm_memory){.frame_map_pa=p->frame_map_pa,
        .frame_low=p->frame_low,.frame_high=p->frame_high,
        .alloc_low=p->alloc_low,.alloc_high=p->alloc_high,
        .map=sptm_map,.publish=sptm_publish,.ctx=c,
        .aperture_va=p->ram_aperture_va,.aperture_size=p->alloc_high-p->mem_low,
        .refs=&c->references,.boot_ranges=p->slide.regions,.boot_count=p->slide.count,
        .shared_regions=&c->shared_regions,.retype_user_tpro=sptm_retype_user_tpro,
        .boot_aliases=c->slide.count ? c->slide.regions : p->slide.regions,
        .boot_alias_count=c->slide.count ? c->slide.count : p->slide.count,
        .sep_firmware_pa=p->sep_firmware_pa,.sep_firmware_size=p->sep_firmware_size,
        .sep_firmware_released=sep_firmware_released(c),
        /* The panel is plain firmware memory behind stage 2, not a modeled
         * device: IOFramebufferUserClient maps it into WindowServer. It is
         * admitted only wholly outside guest RAM and every monitor range. */
        .user_io_pa=p->fb_span && (p->fb_pa>=p->mem_high ||
            (p->fb_span<=p->mem_low && p->fb_pa<=p->mem_low-p->fb_span)) ? p->fb_pa : 0,
        .user_io_size=p->fb_span && (p->fb_pa>=p->mem_high ||
            (p->fb_span<=p->mem_low && p->fb_pa<=p->mem_low-p->fb_span)) ? p->fb_span : 0,
        .audit=&c->pv_audit,.root_memo=SNAP_ROOT_VALIDATE_MEMO ? &c->root_memo : 0,
        .clean_frame=sptm_attr_clean
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
        ,.nest_fast=&c->root_ext->nest_fast
#endif
#if SNAP_DART_MEMO
        ,.dart_memo=&c->root_ext->dart_memo
#endif
#if SNAP_ROOT_INDEX
        ,.root_index=&c->root_ext->root_index
#endif
        };
}
