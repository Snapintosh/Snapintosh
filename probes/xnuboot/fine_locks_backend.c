/* SPDX-License-Identifier: MIT */
/* SNAP_FINE_LOCKS, first block: lock helpers and the converted user
 * backend.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_FINE_LOCKS
/* ---- SNAP_FINE_LOCKS: converted user address-space calls -----------------
 * docs/FINE-LOCKS-20261017.md; compat/fine-lock.h has the lock levels.
 * A converted call is a native SPTM call (MAP_PAGE, UNMAP_REGION,
 * UPDATE_DISJOINT; SWITCH_ROOT cache hits with SNAP_FINE_SWITCH; the user
 * pointer-authentication calls, which name no root, with
 * SNAP_FAST_PAUTH_CALLS) that runs with the gate shared and its roots'
 * stripes held instead of the token. The
 * code below repeats the locked path's statements for that call (the native
 * call entry of xnuboot_trap_locked, monitor_request, monitor_call,
 * monitor_call_impl, the endpoint's case and its backend callbacks), with
 * three differences, each argued in the note:
 *  - global words the locked path writes are written atomically (counters,
 *    tracker bits, the memo clock, epochs), or under aux (the event log, the
 *    SWITCH_ROOT memo, the kernel class proof);
 *  - classification declines, with nothing changed, wherever the call would
 *    leave the converted envelope; the locked path then repeats the call;
 *  - the call's own stores are published at the store (live writes), so it
 *    runs no transaction_publish: no global flush, no runtime-page clean.
 * Frame types, cache identity and validity, root activity (without
 * SNAP_FINE_SWITCH), the arena and the kernel and shared-region state are
 * written only on the token path, so they are read here as constants. */
#if !SNAP_ROOT_CACHE_WIDE || !SNAP_NATIVE_TABLES || !SNAP_NATIVE_SHARED || !SNAP_NATIVE_CALLS || \
    !SNAP_USER_VIEW_CACHE || !SNAP_PRIVATE_VIEW_EPOCH || !SNAP_KERNEL_CLASS_PROOF || \
    !SNAP_ROOT_DIRTY_PUBLISH || !SNAP_TXN_DIRTY_PUBLISH || !SNAP_USER_TREE_MEMO || \
    !SNAP_USER_ONLY_TLBI || !SNAP_USER_UPDATE_KERNEL_SKIP || !SNAP_UPDATE_DISJOINT_FAST || \
    !SNAP_FAST_VCPU_TRAPS || SNAP_INCREMENTAL_PUBLISH || SNAP_STEP_ALU || !SNAP_SERVICE_DETAIL
#error "SNAP_FINE_LOCKS is written for the installed-fresh fast flag set (see docs/FINE-LOCKS-20261017.md)"
#endif
static struct fine_state *fine_of(struct context *c) {return &c->root_ext->fine;}
static struct fine_cpu *fine_cpu(struct context *c) {return &c->root_ext->fine.cpu[vcpu_of(c)->slot];}
#if SNAP_USER_HW_WALK
/* compat/user-hw-walk.h under fine locks (docs/USER-HW-WALK-20261017.md,
 * "Fine locks"). Every piece of hardware-walk state is token-path state: the
 * record index and records (attach in SWITCH_ROOT, detach in CONFIGURE,
 * RETIRE and SHARE), the copy pages (allocated and released only there and
 * in the hw_* backend callbacks), every copy store, the hw_walk_stats
 * counters and the stage-2 table protection (RETYPE). None is reached from a
 * converted call, so none needs a stripe, aux or an atomic: a converted call
 * naming a root that has a record declines with FINE_NO_ROOT, before any
 * stripe is taken, and the locked path runs the hw_* callbacks (an inactive
 * hardware-walk root would otherwise pass fine_user_backend uncached and its
 * TPRO copies would keep a leaf XNU removed). The lookup is a read of the
 * index, which only a token holder writes: with the gate shared it cannot
 * change. A converted switch whose target has a record declines (it is not
 * a cache hit: SWITCH_ROOT never caches a root with a record). A converted
 * switch from such a root to the kernel or to a cached root stays converted:
 * the token path runs no hardware-walk code for it either (sptm_mac_switch_root
 * consults hw_eligible only for its target) and the per-CPU words
 * hw_install_user set are the ones fine_user_root_install rewrites. */
#define FINE_HW_ROOT(c,root) (hw_root((c),(root))!=0)
#endif
#if SNAP_FINE_HW && !SNAP_USER_HW_WALK
#error "SNAP_FINE_HW requires SNAP_USER_HW_WALK"
#endif
#if SNAP_FINE_SWITCH_HW && !SNAP_USER_HW_WALK
#error "SNAP_FINE_SWITCH_HW requires SNAP_USER_HW_WALK"
#endif
/* The latched failures runtime_leave stops on; set elsewhere with plain
 * stores on the token path, read here atomically. */
static uint64_t fine_failed(const struct context *c)
{
    return __atomic_load_n(&c->kernel_view_failed,__ATOMIC_RELAXED) |
           __atomic_load_n(&c->user_view_failed,__ATOMIC_RELAXED) |
           __atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED);
}
static void fine_view_failed(struct context *c) {__atomic_store_n(&c->user_view_failed,1,__ATOMIC_RELAXED);}
static void fine_aux_lock(struct context *c)
{
    struct fine_cpu *f=fine_cpu(c);
    uint64_t start=service_profile_clock();
    if(fine_ticket_lock(&fine_of(c)->aux)) {
        f->profile.aux_contended++;f->aux_wait+=service_profile_clock()-start;
    }
    f->profile.aux_entries++;
}
static void fine_aux_unlock(struct context *c) {fine_ticket_unlock(&fine_of(c)->aux);}

/* native_due, native_tlbi_range, native_store_admit, user_private_write,
 * kernel_table_write, native_copy_write, native_live_shadow,
 * native_store_propagate, mem_write, user_live_write, in that order. */
static int fine_native_due(uint64_t *asks)
{return !(__atomic_fetch_add(asks,1,__ATOMIC_RELAXED)&((UINT64_C(1)<<SNAP_NATIVE_AUDIT_SHIFT)-1));}
static void fine_native_tlbi_range(struct context *c,uint64_t va,uint64_t size)
{
    uint64_t first=va>>12,pages=(size+4095)>>12,saved;
    int all=!pages || pages>NATIVE_TLBI_PAGES;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ishst" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(vcpu_vttbr(&c->vcpus[cpu])) : "memory");
        if(all)__asm__ volatile("tlbi vmalle1is" ::: "memory");
        else for(uint64_t n=0;n<pages;n++)
            __asm__ volatile("tlbi vaae1is, %0" :: "r"((first+n)&((UINT64_C(1)<<44)-1)) : "memory");
    }
    __asm__ volatile("dsb ish; msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    fine_add(&c->native_stats.tlbi_calls,1);
    if(all)fine_add(&c->native_stats.tlbi_full,1);else fine_add(&c->native_stats.tlbi_pages,pages);
    fine_add(&c->shadow_tlb_syncs,1);
}
static int fine_native_store_admit(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i))return 0;
    if(c->table_pool.owner[i]==NATIVE_SHARED_OWNER && (value&1) && sprr_pte_class(value)==9) {
        fine_add(&c->native_stats.refused,1);fine_view_failed(c);return 1;
    }
    int source=native_source(c,i);
    if(!source && (!(value&1) || sprr_pte_class(value)!=9))return 0;
    unsigned owner=c->table_pool.owner[i];
    const struct sprr_views *v=owner && owner<=SPTM_ROOT_CACHE ? &UVIEWS(c)[owner-1] : 0;
    if(!source && (!v || !v->count))return 0;
    if(source && v && v->count &&
       native_views_admit(v,pa,value,native_umprr(&c->user_roots.cache[owner-1])))return 0;
    fine_add(&c->native_stats.refused,1);fine_view_failed(c);return 1;
}
static int fine_mem_write(void *ctx,uint64_t pa,uint64_t value);
/* kernel_table_write without its kernel-copy publication note: a converted
 * call writes only pages its root's slot owns, never a kernel copy, and the
 * note's preparation only marks newly grown kernel copies, which
 * kernel_publish_cpu prepares again before it publishes anything. */
static int fine_kernel_table_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<8)return -1;
    if(*(volatile uint64_t *)pa==value)return 0;
    uint64_t i;unsigned owner=native_page(c,pa,&i) ? c->table_pool.owner[i] : 0;
    if(!owner || owner>SPTM_ROOT_CACHE) {fine_view_failed(c);return -1;}
    return fine_mem_write(ctx,pa,value);
}
static int fine_user_private_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;uint64_t old;
    if(kernel_table_read(c,pa,&old))return -1;
    if(old==value)return 0;
    if((old&1) && (value&1) && ((old^value)&PT_OA_MASK)) {
        if(fine_kernel_table_write(c,pa,0))return -1;
        publish(pa,pa+8);
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        fine_add(&c->shadow_tlb_syncs,1);
    }
    return fine_kernel_table_write(c,pa,value);
}
static int fine_native_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=fine_user_private_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
/* The converted call's allocator: refuses, so a shadow path that would need
 * a table fails preflight before any store and the call declines. */
static uint64_t fine_refuse_alloc(void *ctx)
{
    const struct user_table_owner *owner=ctx;
    fine_cpu(owner->context)->alloc_refused=1;return 0;
}
static struct shadow fine_native_live_shadow(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_view_shadow(c,e);
    s.alloc=fine_refuse_alloc;s.write=fine_native_copy_write;return s;
}
static int fine_native_store_propagate(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i) || !native_source(c,i))return 0;
    unsigned owner=c->table_pool.owner[i];
    if(!owner || owner>SPTM_ROOT_CACHE) {fine_view_failed(c);return 1;}
    struct sptm_root_cached *e=&c->user_roots.cache[owner-1];
    struct shadow s=fine_native_live_shadow(c,e);
    if(!native_views_store(&UVIEWS(c)[owner-1],&s,pa,value,native_umprr(e))) {
        fine_view_failed(c);return 1;
    }
    fine_add(&c->native_stats.propagated,1);return 0;
}
static int fine_mem_write(void *ctx,uint64_t pa,uint64_t value)
{
    if ((pa & 7UL) || !ctx)
        return -1;
    struct context *c=ctx;
    if (c->work_start && pa + 8UL > c->work_start && pa < (c->work_base ? c->work_base : c->work_end))
        return -1;
    int in_dram = c->params && (pa >= c->params->mem_low && pa <= c->params->mem_high - 8UL);
    int in_shadow = c->work_base && (pa >= c->work_base && pa <= (c->next_table ? c->next_table : c->work_end) - 8UL);
    if (!in_dram && !in_shadow)
        return -1;
    if(fine_native_store_admit(c,pa,value))return -1;
    if(pa>=c->work_base && pa<c->next_table && c->next_table-pa>=8 &&
       *(volatile uint64_t *)pa!=value) {
        sprr_table_memo_note_fine(&c->table_memo,pa);
        if(!root_publish_note_fine(&c->root_publish,c->work_base,c->next_table,pa,8))return -1;
        txn_publish_observe_fine(&c->txn_publish,pa,8);
        int private=sprr_private_write_fine(&c->private_pages,c->work_base,c->next_table,pa);
        if(private<0)return -1;
        if(!private)sprr_view_epoch_advance_fine(&c->user_view_epoch);
        /* Kernel tables only: never one of a user root's pages. */
        if(sprr_class_proof_tracked(&c->kernel_class_proof,pa)) {
            fine_aux_lock(c);sprr_class_proof_note(&c->kernel_class_proof,pa);fine_aux_unlock(c);
        }
    }
    fine_cpu(c)->stores++;
    *(volatile uint64_t *)pa = value;
    if(fine_native_store_propagate(c,pa,value))return -1;
    return 0;
}
static int fine_user_live_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=fine_mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
/* sptm_publish: the SWITCH_ROOT memo's write witness, under aux. */
static void fine_sptm_publish(void *ctx,uint64_t pa,uint64_t size)
{
    struct context *c=ctx;const struct params *p=c->params;
    fine_cpu(c)->stores++;
    fine_aux_lock(c);
    sptm_root_memo_publish(&c->root_memo,p->frame_map_pa,p->frame_low,p->frame_high,
                           sptm_map,c,pa,size);
    fine_aux_unlock(c);
    publish(pa, pa + size);
}
/* sptm_context_memory with this CPU's reference batch, snapshots and audit
 * share. No clean_frame: an SH/AttrIndx change is refused in preflight and
 * runs on the token path (attr_updates is token-path state). */
static struct sptm_memory fine_memory(struct context *c)
{
    struct sptm_memory m=sptm_context_memory(c);
    struct fine_cpu *f=fine_cpu(c);
    m.publish=fine_sptm_publish;m.refs=&fine_of(c)->refs[vcpu_of(c)->slot];
    m.audit=&f->audit;m.fine=&f->ref_fine;m.clean_frame=0;
#if SNAP_DART_MEMO
    m.dart_memo=0;   /* the memo is the token path's */
#endif
    return m;
}

/* The user backend: user_live_shadow, user_refresh_all,
 * user_commit_tlb_range, user_tlb_range, user_prepare/commit_leaf,
 * user_prepare_unmap, user_prepare/commit_update, user_commit_unmap,
 * user_backend. */
static struct shadow fine_live_shadow(struct context *c,struct sptm_root_cached *e)
{
    return (struct shadow){.txsz=17,.root=e->shadow,.alloc=fine_refuse_alloc,
        .read=mem_read,.write=fine_user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
}
static int fine_user_refresh_all(struct context *c,struct sptm_root_cached *e)
{
    struct sprr_views *v=user_views(c,e);
    if(!v->count || !fine_native_due(&c->native_stats.audit_asks))return !fine_failed(c);
    int started=detail_begin(c,DETAIL_USER_REFRESH);
    struct shadow s=user_view_shadow(c,e);
    /* Every 64th sampled audit also walks the whole canonical tree. */
    int full=!(__atomic_fetch_add(&c->native_stats.audits,1,__ATOMIC_RELAXED)&63);
    int result=full ? native_views_verify(v,&s,native_umprr(e)) : native_views_exact(v,&s,native_umprr(e));
    fine_add(&c->native_stats.coverages,(uint64_t)full);
    if(!result) {fine_add(&c->native_stats.audit_failures,1);fine_view_failed(c);}
    detail_end(c,DETAIL_USER_REFRESH,started,result);return result;
}
static int fine_user_commit_tlb_range(struct context *c,unsigned kind,uint64_t va,uint64_t size)
{
    if(kind>=4 || fine_failed(c))return 0;
    fine_native_tlbi_range(c,va,size);
    fine_sat_add(&c->user_only_tlbi[kind],1,UINT64_MAX);
    return !fine_failed(c);
}
static int fine_user_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s=fine_live_shadow(c,e);
    if(!sptm_root_prepare_leaf(e,&s,va,shift))return 0;
    /* A class9 leaf's private paths (native_prepare_tpro) are token-path work:
     * refused in preflight, so the call declines. */
    return sprr_pte_class(pte)!=9;
}
static int fine_user_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s=fine_live_shadow(c,e);
    struct sptm_memory m=fine_memory(c);
    if(!sptm_root_commit_leaf(e,&s,&m,va,shift,pte) || !fine_user_refresh_all(c,e))return 0;
    if(!fine_user_commit_tlb_range(c,0,va,UINT64_C(1)<<shift))return 0;
    fine_add(&c->user_live_pages,1);return 1;
}
static int fine_user_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s=fine_live_shadow(c,e);
    struct sptm_memory m=fine_memory(c);
    return sptm_root_prepare_unmap(e,&s,&m,va,shift,count);
}
static int fine_user_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    if(!fine_user_prepare_unmap(ctx,root,va,shift,1))return 0;
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    /* Becoming class9 needs native_prepare_tpro: token path. */
    return !(e && sprr_pte_class(next)==9 && sprr_pte_class(old)!=9);
}
static int fine_user_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s=fine_live_shadow(c,e);
        struct sptm_memory m=fine_memory(c);
        if(!sptm_root_commit_update(e,&s,&m,va,shift,old,next) || !fine_user_refresh_all(c,e))return 0;
    }
    if(update_fast_uncached(old))return !fine_failed(c);
    fine_native_tlbi_range(c,va,UINT64_C(1)<<shift);return !fine_failed(c);
}
static int fine_user_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                  uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s=fine_live_shadow(c,e);
        if(!sptm_root_commit_unmap(e,&s,va,shift,count,removed) || !fine_user_refresh_all(c,e))return 0;
    }
    if(!fine_user_commit_tlb_range(c,1,va,count<<shift))return 0;
    fine_add(&c->user_unmap_calls,1);fine_add(&c->user_unmap_pages,removed);return 1;
}
#if SNAP_FINE_HW && SNAP_USER_HW_WALK
/* ---- SNAP_FINE_HW: hardware-walk roots (docs/FINE-HW-WALK-20261019.md) ----
 * user_backend's hw_* events for a converted MAP_PAGE or UNMAP_REGION, under
 * the root's stripe: the record, its copies and copy pages are read, the
 * copies' existing entries rewritten (compat/user-hw-walk.h hw_walk_fine_*),
 * nothing allocated, linked or released; the shared counters are added
 * atomically. A class-9 leaf and a replacing MAP_PAGE decline before any
 * store (token path: hw_walk_before_tpro and user_commit_update's prelude). */
static void fine_hw_tlb_range(void *ctx,uint64_t va,uint64_t size){fine_native_tlbi_range(ctx,va,size);}
static void fine_hw_counted(struct context *c,const struct hw_walk_fine_counts *n)
{
    if(n->refreshes)fine_add(&c->hw_walk->stats.refreshes,n->refreshes);
    if(n->refreshed)fine_add(&c->hw_walk->stats.refreshed,n->refreshed);
}
#if SNAP_SPTM_FINE
/* SNAP_SPTM_FINE (agents/sptm-locks/FAILURE-MODES.md S9, S10): the events'
 * memory access. hw_ops' copy writer is hw_copy_write, i.e. mem_write, whose
 * tracker updates (memo clock, dirty bits, txn sentinel, private pages, epoch)
 * are plain RMWs: token-path only. A converted event writes a copy through
 * fine_mem_write and publishes it at the store (hw_copy_write's bounds and
 * clean); it never allocates or releases a copy page, so those two latch a
 * view failure if ever reached. */
static int fine_hw_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table)return -1;
    return fine_user_live_write(ctx,pa,value);    /* fine_mem_write, then publish */
}
static uint64_t fine_hw_refuse_alloc(void *ctx){fine_view_failed(ctx);return 0;}
static void fine_hw_refuse_release(void *ctx,uint64_t pa){(void)pa;fine_view_failed(ctx);}
static struct hw_walk_ops fine_hw_ops(struct context *c)
{return (struct hw_walk_ops){hw_table_read,fine_hw_copy_write,fine_hw_refuse_alloc,fine_hw_refuse_release,hw_table_type,c};}
#define FINE_HW_OPS(c) fine_hw_ops(c)
#else
#define FINE_HW_OPS(c) hw_ops(c)
#endif
static int fine_hw_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{(void)va;return hw_walk_fine_prepare_leaf(hw_root(ctx,root),shift,pte);}
static int fine_hw_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct hw_walk_ops o=FINE_HW_OPS(c);struct hw_walk_fine_counts n;
    (void)pte;
    int ok=hw_walk_fine_after_add(&o,hw_root(c,root),va,UINT64_C(1)<<shift,&n);
    fine_hw_counted(c,&n);
    if(!ok) {fine_view_failed(c);return 0;}
    fine_add(&c->user_live_pages,1);
    return 1;
}
static int fine_hw_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{(void)va;(void)count;return hw_walk_fine_prepare_unmap(hw_root(ctx,root),shift);}
static int fine_hw_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct hw_walk_ops o=FINE_HW_OPS(c);struct hw_walk_tlb t={fine_hw_tlb_range,c};
    struct hw_walk_fine_counts n;
    int ok=hw_walk_fine_after_change(&o,hw_root(c,root),va,count<<shift,&t,&n);
    fine_hw_counted(c,&n);
    if(!ok) {fine_view_failed(c);return 0;}
    if(fine_failed(c))return 0;
    fine_add(&c->user_unmap_calls,1);fine_add(&c->user_unmap_pages,removed);return 1;
}
#if SNAP_SPTM_FINE
/* SNAP_SPTM_FINE: a replacing MAP_PAGE and every update on a hardware-walk
 * root run converted. prepare: hw_prepare_update without its class-9 path
 * preparation (allocation: refused, the call declines before any store).
 * commit: user_commit_update's hardware-walk prelude (a hardware-walk root is
 * never cached: one that is fails as there), the copies' refresh, then its
 * skip and its invalidation (native_tlbi_range, every VMID). */
static int fine_hw_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)va;return hw_walk_fine_prepare_update(hw_root(ctx,root),shift,old,next);}
static int fine_hw_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct hw_walk_ops o=FINE_HW_OPS(c);struct hw_walk_tlb t={fine_hw_tlb_range,c};
    struct hw_walk_fine_counts n={0,0};
    (void)next;
    int ok=!user_cached(c,root) &&
        hw_walk_fine_after_update(&o,hw_root(c,root),va,UINT64_C(1)<<shift,!update_fast_uncached(old),&t,&n);
    fine_hw_counted(c,&n);
    if(!ok) {fine_view_failed(c);return 0;}
    return !fine_failed(c);
}
#else
/* A replacing MAP_PAGE (and any update): token path. Both are set because the
 * engine accepts a backend only with both or neither, and neither would let
 * an inactive root's replacement through without events. */
static int fine_hw_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)root;(void)va;(void)shift;(void)old;(void)next;return 0;}
static int fine_hw_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)root;(void)va;(void)shift;(void)old;(void)next;return 0;}
#endif
/* user_backend's hardware-walk branch: the same identity checks (activity
 * words loaded atomically), the events above, the inactive mirror, and no
 * shared-root, detach, attach or nest callbacks (the engine refuses those
 * calls before any store: declined). */
static int fine_hw_backend(struct context *c,uint64_t root,struct sptm_user_backend *b)
{
    b->ttbr0=vcpu_of(c)->guest_ttbr0;b->ttbr1=vcpu_of(c)->guest_ttbr1;
    b->aperture=xnu_aperture(c);b->moved=xnu_moved(c);b->ctx=c;
    b->prepare_leaf=fine_hw_prepare_leaf;b->commit_leaf=fine_hw_commit_leaf;
    b->prepare_unmap=fine_hw_prepare_unmap;b->commit_unmap=fine_hw_commit_unmap;
    b->prepare_update=fine_hw_prepare_update;b->commit_update=fine_hw_commit_update;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        int active=__atomic_load_n(&c->user_roots.active[cpu],__ATOMIC_RELAXED)==root;
        int recorded=(__atomic_load_n(&c->vcpus[cpu].guest_ttbr0,__ATOMIC_RELAXED)&0x0000ffffffffc000UL)==root;
        if(active!=recorded || (c->vcpus[cpu].guest_ttbr1&0x0000ffffffffc000UL)==root)return 0;
        b->active_refs+=active;
    }
    b->mirror=!b->active_refs;
    return 1;
}
#endif
/* user_backend for a converted call: the same identity checks, the fine
 * callbacks, no shared-root, detach, attach or nest callbacks (those roots
 * and operations run on the token path), and a root outside the call's
 * lockset refused, so every root the engine touches is one whose stripe this
 * CPU holds (the records are read again by the engine). Activity words are
 * loaded atomically: with SNAP_FINE_SWITCH another CPU's converted switch
 * writes its own words while this CPU holds other stripes. */
static int fine_user_backend(struct context *c,uint64_t root,struct sptm_user_backend *b)
{
    *b=(struct sptm_user_backend){0};
    if(!fine_lockset_has(&fine_cpu(c)->locks,root))return 0;
#if SNAP_USER_HW_WALK
#if SNAP_FINE_HW
    /* SNAP_FINE_HW: a MAP_PAGE or UNMAP_REGION on one (fine_lockset_for
     * admits no other converted kind) gets the converted hardware-walk events. */
    if(FINE_HW_ROOT(c,root))return fine_hw_backend(c,root,b);
#endif
    /* fine_lockset_for refused it already; every root an engine reaches is
     * checked here again (FINE_HW_ROOT). */
    if(FINE_HW_ROOT(c,root))return 0;
#endif
    b->ttbr0=vcpu_of(c)->guest_ttbr0;b->ttbr1=vcpu_of(c)->guest_ttbr1;
    b->aperture=xnu_aperture(c);b->moved=xnu_moved(c);
    b->prepare_leaf=fine_user_prepare_leaf;b->commit_leaf=fine_user_commit_leaf;b->ctx=c;
    b->prepare_unmap=fine_user_prepare_unmap;b->commit_unmap=fine_user_commit_unmap;
    b->prepare_update=fine_user_prepare_update;b->commit_update=fine_user_commit_update;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        int active=__atomic_load_n(&c->user_roots.active[cpu],__ATOMIC_RELAXED)==root;
        int recorded=(__atomic_load_n(&c->vcpus[cpu].guest_ttbr0,__ATOMIC_RELAXED)&0x0000ffffffffc000UL)==root;
        if(active!=recorded || (c->vcpus[cpu].guest_ttbr1&0x0000ffffffffc000UL)==root)return 0;
        b->active_refs+=active;
    }
    return !b->active_refs || user_cached(c,root)!=0;
}
static int fine_update_backend(void *ctx,uint64_t root,struct sptm_user_backend *b)
{return fine_user_backend(ctx,root,b);}
/* An admitted user root: managed, unlocked, USER_ROOT_TABLE (not a shared
 * root, whose leaves propagate to every alias), not the kernel root. */
static int fine_user_root(struct context *c,uint64_t root)
{
    struct sptm_memory m=sptm_context_memory(c);
    if(root==c->params->ttbr1_root || !sptm_managed_frame(&m,root))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((root-m.frame_low)>>14)*16,16);
    return meta && !meta[0] && !meta[1] && meta[2]==SPTM_MAC_USER_ROOT_TABLE;
}
static unsigned fine_frame_type(struct context *c,uint64_t pa)
{
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,pa&~UINT64_C(0x3fff)))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+(((pa&~UINT64_C(0x3fff))-m.frame_low)>>14)*16,16);
    return meta ? meta[2] : 0;
}

#endif
