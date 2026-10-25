/* SPDX-License-Identifier: MIT */
/* Guest memory access (mem_read/mem_write), register capture, table allocation
 * and publication, and kernel table reads/writes with writer admission.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
static int mem_read(void *ctx, uint64_t pa, uint64_t *out)
{
    if ((pa & 7UL) || !ctx || !out)
        return -1;
    struct context *c = ctx;
    if (c->work_start && pa + 8UL > c->work_start && pa < (c->work_base ? c->work_base : c->work_end))
        return -1;
    int in_dram = c->params && (pa >= c->params->mem_low && pa <= c->params->mem_high - 8UL);
    int in_shadow = c->work_base && (pa >= c->work_base && pa <= (c->next_table ? c->next_table : c->work_end) - 8UL);
    if (!in_dram && !in_shadow)
        return -1;
    *out = *(volatile uint64_t *)pa;
    return 0;
}

#if SNAP_NATIVE_SHARED
/* A root build, NEST or UNNEST linking cached slot `slot`'s tree `s`. */
struct native_links {struct context *c;struct shadow *s;unsigned slot;uint64_t shared;};
static void native_group_release(void *,uint64_t);
static int native_group_unlinked(struct context *,int);
static int user_live_write(void *,uint64_t,uint64_t);
static uint64_t native_shared_root_of(struct context *,uint64_t);
static struct sptm_root_links native_links_for(struct native_links *);
#if SNAP_ROOT_MISS_FAST
static int nl_grouped(void *,uint64_t,uint64_t);
#endif
#endif
#if SNAP_NATIVE_TABLES
static int native_reuse_current(struct context *,const struct shadow *,const uint64_t *);
static int native_store_admit(struct context *,uint64_t,uint64_t);
static int native_store_propagate(struct context *,uint64_t,uint64_t);
static int native_due(uint64_t *);
static void native_mark(struct context *,const struct sprr_views *,int);
#endif
static int mem_write(void *ctx, uint64_t pa, uint64_t value)
{
    if ((pa & 7UL) || !ctx)
        return -1;
    struct context *c = ctx;
    if (c->work_start && pa + 8UL > c->work_start && pa < (c->work_base ? c->work_base : c->work_end))
        return -1;
    int in_dram = c->params && (pa >= c->params->mem_low && pa <= c->params->mem_high - 8UL);
    int in_shadow = c->work_base && (pa >= c->work_base && pa <= (c->next_table ? c->next_table : c->work_end) - 8UL);
    if (!in_dram && !in_shadow)
        return -1;
#if SNAP_NATIVE_TABLES
    /* Before the store: a raw TPRO leaf may enter only a table with variant
     * copies, and a table with copies only a value they can translate. */
    if(native_store_admit(ctx,pa,value))return -1;
#endif
#if SNAP_USER_VIEW_CACHE || SNAP_KERNEL_CLASS_PROOF || SNAP_ROOT_DIRTY_PUBLISH || SNAP_USER_TREE_MEMO
    /* Callback-based canonical stores, separate from the pointer-based SPTM
     * transactions below. Identical stores leave either proof unchanged. */
    if(pa>=c->work_base && pa<c->next_table && c->next_table-pa>=8 &&
       *(volatile uint64_t *)pa!=value) {
#if SNAP_USER_TREE_MEMO
        /* First, so even a store refused below cannot leave a stale claim.
         * Canonical and private pages alike: both are memo inputs. */
        sprr_table_memo_note(&c->table_memo,pa);
#endif
#if SNAP_ROOT_DIRTY_PUBLISH
#if SNAP_INCREMENTAL_PUBLISH
        if(!root_index_note(&c->root_publish,&c->perf.root_index,c->work_base,
                            c->next_table,pa,8))return -1;
#else
        if(!root_publish_note(&c->root_publish,c->work_base,c->next_table,pa,8))return -1;
#endif
#endif
#if SNAP_TXN_DIRTY_PUBLISH
        txn_publish_observe(&c->txn_publish,pa,8);
#endif
#if SNAP_USER_VIEW_CACHE
#if SNAP_PRIVATE_VIEW_EPOCH
        int private=sprr_private_write(&c->private_pages,c->work_base,c->next_table,pa);
        if(private<0)return -1;
        if(!private)
#endif
        sprr_view_epoch_advance(&c->user_view_epoch);
#endif
#if SNAP_KERNEL_CLASS_PROOF
        sprr_class_proof_note(&c->kernel_class_proof,pa);
#endif
    }
#endif
    *(volatile uint64_t *)pa = value;
#if SNAP_NATIVE_TABLES
    /* After it: the same entry of both variant copies (O(1)). */
    if(native_store_propagate(ctx,pa,value))return -1;
#endif
    return 0;
}

/* Copy the guest's registers out of the exception frame.
 *
 * `frame` is what sync_lower pushed, and it pushed x0..x30 before executing
 * anything else, so these are the guest's values and not EL2's. SP and SPSR are
 * read here instead. XNU normally runs with SP_EL0 selected; its exception
 * entry switches to SP_EL1. SPSR_EL2 identifies the stack at this EL2 trap.
 * A capture at XNU's vector needs the original SPSR_EL1 instead (below). */
/* Filled in place, one word at a time, and never by assigning the struct.
 *
 * `*dst = src` and any bulk copy of the register array is lowered by clang into
 * a call to memcpy, which -ffreestanding does not prevent -- it only promises
 * the compiler will not assume the *semantics* of the library, not that it will
 * stop emitting calls into it. This probe links against no libc, so that call
 * has nothing to resolve and the link fails with an undefined symbol for a
 * function the source never mentions. The destinations are volatile so the
 * stores cannot be recognised as a copy idiom and folded back into one. */
static void fill_regs(volatile struct guest_regs *dst, const uint64_t *frame,
                      uint64_t esr, uint64_t pc, uint64_t far)
{
    for (unsigned n = 0; n < 31; n++) dst->x[n] = frame[n];
    uint64_t sp, spsr;
    __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
    if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    dst->sp_el1 = sp;
    dst->spsr = spsr;
    dst->pc = pc;
    dst->esr = esr;
    dst->far = far;
}

static void capture_regs(struct context *c, const uint64_t *frame,
                         uint64_t esr, uint64_t pc, uint64_t far)
{
    uint64_t spsr, sp;
    __asm__ volatile("mrs %0, spsr_el1" : "=r"(spsr));
    if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    if (!vcpu_of(c)->exceptions) {
        fill_regs(&vcpu_of(c)->first_exc, frame, esr, pc, far);
        vcpu_of(c)->first_exc.spsr = spsr;
        vcpu_of(c)->first_exc.sp_el1 = sp;
    }
    fill_regs(&vcpu_of(c)->last_exc, frame, esr, pc, far);
    vcpu_of(c)->last_exc.spsr = spsr;
    vcpu_of(c)->last_exc.sp_el1 = sp;
    vcpu_of(c)->exceptions++;
}

static uint64_t table_alloc_owned(struct context *c,unsigned owner)
{
    uint32_t used=(uint32_t)((c->next_table-c->work_base)/4096);
    uint32_t capacity=(uint32_t)((c->work_end-c->work_base)/4096);
    int index=table_pool_take(&c->table_pool,&used,capacity,owner);
    if(index<0) {c->arena_reclaim.alloc_failures++;return 0;}
    uint64_t table=c->work_base+(uint64_t)index*4096;
    c->next_table=c->work_base+(uint64_t)used*4096;
#if SNAP_ROOT_DIRTY_PUBLISH
#if SNAP_INCREMENTAL_PUBLISH
    if(!root_index_note(&c->root_publish,&c->perf.root_index,c->work_base,
                        c->next_table,table,4096))return 0;
#else
    if(!root_publish_note(&c->root_publish,c->work_base,c->next_table,table,4096))return 0;
#endif
#endif
#if SNAP_TXN_DIRTY_PUBLISH
    txn_publish_observe(&c->txn_publish,table,4096);
#endif
#if SNAP_PRIVATE_VIEW_EPOCH
    if(!sprr_private_clear(&c->private_pages,(unsigned)index,0))return 0;
#endif
#if SNAP_KERNEL_CLASS_PROOF
    sprr_class_proof_note(&c->kernel_class_proof,table);
#endif
#if SNAP_USER_VIEW_CACHE
    sprr_view_epoch_advance(&c->user_view_epoch);
#endif
#if SNAP_USER_TREE_MEMO
    /* Zeroing below bypasses mem_write; reuse gets a new generation and
     * loses any summary. Only allocator-issued pages are memo-eligible. */
    sprr_table_memo_alloc(&c->table_memo,table);
#endif
    for (unsigned n = 0; n < 0x1000 / 8; n++) *(volatile uint64_t *)(table + 8UL * n) = 0;
    return table;
}
static uint64_t table_alloc(void *ctx) {return table_alloc_owned(ctx,0);}
static uint64_t user_table_alloc(void *ctx)
{
    struct user_table_owner *owner=ctx;
    return table_alloc_owned(owner->context,owner->owner);
}
static uint64_t private_table_alloc_owned(struct context *c,unsigned owner)
{
    uint64_t pa=table_alloc_owned(c,owner);
#if SNAP_PRIVATE_VIEW_EPOCH
    if(pa && !sprr_private_mark(&c->private_pages,(unsigned)((pa-c->work_base)/4096)))return 0;
#endif
    return pa;
}
static uint64_t private_kernel_alloc(void *ctx)
{return private_table_alloc_owned(ctx,0);}
static uint64_t private_user_alloc(void *ctx)
{
    struct user_table_owner *owner=ctx;
    return private_table_alloc_owned(owner->context,owner->owner);
}

/* The table walker is a separate observer from our stores; without this it
 * reads whatever was in memory before and reports a translation fault on an
 * entry software can plainly see is valid. */
static void publish(uint64_t start, uint64_t end)
{
    for (uint64_t line = start & ~63UL; line < end; line += 64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
}

#if SNAP_ROOT_DIRTY_PUBLISH
static int root_publish_page(void *ctx,uint64_t pa)
{
    (void)ctx;publish(pa,pa+4096);return 1;
}
#endif
#if SNAP_TXN_DIRTY_PUBLISH || SNAP_ROOT_PUBLISH_BATCH_DSB
/* publish() for one page without its trailing barrier. Nothing is stored
 * between the pages of one flush, so a single dsb ish after the last page
 * gives exactly the completion guarantee of one per page before the TLBI. */
static int publish_page_lines(void *ctx,uint64_t pa)
{
    (void)ctx;
    for(uint64_t line=pa;line<pa+4096;line+=64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    return 1;
}
#endif

static int kernel_table_read(void *ctx,uint64_t pa,uint64_t *out)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<8)return -1;
    return mem_read(ctx,pa,out);
}
#if SNAP_CLASS_PROOF_MAPPED
/* kernel_table_read's bounds applied to a whole page-aligned table: accepted
 * iff all 512 word reads of that page would be accepted. Canonical kernel
 * tables are monitor-owned, guest read-only at stage 2 and stable under the
 * service token for the whole walk. */
static const volatile uint64_t *class_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096)return 0;
    return (const volatile uint64_t *)pa;
}
#endif
static int kernel_table_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<8)return -1;
#if SNAP_KERNEL_DIRTY_PUBLISH
    if(*(volatile uint64_t *)pa==value)return 0;
    if(!sprr_publish_note(&c->kernel_publish_state,&c->kernel_views,pa)) {
        c->kernel_view_failed=1;return -1;
    }
#endif
    return mem_write(ctx,pa,value);
}
/* Admission is separate from breakpoint enablement. Until every publication
 * path and the breakpoint lifecycle are qualified, writer guards stay intact.
 * The physical pages come from the loader's relocated, full-image inventory. */
static int native_writer_admit(struct context *c,enum native_writer_regime regime,
    uint64_t va,uint64_t pa,uint64_t size,uint64_t low,uint64_t upper)
{
    const struct params *p=c->params;
    if(p->stub_count!=(NATIVE_COMPILED_FLAGS|NATIVE_CONTRACT_PAGES))return 0;
    struct native_writer_mapping mapping={{p->stub_pa[NATIVE_CALL_PAGES],
                                          p->stub_pa[NATIVE_CALL_PAGES+1]}};
    return native_writer_mapping_admit(&mapping,regime,va,pa,size,low,upper);
}
static int native_writer_admit_high(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{return native_writer_admit(ctx,NATIVE_WRITER_KERNEL_HIGH,va,pa,size,low,upper);}
static int native_writer_admit_low(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{return native_writer_admit(ctx,NATIVE_WRITER_KERNEL_LOW,va,pa,size,low,upper);}
static int native_writer_admit_user(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{return native_writer_admit(ctx,NATIVE_WRITER_USER,va,pa,size,low,upper);}

