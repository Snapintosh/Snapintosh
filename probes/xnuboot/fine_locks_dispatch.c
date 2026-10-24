/* SPDX-License-Identifier: MIT */
/* SNAP_FINE_LOCKS, third block: PAuth, DART and ANS conversions, the
 * lock-set choice and fine_sptm_call.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_FINE_LOCKS
#if SNAP_FAST_PAUTH_CALLS
/* ---- SNAP_FAST_PAUTH_CALLS: the user pointer-authentication calls -------
 * SIGN_USER_POINTER and AUTH_USER_POINTER (FINE_CALL_PAUTH) and
 * BATCH_SIGN_USER_POINTER (FINE_CALL_PAUTH_BATCH) with the gate shared and no
 * stripe: they name no root. Each runs monitor_call_impl's body for the
 * endpoint (user_pointer_call, user_pointer_batch), so the answer is the
 * locked path's. Besides this CPU's own state the helpers read only words no
 * one writes while the gate is shared: the boot-fixed pauth_domain and
 * aes_hardware, the frame-map geometry, and a batch input frame's type and
 * lock bytes (written only by RETYPE, under the token). The input records
 * themselves are guest memory, as unordered against the other CPUs' EL1 as
 * under the token. The native helpers change this PE's TCR/SCTLR_EL2 and one
 * key pair with DAIF masked and a local TLBI: another CPU signing at once
 * uses its own PE. A refused configuration (TCR, an entered bank, a failed
 * derivation: none changes anything) declines; the locked path repeats it and
 * stops. A failure once the helper ran (key class, AUTH of an upper address,
 * a native failure, a batch's shape, address, type or lock) is terminal with
 * the locked path's record, made under the token (fine_fatal) without a
 * latched view failure: nothing shared was written. A batch publishes its
 * scratch output through fine_memory (fine_sptm_publish: the SWITCH_ROOT
 * memo's write witness under aux, then the clean). No reference batch, no
 * allocation: pv_audit and the arena are left alone (fine_state_admits keeps
 * the arena at its reserve, where arena_reserve only counts). */
static int fine_pauth_pointer(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    int ran=0;
    enum sptm_result r=user_pointer_call(c,frame,(uint32_t)s->x16,&ran);
    if(!ran) {s->reason=FINE_NO_ENGINE;return FINE_DECLINE;}
    if(r) {s->result=r;s->fail_kind=EV_TABLE_FAILED;s->fail_a=s->a0;s->fail_b=(uint32_t)s->x16;return FINE_FATAL;}
    frame[0]=c->pauth_pointer[vcpu_of(c)->slot].result;return FINE_DONE;
}
static int fine_pauth_batch(struct context *c,uint64_t *frame,const struct guest_cpu_buffer *scratch,
                            struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    int ran=0;
    enum sptm_result r=user_pointer_batch(c,&memory,frame,scratch,&ran);
    if(!ran) {s->reason=FINE_NO_ENGINE;return FINE_DECLINE;}
    if(r) {
        s->result=r;s->fail_kind=EV_TABLE_FAILED;s->fail_a=s->a0;
        s->fail_b=c->pauth_batch[vcpu_of(c)->slot].failed_index;return FINE_FATAL;
    }
    frame[0]=c->pauth_batch[vcpu_of(c)->slot].result_va;return FINE_DONE;
}
#define FINE_POINTER_CALL(kind) ((kind)==FINE_CALL_PAUTH || (kind)==FINE_CALL_PAUTH_BATCH)
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
/* ---- The Adreno DART's MAP and UNMAP as converted calls -------------------
 * SNAP_DART_CONVERTED (compat/dart-converted.h, batch 9: this block on its own,
 * re-checked against the phase-fair gate, the fine locks and SNAP_FINE_SWITCH_HW;
 * batch9/dart FAILURES-AND-DESIGN.md A1-A19) or SNAP_TOKEN_TRIM's part B
 * (compat/token-trim.h), never both; the numbers below are batch 5's. The
 * body of monitor_call_impl's table-3 branch for endpoints 2 and 3 on the
 * Adreno virtual DART, stream 0, with ADRENO_F_DART (the SMMU CB0 mirror
 * always runs then): device_dart_admit_frame, sptm_dart_map/unmap, the GPU
 * counters and adreno_mirror. The gate is shared and no stripe is held (the
 * call names no root); the device lock serializes these calls among
 * themselves, and every other writer of what they touch holds the token:
 *  - the DART tables, their frame records' refs and the model's dart_state
 *    (MAP_TABLE, enable, the HVC kext's own unmap, DART MMIO, RETYPE) (9);
 *  - the DART memo (every token-path SPTM publish) (12);
 *  - c->gpu and the SMMU tables (the GPU tick, MMIO, SMC, HVC, quiesce;
 *    vCPU 0's lock-free tick reads only status, quiesce and run_at) (14).
 * Data-frame counts change by atomic delta through this CPU's fine
 * reference batch, beside converted user calls on the same frames (8);
 * frame types are read as constants (RETYPE is exclusive) (11). Both
 * engines are fallible only before their first store, so a refusal declines
 * (17); the reader bit is held until the mirror's SMMU TLBI has completed, so
 * no RETYPE can free a frame whose DART reference an UNMAP dropped while the
 * GPU can still reach it (10). A mirror failure is terminal with the token
 * path's EV_GPU_SMMU record and no latched view failure (19). */
#define FINE_X16_DART_MAP UINT64_C(0x0000000300000002)    /* domain 0, table 3, endpoint 2 */
#define FINE_X16_DART_UNMAP UINT64_C(0x0000000300000003)  /* endpoint 3 */
#define FINE_DART_CALL(kind) ((kind)==FINE_CALL_DART_MAP || (kind)==FINE_CALL_DART_UNMAP)
/* The device lock and this CPU's device-lock wait: batch 5's, or batch 9's.
 * FINE_DART_COUNT keeps batch 5's TOKTRIM1 counters under SNAP_TOKEN_TRIM only:
 * SNAP_DART_CONVERTED reports through the fine profile's DART buckets. */
#if SNAP_TOKEN_TRIM
#define FINE_DART_STATE_T struct token_trim_state
#define FINE_DART_STATE(c) (&(c)->root_ext->trim)
#define FINE_DART_COUNT(...) __VA_ARGS__
#else
#define FINE_DART_STATE_T struct dart_converted_state
#define FINE_DART_STATE(c) (&(c)->root_ext->dart_cv)
#define FINE_DART_COUNT(...)
#endif
/* sptm_publish for a DART call: the DART memo's write witness (the device
 * lock is held), then the SWITCH_ROOT memo's under aux and the clean (12, 13). */
static void fine_dart_publish(void *ctx,uint64_t pa,uint64_t size)
{
#if SNAP_DART_MEMO
    sptm_dart_memo_publish(&((struct context *)ctx)->root_ext->dart_memo,pa,size);
#endif
    fine_sptm_publish(ctx,pa,size);
}
static int fine_dart_call(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    const struct params *p=c->params;
    FINE_DART_STATE_T *t=FINE_DART_STATE(c);
    unsigned slot=(unsigned)vcpu_of(c)->slot,index=0;
    int unmap=s->kind==FINE_CALL_DART_UNMAP;
    t->device_wait[slot][0]=t->device_wait[slot][1]=0;
    /* The token path's admission, read-only; anything else is not this envelope. */
    if(frame[0]!=SPTM_DART_ADRENO || frame[1] || !(p->gpu.flags & ADRENO_F_DART) ||
       device_dart_admit_frame(p->models,c->model_state,(unsigned)p->model_count,5,
                               (unsigned)frame[0],(unsigned)frame[1],2,&index)!=DEVICE_OK) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    uint64_t start=service_profile_clock();
    if(fine_ticket_lock(&t->device)) {
        t->device_wait[slot][0]=service_profile_clock()-start;t->device_wait[slot][1]=1;
        FINE_DART_COUNT(t->stats.device_contended++;t->stats.device_wait+=t->device_wait[slot][0];)
    }
    FINE_DART_COUNT(t->stats.device_entries++;)
    struct sptm_memory memory=fine_memory(c);
    memory.publish=fine_dart_publish;
#if SNAP_DART_MEMO
    memory.dart_memo=&c->root_ext->dart_memo;
#endif
    struct dart_state *d=&c->model_state[index].dart;
    enum sptm_result r=unmap ?
        sptm_dart_unmap(&memory,d,frame[0],frame[1],frame[2],frame[3],frame[4]) :
        sptm_dart_map(&memory,d,frame[0],frame[1],frame[2],frame[3],frame[4],frame[5]);
    if(r) {
        FINE_DART_COUNT(if(!fine_cpu(c)->stores)t->stats.dart_declines++;)
        fine_ticket_unlock(&t->device);
        return fine_engine_end(c,s,r,EV_TABLE_FAILED,frame[2],frame[4]);
    }
    /* Stage 4: stream 0 of the Adreno virtual DART, into SMMU CB0; UNMAP
     * returns only after the SMMU TLB invalidation has completed. */
    struct gpu_leaf_ctx leaf={&memory,d};
    struct adreno_ops o=GPU_LEAF_OPS(c);
    /* Under the device lock; atomic like every context word a converted
     * call writes outside aux (adreno_mirror's own counters are the device
     * lock's: the token path is excluded by the gate). */
    fine_add(unmap ? &c->gpu.unmaps : &c->gpu.maps,1);
    int e=adreno_mirror(&o,&p->gpu,&c->gpu,frame[2],unmap ? frame[3] : frame[4],
                        gpu_leaf,&leaf,p->mem_low,p->mem_high);
    FINE_DART_COUNT(if(!e) {if(unmap)t->stats.dart_unmaps++;else t->stats.dart_maps++;})
    fine_ticket_unlock(&t->device);
    if(e) {
        s->fail_kind=EV_GPU_SMMU;s->fail_value=(uint64_t)(int64_t)e;s->fail_raw=1;
        s->fail_a=frame[2];s->fail_b=unmap ? 3 : 2;return FINE_FATAL;
    }
    frame[0]=0;return FINE_DONE;
}
#endif
#if SNAP_ANS_CONVERTED
/* ---- SNAP_ANS_CONVERTED: the virtual ANS2 off the token -------------------
 * agents/nvme-async/FAILURE-MODES.md N2, N3, N9, N10. Two converted calls under
 * one ANS device lock (FIFO, L1.5: after the gate, never with a stripe, KL or
 * the DART lock; before frame locks and aux):
 *  - FINE_CALL_ANS_SPTM, table-6 MAP_PAGES/UNMAP_PAGES (fine_sptm_call):
 *    compat/ans.c ans_sptm_converted, the references as one all-or-nothing
 *    batch on this CPU's fine memory (fine_ans_frame_refs), every token-path
 *    refusal a decline;
 *  - FINE_CALL_ANS_MMIO, the I/O SQ doorbell 0x24910 and CQ head 0x100c
 *    (fine_ans_mmio, a data abort): compat/ans.c ans_mmio, which with
 *    SNAP_ANS_ASYNC queues and polls but never waits for the SSD.
 * Every other writer of the ANS state (the mailbox, CC, the admin doorbell,
 * the other endpoints, SART, the ticks, the stop) holds the token, which
 * drains the gate. Both calls end with the ANS lines on the AIC model
 * (ans_async_lines): every other AIC writer holds the token and no lock-free
 * path writes it (N3). */
#define FINE_X16_ANS_MAP UINT64_C(0x0000000600000001)     /* domain 0, table 6, endpoint 1 MAP_PAGES */
#define FINE_X16_ANS_UNMAP UINT64_C(0x0000000600000002)   /* endpoint 2 UNMAP_PAGES */
#define FINE_ANS_CALL(kind) ((kind)==FINE_CALL_ANS_MMIO || (kind)==FINE_CALL_ANS_SPTM)
static void fine_ans_lock(struct context *c)
{
    uint64_t *w=c->root_ext->ans_wait[vcpu_of(c)->slot],start=service_profile_clock();
    w[0]=w[1]=0;
    if(fine_ticket_lock(&c->root_ext->ans_lock)) {w[0]=service_profile_clock()-start;w[1]=1;}
}
static void fine_ans_unlock(struct context *c) {fine_ticket_unlock(&c->root_ext->ans_lock);}
/* ans_frame_ref's references as one batch on this CPU's fine memory: every page
 * through sptm_refs_dart (its first touch takes the frame shared under
 * SNAP_SPTM_FINE_RETYPE), the DART data-leaf rule re-checked under that lock,
 * one validate, one atomic commit; anything else changes nothing (1). */
/* ans_dma_frame on a snapshot of the entry: bytes 0..7 (busy, type, metadata) are written only by the token path
 * and a converted RETYPE, which the gate and this frame's shared lock exclude; the +8/+12 counts change under
 * other converted calls' atomic deltas, so they are loaded atomically (tools/test-ans-converted.c, TSan). */
static int fine_ans_dma_frame(volatile uint8_t *e)
{
    uint8_t copy[16];
    for(unsigned i=0;i<8;i++)copy[i]=e[i];
    uint32_t ro=__atomic_load_n((volatile uint32_t *)(volatile void *)(e+8),__ATOMIC_RELAXED);
    uint32_t other=__atomic_load_n((volatile uint32_t *)(volatile void *)(e+12),__ATOMIC_RELAXED);
    for(unsigned i=0;i<4;i++) {copy[8+i]=(uint8_t)(ro>>(8*i));copy[12+i]=(uint8_t)(other>>(8*i));}
    return ans_dma_frame(copy);
}
static int fine_ans_frame_refs(void *ctx,const uint64_t *pa,unsigned n,int writable,int release)
{
    struct context *c=ctx;
    struct sptm_memory m=fine_memory(c);
    sptm_refs_begin(m.refs);
    for(unsigned i=0;i<n;i++) {
        uint64_t f=pa[i]&~0x3fffUL;
        if(!sptm_managed_frame(&m,f))return 1;
        if(release ? sptm_refs_dart_remove(&m,f,!writable) : sptm_refs_dart(&m,f,!writable))return 1;
        if(!release) {
            volatile uint8_t *e=m.map(m.ctx,m.frame_map_pa+((f-m.frame_low)>>14)*16,16);
            if(!e || !fine_ans_dma_frame(e))return 1;
        }
    }
    if(sptm_refs_validate(&m))return 1;
    sptm_refs_commit(&m);
    return 0;
}
/* The token path's single-reference callback never runs here (no converted
 * entry takes one): refuse, so a regression is a decline or a refusal, never a
 * plain global batch off the token. */
static int fine_ans_frame_ref(void *ctx,uint64_t pa,int writable,int release)
{
    (void)ctx;(void)pa;(void)writable;(void)release;return 1;
}
static struct ans_ops fine_ans_ops(struct context *c)
{
    struct ans_ops o=ans_ops_of(c);
    o.frame_ref=fine_ans_frame_ref;o.publish=fine_sptm_publish;o.frame_refs=fine_ans_frame_refs;
    return o;
}
static int fine_ans_sptm(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    struct ans_state *st=c->root_ext->ans;
    if(!st) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    fine_ans_lock(c);
    struct ans_ops o=fine_ans_ops(c);
    uint64_t ret=0;
    int r=ans_sptm_converted(st,&o,(unsigned)(s->x16&0xffff),frame,&ret);
    int decline=r==ANS_DECLINE || r==ANS_DECLINE_BUSY;
    if(!r || decline) {
        /* The progress it ran may have posted or started a command, declined or not. */
        ans_async_schedule(c);
        if(ans_async_lines(c)!=DEVICE_OK)r=ANS_E_STATE,decline=0;
    }
    fine_ans_unlock(c);
    if(decline) {s->reason=r==ANS_DECLINE_BUSY ? FINE_NO_BUSY : FINE_NO_ENGINE;return FINE_DECLINE;}
    if(r) {
        s->fail_kind=EV_ANS;s->fail_a=(uint64_t)r<<32|6u<<8|(s->x16&0xffff);s->fail_b=frame[0];
        return FINE_FATAL;
    }
    guest_interrupt_sync(c);
    timer_arm(c,service_profile_clock(),c->fast_timer_due[vcpu_of(c)->slot].guest);
    frame[0]=ret;return FINE_DONE;
}
/* monitor_request's report of the call_other EV_ANS refusal, under the token
 * after the gate was left (fine_fatal's order); no view failure is latched. */
static int fine_ans_fatal(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,
                          const struct fine_call_state *s)
{
    if(!runtime_enter(c,frame,*elr,(esr>>26)&63))return 1;
    record(c,EV_ANS,*elr,s->fail_a,s->fail_b,frame[1]);
    fill_regs(&vcpu_of(c)->async_regs,frame,0,*elr,0);
    vcpu_of(c)->async_captured=2;
    record(c,EV_MONITOR,*elr,frame[16],frame[0],frame[1]);
    step_arm(c,0);guards_close(c);
    return runtime_leave(c,1);
}
#endif
/* The roots a call names, into this CPU's lockset; 0 declines. Reads the
 * guest's record list once; the backend refuses any root the engine reads
 * later that is not in the set. */
static int fine_lockset_for(struct context *c,const struct fine_call_state *s,struct fine_lockset *set)
{
#if SNAP_ANS_CONVERTED
    /* An ANS call names no root: the empty set; fine_ans_sptm takes the ANS lock. */
    if(s->kind==FINE_CALL_ANS_SPTM) {fine_lockset_init(set);return 1;}
#endif
#if SNAP_FAST_PAUTH_CALLS
    /* A pointer call names no root (a0 is a pointer): the empty set. */
    if(FINE_POINTER_CALL(s->kind)) {fine_lockset_init(set);return 1;}
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    /* A DART call names no root either (a0 is the DART id): the empty set;
     * fine_dart_call takes the device lock. */
    if(FINE_DART_CALL(s->kind)) {fine_lockset_init(set);return 1;}
#endif
#if SNAP_SPTM_FINE
    /* SNAP_SPTM_FINE (agents/sptm-locks/FAILURE-MODES.md S16, S19): a record
     * list's roots (UPDATE_DISJOINT, UNMAP_DISJOINT) and UPDATE_REGION's root
     * must be admitted user roots, hardware-walk ones included (their update
     * and unmap events are converted); a kernel or shared root in a list keeps
     * the whole list on the token path (its mixed and shared engines). RETYPE
     * and the kernel-root calls name no user root: the empty set (the kernel
     * calls take KL in fine_sptm_call). */
    if(s->kind==FINE_CALL_UPDATE_DISJOINT || s->kind==FINE_CALL_UNMAP_DISJOINT) {
        fine_lockset_init(set);
        uint64_t count=s->kind==FINE_CALL_UNMAP_DISJOINT ? (uint32_t)s->a2 : s->a2,list=s->a1;
        if(!count || count>64 || (list&7) || list>UINT64_MAX-count*24)return 0;
        if(!sptm_map(c,list,count*24))return 0;
        for(uint64_t n=0;n<count;n++) {
            uint64_t root;
            if(mem_read(c,list+24*n,&root) || !fine_user_root(c,root) || !fine_lockset_add(set,root))
                return 0;
        }
        return 1;
    }
    if(s->kind==FINE_CALL_UPDATE_REGION) {
        fine_lockset_init(set);
        return fine_user_root(c,s->a0) && fine_lockset_add(set,s->a0);
    }
    if(s->kind==FINE_CALL_RETYPE || s->kind==FINE_CALL_KERNEL_MAP || s->kind==FINE_CALL_KERNEL_UNMAP) {
        fine_lockset_init(set);return 1;
    }
#endif
    fine_lockset_init(set);
#if SNAP_USER_HW_WALK
    /* A call naming a hardware-walk root declines (FINE_HW_ROOT); a switch
     * from one (the old root) stays converted. */
#if SNAP_FINE_SWITCH_HW
    /* SNAP_FINE_SWITCH_HW: nor does a switch to one. It takes the stripes of
     * this CPU's current root and of its target below, as a cache hit does;
     * fine_switch_root converts it only when the target's record exists
     * (fine_hw_switch_eligible never attaches). The decline below then
     * applies to every other kind exactly as before. */
    if(s->kind!=FINE_CALL_SWITCH_HIT)
#endif
#if SNAP_FINE_HW
    /* SNAP_FINE_HW converts MAP_PAGE and UNMAP_REGION on such a root
     * (fine_hw_backend); UPDATE_DISJOINT records and switch targets still
     * decline. */
    if(s->kind!=FINE_CALL_UPDATE_DISJOINT && s->kind!=FINE_CALL_SWITCH_KERNEL && s->kind!=FINE_CALL_MAP_PAGE &&
       s->kind!=FINE_CALL_UNMAP_REGION && FINE_HW_ROOT(c,s->a0))return 0;
#else
    if(s->kind!=FINE_CALL_UPDATE_DISJOINT && s->kind!=FINE_CALL_SWITCH_KERNEL && FINE_HW_ROOT(c,s->a0))return 0;
#endif
#endif
#if SNAP_FINE_SWITCH
    if(s->kind==FINE_CALL_SWITCH_HIT || s->kind==FINE_CALL_SWITCH_KERNEL) {
        /* This CPU's current root (its own word) and a user target. */
        uint64_t old=c->user_roots.active[vcpu_of(c)->slot];
        if(old && (!fine_user_root(c,old) || !fine_lockset_add(set,old)))return 0;
        return s->kind==FINE_CALL_SWITCH_KERNEL ||
               (fine_user_root(c,s->a0) && fine_lockset_add(set,s->a0));
    }
#endif
    if(s->kind==FINE_CALL_UPDATE_DISJOINT) {
        uint64_t count=s->a2,list=s->a1;
        if(!count || count>64 || (list&7) || list>UINT64_MAX-count*24)return 0;
        if(!sptm_map(c,list,count*24))return 0;
        for(uint64_t n=0;n<count;n++) {
            uint64_t root;
            if(mem_read(c,list+24*n,&root) || !fine_user_root(c,root) || !fine_lockset_add(set,root))
                return 0;
#if SNAP_USER_HW_WALK
            if(FINE_HW_ROOT(c,root))return 0;
#endif
        }
        return 1;
    }
    if(!fine_user_root(c,s->a0))return 0;
    return fine_lockset_add(set,s->a0);
}
/* What the locked path requires that this path does not repeat: no latched
 * failure or panic, no monitor step, guard, user-entry probe or pending
 * secondary launch, a ready native-call snapshot, and an arena at its
 * reserve (arena_reserve would otherwise reclaim, a token-path operation). */
static int fine_state_admits(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    return !fine_failed(c) && !c->panic_state.triggered &&
        !v->stepping.active && !v->open_guards && !c->user_execution[v->slot].pending &&
        !(!v->slot && fast_secondary_pending(c)) &&
        arena_available(c)>=SNAP_ARENA_RESERVE_PAGES;
}
/* The token-path report of a commit failure (monitor_call_impl's failure
 * record, monitor_request's capture and stop), under the token. */
static int fine_fatal(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,
                      const struct fine_call_state *s)
{
#if SNAP_ANS_CONVERTED
    if(s->kind==FINE_CALL_ANS_SPTM)return fine_ans_fatal(c,frame,esr,elr,s);
#endif
#if SNAP_FAST_PAUTH_CALLS
    /* A pointer call's failure wrote nothing shared: no latched view failure. */
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    /* Nor a DART call's: it writes no user view (its terminal failure is the
     * SMMU mirror's; its engines fail only before their first store). */
    if(!FINE_DART_CALL(s->kind))
#endif
    if(!FINE_POINTER_CALL(s->kind))
#endif
    fine_view_failed(c);
    if(!runtime_enter(c,frame,*elr,(esr>>26)&63))return 1;
#if SNAP_SPTM_FINE_KERNEL
    /* map_page_failed's counter, beside its record below (EV_MAP_FAILED: the
     * reason travels in result). */
    if(s->fail_kind==EV_MAP_FAILED)fine_add(&c->map_failures,1);
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    if(s->fail_raw)record(c,s->fail_kind,s->elr,s->fail_value,s->fail_a,s->fail_b);else
#endif
    record(c,s->fail_kind,s->elr,s->result,s->fail_a,s->fail_b);
    fill_regs(&vcpu_of(c)->async_regs,frame,0,*elr,0);
    vcpu_of(c)->async_captured=2;
    step_arm(c,0);guards_close(c);
    return runtime_leave(c,1);
}
/* xnuboot_trap's converted call. 0: declined, nothing changed (the locked
 * path takes the trap). 1: handled; *stop as xnuboot_trap would return. */
static int fine_sptm_call(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,int *stop)
{
    if((esr>>26)!=0x20)return 0;
    struct vcpu *v=vcpu_of(c);
    const struct params *p=c->params;
    uint64_t x16=frame[16];
    unsigned kind;
    switch(x16) {
    case SPTM_FN_UPDATE_DISJOINT: kind=FINE_CALL_UPDATE_DISJOINT;break;
#if SNAP_SPTM_FINE_KERNEL
    /* The kernel root's: KL instead of a stripe (compat/sptm-fine.h). */
    case SPTM_FN_MAP_PAGE:
        kind=frame[0]==p->ttbr1_root ? FINE_CALL_KERNEL_MAP : FINE_CALL_MAP_PAGE;break;
    case SPTM_FN_UNMAP_REGION:
        kind=frame[0]==p->ttbr1_root ? FINE_CALL_KERNEL_UNMAP : FINE_CALL_UNMAP_REGION;break;
#else
    case SPTM_FN_MAP_PAGE: kind=FINE_CALL_MAP_PAGE;break;
    case SPTM_FN_UNMAP_REGION: kind=FINE_CALL_UNMAP_REGION;break;
#endif
#if SNAP_SPTM_FINE
    case SPTM_FN_UNMAP_DISJOINT: kind=FINE_CALL_UNMAP_DISJOINT;break;
    case SPTM_FN_UPDATE_REGION: kind=FINE_CALL_UPDATE_REGION;break;
#endif
#if SNAP_SPTM_FINE_RETYPE
    case SPTM_FN_RETYPE: kind=FINE_CALL_RETYPE;break;
#endif
#if SNAP_FINE_SWITCH
    case SPTM_FN_SWITCH_ROOT:
        kind=frame[0]==p->ttbr1_root ? FINE_CALL_SWITCH_KERNEL : FINE_CALL_SWITCH_HIT;break;
#endif
#if SNAP_FAST_PAUTH_CALLS
    case SPTM_FN_SIGN_USER_POINTER: case SPTM_FN_AUTH_USER_POINTER: kind=FINE_CALL_PAUTH;break;
    case SPTM_FN_BATCH_SIGN_USER_POINTER: kind=FINE_CALL_PAUTH_BATCH;break;
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    case FINE_X16_DART_MAP: kind=FINE_CALL_DART_MAP;break;
    case FINE_X16_DART_UNMAP: kind=FINE_CALL_DART_UNMAP;break;
#endif
#if SNAP_ANS_CONVERTED
    case FINE_X16_ANS_MAP: case FINE_X16_ANS_UNMAP: kind=FINE_CALL_ANS_SPTM;break;
#endif
    default: return 0;
    }
    /* The locked path's classification of a native call (xnuboot_trap_locked,
     * EC 0x20 from EL1), read-only: a guarded vector-page fetch whose EL1
     * syndrome is the call stub's undefined instruction. */
    uint64_t hpfar,far,spsr,iss=esr&0x1ffffff;
    __asm__ volatile("mrs %0, hpfar_el2; mrs %1, far_el2; mrs %2, spsr_el2"
                     :"=r"(hpfar),"=r"(far),"=r"(spsr));
    if(!p->vbar || ((iss>>7)&1) || exception_vector_step(esr,*elr,p->vbar_va))return 0;
    uint64_t ipa=guest_pa(far);
    if(!ipa && (hpfar&0x0000fffffffffff0UL))ipa=((hpfar>>4)<<12)|(far&0xfff);
    struct guard *g=guard_find(c,ipa);
    if(!g || g->mode==GUARD_DATA || (ipa&~0xfffUL)!=p->vbar)return 0;
    uint64_t g_esr,g_elr,saved;
    __asm__ volatile("mrs %0, esr_el1; mrs %1, elr_el1; mrs %2, spsr_el1"
                     :"=r"(g_esr),"=r"(g_elr),"=r"(saved));
    uint64_t vector=*elr-p->vbar_va;
    if(g_esr!=(1UL<<25) || ((saved&31)!=8 && (saved&31)!=9) || (g_elr&3) ||
       g_elr<UINT64_C(0xffff800000000000))return 0;
    uint64_t gpa=guest_pa(g_elr),physical=0;
    int call_page=0;
    for(unsigned n=0;n<NATIVE_CALL_PAGES;n++)call_page|=(gpa&~0xfffUL)==p->stub_pa[n];
    uint32_t word=call_page ? *(const uint32_t *)gpa : 0;
    struct native_call_state *ns=&c->native_calls[v->slot];
    if(!native_call_word(word) || ns->ready!=1 ||
       !native_call_return(vector,g_esr,saved,spsr,g_elr,word,&physical))return 0;
    struct guest_cpu_buffer cpu_scratch;
    if(guest_cpu_buffer(&c->cpus,v->slot,p->scratch_pa,p->scratch_va,p->mem_low,
                        p->mem_high,&cpu_scratch)!=CPU_OK)return 0;
    struct fine_cpu *f=fine_cpu(c);
    struct fine_call_state s={.x16=x16,.a0=frame[0],.a1=frame[1],.a2=frame[2],.a3=frame[3],
                              .elr=g_elr,.kind=kind,.reason=FINE_NO_STATE};
    /* L0: the gate, shared. A token holder makes this CPU wait like a token
     * waiter (bounded: a long wait declines and the locked path waits, with
     * its deadline and stop handling). */
    uint64_t t0=service_profile_clock(),t1,t2;
    enum guest_service_result gate;
#if SNAP_GATE_WAIT
#define GATE_WAIT_BUILT 1
    /* compat/token-costs.h: wait out a long token hold, up to 1/200 s and
     * never past this CPU's probe budget, before declining; the locked
     * path's own wait has the one-second deadline and stop handling. */
#if SNAP_PHASE_FAIR_GATE
    /* compat/service-lock.h: a BUSY arrival is announced in the present
     * writer's bank and enters when that writer's phase ends (the next
     * writer waits for it); at the bound it is withdrawn before declining,
     * or this CPU's own token drain would wait for it. */
    unsigned ahead=0;
#endif
    for(int waited=0;;waited=1) {
#if SNAP_PHASE_FAIR_GATE
        gate=waited ? guest_service_wait_shared(&c->services,v->slot,&ahead) :
                      guest_service_enter_shared(&c->services,v->slot);
#else
        gate=guest_service_enter_shared(&c->services,v->slot);
#endif
        uint64_t now=service_profile_clock();
        if(gate!=SERVICE_BUSY) {
            if(waited && gate==SERVICE_OK) {
                fine_add(&c->root_ext->gate[0],1);fine_add(&c->root_ext->gate[1],now-t0);
#if SNAP_PHASE_FAIR_GATE
                if(ahead)fine_add(&c->root_ext->gate[4],1);   /* entered ahead of a queued writer */
#endif
            }
            if(gate==SERVICE_STOPPED)fine_add(&c->root_ext->gate[3],1);
            break;
        }
        if((int64_t)(now-t0-c->params->clock_host_hz/200)>=0 ||
           (v->watchdog_live && (int64_t)(now-v->watchdog_deadline)>=0)) {
#if SNAP_PHASE_FAIR_GATE
            guest_service_leave_shared(&c->services,v->slot);   /* withdraw the arrival */
#endif
            fine_add(&c->root_ext->gate[2],1);break;
        }
        __asm__ volatile("yield");
    }
#else
    for(unsigned spins=0;;spins++) {
        gate=guest_service_enter_shared(&c->services,v->slot);
        if(gate!=SERVICE_BUSY || spins>=(1u<<16))break;
        __asm__ volatile("yield");
    }
#endif
    if(gate!=SERVICE_OK) {f->profile.declined[FINE_NO_GATE]++;return 0;}
    t1=service_profile_clock();
    int result=FINE_DECLINE;
    int admitted=fine_state_admits(c);
    if(admitted)s.reason=FINE_NO_ROOT;
#if SNAP_SPTM_FINE_RETYPE
    /* This call's frame locks (compat/sptm-frame-lock.h), empty until here and
     * released at the one point below, after the call's last TLBI (S5, S25):
     * its reference first touches through ref_fine.held, its input frames now. */
    f->frames.locks=&fine_of(c)->frame_locks;f->frames.count=0;f->frames.exclusive=0;
    f->ref_fine.held=&f->frames;
    if(admitted && !fine_input_frames(c,&s)) {admitted=0;s.reason=FINE_NO_FRAME;}
#endif
    if(admitted && fine_lockset_for(c,&s,&f->locks)) {
        unsigned waited=fine_lockset_acquire(fine_of(c)->stripes,&f->locks);
#if SNAP_SPTM_FINE_KERNEL
        /* KL after the (empty) stripe set: a kernel call holds no stripe. Its
         * wait is charged as stripe wait. */
        int kernel=FINE_KERNEL_CALL(kind);
        if(kernel)waited+=(unsigned)fine_ticket_lock(&fine_of(c)->kernel);
#endif
        t2=service_profile_clock();
        f->stores=0;f->alloc_refused=0;f->aux_wait=0;f->audit=(struct sptm_pv_audit){0};
        s.reason=FINE_NO_SHAPE;
        result=kind==FINE_CALL_MAP_PAGE ? fine_map_page(c,frame,cpu_scratch.pa,&s) :
               kind==FINE_CALL_UNMAP_REGION ? fine_unmap_region(c,frame,cpu_scratch.pa,&s) :
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
               FINE_DART_CALL(kind) ? fine_dart_call(c,frame,&s) :
#endif
#if SNAP_ANS_CONVERTED
               kind==FINE_CALL_ANS_SPTM ? fine_ans_sptm(c,frame,&s) :
#endif
#if SNAP_FAST_PAUTH_CALLS
               kind==FINE_CALL_PAUTH ? fine_pauth_pointer(c,frame,&s) :
               kind==FINE_CALL_PAUTH_BATCH ? fine_pauth_batch(c,frame,&cpu_scratch,&s) :
#endif
#if SNAP_SPTM_FINE
               kind==FINE_CALL_UNMAP_DISJOINT ? fine_unmap_disjoint(c,frame,cpu_scratch.pa,&s) :
               kind==FINE_CALL_UPDATE_REGION ? fine_update_region(c,frame,cpu_scratch.pa,&s) :
#endif
#if SNAP_SPTM_FINE_RETYPE
               kind==FINE_CALL_RETYPE ? fine_retype(c,frame,&s) :
#endif
#if SNAP_SPTM_FINE_KERNEL
               kind==FINE_CALL_KERNEL_MAP ? fine_kernel_map(c,frame,cpu_scratch.pa,&s) :
               kind==FINE_CALL_KERNEL_UNMAP ? fine_kernel_unmap(c,frame,cpu_scratch.pa,&s) :
#endif
#if SNAP_FINE_SWITCH
               kind!=FINE_CALL_UPDATE_DISJOINT ? fine_switch_root(c,frame,&s) :
#endif
               fine_update_disjoint(c,frame,cpu_scratch.pa,&s);
        if(result!=FINE_DECLINE) {
            /* The call entry's effects (xnuboot_trap_locked before
             * monitor_request), now that the call is no longer declined. */
            ns->calls++;ns->last_pc=g_elr;ns->last_word=word;ns->last_saved=saved;
            ns->last_physical=physical;
            native_exception_restore(ns);
            __asm__ volatile("msr spsr_el2, %0" :: "r"(physical) : "memory");
            *elr=g_elr;
        }
        if(result==FINE_DONE) {
            /* monitor_call_impl's prologue (endpoint count, audit share,
             * arena check, EV_MONITOR), the case's own record and its
             * epilogue (calls), in the locked path's order. */
            fine_aux_lock(c);
#if SNAP_ANS_CONVERTED
            /* A table-6 call is counted as other, as monitor_call_impl does. */
            if(kind==FINE_CALL_ANS_SPTM)c->endpoint_other++;else
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
            /* A table-3 call is counted as other, as monitor_call_impl does (18). */
            if(FINE_DART_CALL(kind))c->endpoint_other++;else
#endif
            c->endpoint_calls[x16 & (ENDPOINT_BUCKETS - 1)]++;
            struct arena_reclaim_stats *a=&c->arena_reclaim;
            uint64_t available=arena_available(c);
            if(!a->checks || available<a->low_water)a->low_water=available;
            a->checks++;
#if SNAP_ANS_CONVERTED
            /* call_other records no table-6 MAP/UNMAP_PAGES (one each per SSD command). */
            if(kind!=FINE_CALL_ANS_SPTM)
#endif
            record(c,EV_MONITOR,g_elr,x16,s.a0,s.a1);
            if(kind==FINE_CALL_UNMAP_REGION)record(c,EV_UNMAP_REGION,g_elr,s.a1,s.a2,s.a3);
#if SNAP_SPTM_FINE_RETYPE
            if(kind==FINE_CALL_RETYPE)record(c,EV_RETYPE,g_elr,s.a0,(s.a1<<32)|(s.a2&0xffffffffUL),s.a3);
#endif
#if SNAP_SPTM_FINE_KERNEL
            if(kind==FINE_CALL_KERNEL_UNMAP)record(c,EV_UNMAP_REGION,g_elr,s.a1,s.a2,s.a3);
            if(s.aux_note)auxkc_note_leaf(c,AUXKC_KIND_MAP,g_elr,s.aux_va,s.aux_old,s.aux_new);
#endif
            struct sptm_pv_audit *pv=&c->pv_audit,*mine=&f->audit;
#if SNAP_FAST_PAUTH_CALLS
            /* A pointer call has no reference batch: the pending share stays
             * for the next reference call, which clears it at its own entry;
             * its audit share is zero and merges as nothing. */
            if(!FINE_POINTER_CALL(kind))
#endif
            pv->pending=0;
            pv->moved_pointers+=mine->moved_pointers;
            if(mine->remaps) {pv->remaps+=mine->remaps;pv->remap_va=mine->remap_va;
                pv->remap_old=mine->remap_old;pv->remap_next=mine->remap_next;}
            if(mine->duplicate_records) {pv->duplicate_records+=mine->duplicate_records;
                pv->duplicate_root=mine->duplicate_root;pv->duplicate_va=mine->duplicate_va;}
            c->calls++;
            fine_aux_unlock(c);
        }
#if SNAP_SPTM_FINE_RETYPE
        sptm_frame_release(&f->frames);
#endif
#if SNAP_SPTM_FINE_KERNEL
        if(kernel)fine_ticket_unlock(&fine_of(c)->kernel);
#endif
        fine_lockset_release(fine_of(c)->stripes,&f->locks);
        uint64_t t3=service_profile_clock();
        guest_service_leave_shared(&c->services,v->slot);
        if(result!=FINE_DECLINE) {
            struct fine_bucket *b=&f->profile.call[kind];
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
            /* A DART call's device-lock wait is its stripe wait. */
            const uint64_t *dev=FINE_DART_STATE(c)->device_wait[v->slot];
            if(FINE_DART_CALL(kind)) {
                b->entries++;b->gate_wait+=t1-t0;b->stripe_wait+=t2-t1+dev[0];b->aux_wait+=f->aux_wait;
                b->hold+=t3-t2-f->aux_wait-dev[0];b->contended+=waited!=0 || dev[1];
            } else {
#endif
            b->entries++;b->gate_wait+=t1-t0;b->stripe_wait+=t2-t1;b->aux_wait+=f->aux_wait;
            b->hold+=t3-t2-f->aux_wait;b->contended+=waited!=0;
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
            }
#endif
#if SNAP_ANS_CONVERTED
            /* An ANS call's lock wait is its stripe wait, as a DART call's device wait. */
            if(kind==FINE_CALL_ANS_SPTM) {
                const uint64_t *aw=c->root_ext->ans_wait[v->slot];
                b->stripe_wait+=aw[0];b->hold-=aw[0];b->contended+=!waited && aw[1];
            }
#endif
        }
    }
#if SNAP_SPTM_FINE_RETYPE
    else {sptm_frame_release(&f->frames);guest_service_leave_shared(&c->services,v->slot);}
#else
    else guest_service_leave_shared(&c->services,v->slot);
#endif
    if(result==FINE_DECLINE) {f->profile.declined[s.reason]++;return 0;}
    if(result==FINE_FATAL) {
        f->profile.failures++;
        *stop=fine_fatal(c,frame,esr,elr,&s);
        if(*stop && !v->async_captured) {fill_regs(&v->async_regs,frame,esr,*elr,0);v->async_captured=1;}
        return 1;
    }
    /* monitor_request's step_translation_clear (runtime_enter's for this
     * category too), *elr over the call, runtime_leave's stop decision. */
    step_translation_clear(&c->step_translation[v->slot]);
    *elr+=4;
    int stopping=fine_failed(c)!=0;
    if(stopping)guest_service_stop(&c->services,v->slot,SERVICE_STOP_NORMAL);
    *stop=stopping || guest_service_stopped(&c->services)!=0;
    if(*stop && !v->async_captured) {fill_regs(&v->async_regs,frame,esr,*elr,0);v->async_captured=1;}
    return 1;
}
#if SNAP_ANS_CONVERTED
/* xnuboot_trap's converted ANS MMIO call: a 32-bit store from EL1 to the virtual
 * ANS2's I/O SQ doorbell (0x24910) or I/O CQ head doorbell (0x100c), routed as
 * the locked path routes a data abort (fast_idle_poll's classification). The
 * locked path's model_dispatch for it, with the gate shared and the ANS lock
 * held: ans_mmio (queue and poll, never wait: SNAP_ANS_ASYNC), the ANS lines
 * and this vCPU's view of them, the write count; device_models_route_irqs and
 * timer_sync's model scan are skipped (no other model changed, no model
 * deadline moved; the deadline this call may have started is armed through
 * timer_arm). 0: declined, nothing changed. 1: handled, *stop as xnuboot_trap
 * would return. A refusal is terminal with model_dispatch's EV_ANS record,
 * under the token after the gate was left. */
static int fine_ans_mmio(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr,int *stop)
{
    if((esr>>26)!=0x24 || (esr&(1UL<<7)))return 0;
    struct dc_access acc=dc_decode(esr);
    if(!acc.valid || !acc.write || acc.size!=4)return 0;
    struct ans_state *st=c->root_ext->ans;
    if(!st)return 0;
    struct vcpu *v=vcpu_of(c);
    const struct params *p=c->params;
    uint64_t spsr,far,hpfar;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2; mrs %2, hpfar_el2":"=r"(spsr),"=r"(far),"=r"(hpfar));
    if((spsr&31)!=4 && (spsr&31)!=5)return 0;
    uint64_t ipa=guest_pa(far),off=0;
    if(!ipa && (hpfar&0x0000fffffffffff0UL))ipa=((hpfar>>4)<<12)|(far&0xfff);
    if(!ipa || dc_window(p->device_pa,p->device_span,p->device_count,ipa,&off)>=0)return 0;
    int index=device_model_find(p->models,p->model_count,ipa,&off);
    if(index<0 || p->models[index].kind!=DEVICE_ANS_NVME_V1 || (off!=0x24910 && off!=0x100c))return 0;
    struct fine_cpu *f=fine_cpu(c);
    if(!fast_admitted(c,v,esr) || !fast_lines_current(v) || fast_reset_latched(c)) {
        f->profile.declined[FINE_NO_STATE]++;return 0;
    }
    uint64_t value=dc_narrow(&acc,acc.reg==31 ? 0 : frame[acc.reg]);
    /* L0, shared: fine_sptm_call's bounded wait (its statements, this CPU's lock and slot named once). */
    uint64_t t0=service_profile_clock(),t1,t2,t3;
    struct guest_service_lock *gl=&c->services;
    unsigned me=(unsigned)v->slot;
    enum guest_service_result gate;
#if SNAP_GATE_WAIT
#if SNAP_PHASE_FAIR_GATE
    unsigned ahead=0;
#endif
    for(int again=0;;again=1) {
#if SNAP_PHASE_FAIR_GATE
        gate=again ? guest_service_wait_shared(gl,me,&ahead) : guest_service_enter_shared(gl,me);
#else
        gate=guest_service_enter_shared(gl,me);
#endif
        uint64_t now=service_profile_clock();
        if(gate!=SERVICE_BUSY) {
            if(again && gate==SERVICE_OK) {
                fine_add(&c->root_ext->gate[0],1);fine_add(&c->root_ext->gate[1],now-t0);
#if SNAP_PHASE_FAIR_GATE
                if(ahead)fine_add(&c->root_ext->gate[4],1);
#endif
            }
            if(gate==SERVICE_STOPPED)fine_add(&c->root_ext->gate[3],1);
            break;
        }
        if((int64_t)(now-t0-p->clock_host_hz/200)>=0 ||
           (v->watchdog_live && (int64_t)(now-v->watchdog_deadline)>=0)) {
#if SNAP_PHASE_FAIR_GATE
            guest_service_leave_shared(gl,me);       /* withdraw the arrival */
#endif
            fine_add(&c->root_ext->gate[2],1);break;
        }
        __asm__ volatile("yield");
    }
#else
    for(unsigned tries=0;;tries++) {
        gate=guest_service_enter_shared(gl,me);
        if(gate!=SERVICE_BUSY || tries>=(1u<<16))break;
        __asm__ volatile("yield");
    }
#endif
    if(gate!=SERVICE_OK) {f->profile.declined[FINE_NO_GATE]++;return 0;}
    t1=service_profile_clock();
    if(!fine_state_admits(c)) {
        guest_service_leave_shared(&c->services,v->slot);
        f->profile.declined[FINE_NO_STATE]++;return 0;
    }
    fine_ans_lock(c);
    t2=service_profile_clock();
    f->aux_wait=0;
    struct ans_ops o=fine_ans_ops(c);
    int r=ans_mmio(st,&o,1,off,4,1,&value);
    if(!r) {
        ans_async_schedule(c);
        if(ans_async_lines(c)!=DEVICE_OK)r=ANS_E_STATE;
    }
    fine_ans_unlock(c);
    t3=service_profile_clock();
    guest_service_leave_shared(&c->services,v->slot);
    const uint64_t *aw=c->root_ext->ans_wait[v->slot];
    struct fine_bucket *b=&f->profile.call[FINE_CALL_ANS_MMIO];
    b->entries++;b->gate_wait+=t1-t0;b->stripe_wait+=aw[0];b->aux_wait+=f->aux_wait;
    b->hold+=t3-t2-f->aux_wait;b->contended+=aw[1];
    if(r) {
        /* model_dispatch's refusal: EV_ANS (reason << 32 | kind), the access, and the stop. */
        f->profile.failures++;
        if(!runtime_enter(c,frame,*elr,0x24)) {*stop=1;return 1;}
        record(c,EV_ANS,*elr,(uint64_t)(r&0xff)<<32|DEVICE_ANS_NVME_V1,ipa,esr);
        fill_regs(&v->async_regs,frame,esr,*elr,ipa);
        v->async_captured=3;
        *stop=runtime_leave(c,1);
        return 1;
    }
    /* model_dispatch's success: the write count, the lines, the next instruction. */
    __atomic_fetch_add(&c->model_writes[index],1,__ATOMIC_RELAXED);
    step_translation_clear(&c->step_translation[v->slot]);
    guest_interrupt_sync(c);
    timer_arm(c,service_profile_clock(),c->fast_timer_due[v->slot].guest);
    *elr+=4;
    /* fine_sptm_call's stop decision. */
    int stopping=fine_failed(c)!=0;
    if(stopping)guest_service_stop(&c->services,v->slot,SERVICE_STOP_NORMAL);
    *stop=stopping || guest_service_stopped(&c->services)!=0;
    if(*stop && !v->async_captured) {fill_regs(&v->async_regs,frame,esr,*elr,0);v->async_captured=1;}
    return 1;
}
#endif
#endif
