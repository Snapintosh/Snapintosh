/* SPDX-License-Identifier: MIT */
/* SPTM endpoint numbers and return codes: from m1n1, https://github.com/AsahiLinux/m1n1:
 * Copyright The Asahi Linux Contributors, MIT. */
/* Apple IMPDEF register names and monitor_call_impl, the SPTM/TXM call
 * dispatcher.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

/* Apple IMPDEF registers, reached through HCR_EL2.TIDCP. Names from
 * m1n1 (AsahiLinux, cpu_regs.h) and the author's J700 research fork. */
#define SR_AMXIDR_EL1     SYSREG(3, 6, 15, 2, 7)
#define SR_GXF_STATUS_EL1 SYSREG(3, 6, 15, 8, 0)
#define SR_CONST_LOWER   SYSREG(3, 0, 11, 1, 2)
#define SR_CONST_UPPER   SYSREG(3, 0, 11, 1, 3)


/* AMX is not optional to this kernel. `machine_routines_apple.c:165` decodes
 * AMXIDR_EL1 as a version: bits 0..5 select versions 1..6, anything set in bits
 * 6..15 panics, and so does zero --
 *
 *     panic: AMXIDR_EL1 doesn't advertise any known version of AMX
 *
 * which is what a zero answer produced. Version 1 is the smallest claim that
 * satisfies it, and XNU takes an extra path only at version 5 and above, so it
 * is also the one that asks the least of a machine that has no AMX at all. */
#define AMXIDR_VERSION_1  1UL

/* Opt-in: after XNU's PANIC_ENTRY, serve ordinary calls instead of stopping.
 * Apple's dispatcher then switches to a panic-only protocol this monitor does
 * not implement (docs/PANIC-STATE-HANDOFF-20260922.md), so by default the first
 * post-panic call from any CPU stops the run, which can happen before the
 * panicking CPU has printed its panic string (v32: CPU 1's SWITCH_ROOT after
 * CPU 2's entry). With this define the dying guest is served as if it had not
 * panicked, so it can finish its report; panic_state.rejected counts the calls
 * served this way. An invalid panic state still stops. */
#ifndef SNAP_PANIC_SERVE
#define SNAP_PANIC_SERVE 0
#endif

/* Answer a monitor call in place, or 0 if it is one we do not implement yet.
 *
 * The first thing a stock XNU asks for is SERIAL_PUTC. Answering it is what
 * turns this from a machine that stops at the first question into one that
 * tells us what it is doing, so it is the first endpoint implemented and the
 * console it produces is the report. */
static int monitor_call_impl(struct context *c, uint64_t *frame, uint64_t *elr)
{
    uint64_t x16 = frame[16];
    uint32_t cmd = (uint32_t)((x16 >> 56) & 0xff);
    uint32_t domain = (uint32_t)((x16 >> 48) & 0xff);
    /* Sixteen bits, not eight. Not a live bug in this kernelcache -- all 173
     * distinct x16 constants it builds have bits 47:40 clear, so the two masks
     * give identical answers for every call it makes -- but the dispatcher
     * takes the whole of bits 63:32 with `lsr x21, x0, #32` and narrows
     * nothing, so eight bits is an assumption rather than a reading. Widening
     * costs nothing and makes two tables aliasing onto one impossible, which is
     * the bug this file just fixed one field over. */
    uint32_t table = (uint32_t)((x16 >> 32) & 0xffff);
    uint32_t endpoint = (uint32_t)x16;
    if(!sptm_panic_dispatch(&c->panic_state,(unsigned)vcpu_of(c)->slot,x16)
#if SNAP_PANIC_SERVE
       && !(c->panic_state.triggered==1 && c->panic_state.phase==1 && c->panic_state.owner<6 &&
            vcpu_of(c)->slot<6)
#endif
       ) {
        record(c,EV_PANIC_STATE_FAILED,*elr,x16,c->panic_state.owner,vcpu_of(c)->slot);
        return 0;
    }

    /* Counted here, at the top, before any branch can decline to answer.
     *
     * Every path out of this function is a call that happened: the ones we
     * implement, the ones we acknowledge permissively, and the ones we refuse
     * and stop on. Counting after the dispatch would leave the refusals out,
     * and the refusals are the ones worth counting. The guard on `endpoint` is
     * what keeps the index honest rather than merely in range -- see the
     * declaration. */
    if (cmd == SPTM_CMD_ENDPOINT && domain == 0 && table == 0 &&
        endpoint < ENDPOINT_BUCKETS)
        c->endpoint_calls[endpoint & (ENDPOINT_BUCKETS - 1)]++;
    else
        c->endpoint_other++;
    /* A reference batch abandoned by an earlier refusal is not a remap. */
    c->pv_audit.pending = 0;
    /* Before any endpoint can allocate a table: restore the arena reserve. */
    if (cmd == SPTM_CMD_ENDPOINT) arena_reserve(c, frame);

    /* The dispatch command comes first, because it decides whether the rest of
     * the word means anything at all.
     *
     * This field was unread until now, and not reading it was not a cosmetic
     * gap: four distinct calls the kernel makes -- x16 = 0x02, 0x04, 0x05 and
     * 0x06 in bits 63:56, with domain, table and endpoint all zero -- decoded
     * as domain 0 / table 0 / endpoint 0, which is LOCKDOWN. We answered all
     * four with SPTM_SUCCESS. Four different questions, one wrong answer each.
     *
     * SPTM's own dispatcher is the authority. `dispatch_cmd_handler` at
     * 0xfffffff0270f2270 does exactly this:
     *
     *   lsr  x20, x0, #56          ; the dispatch command
     *   ubfx x9,  x0, #48, #8      ; the domain
     *   lsr  x21, x0, #32          ; the table, in the low byte
     *   cmp  x20, #0x7 ; b.hs      -> illegal dispatch command
     *   ldr  x10, [x12, x20, lsl #3]   ; table[calling_domain][command]
     *
     * so the commands run 0..6 and are indexed per calling domain, and its
     * error strings name the field: "dispatch_cmd_id(%u)",
     * VIOLATION_ILLEGAL_DISPATCH_CMD. XNU is calling domain 1: the table at
     * 0xfffffff02701f4f8 has handlers for that row at commands 0, 4, 5 and 6,
     * and command 2 is special-cased before the lookup (0xfffffff0270f2310
     * tests exactly `cmd == 2 && calling_domain == 1`). That is the full set
     * the kernelcache emits, which is the cross-check.
     *
     * Command 0 is an ordinary endpoint call and is the only one this monitor
     * implements. The genuine LOCKDOWN call still reaches its handler: the stub
     * at 0xfffffe000c22b37c builds x16 = 0 outright -- all four fields zero --
     * and its genter is at 0xfffffe000c22b38c. */
    if (cmd == SPTM_CMD_PANIC_ENTRY) {
        if(x16!=UINT64_C(0x0200000000000000) ||
           !sptm_panic_enter(&c->panic_state,(unsigned)vcpu_of(c)->slot)) {
            record(c,EV_PANIC_STATE_FAILED,*elr,x16,c->panic_state.owner,vcpu_of(c)->slot);
            return 0;
        }
        /* The same global service token serializes first-owner selection,
         * byte publication and the return to any of the six guest CPUs. */
        uint64_t panic_page=c->params->scratch_pa-SPTM_PANIC_PAGE_SIZE;
        *(volatile uint8_t *)panic_page=1;
        publish(panic_page,panic_page+1);
        /* XNU announcing that it is taking a fatal exception.
         *
         * Implemented, not acknowledged, and the distinction is the point: the
         * return values below are not a permissive stub that happens to be
         * zero. Apple's handler is the five instructions at 0xfffffff0270f2520
         * -- a call to a helper, `mov x0, #0`, `mov x1, #0`, and a branch to the
         * monitor exit -- so zero in both is byte-for-byte what the real monitor
         * returns. The trampoline marshals nothing (`mov x16, #0x200...; genter;
         * ret`), so there are no arguments to read either.
         *
         * The helper at 0xfffffff0270f220c has exactly three side effects and
         * including a guest-visible byte: 0xfffffff0271100a4 is set
         * to 1, a halfword at 0xfffffff02710c00c compare-and-swapped from its
         * 0x8000 "nobody" sentinel to this CPU's logical id, and a byte at
         * 0xfffffff02710c00e swapped from 0xff to 1. XNU's EL0 fault path
         * reads that byte through handoff +0x198. The loader supplies a private
         * page, read-only and execute-never in all six stage-2 roots.
         *
         * First-owner and flag semantics are implemented. Native SPTM's
         * restricted panic dispatch uses a separate exception-return protocol;
         * that protocol remains unsupported. The gate above stops explicitly
         * if requested instead of continuing ordinary services after panic.
         *
         * It is rare, not hot, and the distinction was worth correcting: this
         * is not called on every synchronous exception. XNU runs the kernel
         * with SPSel = 0, so an ordinary kernel exception takes the EL1t vector
         * and never comes here; the EL1h sites are reached only when an
         * exception happened inside a handler, which SPTM itself calls an error
         * ("Synchronous exception taken while SP1 selected"). The normal
         * continuation at 0xfffffe000b86f61c gates twice before calling --
         * `tst x4, #0xc` on SPSR_EL1 so EL0 exceptions never reach it, then a
         * fatal-class predicate at 0xfffffe000ba862c0 -- so it fires for
         * unrecoverable kernel control-flow failures and nothing else. Never
         * for EL0, never for ordinary page faults, never for copyio. In
         * practice once per boot. */
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);

        /* The fault itself, which is the reason this call is worth anything.
         *
         * XNU reads ELR_EL1, ESR_EL1 and FAR_EL1 into x26, x27 and x28 in the
         * three instructions before the genter -- but only at three of the six
         * call sites. At 0xfffffe000b86ebbc (the wedge), 0xfffffe000b8c13b8 and
         * 0xfffffe000b8c1b48, those registers hold something else entirely, so
         * reading them as a fault there would report a per-CPU pointer as a
         * faulting address and be believed.
         *
         * So the registers are recorded raw and the host decides, and the
         * system registers are read here as well: EL1 still holds the fault
         * that got us here -- XNU has only copied them, not rewritten them --
         * which is a source that does not depend on which caller it was. */
        uint64_t p_esr, p_far, p_elr;
        __asm__ volatile("mrs %0, esr_el1" : "=r"(p_esr));
        __asm__ volatile("mrs %0, far_el1" : "=r"(p_far));
        __asm__ volatile("mrs %0, elr_el1" : "=r"(p_elr));
        if (!vcpu_of(c)->panic_calls)
            fill_regs(&vcpu_of(c)->panic_exc, frame, p_esr, p_elr, p_far);
        /* x30 names the caller, and one of them decides whether anything after
         * this runs at all: a return to 0xfffffe000b86ebc0 lands on `wfe` and a
         * branch to itself. The host spells that out. */
        record(c, EV_PANIC_ENTRY, *elr, frame[30], p_elr, p_esr);
        vcpu_of(c)->panic_calls++;

        frame[0] = 0;
        frame[1] = 0;
        c->calls++;
        *elr += 4;
        return 1;
    }

    if (cmd != SPTM_CMD_ENDPOINT) {
        /* Recorded twice on purpose: once as the call it is, so the transcript
         * shows where it sits in the sequence, and once as the reason we
         * stopped, so the last event names the command rather than leaving a
         * reader to decode the top byte of x16 by hand. */
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        record(c, EV_DISPATCH_CMD, *elr, cmd, domain, x16);
        c->dispatch_cmds++;
        /* Not answered, and not answered even in permissive mode.
         *
         * Permissive exists so one run can show the whole sequence of endpoints
         * XNU asks for, and for an endpoint the cost of a false acknowledgement
         * is a wrong value. Here it is worse than that. Two of these calls do
         * not return: the trampolines for 0x05 (0xfffffe000c22a9b0) and 0x06
         * (0xfffffe000c22a9d4) are followed by `b #0x0`, a branch to
         * themselves, because SPTM transfers control into another domain and
         * never comes back to that instruction. Stepping over one of those puts
         * the guest in a one-instruction infinite loop, which the watchdog
         * would report as "still running" -- a hang wearing the costume of
         * progress. 0x04 does not return either. Only 0x02 ends in a `ret`.
         *
         * So there is no acknowledgement to give that is not a lie, and the
         * honest move is to stop and say which command was asked for. */
        return 0;
    }

    if (domain == 2 && table == 0 &&
        (endpoint == 1 || endpoint == 2 || endpoint == 3 || endpoint == 7 || endpoint == 12 || endpoint == 14 || endpoint == 16 ||
         endpoint == 26 || endpoint == 30 || endpoint == 31 ||
         endpoint == 35 || endpoint == 36 || endpoint == 37 || endpoint == 45 || endpoint == 52)) {
        const struct params *p = c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        memory.retype_txm_owned=sptm_retype_txm_owned;
        struct sptm_aperture aperture = {p->mem_low, p->ram_aperture_va,
                                        p->mem_high - p->mem_low};
        struct txm_service service = {p->txm_stacks_pa, p->txm_stack_count,
            p->txm_log_pa, sptm_aperture_pointer(&aperture, p->txm_log_pa, 0x4000),
            p->txm_rw_pa, sptm_aperture_pointer(&aperture, p->txm_rw_pa, 0x4000),
            p->txm_ro_pa, sptm_aperture_pointer(&aperture, p->txm_ro_pa, 0x4000)};
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        struct txm_arena arena = {p->txm_aspace_pa,
            sptm_aperture_pointer(&aperture, p->txm_aspace_pa, TXM_ASPACE_SIZE)};
        struct txm_kernel_memory kernel_memory={&memory,
            vcpu_of(c)->guest_ttbr1&0x0000ffffffffc000UL,vcpu_of(c)->guest_tcr};
        uint64_t image4_status=TXM_IMAGE4_UUID_UNAVAILABLE;
        uint64_t trust_status=TXM_TRUST_CACHE_MISS;
        uint64_t compilation_status=8;
        struct txm_load_ops load_ops={c,txm_load_prepare,txm_load_stage,txm_load_authenticate};
        enum sptm_result result = !service.log_va ? SPTM_BAD_CONFIG :
            endpoint == 12 ?
            txm_trust_load(&memory,&service,&p->trust_cache,&c->trust_state,
                &c->txm_load,&load_ops,frame,&trust_status) :
            endpoint == 7 ?
            txm_sep_channel_unavailable(&memory,&service,endpoint,frame) :
            endpoint == 26 ?
            txm_set_local_key(&memory,&service,&c->txm_local_key,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame) :
            endpoint == 52 ?
            txm_image4_nonce_digest(&memory,&service,&c->txm_nonce_digests,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame) :
            endpoint == 14 ?
            txm_trust_query(&memory,&service,&p->trust_cache,&c->trust_state,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&trust_status) :
            endpoint == 16 ?
            txm_trust_uuid(&memory,&service,&p->trust_cache,&c->trust_state,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&trust_status) :
            endpoint == 30 ?
            txm_compilation_match_empty(&memory,&service,txm_copy_kernel_input,
                &kernel_memory,endpoint,frame,&compilation_status) :
            endpoint == 45 && frame[1]==0 ?
            txm_image4_release_type(&memory,&service,&c->txm_release_type,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&image4_status) :
            endpoint == 45 && frame[1]==3 ?
            txm_image4_nonce(&memory,&service,&c->txm_nonces,
                txm_copy_kernel_input,&kernel_memory,endpoint,frame,&image4_status) :
            endpoint == 45 ? txm_image4(&memory,&service,endpoint,frame) :
            endpoint == 31 ?
            txm_developer_mode(&memory, &service, endpoint, frame) :
            endpoint == 35 || endpoint == 36 || endpoint == 37 ?
            txm_aspace(&memory, &service, &arena, TXM_REG(c), endpoint, frame) :
            txm_info_with_trust(&memory,&service,&p->trust_cache,&c->trust_state,endpoint,frame);
        if (result != SPTM_OK) {
            record(c,EV_TXM_FAILED,*elr,result,
                   frame[1],endpoint);return 0;
        }
        frame[0] = endpoint==45 ? image4_status : (endpoint==12 || endpoint==14) ? trust_status :
            endpoint==30 ? compilation_status : endpoint==7 ? TXM_SEP_CHANNEL_UNAVAILABLE : 0;
        if (endpoint==45 && frame[1]==6) c->txm_image4_uuid_rejections++;
        if (endpoint == 31) c->txm_developer_notifications++;
        c->calls++;
        *elr += 4;
        return 1;
    }
    if (domain == 0 && table == 3 && (endpoint == 0 || endpoint == 2 || endpoint == 3 || endpoint == 8)) {
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        unsigned index;
        unsigned level=endpoint==0 ? (unsigned)frame[3] : (endpoint==2 || endpoint==3) ? 2 : 0;
        if (frame[0]>=32 || frame[1]>=2 || (endpoint==0 && frame[3]>2) ||
            device_dart_admit_frame(c->params->models,c->model_state,
                (unsigned)c->params->model_count,5,(unsigned)frame[0],
                (unsigned)frame[1],level,&index)!=DEVICE_OK) return 0;
        struct sptm_memory memory=sptm_context_memory(c);
        enum sptm_result result=endpoint==0 ?
            sptm_dart_map_table(&memory,&c->model_state[index].dart,
                frame[0],frame[1],frame[2],frame[3],frame[4]) :
            endpoint==2 ? sptm_dart_map(&memory,&c->model_state[index].dart,
                frame[0],frame[1],frame[2],frame[3],frame[4],frame[5]) :
            endpoint==3 ? sptm_dart_unmap(&memory,&c->model_state[index].dart,
                frame[0],frame[1],frame[2],frame[3],frame[4]) :
            sptm_dart_enable(&memory,&c->model_state[index].dart,frame[0],frame[1]);
        if (result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[2],frame[4]);return 0;
        }
        /* Stage 4: stream 0 of the Adreno virtual DART, into SMMU CB0. UNMAP
         * returns only after the SMMU TLB invalidation has completed. */
        const struct params *gp=c->params;
        if ((endpoint==2 || endpoint==3) && (gp->gpu.flags & ADRENO_F_DART) &&
            frame[0]==SPTM_DART_ADRENO && !frame[1]) {
            struct gpu_leaf_ctx leaf={&memory,&c->model_state[index].dart};
            struct adreno_ops o=GPU_LEAF_OPS(c);
            if (endpoint==2) c->gpu.maps++; else c->gpu.unmaps++;
            int e=adreno_mirror(&o,&gp->gpu,&c->gpu,frame[2],endpoint==2 ? frame[4] : frame[3],
                                gpu_leaf,&leaf,gp->mem_low,gp->mem_high);
            if (e) {record(c,EV_GPU_SMMU,*elr,(uint64_t)(int64_t)e,frame[2],endpoint);return 0;}
        }
        frame[0]=0;c->calls++;*elr+=4;return 1;
    }
    if (domain == 0 && table == 3 && (endpoint == 5 || endpoint == 6)) {
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        enum device_result result=endpoint==6 ?
            device_dart_monitor_init(c->params->models,c->model_state,
                (unsigned)c->params->model_count,frame[0]) :
            device_dart_monitor_powerup(c->params->models,c->model_state,
                (unsigned)c->params->model_count,frame[0]);
        if (result != DEVICE_OK) return 0;
        /* Both services are void. The kernel control wrapper supplies its
         * own success status; x1..x7 are not inputs. */
        frame[0] = 0;
        c->calls++;
        *elr += 4;
        return 1;
    }
    if (domain == 0 && table == 7 && endpoint == 12) {
        const struct params *p = c->params;
        struct sptm_aperture aperture = {p->mem_low, p->ram_aperture_va,
                                        p->mem_high - p->mem_low};
        uint64_t value;
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        if (uat_get_info(&p->uat, &aperture, frame[0], &value) != SPTM_OK) return 0;
        frame[0] = value;
        c->calls++;
        *elr += 4;
        return 1;
    }
    if (domain == 0 && table == 9) {
        uint64_t value;
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        if (!cputrace_empty_query(endpoint, &value)) return 0;
        if (c->cputrace_queries[endpoint-1] != UINT32_MAX)
            c->cputrace_queries[endpoint-1]++;
        frame[0] = value;
        c->calls++;
        *elr += 4;
        return 1;
    }
    /* SPTM table 6 (NVME) and 5 (SART): the virtual ANS2 only. Without its
     * models these fall through exactly as before (unimplemented). */
    if (domain == 0 && (table == 5 || table == 6) && ans_state_of(c)) {
        struct ans_state *s=ans_state_of(c);
        struct ans_ops o=ans_ops_of(c);
        uint64_t ret=0;
        if (table == 5 || endpoint > 2) record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);
        int r=ans_sptm(s,&o,table,endpoint,frame,&ret);
        if (r) {
            record(c, EV_ANS, *elr, (uint64_t)r << 32 | table << 8 | endpoint, frame[0], frame[1]);
            return 0;
        }
#if SNAP_ANS_ASYNC
        /* The call polled queue 1 first (compat/ans.c): a completion it posted raises its line here, and a
         * command it started arms this vCPU's deadline (N3). */
        ans_async_schedule(c);
        if (ans_async_lines(c)!=DEVICE_OK) {
            record(c, EV_ANS, *elr, (uint64_t)ANS_E_STATE << 32 | table << 8 | endpoint, frame[0], frame[1]);
            return 0;
        }
        timer_sync(c);
#endif
        frame[0]=ret; c->calls++; *elr += 4;
        return 1;
    }
    if (domain != 0 || table != 0) return 0;

    /* Log every call, not just the ones we cannot answer. An implemented
     * endpoint that returns the wrong thing is invisible otherwise, and the
     * sequence of what XNU asks for is most of the evidence about what it is
     * doing. SERIAL_PUTC is the exception: it is one call per character and
     * would fill the log with the console, which is already captured. */
    if (endpoint != SPTM_FN_SERIAL_PUTC)
        record(c, EV_MONITOR, *elr, x16, frame[0], frame[1]);

    struct guest_cpu_buffer cpu_scratch;
    enum guest_cpu_result cpu_status = guest_cpu_buffer(&c->cpus,vcpu_of(c)->slot,
        c->params->scratch_pa,c->params->scratch_va,c->params->mem_low,
        c->params->mem_high,&cpu_scratch);
    if (cpu_status != CPU_OK) {
        record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,vcpu_of(c)->slot);
        return 0;
    }

    switch (endpoint) {
    case SPTM_FN_SIGN_USER_POINTER:
    case SPTM_FN_AUTH_USER_POINTER: {
#if SNAP_FAST_PAUTH_CALLS
        /* The converted call's body too; a refused configuration is
         * SPTM_BAD_CONFIG, recorded as below. */
        struct vcpu *v=vcpu_of(c);int ran=0;
        enum sptm_result result=user_pointer_call(c,frame,endpoint,&ran);
#else
        struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;uint64_t tcr;
        __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
        if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
           !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                     &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
            aes_clear(&native,sizeof(native));
            record(c,EV_TABLE_FAILED,*elr,SPTM_BAD_CONFIG,frame[0],endpoint);return 0;
        }
        enum sptm_result result=pauth_pointer(frame[0],frame[1],frame[2],
            endpoint==SPTM_FN_AUTH_USER_POINTER,(tcr>>37)&1,(tcr>>51)&1,
            pauth_pointer_native_sign,&native,&c->pauth_pointer[v->slot]);
        aes_clear(&native,sizeof(native));
#endif
        if(result) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],endpoint);return 0;
        }
        frame[0]=c->pauth_pointer[v->slot].result;
        break;
    }
    case SPTM_FN_BATCH_SIGN_USER_POINTER: {
#if SNAP_FAST_PAUTH_CALLS
        /* As above; a refused configuration ran nothing, so its record
         * names the endpoint, not a failed_index. */
        struct vcpu *v=vcpu_of(c);int ran=0;
        struct sptm_memory memory=sptm_context_memory(c);
        enum sptm_result result=user_pointer_batch(c,&memory,frame,&cpu_scratch,&ran);
        if(result) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],ran ? c->pauth_batch[v->slot].failed_index : endpoint);
            return 0;
        }
#else
        struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;
        struct sptm_memory memory=sptm_context_memory(c);uint64_t tcr;
        __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
        if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
           !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                     &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
            aes_clear(&native,sizeof(native));
            record(c,EV_TABLE_FAILED,*elr,SPTM_BAD_CONFIG,frame[0],endpoint);return 0;
        }
        enum sptm_result result=pauth_batch_sign(&memory,&c->pauth_batch[v->slot],
            frame[0],frame[1],cpu_scratch.pa,cpu_scratch.va,(tcr>>37)&1,(tcr>>51)&1,
            pauth_batch_native_sign,&native);
        aes_clear(&native,sizeof(native));
        if(result) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],c->pauth_batch[v->slot].failed_index);
            return 0;
        }
#endif
        frame[0]=c->pauth_batch[v->slot].result_va;
        break;
    }
    case SPTM_FN_SWITCH_ROOT: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_root_backend backend={.kernel_root=c->params->ttbr1_root,
            .kernel_shadow=vcpu_of(c)->low_root,.build=user_root_build,
            .install=user_root_install,.ctx=c,
            .validate=SNAP_ROOT_VALIDATE_WORDS ? &c->root_validate : 0,
            .evictions=&c->root_evictions,
            .memo=SNAP_ROOT_VALIDATE_MEMO ? &c->root_memo : 0,
            .skip_hit_validation=NATIVE_SKIP_HIT
#if SNAP_ROOT_MISS_FAST
            ,.stamp=USTAMPS(c),.linked_builds=1
#endif
#if SNAP_USER_HW_WALK
            ,.hw_eligible=hw_switch_eligible
#endif
            };
        uint64_t full=UNS(c).full;
        enum sptm_result r=sptm_mac_switch_root(&memory,&c->user_roots,&backend,
            (unsigned)vcpu_of(c)->slot,frame[0],frame[1],frame[2]);
        if(r || c->root_install_failures) {
            if(UNS(c).full!=full)
                record(c,EV_NATIVE_SHARED_FULL,*elr,UNS(c).full,frame[0],NATIVE_SHARED_GROUPS);
            else record(c,EV_REFERENCE_FAILED,*elr,r,frame[0],frame[1]);
            return 0;
        }
#if SNAP_USER_HW_WALK
        /* A hardware-walk root has a record, not a cache entry (v53). */
        if(!hw_walk_note_loaded(&c->user_roots,c->hw_walk,c->root_loaded,(unsigned)vcpu_of(c)->slot)) {
#else
        if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,(unsigned)vcpu_of(c)->slot)) {
#endif
            record(c,EV_REFERENCE_FAILED,*elr,SPTM_BAD_CONFIG,frame[0],frame[1]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_SLIDE_REGION: {
        const struct params *p=c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_update_backend backend={.kernel_root=p->ttbr1_root,
            .shadow_root=vcpu_of(c)->shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
        kernel_class_proof_forget(c);
        enum sptm_result result=sptm_mac_slide_region(&memory,&backend,&p->slide,
            &c->slide,frame[0],frame[1],c->lockdowns!=0);
        if(result!=SPTM_OK) {
            record(c,EV_SLIDE_FAILED,*elr,result,frame[0],frame[1]);return 0;
        }
        if(!transaction_publish(c)) {
            record(c,EV_SLIDE_FAILED,*elr,SPTM_SHADOW_FAILED,frame[0],frame[1]);return 0;
        }
        shadow_tlb_sync(c);
        record(c,EV_SLIDE_REGION,*elr,frame[0],c->slide.cursor-frame[1]*0x4000,frame[1]);
        frame[0]=SPTM_SUCCESS;
        break;
    }
    case SPTM_FN_UPDATE_REGION: {
        const struct params *p=c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        c->attr_updates.pending=0;
        if(frame[0]!=p->ttbr1_root) {
            struct sptm_user_backend user={0};uint64_t result=0;
            enum sptm_result r=SPTM_BAD_TABLE;
            if(user_backend(c,frame[0],&user)) {
                volatile uint8_t *meta=0;
                if(!(frame[0]&0x3fff) && sptm_managed_frame(&memory,frame[0]))
                    meta=memory.map(memory.ctx,memory.frame_map_pa+((frame[0]-memory.frame_low)>>14)*16,16);
                if(meta && meta[2]==SPTM_MAC_SHARED_ROOT_TABLE)
                    r=sptm_mac_update_shared_region(&memory,&user,frame[0],frame[1],frame[2],
                        frame[3],frame[4],cpu_scratch.pa,&result,&c->shared_regions_updates[vcpu_of(c)->slot]);
                else r=sptm_mac_update_user_region(&memory,&user,frame[0],frame[1],frame[2],
                        frame[3],frame[4],cpu_scratch.pa,&result,&c->user_regions[vcpu_of(c)->slot]);
            }
            if(r) {record(c,EV_REGION_FAILED,*elr,r,frame[1],frame[4]);return 0;}
            /* Every changed leaf's commit_update completed its all-VMID TLBI. */
            attr_clean_finish(c);
            frame[0]=result;break;
        }
        struct sptm_update_backend backend={.kernel_root=p->ttbr1_root,
            .shadow_root=vcpu_of(c)->shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
        enum sptm_result result=SPTM_BAD_CONFIG;
        if (((p->tcr>>16)&63)==17) {
            kernel_class_proof_forget(c);
            result=sptm_mac_update_region(&memory,&backend,&c->update_workspace,
                frame[0],frame[1],frame[2],frame[3],frame[4],cpu_scratch.pa);
        }
        if (result!=SPTM_OK) {
            record(c,EV_REGION_FAILED,*elr,result,frame[1],frame[4]);return 0;
        }
        if(!transaction_publish(c)) {
            record(c,EV_REGION_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],frame[4]);return 0;
        }
        shadow_tlb_sync(c);
        attr_clean_finish(c);
        c->region_calls++;c->region_entries+=frame[2];
        if(auxkc_overlaps(&p->auxkc,frame[1],frame[2]))
            for(uint64_t n=0;n<frame[2] && n<SPTM_DISJOINT_MAX;n++)
                auxkc_note_leaf(c,AUXKC_KIND_UPDATE,*elr,frame[1]+n*0x4000,
                    c->update_workspace.entries[n].old,c->update_workspace.entries[n].next);
        frame[0]=sptm_update_result(&c->update_workspace,frame[2],frame[4]);
        break;
    }
    case SPTM_FN_UPDATE_DISJOINT: {
        uint64_t response;
        if(!update_disjoint_call(c,frame[0],frame[1],frame[2],frame[3],cpu_scratch.pa,
                                 *elr,&response))return 0;
        frame[0]=response;
        break;
    }
    case SPTM_FN_UPDATE_DISJOINT_MULTIPAGE: {
        /* (ops PA, record count). Each header's group is its aperture step
         * (no 0x200), then one UPDATE_DISJOINT engine call; the result is 5
         * if any step returned 5. The plan is copied and validated whole
         * before the first group runs. */
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_multipage_plan plan;
        enum sptm_result r=sptm_mac_multipage_plan(&memory,frame[0],frame[1],&plan);
        if(r) {record(c,EV_UPDATE_FAILED,*elr,r,frame[0],frame[1]);return 0;}
        uint64_t response=SPTM_SUCCESS;
#if SNAP_MULTIPAGE_FAST
        if(!multipage_fast(c,&plan,*elr,cpu_scratch.pa,&response))return 0;
#else
        for(uint64_t g=0;g<plan.groups;g++) {
            uint64_t one;
            /* A failed step leaves earlier ones applied; the guest is not resumed. */
            if(plan.group[g].aperture_flags) {
                if(!multipage_aperture(c,&plan.group[g],*elr,&one))return 0;
                if(one==5)response=5;
            }
            if(!plan.group[g].count)continue;
            if(!update_disjoint_call(c,plan.group[g].target,plan.group[g].list,
                   plan.group[g].count,plan.group[g].options,cpu_scratch.pa,*elr,&one))
                return 0;
            if(one==5)response=5;
        }
#endif
        c->multipage_calls++;c->multipage_groups+=plan.groups;
        frame[0]=response;
        break;
    }
    case SPTM_FN_UNMAP_DISJOINT: {
        const struct params *p=c->params;
        struct sptm_memory memory=sptm_context_memory(c);
        uint64_t count=(uint32_t)frame[2];
        volatile uint8_t *records=count && count<=64 && !(frame[1]&7) ?
            memory.map(memory.ctx,frame[1],count*24):0;
        int kernel=records && *(volatile uint64_t *)records==p->ttbr1_root;
#if SNAP_UNMAP_MIXED
        /* Every record's domain, as UPDATE_DISJOINT: one frame aliased by user
         * and kernel roots comes as one list (v39 stopped on a user-first
         * one). A mixed list then publishes as a kernel one below. */
        int mixed=0;
        if(records)for(uint64_t n=1;n<count;n++)
            mixed|=(((volatile uint64_t *)records)[n*3]==p->ttbr1_root)!=kernel;
        if(mixed)kernel=1;
#endif
        enum sptm_result result=SPTM_BAD_CONFIG;
#if SNAP_UNMAP_MIXED
        if(mixed) {
            if(((p->tcr>>16)&63)==17) {
                struct shadow shadow={.txsz=17,.root=vcpu_of(c)->shadow_root,.alloc=table_alloc,
                    .read=mem_read,.write=mem_write,.ctx=c};
                const struct sptm_unmap_kernel k={p->ttbr1_root,&shadow,
                    &c->kernel_disjoint_unmaps[vcpu_of(c)->slot]};
                kernel_class_proof_forget(c);
                result=sptm_mac_unmap_mixed_disjoint(&memory,user_update_backend,c,&k,
                    frame[0],frame[1],count,cpu_scratch.pa,
                    &c->user_disjoint_unmaps[vcpu_of(c)->slot]);
            }
        } else
#endif
        if(kernel && ((p->tcr>>16)&63)==17) {
            struct shadow shadow={.txsz=17,.root=vcpu_of(c)->shadow_root,.alloc=table_alloc,
                .read=mem_read,.write=mem_write,.ctx=c};
            kernel_class_proof_forget(c);
            result=sptm_mac_unmap_kernel_disjoint(&memory,&shadow,p->ttbr1_root,
                frame[0],frame[1],count,cpu_scratch.pa,
                &c->kernel_disjoint_unmaps[vcpu_of(c)->slot]);
        } else if(!kernel)
            result=sptm_mac_unmap_user_disjoint(&memory,user_update_backend,c,
                frame[0],frame[1],count,cpu_scratch.pa,
                &c->user_disjoint_unmaps[vcpu_of(c)->slot]);
        if(result) {
            record(c,EV_UNMAP_FAILED,*elr,result,frame[0],frame[2]);return 0;
        }
        if(kernel) {
            if(!transaction_publish(c)) {
                record(c,EV_UNMAP_FAILED,*elr,SPTM_SHADOW_FAILED,frame[0],count);return 0;
            }
            shadow_tlb_sync(c);
            if(c->kernel_view_failed) {
                record(c,EV_UNMAP_FAILED,*elr,SPTM_SHADOW_FAILED,frame[0],count);return 0;
            }
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_UNMAP_REGION: {
        const struct params *p=c->params;
        record(c,EV_UNMAP_REGION,*elr,frame[1],frame[2],frame[3]);
        struct sptm_memory memory=sptm_context_memory(c);
        struct shadow shadow={.txsz=17,.root=vcpu_of(c)->shadow_root,.alloc=table_alloc,
            .read=mem_read,.write=mem_write,.ctx=c,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
        enum sptm_result result=SPTM_BAD_TABLE;
        if (frame[0]==p->ttbr1_root && ((p->tcr>>16)&63)==17)
            result=sptm_mac_unmap_region(&memory,&shadow,frame[0],frame[1],
                                         frame[2],frame[3],cpu_scratch.pa);
        struct sptm_user_backend user={0};
        if(frame[0]!=p->ttbr1_root && user_backend(c,frame[0],&user))
            result=sptm_mac_unmap_user_region(&memory,&user,frame[0],frame[1],
                                             frame[2],frame[3],cpu_scratch.pa);
        if (result!=SPTM_OK) {
            record(c,EV_UNMAP_FAILED,*elr,result,frame[1],frame[2]);
            return 0;
        }
        if(frame[0]==p->ttbr1_root) {
            if(!transaction_publish(c)) {
                record(c,EV_UNMAP_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],frame[2]);return 0;
            }
            shadow_tlb_sync(c);
        }
        frame[0]=SPTM_SUCCESS;
        break;
    }
    case SPTM_FN_NEST_REGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};enum sptm_result r=SPTM_BAD_TABLE;
        uint64_t full=UNS(c).full;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_nest_region(&memory,&backend,frame[0],frame[1],frame[2],frame[3]);
        if(r && UNS(c).full!=full) {
            record(c,EV_NATIVE_SHARED_FULL,*elr,UNS(c).full,frame[1],NATIVE_SHARED_GROUPS);return 0;
        }
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[2],frame[3]);return 0;}
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_UNNEST_REGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};enum sptm_result r=SPTM_BAD_TABLE;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_unnest_region(&memory,&backend,frame[0],frame[1],frame[2],frame[3]);
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[2],frame[3]);return 0;}
        c->unnest_va=frame[2];c->unnest_pages=(uint32_t)frame[3];c->unnest_cpu=vcpu_of(c)->slot;
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_UNMAP_TABLE: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};
        enum sptm_result r=SPTM_BAD_TABLE;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_unmap_user_table(&memory,&backend,frame[0],frame[1],frame[2]);
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[1],frame[2]);return 0;}
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_CONDEMN_LEAF_TABLE:
    case SPTM_FN_UNCONDEMN_LEAF_TABLE: {
        struct sptm_memory memory=sptm_context_memory(c);
        struct sptm_user_backend backend={0};uint64_t result=0;
        enum sptm_result r=SPTM_BAD_TABLE;
        unsigned condemn=x16==SPTM_FN_CONDEMN_LEAF_TABLE;
        if(frame[0]!=c->params->ttbr1_root && user_backend(c,frame[0],&backend))
            r=sptm_mac_condemn_user_table(&memory,&backend,frame[0],frame[1],condemn,&result);
        if(r) {record(c,EV_TABLE_FAILED,*elr,r,frame[1],x16);return 0;}
#if SNAP_USER_HW_WALK
        /* The level-2 group's software bit: copies stay byte-exact. */
        if(!result && !hw_after_table(c,frame[0],frame[1],2)) {
            record(c,EV_TABLE_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],x16);return 0;
        }
#endif
        if(!result) {
            if(condemn)c->user_condemn_calls++;else c->user_uncondemn_calls++;
        }
        frame[0]=result;break;
    }
    case SPTM_FN_MAP_TABLE: {
        const struct params *p = c->params;
        record(c, EV_MAP_TABLE, *elr, frame[1], frame[2], frame[3]);
        struct sptm_memory memory=sptm_context_memory(c);
        enum sptm_result result = SPTM_BAD_TABLE;
        if (frame[0] == p->ttbr1_root && ((p->tcr >> 16) & 63) == 17)
            result = sptm_mac_map_table(&memory, frame[0], frame[1], frame[2], frame[3]);
        struct sptm_user_backend user={0};
        if(frame[0]!=p->ttbr1_root && user_backend(c,frame[0],&user))
            result=sptm_mac_map_user_table_live(&memory,&user,frame[0],frame[1],frame[2],frame[3]);
        if (result != SPTM_OK && result != SPTM_TABLE_MISSING && result != SPTM_TABLE_EXISTS) {
            record(c, EV_TABLE_FAILED, *elr, result, frame[1], frame[3]);
            return 0;
        }
#if SNAP_USER_HW_WALK
        if(result==SPTM_OK && frame[0]!=p->ttbr1_root &&
           !hw_after_table(c,frame[0],frame[1],(unsigned)frame[2])) {
            record(c,EV_TABLE_FAILED,*elr,SPTM_SHADOW_FAILED,frame[1],frame[3]);return 0;
        }
#endif
        if(result==SPTM_OK && frame[0]!=p->ttbr1_root) {
            /* An empty table adds no hardware mappings; retain live roots. */
            if(user.active_refs)c->user_live_tables++;
#if SNAP_INACTIVE_MIRROR
            /* And cached inactive ones: the attach callbacks already copied a
             * commpage table's leaves into every cached root. */
            else if(user_cached(c,frame[0]))c->inactive_mirror.stats.tables++;
#endif
            else if(!sptm_root_invalidate(&c->user_roots,frame[0],0))return 0;
        }
        frame[0] = result == SPTM_TABLE_MISSING ? 7 : result == SPTM_TABLE_EXISTS ? 8 : 0;
        break;
    }
    case SPTM_FN_CONFIGURE_ROOT: {
        struct sptm_memory memory=sptm_context_memory(c);
        memory.configure_user_root=sptm_configure_user_root;
        memory.root_configuration=&c->root_configuration;
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        enum sptm_result result=sptm_mac_configure_root(&memory,frame[0],frame[1],frame[2]);
        if(result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],frame[2]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_SET_SHARED_REGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        memory.bind_shared_root=sptm_bind_shared_root;
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        enum sptm_result result=sptm_mac_set_shared_region(&memory,frame[0],frame[1]);
        if(result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],frame[1]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_CONFIGURE_SHAREDREGION: {
        struct sptm_memory memory=sptm_context_memory(c);
        record(c,EV_MONITOR,*elr,x16,frame[0],frame[1]);
        enum sptm_result result=sptm_mac_configure_sharedregion(&memory,frame[0],frame[1],frame[2]);
        if(result!=SPTM_OK) {
            record(c,EV_TABLE_FAILED,*elr,result,frame[0],frame[2]);return 0;
        }
        frame[0]=SPTM_SUCCESS;break;
    }
    case SPTM_FN_RETYPE: {
        struct sptm_memory memory=sptm_context_memory(c);
        memory.retire_user_root=sptm_retire_user_root;
        memory.share_user_root=sptm_share_user_root;
        memory.retire_shared_root=sptm_retire_shared_root;
        memory.admit_iommu=sptm_admit_iommu;
        memory.retype_rozone=sptm_retype_rozone;
        memory.retype_user_exec=sptm_retype_user_exec;
        memory.retype_txm_default=sptm_retype_txm_default;
#if SNAP_NATIVE_LIVE
        memory.created_user_root=native_root_created;
#endif
        record(c, EV_RETYPE, *elr, frame[0],
               (frame[1] << 32) | (frame[2] & 0xffffffffUL), frame[3]);
        int aux_frame = auxkc_observe_retype(&c->auxkc_exec, &c->params->auxkc,
                                             frame[0], frame[1], frame[2]);
        enum sptm_result result = sptm_mac_retype(&memory, frame[0], frame[1],
                                                frame[2], frame[3]);
        if (result != SPTM_OK) {
            c->auxkc_exec.retype_failed += (uint64_t)aux_frame;
            record(c, EV_RETYPE_FAILED, *elr, result, frame[0], frame[2]);
            return 0;       /* no permissive acknowledgement of a failed retype */
        }
#if SNAP_USER_HW_WALK_S2RO
        /* A frame that became (or stopped being) an SPTM table: read-only
         * (or RW again) at stage 2 before XNU sees the result. */
        int s2=hw_s2_retype_action((unsigned)frame[1],(unsigned)frame[2]);
        if (s2 >= 0 && !hw_s2_frame(c, frame[0], s2)) {
            record(c, EV_RETYPE_FAILED, *elr, SPTM_SHADOW_FAILED, frame[0], frame[2]);
            return 0;
        }
#endif
        frame[0] = SPTM_SUCCESS;
        break;
    }
    case SPTM_FN_MAP_PAGE: {
        /* (root_pa, va, new_pte). The reference handler is
         * m1n1-j700/src/sptm/xnu.c:163.
         *
         * Two views have to agree or the guest and the hardware diverge
         * silently: XNU's own 16K tables, which it reads back and reasons
         * about, and the 4K shadow the MMU actually walks. Writing the guest
         * slot and then re-inserting that one leaf into the shadow is the whole
         * transaction, and doing it in that order means the shadow is derived
         * from what the guest now says rather than from what we were passed --
         * so a PTE we decode wrongly shows up as a shadow that disagrees with
         * the guest, which test-shadow.c is built to catch, instead of as two
         * consistent wrong answers.
         *
         * This does not create tables. The reference returns TABLE_NOT_PRESENT
         * when a level is missing, and MAP_TABLE is the call that adds one. */
        uint64_t root_pa = frame[0], va = frame[1], new_pte = frame[2];
        /* User leaves update their own shared shadow, never TTBR1's image. */
        if(root_pa!=c->params->ttbr1_root) {
            struct sptm_memory memory=sptm_context_memory(c);
            struct sptm_user_backend backend={0};
            uint64_t shared_before=c->shared_map_calls;
            uint64_t result;
            enum sptm_result r=SPTM_BAD_TABLE;
#if SNAP_INACTIVE_MIRROR
            struct sptm_root_cached *kept=0;uint64_t live=c->user_live_pages;
#endif
            if(user_backend(c,root_pa,&backend)) {
                backend.map_updates=&c->user_map_replacements[vcpu_of(c)->slot];
#if SNAP_INACTIVE_MIRROR
                if(!backend.active_refs && (kept=user_cached(c,root_pa))!=0)
#if SNAP_NATIVE_LIVE
                    /* Every leaf, TPRO included, is O(1) to mirror (variant
                     * copies follow each store): only arena room is asked. */
                    backend.mirror=arena_available(c)>=INACTIVE_MIRROR_ARENA_PAGES;
#else
                    backend.mirror=(unsigned)inactive_mirror_admit(0,1,new_pte,
                        UBUDGETS(c)[kept-c->user_roots.cache],arena_available(c));
#endif
#endif
                r=sptm_mac_map_user_page(&memory,&backend,root_pa,
                    va,new_pte,frame[3],cpu_scratch.pa,&result);
            }
            if(r==SPTM_TABLE_MISSING) {
                c->user_missing_tables++;frame[0]=7;break;
            }
            if(r) {record(c,EV_REFERENCE_FAILED,*elr,r,va,new_pte);return 0;}
            if(c->shared_map_calls!=shared_before) {
                c->shared_map_requested=new_pte;c->shared_map_options=frame[3];
                c->shared_map_result=result;c->shared_map_cpu=vcpu_of(c)->slot;
            }
            if(result==SPTM_USER_MAP_CONFLICT) {
                struct user_map_conflict_state *s=&c->user_map_conflict[vcpu_of(c)->slot];
                s->count++;s->root=root_pa;s->va=va;s->wanted=new_pte;
                s->options=frame[3];s->old=s->pointer=0;s->result=result;
                if(!(frame[3]&1)) {
                    volatile uint64_t *out=(volatile uint64_t *)cpu_scratch.pa;
                    s->old=out[0];s->pointer=out[1];
                }
            } else if(!backend.active_refs &&
#if SNAP_INACTIVE_MIRROR
                      !inactive_map_keep(c,kept,&backend,new_pte,result,live) &&
#endif
                      !sptm_root_invalidate(&c->user_roots,root_pa,0))return 0;
            c->map_pages++;frame[0]=result;break;
        }
        /* ROZONE aperture leaves are created by the validated RETYPE path,
         * which detaches private CPU views before publishing selector2.
         * MAP_PAGE must not expose that raw selector through a shared branch. */
        if((new_pte&1) && (sprr_pte_class(new_pte)==2 || sprr_pte_class(new_pte)==4 ||
                          sprr_pte_class(new_pte)==9)) {
            map_page_failed(c,*elr,MAP_FAIL_SPRR_CLASS,va,new_pte);return 0;
        }
        uint32_t t1sz = (uint32_t)((c->params->tcr >> 16) & 0x3f);
        struct mmu_config guest = {.granule_shift = 14, .txsz = t1sz, .root = root_pa};

        /* Is the root we were handed inside memory we own?
         *
         * The walk below dereferences it at EL2 through mem_read, which is a
         * raw load that cannot fail and has no return code to check. So a root
         * pointing anywhere else is not a failure reason: it is an EL2 fault
         * with no label, which arrives at the host as "the monitor faulted,
         * ESR ..." and says nothing about which call did it or with what.
         *
         * Checking first is what turns that into a named, counted refusal with
         * the VA and the root in it. Refused rather than reported, unlike the
         * out-of-window PTE below: a PTE we cannot vouch for still describes a
         * mapping the kernel wants, while a root we cannot read is an address
         * we are about to fault on. The whole root table has to fit, not just
         * its first byte. */
        if (c->params->mem_low &&
            (root_pa < c->params->mem_low ||
             root_pa + 0x4000 > c->params->mem_high)) {
            map_page_failed(c, *elr, MAP_FAIL_ROOT_OUTSIDE, va, root_pa);
            frame[0] = SPTM_TABLE_NOT_PRESENT;
            break;
        }

        /* Every failure below says which one it was.
         *
         * All six returned the same SPTM_TABLE_NOT_PRESENT and recorded
         * nothing, so a run that failed a map looked exactly like one that did
         * not: the transcript showed 144 consecutive successes and then a panic
         * from pmap, with no way to tell which call failed or why. That is the
         * endpoint-0 collapse again, one layer down -- several distinct causes
         * flattened onto one answer. The count and the address are what turn
         * "MAP_PAGE failed" into a question with one answer instead of six. */
        uint64_t table = root_pa;
        int start = mmu_start_level(14, t1sz);
        if (start < 0) { map_page_failed(c, *elr, MAP_FAIL_START_LEVEL, va, root_pa);
                         frame[0] = SPTM_TABLE_NOT_PRESENT; break; }
        int missing = 0;
        uint64_t missing_at = 0;
        for (int level = start; level < 3; level++) {
            uint64_t entry;
            if (mem_read(c, table + 8UL * mmu_index(14, (uint32_t)level, va), &entry)
                || (entry & 3) != 3) { missing = 1; missing_at = (uint64_t)level; break; }
            table = entry & PT_OA_MASK;
        }
        /* The one a missing table hierarchy produces, and the one that decides
         * whether MAP_TABLE is what we are missing. The level is recorded
         * because "which level was absent" is the next question after "was it
         * this branch". */
        if (missing) { record(c, EV_MAP_NEEDS_TABLE, *elr, missing_at, va, table);
                       frame[0] = SPTM_TABLE_NOT_PRESENT; break; }

        /* Does this PTE point at memory we told XNU about?
         *
         * Reported, never refused. We do not know whether a PTE outside the
         * window is XNU asking for something wrong or our idea of the window
         * being too narrow, and refusing a mapping the kernel needs turns a
         * diagnosable problem into a hang. So this completes the map and says
         * so -- counted separately from the failures, because it is not one.
         *
         * Worth having because of what it would have caught: 379 maps were
         * accepted with output addresses at 8 and 12 GiB, against a window that
         * ends at 3.83 GiB, and nothing said a word. That is the same shape as
         * every other bug this file has grown a log line for -- an answer that
         * could be wrong in a way nobody can see.
         *
         * The whole PTE goes in the record rather than a decode of it: the
         * attribute bits differ between the entries we write and the ones XNU
         * does (0x703 against 0x40f), that difference may matter, and the host
         * can decode a PTE better than this can. */
        uint64_t pte_pa = new_pte & PT_OA_MASK;
        int points_outside = 0;
        if (c->params->mem_low && (new_pte & 1) &&
            (pte_pa < c->params->mem_low || pte_pa >= c->params->mem_high) &&
            !(c->params->fb_span && pte_pa >= c->params->fb_pa &&
              pte_pa - c->params->fb_pa < c->params->fb_span)) {
            points_outside = 1;
            /* Only the first few, because they are all the same shape and
             * the log is 64 entries. 379 identical lines say nothing that five
             * do not, and they push every other event out -- which is how this
             * broke the classifier the first time it fired in anger. The
             * counter carries the true total either way. */
            if (c->map_outside < MAP_OUTSIDE_LOGGED)
                record(c, EV_MAP_OUTSIDE, *elr, pte_pa, va, new_pte);
            c->map_outside++;
            /* Here rather than beside one of the branches below, so the table
             * and the counter describe the same set of pages by construction:
             * the spans must add up to map_outside, and the host checks that
             * they do. */
            map_range_note(c, va, pte_pa, new_pte & 0xfff);
        }

        uint64_t slot = table + 8UL * mmu_index(14, 3, va);
        struct sptm_aperture aperture = xnu_aperture(c);
        struct sptm_moved moved = xnu_moved(c);
        uint64_t existing = 0;
        if (mem_read(c, slot, &existing)) { map_page_failed(c, *elr, MAP_FAIL_READ_LEAF, va, slot);
                                            frame[0] = SPTM_TABLE_NOT_PRESENT; break; }
        if ((new_pte&3)!=3) {
            map_page_failed(c,*elr,MAP_FAIL_LEAF_INVALID,va,new_pte);return 0;
        }
        /* The old leaf decides before anything is written (sptm.h). */
        struct sptm_kernel_leaf plan;
        if (sptm_mac_kernel_map_leaf(&aperture, &moved, slot, existing, new_pte, &plan)) {
            map_page_failed(c, *elr, MAP_FAIL_READ_LEAF, va, slot);
            frame[0] = SPTM_TABLE_NOT_PRESENT;
            break;
        }
        uint64_t slot_va = plan.pointer;
        int moved_pointer = slot_va != sptm_aperture_pointer(&aperture, slot, 8);
        if (!plan.install) {
            /* A valid leaf of another page: CONFLICT, no store, no reference
             * move, shadow untouched. XNU removes the old mapping (and its PV
             * entry) and retries. The old PTE and pointer are reported as on
             * the accepted path below. */
            if (cpu_scratch.pa) {
                volatile uint64_t *out = (volatile uint64_t *)cpu_scratch.pa;
                out[0] = plan.old;
                out[1] = plan.pointer;
                __asm__ volatile("dc cvau, %0\n\tdc cvau, %1\n\tdsb ish"
                                 :: "r"(&out[0]), "r"(&out[1]) : "memory");
            }
            c->kernel_map_conflict = (struct kernel_map_conflict_state){
                .count = c->kernel_map_conflict.count + 1, .va = va,
                .wanted = new_pte, .old = plan.old, .pointer = plan.pointer};
            c->map_pages++;
            frame[0] = plan.status;
            break;
        }
        struct sptm_memory memory=sptm_context_memory(c);
        sptm_refs_begin(memory.refs);
        enum sptm_result ref_result=sptm_refs_leaf(&memory,table,va,existing,new_pte);
        if (ref_result==SPTM_OK) ref_result=sptm_refs_validate(&memory);
        if (ref_result!=SPTM_OK) {
            record(c,EV_REFERENCE_FAILED,*elr,ref_result,va,new_pte);return 0;
        }
        if (mem_write(c, slot, new_pte)) { map_page_failed(c, *elr, MAP_FAIL_WRITE_LEAF, va, slot);
                                           return 0; }

        /* What the caller reads back afterwards. The reference writes the PTE
         * that was replaced and the guest VA of the entry itself; XNU reads both
         * and a zero where it expects a pointer is a null dereference several
         * thousand calls later, a long way from here. The clean is not
         * decoration: this is written at EL2 and read at EL1, and nothing else
         * makes the line visible to the other reader.
         *
         * 0xfffffe000ba62e0c is the read: the instruction after this call
         * returns loads cpu_data + 0 and dereferences it. That word is the
         * answer to SPTM_FN_OUTPUT_AREA below, which is why the two have to name
         * the same page. */
        if (cpu_scratch.pa) {
            volatile uint64_t *out = (volatile uint64_t *)cpu_scratch.pa;
            out[0] = existing;
            out[1] = slot_va;
            __asm__ volatile("dc cvau, %0\n\tdc cvau, %1\n\tdsb ish"
                             :: "r"(&out[0]), "r"(&out[1]) : "memory");
            c->pv_audit.moved_pointers += (uint64_t)moved_pointer;
        }

        /* Re-read through the guest's own tables, so the shadow copies what the
         * guest will see rather than what the caller said. */
        struct mmu_leaf leaf;
        if (mmu_walk(&guest, va, mem_read, c, &leaf) < 0) {
            /* The PTE went in and the re-read disagreed, which means the guest
             * table and our decode of it have diverged -- a different failure
             * from the table simply not being there, and the guest has already
             * been modified by the time we get here. */
            map_page_failed(c, *elr, MAP_FAIL_REREAD, va, new_pte);
            return 0;
        }
        int is_device = 0;
        uint64_t model_off;
        if (device_model_find(c->params->models, c->params->model_count,
                              pte_pa, &model_off) >= 0) is_device = 1;
        for (uint64_t n = 0; n < c->params->device_count && n < 4; n++) {
            if (pte_pa >= c->params->device_pa[n] &&
                pte_pa < c->params->device_pa[n] + c->params->device_span[n]) {
                is_device = 1;
                break;
            }
        }
        /* The GPU node's reg windows (adreno.h): passthrough at stage 2. */
        unsigned gpu_block = adreno_block(pte_pa, c->params->gpu.flags);
        if (c->params->gpu.flags && (gpu_block == ADRENO_PASS || gpu_block == ADRENO_CX_MISC_RO))
            is_device = 1;
#if SNAP_I2C_INPUT
        /* The input node's reg page (compat/i2c-input.h): passthrough at stage 2. */
        if (i2c_input_window(&c->params->i2c_input, pte_pa))
            is_device = 1;
#endif
#if SNAP_QCC2072_WIFI
        /* The QCC2072 node's reg windows (compat/qcc2072-wifi.h): passthrough at stage 2. */
        if (qcc2072_wifi_window(qcc2072_wifi_block(c->params), pte_pa))
            is_device = 1;
#endif
#if SNAP_DISPLAY_TIMING
        /* The DPU INTF_5 page (compat/display-timing.h): read-only passthrough at stage 2. */
        if (display_timing_window(display_timing_block(c->params), pte_pa))
            is_device = 1;
#endif
        if (leaf.valid && points_outside && is_device) {
            /* A device the guest's own tree names, so the kernel is right to
             * ask and we are right to answer. The leaf goes in.
             *
             * This is only safe because stage 2 is narrowed (T4). The guest's
             * stage-1 walk now resolves, the access reaches stage 2, the IPA is
             * absent there, and it traps to EL2 with the address -- which is
             * how a device model ever gets a chance to answer. Withholding
             * instead leaves a stage-1 fault that EL1 handles itself, and the
             * kernel dies inside its own serial driver having never reached us.
             *
             * Under the old identity map this would have been the machine
             * reset. The order those two changes landed in was luck, not
             * judgement, and it is worth saying so. */
            if (c->map_device <= MAP_OUTSIDE_LOGGED)
                record(c, EV_MAP_DEVICE, *elr, pte_pa, va, new_pte);
            c->map_device++;
        }
        if (leaf.valid) {
            /* Every PTE goes in, including the ones pointing outside the memory
             * we declared. Withholding is gone, and the reasoning inverts the
             * one that used to sit here.
             *
             * That branch called itself "the accident becomes the policy", and
             * it was right about the accident: before the clip fix, a leaf like
             * this went into a slot the hardware never reads, so withholding
             * was what the code happened to do rather than what it meant. The
             * fix made every insert real, the first run after it reset the
             * machine, and withholding was adopted to stop that.
             *
             * What has changed since is stage 2. Under the narrowed map (T4)
             * these addresses are not identity-mapped to the Snapdragon's bus
             * any more -- they are absent, so an installed PTE means the
             * guest's stage-1 walk resolves, the access reaches stage 2, and it
             * traps to EL2 with the IPA, the register, the size and the
             * direction. That is a device access we can answer or name.
             * Withholding instead leaves a stage-1 fault that EL1 handles
             * itself, and the transcript reads "XNU faulted" where it could
             * have read "the AIC at 0x301000000 was read". The reset this
             * branch was protecting against cannot happen through a map that
             * does not contain those pages.
             *
             * So installing is the loud option and withholding was the quiet
             * one, which is the opposite of how they were introduced. The
             * counter and the span table stay: what is reported has not
             * shrunk, only what is refused. Device models stay per-device,
             * strict and on demand -- the window list is consulted at fault
             * time, not here. */
            /* The clip bounds go in the regime's offset space, not the caller's.
             *
             * This is the bug that made five successful MAP_PAGEs produce a
             * level-1 translation fault. mmu_walk reports `leaf.base` masked
             * into the regime -- `out->base = address & ~(size - 1)`, where
             * `address` has already had the top bits stripped -- but the clip
             * was the raw kernel VA. Being the larger of the two it won, so
             * shadow_map indexed with the raw address: for
             * 0xfffffed000010000 that is level-0 slot 509 where the hardware
             * reads slot 253. The leaf was written into a slot nothing walks.
             *
             * It stayed invisible because every VA mapped before this was
             * already in the shadow from the initial shadow_build, which passes
             * bounds in the same space its walk produces. The wrongly-indexed
             * entries were harmless duplicates of mappings that already
             * resolved. The range above the static map was the first with no
             * prior entry, so it was the first where the wrong slot mattered. */
            uint64_t va_off = va & ((1UL << (64 - t1sz)) - 1);
            struct shadow shadow = {.txsz = t1sz, .root = vcpu_of(c)->shadow_root,
                                    .alloc = table_alloc, .read = mem_read,
                                    .write = mem_write, .ctx = c,
                                    .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
            int put_leaf = shadow_insert(&shadow, &leaf, va_off,
                                         va_off + (1UL << 14));
            if (put_leaf < 0) {
                /* Almost always the 4K shadow's table arena being exhausted,
                 * so the work pointer is recorded rather than the guest's --
                 * that is the number that says whether we ran out of room. */
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_INSERT, va, c->next_table);
                return 0;
            }
            if (put_leaf == SHADOW_NOTHING) {
                /* Accepted and did nothing. This is what a clip in the wrong
                 * address space produced, and reporting success for it is what
                 * let five mappings go missing without a word. */
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_EMPTY, va, leaf.base);
                return 0;
            }

            /* And read it back through the shadow, which is what the hardware
             * actually walks.
             *
             * The guest half of this call has been re-read since the day it was
             * written -- the PTE goes in, then it is walked back through the
             * guest's own tables, so a decode error shows up as a disagreement
             * rather than as two consistent wrong answers. The shadow half was
             * still taking shadow_insert's word for it, and a success there
             * means "nothing refused me", not "the mapping is present".
             *
             * That gap is not theoretical: XNU mapped five pages into the
             * tables above the static map, every call returned success, and it
             * then took a level-1 translation fault reading the fifth. The
             * hardware disagreed with what we had reported, and nothing in the
             * transcript said so.
             *
             * Same walker, 4K config, rooted where TTBR1 points. */
            struct mmu_config shadow_view = {.granule_shift = 12, .txsz = t1sz,
                                             .root = vcpu_of(c)->shadow_root};
            struct mmu_leaf got;
            uint64_t want = leaf.descriptor & PT_OA_MASK & ~(leaf.size - 1);
            if (mmu_walk(&shadow_view, va_off, mem_read, c, &got) < 0 || !got.valid) {
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_ABSENT, va, vcpu_of(c)->shadow_root);
                return 0;
            }
            uint64_t resolved = (got.descriptor & PT_OA_MASK & ~(got.size - 1))
                                + (va_off - got.base);
            if (resolved != want) {
                map_page_failed(c, *elr, MAP_FAIL_SHADOW_WRONG, va, resolved);
                return 0;
            }
        } else {
            /* The guest's own tables say this address is not mapped, yet we are
             * about to report success. That is a silent no-op: any shadow entry
             * from a previous mapping of this address is still there, so the
             * hardware and the guest now disagree in the other direction.
             *
             * Recorded rather than fixed. Removing the shadow leaf is what an
             * unmap should do, and whether this call IS an unmap -- rather than
             * a PTE we decoded wrongly -- is not established. */
            map_page_failed(c, *elr, MAP_FAIL_LEAF_INVALID, va, new_pte);
            return 0;
        }
        /* The shadow is what the MMU walks, so a stale entry for this address
         * outlives the write unless it is dropped. */
        shadow_tlb_sync(c);
        sptm_refs_commit(&memory);
        c->map_pages++;
        auxkc_note_leaf(c, AUXKC_KIND_MAP, *elr, va, existing, new_pte);
        /* Apple reports 1 when a valid same-PA leaf was already present and 0
         * only for an empty slot (sptm_mac_map_page_status); a different-PA
         * valid leaf returned CONFLICT above. */
        frame[0] = plan.status;
        break;
    }
    case SPTM_FN_SERIAL_PUTC:
        console_put(c, (uint8_t)frame[0]);
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_LOCKDOWN:
        if(const_region_seal(c)) {
            record(c,EV_MAP_FAILED,*elr,0x434f4e53,c->params->const_begin,c->params->const_end);
            return 0;
        }
        c->lockdowns++;
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_SERIAL_DISABLE:
        /* The kernel letting go of the monitor's early serial, which it does
         * when it is ready to drive a console of its own. Nothing to release
         * here -- the "serial" is a byte buffer in this context -- so this is
         * an acknowledgement rather than a stub standing in for work.
         *
         * It is recorded because it marks the end of the transcript: any kernel
         * output after this point is the kernel's own console on the panel, not
         * bytes relayed through us, and a console that goes quiet here has
         * succeeded rather than hung. */
        c->serial_disabled = 1;
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_REGISTER_CPU:
        cpu_status = guest_cpu_register(&c->cpus,frame[0]);
        if (cpu_status != CPU_OK) {
            record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,frame[0]);return 0;
        }
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_REGISTER_EXC_RETURN:
        /* The trampoline the monitor is to place in ELR_EL1 when it returns an
         * interrupt to XNU. Recorded because it will be needed the moment
         * anything is delivered, and answered so boot continues. */
        c->exc_return = frame[0];
        frame[0] = SPTM_SUCCESS;
        break;
    case SPTM_FN_CPU_ID:
        /* ba78910 supplies the topology's physical affinity. Its result is
         * a slot index, stored as u16 and used with a 0x8000-byte stride. */
        {
            uint64_t slot;
            cpu_status = guest_cpu_id(&c->cpus,frame[0],&slot);
            if (cpu_status != CPU_OK) {
                record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,frame[0]);return 0;
            }
            frame[0] = slot;
        }
        break;
    case SPTM_FN_OUTPUT_AREA: {
        /* "Where do I read slot N's results?" -- and the answer is dereferenced,
         * so it is a virtual address and not the physical one we hold.
         *
         * Apple's handler is `sptm_output_area` at 0xfffffff0270bd8d0: it bounds
         * the id against sptm_n_cpus, checks the cpu record agrees with its own
         * index, and returns that record's `+0x1680`, panicking "Scratch page
         * not configured for cpu %p (ID %d)" if it is zero. So a zero is not a
         * neutral answer here; it is the one value the real monitor refuses to
         * give back.
         *
         * What XNU does with it settles the address space. At
         * 0xfffffe000ba7894c it stores the answer at cpu_data + 0, and at
         * 0xfffffe000ba62e0c -- the instruction after a MAP_PAGE call returns --
         * it reloads that word and immediately runs `ldr x8, [x9]` and
         * `ldr x1, [x9, #8]`, keeping the first and comparing it against the PTE
         * it had just asked for. Those two words are exactly what MAP_PAGE above
         * writes into the scratch page: the entry we replaced, and the address
         * of the entry. This is one channel, written at EL2 and read at EL1, and
         * the read is an ordinary EL1 load through the guest's own tables -- so
         * the value handed back has to be the scratch page's *virtual* address.
         *
         * The loader now backs six separate areas in reserved monitor data.
         * Registration and a valid slot are required; no result aliases a
         * different CPU. Allocation does not claim that a CPU has started. */
        uint64_t slot = frame[0];
        struct guest_cpu_buffer output;
        cpu_status = guest_cpu_output(&c->cpus,slot,c->params->scratch_pa,
            c->params->scratch_va,c->params->mem_low,c->params->mem_high,&output);
        if (cpu_status != CPU_OK) {
            record(c,EV_CPU_FAILED,*elr,cpu_status,endpoint,slot);return 0;
        }
        frame[0] = output.va;
        break;
    }
    case SPTM_FN_FIXUPS_COMPLETE:
        /* On a real machine this is where SPTM retypes the frames it just let
         * XNU rebase. The host loader applied the chained fixups before the
         * image was ever uploaded (tools/kc-load.py), so there is nothing left
         * to do but agree. */
        frame[0] = SPTM_SUCCESS;
        break;
    default:
        /* Bring-up mode: acknowledge what is not implemented and log it, so one
         * run shows the whole sequence of what XNU asks for instead of one
         * endpoint per round trip. Every answer here is a lie of omission, and
         * the run after a new endpoint appears is the one that has to make it
         * true. */
        if (!c->params->permissive) return 0;
        frame[0] = SPTM_SUCCESS;
        break;
    }

    c->calls++;
    *elr += 4;                      /* over the call, onto the stub's own return */
    return 1;
}
static int monitor_call(struct context *c,uint64_t *frame,uint64_t *elr)
{
    unsigned kind=service_detail_call_bucket(frame[16]);
    int started=detail_begin(c,kind);
    int result=monitor_call_impl(c,frame,elr);
    detail_end(c,kind,started,result);return result;
}

