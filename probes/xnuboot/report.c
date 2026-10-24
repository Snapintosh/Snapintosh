/* SPDX-License-Identifier: MIT */
/* Host restore and the end-of-run report.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
/* Quarantine restores CPU0 only. No peer/shared cleanup, RAM publication or
 * broadcast TLB maintenance is allowed while ownership is unresolved. */
static void xnuboot_restore_host(struct context *c, int shared_safe)
{
    if(SNAP_NATIVE_WRITER_BREAKPOINTS)
        native_writer_debug_restore(&c->writer_debug[vcpu_of(c)->slot],&writer_debug_ops);
    __asm__ volatile("msr mdcr_el2, %0" :: "r"(vcpu_of(c)->save_mdcr));
    __asm__ volatile("msr mdscr_el1, %0" :: "r"(vcpu_of(c)->save_mdscr));
    if (vcpu_of(c)->dbg_oslsr & (1UL << 1)) {
        uint64_t one = 1;
        __asm__ volatile("msr oslar_el1, %0" :: "r"(one));
    }
    watchdog_off(c);
    /* Everything the probe changed, put back. Translation is turned off before
     * the registers behind it are restored, and the TLBs are flushed after, so
     * nothing of the guest's regime can outlive the probe. TPIDR_EL2 is last
     * because it is what `context_of` reads. */
    __asm__ volatile("msr vbar_el2, %0" :: "r"(vcpu_of(c)->save_vbar));
    __asm__ volatile("msr sctlr_el1, xzr; isb");
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(vcpu_of(c)->save_ttbr0));
    __asm__ volatile("msr ttbr1_el1, %0" :: "r"(vcpu_of(c)->save_ttbr1));
    __asm__ volatile("msr mair_el1, %0" :: "r"(vcpu_of(c)->save_mair));
    __asm__ volatile("msr vttbr_el2, %0" :: "r"(vcpu_of(c)->save_vttbr));
    __asm__ volatile("msr vtcr_el2, %0" :: "r"(vcpu_of(c)->save_vtcr));
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(vcpu_of(c)->save_sctlr));
    __asm__ volatile("msr tcr_el1, %0" :: "r"(vcpu_of(c)->save_tcr));
    if (shared_safe)
        __asm__ volatile("dsb ish; tlbi vmalls12e1is; tlbi alle1is; dsb ish; isb");
    else
        __asm__ volatile("dsb nsh; tlbi vmalls12e1; tlbi alle1; dsb nsh; isb");
#if SNAP_NATIVE_PACGA
    native_pacga_restore(c, vcpu_of(c));
#endif
#if SNAP_LEAN_TRAPS == 2
    lean_fgt_restore(c, vcpu_of(c));
#endif
    __asm__ volatile("msr hcr_el2, %0" :: "r"(vcpu_of(c)->save_hcr));
    __asm__ volatile("msr vmpidr_el2, %0" :: "r"(vcpu_of(c)->save_vmpidr));
    if (vcpu_of(c)->clock_saved) {
        __asm__ volatile("msr cntkctl_el1, %0" :: "r"(vcpu_of(c)->save_cntkctl));
        __asm__ volatile("msr cnthctl_el2, %0; isb" :: "r"(vcpu_of(c)->save_cnthctl));
    }
    __asm__ volatile("msr daif, %0" :: "r"(vcpu_of(c)->save_daif));
    uint64_t tpidr = vcpu_of(c)->save_tpidr;
    __asm__ volatile("msr tpidr_el2, %0; isb" :: "r"(tpidr) : "memory");
}

uint64_t xnuboot_report(uint64_t *out);
uint64_t xnuboot_report(uint64_t *out)
{
    struct context *c = context_of();
    struct vcpu *v = vcpu_of(c);
#if SNAP_BOOT_RELOCATE
    boot_relocation_settle(c);   /* vCPU 0's CPU is OFF and q1n1's registers are back */
#endif
    watchdog_off(c);
    enum guest_service_result finished = guest_service_finish(&c->services, v->slot);
    if (finished != SERVICE_OK) v->service_fault = finished;
    int retired = !v->slot && secondary_collect(c);
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
    if (!v->slot) dvfs_cpu_restore(c);   /* C5/U10: also when the ownership check below quarantines */
#endif
    /* Only drained executors may publish a shared report or touch the GPU.
     * A bounded failure returns quarantine; it never steals a peer's token or
     * marks an unresolved executor OFF. The host must not touch/reuse this RAM. */
    if (!retired || !guest_service_reusable(&c->services)) {
        v->service_fault = SERVICE_NOT_QUIESCENT;
        xnuboot_restore_host(c, 0);
        return XNUBOOT_TERMINAL_OWNERSHIP;
    }
    guards_close(c);
    /* No executor remains: publish a budget stop recorded privately while
     * waiting, without writing the shared event log outside ownership. */
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)if(c->service_budget_stops[cpu])
        record(c,EV_WATCHDOG,c->vcpus[cpu].async_regs.pc,0,0,0);
    /* Early stop: release q1n1's call service (never from inside a fault in
     * it) and settle the outcome against the final stop word. */
    if (c->early_stop.host_armed && !c->early_stop.host_in_call && c->params->early_stop.host_call)
        early_stop_host_call(c, EARLY_STOP_HOST_DISARM, 0, 0, 0);
    early_stop_finish(&c->early_stop, guest_service_stopped(&c->services));
    for (unsigned n = 0; n < EARLY_STOP_STATE_WORDS; n++)
        out[OUT_EARLY_STOP + n] = ((const uint64_t *)&c->early_stop)[n];
    for(unsigned n=0;n<A16_THERMAL_REPORT_WORDS;n++)
        out[OUT_THERMAL+n]=c->thermal?((const uint64_t *)c->thermal)[n]:0;
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
    /* Every executor has quiesced: the per-CPU exit words are final. */
    out[OUT_EXIT_PROFILE] = EXIT_PROFILE_MAGIC;
    out[OUT_EXIT_PROFILE + 1] = (uint64_t)SNAP_FAST_EL0_SYSREG | (uint64_t)SNAP_SERVICE_SUBCLASS << 1 |
                                (uint64_t)sizeof(struct exit_profile) << 32;
    for (unsigned n = 0; n < EXIT_PROFILE_WORDS; n++)
        out[OUT_EXIT_PROFILE + 2 + n] = ((const uint64_t *)&c->exit_profile)[n];
#endif
#if SNAP_FINE_LOCKS
    out[OUT_FINE_PROFILE] = FINE_PROFILE_MAGIC;
    out[OUT_FINE_PROFILE + 1] = (uint64_t)SNAP_FINE_SWITCH | (uint64_t)SNAP_FAST_PAUTH_CALLS << 1 |
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
                                UINT64_C(4) |   /* the DART kinds follow the pointer kinds */
#endif
#if SNAP_SPTM_FINE
                                UINT64_C(8) |   /* the SPTM_FINE kinds and declines follow (fine-lock.h) */
#endif
#if SNAP_ANS_CONVERTED
                                UINT64_C(16) |  /* the ANS kinds and the busy decline follow (agents/nvme-async) */
#endif
                                (uint64_t)sizeof(struct fine_profile) << 32;
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        for (unsigned n = 0; n < FINE_PROFILE_WORDS; n++)
            out[OUT_FINE_PROFILE + 2 + cpu*FINE_PROFILE_WORDS + n] =
                ((const uint64_t *)&c->root_ext->fine.cpu[cpu].profile)[n];
#endif
#if SNAP_TOKEN_COSTS
    /* compat/token-costs.h struct token_costs_report, word by word. */
    out[OUT_TOKEN_COSTS] = TOKEN_COSTS_MAGIC;
    out[OUT_TOKEN_COSTS + 1] = (uint64_t)SNAP_NEST_FAST | (uint64_t)SNAP_DETACH_FAST << 1 |
        (uint64_t)SNAP_ROOT_INDEX << 2 | (uint64_t)SNAP_OTHER_PROFILE << 3 |
        (uint64_t)SNAP_GATE_WAIT << 4 |
#if SNAP_PHASE_FAIR_GATE
        UINT64_C(1) << 5 |   /* gate[4..6]: phase entries, drains, drain ticks */
#endif
        (uint64_t)sizeof(struct token_costs_report) << 32;
    for (unsigned n = 0; n < TOKEN_COSTS_WORDS; n++) out[OUT_TOKEN_COSTS + 2 + n] = 0;
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
    for (unsigned n = 0; n < 16; n++)
        out[OUT_TOKEN_COSTS + 2 + n] = ((const uint64_t *)&c->root_ext->nest_fast)[n];
#endif
#if SNAP_ROOT_INDEX
    for (unsigned n = 0; n < 16; n++)
        out[OUT_TOKEN_COSTS + 2 + 16 + n] = ((const uint64_t *)&c->root_ext->root_index.stats)[n];
#endif
#if SNAP_OTHER_PROFILE
    for (unsigned n = 0; n < 3 * OTHER_CLASSES; n++)
        out[OUT_TOKEN_COSTS + 2 + 32 + n] = ((const uint64_t *)c->root_ext->other.buckets)[n];
#endif
#if SNAP_GATE_WAIT
    for (unsigned n = 0; n < 16; n++)
        out[OUT_TOKEN_COSTS + 2 + 80 + n] = __atomic_load_n(&c->root_ext->gate[n], __ATOMIC_RELAXED);
#endif
#endif
#if SNAP_FAST_TIMER_IRQ
    out[OUT_FAST_IRQ] = FAST_IRQ_MAGIC;
    out[OUT_FAST_IRQ + 1] = (uint64_t)SNAP_WFI_RESUME | (uint64_t)sizeof(struct fast_irq_cpu) << 32;
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        for (unsigned n = 0; n < FAST_IRQ_WORDS; n++)
            out[OUT_FAST_IRQ + 2 + cpu*FAST_IRQ_WORDS + n] = ((const uint64_t *)&c->root_ext->fast_irq[cpu])[n];
#endif
#if SNAP_FAST_IPI
    out[OUT_FAST_IPI] = FAST_IPI_MAGIC;
    out[OUT_FAST_IPI + 1] = (uint64_t)sizeof(struct fast_ipi_cpu) << 32;
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        for (unsigned n = 0; n < FAST_IPI_WORDS; n++)
            out[OUT_FAST_IPI + 2 + cpu*FAST_IPI_WORDS + n] = ((const uint64_t *)&c->root_ext->fast_ipi[cpu])[n];
#endif
#if SNAP_GUEST_NET
    if (c->guest_net) {   /* setup may have stopped before taking its page */
    out[OUT_GUEST_NET] = GUEST_NET_REPORT_MAGIC;
    out[OUT_GUEST_NET + 1] = (uint64_t)!!(c->params->early_stop.flags & EARLY_STOP_F_NET) |
                             (uint64_t)sizeof(struct guest_net_link) << 32;
    for (unsigned n = 0; n < GUEST_NET_LINK_WORDS; n++)
        out[OUT_GUEST_NET + 2 + n] = ((const uint64_t *)&c->guest_net->link)[n];
    for (unsigned n = 0; n < GUEST_NET_VIEW_WORDS; n++)
        out[OUT_GUEST_NET + 2 + GUEST_NET_LINK_WORDS + n] = ((const uint64_t *)&c->guest_net->view)[n];
    }
#endif
#if SNAP_DART_MEMO
    out[OUT_DART_MEMO] = DART_MEMO_MAGIC;
    out[OUT_DART_MEMO + 1] = (uint64_t)sizeof(struct sptm_dart_memo_stats) << 32;
    for (unsigned n = 0; n < DART_MEMO_STATS_WORDS; n++)
        out[OUT_DART_MEMO + 2 + n] = ((const uint64_t *)&c->root_ext->dart_memo.stats)[n];
    out[OUT_DART_MEMO + 2 + DART_MEMO_STATS_WORDS] = c->root_ext->dart_memo.live;
#endif
#if SNAP_VIEW_RECLAIM
    out[OUT_VIEW_RECLAIM] = VIEW_RECLAIM_MAGIC;
    out[OUT_VIEW_RECLAIM + 1] = (uint64_t)(8 * VIEW_RECLAIM_WORDS) << 32;
    out[OUT_VIEW_RECLAIM + 2] = c->kernel_views.count;
    /* A refused prepare leaves no count above the last success's. */
    out[OUT_VIEW_RECLAIM + 3] = c->kernel_view_reclaim.high_water > c->kernel_views.count ?
                                c->kernel_view_reclaim.high_water : c->kernel_views.count;
    out[OUT_VIEW_RECLAIM + 4] = c->kernel_view_reclaim.reclaims;
    out[OUT_VIEW_RECLAIM + 5] = c->kernel_view_reclaim.retired;
    out[OUT_VIEW_RECLAIM + 6] = c->kernel_view_reclaim.full;
    out[OUT_VIEW_RECLAIM + 7] = SPRR_VIEW_TABLES;
#endif
#if SNAP_TOKEN_TRIM
    out[OUT_TOKEN_TRIM] = TOKEN_TRIM_MAGIC;
    out[OUT_TOKEN_TRIM + 1] = (uint64_t)sizeof(struct token_trim_stats) << 32;
    for (unsigned n = 0; n < TOKEN_TRIM_WORDS; n++)
        out[OUT_TOKEN_TRIM + 2 + n] = ((const uint64_t *)&c->root_ext->trim.stats)[n];
#endif
#if SNAP_ROOT_CACHE_WIDE
    root_ext_mirror(c);
#endif
#if SNAP_TXM_ASPACE_WIDE
    txm_ext_mirror(c);
#endif
#if SNAP_ADRENO_IB_ASYNC
    /* An IB still in flight at the stop (A5) is polled to its final status, at most hz / 10 and never past its
     * budget, before quiesce halts GPU traffic and polls CB0 faults; then the flight is reported (IBASYNC1). */
    if (c->root_ext) {   /* setup may have stopped before taking its pages */
        struct adreno_ib_flight *f = IB_FLIGHT(c);
        struct adreno_ops o = gpu_ops(c);
        uint64_t ib_va = f->va, ib_dwords = f->dwords;
        int final;
        if ((c->gpu.status & ADRENO_S_ADOPTED) &&
            adreno_ib_flight_drain(&o, &c->params->gpu, &c->gpu, f, c->params->clock_host_hz / 10, &final))
            record(c, EV_GPU_IB, 0, ib_va, ib_dwords << 32 | (uint32_t)final, f->last_ticks);
        out[OUT_IB_ASYNC] = IB_ASYNC_MAGIC;
        out[OUT_IB_ASYNC + 1] = (uint64_t)sizeof(struct adreno_ib_flight) << 32 | ADRENO_IB_POLL_DIVISOR;
        for (unsigned n = 0; n < ADRENO_IB_FLIGHT_WORDS; n++)
            out[OUT_IB_ASYNC + 2 + n] = ((const uint64_t *)f)[n];
    }
#endif
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
    dvfs_stop(c, out);   /* the GPU back to OPP 1 before quiesce; the record OUT_DVFS */
#endif
#if SNAP_ANS_ASYNC
    /* agents/nvme-async N6: every executor has stopped; reap the SSD command in flight (bounded by its timeout)
     * so q1n1 takes the controller back with its I/O queue idle; queued commands are abandoned and counted. */
    if (c->root_ext && c->root_ext->ans) {
        struct ans_ops o = ans_ops_of(c);
        ans_async_stop(c->root_ext->ans, &o);
    }
#endif
    /* GPU DMA halted and the mirror unlinked before the guest's memory is
     * published and handed back (and so before any chainload). */
    if (!gpu_quiesce(c)) {
        xnuboot_restore_host(c, 1);
        return XNUBOOT_TERMINAL_GPU;
    }
    ans_window_stop(c);
    c->gpu.irq_fired=c->gpu.irq.line[0].fired;
    c->gpu.irq_kept=c->gpu.irq.line[0].kept;
    c->gpu.irq_resampled=c->gpu.irq.line[0].resampled;
    c->gpu.irq_spurious=c->gpu.irq.line[0].spurious;
    for (unsigned n=0;n<ADRENO_STATE_WORDS;n++) out[OUT_GPU_FLOW+n]=((const uint64_t *)&c->gpu)[n];
    uint64_t timer_ctl = guest_timer_control(&vcpu_of(c)->timer, clock_counter(c));
    /* Complete guest writes before hashing pixels, USB diagnostics, or a
     * subsequent upload reuses the same physical memory. q1n1 resumes only
     * after this report, so its UI cannot race the framebuffer witness. */
    watchdog_off(c);
    if (vcpu_of(c)->guest_sctlr) {
        publish(c->params->mem_low, c->params->mem_high);
        if (c->fb_observed)
            publish(c->params->fb_pa, c->params->fb_pa + c->fb_observed);
    }
    out[OUT_FRAMEBUFFER + 0] = c->fb_observed;
    out[OUT_FRAMEBUFFER + 1] = c->fb_before;
    out[OUT_FRAMEBUFFER + 2] = c->fb_observed ? framebuffer_hash(c->params) : 0;
    out[OUT_ASYNC_REGS] = vcpu_of(c)->async_captured;
    const uint64_t *async = (const uint64_t *)&vcpu_of(c)->async_regs;
    for (unsigned n = 0; n < GUEST_REGS_WORDS; n++)
        out[OUT_ASYNC_REGS + 1 + n] = async[n];
    out[OUT_EXCEPTION_FLOW + 0] = vcpu_of(c)->kernel_returns;
    out[OUT_EXCEPTION_FLOW + 1] = vcpu_of(c)->pacga_calls;
    out[OUT_EXCEPTION_FLOW + 2] = vcpu_of(c)->last_kernel_return;
    out[OUT_UPDATE_FLOW + 0] = c->update_calls;
    out[OUT_UPDATE_FLOW + 1] = c->update_entries;
    out[OUT_UPDATE_FLOW + 2] = c->region_calls;
    out[OUT_UPDATE_FLOW + 3] = c->region_entries;
    out[OUT_SLIDE_FLOW + 0] = c->slide.calls;
    out[OUT_SLIDE_FLOW + 1] = c->slide.pages;
    out[OUT_SLIDE_FLOW + 2] = c->slide.cursor;
    out[OUT_CLOCK_FLOW + 0] = vcpu_of(c)->clock.reads;
    out[OUT_CLOCK_FLOW + 1] = vcpu_of(c)->clock.first;
    out[OUT_CLOCK_FLOW + 2] = vcpu_of(c)->clock.last;
    out[OUT_CLOCK_FLOW + 3] = vcpu_of(c)->clock.writes;
    out[OUT_CLOCK_FLOW + 4] = vcpu_of(c)->clock.cntkctl;
    out[OUT_CLOCK_FLOW + 5] = vcpu_of(c)->clock_hz;
    uint64_t cntkctl = 0;
    if (vcpu_of(c)->clock_saved)
        __asm__ volatile("mrs %0, cntkctl_el1" : "=r"(cntkctl));
    out[OUT_CLOCK_FLOW + 6] = cntkctl;
    out[OUT_CLOCK_FLOW + 7] = vcpu_of(c)->save_cntkctl;
    out[OUT_CLOCK_ADAPTER + 0] = vcpu_of(c)->clock_rate.host_hz;
    out[OUT_CLOCK_ADAPTER + 1] = vcpu_of(c)->clock_rate.guest_hz;
    out[OUT_CLOCK_ADAPTER + 2] = vcpu_of(c)->save_cnthctl;
    out[OUT_CLOCK_ADAPTER + 3] = vcpu_of(c)->guest_cnthctl;
    out[OUT_CLOCK_ADAPTER + 4] = vcpu_of(c)->wfe_traps;
    out[OUT_CLOCK_ADAPTER + 5] = vcpu_of(c)->event_wakes;
    out[OUT_CLOCK_ADAPTER + 6] = vcpu_of(c)->wfe_early;
    out[OUT_CLOCK_ADAPTER + 7] = vcpu_of(c)->arch_counter_reads;
    out[OUT_CLOCK_ADAPTER + 8] = vcpu_of(c)->clock_raw_first;
    out[OUT_CLOCK_ADAPTER + 9] = vcpu_of(c)->clock_raw_last;
    out[OUT_CLOCK_ADAPTER + 10] = vcpu_of(c)->clock_guest_first;
    out[OUT_CLOCK_ADAPTER + 11] = vcpu_of(c)->clock_guest_last;
    out[OUT_AIC_FLOW + 0] = vcpu_of(c)->model_irq_pending;
    out[OUT_AIC_FLOW + 1] = vcpu_of(c)->model_irq_asserts;
    out[OUT_AIC_FLOW + 2] = vcpu_of(c)->model_irq_clears;
    out[OUT_AIC_FLOW + 3] = vcpu_of(c)->model_irq_vectors;
    uint64_t aic_events = 0;
    for (unsigned i=0; i<c->params->model_count && i<DEVICE_MODEL_MAX; i++)
        aic_events += c->model_state[i].aic.events;
    out[OUT_AIC_FLOW + 4] = aic_events;
    for (unsigned i=0;i<DEVICE_RESET_WORDS;i++)
        out[OUT_WATCHDOG_FLOW+i] = c->device_reset_mask[i];
    out[OUT_OPTIONAL_FLOW] = c->txm_developer_notifications;
    out[OUT_OPTIONAL_FLOW+1] = c->cputrace_queries[0] |
                             ((uint64_t)c->cputrace_queries[1] << 32);
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        const struct vcpu *v = &c->vcpus[n];
        unsigned at = OUT_VCPU_FLOW+n*12;
        out[at+0] = (uint64_t)v;
        out[at+1] = v->slot;
        out[at+2] = v->vmpidr;
        out[at+3] = v->prepared;
        out[at+4] = v->guest_ttbr1;
        out[at+5] = v->timer.reads;
        out[at+6] = v->ipi.requests;
        out[at+7] = v->exceptions;
        out[at+8] = v->stage2_root;
        out[at+9] = vcpu_vttbr(v);
        out[at+10] = v->guard_count;
        out[at+11] = v->open_guards;
    }
    out[OUT_SHARED_FLOW] = c->shadow_tlb_syncs;
    out[OUT_SHARED_FLOW+1] = c->root_checks;
    out[OUT_SHARED_FLOW+2] = c->root_busy_refusals;
    out[OUT_SERVICE_FLOW] = guest_service_owner(&c->services);
    out[OUT_SERVICE_FLOW+1] = guest_service_stopped(&c->services);
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        out[OUT_SERVICE_FLOW+2+n*2] = c->vcpus[n].service_acquires;
        out[OUT_SERVICE_FLOW+3+n*2] = c->vcpus[n].service_fault;
    }
    out[OUT_SERVICE_FLOW+2+GUEST_CPU_COUNT*2] = guest_service_lifecycle(&c->services);
    out[OUT_SERVICE_FLOW+3+GUEST_CPU_COUNT*2] = guest_service_reusable(&c->services);
    for (unsigned n=0; n<GUEST_CPU_COUNT; n++) {
        const struct vcpu *v=&c->vcpus[n];
        unsigned at=OUT_RUNTIME_STORAGE+n*5;
        out[at]=v->vncr_va;
        out[at+1]=n ? v->out_ptr : 0;
        out[at+2]=n && v->el2_sp ? v->el2_sp-GUEST_RUNTIME_STACK : 0;
        out[at+3]=n ? v->el2_sp : 0;
        out[at+4]=v->vncr_va ? *(const volatile uint64_t *)(v->vncr_va+0x78) : 0;
    }
    uint64_t active_vncr;
    __asm__ volatile("mrs %0, s3_4_c2_c2_0" : "=r"(active_vncr));
    out[OUT_RUNTIME_STORAGE+GUEST_CPU_COUNT*5]=active_vncr;
    out[OUT_IPI_FLOW+0]=vcpu_of(c)->ipi.pending;
    out[OUT_IPI_FLOW+1]=vcpu_of(c)->ipi.requests;
    out[OUT_IPI_FLOW+2]=vcpu_of(c)->ipi.reads;
    out[OUT_IPI_FLOW+3]=vcpu_of(c)->ipi.acks;
    out[OUT_IPI_FLOW+4]=vcpu_of(c)->ipi.coalesced;
    out[OUT_IPI_FLOW+5]=vcpu_of(c)->ipi.last_request;
    out[OUT_IPI_FLOW+6]=vcpu_of(c)->ipi_request_pc;
    out[OUT_IPI_FLOW+7]=vcpu_of(c)->ipi_ack_pc;
    out[OUT_CPU_FLOW+0]=c->cpus.registered;
    out[OUT_CPU_FLOW+1]=c->cpus.registrations;
    out[OUT_CPU_FLOW+2]=c->cpus.id_queries;
    out[OUT_CPU_FLOW+3]=c->cpus.output_queries;
    out[OUT_CPU_FLOW+4]=vcpu_of(c)->slot;
    out[OUT_CPU_FLOW+5]=c->cpus.last_affinity;
    out[OUT_CPU_FLOW+6]=c->cpus.last_slot;
    out[OUT_CPU_FLOW+7]=c->cpus.reserved;
    for (unsigned i=0; i<DEVICE_MODEL_MAX; i++) {
        const struct watchdog_state *wd = &c->model_state[i].watchdog;
        out[OUT_WATCHDOG_FLOW+DEVICE_RESET_WORDS+3*i] = wd->current | ((uint64_t)wd->control << 32);
        out[OUT_WATCHDOG_FLOW+DEVICE_RESET_WORDS+1+3*i] = wd->bite | ((uint64_t)wd->reset << 32);
        out[OUT_WATCHDOG_FLOW+DEVICE_RESET_WORDS+2+3*i] = wd->last;
    }
    out[OUT_TIMER_FLOW + 0] = vcpu_of(c)->timer.reads;
    out[OUT_TIMER_FLOW + 1] = vcpu_of(c)->timer.writes;
    out[OUT_TIMER_FLOW + 2] = vcpu_of(c)->timer_irqs;
    out[OUT_TIMER_FLOW + 3] = vcpu_of(c)->timer_asserts;
    out[OUT_TIMER_FLOW + 4] = vcpu_of(c)->timer_clears;
    out[OUT_TIMER_FLOW + 5] = vcpu_of(c)->timer_vectors;
    out[OUT_TIMER_FLOW + 6] = timer_ctl;
    out[OUT_TIMER_FLOW + 7] = vcpu_of(c)->timer.cval;
    out[OUT_TIMER_FLOW + 8] = vcpu_of(c)->timer_irq_pc;
    out[OUT_TIMER_FLOW + 9] = vcpu_of(c)->watchdog_deadline;
    out[OUT_TIMER_FLOW + 10] = vcpu_of(c)->step_exception_repairs;
    out[OUT_DEVICE_FLOW] = c->params->model_count;
    for (unsigned i=0; i<DEVICE_MODEL_MAX; i++) {
        out[OUT_DEVICE_FLOW + 1 + 2*i] = c->model_reads[i];
        out[OUT_DEVICE_FLOW + 2 + 2*i] = c->model_writes[i];
    }
    out[0] = vcpu_of(c)->shadow_root;
    out[1] = c->leaves;
#if SNAP_FAST_VCPU_TRAPS
    /* Every emulated system-register trap, locked or fast. The executors have
     * quiesced, so their private counters are final. */
    {
        uint64_t fast = 0;
        for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) fast += c->perf.fast[n].sysreg;
        out[2] = c->traps + fast;
    }
#else
    out[2] = c->traps;
#endif
    out[3] = c->events;
    out[4] = c->aborts | (c->steps << 32);
    out[5] = vcpu_of(c)->stage2_root;
    /* A syndrome, and nothing else. The only thing that writes it is the
     * failed AT S1E1R in xnuboot_prepare(), which carries PAR_EL1 -- so on a
     * run that entered, this is zero unless something records a fault. */
    out[6] = vcpu_of(c)->fault_esr;
    out[7] = c->calls | (c->console_len << 32);
    uint8_t *console = (uint8_t *)&out[8 + 6 * EVENT_MAX];
    for (unsigned n = 0; n < CONSOLE_MAX; n++) console[n] = c->console[n];
    for (unsigned n = 0; n < EVENT_MAX; n++) {
        out[8 + 6 * n + 0] = c->log[n].kind;
        out[8 + 6 * n + 1] = c->log[n].pc;
        out[8 + 6 * n + 2] = c->log[n].a;
        out[8 + 6 * n + 3] = c->log[n].b;
        out[8 + 6 * n + 4] = c->log[n].c;
        out[8 + 6 * n + 5] = c->log[n].repeats;
    }

    /* The register snapshots, after the console so nothing already parsed
     * moves. probes/run.py reads them at OUT_GUEST_REGS; the two files agree
     * through the _Static_assert below and the same constant on that side. */
    {
        uint64_t *regs_out = &out[OUT_GUEST_REGS];
        regs_out[0] = vcpu_of(c)->exceptions;
        const uint64_t *src = (const uint64_t *)&vcpu_of(c)->first_exc;
        for (unsigned n = 0; n < GUEST_REGS_WORDS; n++) regs_out[1 + n] = src[n];
        src = (const uint64_t *)&vcpu_of(c)->last_exc;
        for (unsigned n = 0; n < GUEST_REGS_WORDS; n++)
            regs_out[1 + GUEST_REGS_WORDS + n] = src[n];

        uint64_t *panic_out = &out[OUT_PANIC_REGS];
        panic_out[0] = vcpu_of(c)->panic_calls;
        src = (const uint64_t *)&vcpu_of(c)->panic_exc;
        for (unsigned n = 0; n < GUEST_REGS_WORDS; n++) panic_out[1 + n] = src[n];

        uint64_t *counters = &out[OUT_COUNTERS];
        counters[0] = c->map_pages;
        counters[1] = c->map_failures;
        counters[2] = c->dispatch_cmds;
        counters[3] = vcpu_of(c)->panic_calls;
        counters[4] = c->undef_skipped;
        counters[5] = c->map_outside;
        counters[6] = c->log_dropped;
        counters[7] = c->console_dropped;
        counters[8] = c->ranges_dropped;
        counters[9] = c->map_device;
        counters[10] = c->mmio_reads;
        counters[11] = c->mmio_writes;
        counters[12] = c->uart_tx;

        out[OUT_EXC_RETURN] = c->exc_return;
        out[OUT_BAD_REGS + 0] = vcpu_of(c)->bad_elr;
        out[OUT_BAD_REGS + 1] = vcpu_of(c)->bad_far;

        /* The terminal word, in the shape of a log entry so the host reads it
         * with the same unpack. Written even when it is empty, so the host
         * never has to distinguish "no event" from "a short read". */
        out[OUT_LAST_EVENT + 0] = c->last.kind;
        out[OUT_LAST_EVENT + 1] = c->last.pc;
        out[OUT_LAST_EVENT + 2] = c->last.a;
        out[OUT_LAST_EVENT + 3] = c->last.b;
        out[OUT_LAST_EVENT + 4] = c->last.c;
        out[OUT_LAST_EVENT + 5] = c->last.repeats;

        /* Sixty-four buckets and the one for everything else. */
        for (unsigned n = 0; n < ENDPOINT_BUCKETS; n++)
            out[OUT_ENDPOINTS + n] = c->endpoint_calls[n];
        out[OUT_ENDPOINTS + ENDPOINT_BUCKETS] = c->endpoint_other;

        /* The span table: how many slots are used, how many spans did not fit,
         * then the slots themselves. Every slot is written, used or not, so a
         * short read cannot be mistaken for an empty one. */
        uint64_t *ranges = &out[OUT_RANGES];
        ranges[0] = c->range_count;
        ranges[1] = c->ranges_dropped;
        for (unsigned n = 0; n < MAP_RANGES; n++) {
            ranges[2 + MAP_RANGE_WORDS * n + 0] = c->ranges[n].va;
            ranges[2 + MAP_RANGE_WORDS * n + 1] = c->ranges[n].pa;
            ranges[2 + MAP_RANGE_WORDS * n + 2] = c->ranges[n].pages;
            ranges[2 + MAP_RANGE_WORDS * n + 3] = c->ranges[n].attrs;
        }

        /* The guest's translation registers, in the order run.py names them. */
        out[OUT_GUEST_SYSREGS + 0] = vcpu_of(c)->guest_ttbr0;
        out[OUT_GUEST_SYSREGS + 1] = vcpu_of(c)->guest_ttbr1;
        out[OUT_GUEST_SYSREGS + 2] = vcpu_of(c)->guest_tcr;
        out[OUT_GUEST_SYSREGS + 3] = vcpu_of(c)->guest_mair;
        out[OUT_GUEST_SYSREGS + 4] = vcpu_of(c)->guest_sctlr;
    }

    xnuboot_restore_host(c, 1);
    return XNUBOOT_TERMINAL_OK;
}
#if SNAP_GATE_WAIT && !defined(GATE_WAIT_BUILT)
#error "SNAP_GATE_WAIT waits on the converted calls' gate: build with the fine locks"
#endif
