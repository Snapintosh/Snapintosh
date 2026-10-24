/* SPDX-License-Identifier: MIT */
/* Vector branch, stage-2 fault retry and xnuboot_trap_locked, the locked
 * trap dispatcher.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_VECTOR_BRANCH
/* Perform the first instruction of the vector slot at *elr, an unconditional
 * B out of the vector page (fast_vector_branch), and never open the page:
 * the same state the single step would leave, with the step disarmed and
 * every guard closed, but without the step exit, the two stage-2 descriptor
 * writes and the two broadcast TLB invalidations. 0: the slot holds anything
 * else, nothing changed, and the caller opens and steps the page as before. */
static int vector_branch(struct context *c, uint64_t *elr)
{
    const struct params *p = c->params;
    uint64_t target;
    if (*elr - p->vbar_va >= 0x800 ||
        !fast_vector_branch(*(const volatile uint32_t *)(p->vbar | (*elr & 0xfff)), *elr, &target))
        return 0;
    step_arm(c, 0);
    guards_close(c);
    c->perf.fast[vcpu_of(c)->slot].branches++;
    *elr = target;
    return 1;
}
#endif

#if SNAP_S2_FAULT_RETRY
/* compat/s2-fault-retry.h: a guest abort that is about to stop the run as a
 * stage-2 fault (no guard, device window, model or Adreno block took it).
 * Every translation fault is snapshotted; one whose HPFAR IPA is guest RAM
 * that this CPU's tree maps (or, with SNAP_S2_FAULT_RETRY_STAGE1, whose
 * stage-1 re-walk's IPA is) is retried within the bounds: this CPU's stage 1
 * and stage 2 for its VMID are invalidated and the instruction runs again
 * (1). 0: stop as before. */
static int s2_fault_retry(struct context *c, uint64_t esr, uint64_t elr, uint64_t far, uint64_t hpfar)
{
    const struct params *p = c->params;
    struct vcpu *v = vcpu_of(c);
    struct s2_retry_state *s = c->s2_retry;
    int level = s2_retry_translation(esr);
    if (!s || level < 0 || v->slot >= S2_RETRY_CPUS) return 0;
    struct s2_retry_entry e = {0};
    uint64_t parange;
    __asm__ volatile("mrs %0, vttbr_el2; mrs %1, vtcr_el2; mrs %2, hcr_el2; mrs %3, spsr_el2"
                     : "=r"(e.vttbr), "=r"(e.vtcr), "=r"(e.hcr), "=r"(e.spsr));
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1; mrs %2, mpidr_el1; mrs %3, id_aa64mmfr0_el1"
                     : "=r"(e.ttbr0), "=r"(e.tcr), "=r"(e.mpidr), "=r"(parange));
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(e.counter));
    parange &= 0xf;
    if (parange > 5) parange = 5;               /* as vcpu_arch_prepare */
    e.esr = esr; e.far = far; e.hpfar = hpfar; e.elr = elr;
    e.vttbr_expected = vcpu_vttbr(v);
    e.vtcr_expected = s2_retry_vtcr(S2_TXSZ, parange);
    e.ipa_hw = s2_retry_hpfar_ipa(hpfar, far, esr);
    e.ipa_at = ((esr >> 7) & 1) ? 0 : guest_pa(far);
    /* Both walks through the tree VTTBR names now, whatever it is. */
    uint64_t root = e.vttbr & UINT64_C(0x0000fffffffffffe);
    int hw_mapped = s2_retry_dram(e.ipa_hw, p->mem_low, p->mem_high) &&
                    s2_retry_walk(mem_read, c, root, S2_TXSZ, e.ipa_hw, e.d_hw);
    int at_mapped = e.ipa_at && s2_retry_dram(e.ipa_at, p->mem_low, p->mem_high) &&
                    s2_retry_walk(mem_read, c, root, S2_TXSZ, e.ipa_at, e.d_at);
    enum s2_retry_kind kind;
    enum s2_retry_verdict verdict =
        s2_retry_judge(&s->cpu[v->slot],
                       s2_retry_registers_ok(e.vttbr, e.vttbr_expected, e.vtcr, e.vtcr_expected, e.hcr),
                       hw_mapped, at_mapped, SNAP_S2_FAULT_RETRY_STAGE1, e.counter,
                       p->clock_host_hz, elr, far, &kind);
    s2_retry_note(s, &e, (unsigned)v->slot, level, kind, verdict);
    if (verdict != S2_RETRY_RESUME) return 0;
    record(c, EV_S2_RETRY, elr, e.ipa_hw, esr, far);
    __asm__ volatile("dsb ish; tlbi vmalls12e1; dsb nsh; isb" ::: "memory");
    return 1;
}
#endif

static int xnuboot_trap_locked(uint64_t *frame, uint64_t esr, uint64_t *elr)
{
    struct context *c = context_of();
    const struct params *p = c->params;
    uint64_t ec = esr >> 26, iss = esr & 0x1ffffff;
    struct user_execution *user=&c->user_execution[vcpu_of(c)->slot];
    uint64_t physical_spsr;
    __asm__ volatile("mrs %0, spsr_el2":"=r"(physical_spsr));
    if(SNAP_NATIVE_WRITER_BREAKPOINTS && ec==0x30) {
        struct vcpu *v=vcpu_of(c);
        struct native_writer_debug *debug=&c->writer_debug[v->slot];
        uint64_t value=0,pa=0;int spsr=0;unsigned site=0;uint32_t word=0;
        debug->last_pc=*elr;
        unsigned mode=physical_spsr&31;
        if(debug->installed && (mode==4 || mode==5) && (esr&(1UL<<25))) {
            pa=guest_pa(*elr);
            for(unsigned i=0;i<NATIVE_WRITER_SITE_COUNT;i++) {
                const struct native_writer_site *entry=&native_writer_sites[i];
                uint64_t expected=p->stub_pa[NATIVE_CALL_PAGES+entry->page]+(entry->va&4095);
                if(*elr==entry->va && pa==expected)word=*(const volatile uint32_t *)expected;
            }
        }
        debug->last_word=word;
        if(!native_writer_value(*elr,word,frame,&value,&spsr,&site)) {
            debug->rejected++;
            record(c,EV_NATIVE_WRITER_FAILED,*elr,esr,pa,word);
            fill_regs(&v->async_regs,frame,esr,*elr,pa);v->async_captured=2;return 1;
        }
        if(spsr) {__asm__ volatile("msr spsr_el1, %0"::"r"(value):"memory");}
        else {__asm__ volatile("msr elr_el1, %0"::"r"(value):"memory");}
        if(v->stepping.active) {debug->stepped++;step_arm(c,0);}
        guards_close(c);debug->traps++;*elr+=4;
        /* The common exit snapshots both physical exception registers before
         * a later native private call can overwrite them. */
        return 0;
    }
    if(user->pending && ec==0x32 && !(physical_spsr&31)) {
        uint64_t sp;__asm__ volatile("mrs %0, sp_el0":"=r"(sp));
        user->observed_pc=*elr;user->observed_spsr=physical_spsr;
        user->observed_esr=esr;user->observed_x0=frame[0];user->observed_sp=sp;
        int done=exception_user_step((uint32_t)user->instruction,user->entry,user->stack,
                                    esr,physical_spsr,*elr,frame[0],sp);
        user->pending=0;
        step_arm(c,0);guards_close(c);
        record(c,done ? EV_USER_EXECUTED : EV_USER_STEP_FAILED,*elr,user->entry,frame[0],physical_spsr);
        if(done) {user->executed++;return 0;}
        fill_regs(&vcpu_of(c)->async_regs,frame,esr,*elr,sp);
        vcpu_of(c)->async_captured=2;return 1;
    }

#if SNAP_GUEST_BRK_REFLECT
    /* BRK64 (EC 0x3c) from guest AArch64 EL0/EL1 arrives here only because
     * MDCR_EL2.TDE is set. Take it to EL1 as the architecture would without
     * TDE: ESR/ELR/SPSR_EL1 from the trap, FAR_EL1 untouched (UNKNOWN for
     * BRK), vector +0x400 from EL0, +0x200 from EL1h, +0x000 from EL1t.
     * Entry PSTATE is EL1h with DAIF masked, PAN set (SCTLR_EL1.SPAN=0 in
     * guest_sctlr), SSBS clear (DSSBS=0), SS/IL/BTYPE clear. Not while the
     * monitor single-steps (its own debug state owns that window). */
    if(ec==0x3c && !(physical_spsr&(1UL<<4)) && !vcpu_of(c)->stepping.active && !user->pending) {
        unsigned mode=physical_spsr&31;
        uint64_t sctlr,vbar,offset=mode==0 ? 0x400 : mode==5 ? 0x200 : mode==4 ? 0 : 1;
        __asm__ volatile("mrs %0, sctlr_el1; mrs %1, vbar_el1":"=r"(sctlr),"=r"(vbar));
        if(offset!=1 && vbar && !(vbar&0x7ff) && !(sctlr&(1UL<<23)) && !(sctlr&(1UL<<44))) {
            struct guest_brk_stats *b=&c->guest_brk[vcpu_of(c)->slot];
            __asm__ volatile("msr elr_el1, %0; msr spsr_el1, %1; msr esr_el1, %2; isb"
                             ::"r"(*elr),"r"(physical_spsr),"r"(esr):"memory");
            if(mode)b->el1++;else b->el0++;
            b->last_pc=*elr;b->last_esr=esr;b->last_spsr=physical_spsr;
            __asm__ volatile("msr spsr_el2, %0"::"r"(UINT64_C(0x3c5)|(UINT64_C(1)<<22)):"memory");
            guards_close(c);
            *elr=vbar+offset;
            return 0;
        }
    }
#endif
    /* A stepped instruction can enter EL1's exception vectors. The debug
     * exception is delivered before the vector's first instruction, without
     * an intervening stage-2 execute fault. Treat that landing exactly like
     * a guarded vector fetch, or we lose the primary exception and observe
     * only the fault inside XNU's not-yet-initialized exception handler. */
    int vector_step = p->vbar && exception_vector_step(esr, *elr, p->vbar_va);
    if (vector_step) {
        step_translation_clear(&c->step_translation[vcpu_of(c)->slot]);
        ec = 0x20; iss = 0;
    }

    if (ec == 0x20 || ec == 0x24) {              /* abort from EL1, insn or data */
        uint64_t hpfar, far;
        __asm__ volatile("mrs %0, hpfar_el2" : "=r"(hpfar));
        __asm__ volatile("mrs %0, far_el2" : "=r"(far));
        if (vector_step) far = *elr;
        /* Where the IPA comes from. HPFAR_EL2 read back as zero for a stage-2
         * permission fault on this silicon, so the address is recovered by
         * translating the VA through stage 1, which answers whenever stage 1
         * itself resolved. When the stage-1 walk is what faulted (S1PTW: a
         * table page stage 2 does not map, or would not let the walker write)
         * the VA translates to nothing and HPFAR names the table page, without
         * an offset. Zero means neither could say, and is reported as that
         * rather than as an address. */
        uint64_t s1ptw = (iss >> 7) & 1;
        uint64_t ipa = s1ptw ? 0 : guest_pa(far);
        if (!ipa && (hpfar & 0x0000fffffffffff0UL))
            ipa = ((hpfar >> 4) << 12) | (s1ptw ? 0 : (far & 0xfff));

        struct guard *g = guard_find(c, ipa);
        if (g && g->mode == GUARD_DATA) {
            /* A handoff field. Log which one, then let exactly one instruction
             * run against it. */
            record(c, EV_HANDOFF, *elr, ipa - p->watch_pa, esr, far);
            guard_open(c, g);
            step_arm(c, 1);
            return 0;
        }
        if (ec == 0x20 && g) {
            if (p->vbar && (ipa & ~0xfffUL) == p->vbar) {
                /* XNU tried to enter its own vectors: it faulted. Its syndrome
                 * is what we actually want, not ours. */
                uint64_t g_esr, g_far, g_elr;
                __asm__ volatile("mrs %0, esr_el1" : "=r"(g_esr));
                __asm__ volatile("mrs %0, far_el1" : "=r"(g_far));
                __asm__ volatile("mrs %0, elr_el1" : "=r"(g_elr));
                /* IRQ/FIQ entries do not update ESR/FAR. Recognize their
                 * architectural slots and require our asserted AIC/timer
                 * level. Never infer an interrupt from a stale syndrome. */
                uint64_t vector = *elr - p->vbar_va, hcr, saved;
                __asm__ volatile("mrs %0, spsr_el1" : "=r"(saved));
                if (SNAP_NATIVE_CALLS && g_esr==(1UL<<25) &&
                    ((saved&31)==8 || (saved&31)==9) && !(g_elr&3) &&
                    g_elr>=UINT64_C(0xffff800000000000)) {
                    uint64_t pa=guest_pa(g_elr),physical=0;
                    int call_page=0;
                    for(unsigned n=0;n<NATIVE_CALL_PAGES;n++)
                        call_page|=(pa&~0xfffUL)==p->stub_pa[n];
                    uint32_t word=call_page ? *(const uint32_t *)pa : 0;
                    if (native_call_word(word)) {
                        SERVICE_SUB_TAG(c,service_sub_call(frame[16],SPTM_CMD_ENDPOINT));
#if SNAP_OTHER_PROFILE
                        other_profile_tag(&c->root_ext->other,(unsigned)vcpu_of(c)->slot,frame[16]);
#endif
                        struct vcpu *v=vcpu_of(c);
                        struct native_call_state *s=&c->native_calls[v->slot];
                        s->calls++;s->last_pc=g_elr;s->last_word=word;s->last_saved=saved;
                        if (s->ready!=1 || v->stepping.active || v->open_guards ||
                            !native_call_return(vector,g_esr,saved,physical_spsr,
                                                g_elr,word,&physical)) {
                            s->rejected++;
                            fill_regs(&v->async_regs,frame,g_esr,g_elr,g_far);
                            v->async_captured=2;
                            record(c,EV_MONITOR,g_elr,word,saved,physical_spsr);
                            return 1;
                        }
                        s->last_physical=physical;
                        native_exception_restore(s);
                        __asm__ volatile("msr spsr_el2, %0" :: "r"(physical) : "memory");
                        *elr=g_elr;
                        return monitor_request(c,frame,elr);
                    }
                }
                if (vector < 0x800 && !(vector & 0x7f)) {
                    if(vector>=0x400 && vector<=0x580 && !(saved&31)) {
                        struct pan_entry_state *pan=&c->pan_entry[vcpu_of(c)->slot];
                        pan->user_vectors++;
                        pan->protected_vectors+=!!(physical_spsr&(1UL<<22));
                        pan->vector=vector;pan->saved_spsr=saved;
                        pan->entry_spsr=physical_spsr;
                        __asm__ volatile("mrs %0, sctlr_el1":"=r"(pan->entry_sctlr));
                    }
                    if(user->pending) {user->interrupted++;user->pending=0;}
                    if (exception_step_suspend(&vcpu_of(c)->stepping, &saved)) {
                        __asm__ volatile("msr spsr_el1, %0" :: "r"(saved));
                        vcpu_of(c)->step_exception_repairs++;
                        step_arm(c, 0);
                    }
                }
                if(user_sysreg_access(c,frame,g_elr,saved,g_esr,vector,elr))return 0;
                SERVICE_SUB_TAG(c,SERVICE_SUB_VECTOR);
                /* This is the first instruction of a lower-EL vector,
                 * including IRQ/FIQ. Switch to PPERM before opening it.
                 * The emulated EL0 sysreg fast return above executes no EL1
                 * instruction and retains its UPERM view throughout. */
                if(vector>=0x400 && vector<=0x580 && !(vector&0x7f) &&
                   !(saved&31) && !user_enter_mode(c,0))return 1;
                __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
                if ((vector == 0x100 || vector == 0x300 ||
                     (vector == 0x500 && !(saved&31))) && (hcr & (1UL << 6))) {
                    vcpu_of(c)->timer_vectors++;
                    record(c, EV_TIMER_FIQ, *elr, g_elr, vcpu_of(c)->timer.ctl, vcpu_of(c)->timer.cval);
                    vcpu_of(c)->fault_esr = vcpu_of(c)->fault_far = 0;
                    step_arm(c, 0);
#if SNAP_VECTOR_BRANCH
                    if (vector_branch(c, elr)) return 0;
#endif
                    guard_open(c, g);
                    if (SNAP_NATIVE_WRITER_BREAKPOINTS) step_arm(c, 1);
                    return 0;
                }
                if ((vector == 0x80 || vector == 0x280 ||
                     (vector == 0x480 && !(saved&31))) && (hcr & (1UL << 7))) {
                    vcpu_of(c)->model_irq_vectors++;
                    record(c, EV_DEVICE_IRQ, *elr, g_elr, vcpu_of(c)->model_irq_pending, 0);
                    vcpu_of(c)->fault_esr = vcpu_of(c)->fault_far = 0;
                    step_arm(c, 0);
#if SNAP_VECTOR_BRANCH
                    if (vector_branch(c, elr)) return 0;
#endif
                    guard_open(c, g);
                    if (SNAP_NATIVE_WRITER_BREAKPOINTS) step_arm(c, 1);
                    return 0;
                }
                /* The caller, not the vector. Every blocker at this stage is
                 * a null pointer somewhere, and the faulting PC is usually
                 * inside bzero or memcpy -- shared by dozens of call sites, so
                 * it names nothing. x30 is the one register that says which of
                 * them, and the guest's copy is right here in the frame. The
                 * vector address it replaces was never informative: it is the
                 * page we guarded, so we already knew it. */
                /* An instruction this silicon does not implement.
                 *
                 * EC 0 is "unknown reason", which at EL1 is what an unallocated
                 * encoding produces -- and this kernel is built for a CPU with
                 * Apple's additions. Stopping here reports one instruction and
                 * learns nothing more; stepping over it asks the only question
                 * that matters, which is whether anything downstream needed its
                 * effect. If the boot goes further, the encoding is worth
                 * identifying properly. If it faults immediately afterwards on
                 * whatever the instruction should have produced, that is the
                 * answer too, and a louder one.
                 *
                 * This is a lie of omission and is counted as one: skipped is
                 * reported separately from answered, so a run that only gets
                 * further because of this cannot be read as one that works. */
                if ((g_esr >> 26) == 0 && c->skip_undef) {
                    uint64_t pa = guest_pa(g_elr);
                    uint32_t word = pa ? *(volatile uint32_t *)pa : 0;
                    record(c, EV_OTHER, g_elr, 0xDEAD0000UL | (word & 0xffff),
                           word, c->undef_skipped);
                    c->undef_skipped++;
                    __asm__ volatile("msr elr_el1, %0" :: "r"(g_elr + 4));
                    *elr = g_elr + 4;
                    guards_close(c);
                    return 0;
                }
                /* The whole register file, into its own area rather than into
                 * the log. The four EV_OTHER records below predate it and are
                 * kept because the report already parses them, but they are a
                 * twelve-register sample and this is all of it. */
                capture_regs(c, frame, g_esr, g_elr, g_far);
                /* And the registers the fault was computed from. A null pointer
                 * says nothing about where it came from; the callee-saved
                 * registers of the frame that produced it usually say exactly.
                 * Cheaper than a second event kind, and this is the one moment
                 * the guest's register file is worth more than any counter. */
                record(c, EV_OTHER, 8, frame[8], frame[9], frame[10]);
                record(c, EV_OTHER, 11, frame[11], frame[12], frame[13]);
                record(c, EV_OTHER, 19, frame[19], frame[20], frame[21]);
                record(c, EV_OTHER, 22, frame[22], frame[23], frame[24]);
                /* Keep the terminal slot meaningful when the detailed log
                 * is full; the register sample is secondary to the fault. */
                record(c, EV_GUEST_EXC, frame[30], g_esr, g_far, g_elr);
                vcpu_of(c)->fault_esr = g_esr;
                vcpu_of(c)->fault_far = g_far;
                step_arm(c, 0);

                /* Demand paging requires XNU to see ordinary kernel memory
                 * faults. Record them, then let its handler decide whether
                 * to resolve them or panic. Other exceptions stop by default;
                 * let_panic explicitly allows their diagnostic handlers too.
                 * The watchdog still bounds every run, and unsupported
                 * monitor endpoints remain strict. */
                int user_sync=exception_user_sync(vector,saved,g_esr);
                if(user_sync) {
                    if((g_esr>>26)==0x15)user->svcs++;else user->faults++;
                }
#if SNAP_GUEST_BRK_REFLECT
                /* Process-fatal EL0 synchronous exceptions at the lower-EL
                 * AArch64 sync vector: XNU turns these into the task's own
                 * exception/signal (BRK64 0x3c, unknown 0x00, illegal state
                 * 0x0e, FPAC 0x1c, PC/SP alignment 0x22/0x26). EL1 origins
                 * and every other class still stop the run. */
                if(!user_sync && vector==0x400 && !(saved&31) && !(saved&(1UL<<4))) {
                    unsigned uec=(unsigned)(g_esr>>26)&63;
                    if(uec==0x3c || uec==0x00 || uec==0x0e || uec==0x1c || uec==0x22 || uec==0x26) {
                        user_sync=1;c->guest_user_signal[vcpu_of(c)->slot]++;
                    }
                }
#endif
#if SNAP_USER_CRASH_RING
                /* Evidence before XNU acts: the same lower-EL AArch64 sync
                 * entry the gates above test. Recording changes nothing. */
                if(vector==0x400 && !(saved&31)) {
                    unsigned crash=user_crash_classify(g_esr,g_far,frame[16],frame[1]);
                    if(crash)user_crash_note(c,crash,frame,g_esr,g_elr,g_far);
                }
#endif
                if (exception_kernel_page_fault(g_esr) || user_sync || p->permissive || p->let_panic) {
                    /* These were observations, not terminal faults. The
                     * register snapshots retain them; later refusals must
                     * not inherit a stale syndrome as their stop reason. */
                    vcpu_of(c)->fault_esr = 0;
                    vcpu_of(c)->fault_far = 0;
#if SNAP_VECTOR_BRANCH
                    if (vector_branch(c, elr)) return 0;
#endif
                    guard_open(c, g);
                    /* Writer pages no longer fault when breakpoints own them.
                     * Step only through this vector page so guard_step closes
                     * it at the first instruction outside it. Otherwise the
                     * next private call enters an unguarded XNU vector. */
                    if (SNAP_NATIVE_WRITER_BREAKPOINTS) step_arm(c, 1);
                    return 0;
                }
                return 1;
            }
            /* A monitor call page. The stub marshals its arguments before the
             * call instruction, so the useful state is at the call itself --
             * which means letting the stub run up to it, one instruction at a
             * time, rather than emulating it from its first byte. */
            c->aborts++;
            guard_open(c, g);
            step_arm(c, 1);
            return 0;
        }

        /* A device window the guest's own tree names. MAP_PAGE installed the
         * leaf for exactly this reason: the stage-1 walk resolves, the access
         * reaches stage 2, the IPA is absent there, and it arrives here where
         * a model can answer it. */
        {
            uint64_t off = 0;
#if SNAP_QCC2072_WIFI
            /* The QCC2072's ECAM page is read-only at stage 2. A store to its
             * command register with memory decode on and bus mastering on or
             * off (2 or 6) is performed here, sixteen bits, and read back; any
             * other store falls through and stops the run like any other
             * stage-2 fault (compat/qcc2072-wifi.h). */
            if (ec == 0x24 && !(iss & (1U << 7))) {
                const struct qcc2072_wifi_params *q = qcc2072_wifi_block(p);
                struct dc_access a = dc_decode(esr);
                uint16_t command;
                if (a.valid && a.write &&
                    qcc2072_wifi_command_store(q, ipa, a.size,
                                               dc_narrow(&a, a.reg == 31 ? 0 : frame[a.reg]), &command)) {
                    volatile uint16_t *reg = (volatile uint16_t *)(uintptr_t)(QCC2072_WIFI_ECAM_PA +
                                                                             QCC2072_WIFI_COMMAND);
                    __asm__ volatile("dsb sy" ::: "memory");
                    *reg = command;
                    __asm__ volatile("dsb sy" ::: "memory");
                    uint16_t back = *reg;
                    record(c, EV_QCC2072_COMMAND, *elr, command, back, esr);
                    *elr += 4;
                    return 0;
                }
            }
#endif
            /* Exact binary: global core mask at +4 precedes cluster starts
             * at +8/+c. Only the cluster write may call the real executor. */
            if (ipa>=UINT64_C(0x300734004) && ipa<=UINT64_C(0x30073400c) &&
                c->host_cpus && ec==0x24 &&
                !(iss&(1U<<7))) {
                struct dc_access a=dc_decode(esr);
                uint64_t value=dc_narrow(&a,a.reg==31 ? 0 : frame[a.reg]);
                struct secondary_request request={c,*elr};
                if (a.valid && a.write && guest_cpu_release_write(&c->cpu_release,
#if SNAP_BOOT_RELOCATE
                    boot_relocate_release_mask(c->host_cpus->mask),ipa-UINT64_C(0x300734000),a.size,value,
#else
                    c->host_cpus->mask,ipa-UINT64_C(0x300734000),a.size,value,
#endif
                    secondary_release,&request)) { *elr+=4;return 0; }
            }
            int window = dc_window(p->device_pa, p->device_span,
                                   p->device_count, ipa, &off);
            if (window >= 0)
                return mmio_dispatch(c, frame, elr, esr, ipa, window, off);
            int model = device_model_find(p->models, p->model_count, ipa, &off);
            if (model >= 0)
                return model_dispatch(c, frame, elr, esr, ipa, (unsigned)model, off);
        }

        /* Everything the next step needs, and then the run stops: the IPA
         * says which device, the ESR's ISS says the access size, the register
         * and the direction (when ISV is set) and whether the stage-1 walk was
         * what faulted, the guest VA says which of the kernel's mappings was
         * used, and the PC says which code. Nothing is answered until it has
         * a model (docs/PLAN-HISTORY-20260922.md steps B and F). */
        unsigned block = adreno_block(ipa, p->gpu.flags);
#if SNAP_S2_FAULT_RETRY
        if (!(p->gpu.flags && block) && s2_fault_retry(c, esr, *elr, far, hpfar)) return 0;
#endif
        if (p->gpu.flags && block) {
            c->gpu.traps++;
            c->gpu.trap_ipa = ipa;
            c->gpu.trap_esr = esr;
            c->gpu.trap_block = block;
            record(c, EV_GPU_TRAP, *elr, ipa, esr, block);
        } else {
            record(c, EV_S2_FAULT, *elr, ipa, esr, far);
#if SNAP_S2_FAULT_RETRY
            /* The terminal word's sixth word, otherwise always zero: HPFAR_EL2,
             * the IPA the hardware faulted on (ipa above is the stage-1
             * re-walk's), printed by probes/run.py stage2_stop_hpfar. */
            c->last.repeats = hpfar;
#endif
        }
        fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, far);
        vcpu_of(c)->async_captured = 3;
        return 1;
    }

    if (ec == 0x32) {                            /* the stepped instruction is done */
        c->steps++;
        uint64_t pa = step_instruction_pa(c, *elr, physical_spsr);
        if (SNAP_STEP_ALU && pa && exception_monitor_origin(*elr, physical_spsr) &&
            vcpu_of(c)->stepping.active && vcpu_of(c)->open_guards == 1 &&
            (pa & ~0xfffUL) != p->vbar) {
            struct guard *g = guard_find(c, pa);
            /* The service lock excludes every guest stage-1 update. Stage-2
             * read-only code excludes concurrent stores. No memory access,
             * flags change, SP access, branch, or system operation is emulated.
             * The bounded batch remains in this translation; all unsupported
             * instructions retain their existing native-step/monitor path. */
            uint64_t mdscr;
            __asm__ volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
            if (g && g->mode == GUARD_EXEC && !(g->descriptor & (1UL << 7)) &&
                *(volatile uint64_t *)g->slot == g->descriptor &&
                step_alu_ready(&c->step_alu[vcpu_of(c)->slot], *elr,
                               c->shadow_tlb_syncs, physical_spsr, mdscr)) {
                unsigned n = step_alu_batch((volatile uint32_t *)pa, elr, frame);
                if (n) {
                    struct step_alu_state *s = &c->step_alu[vcpu_of(c)->slot];
                    s->batches++;
                    s->instructions += n;
                    if (s->max_batch < n) s->max_batch = n;
                    pa += n * 4;
                }
            }
        }
        uint32_t word = pa ? *(volatile uint32_t *)pa : 0;
        /* genter, and the second call encoding this kernelcache pairs with every
         * one of them. Both are undefined instructions on this silicon; what
         * matters is that the stub has arrived at one. */
        if (exception_monitor_origin(*elr,physical_spsr) &&
            (word == 0x00201420 || word == 0xd4e00000)) {
            /* Single stepping is still armed, so answering the call and
             * returning keeps us on the next instruction -- which is how the
             * rest of the stub page stays under observation. */
            return monitor_request(c,frame,elr);
        }
        guard_step(c, pa);
        if (SNAP_STEP_ALU && vcpu_of(c)->stepping.active)
            step_alu_resume(&c->step_alu[vcpu_of(c)->slot], *elr, c->shadow_tlb_syncs);
        return 0;
    }

    if (ec == 1 && (iss & 1)) {                  /* trapped WFE */
        clock_wfe(c);
        if (device_reset_stop(c, *elr, frame)) return 1;
        *elr += 4;
        return 0;
    }
    if (ec == 0x16) {                            /* HVC from the guest */
#if SNAP_SPTM_HVC_CALLS
        if ((iss & 0xffff) == NATIVE_HVC_IMMEDIATE) {
            struct vcpu *v=vcpu_of(c);
            struct native_hvc_state *s=&c->sptm_hvc[v->slot];
            uint64_t pc=*elr-4,pa=0;uint32_t word=0;
            unsigned mode=physical_spsr&31;int page=0;
            s->last_pc=pc;
            if((mode==4 || mode==5) && !(pc&3) &&
               pc>=UINT64_C(0xffff800000000000)) {
                pa=guest_pa(pc);
                for(unsigned n=0;n<NATIVE_CALL_PAGES;n++)
                    page|=(pa&~UINT64_C(4095))==p->stub_pa[n] &&
                          (pc&~UINT64_C(4095))==native_call_page_va(n);
                if(page)word=*(const volatile uint32_t *)pa;
            }
            if(p->stub_count!=(NATIVE_COMPILED_FLAGS|NATIVE_CONTRACT_PAGES) ||
               esr!=((UINT64_C(0x16)<<26)|(UINT64_C(1)<<25)|NATIVE_HVC_IMMEDIATE) ||
               !page || word!=NATIVE_HVC_WORD || v->stepping.active || v->open_guards ||
               !v->prepared || c->native_calls[v->slot].ready!=1 ||
               (physical_spsr>>32) || (physical_spsr&((1UL<<20)|(1UL<<21)))) {
                s->rejected++;
                record(c,EV_MONITOR,pc,esr,pa,word);
                fill_regs(&v->async_regs,frame,esr,pc,pa);v->async_captured=2;
                return 1;
            }
            /* HVC already saved the following PC. The shared dispatcher takes
             * the call PC and advances once; failure evidence names that call.
             * EL1's ELR/SPSR/ESR/FAR were not overwritten, so never restore the
             * private-call snapshot here. Endpoint/lock semantics are unchanged. */
            s->calls++;*elr=pc;
            return monitor_request(c,frame,elr);
        }
#endif
        if ((iss & 0xffff) == ADRENO_GUEST_HVC && (p->gpu.flags & ADRENO_F_ENABLE)) {
            if (frame[0] == ADRENO_GUEST_STOP) {
                early_stop_hvc(c, frame, *elr, physical_spsr);
                return 0;
            }
#if SNAP_GUEST_NET
            if (frame[0] == ADRENO_GUEST_NET) {
                guest_net_hvc(c, frame, *elr, physical_spsr);
                return 0;
            }
#endif
#if SNAP_EDP_BACKLIGHT
            if (frame[0] == ADRENO_GUEST_BACKLIGHT) {
                edp_backlight_hvc(c, frame, *elr, physical_spsr);
                return 0;
            }
#endif
#if SNAP_ADRENO_IB_ASYNC
            if (frame[0] == ADRENO_GUEST_IB_POLL) {
                gpu_ib_poll_hvc(c, frame, *elr);
                return 0;
            }
#endif
#if SNAP_ADRENO_COHERENT
            if (frame[0] == ADRENO_GUEST_COHERENT) {
                /* QUERY, under the token like the rest of the GPU state; the epoch is attr_updates.cleans + 1. */
                adreno_coherent_query(&c->root_ext->gpu_coherent, c->attr_updates.cleans + 1, frame);
                return 0;
            }
#endif
#if SNAP_ADRENO_RECOVER
            if (frame[0] == ADRENO_GUEST_RECOVER) {
                gpu_recover_hvc(c, frame, *elr);
                return 0;
            }
            const uint64_t recover_attempts = GPU_RECOVER(c)->attempts, recover_faults = c->gpu.faults;
#endif
            /* runtime_enter holds the service lock across native DART lookup,
             * mirror validation and the bounded CP poll. HVC ELR is advanced. */
            uint64_t r[4] = {frame[0], frame[1], frame[2], frame[3]};
            unsigned index;
            int e = ADRENO_E_PARAMS;
            if (device_dart_admit_frame(p->models, c->model_state,
                    (unsigned)p->model_count, 5, SPTM_DART_ADRENO, 0, 2, &index) == DEVICE_OK) {
                struct sptm_memory memory = sptm_context_memory(c);
                struct gpu_leaf_ctx leaf = {&memory, &c->model_state[index].dart};
                struct adreno_ops o = GPU_LEAF_OPS(c);
#if SNAP_GPU_DVFS
                /* G18: the first IB of a burst runs at the ceiling: vote it before this doorbell (once per burst;
                 * every IB holds it). A START refused because a flight is active is not a doorbell. */
                if (r[0] == ADRENO_GUEST_IB
#if SNAP_ADRENO_IB_ASYNC
                    || (r[0] == ADRENO_GUEST_IB_START && !IB_FLIGHT(c)->active)
#endif
                    )
                    dvfs_gpu_kick(c);
#endif
#if SNAP_ADRENO_RECOVER
                /* agents/gpu-recovery R25: after the monitor gave up, ring users are refused before any write. */
                e = adreno_recover_refuse(GPU_RECOVER(c), &c->gpu, r);
                if (!e)
#endif
#if SNAP_ADRENO_IB_ASYNC
                /* An IB in flight: ring users and an UNMAP of its package are refused before any write (A7, A1b). */
                e = adreno_ib_flight_refuse(&c->gpu, IB_FLIGHT(c), r);
                if (!e)
#endif
                e = r[0] == ADRENO_GUEST_UNMAP ?
                    adreno_guest_unmap(&o, &p->gpu, &c->gpu, r, gpu_leaf, gpu_unmap, &leaf,
                                       p->mem_low, p->mem_high) :
#if SNAP_ADRENO_COHERENT
                    r[0] == ADRENO_GUEST_CACHE && (r[3] & ADRENO_CACHE_COHERENT) ?
                    adreno_coherent_cache(&o, &p->gpu, &c->gpu, &c->root_ext->gpu_coherent, r, gpu_leaf, &leaf,
                                          gpu_cpu_writeback, c, p->mem_low, p->mem_high) :
#endif
                    r[0] == ADRENO_GUEST_CACHE ?
                    adreno_guest_cache(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                       p->mem_low, p->mem_high) :
                    r[0] == ADRENO_GUEST_FILL32 ?
                    adreno_guest_fill32(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                       p->mem_low, p->mem_high) :
                    r[0] == ADRENO_GUEST_IB ?
                    adreno_guest_ib(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                    p->mem_low, p->mem_high) :
#if SNAP_ADRENO_RECOVER
                    r[0] == ADRENO_GUEST_IB_START ?
                    adreno_recover_start(&o, &p->gpu, &c->gpu, IB_FLIGHT(c), GPU_RECOVER(c), r, gpu_leaf, &leaf,
                                         p->mem_low, p->mem_high) :
#elif SNAP_ADRENO_IB_ASYNC
                    r[0] == ADRENO_GUEST_IB_START ?
                    adreno_guest_ib_start(&o, &p->gpu, &c->gpu, IB_FLIGHT(c), r, gpu_leaf, &leaf,
                                          p->mem_low, p->mem_high) :
#endif
                    adreno_guest_fence(&o, &p->gpu, &c->gpu, r, gpu_leaf, &leaf,
                                       p->mem_low, p->mem_high);
            } else {
                r[0] = (uint64_t)(int64_t)e; r[1] = r[2] = 0; r[3] = c->gpu.wptr;
                c->gpu.fence_error = r[0];
            }
#if SNAP_ADRENO_RECOVER
            gpu_recover_record(c, *elr, recover_attempts, recover_faults);
#endif
            if (frame[0] == ADRENO_GUEST_UNMAP || frame[0] == ADRENO_GUEST_CACHE)
                record(c, EV_GPU_SMMU, *elr, (uint64_t)(int64_t)e, frame[1], frame[0]);
            else if (frame[0] == ADRENO_GUEST_IB)
                record(c, EV_GPU_IB, *elr, frame[1], frame[2] << 32 | (uint32_t)e, r[2]);
#if SNAP_ADRENO_IB_ASYNC
            else if (frame[0] == ADRENO_GUEST_IB_START) {
                /* One EV_GPU_IB per IB (A18): here when START ended it, else by the POLL that does. */
                if (e != ADRENO_IB_PENDING)
                    record(c, EV_GPU_IB, *elr, frame[1], frame[2] << 32 | (uint32_t)e, r[2]);
            }
#endif
            else
                record(c, EV_GPU_RING, *elr,
                       frame[0] == ADRENO_GUEST_FILL32 ? frame[3] : frame[2],
                       (uint64_t)(int64_t)e, r[2]);
#if SNAP_GPU_DVFS
            /* G9: the GPU time of each synchronous submission (an IB's doorbell to completion, a fence's or
             * FILL32's ticks); async flights count when they end (dvfs_tick, sum_ticks). */
            if (c->root_ext && (frame[0] == ADRENO_GUEST_IB || frame[0] == ADRENO_GUEST_FENCE ||
                                frame[0] == ADRENO_GUEST_FILL32
#if SNAP_ADRENO_IB_ASYNC
                                || (frame[0] == ADRENO_GUEST_IB_START && e != ADRENO_IB_PENDING)
#endif
                                ))
                gpu_dvfs_busy(&c->root_ext->gpu_dvfs, r[2]);
#endif
            for (unsigned n = 0; n < 4; n++) frame[n] = r[n];
            return 0;
        }
        if (!(iss & 0xffff) && (p->gpu.flags & ADRENO_F_ENABLE)) {
            /* HVC #0 as SMCCC: the two TrustZone GPU calls q1n1 forwards. */
            uint64_t r[8] = {frame[0], frame[1], frame[2], frame[3]};
            struct adreno_ops o = gpu_ops(c);
            int refused = adreno_smc(&o, p->gpu.flags, &c->gpu, r);
            record(c, EV_GPU_SMC, *elr, frame[0], frame[1], refused ? ~0UL : r[0]);
            if (refused) return 1;
            for (unsigned n = 0; n < 4; n++) frame[n] = r[n];
            return 0;
        }
        record(c, EV_OTHER, *elr, esr, frame[0], 0);
        return 1;
    }

    if (ec == 0x1a) { /* HCR.NV traps ERET from the nested host kernel. */
        uint64_t target, spsr, translated, pa = guest_pa(*elr);
        __asm__ volatile("mrs %0, elr_el1" : "=r"(target));
        __asm__ volatile("mrs %0, spsr_el1" : "=r"(spsr));
        uint32_t word = pa >= p->mem_low && pa <= p->mem_high - 4
            ? *(volatile uint32_t *)pa : 0;
        uint64_t vhcr = vcpu_of(c)->vncr_va ? *(volatile uint64_t *)(vcpu_of(c)->vncr_va + 0x78) : 0;
        uint64_t target_pa = guest_pa(target);
        if (target_pa >= p->mem_low && target_pa <= p->mem_high - 4 &&
            exception_kernel_return(word, vhcr, target, spsr, &translated)) {
            step_arm(c, 0);
            guards_close(c);
            __asm__ volatile("msr spsr_el2, %0" :: "r"(translated));
            record(c, EV_EXCEPTION_RETURN, *elr, target, spsr, translated);
            vcpu_of(c)->kernel_returns++;
            vcpu_of(c)->last_kernel_return = target;
            *elr = target;
            return 0;
        }
        struct sptm_root_cached *root;
        if(exception_monitor_origin(*elr,physical_spsr) &&
           exception_user_return(word,vhcr,target,spsr,&translated) &&
           (root=user_return_root(c))) {
            if(!user_enter_mode(c,1))return 1;
            step_arm(c,0);guards_close(c);
            int probe=!user->returns && user_entry_snapshot(c,root,user,target,spsr,frame[0]);
            user->returns++;
            __asm__ volatile("msr spsr_el2, %0"::"r"(translated));
            record(c,EV_USER_RETURN,*elr,target,spsr,root->root);
            *elr=target;
            if(probe) {user->pending=1;step_arm(c,1);}
            return 0;
        }
        fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, target);
        vcpu_of(c)->async_captured = 2;
        record(c, EV_RETURN_REFUSED, *elr, target, spsr, word);
        return 1;
    }
    if (ec == 0x09 && generic_pauth_supported()) {
        uint64_t pa = guest_pa(*elr), sp, spsr;
        /* Executable guest memory only; never read an instruction from MMIO
         * or from a translation that points outside the owned RAM window. */
        if (pa >= p->mem_low && pa <= p->mem_high - 4) {
            __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
            if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
            else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
            uint32_t word = *(volatile uint32_t *)pa;
            if (pauth_pacga(word, frame, sp, generic_sign, c)) {
                vcpu_of(c)->pacga_calls++;
                record(c, EV_OTHER, *elr, 0x50414347, word, 0);
                *elr += 4;
                return 0;
            }
        }
    }
    if (ec != 0x18) {
        __asm__ volatile("mrs %0, far_el2" : "=r"(vcpu_of(c)->fault_far));
        record(c, EV_OTHER, *elr, esr, vcpu_of(c)->fault_far, 0);
        return 1;
    }

    c->traps++;
    uint64_t reg = ISS_REG(iss), rt = ISS_RT(iss);
    /* The ID group, trapped by TID3: answer with the truth, minus the features
     * this hypervisor cannot stand behind. An unallocated or reserved encoding
     * (FEAT_IDST brings those here too) reads as zero: id_register never
     * executes an MRS of one, which would fault at EL2 (probes/idregs.h). */
    uint32_t op0 = (uint32_t)((iss >> 20) & 3), op1 = (uint32_t)((iss >> 14) & 7);
    uint32_t crn = (uint32_t)((iss >> 10) & 0xf), crm = (uint32_t)((iss >> 1) & 0xf);
    uint32_t op2 = (uint32_t)((iss >> 17) & 7);
    if (op0 == 3 && op1 == 0 && crn == 0 && crm < 8 && (iss & 1)) {
        if (rt != 31) frame[rt] = id_forge(crm, op2, id_register(crm, op2));
        *elr += 4;
        return 0;
    }
    uint64_t value = (rt == 31) ? 0 : frame[rt];
    int is_read = ISS_READ(iss);
    if(pauth_user_reg(&c->user_pauth[vcpu_of(c)->slot],reg,is_read,&value)) {
        /* Preserve PACGA's existing scoped native backend while replacing
         * ignored key/control MSRs with explicit guest operator state.
         * Address PAC consumers remain disabled until their key domain and
         * EL0 entry/exit switching are integrated and qualified. */
        struct pauth_user_state *state=&c->user_pauth[vcpu_of(c)->slot];
#if SNAP_NATIVE_PACGA
        uint64_t apga_lo=vcpu_of(c)->guest_apga_lo,apga_hi=vcpu_of(c)->guest_apga_hi;
#endif
        vcpu_of(c)->guest_apga_lo=state->key[PAUTH_GA].lo;
        vcpu_of(c)->guest_apga_hi=state->key[PAUTH_GA].hi;
#if SNAP_NATIVE_PACGA
        native_pacga_sync(c,vcpu_of(c),apga_lo,apga_hi);
#endif
        if(is_read && rt!=31)frame[rt]=value;
        *elr+=4;return 0;
    }
    enum ipi_result ipi_status=IPI_UNHANDLED;
    if(reg==IPI_RR_LOCAL || reg==IPI_RR_GLOBAL || reg==IPI_SR) {
        struct guest_ipi *states[GUEST_CPU_COUNT];
        uint64_t affinities[GUEST_CPU_COUNT],runnable=0;
        uint64_t life=guest_service_lifecycle(&c->services);
        for(unsigned i=0;i<GUEST_CPU_COUNT;i++) {
            states[i]=&c->vcpus[i].ipi;affinities[i]=c->vcpus[i].vmpidr;
            if(!(life&SERVICE_ADMISSION_CLOSED) && c->vcpus[i].prepared &&
               ((life>>(i*3))&7)==EXECUTOR_RUNNING) runnable|=UINT64_C(1)<<i;
        }
        ipi_status=guest_ipi_route(states,affinities,GUEST_CPU_COUNT,runnable,
                                    (unsigned)vcpu_of(c)->slot,reg,is_read,&value);
    }
    if(ipi_status!=IPI_UNHANDLED) {
        if(ipi_status!=IPI_OK) {
            record(c,EV_IPI_FAILED,*elr,ipi_status,iss,value);
            return 1;
        }
        if(!is_read) {
            if(reg==IPI_SR && value) vcpu_of(c)->ipi_ack_pc=*elr;
            else if(reg!=IPI_SR) vcpu_of(c)->ipi_request_pc=*elr;
        }
        guest_interrupt_sync(c);
        if(is_read && rt!=31) frame[rt]=value;
        *elr+=4;
        return 0;
    }
    if (reg == CLOCK_ARCH_CNTP_CTL) {
        enum clock_result status = guest_timer_idle_access(&vcpu_of(c)->idle_physical_timer,
                                                           reg, is_read, &value);
        if (status != CLOCK_OK) {
            record(c, EV_CLOCK_FAILED, *elr, status, iss, value);
            return 1;
        }
        if (is_read && rt != 31) frame[rt] = value;
        *elr += 4;
        return 0;
    }
    if (op0 == 3 && op1 == 3 && crn == 14 &&
        reg != CLOCK_ARCH_CNTVCT && reg != CLOCK_ARCH_CNTVCTSS) {
        record(c, EV_CLOCK_FAILED, *elr, CLOCK_TIMER_UNSUPPORTED, iss, value);
        return 1;
    }
    if (reg == CLOCK_ARCH_CNTVCT || reg == CLOCK_ARCH_CNTVCTSS)
        vcpu_of(c)->arch_counter_reads += is_read;

    if (reg == CLOCK_CNTV_CTL || reg == CLOCK_CNTV_TVAL) {
        uint64_t now = clock_counter(c);
        enum clock_result status = guest_timer_access(&vcpu_of(c)->timer, reg, is_read, &value, now);
        if (status != CLOCK_OK) {
            record(c, EV_CLOCK_FAILED, *elr, status, iss, value);
            return 1;
        }
        timer_sync(c);
        if (device_reset_stop(c, *elr, frame)) return 1;
        if (is_read && rt != 31) frame[rt] = value;
        *elr += 4;
        return 0;
    }

    struct clock_backend clock_host = {c, clock_counter, clock_control};
    enum clock_result clock_status = guest_clock_access(&vcpu_of(c)->clock, &clock_host,
                                                        reg, is_read, &value);
    if (clock_status != CLOCK_UNHANDLED) {
        if (clock_status != CLOCK_OK) {
            record(c, EV_CLOCK_FAILED, *elr, clock_status, iss, value);
            return 1;
        }
        if (is_read && rt != 31) frame[rt] = value;
        *elr += 4;
        return 0;
    }

    struct sprr_state *sprr=&c->user_roots.sprr[vcpu_of(c)->slot];
    enum sprr_result sprr_status;
    if(reg==SPRR_UPERM && !is_read && value!=sprr->uperm) {
        uint64_t saved;__asm__ volatile("mrs %0, spsr_el2":"=r"(saved));
        sprr_status=user_write_uperm(c,frame,*elr,saved,0xd51ef1a0U|rt);
    } else sprr_status=sprr_access_with(sprr,reg,is_read,&value,kernel_change_pperm,c);
    if(sprr_status!=SPRR_UNHANDLED) {
        if(sprr_status!=SPRR_OK) {
            record(c,EV_SPRR_FAILED,*elr,sprr_status,iss,value);
            /* A system-register trap need not pass through XNU's exception
             * vectors. Preserve this CPU's actual frame for the stop reader;
             * last_exc may be empty or belong to an earlier guest exception. */
            fill_regs(&vcpu_of(c)->async_regs,frame,esr,*elr,0);
            vcpu_of(c)->async_captured=2;
            return 1;
        }
        if(is_read && rt!=31)frame[rt]=value;
        *elr+=4;return 0;
    }
    switch (reg) {
    case SR_CONST_LOWER:
    case SR_CONST_UPPER:
        /* ...ba87c08/c14 read these; c18 adds 0xfff to the upper
         * page base. Guest writes cannot change the firmware-owned range. */
        if(!is_read)return 1;
        value=reg==SR_CONST_LOWER ? p->const_begin : p->const_end-4096;
        c->const_reads[reg==SR_CONST_UPPER]++;
        break;
    case SR_ESR_EL1:
        /* TVM/TRVM also trap these architectural exception registers. A
         * zero fallback hides the data abort's IL/EC/FSC from XNU and makes
         * it panic about a two-byte instruction instead of paging it in. */
        if (is_read) __asm__ volatile("mrs %0, esr_el1" : "=r"(value));
        else __asm__ volatile("msr esr_el1, %0" :: "r"(value));
        break;
    case SR_FAR_EL1:
        if (is_read) __asm__ volatile("mrs %0, far_el1" : "=r"(value));
        else __asm__ volatile("msr far_el1, %0" :: "r"(value));
        break;
    case SR_TTBR0_EL1:
        if (is_read) value = vcpu_of(c)->guest_ttbr0; else vcpu_of(c)->guest_ttbr0 = value;
        break;
    case SR_TTBR1_EL1:
        if (is_read) value = vcpu_of(c)->guest_ttbr1; else vcpu_of(c)->guest_ttbr1 = value;
        break;
    case SR_TCR_EL1:
        if (is_read) value = vcpu_of(c)->guest_tcr; else vcpu_of(c)->guest_tcr = value;
        break;
    case SR_MAIR_EL1:
        if (is_read) value = vcpu_of(c)->guest_mair; else vcpu_of(c)->guest_mair = value;
        break;
    case SR_SCTLR_EL1:
        if (is_read) value = vcpu_of(c)->guest_sctlr; else vcpu_of(c)->guest_sctlr = value;
        break;
    case SR_AMXIDR_EL1:
        if (is_read) value = AMXIDR_VERSION_1;
        break;
    case SR_GXF_STATUS_EL1:
        /* There is no guarded world here, so execution is never inside one.
         * Zero is the truthful answer rather than a placeholder. */
        if (is_read) value = 0;
        break;
    default:
        /* Remaining Apple IMPDEF registers are still provisional zero/ignored
         * models. A constant read is not evidence of hardware compatibility:
         * the counter aliases above demonstrated why each reached register
         * needs its own semantics. Keep this remaining surface in the log. */
        record(c, EV_SYSREG, *elr, iss, value, is_read);
        if (is_read) value = 0;
        break;
    }

    if (is_read && rt != 31) frame[rt] = value;
    *elr += 4;
    return 0;
}

