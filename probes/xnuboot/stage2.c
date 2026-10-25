/* SPDX-License-Identifier: MIT */
/* Stage 2: guards, writer debug hooks, per-vCPU stage-2 tables, guest PA and step
 * translation, shadow TCR, the table arena and user-root build/install.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
/* --- stage 2 ---------------------------------------------------------------
 *
 * Stage 2 is what makes a first boot legible. It translates what stage 1
 * produced, the guest cannot see or change it, and a miss raises a fault at EL2
 * carrying the address. So it is built to cover exactly what we own -- the map
 * itself is shadow/stage2.c, walked page by page in tools/test-stage2.c -- and
 * anything XNU reaches for that we did not prepare lands here with its address,
 * which is the question to answer next rather than a hang.
 *
 * Until docs/PLAN-HISTORY-20260922.md's T4 this was sixty-four 1 GiB identity blocks over the whole
 * 36-bit space: every device access passed through to whatever the SoC keeps
 * at that physical address, unreported, and the kernel's console -- once it
 * released the monitor's serial -- went somewhere that was not us. That state
 * does not come back. The attribute bits are in stage2.h.
 */
#define S2_TXSZ    28u             /* 36-bit IPA: one 64-entry level-1 table */

static int guard_add(struct context *c, struct vcpu *v, uint64_t root,
                     uint64_t pa, uint64_t mode)
{
    if (v->guard_count >= 12) return -1;
    /* The page has to be in the map already: a guard changes what a mapped
     * page does, and an absent page is not guarded into existence. */
    struct shadow s2 = {.txsz = S2_TXSZ, .root = root, .alloc = table_alloc,
                        .read = mem_read, .write = mem_write, .ctx = c};
    uint64_t l3 = stage2_split(&s2, pa);
    if (!l3) return -1;
    struct guard *g = &v->guards[v->guard_count++];
    g->pa = pa & ~0xfffUL;
    g->slot = l3 + 8UL * ((pa >> 12) & 0x1ff);
    g->descriptor = *(volatile uint64_t *)g->slot;
    g->mode = mode;
    return 0;
}

static uint64_t writer_debug_read(void *ctx,unsigned index,int control)
{
    (void)ctx;uint64_t value=~0UL;
#define READ_WRITER_DEBUG(n) case n: \
    if(control) {__asm__ volatile("mrs %0, dbgbcr" #n "_el1":"=r"(value));} \
    else {__asm__ volatile("mrs %0, dbgbvr" #n "_el1":"=r"(value));} break
    switch(index) {
        READ_WRITER_DEBUG(0);READ_WRITER_DEBUG(1);READ_WRITER_DEBUG(2);
        READ_WRITER_DEBUG(3);READ_WRITER_DEBUG(4);READ_WRITER_DEBUG(5);
    }
#undef READ_WRITER_DEBUG
    return value;
}
static void writer_debug_write(void *ctx,unsigned index,int control,uint64_t value)
{
    (void)ctx;
#define WRITE_WRITER_DEBUG(n) case n: \
    if(control) {__asm__ volatile("msr dbgbcr" #n "_el1, %0"::"r"(value):"memory");} \
    else {__asm__ volatile("msr dbgbvr" #n "_el1, %0"::"r"(value):"memory");} break
    switch(index) {
        WRITE_WRITER_DEBUG(0);WRITE_WRITER_DEBUG(1);WRITE_WRITER_DEBUG(2);
        WRITE_WRITER_DEBUG(3);WRITE_WRITER_DEBUG(4);WRITE_WRITER_DEBUG(5);
    }
#undef WRITE_WRITER_DEBUG
}
static void writer_debug_barrier(void *ctx)
{(void)ctx;__asm__ volatile("isb":::"memory");}
static const struct native_writer_debug_ops writer_debug_ops={
    .read=writer_debug_read,.write=writer_debug_write,.barrier=writer_debug_barrier};

static void native_exception_snapshot(struct context *c)
{
    struct native_call_state *s=&c->native_calls[vcpu_of(c)->slot];
    uint64_t elr,spsr,esr,far;
    __asm__ volatile("mrs %0, elr_el1; mrs %1, spsr_el1; "
                     "mrs %2, esr_el1; mrs %3, far_el1"
                     : "=r"(elr), "=r"(spsr), "=r"(esr), "=r"(far)
                     :: "memory");
    /* Avoid dirtying adjacent CPU state when the legitimate values did not
     * change. In particular, ready is published only once per CPU. */
    if(s->elr!=elr)s->elr=elr;
    if(s->spsr!=spsr)s->spsr=spsr;
    if(s->esr!=esr)s->esr=esr;
    if(s->far!=far)s->far=far;
    if(!s->ready)s->ready=1;
}

static void native_exception_restore(struct native_call_state *s)
{
    __asm__ volatile("msr elr_el1, %0; msr spsr_el1, %1; "
                     "msr esr_el1, %2; msr far_el1, %3; isb"
                     :: "r"(s->elr), "r"(s->spsr), "r"(s->esr), "r"(s->far)
                     : "memory");
    s->restores++;
}

static void guard_write(struct context *c, struct guard *g, int open)
{
    uint64_t value = g->descriptor;
    if (!open) value = (g->mode == GUARD_EXEC) ? (value | S2_XN) : (value & ~PT_VALID);
#if SNAP_USER_TREE_MEMO
    /* The one post-boot arena store outside mem_write: a stage-2 guard
     * descriptor. Stage-2 pages are never user sources or copies; noting
     * them keeps the witness complete without relying on that. */
    if (g->slot >= c->work_base && g->slot < c->next_table)
        sprr_table_memo_note(&c->table_memo, g->slot);
#else
    (void)c;
#endif
    *(volatile uint64_t *)g->slot = value;
    __asm__ volatile("dc civac, %0" :: "r"(g->slot) : "memory");
}

static struct guard *guard_find(struct context *c, uint64_t pa)
{
    for (uint64_t n = 0; n < vcpu_of(c)->guard_count; n++)
        if (vcpu_of(c)->guards[n].pa == (pa & ~0xfffUL)) return &vcpu_of(c)->guards[n];
    return 0;
}

static void guard_open(struct context *c, struct guard *g)
{
    guard_write(c, g, 1);
    vcpu_of(c)->open_guards++;
    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");
}

/* Shut every guard when leaving a stepped page or consuming a DATA access.
 * The normal same-page EXEC step can retain its one open descriptor. */
static void guards_close(struct context *c)
{
    if (!vcpu_of(c)->open_guards) return;
    for (uint64_t n = 0; n < vcpu_of(c)->guard_count; n++) guard_write(c, &vcpu_of(c)->guards[n], 0);
    vcpu_of(c)->open_guards = 0;
    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");
}

/* Build private stage-2 tables and guards before running any guest CPU.
 * Shared allocator synchronization remains required for concurrent execution. */
static int vcpu_stage2_prepare(struct context *c, struct vcpu *v)
{
    const struct params *p = c->params;
    uint64_t stub_count = p->stub_count & ~NATIVE_CALL_FLAGS;
    if (!!(p->stub_count & NATIVE_CALL_FLAG) != !!SNAP_NATIVE_CALLS ||
        !!(p->stub_count & NATIVE_HVC_FLAG) != !!SNAP_SPTM_HVC_CALLS ||
        stub_count > 8) return -30;
    if (SNAP_NATIVE_CALLS) {
        unsigned calls=0,writers=0;
        if (stub_count != NATIVE_CONTRACT_PAGES || !p->vncr_va ||
            !p->vbar || !p->vbar_va || p->const_begin<p->mem_low ||
            p->const_begin>=p->const_end || p->const_end>p->alloc_low ||
            ((p->const_begin|p->const_end)&0x3fff)) return -31;
        for (unsigned n=0;n<stub_count;n++) {
            uint64_t pa=p->stub_pa[n];
            unsigned nc=0,nw=0;
            if ((pa&4095) || pa<p->const_begin || pa>p->const_end-4096) return -32;
            for (unsigned j=0;j<n;j++) if(pa==p->stub_pa[j]) return -32;
            const uint32_t *words=(const uint32_t *)pa;
            for (unsigned i=0;i<1024;i++) {
                nc+=SNAP_SPTM_HVC_CALLS ? words[i]==NATIVE_HVC_WORD : native_call_word(words[i]);
                if(SNAP_SPTM_HVC_CALLS ? native_call_word(words[i]) : words[i]==NATIVE_HVC_WORD)
                    return -35;
                nw+=native_exception_writer(words[i]);
            }
            if (n<NATIVE_CALL_PAGES ? (!nc || nw) : (!nw || nc)) return -33;
            calls+=nc;writers+=nw;
        }
        if (calls!=348 || writers!=10) return -34;
    }
    uint64_t root = table_alloc(c);
    if (!root) return -3;
    struct shadow s2 = {.txsz = S2_TXSZ, .root = root, .alloc = table_alloc,
                        .read = mem_read, .write = mem_write, .ctx = c};
#if SNAP_I2C_INPUT && SNAP_QCC2072_WIFI
    struct stage2_range ranges[8 + I2C_INPUT_STAGE2_MAX + QCC2072_WIFI_STAGE2_MAX + SNAP_DISPLAY_TIMING_ROWS];
#elif SNAP_I2C_INPUT
    struct stage2_range ranges[8 + I2C_INPUT_STAGE2_MAX + SNAP_DISPLAY_TIMING_ROWS];
#elif SNAP_QCC2072_WIFI
    struct stage2_range ranges[8 + QCC2072_WIFI_STAGE2_MAX + SNAP_DISPLAY_TIMING_ROWS];
#else
    struct stage2_range ranges[8 + SNAP_DISPLAY_TIMING_ROWS];
#endif
    unsigned count = 0;
    uint64_t panic_page=p->scratch_pa-SPTM_PANIC_PAGE_SIZE;
    ranges[count++] = (struct stage2_range){
        .lo = p->mem_low, .hi = panic_page, .low = S2_AP_RW | S2_ATTRS, .upper = 0};
    ranges[count++] = (struct stage2_range){
        .lo = panic_page, .hi = p->scratch_pa, .low = S2_AP_RO | S2_ATTRS, .upper = S2_XN};
    ranges[count++] = (struct stage2_range){
        .lo = p->scratch_pa, .hi = p->mem_high, .low = S2_AP_RW | S2_ATTRS, .upper = 0};
    if (p->fb_span)
        ranges[count++] = (struct stage2_range){
            .lo = p->fb_pa, .hi = p->fb_pa + p->fb_span,
            .low = S2_AP_RW | S2_ATTRS, .upper = S2_XN};
    ranges[count++] = (struct stage2_range){
        .lo = c->work_base, .hi = c->work_end,
        .low = S2_AP_RO | S2_ATTRS, .upper = S2_XN};
    /* Stage 4: the Adreno register windows the guest drives itself, as device
     * memory; every other block of the GPU aperture stays absent (adreno.h). */
    if (p->gpu.flags & ADRENO_F_ENABLE) {
        ranges[count++] = (struct stage2_range){ADRENO_PA, ADRENO_PASS0_END,
            S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
        ranges[count++] = (struct stage2_range){ADRENO_PASS1_PA, ADRENO_PASS1_END,
            S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
        if (p->gpu.flags & ADRENO_F_CX_MISC)
            ranges[count++] = (struct stage2_range){ADRENO_CX_MISC_PA, ADRENO_CX_MISC_END,
                S2_AP_RO | S2_ATTRS_DEVICE, S2_XN};
    }
#if SNAP_I2C_INPUT
    /* The keyboard's GENI page only, after an exact allow-list check of the
     * loader's words: anything else refuses the boot before a guest runs. */
    {
        int rows = i2c_input_rows(&p->i2c_input, ranges + count);
        if (rows < 0) return -41;
        count += (unsigned)rows;
    }
#endif
#if SNAP_QCC2072_WIFI
    /* The QCC2072's five windows, after an exact allow-list check of the
     * loader's words and of the provider record it placed on the control page
     * (read here through EL2's identity map). Anything else refuses the boot. */
    {
        const struct qcc2072_wifi_params *q = qcc2072_wifi_block(p);
        int rows = qcc2072_wifi_valid(q) ?
            qcc2072_wifi_rows(q, (const volatile uint64_t *)(uintptr_t)q->control_pa, ranges + count) : -1;
        if (rows < 0) return -42;
        count += (unsigned)rows;
    }
#endif
#if SNAP_DISPLAY_TIMING
    /* The eDP interface's timing page, read-only Device-nGnRE, after an exact allow-list check of the loader's words
     * (compat/display-timing.h): anything else, a missing block included, refuses the boot before a guest runs. */
    {
        int rows = display_timing_rows(display_timing_block(p), ranges + count);
        if (rows < 0) return -43;
        count += (unsigned)rows;
    }
#endif
    int built = stage2_build(&s2, ranges, count);
    if (built == STAGE2_BAD_RANGES) return -10;
    if (built) return -11;
    if(p->const_begin<p->mem_low || p->const_begin>=p->const_end ||
       p->const_end>p->alloc_low || ((p->const_begin|p->const_end)&0x3fff) ||
       !stage2_split(&s2,p->const_begin) || !stage2_split(&s2,p->const_end-4096))return -20;
    if(p->trust_cache.pa) {
        uint64_t begin=p->trust_cache.pa;
        uint64_t end=begin+0x4000+((p->trust_cache.size+0x3fff)&~0x3fffUL);
        if(!stage2_split(&s2,begin) || !stage2_split(&s2,end-4096) ||
           stage2_readonly(&s2,begin,end,0))return -21;
    }
    if (p->write_watch_pa) {
        if ((p->write_watch_pa & 0xfff) || p->write_watch_pa < p->mem_low ||
            p->write_watch_pa >= p->mem_high) return -12;
        uint64_t l3 = stage2_split(&s2, p->write_watch_pa);
        if (!l3) return -12;
        uint64_t *slot = (uint64_t *)(l3 + 8 * ((p->write_watch_pa >> 12) & 511));
        *slot &= ~(1UL << 7);  /* S2AP RW -> RO; execute guards retain this */
    }

    for (uint64_t n = SNAP_NATIVE_WRITER_BREAKPOINTS ? stub_count :
             SNAP_NATIVE_CALLS ? NATIVE_CALL_PAGES : 0; n < stub_count; n++)
        if (guard_add(c, v, root, p->stub_pa[n], GUARD_EXEC)) return -4;
    if (p->vbar && guard_add(c, v, root, p->vbar, GUARD_EXEC)) return -5;
    /* The handoff, observed rather than guessed. Every field XNU reads faults
     * here with its own offset, which is the struct layout measured instead of
     * inferred from a header that may have moved. */
    for (uint64_t n = 0; n < p->watch_count; n++)
        if (guard_add(c, v, root, p->watch_pa + n * 0x1000, GUARD_DATA)) return -7;
    for (uint64_t n = 0; n < v->guard_count; n++) guard_write(c, &v->guards[n], 0);
    /* Publish all descendants before installing this previously unused root. */
    publish(root, c->next_table);
    v->stage2_root = root;
    return 0;
}

static uint64_t vcpu_vttbr(const struct vcpu *v)
{
    /* VTCR.VS is zero: eight-bit VMIDs. Distinct roots also need distinct
     * translation-cache identities to keep temporary guards CPU-local. */
    return v->stage2_root | ((v->slot + 1UL) << 48);
}

static int const_region_seal(struct context *c)
{
    const struct params *p=c->params;
    /* Validate every CPU before the first permission change. Boundaries were
     * split before entry: no live block-to-table transition or allocation. */
    for(unsigned pass=0;pass<2;pass++)for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        struct vcpu *v=&c->vcpus[cpu];
        struct shadow s={.txsz=S2_TXSZ,.root=v->stage2_root,
            .read=mem_read,.write=mem_write,.ctx=c};
        if(stage2_readonly(&s,p->const_begin,p->const_end,!pass))return -1;
        if(pass)for(unsigned g=0;g<v->guard_count;g++)
            if(v->guards[g].pa>=p->const_begin && v->guards[g].pa<p->const_end)
                v->guards[g].descriptor&=~(1UL<<7);
    }
    publish(c->work_base,c->next_table);
    /* Publish the permission changes, then invalidate stage 1+2 for each distinct
     * VMID, including prepared CPUs that have not entered yet. */
    uint64_t saved;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ish" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        uint64_t vttbr=vcpu_vttbr(&c->vcpus[cpu]);
        __asm__ volatile("msr vttbr_el2, %0; isb; tlbi vmalls12e1is; dsb ish; isb"
                         :: "r"(vttbr) : "memory");
        c->const_tlb_invalidations++;
    }
    __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    c->const_sealed_cpus=(1UL<<GUEST_CPU_COUNT)-1;
    return 0;
}

/* A guest virtual address, resolved to a physical one.
 *
 * EL2 has its own flat view of memory and cannot dereference a kernel VA. With
 * stage 2 enabled AT S1E1R performs stage 1 alone and reports the intermediate
 * address, which this stage-2 map translates to itself, so the result is usable
 * directly. Zero means the walk faulted. */
static uint64_t guest_pa(uint64_t va)
{
    uint64_t par, saved_par;
    /* PAR_EL1 belongs to the guest too. A debug step can arrive between its
     * AT and MRS PAR_EL1: fetching the stepped instruction must not replace
     * its data translation with the physical address of the code page. */
    __asm__ volatile("mrs %0, par_el1; at s1e1r, %2; isb; "
                     "mrs %1, par_el1; msr par_el1, %0; isb"
                     : "=&r"(saved_par), "=&r"(par) : "r"(va) : "memory");
    if (par & 1) return 0;
    return (par & 0x0000fffffffff000UL) | (va & 0xfff);
}

static inline int guest_insn_pa_ok(const struct context *c, uint64_t pa)
{
    return pa && !(pa & 3UL) && c->params &&
           pa >= c->params->mem_low && pa <= c->params->mem_high - 4UL &&
           (!c->work_start || pa + 4UL <= c->work_start || pa >= c->work_end);
}

static uint64_t step_instruction_pa(struct context *c, uint64_t va, uint64_t spsr)
{
    struct vcpu *v = vcpu_of(c);
    struct step_translation *t = &c->step_translation[v->slot];
    int eligible = SNAP_STEP_TRANSLATION && exception_monitor_origin(va, spsr) &&
                   v->stepping.active && v->open_guards == 1;
    if (eligible && step_translation_match(t, va, c->shadow_tlb_syncs) &&
        t->guard < v->guard_count) {
        struct guard *g = &v->guards[t->guard];
        if (g->mode == GUARD_EXEC && g->pa == t->pa_page &&
            *(volatile uint64_t *)g->slot == g->descriptor) {
            uint64_t pa = t->pa_page | (va & 0xfff);
            t->hits++;
            /* Diagnostic builds sample the actual architectural translation.
             * A mismatch stops the run rather than using a stale address. */
            if (SNAP_STEP_TRANSLATION_VERIFY && !(t->hits & 1023)) {
                uint64_t actual = guest_pa(va);
                t->verified++;
                if (actual != pa) {
                    t->mismatches++;
                    step_translation_clear(t);
                    c->kernel_view_failed = 1;
                    return 0;
                }
            }
            return guest_insn_pa_ok(c, pa) ? pa : 0;
        }
    }
    t->misses++;
    step_translation_clear(t);
    uint64_t pa = guest_pa(va);
    if (!guest_insn_pa_ok(c, pa)) return 0;
    if (eligible && pa) {
        struct guard *g = guard_find(c, pa);
        if (g && g->mode == GUARD_EXEC &&
            *(volatile uint64_t *)g->slot == g->descriptor) {
            t->va_page = va & ~UINT64_C(0xfff);
            t->pa_page = pa & ~UINT64_C(0xfff);
            t->generation = c->shadow_tlb_syncs;
            t->guard = (uint64_t)(g - v->guards);
            t->valid = 1;
        }
    }
    return pa;
}

/* Software step, driven from EL2: MDCR_EL2.TDE routes the guest's debug
 * exceptions here, MDSCR_EL1.SS plus SPSR_EL2.SS means "one instruction, then
 * except". PSTATE.D masks debug exceptions and the guest runs with it set, so
 * it is cleared for the duration and put back. This machine's firmware also
 * leaves the OS Lock held, which disables self-hosted debug outright; without
 * clearing it the step silently never fires. */
static void guest_interrupt_sync(struct context *c)
{
    uint64_t hcr;
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
    int fiq = exception_step_fiq(&vcpu_of(c)->stepping, guest_ipi_fiq(&vcpu_of(c)->ipi,vcpu_of(c)->timer_pending));
    int irq = exception_step_fiq(&vcpu_of(c)->stepping, vcpu_of(c)->model_irq_pending);
    if (fiq != !!(hcr & (1UL << 6))) {
        if (fiq) vcpu_of(c)->timer_asserts++; else vcpu_of(c)->timer_clears++;
    }
    if (irq != !!(hcr & (1UL << 7))) {
        if (irq) vcpu_of(c)->model_irq_asserts++; else vcpu_of(c)->model_irq_clears++;
    }
    uint64_t next = (hcr & ~((1UL << 6) | (1UL << 7))) |
                    (fiq ? 1UL << 6 : 0) | (irq ? 1UL << 7 : 0);
    if (next != hcr) __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(next));
}

static void step_arm(struct context *c, int on)
{
    uint64_t mdscr, spsr;
    __asm__ volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
    exception_step_set(&vcpu_of(c)->stepping, on, &spsr, &mdscr);
    __asm__ volatile("msr mdscr_el1, %0" :: "r"(mdscr));
    __asm__ volatile("msr spsr_el2, %0" :: "r"(spsr));
    __asm__ volatile("isb");
    /* Do not expose our temporary D=0/SS=1 in XNU's saved IRQ/FIQ state. Hold the
     * level pending during monitor stepping, then assert it after restoring
     * the guest mask. Physical timer IRQs and the watchdog remain enabled. */
    guest_interrupt_sync(c);
}

static void guard_step(struct context *c, uint64_t pa)
{
    struct guard *here = pa ? guard_find(c, pa) : 0;
    struct vcpu *v = vcpu_of(c);
    /* Every guard_open increments open_guards, and guards_close resets it.
     * Exactly one open plus this unchanged open descriptor rules out an
     * outstanding DATA access or a different open EXEC page. Keep observing
     * each instruction without rewriting identical descriptors and issuing
     * two broadcast TLB invalidations. Rearm SS while preserving saved D and
     * the pending guest interrupt mask. Synchronous vectors are handled before
     * this path; all other cases retain the close/reopen sequence. */
    if (here && here->mode == GUARD_EXEC && v->stepping.active &&
        v->open_guards == 1 &&
        *(volatile uint64_t *)here->slot == here->descriptor) {
        step_arm(c, 1);
        return;
    }
    step_arm(c, 0);
    guards_close(c);
    if (here && here->mode == GUARD_EXEC) {
        guard_open(c, here);
        step_arm(c, 1);
    }
}

static uint64_t shadow_tcr(uint64_t guest_tcr)
{
    /* TG1 is not TG0: the field at [31:30] encodes 0b10 as 4K, while TG0 at
     * [15:14] encodes 0b00 as 4K. Both halves are forced to 4K here.
     *
     * TTBR0 used to be disabled, on the grounds that the kernelcache lives
     * entirely in the upper half. That is true of the image and does not cover
     * what the kernel does: it walks and then *accesses* addresses numerically
     * equal to physical ones, down at level-1 entry 0. Its software walker
     * masks a virtual address into the regime's offset space and never asks
     * which table base would apply, so those walks resolved through the upper
     * tables while the first real load through one went to a regime that was
     * switched off -- a level-0 translation fault on 0xf6010000 with everything
     * correctly mapped. See docs/APERTURE-FAULT.md. */
    uint64_t tcr = (guest_tcr & ~(3UL << 30)) | (2UL << 30);
    tcr &= ~(1UL << 23);                       /* EPD1 clear: walk TTBR1 */
    tcr &= ~(1UL << 7);                        /* EPD0 clear: walk TTBR0 too */
    tcr = (tcr & ~(3UL << 14));                /* TG0 = 0b00, 4K */
    /* T0SZ matches T1SZ so both halves are the same shape and one shadow
     * builder serves both. */
    tcr = (tcr & ~0x3fUL) | ((guest_tcr >> 16) & 0x3f);

    /* IPS is ours, not the guest's. XNU ships TCR_EL1.IPS = 0, which caps every
     * output address of this regime -- including the shadow's own table
     * addresses -- at 32 bits. That held only because the image and the probe's
     * work area both happened to sit under 4 GiB on the A16. They do not have
     * to: the work area comes from q1n1's heap, and firmware that allocates from
     * the top of a 4 GiB map puts it above the line, at which point the very
     * first table fetch is an address size fault and the entry point looks
     * unmappable. The guest never sees this value -- TRVM hands XNU back its own
     * TCR -- so it is set from what the hardware can actually address. */
    uint64_t parange;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(parange));
    parange &= 0xf;
    if (parange > 5) parange = 5;              /* 48 bits; no LPA here */
    tcr = (tcr & ~(7UL << 32)) | (parange << 32);
    return tcr;
}

/* Give back every table page cache slot `slot` owns: canonical shadow and
 * private CPU copies alike (both carry owner slot+1). No CPU can install the
 * slot while the service lock is held and its entry is invalid. Retire all
 * VMID translations before recycling its canonical and private pages; other
 * roots and permanent monitor pages retain ownership. With require_flush a
 * TLBI that did not happen (kernel refresh failure) keeps every page owned.
 * Returns the number of pages released, or -1. */
static int root_slot_release(struct context *c,unsigned slot,int require_flush)
{
    uint64_t syncs=c->shadow_tlb_syncs;
    shadow_tlb_sync(c);
    if(require_flush && c->shadow_tlb_syncs==syncs)return -1;
#if SNAP_NATIVE_SHARED
    /* The slot's tables and the links in them go; the groups stay. */
    if(!native_shared_forget_slot(&UNS(c),slot))return -1;
#endif
#if SNAP_USER_VIEW_CACHE
    sprr_view_epoch_advance(&c->user_view_epoch);
    UPROOFS(c)[slot].valid=0;
#endif
#if SNAP_PRIVATE_VIEW_EPOCH
    for(unsigned i=0;i<(c->next_table-c->work_base)/4096;i++)
        if(c->table_pool.owner[i]==slot+1 && !sprr_private_clear(&c->private_pages,i,1))return -1;
#endif
    int released=table_pool_release(&c->table_pool,
        (uint32_t)((c->next_table-c->work_base)/4096),slot+1);
    if(released<0)return -1;
#if SNAP_NATIVE_TABLES
    native_mark(c,&UVIEWS(c)[slot],0);
#endif
    volatile uint64_t *view=(volatile uint64_t *)&UVIEWS(c)[slot];
    for(unsigned i=0;i<sizeof(UVIEWS(c)[slot])/8;i++)view[i]=0;
    /* The view's claims describe metadata that no longer exists. */
    volatile uint64_t *memo=(volatile uint64_t *)&UMEMOS(c)[slot];
    for(unsigned i=0;i<sizeof(UMEMOS(c)[slot])/8;i++)memo[i]=0;
    return released;
}
static uint64_t arena_available(const struct context *c)
{
    return (c->work_end-c->next_table)/4096+c->table_pool.count;
}
/* Table-arena pressure: give back inactive cached roots, cheapest first
 * (sptm_root_reclaim_pick), until `target` pages are free or none qualifies.
 * Only between transactions -- at a monitor-call entry or inside a root build,
 * whose own slot is in `exclude` -- never from an allocation callback, since
 * prepare/commit alias masks and reservations name cached slots. A given-back
 * root is simply uncached: user updates to it go to its guest tables and its
 * next SWITCH_ROOT rebuilds the shadow, exactly as after a full-cache eviction. */
static void arena_reclaim(struct context *c,uint64_t target,sptm_root_mask_t exclude)
{
    struct arena_reclaim_stats *a=&c->arena_reclaim;
    for(unsigned n=0;n<SPTM_ROOT_CACHE && arena_available(c)<target;n++) {
        unsigned slot=sptm_root_reclaim_pick(&c->user_roots,USTAMPS(c),exclude);
        if(slot>=SPTM_ROOT_CACHE)return;
        SPTM_ROOT_MASK_SET(exclude,slot);
        struct sptm_root_cached *e=&c->user_roots.cache[slot];
        if(e->root && vcpu_root_busy(c,e->root))continue;
        unsigned kind=!e->root ? 0 : e->valid ? 2 : 1;
        if(!sptm_root_reclaim_forget(&c->user_roots,slot))return;
        int released=root_slot_release(c,slot,1);
        if(released<0) {a->flush_failures++;return;}
        a->slots++;a->pages+=(unsigned)released;
        if(kind==0)a->retired++;else if(kind==1)a->invalid++;else a->valid++;
    }
}
/* Monitor-call entry: record the arena low-water mark and restore the
 * reserve before the call can allocate. SWITCH_ROOT's own target is never
 * given back just to be rebuilt by the same call. */
static void arena_reserve(struct context *c,const uint64_t *frame)
{
    struct arena_reclaim_stats *a=&c->arena_reclaim;
    const uint64_t reserve=SNAP_ARENA_RESERVE_PAGES;
    uint64_t available=arena_available(c);
    if(!a->checks || available<a->low_water)a->low_water=available;
    a->checks++;
    if(!reserve || available>=reserve || c->kernel_view_failed)return;
    sptm_root_mask_t exclude=SPTM_ROOT_MASK_NONE;
    if(frame[16]==SPTM_FN_SWITCH_ROOT && frame[0])
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
            if(c->user_roots.cache[i].root==frame[0])SPTM_ROOT_MASK_SET(exclude,i);
    a->reclaims++;
    arena_reclaim(c,reserve+reserve/2,exclude);
}
#if SNAP_NATIVE_LIVE
/* USER_ROOT constructor (the new root page is empty): cache the root with an
 * empty tree in a never-used slot, else the cheapest inactive one
 * (sptm_root_reclaim_pick; never an active root). Best effort: without a slot
 * or a page the root stays uncached and its first switch builds as before. */
static void native_root_created(void *ctx,uint64_t pa,uint16_t asid,unsigned format,unsigned flags)
{
    struct context *c=ctx;struct sptm_root_state *s=&c->user_roots;
    unsigned slot=SPTM_ROOT_CACHE;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        if(s->cache[i].root==pa) {c->native_stats.uncreated++;return;}
        if(slot==SPTM_ROOT_CACHE && !s->cache[i].root && !s->cache[i].shadow)slot=i;
    }
    if(format) {c->native_stats.uncreated++;return;}
    if(slot==SPTM_ROOT_CACHE) {
        slot=sptm_root_reclaim_pick(s,USTAMPS(c),SPTM_ROOT_MASK_NONE);
        if(slot>=SPTM_ROOT_CACHE || (s->cache[slot].root && vcpu_root_busy(c,s->cache[slot].root)) ||
           !sptm_root_reclaim_forget(s,slot) || root_slot_release(c,slot,1)<0) {
            c->native_stats.uncreated++;return;
        }
        c->root_evictions++;
    }
    uint64_t shadow=user_table_alloc(&UOWNERS(c)[slot]);
    if(!shadow) {c->native_stats.uncreated++;return;}
    s->cache[slot]=(struct sptm_root_cached){.root=pa,.shadow=shadow,.asid=asid,.format=0,
                                             .flags=flags,.valid=1};
    USTAMPS(c)[slot]=++c->arena_reclaim.clock;
    c->native_stats.created++;
}
#endif
static int user_root_build(void *ctx,const struct sptm_memory *memory,
    uint64_t root,unsigned format,unsigned flags,uint64_t previous,
    uint64_t *result,uint64_t *leaves)
{
    struct context *c=ctx;
    unsigned slot=SPTM_ROOT_CACHE;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];
        if((previous && e->shadow==previous) ||
           (!previous && !e->shadow && (!e->root || e->root==root))) {slot=i;break;}
    }
    if(slot==SPTM_ROOT_CACHE)return 0;
    struct sptm_root_cached *e=&c->user_roots.cache[slot];
    if(e->valid || (e->root && vcpu_root_busy(c,e->root)))return 0;
    for(unsigned attempt=0;;attempt++) {
        uint64_t failures=c->arena_reclaim.alloc_failures;
        if(root_slot_release(c,slot,0)<0)return 0;
        struct user_table_owner *owner=&UOWNERS(c)[slot];
        struct shadow s={.txsz=17,.root=user_table_alloc(owner),
            .alloc=user_table_alloc,.read=mem_read,.write=mem_write,.ctx=c,.alloc_ctx=owner,
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
#if SNAP_NATIVE_SHARED
        /* 16K roots link their nested shared tables' groups. */
        struct native_links nl={c,&s,slot,native_shared_root_of(c,root)};
        struct sptm_root_links links=native_links_for(&nl);
        int built=s.root && (format ? sptm_root_build_shadow(memory,&s,root,format,flags,leaves) :
#if SNAP_ROOT_MISS_FAST
                             /* Linked shared tables may be answered by retained
                              * verdicts; copied tables are scanned (compat/root-miss.h). */
                             sptm_root_build_linked_memo(memory,&s,root,format,flags,leaves,&links,
                                                         &c->root_memo,nl_grouped));
#else
                             sptm_root_build_linked(memory,&s,root,format,flags,leaves,&links));
#endif
#else
        int built=s.root && sptm_root_build_shadow(memory,&s,root,format,flags,leaves);
#endif
        if(built) {
            *result=s.root;return 1;
        }
        /* Only a build the arena ran dry is retried, once: give back other
         * inactive slots, then release this slot's partial tables (the next
         * pass does) and build again from the unchanged guest tables. Any
         * other failure is terminal; partial allocations stay owned for
         * capture -- rewinding the bump pointer would lose reclaimed-page
         * ownership. */
        if(attempt || c->arena_reclaim.alloc_failures==failures || c->kernel_view_failed)
            return 0;
        c->arena_reclaim.build_retries++;
        arena_reclaim(c,ARENA_RETRY_PAGES,SPTM_ROOT_MASK_ONE(slot));
    }
}

static struct sptm_root_cached *user_cached(struct context *,uint64_t);
static uint64_t user_install_view(struct context *,uint64_t,uint64_t,int);
/* A root installation's earlier invalidations cover only this CPU's own
 * kernel copy and its old/new user copy (every copy page belongs to exactly one
 * CPU's view; other CPUs' copies are invalidated by the refresh that writes
 * them). This CPU stays at EL2 until the final sequence below has completed
 * its all-VMID TLBI, after the same publication. With SNAP_INSTALL_TLBI_DEFER
 * those inner TLBIs are folded into that one; any failure exit still issues
 * the deferred invalidation before returning. */
static void install_failed(struct context *c,int deferred)
{
    c->root_install_failures++;
    if(deferred) {
        c->install_tlbi.failure_flushes++;
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        c->shadow_tlb_syncs++;
    }
}
static void user_root_install(void *ctx,uint64_t shadow,uint64_t guest_root,
                              uint64_t asid,unsigned format)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
#if SNAP_EL0_MEMO
    /* Before anything changes: this vCPU's EL0 fetch memo is stale. */
    el0_memo_installed(&EL0M(c)[v->slot]);
#endif
    const int defer=SNAP_INSTALL_TLBI_DEFER;int deferred=0;
    if(defer)c->install_tlbi.installs++;
#if SNAP_NATIVE_TABLES
    /* The reset PPERM is usually this CPU's value already, and its kernel
     * copy is exact for it: nothing to do. Otherwise the transaction runs
     * with its own invalidation, since no install-wide flush follows. Nothing
     * is folded (install_tlbi counts installs only); a failure still flushes
     * on its way to the terminal stop. */
    if(c->user_roots.sprr[v->slot].pperm!=SPRR_PPERM_INITIAL) {
        if(!kernel_change_pperm_timed(c,SPRR_PPERM_INITIAL,1)) {c->root_install_failures++;return;}
    } else c->native_stats.pperm_skips++;
    deferred=defer;
#if SNAP_USER_HW_WALK
    /* compat/sptm-root.c installs a hardware-walk root with shadow 0: the
     * same PPERM reset above, then its own TTBR0 values (hw_install_user). */
    if(asid && !shadow) {hw_install_user(c,guest_root,asid,format);return;}
#endif
    if(asid) {
        shadow=user_install_view(c,guest_root,shadow,0);
        if(!shadow) {install_failed(c,deferred);return;}
    } else {
#else
    if(!kernel_change_pperm_timed(c,SPRR_PPERM_INITIAL,!defer)) {c->root_install_failures++;return;}
    if(defer) {deferred=1;c->install_tlbi.pperm_folded++;}
    if(asid) {
        shadow=user_install_view(c,guest_root,shadow,!defer);
        if(!shadow) {install_failed(c,deferred);return;}
        if(defer)c->install_tlbi.view_folded++;
    } else {
#endif
        struct user_view_state *u=&c->user_view_state[v->slot];
        u->root=u->shadow=u->el0=u->uperm=u->pperm=u->umprr=0;
#if SNAP_NATIVE_TABLES
        native_uninstall(&c->native_cpu[v->slot]);
#endif
    }
    /* mac-v1 format descriptors ...2701ec78/...2701ece0, with AS set by
     * SWITCH_ROOT. Both become the same hardware4K regime on the A16. */
    if(asid) {
        v->guest_tcr=(format ? SPTM_ROOT_TCR_4K : SPTM_ROOT_TCR_16K)|(1UL<<36);
        struct sptm_root_cached *entry=user_cached(c,guest_root);
        if(!entry) {install_failed(c,deferred);return;}
        USTAMPS(c)[entry-c->user_roots.cache]=++c->arena_reclaim.clock;
        v->guest_sctlr=pauth_root_enables(v->guest_sctlr,(unsigned)entry->flags);
    }
#if SNAP_NATIVE_TABLES
    /* The variant native_install named, in its own ASID; XNU's ASID stays
     * in guest_ttbr0. */
    const struct native_cpu *nc=&c->native_cpu[v->slot];
    uint64_t ttbr=asid ? nc->ttbr0[nc->w&1][nc->k&1] : shadow;
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    if(asid && (ttbr&PT_OA_MASK)!=shadow) {install_failed(c,deferred);return;}
#else
    uint64_t ttbr=shadow|(asid<<48),tcr=shadow_tcr(v->guest_tcr);
#endif
#if SNAP_ROOT_DIRTY_PUBLISH
    /* With SNAP_ROOT_PUBLISH_BATCH_DSB the pages are cleaned without per-page
     * barriers; the leading dsb ish of the sequence below completes them all
     * before the TLBI, as each per-page barrier did. */
#if SNAP_ROOT_PUBLISH_BATCH_DSB
    int (*page)(void *,uint64_t)=publish_page_lines;
#else
    int (*page)(void *,uint64_t)=root_publish_page;
#endif
#if SNAP_INCREMENTAL_PUBLISH
    if(!root_index_flush(&c->root_publish,&c->perf.root_index,c->work_base,c->next_table,page,c)) {
#else
    if(!root_publish_flush(&c->root_publish,c->work_base,c->next_table,page,c)) {
#endif
        __asm__ volatile("dsb ish" ::: "memory");
        install_failed(c,deferred);return;
    }
#else
    publish(c->work_base,c->next_table);
#endif
#if SNAP_NATIVE_TABLES
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    if(live_tcr==tcr) {
        /* Same regime: every address space and variant has its own ASID, so
         * a switch is a TTBR0 write. Only crossing between the kernel root
         * (ASID 0, global low entries) and a user root drops this CPU's
         * entries, locally: its VMID is its own. */
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        /* A different shared region than the one whose global entries this CPU may hold: flush them, as SPTM does
         * (see user_shared_slot). An unreadable binding flushes too. */
        int shared_flush=0;
        if(asid) {
            struct sptm_memory memory=sptm_context_memory(c);
            int region=sptm_mac_root_shared_slot(&memory,guest_root);
            uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
            uint16_t last=c->user_shared_slot[v->slot];
            shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        }
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            c->native_stats.local_flushes++;
            if(shared_flush)c->shared_switch_flushes[v->slot]++;
            c->user_shared_slot[v->slot]=0;
        }
    } else
#endif
    /* Break the old regime before changing granule/control values. Flush all
     * guest VMIDs because each CPU owns a private stage2 identity. */
    __asm__ volatile("dsb ish; msr tcr_el1, %2; isb; tlbi alle1is; dsb ish; "
                     "msr ttbr0_el1, %0; isb; msr tcr_el1, %1; isb"
                     :: "r"(ttbr),"r"(tcr),"r"(tcr|(1UL<<7)):"memory");
    uint64_t actual_ttbr,actual_tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1"
                     :"=r"(actual_ttbr),"=r"(actual_tcr));
    c->root_installed[v->slot][0]=actual_ttbr;
    c->root_installed[v->slot][1]=actual_tcr;
    /* Record the region whose global entries this CPU may now cache (after any flush above). */
    if(asid) {
        struct sptm_memory memory=sptm_context_memory(c);
        int region=sptm_mac_root_shared_slot(&memory,guest_root);
        c->user_shared_slot[v->slot]=region<0 || region==255 ? 0 : (uint16_t)(region+1);
    }
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)c->root_install_failures++;
    v->guest_ttbr0=guest_root|(asid<<48);
    c->shadow_tlb_syncs++;
}
