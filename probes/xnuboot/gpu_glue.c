/* SPDX-License-Identifier: MIT */
/* Adreno and interrupt-forwarding glue: GPU ops, IRQ, tick, recovery, IB polling,
 * quiesce and DART unmap.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
/* Stage 4: the Adreno through compat/adreno.h. EL2 reaches the GPU registers,
 * the GIC distributor and the q1n1 GPU arena through q1n1's identity map; the
 * guest reaches none of the arena and only the passthrough register windows. */
static uint32_t gpu_rd(uint64_t pa) {return *(volatile uint32_t *)pa;}
static void gpu_wr(uint64_t pa,uint32_t v) {*(volatile uint32_t *)pa=v;}
static int gpu_smc(void *ctx,uint64_t *r)
{
    (void)ctx;
    register uint64_t x0 __asm__("x0")=r[0],x1 __asm__("x1")=r[1],x2 __asm__("x2")=r[2],
        x3 __asm__("x3")=r[3],x4 __asm__("x4")=r[4],x5 __asm__("x5")=r[5],
        x6 __asm__("x6")=r[6],x7 __asm__("x7")=r[7];
    __asm__ volatile("smc #0" : "+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3),"+r"(x4),"+r"(x5),
                     "+r"(x6),"+r"(x7) :: "x8","x9","x10","x11","x12","x13","x14",
                     "x15","x16","x17","memory");
    r[0]=x0;r[1]=x1;r[2]=x2;r[3]=x3;r[4]=x4;r[5]=x5;r[6]=x6;r[7]=x7;
    return 0;
}
static struct adreno_ops gpu_ops(struct context *c)
{
    /* adreno.c reaches registers, DRAM, caches and the counter itself here. */
    return (struct adreno_ops){.ctx=c,.smc=gpu_smc,.hz=c->params->clock_host_hz};
}
#if SNAP_ADRENO_COHERENT
/* gpu_ops with the leaf word the self-test chose (0, today's, until it passed), for every path that writes or checks a
 * mirror leaf: the DART mirror (map, unmap) and the guest GPU calls (fence, cache, FILL32, IB). A path given plain
 * gpu_ops by mistake fails closed: its placement checks refuse the coherent leaves, or its mirror writes today's. */
static struct adreno_ops gpu_leaf_ops(struct context *c)
{
    struct adreno_ops o=gpu_ops(c);
    o.leaf=c->root_ext->gpu_coherent.leaf;
    return o;
}
#define GPU_LEAF_OPS(c) gpu_leaf_ops(c)
#else
#define GPU_LEAF_OPS(c) gpu_ops(c)
#endif
static int aic_model(const struct context *c)
{
    for (unsigned i=0;i<c->params->model_count;i++)
        if (c->params->models[i].kind==DEVICE_AIC3_FLAT_V1) return (int)i;
    return -1;
}
static void fwd_disable(void *ctx,uint32_t intid)
{
    uint64_t g=((struct context *)ctx)->params->gpu.gicd;
    gpu_wr(g+GICD_ICENABLER+4*(intid/32),1u<<(intid%32));
    for (unsigned n=0;n<100000 && (gpu_rd(g+GICD_CTLR)&(1u<<31));n++) {}
}
static void fwd_enable(void *ctx,uint32_t intid)
{
    gpu_wr(((struct context *)ctx)->params->gpu.gicd+GICD_ISENABLER+4*(intid/32),1u<<(intid%32));
}
static int fwd_pending(void *ctx,uint32_t intid)
{
    return !!(gpu_rd(((struct context *)ctx)->params->gpu.gicd+GICD_ISPENDR+4*(intid/32))&
              (1u<<(intid%32)));
}
static void fwd_complete(void *ctx,uint32_t intid) {(void)ctx;timer_eoi(intid);}
static int fwd_level(void *ctx,uint32_t irq,int level)
{
    struct context *c=ctx;
    int a=aic_model(c);
    return a<0 || device_irq_set_level(&c->params->models[a],&c->model_state[a],irq,level)!=DEVICE_OK;
}
static struct irqfwd_ops fwd_ops(struct context *c)
{
    return (struct irqfwd_ops){c,fwd_disable,fwd_enable,fwd_pending,fwd_complete,fwd_level};
}
static void gpu_serror_check(struct context *c)
{
    uint64_t isr;
    __asm__ volatile("mrs %0, isr_el1" : "=r"(isr));
    if (isr&(1u<<8)) c->gpu.serrors++;
}
static void gpu_fault_record(struct context *c,uint64_t pc)
{
    const struct adreno_state *s=&c->gpu;
    record(c,EV_GPU_SMMU,pc,s->fault_fsynr0<<32|s->fault_fsr,s->fault_far,
           s->fault_gfsr<<32|s->fault_cbfrsynra);
}
/* EL2 IRQ for INTID 0x14C: mask, complete, raise AIC 975 (compat/irq-forward.c). */
static void gpu_irq(struct context *c)
{
    uint64_t intid;
    __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy" : "=r"(intid) :: "memory");
    struct irqfwd_ops f=fwd_ops(c);
    if (irqfwd_physical(&c->gpu.irq,&f,(uint32_t)intid)==IRQFWD_NOT_OURS && intid<1020)
        timer_eoi(intid);   /* a level source that is not ours re-asserts on its own */
    vcpu_of(c)->model_irq_pending=0;
    for (unsigned i=0;i<c->params->model_count;i++)
        vcpu_of(c)->model_irq_pending|=device_irq_pending(&c->params->models[i],&c->model_state[i]);
    guest_interrupt_sync(c);
}
#if SNAP_ADRENO_RECOVER
/* After a call that may have run adreno_recover: its EV_GPU_RECOVER, and the fault it recorded and cleared. */
static void gpu_recover_record(struct context *c,uint64_t pc,uint64_t attempts,uint64_t faults)
{
    const struct adreno_recover_state *rs=GPU_RECOVER(c);
    if (rs->attempts!=attempts)
        record(c,EV_GPU_RECOVER,pc,rs->last_cause<<56|(rs->dead&0xffff)<<32|(uint32_t)rs->epoch,
               rs->snap[0]<<32|(uint32_t)rs->snap[1],rs->snap[2]<<32|(uint32_t)rs->last_ticks);
    if (c->gpu.faults!=faults) gpu_fault_record(c,pc);
    IB_FLIGHT(c)->reserved[2]=rs->epoch;
}
/* ADRENO_GUEST_RECOVER (compat/adreno-guest.h): QUERY and SETTLE, under the token like the rest of the GPU state. */
static void gpu_recover_hvc(struct context *c,uint64_t *frame,uint64_t elr)
{
    uint64_t r[4]={frame[0],frame[1],frame[2],frame[3]};
    struct adreno_ops o=gpu_ops(c);
    const uint64_t attempts=GPU_RECOVER(c)->attempts,faults=c->gpu.faults;
    adreno_guest_recover(&o,&c->params->gpu,&c->gpu,IB_FLIGHT(c),GPU_RECOVER(c),r);
    gpu_recover_record(c,elr,attempts,faults);
    for (unsigned n=0;n<4;n++) frame[n]=r[n];
}
#endif
/* vCPU 0's timer tick: once a second after ring_at, poll CB0 for faults and
 * make the in-run test fence (and the one-shot GIC self-test of the IRQ path
 * while the guest still holds AIC 975 masked). */
static void gpu_tick(struct context *c,uint64_t pc)
{
    const struct params *p=c->params;
    struct adreno_state *s=&c->gpu;
    uint64_t now=service_profile_clock();
    if (!(s->status&ADRENO_S_ADOPTED) || (s->status&ADRENO_S_QUIESCED) || now<s->run_at) return;
    s->run_at=now+p->clock_host_hz;
    struct adreno_ops o=gpu_ops(c);
#if SNAP_ADRENO_IB_ASYNC
    /* No fault poll (it clears FSR before the IB's own POLL sees it) and no run fence while an IB is in flight
     * (A2, A7). A flight nobody polled for its budget + grace ends here, recorded as its POLL would have (A3). */
    struct adreno_ib_flight *f=IB_FLIGHT(c);
    uint64_t ib_va=f->va,ib_dwords=f->dwords;
    int final,idle=adreno_ib_flight_tick(&o,&p->gpu,s,f,ADRENO_IB_FLIGHT_GRACE_SECONDS*p->clock_host_hz,&final);
#if SNAP_ADRENO_RECOVER
    if (final!=ADRENO_IB_PENDING) {   /* agents/gpu-recovery R20: an abandoned flight is recovered here */
        const uint64_t attempts=GPU_RECOVER(c)->attempts,faults=s->faults;
        final=adreno_recover_final(&o,&p->gpu,s,f,GPU_RECOVER(c),final,1,0);
        gpu_recover_record(c,pc,attempts,faults);
    }
#endif
    if (final!=ADRENO_IB_PENDING) record(c,EV_GPU_IB,pc,ib_va,ib_dwords<<32|(uint32_t)final,f->last_ticks);
    if (!idle) {gpu_serror_check(c);return;}
#endif
    if (adreno_fault_poll(&o,s)) gpu_fault_record(c,pc);
    if ((p->gpu.flags&ADRENO_F_RING) && !(s->status&ADRENO_S_RUN_FENCE)) {
        s->status|=ADRENO_S_RUN_FENCE;
        int e=adreno_fence(&o,&p->gpu,s,0x534e0002u);
        record(c,EV_GPU_RING,pc,0x534e0002u,(uint64_t)(int64_t)e,s->fence_ticks);
        int a=aic_model(c);
        if ((p->gpu.flags&ADRENO_F_SELF_IRQ) && a>=0 &&
            !(c->model_state[a].aic.unmasked[ADRENO_AIC_IRQ/32]&(1u<<(ADRENO_AIC_IRQ%32)))) {
            gpu_wr(p->gpu.gicd+GICD_ISPENDR+4*(ADRENO_INTID/32),1u<<(ADRENO_INTID%32));
            s->self_irq++;
        }
    }
    gpu_serror_check(c);
}
#if SNAP_ADRENO_IB_ASYNC
/* ADRENO_GUEST_IB_POLL (compat/adreno-guest.h): one completion pass of the IB in flight, from any vCPU (A4). No
 * DART access, so no DART model admission. One EV_GPU_IB per IB (A18): the POLL that ends the flight records it
 * with ADRENO_GUEST_IB's fields; PENDING and IDLE are counted in the flight, not logged. */
static void gpu_ib_poll_hvc(struct context *c, uint64_t *frame, uint64_t elr)
{
    uint64_t r[4] = {frame[0], frame[1], frame[2], frame[3]};
    struct adreno_ops o = gpu_ops(c);
    struct adreno_ib_flight *f = IB_FLIGHT(c);
    uint64_t va = f->va, dwords = f->dwords, active = f->active;
    int e = adreno_guest_ib_poll(&o, &c->params->gpu, &c->gpu, f, r);
#if SNAP_ADRENO_RECOVER
    if (active && !f->active) {          /* agents/gpu-recovery: UNCERTAIN/GPU_ERROR may become a reset (RESET) */
        const uint64_t attempts = GPU_RECOVER(c)->attempts, faults = c->gpu.faults;
        e = adreno_recover_final(&o, &c->params->gpu, &c->gpu, f, GPU_RECOVER(c), e, 1, r);
        gpu_recover_record(c, elr, attempts, faults);
    }
#endif
    if (active && !f->active) record(c, EV_GPU_IB, elr, va, dwords << 32 | (uint32_t)e, r[2]);
    for (unsigned n = 0; n < 4; n++) frame[n] = r[n];
}
#endif
#if SNAP_ADRENO_COHERENT
/* ADRENO_GUEST_COHERENT's epoch is attr_updates.cleans + 1: every frame an SPTM SH/AttrIndx change cleans is counted
 * there (sptm_attr_clean, attr_clean_note), under the token, and nothing resets it, so a kext verdict made at one
 * epoch is stale as soon as any attribute changed. root_ext exists whenever the guest runs (SNAP_ROOT_CACHE_WIDE:
 * xnuboot_setup takes its pages before anything else), so the GPU paths below use it unchecked. */
/* Whether a 16 KiB guest frame is Normal write-back for the CPU right now: the AttrIndx of its physical-aperture
 * leaf in the guest's kernel tables. XNU keeps one WIMG per managed page and rewrites the aperture with every change
 * (pmap_batch_set_cache_attributes -> UPDATE_DISJOINT_MULTIPAGE's aperture step). sptm_papt_prepare_attr changes the
 * linear alias and, for a frame SLIDE_REGION moved, the alias phystokv uses together, so the linear one is the
 * frame's attribute. Anything this walk cannot prove reads as not write-back, which only keeps maintenance. */
static struct sptm_aperture xnu_aperture(const struct context *);
static int gpu_aperture_writeback(struct context *c,uint64_t pa)
{
    struct sptm_aperture a=xnu_aperture(c);
    uint64_t va=(pa&0x3fff) ? 0 : sptm_aperture_pointer(&a,pa,0x4000),table=c->params->ttbr1_root;
    if (!va || (va&0x3fff) || va<0xffff800000000000UL || !table || (table&0x3fff)) return 0;
    for (unsigned level=1;level<=3;level++) {
        volatile uint8_t *page=sptm_map(c,table,0x4000);
        if (!page) return 0;
        /* 16 KiB granule, levels 1..3: 11 index bits each above the 14-bit page offset (shadow/mmu.c mmu_index). */
        uint64_t d=*(volatile uint64_t *)(page+8UL*((va>>(14+11*(3-level)))&0x7ff));
        if (level==3)
            return (d&3)==3 && (d&0x0000ffffffffc000UL)==pa && ADRENO_COHERENT_CPU_WB((unsigned)((d>>2)&7));
        if ((d&~0x0000ffffffffc000UL)!=3) return 0;
        table=d&0x0000ffffffffc000UL;
    }
    return 0;
}
/* adreno_guest_cache_filtered's oracle (the kext counts what it skips and what x2 says was still maintained). */
static int gpu_cpu_writeback(void *ctx,uint64_t pa)
{
    return gpu_aperture_writeback(ctx,pa);
}
#endif
static int64_t gpu_prepare(struct context *c)
{
    const struct params *p=c->params;
    if (!p->gpu.flags) return 0;
    struct adreno_params g=p->gpu;
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    g.affinity=(mpidr&0xffffff)|((mpidr>>32)&0xff)<<32;  /* this CPU runs vCPU 0 */
#if SNAP_BOOT_RELOCATE
    const struct boot_relocation *relocated=boot_relocation_of(c);
    if (relocated) g.affinity=relocated->record.affinity;  /* unless it is relocated */
#endif
    /* The loader proved the arena clear of the panel and the work area
     * (probes/adreno.py); adreno_adopt proves it clear of guest memory. */
    int a=aic_model(c);
    if (a<0 || p->models[a].config[0]<=ADRENO_AIC_IRQ)
        return c->gpu.prepare=(uint64_t)(int64_t)ADRENO_E_PARAMS,ADRENO_E_PARAMS;
    struct adreno_ops o=gpu_ops(c);
    int e=adreno_adopt(&o,&g,&c->gpu,p->mem_low,p->mem_high);
    if (!e && irqfwd_add(&c->gpu.irq,ADRENO_INTID,ADRENO_AIC_IRQ)!=IRQFWD_OK) e=ADRENO_E_PARAMS;
    if (e) return e;
    e=adreno_gic_route(&o,&g,&c->gpu);
    if (e) return c->gpu.prepare=(uint64_t)(int64_t)e,e;
    fwd_enable(c,ADRENO_INTID);
    if (g.flags&ADRENO_F_RING) {
        e=adreno_fence(&o,&g,&c->gpu,0x534e0001u);
        record(c,EV_GPU_RING,0,0x534e0001u,(uint64_t)(int64_t)e,c->gpu.fence_ticks);
    }
    c->gpu.run_at=service_profile_clock()+g.ring_at_seconds*p->clock_host_hz;
#if SNAP_ADRENO_COHERENT
    /* Before the guest exists and before recovery snapshots the CP: the mirror is empty, so the leaf word can still
     * change. The record is written whatever the outcome; an OFF state keeps today's leaves and maintenance. */
    if (c->root_ext) {
        struct adreno_coherent_state *cs=&c->root_ext->gpu_coherent;
        /* The sweep reads the first 24 MiB of guest RAM (GiBs on every A16 profile), nothing else. */
        adreno_coherent_selftest(&o,&g,&c->gpu,cs,p->mem_low,ADRENO_COHERENT_SWEEP_MAX,p->mem_low,p->mem_high);
        record(c,EV_GPU_COHERENT,cs->pmu[0],cs->state<<32|cs->detail,cs->passed|cs->pmu[1]<<16,
               cs->stale[0]<<32|cs->stale[1]);
    }
#endif
#if SNAP_ADRENO_RECOVER
    if (c->root_ext) adreno_recover_init(&o,&g,&c->gpu,GPU_RECOVER(c));   /* agents/gpu-recovery R8 */
#endif
    gpu_serror_check(c);
    return e;
}
/* Before the guest's memory is handed back: the line, then the GPU (adreno.h). */
static int gpu_quiesce(struct context *c)
{
    if (!(c->gpu.status&ADRENO_S_ADOPTED)) return 1;
    struct irqfwd_ops f=fwd_ops(c);
    struct adreno_ops o=gpu_ops(c);
    irqfwd_quiesce(&c->gpu.irq,&f);
    adreno_gic_restore(&o,&c->params->gpu,&c->gpu);
    uint64_t faults=c->gpu.faults;
    adreno_quiesce(&o,&c->params->gpu,&c->gpu);
    if (c->gpu.faults!=faults) gpu_fault_record(c,0);
    gpu_serror_check(c);
    if (c->gpu.serrors) c->gpu.status &= ~ADRENO_S_QUIESCED;
    return !!(c->gpu.status & ADRENO_S_QUIESCED);
}
struct gpu_leaf_ctx { const struct sptm_memory *memory; struct dart_state *dart; };
static uint64_t gpu_leaf(void *ctx,uint64_t iova)
{
    struct gpu_leaf_ctx *l=ctx;
    return sptm_dart_leaf(l->memory,l->dart,SPTM_DART_ADRENO,0,iova);
}
#if SNAP_DART_WIREDCNT
_Static_assert(sizeof(((struct context *)0)->dart_wiredcnt) == DWC_WORDS * 8 &&
               sizeof(((struct context *)0)->dart_wiredcnt_pins) == DWC_PIN_WORDS * 8,
               "DWC state words");
static uint64_t dwc_kva(void *ctx, uint64_t va) {(void)ctx; return guest_pa(va);}
static uint64_t dwc_read(void *ctx, uint64_t pa, unsigned size)
{
    (void)ctx;
    return size == 8 ? *(volatile uint64_t *)pa : size == 4 ? *(volatile uint32_t *)pa :
           *(volatile uint16_t *)pa;
}
static int dwc_cas16(void *ctx, uint64_t pa, uint16_t expected, uint16_t desired)
{
    (void)ctx;
    return __atomic_compare_exchange_n((uint16_t *)pa, &expected, desired, 0,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
/* The level-2 (leaf) table the Adreno DART's level-1 root names for iova. */
static uint64_t dwc_table(void *ctx, uint64_t iova)
{
    struct gpu_leaf_ctx *l=ctx;
    uint32_t ttbr=l->dart->ttbr[0];
    if (!(ttbr&1)) return 0;
    volatile uint8_t *root=l->memory->map(l->memory->ctx,(uint64_t)(ttbr&0x3ffffffcU)<<12,0x4000);
    if (!root) return 0;
    uint64_t v=*(volatile uint64_t *)(root+8*((iova>>25)&2047));
    return (v&1) ? (v&0x3ffffffc00UL)<<4 : 0;
}
static int dwc_sptm_unmap(void *ctx, uint64_t iova, uint64_t size)
{
    struct gpu_leaf_ctx *l=ctx;
    return sptm_dart_unmap(l->memory,l->dart,SPTM_DART_ADRENO,0,iova,size,2);
}
#endif
static int gpu_unmap(void *ctx,uint64_t iova,uint64_t size)
{
    struct gpu_leaf_ctx *l=ctx;
#if SNAP_DART_WIREDCNT
    /* The same clear, plus XNU's own count of the leaves it removes. */
    struct context *c=context_of();
    const struct params *p=c->params;
    const struct dwc_ops o={l,p->mem_low,p->mem_high,
        (const volatile uint32_t *)(uintptr_t)p->const_begin,p->const_begin,
        p->const_end>p->const_begin ? (p->const_end-p->const_begin)/4 : 0,
        p->vbar_va-p->vbar,SPTM_DART_ADRENO,
        dwc_kva,dwc_read,dwc_cas16,dwc_table,gpu_leaf,dwc_sptm_unmap};
    return dwc_unmap(&o,c->dart_wiredcnt,c->dart_wiredcnt_pins,iova,size);
#else
    /* Permit holes when rolling back a partially inserted resource. This is
     * native table-3 endpoint3/option2, with its ownership/reference checks. */
    return sptm_dart_unmap(l->memory,l->dart,SPTM_DART_ADRENO,0,iova,size,2);
#endif
}

