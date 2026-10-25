/* SPDX-License-Identifier: MIT */
/* Secondary CPU records, launch, run, stop and collection, and boot relocation.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

static struct secondary *secondary_of(struct context *c,unsigned slot)
{
    return (struct secondary *)(c->secondary_base+(uint64_t)slot*4096);
}
void xnuboot_secondary_stop(void) __attribute__((noreturn));
static void secondary_run(struct secondary *s) __attribute__((noreturn));
#if SNAP_BOOT_RELOCATE
void xnuboot_relocated_stop(void) __attribute__((noreturn));
static void boot_relocated_run(struct secondary *s) __attribute__((noreturn));
void boot_guest_enter(uint64_t entry, uint64_t out, uint64_t x1, uint64_t x2) __attribute__((noreturn));
#endif
extern const uint8_t xnuboot_vectors[];
static int secondary_prepare_records(struct context *c)
{
    const struct secondary_config *h=c->host_cpus;
    if (!h) return 1;
    uint64_t mpidr,regime[4];
    __asm__ volatile("mrs %0, mpidr_el1":"=r"(mpidr));
    __asm__ volatile("mrs %0, sctlr_el2":"=r"(regime[0]));
    __asm__ volatile("mrs %0, tcr_el2":"=r"(regime[1]));
    __asm__ volatile("mrs %0, ttbr0_el2":"=r"(regime[2]));
    __asm__ volatile("mrs %0, mair_el2":"=r"(regime[3]));
#if SNAP_BOOT_RELOCATE
    /* Bit 0: vCPU 0 on affinity[0], with an EL2 stack of its own. */
    uint64_t relocate=h->mask&BOOT_RELOCATE_MASK ? GUEST_RUNTIME_STACK : 0;
    if (h->magic!=SECONDARY_MAGIC || h->size!=sizeof(*h) ||
        (mpidr&UINT64_C(0xff00ffffff))!=h->boot_affinity ||
        !h->mask || h->mask&~UINT64_C(0x3f) ||
        !boot_relocate_layout_valid(h->boot_affinity,h->mask,h->affinity,h->redistributor) ||
        c->work_end-c->next_table<6*4096+relocate) return 0;
#else
    if (h->magic!=SECONDARY_MAGIC || h->size!=sizeof(*h) ||
        (mpidr&UINT64_C(0xff00ffffff))!=h->boot_affinity ||
        !h->mask || h->mask&~UINT64_C(0x3e) ||
        c->work_end-c->next_table<6*4096) return 0;
#endif
    for (unsigned i=0;i<4;i++) if (regime[i]!=h->regime[i]) return 0;
    for (unsigned i=1;i<6;i++) if (h->mask&(1U<<i)) {
        uint64_t r=h->redistributor[i];
        if (h->affinity[i]&~UINT64_C(0xff00ffffff) || h->affinity[i]==h->boot_affinity ||
            r<0x17080000 || r>=0x17500000 || (r-0x17080000)%0x40000) return 0;
        for (unsigned j=1;j<i;j++) if ((h->mask&(1U<<j)) &&
            (h->affinity[i]==h->affinity[j] || r==h->redistributor[j])) return 0;
    }
    c->secondary_base=c->next_table;
    c->next_table+=6*4096;
    for (uint64_t p=c->secondary_base;p<c->next_table;p+=8) *(uint64_t *)p=0;
#if SNAP_BOOT_RELOCATE
    if (relocate) {
        struct boot_relocation *r=(struct boot_relocation *)secondary_of(c,0);
        uint64_t stack=c->next_table;
        c->next_table+=relocate;
        for (uint64_t p=stack;p<c->next_table;p+=8) *(uint64_t *)p=0;
        for (unsigned j=0;j<4;j++) r->record.regime[j]=regime[j];
        r->record.cpu=(uint64_t)&c->vcpus[0];r->record.stack=c->next_table;
        r->record.affinity=h->affinity[0];r->record.redistributor=h->redistributor[0];
        r->record.vectors=(uint64_t)xnuboot_vectors;r->record.callback=(uint64_t)boot_relocated_run;
        r->record.stop_callback=(uint64_t)xnuboot_relocated_stop;
        r->record.on_result=r->record.off_result=r->record.affinity_result=UINT64_MAX;
        r->armed=1;
    }
#endif
    for (unsigned i=1;i<6;i++) if (h->mask&(1U<<i)) {
        struct secondary *s=secondary_of(c,i);
        for (unsigned j=0;j<4;j++) s->regime[j]=regime[j];
        s->cpu=(uint64_t)&c->vcpus[i];s->stack=c->vcpus[i].el2_sp;
        s->affinity=h->affinity[i];s->redistributor=h->redistributor[i];
        s->vectors=(uint64_t)xnuboot_vectors;s->callback=(uint64_t)secondary_run;
        s->stop_callback=(uint64_t)xnuboot_secondary_stop;
        s->on_result=s->off_result=s->affinity_result=UINT64_MAX;
    }
    return 1;
}
static void secondary_run(struct secondary *s)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    __atomic_store_n(&s->phase,1,__ATOMIC_RELEASE);
    enum guest_service_result arrived=guest_service_arrive(&c->services,v->slot);
    if (arrived!=SERVICE_OK) { s->error=arrived; xnuboot_secondary_stop(); }
    if (!secondary_gic_start(s)) { s->error=0x100;xnuboot_secondary_stop(); }
    __atomic_store_n(&s->phase,2,__ATOMIC_RELEASE);
    uint64_t frame[34]={0};
    if (!runtime_enter(c,frame,c->params->entry,SERVICE_PROFILE_BOOT)) xnuboot_secondary_stop();
    uint64_t hcr=(UINT64_C(1)<<31)|(UINT64_C(1)<<26)|(UINT64_C(1)<<30)|
        (UINT64_C(1)<<20)|(UINT64_C(1)<<18)|(UINT64_C(1)<<14)|1;
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr));
    s->prepare_result=(uint64_t)xnuboot_prepare_cpu();
    *(uint64_t *)v->out_ptr=s->prepare_result;
    if (s->prepare_result) { s->error=0x101;xnuboot_secondary_stop(); }
    __asm__ volatile("mrs %0, s3_4_c2_c2_0":"=r"(s->active_vncr));
    __asm__ volatile("mrs %0, vmpidr_el2":"=r"(s->active_vmpidr));
    __asm__ volatile("mrs %0, vttbr_el2":"=r"(s->active_vttbr));
    if (s->active_vncr!=v->vncr_va || s->active_vmpidr!=v->vmpidr ||
        s->active_vttbr!=vcpu_vttbr(v)) { s->error=0x103;xnuboot_secondary_stop(); }
    /* Firmware enables SIMD on its boot CPU, but PSCI secondaries can enter
     * with FPEN clear. The stock warm path assumes the platform supplied FP.
     * These are native per-CPU registers; SVE/SME access policy is unchanged. */
    uint64_t pfr0,cpacr,cptr;
    __asm__ volatile("mrs %0, id_aa64pfr0_el1":"=r"(pfr0));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->initial_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->initial_cptr));
    if (((pfr0>>16)&15)>1 || ((pfr0>>20)&15)>1) {
        s->error=0x104;xnuboot_secondary_stop();
    }
    __asm__ volatile("msr cpacr_el1, %0; msr cptr_el2, %1; isb"::
        "r"(s->initial_cpacr|(UINT64_C(3)<<20)),"r"(s->initial_cptr&~(UINT64_C(1)<<10)));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(cptr));
    if ((cpacr&(UINT64_C(3)<<20))!=(UINT64_C(3)<<20) || (cptr&(UINT64_C(1)<<10))) {
        s->error=0x105;xnuboot_secondary_stop();
    }
    xnuboot_watchdog(c->params->watchdog_seconds);
    __asm__ volatile("mrs %0, hcr_el2":"=r"(hcr));
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr|24));
    if (runtime_leave(c,0)) xnuboot_secondary_stop();
    s->entered=1;
    __atomic_store_n(&s->phase,3,__ATOMIC_RELEASE);
    secondary_guest_enter(c->params->entry,v->out_ptr);
}
void xnuboot_secondary_stop(void)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    if (!v->slot || v->slot>=6 || !c->secondary_base)
        for (;;) __asm__ volatile("yield":::"memory");
    struct secondary *s=secondary_of(c,(unsigned)v->slot);
    watchdog_off(c);
    guards_close(c);
    /* Secondary CPUs bypass xnuboot_report and go straight to PSCI CPU_OFF.
     * Restore their bank on its owning CPU, while its debug state is still
     * accessible, including after a partially successful preparation. */
    if (SNAP_NATIVE_WRITER_BREAKPOINTS && c->writer_debug[v->slot].saved) {
        int restored=native_writer_debug_restore(&c->writer_debug[v->slot],&writer_debug_ops);
        __asm__ volatile("msr mdcr_el2, %0; msr mdscr_el1, %1; isb"::
                         "r"(v->save_mdcr),"r"(v->save_mdscr):"memory");
        if (v->dbg_oslsr & (1UL<<1)) {
            uint64_t one=1;
            __asm__ volatile("msr oslar_el1, %0; isb"::"r"(one):"memory");
        }
        if (!restored) { s->error=0x106;v->service_fault=SERVICE_BAD_STATE; }
    }
#if SNAP_NATIVE_PACGA
    native_pacga_restore(c,v);
#endif
#if SNAP_LEAN_TRAPS == 2
    lean_fgt_restore(c,v);
#endif
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->final_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->final_cptr));
    if (!secondary_gic_stop(s)) { s->error=0x102;v->service_fault=SERVICE_BAD_STATE; }
    if (s->error || v->service_fault)
        guest_service_stop(&c->services,v->slot,SERVICE_STOP_FAULT);
    /* Preserve this CPU's terminal snapshot independently of CPU0's report. */
    const uint64_t *snapshot=(const uint64_t *)(v->async_captured ? &v->async_regs : &v->last_exc);
    uint64_t *out=(uint64_t *)v->out_ptr;
    out[2]=v->fault_esr;out[3]=v->fault_elr;out[4]=v->bad_elr;out[5]=v->bad_far;
    out[6]=v->async_captured ? v->async_captured : v->exceptions ? 4 : 0;
    out[7]=v->service_fault;
    for (unsigned i=0;i<GUEST_REGS_WORDS;i++) out[8+i]=snapshot[i];
    s->finish_result=guest_service_finish(&c->services,v->slot);
    if (s->finish_result!=SERVICE_OK) v->service_fault=s->finish_result;
    __atomic_store_n(&s->phase,4,__ATOMIC_RELEASE);
    secondary_power_off(s);
}
#if SNAP_BOOT_RELOCATE
/* The relocated vCPU 0's CPU (compat/boot-relocate.h), from secondary_entry
 * with record page 0: the boot path's per-CPU half, then the guest's cold
 * entry. No other executor exists yet (secondaries start only at the guest's
 * request) and q1n1's CPU touches only the relay, so, as on the boot path, no
 * service token is taken before guest_service_boot (in vcpu_arch_prepare). */
static void boot_relocated_run(struct secondary *s)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    struct boot_relocation *r=(struct boot_relocation *)s;
    __atomic_store_n(&s->phase,1,__ATOMIC_RELEASE);
    boot_relocation_ids(r->target_id,r->target_cache);
    r->id_mismatch=boot_relocate_id_mismatch(r->boot_id,r->target_id);
    if (r->id_mismatch) { s->error=BOOT_RELOCATE_ERROR_ID;xnuboot_relocated_stop(); }
    __asm__ volatile("mrs %0, cntvoff_el2":"=r"(r->target_cntvoff));
    __asm__ volatile("mrs %0, cntfrq_el0":"=r"(r->target_cntfrq));
    if (r->target_cntvoff!=r->boot_cntvoff || r->target_cntfrq!=r->boot_cntfrq ||
        r->target_cntfrq!=c->params->clock_host_hz) {
        s->error=BOOT_RELOCATE_ERROR_CLOCK;xnuboot_relocated_stop();
    }
    if (!secondary_gic_start(s)) { s->error=0x100;xnuboot_relocated_stop(); }
    __atomic_store_n(&s->phase,2,__ATOMIC_RELEASE);
    /* _start's HCR_EL2; vcpu_arch_prepare adds NV/NV2 (and clears TWE). */
    uint64_t hcr=(UINT64_C(1)<<31)|(UINT64_C(1)<<26)|(UINT64_C(1)<<30)|
        (UINT64_C(1)<<20)|(UINT64_C(1)<<18)|(UINT64_C(1)<<14)|1;
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr));
    /* As secondary_run: PSCI can start this CPU with FP/SIMD trapped. */
    uint64_t pfr0,cpacr,cptr;
    __asm__ volatile("mrs %0, id_aa64pfr0_el1":"=r"(pfr0));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->initial_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->initial_cptr));
    if (((pfr0>>16)&15)>1 || ((pfr0>>20)&15)>1) { s->error=0x104;xnuboot_relocated_stop(); }
    __asm__ volatile("msr cpacr_el1, %0; msr cptr_el2, %1; isb"::
        "r"(s->initial_cpacr|(UINT64_C(3)<<20)),"r"(s->initial_cptr&~(UINT64_C(1)<<10)));
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(cptr));
    if ((cpacr&(UINT64_C(3)<<20))!=(UINT64_C(3)<<20) || (cptr&(UINT64_C(1)<<10))) {
        s->error=0x105;xnuboot_relocated_stop();
    }
    s->prepare_result=(uint64_t)vcpu_arch_prepare(c);
    if (s->prepare_result) { s->error=0x101;xnuboot_relocated_stop(); }
    __asm__ volatile("mrs %0, s3_4_c2_c2_0":"=r"(s->active_vncr));
    __asm__ volatile("mrs %0, vmpidr_el2":"=r"(s->active_vmpidr));
    __asm__ volatile("mrs %0, vttbr_el2":"=r"(s->active_vttbr));
    if (s->active_vncr!=v->vncr_va || s->active_vmpidr!=v->vmpidr ||
        s->active_vttbr!=vcpu_vttbr(v)) { s->error=0x103;xnuboot_relocated_stop(); }
    xnuboot_watchdog(c->params->watchdog_seconds);
    __asm__ volatile("mrs %0, hcr_el2":"=r"(hcr));
    __asm__ volatile("msr hcr_el2, %0; isb"::"r"(hcr|24));   /* IMO, FMO */
    s->entered=1;
    __atomic_store_n(&s->phase,3,__ATOMIC_RELEASE);
    boot_guest_enter(c->params->entry,v->out_ptr,c->params->x1,c->params->x2);
}
/* The relocated CPU's terminal path, from the exit path (xnuboot.S, on its own
 * stack) or a refusal above: like xnuboot_secondary_stop, it puts back only
 * this CPU's state, finishes vCPU 0's executor and powers off. q1n1's CPU
 * reports once AFFINITY_INFO says OFF. */
void xnuboot_relocated_stop(void)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    struct boot_relocation *r=boot_relocation_of(c);
    if (v->slot || !r || boot_relocation_on_boot_cpu(c))
        for (;;) __asm__ volatile("yield":::"memory");
    struct secondary *s=&r->record;
    watchdog_off(c);
    guards_close(c);
    if (SNAP_NATIVE_WRITER_BREAKPOINTS && c->writer_debug[0].saved) {
        int restored=native_writer_debug_restore(&c->writer_debug[0],&writer_debug_ops);
        __asm__ volatile("msr mdcr_el2, %0; msr mdscr_el1, %1; isb"::
                         "r"(v->save_mdcr),"r"(v->save_mdscr):"memory");
        if (v->dbg_oslsr & (1UL<<1)) {
            uint64_t one=1;
            __asm__ volatile("msr oslar_el1, %0; isb"::"r"(one):"memory");
        }
        /* This CPU's bank: the report must not restore it onto q1n1's CPU. */
        c->writer_debug[0].saved=0;
        if (!restored) { s->error=0x106;v->service_fault=SERVICE_BAD_STATE; }
    }
#if SNAP_NATIVE_PACGA
    native_pacga_restore(c,v);
#endif
#if SNAP_LEAN_TRAPS == 2
    lean_fgt_restore(c,v);
#endif
    __asm__ volatile("mrs %0, cpacr_el1":"=r"(s->final_cpacr));
    __asm__ volatile("mrs %0, cptr_el2":"=r"(s->final_cptr));
    if (!secondary_gic_stop(s)) { s->error=0x102;v->service_fault=SERVICE_BAD_STATE; }
    if (s->error || v->service_fault)
        guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
    s->finish_result=guest_service_finish(&c->services,0);
    if (s->finish_result!=SERVICE_OK) v->service_fault=s->finish_result;
    __atomic_store_n(&s->phase,4,__ATOMIC_RELEASE);
    secondary_power_off(s);
}
/* On q1n1's CPU: run one relayed call. Not live (after an EL2 fault on this
 * CPU, possibly inside q1n1): answer without calling it. */
static void boot_relay_serve(struct context *c, struct boot_relocation *r, uint64_t ticket, int live)
{
    struct boot_relay *q=&r->relay;
    if (!live || !c->params->early_stop.host_call) {
        q->refused++;
        boot_relay_answer(q,ticket,BOOT_RELAY_FAILED);
        return;
    }
    uint64_t (*call)(uint64_t, uint64_t, uint64_t, uint64_t) =
        (uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)c->params->early_stop.host_call;
    uint64_t before,after;
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(before));
    q->in_call=1;
    uint64_t result=call(q->op,q->a1,q->a2,q->a3);
    q->in_call=0;
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(after));
    if (after-before>q->max_ticks) q->max_ticks=after-before;
    q->served++;
    boot_relay_answer(q,ticket,result);
}
/* q1n1's CPU until the target can no longer execute monitor code. */
static void boot_relocation_wait(struct context *c, struct boot_relocation *r, int live)
{
    uint64_t hz=c->params->clock_host_hz,queried=0;
    struct boot_wait w={.off=-1,.launched=r->launch_tick,.arrival=hz,
                        .session=(c->params->watchdog_seconds+60)*hz};
    for (;;) {
        uint64_t ticket;
        if (boot_relay_take(&r->relay,&ticket)) boot_relay_serve(c,r,ticket,live);
        w.phase=__atomic_load_n(&r->record.phase,__ATOMIC_ACQUIRE);
        __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(w.now));
        w.stopped=guest_service_stopped(&c->services)!=0;
        /* AFFINITY_INFO only where it decides, at most once a millisecond. */
        if ((w.phase==4 || (!w.phase && w.now-w.launched>=w.arrival)) && w.now-queried>=hz/1000) {
            w.off=secondary_psci(0xc4000004,r->record.affinity,0,0);
            queried=w.now;
        }
        r->wait_polls++;
        switch (boot_relocate_wait(&w)) {
        case BOOT_WAIT_HANDBACK:
            r->record.affinity_result=(uint64_t)w.off;
            return;
        case BOOT_WAIT_STOP:
            r->stop_requested++;
            guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
            break;
        case BOOT_WAIT_QUARANTINE:
            /* As the report for a peer that never quiesced: never return to q1n1. */
            r->quarantined=1;
            guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
            for (;;) __asm__ volatile("yield":::"memory");
        case BOOT_WAIT_SERVE:
            break;
        }
        __asm__ volatile("yield":::"memory");
    }
}
/* The target is OFF (or never started): q1n1's own registers back into vCPU
 * 0's record for the report, and a prepare result if the guest never ran. */
static void boot_relocation_handback(struct context *c, struct boot_relocation *r)
{
    struct vcpu *v=&c->vcpus[0];
    if (r->captured) {
        const uint64_t *h=r->host;
        v->save_vttbr=h[0];v->save_vtcr=h[1];v->save_vmpidr=h[2];v->save_cntkctl=h[3];
        v->save_cnthctl=h[4];v->save_mdcr=h[5];v->save_mdscr=h[6];v->dbg_oslsr=h[7];
        v->save_ttbr0=h[8];v->save_ttbr1=h[9];v->save_mair=h[10];
    }
    /* A fault inside a relayed q1n1 call ended the run: never re-enter it. */
    if (r->relay.in_call) c->early_stop.host_in_call=1;
    uint64_t *out=(uint64_t *)v->out_ptr;
    if (!out[0] && !out[1]) {
        const struct secondary *s=&r->record;
        out[0]=(uint64_t)(int64_t)(!r->launched ? BOOT_RELOCATE_E_CPU_ON :
            !s->phase ? BOOT_RELOCATE_E_ARRIVAL :
            (int64_t)s->prepare_result<0 ? (int64_t)s->prepare_result : BOOT_RELOCATE_E_TARGET);
    }
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(r->handback_tick));
    __atomic_store_n(&r->handed_back,1,__ATOMIC_RELEASE);
}
/* From _start after the shared preparation: 0 when vCPU 0 stays here (no
 * request); otherwise launch it on the target, serve until it is OFF, hand
 * back, and return 1 for the exit path's report. */
int xnuboot_boot_relocate(void);
int xnuboot_boot_relocate(void)
{
    struct context *c=context_of();
    struct boot_relocation *r=boot_relocation_of(c);
    if (!r) return 0;
    struct secondary *s=&r->record;
    s->affinity_result=(uint64_t)secondary_psci(0xc4000004,s->affinity,0,0);
    if (s->affinity_result==1) {
        r->launched=1;
        publish(c->work_start,c->next_table);
        __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(r->launch_tick));
        int64_t on=secondary_psci(0xc4000003,s->affinity,(uint64_t)secondary_entry,(uint64_t)s);
        s->on_result=(uint64_t)on;   /* not record(): the target may already be logging */
        if (on) {
            /* Only a definite refusal of a CPU that is OFF rules out a start. */
            s->affinity_result=(uint64_t)secondary_psci(0xc4000004,s->affinity,0,0);
            if (s->affinity_result==1 && (on==-1 || on==-2 || on==-3 || on==-9)) r->launched=0;
        }
        if (r->launched) boot_relocation_wait(c,r,1);
    }
    boot_relocation_handback(c,r);
    return 1;
}
/* The report's first step on q1n1's CPU: normally a no-op after the handback.
 * Reached without it, this CPU took an EL2 fault while the target runs: stop
 * it, wait without calling q1n1, then hand back. */
static void boot_relocation_settle(struct context *c)
{
    struct boot_relocation *r=boot_relocation_of(c);
    if (!r || __atomic_load_n(&r->handed_back,__ATOMIC_ACQUIRE)) return;
    if (!boot_relocation_on_boot_cpu(c)) xnuboot_relocated_stop();
    if (r->launched) {
        r->stop_requested++;
        guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
        boot_relocation_wait(c,r,0);
    }
    boot_relocation_handback(c,r);
}
#endif
/* Called with the requesting executor's service token. Success means firmware accepted a real
 * launch, not that the guest completed initialization. No request is retried. */
static int secondary_launch(struct context *c,unsigned slot,uint64_t pc)
{
    unsigned caller=(unsigned)vcpu_of(c)->slot;
    if (!c->host_cpus || !c->secondary_base || !slot || slot>=6 ||
        !(c->host_cpus->mask&(1U<<slot)) || !(c->cpus.registered&(1U<<slot))) return 0;
    struct secondary *s=secondary_of(c,slot);
    if (s->phase || s->on_result!=UINT64_MAX ||
        secondary_psci(0xc4000004,s->affinity,0,0)!=1 ||
        guest_service_reserve(&c->services,caller,slot)!=SERVICE_OK) return 0;
    publish(c->work_start,c->next_table);
    int64_t result=secondary_psci(0xc4000003,s->affinity,(uint64_t)secondary_entry,(uint64_t)s);
    s->on_result=(uint64_t)result;
    record(c,EV_OTHER,pc,UINT64_C(0x534d504f),slot,(uint64_t)result);
    if (!result) return 1;
    int64_t off=secondary_psci(0xc4000004,s->affinity,0,0);
    s->affinity_result=(uint64_t)off;
    guest_service_cancel_launch(&c->services,caller,slot,result,off);
    return 0;
}
struct secondary_request { struct context *context;uint64_t pc; };
static int secondary_release(void *opaque,unsigned slot)
{
    struct secondary_request *request=opaque;
    return secondary_launch(request->context,slot,request->pc);
}
static int secondary_collect(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    if(guest_service_reusable(&c->services))return 1;
    uint64_t hz=c->params->clock_host_hz;
    if(v->slot || !c->secondary_base || hz<1000 || hz>1000000000)goto quarantine;
    uint64_t started=service_profile_clock();
    struct early_stop_state retirement_stop={0};
    const struct a16_thermal_io thermal_io={c,thermal_read,thermal_clock};
    /* CPU0 has finished its executor and its guest timer is off. Bound this
     * wait independently, retaining every unresolved owner/reservation. Only
     * CPU0 writes thermal state; a local stop record avoids shared log/state
     * writes while a peer may still own the service. */
    while (!guest_service_reusable(&c->services)) {
        uint64_t now=service_profile_clock();
        if(now-started>=hz)goto quarantine;
        int thermal_failed=c->thermal && (c->thermal->read_inflight ||
            a16_thermal_poll(c->thermal,&retirement_stop,now,hz,&thermal_io));
        for (unsigned i=1;i<6;i++) {
            uint64_t state=(guest_service_lifecycle(&c->services)>>(i*3))&7;
            if (state!=EXECUTOR_QUIESCED) continue;
            struct secondary *s=secondary_of(c,i);
            uint64_t phase=__atomic_load_n(&s->phase,__ATOMIC_ACQUIRE);
            if(phase==5)goto quarantine; /* CPU_OFF returned, never reusable. */
            if(phase!=4)continue;
            int64_t off=secondary_psci(0xc4000004,s->affinity,0,0);
            s->affinity_result=(uint64_t)off;
            if(off<0 || off>2)goto quarantine;
            if (off==1) guest_service_confirm_off(&c->services,0,i,off);
        }
        /* Still reconcile peers already physically OFF on a thermal stop;
         * do not extend the wait if any owner/reservation remains. */
        if(thermal_failed && !guest_service_reusable(&c->services))goto quarantine;
        __asm__ volatile("yield":::"memory");
    }
    return 1;
quarantine:
    v->service_fault=SERVICE_NOT_QUIESCENT;
    return 0;
}
static int secondary_wait_entry(struct context *c)
{
    if (!c->secondary_base || vcpu_of(c)->slot) return 0;
    for (unsigned i=1;i<6;i++) {
        if (!(c->host_cpus->mask&(1U<<i))) continue;
        struct secondary *s=secondary_of(c,i);
        if (s->on_result || __atomic_load_n(&s->phase,__ATOMIC_ACQUIRE)>=3) continue;
        uint64_t now,deadline;
        __asm__ volatile("mrs %0, cntpct_el0":"=r"(now));
        deadline=now+c->params->clock_host_hz;
        while (__atomic_load_n(&s->phase,__ATOMIC_ACQUIRE)<3 &&
               !guest_service_stopped(&c->services)) {
            __asm__ volatile("mrs %0, cntpct_el0":"=r"(now));
            if ((int64_t)(deadline-now)<=0) {
                vcpu_of(c)->service_fault=SERVICE_TIMEOUT;
                guest_service_stop(&c->services,0,SERVICE_STOP_FAULT);
                return 1;
            }
            __asm__ volatile("yield":::"memory");
        }
    }
    return guest_service_stopped(&c->services)!=0;
}
