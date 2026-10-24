/* SPDX-License-Identifier: MIT */
/* Trapped MMIO dispatch, device-model access, AES/SEP services, monitor
 * requests, early-stop and guest-network calls.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
/* --------------------------------------------------------------------------
 * Trapped MMIO: giving XNU back its console.
 *
 * *The story.* The kernel's device tree says there is a UART at 12.13 GiB.
 * There is not -- that is a J700 address and this is a Snapdragon -- so the
 * stage-2 map deliberately leaves those pages absent and every touch of them
 * arrives here instead of wandering onto a bus we do not own. This is where
 * they are answered. The fault syndrome already says how wide the access was,
 * which register it used and which way it went, so the instruction at the PC
 * never has to be fetched or decoded; the device model says what the register
 * holds; the guest's PC steps over the instruction and EL1 resumes none the
 * wiser. A byte written to the transmit register lands in the same console
 * buffer the host has been reading since the first SPTM_FN_SERIAL_PUTC.
 *
 * Keyed by IPA page through the windows the loader derived from the tree, not
 * by a constant: a different tree moves the UART and this still finds it.
 *
 * Strict, and loudly so. An offset the model does not answer stops the run and
 * names the window, the offset, the size and the direction, so the next one is
 * one iteration away rather than a guess. Nothing is ever read as zero because
 * we did not recognise it -- that is step F's SNAP_MMIO_INVENTORY, which is
 * labelled and counted, and doing it here would let a run get further past a
 * register we do not understand and call that progress.
 */

/* Everything the next iteration needs, in one event, and then the run stops. */
static int mmio_stop(struct context *c, uint64_t pc, uint64_t reason,
                     uint64_t window, uint64_t off, uint64_t esr, uint64_t ipa)
{
    record(c, EV_MMIO_STOP, pc, (reason << 48) | (window << 32) | off, esr, ipa);
    return 1;
}

/* Returns 1 to stop and report, 0 to step over the access and resume. */
static int mmio_dispatch(struct context *c, uint64_t *frame, uint64_t *elr,
                         uint64_t esr, uint64_t ipa, int window, uint64_t off)
{
    const struct params *p = c->params;
    uint64_t iss = esr & 0x1ffffff;
    uint64_t w = (uint64_t)window;
    struct dc_access a;

    /* The windows this model was written against. A tree whose node is a
     * different shape would have its offsets mean other things, and answering
     * them anyway is how a model becomes fiction. */
    if (!dc_shape(p->device_span, p->device_count))
        return mmio_stop(c, *elr, MMIO_STOP_SHAPE, w, off, esr, ipa);
    /* An instruction fetch out of a device page. There is no register and no
     * value to emulate, only a PC that should not be there. */
    if ((esr >> 26) != 0x24)
        return mmio_stop(c, *elr, MMIO_STOP_FETCH, w, off, esr, ipa);
    /* S1PTW: it is the stage-1 table walker that faulted, not the access. The
     * syndrome describes the access that provoked the walk, so emulating from
     * it would move the wrong register. */
    if ((iss >> 7) & 1)
        return mmio_stop(c, *elr, MMIO_STOP_S1PTW, w, off, esr, ipa);

    a = dc_decode(esr);
    if (!a.valid)
        return mmio_stop(c, *elr, MMIO_STOP_NO_ISV, w, off, esr, ipa);

    if (a.write) {
        uint8_t tx[4];
        unsigned tx_len = 0, n;
        uint64_t value = dc_narrow(&a, a.reg == 31 ? 0 : frame[a.reg]);
        if (dc_write(&c->uart, window, off, value, tx, &tx_len) != DC_OK)
            return mmio_stop(c, *elr, MMIO_STOP_OFFSET, w, off, esr, ipa);
        for (n = 0; n < tx_len; n++) {
            console_put(c, tx[n]);
            c->uart_tx++;
        }
        c->mmio_writes++;
    } else {
        /* Host input reaches the receive registers only when the launch
         * enabled the console link; otherwise dc_read_rx is dc_read. This
         * runs under the service lock, as console_link_drain does, so it
         * must stay off any lock-free fast path while the ring exists. */
        uint64_t value = 0;
        struct dc_rx *rx = (p->early_stop.flags & EARLY_STOP_F_CONSOLE) ? &c->console_link.rx : 0;
        if (dc_read_rx(&c->uart, rx, window, off, &value) != DC_OK)
            return mmio_stop(c, *elr, MMIO_STOP_OFFSET, w, off, esr, ipa);
        if (a.reg != 31)
            frame[a.reg] = dc_extend(&a, value);
        c->mmio_reads++;
    }

    /* Over the instruction we just stood in for, and back to EL1. */
    *elr += 4;
    return 0;
}

/* PTD reads and ASC messages use integer pairs, whose abort has ISV=0.
 * Validate the instruction and both stage-1 translations before consuming
 * device state. No instruction fetch or data read can reach physical MMIO. */
static enum device_result model_pair_access(struct context *c, uint64_t *frame,
    uint64_t pc, uint64_t esr, uint64_t ipa, unsigned index)
{
    const struct params *p=c->params;
    const struct device_model *model=&p->models[index];
    int write=!!(esr&(1UL<<6));
    if ((model->kind != DEVICE_MCC_PTD_COHERENT_V1 &&
         model->kind != DEVICE_PTD_PMP_ACTIVE_V1 &&
         model->kind != DEVICE_SEP_ASC_MAILBOX_V1 && model->kind != DEVICE_ANS_ASC_V1) || (pc & 3) ||
        (write && model->kind!=DEVICE_SEP_ASC_MAILBOX_V1 && model->kind!=DEVICE_ANS_ASC_V1) ||
        (vcpu_of(c)->guest_sctlr & (1UL << 25))) return DEVICE_BAD_WIDTH;
    uint64_t code=guest_pa(pc), spsr, sp, far;
    if (code < p->mem_low || code > p->mem_high-4) return DEVICE_BAD_WIDTH;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2"
                     : "=r"(spsr), "=r"(far));
    if ((spsr & 31) != 4 && (spsr & 31) != 5) return DEVICE_BAD_WIDTH;
    if (spsr & 1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    struct mmio_pair pair;
    uint32_t instruction=*(volatile uint32_t *)code;
    int decoded=write ? mmio_stp64_decode(instruction,esr,frame,sp,&pair) :
                        mmio_ldp64_decode(instruction,esr,frame,sp,&pair);
    if (!decoded ||
        (far != pair.address && far != pair.address+8)) return DEVICE_BAD_WIDTH;
    uint64_t first=guest_pa(pair.address), second=guest_pa(pair.address+8);
    if (!first || first > UINT64_MAX-15 || second != first+8 ||
        (ipa != first && ipa != second) || first < model->base ||
        first-model->base >= model->span || model->span-(first-model->base)<16)
        return DEVICE_NOT_FOUND;
    uint64_t values[2];
    if (model->kind==DEVICE_ANS_ASC_V1) {
        struct ans_ops o=ans_ops_of(c);
        if (write) for (unsigned i=0;i<2;i++) values[i]=pair.reg[i]==31 ? 0 : frame[pair.reg[i]];
        int r=ans_mailbox_pair(ans_state_of(c),&o,first-model->base,write,values);
        if (r) return (enum device_result)(0x100|r);
#if SNAP_ANS_ASYNC
        ans_async_schedule(c);
#endif
        if (!write) mmio_ldp64_complete(&pair,values,frame);
        return ans_route(c);
    }
    if (write) {
        for (unsigned i=0;i<2;i++) values[i]=pair.reg[i]==31 ? 0 : frame[pair.reg[i]];
        enum device_result result=device_model_write_pair(model,&c->model_state[index],
                                                           first-model->base,values);
        if (result==DEVICE_OK) c->model_writes[index]+=2;
        return result;
    }
    enum device_result result=device_model_read_pair(model,&c->model_state[index],
                                                      first-model->base,values);
    if (result == DEVICE_OK) {
        mmio_ldp64_complete(&pair,values,frame);
        __atomic_fetch_add(&c->model_reads[index],2,__ATOMIC_RELAXED);
    }
    return result;
}

/* The I2C error path uses a pre-indexed LDR Wt with ISV=0. Fetch and decode
 * it from guest RAM, then bind its effective address to FAR and the trapped
 * device IPA before reading the model. Base writeback happens only on success. */
static enum device_result model_preload_read(struct context *c, uint64_t *frame,
    uint64_t pc, uint64_t esr, uint64_t ipa, unsigned index)
{
    const struct params *p=c->params;
    const struct device_model *model=&p->models[index];
    if (model->kind!=DEVICE_I2C_EMPTY_V1 || (pc&3) ||
        (vcpu_of(c)->guest_sctlr&(1UL<<25))) return DEVICE_BAD_WIDTH;
    uint64_t code=guest_pa(pc), spsr, sp, far;
    if (code<p->mem_low || code>p->mem_high-4) return DEVICE_BAD_WIDTH;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2" : "=r"(spsr), "=r"(far));
    if ((spsr&31)!=4 && (spsr&31)!=5) return DEVICE_BAD_WIDTH;
    if (spsr&1) __asm__ volatile("mrs %0, sp_el1" : "=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
    struct mmio_preload load;
    if (!mmio_ldr32_pre_decode(*(volatile uint32_t *)code,esr,frame,sp,&load) ||
        far!=load.address) return DEVICE_BAD_WIDTH;
    uint64_t translated=guest_pa(load.address);
    if (!translated || translated!=ipa || translated<model->base ||
        model->span<4 || translated-model->base>model->span-4) return DEVICE_NOT_FOUND;
    uint64_t value=0;
    const struct device_power_resources resources={c,gfx_power_idle};
    enum device_result result=device_models_access_power_at(p->models,c->model_state,
        (unsigned)p->model_count,index,clock_counter(c),translated-model->base,
        4,0,&value,&resources);
    if (result==DEVICE_OK) {
        mmio_ldr32_pre_complete(&load,(uint32_t)value,frame,&sp);
        if (load.base==31) {
            if (spsr&1) __asm__ volatile("msr sp_el1, %0" :: "r"(sp));
            else __asm__ volatile("msr sp_el0, %0" :: "r"(sp));
        }
        __atomic_fetch_add(&c->model_reads[index],1,__ATOMIC_RELAXED);
    }
    return result;
}

struct aes_dma_context {
    struct context *c;
    const struct device_model *model;
    enum sptm_result refusal;
    uint64_t refused_iova;
};
static volatile uint8_t *aes_dma_map(void *opaque,uint64_t iova,size_t size,int write)
{
    struct aes_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if (device_dart_admit_frame(c->params->models,c->model_state,
        (unsigned)c->params->model_count,5,(unsigned)a->model->config[3],
        (unsigned)a->model->config[4],0,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;a->refused_iova=iova;return 0;
    }
    struct sptm_memory memory=sptm_context_memory(c);uint64_t pa;
    enum sptm_result r=sptm_dart_dma_translate(&memory,&c->model_state[index].dart,
        a->model->config[3],a->model->config[4],iova,size,write,&pa);
    if (r) {a->refusal=r;a->refused_iova=iova;return 0;}
    return memory.map(memory.ctx,pa,size);
}
static void aes_dma_publish(void *opaque,volatile uint8_t *p,size_t size)
{
    struct aes_dma_context *a=opaque;
    sptm_publish(a->c,(uint64_t)p,size);
}
struct sep_rom_dma_context {
    struct context *c;enum sptm_result refusal;
    unsigned index,pnon_refusal;uint64_t shared_iova,shared_size;
    const struct device_sep_asc *asc;
    uint64_t sks_translations;
    unsigned sks_prepared;
};
static int sep_rom_admit(void *opaque,unsigned kind,uint64_t iova,uint64_t size)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if(device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    struct sptm_memory memory=sptm_context_memory(c);
    a->refusal=sptm_sep_rom_buffer(&memory,&c->model_state[index].dart,kind,iova,size);
    return a->refusal==SPTM_OK;
}
static int sep_bootstrap_read(void *opaque,uint32_t offset,size_t size,void *out)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;
    if(!size || size>64 || offset>a->shared_size || size>a->shared_size-offset ||
       (offset&0x3fff)+size>0x4000) {a->refusal=SPTM_BAD_ADDRESS;return 0;}
    struct sptm_memory memory=sptm_context_memory(c);uint64_t pa;
    a->refusal=sptm_dart_dma_translate(&memory,&c->model_state[a->index].dart,
        20,0,a->shared_iova+offset,size,0,&pa);
    if(a->refusal)return 0;
    const volatile uint8_t *source=memory.map(memory.ctx,pa,size);
    if(!source){a->refusal=SPTM_MEMORY_UNAVAILABLE;return 0;}
    uint8_t *target=out;for(size_t i=0;i<size;i++)target[i]=source[i];
    return 1;
}
static int sep_rom_bootstrap(void *opaque,uint64_t iova,uint64_t size,struct sep_bootstrap *out)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;
    if(size!=0x14000 || device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&a->index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    struct dart_state *dart=&c->model_state[a->index].dart;
    uint64_t before=dart->translations;
    if(before>UINT64_MAX-14){a->refusal=SPTM_BAD_CONFIG;return 0;}
    struct sptm_memory memory=sptm_context_memory(c);
    a->refusal=sptm_sep_rom_buffer(&memory,dart,1,iova,size);
    if(a->refusal)return 0;
    a->shared_iova=iova;a->shared_size=size;
    const struct sep_bootstrap_reader reader={a,sep_bootstrap_read};
    if(sep_bootstrap_parse(&reader,size,out)!=SEP_BOOTSTRAP_OK ||
       out->panic_offset!=0x4000 || out->panic_size!=0x8000 ||
       out->flags_offset!=0xc000 || out->scot_offset!=0x10000) {
        if(!a->refusal)a->refusal=SPTM_BAD_CONFIG;
        dart->translations=before;return 0;
    }
    return 1;
}
static int sep_service_admit(struct sep_rom_dma_context *a,unsigned owner,
    unsigned candidate,uint64_t iova,uint64_t size,uint64_t physical[SPTM_SEP_ALL_PAGES],
    unsigned positions[2])
{
    struct context *c=a->c;
    if(owner>2 || candidate>2 || !a->asc || !sep_pnon_valid(&a->asc->pnon) ||
       !sep_xars_valid(&a->asc->xars) || !sep_sks_endpoint_valid(&a->asc->sks) ||
       a->shared_size!=0x14000 ||
       device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&a->index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    struct sptm_sep_span spans[7]={{a->shared_iova,a->shared_size,0}};
    unsigned count=1,pages=5;
    for(unsigned endpoint=0;endpoint<3;endpoint++)for(unsigned d=0;d<2;d++) {
        unsigned replace=endpoint==owner && d==candidate;
        uint64_t stage=endpoint==2 ? a->asc->sks.stage[d] : endpoint ? a->asc->xars.stage[d] : a->asc->pnon.stage[d];
        uint64_t old_iova=endpoint==2 ? a->asc->sks.iova[d] : endpoint ? a->asc->xars.iova[d] : a->asc->pnon.iova[d];
        uint64_t old_size=endpoint==2 ? a->asc->sks.size[d] : endpoint ? a->asc->xars.size[d] : a->asc->pnon.size[d];
        const uint64_t *old_physical=endpoint==2 ? a->asc->sks.physical[d] : endpoint ? a->asc->xars.physical[d] : a->asc->pnon.physical[d];
        if(endpoint==owner)positions[d]=pages;
        if(!replace && stage!=2)continue;
        spans[count++]=(struct sptm_sep_span){replace ? iova : old_iova,
            replace ? size : old_size,stage==2 ? old_physical : 0};
        pages+=(unsigned)(spans[count-1].size/0x4000);
    }
    struct sptm_memory memory=sptm_context_memory(c);
    a->refusal=sptm_sep_all_buffers(&memory,&c->model_state[a->index].dart,spans,count,physical);
    return a->refusal==SPTM_OK;
}
static int sep_pnon_bind(void *opaque,const struct sep_pnon *s,unsigned direction,
                        uint64_t iova,uint64_t size,uint64_t out[SEP_PNON_PAGES])
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(direction>1 || !a->asc || s!=&a->asc->pnon ||
       !sep_service_admit(a,0,direction,iova,size,pages,positions))return 0;
    for(unsigned i=0;i<SEP_PNON_PAGES;i++)out[i]=i<size/0x4000 ? pages[positions[direction]+i] : 0;
    return 1;
}
static int sep_pnon_query(void *opaque,const struct sep_pnon *s,uint64_t request_length)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if(device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    uint64_t before=c->model_state[index].dart.translations;
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(!a->asc || s!=&a->asc->pnon || !sep_service_admit(a,0,2,0,0,pages,positions))return 0;
    struct sptm_memory memory=sptm_context_memory(c);
    const volatile uint8_t *source=memory.map(memory.ctx,pages[positions[0]],32);
    volatile uint8_t *target=memory.map(memory.ctx,pages[positions[1]],36);
    uint8_t request[32],reply[36];int length=0;
    if(source && target) {
        for(unsigned i=0;i<32;i++)request[i]=source[i];
        /* Only the 32-byte header is read; a longer command's body stays
         * in the send buffer unread and gets the not-supported reply. */
        length=a->pnon_refusal ? sep_pnon_refuse_sized(request,request_length,reply) :
            sep_pnon_reply_sized(request,request_length,reply);
    } else a->refusal=SPTM_MEMORY_UNAVAILABLE;
    if(length) {
        for(int i=0;i<length;i++)target[i]=reply[i];
        sptm_publish(c,(uint64_t)target,(uint64_t)length);
    } else c->model_state[index].dart.translations=before;
    aes_clear(request,sizeof(request));aes_clear(reply,sizeof(reply));return length;
}
static int sep_xars_bind(void *opaque,const struct sep_xars *s,unsigned direction,
                        uint64_t iova,uint64_t size,uint64_t out[SEP_XARS_PAGES])
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(direction>1 || !a->asc || s!=&a->asc->xars ||
       !sep_service_admit(a,1,direction,iova,size,pages,positions))return 0;
    for(unsigned i=0;i<SEP_XARS_PAGES;i++)out[i]=pages[positions[direction]+i];
    return 1;
}
static int sep_xars_validate(void *opaque,const struct sep_xars *s)
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    return a->asc && s==&a->asc->xars && sep_service_admit(a,1,2,0,0,pages,positions);
}
static int sep_xars_slot(void *opaque,const struct sep_xars *s,unsigned bytes)
{
    if(bytes!=SEP_XARS_SLOT_BYTES && bytes!=SEP_XARS_EPOCH_BYTES)return 0;
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if(device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    uint64_t before=c->model_state[index].dart.translations;
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(!a->asc || s!=&a->asc->xars || !sep_service_admit(a,1,2,0,0,pages,positions))return 0;
    struct sptm_memory memory=sptm_context_memory(c);
    volatile uint8_t *target=memory.map(memory.ctx,pages[positions[1]],bytes);
    if(!target) {
        a->refusal=SPTM_MEMORY_UNAVAILABLE;
        c->model_state[index].dart.translations=before;return 0;
    }
    /* Empty virtual state at the receive-buffer start: a zero BNCN and commit
     * hash for an AP-nonce slot, or eight empty epoch slots. */
    for(unsigned i=0;i<bytes;i++)target[i]=0;
    sptm_publish(c,(uint64_t)target,bytes);
    return 1;
}
static int sep_sks_bind(void *opaque,const struct sep_sks_endpoint *s,unsigned direction,
                        uint64_t iova,uint64_t size,uint64_t out[SEP_SKS_PAGES])
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(direction>1 || !a->asc || s!=&a->asc->sks ||
       !sep_service_admit(a,2,direction,iova,size,pages,positions))return 0;
    for(unsigned i=0;i<SEP_SKS_PAGES;i++)out[i]=pages[positions[direction]+i];
    return 1;
}
static int sep_sks_prepare(void *opaque,const struct sep_sks_endpoint *s,unsigned command,
    unsigned length,struct sep_sks_wire_state *staged,uint8_t reply[SEP_SKS_REPLY_BYTES],
    uint16_t *reply_bytes,uint8_t *status)
{
    /* runtime_enter holds the guest service lock through preparation/publication.
     * A bounded shared scratch avoids a16KiB request on each EL2 stack. */
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    uint8_t *request=c->sep_sks_request;
    a->sks_prepared=0;
    if(!a->asc || s!=&a->asc->sks || device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    a->sks_translations=c->model_state[index].dart.translations;
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(!sep_service_admit(a,2,2,0,0,pages,positions))return 0;
    if(length>SEP_SKS_WIRE_MAX) {
        *reply_bytes=0;*status=SEP_SKS_MALFORMED;a->sks_prepared=1;return 1;
    }
    struct sptm_memory memory=sptm_context_memory(c);
    const volatile uint8_t *source=length ? memory.map(memory.ctx,pages[positions[0]],length) : 0;
    if(length && !source) {
        a->refusal=SPTM_MEMORY_UNAVAILABLE;
        c->model_state[index].dart.translations=a->sks_translations;return 0;
    }
    for(unsigned i=0;i<length;i++)request[i]=source[i];
    uint32_t result_bytes=0;
    *status=sep_sks_wire(staged,command,request,length,reply,SEP_SKS_REPLY_BYTES,&result_bytes);
    aes_clear(request,length);
    *reply_bytes=(uint16_t)result_bytes;a->sks_prepared=1;return 1;
}
static int sep_sks_publish(void *opaque,const struct sep_sks_endpoint *s,
                           const uint8_t *reply,uint16_t bytes)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;
    if(!a->sks_prepared || !a->asc || s!=&a->asc->sks || bytes>SEP_SKS_REPLY_BYTES) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    unsigned index=a->index;
    if(!sep_service_admit(a,2,2,0,0,pages,positions)) {
        c->model_state[index].dart.translations=a->sks_translations;return 0;
    }
    struct sptm_memory memory=sptm_context_memory(c);
    volatile uint8_t *target=bytes ? memory.map(memory.ctx,pages[positions[1]],bytes) : 0;
    if(bytes && !target) {
        a->refusal=SPTM_MEMORY_UNAVAILABLE;
        c->model_state[index].dart.translations=a->sks_translations;return 0;
    }
    for(unsigned i=0;i<bytes;i++)target[i]=reply[i];
    if(bytes)sptm_publish(c,(uint64_t)target,bytes);
    a->sks_prepared=0;return 1;
}
static int sep_entropy32(void *opaque,uint32_t *out)
{
    (void)opaque;
    uint64_t isar0,word=0;
    __asm__ volatile("mrs %0,id_aa64isar0_el1":"=r"(isar0));
    if((isar0>>60)!=1)return 0;
    /* Independent RNDR output, never the boot seed or private PAC seed.
     * As in pauth_domain_prepare, NE records RNDR's architected success.
     * Exhaustion stops the service; no deterministic/unavailable fallback. */
    for(unsigned retry=0;retry<64;retry++) {
        unsigned ok;
        __asm__ volatile("mrs %0,s3_3_c2_c4_0; cset %w1,ne"
                         :"=r"(word),"=r"(ok)::"cc");
        if(ok){*out=(uint32_t)word;aes_clear(&word,sizeof(word));return 1;}
    }
    aes_clear(&word,sizeof(word));return 0;
}
static int model_dispatch(struct context *c, uint64_t *frame, uint64_t *elr,
                          uint64_t esr, uint64_t ipa, unsigned index, uint64_t offset)
{
    const struct device_model *model = &c->params->models[index];
    struct dc_access access = dc_decode(esr);
    enum device_result result = DEVICE_BAD_WIDTH;
    if ((esr >> 26) == 0x24 && !(esr & (1UL << 7)) && access.valid) {
        uint64_t value = access.write ? dc_narrow(&access,
            access.reg == 31 ? 0 : frame[access.reg]) : 0;
        const struct device_power_resources resources={c,gfx_power_idle};
        if (model->kind==DEVICE_ANS_ASC_V1 || model->kind==DEVICE_ANS_NVME_V1) {
            struct ans_ops o=ans_ops_of(c);
            int r=ans_mmio(ans_state_of(c),&o,model->kind==DEVICE_ANS_NVME_V1,offset,
                           access.size,access.write,&value);
#if SNAP_ANS_ASYNC
            if(!r)ans_async_schedule(c);   /* timer_sync below arms the owner's deadline */
#endif
            result=r ? (enum device_result)(0x100|r) : ans_route(c);
        } else if (model->kind==DEVICE_AES_SOFTWARE_V1) {
            /* The trap-wide service lock serializes DMA with SPTM ownership
             * and DART changes. All fragments are admitted before data writes. */
            struct aes_dma_context a={.c=c,.model=model};
            const struct aes_dma dma={&a,aes_dma_map,aes_dma_publish};
            enum aes_result r=device_aes_powered(c->params->models,c->model_state,
                (unsigned)c->params->model_count,index)==DEVICE_OK ?
                aes_engine_access(&c->model_state[index].aes,&dma,
                    offset,access.size,access.write,&value) : AES_BAD_STATE;
            result=r==AES_OK ? DEVICE_OK : DEVICE_BAD_VALUE;
            if (r!=AES_OK) record(c,EV_TABLE_FAILED,*elr,
                0x4145530000000000UL|((uint64_t)r<<32)|a.refusal,a.refused_iova,value);
        } else result = device_models_access_power_at(c->params->models, c->model_state,
                (unsigned)c->params->model_count, index, clock_counter(c),
                offset, access.size, access.write, &value,&resources);
        if (result == DEVICE_OK) {
            if (access.write) {
                c->model_writes[index]++;
                /* AIC MASK_CLR: the guest finished an event; resample the line. */
                if (model->kind == DEVICE_AIC3_FLAT_V1 && offset >= 0x14600 &&
                    offset < 0x14800 && c->params->gpu.flags) {
                    struct irqfwd_ops f = fwd_ops(c);
                    irqfwd_unmasked(&c->gpu.irq, &f, (unsigned)((offset - 0x14600) / 4),
                                    (uint32_t)value);
                }
            } else {
                if (access.reg != 31) frame[access.reg] = dc_extend(&access, value);
                __atomic_fetch_add(&c->model_reads[index],1,__ATOMIC_RELAXED);
                if (model->kind==DEVICE_PMGR_CPU_PERF_BOOT_V1 &&
                    (offset==0x48 || offset==0x50)) {
                    uint64_t *w=c->model_state[index].cpu_perf_reads[(offset-0x48)/8];
                    if (w[0]!=UINT64_MAX) w[0]++;
                    w[1]=*elr;w[2]=ipa;w[3]=esr;w[4]=value;
                    w[5]=access.reg==31 ? 0 : frame[access.reg];
                    w[6]=frame[30];w[7]=vcpu_of(c)->slot;
                }
            }
        }
    } else if ((esr >> 26) == 0x24 && !(esr & (1UL << 24))) {
        if (model->kind==DEVICE_I2C_EMPTY_V1)
            result=model_preload_read(c,frame,*elr,esr,ipa,index);
        else result=model_pair_access(c,frame,*elr,esr,ipa,index);
    }
    if (result == DEVICE_OK && model->kind==DEVICE_SEP_ASC_MAILBOX_V1 && model->config[4]) {
        struct sep_rom_dma_context dma={.c=c,
            .pnon_refusal=!!(model->config[4]&16),
            .shared_iova=c->model_state[index].sep_asc.rom_shared_iova,
            .shared_size=c->model_state[index].sep_asc.rom_shared_size,
            .asc=&c->model_state[index].sep_asc};
        const struct sep_pnon_io pnon={&dma,sep_pnon_bind,sep_pnon_query};
        const struct sep_xars_io xars={&dma,sep_xars_bind,sep_xars_validate,sep_xars_slot};
        const struct sep_sks_endpoint_io sks={&dma,sep_sks_bind,sep_sks_prepare,sep_sks_publish};
        const struct device_sep_rom_resources resources={&dma,c->params->sep_firmware_size,
            sep_rom_admit,sep_rom_bootstrap,sep_entropy32,&pnon,&xars,&sks};
        result=device_sep_rom_step(model,&c->model_state[index],&resources);
        if(dma.refusal)record(c,EV_TABLE_FAILED,*elr,0x5345500000000000UL|dma.refusal,
            c->model_state[index].sep_asc.request[0][0],c->params->sep_firmware_size);
    }
    if (result == DEVICE_OK)
        result=device_models_route_irqs(c->params->models,c->model_state,
                                       (unsigned)c->params->model_count);
    if (result == DEVICE_OK) {
        vcpu_of(c)->model_irq_pending = 0;
        for (unsigned i=0; i<c->params->model_count; i++)
            vcpu_of(c)->model_irq_pending |= device_irq_pending(&c->params->models[i],
                                                       &c->model_state[i]);
        timer_sync(c);
        if (device_reset_stop(c, *elr, frame)) return 1;
        *elr += 4;
        return 0;
    }
    if (result & 0x100) record(c, EV_ANS, *elr, (uint64_t)(result & 0xff) << 32 | model->kind, ipa, esr);
    else record(c, EV_DEVICE_FAILED, *elr, (model->kind << 32) | result, ipa, esr);
    fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, ipa);
    vcpu_of(c)->async_captured = 3;
    return 1;
}

/* Returns 1 to stop and report, 0 to resume the guest. */
static int monitor_request(struct context *c, uint64_t *frame, uint64_t *elr)
{
    step_translation_clear(&c->step_translation[vcpu_of(c)->slot]);
    if (monitor_call(c, frame, elr)) return 0;
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, *elr, 0);
    vcpu_of(c)->async_captured = 2;
    if (c->last.kind != EV_RETYPE_FAILED && c->last.kind != EV_TABLE_FAILED &&
        c->last.kind != EV_UNMAP_FAILED && c->last.kind != EV_UPDATE_FAILED &&
        c->last.kind != EV_REGION_FAILED && c->last.kind != EV_REFERENCE_FAILED &&
        c->last.kind != EV_SLIDE_FAILED && c->last.kind != EV_TXM_FAILED &&
        c->last.kind != EV_MAP_FAILED && c->last.kind != EV_PANIC_STATE_FAILED &&
        c->last.kind != EV_NATIVE_SHARED_FULL)
        record(c, EV_MONITOR, *elr, frame[16], frame[0], frame[1]);
    step_arm(c, 0);
    guards_close(c);
    return 1;
}

/* ADRENO_GUEST_STOP (compat/adreno-guest.h): admitted only when the launch
 * enabled it, from EL1, and for the HVC that the loaded AuxKC's own frames
 * hold -- its one bundle is our Adreno kext. The request is recorded and
 * answered; the run continues until the deadline expires on some CPU. */
static void early_stop_hvc(struct context *c, uint64_t *frame, uint64_t elr, uint64_t spsr)
{
    const struct params *p = c->params;
    struct early_stop_state *s = &c->early_stop;
    uint64_t hvc = elr - 4, pa = guest_pa(hvc), now, accepted = 0;
    uint32_t word = 0;
    if (pa && p->auxkc.pa_end > p->auxkc.pa_base + 4 &&
        pa >= p->auxkc.pa_base && pa <= p->auxkc.pa_end - 4)
        word = *(volatile uint32_t *)pa;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(now));
    int e = early_stop_guest_admit(&p->early_stop, &p->auxkc, hvc, pa, word, spsr,
                                   frame[1], frame[2], &accepted);
    if (!e) e = early_stop_request(s, EARLY_STOP_SOURCE_GUEST, frame[1], frame[3], frame[2],
                                   accepted, now, p->clock_host_hz, (unsigned)vcpu_of(c)->slot,
                                   hvc, 0);
    else early_stop_refuse(s, e);
    record(c, EV_EARLY_STOP_REQUEST, hvc, (uint64_t)EARLY_STOP_SOURCE_GUEST << 32 | (uint32_t)frame[1],
           frame[2] << 32 | (uint32_t)frame[3], (uint64_t)(int64_t)e);
    frame[0] = (uint64_t)(int64_t)e;
    frame[1] = e < 0 ? 0 : accepted;
    frame[2] = __atomic_load_n(&s->state, __ATOMIC_ACQUIRE);
    frame[3] = p->early_stop.max_delay_s;
}

#if SNAP_GUEST_NET
/* compat/guest-net-link.h's operations: the ring's frames are held under the
 * virtual ANS's DMA rule (XNU_DEFAULT, clear metadata, a DART reference), and
 * guest RAM is the monitor's identity mapping, as every guest buffer is. */
static int guest_net_monitor_page(void *ctx, uint64_t pa)
{
    const struct context *c = ctx;
    const struct auxkc_range *kc = &c->params->auxkc;
    return (pa >= c->work_start && pa < c->work_end) || (pa >= kc->pa_base && pa < kc->pa_end);
}
static int guest_net_frame_ref(void *ctx, uint64_t pa, int release) {return ans_frame_ref(ctx, pa, 1, release);}
static volatile void *guest_net_map(void *ctx, uint64_t pa)
{
    const struct params *p = ((const struct context *)ctx)->params;
    return pa >= p->mem_low && pa < p->mem_high ? (volatile void *)(uintptr_t)pa : 0;
}
static struct guest_net_ops guest_net_ops_of(struct context *c)
{
    return (struct guest_net_ops){c, c->params->mem_low, c->params->mem_high,
                                  guest_net_monitor_page, guest_net_frame_ref, guest_net_map};
}

/* ADRENO_GUEST_NET (compat/guest-net.h): admitted only when the launch enabled
 * the network, from EL1, for the HVC the loaded AuxKC's own frames hold
 * (early_stop_guest_caller, as ADRENO_GUEST_STOP). Under the service lock. */
static void guest_net_hvc(struct context *c, uint64_t *frame, uint64_t elr, uint64_t spsr)
{
    const struct params *p = c->params;
    struct guest_net_link *l = &c->guest_net->link;
    const struct guest_net_ops o = guest_net_ops_of(c);
    uint64_t hvc = elr - 4, pa = guest_pa(hvc), generation = 0;
    uint32_t word = 0;
    if (pa && p->auxkc.pa_end > p->auxkc.pa_base + 4 &&
        pa >= p->auxkc.pa_base && pa <= p->auxkc.pa_end - 4)
        word = *(volatile uint32_t *)pa;
    int e;
    if (!(p->early_stop.flags & EARLY_STOP_F_NET) || !(p->early_stop.flags & EARLY_STOP_F_HOST))
        e = guest_net_refuse(l, GUEST_NET_E_DISABLED);
    else if (early_stop_guest_caller(&p->auxkc, hvc, pa, word, spsr))
        e = guest_net_refuse(l, GUEST_NET_E_ORIGIN);
    else if (frame[1] == GUEST_NET_ATTACH)
        e = guest_net_attach(l, &o, frame[2], frame[3], &generation);
    else if (frame[1] == GUEST_NET_DETACH) {
        guest_net_detach(l, &o);
        e = 0;
    } else
        e = guest_net_refuse(l, GUEST_NET_E_OP);
    record(c, EV_GUEST_NET, hvc, frame[1], frame[2], (uint64_t)(uint32_t)e << 32 | (uint32_t)generation);
    int attached = !e && frame[1] == GUEST_NET_ATTACH;
    frame[0] = (uint64_t)(int64_t)e;
    frame[1] = attached ? GUEST_NET_LINK_UP : 0;
    frame[2] = attached ? GUEST_NET_MTU : 0;
    frame[3] = attached ? generation : 0;
}
#endif

#if SNAP_EDP_BACKLIGHT
/* compat/edp-backlight.c reaches the eDP controller and dispcc through these, physical addresses in q1n1's EL2
 * identity map (Device memory, as the thermal guard's reads). The engine admits only its allow-list
 * (edp_bl_mmio_read_ok/edp_bl_mmio_write_ok, proven by tools/test-edp-backlight.c); the barrier orders each access
 * before the next, as the controller's FIFO protocol needs. */
static int edp_backlight_read(void *ctx, uint64_t pa, uint32_t *value)
{
    (void)ctx;
    *value = *(const volatile uint32_t *)pa;
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}
static int edp_backlight_write(void *ctx, uint64_t pa, uint32_t value)
{
    (void)ctx;
    *(volatile uint32_t *)pa = value;
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}
static uint64_t edp_backlight_clock(void *ctx) {(void)ctx; return service_profile_clock();}

/* ADRENO_GUEST_BACKLIGHT (compat/edp-backlight.h): admitted from EL1 for the HVC the loaded AuxKC's own bytes hold
 * (early_stop_guest_caller, as ADRENO_GUEST_STOP). Under the service lock: one AUX transaction at a time, each
 * bounded by hz / EDP_BL_AUX_BUDGET_DIV. */
static void edp_backlight_hvc(struct context *c, uint64_t *frame, uint64_t elr, uint64_t spsr)
{
    const struct params *p = c->params;
    const struct edp_backlight_io io = {c, edp_backlight_read, edp_backlight_write, edp_backlight_clock,
                                        p->clock_host_hz};
    uint64_t hvc = elr - 4, pa = guest_pa(hvc), r[4] = {frame[0], frame[1], frame[2], frame[3]};
    uint32_t word = 0;
    if (pa && p->auxkc.pa_end > p->auxkc.pa_base + 4 && pa >= p->auxkc.pa_base && pa <= p->auxkc.pa_end - 4)
        word = *(volatile uint32_t *)pa;
    if (early_stop_guest_caller(&p->auxkc, hvc, pa, word, spsr)) {
        r[0] = (uint64_t)(int64_t)EDP_BL_E_ORIGIN;
        r[1] = r[2] = r[3] = 0;
    } else
        edp_backlight_call(c->edp_backlight, &io, r);
    record(c, EV_EDP_BACKLIGHT, hvc, frame[1] << 32 | (uint32_t)frame[2], r[0] << 32 | (uint32_t)r[3], r[1]);
    for (unsigned n = 0; n < 4; n++) frame[n] = r[n];
}
#endif

