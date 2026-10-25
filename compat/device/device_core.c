/* SPDX-License-Identifier: MIT */
/* Model validation, start and reset, timed access, memory-controller (MCC/DCS/PTD) models and
 * paired reads.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */
static uint64_t gpio_route(const struct device_model *d, unsigned index)
{
    if (d->kind == DEVICE_GPIO_UART_RX_IDLE_V1)
        return index < 2 ? d->config[3+index] : 0;
    if (d->kind == DEVICE_GPIO_IDLE_INPUTS_V1 && index < 6)
        return (d->config[3+index/3] >> (18*(index%3))) & 0x3ffff;
    if (d->kind == DEVICE_GPIO_IDLE_PADS_V2 && index < 8) {
        uint64_t raw=(d->config[3+index/4] >> (11*(index%4))) & 0x7ff;
        return (raw&0x1ff) | ((raw>>9)<<16);
    }
    return 0;
}

static int gpio_idle_input(const struct device_model *d, unsigned pin, unsigned mux)
{
    uint64_t route=(pin+1) | ((uint64_t)mux << 16);
    for (unsigned i=0; i<8; i++) if (gpio_route(d,i) == route) return 1;
    return 0;
}

static int valid(const struct device_model *d)
{
    if (!d || !d->span || ((d->base | d->span) & 0xfff) ||
        d->base >= (1UL << 36) || d->span > (1UL << 36) - d->base)
        return 0;
    if (d->kind == DEVICE_MCC_COHERENT_V1) {
        if (!d->config[0] || d->config[0] > 4 ||
            d->span < (d->config[0]-1)*0x40000 + 0x2e008 ||
            d->span < 0x102804) return 0;
    } else if (d->kind == DEVICE_MCC_DCS_COHERENT_V1) {
        if (d->config[0] || d->span < 0x4070) return 0;
    } else if (d->kind == DEVICE_MCC_SOCNI_V1) {
        if (!d->config[0] || d->config[0] > 64 ||
            d->span < 0x4000 + 8*d->config[0]) return 0;
    } else if (d->kind == DEVICE_WATCHDOG_WD1_V1) {
        if (!d->config[0] || d->config[0] > UINT32_MAX) return 0;
    } else if (d->kind == DEVICE_WATCHDOG_SMC_DISARM_V1) {
        if (d->span!=0x1000 || d->config[0]!=8) return 0;
    } else if (d->kind == DEVICE_AOP_TIMEBASE_V1) {
        if (d->span != 0x1000 || d->config[0] != 24000000) return 0;
    } else if (d->kind == DEVICE_PMGR_ACTIVE_BOOT_V1) {
        if (d->config[0]>1 || d->span!=(d->config[0] ? 0x9000UL : 0x11000UL)) return 0;
        return d->config[1]<=(d->config[0] ? 0 : DEVICE_PMGR_CPU0_BOOT_V1) &&
            !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_PMGR_AON_FUSES_V1) {
        if (d->config[0] || d->span!=0x4000) return 0;
    } else if (d->kind == DEVICE_PMGR_CPU_PERF_BOOT_V1) {
        if (d->config[0]>1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_DVMR_WEIGHTS_V1) {
        if (d->config[0]>1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_AON_COUNTER_CONFIG_V1) {
        if ((d->config[0]!=6 && d->config[0]!=7) || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_SOC_PERF_RESTORE_V1) {
        if (d->config[0]>5 || d->span!=(d->config[0]==0 ? 0x2000UL :
                d->config[0]==1 ? 0x3000UL : 0x1000UL)) return 0;
    } else if (d->kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1) {
        if (d->config[0]>1 || d->span!=0x2000) return 0;
    } else if (d->kind == DEVICE_PMGR_ACC_BOOT_POLICY_V1) {
        if (d->config[0]>1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_LLT_DISABLED_V1) {
        if (d->base!=0x300740000 || d->span!=0x1000 || d->config[0]) return 0;
    } else if (d->kind == DEVICE_CORESIGHT_LOCK_V1) {
        uint64_t cpu=d->config[0];
        if (cpu>5 || d->span!=0x1000 || d->base !=
            (cpu<4 ? 0x210010000UL+cpu*0x100000 :
                     0x211010000UL+(cpu-4)*0x100000)) return 0;
    } else if (d->kind == DEVICE_QSPI_BOOT_V1) {
        if (d->span!=0x5000 || d->config[0]) return 0;
    } else if (d->kind == DEVICE_DWI_STARTUP_V1) {
        if (d->base!=0x300200000 || d->span!=0x4000 || d->config[0]) return 0;
    } else if (d->kind == DEVICE_I2C_EMPTY_V1) {
        return d->base==0x385018000UL && d->span==0x4000 &&
            d->config[0]==2 && d->config[1]==6 && d->config[2]==1110 &&
            !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_SEP_ASC_MAILBOX_V1) {
        return d->base==0x282600000UL && d->span==0x9000 &&
            d->config[0]==DEVICE_SEP_ASC_MESSAGES &&
            d->config[1]<=1 && d->config[2]==(d->config[1] ? 346 : 0) &&
            d->config[3]==(d->config[1] ? 343 : 0) &&
            (!d->config[4] || (d->config[1] &&
                (d->config[4]==1 || d->config[4]==3 || d->config[4]==7 ||
                 d->config[4]==11 || d->config[4]==15 ||
                 d->config[4]==19 || d->config[4]==27 || d->config[4]==59)));
    } else if (d->kind == DEVICE_PMGR_AP_WAKE_MASK_V1) {
        if (d->config[0] || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PTD_IRQ_CONFIG_V1) {
        if (d->config[0] || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1) {
        if (d->config[0]>DEVICE_PMGR_AVE_CLUSTER_V1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_ENERGY_RESTORE_V1 ||
               d->kind == DEVICE_PMGR_AVE_TVM_IDLE_V1 ||
               d->kind == DEVICE_PMGR_SOC_GATE_POLICY_V1 ||
               d->kind == DEVICE_PMGR_AXI2AF_POLICY_V1 ||
               d->kind == DEVICE_PMC_ENABLE_POLICY_V1 ||
               d->kind == DEVICE_PMC_RMBS_REQUEST_V1) {
        if (d->config[0] || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_SOC_DPE_POLICY_V1) {
        if (d->config[0] || d->span!=0x3000) return 0;
    } else if (d->kind == DEVICE_PMC_DVMR_CONFIG_V1) {
        if (d->config[0] || d->span!=0x6000) return 0;
    } else if (d->kind == DEVICE_DART_T8110_V1) {
        return (d->span==0xc000 || d->span==0x20000) &&
            d->config[0] && d->config[0]<=DART_STREAMS &&
            (d->config[1]==44 || (d->config[1]==DEVICE_DART_SIO_BOOT_V1 &&
                d->config[0]==16 && d->span==0x20000 && d->config[4] &&
                !(d->config[4]&(d->config[4]-1))) ||
             (d->config[1]==DEVICE_DART_SEP_BOOT_V1 && d->base==0x280b80000UL &&
                d->span==0x20000 && d->config[0]==3 && d->config[2]==353 &&
                d->config[4]==(1U<<20)) ||
             (d->config[1]==DEVICE_DART_ADRENO_BOOT_V1 && d->span==0x20000 &&
                d->config[0]==16 && d->config[4]==(1UL<<31)) ||
             (d->config[1]==DEVICE_DART_ANE_INIT_V1 &&
                ((d->base==0x401800000UL && d->span==0xc000) ||
                 ((d->base==0x401820000UL || d->base==0x401840000UL) && d->span==0x20000)) &&
                d->config[0]==16 && d->config[2]==656 && d->config[4]==1)) &&
            d->config[2]<AIC_MAX_IRQS && d->config[3]==36 && !(d->config[4]>>32);
    } else if (d->kind == DEVICE_SPMI_GEN3_EMPTY_V1 || d->kind == DEVICE_SPMI_PMU_RTC_V1) {
        return d->config[0] >= 0x8000 && !(d->config[0] & 0x3fff) &&
            d->config[0] <= d->span && d->span-d->config[0] == 0x4000 &&
            d->config[1] >= 0x4000 && !(d->config[1] & 0x3fff) &&
            d->config[1] <= d->config[0]-0x4000 && d->config[2] < AIC_MAX_IRQS &&
            (d->kind == DEVICE_SPMI_GEN3_EMPTY_V1 ?
             d->config[3] == DEVICE_SPMI_FIFO_MAX && d->config[4] == DEVICE_SPMI_FIFO_MAX :
             d->base == UINT64_C(0x308700000) && d->config[0] == 0x14000 &&
             d->config[1] == 0x4000 && d->config[2] == 487 && d->config[3] <= PMU_RTC_LIMIT_US &&
             d->config[4] == PMU_RTC_CONTRACT);
    } else if (d->kind == DEVICE_GPIO_QUIET_V1 || d->kind == DEVICE_GPIO_UART_RX_IDLE_V1 ||
               d->kind == DEVICE_GPIO_IDLE_INPUTS_V1 || d->kind == DEVICE_GPIO_IDLE_PADS_V2) {
        int route=!d->config[3] && !d->config[4];
        if (d->kind != DEVICE_GPIO_QUIET_V1) {
            route=gpio_route(d,0) != 0;
            if (d->kind == DEVICE_GPIO_IDLE_INPUTS_V1 &&
                ((d->config[3] | d->config[4]) >> 54)) route=0;
            if (d->kind == DEVICE_GPIO_IDLE_PADS_V2 &&
                ((d->config[3] | d->config[4]) >> 44)) route=0;
            for (unsigned i=0; i<8; i++) if (gpio_route(d,i)) {
                uint64_t word=gpio_route(d,i), pin=word & 0xffff, mux=word >> 16;
                route &= pin && pin <= d->config[0] && mux >= 1 && mux <= 3;
                for (unsigned j=0; j<i; j++)
                    if ((gpio_route(d,j) & 0xffff) == pin) route=0;
            }
        }
        return d->config[0] && d->config[0] <= DEVICE_GPIO_PINS_MAX &&
            d->config[1] && d->config[1] <= 7 && d->config[2] &&
            !(d->config[2] >> d->config[1]) && route &&
            d->span >= 0x800 + d->config[1]*0x40;
    } else if (d->kind == DEVICE_DOCK_ABSENT_V1) {
        uint64_t mask=d->config[1];
        return d->span == 0x1000 && !(d->config[0] & 3) &&
            d->config[0] <= d->span-4 && mask && mask <= UINT32_MAX &&
            !(mask & (mask-1)) && !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_DOCK_FIFO_V1) {
        /* Single channel, six audited t8002 windows. Holes stay trapped. */
        return d->span == 0x35000 && d->config[0] == 0x14000 &&
            d->config[1] == 0x28000 && d->config[2] < AIC_MAX_IRQS &&
            d->config[3] == DEVICE_DOCK_FIFO_MAX && !d->config[4];
    } else if (d->kind == DEVICE_SOCNI_ERRORS_V1) {
        return d->span == 0x4000 && d->config[0] < 6 && !d->config[1] &&
            !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_PLATFORM_ERROR_POLICY_V1) {
        return ((d->span == 0x1000 && d->config[0] == 0x104 && d->config[1] == 1) ||
                (d->span == 0x20000 && d->config[0] == 0x4084 && !d->config[1])) &&
               !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_AES_IDLE_V1) {
        return d->span==0x4000 && d->config[0]==5 && !d->config[1] &&
            !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_AES_SOFTWARE_V1) {
        return d->span==0x4000 && d->config[0]==5 && d->config[1]==42 &&
            d->config[2]==1107 && d->config[3]==21 && d->config[4]==1;
    } else if (d->kind == DEVICE_AES_NO_KEYS_V1) {
        /* config[4]: zero, or PMGR's BPR word, aligned, inside, never a key word. */
        if (d->config[4] && ((d->config[4] & 3) || d->config[4] > d->span-4)) return 0;
        for (unsigned i=0; i<4; i++) {
            if ((d->config[i] & 3) || d->config[i] > d->span-4 ||
                (d->config[4] && d->config[i] == d->config[4])) return 0;
            for (unsigned j=0; j<i; j++)
                if (d->config[i] == d->config[j]) return 0;
        }
        return 1;
    } else if (d->kind == DEVICE_PTD_PMP_ACTIVE_V1) {
        /* Pinned single-instance AP voter 0 plus the MCC transport. */
        return d->span==0x14000 && d->config[0]==0x10000 &&
            d->config[1]==0x1a8 && d->config[2]==0x1b8 && d->config[3]==8 &&
            d->config[4]==DEVICE_PMP_ACTIVE_MASK;
    } else if (d->kind == DEVICE_MCC_PTD_COHERENT_V1) {
        uint64_t update=d->config[0], request=d->config[1];
        uint64_t reply=d->config[2], quotas=d->config[3];
        /* One state owns both apertures. The intervening gap is not a
         * register bank and access to it remains an explicit refusal. */
        return update >= 0x4000 && !(update & 0xfff) &&
            update <= d->span && d->span-update == 0x4000 &&
            quotas && quotas <= 8 && request <= 1024-quotas-2 &&
            reply <= 1024-quotas-1 &&
            (request+quotas+2 <= reply || reply+quotas+1 <= request) &&
            !d->config[4];
    } else if (d->kind == DEVICE_ANS_ASC_V1 || d->kind == DEVICE_ANS_NVME_V1) {
        int nvme=d->kind == DEVICE_ANS_NVME_V1;
        return d->base==(nvme ? 0x38dcc0000UL : 0x389600000UL) &&
            d->span==(nvme ? 0x60000UL : 0x9000UL) && d->config[0] &&
            !(d->config[0]&0x3fff) && d->config[0] < (1UL<<36)-ANS_DISK_OFFSET-ANS_DISK_MAX &&
            (nvme ? d->config[2]==1039 &&
                    (d->config[3]==ANS_WINDOW_MODE ?     /* full-install M6: the SSD window */
                     !(d->config[0]&0xfffff) && d->config[1]>=(1UL<<30) && !(d->config[1]&0xfffff) :
                     !d->config[3] && d->config[1] && !(d->config[1]&0xfff) && d->config[1]<=ANS_DISK_MAX) :
                    d->config[1]==1010 && d->config[2]==1007 && !d->config[3]) &&
            !d->config[4];
    } else if (d->kind == DEVICE_AIC3_FLAT_V1) {
        /* Single virtual die; fixed capacity preserves the audited 0x4a00
         * bank stride. EVENT placement is published to the guest DT. */
        return d->config[0] && d->config[0] <= 4096 &&
            !(d->config[0] & 31) && d->config[1] == 4096 &&
            d->config[2] >= 0x14a00 && !(d->config[2] & 3) &&
            d->config[2] <= d->span - 4 && d->config[3] == 0xa && !d->config[4];
    } else return 0;
    for (unsigned i=1; i<5; i++) if (d->config[i]) return 0;
    return 1;
}

static int overlaps(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{
    if (!m) return 0;
    /* Difference form avoids wrapping either end. */
    return a >= b ? a-b < m : b-a < n;
}

enum device_result device_latch_resets(const struct device_model *models,
    const struct device_state *states, unsigned count,
    uint64_t bitmap[DEVICE_RESET_WORDS])
{
    if (!bitmap || count>DEVICE_MODEL_MAX || (count && (!models || !states)))
        return DEVICE_BAD_CONFIG;
    for (unsigned i=0;i<count;i++) if (!valid(&models[i])) return DEVICE_BAD_CONFIG;
    for (unsigned i=0;i<count;i++) if (device_reset_pending(&models[i],&states[i]))
        bitmap[i/64] |= 1UL<<(i%64);
    return DEVICE_OK;
}

static int cpu_boot_registry(const struct device_model *models, unsigned count)
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 2 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL) ||
                (!m->config[0] && m->config[1]!=DEVICE_PMGR_CPU0_BOOT_V1)) return 0;
            found|=bit;
        }
        if (m->kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1) {
            if ((found&4) || !valid(m) || m->base!=0x300780000) return 0;
            found|=4;
        }
    }
    return found==7;
}

int device_models_boot_cpu_valid(const struct device_model *models, unsigned count,
                                uint64_t boot_mpidr)
{
    if (!models || !count || count>DEVICE_MODEL_MAX) return 0;
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && models[i].config[1])
            return boot_mpidr==0x80000000 && cpu_boot_registry(models,count);
    return 1;
}

static int ave_registry_valid(const struct device_model *models, unsigned count);

int device_models_valid(const struct device_model *models, uint64_t count,
                        const struct device_range *exclude, uint64_t excluded)
{
    if (count > DEVICE_MODEL_MAX || (count && !models) || (excluded && !exclude))
        return 0;
    for (uint64_t j=0; j<excluded; j++)
        if (exclude[j].span > UINT64_MAX-exclude[j].base) return 0;
    for (uint64_t i=0; i<count; i++) {
        if (!valid(&models[i])) return 0;
        if ((models[i].kind==DEVICE_PMGR_AVE_TVM_IDLE_V1 ||
             (models[i].kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 && models[i].config[0])) &&
            !ave_registry_valid(models,(unsigned)count)) return 0;
        if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && models[i].config[1] &&
            !cpu_boot_registry(models,(unsigned)count)) return 0;
        if (models[i].kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            /* PMP actual states come from both registered PMGR banks.
             * AVD has registry-owned power/vote transitions; other covered
             * systems remain active. Encoder/ISP child subdomains are not
             * PMP rows and cannot independently change a system ACK. */
            unsigned groups=0;
            for (uint64_t j=0;j<count;j++)
                if (models[j].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && valid(&models[j]) &&
                    models[j].base==(models[j].config[0] ? 0x308280000UL : 0x300700000UL))
                    groups|=1U<<(unsigned)models[j].config[0];
            if (groups!=3) return 0;
        }
        if (models[i].kind==DEVICE_ANS_ASC_V1 || models[i].kind==DEVICE_ANS_NVME_V1) {
            /* Exactly one pair, sharing one reservation that misses every
             * guest, framebuffer, work and device range. */
            unsigned pair=0;uint64_t span=0;
            for (uint64_t j=0;j<count;j++)
                if (models[j].kind==DEVICE_ANS_ASC_V1 || models[j].kind==DEVICE_ANS_NVME_V1) {
                    if (models[j].config[0]!=models[i].config[0]) return 0;
                    pair+=models[j].kind==DEVICE_ANS_ASC_V1 ? 1 : 16;
                    if (models[j].kind==DEVICE_ANS_NVME_V1)
                        span=models[j].config[3]==ANS_WINDOW_MODE ? ANS_WINDOW_BYTES :
                             ANS_DISK_OFFSET+models[j].config[1];
                }
            if (pair!=17) return 0;
            for (uint64_t j=0; j<excluded; j++)
                if (overlaps(models[i].config[0], span,
                             exclude[j].base, exclude[j].span)) return 0;
        }
        for (uint64_t j=0; j<i; j++)
            if (overlaps(models[i].base, models[i].span, models[j].base, models[j].span))
                return 0;
        for (uint64_t j=0; j<excluded; j++)
            if (overlaps(models[i].base, models[i].span, exclude[j].base, exclude[j].span))
                return 0;
    }
    return 1;
}

int device_model_find(const struct device_model *models, uint64_t count,
                      uint64_t ipa, uint64_t *offset)
{
    if (!models || count > DEVICE_MODEL_MAX || !offset) return -1;
    for (uint64_t i=0; i<count; i++)
        if (ipa >= models[i].base && ipa-models[i].base < models[i].span) {
            *offset=ipa-models[i].base;
            return (int)i;
        }
    return -1;
}

enum device_result device_model_access(const struct device_model *model,
    uint64_t offset, unsigned width, int write, uint64_t *value)
{
    return device_model_access_state(model, 0, offset, width, write, value);
}

enum device_result device_model_start(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t frequency)
{
    if (!valid(model) || !state) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_AES_NO_KEYS_V1) {
        for (unsigned i=0;i<4;i++) state->aes_key_disable_writes[i]=0;
        state->aes_pmgr_bpr=state->aes_pmgr_bpr_reads=state->aes_pmgr_bpr_writes=0;
    }
    if (model->kind == DEVICE_AES_SOFTWARE_V1) {
        volatile uint8_t *p=(volatile uint8_t *)&state->aes;
        for (unsigned i=0;i<sizeof(state->aes);i++) p[i]=0;
        state->aes.ready=1;
    }
    if (model->kind == DEVICE_AES_IDLE_V1) {
        state->aes_idle.ready=1;
        state->aes_idle.running=state->aes_idle.irq_enable=state->aes_idle.fifo_threshold=0;
        state->aes_idle.starts=state->aes_idle.stops=0;
        state->aes_idle.reads=state->aes_idle.writes=0;
    }
    if (model->kind == DEVICE_DART_T8110_V1) dart_init(&state->dart);
    if (model->kind == DEVICE_PMGR_ACTIVE_BOOT_V1) {
        for (unsigned i=0;i<128;i++) state->pmgr_policy[i]=0;
        for (unsigned i=0;i<10;i++) state->pmgr_venc[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<13;i++) state->pmgr_isp[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<3;i++) state->pmgr_atc[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<2;i++) state->pmgr_dpa[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<5;i++) state->pmgr_spi[i]=state->pmgr_i2c[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<5;i++) state->pmgr_aux[i]=model->config[0] ? 0 : 15;
        state->pmgr_ane=model->config[0] ? 0 : 15;
        state->pmgr_avd=model->config[0] ? 0 : 15;
        state->pmgr_isp_sys=model->config[0] ? 0 : 15;
        state->pmgr_prores=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<2;i++) state->pmgr_venc_sys[i]=model->config[0] ? 0 : 15;
        state->pmgr_msr=state->pmgr_jpg=model->config[0] ? 0 : 15;
        state->pmgr_gfx=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<3;i++) state->pmgr_misc[i]=model->config[0] ? 0 : 15;
        state->pmgr_sep_aon=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<8;i++)
            state->pmgr_cpu_boot[i]=model->config[1] && (i==0 || i>=6) ? 0xf0 : 0;
        state->pmgr_cpu_reads=state->pmgr_cpu_writes=0;
        state->pmgr_aes=model->config[0] ? 0 : 15;
    }
    if (model->kind == DEVICE_PMGR_AON_COUNTER_CONFIG_V1)
        for (unsigned i=0;i<70;i++) state->pmgr_counter_config[i]=0;
    if (model->kind == DEVICE_PMGR_SOC_PERF_RESTORE_V1) {
        for (unsigned i=0;i<296;i++) state->pmgr_perf.control[i]=0;
        for (unsigned i=0;i<39;i++) state->pmgr_perf.extra[i]=0;
        for (unsigned i=0;i<295;i++) state->pmgr_perf.written[i]=0;
        for (unsigned i=0;i<256;i++) state->counter[i/64][i%64]=0;
    }
    if (model->kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1) {
        for (unsigned i=0;i<72;i++) state->acc_perf.values[i]=0;
        state->acc_perf.written[0]=state->acc_perf.written[1]=0;
    }
    if (model->kind == DEVICE_PMGR_ENERGY_RESTORE_V1) {
        state->energy_restore.values[0]=state->energy_restore.values[1]=0;
        state->energy_restore.written=0;
    }
    if (model->kind == DEVICE_PMGR_DVMR_WEIGHTS_V1)
        state->pmgr_energy_control=0;
    if (model->kind == DEVICE_PMGR_ACC_BOOT_POLICY_V1) {
        state->acc_boot_policy=0;
        state->acc_selector_written=0;
        for (unsigned i=0;i<10;i++) state->acc_selectors[i]=0;
    }
    if (model->kind == DEVICE_PMGR_LLT_DISABLED_V1)
        state->pmgr_llt_limit=0;
    if (model->kind == DEVICE_CORESIGHT_LOCK_V1)
        state->coresight_unlocked=0;
    if (model->kind == DEVICE_QSPI_BOOT_V1) {
        for (unsigned i=0;i<DEVICE_QSPI_FIFO_WORDS;i++)
            state->qspi.tx[i]=state->qspi.rx[i]=0;
        state->qspi.tx_count=state->qspi.rx_count=state->qspi.resets=0;
        state->qspi.ready=1;
    }
    if (model->kind == DEVICE_DWI_STARTUP_V1) {
        for (unsigned i=0;i<5;i++) state->dwi.values[i]=0;
        state->dwi.written=0;
        state->dwi.ready=1;
    }
    if (model->kind == DEVICE_I2C_EMPTY_V1) {
        state->i2c=(struct device_i2c_empty){0};
        state->i2c.ready=1;
    }
    if (model->kind == DEVICE_SEP_ASC_MAILBOX_V1) {
        /* Keep reset freestanding as this structure grows: an aggregate
         * assignment otherwise lowers to an unavailable libc memset. */
        volatile unsigned char *bytes=(volatile unsigned char *)&state->sep_asc;
        for (unsigned i=0;i<sizeof(state->sep_asc);i++) bytes[i]=0;
        state->sep_asc.ready=1;
        state->sep_asc.enable[0]=1; /* Requests can enter the retained queue. */
    }
    if (model->kind == DEVICE_PMGR_AP_WAKE_MASK_V1)
        for (unsigned i=0;i<8;i++)
            state->pmgr_wake_mask[i]=i==7 ? 0x1fffff : UINT32_MAX;
    if (model->kind == DEVICE_PMGR_SOC_GATE_POLICY_V1)
        for (unsigned i=0;i<4;i++) state->pmgr_soc_gate[i]=0;
    if (model->kind == DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 && model->config[0])
        state->pmgr_ave_cluster=15;
    if (model->kind == DEVICE_PMGR_SOC_DPE_POLICY_V1)
        for (unsigned i=0;i<30;i++) state->pmgr_soc_dpe[i]=0;
    if (model->kind == DEVICE_PMGR_AXI2AF_POLICY_V1)
        for (unsigned i=0;i<2;i++) state->pmgr_axi2af[i]=0;
    if (model->kind == DEVICE_PMC_ENABLE_POLICY_V1)
        for (unsigned i=0;i<7;i++) state->pmc_enable[i]=0;
    if (model->kind == DEVICE_PMC_RMBS_REQUEST_V1)
        state->pmc_rmbs.value=state->pmc_rmbs.valid=0;
    if (model->kind == DEVICE_PMC_DVMR_CONFIG_V1) {
        state->pmc_dvmr.enabled=0;
        state->pmc_dvmr.count=state->pmc_dvmr.count_valid=0;
        /* The virtual reset starts both encoder systems active. Their
         * shared cluster is therefore active until admitted shutdown. */
        state->pmc_dvmr.venc_cluster=8;
    }
    if (model->kind == DEVICE_PTD_IRQ_CONFIG_V1) {
        for (unsigned i=0;i<256;i++) state->ptd_irq.route[i]=0;
        for (unsigned i=0;i<32;i++) state->ptd_irq.enabled[i]=0;
    }
    if (model->kind == DEVICE_PTD_PMP_ACTIVE_V1) {
        state->pmp_active.request=0;
        state->pmp_active.ack=model->config[4];
        state->pmp_active.request_updated=state->pmp_active.ack_updated=0;
        state->pmp_active.ready=state->pmp_active.ready_updated=0;
        state->pmp_active.status_reads=0;
        for (unsigned i=0;i<10;i++) state->ptd_request[i]=0;
        state->ptd_ack=0;
        state->ptd_payload_ready=0;
        state->ptd_request_updated=state->ptd_reply_updated=0;
    }
    if (model->kind == DEVICE_AOP_TIMEBASE_V1 && frequency != model->config[0])
        return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_WATCHDOG_SMC_DISARM_V1)
        state->watchdog_smc_disarms=0;
    if (model->kind == DEVICE_WATCHDOG_WD1_V1) {
        if (frequency != model->config[0]) return DEVICE_BAD_CONFIG;
        watchdog_init(&state->watchdog, now);
    } else if (model->kind == DEVICE_GPIO_QUIET_V1 || model->kind == DEVICE_GPIO_UART_RX_IDLE_V1 ||
               model->kind == DEVICE_GPIO_IDLE_INPUTS_V1 || model->kind == DEVICE_GPIO_IDLE_PADS_V2) {
        unsigned group=0;
        while (!(model->config[2] & (1UL << group))) group++;
        /* Mode 7 is input with interrupts disabled. Choose a group this
         * controller supports, including sparse group sets such as MTP. */
        for (unsigned i=0; i<model->config[0]; i++)
            state->gpio_pin[i]=(group << 16) | 14;
    } else if (model->kind == DEVICE_SPMI_GEN3_EMPTY_V1 || model->kind == DEVICE_SPMI_PMU_RTC_V1) {
        if (model->kind == DEVICE_SPMI_PMU_RTC_V1 &&
            !pmu_rtc_start(&state->pmu_rtc,model->config[3],now,frequency))
            return DEVICE_BAD_CONFIG;
#if SNAP_SPMI_SCRATCH
        if (model->kind == DEVICE_SPMI_PMU_RTC_V1) pmu_scratch_start(&state->pmu_scratch);
#endif
        state->spmi_recovery.config_reads=state->spmi_recovery.config_writes=0;
        state->spmi_recovery.fifo_clears=0;
        state->spmi.rx_head=state->spmi.rx_count=0;
        state->spmi.tx_words=state->spmi.tx_need=0;
        state->spmi.command=0;
        for (unsigned i=0; i<9; i++) state->spmi.enable[i]=state->spmi.flags[i]=0;
    } else if (model->kind == DEVICE_DOCK_FIFO_V1) {
        for (unsigned i=0; i<2; i++) {
            state->dockfifo.head[i]=state->dockfifo.count[i]=0;
            state->dockfifo.threshold[i][0]=state->dockfifo.threshold[i][1]=0;
        }
        state->dockfifo.mask=state->dockfifo.flags=0;
    }
    return DEVICE_OK;
}

enum device_result device_models_start(const struct device_model *models,
    struct device_state *states, unsigned count, uint64_t now, uint64_t frequency)
{
    if (!states || !device_models_valid(models,count,0,0)) return DEVICE_BAD_CONFIG;
    /* Disarm publication before restarting any backend. In particular, a
     * failed timed backend must not leave an old ready state observable. */
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            states[i].pmp_active.ready=states[i].pmp_active.ready_updated=0;
            states[i].pmp_active.status_reads=0;
        }
        else if (models[i].kind==DEVICE_SPMI_PMU_RTC_V1) states[i].pmu_rtc.ready=0;
    for (unsigned i=0;i<count;i++) {
        enum device_result result=device_model_start(models+i,states+i,now,frequency);
        if (result!=DEVICE_OK) return result;
    }
    /* The virtual power service is now able to serve its admitted commands.
     * This is not an Apple firmware, GPU, SEP, or DVFS completion report.
     * Commands outside the modeled service continue to fail explicitly. */
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            states[i].pmp_active.ready=1;
            states[i].pmp_active.ready_updated=1;
        }
    return DEVICE_OK;
}

uint64_t device_model_wait(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t budget)
{
    if (model && state && model->kind == DEVICE_WATCHDOG_WD1_V1)
        return watchdog_wait(&state->watchdog, now, budget);
    return budget;
}

int device_reset_pending(const struct device_model *model,
    const struct device_state *state)
{
    return model && state && model->kind == DEVICE_WATCHDOG_WD1_V1 &&
           state->watchdog.reset;
}

enum device_result device_model_access_at(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t offset, unsigned width,
    int write, uint64_t *value)
{
    if (!valid(model) || !state || !value) return DEVICE_BAD_CONFIG;
    if (width > model->span || offset > model->span - width) return DEVICE_NOT_FOUND;
    if (model->kind == DEVICE_SPMI_PMU_RTC_V1) {
        if (!state->pmu_rtc.ready) return DEVICE_BAD_CONFIG;
        return spmi_access(model,state,now,offset,width,write,value);
    }
    if (model->kind == DEVICE_AOP_TIMEBASE_V1) {
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset != 0 && offset != 4) return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        /* AppleSPUTimesyncV2 reads high/low/high and retries at rollover.
         * Sample the same 24 MHz domain as CNTVCT; never advance on access
         * or latch the halves, which would defeat that consistency check. */
        *value=(uint32_t)(now >> (offset ? 32 : 0));
        return DEVICE_OK;
    }
    if (model->kind != DEVICE_WATCHDOG_WD1_V1)
        return device_model_access_state(model, state, offset, width, write, value);
    switch (watchdog_access(&state->watchdog, now, offset, width, write, value)) {
    case WATCHDOG_OK: return DEVICE_OK;
    case WATCHDOG_BAD_STATE: return DEVICE_BAD_CONFIG;
    case WATCHDOG_UNKNOWN_REGISTER: return DEVICE_UNKNOWN_REGISTER;
    case WATCHDOG_BAD_WIDTH: return DEVICE_BAD_WIDTH;
    case WATCHDOG_BAD_VALUE: return DEVICE_BAD_VALUE;
    }
    return DEVICE_BAD_CONFIG;
}

enum device_result device_mcc_event(const struct device_model *model,
    struct device_state *state, unsigned bank, unsigned counter, uint64_t count)
{
    if (!valid(model) || !state)
        return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_MCC_COHERENT_V1) {
        if (bank >= model->config[0] || counter >= 32) return DEVICE_BAD_VALUE;
    } else if (model->kind == DEVICE_MCC_SOCNI_V1) {
        if (bank || counter >= model->config[0]) return DEVICE_BAD_VALUE;
        if (!state->counter_enable[1]) return DEVICE_OK;
    } else if (model->kind == DEVICE_MCC_DCS_COHERENT_V1) {
        if (bank || counter >= 14) return DEVICE_BAD_VALUE;
        if (counter >= 10) {
            if (state->counter_enable[1] & (1UL << (4*(counter-10))))
                state->counter[0][counter] += count;
            return DEVICE_OK;
        }
    } else return DEVICE_BAD_CONFIG;
    if (state->counter_enable[bank] & (1UL << counter))
        state->counter[bank][counter] += count;
    return DEVICE_OK;
}

static enum device_result dcs_access(struct device_state *state, uint64_t offset,
    unsigned width, int write, uint64_t *value)
{
    if (!state) return DEVICE_BAD_CONFIG;
    /* Fifteen _dcsEnableErrors policy words from the stock 26A428 table at
     * fffffe000c903098. Extended apertures are admitted by the loader only
     * when covered by the platform error-handler's declared MMIO window. */
    static const uint32_t error_offsets[15]={0x7a0,0x38014,0x13c10,0x13c14,
        0x13c18,0x13c1c,0x13c20,0x13c28,0x13c2c,0x13c00,0x18400,0x20400,
        0x38050,0x13c24,0x48};
    for (unsigned i=0; i<15; i++) if (offset == error_offsets[i]) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            state->dcs_error_mask[i]=(uint32_t)*value;
        } else *value=state->dcs_error_mask[i];
        return DEVICE_OK;
    }
    if (offset >= 0x4000 && offset < 0x4070) {
        if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
        if (write) return DEVICE_READ_ONLY;
        *value = state->counter[0][(offset-0x4000)/8];
        return DEVICE_OK;
    }
    if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
    if (offset >= 0x590 && offset < 0x680) {
        uint32_t *selector = &state->dcs_select[(offset-0x590)/24][((offset-0x590)%24)/4];
        if (write) *selector = (uint32_t)*value;
        else *value = *selector;
        return DEVICE_OK;
    }
    switch (offset) {
    case 0x580:
        /* W1 command plus ten counter-select bits. Completion is synchronous:
         * reset exactly the selected counters, then self-clear the command. */
        if (write) {
            if ((*value & ~0x3ff1UL) ||
                (*value && (!(*value & 1) || !(*value & 0x3ff0))))
                return DEVICE_BAD_VALUE;
            for (unsigned i=0;i<10;i++)
                if (*value & (1UL << (i+4))) state->counter[0][i] = 0;
        } else *value = 0;
        return DEVICE_OK;
    case 0x584:
        if (write) {
            if (*value & ~0x3ffUL) return DEVICE_BAD_VALUE;
            state->counter_enable[0] = *value;
        } else *value = state->counter_enable[0];
        return DEVICE_OK;
    case 0x588:
        /* Four enable bits at nibble boundaries; corresponding W1 reset
         * requests are 16 bits above them. Clear busy/request only after
         * performing the reset, so the guest's completion poll is truthful. */
        if (write) {
            if (*value & ~0x11111111UL) return DEVICE_BAD_VALUE;
            for (unsigned i=0;i<4;i++)
                if (*value & (1UL << (16+4*i))) state->counter[0][10+i] = 0;
            state->counter_enable[1] = *value & 0x1111;
        } else *value = state->counter_enable[1];
        return DEVICE_OK;
    case 0x58c:
        if (write) {
            if (*value & ~0x3f3f3f3fUL) return DEVICE_BAD_VALUE;
            state->dcs_power_select = (uint32_t)*value;
        } else *value = state->dcs_power_select;
        return DEVICE_OK;
    case 0x1d48:
        /* Opaque guest DRAM policy; never changes physical host DRAM. */
        if (write) state->dram_policy = (uint32_t)*value;
        else *value = (uint32_t)state->dram_policy;
        return DEVICE_OK;
    default:
        return DEVICE_UNKNOWN_REGISTER;
    }
}

enum device_result device_mcc_cache_event(const struct device_model *model,
    struct device_state *state, unsigned bank, int hit, uint64_t count)
{
    if (!valid(model) || model->kind != DEVICE_MCC_COHERENT_V1 || !state)
        return DEVICE_BAD_CONFIG;
    if (bank >= model->config[0] || (hit != 0 && hit != 1) || (hit && count))
        return DEVICE_BAD_VALUE;
    if (!hit) state->counter[bank][33] += count;
    return DEVICE_OK;
}

static enum device_result mcc_ptd_access(const struct device_model *model,
    struct device_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value)
{
    if (!state) return DEVICE_BAD_CONFIG;
    if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
    if (model->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
        /* J700 PMP-STATUS: range 2, slot 1. Native PMGR consumes a nonzero
         * data word and latches its per-die readiness byte. Metadata follows
         * the same update-consumption rule as the existing PTD producers. */
        if (offset==0x10 || offset==0x18) {
            if (write) return DEVICE_READ_ONLY;
            if (state->pmp_active.ready>1 || state->pmp_active.ready_updated>1)
                return DEVICE_BAD_VALUE;
            if (offset==0x10) *value=state->pmp_active.ready;
            else {
                *value=state->pmp_active.ready_updated ? 2 : 0;
                state->pmp_active.ready_updated=0;
                if (state->pmp_active.status_reads!=UINT32_MAX)
                    state->pmp_active.status_reads++;
            }
            return DEVICE_OK;
        }
        /* AP voter 0 owns only the first entry of each four-entry range.
         * A pair load consumes metadata once and retains its data word. */
        if (offset==0x1880 || offset==0x1888 || offset==0x18c0 || offset==0x18c8) {
            if (write) return DEVICE_READ_ONLY;
            int ack=offset>=0x18c0;
            uint32_t *updated=ack ? &state->pmp_active.ack_updated :
                                   &state->pmp_active.request_updated;
            if (offset&8) { *value=*updated ? 2 : 0; *updated=0; }
            else *value=ack ? state->pmp_active.ack : state->pmp_active.request;
            return DEVICE_OK;
        }
        if (offset>=0x1b20 && offset<0x1b50) {
            /* PMP V2 energy nodes VDEC, SOC_AON, SOC_REST (entries 0x1b2..4,
             * from the PMP nub's energy-counter): _runEnergyModel reads each
             * as an LDP pair through the PTD dashboard. No energy producer:
             * data 0 and metadata 0 (no update), so the kernel keeps its
             * cached zero (PMGR-IOREPORT-20261017). */
            if (write) return DEVICE_READ_ONLY;
            *value=0;return DEVICE_OK;
        }
        if (offset==0x10c40) {
            if (!write) return DEVICE_UNKNOWN_REGISTER;
            /* This local transport can retain votes for already-active
             * domains, but cannot cause a power transition. Registry-aware
             * admission owns AVD wake/release and publishes actual states.
             * Never restore the reset-time ACK mask after a domain gates. */
            if ((*value&~model->config[4]) ||
                (*value&~state->pmp_active.ack) ||
                (state->pmp_active.request&~*value)) return DEVICE_BAD_VALUE;
            state->pmp_active.request=*value;
            state->pmp_active.request_updated=state->pmp_active.ack_updated=1;
            return DEVICE_OK;
        }
    }
    unsigned request=(unsigned)model->config[1], reply=(unsigned)model->config[2];
    unsigned quotas=(unsigned)model->config[3];
    if (offset < 0x4000) {
        unsigned index=(unsigned)(offset/16), status=(unsigned)(offset & 8);
        uint32_t *updated;
        unsigned slot;
        uint64_t data;
        if (index >= request && index-request < quotas+2) {
            slot=index-request;
            updated=&state->ptd_request_updated;
            data=state->ptd_request[slot];
        } else if (index >= reply && index-reply < quotas+1) {
            slot=index-reply;
            updated=&state->ptd_reply_updated;
            data=slot == quotas ? state->ptd_ack : 0;
        } else return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        /* Data precedes metadata in readPTDMsg's LDP. Consume the update
         * indication only when metadata is read, retaining the last data. */
        if (status) {
            *value=(*updated & (1U << slot)) ? 2 : 0;
            *updated &= ~(1U << slot);
        } else *value=data;
        return DEVICE_OK;
    }
    if (offset < model->config[0] || offset-model->config[0] >= 0x4000)
        return DEVICE_UNKNOWN_REGISTER;
    unsigned index=(unsigned)((offset-model->config[0])/8);
    if (index < request || index-request >= quotas+2)
        return DEVICE_UNKNOWN_REGISTER;
    if (!write) return DEVICE_UNKNOWN_REGISTER; /* update-only aperture */
    unsigned slot=index-request;
    if (slot < quotas) {
        /* Four size[11:0]/policy[13:12] requests. Keep the request for the
         * driver's read/modify/write; zero capacity yields zero grants. */
        if (*value & 0xc000c000c000c000UL) return DEVICE_BAD_VALUE;
        state->ptd_reply_updated |= 1U << slot;
    } else if (slot == quotas+1) {
        state->ptd_payload_ready=1;
    } else {
        /* Audited SET_AVAILABLE_CACHE_SIZE opcode 1, sequence[11:0]. Only
         * zero is truthful for this backend. No generic PMP acknowledgement. */
        if ((*value >> 12) != 1 || !(*value & 0xfff) ||
            !state->ptd_payload_ready || state->ptd_request[quotas+1])
            return DEVICE_BAD_VALUE;
        state->ptd_ack=(uint16_t)(*value & 0xfff);
        state->ptd_reply_updated |= (1U << (quotas+1))-1;
        state->ptd_payload_ready=0;
    }
    state->ptd_request[slot]=*value;
    state->ptd_request_updated |= 1U << slot;
    return DEVICE_OK;
}

enum device_result device_model_read_pair(const struct device_model *model,
    struct device_state *state, uint64_t offset, uint64_t values[2])
{
    if (!valid(model) || !state || !values) return DEVICE_BAD_CONFIG;
    if (model->kind==DEVICE_SEP_ASC_MAILBOX_V1) {
        if (!sep_asc_valid(&state->sep_asc,(unsigned)model->config[1])) return DEVICE_BAD_CONFIG;
        if (offset>=model->span || model->span-offset<16) return DEVICE_NOT_FOUND;
        if (offset&7) return DEVICE_BAD_WIDTH;
        if (offset!=0x8830) return DEVICE_UNKNOWN_REGISTER;
        return model->config[1] ? sep_asc_receive(&state->sep_asc,values) : DEVICE_BAD_VALUE;
    }
    if (model->kind != DEVICE_MCC_PTD_COHERENT_V1 &&
        model->kind != DEVICE_PTD_PMP_ACTIVE_V1) return DEVICE_BAD_WIDTH;
    if (offset >= model->span || model->span-offset < 16) return DEVICE_NOT_FOUND;
    if (offset & 15) return DEVICE_BAD_WIDTH;
    uint64_t pair[2];
    /* The first lane is side-effect-free data. For an admitted PTD entry,
     * its second lane is metadata; only that read consumes the update bit. */
    enum device_result result=mcc_ptd_access(model,state,offset,8,0,&pair[0]);
    if (result != DEVICE_OK) return result;
    result=mcc_ptd_access(model,state,offset+8,8,0,&pair[1]);
    if (result != DEVICE_OK) return result;
    values[0]=pair[0]; values[1]=pair[1];
    return DEVICE_OK;
}

