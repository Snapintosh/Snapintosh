/* SPDX-License-Identifier: MIT */
/* device_model_access_state, the per-kind register models, and the IRQ level helpers.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */
enum device_result device_model_access_state(const struct device_model *model,
    struct device_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value)
{
    if (!valid(model) || !value) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_SPMI_PMU_RTC_V1) return DEVICE_BAD_CONFIG;
    if (width > model->span || offset > model->span - width) return DEVICE_NOT_FOUND;
    if (model->kind == DEVICE_PMGR_ACC_BOOT_POLICY_V1) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_SEP_ASC_MAILBOX_V1)
        return state ? sep_asc_access(&state->sep_asc,offset,width,write,value,
                                     (unsigned)model->config[1]) : DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_I2C_EMPTY_V1) {
        if (!state || !i2c_valid(&state->i2c)) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (write && *value>UINT32_MAX) return DEVICE_BAD_VALUE;
        struct device_i2c_empty *s=&state->i2c;
        uint32_t v=(uint32_t)*value;
        if (offset==0) {
            if (!write) return DEVICE_BAD_VALUE;
            if (!(s->control&0x800) || s->shadow_command!=0x100000 || (v&~0x7ffU) ||
                s->tx_count==DEVICE_I2C_FIFO_WORDS) return DEVICE_BAD_VALUE;
            if (!s->blocked && !s->tx_count) {
                if (!(v&0x100) || (v&0x400)) return DEVICE_BAD_VALUE;
            }
            s->tx[s->tx_count++]=v;
            i2c_run(s);
        } else if (offset==4 || offset==8 || offset==0xc || offset==0x28) {
            if (write) return DEVICE_READ_ONLY;
            *value=offset==4 ? 0x100 : offset==8 ? s->tx_count :
                   offset==0x28 ? model->config[1] : 0;
        } else if (offset==0x10) {
            if (write) {
                /* Debug line sensing only. Slave and bitbang modes are not
                 * implemented and must not silently acquire an endpoint. */
                if (v&~0x80000000U) return DEVICE_BAD_VALUE;
                s->address=v;
            } else *value=s->address;
        } else if (offset==0x14) {
            if (write) s->status&=~v; /* W1C never changes FIFO-derived bits. */
            else *value=i2c_status(s);
        } else if (offset==0x18) {
            if (write) s->mask=v;
            else *value=s->mask;
        } else if (offset==0x1c) {
            if (write) {
                if (v&~I2C_CONTROL) return DEVICE_BAD_VALUE;
                if (v&0x200) {
                    for (unsigned i=0;i<DEVICE_I2C_FIFO_WORDS;i++) s->tx[i]=0;
                    s->tx_count=s->blocked=0;
                }
                if (v&0x600) s->resets++;
                /* Reset commands self-clear after the queue is emptied.
                 * RX is always empty because this bus never gets an ACK. */
                s->control=v&~0x600U;
                i2c_run(s);
            } else *value=s->control;
        } else if (offset==0x40) {
            /* The pinned _checkBusStatus programs this before submitting a
             * command; its other references are diagnostic reads. Preserve
             * the exact programming contract without claiming a packed
             * interrupt-history format or inventing a completion. Transfers
             * require this admission; actual IRQs come from FIFO/status. */
            if (!write) return DEVICE_BAD_VALUE;
            if (v!=0x100000 || !(s->control&0x800) || s->mask || s->status ||
                s->tx_count || s->blocked) return DEVICE_BAD_VALUE;
            s->shadow_command=v;
            s->shadow_writes++;
        } else if (offset==0x44) {
            if (write) {
                if (v&~1U) return DEVICE_BAD_VALUE;
                s->halt=v;
                i2c_run(s);
            } else *value=s->halt;
        } else if (offset==0x2c || offset==0x30 || offset==0x38) {
            unsigned i=offset==0x2c ? 0 : offset==0x30 ? 1 : 2;
            if (write) s->timing[i]=v;
            else *value=s->timing[i];
        } else return DEVICE_UNKNOWN_REGISTER;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_DWI_STARTUP_V1) {
        if (!state || state->dwi.ready!=1 || (state->dwi.written&~31U))
            return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* 26A428 AppleS8000DWI::_dwiSetConfig / start. nclk-div=1,
         * polarity=1, str-delay=8000 and lockout-us=5 produce these exact
         * values at 24 MHz. Retain programming, without inventing a
         * voltage/backlight completion or forwarding physical host MMIO.
         * +80/+84 are shared with transaction submission: other payloads
         * and commands (including 0x71) remain unsupported. */
        static const uint32_t offsets[5]={0,0xd0,4,0x84,0x80};
        static const uint32_t startup[5]={1,192000,120,0,0x41};
        unsigned i=0;
        while (i<5 && offset!=offsets[i]) i++;
        if (i==5) return DEVICE_UNKNOWN_REGISTER;
        if (!write) {
            /* Never return a made-up reset or transaction status. Only
             * the three non-command configuration words have readback. */
            if (i>=3 || !(state->dwi.written&(1U<<i))) return DEVICE_BAD_VALUE;
            *value=state->dwi.values[i];
            return DEVICE_OK;
        }
        if (*value!=startup[i] || (i==4 && (state->dwi.written&15)!=15))
            return DEVICE_BAD_VALUE;
        state->dwi.values[i]=(uint32_t)*value;
        state->dwi.written|=1U<<i;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_QSPI_BOOT_V1) {
        if (!state || state->qspi.ready!=1 ||
            state->qspi.tx_count>DEVICE_QSPI_FIFO_WORDS ||
            state->qspi.rx_count>DEVICE_QSPI_FIFO_WORDS) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* 26A428 AppleQSPIMCController::start: common VERSION at +3c,
         * peripheral FIFO capacities at +838 and RESET at +800. The two
         * overlapping DT windows share one state. Reset really clears our
         * queues synchronously, so bit8 is clear on subsequent readback.
         * Unknown control bits, transfers, status and IRQs stay trapped. */
        if (offset==0x3c || offset==0x838) {
            if (write) return DEVICE_READ_ONLY;
            *value=offset==0x3c ? 1 : DEVICE_QSPI_FIFO_WORDS | (DEVICE_QSPI_FIFO_WORDS<<8);
            return DEVICE_OK;
        }
        if (offset!=0x800) return DEVICE_UNKNOWN_REGISTER;
        if (!write) { *value=0;return DEVICE_OK; }
        if (*value!=0x100) return DEVICE_BAD_VALUE;
        for (unsigned i=0;i<DEVICE_QSPI_FIFO_WORDS;i++)
            state->qspi.tx[i]=state->qspi.rx[i]=0;
        state->qspi.tx_count=state->qspi.rx_count=0;
        if (state->qspi.resets!=UINT32_MAX) state->qspi.resets++;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_ENERGY_RESTORE_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        if (offset!=0 && offset!=8) return DEVICE_UNKNOWN_REGISTER;
        /* Saved energy is a writable baseline, never a fabricated sample.
         * These writes do not alter CPU power or start an energy producer. */
        if (state->energy_restore.written&~3UL) return DEVICE_BAD_VALUE;
        unsigned slot=(unsigned)(offset/8);
        if (!write) {
            /* IOReport's _snapshotCPUEnergyAccumulators and _runEnergyModel:
             * nothing accumulates, so the restored baseline (0 if none) is
             * the reading and every delta is zero (PMGR-IOREPORT-20261017). */
            *value=state->energy_restore.written&(1UL<<slot) ? state->energy_restore.values[slot] : 0;
            return DEVICE_OK;
        }
        state->energy_restore.values[slot]=*value;
        state->energy_restore.written|=1UL<<slot;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        if (offset==0x20) {
            /* DVFS command readback, not a live frequency/counter sample.
             * No frequency command is admitted by this virtual controller:
             * its reset command is zero and BUSY[31] is therefore clear.
             * cpuComplexIdleEnter polls that interlock before entering idle.
             * Reject every command write; +50 actual-P-state status and
             * transition timestamps remain unsupported. */
            if (write) return DEVICE_BAD_VALUE;
            *value=0;
            return DEVICE_OK;
        }
        int slot=acc_perf_slot((unsigned)model->config[0],offset);
        if (slot<0) return DEVICE_UNKNOWN_REGISTER;
        unsigned count=model->config[0] ? 18 : 8;
        uint64_t residency=(1UL<<count)-1;
        uint64_t allowed[2]={residency|(residency<<18)|
            (((1UL<<(model->config[0] ? 6 : 10))-1)<<36)|
            (model->config[0] ? 0 : 0xffUL<<46),0};
        for (unsigned i=0;i<count;i++) allowed[(54+i)/64]|=1UL<<((54+i)%64);
        if ((state->acc_perf.written[0]&~allowed[0]) ||
            (state->acc_perf.written[1]&~allowed[1])) return DEVICE_BAD_VALUE;
        if (!write) {
            /* IOReport's _snapshotPerfCountersACC: no event/time source runs,
             * so a counter holds its restored value (0 if never restored) and
             * every sample delta is zero (PMGR-IOREPORT-20261017). */
            *value=state->acc_perf.written[slot/64]&(1UL<<(slot%64)) ? state->acc_perf.values[slot] : 0;
            return DEVICE_OK;
        }
        state->acc_perf.values[slot]=*value;
        state->acc_perf.written[slot/64]|=1UL<<(slot%64);
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_SOC_PERF_RESTORE_V1)
        return soc_perf_access(model,state,offset,width,write,value);
    if (model->kind == DEVICE_PMGR_ACTIVE_BOOT_V1)
        return pmgr_boot_access(model,state,offset,width,write,value,0);
    if (model->kind == DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset==8 && model->config[0]) {
            /* Resource admission lives in the registry path. */
            if (state->pmgr_ave_cluster!=0 && state->pmgr_ave_cluster!=15) return DEVICE_BAD_VALUE;
            if (write) return DEVICE_BAD_CONFIG;
            *value=state->pmgr_ave_cluster;return DEVICE_OK;
        }
        if ((offset==0xc || offset==0x10) && model->config[0]) {
            /* Hash-bound soc-clusters rows 3/4, DISP and DCS: the IOReport
             * cluster power-state loop reads them. Both are always on in
             * this virtual SoC; a gate request needs its own contract. */
            if (write) return DEVICE_READ_ONLY;
            *value=15;return DEVICE_OK;
        }
        if (offset!=0 && offset!=4) return DEVICE_UNKNOWN_REGISTER;
        /* configCPUComplexPowerState requests nibble 15 for active and
         * waits for bit 4 to clear. Both virtual clusters are already
         * active; no transition is busy. Off/reset need CPU lifecycle work.
         * This register does not have the ordinary PS bank's 0xf0 status. */
        if (write) return *value==15 ? DEVICE_OK : DEVICE_BAD_VALUE;
        *value=15;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AVE_TVM_IDLE_V1) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_PMC_DVMR_CONFIG_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if ((offset==0x5c18 || offset==0x5c1c) && !write) {
            *value=state->pmc_dvmr.venc_cluster;return DEVICE_OK;
        }
        if (offset==0x5c18 && write)
            return *value==state->pmc_dvmr.venc_cluster ? DEVICE_OK : DEVICE_BAD_VALUE;
        if (offset==0) {
            if (write) {
                if (*value & ~3UL) return DEVICE_BAD_VALUE;
                /* Both declared display agents are local configuration:
                 * acceptance commits the enable set synchronously. There
                 * is no pending voltage/frequency operation to acknowledge. */
                state->pmc_dvmr.enabled=(uint32_t)*value;
                state->pmc_dvmr.count_valid=0;
            } else *value=state->pmc_dvmr.enabled;
            return DEVICE_OK;
        }
        if (offset==0x20 && !write) {
            *value=0; /* configuration busy bit 0: synchronous commit above */
            return DEVICE_OK;
        }
        if (offset==0x5c14 && write) {
            unsigned enabled=state->pmc_dvmr.enabled;
            unsigned count=(enabled&1)+((enabled>>1)&1);
            if (*value!=count) return DEVICE_BAD_VALUE;
            state->pmc_dvmr.count=count;
            state->pmc_dvmr.count_valid=1;
            return DEVICE_OK;
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_PMC_RMBS_REQUEST_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset || !write) return DEVICE_UNKNOWN_REGISTER;
        if (*value>UINT32_MAX) return DEVICE_BAD_VALUE;
        /* pmcWriteLTR forwards an opaque u32 through writeRMBS; boot
         * submits getRMBSInitVal() == UINT32_MAX. Retain the preference,
         * without inventing applied state, readback or completion. */
        state->pmc_rmbs.value=(uint32_t)*value;
        state->pmc_rmbs.valid=1;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMC_ENABLE_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        unsigned index;uint64_t mask;
        if (offset<=0xc) { index=(unsigned)offset/4;mask=0xf; }
        else if (offset==0x24) { index=4;mask=3; }
        else if (offset==0x28) { index=5;mask=0x3f; }
        else if (offset==0x20) { index=6;mask=7; }
        else return DEVICE_UNKNOWN_REGISTER;
        /* PMP/CLPC/GFX/AP have declared interfaces on DCS/SOC/DISP/AVE.
         * Enabling an interface does not synthesize votes or completion.
         * RMBS enable/keep-alive occupies bits 1/0. Six boost agents and
         * three active BWR agents have independent RMW enable bits; BWR
         * spare rows are disabled in the hash-bound agent table. */
        if (write) {
            if (*value & ~mask) return DEVICE_BAD_VALUE;
            state->pmc_enable[index]=(uint32_t)*value;
        } else *value=state->pmc_enable[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AXI2AF_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset!=0x104 && offset!=0x108) return DEVICE_UNKNOWN_REGISTER;
        unsigned index=(unsigned)(offset-0x104)/4;
        /* _applyAxi2afWorkaround sets or clears bit 0 in two control
         * words. Retain policy only: no physical bus, idle transition,
         * transaction drain, readiness or completion status is supplied. */
        if (write) {
            if (*value & ~1UL) return DEVICE_BAD_VALUE;
            state->pmgr_axi2af[index]=(uint32_t)*value;
        } else *value=state->pmgr_axi2af[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_SOC_DPE_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* restoreSOCDPE uses ten bases 0x2400..0x4800 in logical reg 78.
         * This model owns only pages +0x2000..0x4fff. Each group exposes
         * +0/+0x200/+0x300, except group 7 has no +0 operation. */
        if (offset<0x400 || offset>=0x2c00) return DEVICE_UNKNOWN_REGISTER;
        unsigned group=(unsigned)(offset-0x400)/0x400;
        unsigned word=(unsigned)(offset-0x400)%0x400, slot;
        if (word==0 && group!=7) slot=0;
        else if (word==0x200) slot=1;
        else if (word==0x300) slot=2;
        else return DEVICE_UNKNOWN_REGISTER;
        unsigned index=3*group+slot;
        if (write) {
            /* The audited consumer changes only bit 0. Retain enable
             * policy; no virtual idle producer, host gate or ready status. */
            if (*value & ~1UL) return DEVICE_BAD_VALUE;
            state->pmgr_soc_dpe[index]=(uint32_t)*value;
        } else *value=state->pmgr_soc_dpe[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_CORESIGHT_LOCK_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (state->coresight_unlocked>1) return DEVICE_BAD_VALUE;
        if (offset==0xfb0) {
            if (!write) return DEVICE_UNKNOWN_REGISTER;
            if (*value>UINT32_MAX) return DEVICE_BAD_VALUE;
            state->coresight_unlocked=(*value==0xc5acce55);
        } else if (offset==0xfb4) {
            if (write) return DEVICE_BAD_VALUE;
            /* SLI=1, SLK reflects our lock, nTT=0 (32-bit lock access). */
            *value=1 | (state->coresight_unlocked ? 0 : 2);
        } else return DEVICE_UNKNOWN_REGISTER;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_LLT_DISABLED_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset) return DEVICE_UNKNOWN_REGISTER;
        /* T8140 enableLltLimit reads SOC misc +0x10000, changes bit 0,
         * and writes the same word. This backend has no limiter: only
         * its disabled configuration can be read or written. */
        if (state->pmgr_llt_limit || (write && *value)) return DEVICE_BAD_VALUE;
        if (!write) *value=0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_SOC_GATE_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        unsigned index;
        if (offset==0) index=0;
        else if (offset==0x40) index=1;
        else if (offset==0x60) index=2;
        else if (offset==0x68) index=3;
        else return DEVICE_UNKNOWN_REGISTER;
        /* restoreHW and enableCPMPowerDomainGating only change bit 31.
         * Retain that policy independently; no virtual idle producer can
         * gate a domain, and no physical power controller is touched. */
        if (write) {
            if (*value & ~0x80000000UL) return DEVICE_BAD_VALUE;
            state->pmgr_soc_gate[index]=(uint32_t)*value;
        } else *value=state->pmgr_soc_gate[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AP_WAKE_MASK_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* enableSlpDdrForS2R clears bit 0 at logical reg 66 +0x4000.
         * No DDR sleep controller is attached: retain the disabled
         * configuration, and reject every enable/reserved-bit request. */
        if (!offset) {
            if (write && *value) return DEVICE_BAD_VALUE;
            if (!write) *value=0;
            return DEVICE_OK;
        }
        /* T8140 setAPWakeupSources writes valid_mask & ~requested to
         * 0x4008..0x4024 through logical reg 66 (DT reg 4, base 0x4000).
         * Store the policy, independently per word. The distinct wake-cause
         * words at +0x28..0x44, mask reads and low-power commands stay trapped;
         * this does not claim to deliver an AOP/PMIC wake event. */
        if (!write || offset<8 || offset>0x24) return DEVICE_UNKNOWN_REGISTER;
        unsigned index=(unsigned)(offset-8)/4;
        uint64_t valid_bits=index==7 ? 0x1fffff : UINT32_MAX;
        if (*value & ~valid_bits) return DEVICE_BAD_VALUE;
        state->pmgr_wake_mask[index]=(uint32_t)*value;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AON_COUNTER_CONFIG_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* Pinned perf-groups 6/7: _enableSOCPerfCounter(Ehjbbj) and
         * _enableSOCPerfCountersV2. Include the six secondary controls
         * selected by type-1 flags bit 1; these fill the primary-table gaps.
         * Group 6 starts halfway through its page; group 7 starts at zero. */
        unsigned base=model->config[0]==6 ? 0x800 : 0;
        unsigned count=model->config[0]==6 ? 6 : 69, index;
        if (offset>=base+0x100 && offset<base+0x100+count*0x20 &&
            (((offset-base-0x100)&0x1f)==0x10 || ((offset-base-0x100)&0x1f)==0x14)) {
            /* _snapshotPerfCountersV2 samples groups 6/7 too (high/low/high).
             * Nothing programs or restores an AON value and no clock runs:
             * both halves read 0, every delta is zero. Data writes stay
             * refused (PMGR-IOREPORT-20261017). */
            if (write) return DEVICE_READ_ONLY;
            *value=0;return DEVICE_OK;
        }
        if (offset==base) index=0;
        else if (offset>=base+0x100 && offset<base+0x100+count*0x20 &&
                 !((offset-base-0x100)&0x1f))
            index=1+(unsigned)(offset-base-0x100)/0x20;
        else return DEVICE_UNKNOWN_REGISTER;
        /* Mode 0/1 and enable bit 2 are configuration latches only.
         * Global bit 0 gates sampling but does not clear per-counter setup.
         * Other modes, data words, snapshots and reset controls stay trapped;
         * no Apple/Qualcomm clock telemetry or completed sampling is faked. */
        uint64_t mask=index ? 5 : 1;
        if (write) {
            if (*value & ~mask) return DEVICE_BAD_VALUE;
            state->pmgr_counter_config[index]=(uint32_t)*value;
        } else *value=state->pmgr_counter_config[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AON_FUSES_V1) {
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* T8140CLPC::isRunningOnSilicon tests bits 31:28 of this word.
         * Declare the non-silicon branch for our virtual Apple platform;
         * there is no physical T8140 voltage/energy controller behind it.
         * 1 is our virtual type value, not a recovered Apple subtype code
         * or a characterization of the physical Qualcomm processor. */
        if (offset==0x80c) {
            if (write) return DEVICE_READ_ONLY;
            *value=UINT32_C(0x10000000);
            return DEVICE_OK;
        }
        /* Stock T8140 PMGR reports these ten characterization words; its
         * rail-IDS getter extracts fields from 0x114 and 0x124. This virtual
         * platform has no calibrated leakage or physical voltage backend.
         * Zero is our immutable characterization, not host fuse contents.
         * Other fuse/register consumers remain explicit unsupported stops. */
        if (!((offset>=0x114 && offset<=0x12c) ||
              (offset>=0x214 && offset<=0x21c))) return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        *value=0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_CPU_PERF_BOOT_V1) {
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        /* Single declared CPU performance state: ACC 0xe78048/0xe78050. DVMR
         * weight[42:38] is zero; this backend has no voltage-margin engine.
         * Cluster 1's FANE indices [33:29], [38:34], [43:39] select the
         * backed active ANE state, index one. CLPC treats index zero as
         * inactive. Cluster 0 has no FANE index word.
         * Control writes and other performance-state entries stay trapped. */
        if (offset!=0x48 && !(model->config[0]==1 && offset==0x50))
            return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        *value=offset==0x50 ? (1UL<<29)|(1UL<<34)|(1UL<<39) : 0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_DVMR_WEIGHTS_V1) {
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        if (offset==0x178) {
            if (!state) return DEVICE_BAD_CONFIG;
            const uint64_t enabled=0xa800000000000000UL;
            /* The stock boolean setter changes all three enable bits.
             * Readback is requested configuration, not sampling readiness;
             * energy-value reads remain rejected by their separate banks. */
            if (state->pmgr_energy_control && state->pmgr_energy_control!=enabled)
                return DEVICE_BAD_VALUE;
            if (!write) *value=state->pmgr_energy_control;
            else {
                if (*value && *value!=enabled) return DEVICE_BAD_VALUE;
                state->pmgr_energy_control=*value;
            }
            return DEVICE_OK;
        }
        /* Pinned two-/four-entry DVMRWeightTable register lists. CLPC
         * treats an all-zero table as disabled. The P-cluster ANE-only
         * table therefore admits 0..2 CPUs at the sole state's weight 0,
         * with weight 31 in the unused 3..8 CPU lanes. Native topology
         * checks exclude those lanes even at weight 31. Other tables
         * remain disabled. This describes static guest frequency coupling;
         * it does not claim a physical voltage-margin engine or ANE work. */
        if (offset!=0xa8 && offset!=0xd0 &&
            !(model->config[0] && (offset==0xb0 || offset==0xd8)))
            return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        *value=model->config[0] && offset==0xb0 ? 0x1fffffff8000UL : 0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_DART_T8110_V1) {
        enum dart_result r=dart_access(state ? &state->dart : 0,(unsigned)model->config[0],
                                      offset,width,write,value);
        switch (r) {
        case DART_OK: return DEVICE_OK;
        case DART_BAD_CONFIG: return DEVICE_BAD_CONFIG;
        case DART_BAD_WIDTH: return DEVICE_BAD_WIDTH;
        case DART_READ_ONLY: return DEVICE_READ_ONLY;
        case DART_UNKNOWN_REGISTER: return DEVICE_UNKNOWN_REGISTER;
        default: return DEVICE_BAD_VALUE;
        }
    }
    if (model->kind == DEVICE_SPMI_GEN3_EMPTY_V1)
        return spmi_access(model,state,0,offset,width,write,value);
    if (model->kind == DEVICE_DOCK_FIFO_V1)
        return dockfifo_access(state,offset,width,write,value);
    if (model->kind == DEVICE_SOCNI_ERRORS_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        /* _afxSocNiEnableErrors uses two masks per declared report source.
         * Captured six tables at c902c98 identify exact offsets and gaps;
         * status/acknowledgement registers are not part of this contract. */
        static const unsigned base[6]={0x1800,0x1a00,0x1400,0x2400,0x2000,0x1c00};
        static const unsigned count[6]={25,25,25,25,23,22};
        unsigned bank=(unsigned)model->config[0], n=count[bank];
        if (offset < base[bank] || offset >= base[bank]+8*n) return DEVICE_UNKNOWN_REGISTER;
        unsigned index=(unsigned)(offset-base[bank])/4, source=index%n;
        if ((bank < 4 && (source == 11 || source == 13)) ||
            (bank == 4 && source == 12) || (bank == 5 && source == 11))
            return DEVICE_UNKNOWN_REGISTER;
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            state->socni_error_mask[index]=(uint32_t)*value;
        } else *value=state->socni_error_mask[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PLATFORM_ERROR_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset != model->config[0] || (!write && model->config[1]))
            return DEVICE_UNKNOWN_REGISTER;
        /* _afiNsDisableErrors writes a complete disable policy at +104;
         * its read semantics are not yet established. _afxPioGwEnableErrors
         * does a genuine RMW at +4084. Neither has a physical fault producer. */
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            state->platform_error_policy=(uint32_t)*value;
        } else *value=state->platform_error_policy;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_DOCK_ABSENT_V1) {
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset != model->config[0]) return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        /* Only the root dock-connect status word is exposed. The virtual
         * Apple dock is absent; neighboring PMGR registers remain trapped. */
        *value=0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_AES_IDLE_V1) {
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (!state || state->aes_idle.ready!=1 || state->aes_idle.running>1 ||
            (state->aes_idle.irq_enable&~0x3effeU) ||
            (state->aes_idle.fifo_threshold && state->aes_idle.fifo_threshold!=0x40))
            return DEVICE_BAD_CONFIG;
        if (write) {
            uint64_t v=*value;
            switch (offset) {
            case 0x08: /* Native _enableAES START/STOP; neither submits work. */
                if (v!=1 && v!=2) return DEVICE_BAD_VALUE;
                state->aes_idle.running=v==1;
                if (v==1) state->aes_idle.starts++;
                else state->aes_idle.stops++;
                break;
            case 0x18: /* W1C: no command has been accepted, hence no IRQ. */
                if (v&~0x3effeUL) return DEVICE_BAD_VALUE;
                break;
            case 0x1c:
                if (v&~0x3effeUL) return DEVICE_BAD_VALUE;
                state->aes_idle.irq_enable=(uint32_t)v;
                break;
            case 0x20: /* Audited half-full threshold for the 128-word FIFO. */
                if (v!=0x40) return DEVICE_BAD_VALUE;
                state->aes_idle.fifo_threshold=(uint32_t)v;
                break;
            case 0x0c: case 0x24: return DEVICE_READ_ONLY;
            default: return DEVICE_UNKNOWN_REGISTER;
            }
            state->aes_idle.writes |= 1U<<(offset/4);
        } else {
            uint64_t v;
            switch (offset) {
            case 0x0c: v=0x3f80; break; /* All audited version-5 engines idle. */
            case 0x18: v=0; break;      /* No completion or error producer. */
            case 0x24: v=2; break;      /* Empty FIFO, zero read/write pointers. */
            default: return DEVICE_UNKNOWN_REGISTER;
            }
            *value=v;
            state->aes_idle.reads |= 1U<<(offset/4);
        }
        /* In particular 0x200 never accepts a FIFO command. No guest buffer,
         * DMA mapping, key bytes, crypto result or interrupt is fabricated. */
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_AES_NO_KEYS_V1) {
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (model->config[4] && offset == model->config[4]) {
            /* PMGR's BPR (AppleT8140PMGR read32/write32 of range 1 +0x5c030):
             * a plain 32-bit word. It starts at 0 -- no earlier boot-progress or
             * panic state -- and only a guest write changes it. */
            if (!state) return DEVICE_BAD_CONFIG;
            if (write) {
                if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
                state->aes_pmgr_bpr=(uint32_t)*value;
                if (state->aes_pmgr_bpr_writes!=UINT32_MAX) state->aes_pmgr_bpr_writes++;
            } else {
                *value=state->aes_pmgr_bpr;
                if (state->aes_pmgr_bpr_reads!=UINT32_MAX) state->aes_pmgr_bpr_reads++;
            }
            return DEVICE_OK;
        }
        for (unsigned i=0; i<4; i++) if (offset == model->config[i]) {
            if (write) {
                /* Shipped disableHardwareKey: dedicated disable command
                 * a55ac33c, or one legacy disable bit. These keys are already
                 * absent, so repeat disabling is idempotent. Never accept the
                 * a050c030 enable sentinel or make any fused key available. */
                if (i ? *value!=0xa55ac33cUL :
                    (*value!=1 && *value!=2 && *value!=4 && *value!=8))
                    return DEVICE_BAD_VALUE;
                if (!state) return DEVICE_BAD_CONFIG;
                if (state->aes_key_disable_writes[i]!=UINT32_MAX)
                    state->aes_key_disable_writes[i]++;
                return DEVICE_OK;
            }
            /* Legacy disable bits include UID0 (bit 3). Dedicated UID1 /
             * GID words are disabled unless equal to 0xa050c030; zero is
             * deliberately NOT a claim that a hardware key is available. */
            *value=i ? 0 : 15;
            return DEVICE_OK;
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_GPIO_QUIET_V1 || model->kind == DEVICE_GPIO_UART_RX_IDLE_V1 ||
        model->kind == DEVICE_GPIO_IDLE_INPUTS_V1 || model->kind == DEVICE_GPIO_IDLE_PADS_V2) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset < model->config[0]*4) {
            uint32_t *pin=&state->gpio_pin[offset/4];
            unsigned old_mode=(*pin >> 1) & 7, old_mux=(*pin >> 5) & 3;
            int route=gpio_idle_input(model,(unsigned)(offset/4),old_mux);
            /* The pad's current level: a driven output's latch, a declared
             * idle-high input route, or otherwise externally held low. */
            unsigned level=old_mode == 1 ? (*pin & 1U) :
                (unsigned)(route && old_mode == 7 && (*pin & (1U << 9)));
            if (!write) {
                *value=old_mode == 1 ? *pin : (*pin & ~1U) | level;
                return DEVICE_OK;
            }
            uint64_t v=*value;
            unsigned mode=(v >> 1) & 7, group=(v >> 16) & 7, mux=(v >> 5) & 3;
            int idle_route=mode == 7 && gpio_idle_input(model,(unsigned)(offset/4),mux);
            /* 26A428 AppleT8101GPIOIC::_decodeVectorInfo (...916086c) maps
             * interrupt types to modes 2 level-high, 3 level-low, 4 rising,
             * 5 falling and 6 either edge. initVector (...915f934) first
             * writes mode 7 with input enable; enableVector (...915fcec)
             * then replaces only bits 3:1, and disableVectorHard (...915fba8)
             * clears them to mode 0. No GPIO interrupt producer exists, so
             * an interrupt mode is admitted only on a GPIO-function pad
             * (mux 0: externally held low) whose condition can never become
             * true: level-high and rising edge always; falling or either
             * edge unless this very write releases a driven-high output.
             * Level-low would assert at once and stays unsupported. Pending
             * banks therefore truthfully remain zero. Declared idle-high
             * inputs have no asserted clock requests, edges or serial data. */
            int irq=mode >= 2 && mode <= 6;
            if (irq && (mux || mode == 3 || ((mode == 5 || mode == 6) && level)))
                return DEVICE_BAD_VALUE;
            if ((v & ~0xe78fefUL) || (!irq && mode != 0 && mode != 1 && mode != 7) ||
                (mux && !idle_route) || !(model->config[2] & (1UL << group)) ||
                ((*pin & (1U << 21)) && ((v ^ *pin) & ~1UL)))
                return DEVICE_BAD_VALUE;
            *pin=(uint32_t)v;
            return DEVICE_OK;
        }
        if (offset >= 0x800) {
            uint64_t group=(offset-0x800)/0x40, bank=((offset-0x800)%0x40)/4;
            if (group < model->config[1] && (model->config[2] & (1UL << group)) &&
                bank < (model->config[0]+31)/32) {
                /* W1C pending banks have no source in this backend. Ack of
                 * any mask (including unused final-bank bits) is harmless. */
                if (write && *value > UINT32_MAX) return DEVICE_BAD_VALUE;
                if (!write) *value=0;
                return DEVICE_OK;
            }
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_WATCHDOG_SMC_DISARM_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset!=model->config[0] || !write) return DEVICE_UNKNOWN_REGISTER;
        /* Native start and _disarmWatchdogMechanism clear this deadline.
         * Zero leaves the virtual SMC timer disarmed. Do not pretend an
         * unimplemented firmware timer can consume a nonzero deadline. */
        if (*value) return DEVICE_BAD_VALUE;
        if (state->watchdog_smc_disarms!=UINT32_MAX) state->watchdog_smc_disarms++;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_WATCHDOG_WD1_V1 || model->kind == DEVICE_AOP_TIMEBASE_V1)
        return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_PTD_IRQ_CONFIG_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset>=0x400 && offset<0x800) {
            /* _setIrq format 1 interleaves groups of four between the
             * low/high 0x200-byte halves. Keep state in entry order. */
            unsigned word=(unsigned)(((offset&0x1ff)/4)*2+((offset>>9)&1));
            if (write) {
                if (*value & ~0x1f1f1f1fUL) return DEVICE_BAD_VALUE;
                state->ptd_irq.route[word]=(uint32_t)*value;
            } else *value=state->ptd_irq.route[word];
            return DEVICE_OK;
        }
        if ((offset>=0x200 && offset<0x280) ||
            (offset>=0x300 && offset<0x380)) {
            /* _enableIrq / _disableIrq: W1S / W1C, not replacement. */
            if (!write) return DEVICE_UNKNOWN_REGISTER;
            if (*value>UINT32_MAX) return DEVICE_BAD_VALUE;
            unsigned word=(unsigned)((offset&0xff)/4);
            if (offset<0x300) state->ptd_irq.enabled[word]|=(uint32_t)*value;
            else state->ptd_irq.enabled[word]&=~(uint32_t)*value;
            return DEVICE_OK;
        }
        /* Pending, enable readback, status delivery and PMP readiness need
         * a producer contract. Never synthesize them from configuration. */
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_MCC_PTD_COHERENT_V1 || model->kind == DEVICE_PTD_PMP_ACTIVE_V1)
        return mcc_ptd_access(model, state, offset, width, write, value);
    if (model->kind == DEVICE_MCC_DCS_COHERENT_V1)
        return dcs_access(state, offset, width, write, value);
    if (model->kind == DEVICE_MCC_SOCNI_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (offset == 0x100) {
            /* T8140 enablePerfCtrl starts the SOCNI bank after configuring
             * an individual counter. Keep the bank and source gates distinct. */
            if (width != 4) return DEVICE_BAD_WIDTH;
            if (write) {
                if (*value > 1) return DEVICE_BAD_VALUE;
                state->counter_enable[1] = *value;
            } else *value = state->counter_enable[1];
            return DEVICE_OK;
        }
        if (offset < model->config[0]*4) {
            if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
            uint64_t bit = 1UL << (offset/4);
            /* enableSocniCntr writes exactly 3 to start, 0 to stop.
             * Other control combinations need separate semantics. */
            if (write) {
                if (*value != 0 && *value != 3) return DEVICE_BAD_VALUE;
                if (*value) state->counter_enable[0] |= bit;
                else state->counter_enable[0] &= ~bit;
            } else *value = (state->counter_enable[0] & bit) ? 3 : 0;
            return DEVICE_OK;
        }
        if (offset >= 0x4000 && offset < 0x4000 + model->config[0]*8) {
            if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
            if (write) return DEVICE_READ_ONLY;
            *value = state->counter[0][(offset-0x4000)/8];
            return DEVICE_OK;
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    uint64_t bank = offset / 0x40000, reg = offset % 0x40000;
    if (model->kind == DEVICE_MCC_COHERENT_V1 && offset == 0x10082c) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        /* mccEnableCacheMode and mccFlush deassert the global flush request
         * with zero. cacheFlush asserts it with one and then uses per-DCS
         * +2844 completion: that active sequence is a separate contract.
         * No request has been admitted, so idle reads/clears are truthful. */
        if (write && *value) return DEVICE_BAD_VALUE;
        if (!write) *value = 0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && offset == 0x102800) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        /* mccEnableCacheMode's requested way budget. The audited guest caps
         * it at twelve. With zero private cache capacity there are no lines
         * to move or evict; this policy never changes host cacheability. */
        if (write) {
            if (*value > 12) return DEVICE_BAD_VALUE;
            state->cache_way_policy = (uint32_t)*value;
        } else *value = state->cache_way_policy;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] && reg == 0x2804) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        if (write) return DEVICE_READ_ONLY;
        /* mccWaitForWaysPwrOn compares both seven-bit fields with the
         * requested way budget. This coherent, zero-capacity backend applies
         * that policy synchronously: no private lines need movement or power
         * sequencing. Report the applied policy, not physical Qualcomm ways. */
        *value = ((uint64_t)state->cache_way_policy << 24) |
                 ((uint64_t)state->cache_way_policy << 8);
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        reg >= 0x25000 && reg <= 0x25030 && !(reg & 7)) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4) return DEVICE_BAD_WIDTH;
        /* _amccEnableErrors reads, ORs the driver's enable bits and clears
         * its disable bits before writing seven registers per DCS. These
         * are policy latches only; the coherent backend has no AMCC fault
         * producer. Adjacent error status/acknowledgement words stay trapped. */
        uint32_t *mask=&state->mcc_error_mask[bank][(reg-0x25000)/8];
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            *mask=(uint32_t)*value;
        } else *value=*mask;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        (reg == 0x2a000 || reg == 0x2a008 || reg == 0x2a010 || reg == 0x2e000)) {
        if (width != (reg == 0x2e000 ? 4 : 8)) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        unsigned slot = reg == 0x2e000 ? 3 : (reg-0x2a000)/8;
        /* enableDsidProfileCounters writes these configuration words. The
         * guest labels +2e000 as sampling interval and packs +2a008 as a
         * five-bit DSID plus a three-bit mode. Keep the other control words
         * opaque: bit 4 in +2a000 is not evidence of a reset or completion.
         * No profile sample/status registers are implemented by these latches. */
        if (write) {
            if ((slot == 0 && *value != 0 && *value != 1 && *value != 0x11) ||
                (slot == 1 && (*value & ~0x71fUL)) ||
                (slot == 2 && *value != 0 && *value != 0x10000000) ||
                (slot == 3 && *value != 0 && *value != 0x100))
                return DEVICE_BAD_VALUE;
            state->dsid_profile[bank][slot] = *value;
        } else *value = state->dsid_profile[bank][slot];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        (reg == 0x2a058 || reg == 0x2a060)) {
        if (width != 8) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        if (write) return DEVICE_READ_ONLY;
        /* setDsidCntrCtrlParameters / DSID 0 Hits and DSID 0 Misses. */
        *value = state->counter[bank][32 + (reg == 0x2a060)];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        (reg == 0x28000 || (reg >= 0x29000 && reg < 0x29100))) {
        /* setAmccCntrCtrlParameters selects 32 possible counter bits and
         * pairs each with read64 at DCS*0x40000 + 0x29000 + index*8.
         * Enable gates submitted virtual-fabric events; disabling preserves
         * accumulated values. No physical-host performance counts are used.
         * Register reset/selection beyond this fixed bank remains unsupported. */
        if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        if (reg == 0x28000) {
            if (write) {
                if (*value >> 32) return DEVICE_BAD_VALUE;
                state->counter_enable[bank] = *value;
            } else *value = state->counter_enable[bank];
            return DEVICE_OK;
        }
        if (write) return DEVICE_READ_ONLY;
        *value = state->counter[bank][(reg-0x29000)/8];
        return DEVICE_OK;
    }
    if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
    if (model->kind == DEVICE_AIC3_FLAT_V1) {
        struct aic_config config = {(uint32_t)model->config[0],
                                    (uint32_t)model->config[3], model->config[2]};
        const enum device_result results[] = {DEVICE_OK, DEVICE_BAD_CONFIG,
            DEVICE_UNKNOWN_REGISTER, DEVICE_READ_ONLY, DEVICE_BAD_WIDTH, DEVICE_BAD_VALUE};
        return results[aic_access(&config, state ? &state->aic : 0,
                                  offset, width, write, value)];
    }
    /* MemCacheCIP::readCacheSize decodes bits 23:8 as KiB per DCS and
     * multiplies by DCS count. The coherent backend has no separate Apple
     * memory-side cache, so its capacity is zero. CPU caches remain real and
     * use architectural maintenance; this does not report their capacity or
     * claim to implement MCC flush, power, protection, or error registers. */
    /* getDSIDGroupQuota accepts indices 0..32 and decodes the low six
     * bits in units of 128 KiB per DCS. No private cache means no quota. */
    int quota = reg >= 0xa000 && reg <= 0xa080;
    /* AppleH17PPlatformErrorHandler::_initDSIDTimeoutReporter walks 191
     * client selectors at 9000..92f8, then indexes a800..a87c by the low
     * five bits. This coherent backend routes clients to group zero and
     * has no private-cache timeout engine: all timeout enables are clear.
     * These global tables are read-only; no error/completion is fabricated. */
    int timeout = (offset >= 0x9000 && offset <= 0x92f8) ||
                  (offset >= 0xa800 && offset <= 0xa87c);
    /* AppleH17PPlatformErrorHandler::_amccSramEventHandler sums sixteen
     * global counters at 34400 + index*16, masks each to nineteen bits and
     * scales by 512 bytes (26A428: 9b38eb4..ee0). This backend owns no
     * private MCC SRAM and accepts no SRAM allocation commands, so allocated
     * bytes are zero. These are not per-DCS banks or DRAM capacity registers;
     * adjacent status/control words and all writes remain unsupported. */
    int sram = model->kind == DEVICE_MCC_COHERENT_V1 &&
               offset >= 0x34400 && offset <= 0x344f0 && !(offset & 15);
    if (offset / 0x40000 >= model->config[0] ||
        (reg != 0x2c && !quota && !timeout && !sram))
        return DEVICE_UNKNOWN_REGISTER;
    if (write) return DEVICE_READ_ONLY;
    *value=0;
    return DEVICE_OK;
}

int device_irq_pending(const struct device_model *model, const struct device_state *state)
{
    if (!valid(model) || !state || model->kind != DEVICE_AIC3_FLAT_V1) return 0;
    struct aic_config config = {(uint32_t)model->config[0],
                                (uint32_t)model->config[3], model->config[2]};
    return aic_pending(&config, &state->aic);
}

enum device_result device_irq_set_level(const struct device_model *model,
    struct device_state *state, unsigned irq, int level)
{
    if (!valid(model) || !state || model->kind != DEVICE_AIC3_FLAT_V1)
        return DEVICE_BAD_CONFIG;
    struct aic_config config = {(uint32_t)model->config[0],
                                (uint32_t)model->config[3], model->config[2]};
    return aic_set_level(&config, &state->aic, irq, level) == AIC_OK ?
           DEVICE_OK : DEVICE_BAD_VALUE;
}
