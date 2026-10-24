/* SPDX-License-Identifier: MIT */
/* xnuboot_setup and xnuboot_save: the monitor-side state set up before entry.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

int xnuboot_setup(uint64_t work, uint64_t size, uint64_t params, uint64_t out,
                  const struct secondary_config *host_cpus);
int xnuboot_setup(uint64_t work, uint64_t size, uint64_t params, uint64_t out,
                  const struct secondary_config *host_cpus)
{
    struct context *c = (struct context *)work;
    for (unsigned n = 0; n < sizeof(*c) / 8; n++) ((uint64_t *)c)[n] = 0;
#if SNAP_ROOT_CACHE_WIDE
    /* The wide cache's state takes the arena's first pages (owner 0, never
     * released); next_table starts after it below. */
    if (size < sizeof(*c) + 4096 + ROOT_EXT_PAGES * 4096) return 1;
    c->root_ext = (struct root_ext *)((work + sizeof(*c) + 0xfff) & ~0xfffUL);
    for (uint64_t n = 0; n < ROOT_EXT_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->root_ext)[n] = 0;
#endif
#if SNAP_TXM_ASPACE_WIDE
    /* The TXM registry follows (compat/txm.h A3/A5): zeroed before any TXM
     * call, owner 0, below next_table, never a table. */
    if ((work & 0xfff) || size < TXM_EXT_OFFSET + TXM_EXT_PAGES * 4096 + 4096) return 1;
    for (uint64_t n = 0; n < TXM_EXT_PAGES * 4096 / 8; n++) ((volatile uint64_t *)TXM_REG(c))[n] = 0;
#endif
    c->params = (const struct params *)params;
    c->writer_breakpoints_enabled=SNAP_NATIVE_WRITER_BREAKPOINTS;
    c->host_cpus=host_cpus;
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        c->vcpus[n].context = c;
        c->vcpus[n].slot = n;
        c->vcpus[n].vmpidr = 0x80000000UL | (n < 4 ? n : 0x100+n-4);
        sprr_root_reset(&c->user_roots.sprr[n],0);
        if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,n))return 1;
        pauth_user_init(&c->user_pauth[n]);
        c->vcpus[n].guest_apga_lo=c->user_pauth[n].key[PAUTH_GA].lo;
        c->vcpus[n].guest_apga_hi=c->user_pauth[n].key[PAUTH_GA].hi;
    }
    c->vcpus[0].vmpidr = c->params->vmpidr;
    c->vcpus[0].vncr_va = c->params->vncr_va;
    __asm__ volatile("msr tpidr_el2, %0; isb" :: "r"(&c->vcpus[0]) : "memory");
    c->skip_undef = c->params->skip_undef;
    vcpu_of(c)->out_ptr = out;
    c->cpus.registered = 1; /* The loader has already entered guest CPU0. */
    c->next_table = (work + sizeof(*c) + 0xfff) & ~0xfffUL;
    c->work_start = work;
    c->work_base = c->next_table;
#if SNAP_ROOT_CACHE_WIDE
    c->next_table += ROOT_EXT_PAGES * 4096;
#endif
#if SNAP_TXM_ASPACE_WIDE
    if (c->next_table != (uint64_t)TXM_REG(c)) return 1;
    c->next_table += TXM_EXT_PAGES * 4096;
#endif
#if SNAP_USER_HW_WALK
    /* The records follow root_ext and (SNAP_TXM_ASPACE_WIDE) the TXM registry,
     * whose fixed offset assumes it sits right after root_ext; also owner 0
     * (the pool's owner bytes start zero), stored without a note and so
     * never a coverage sentinel (txn_publish_exclude). */
    if (c->next_table + HW_WALK_PAGES * 4096 > work + size) return 1;
    c->hw_walk = (struct hw_walk_state *)c->next_table;
    for (uint64_t n = 0; n < HW_WALK_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->hw_walk)[n] = 0;
    /* The zeroing is done through a uint64_t view: no typed store below may
     * be moved above it (compat/user-hw-walk.h hw_walk_prune, v55). */
    __asm__ volatile("" ::: "memory");
    for (unsigned n = 0; n < HW_WALK_ROOTS; n++) c->hw_walk->roots[n].index = n;
    c->next_table += HW_WALK_PAGES * 4096;
#endif
    c->work_end = work + size;
    if(c->params->txm_native.image) {
        const struct txm_native_params *n=&c->params->txm_native;
        if(n->image!=0xb0600000 || n->size!=TXM_NATIVE_BYTES ||
           size<TXM_NATIVE_BYTES || n->work!=work+size-TXM_NATIVE_BYTES ||
           (n->work&0x3fff) || !n->tree_size || n->tree_size>0x100000)return 1;
        c->work_end=n->work; /* Private crypto scratch must never become a shadow table. */
    } else if(c->params->txm_native.work || c->params->txm_native.size || c->params->txm_native.tree_size)return 1;
#if SNAP_S2_FAULT_RETRY
    /* compat/s2-fault-retry.h: one page, owner 0 (the pool's owner bytes
     * start zero), zeroed through a uint64_t view and stored without a note
     * (txn_publish_exclude). */
    if (c->next_table + S2_RETRY_PAGES * 4096 > c->work_end) return 1;
    c->s2_retry = (struct s2_retry_state *)c->next_table;
    for (uint64_t n = 0; n < S2_RETRY_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->s2_retry)[n] = 0;
    __asm__ volatile("" ::: "memory");
    c->next_table += S2_RETRY_PAGES * 4096;
#endif
#if SNAP_GUEST_NET
    /* compat/guest-net-link.h: stored the same way (txn_publish_exclude). */
    if (c->next_table + GUEST_NET_STATE_PAGES * 4096 > c->work_end) return 1;
    c->guest_net = (struct guest_net_state *)c->next_table;
    for (uint64_t n = 0; n < GUEST_NET_STATE_PAGES * 4096 / 8; n++) ((volatile uint64_t *)c->guest_net)[n] = 0;
    __asm__ volatile("" ::: "memory");
    c->next_table += GUEST_NET_STATE_PAGES * 4096;
#endif
#if SNAP_EDP_BACKLIGHT
    /* compat/edp-backlight.h: one page, zeroed (EDP_BL_STATE_UNPROBED), probed by the first guest call. */
    if (c->next_table + 4096 > c->work_end) return 1;
    c->edp_backlight = (struct edp_backlight_state *)c->next_table;
    for (uint64_t n = 0; n < 4096 / 8; n++) ((volatile uint64_t *)c->edp_backlight)[n] = 0;
    __asm__ volatile("" ::: "memory");
    c->next_table += 4096;
#endif
    if(c->params->early_stop.flags & EARLY_STOP_F_THERMAL) {
        if(c->next_table>c->work_end || c->work_end-c->next_table<4096)return 1;
        c->thermal=(struct a16_thermal_state *)c->next_table;
        for(unsigned n=0;n<4096/8;n++)((volatile uint64_t *)c->thermal)[n]=0;
        __asm__ volatile("" ::: "memory");
        c->next_table+=4096;
    }
    if(c->work_end<c->work_base || (c->work_end-c->work_base)/4096>TABLE_POOL_MAX)return 1;
    c->table_pool.head=TABLE_POOL_MAX;
    /* Every table page lies in [work_base, work_base+pages*4096). */
    c->table_memo.base=c->work_base;
    c->table_memo.pages=(c->work_end-c->work_base)/4096;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        UOWNERS(c)[i].context=c;UOWNERS(c)[i].owner=i+1;
    }
    return 0;
}

void xnuboot_save(uint64_t vbar, uint64_t hcr, uint64_t tpidr,
                  uint64_t sctlr, uint64_t tcr, uint64_t daif);
void xnuboot_save(uint64_t vbar, uint64_t hcr, uint64_t tpidr,
                  uint64_t sctlr, uint64_t tcr, uint64_t daif)
{
    struct context *c = context_of();
    vcpu_of(c)->save_vbar = vbar;
    vcpu_of(c)->save_hcr = hcr;
    vcpu_of(c)->save_tpidr = tpidr;
    vcpu_of(c)->save_sctlr = sctlr;
    vcpu_of(c)->save_tcr = tcr;
    vcpu_of(c)->save_daif = daif;
}
