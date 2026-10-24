/* SPDX-License-Identifier: MIT */
/* The shared context and vCPU types, their layout checks, boot-relocation and
 * context accessors, and service-detail timing.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

struct context;
struct user_table_owner {struct context *context; unsigned owner;};
/* TPIDR_EL2 points to the current physical executor's private guest CPU.
 * Shared services and models live in context under the runtime service lock.
 * Coordinated stop and secondary setup remain before another executor may run. */
struct vcpu {
    /* Assembly exception/return ABI; never use a shared active-CPU index. */
    uint64_t el2_sp, out_ptr, bad_elr, bad_far;
    struct context *context;
    uint64_t slot, vmpidr, vncr_va, prepared;
    uint64_t shadow_root, stage2_root, low_root, low_leaves;
    uint64_t guest_ttbr0, guest_ttbr1, guest_tcr, guest_mair, guest_sctlr;
    uint64_t guest_apga_lo, guest_apga_hi;
    uint64_t kernel_returns, pacga_calls, last_kernel_return;
    struct guest_clock clock;
    struct guest_timer timer, idle_physical_timer;
    struct clock_rate clock_rate;
    struct guest_event clock_event;
    uint64_t save_cnthctl, guest_cnthctl;
    uint64_t clock_backend_reads, clock_raw_first, clock_raw_last;
    uint64_t clock_guest_first, clock_guest_last;
    uint64_t wfe_traps, event_wakes, wfe_early, arch_counter_reads;
    uint64_t save_cntkctl, clock_saved, clock_hz;
    uint64_t watchdog_deadline, watchdog_live;
    uint64_t timer_irqs, timer_asserts, timer_clears, timer_vectors, timer_irq_pc;
    uint64_t fault_esr, fault_far, fault_elr;
    uint64_t save_mdcr, save_mdscr, dbg_oslsr;
    struct exception_step stepping;
    uint64_t timer_pending;
    uint64_t model_irq_pending, model_irq_asserts, model_irq_clears, model_irq_vectors;
    uint64_t step_exception_repairs;
    uint64_t save_vbar, save_hcr, save_tpidr, save_sctlr, save_tcr, save_daif;
    uint64_t save_vmpidr, save_cnthp_ctl, save_cnthp_cval;
    uint64_t save_ttbr0, save_ttbr1, save_mair, save_vttbr, save_vtcr;
    struct guard guards[12];
    uint64_t guard_count, open_guards;
    uint64_t exceptions, panic_calls, async_captured;
    struct guest_regs first_exc, last_exc, panic_exc, async_regs;
    struct guest_ipi ipi;
    uint64_t ipi_request_pc, ipi_ack_pc;
    uint64_t service_acquires, service_fault;
} __attribute__((aligned(64))); /* independent cache lines for each CPU */

struct user_execution {
    uint64_t returns, pending, executed, interrupted, faults, svcs;
    uint64_t entry, stack, initial_spsr, root, shadow, ttbr, tcr;
    uint64_t entry_pa, source_pte, shadow_pte, instruction, initial_x0;
    uint64_t observed_pc, observed_spsr, observed_esr, observed_x0, observed_sp;
};

struct view_table_read_stats {
    uint64_t calls,complete,tables,map_calls,map_complete,errors;
};
struct context {
    const struct params *params;
#if SNAP_TXM_ASPACE_WIDE
    /* Define-free 512-slot twin for host readers, refreshed at the stop
     * (txm_ext_mirror); the live registry is TXM_REG(c), in arena pages
     * after the context (compat/txm.h A3). */
    struct txm_registry_compat txm_registry_host;
#else
    struct txm_registry txm_registry;
#endif
    uint64_t serial_disabled; /* the kernel has taken its console back */
    uint64_t lockdowns;       /* SPTM_FN_LOCKDOWN calls acknowledged */
    uint64_t skip_undef;      /* step over instructions this CPU lacks */
    uint64_t undef_skipped;   /* how many were stepped over: not "answered" */
    uint64_t next_table, work_start, work_base, work_end;
    uint64_t leaves, traps, events, steps, aborts;
    uint64_t map_pages;       /* SPTM_FN_MAP_PAGE calls completed */
    uint64_t map_failures;    /* ...and how many returned an error instead */
    uint64_t map_outside;     /* ...and how many pointed outside our memory */
    uint64_t map_device;      /* ...and how many were a device the tree names */
    uint64_t log_dropped;     /* events the log had no room for */
    uint64_t dispatch_cmds;   /* calls refused because they were not endpoint calls */
    /* Every monitor call that reached the dispatcher, by endpoint, whatever
     * became of it -- answered, refused, or acknowledged permissively. The
     * log cannot carry this: it collapses repeats and then drops the rest, so
     * a run that calls one endpoint four hundred times and another once shows
     * two lines and no counts. `endpoint_other` is the single bucket for
     * everything that is not an XNU_BOOTSTRAP endpoint call: another domain,
     * another table, a dispatch command that is not a call, or an endpoint
     * number too large to bucket honestly. Aliasing endpoint 64 onto endpoint
     * 0 would put a stranger's calls in LOCKDOWN's column, which is precisely
     * the kind of silent collapse this file keeps finding, so it does not. */
    uint64_t endpoint_calls[ENDPOINT_BUCKETS];
    uint64_t endpoint_other;
    /* Every PTE that pointed outside the memory we declared, as spans. A slot
     * is extended when the next page continues it in BOTH address spaces and
     * carries the same attributes; anything else starts a new one. All three
     * conditions matter: same VA run and same PA run is what makes it one
     * mapping rather than two that happen to be adjacent, and equal attributes
     * are what let a single `attrs` field describe the whole span instead of
     * quietly describing only its first page. */
    struct map_range { uint64_t va, pa, pages, attrs; } ranges[MAP_RANGES];
    uint64_t range_count;     /* slots used */
    uint64_t ranges_dropped;  /* spans that would have needed a 25th slot */
    uint64_t update_calls, update_entries;
    uint64_t region_calls, region_entries;
    struct sptm_update_workspace update_workspace;
    struct sptm_ref_batch references;
    struct sptm_slide_state slide;
    uint64_t device_reset_mask[DEVICE_RESET_WORDS];
    uint64_t txm_developer_notifications;
    uint32_t cputrace_queries[2]; /* independently saturated at UINT32_MAX */
    uint64_t model_reads[DEVICE_MODEL_MAX], model_writes[DEVICE_MODEL_MAX];
    struct device_state model_state[DEVICE_MODEL_MAX];
    uint64_t calls, console_len, exc_return;
    uint64_t console_dropped;  /* bytes past CONSOLE_MAX, counted not kept */
    /* The trapped-MMIO dispatcher. Every access to a device window the guest's
     * own tree names arrives at EL2 and is answered here; these are the tally,
     * because there is one per character of the kernel's output and the event
     * log would be nothing else. `uart_tx` is the one that matters: it is how
     * many bytes XNU put on its own serial line, which is the difference
     * between a console that works and a console that was never reached. */
    uint64_t mmio_reads, mmio_writes, uart_tx;
    struct dockchannel uart;  /* what its config and mask registers remember */
    uint8_t console[CONSOLE_MAX];
    /* The terminal word: the last event recorded, held outside the ring.
     *
     * The log fills from the front and drops the rest, so what it keeps is the
     * START of the run. That is the right trade -- a MAP_PAGE we refused is a
     * fact wherever it sits -- but it means the END of a long run is not in
     * the log at all, and "what was the last thing that happened" is the
     * question every unexplained stop starts with. One slot, written by
     * record() before it decides whether the ring has room, answers it for
     * free and cannot be dropped. */
    struct event last;
    struct event log[EVENT_MAX];
    uint64_t fb_observed, fb_before;
    /* Append-only: keep existing report/collector state offsets stable. */
    struct guest_cpu_registry cpus;
    const struct secondary_config *host_cpus;
    uint64_t secondary_base;
    struct guest_cpu_release cpu_release;
    struct vcpu vcpus[GUEST_CPU_COUNT];
    uint64_t shadow_tlb_syncs, root_checks, root_busy_refusals;
    /* SNAP_DART_WIREDCNT (compat/dart-wiredcnt.h DWC_*): located text PA,
     * commits, entries subtracted, refusals, last refusal reason | table << 8.
     * In the former alignment hole before services: every build, zero unless
     * on, with no other offset or the context size changed. */
    uint64_t dart_wiredcnt[5];
    struct guest_service_lock services;
    uint64_t txm_image4_uuid_rejections;
    struct txm_nonce_registry txm_nonces;
#if SNAP_ROOT_CACHE_WIDE
    struct sptm_root_state_compat user_roots_host;   /* live: root_ext->roots */
#else
    struct sptm_root_state user_roots;
#endif
    uint64_t root_installed[GUEST_CPU_COUNT][2], root_install_failures;
    uint64_t const_reads[2], const_sealed_cpus, const_tlb_invalidations;
    uint64_t user_live_tables, user_live_pages, user_missing_tables;
    uint64_t user_unmap_calls, user_unmap_pages;
    uint64_t user_condemn_calls, user_uncondemn_calls, user_detach_calls;
    struct txm_nonce_digest_registry txm_nonce_digests;
    uint64_t user_comm_attach_calls,user_comm_attach_leaves;
    uint64_t shared_root_converts,shared_root_releases;
    struct sptm_root_configuration root_configuration;
    struct sptm_shared_registry shared_regions;
    struct txm_trust_state trust_state;
    struct sptm_nest_state nest_state;
    struct sprr_views kernel_views;
    uint64_t kernel_installed[GUEST_CPU_COUNT],kernel_view_failed;
    uint64_t papt_protects,papt_releases,kernel_permission_changes;
    uint64_t user_exec_protects,user_exec_releases,user_exec_cache_syncs;
    struct user_execution user_execution[GUEST_CPU_COUNT];
    struct sptm_panic_state panic_state;
    /* Physical exception-entry evidence; keep the existing vCPU ABI stable. */
    struct pan_entry_state {
        uint64_t mmfr1, installed_sctlr, user_vectors, protected_vectors;
        uint64_t vector, saved_spsr, entry_spsr, entry_sctlr;
    } pan_entry[GUEST_CPU_COUNT];
    struct user_clock_state {
        uint64_t reads, pc, word, value, spsr, sp, root, cntkctl;
        uint64_t raw, host_hz, guest_hz;
    } user_clock[GUEST_CPU_COUNT];
    struct user_map_conflict_state {
        uint64_t count, root, va, wanted, options, old, pointer, result;
    } user_map_conflict[GUEST_CPU_COUNT];
    struct user_sprr_state {
        uint64_t reads, pc, word, value, spsr, sp, root, umprr;
    } user_sprr[GUEST_CPU_COUNT];
    struct sprr_uperm_update_state {
        uint64_t writes,changes,pc,word,before,after,spsr,sp;
        uint64_t root,shadow,tables,pages,classes,umprr;
    } sprr_uperm_update[GUEST_CPU_COUNT];
    struct sprr_pperm_update_state {
        uint64_t transactions,grants,restores,before,after,pc;
        uint64_t user_root,user_shadow,user_tables,user_pages,user_classes;
        uint64_t kernel_root,kernel_tables,kernel_pages,kernel_classes;
    } sprr_pperm_update[GUEST_CPU_COUNT];
    struct sprr_views user_views[SPTM_ROOT_CACHE_COMPAT];
    struct user_view_state {
        uint64_t root,shadow,el0,uperm,pperm,umprr;
        uint64_t syncs,entries,returns;
    } user_view_state[GUEST_CPU_COUNT];
    uint64_t user_view_failed,user_tpro_protects,user_tpro_releases;
    struct sptm_user_update_state user_updates[GUEST_CPU_COUNT];
    struct sptm_user_update_state kernel_updates[GUEST_CPU_COUNT];
    uint64_t shared_plan_mask,shared_plan_root,shared_plan_va,shared_plan_count;
    uint64_t shared_map_calls,shared_map_inserts,shared_map_updates,shared_map_aliases;
    uint64_t shared_map_root,shared_map_va,shared_map_old,shared_map_next,shared_map_shift;
    uint64_t shared_map_mask,shared_unmap_calls,shared_unmap_pages;
    uint64_t shared_map_requested,shared_map_options,shared_map_result,shared_map_cpu;
    uint64_t unnest_calls,unnest_descriptors,unnest_leaves,unnest_root,unnest_shared;
    uint64_t unnest_va,unnest_pages,unnest_cpu,unnest_format;
    struct sptm_unnest_plan unnest_plan;
    struct sptm_shared_detach_state shared_detaches;
    struct sptm_user_update_state user_regions[GUEST_CPU_COUNT];
    uint64_t service_budget_stops[GUEST_CPU_COUNT];
    struct sptm_shared_update_state shared_regions_updates[GUEST_CPU_COUNT];
    struct pauth_user_state user_pauth[GUEST_CPU_COUNT];
    struct pauth_switch pauth_bank[GUEST_CPU_COUNT];
    struct pauth_domain pauth_domain;
    uint64_t pauth_key_version[GUEST_CPU_COUNT],pauth_key_valid[GUEST_CPU_COUNT];
    struct pauth_batch_state pauth_batch[GUEST_CPU_COUNT];
    struct pauth_pointer_state pauth_pointer[GUEST_CPU_COUNT];
    struct sptm_shared_update_state user_disjoint_unmaps[GUEST_CPU_COUNT];
    struct sptm_user_update_state user_map_replacements[GUEST_CPU_COUNT];
    struct txm_release_type txm_release_type;
    struct txm_local_key txm_local_key;
    struct table_pool table_pool;
    struct user_table_owner user_table_owner[SPTM_ROOT_CACHE_COMPAT];
    struct service_profile service_profile[GUEST_CPU_COUNT];
    struct step_translation step_translation[GUEST_CPU_COUNT];
    struct step_alu_state step_alu[GUEST_CPU_COUNT];
    struct native_call_state native_calls[GUEST_CPU_COUNT];
    uint64_t user_view_epoch;
    struct sprr_view_proof user_view_proofs[SPTM_ROOT_CACHE_COMPAT];
    struct sprr_view_proof_stats user_view_proof_stats[GUEST_CPU_COUNT];
    uint64_t user_only_tlbi[4]; /* leaf, unmap, commpage attach, nest */
    struct service_detail service_detail[GUEST_CPU_COUNT];
    struct sprr_publish_state kernel_publish_state;
    struct sprr_reuse_state kernel_reuse_state;
#if SNAP_VIEW_RECLAIM
    /* kernel_views_prepare_change: reclaims that retired tables, tables they
     * retired, refusals that found nothing to retire, the highest count. With
     * this define every offset from kernel_views on moves anyway (the wider
     * struct sprr_views); placed after pauth_bank so PAUTH_BANK_CONTEXT moves
     * by whole views only. */
    struct kernel_view_reclaim {uint64_t reclaims,retired,full,high_water;} kernel_view_reclaim;
#endif
    uint64_t user_fused_syncs;
    struct sprr_class_proof kernel_class_proof;
    struct sprr_user_prepare_stats user_prepare_stats;
    struct sprr_user_prepare_plan user_prepare_plan;
    struct sprr_private_pages private_pages;
    struct root_publish_state root_publish;
    struct user_publish_stats user_publish;
    uint64_t user_table_reads[3]; /* calls, complete, errors */
    struct view_table_read_stats view_table_reads[2]; /* kernel, single-CPU user */
    struct sprr_user_zero_stats user_zero_groups;
    struct native_writer_debug writer_debug[GUEST_CPU_COUNT];
    uint64_t writer_breakpoints_enabled;
    struct sprr_store_compare_stats view_store_compare[2]; /* kernel, single-CPU user */
    struct sprr_store_compare_stats user_fused_compare;
    /* Appended: FEAT_AES present, set once by pauth_domain_prepare. */
    uint64_t aes_hardware;
    /* Appended: per-vCPU PAC key derivation memo (install and user signing). */
    struct pauth_derive_cache pauth_derive[GUEST_CPU_COUNT];
    /* Appended: mode switches skipped, sampled full syncs, and sampled syncs
     * that still had to store (must stay zero). */
    struct user_mode_skip_stats { uint64_t skips,checks,mismatches,differs; }
        user_mode_skip[GUEST_CPU_COUNT];
    /* Appended: guest BRK64 exceptions delivered to EL1 (TDE-routed). */
    struct guest_brk_stats { uint64_t el0,el1,last_pc,last_esr,last_spsr; }
        guest_brk[GUEST_CPU_COUNT];
    /* Appended (kernel-ops-perf): transaction dirty publication + sentinel. */
    struct txn_publish_stats txn_publish;
    /* Appended: PPERM transactions against the exact kernel reuse snapshot.
     * skipped kernel syncs; verified = sampled read-only checks of a skipped
     * view (1 per 64 skips); mismatches must stay zero. */
    struct kernel_pperm_reuse_stats {
        uint64_t calls,current,skipped,synced,repinned,verified,mismatches,errors;
    } kernel_pperm_reuse;
    /* Appended: user UPDATE_DISJOINT kernel refreshes skipped and their
     * sampled (1/64) all-CPU read-only kernel view verification. */
    struct user_update_skip_stats {
        uint64_t skipped,verified,mismatches;
    } user_update_skip;
    /* Appended: root installations whose inner private-copy TLBIs were folded
     * into the installation's final all-VMID invalidation. */
    struct install_tlbi_stats {
        uint64_t installs,pperm_folded,view_folded,failure_flushes;
    } install_tlbi;
    /* Appended: mapped class-proof walks and their sampled differential walks
     * through the original word reader (mismatches must stay zero). */
    struct class_proof_mapped_stats {
        uint64_t walks,tables,groups,empty_groups,compared,errors;
    } class_proof_mapped;
    /* Appended: SWITCH_ROOT word-load validations and sampled byte re-walks. */
    struct sptm_root_validate_stats root_validate;
    /* Appended: process-fatal EL0 exceptions passed to XNU's vector. */
    uint64_t guest_user_signal[GUEST_CPU_COUNT];
    /* Appended: per-page write witness for the table arena and per-user-view
     * private-copy claims (SNAP_USER_TREE_MEMO); present in every build so the
     * layout readers see one context size. */
    struct sprr_table_memo table_memo;
    struct sprr_view_memo user_view_memo[SPTM_ROOT_CACHE_COMPAT];
    /* SWITCH_ROOT found all SPTM_ROOT_CACHE slots named and took one from a
     * root no CPU had installed (its shadow is rebuilt on its next switch). */
    uint64_t root_evictions;
    /* Appended: table-arena pressure reclaim. root_stamp orders valid cached
     * roots by last installation (arena_reclaim.clock). low_water is the
     * fewest free arena pages seen at any monitor-call entry; slots/pages
     * count cache slots given back and their table pages (retired, invalid
     * and valid slots separately); alloc_failures counts table allocations
     * refused for lack of pages; build_retries counts SWITCH_ROOT builds
     * retried after a reclaim; flush_failures must stay zero. */
    uint64_t root_stamp[SPTM_ROOT_CACHE_COMPAT];
    struct arena_reclaim_stats {
        uint64_t checks,low_water,clock,reclaims,slots,pages;
        uint64_t retired,invalid,valid,alloc_failures,build_retries,flush_failures;
    } arena_reclaim;
    /* Appended: last EL0 crash-class events per vCPU (SNAP_USER_CRASH_RING);
     * present in every build so the layout readers see one context size. */
    struct user_crash_ring user_crashes[GUEST_CPU_COUNT];
    /* Appended: UPDATE_DISJOINT_MULTIPAGE calls and their per-frame groups. */
    uint64_t multipage_calls, multipage_groups;
    /* Appended: kernel-root MAP_PAGE answered CONFLICT(6), count and last. */
    struct kernel_map_conflict_state {
        uint64_t count, va, wanted, old, pointer;
    } kernel_map_conflict;
    /* Appended: PV self-checks (moved MAP_PAGE pointers, different-PA leaf
     * replacements, duplicate disjoint records); see struct sptm_pv_audit. */
    struct sptm_pv_audit pv_audit;
    /* Appended: kernel-root SPTM calls touching the linked AuxKC. Counters
     * only, never a gate: tools/auxkc_counters.py decodes this. */
    struct auxkc_exec_state auxkc_exec;
    /* Appended: the adopted Adreno (compat/adreno.h); tools/adreno_counters.py. */
    struct adreno_state gpu;
    /* Append only: preserve the report and all earlier private offsets.
     * console_put runs under the shared service lock. The host reads this
     * late-boot ring only after all guest CPUs have stopped. */
    uint64_t console_tail_bytes;
    uint8_t console_tail[CONSOLE_TAIL_MAX];
    /* Appended: endpoint8 kernel removals, latest and last changed per CPU. */
    struct sptm_shared_update_state kernel_disjoint_unmaps[GUEST_CPU_COUNT];
    /* Appended: successful DEFAULT -> TXM_DEFAULT ownership transitions. */
    uint64_t txm_donations;
    uint64_t txm_imports,txm_releases;
    struct txm_native_state txm_native;
    struct txm_load_state txm_load;
    /* Appended private cache; its scalar prefix is captured independently.
     * Present even when disabled so host readers have one context layout. */
    struct sprr_class_leaf_cache class_leaf;
    /* Appended: policy loaded by the last successful SWITCH_ROOT on each CPU,
     * separately from root metadata subsequently changed by CONFIGURE_ROOT. */
    struct sptm_loaded_root root_loaded[GUEST_CPU_COUNT];
    /* SNAP_DART_WIREDCNT: Adreno DART level-1 slots whose table holds the
     * monitor's one reference (compat/dart-wiredcnt.h). In the former
     * alignment hole before perf: every build, zero unless on. */
    uint64_t dart_wiredcnt_pins[2];
    /* Appended (perf): fast-trap/census counters, the publication index and
     * canonical-view proof counters, zero unless their define is on. Present
     * in every build so layout readers see one context size;
     * tools/perf_counters.py decodes it. */
    struct perf_state perf;
    /* Appended service-lock-protected request capture; never guest key state. */
    uint8_t sep_sks_request[SEP_SKS_WIRE_MAX];
    /* Appended: SWITCH_ROOT level-3 verdict memo (SNAP_ROOT_VALIDATE_MEMO);
     * its stats prefix is a kernel-ops-perf record. Present in every build so
     * layout readers see one context size. */
    struct sptm_root_memo root_memo;
    /* Appended: memory-attribute changes (UPDATE options 0x10/0x20 and the
     * MULTIPAGE aperture AttrIndx step). cleans counts frames cleaned to PoC
     * before a commit, recleans the same frames again once that transaction's
     * TLBI completed (pending holds them in between), apertures the aperture
     * leaves rewritten; last_* describe the latest aperture step. */
    struct attr_update_state {
        uint64_t cleans,recleans,refused,apertures,last_pa,last_before,last_after,pending;
        uint64_t pending_pa[SPTM_DISJOINT_MAX];
    } attr_updates;
    /* Appended: early-stop request and outcome (compat/early-stop.h). Present
     * in every build so layout readers see one context size. */
    struct early_stop_state early_stop;
    /* Appended: inactive-root mirroring (SNAP_INACTIVE_MIRROR); its stats
     * prefix is a kernel-ops-perf record. budget[slot] counts fresh leaves
     * committed into that cache slot since its root was last installed.
     * Present in every build so layout readers see one context size. */
    struct inactive_mirror_state {
        struct inactive_mirror_stats stats;
        uint64_t budget[SPTM_ROOT_CACHE_COMPAT];
    } inactive_mirror;
    /* Appended: native page tables (SNAP_NATIVE_TABLES). Per-CPU variant
     * selection (compat/native-select.h); one bit per arena page whose stores
     * are propagated into variant copies; counters. Present in every build so
     * layout readers see one context size. */
    struct native_cpu native_cpu[GUEST_CPU_COUNT];
    uint64_t native_sources[MONITOR_ARENA_PAGES/64];
    struct native_table_stats {
        uint64_t propagated,refused,paths,syncs,installs,local_flushes,flips;
        uint64_t tlbi_calls,tlbi_pages,tlbi_full;
        uint64_t audit_asks,audits,audit_failures,hit_asks,hit_skips,proof_asks,proof_skips;
        uint64_t pperm_skips;
        /* Phase 2a: PPERM transactions. */
        uint64_t reuse_asks,reuse_checks,reuse_failures,pperm_flushes;
        /* Phase 3: roots cached at their constructor, and those it could not
         * cache (no slot or no page); full coverage audits. */
        uint64_t created,uncreated,coverages;
    } native_stats;
    /* Appended: shared-region groups (SNAP_NATIVE_SHARED), in every build. */
#if SNAP_ROOT_CACHE_WIDE
    struct native_shared_compat native_shared_host;  /* live: root_ext->native_shared */
#else
    struct native_shared native_shared;
#endif
    /* Appended in every build so offline layout readers agree. */
    struct native_hvc_state sptm_hvc[GUEST_CPU_COUNT];
    /* Appended: the device deadline timer_sync last armed for, per vCPU, as
     * guest ticks and host physical time (UINT64_MAX: none; zero until the
     * first sync, which makes the fast write decline). SNAP_FAST_TIMER_WRITE
     * rearms with it and declines once it has passed. */
    struct fast_timer_due { uint64_t guest,physical; } fast_timer_due[GUEST_CPU_COUNT];
    /* Appended: each CPU's other kernel copy column (SNAP_KERNEL_PPERM_VARIANTS). */
    struct sprr_view_variants kernel_variants;
    /* Appended: the first CONSOLE_LOG_MAX console bytes, never overwritten;
     * console_tail keeps the end. Both count with console_tail_bytes. */
    uint8_t console_log[CONSOLE_LOG_MAX];
    /* Appended: the two-way console (compat/console-link.h): q1n1's view, the
     * DockChannel receive ring, and what every host poll cost. Present in
     * every build so layout readers see one context size. */
    struct console_link console_link;
    /* Appended: UPDATE_DISJOINT records naming a configured shared-region root
     * (XNU aging the shared cache, compat/sptm-user.c), per CPU: the record
     * count and the latest one (root, VA, template, options, result, target,
     * the old leaf it returned; slot holds the caller's ELR). Diagnostic only. */
    uint64_t shared_disjoint_records[GUEST_CPU_COUNT];
    struct sptm_user_update_state shared_disjoint[GUEST_CPU_COUNT];
    /* Appended: per CPU, 1 + the shared-region slot of the last user root installed since this CPU's last full local
     * flush (0: none cached). Shared-region leaves are global (no nG), so a user-to-user TTBR0 switch keeps the
     * previous region's translations. SPTM's SWITCH_ROOT flushes them when the incoming root's slot differs
     * (sptm.t8140.release 0xfffffff02710050c: ldrb w25,[x19,#8] against the per-CPU byte, then tlbi rvaae1nxs or
     * vmalle1nxs); user_root_install does the same with a local tlbi vmalle1. Without it, the fast variant (no
     * per-exception guard flushes) ran processes on another region's shared-cache bytes: the v14-v16 crash storm. */
    uint16_t user_shared_slot[GUEST_CPU_COUNT];
    uint64_t shared_switch_flushes[GUEST_CPU_COUNT];
    struct a16_thermal_state *thermal; /* optional monitor-only arena page */
#if SNAP_ROOT_CACHE_WIDE
    /* The wide root cache's state (monitor arena pages, setup); appended in
     * the context's last page (the former tail padding), asserted below. */
    struct root_ext *root_ext;
#endif
#if SNAP_USER_HW_WALK
    /* compat/user-hw-walk.h: records, copies index and counters, in monitor
     * arena pages taken at setup (owner 0, never released); appended in the
     * context's last page, asserted below. */
    struct hw_walk_state *hw_walk;
#endif
#if SNAP_S2_FAULT_RETRY
    /* compat/s2-fault-retry.h: counters, per-vCPU bounds and the snapshot
     * ring, in a monitor arena page taken at setup (owner 0, never released). */
    struct s2_retry_state *s2_retry;
#endif
#if SNAP_GUEST_NET
    /* compat/guest-net-link.h: the link, the net view and POLL2's views, in
     * monitor arena pages taken at setup (owner 0, never released). */
    struct guest_net_state *guest_net;
#endif
#if SNAP_EDP_BACKLIGHT
    /* compat/edp-backlight.h: ADRENO_GUEST_BACKLIGHT's state, one monitor
     * arena page taken at setup (owner 0, never released). */
    struct edp_backlight_state *edp_backlight;
#endif
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
    /* Appended only under these opt-in defines, inside the page before the
     * table arena (asserted below), so define-free layout readers keep every
     * offset and the arena base (compat/perf-state.h struct exit_profile). */
    struct exit_profile exit_profile;
#endif
};
#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,exit_profile)+4095)/4096,
               "the exit profile must not move the table arena (next_table, probes/run.py)");
#endif
#if SNAP_GUEST_NET
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,guest_net)+4095)/4096,
               "the guest-network pointer must not move the table arena (next_table, probes/run.py)");
#endif
#if SNAP_USER_HW_WALK
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,hw_walk)+4095)/4096,
               "the hardware-walk pointer must not move the table arena (next_table, probes/run.py)");
static struct hw_walk_root *hw_root(struct context *,uint64_t);
static struct hw_walk_ops hw_ops(struct context *);
static void hw_install_user(struct context *,uint64_t,uint64_t,unsigned);
static int hw_fail(struct context *);
#if SNAP_USER_HW_WALK_S2RO
static int hw_s2_presplit_all(struct context *);
#endif
#endif
#if SNAP_ROOT_CACHE_WIDE
_Static_assert((sizeof(struct context)+4095)/4096==
               (__builtin_offsetof(struct context,root_ext)+4095)/4096,
               "the wide root cache must not move the table arena (next_table, probes/run.py)");
#if SNAP_FINE_LOCKS
/* SNAP_FINE_LOCKS (compat/fine-lock.h): the stripes, aux and each CPU's
 * converted-call state, in the wide cache's arena pages (monitor-only,
 * written without notes, excluded from the publication sentinel). */
struct fine_cpu {
    struct fine_lockset locks;      /* this call's stripes */
    uint64_t stores;                /* stores made by this call (decline vs fatal) */
    uint64_t aux_wait;              /* this call's aux wait ticks */
    int alloc_refused;              /* this call's shadow allocator was asked */
    struct sptm_pv_audit audit;     /* this call's audit share, merged on success */
    struct fine_profile profile;
    struct sptm_ref_fine ref_fine;  /* this call's reference snapshots */
#if SNAP_SPTM_FINE_RETYPE
    struct sptm_frame_held frames;  /* this call's frame locks (compat/sptm-frame-lock.h) */
#endif
} __attribute__((aligned(64)));
struct fine_state {
    struct fine_ticket stripes[FINE_STRIPES];
    struct fine_ticket aux;
    struct fine_cpu cpu[GUEST_CPU_COUNT];
    struct sptm_ref_batch refs[GUEST_CPU_COUNT];
#if SNAP_SPTM_FINE_KERNEL
    struct fine_ticket kernel;      /* KL: converted kernel-root calls (compat/sptm-fine.h) */
#endif
#if SNAP_SPTM_FINE_RETYPE
    struct sptm_frame_locks frame_locks;
#endif
};
#endif
/* Every slot's state, SPTM_ROOT_CACHE of each (compat/root-wide.h). */
struct root_ext {
    struct sptm_root_state roots;
    struct native_shared native_shared;
    struct sprr_views views[SPTM_ROOT_CACHE];
    struct user_table_owner owner[SPTM_ROOT_CACHE];
    struct sprr_view_proof proofs[SPTM_ROOT_CACHE];
    struct sprr_view_memo memo[SPTM_ROOT_CACHE];
    uint64_t stamp[SPTM_ROOT_CACHE],budget[SPTM_ROOT_CACHE];
    sptm_root_mask_t shared_plan_mask;
#if SNAP_FINE_LOCKS
    struct fine_state fine;
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
    struct sptm_nest_fast_stats nest_fast;    /* compat/nest-fast.h, reported (OUT_TOKEN_COSTS) */
#endif
#if SNAP_ROOT_INDEX
    struct sptm_root_index root_index;        /* compat/root-index.h, stats reported */
#endif
#if SNAP_OTHER_PROFILE
    struct other_profile other;               /* compat/token-costs.h */
#endif
#if SNAP_DART_MEMO
    struct sptm_dart_memo dart_memo;          /* compat/sptm-dart-memo.h, under the token (OUT_DART_MEMO) */
#endif
#if SNAP_GATE_WAIT
    uint64_t gate[16];                        /* waited, wait ticks, timeouts, stopped (atomic) */
#endif
#if SNAP_TOKEN_TRIM
    struct token_trim_state trim;             /* compat/token-trim.h (OUT_TOKEN_TRIM) */
#endif
#if SNAP_DART_CONVERTED
    struct dart_converted_state dart_cv;      /* compat/dart-converted.h (no record of its own) */
#endif
#if SNAP_FAST_IPI
    struct fast_ipi_cpu fast_ipi[GUEST_CPU_COUNT];  /* compat/fast-ipi.h, that CPU's (OUT_FAST_IPI) */
#endif
#if SNAP_FAST_TIMER_IRQ_CPU0
    struct fast_irq_cpu0 cpu0_tick;                 /* compat/fast-timer-irq.h, vCPU 0's only */
#endif
#if SNAP_LEAN_TRAPS
    struct lean_trap_cpu lean[GUEST_CPU_COUNT];     /* compat/lean-trap.h, that CPU's (not reported) */
#endif
#if SNAP_EL0_MEMO
    struct el0_memo_cpu el0_memo[GUEST_CPU_COUNT];         /* compat/el0-memo.h, that CPU's (not reported) */
    struct pauth_derive_wide derive_wide[GUEST_CPU_COUNT]; /* compat/pauth-domain.h, that CPU's */
    uint64_t pauth_epoch;                                  /* xnuboot_prepare: one per domain preparation */
#endif
#if SNAP_FAST_TIMER_IRQ
    struct fast_irq_cpu fast_irq[GUEST_CPU_COUNT];  /* compat/fast-timer-irq.h, that CPU's (OUT_FAST_IRQ) */
#endif
#if SNAP_ADRENO_IB_ASYNC
    /* compat/adreno-ib.h: the IB in flight and its counters (OUT_IB_ASYNC), under the token. Here because the
     * context's last page is full (a member would move the table arena) and these pages are monitor-only arena
     * pages already (zeroed at setup, txn_publish_exclude). Last, so no other member moves. */
    struct adreno_ib_flight ib_flight;
#endif
#if SNAP_CPU_DVFS
    struct cpu_dvfs_state cpu_dvfs;   /* compat/cpu-dvfs.h: vCPU 0's tick and the stop only (OUT_DVFS); last */
#endif
#if SNAP_GPU_DVFS
    struct gpu_dvfs_state gpu_dvfs;   /* compat/gpu-dvfs.h: under the token (OUT_DVFS); last */
#endif
#if ADRENO_VA_WIDE && SNAP_DART_WIREDCNT
    /* agents/gpu-va-wide V15: level-1 slots 0..511 (the context keeps its 2-word, slots 0..127 field so its
     * page count, and the table arena after it, do not move); zeroed with the rest of root_ext at setup. */
    uint64_t dart_wiredcnt_pins_wide[DWC_PIN_WORDS];
#endif
#if SNAP_ANS_ASYNC
    /* agents/nvme-async: the virtual ANS2's state when its window backend is adopted (ans_window_prepare), else
     * 0; read lock-free by timer_arm and the fast tick for the poll schedule (struct ans_async). Last. */
    struct ans_state *ans;
#endif
#if SNAP_ANS_CONVERTED
    /* The ANS device lock (FIFO, L1.5 beside the DART's) and this CPU's wait for the converted call in progress. */
    struct fine_ticket ans_lock;
    uint64_t ans_wait[GUEST_CPU_COUNT][2];
#endif
#if SNAP_ATTR_CLEAN_DEFER
    /* (d) Each CPU's second cleans of an attribute change, deferred past the token (attr_clean_finish). */
    struct attr_defer_cpu {uint64_t count,deferred,overflow,flushed;uint64_t pa[ATTR_DEFER_MAX];} attr_defer[GUEST_CPU_COUNT];
#endif
#if SNAP_ADRENO_RECOVER
    /* compat/adreno-ib.h (agents/gpu-recovery): level, epoch, the give-up state, the SQE sum. Under the token. Last, so
     * no other member moves; its counters ride in the IBASYNC1 record's reserved words and in EV_GPU_RECOVER. */
    struct adreno_recover_state gpu_recover;
#endif
#if SNAP_MULTIPAGE_FAST
    /* agents/sptm-locks/multipage: each vCPU's aperture targets cleaned before this trap took the token (P2;
     * frames counts them), and the batch counters, written under the token (P17). */
    struct multipage_preclean_cpu {uint64_t count,frames;uint64_t pa[SPTM_MULTIPAGE_MAX];} multipage_preclean[GUEST_CPU_COUNT];
    struct multipage_fast_stats {
        uint64_t preclean_hits,inline_cleans,same_class,patched,unpatched,variants,closes,barrier_closes,failures;
    } multipage_fast;
#endif
#if SNAP_ADRENO_COHERENT
    /* SNAP_ADRENO_COHERENT: the self-test's outcome and the run's mirror leaf word, under the token. Last, so no other
     * member moves. */
    struct adreno_coherent_state gpu_coherent;
#endif
};
#if ADRENO_VA_WIDE && SNAP_DART_WIREDCNT
/* The wide bitmap replaces the context's field for all monitor code (as user_roots below). */
#define dart_wiredcnt_pins root_ext->dart_wiredcnt_pins_wide
#endif
#if SNAP_ADRENO_IB_ASYNC
#define IB_FLIGHT(c) (&(c)->root_ext->ib_flight)
#endif
#if SNAP_ADRENO_RECOVER
#define GPU_RECOVER(c) (&(c)->root_ext->gpu_recover)
#endif
#if SNAP_EL0_MEMO
#define EL0M(c) ((c)->root_ext->el0_memo)
#endif
#define ROOT_EXT_PAGES ((sizeof(struct root_ext)+4095)/4096)
/* The live state replaces the define-free fields for all monitor code. */
#define user_roots root_ext->roots
#define UNS(c) ((c)->root_ext->native_shared)
#define UVIEWS(c) ((c)->root_ext->views)
#define UOWNERS(c) ((c)->root_ext->owner)
#define UPROOFS(c) ((c)->root_ext->proofs)
#define UMEMOS(c) ((c)->root_ext->memo)
#define USTAMPS(c) ((c)->root_ext->stamp)
#define UBUDGETS(c) ((c)->root_ext->budget)
#define ROOT_PLAN_SET(c,m) ((c)->root_ext->shared_plan_mask=(m),(c)->shared_plan_mask=SPTM_ROOT_MASK_LOW(m))
#define ROOT_PLAN_MASK(c) ((c)->root_ext->shared_plan_mask)
#else
#define UNS(c) ((c)->native_shared)
#define UVIEWS(c) ((c)->user_views)
#define UOWNERS(c) ((c)->user_table_owner)
#define UPROOFS(c) ((c)->user_view_proofs)
#define UMEMOS(c) ((c)->user_view_memo)
#define USTAMPS(c) ((c)->root_stamp)
#define UBUDGETS(c) ((c)->inactive_mirror.budget)
#define ROOT_PLAN_SET(c,m) ((c)->shared_plan_mask=(m))
#define ROOT_PLAN_MASK(c) ((c)->shared_plan_mask)
#endif
#if SNAP_TXM_ASPACE_WIDE
/* compat/txm.h A3/A5: the 4096-slot registry takes the arena pages after the
 * context and root_ext; xnuboot_setup refuses an unaligned work base, so the
 * context's address plus this constant is that page. */
#define TXM_EXT_PAGES ((sizeof(struct txm_registry)+4095)/4096)
#if SNAP_ROOT_CACHE_WIDE
#define TXM_EXT_AFTER_ROOT (ROOT_EXT_PAGES*4096)
#else
#define TXM_EXT_AFTER_ROOT 0
#endif
#define TXM_EXT_OFFSET ((((uint64_t)sizeof(struct context)+0xfffUL)&~0xfffUL)+(uint64_t)TXM_EXT_AFTER_ROOT)
#define TXM_REG(c) ((struct txm_registry *)((uint64_t)(c)+TXM_EXT_OFFSET))
_Static_assert(__builtin_offsetof(struct context,txm_registry_host)==8 &&
               sizeof(struct txm_registry_compat)==17952,
               "the define-free TXM registry keeps its offset and size (host readers)");
#else
#define TXM_REG(c) (&(c)->txm_registry)
#endif

/* The vector ABI is private to each CPU, including failure and return state. */
_Static_assert(__builtin_offsetof(struct vcpu, el2_sp) == 0, "CPU return stack ABI");
_Static_assert(__builtin_offsetof(struct vcpu, out_ptr) == 8, "CPU output ABI");
_Static_assert(__builtin_offsetof(struct vcpu, bad_elr) == 16, "CPU bad ELR ABI");
_Static_assert(__builtin_offsetof(struct vcpu, bad_far) == 24, "CPU bad FAR ABI");
_Static_assert(__builtin_offsetof(struct vcpu, context) == 32, "PA context ABI");
_Static_assert(__builtin_offsetof(struct vcpu, slot) == 40, "PA CPU slot ABI");
_Static_assert(__builtin_offsetof(struct context, pauth_bank) == PAUTH_BANK_CONTEXT,"PA bank context ABI");
_Static_assert(sizeof(struct vcpu)==2368,"unchanged private CPU stride");
#if SNAP_BOOT_RELOCATE
/* Secondary record page 0 (otherwise unused): secondary_entry's record first,
 * then the relocation's own state. Host readers: tools/secondary-runtime.py. */
#define BOOT_HOST_WORDS 11
struct boot_relocation {
    struct secondary record;
    uint64_t armed, launched, handed_back, captured;
    uint64_t launch_tick, handback_tick, stop_requested, quarantined, wait_polls;
    uint64_t id_mismatch;
    /* The guest clock is CNTVCT_EL0 at EL2 (clock_counter): CNTPCT minus this
     * CPU's CNTVOFF_EL2, which the monitor never programs. Both CPUs' values,
     * and CNTFRQ_EL0, must agree for vCPU 0 to keep q1n1's CPU's timebase. */
    uint64_t boot_cntvoff, target_cntvoff, boot_cntfrq, target_cntfrq;
    /* q1n1's CPU's own values of what vcpu_arch_prepare saves and the report
     * restores: VTTBR VTCR VMPIDR CNTKCTL CNTHCTL MDCR MDSCR OSLSR TTBR0 TTBR1 MAIR. */
    uint64_t host[BOOT_HOST_WORDS];
    uint64_t boot_cache[2], target_cache[2];   /* CTR_EL0, DCZID_EL0 */
    uint64_t boot_id[BOOT_ID_COUNT], target_id[BOOT_ID_COUNT];   /* BOOT_RELOCATE_ID_REGS order */
    struct boot_relay relay;
};
_Static_assert(__builtin_offsetof(struct boot_relocation, armed) == BOOT_RELOCATE_ARMED,
               "the exit path reads armed");
_Static_assert(sizeof(struct boot_relocation) <= 4096, "record page 0");
_Static_assert(__builtin_offsetof(struct context, secondary_base) == CONTEXT_SECONDARY_BASE,
               "the exit path reads secondary_base");
static struct boot_relocation *boot_relocation_of(const struct context *c)
{
    struct boot_relocation *r = (struct boot_relocation *)c->secondary_base;
    return r && r->armed ? r : 0;
}
static int boot_relocation_on_boot_cpu(const struct context *c)
{
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return c->host_cpus && (mpidr & BOOT_RELOCATE_AFFINITY) == c->host_cpus->boot_affinity;
}
#endif

static struct vcpu *vcpu_of(const struct context *c)
{
    /* c documents the shared owner; selection is always this PE's TPIDR. */
    (void)c;
    uint64_t p;
    __asm__ volatile("mrs %0, tpidr_el2" : "=r"(p));
    return (struct vcpu *)p;
}

/* SNAP_SERVICE_SUBCLASS hooks; nothing at all without it. SERVICE_SUB_TAG
 * names what the locked handler decoded its entry to be (charged by
 * runtime_leave); FAST_EXIT_MARK records a lock-free exit's class in frame
 * slot 31 over sync_lower's start tick; FAST_EXIT_END, at the end of
 * xnuboot_pauth_resume, charges the round trip. */
#if SNAP_SERVICE_SUBCLASS
static void fast_exit_end(struct context *c,const struct vcpu *v,const uint64_t *frame)
{
    uint64_t now;
    __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(now)::"memory");
    fast_exit_charge(&c->exit_profile.cpu[v->slot],frame[31],now);
}
#define SERVICE_SUB_TAG(c,tag) service_sub_tag(&(c)->exit_profile.sub,(unsigned)vcpu_of(c)->slot,(tag))
#define FAST_EXIT_MARK(frame,slot) ((frame)[31]=fast_exit_mark((frame)[31],(slot)))
#define FAST_EXIT_END(c,v,frame) fast_exit_end((c),(v),(frame))
#else
#define SERVICE_SUB_TAG(c,tag) ((void)0)
#define FAST_EXIT_MARK(frame,slot) ((void)0)
#define FAST_EXIT_END(c,v,frame) ((void)0)
#endif

static struct context *context_of(void)
{
    return vcpu_of(0)->context;
}

static uint64_t service_profile_clock(void);
static int detail_begin(struct context *c,unsigned kind)
{
#if SNAP_SERVICE_DETAIL
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    /* Initial table construction precedes lock profiling and is deliberately
     * excluded. Otherwise the detailed totals could exceed runtime hold. */
    if(c->service_profile[cpu].stage!=2)return 0;
    return service_detail_begin(&c->service_detail[cpu],kind,service_profile_clock());
#else
    (void)c;(void)kind;return 0;
#endif
}
static void detail_end(struct context *c,unsigned kind,int started,int success)
{
#if SNAP_SERVICE_DETAIL
    if(started)service_detail_end(&c->service_detail[vcpu_of(c)->slot],kind,
                                 service_profile_clock(),success);
#else
    (void)c;(void)kind;(void)started;(void)success;
#endif
}

/* Both reads occur while q1n1's event loop and timer UI are suspended: one
 * before ERET, one before returning to q1n1. Unlike USB-side samples, status
 * redraws cannot produce a false difference during this interval. The hash
 * witnesses writes, not their glyph semantics; acquisition and capture still
 * need to agree. This code only reads the framebuffer. */
static uint64_t framebuffer_hash(const struct params *p)
{
    uint64_t hash = 0xcbf29ce484222325UL;
    __asm__ volatile("dsb sy" ::: "memory");
    for (uint64_t i = 0; i < p->fb_span; i += 8)
        hash = (hash ^ *(volatile uint64_t *)(p->fb_pa + i)) * 0x100000001b3UL;
    return hash;
}

