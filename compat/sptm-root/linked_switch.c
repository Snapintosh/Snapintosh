/* SPDX-License-Identifier: MIT */
/* Linked shared roots, nest proofs, invalidation and reclaim, and SWITCH_ROOT.
 * Part of compat/sptm-root.c's translation unit, included in order; not compiled on its own. */
/* SNAP_NATIVE_SHARED: nested guest level-2 entries are linked to shared
 * 4K groups (sptm-root.h, struct sptm_root_links) instead of copied. */
static int links_valid(const struct sptm_root_links *l)
{return l && l->group && l->link && l->linked && l->unlink;}
/* The guest level-2 entry of 16K root `root` at va, or 0 when a level above
 * is absent; -1 when unreadable or malformed. */
static int guest_level2(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t root,uint64_t va,uint64_t *entry)
{
    uint64_t l1;
    if(g->shift!=14 || g->start!=1 ||
       checked_read((void *)m,root+8UL*sptm_mac_user_index(g,1,va),&l1))return -1;
    if(!(l1&1)) {*entry=0;return 0;}
    if((l1&~g->pa_mask)!=3 || !(l1&g->pa_mask))return -1;
    return checked_read((void *)m,(l1&g->pa_mask)+8UL*sptm_mac_user_index(g,2,va),entry) ? -1 : 0;
}
/* A table entry naming a shared level-3 table: its PA, else 0. */
static uint64_t shared_child(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t entry)
{
    if((entry&3)!=3 || (entry&~g->pa_mask)!=3)return 0;
    volatile uint8_t *child=metadata(m,entry&g->pa_mask);
    return child && child[2]==SPTM_MAC_PAGE_TABLE_SHARED && child[4]==3 ? entry&g->pa_mask : 0;
}
uint64_t sptm_root_shared_child(const struct sptm_memory *m,uint64_t root,uint64_t va)
{
    struct sptm_user_geometry g;uint64_t entry;
    if(!m || !m->map || !sptm_mac_user_geometry(0,SPTM_MAC_ROOT_FLAGS_USER,&g) ||
       va>=(UINT64_C(1)<<47) || guest_level2(m,&g,root,va,&entry))return 0;
    return shared_child(m,&g,entry);
}
#if SNAP_ROOT_MISS_FAST
static int build_linked(const struct sptm_memory *m,struct shadow *s,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l,
    struct sptm_root_memo *memo,int (*grouped)(void *,uint64_t,uint64_t));
int sptm_root_build_linked(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l)
{return build_linked(m,s,root,format,flags,leaves,l,0,0);}
int sptm_root_build_linked_memo(const struct sptm_memory *m,struct shadow *s,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l,
    struct sptm_root_memo *memo,int (*grouped)(void *,uint64_t,uint64_t))
{return memo && !grouped ? 0 : build_linked(m,s,root,format,flags,leaves,l,memo,grouped);}
/* Only the shared children this build links to an existing group
 * (shared_child below: attrs 3, type SHARED, level 3 -- exactly
 * validate_table's shared branch) may be answered by a verdict: a child
 * whose group the build creates is copied into it, so it is scanned in full
 * first, like every table the build copies into the root's own tree. */
static int build_linked(const struct sptm_memory *m,struct shadow *s,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l,
    struct sptm_root_memo *memo,int (*grouped)(void *,uint64_t,uint64_t))
#else
int sptm_root_build_linked(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l)
#endif
{
    struct sptm_user_geometry g;
    if(!links_valid(l) || format || !m || !m->map || !s || !s->read || !leaves ||
       s->txsz!=17 || !s->root || !sptm_mac_user_geometry(format,flags,&g))return 0;
#if SNAP_ROOT_MISS_FAST
    struct validation v={m,&g,flags,0,0,root,0,memo,1};
#else
    struct validation v={m,&g,flags,0,0,root,0,0};
#endif
    if(!validate_table(&v,root,g.start,0))return 0;
    /* A fresh tree only: clearing through a linked group would clear leaves
     * every nesting address space shares. */
    for(unsigned i=0;i<512;i++) {
        uint64_t d;
        if(s->read(s->ctx,s->root+8UL*i,&d) || d)return 0;
    }
    struct mmu_config cfg={g.shift,17,root};
    uint64_t total=0,span=mmu_level_size(14,2);
    for(uint64_t va=0;va<g.va_limit;) {
        uint64_t l1;
        if(checked_read((void *)m,root+8UL*sptm_mac_user_index(&g,1,va),&l1))return 0;
        uint64_t next=next_boundary(va,14,1);
        if(!(l1&1)) {va=next;continue;}
        if(next>g.va_limit)next=g.va_limit;
        for(;va<next;va+=span) {
            uint64_t entry,child,n=0;
            if(guest_level2(m,&g,root,va,&entry))return 0;
            if(!(entry&1))continue;
            if((child=shared_child(m,&g,entry))) {
#if SNAP_ROOT_MISS_FAST
                if(memo && !root_miss_linked_only(grouped(l->ctx,child,va))) {
                    struct validation full={m,&g,flags,0,0,root,0,0,0};
                    if(!validate_table(&full,child,3,va))return 0;
                }
#endif
                if(va+span>g.va_limit || l->group(l->ctx,child,va)<0 ||
                   !l->link(l->ctx,child,va,&n))return 0;
            } else {
                long built=shadow_build(s,&cfg,va,va+span<next ? va+span : next,checked_read,(void *)m);
                if(built<0)return 0;
                n=(uint64_t)built;
            }
            total+=n;
        }
    }
    *leaves=total;return 1;
}
#if SNAP_NEST_FAST
/* compat/nest-fast.h. validate_table's level-3 scan of shared table `table`
 * reached at `base` under root `flags`, without the memo: what a retained
 * verdict means. */
static int shared_validates(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t table,uint64_t base,unsigned flags)
{
#if SNAP_ROOT_MISS_FAST
    struct validation v={m,g,flags,0,0,0,1,0,0};
#else
    struct validation v={m,g,flags,0,0,0,1,0};
#endif
    return validate_table(&v,table,3,base);
}
/* 1: the table's level-3 scan is proved, by a retained verdict or by
 * shared_validates (recorded at once); 0: not proved; -1: a sampled rescan
 * of a retained verdict failed (fatal, a mismatch). */
static int shared_proof(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t table,uint64_t base,unsigned flags,int unnest)
{
    struct sptm_nest_fast_stats *st=m->nest_fast;
    struct sptm_root_memo *memo=m->root_memo;
    volatile uint8_t *meta=metadata(m,table&MASK);
#if SNAP_UNNEST_4K_FAST
    /* compat/nest-fast.h 3: also a 4K table, 4K aligned in its frame. */
    if(!memo || !meta || (g->shift!=14 && g->shift!=12) || (table&g->pa_mask)!=table)return 0;
#else
    if(!memo || !meta || g->shift!=14 || (table&MASK)!=table)return 0;
#endif
    uint64_t record=sptm_root_memo_record_bytes(meta);
    if(sptm_root_memo_peek(memo,table,base,flags,g->shift,record)) {
        memo->stats.hits++;
        uint64_t n=st ? (unnest ? ++st->unnest_hits : ++st->nest_hits) : 0;
        if(!(n&SPTM_NEST_FAST_SAMPLE)) {
            if(st)st->sampled++;
            if(!shared_validates(m,g,table,base,flags)) {if(st)st->mismatches++;return -1;}
        }
        return 1;
    }
    if(st) {if(unnest)st->unnest_scans++;else st->nest_scans++;}
    if(!shared_validates(m,g,table,base,flags))return 0;
    memo->stats.misses++;
    sptm_root_memo_store(memo,table,base,flags,g->shift,record);
    if(st) {if(unnest)st->unnest_records++;else st->nest_records++;}
    return 1;
}
int sptm_root_shared_proof(const struct sptm_memory *m,uint64_t table,uint64_t base,
                           unsigned format,unsigned flags)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !sptm_mac_user_geometry(format,flags,&g))return 0;
    return shared_proof(m,&g,table,base,flags,1);
}
#if SNAP_UNNEST_4K_FAST
/* compat/nest-fast.h 3: shared_proof itself for a 4K table at shift 12 (the
 * same verdicts, sampling and accounting). A hit that was not sampled also
 * hands back the leaf count its verdict carries; a sampled hit (rescanned by
 * shared_proof), a recorded miss or no counters leave *known UINT64_MAX, so
 * the caller counts and sptm_root_shared_count_4k records or compares. */
int sptm_root_shared_proof_4k(const struct sptm_memory *m,uint64_t table,uint64_t base,
                              unsigned format,unsigned flags,uint64_t *known)
{
    struct sptm_user_geometry g;
    if(!known)return 0;
    *known=UINT64_MAX;
    if(!m || !m->map || !sptm_mac_user_geometry(format,flags,&g) || g.shift!=12)return 0;
    struct sptm_nest_fast_stats *st=m->nest_fast;
    uint64_t hits=st ? st->unnest_hits : 0,sampled=st ? st->sampled : 0;
    int r=shared_proof(m,&g,table,base,flags,1);
    if(r==1 && st && st->unnest_hits!=hits && st->sampled==sampled) {
        volatile uint8_t *meta=metadata(m,table&MASK);
        struct sptm_root_memo_entry *e=!meta ? 0 :
            sptm_root_memo_entry_of(m->root_memo,table,base,flags,g.shift,sptm_root_memo_record_bytes(meta));
        if(e)*known=sptm_root_memo_leaves(e);
        if(*known!=UINT64_MAX)st->unnest_counted++;
    }
    return r;
}
int sptm_root_shared_count_4k(const struct sptm_memory *m,uint64_t table,uint64_t base,
                              unsigned format,unsigned flags,uint64_t leaves)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !sptm_mac_user_geometry(format,flags,&g) || g.shift!=12 ||
       leaves>g.page_size/8)return 0;
    struct sptm_root_memo *memo=m->root_memo;
    volatile uint8_t *meta=metadata(m,table&MASK);
    if(!memo || !meta)return 0;
    struct sptm_root_memo_entry *e=
        sptm_root_memo_entry_of(memo,table,base,flags,g.shift,sptm_root_memo_record_bytes(meta));
    if(!e)return 0;
    uint64_t had=sptm_root_memo_leaves(e);
    if(had!=UINT64_MAX && had!=leaves) {if(m->nest_fast)m->nest_fast->mismatches++;return -1;}
    sptm_root_memo_set_leaves(e,leaves);
    return 1;
}
#endif
/* The per-address source check of sptm_root_prepare_nest_linked over the
 * 32 MiB of a level-2 entry naming shared table `table`, reading the table
 * once with word loads: every valid leaf (bits1:0 = 3, what mmu_walk reports
 * as a level-3 leaf) is a fixed native class over an unlocked managed frame
 * the root's policy admits, mappable. -1: the page cannot be mapped (the
 * caller walks per address, as before). */
static int nest_table_scan(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t table,uint64_t base,unsigned flags)
{
    volatile uint8_t *page=m->map(m->ctx,table,g->page_size);
    if(!page)return -1;
    for(unsigned i=0;i<g->page_size/8;i++) {
        uint64_t pte=*(volatile uint64_t *)(void *)(page+8UL*i);
        if((pte&3)!=3)continue;
        uint64_t addr=base+i*g->page_size;
        volatile uint8_t *data=metadata(m,pte&MASK);
        if(!sprr_fixed_native_leaf(pte) || !data || get(data,2) ||
           sptm_mac_user_leaf_policy(flags,21,data[2],addr,pte,g) ||
           !m->map(m->ctx,pte&MASK,g->page_size))return 0;
    }
    return 1;
}
#endif
int sptm_root_prepare_nest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    const struct sptm_root_links *l)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!links_valid(l) || shift!=14 || !nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))
        return 0;
    struct mmu_config source={shift,17,shared},target={shift,17,e->root},hw={12,17,e->shadow};
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf b,h;
        if(mmu_walk(&target,addr,checked_read,(void *)m,&b) ||
           mmu_walk(&hw,addr,s->read,s->ctx,&h) || b.valid || h.valid)return 0;
        uint64_t next=end;
        uint64_t x=next_boundary(addr,shift,b.level),y=next_boundary(addr,12,h.level);
        if(x<next)next=x;
        if(y<next)next=y;
        if(next<=addr)return 0;
        addr=next;
    }
    /* Every source leaf must suit this root's policy, exactly as for a copy. */
#if SNAP_NEST_FAST
    /* Per level-2 entry (compat/nest-fast.h 1); any entry not naming a
     * shared level-3 table, or whose page cannot be mapped, is walked per
     * address over its 32 MiB exactly as before. */
    uint64_t lspan=mmu_level_size(14,2);
    for(uint64_t at=base;at<end;at+=lspan) {
        uint64_t entry,child;int r=0;
        if(!guest_level2(m,&g,shared,at,&entry) && (child=shared_child(m,&g,entry))) {
            if(m->nest_fast)m->nest_fast->nest_tables++;
            r=shared_proof(m,&g,child,at,(unsigned)e->flags,0);
            if(r<0)return 0;
            if(!r)r=nest_table_scan(m,&g,child,at,(unsigned)e->flags);
            if(!r)return 0;
        }
        if(r==1)continue;
        if(m->nest_fast)m->nest_fast->nest_walked++;
        for(uint64_t addr=at;addr<at+lspan;) {
#else
    for(uint64_t addr=base;addr<end;) {
#endif
        struct mmu_leaf a;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a))return 0;
        if(a.valid) {
            volatile uint8_t *data=metadata(m,a.pa&MASK);
            if(a.level!=3 || a.size!=g.page_size || !sprr_fixed_native_leaf(a.descriptor) ||
               !data || get(data,2) ||
               sptm_mac_user_leaf_policy(e->flags,21,data[2],addr,a.descriptor,&g) ||
               !m->map(m->ctx,a.pa,g.page_size))return 0;
        }
        uint64_t next=next_boundary(addr,shift,a.level);
        if(next<=addr)return 0;
        addr=next;
    }
#if SNAP_NEST_FAST
    }
#endif
    /* Groups exist and the level-2 path is allocated before publication. */
    uint64_t span=mmu_level_size(14,2);
    for(uint64_t addr=base;addr<end;addr+=span) {
        uint64_t entry,child,table;
        if(guest_level2(m,&g,shared,addr,&entry) || !(child=shared_child(m,&g,entry)) ||
           l->group(l->ctx,child,addr)<0 || shadow_table(s,2,addr,&table))return 0;
    }
    return 1;
}
int sptm_root_commit_nest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    const struct sptm_root_links *l)
{
    struct sptm_user_geometry g;uint64_t base,end,added=0;
    if(!links_valid(l) || shift!=14 || !nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))
        return 0;
    uint64_t span=mmu_level_size(14,2);
    for(uint64_t addr=base;addr<end;addr+=span) {
        uint64_t a,b,child,n;
        if(guest_level2(m,&g,shared,addr,&a) || guest_level2(m,&g,e->root,addr,&b) ||
           a!=b || !(child=shared_child(m,&g,a)) || !l->link(l->ctx,child,addr,&n))return 0;
        added+=n;
    }
    e->leaves+=added;return 1;
}
static int unnest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,
    const struct sptm_unnest_plan *p,const struct sptm_root_links *l,int commit)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!links_valid(l) || shift!=14 || !p || !p->count || p->count>2048 ||
       p->span!=mmu_level_size(shift,2) ||
       !nest_geometry(e,s,m,shared,p->base,shift,p->count*p->span/(1UL<<shift),&g,&base,&end) ||
       base!=p->base || p->leaves>e->leaves)return 0;
    uint64_t found=0,descriptors=0;
    for(unsigned i=0;i<2048;i++)if(p->mask[i/64]&(1UL<<(i%64))) {
        if(i>=p->count)return 0;
        descriptors++;
        uint64_t addr=p->base+i*p->span,a,b,child,n;
        /* Before publication the root still names the shared table; after
         * it, nothing. The group is always found through the shared root. */
        if(guest_level2(m,&g,shared,addr,&a) || guest_level2(m,&g,e->root,addr,&b) ||
           !(child=shared_child(m,&g,a)) || (commit ? b!=0 : b!=a))return 0;
        if(!(commit ? l->unlink(l->ctx,child,addr,&n) : l->linked(l->ctx,child,addr,&n)))return 0;
        found+=n;
    }
    if(found!=p->leaves || descriptors!=p->descriptors)return 0;
    if(commit)e->leaves-=found;
    return 1;
}
int sptm_root_prepare_unnest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p,
    const struct sptm_root_links *l)
{return unnest_linked(e,s,m,shared,shift,p,l,0);}
int sptm_root_commit_unnest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p,
    const struct sptm_root_links *l)
{return unnest_linked(e,s,m,shared,shift,p,l,1);}
int sptm_root_invalidate(struct sptm_root_state *s,uint64_t root,int retire)
{
    if(!s || !root || active_count(s,root))return 0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s->cache[i].root==root) {
        s->cache[i].valid=0;
        if(retire)s->cache[i].root=0;
        s->invalidations++;
    }
    return 1;
}
unsigned sptm_root_reclaim_pick(const struct sptm_root_state *s,
    const uint64_t stamp[SPTM_ROOT_CACHE],sptm_root_mask_t exclude)
{
    unsigned best=SPTM_ROOT_CACHE,best_rank=4;uint64_t best_age=UINT64_MAX;
    if(!s)return best;
    for(unsigned n=0;n<SPTM_ROOT_CACHE;n++) {
        unsigned i=(unsigned)((s->builds+n)%SPTM_ROOT_CACHE);
        const struct sptm_root_cached *e=&s->cache[i];
        if(SPTM_ROOT_MASK_HAS(exclude,i))continue;
        unsigned rank;
        if(!e->root) {
            if(!e->shadow)continue;
            rank=1;
        } else {
            if(active_count(s,e->root))continue;
            rank=e->valid ? 3 : 2;
        }
        uint64_t age=rank==3 && stamp ? stamp[i] : 0;
        if(rank<best_rank || (rank==best_rank && age<best_age)) {
            best=i;best_rank=rank;best_age=age;
        }
    }
    return best;
}
int sptm_root_reclaim_forget(struct sptm_root_state *s,unsigned slot)
{
    if(!s || slot>=SPTM_ROOT_CACHE)return 0;
    struct sptm_root_cached *e=&s->cache[slot];
    if(e->root && active_count(s,e->root))return 0;
    if(e->valid)s->invalidations++;
    e->root=0;e->shadow=0;e->leaves=0;e->asid=0;e->format=0;e->flags=0;e->valid=0;
    return 1;
}
/* Read-only: the cache entry sptm_mac_switch_root selects for root (the last
 * slot naming it) is valid for this identity, so no build follows. */
static int cache_hit(const struct sptm_root_state *s,uint64_t root,unsigned asid,
                     unsigned format,unsigned flags)
{
    const struct sptm_root_cached *entry=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s->cache[i].root==root)entry=&s->cache[i];
    return entry && entry->valid && entry->asid==asid && entry->format==format && entry->flags==flags;
}
enum sptm_result sptm_mac_switch_root(const struct sptm_memory *m,
    struct sptm_root_state *s,const struct sptm_root_backend *b,unsigned cpu,
    uint64_t root,uint64_t set_flags,uint64_t clear_flags)
{
    if(!m || !m->map || !m->publish || !s || !b || !b->build || !b->install ||
       cpu>=SPTM_ROOT_CPUS || !b->kernel_root || !b->kernel_shadow ||
       (b->kernel_root&0x3fff) || (b->kernel_shadow&0xfff) ||
       !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high ||
       m->frame_map_pa>UINT64_MAX-((m->frame_high-m->frame_low)>>14)*16)
        return SPTM_BAD_CONFIG;
    /* The observed native call uses no overrides. APRR/domain overrides have
     * additional semantics; do not accept them as harmless flag changes. */
    if(set_flags || clear_flags)return SPTM_UNSUPPORTED_OPTIONS;
    if(!root || (root&0x3fff))return SPTM_BAD_ADDRESS;
    uint64_t old=s->active[cpu];
    volatile uint8_t *old_meta=old ? metadata(m,old) : 0;
    struct sptm_user_geometry g;
    if(old && (!root_header(m,old_meta,&g) || get(old_meta+6,2)<active_count(s,old)))
        return SPTM_BAD_REFERENCE;
    if(root==b->kernel_root) {
        b->install(b->ctx,b->kernel_shadow,b->kernel_root,0,0);
        sprr_root_reset(&s->sprr[cpu],0);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
        s->active[cpu]=0;s->switches++;s->kernel_switches++;
        return SPTM_OK;
    }
    volatile uint8_t *meta=metadata(m,root);
    if(!root_header(m,meta,&g))return SPTM_BAD_TABLE;
    unsigned flags=(unsigned)get(meta+10,2),asid=(unsigned)get(meta+4,2),format=meta[12];
#if SNAP_USER_HW_WALK
    if(b->hw_eligible) {
        int hw=b->hw_eligible(b->ctx,m,root,asid,format,flags);
        if(hw<0)return SPTM_BAD_TABLE;
        if(hw) {
            /* No walk counts the root's children: keep the bounds config()
             * applies to every user call (children plus CPU references). */
            unsigned cpus=active_count(s,root);
            if(get(meta+6,2)<cpus || get(meta+6,2)>g.root_groups+cpus)return SPTM_BAD_REFERENCE;
            b->install(b->ctx,0,root,asid,format);
            goto installed;
        }
    }
#endif
    /* Keep the actual activation state, including UMPRR field9. The explicit
     * TPRO backend contract admits typed raw selector9 only in canonical
     * storage; install must translate it before guest resumption. */
    struct sptm_root_validate_stats *vs=b->validate;
    int hit=cache_hit(s,root,asid,format,flags);
    /* Audit mode: an exact-by-construction cached shadow is not walked on
     * every hit; the owner samples which hits still are. */
    int walk=!hit || !b->skip_hit_validation || !b->skip_hit_validation(b->ctx);
    /* Retained level-3 verdicts only when this switch installs the cached
     * shadow (the entry selected below is already valid for this identity),
     * and only with the sampled reference walk that checks them. */
#if SNAP_ROOT_MISS_FAST
    /* A miss of a 16K root whose build links its shared tables: the walk may
     * answer those tables, and only those, from memo (compat/root-miss.h).
     * calls still counts cache-hit validations only. */
    int shared_only=!hit && b->linked_builds && !format;
    struct sptm_root_memo *memo=vs && b->memo && (hit || shared_only) ? b->memo : 0;
    struct validation v={m,&g,flags,0,0,root,vs!=0,memo,shared_only};
    if(walk && memo && hit)memo->stats.calls++;
#else
    struct sptm_root_memo *memo=vs && b->memo && hit ? b->memo : 0;
    struct validation v={m,&g,flags,0,0,root,vs!=0,memo};
    if(walk && memo)memo->stats.calls++;
#endif
    int valid=!walk || validate_table(&v,root,g.start,0);
    if(walk && vs) {
        /* Every 64th word-load validation repeats the original byte-load walk
         * and must reach the same verdict, table count and root-group count.
         * A difference is terminal; the byte result is never substituted.
         * The reference walk never uses retained verdicts. */
        if(!(++vs->validations&SPTM_ROOT_VALIDATE_SAMPLE)) {
#if SNAP_ROOT_MISS_FAST
            struct validation bytes={m,&g,flags,0,0,root,0,0,0};
#else
            struct validation bytes={m,&g,flags,0,0,root,0,0};
#endif
            int again=validate_table(&bytes,root,g.start,0);
            vs->sampled++;if(memo)memo->stats.sampled++;
            if(again!=valid || bytes.tables!=v.tables || bytes.root_children!=v.root_children) {
                vs->mismatches++;if(memo)memo->stats.mismatches++;return SPTM_BAD_TABLE;
            }
        }
        vs->tables+=v.tables;
    }
    if(!valid)return SPTM_BAD_TABLE;
    if((walk && get(meta+6,2)!=v.root_children+active_count(s,root)) ||
       get(meta+6,2)>=0x80b)return SPTM_BAD_REFERENCE;
    struct sptm_root_cached *entry=0,*empty=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&s->cache[i];
        if(e->root==root)entry=e;
        if(!e->root && !empty)empty=e;
        if(e->root && e->root!=root && e->asid==asid)return SPTM_FRAME_BUSY;
    }
    if(!entry)entry=empty;
#if SNAP_ROOT_MISS_FAST
    /* Full cache with stamps: the least recently installed inactive root
     * gives up its slot (compat/root-miss.h), accounted as below. */
    if(!entry && b->stamp) {
        if(!(entry=root_miss_victim(s,b->stamp,root)))return SPTM_MEMORY_UNAVAILABLE;
        entry->valid=0;entry->root=0;s->invalidations++;
        if(b->evictions)(*b->evictions)++;
    }
#endif
    if(!entry) {
        /* Every slot names a root: more address spaces are live than slots.
         * A fast boot reaches that (61 processes plus an exec'ing xpcproxy
         * filled all 64). A cached shadow is derived state, so take the slot
         * of a root no CPU has installed -- an already invalidated one first,
         * then round robin. It loses nothing: user updates to an uncached
         * inactive root go to its guest tables, and its next switch rebuilds
         * the shadow from them. build() flushes all-VMID translations and
         * resets the slot's views before reuse, as for a retired root. */
        for(unsigned pass=0;pass<2 && !entry;pass++)
            for(unsigned n=0;n<SPTM_ROOT_CACHE && !entry;n++) {
                struct sptm_root_cached *e=&s->cache[(s->builds+n)%SPTM_ROOT_CACHE];
                if(e->root && e->root!=root && e->valid==pass && !active_count(s,e->root))entry=e;
            }
        if(!entry)return SPTM_MEMORY_UNAVAILABLE;
        entry->valid=0;entry->root=0;s->invalidations++;
        if(b->evictions)(*b->evictions)++;
    }
    if(entry->valid && (entry->asid!=asid || entry->format!=format || entry->flags!=flags))
        return SPTM_BAD_TABLE;
    uint64_t shadow=entry->shadow,leaves=entry->leaves;
    if(!entry->valid) {
        if(active_count(s,root))return SPTM_FRAME_BUSY;
        if(!b->build(b->ctx,m,root,format,flags,shadow,&shadow,&leaves) ||
           !shadow || (shadow&0xfff))return SPTM_MEMORY_UNAVAILABLE;
        entry->root=root;entry->shadow=shadow;entry->leaves=leaves;
        entry->asid=asid;entry->format=format;entry->flags=flags;entry->valid=1;
        s->builds++;
    }
    b->install(b->ctx,shadow,root,asid,format);
#if SNAP_USER_HW_WALK
installed:
#endif
    sprr_root_reset(&s->sprr[cpu],flags);
    if(old!=root) {
        put16(meta+6,(unsigned)get(meta+6,2)+1);
        m->publish(m->ctx,m->frame_map_pa+((root-m->frame_low)>>14)*16,16);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
    }
    s->active[cpu]=root;s->switches++;s->user_switches++;
    return SPTM_OK;
}
