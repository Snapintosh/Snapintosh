/* SPDX-License-Identifier: MIT */
/* Leaf, update, unmap, detach, attach, nest and unnest hooks on a root view and
 * shadow builds.
 * Part of compat/sptm-root.c's translation unit, included in order; not compiled on its own. */
static int commit_leaf(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t expected,int inserted)
{
    struct sptm_user_geometry g;
    if(!e || !e->valid || !s || s->txsz!=17 || s->root!=e->shadow || !m || !m->map ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,&g) ||
       shift!=g.shift || (va&(g.page_size-1)) || va>=g.va_limit)return 0;
    struct mmu_config cfg={shift,17,e->root};struct mmu_leaf leaf;
    if(mmu_walk(&cfg,va,checked_read,(void *)m,&leaf) || !leaf.valid ||
       leaf.level!=3 || leaf.descriptor!=expected || leaf.size!=g.page_size ||
       !canonical_leaf(m,(unsigned)e->flags,&g,va,leaf.descriptor))return 0;
    struct shadow commit=*s;commit.alloc=no_alloc;
    if(shadow_insert(&commit,&leaf,va,va+g.page_size))return 0;
    e->leaves+=(unsigned)inserted;return 1;
}
int sptm_root_commit_leaf(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t expected)
{return commit_leaf(e,s,m,va,shift,expected,1);}
int sptm_root_commit_update(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    if((shift!=12 && shift!=14) || (old&3)!=3 || (next&3)!=3 ||
       ((old^next)&(PT_OA_MASK&~((1UL<<shift)-1))) || !e || !e->leaves || !s)return 0;
    struct mmu_config cfg={12,17,e->shadow};
    for(uint64_t off=0;off<(1UL<<shift);off+=4096) {
        struct mmu_leaf leaf;
        if(mmu_walk(&cfg,va+off,s->read,s->ctx,&leaf) || !leaf.valid || leaf.level!=3 ||
           leaf.pa!=(old&(PT_OA_MASK&~((1UL<<shift)-1)))+off ||
           ((leaf.descriptor^old)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))return 0;
    }
    return commit_leaf(e,s,m,va,shift,next,0);
}
static int unmap_geometry(struct sptm_root_cached *e,struct shadow *s,
    uint64_t va,unsigned shift,uint64_t count,struct sptm_user_geometry *g)
{
    return e && e->valid && s && s->read && s->write && s->txsz==17 &&
        s->root==e->shadow && sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,g) &&
        shift==g->shift && !(va&(g->page_size-1)) && va<g->va_limit &&
        count && count<=64 && count<=(g->va_limit-va)/g->page_size &&
        (va>>(2*shift-3))==((va+count*g->page_size-1)>>(2*shift-3));
}
int sptm_root_prepare_unmap(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t count)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !unmap_geometry(e,s,va,shift,count,&g))return 0;
    volatile uint8_t *meta=metadata(m,e->root);struct sptm_user_geometry root_g;
    if(!root_header(m,meta,&root_g) || get(meta+4,2)!=e->asid ||
       get(meta+10,2)!=e->flags || meta[12]!=e->format)return 0;
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};
    uint64_t removed=0;
    for(uint64_t n=0;n<count;n++) {
        uint64_t addr=va+n*g.page_size;struct mmu_leaf leaf;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&leaf))return 0;
        if(leaf.valid && (leaf.level!=3 || leaf.size!=g.page_size))return 0;
        removed+=leaf.valid;
        for(uint64_t off=0;off<g.page_size;off+=4096) {
            struct mmu_leaf actual;
            if(mmu_walk(&hw,addr+off,s->read,s->ctx,&actual) || actual.valid!=leaf.valid)return 0;
            if(actual.valid && (actual.level!=3 || actual.pa!=leaf.pa+off ||
                ((actual.descriptor^leaf.descriptor)&(PT_LEAF_ATTRS|PT_LEAF_UPPER))))return 0;
        }
    }
    return removed<=e->leaves && !shadow_unmap(s,va,count*g.page_size,1);
}
int sptm_root_commit_unmap(struct sptm_root_cached *e,struct shadow *s,
    uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    struct sptm_user_geometry g;
    if(!unmap_geometry(e,s,va,shift,count,&g) || removed>count || removed>e->leaves)return 0;
    struct shadow commit=*s;commit.alloc=no_alloc;
    if(shadow_unmap(&commit,va,count*g.page_size,0))return 0;
    e->leaves-=removed;return 1;
}
static int detach_range(struct sptm_root_cached *e,struct shadow *s,uint64_t va,
    unsigned shift,unsigned level,struct sptm_user_geometry *g,uint64_t *base,uint64_t *end)
{
    if(!e || !e->valid || !s || !s->read || !s->write || s->txsz!=17 || s->root!=e->shadow ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,g) ||
       shift!=g->shift || level<g->start || level>2 || (va&(g->page_size-1)) ||
       va>=g->va_limit || (sptm_mac_user_index(g,level,va)&(g->group-1)))return 0;
    uint64_t span=mmu_level_size(shift,level)*g->group;
    *base=va&~(span-1);*end=*base+span;
    if(*end>g->va_limit)*end=g->va_limit;
    return 1;
}
#if SNAP_DETACH_FAST
static int guest_level2(const struct sptm_memory *,const struct sptm_user_geometry *,
                        uint64_t,uint64_t,uint64_t *);
/* compat/nest-fast.h: 1 when neither the 16K guest tree nor the 4K shadow
 * maps a page in the 32 MiB [base,end) of one level-2 entry: the guest entry
 * is absent or names a table without a valid leaf, and shadow_range_empty
 * holds. 0: something is mapped, unusual or unreadable (the caller walks). */
static int detach_empty(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,const struct sptm_user_geometry *g,uint64_t base,uint64_t end)
{
    uint64_t entry;
    if(guest_level2(m,g,e->root,base,&entry))return 0;
    if(entry&PT_VALID) {
        uint64_t table=entry&PT_OA_MASK;
        if(!(entry&PT_TABLE) || table!=(entry&g->pa_mask))return 0;
        volatile uint8_t *page=m->map(m->ctx,table,g->page_size);
        if(!page)return 0;
        for(unsigned i=0;i<g->page_size/8;i++)
            if((*(volatile uint64_t *)(void *)(page+8UL*i)&3)==3)return 0;
    }
    return shadow_range_empty(s,base,end-base)==1;
}
#endif
int sptm_root_prepare_detach(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!m || !m->map || !detach_range(e,s,va,shift,level,&g,&base,&end) || removed>e->leaves)return 0;
    volatile uint8_t *meta=metadata(m,e->root);struct sptm_user_geometry root_g;
    if(!root_header(m,meta,&root_g) || get(meta+4,2)!=e->asid ||
       get(meta+10,2)!=e->flags || meta[12]!=e->format)return 0;
#if SNAP_DETACH_FAST
    /* An empty level-3 table: the walks below find nothing and shadow_unmap
     * (check only) refuses nothing that shadow_range_empty accepted. */
    if(level==2 && !removed && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2)) {
        if(detach_empty(e,s,m,&g,base,end)) {
            if(m->nest_fast)m->nest_fast->detach_fast++;
            return 1;
        }
        if(m->nest_fast)m->nest_fast->detach_slow++;
    }
#endif
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};uint64_t found=0;
    /* Skip absent subtrees using both walkers' returned levels. Higher-level
     * empty detachment must not iterate through terabytes one4K page at a time. */
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf leaf,actual;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&leaf) ||
           mmu_walk(&hw,addr,s->read,s->ctx,&actual) || leaf.valid!=actual.valid)return 0;
        if(leaf.valid) {
            if(leaf.level!=3 || actual.level!=3 || leaf.pa!=actual.pa ||
               ((leaf.descriptor^actual.descriptor)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))return 0;
            found+=!(addr&(g.page_size-1));addr+=4096;
        } else {
            uint64_t a=mmu_level_size(shift,leaf.level),b=mmu_level_size(12,actual.level);
            a=(addr&~(a-1))+a;b=(addr&~(b-1))+b;
            uint64_t next=a<b ? a:b;if(next<=addr)return 0;addr=next;
        }
    }
    return found==removed && !shadow_unmap(s,base,end-base,1);
}
int sptm_root_commit_detach(struct sptm_root_cached *e,struct shadow *s,
    uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!detach_range(e,s,va,shift,level,&g,&base,&end) || removed>e->leaves)return 0;
    struct shadow commit=*s;commit.alloc=no_alloc;
#if SNAP_DETACH_FAST
    /* Nothing to remove: shadow_unmap would validate, then store nothing. */
    if(level==2 && !removed && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2) &&
       shadow_range_empty(&commit,base,end-base)==1)return 1;
#endif
    if(shadow_unmap(&commit,base,end-base,0))return 0;
    e->leaves-=removed;return 1;
}
static int attach_geometry(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t child,
    struct sptm_user_geometry *g,uint64_t *base,uint64_t *end)
{
    if(!m || !m->map || (child&0x3fff) ||
       !detach_range(e,s,va,shift,2,g,base,end))return 0;
    volatile uint8_t *root=metadata(m,e->root),*table=metadata(m,child);
    struct sptm_user_geometry root_g;
    return root_header(m,root,&root_g) && get(root+4,2)==e->asid &&
        get(root+10,2)==e->flags && root[12]==e->format &&
        sptm_mac_commpage_table_va((unsigned)e->flags,va) &&
        table && !get(table,2) && table[2]==SPTM_MAC_PAGE_TABLE_COMMPAGE && table[4]==3;
}
int sptm_root_prepare_attach(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t child)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!attach_geometry(e,s,m,va,shift,child,&g,&base,&end))return 0;
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf a,b;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a) ||
           mmu_walk(&hw,addr,s->read,s->ctx,&b) || a.valid || b.valid)return 0;
        uint64_t x=mmu_level_size(shift,a.level),y=mmu_level_size(12,b.level);
        x=(addr&~(x-1))+x;y=(addr&~(y-1))+y;
        uint64_t next=x<y ? x:y;if(next<=addr)return 0;addr=next;
    }
    volatile uint8_t *page=m->map(m->ctx,child,0x4000);
    if(!page)return 0;
    for(unsigned i=0;i<2048;i++) {
        uint64_t pte=get(page+i*8,8),addr=base+i*g.page_size;
        if(!pte)continue;
        if((pte&3)!=3 || addr>=end || shadow_reserve(s,addr,g.page_size))return 0;
    }
    return 1;
}
int sptm_root_commit_attach(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t child)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!attach_geometry(e,s,m,va,shift,child,&g,&base,&end))return 0;
    volatile uint8_t *page=m->map(m->ctx,child,0x4000);
    if(!page)return 0;
    for(unsigned i=0;i<2048;i++) {
        uint64_t pte=get(page+i*8,8),addr=base+i*g.page_size;
        if(!pte)continue;
        if((pte&3)!=3 || addr>=end ||
           !sptm_root_commit_leaf(e,s,m,addr,shift,pte))return 0;
    }
    return 1;
}
static int nest_geometry(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    struct sptm_user_geometry *g,uint64_t *base,uint64_t *end)
{
    if(!m || !m->map || !s || !s->read || !s->write || !e || !e->valid ||
       s->root!=e->shadow || s->txsz!=17 ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,g) ||
       shift!=g->shift || (va&(g->page_size-1)) || va>=g->va_limit ||
       !pages || pages>(g->va_limit-va)/g->page_size)return 0;
    volatile uint8_t *u=metadata(m,e->root);struct sptm_user_geometry actual;
    if(!root_header(m,u,&actual) || get(u+4,2)!=e->asid || u[12]!=e->format ||
       get(u+10,2)!=e->flags || u[8]==255 ||
       m->shared_regions->slots[u[8]].root!=shared)return 0;
    uint64_t span=mmu_level_size(shift,2);
    *base=va&~(span-1);*end=(va+(pages-1)*g->page_size+span)&~(span-1);
    return *end<=g->va_limit && *end>*base;
}
static uint64_t next_boundary(uint64_t addr,unsigned shift,unsigned level)
{
    uint64_t span=mmu_level_size(shift,level);
    return (addr&~(span-1))+span;
}
int sptm_root_prepare_nest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))return 0;
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
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf a;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a))return 0;
        if(a.valid) {
            volatile uint8_t *data=metadata(m,a.pa&MASK);
            if(a.level!=3 || a.size!=g.page_size || !sprr_fixed_native_leaf(a.descriptor) ||
               !data || get(data,2) ||
               sptm_mac_user_leaf_policy(e->flags,21,data[2],addr,a.descriptor,&g) ||
               !m->map(m->ctx,a.pa,g.page_size) || shadow_reserve(s,addr,g.page_size))return 0;
        }
        uint64_t next=next_boundary(addr,shift,a.level);
        if(next<=addr)return 0;
        addr=next;
    }
    return 1;
}
int sptm_root_commit_nest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))return 0;
    struct mmu_config source={shift,17,shared},target={shift,17,e->root};
    struct shadow commit=*s;commit.alloc=no_alloc;
    uint64_t added=0;
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf a,b;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a) ||
           mmu_walk(&target,addr,checked_read,(void *)m,&b) ||
           a.valid!=b.valid || a.level!=b.level || a.descriptor!=b.descriptor)return 0;
        if(a.valid) {
            if(a.level!=3 || a.size!=g.page_size || !sprr_fixed_native_leaf(a.descriptor) ||
               shadow_insert(&commit,&a,addr,addr+g.page_size))return 0;
            added++;
        }
        uint64_t next=next_boundary(addr,shift,a.level);
        if(next<=addr)return 0;
        addr=next;
    }
    e->leaves+=added;return 1;
}
static int unnest_view(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,
    const struct sptm_unnest_plan *p,int commit)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!p || !p->count || p->count>2048 || p->span!=mmu_level_size(shift,2) ||
       !nest_geometry(e,s,m,shared,p->base,shift,p->count*p->span/(1UL<<shift),&g,&base,&end) ||
       base!=p->base || p->leaves>e->leaves)return 0;
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};
    uint64_t found=0,descriptors=0;
    for(unsigned i=0;i<2048;i++)if(p->mask[i/64]&(1UL<<(i%64))) {
        if(i>=p->count)return 0;
        descriptors++;
        uint64_t start=p->base+i*p->span,stop=start+p->span;
        for(uint64_t addr=start;addr<stop;) {
            struct mmu_leaf a,b;
            if(mmu_walk(&source,addr,checked_read,(void *)m,&a) ||
               mmu_walk(&hw,addr,s->read,s->ctx,&b))return 0;
            if(commit) {if(a.valid || a.level>2)return 0;}
            else if(a.valid!=b.valid)return 0;
            if(b.valid) {
                if(b.level!=3 || (!commit && (a.level!=3 || a.pa!=b.pa ||
                    ((a.descriptor^b.descriptor)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))))return 0;
                found+=!(addr&(g.page_size-1));addr+=4096;
            } else {
                uint64_t next=next_boundary(addr,12,b.level);
                if(!commit) {uint64_t x=next_boundary(addr,shift,a.level);if(x<next)next=x;}
                if(next<=addr)return 0;
                addr=next;
            }
        }
        if(shadow_unmap(s,start,p->span,1))return 0;
    }
    if(found!=p->leaves || descriptors!=p->descriptors)return 0;
    if(commit) {
        struct shadow noalloc=*s;noalloc.alloc=no_alloc;
        for(unsigned i=0;i<p->count;i++)if(p->mask[i/64]&(1UL<<(i%64)))
            if(shadow_unmap(&noalloc,p->base+i*p->span,p->span,0))return 0;
        e->leaves-=found;
    }
    return 1;
}
int sptm_root_prepare_unnest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{return unnest_view(e,s,m,shared,shift,p,0);}
int sptm_root_commit_unnest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{return unnest_view(e,s,m,shared,shift,p,1);}
int sptm_root_build_shadow(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !s || !leaves || s->txsz!=17 || !s->root ||
       !sptm_mac_user_geometry(format,flags,&g))return 0;
    /* A build decides the shadow's content: never retained verdicts. */
#if SNAP_ROOT_MISS_FAST
    struct validation v={m,&g,flags,0,0,root,0,0,0};
#else
    struct validation v={m,&g,flags,0,0,root,0,0};
#endif
    if(!validate_table(&v,root,g.start,0))return 0;
    /* Existing root is inactive. Clear through the full shadow width even
     * when its new owner has a32-bit limit. Preserve empty table allocations. */
    if(shadow_unmap(s,0,1UL<<47,0))return 0;
    struct mmu_config cfg={g.shift,17,root};
    long n=shadow_build(s,&cfg,0,g.va_limit,checked_read,(void *)m);
    if(n<0)return 0;
    *leaves=(uint64_t)n;
    return 1;
}
