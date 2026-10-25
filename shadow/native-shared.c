/* SPDX-License-Identifier: MIT */
#include "native-shared.h"
#include "../compat/sprr.h"

#define GUEST_OA UINT64_C(0x0000ffffffffc000)
#define INDEX_MASK (NATIVE_SHARED_INDEX-1u)

static int live(const struct native_shared *ns,int g)
{return ns && g>=0 && (unsigned)g<NATIVE_SHARED_GROUPS && ns->group[g].guest;}
/* Probe start of a 16K-aligned guest table PA (multiplicative hashing). */
static unsigned home(uint64_t guest)
{return (unsigned)(((guest>>14)*UINT64_C(0x9e3779b97f4a7c15))>>(64-13))&INDEX_MASK;}
_Static_assert(NATIVE_SHARED_INDEX==1u<<13,"home() takes 13 bits");
/* The index position holding g, or NATIVE_SHARED_INDEX. */
static unsigned position(const struct native_shared *ns,uint64_t guest)
{
    unsigned i=home(guest);
    for(unsigned n=0;n<NATIVE_SHARED_INDEX;n++,i=(i+1)&INDEX_MASK) {
        unsigned v=ns->index[i];
        if(!v)return NATIVE_SHARED_INDEX;
        if(v<=NATIVE_SHARED_GROUPS && ns->group[v-1].guest==guest)return i;
    }
    return NATIVE_SHARED_INDEX;
}
int native_shared_find(const struct native_shared *ns,uint64_t guest)
{
    if(!ns || !guest)return -1;
    unsigned i=position(ns,guest);
    return i<NATIVE_SHARED_INDEX ? (int)ns->index[i]-1 : -1;
}
static int index_insert(struct native_shared *ns,int g)
{
    unsigned i=home(ns->group[g].guest);
    for(unsigned n=0;n<NATIVE_SHARED_INDEX;n++,i=(i+1)&INDEX_MASK)
        if(!ns->index[i]) {ns->index[i]=(uint16_t)(g+1);return 1;}
    return 0;
}
/* Backward-shift deletion: every later member of the cluster that may move
 * closer to its home does, so a probe never stops early at the hole. */
static int index_remove(struct native_shared *ns,uint64_t guest)
{
    unsigned hole=position(ns,guest);
    if(hole>=NATIVE_SHARED_INDEX)return 0;
    for(unsigned j=(hole+1)&INDEX_MASK;ns->index[j];j=(j+1)&INDEX_MASK) {
        unsigned k=home(ns->group[ns->index[j]-1].guest);
        /* Movable unless its home lies cyclically in (hole, j]. */
        if(((j-k)&INDEX_MASK)>=((j-hole)&INDEX_MASK)) {ns->index[hole]=ns->index[j];hole=j;}
    }
    ns->index[hole]=0;
    return 1;
}
/* A 16K leaf's four 4K descriptors, as shadow_map writes them; 0 when it may
 * not enter a group. An invalid entry maps nothing, as for shadow_build
 * (XNU's compressed markers keep only software bits). */
static int translate(uint64_t d,uint64_t out[4])
{
    if(!(d&1)) {for(unsigned k=0;k<4;k++)out[k]=0;return 1;}
    if((d&3)!=3 || !sprr_fixed_native_leaf(d))return 0;
    uint64_t oa=d&GUEST_OA,attrs=(d&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|PT_VALID|PT_TABLE;
    for(unsigned k=0;k<4;k++)out[k]=(oa+4096UL*k)|attrs;
    return 1;
}
static uint64_t entry(const struct native_shared_group *grp,unsigned j,unsigned k)
{return grp->pages[j/128]+8UL*(4*(j%128)+k);}
static uint64_t link_entry(const struct native_shared_group *grp,unsigned p)
{return grp->pages[p] ? grp->pages[p]|PT_VALID|PT_TABLE : 0;}
int native_shared_create(struct native_shared *ns,const struct shadow *w,uint64_t shared,
                         uint64_t guest,uint64_t va,mmu_read_fn read,void *rctx,
                         void (*release)(void *,uint64_t),void *release_ctx)
{
    if(!ns)return -1;
    if(!w || !w->write || !w->alloc || !read || !release || !guest || (guest&16383) || !shared ||
       (va&(NATIVE_SHARED_SPAN-1)) || va>=(UINT64_C(1)<<47) || native_shared_find(ns,guest)>=0) {
        ns->errors++;return -1;
    }
    int g=-1;
    for(unsigned n=0;n<NATIVE_SHARED_GROUPS;n++)if(!ns->group[n].guest) {g=(int)n;break;}
    if(g<0) {ns->full++;return -1;}
    /* Every guest entry must translate before a page is taken. */
    unsigned used=0;
    for(unsigned j=0;j<2048;j++) {
        uint64_t d,e[4];
        if(read(rctx,guest+8UL*j,&d) || !translate(d,e)) {ns->errors++;return -1;}
        if(d&1)used|=1u<<(j/128);
    }
    struct native_shared_group grp={.guest=guest,.shared=shared,.va=va};
    for(unsigned p=0;p<NATIVE_SHARED_PAGES;p++)if(used>>p&1) {
        uint64_t pa=shadow_alloc_page(w);
        int bad=!pa || (pa&4095);
        for(unsigned q=0;q<p && !bad;q++)bad=grp.pages[q]==pa;
        if(bad)goto fail;
        grp.pages[p]=pa;
    }
    /* The pages are zeroed and unreachable: only leaves need storing. */
    for(unsigned j=0;j<2048;j++) {
        uint64_t d,e[4];
        if(read(rctx,guest+8UL*j,&d) || !translate(d,e) || ((d&1) && !grp.pages[j/128]))goto fail;
        if(!(d&1))continue;
        for(unsigned k=0;k<4;k++)if(w->write(w->ctx,entry(&grp,j,k),e[k]))goto fail;
        grp.leaves++;
    }
    ns->group[g]=grp;
    if(!index_insert(ns,g)) {ns->group[g]=(struct native_shared_group){0};goto fail;}
    ns->live++;ns->created++;
    return g;
fail:
    /* Unreachable yet: every page taken goes back. */
    for(unsigned q=0;q<NATIVE_SHARED_PAGES;q++)if(grp.pages[q])release(release_ctx,grp.pages[q]);
    ns->errors++;return -1;
}
/* The 4K level-2 table of s holding va's entry, without allocating. */
static int level2(const struct shadow *s,uint64_t va,uint64_t *table)
{
    if(!s || !s->read || s->txsz<16 || s->txsz>39 || va>=(UINT64_C(1)<<(64-s->txsz)))return 0;
    int start=mmu_start_level(12,s->txsz);
    if(start<0 || start>2)return 0;
    uint64_t current=s->root&PT_OA_MASK;
    for(unsigned l=(unsigned)start;l<2;l++) {
        uint64_t d;
        if(s->read(s->ctx,current+8UL*mmu_index(12,l,va),&d) || (d&~PT_OA_MASK)!=3 ||
           !(d&PT_OA_MASK))return 0;
        current=d&PT_OA_MASK;
    }
    *table=current;return 1;
}
int native_shared_grow(struct native_shared *ns,const struct shadow *w,int g,uint64_t va,
                       const struct native_shared_roots *roots)
{
    if(!live(ns,g) || !w || !w->alloc || !roots || !roots->tree) {if(ns)ns->errors++;return 0;}
    struct native_shared_group *grp=&ns->group[g];
    if(va<grp->va || va-grp->va>=NATIVE_SHARED_SPAN) {ns->errors++;return 0;}
    unsigned p=(unsigned)((va-grp->va)>>21);
    if(grp->pages[p])return 1;
    /* Every linking tree must take the new entry: check each slot before any
     * change (two passes; the monitor stack holds no per-slot copies). */
    unsigned first=mmu_index(12,2,grp->va)+p;
    for(unsigned pass=0;pass<2;pass++) {
        uint64_t pa=0;
        if(pass) {
            pa=shadow_alloc_page(w);
            int bad=!pa || (pa&4095);
            for(unsigned q=0;q<NATIVE_SHARED_PAGES && !bad;q++)bad=grp->pages[q]==pa;
            if(bad) {ns->errors++;return 0;}
            /* The new page is zero, so each root still maps nothing there. */
            grp->pages[p]=pa;
        }
        for(unsigned s=0;s<NATIVE_SHARED_SLOTS;s++)if(NATIVE_SHARED_SLOT_HAS(grp->slots,s)) {
            struct shadow tree;uint64_t table,d;
            if(roots->tree(roots->ctx,s,&tree) || !tree.write || !level2(&tree,grp->va,&table) ||
               tree.read(tree.ctx,table+8UL*first,&d) || d ||
               (pass && tree.write(tree.ctx,table+8UL*first,pa|PT_VALID|PT_TABLE))) {ns->errors++;return 0;}
        }
    }
    return 1;
}
int native_shared_store(struct native_shared *ns,const struct shadow *w,int g,uint64_t va,
                        uint64_t next)
{
    if(!live(ns,g) || !w || !w->read || !w->write) {if(ns)ns->errors++;return 0;}
    struct native_shared_group *grp=&ns->group[g];
    uint64_t e[4],old;
    if(va<grp->va || va-grp->va>=NATIVE_SHARED_SPAN || (va&16383) || (next && !(next&1)) ||
       !translate(next,e)) {
        ns->errors++;return 0;
    }
    unsigned j=(unsigned)((va-grp->va)>>14);
    if(!grp->pages[j/128]) {
        /* Nothing is mapped in this 2 MiB: clearing is done, mapping needs a page. */
        if(next) {ns->errors++;return 0;}
        ns->stores++;return 1;
    }
    if(w->read(w->ctx,entry(grp,j,0),&old)) {ns->errors++;return 0;}
    for(unsigned k=0;k<4;k++)if(w->write(w->ctx,entry(grp,j,k),e[k])) {ns->errors++;return 0;}
    if(!(old&1) && next)grp->leaves++;
    else if((old&1) && !next)grp->leaves--;
    ns->stores++;return 1;
}
int native_shared_storable(uint64_t next)
{uint64_t e[4];return (!next || (next&1)) && translate(next,e);}
int native_shared_holds(const struct native_shared *ns,const struct shadow *w,int g,uint64_t va,
                        uint64_t guest)
{
    if(!live(ns,g) || !w || !w->read)return 0;
    const struct native_shared_group *grp=&ns->group[g];
    uint64_t e[4];
    if(va<grp->va || va-grp->va>=NATIVE_SHARED_SPAN || (va&16383) || !translate(guest,e))return 0;
    unsigned j=(unsigned)((va-grp->va)>>14);
    if(!grp->pages[j/128])return !(guest&1);
    for(unsigned k=0;k<4;k++) {
        uint64_t actual;
        if(w->read(w->ctx,entry(grp,j,k),&actual) || actual!=e[k])return 0;
    }
    return 1;
}
int native_shared_slot_links(const struct native_shared *ns,unsigned slot,int g)
{return live(ns,g) && slot<NATIVE_SHARED_SLOTS && NATIVE_SHARED_SLOT_HAS(ns->group[g].slots,slot);}
int native_shared_linked(const struct native_shared *ns,const struct shadow *s,int g)
{
    uint64_t table;
    if(!live(ns,g) || !level2(s,ns->group[g].va,&table))return 0;
    unsigned first=mmu_index(12,2,ns->group[g].va);
    for(unsigned i=0;i<NATIVE_SHARED_PAGES;i++) {
        uint64_t d;
        if(s->read(s->ctx,table+8UL*(first+i),&d) || d!=link_entry(&ns->group[g],i))return 0;
    }
    return 1;
}
int native_shared_link(struct native_shared *ns,struct shadow *s,unsigned slot,int g)
{
    uint64_t table;
    if(!live(ns,g) || !s || !s->read || !s->write || slot>=NATIVE_SHARED_SLOTS ||
       native_shared_slot_links(ns,slot,g) || shadow_table(s,2,ns->group[g].va,&table)) {
        if(ns)ns->errors++;
        return 0;
    }
    const struct native_shared_group *grp=&ns->group[g];
    unsigned first=mmu_index(12,2,grp->va);
    for(unsigned i=0;i<NATIVE_SHARED_PAGES;i++) {
        uint64_t d;
        if(s->read(s->ctx,table+8UL*(first+i),&d) || d) {ns->errors++;return 0;}
    }
    for(unsigned i=0;i<NATIVE_SHARED_PAGES;i++)if(grp->pages[i])
        if(s->write(s->ctx,table+8UL*(first+i),link_entry(grp,i))) {ns->errors++;return 0;}
    NATIVE_SHARED_SLOT_SET(ns->group[g].slots,slot);ns->linked++;return 1;
}
int native_shared_unlink(struct native_shared *ns,struct shadow *s,unsigned slot,int g)
{
    uint64_t table;
    if(!live(ns,g) || !s || !s->write || !native_shared_slot_links(ns,slot,g) ||
       !native_shared_linked(ns,s,g) || !level2(s,ns->group[g].va,&table)) {
        if(ns)ns->errors++;
        return 0;
    }
    unsigned first=mmu_index(12,2,ns->group[g].va);
    for(unsigned i=0;i<NATIVE_SHARED_PAGES;i++)if(ns->group[g].pages[i])
        if(s->write(s->ctx,table+8UL*(first+i),0)) {ns->errors++;return 0;}
    NATIVE_SHARED_SLOT_CLEAR(ns->group[g].slots,slot);ns->unlinked++;return 1;
}
int native_shared_forget_slot(struct native_shared *ns,unsigned slot)
{
    if(!ns || slot>=NATIVE_SHARED_SLOTS)return 0;
    for(unsigned g=0;g<NATIVE_SHARED_GROUPS;g++)
        if(ns->group[g].guest && NATIVE_SHARED_SLOT_HAS(ns->group[g].slots,slot)) {
            NATIVE_SHARED_SLOT_CLEAR(ns->group[g].slots,slot);ns->unlinked++;
        }
    return 1;
}
int native_shared_free(struct native_shared *ns,int g,void (*release)(void *,uint64_t),void *ctx)
{
    if(!live(ns,g) || !release || NATIVE_SHARED_SLOTS_ANY(ns->group[g].slots) ||
       !index_remove(ns,ns->group[g].guest)) {
        if(ns)ns->errors++;
        return 0;
    }
    for(unsigned p=0;p<NATIVE_SHARED_PAGES;p++)if(ns->group[g].pages[p])release(ctx,ns->group[g].pages[p]);
    ns->group[g]=(struct native_shared_group){0};ns->live--;ns->freed++;
    return 1;
}
int native_shared_verify(const struct native_shared *ns,const struct shadow *w,int g,
                         mmu_read_fn read,void *rctx)
{
    if(!live(ns,g) || !w || !w->read || !read)return 0;
    const struct native_shared_group *grp=&ns->group[g];
    if((grp->guest&16383) || (grp->va&(NATIVE_SHARED_SPAN-1)) || !grp->shared ||
       native_shared_find(ns,grp->guest)!=g)return 0;
    for(unsigned p=0;p<NATIVE_SHARED_PAGES;p++) {
        if(grp->pages[p]&4095)return 0;
        for(unsigned q=0;q<p;q++)if(grp->pages[p] && grp->pages[q]==grp->pages[p])return 0;
    }
    uint64_t leaves=0;
    for(unsigned j=0;j<2048;j++) {
        uint64_t d,e[4];
        if(read(rctx,grp->guest+8UL*j,&d) || !translate(d,e))return 0;
        leaves+=d&1;
        if(!grp->pages[j/128]) {
            if(d&1)return 0;
            continue;
        }
        for(unsigned k=0;k<4;k++) {
            uint64_t actual;
            if(w->read(w->ctx,entry(grp,j,k),&actual) || actual!=e[k])return 0;
        }
    }
    return leaves==grp->leaves;
}
