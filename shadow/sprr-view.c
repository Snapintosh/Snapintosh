/* SPDX-License-Identifier: MIT */
#include "sprr-view.h"
#include "../compat/sprr.h"

static int inspect_classes(const struct shadow *s,uint64_t table,unsigned level,
    uint64_t path[4],uint64_t forbidden,struct sprr_view_classes *v)
{
    if(!table || (table&4095) || ++v->tables>SPRR_CLASS_WALK_TABLES)return 0;
    for(unsigned n=0;n<level;n++)if(path[n]==table)return 0;
    path[level]=table;
    for(unsigned i=0;i<512;i++) {
        uint64_t d;if(s->read(s->ctx,table+8UL*i,&d))return 0;
        if(!d)continue;
        if(!(d&1) || (!level && i>=256))return 0;
        if(level<3 && (d&3)==3) {
            if((d&~PT_OA_MASK)!=3 ||
               !inspect_classes(s,d&PT_OA_MASK,level+1,path,forbidden,v))return 0;
        } else {
            if(!level || (d&3)!=(level==3 ? 3u : 1u))return 0;
            uint64_t size=mmu_level_size(12,level),bit=1UL<<sprr_pte_class(d);
            if(((d&PT_OA_MASK)&(size-1)) || (forbidden&bit))return 0;
            v->pages+=size/4096;v->classes|=bit;
        }
    }
    return 1;
}
int sprr_views_check_classes(const struct shadow *s,uint64_t forbidden,
                             struct sprr_view_classes *out)
{
    uint64_t path[4];struct sprr_view_classes v={0};
    if(!s || s->txsz!=17 || !s->read || !out || (forbidden&~0xffffUL) ||
       !inspect_classes(s,s->root,0,path,forbidden,&v))return 0;
    *out=v;return 1;
}
/* inspect_classes with one bounded mapping per table instead of 512 callback
 * reads. The reader's per-page verdict equals the verdict every word read of
 * that page-aligned table would get. Every descriptor is still loaded; a zero
 * eight-word group (all eight volatile words loaded and ORed) is exactly eight
 * accepted empty descriptors. Nonzero words take the identical decisions in the
 * identical order, including early failure and the path/cycle/count limits. */
static int inspect_classes_mapped(const struct shadow *s,uint64_t table,unsigned level,
    uint64_t path[4],uint64_t forbidden,struct sprr_view_classes *v,
    sprr_table_reader read_table,struct sprr_class_walk_stats *walk)
{
    if(!table || (table&4095) || ++v->tables>SPRR_CLASS_WALK_TABLES)return 0;
    for(unsigned n=0;n<level;n++)if(path[n]==table)return 0;
    path[level]=table;
    const volatile uint64_t *w=read_table(s->ctx,table);
    if(!w || ((uintptr_t)w&7))return 0;
    walk->tables++;
    for(unsigned i=0;i<512;i++) {
        if(!(i&7)) {
            uint64_t any=w[i]|w[i+1]|w[i+2]|w[i+3]|w[i+4]|w[i+5]|w[i+6]|w[i+7];
            walk->groups++;
            if(!any) {walk->empty_groups++;i+=7;continue;}
        }
        uint64_t d=w[i];
        if(!d)continue;
        if(!(d&1) || (!level && i>=256))return 0;
        if(level<3 && (d&3)==3) {
            if((d&~PT_OA_MASK)!=3 ||
               !inspect_classes_mapped(s,d&PT_OA_MASK,level+1,path,forbidden,v,
                                       read_table,walk))return 0;
        } else {
            if(!level || (d&3)!=(level==3 ? 3u : 1u))return 0;
            uint64_t size=mmu_level_size(12,level),bit=1UL<<sprr_pte_class(d);
            if(((d&PT_OA_MASK)&(size-1)) || (forbidden&bit))return 0;
            v->pages+=size/4096;v->classes|=bit;
        }
    }
    return 1;
}
int sprr_views_check_classes_mapped(const struct shadow *s,uint64_t forbidden,
    struct sprr_view_classes *out,sprr_table_reader read_table,
    struct sprr_class_walk_stats *walk)
{
    uint64_t path[4];struct sprr_view_classes v={0};struct sprr_class_walk_stats k={0};
    if(!s || s->txsz!=17 || !read_table || !out || !walk || (forbidden&~0xffffUL) ||
       !inspect_classes_mapped(s,s->root,0,path,forbidden,&v,read_table,&k))return 0;
    walk->tables+=k.tables;walk->groups+=k.groups;walk->empty_groups+=k.empty_groups;
    *out=v;return 1;
}

static int configured(const struct sprr_views *v,const struct shadow *s)
{
    return v && s && s->txsz==17 && s->root && !(s->root&4095) &&
        s->read && s->write && s->alloc && v->canonical_root==s->root &&
        v->count && v->count<=SPRR_VIEW_TABLES &&
        v->tables[0].source==s->root && !v->tables[0].level;
}
static int find(const struct sprr_views *v,uint64_t source)
{
    for(unsigned n=0;n<v->count;n++)if(v->tables[n].source==source)return (int)n;
    return -1;
}
static int add(struct sprr_views *v,const struct shadow *s,uint64_t source,unsigned level)
{
    int found=find(v,source);
    if(found>=0)return v->tables[found].level==level;
    if(v->count>=SPRR_VIEW_TABLES || !source || (source&4095) || level>3)return 0;
    struct sprr_view_table *t=&v->tables[v->count];
#if SNAP_VIEW_RECLAIM
    /* Pages still waiting for sprr_views_reclaim's invalidation stay unused. */
    if(t->level)return 0;
#endif
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
#if SNAP_VIEW_RECLAIM
        /* A retired set, or pages a failed add kept: no CPU can reach them
         * any more, and they pass the same alias checks as fresh pages. The
         * next sync stores every word that differs from its translation
         * before a parent links them, and the publication rows mark every
         * position at or past their count, so the whole page is cleaned
         * before the next TLBI. */
        uint64_t pa=t->copy[cpu] ? t->copy[cpu] : shadow_alloc_page(s);
#else
        uint64_t pa=shadow_alloc_page(s);
#endif
        if(!pa || (pa&4095) || pa==source)return 0;
        for(unsigned n=0;n<v->count;n++) {
            if(pa==v->tables[n].source)return 0;
            for(unsigned k=0;k<SPRR_VIEW_CPUS;k++)if(pa==v->tables[n].copy[k])return 0;
        }
        for(unsigned k=0;k<cpu;k++)if(pa==t->copy[k])return 0;
        t->copy[cpu]=pa;
    }
    t->source=source;t->level=level;v->count++;return 1;
}
int sprr_views_init(struct sprr_views *v,const struct shadow *s)
{
    if(!v || !s || v->count || v->canonical_root || s->txsz!=17 ||
       !s->root || (s->root&4095) || !s->read || !s->write || !s->alloc)return 0;
    if(!add(v,s,s->root,0))return 0;
    v->canonical_root=s->root;return 1;
}
uint64_t sprr_views_root(const struct sprr_views *v,unsigned cpu)
{
    return v && v->count && cpu<SPRR_VIEW_CPUS ? v->tables[0].copy[cpu] : 0;
}
static int prepare_path(struct sprr_views *v,const struct shadow *s,uint64_t va,int empty)
{
    if(!configured(v,s))return 0;
    uint64_t path[4],table=s->root;va&=(1UL<<47)-1;
    /* Validate the complete path before retaining any copies. Blocks need
     * splitting before a 16K frame can acquire independent permissions. */
    for(unsigned level=0;level<4;level++) {
        if(!table || (table&4095))return 0;
        for(unsigned n=0;n<level;n++)if(path[n]==table)return 0;
        for(unsigned n=0;n<v->count;n++) {
            if(v->tables[n].source==table && v->tables[n].level!=level)return 0;
            for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
                if(v->tables[n].copy[cpu]==table)return 0;
        }
        path[level]=table;uint64_t pte;
        if(s->read(s->ctx,table+8UL*mmu_index(12,level,va),&pte))return 0;
        if(level==3) {if((pte&3)!=3 && !(empty && !pte))return 0;}
        else {
            if((pte&~PT_OA_MASK)!=3)return 0;
            table=pte&PT_OA_MASK;
        }
    }
#if SNAP_VIEW_RECLAIM
    /* Room for the whole path or no change: a full pool refuses before any
     * add, so the caller can reclaim and prepare again from a clean state. */
    unsigned missing=0;
    for(unsigned level=0;level<4;level++)missing+=find(v,path[level])<0;
    if(v->count+missing>SPRR_VIEW_TABLES)return 0;
#endif
    for(unsigned level=0;level<4;level++)if(!add(v,s,path[level],level))return 0;
    return 1;
}
int sprr_views_prepare(struct sprr_views *v,const struct shadow *s,uint64_t va)
{return prepare_path(v,s,va,0);}
int sprr_views_prepare_user_leaf(struct sprr_views *v,const struct shadow *s,uint64_t va)
{
    if(va>=(1UL<<47) || (va&4095))return 0;
    return prepare_path(v,s,va,1);
}
#if SNAP_VIEW_RECLAIM
int sprr_views_reclaim(struct sprr_views *v,const struct shadow *s,int (*quiesce)(void *),void *ctx)
{
    if(!configured(v,s) || !quiesce)return -1;
    unsigned count=(unsigned)v->count,kept=0;
    for(unsigned n=0;n<count;n++)if(v->tables[n].level>3)return -1;
    uint8_t keep[SPRR_VIEW_TABLES];
    /* Levels 3 to 0, so every copied child is judged before its parent. A
     * child at the wrong level is kept (its parent's sync refuses it anyway). */
    for(unsigned level=4;level--;)for(unsigned n=0;n<count;n++) {
        const struct sprr_view_table *t=&v->tables[n];
        if(t->level!=level)continue;
        int need=!level;
        for(unsigned i=0;i<512 && !need;i++) {
            uint64_t d;
            if(s->read(s->ctx,t->source+8UL*i,&d))return -1;
            if(!(d&1))continue;
            if(level<3 && (d&3)==3) {
                int child=find(v,d&PT_OA_MASK);
                need=child>=0 && (v->tables[child].level!=level+1 || keep[child]);
            } else need=(UINT32_C(0x214)>>sprr_pte_class(d))&1;  /* selector 2, 4 or 9 */
        }
        keep[n]=(uint8_t)need;kept+=(unsigned)need;
    }
    if(kept==count)return 0;
    /* Stable for the kept tables; a retired entry keeps its own six pages. */
    unsigned w=0;
    for(unsigned n=0;n<count;n++)if(keep[n]) {
        struct sprr_view_table t=v->tables[w];
        v->tables[w++]=v->tables[n];v->tables[n]=t;
    }
    for(unsigned n=w;n<count;n++) {v->tables[n].source=0;v->tables[n].level=SPRR_VIEW_RETIRED;}
    v->count=w;
    if(!quiesce(ctx))return -1;
    for(unsigned n=w;n<count;n++)v->tables[n].level=0;
    return (int)(count-w);
}
#endif

static int entry_decode(const struct sprr_views *v,unsigned n,uint64_t d,
                  unsigned index,unsigned cpu,uint64_t pperm,
                  const struct sprr_state *user,int el0,uint64_t *result)
{
    const struct sprr_view_table *t=&v->tables[n];
    if(!t->level && index>=256 && (d&1))return 0;
    if(!(d&1)) {*result=d;return 1;}
    if(t->level<3 && (d&3)==3) {
        if((d&~PT_OA_MASK)!=3 || !(d&PT_OA_MASK))return 0;
        int child=find(v,d&PT_OA_MASK);
        if(child>=0) {
            if(v->tables[child].level!=t->level+1)return 0;
            d=v->tables[child].copy[cpu]|3;
        }
    } else {
        if(!t->level || (t->level==3 ? (d&3)!=3 : (d&3)!=1))return 0;
        uint64_t size=mmu_level_size(12,(unsigned)t->level);
        if((d&PT_OA_MASK)&(size-1))return 0;
        if(user) {
            if(t->level!=3)return 0;
            if(sprr_pte_class(d)==9) {
                if((user->umprr&0xc0000)!=0x40000)return 0;
                uint64_t permission=el0 ? user->uperm : user->pperm;
                /* Both reached permissions allow data reads. Bit36 grants
                 * writes; execute is always forbidden at both ELs. PAN must
                 * still recognize this as a user-accessible page at EL1. */
                d=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN|(1UL<<6);
                if(!(permission&SPRR_UPERM_TPRO_WRITE))d|=2UL<<6;
            } else if(!sprr_fixed_native_leaf(d))return 0;
        } else if(sprr_pte_class(d)==9)return 0; /* no raw TPRO on a kernel view */
        else if(sprr_pte_class(d)==2 || sprr_pte_class(d)==4) {
            if(t->level!=3)return 0;
            unsigned selector=sprr_pte_class(d);
            /* Selector2 is EL1 data only: A=RO, B=RW. In either state it
             * must not gain execute or EL0 access from its raw Apple bits. */
            d=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN;
            /* Selector4's fixed nibbleA protects the TXM aperture. The
             * mutable selector2 bit must never enable writes to this class. */
            if(selector==4 || !(pperm&0x100))d|=2UL<<6;
        }
    }
    *result=d;return 1;
}
static int entry(const struct sprr_views *v,const struct shadow *s,unsigned n,
                  unsigned index,unsigned cpu,uint64_t pperm,
                  const struct sprr_state *user,int el0,uint64_t *result)
{
    const struct sprr_view_table *t=&v->tables[n];uint64_t d;
    if(t->level>3 || (t->source&4095) ||
       s->read(s->ctx,t->source+8UL*index,&d))return 0;
    return entry_decode(v,n,d,index,cpu,pperm,user,el0,result);
}
static int preflight_cpu(struct sprr_views *v,const struct shadow *s,unsigned cpu,
                         uint64_t pperm,const struct sprr_state *user,int el0)
{
    if(!configured(v,s) || cpu>=SPRR_VIEW_CPUS ||
       (pperm&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;
    /* Validation errors cannot partly modify a live view. The backend must
     * keep source memory stable across this preflight and the commit pass. */
    for(unsigned n=0;n<v->count;n++) {
        if(!v->tables[n].copy[cpu] || (v->tables[n].copy[cpu]&4095))return 0;
        for(unsigned i=0;i<512;i++) {
            uint64_t d;if(!entry(v,s,n,i,cpu,pperm,user,el0,&d))return 0;
        }
    }
    return 1;
}
static int commit_cpu(struct sprr_views *v,const struct shadow *s,unsigned cpu,
                      uint64_t pperm,const struct sprr_state *user,int el0)
{
    /* Children before parents: a newly copied branch is fully populated
     * before a copied ancestor can make it reachable. */
    for(unsigned level=4;level--;)for(unsigned n=0;n<v->count;n++)
        if(v->tables[n].level==level)for(unsigned i=0;i<512;i++) {
            uint64_t d;if(!entry(v,s,n,i,cpu,pperm,user,el0,&d) ||
                s->write(s->ctx,v->tables[n].copy[cpu]+8UL*i,d))return 0;
        }
    if(v->syncs[cpu]!=UINT64_MAX)v->syncs[cpu]++;
    return 1;
}
static int sync_cpu(struct sprr_views *v,const struct shadow *s,unsigned cpu,
                     uint64_t pperm,const struct sprr_state *user,int el0)
{
    return preflight_cpu(v,s,cpu,pperm,user,el0) &&
           commit_cpu(v,s,cpu,pperm,user,el0);
}
/* Cross-transaction claims (sprr-table-memo.h). A word is trusted only for an
 * allocator-issued arena page while the witness is usable. */
static uint64_t *memo_word(struct sprr_table_memo *m,uint64_t pa)
{
    if(!sprr_table_memo_usable(m) || (pa&4095) || pa<m->base || (pa-m->base)/4096>=m->pages)
        return 0;
    uint64_t *w=&m->page[(pa-m->base)/4096];
    return (*w&SPRR_TABLE_MEMO_POOL) ? w : 0;
}
static int memo_clean(struct sprr_table_memo *m,uint64_t pa,uint64_t stamp)
{
    const uint64_t *w=memo_word(m,pa);
    return w && (*w>>16)<=stamp;
}
/* The only per-CPU input to a user private descriptor: whether a class9 leaf
 * is accepted at all (UMPRR) and whether the reached permission grants write. */
static uint64_t memo_key(const struct sprr_state *s,int el0)
{
    uint64_t permission=el0 ? s->uperm : s->pperm;
    return ((s->umprr&0xc0000)==0x40000 ? 1u : 0u)|((permission&SPRR_UPERM_TPRO_WRITE) ? 2u : 0u);
}
static int memo_bit(const uint64_t bits[SPRR_VIEW_TABLES/64],unsigned n)
{return !!(bits[n/64]&(UINT64_C(1)<<(n%64)));}
static void memo_set_bit(uint64_t bits[SPRR_VIEW_TABLES/64],unsigned n,int value)
{
    bits[n/64]&=~(UINT64_C(1)<<(n%64));
    bits[n/64]|=(uint64_t)!!value<<(n%64);
}
/* View metadata only grows by append; equal root and count imply equal
 * sources, levels and copy addresses (a view reset also zeroes the memo). */
static int memo_matches(struct sprr_table_memo *m,const struct sprr_view_memo *vm,
                        const struct sprr_views *v)
{
    return sprr_table_memo_usable(m) && vm && v->count && vm->count==v->count &&
        vm->root==v->canonical_root;
}
static int memo_current(struct sprr_table_memo *m,const struct sprr_view_memo *vm,
    const struct sprr_views *v,unsigned n,unsigned cpu,uint64_t key)
{
    const struct sprr_view_table *t=&v->tables[n];
    return ((vm->valid>>cpu)&1) && memo_clean(m,t->source,vm->stamp[cpu]) &&
        memo_clean(m,t->copy[cpu],vm->stamp[cpu]) &&
        (vm->key[cpu]==key || !memo_bit(vm->has9,n));
}
static int memo_begin(struct sprr_table_memo *m)
{
    sprr_count(&m->stats.calls);
    int periodic=!(m->stats.calls%SPRR_TABLE_MEMO_SAMPLE),forced=!periodic && m->force;
    if(periodic)sprr_count(&m->stats.samples);
    if(forced)sprr_count(&m->stats.forced);
    m->force=0;
    return periodic || forced;
}
static unsigned memo_count_bits(unsigned bits)
{unsigned n=0;for(;bits;bits&=bits-1)n++;return n;}
static int sync_cpu_mapped(struct sprr_views *v,const struct shadow *s,unsigned cpu,
    uint64_t pperm,const struct sprr_state *user,int el0,sprr_table_reader read_table,
    sprr_table_reader read_copy,struct sprr_store_compare_stats *compare,
    struct sprr_table_memo *memo,struct sprr_view_memo *vm,int sample)
{
    if(compare)sprr_count(&compare->calls);
    if(!!read_copy!=!!compare || (compare && !read_table))goto failed;
    if(memo && (!compare || !vm || !user))goto failed;
    if(!read_table)return sync_cpu(v,s,cpu,pperm,user,el0);
    if(!configured(v,s) || cpu>=SPRR_VIEW_CPUS ||
       (pperm&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)goto failed;
    const volatile uint64_t *pages[SPRR_VIEW_TABLES];
    const volatile uint64_t *copies[SPRR_VIEW_TABLES];
    uint8_t current[SPRR_VIEW_TABLES];
    uint64_t has9[SPRR_VIEW_TABLES/64]={0},key=memo ? memo_key(user,el0) : 0;
    int matches=memo && memo_matches(memo,vm,v);
    if(matches)for(unsigned w=0;w<SPRR_VIEW_TABLES/64;w++)has9[w]=vm->has9[w];
    if(compare)compare->tables+=v->count;
    /* Every source is mapped once, every descriptor checked before any
     * private store. Sources and metadata remain stable under the service
     * token, including while write callbacks update separate private pages. */
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *t=&v->tables[n];
        if(t->level>3 || (t->source&4095) || !t->copy[cpu] || (t->copy[cpu]&4095))goto failed;
        pages[n]=read_table(s->ctx,t->source);
        if(!pages[n] || ((uintptr_t)pages[n]&7))goto failed;
        if(compare) {
            copies[n]=read_copy(s->ctx,t->copy[cpu]);
            if(!copies[n] || ((uintptr_t)copies[n]&7))goto failed;
        }
        /* A current copy was produced from these exact source bytes, view
         * metadata and class9 key by a completed sync: its preflight passed
         * then and every entry already equals its translation now. */
        current[n]=(uint8_t)(matches && memo_current(memo,vm,v,n,cpu,key));
        if(current[n] && !sample)continue;
        int nine=0;
        for(unsigned i=0;i<512;i++) {
            uint64_t raw=pages[n][i],d;
            if(!entry_decode(v,n,raw,i,cpu,pperm,user,el0,&d))goto failed;
            if(memo && t->level==3 && (raw&3)==3 && sprr_pte_class(raw)==9)nine=1;
            if(current[n] && copies[n][i]!=d) {sprr_count(&memo->stats.mismatches);goto failed;}
        }
        if(current[n]) {
            sprr_count(&memo->stats.checked);
            if(nine!=memo_bit(vm->has9,n)) {sprr_count(&memo->stats.mismatches);goto failed;}
        }
        memo_set_bit(has9,n,nine);
    }
    /* Reload the stable source bytes, retaining child-before-parent order
     * and the ordinary write callback (publication/epochs remain its job). */
    for(unsigned level=4;level--;)for(unsigned n=0;n<v->count;n++)
        if(v->tables[n].level==level) {
            if(memo) {
                if(current[n] && !sample)memo->stats.copy_hits++;
                else memo->stats.copy_misses++;
            }
            if(current[n] && !sample) {
                /* Proven equal: the same outcome as 512 skipped compares. */
                compare->compared+=512;compare->skipped+=512;continue;
            }
            for(unsigned i=0;i<512;i++) {
                uint64_t d;
                if(!entry_decode(v,n,pages[n][i],i,cpu,pperm,user,el0,&d))goto failed;
                if(compare) {
                    sprr_count(&compare->compared);
                    if(copies[n][i]==d) {sprr_count(&compare->skipped);continue;}
                    sprr_count(&compare->changed);
                }
                if(s->write(s->ctx,v->tables[n].copy[cpu]+8UL*i,d))goto failed;
            }
        }
    if(v->syncs[cpu]!=UINT64_MAX)v->syncs[cpu]++;
    if(compare)sprr_count(&compare->complete);
    if(memo) {
        /* Every copy of this CPU now holds the translation for key. Other
         * CPUs keep their own stamps unless the metadata they describe changed. */
        if(!sprr_table_memo_usable(memo)) {vm->valid=0;return 1;}
        if(!matches) {vm->valid=0;vm->root=v->canonical_root;vm->count=v->count;}
        for(unsigned w=0;w<SPRR_VIEW_TABLES/64;w++)vm->has9[w]=has9[w];
        vm->stamp[cpu]=memo->clock;vm->key[cpu]=key;vm->valid|=UINT64_C(1)<<cpu;
    }
    return 1;
failed:
    if(compare)sprr_count(&compare->failures);
    if(memo && vm)vm->valid=0;
    return 0;
}
int sprr_views_sync_cpu(struct sprr_views *v,const struct shadow *s,unsigned cpu,
                        uint64_t pperm)
{return sync_cpu(v,s,cpu,pperm,0,0);}
int sprr_views_sync_cpu_mapped(struct sprr_views *v,const struct shadow *s,unsigned cpu,
                              uint64_t pperm,sprr_table_reader read_table)
{return sync_cpu_mapped(v,s,cpu,pperm,0,0,read_table,0,0,0,0,0);}
int sprr_views_sync_cpu_compared(struct sprr_views *v,const struct shadow *s,unsigned cpu,
    uint64_t pperm,sprr_table_reader source,sprr_table_reader destination,
    struct sprr_store_compare_stats *stats)
{
    if(!source || !destination || !stats)return 0;
    return sync_cpu_mapped(v,s,cpu,pperm,0,0,source,destination,stats,0,0,0);
}
int sprr_views_verify_cpu(struct sprr_views *v,const struct shadow *s,unsigned cpu,
                          uint64_t pperm)
{
    if(!configured(v,s) || cpu>=SPRR_VIEW_CPUS ||
       (pperm&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;
    for(unsigned n=0;n<v->count;n++) {
        if(!v->tables[n].copy[cpu] || (v->tables[n].copy[cpu]&4095))return 0;
        for(unsigned i=0;i<512;i++) {
            uint64_t expected,actual;
            if(!entry(v,s,n,i,cpu,pperm,0,0,&expected) ||
               s->read(s->ctx,v->tables[n].copy[cpu]+8UL*i,&actual) ||
               actual!=expected)return 0;
        }
    }
    return 1;
}
#if SNAP_UPDATE_DISJOINT_FAST
/* compat/update-fast.h V1/V2: the conjunction of sprr_views_verify_cpu over
 * all CPUs. Every predicate it evaluates (configuration, each CPU's PPERM,
 * each copy's presence and alignment, the table's level and source, each
 * source read, each CPU's own decode of that word and read of its own copy)
 * is pure under the caller's lock, so evaluating them table by table with
 * one source read per word yields the same verdict. */
int sprr_views_verify_all(struct sprr_views *v,const struct shadow *s,
                          const uint64_t pperm[SPRR_VIEW_CPUS])
{
    if(!configured(v,s) || !pperm)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if((pperm[cpu]&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *t=&v->tables[n];
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
            if(!t->copy[cpu] || (t->copy[cpu]&4095))return 0;
        if(t->level>3 || (t->source&4095))return 0;
        for(unsigned i=0;i<512;i++) {
            uint64_t d;
            if(s->read(s->ctx,t->source+8UL*i,&d))return 0;
            for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
                uint64_t expected,actual;
                if(!entry_decode(v,n,d,i,cpu,pperm[cpu],0,0,&expected) ||
                   s->read(s->ctx,t->copy[cpu]+8UL*i,&actual) || actual!=expected)return 0;
            }
        }
    }
    return 1;
}
#endif
#if SNAP_MULTIPAGE_FAST
int sprr_views_word_table(const struct sprr_views *v,uint64_t pa)
{
    if(!v || (pa&7))return -1;
    int n=find(v,pa&~UINT64_C(4095));
    return n<0 ? -1 : v->tables[n].level!=3 ? -2 : n;
}
int sprr_views_sync_word(struct sprr_views *v,const struct shadow *s,unsigned n,unsigned index,
                         const uint64_t pperm[SPRR_VIEW_CPUS],const uint64_t extra[SPRR_VIEW_CPUS],
                         const uint64_t extra_pperm[SPRR_VIEW_CPUS])
{
    if(!configured(v,s) || !pperm || n>=v->count || index>=512 || v->tables[n].level!=3)return 0;
    const struct sprr_view_table *t=&v->tables[n];
    uint64_t d[SPRR_VIEW_CPUS],e[SPRR_VIEW_CPUS];
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
        if((pperm[cpu]&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL ||
           !t->copy[cpu] || (t->copy[cpu]&4095) ||
           !entry(v,s,n,index,cpu,pperm[cpu],0,0,&d[cpu]))return 0;
        if(extra && extra[cpu] &&
           (!extra_pperm || (extra_pperm[cpu]&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL || (extra[cpu]&4095) ||
            !entry(v,s,n,index,cpu,extra_pperm[cpu],0,0,&e[cpu])))return 0;
    }
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
        if(s->write(s->ctx,t->copy[cpu]+8UL*index,d[cpu]))return 0;
        if(extra && extra[cpu] && s->write(s->ctx,extra[cpu]+8UL*index,e[cpu]))return 0;
    }
    return 1;
}
#endif

static int user_plan_path(struct sprr_user_prepare_plan *p,uint64_t source,unsigned level)
{
    for(unsigned n=0;n<p->required_count;n++)if(p->required[n].source==source)
        return p->required[n].level==level;
    if(p->required_count>=SPRR_VIEW_TABLES)return 0;
    p->required[p->required_count++]=(struct sprr_user_prepare_path){source,level};
    return 1;
}
/* A full source walk proves that no affected leaf can escape through a
 * shared branch. pass0 validates, pass1 prepares private paths, pass2 checks
 * coverage, pass3 validates and records a transaction-local allocation plan.
 * No live private-table write occurs in any pass. */
static int user_tree(struct sprr_views *v,const struct shadow *s,uint64_t table,
    unsigned level,uint64_t va,uint64_t path[4],uint64_t *tables,unsigned pass,
    struct sprr_user_prepare_plan *plan,sprr_user_table_reader read_table,
    struct sprr_user_zero_stats *zero,struct sprr_table_memo *memo,int sample)
{
    if(!table || (table&4095) || ++*tables>8192)return 0;
    if(pass==3) {
        if(!plan)return 0;
        plan->sources[*tables-1]=table;plan->source_count=*tables;
    }
    for(unsigned n=0;n<level;n++)if(path[n]==table)return 0;
    for(unsigned n=0;n<v->count;n++)for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if(v->tables[n].copy[cpu]==table)return 0;
    path[level]=table;
    int found=find(v,table);
    if(found>=0 && v->tables[found].level!=level)return 0;
    const volatile uint64_t *mapped=0;
    if(read_table) {
        mapped=read_table(s->ctx,table);
        if(!mapped || ((uintptr_t)mapped&7))return 0;
    }
    /* A level3 scan is a pure function of the page bytes: every nonzero
     * entry must be a valid page leaf of class9 or a fixed native class; only
     * class9's consequence differs by pass (pass3 adds the walk-supplied path
     * to the plan, pass2 requires it to be private already). A current summary
     * was taken from these exact bytes after a complete successful scan in
     * either pass, so it replays the same class9 consequence once, at the same
     * walk position (repeats are idempotent), and the same zero-group totals.
     * Every check above still ran for this visit. Pass0/1 never use claims. */
    int memo_scan=memo && level==3 && ((pass==3 && zero && mapped) || (pass==2 && !zero));
    uint64_t *summary=memo_scan ? memo_word(memo,table) : 0;
    if(summary && !sample && (*summary&SPRR_TABLE_MEMO_SCAN) &&
       (*summary&SPRR_TABLE_MEMO_LEVEL)==3) {
        if(*summary&SPRR_TABLE_MEMO_HAS9)for(unsigned n=0;n<4;n++) {
            if(pass==3 && !user_plan_path(plan,path[n],n))return 0;
            if(pass==2) {
                int p=find(v,path[n]);
                if(p<0 || v->tables[p].level!=n)return 0;
            }
        }
        if(zero) {zero->groups+=64;zero->empty_groups+=(*summary>>SPRR_TABLE_MEMO_EMPTY_SHIFT)&127;}
        sprr_count(pass==3 ? &memo->stats.scan_hits : &memo->stats.walk_hits);
        return 1;
    }
    uint64_t empty=0,groups=0;int has9=0;
    for(unsigned i=0;i<512;i++) {
        if(zero && !(i&7)) {
            /* Bitwise OR reads every volatile word, including the last one.
             * Under the service token the source remains unchanged. Zero is
             * the exact already-accepted empty descriptor at every level. */
            uint64_t any=mapped[i]|mapped[i+1]|mapped[i+2]|mapped[i+3]|
                         mapped[i+4]|mapped[i+5]|mapped[i+6]|mapped[i+7];
            if(!any) {empty++;i+=7;continue;}
        }
        uint64_t d;
        if(mapped)d=mapped[i];
        else if(s->read(s->ctx,table+8UL*i,&d))return 0;
        if(!d)continue;
        groups|=UINT64_C(1)<<(i/8);
        if(!(d&1) || (!level && i>=256))return 0;
        uint64_t address=va|((uint64_t)i<<(12+9*(3-level)));
        if(level<3) {
            if((d&~PT_OA_MASK)!=3 ||
               !user_tree(v,s,d&PT_OA_MASK,level+1,address,path,tables,pass,plan,read_table,zero,
                         memo,sample))return 0;
        } else {
            if((d&3)!=3)return 0;
            if(sprr_pte_class(d)==9) {
                has9=1;
                if(pass==1 && !sprr_views_prepare(v,s,address))return 0;
                if(pass==3)for(unsigned n=0;n<4;n++)
                    if(!user_plan_path(plan,path[n],n))return 0;
                if(pass==2)for(unsigned n=0;n<4;n++) {
                    int p=find(v,path[n]);
                    if(p<0 || v->tables[p].level!=n)return 0;
                }
            } else if(!sprr_fixed_native_leaf(d))return 0;
        }
    }
    if(zero) {zero->groups+=64;zero->empty_groups+=empty;}
    if(memo_scan)sprr_count(pass==3 ? &memo->stats.scan_misses : &memo->stats.walk_misses);
    if(summary) {
        /* Grouped scans count empty groups directly; word scans from the set
         * of groups holding a nonzero word. Both describe the same bytes. */
        if(!zero) {empty=64;for(uint64_t g=groups;g;g&=g-1)empty--;}
        uint64_t next=(*summary&~UINT64_C(0xffff))|SPRR_TABLE_MEMO_POOL|SPRR_TABLE_MEMO_SCAN|3|
            (has9 ? SPRR_TABLE_MEMO_HAS9 : 0)|(empty<<SPRR_TABLE_MEMO_EMPTY_SHIFT);
        if(sample && (*summary&SPRR_TABLE_MEMO_SCAN)) {
            /* A sampled rescan of a page whose summary claimed to be current. */
            sprr_count(&memo->stats.checked);
            if((*summary^next)&UINT64_C(0xffff)) {sprr_count(&memo->stats.mismatches);return 0;}
        }
        *summary=next;
    }
    return 1;
}
int sprr_views_prepare_user(struct sprr_views *v,const struct shadow *s)
{
    if(!configured(v,s))return 0;
    uint64_t path[4],tables=0;
    if(!user_tree(v,s,s->root,0,0,path,&tables,0,0,0,0,0,0))return 0;
    tables=0;return user_tree(v,s,s->root,0,0,path,&tables,1,0,0,0,0,0);
}
int sprr_views_sync_user_cpu(struct sprr_views *v,const struct shadow *s,unsigned cpu,
                            const struct sprr_state *state,int el0)
{
    if(!configured(v,s) || cpu>=SPRR_VIEW_CPUS || !sprr_fixed_state_valid(state) ||
       (el0!=0 && el0!=1))return 0;
    uint64_t path[4],tables=0;
    if(!user_tree(v,s,s->root,0,0,path,&tables,2,0,0,0,0,0))return 0;
    return sync_cpu(v,s,cpu,state->pperm,state,el0);
}
int sprr_views_sync_user_all(struct sprr_views *v,const struct shadow *s,
                            const struct sprr_state states[SPRR_VIEW_CPUS],
                            const int el0[SPRR_VIEW_CPUS])
{
    if(!configured(v,s) || !states || !el0)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if(!sprr_fixed_state_valid(&states[cpu]) || (el0[cpu]!=0 && el0[cpu]!=1))return 0;
    /* The canonical tree and private-path coverage are independent of each
     * CPU's permissions. Under the caller's service lock this proof is the
     * same for all six views. Keep per-CPU descriptor validation and publish
     * nothing until every view has passed its preflight. */
    uint64_t path[4],tables=0;
    if(!user_tree(v,s,s->root,0,0,path,&tables,2,0,0,0,0,0))return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if(!preflight_cpu(v,s,cpu,states[cpu].pperm,&states[cpu],el0[cpu]))return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if(!commit_cpu(v,s,cpu,states[cpu].pperm,&states[cpu],el0[cpu]))return 0;
    return 1;
}
static int user_batch_entry(const struct sprr_views *v,const struct shadow *s,
    unsigned n,unsigned index,const struct sprr_state states[SPRR_VIEW_CPUS],
    const int el0[SPRR_VIEW_CPUS],uint64_t result[SPRR_VIEW_CPUS],
    const volatile uint64_t *mapped,int *class9)
{
    const struct sprr_view_table *t=&v->tables[n];uint64_t d;
    if(t->level>3 || (t->source&4095))return 0;
    if(mapped)d=mapped[index];
    else if(s->read(s->ctx,t->source+8UL*index,&d))return 0;
    if(!t->level && index>=256 && (d&1))return 0;
    if(d&1) {
        if(t->level<3 && (d&3)==3) {
            if((d&~PT_OA_MASK)!=3 || !(d&PT_OA_MASK))return 0;
            int child=find(v,d&PT_OA_MASK);
            if(child>=0) {
                if(v->tables[child].level!=t->level+1)return 0;
                for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
                    result[cpu]=v->tables[child].copy[cpu]|3;
                return 1;
            }
        } else {
            /* User private leaves have no supported block form. */
            if(t->level!=3 || (d&3)!=3)return 0;
            if(sprr_pte_class(d)==9) {
                if(class9)*class9=1;
                uint64_t base=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN|(1UL<<6);
                for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
                    if((states[cpu].umprr&0xc0000)!=0x40000)return 0;
                    uint64_t permission=el0[cpu] ? states[cpu].uperm : states[cpu].pperm;
                    result[cpu]=base|((permission&SPRR_UPERM_TPRO_WRITE) ? 0 : 2UL<<6);
                }
                return 1;
            }
            if(!sprr_fixed_native_leaf(d))return 0;
        }
    }
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)result[cpu]=d;
    return 1;
}
static int user_fused_ready(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS])
{
    if(!configured(v,s) || !states || !el0)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
        if(!sprr_fixed_state_valid(&states[cpu]) || (el0[cpu]!=0 && el0[cpu]!=1))return 0;
        for(unsigned n=0;n<v->count;n++)
            if(!v->tables[n].copy[cpu] || (v->tables[n].copy[cpu]&4095))return 0;
    }
    return 1;
}
static int user_fused_apply(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    sprr_table_reader source,sprr_table_reader destination,struct sprr_store_compare_stats *compare,
    struct sprr_table_memo *memo,struct sprr_view_memo *vm,int sample)
{
    const unsigned all=(1u<<SPRR_VIEW_CPUS)-1;
    uint64_t result[SPRR_VIEW_CPUS],key[SPRR_VIEW_CPUS],has9[SPRR_VIEW_TABLES/64]={0};
    const volatile uint64_t *pages[SPRR_VIEW_TABLES];
    const volatile uint64_t *copies[SPRR_VIEW_TABLES][SPRR_VIEW_CPUS];
    uint8_t current[SPRR_VIEW_TABLES];
    if(compare) {
        sprr_count(&compare->calls);compare->tables+=SPRR_VIEW_CPUS*v->count;
        if(!source || !destination)goto failed;
        /* Map every source and destination before descriptor preflight. No
         * pointer survives this transaction or bypasses changed-word stores. */
        for(unsigned n=0;n<v->count;n++) {
            pages[n]=source(s->ctx,v->tables[n].source);
            if(!pages[n] || ((uintptr_t)pages[n]&7))goto failed;
            for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
                copies[n][cpu]=destination(s->ctx,v->tables[n].copy[cpu]);
                if(!copies[n][cpu] || ((uintptr_t)copies[n][cpu]&7))goto failed;
            }
        }
    } else if(source || destination)return 0;
    if(memo && (!compare || !vm))goto failed;
    int matches=memo && memo_matches(memo,vm,v);
    if(matches)for(unsigned w=0;w<SPRR_VIEW_TABLES/64;w++)has9[w]=vm->has9[w];
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)key[cpu]=memo_key(&states[cpu],el0[cpu]);
    /* current bit cpu: copy[cpu] of table n is proven to hold its translation
     * already (see memo_current); it needs neither preflight nor compare. */
    for(unsigned n=0;n<v->count;n++) {
        current[n]=0;
        if(matches)for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
            if(memo_current(memo,vm,v,n,cpu,key[cpu]))current[n]|=(uint8_t)(1u<<cpu);
    }
    /* Source structure is common; TPRO grants and child-copy addresses are
     * still derived independently for all CPUs before any live write. A
     * table current for every CPU passed this exact preflight before: same
     * bytes, metadata and (where class9 matters) the same accepted UMPRR. */
    for(unsigned n=0;n<v->count;n++) {
        if(current[n]==all && !sample)continue;
        int nine=0;
        for(unsigned i=0;i<512;i++) {
            if(!user_batch_entry(v,s,n,i,states,el0,result,compare ? pages[n]:0,&nine))goto failed;
            /* Sampled: every claim is checked read-only before any store. */
            if(current[n])for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
                if(((current[n]>>cpu)&1) && copies[n][cpu][i]!=result[cpu]) {
                    sprr_count(&memo->stats.mismatches);goto failed;
                }
        }
        if(current[n]) {
            memo->stats.checked+=memo_count_bits(current[n]);
            if(nine!=memo_bit(vm->has9,n)) {sprr_count(&memo->stats.mismatches);goto failed;}
        }
        memo_set_bit(has9,n,nine);
    }
    /* Populate all child copies before publishing a private parent path.
     * The caller still owns cache publication and hardware invalidation. */
    for(unsigned level=4;level--;)for(unsigned n=0;n<v->count;n++)
        if(v->tables[n].level==level) {
            unsigned skip=sample ? 0 : current[n];
            if(memo) {
                unsigned hits=memo_count_bits(skip);
                memo->stats.copy_hits+=hits;memo->stats.copy_misses+=SPRR_VIEW_CPUS-hits;
            }
            if(skip==all) {
                /* Proven equal: the outcome of 6*512 skipped compares. */
                compare->compared+=SPRR_VIEW_CPUS*512;compare->skipped+=SPRR_VIEW_CPUS*512;
                continue;
            }
            for(unsigned i=0;i<512;i++) {
                if(!user_batch_entry(v,s,n,i,states,el0,result,compare ? pages[n]:0,0))goto failed;
                for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
                    if(compare) {
                        compare->compared++;
                        if(((skip>>cpu)&1) || copies[n][cpu][i]==result[cpu]) {
                            compare->skipped++;continue;
                        }
                        compare->changed++;
                    }
                    if(s->write(s->ctx,v->tables[n].copy[cpu]+8UL*i,result[cpu]))goto failed;
                }
            }
        }
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)sprr_count(&v->syncs[cpu]);
    if(compare)sprr_count(&compare->complete);
    if(memo) {
        /* Every copy now holds its translation for this key; the stamp covers
         * the stores just made and nothing later. */
        if(!sprr_table_memo_usable(memo)) {vm->valid=0;return 1;}
        vm->root=v->canonical_root;vm->count=v->count;
        for(unsigned w=0;w<SPRR_VIEW_TABLES/64;w++)vm->has9[w]=has9[w];
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
            vm->stamp[cpu]=memo->clock;vm->key[cpu]=key[cpu];
        }
        vm->valid=all;
    }
    return 1;
failed:
    if(compare)sprr_count(&compare->failures);
    if(memo && vm)vm->valid=0;
    return 0;
}
int sprr_views_sync_user_fused(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS])
{
    if(!user_fused_ready(v,s,states,el0))return 0;
    uint64_t path[4],tables=0;
    if(!user_tree(v,s,s->root,0,0,path,&tables,2,0,0,0,0,0))return 0;
    return user_fused_apply(v,s,states,el0,0,0,0,0,0,0);
}
static int prepare_sync_user_grouped(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *plan,struct sprr_user_prepare_stats *stats,
    sprr_user_table_reader read_table,struct sprr_user_zero_stats *zero,
    sprr_table_reader source,sprr_table_reader destination,struct sprr_store_compare_stats *compare,
    struct sprr_table_memo *memo,struct sprr_view_memo *vm)
{
    if(!stats)return 0;
    sprr_count(&stats->calls);
    if(!plan || !configured(v,s) || (zero && !read_table))goto failed;
    if(memo && (!zero || !compare || !vm))goto failed;
    int sample=memo ? memo_begin(memo) : 0;
    plan->root=s->root;plan->source_count=plan->required_count=0;
    uint64_t path[4],tables=0;
    if(!user_tree(v,s,s->root,0,0,path,&tables,3,plan,read_table,zero,memo,sample))goto failed;
    /* The immutable source walk proves which complete paths need copies.
     * Allocation follows the same first-encounter order as prepare_user. */
    for(unsigned n=0;n<plan->required_count;n++)
        if(!add(v,s,plan->required[n].source,(unsigned)plan->required[n].level))goto failed;
    /* Detect even a bad allocator returning an earlier ordinary source page:
     * the post-allocation reference walk would also reject that alias. */
    for(unsigned n=0;n<v->count;n++)for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        for(unsigned source=0;source<plan->source_count;source++)
            if(v->tables[n].copy[cpu]==plan->sources[source])goto failed;
    if(!user_fused_ready(v,s,states,el0))goto failed;
    if(!(stats->calls&63)) {
        sprr_count(&stats->verified);tables=0;
        if(!user_tree(v,s,s->root,0,0,path,&tables,2,0,0,0,0,0)) {
            sprr_count(&stats->mismatches);goto failed;
        }
    }
    if(!user_fused_apply(v,s,states,el0,source,destination,compare,memo,vm,sample))goto failed;
    sprr_count(&stats->successes);
    stats->source_tables+=plan->source_count;stats->private_tables+=v->count;
    return 1;
failed:
    if(memo && vm)vm->valid=0;
    sprr_count(&stats->failures);return 0;
}
int sprr_views_prepare_sync_user_grouped(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *plan,struct sprr_user_prepare_stats *stats,
    sprr_user_table_reader read_table,struct sprr_user_zero_stats *zero)
{return prepare_sync_user_grouped(v,s,states,el0,plan,stats,read_table,zero,0,0,0,0,0);}
int sprr_views_prepare_sync_user_compared(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *plan,struct sprr_user_prepare_stats *stats,
    sprr_user_table_reader read_table,struct sprr_user_zero_stats *zero,
    sprr_table_reader source,sprr_table_reader destination,struct sprr_store_compare_stats *compare)
{
    if(!source || !destination || !compare)return 0;
    return prepare_sync_user_grouped(v,s,states,el0,plan,stats,read_table,zero,source,destination,
                                     compare,0,0);
}
int sprr_views_prepare_sync_user_memo(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *plan,struct sprr_user_prepare_stats *stats,
    sprr_user_table_reader read_table,struct sprr_user_zero_stats *zero,
    sprr_table_reader source,sprr_table_reader destination,struct sprr_store_compare_stats *compare,
    struct sprr_table_memo *memo,struct sprr_view_memo *vm)
{
    if(!source || !destination || !compare || !memo || !vm || !zero || !read_table) {
        if(vm)vm->valid=0;
        return 0;
    }
    return prepare_sync_user_grouped(v,s,states,el0,plan,stats,read_table,zero,source,destination,
                                     compare,memo,vm);
}
int sprr_views_prepare_sync_user_mapped(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *plan,struct sprr_user_prepare_stats *stats,
    sprr_user_table_reader read_table)
{return sprr_views_prepare_sync_user_grouped(v,s,states,el0,plan,stats,read_table,0);}
int sprr_views_prepare_sync_user_fused(struct sprr_views *v,const struct shadow *s,
    const struct sprr_state states[SPRR_VIEW_CPUS],const int el0[SPRR_VIEW_CPUS],
    struct sprr_user_prepare_plan *plan,struct sprr_user_prepare_stats *stats)
{return sprr_views_prepare_sync_user_mapped(v,s,states,el0,plan,stats,0);}
static int sync_user_cached_mapped(struct sprr_views *v,const struct shadow *s,unsigned cpu,
    const struct sprr_state *state,int el0,uint64_t *epoch,struct sprr_view_proof *proof,
    struct sprr_view_proof_stats *stats,int verify,sprr_table_reader read_table,
    sprr_table_reader read_copy,struct sprr_store_compare_stats *compare,
    struct sprr_table_memo *memo,struct sprr_view_memo *vm)
{
    if(!proof) {if(vm)vm->valid=0;return 0;}
    if(!configured(v,s) || cpu>=SPRR_VIEW_CPUS || !sprr_fixed_state_valid(state) ||
       (el0!=0 && el0!=1) || !epoch || !stats || (verify!=0 && verify!=1)) {
        proof->valid=0;if(vm)vm->valid=0;return 0;
    }
    int hit=proof->valid==1 && proof->root==s->root && proof->count==v->count &&
            proof->epoch==*epoch && *epoch!=UINT64_MAX;
    proof->valid=0;
    sprr_count(&stats->calls);
    int check=0,sample=memo ? memo_begin(memo) : 0;
    if(hit) {check=verify && !(stats->hits&63);sprr_count(&stats->hits);}
    if(!hit || check) {
        uint64_t path[4],tables=0;
        if(check)sprr_count(&stats->verified);
        /* A proof miss may replay current level3 summaries (memo); the
         * sampled verification of a proof hit is always an independent,
         * claim-free word walk. */
        if(!user_tree(v,s,s->root,0,0,path,&tables,2,0,0,0,check ? 0 : memo,sample)) {
            if(hit)sprr_count(&stats->mismatches);
            if(vm)vm->valid=0;
            return 0;
        }
    }
    /* Only the common structural proof is reused. Control/descriptor
     * preflight and permission translation remain per CPU on every call,
     * except for private tables whose memo claim (when enabled) proves them
     * current; every SPRR_TABLE_MEMO_SAMPLE-th memo call checks all claims.
     * sync_cpu writes private copies only, so its own epoch increments cannot
     * invalidate the canonical-coverage result established above. */
    if(!sync_cpu_mapped(v,s,cpu,state->pperm,state,el0,read_table,read_copy,compare,
                        memo,vm,sample))return 0;
    proof->root=s->root;proof->count=v->count;proof->epoch=*epoch;
    proof->valid=*epoch!=UINT64_MAX;
    return 1;
}
int sprr_views_sync_user_cached_mapped(struct sprr_views *v,const struct shadow *s,unsigned cpu,
    const struct sprr_state *state,int el0,uint64_t *epoch,struct sprr_view_proof *proof,
    struct sprr_view_proof_stats *stats,int verify,sprr_table_reader read_table)
{return sync_user_cached_mapped(v,s,cpu,state,el0,epoch,proof,stats,verify,read_table,0,0,0,0);}
int sprr_views_sync_user_cached_compared(struct sprr_views *v,const struct shadow *s,unsigned cpu,
    const struct sprr_state *state,int el0,uint64_t *epoch,struct sprr_view_proof *proof,
    struct sprr_view_proof_stats *stats,int verify,sprr_table_reader source,
    sprr_table_reader destination,struct sprr_store_compare_stats *compare)
{
    if(!source || !destination || !compare) {if(proof)proof->valid=0;return 0;}
    return sync_user_cached_mapped(v,s,cpu,state,el0,epoch,proof,stats,verify,source,destination,
                                   compare,0,0);
}
int sprr_views_sync_user_cached_memo(struct sprr_views *v,const struct shadow *s,unsigned cpu,
    const struct sprr_state *state,int el0,uint64_t *epoch,struct sprr_view_proof *proof,
    struct sprr_view_proof_stats *stats,int verify,sprr_table_reader source,
    sprr_table_reader destination,struct sprr_store_compare_stats *compare,
    struct sprr_table_memo *memo,struct sprr_view_memo *vm)
{
    if(!source || !destination || !compare || !memo || !vm) {
        if(proof)proof->valid=0;
        if(vm)vm->valid=0;
        return 0;
    }
    return sync_user_cached_mapped(v,s,cpu,state,el0,epoch,proof,stats,verify,source,destination,
                                   compare,memo,vm);
}
int sprr_views_sync_user_cached(struct sprr_views *v,const struct shadow *s,unsigned cpu,
    const struct sprr_state *state,int el0,uint64_t *epoch,struct sprr_view_proof *proof,
    struct sprr_view_proof_stats *stats,int verify)
{return sprr_views_sync_user_cached_mapped(v,s,cpu,state,el0,epoch,proof,stats,verify,0);}
