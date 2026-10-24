/* SPDX-License-Identifier: MIT */
#pragma once
#include "sprr-view.h"
#include "sprr-reuse.h"
#include "sprr-publish.h"

/* Kernel PPERM variants (docs/KERNEL-PPERM-VARIANTS-20261016.md). Per CPU, a
 * second private copy column that is never linked into the views. A flip of
 * SPRR_KERNEL_VIEW_PPERM exchanges the CPU's whole column, so each set stays
 * self-linked (entry_decode links a copied child through the same column), and
 * the caller installs the new root. The caller owns the service lock,
 * publication, the TTBR1 write and the invalidation. */
struct sprr_view_variants {
    uint64_t copy[SPRR_VIEW_TABLES][SPRR_VIEW_CPUS];
    uint64_t source[SPRR_VIEW_TABLES][SPRR_VIEW_CPUS];
    uint64_t count[SPRR_VIEW_CPUS],pperm[SPRR_VIEW_CPUS],saves[SPRR_VIEW_CPUS];
    uint64_t swaps,exact,synced,reserved,verified,mismatches,fallbacks,errors;
};
static inline int sprr_variants_shape(const struct sprr_views *v,unsigned cpu)
{return cpu<SPRR_VIEW_CPUS && v->count && v->count<=SPRR_VIEW_TABLES;}
static inline int sprr_variants_aliases(const struct sprr_view_variants *a,
                                        const struct sprr_views *v,uint64_t pa)
{
    for(unsigned n=0;n<v->count;n++) {
        if(v->tables[n].source==pa)return 1;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(v->tables[n].copy[cpu]==pa)return 1;
    }
    for(unsigned n=0;n<SPRR_VIEW_TABLES;n++)for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if(a->copy[n][cpu]==pa)return 1;
    return 0;
}
/* Allocate this CPU's missing variant pages. alloc must return fresh, zeroed
 * pages whose zeroing the table walker already sees. Pages are kept on
 * failure; a refused page is never recorded. */
static inline int sprr_variants_reserve(struct sprr_view_variants *a,const struct sprr_views *v,
                                        const struct shadow *s,unsigned cpu)
{
    if(!sprr_variants_shape(v,cpu) || !s->alloc) {a->errors++;return 0;}
    for(unsigned n=0;n<v->count;n++) {
        if(a->copy[n][cpu])continue;
        uint64_t pa=shadow_alloc_page(s);
        if(!pa || (pa&4095) || sprr_variants_aliases(a,v,pa)) {a->errors++;return 0;}
        a->copy[n][cpu]=pa;a->reserved++;
    }
    return 1;
}
/* 1 iff this CPU's variant column equals the translation of the current
 * canonical words under pperm. Legal only when sprr_reuse_current() held at
 * the start of the transaction: then an unchanged r->saves since the swap-out
 * means no canonical kernel word changed (every change re-saves before the
 * next PPERM transaction), and a kernel copy decodes only
 * SPRR_KERNEL_VIEW_PPERM. A column never swapped out has saves 0. */
static inline int sprr_variants_exact(const struct sprr_view_variants *a,const struct sprr_views *v,
    const struct sprr_reuse_state *r,unsigned cpu,uint64_t pperm)
{
    if(!sprr_variants_shape(v,cpu) || a->count[cpu]!=v->count || !a->saves[cpu] ||
       a->saves[cpu]!=r->saves || ((a->pperm[cpu]^pperm)&SPRR_KERNEL_VIEW_PPERM) ||
       (pperm&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;
    for(unsigned n=0;n<v->count;n++)
        if(!a->copy[n][cpu] || a->source[n][cpu]!=v->tables[n].source)return 0;
    return 1;
}
/* Exchange this CPU's column with its reserved variant column. The outgoing
 * column becomes the variant for `before` at snapshot generation `saves`:
 * legal only when it equals that translation (the snapshot was current at the
 * start of this transaction) and is fully published (an empty pending row,
 * which also keeps every pending bit naming the page it was set for). */
static inline int sprr_variants_swap(struct sprr_view_variants *a,struct sprr_views *v,
    const struct sprr_publish_state *p,unsigned cpu,uint64_t before,uint64_t saves)
{
    if(!sprr_variants_shape(v,cpu) || !saves || p->root!=v->canonical_root ||
       p->count!=v->count || !sprr_publish_row_empty(p,cpu) ||
       (before&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL) {a->errors++;return 0;}
    for(unsigned n=0;n<v->count;n++)
        if(!a->copy[n][cpu] || (a->copy[n][cpu]&4095)) {a->errors++;return 0;}
    for(unsigned n=0;n<v->count;n++) {
        uint64_t out=v->tables[n].copy[cpu];
        v->tables[n].copy[cpu]=a->copy[n][cpu];a->copy[n][cpu]=out;
        a->source[n][cpu]=v->tables[n].source;
    }
    a->count[cpu]=v->count;a->pperm[cpu]=before;a->saves[cpu]=saves;a->swaps++;
    return 1;
}
/* sprr_reuse_repin after a swap: the snapshot names this CPU's new column.
 * Legal only when sprr_reuse_current() held at the start of the transaction,
 * no canonical word or other column changed, and the new column now equals
 * its translation under pperm (an exact swap, or a swap then a full sync). */
static inline int sprr_variants_repin(struct sprr_reuse_state *r,const struct sprr_views *v,
                                      unsigned cpu,uint64_t pperm)
{
    if(!sprr_variants_shape(v,cpu) || r->count!=v->count || r->root!=v->canonical_root ||
       (pperm&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;
    for(unsigned n=0;n<v->count;n++)
        if(r->tables[n].source!=v->tables[n].source || r->tables[n].level!=v->tables[n].level)
            return 0;
    for(unsigned n=0;n<v->count;n++)r->tables[n].copy[cpu]=v->tables[n].copy[cpu];
    return sprr_reuse_repin(r,v,cpu,pperm);
}
