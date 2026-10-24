/* SPDX-License-Identifier: MIT */
/* compat/adreno-coherent-skip.h - IO-coherent CB0 leaves (-DADRENO_COHERENT_SKIP_MAINT=1, AdrenoMemoryMap.cpp and
 * tools/test-adreno-coherent-kext.c): when the kext may leave out a map's CPU cache maintenance.
 *
 * Why: with IO-coherent CB0 leaves (the monitor's boot self-test proved that GPU accesses snoop the CPU's caches,
 * compat/adreno-guest.h ADRENO_GUEST_COHERENT), memory the CPU maps write-back needs no DC CIVAC before a GPU read
 * and no DC IVAC after a GPU write. The CPU's attribute is the monitor's to know (it mediates every SPTM SH/AttrIndx
 * change), so a map is skipped only after the monitor found every frame of it write-back, and only at the attribute
 * epoch it found that at:
 *   PLAIN    today's ADRENO_GUEST_CACHE: no ON answer (self-test failed, older monitor, boot-arg absent, or a
 *            debug monitor's forced ON without the kext's own adreno_coherent_force=1), or a
 *            backing whose declared cache mode is not write-back (an IOSurface in inhibit, write-through,
 *            write-combine or another mode: kept even after AdrenoDisplay converts a framebuffer to write-back);
 *   CALL     ADRENO_GUEST_CACHE with ADRENO_CACHE_COHERENT: the monitor maintains only the frames the CPU does not
 *            map write-back and says how many bytes that was (x2); a whole-map pass with 0 makes the verdict;
 *   SKIP     the verdict holds at the current epoch: no call, validation only.
 * Header-only so the host model runs exactly these rules. */
#pragma once
#include <stdint.h>
#include "adreno-guest.h"
#ifndef ADRENO_COHERENT_SKIP_MAINT
#define ADRENO_COHERENT_SKIP_MAINT 0
#endif
#if ADRENO_COHERENT_SKIP_MAINT

/* The monitor's answer as the kext last read it (AdrenoMemoryMap::coherentRefresh, start of every kernel command,
 * under the submission lock). on: QUERY answered ABI 1 and state ON with a nonzero epoch, and, when the detail says
 * the ON was forced (ADRENO_COHERENT_DETAIL_FORCED: no self-test ran), the kext was told to accept that. */
struct adreno_coherent_gate { uint64_t asked, on, epoch, answer, forced; };
enum { ADRENO_COHERENT_PLAIN = 0, ADRENO_COHERENT_CALL = 1, ADRENO_COHERENT_SKIP = 2 };

static inline void adreno_coherent_gate_reply(struct adreno_coherent_gate *g, uint64_t x0, uint64_t x1, uint64_t x2,
                                              int accept_forced)
{
    g->asked = 1;
    g->answer = x0 ? 0 : x1;
    g->forced = !x0 && ((x1 >> 16) & ADRENO_COHERENT_DETAIL_FORCED);
    g->on = !x0 && (x1 & 0xff) == ADRENO_COHERENT_ABI && ((x1 >> 8) & 0xff) == ADRENO_COHERENT_STATE_ON && x2 &&
            (!g->forced || accept_forced);
    g->epoch = g->on ? x2 : 0;
}
/* declared_wb: the backing is not an IOSurface, or an IOSurface whose getCacheMode() is default or copyback.
 * verdict: the epoch at which the monitor found every frame write-back, 0 for none. */
static inline unsigned adreno_coherent_choose(const struct adreno_coherent_gate *g, int declared_wb, uint64_t verdict)
{
    if (!g->on || !declared_wb) return ADRENO_COHERENT_PLAIN;
    return verdict && verdict == g->epoch ? ADRENO_COHERENT_SKIP : ADRENO_COHERENT_CALL;
}
/* x3 of a maintenance call, and whether its reply is a success: a coherent call may report up to `bytes` still
 * maintained in x2; a plain one reports 0 there. */
static inline uint64_t adreno_coherent_direction(unsigned how, unsigned direction)
{
    return how == ADRENO_COHERENT_CALL ? (uint64_t)direction | ADRENO_CACHE_COHERENT : direction;
}
static inline int adreno_coherent_reply_ok(unsigned how, uint64_t bytes, uint64_t x0, uint64_t x1, uint64_t x2)
{
    return !x0 && x1 == bytes && (how == ADRENO_COHERENT_CALL ? x2 <= bytes : !x2);
}
/* After a whole-map pass of coherent calls: its verdict (a range pass never makes one). */
static inline uint64_t adreno_coherent_verdict(const struct adreno_coherent_gate *g, int result, uint64_t maintained)
{
    return !result && !maintained ? g->epoch : 0;
}
#endif
