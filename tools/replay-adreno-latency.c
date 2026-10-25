/* SPDX-License-Identifier: MIT */
/* Touch-to-photon latency of the presentation path (agents/input-latency FAILURE-MODES.md, written before the code):
 * included by tools/replay-adreno-presentation.c after replay-adreno-beam.c (-DADRENO_BEAM=1). Built without
 * -DADRENO_LATCH it measures the deployed beam path ("before", policy BEAM only). Built with it, the same scenarios run
 * under three policies:
 * - BEAM: slack 0 and the hold off, which must reproduce the build without the define (L5);
 * - LATCH: the late latch;
 * - HOLD: the late latch plus the release hold ("after").
 *
 * The world is replay-adreno-beam.c's: the A16 scanout model (3840 lines, the 2040-line blank first, 59.51 Hz), the
 * production present (AdrenoDisplayPresent.h) with the beam gate (AdrenoDisplayBeam.h), the thread-call timer slop, the
 * copy costs, and the row logs that rebuild every scanned frame. A frame is torn when it is not exactly the image of
 * one swap.
 *
 * New here:
 * - A WindowServer model. Each swap is rendered (R from a distribution) and submitted, and at most two swaps are
 *   outstanding (submitted, not completed): b12v6/b12v8 show a swap pending at 98.5% of the ticks with q = P - R.
 *   Three triggers for the next render:
 *   - SLOT: whenever fewer than two are outstanding;
 *   - EVENT: once per completion;
 *   - TIMER: a free-running 60.000 Hz timer, which skips a tick while two are outstanding (H11).
 * - The IOMFB family's swap queue: one current swap, completions in order.
 * - A frame path that mirrors AdrenoDisplay.cpp step for step: swap_begin_gated (C6), vsyncGated, armFrameTimerGated
 *   or beamArmGated, presentGated, and, with ADRENO_LATCH, holdLatchGated, holdArmReleaseGated and holdReleaseGated.
 * - Latency, rebuilt from the scanned frames. For every swap: its render start, its arrival, and the scan time of row
 *   0 and of row 900 of the first frame that shows it, or shows a newer swap.
 * - Input latency: an input event at a uniform random time is shown by the first swap whose render starts after it,
 *   at mid-screen (row 900).
 * Times are ns. */
#if ADRENO_LATCH
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayLatch.h"
#endif
#if ADRENO_PRESENT_SYNC
#if !ADRENO_LATCH
#error "the present-sync scenarios run on the latch build's policies (-DADRENO_LATCH=1)"
#endif
/* agents/present-sync FAILURE-MODES.md: a WindowServer frame's GPU work against its swap (presentsync_scenarios below) */
#include "../gpu/adreno-kext/kext/src/AdrenoDisplaySync.h"
#endif
#ifndef ADRENO_PIPELINE
#define ADRENO_PIPELINE 0
#endif
#if ADRENO_PIPELINE
#if !ADRENO_PRESENT_SYNC
#error "the pipeline scenarios extend the present-sync ones (-DADRENO_PRESENT_SYNC=1)"
#endif
/* agents/gpu-pipeline FAILURE-MODES.md: the kext's IB pipeline (presentsync_scenarios' P runs, pipeline_scenarios) */
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayPipe.h"
#endif
#ifndef ADRENO_PRESENT_RELATCH
#define ADRENO_PRESENT_RELATCH 0
#endif
#if ADRENO_PRESENT_RELATCH
#if !ADRENO_PIPELINE
#error "the present-pacing scenarios extend the pipeline ones (-DADRENO_PIPELINE=1)"
#endif
/* agents/present-pacing FAILURE-MODES.md: the b12v17 pipeline with its submit lock, and the relatch (relatch_scenarios) */
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayRelatch.h"
#endif
#ifndef ADRENO_PRESENT_EARLY_DONE
#define ADRENO_PRESENT_EARLY_DONE 0
#endif
#if ADRENO_PRESENT_EARLY_DONE
#if !ADRENO_PRESENT_RELATCH
#error "the early-completion scenarios run in the present-pacing world (-DADRENO_PRESENT_RELATCH=1)"
#endif
/* AdrenoDisplayEarlyDone.h: a layer-0 swap completed right after its copy, always or while WindowServer is behind (early_done_scenarios) */
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayEarlyDone.h"
#endif

enum { WS_SLOT = 0, WS_EVENT = 1, WS_TIMER = 2, WS_FREE = 3 };
enum { LP_BEAM = 0, LP_LATCH = 1, LP_HOLD = 2, LP_HOLD_NOGATE = 3 };
#define LMAX 4096u
#define LINF UINT64_MAX
static const char *const ws_name[] = {"slot", "event", "timer", "free"};
static const char *const lp_name[] = {"beam", "latch", "hold", "hold_nogate"};

struct lswap { uint32_t id; uint8_t layers; };
struct lworld {
    struct bworld w;
    int ws_kind, policy;
    /* WindowServer */
    unsigned outstanding, events; int rendering; uint64_t render_done, timer_next; uint32_t next_id, render_id;
    uint64_t r_min, r_max, spike_min, spike_max; unsigned spike_pct;
    uint64_t renders, submits, started_at;
    /* cursor-only swaps (H5): injected at random gaps, never counted against WindowServer's two */
    uint64_t cursor_next, cursor_gap_min, cursor_gap_max; uint32_t cursor_ids; uint64_t cursor_swaps;
    /* the family queue and the frame path */
    struct lswap q[64]; unsigned qn;
    uint32_t cur; uint8_t cur_layers; int presented;
    uint64_t pending_since, queued_at, q_sum, q_n;
    uint64_t copies;
    /* the hold */
#if ADRENO_LATCH
    struct adreno_hold h;
#endif
    uint32_t precopied; int rel_armed; uint64_t rel_at;
    unsigned drop_pct, rel_tail_pct; uint64_t rel_tail_min, rel_tail_max, drops;
    /* b12v11 (G1-G3): a share of WindowServer's frames end their IB after the swap arrives (ib_end), and app IBs keep
     * the GPU busy at random; gpu_busy() is what the kext's submission counter shows; a copy before its swap's IB ended
     * is stale (its pixels not final) */
    unsigned ib_pct, app_busy_pct; uint64_t ib_min, ib_max, app_min, app_max, app_until, app_next;
    uint64_t ib_end[LMAX]; uint64_t stale, gated; uint64_t gate_ns;
    /* checks */
    uint32_t last_completed; uint64_t order_errors, completions; int deadlock;
    uint64_t reset_at; int reset_done;
    /* per swap (index = id) */
    uint64_t rstart[LMAX], arrive[LMAX], row0_ns[LMAX], mid_ns[LMAX], copy_ns[LMAX];
    uint8_t shown[LMAX], copied[LMAX];
    uint32_t shown_upto; uint64_t last_new_t, max_stall;
    uint64_t frames, torn, eval_frame, unknown;
    uint64_t slack_peak;
#if ADRENO_PRESENT_SYNC
    /* present sync: g_pct of WindowServer's frames carry GPU work. At its commit the command buffer reaches the kext uq
     * later, behind the previous frame's (the submission queue submits in order), waits for an app IB holding the submit
     * lock (lock_pct, 0..lock_max), then runs ib (bins). The kext marks the surface from g_enter to ib_end. s_wait: S, its
     * commitAndWaitUntilSubmitted returns only then (bounded 250 ms) and WindowServer swaps after it. k_gate: K. */
    int s_wait, k_gate; unsigned g_pct, lock_pct; uint64_t uq_min, uq_max, lock_max, g_last_end;
    uint64_t g_lo[3], g_hi[3]; unsigned g_w[3];
    uint64_t g_enter[LMAX];
    int ws_gpu_wait; uint32_t stuck_id;
    struct adreno_sync_gate sg;
    uint64_t gpu_frames, s_waits, s_wait_ns, s_bound;
#endif
#if ADRENO_PIPELINE
    /* the pipeline (agents/gpu-pipeline): the kext STARTs a frame's IB once the previous one's final reply is seen
     * (a submitter waiting: IODelay backoff, detection 0..spin_max; nobody waiting: the completion timer, 0..timer_max)
     * plus start_cost; the submission returns at that START (ib_start) and WindowServer swaps then; the marks last
     * until the finish (fin_end), which a waiting submitter does right after its own START */
    int pipe; uint64_t spin_max, timer_max, start_cost, g_last_fin, g_last_ib_end; uint32_t g_last_id;
    uint64_t ib_start[LMAX], fin_end[LMAX];
    uint64_t pipe_overlapped;
    /* WS_FREE (agents/gpu-pipeline): WindowServer renders the next frame as soon as it swapped the last one and waits
     * for a free swap entry only to swap (swap_blocked), not to start rendering. complete_at_copy (what-if): the
     * display completes a layer-0 swap right after its copy instead of at the next tick (early_done). */
    int swap_blocked, complete_at_copy; uint32_t early_done; uint64_t swap_block_ns, render_done_blocked;
#endif
#if ADRENO_PRESENT_RELATCH
    /* agents/present-pacing: the b12v17 pipeline (p2). One submit lock, reserved in time order by every user: a
     * WindowServer submission (TO_DEVICE, then the flight's final reply, START, the older flight's FROM_DEVICE), the
     * completion timer (one POLL a period; a final flight is finished under the lock), app IBs (TO_DEVICE, the flight
     * first, then their own IB synchronously, or as a flight with app_pipe). A finished flight's marks go at the post
     * (after the unlock that ends the critical section that finished it) or, with EP1, at the end of its FROM_DEVICE. */
    int p2;
    uint64_t lock_free;                                   /* the lock is reserved until then */
    int fl_on; uint32_t fl_id; uint64_t fl_end, fl_f;     /* the flight: its frame (0 = an app's), GPU end, FROM_DEVICE */
    uint64_t tmr_at, tmr_period, urgent_period;           /* the completion timer (LINF: not armed); urgent 0 = off */
    uint64_t b_lo, b_hi, f_lo, f_hi;                      /* WindowServer's TO_DEVICE and FROM_DEVICE per IB */
    uint64_t enter_at; uint32_t enter_id;                 /* a WindowServer submission entering the kext (LINF none) */
    uint64_t app_at, app_mean, app_lo[3], app_hi[3], app_b, app_f, app_from; unsigned app_w[3]; int app_pipe;   /* G1: app_until */
    int early; uint64_t assist;                           /* EP1+EP2; EP3's period (0 = off) */
    unsigned multi_pct;                                   /* frames with two command buffers (two IBs) */
    int rl_on, urgent; struct adreno_relatch rl; uint64_t rl_at; uint32_t rl_cand;
    uint64_t c_ovl, c_tmr, c_pre, c_ast, c_app, c_apps, c_polls, c_late_unmark;
    uint64_t ret_at[LMAX];                                /* the submission's return: G1 busy until then, S returns then */
#endif
#if ADRENO_PRESENT_EARLY_DONE
    /* AdrenoDisplay's fEarly: mode = complete_at_copy (1 always, as the pipeline what-if; 2 adaptive), its hold */
    struct adreno_early_done ed; uint64_t ed_hold;
#endif
};

/* ---- WindowServer ---- */
static uint64_t l_render_time(struct lworld *l)
{
    struct bworld *w = &l->w;
    if (l->spike_pct && brnd(w) % 100 < l->spike_pct) return l->spike_min + brnd(w) % (l->spike_max - l->spike_min + 1);
    return l->r_min + brnd(w) % (l->r_max - l->r_min + 1);
}
static void ws_start(struct lworld *l)
{
    if (l->next_id + 1 >= LMAX) return;
    l->rendering = 1; l->render_id = ++l->next_id; l->rstart[l->render_id] = l->w.now;
    l->render_done = l->w.now + l_render_time(l); l->renders++;
}
static void ws_try_render(struct lworld *l)
{
    if (l->rendering || (l->outstanding >= 2 && l->ws_kind != WS_FREE) || l->ws_kind == WS_TIMER) return;
    if (l->ws_kind == WS_EVENT) { if (!l->events) return; l->events--; }
    ws_start(l);
}
static void ws_completed(struct lworld *l, uint32_t id)      /* the family completed (or dropped) WindowServer's swap */
{
    if (id <= l->last_completed) l->order_errors++;           /* H8 */
    l->last_completed = id; l->completions++;
    if (l->outstanding) l->outstanding--;
    if (l->ws_kind == WS_EVENT) l->events++;
#if ADRENO_PIPELINE
    if (l->swap_blocked) { l->swap_blocked = 0; l->swap_block_ns += l->w.now - l->render_done_blocked; l->render_done = l->w.now; }
#endif
    ws_try_render(l);
}

/* ---- the frame path: AdrenoDisplay.cpp ---- */
static void l_swap_begin(struct lworld *l, int in_tick);
static void l_complete(struct lworld *l)                     /* swap_complete_gated */
{
    const uint32_t id = l->cur; const uint8_t layers = l->cur_layers;
    l->cur = 0; l->presented = 0;
#if ADRENO_PIPELINE
    if ((layers & 1) && l->early_done == id) { l->early_done = 0; return; }   /* completed at its copy already */
#endif
    if (layers & 1) ws_completed(l, id);
}
static void l_arm(struct lworld *l)                          /* armFrameTimerGated */
{
    struct bworld *w = &l->w;
    if (w->armed || (!l->cur && !l->qn)) return;
    if (beam_arm(w)) return;
    const uint64_t now = tb(w, w->now);
    const uint64_t at = adreno_vsync_arm_time(&w->v, now, adreno_vsync_target(&w->v, now, w->in_tick));
    w->armed = 1; w->fire_at = bfire(w, w->now, tb_ns(w, at));
}
static int l_gpu_busy(struct lworld *l)                     /* gAdrenoGPUBusy != 0 */
{
    const uint64_t t = l->w.now;
    if (l->app_until > t) return 1;
#if ADRENO_PRESENT_RELATCH
    if (l->p2) {                                              /* G1: WindowServer's and the apps' submissions in the kext */
        if (l->app_from <= t && t < l->app_until) return 1;
        for (uint32_t k = l->next_id; k && k + 8 > l->next_id; k--)
            if (l->g_enter[k] && l->g_enter[k] <= t && (!l->ret_at[k] || t < l->ret_at[k])) return 1;
        return 0;
    }
#endif
#if ADRENO_PIPELINE
    if (l->pipe) {                                            /* D5: submissions inside the kext (entry to return) */
        for (uint32_t k = l->next_id; k && k + 8 > l->next_id; k--) if (l->g_enter[k] && l->g_enter[k] <= t && t < l->ib_start[k]) return 1;
        return 0;
    }
#endif
    for (uint32_t k = l->next_id; k && k + 8 > l->next_id; k--) if (l->ib_end[k] > t && l->arrive[k] && l->arrive[k] < t + 2 * MS) return 1;
    return 0;
}
/* copyGatedGated: a layer-0 head first seen less than the gate window ago waits a latch while the GPU has work */
static int l_gate(struct lworld *l)
{
    if (!l->gate_ns || l->w.b.state != ADRENO_BEAM_LOCKED || !l->qn || !(l->q[0].layers & 1) || !l->pending_since) return 0;
    if (!l_gpu_busy(l)) return 0;
    return l->w.now - l->pending_since < l->gate_ns;
}
#if ADRENO_PRESENT_SYNC
/* syncWaitGated (K1 K2 K11): the head's surface is marked while its write is in the kext (entered, not ended). The head
 * is named by its swap ID (as pointer plus +0x3d4 in the kext). */
static int l_sync_wait(struct lworld *l)
{
    if (!l->k_gate || !l->qn || !(l->q[0].layers & 1) || l->q[0].id >= LMAX) return 0;
    const uint32_t id = l->q[0].id; const uint64_t t = l->w.now;
#if ADRENO_PIPELINE
    const uint64_t marked_until = l->pipe ? l->fin_end[id] : l->ib_end[id];   /* D1: marked to the flight's finish */
#else
    const uint64_t marked_until = l->ib_end[id];
#endif
    const uint32_t writers = l->g_enter[id] && t >= l->g_enter[id] && t < marked_until;
#if ADRENO_PRESENT_RELATCH
    const int wait = adreno_sync_decide(&l->sg, (const void *)(uintptr_t)(id + 1u), id, writers, l->g_enter[id], t) == ADRENO_SYNC_WAIT;
    if (wait && l->w.in_tick) l->rl_cand = id;               /* RL4: the head this tick deferred (syncWaitGated) */
    return wait;
#else
    return adreno_sync_decide(&l->sg, (const void *)(uintptr_t)(id + 1u), id, writers, l->g_enter[id], t) == ADRENO_SYNC_WAIT;
#endif
}
/* WindowServer commits frame id: its GPU work, if it has any (g_enter, ib_end; 0 when none) */
static void l_gpu_commit(struct lworld *l, uint32_t id)
{
    struct bworld *w = &l->w;
    l->g_enter[id] = 0; l->ib_end[id] = 0;
    if (brnd(w) % 100 >= l->g_pct) return;
    uint64_t enter = w->now + l->uq_min + brnd(w) % (l->uq_max - l->uq_min + 1);
    if (enter < l->g_last_end) enter = l->g_last_end;
    uint64_t start = enter;
    if (l->lock_pct && brnd(w) % 100 < l->lock_pct) start += brnd(w) % (l->lock_max + 1);
    const unsigned r = (unsigned)(brnd(w) % 100);
    const unsigned b = r < l->g_w[0] ? 0 : r < l->g_w[0] + l->g_w[1] ? 1 : 2;
    l->g_enter[id] = enter;
    const uint64_t gpu = id == l->stuck_id ? 400 * MS : l->g_lo[b] + brnd(w) % (l->g_hi[b] - l->g_lo[b] + 1);
#if ADRENO_PIPELINE
    if (l->pipe) {
        /* the IB STARTs when the previous flight's final reply is seen: a waiting submitter (this one) polls with
         * backoff; the flight is finished (marks released) right after this START. A flight nobody waited for was
         * finished by the timer. */
        uint64_t at = start;                                  /* in the kext, the lock held (stage, clean) */
        if (l->g_last_ib_end > at) {
            const uint64_t seen = l->g_last_ib_end + brnd(w) % (l->spin_max + 1);
            at = seen;
            l->pipe_overlapped++;
            if (l->g_last_id && l->fin_end[l->g_last_id] > seen + l->start_cost) l->fin_end[l->g_last_id] = seen + l->start_cost;
        } else if (l->g_last_fin > at) {
            at = l->g_last_fin;                               /* the timer is finishing it under the lock */
        }
        at += l->start_cost;
        l->ib_start[id] = at;
        l->ib_end[id] = at + gpu;
        l->fin_end[id] = l->ib_end[id] + brnd(w) % (l->timer_max + 1);   /* the timer, unless a submitter comes first */
        l->g_last_ib_end = l->ib_end[id]; l->g_last_fin = l->fin_end[id]; l->g_last_id = id;
        l->g_last_end = l->ib_start[id];                      /* the submission queue's next syscall: after this return */
        l->gpu_frames++;
        return;
    }
#endif
    /* K2: the stuck write runs 400 ms (an IB at its timeout); every later one queues behind it */
    l->ib_end[id] = start + gpu;
    l->g_last_end = l->ib_end[id];
    l->gpu_frames++;
}
#endif
static void l_copy(struct lworld *l, uint32_t id)            /* presentGated's layer-0 copy (present_swap's body) */
{
    struct bworld *w = &l->w;
    if (id < LMAX && l->ib_end[id] > w->now) l->stale++;
#if ADRENO_PRESENT_RELATCH
    if (l->p2 && id < LMAX && l->g_enter[id] && w->now < l->fin_end[id]) l->c_late_unmark++;   /* RL2: copied while marked */
#endif
    produce(w, id);
    struct adreno_display_cursor c; memset(&c, 0, sizeof c);
    struct adreno_display_scanout d = {w->dst, (uint64_t)BH * BROW, BROW, BW, BH};
    struct adreno_display_surface s = {w->src, (uint64_t)BH * BROW, 0, BROW, BW, BH, ADRENO_DISPLAY_FORMAT_BGRA};
    const int beam = w->b.state == ADRENO_BEAM_LOCKED;
    if (beam) adreno_beam_begin(&w->b, 0, 0, BH);
    struct adreno_display_present_ops ops = {b_maintain, b_barrier, b_clock, w, b_observe, w, beam ? b_gate : NULL, w};
    struct adreno_display_present_result r;
    w->stall_chunk = -1;
    if (w->stall_pct && brnd(w) % 100 < w->stall_pct) {
        w->stall_chunk = (int)(brnd(w) % 113);
        w->stall_ns = w->stall_min + brnd(w) % (w->stall_max - w->stall_min + 1);
    }
    w->clocks = 0; w->clock_base = 3; w->first_row = 0;
    if (!w->first_present_t) w->first_present_t = w->now;
    if (id < LMAX) { if (!l->copied[id]) l->copy_ns[id] = w->now; l->copied[id] = 1; }
    if (l->queued_at && w->now >= l->queued_at) { l->q_sum += w->now - l->queued_at; l->q_n++; }
    l->queued_at = 0;
    const uint64_t started = tb(w, w->now);
    const int error = adreno_display_present(&c, &d, &s, &w->ws, &ops, &r);
    CHECK(error == 0);
    if (beam) {
        w->b.maint = w->b.maint - w->b.maint / 8 + (r.maint_ticks + r.barrier_ticks) / 8;
        adreno_beam_copied(&w->b, tb(w, w->now) - started);
        adreno_beam_end(&w->b);
    }
#if ADRENO_LATCH
    if (w->b.slack > l->slack_peak) l->slack_peak = w->b.slack;
#endif
    w->presents++; l->copies++;
    w->last_present_t = w->now;
}
static void l_present(struct lworld *l, uint32_t id, uint8_t layers)   /* presentGated (not a precopy) */
{
    l->presented = 1;
    if (layers & 1) l_copy(l, id);
#if ADRENO_PIPELINE
#if ADRENO_PRESENT_EARLY_DONE
    /* earlyDoneNowGated by mode (1 is also gpu-pipeline's what-if, whose hold rows keep it: the kext refuses the hold
     * with early completion, the early-completion scenarios never run the hold) */
    if ((layers & 1) && l->complete_at_copy && adreno_early_active(&l->ed, l->w.now)) {
        l->early_done = id; adreno_early_completed(&l->ed); ws_completed(l, id);
    }
#else
    if ((layers & 1) && l->complete_at_copy) { l->early_done = id; ws_completed(l, id); }   /* what-if */
#endif
#endif
}
static void l_pop(struct lworld *l) { memmove(l->q, l->q + 1, (l->qn - 1) * sizeof l->q[0]); l->qn--; }
static void l_swap_begin(struct lworld *l, int in_tick)       /* swap_begin_gated */
{
    struct bworld *w = &l->w;
#if ADRENO_PRESENT_EARLY_DONE
    if (!in_tick && l->qn && !l->pending_since && (l->q[0].layers & 1))
        adreno_early_arrival(&l->ed, w->now, l->qn == 1);                            /* swap_begin_gated, F1's read */
#endif
    if (!in_tick && l->qn && !l->pending_since) l->pending_since = w->now;          /* F1 */
#if ADRENO_LATCH
    if (!in_tick && l->pending_since && l->h.released_at) adreno_hold_arrival(&l->h, tb(w, l->pending_since));
#endif
    if (!in_tick && !l->cur && w->b.state == ADRENO_BEAM_LOCKED && l->qn && (l->q[0].layers & 1)) {
        l_arm(l); return;                                                            /* C6 */
    }
    while (!l->cur && l->qn) {
#if ADRENO_PRESENT_SYNC
        if (l_sync_wait(l)) break;                                                   /* K1: stays queued */
#endif
        const struct lswap s = l->q[0];
        l_pop(l);
        l->cur = s.id; l->cur_layers = s.layers;
        l_arm(l);
        l->queued_at = l->pending_since; l->pending_since = 0;
        if (s.id == l->precopied) l->precopied = 0;                                 /* H4 */
        l_present(l, s.id, s.layers);
        if (!(s.layers & 1)) { l->presented = 0; l_complete(l); continue; }          /* cursor-only: at once (PV) */
        break;
    }
    l_arm(l);
}
#if ADRENO_LATCH
static void l_hold_release(struct lworld *l);
static void l_hold_arm_release(struct lworld *l)             /* holdArmReleaseGated */
{
    struct bworld *w = &l->w;
    if (!l->h.enabled || !l->cur || !l->presented) return;
    l->rel_armed = 0;
    if (!w->armed || w->b.state != ADRENO_BEAM_LOCKED || !w->b.armed_fire || !w->b.frame) return;
    const uint64_t now = tb(w, w->now);
    const uint64_t at = adreno_hold_release_time(&l->h, now, w->b.armed_fire, w->b.frame);
    if (at <= now) { l_hold_release(l); return; }
    uint64_t lead = (at - now) / 9;
    if (lead > w->v.lead_max) lead = w->v.lead_max;
    uint64_t fire = bfire(w, w->now, tb_ns(w, at - lead));
    if (l->rel_tail_pct && brnd(w) % 100 < l->rel_tail_pct)
        fire += l->rel_tail_min + brnd(w) % (l->rel_tail_max - l->rel_tail_min + 1);
    l->rel_armed = 1; l->rel_at = fire;
}
static void l_hold_release(struct lworld *l)                 /* holdReleaseGated */
{
    struct bworld *w = &l->w;
    l->rel_armed = 0;
    if (!l->cur || !l->presented) return;
    const int precopied = l->qn && l->precopied && l->q[0].id == l->precopied;
    if (l->qn && !precopied) { l->h.rel_deferred++; return; }                       /* H3 */
    l_complete(l);
    if (precopied) {
        l->h.rel_successor++;
        if (l->drop_pct && brnd(w) % 100 < l->drop_pct) {                            /* H4: the family drops it */
            const uint32_t id = l->q[0].id;
            l_pop(l); l->drops++; ws_completed(l, id);
        } else if (l->qn && l->q[0].id == l->precopied) {
            l->cur = l->q[0].id; l->cur_layers = l->q[0].layers; l_pop(l); l->presented = 1;
        }
        l->precopied = 0;
    } else {
        l->h.rel_lone++;
    }
    if (!l->qn) adreno_hold_released(&l->h, tb(w, w->now));
    if (!l->cur && l->qn) l_arm(l);
}
static int l_hold_latch(struct lworld *l)                    /* holdLatchGated */
{
    struct bworld *w = &l->w;
    if (!l->h.enabled || w->b.state != ADRENO_BEAM_LOCKED || !w->b.go_row0) return 0;
    if (l->rel_armed) { l->rel_armed = 0; l->h.rel_overdue++; l_hold_release(l); }
    if (!l->cur || !l->presented) return 0;
    if (l->qn && (!(l->q[0].layers & 1) || l->q[0].id == l->precopied)) { l->h.fallbacks++; return 0; }
#if ADRENO_PRESENT_SYNC
    if (!l->qn || l_gate(l) || l_sync_wait(l)) {                                      /* K8 */
#else
    if (!l->qn || l_gate(l)) {
#endif
        if (l->qn) l->gated++;
        else adreno_hold_missed(&l->h, tb(w, w->now));
        w->b.go_row0 = 0; l_arm(l); l_hold_arm_release(l);
        return 1;
    }
    l->queued_at = l->pending_since; l->pending_since = 0;
    l_arm(l);
    const uint32_t id = l->q[0].id;
    l_copy(l, id);
    l->precopied = id; l->h.precopies++;
    w->b.go_row0 = 0;
    l_hold_arm_release(l);
    return 1;
}
#endif
#if ADRENO_PRESENT_RELATCH
static void p2_relatch_end(struct lworld *l, int tick);
static void p2_relatch_arm(struct lworld *l);
static void p2_relatch_poll(struct lworld *l);
static void p2_ws_enter(struct lworld *l);
static void p2_timer(struct lworld *l);
static void p2_app(struct lworld *l);
#endif
static void l_tick(struct lworld *l)                         /* vsyncGated */
{
    struct bworld *w = &l->w;
    w->armed = 0; w->fires++;
    if (w->last_fire && w->now - w->last_fire < w->min_gap) w->min_gap = w->now - w->last_fire;
    w->last_fire = w->now;
    adreno_vsync_fired(&w->v, tb(w, w->now));
    if (w->b.state == ADRENO_BEAM_LOCKED && (w->b.target || w->b.armed_fire)) {
        uint64_t now = 0;
        const uint64_t pos = adreno_beam_sample(&w->b, bio(w), &now);
        const int r = adreno_beam_fire(&w->b, now, pos);
        if (r == ADRENO_BEAM_EARLY || r == ADRENO_BEAM_LATE) { l_arm(l); return; }
    }
#if ADRENO_PRESENT_RELATCH
    if (l->p2) { p2_relatch_end(l, 1); l->rl_cand = 0; }     /* RL3 RL4: a tick that proceeds */
#endif
#if ADRENO_LATCH
    w->in_tick = 1;
    const int held = l_hold_latch(l);
    w->in_tick = 0;
    if (!held) {
        if (l->rel_armed && l->cur && l->presented) l->rel_armed = 0;
#endif
#if ADRENO_PRESENT_EARLY_DONE
    const int ed_had = l->cur && l->presented && (l->cur_layers & 1);   /* completed here, or held since its copy */
    const uint64_t ed_copies = l->copies;
#endif
    if (l->cur && l->presented) l_complete(l);
    w->in_tick = 1;
    if (l_gate(l)) { l->gated++; l_arm(l); } else l_swap_begin(l, 1);
#if ADRENO_PRESENT_RELATCH
    if (l->p2) p2_relatch_arm(l);                            /* RL4: the GO's frame unused and its head deferred */
#endif
#if ADRENO_PRESENT_EARLY_DONE
    adreno_early_tick(&l->ed, w->now, ed_had, l->copies != ed_copies || (l->qn && (l->q[0].layers & 1)));
#endif
    w->b.go_row0 = 0; w->in_tick = 0;
#if ADRENO_LATCH
        if (l->h.enabled && l->cur && l->presented && w->b.state == ADRENO_BEAM_LOCKED) {
            l->h.fallbacks++;
            l_hold_arm_release(l);
        }
    }
#endif
}

/* ---- the scanned frames: which swap each shows, and when ---- */
static void l_evaluate(struct lworld *l)
{
    struct bworld *w = &l->w;
    const struct scan *s = &w->s;
    for (;;) {
        const uint64_t f = l->eval_frame, row0 = f * s->vt + s->a0;
        const uint64_t last = scan_time(s, row0 + BH - 1 - (row0 + BH - 1 >= s->fetch_lead ? s->fetch_lead : 0));
        if (last >= w->now) return;
        static uint32_t vis[BH]; uint32_t p = 0; int ok = 1;
        for (uint64_t y = 0; y < BH; y++) {
            const uint64_t pos = row0 + y >= s->fetch_lead ? row0 + y - s->fetch_lead : 0;
            if (!visible_at(w, y, scan_time(s, pos), &vis[y])) { ok = 0; break; }
            if (vis[y] > p) p = vis[y];
        }
        l->eval_frame++;
        if (!ok) { l->unknown++; continue; }
        /* (no upper bound at the last present, unlike evaluate_frames: a late latch copies after the previous frame
         * ended, so that bound would drop every frame scanned between two latches) */
        if (!w->first_present_t || scan_time(s, row0) < w->first_present_t) continue;
        int consistent = 1;
        for (uint64_t y = 0; y < BH && consistent; y++) {
            uint32_t want;
            if (version_of(w, y, p, &want) && want != vis[y]) consistent = 0;
        }
        l->frames++;
        if (!consistent) l->torn++;
        uint32_t q = p;
        for (; q > l->shown_upto; q--) {
            int all = 1;
            for (uint64_t y = 0; y < BH && all; y++) { uint32_t want; if (version_of(w, y, q, &want) && vis[y] < want) all = 0; }
            if (all) break;
        }
        if (q > l->shown_upto) {
            const uint64_t t0 = scan_time(s, row0), tm = scan_time(s, row0 + BH / 2);
            for (uint32_t k = l->shown_upto + 1; k <= q && k < LMAX; k++) { l->shown[k] = 1; l->row0_ns[k] = t0; l->mid_ns[k] = tm; }
            if (l->last_new_t && t0 - l->last_new_t > l->max_stall) l->max_stall = t0 - l->last_new_t;
            l->last_new_t = t0;
            l->shown_upto = q;
        }
    }
}

/* ---- the run ---- */
static void l_init(struct lworld *l, int policy, int ws_kind, double hz, uint32_t vt, uint64_t seed)
{
    struct bworld *w = &l->w;
    bworld_init(w, BEAM, hz, seed);
    if (vt == 3840) { scan_init(&w->s, hz, 3840); w->s.regs = a16_regs(); w->s.base = 1; }
    else scan_init(&w->s, hz, vt);
    /* everything after the bworld */
    memset((char *)l + sizeof l->w, 0, sizeof *l - sizeof l->w);
    l->policy = policy; l->ws_kind = ws_kind;
    l->r_min = 2000 * US; l->r_max = 3600 * US;                 /* quiet: b12v6/b12v8 R = P - q = 2.8 ms */
}
static void l_start(struct lworld *l)
{
    struct bworld *w = &l->w;
    bworld_start(w);
    w->swaps = LMAX;
#if ADRENO_LATCH
    /* the shipped default since b12v11 is LATCH: the late latch with the copy gate, the hold off */
    const uint64_t ms = tb_ms(w);
    adreno_beam_latch(&w->b, l->policy == LP_BEAM ? 0 : 3 * ms);
    adreno_hold_init(&l->h, l->policy == LP_HOLD || l->policy == LP_HOLD_NOGATE, ms * 3 / 2, ms * ADRENO_HOLD_FLOOR_US / 1000);
    l->gate_ns = l->policy == LP_LATCH || l->policy == LP_HOLD ? 4 * MS : 0;
#endif
#if ADRENO_PRESENT_EARLY_DONE
    adreno_early_init(&l->ed, (uint32_t)l->complete_at_copy, 16666667, l->ed_hold ? l->ed_hold : 2000 * MS, MS);
#endif
    l->started_at = w->now;
    if (l->ws_kind == WS_EVENT) l->events = 1;
    if (l->ws_kind == WS_TIMER) l->timer_next = w->now; else ws_try_render(l);
}
static void l_run(struct lworld *l, unsigned swaps)
{
    struct bworld *w = &l->w;
    while (l->next_id < swaps) {
        const uint64_t t_tick = w->armed ? w->fire_at : LINF;
        const uint64_t t_rel = l->rel_armed ? l->rel_at : LINF;
        const uint64_t t_ws = l->rendering ? l->render_done : LINF;
        const uint64_t t_wst = l->ws_kind == WS_TIMER ? l->timer_next : LINF;
        const uint64_t t_cur = l->cursor_next ? l->cursor_next : LINF;
        uint64_t t = t_tick;
        if (t_rel < t) t = t_rel;
        if (t_ws < t) t = t_ws;
        if (t_wst < t) t = t_wst;
        if (t_cur < t) t = t_cur;
#if ADRENO_PRESENT_RELATCH
        const uint64_t t_ent = l->p2 ? l->enter_at : LINF, t_tmr = l->p2 ? l->tmr_at : LINF;
        const uint64_t t_app = l->p2 && l->app_mean ? l->app_at : LINF, t_rl = l->p2 ? l->rl_at : LINF;
        if (t_ent < t) t = t_ent;
        if (t_tmr < t) t = t_tmr;
        if (t_app < t) t = t_app;
        if (t_rl < t) t = t_rl;
#endif
        if (t == LINF) { l->deadlock = 1; return; }                                   /* H2 */
        if (t > w->now) w->now = t;
        l_evaluate(l);
        while (l->app_busy_pct && l->app_next <= w->now) {         /* app IBs: busy app_min..app_max, app_busy_pct of the time */
            const uint64_t d = l->app_min + brnd(w) % (l->app_max - l->app_min + 1);
            l->app_until = l->app_next + d;
            l->app_next += d * 100 / l->app_busy_pct;
        }
        if (l->reset_at && !l->reset_done && w->now >= l->reset_at) {                /* H7: stop and start */
            l->reset_done = 1; adreno_vsync_reset(&w->v); adreno_beam_reset(&w->b); w->armed = 0;
            l->rel_armed = 0; l->precopied = 0;
#if ADRENO_LATCH
            l->h.released_at = 0;
#endif
            l_arm(l);
            continue;
        }
        if (t == t_tick) l_tick(l);
#if ADRENO_LATCH
        else if (t == t_rel) l_hold_release(l);
#endif
        else if (t == t_ws) {                                    /* WindowServer submits */
#if ADRENO_PRESENT_RELATCH
            if (l->p2 && !l->ws_gpu_wait) {                      /* the commit; S waits for the kernel submission */
                if (brnd(w) % 100 < l->g_pct) {
                    l->enter_id = l->render_id; l->enter_at = w->now + l->uq_min + brnd(w) % (l->uq_max - l->uq_min + 1);
                    l->g_enter[l->render_id] = l->enter_at;       /* AdrenoSurfaceWrites marks before the lock wait */
                    l->ws_gpu_wait = 1; l->render_done = LINF; l->s_waits++;
                    continue;
                }
            } else if (l->p2) {
                l->ws_gpu_wait = 0;                              /* returned: swap now */
            } else
#endif
#if ADRENO_PRESENT_SYNC
            if (l->g_pct && !l->ws_gpu_wait) {                   /* flush(true): the frame's command buffer commits */
                l_gpu_commit(l, l->render_id);
#if ADRENO_PIPELINE
                const uint64_t returns = l->pipe ? l->ib_start[l->render_id] : l->ib_end[l->render_id];
#else
                const uint64_t returns = l->ib_end[l->render_id];
#endif
                if (l->s_wait && returns > w->now) {          /* S: the wait returns when the kernel submission does */
                    uint64_t until = returns;
                    if (until > w->now + 250 * MS) { until = w->now + 250 * MS; l->s_bound++; }
                    l->s_waits++; l->s_wait_ns += until - w->now;
                    l->ws_gpu_wait = 1; l->render_done = until;
                    continue;
                }
            }
            l->ws_gpu_wait = 0;
#endif
#if ADRENO_PIPELINE
            if (l->ws_kind == WS_FREE && l->outstanding >= 2) {   /* swap_wait on a full ring; the GPU work is in */
                l->swap_blocked = 1; l->render_done_blocked = w->now; l->render_done = LINF; l->ws_gpu_wait = 1;
                continue;
            }
#endif
            l->rendering = 0; l->outstanding++; l->submits++;
            if (l->qn < 64) { l->q[l->qn++] = (struct lswap){l->render_id, 1}; }
            l->arrive[l->render_id] = w->now;
            if (l->ib_pct && brnd(w) % 100 < l->ib_pct)            /* its IB ends after the swap arrives (b12v11 ibaft) */
                l->ib_end[l->render_id] = w->now + l->ib_min + brnd(w) % (l->ib_max - l->ib_min + 1);
            l_swap_begin(l, 0);
            ws_try_render(l);
        } else if (t == t_wst) {
            l->timer_next += 16666667;
            if (!l->rendering && l->outstanding < 2) ws_start(l);
        }
#if ADRENO_PRESENT_RELATCH
        else if (t == t_ent) p2_ws_enter(l);                    /* the submission takes the lock (p2) */
        else if (t == t_tmr) p2_timer(l);                        /* pipelineTimerFired */
        else if (t == t_app) p2_app(l);                          /* a synchronous (or pipelined) app IB */
        else if (t == t_rl) p2_relatch_poll(l);                  /* relatchFireGated */
#endif
        else {                                                   /* a cursor-only swap (H5) */
            l->cursor_next = w->now + l->cursor_gap_min + brnd(w) % (l->cursor_gap_max - l->cursor_gap_min + 1);
            if (l->qn < 64) { l->q[l->qn++] = (struct lswap){0x80000000u + ++l->cursor_ids, 2}; l->cursor_swaps++; }
            l_swap_begin(l, 0);
        }
    }
    w->now += 100 * MS;
    l_evaluate(l);
}

struct lres {
    uint64_t frames, torn, ovt, forced, late, fps_x10, renders_x10, copies_x10, q_us;
    uint64_t r2first_us, r2mid_us, in_mean_us, in_p95_us, max_stall_ms, order_errors, deadlock, shown, misses;
    uint64_t precopies, rel_successor, rel_lone, rel_deferred, rel_overdue, slack_peak_us, drops, min_gap_us, stale, gated;
};
static int u64cmp(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static struct lres l_summary(struct lworld *l)
{
    struct bworld *w = &l->w;
    struct lres r; memset(&r, 0, sizeof r);
    r.frames = l->frames; r.torn = l->torn; r.ovt = w->b.ovt; r.forced = w->b.forced; r.late = w->b.late;
    r.order_errors = l->order_errors; r.deadlock = (uint64_t)l->deadlock; r.max_stall_ms = l->max_stall / MS;
    r.min_gap_us = w->min_gap == UINT64_MAX ? 0 : w->min_gap / 1000;
    /* rates over the span of the shown swaps' render starts */
    uint32_t first = 0, lastk = 0;
    for (uint32_t k = 1; k < LMAX && k <= l->next_id; k++) if (l->shown[k]) { if (!first) first = k; lastk = k; }
    const uint64_t span = first && lastk > first ? l->rstart[lastk] - l->rstart[first] : 0;
    uint64_t distinct = 0, sum_first = 0, sum_mid = 0, n = 0;
    for (uint32_t k = first; k && k <= lastk; k++) {
        if (!l->shown[k]) continue;
        if (l->copied[k]) distinct++;
        sum_first += l->row0_ns[k] - l->rstart[k]; sum_mid += l->mid_ns[k] - l->rstart[k]; n++;
    }
    r.shown = n;
    r.fps_x10 = span ? distinct * 10000000000ull / span : 0;
    r.renders_x10 = span ? (uint64_t)(lastk - first) * 10000000000ull / span : 0;
    r.copies_x10 = span ? l->copies * 10000000000ull / (w->last_present_t - w->first_present_t + 1) : 0;
    r.r2first_us = n ? sum_first / n / 1000 : 0;
    r.r2mid_us = n ? sum_mid / n / 1000 : 0;
    r.q_us = l->q_n ? l->q_sum / l->q_n / 1000 : 0;
    /* input events: uniform over the shown span; each shown by the first swap whose render starts after it */
    static uint64_t lat[20000]; unsigned m = 0; uint64_t rng = 0x243f6a8885a308d3ull, sum = 0;
    for (unsigned i = 0; span && i < 20000; i++) {
        const uint64_t t = l->rstart[first] + vrnd(&rng) % span;
        uint32_t lo = first, hi = lastk;                         /* the first k with rstart[k] >= t */
        while (lo < hi) { const uint32_t mid = lo + (hi - lo) / 2; if (l->rstart[mid] >= t) hi = mid; else lo = mid + 1; }
        if (!l->shown[lo] || l->mid_ns[lo] < t) continue;
        lat[m++] = l->mid_ns[lo] - t; sum += l->mid_ns[lo] - t;
    }
    if (m) { qsort(lat, m, sizeof lat[0], u64cmp); r.in_mean_us = sum / m / 1000; r.in_p95_us = lat[m * 95 / 100] / 1000; }
#if ADRENO_LATCH
    r.misses = l->h.misses; r.precopies = l->h.precopies; r.rel_successor = l->h.rel_successor; r.rel_lone = l->h.rel_lone;
    r.rel_deferred = l->h.rel_deferred; r.rel_overdue = l->h.rel_overdue;
    r.slack_peak_us = (w->tb24 ? l->slack_peak * 1000 / 24 : l->slack_peak) / 1000;     /* a duration in timebase units */
#endif
    r.drops = l->drops; r.stale = l->stale; r.gated = l->gated;
    return r;
}
static FILE *LJ; static int lfirst;
static void lreport(const char *name, const struct lres *r)
{
    fprintf(LJ, "%s\"%s\":{\"frames\":%llu,\"torn\":%llu,\"ovt\":%llu,\"forced\":%llu,\"late\":%llu,\"fps_x10\":%llu,"
            "\"renders_x10\":%llu,\"copies_x10\":%llu,\"q_us\":%llu,\"render_to_first_us\":%llu,\"render_to_mid_us\":%llu,"
            "\"input_mean_us\":%llu,\"input_p95_us\":%llu,\"max_stall_ms\":%llu,\"order_errors\":%llu,\"deadlock\":%llu,"
            "\"misses\":%llu,\"precopies\":%llu,\"rel\":[%llu,%llu,%llu,%llu],\"slack_peak_us\":%llu,\"drops\":%llu,"
            "\"min_gap_us\":%llu,\"stale\":%llu,\"gated\":%llu}",
            lfirst++ ? "," : "", name, (unsigned long long)r->frames, (unsigned long long)r->torn,
            (unsigned long long)r->ovt, (unsigned long long)r->forced, (unsigned long long)r->late,
            (unsigned long long)r->fps_x10, (unsigned long long)r->renders_x10, (unsigned long long)r->copies_x10,
            (unsigned long long)r->q_us, (unsigned long long)r->r2first_us, (unsigned long long)r->r2mid_us,
            (unsigned long long)r->in_mean_us, (unsigned long long)r->in_p95_us, (unsigned long long)r->max_stall_ms,
            (unsigned long long)r->order_errors, (unsigned long long)r->deadlock, (unsigned long long)r->misses,
            (unsigned long long)r->precopies, (unsigned long long)r->rel_successor, (unsigned long long)r->rel_lone,
            (unsigned long long)r->rel_deferred, (unsigned long long)r->rel_overdue, (unsigned long long)r->slack_peak_us,
            (unsigned long long)r->drops, (unsigned long long)r->min_gap_us, (unsigned long long)r->stale,
            (unsigned long long)r->gated);
    printf("latency %-30s fps %3llu.%llu renders %3llu.%llu q %6llu us render->row0 %6llu mid %6llu input %6llu (p95 %6llu) us"
           " torn %llu ovt %llu forced %llu late %llu stall %llu ms miss %llu pre %llu rel %llu/%llu/%llu/%llu slack %llu us stale %llu gated %llu%s\n",
           name, (unsigned long long)r->fps_x10 / 10, (unsigned long long)r->fps_x10 % 10,
           (unsigned long long)r->renders_x10 / 10, (unsigned long long)r->renders_x10 % 10, (unsigned long long)r->q_us,
           (unsigned long long)r->r2first_us, (unsigned long long)r->r2mid_us, (unsigned long long)r->in_mean_us,
           (unsigned long long)r->in_p95_us, (unsigned long long)r->torn, (unsigned long long)r->ovt,
           (unsigned long long)r->forced, (unsigned long long)r->late, (unsigned long long)r->max_stall_ms,
           (unsigned long long)r->misses, (unsigned long long)r->precopies, (unsigned long long)r->rel_successor,
           (unsigned long long)r->rel_lone, (unsigned long long)r->rel_deferred, (unsigned long long)r->rel_overdue,
           (unsigned long long)r->slack_peak_us, (unsigned long long)r->stale, (unsigned long long)r->gated,
           r->deadlock ? " DEADLOCK" : r->order_errors ? " ORDER" : "");
}

/* ---- the scenarios ---- */
struct lcase {
    const char *name; int ws; uint64_t r_min, r_max; unsigned spike_pct; uint64_t spike_min, spike_max;
    unsigned stall_pct; uint64_t stall_min, stall_max; unsigned tail_pct; uint64_t tail_min, tail_max;
    double hz; uint32_t vt; unsigned drop_pct, rel_tail_pct; uint64_t rel_tail_min, rel_tail_max;
    uint64_t cursor_gap_min, cursor_gap_max, reset_ms, freeze_ms; int kind;
    unsigned ib_pct, app_busy_pct; uint64_t ib_min, ib_max, app_min, app_max;
};
enum { LK_LOAD = 0, LK_STALLS, LK_HEAVY, LK_DP, LK_DROP, LK_CURSOR, LK_RESET, LK_LATEREL, LK_FREEZE, LK_GPURACE };
static struct lres l_case(const struct lcase *c, int policy, unsigned swaps)
{
    static struct lworld l;
    l_init(&l, policy, c->ws, c->hz, c->vt, 7 + (uint64_t)c->kind * 31 + (uint64_t)c->ws * 7 + c->r_max / US);
    if (c->r_max) { l.r_min = c->r_min; l.r_max = c->r_max; }
    l.spike_pct = c->spike_pct; l.spike_min = c->spike_min; l.spike_max = c->spike_max;
    l.w.stall_pct = c->stall_pct; l.w.stall_min = c->stall_min; l.w.stall_max = c->stall_max;
    l.w.tail_pct = c->tail_pct; l.w.tail_min = c->tail_min; l.w.tail_max = c->tail_max;
    l.drop_pct = c->drop_pct; l.rel_tail_pct = c->rel_tail_pct; l.rel_tail_min = c->rel_tail_min; l.rel_tail_max = c->rel_tail_max;
    l.cursor_gap_min = c->cursor_gap_min; l.cursor_gap_max = c->cursor_gap_max;
    l.ib_pct = c->ib_pct; l.ib_min = c->ib_min; l.ib_max = c->ib_max;
    l.app_busy_pct = c->app_busy_pct; l.app_min = c->app_min; l.app_max = c->app_max; l.app_next = l.w.now;
    if (c->freeze_ms) { l.w.s.freeze_from = l.w.now + 5000 * MS; l.w.s.freeze_until = l.w.s.freeze_from + c->freeze_ms * MS; }
    l_start(&l);
    if (c->cursor_gap_min) l.cursor_next = l.w.now + c->cursor_gap_min;
    if (c->reset_ms) l.reset_at = l.w.now + c->reset_ms * MS;
    l_run(&l, swaps);
    char name[96]; snprintf(name, sizeof name, "%s_%s_%s", c->name, ws_name[c->ws], lp_name[policy]);
    struct lres r = l_summary(&l);
    lreport(name, &r);
    /* every scenario: torn frames are counted ones, completions in order, no deadlock, no long stall (H2 H8 L1 L2) */
    /* (the freeze runs on the grid while the beam is stalled: tear-free is not claimed there, as beam_freeze_2s) */
    CHECK(c->kind == LK_FREEZE || r.torn <= r.ovt + r.forced);
    CHECK(r.order_errors == 0);
    CHECK(!r.deadlock);
    CHECK(c->kind == LK_FREEZE || r.max_stall_ms < 250);
    CHECK(r.shown > swaps / 2);
#if ADRENO_LATCH
    if (policy == LP_HOLD && c->drop_pct) CHECK(r.drops > 0);
    if (policy == LP_HOLD && c->rel_tail_pct) CHECK(r.rel_overdue > 0);
#endif
    if (c->cursor_gap_min) CHECK(l.cursor_swaps > 0);
    return r;
}

#if ADRENO_LATCH
/* L3: the latch's arithmetic over every phase of an A16 frame, and the perf latch line (H9). */
static void latch_units(void)
{
    static struct bworld g;
    bworld_init(&g, BEAM, 59.51, 61); scan_init(&g.s, 59.51, 3840); g.s.regs = a16_regs(); g.s.base = 1;
    bworld_start(&g);
    CHECK(g.b.state == ADRENO_BEAM_LOCKED);
    const uint64_t ms = tb_ms(&g), vt = g.b.t.vtotal;
    adreno_beam_latch(&g.b, 3 * ms);
    const uint64_t off = adreno_beam_latch_lines(&g.b), gap = vt - g.b.t.a1 - 1 + g.b.t.a0;
    /* 2040 lines of blank at 4.35 us a line, less 34 lines and 3 ms of slack (690 lines): about 1316 lines on */
    CHECK(off > 1200 && off < 1400 && off < gap);
    printf("latch units: gap %llu lines, slack 3 ms = off %llu lines (%.2f ms after the vblank start, %.2f ms before row 0)\n",
           (unsigned long long)gap, (unsigned long long)off, (double)tb_ns(&g, g.tb_off + adreno_beam_ticks(&g.b, off)) / 1e6,
           (double)tb_ns(&g, g.tb_off + adreno_beam_ticks(&g.b, gap - off)) / 1e6);
    for (uint64_t ph = 0; ph < vt; ph += 37) {
        const uint64_t base = 100 * vt, pos = base + ph, now = g.now;
        g.b.last_tick = 0;
        const uint64_t target = adreno_beam_target(&g.b, pos, 0);
        /* the latch point is ahead by at least the head, and is the first such (a frame earlier would not be) */
        CHECK(target + g.b.latch_off >= pos + adreno_beam_head(&g.b));
        CHECK(target < vt || target - vt + g.b.latch_off < pos + adreno_beam_head(&g.b));
        const uint64_t fire = adreno_beam_fire_time(&g.b, now, pos);
        CHECK(fire >= now && fire <= now + adreno_beam_ticks(&g.b, 2 * vt));
        /* from a GO: the next frame, never the same one (L4) */
        g.b.last_tick = target;
        const uint64_t next = adreno_beam_target(&g.b, target + g.b.latch_off, 1);
        CHECK(next == target + vt);
    }
    /* L5: slack 0 is today's arithmetic */
    adreno_beam_latch(&g.b, 0);
    CHECK(adreno_beam_latch_lines(&g.b) == 0);
    g.b.last_tick = 0;
    CHECK(adreno_beam_target(&g.b, 100 * vt + 5, 0) == adreno_beam_next_vblank(&g.b, 100 * vt + 5 + adreno_beam_head(&g.b)));
    /* L9: raises double up to the cap, where the offset is 0; decay returns to the base */
    adreno_beam_latch(&g.b, 3 * ms);
    adreno_beam_slack_raise(&g.b); CHECK(g.b.slack == 6 * ms);
    adreno_beam_slack_raise(&g.b); CHECK(g.b.slack == adreno_beam_slack_cap(&g.b) && adreno_beam_latch_lines(&g.b) == 0);
    for (unsigned i = 0; i < 2000; i++) adreno_beam_slack_decay(&g.b);
    CHECK(g.b.slack == 3 * ms);
    /* H1: the budget and the release time */
    struct adreno_hold h; adreno_hold_init(&h, 1, ms * 3 / 2, 2 * ms);
    const uint64_t P = g.b.frame;
    CHECK(adreno_hold_budget(&h, P) == P);                       /* no sample: no hold */
    adreno_hold_released(&h, 1000 * ms); adreno_hold_arrival(&h, 1000 * ms + 3 * ms);
    CHECK(h.r_hi == 3 * ms && adreno_hold_budget(&h, P) == 3 * ms + ms * 3 / 2);
    CHECK(adreno_hold_release_time(&h, 2000 * ms, 2000 * ms + P, P) == 2000 * ms + P - (3 * ms + ms * 3 / 2));
    CHECK(adreno_hold_release_time(&h, 2000 * ms, 2000 * ms + 2 * ms, P) == 2000 * ms);   /* past: at once */
    adreno_hold_released(&h, 3000 * ms); adreno_hold_missed(&h, 3000 * ms + 9 * ms);
    CHECK(h.r_hi == 9 * ms && h.misses == 1);
    /* H9: the perf latch line at its caps, and parsed back */
    char line[512]; struct adreno_latch_summary big; memset(&big, 0xff, sizeof big);
    int n = adreno_perf_line_latch(line, sizeof line, ~0ull, &big);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    printf("latch perf line at caps: %d bytes\n", n);
    struct adreno_latch_summary sm; memset(&sm, 0, sizeof sm); sm.slack_us = 3000; sm.slack_peak_us = 6000; sm.off = 1316;
    sm.precopies = 590; sm.rel_successor = 588; sm.misses = 2;
    n = adreno_perf_line_latch(line, sizeof line, 7, &sm);
    CHECK(!strncmp(line, "AdrenoDisplay: perf latch s=7 slack=3000/6000 off=1316 ", 55) && strstr(line, " pre=590 rel=588/0/0/0 miss=2 "));
    printf("%s\n", line);
}
#endif

static void latency_scenarios(const char *dir)
{
    unsigned c0 = checks, f0 = failures, cc0 = cost_checks, cf0 = cost_failures;
    char path[4096]; snprintf(path, sizeof path, "%s/latency.json", dir);
    LJ = fopen(path, "w"); assert(LJ);
    fprintf(LJ, "{\"scenarios\":{");
#if ADRENO_LATCH
    latch_units();
    const int policies[] = {LP_BEAM, LP_LATCH, LP_HOLD, LP_HOLD_NOGATE}; const unsigned np = 3;
#else
    const int policies[] = {LP_BEAM}; const unsigned np = 1;
#endif
    const uint64_t M = MS;
    const struct lcase cases[] = {
        /* name     ws        r_min      r_max    spike%      spike         stall%     stall          tail%  tail     hz    vt */
        {"quiet",   WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_LOAD, 0, 0, 0, 0, 0, 0},
        {"quiet",   WS_EVENT, 2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_LOAD, 0, 0, 0, 0, 0, 0},
        {"quiet",   WS_TIMER, 2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_LOAD, 0, 0, 0, 0, 0, 0},
        {"busy",    WS_SLOT,  2000 * US, 6000 * US, 10, 6 * M, 12 * M, 0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_LOAD, 0, 0, 0, 0, 0, 0},
        {"busy",    WS_EVENT, 2000 * US, 6000 * US, 10, 6 * M, 12 * M, 0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_LOAD, 0, 0, 0, 0, 0, 0},
        {"spiky",   WS_SLOT,  2000 * US, 3600 * US, 5, 15 * M, 30 * M, 0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_LOAD, 0, 0, 0, 0, 0, 0},
        {"spiky",   WS_EVENT, 2000 * US, 3600 * US, 5, 15 * M, 30 * M, 0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_LOAD, 0, 0, 0, 0, 0, 0},
        {"stalls",  WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           2, 3 * M, 30 * M,    2, 2 * M, 40 * M, 59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_STALLS, 0, 0, 0, 0, 0, 0},
        {"heavy",   WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           20, 2 * M, 15 * M,   0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_HEAVY, 0, 0, 0, 0, 0, 0},
        {"dp60",    WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  60.02, 1852, 0, 0, 0, 0, 0, 0, 0, 0, LK_DP, 0, 0, 0, 0, 0, 0},
        {"drop",    WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 5, 0, 0, 0, 0, 0, 0, 0, LK_DROP, 0, 0, 0, 0, 0, 0},
        {"cursor",  WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 30 * M, 90 * M, 0, 0, LK_CURSOR, 0, 0, 0, 0, 0, 0},
        {"reset",   WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 6000, 0, LK_RESET, 0, 0, 0, 0, 0, 0},
        {"laterel", WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 10, 5 * M, 30 * M, 0, 0, 0, 0, LK_LATEREL, 0, 0, 0, 0, 0, 0},
        {"freeze",  WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 2000, LK_FREEZE, 0, 0, 0, 0, 0, 0},
        /* b12v11: 30% of WindowServer's frames end their IB 0.5-6 ms after the swap arrives; app IBs (1-10 ms) keep the
         * GPU busy 20% of the time */
        {"gpurace", WS_SLOT,  2000 * US, 3600 * US, 0, 0, 0,           0, 0, 0,             0, 0, 0,  59.51, 3840, 0, 0, 0, 0, 0, 0, 0, 0, LK_GPURACE,
         30, 20, 500 * US, 6 * M, 1 * M, 10 * M},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct lres r[4]; memset(r, 0, sizeof r);
        const unsigned n = np + (np == 3 && cases[i].kind == LK_GPURACE);     /* the hold without its gate: b12v11 */
        for (unsigned j = 0; j < n; j++) r[j] = l_case(&cases[i], policies[j], 1200);
        const int kind = cases[i].kind, ws = cases[i].ws;
        if (kind == LK_FREEZE) CHECK(r[0].fps_x10 >= 500);
        if (kind == LK_DP) CHECK(r[0].torn == 0);
#if ADRENO_LATCH
        const struct lres *beam = &r[0], *latch = &r[1], *hold = &r[2];
        if (kind == LK_FREEZE) { CHECK(latch->fps_x10 >= 500 && hold->fps_x10 >= 500); continue; }
        if (kind == LK_GPURACE) {
            /* G1-G3: the shipped default (latch, gate, no hold) copies no more unfinished frames than today; the hold
             * without the gate copies more (b12v11's glitches); the gate cuts the hold's */
            const struct lres *nogate = &r[3];
            CHECK(latch->stale <= beam->stale);
            COST(nogate->stale > beam->stale);
            CHECK(hold->stale <= nogate->stale);
            COST(latch->in_mean_us + 3000 <= beam->in_mean_us);
            continue;
        }
        if (kind == LK_DP) { CHECK(latch->torn == 0 && hold->torn == 0); COST(latch->in_mean_us <= beam->in_mean_us + 500); }
        if (kind == LK_LOAD) {
            /* the late latch: at least 4 ms off the input latency, the frame rate kept (L1 L2) */
            COST(latch->in_mean_us + 4000 <= beam->in_mean_us);
            CHECK(latch->fps_x10 * 100 >= beam->fps_x10 * 95);
            /* the hold: at least 4 ms more off, the frame rate kept, no extra rendering (H1 H3) */
            if (ws != WS_TIMER) COST(hold->in_mean_us + 4000 <= latch->in_mean_us);
            CHECK(hold->fps_x10 * 100 >= beam->fps_x10 * 95);
            if (ws == WS_SLOT) CHECK(hold->renders_x10 * 100 <= hold->fps_x10 * 105);
            if (ws == WS_SLOT) CHECK(hold->q_us < 8000);         /* H3: no queued frame (P is 16.7 ms) */
            CHECK(hold->torn <= beam->torn + 2 && latch->torn <= beam->torn + 2);
        }
        if (kind == LK_STALLS) COST(latch->torn <= 3 * beam->torn + 2 && hold->torn <= 3 * beam->torn + 2);
        if (kind == LK_HEAVY) {
            CHECK(latch->slack_peak_us >= 8000);                 /* L9: raised to the cap */
            COST(latch->in_mean_us <= beam->in_mean_us + 1000);
        }
        if (kind == LK_DROP || kind == LK_CURSOR || kind == LK_RESET || kind == LK_LATEREL)
            CHECK(hold->fps_x10 * 100 >= beam->fps_x10 * 90);
#else
        (void)ws;
#endif
    }
    fprintf(LJ, "},\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", checks - c0, failures - f0,
            cost_checks - cc0, cost_failures - cf0);
    fclose(LJ);
    printf("{\"latency_checks\":%u,\"latency_failures\":%u,\"latency_cost_checks\":%u,\"latency_cost_failures\":%u}\n",
           checks - c0, failures - f0, cost_checks - cc0, cost_failures - cf0);
}

#if ADRENO_PRESENT_SYNC
/* ---- present sync (agents/present-sync FAILURE-MODES.md S5, K1-K11) ----
 * WindowServer's frames against their GPU work, calibrated to b12v9/b12v11: per IB the submit path held 6-12 ms in busy
 * windows (10.8 ms of GPU time on average, a maximum of 108 ms), app IBs hold the submit lock, and the swap reached the
 * display before its IB finished (b12v11: 87 of 122 IBs in one window). Each scenario runs the shipped default (LATCH:
 * the late latch and G1, no hold) four ways: today (the plug-in returns from commitAndWaitUntilSubmitted at once), K
 * (the kext's gate), S (the plug-in waits for the submission) and S+K; BEAM today for reference; HOLD with S+K (K8).
 * "Unfinished" is a copy that starts before its swap's GPU work ended (lres.stale). */
struct pcase { const char *name; int ws; unsigned g_pct; uint64_t lo[3], hi[3]; unsigned wt[3]; unsigned lock_pct;
               uint64_t lock_max; uint32_t stuck; uint64_t r_min, r_max; };   /* r: WindowServer's CPU (0: quiet) */
enum { PS_TODAY = 0, PS_K = 1, PS_S = 2, PS_SK = 3, PS_PIPE = 4 };
static const char *const ps_name[] = {"today", "k", "s", "s_k", "pipe"};
struct pres { struct lres r; uint64_t gpu_frames, defer, swaps, forced, max_wait_us, busy, s_waits, s_wait_us, s_bound;
              uint64_t overlapped, gpu_busy_pct; };
static FILE *PJ; static int pfirst;
#if ADRENO_PIPELINE
static int pcase_complete_at_copy;                          /* pipeline_scenarios' what-if */
#endif
static struct pres p_case(const struct pcase *c, int lp, int ps, unsigned swaps)
{
    static struct lworld l;
    l_init(&l, lp, c->ws, 59.51, 3840, 911 + (uint64_t)c->g_pct * 7 + (uint64_t)c->ws * 3 + c->hi[0] / US);
    l.g_pct = c->g_pct; l.uq_min = 50 * US; l.uq_max = 500 * US; l.lock_pct = c->lock_pct; l.lock_max = c->lock_max;
    for (unsigned b = 0; b < 3; b++) { l.g_lo[b] = c->lo[b]; l.g_hi[b] = c->hi[b] > c->lo[b] ? c->hi[b] : c->lo[b] + 1; l.g_w[b] = c->wt[b]; }
    l.stuck_id = c->stuck;
    l.s_wait = ps == PS_S || ps == PS_SK || ps == PS_PIPE; l.k_gate = ps == PS_K || ps == PS_SK || ps == PS_PIPE;
#if ADRENO_PIPELINE
    /* P (agents/gpu-pipeline): S waits for the submission, which returns at START; K holds to the finish, bound 1.1 s
     * (D2); detection 0..200 us by a waiting submitter, 0..500 us by the timer; 30 us from the final reply to START */
    if (c->r_max) { l.r_min = c->r_min; l.r_max = c->r_max; }
    l.pipe = ps == PS_PIPE; l.spin_max = 200 * US; l.timer_max = 500 * US; l.start_cost = 30 * US;
    l.complete_at_copy = pcase_complete_at_copy;
    adreno_sync_gate_init(&l.sg, l.k_gate ? (l.pipe ? 1100 : 50) * MS : 0, 2000 * MS);
#else
    adreno_sync_gate_init(&l.sg, l.k_gate ? 50 * MS : 0, 2000 * MS);
#endif
    l_start(&l);
    l_run(&l, swaps);
    struct pres p; memset(&p, 0, sizeof p);
    p.r = l_summary(&l);
    p.gpu_frames = l.gpu_frames; p.defer = l.sg.defer; p.swaps = l.sg.swaps; p.forced = l.sg.forced;
    p.max_wait_us = l.sg.max_waited / 1000; p.busy = l.sg.busy;
    p.s_waits = l.s_waits; p.s_wait_us = l.s_waits ? l.s_wait_ns / l.s_waits / 1000 : 0; p.s_bound = l.s_bound;
    char name[96]; snprintf(name, sizeof name, "%s_%s_%s_%s", c->name, ws_name[c->ws], lp_name[lp], ps_name[ps]);
#if ADRENO_PIPELINE
    if (pcase_complete_at_copy) strncat(name, "_copydone", sizeof name - strlen(name) - 1);
#endif
    const struct lres *r = &p.r;
    fprintf(PJ, "%s\"%s\":{\"frames\":%llu,\"torn\":%llu,\"ovt\":%llu,\"beam_forced\":%llu,\"fps_x10\":%llu,\"renders_x10\":%llu,"
            "\"q_us\":%llu,\"input_mean_us\":%llu,\"input_p95_us\":%llu,\"max_stall_ms\":%llu,\"order_errors\":%llu,\"deadlock\":%llu,"
            "\"shown\":%llu,\"gpu_frames\":%llu,\"unfinished\":%llu,\"g1_gated\":%llu,\"sync_defer\":%llu,\"sync_swaps\":%llu,"
            "\"sync_forced\":%llu,\"sync_max_wait_us\":%llu,\"s_waits\":%llu,\"s_wait_mean_us\":%llu,\"s_bound\":%llu}",
            pfirst++ ? "," : "", name, (unsigned long long)r->frames, (unsigned long long)r->torn, (unsigned long long)r->ovt,
            (unsigned long long)r->forced, (unsigned long long)r->fps_x10, (unsigned long long)r->renders_x10,
            (unsigned long long)r->q_us, (unsigned long long)r->in_mean_us, (unsigned long long)r->in_p95_us,
            (unsigned long long)r->max_stall_ms, (unsigned long long)r->order_errors, (unsigned long long)r->deadlock,
            (unsigned long long)r->shown, (unsigned long long)p.gpu_frames, (unsigned long long)r->stale,
            (unsigned long long)r->gated, (unsigned long long)p.defer, (unsigned long long)p.swaps,
            (unsigned long long)p.forced, (unsigned long long)p.max_wait_us, (unsigned long long)p.s_waits,
            (unsigned long long)p.s_wait_us, (unsigned long long)p.s_bound);
#if ADRENO_PIPELINE
    if (ps == PS_PIPE) {   /* the share of the run the GPU was busy, and the IBs whose submitter found a flight */
        uint64_t busy = 0, first = 0, last = 0;
        for (uint32_t k = 1; k < LMAX && k <= l.next_id; k++) {
            if (!l.ib_end[k]) continue;
            busy += l.ib_end[k] - l.ib_start[k];
            if (!first) first = l.ib_start[k];
            last = l.ib_end[k];
        }
        p.overlapped = l.pipe_overlapped; p.gpu_busy_pct = last > first ? busy * 100 / (last - first) : 0;
        fseek(PJ, -1, SEEK_CUR);
        fprintf(PJ, ",\"overlapped\":%llu,\"gpu_busy_pct\":%llu}", (unsigned long long)p.overlapped,
                (unsigned long long)p.gpu_busy_pct);
    }
#endif
    printf("presentsync %-32s fps %3llu.%llu input %6llu us (p95 %6llu) q %5llu us gpu frames %4llu unfinished %4llu "
           "sync defer %4llu swaps %4llu forced %llu max %6llu us; S waits %4llu mean %6llu us bound %llu; torn %llu stall %llu ms%s\n",
           name, (unsigned long long)r->fps_x10 / 10, (unsigned long long)r->fps_x10 % 10, (unsigned long long)r->in_mean_us,
           (unsigned long long)r->in_p95_us, (unsigned long long)r->q_us, (unsigned long long)p.gpu_frames,
           (unsigned long long)r->stale, (unsigned long long)p.defer, (unsigned long long)p.swaps,
           (unsigned long long)p.forced, (unsigned long long)p.max_wait_us, (unsigned long long)p.s_waits,
           (unsigned long long)p.s_wait_us, (unsigned long long)p.s_bound, (unsigned long long)r->torn,
           (unsigned long long)r->max_stall_ms, r->deadlock ? " DEADLOCK" : r->order_errors ? " ORDER" : "");
    /* every run (K3 K4): counted tears only, completions in order, no deadlock, no long stall, most swaps shown */
    CHECK(r->torn <= r->ovt + r->forced);
    CHECK(r->order_errors == 0);
    CHECK(!r->deadlock);
    CHECK(r->max_stall_ms < (c->stuck ? 900u : 250u));
    CHECK(r->shown > swaps / 2);
    return p;
}

/* K5 K9 K11: the table and the gate as units, and the perf sync line at its caps */
static void sync_units(void)
{
    struct adreno_sync_table t; memset(&t, 0, sizeof t);
    uint64_t since = 0;
    adreno_sync_mark(&t, 7, 100); adreno_sync_mark(&t, 7, 200); adreno_sync_mark(&t, 9, 300);
    CHECK(adreno_sync_query(&t, 7, &since) == 2 && since == 100 && adreno_sync_query(&t, 9, NULL) == 1);
    CHECK(adreno_sync_query(&t, 8, &since) == 0 && since == 0);
    adreno_sync_unmark(&t, 7); adreno_sync_unmark(&t, 7);
    CHECK(adreno_sync_query(&t, 7, NULL) == 0 && adreno_sync_query(&t, 9, NULL) == 1);
    adreno_sync_unmark(&t, 9); adreno_sync_unmark(&t, 9);                  /* one too many: counted, nothing below 0 */
    CHECK(t.unmatched == 1 && adreno_sync_query(&t, 9, NULL) == 0);
    for (uint32_t i = 1; i <= ADRENO_SYNC_SLOTS + 3; i++) adreno_sync_mark(&t, 1000 + i, 400);   /* 3 overflow */
    CHECK(t.overflows == 3 && t.wild == 3);
    CHECK(adreno_sync_query(&t, 5, NULL) == 3);                            /* K5: overflow makes every surface written */
    for (uint32_t i = 1; i <= ADRENO_SYNC_SLOTS + 3; i++) adreno_sync_unmark(&t, 1000 + i);
    CHECK(t.wild == 0 && t.unmatched == 1 && adreno_sync_query(&t, 1001, NULL) == 0);
    adreno_sync_mark(&t, ADRENO_SYNC_WILDCARD, 500);
    CHECK(adreno_sync_query(&t, 77, &since) == 1 && since == 500);
    adreno_sync_unmark(&t, ADRENO_SYNC_WILDCARD);
    CHECK(adreno_sync_query(&t, 77, NULL) == 0);
    /* the gate: wait, a new head restarts, the bound forces, staleness, off */
    struct adreno_sync_gate g; adreno_sync_gate_init(&g, 50, 2000);
    int a = 0x11, b = 0x22;
    CHECK(adreno_sync_decide(&g, &a, 1, 0, 0, 1000) == ADRENO_SYNC_GO && g.swaps == 0);
    CHECK(adreno_sync_decide(&g, &a, 1, 1, 990, 1000) == ADRENO_SYNC_WAIT && g.swaps == 1);
    CHECK(adreno_sync_decide(&g, &a, 1, 1, 990, 1030) == ADRENO_SYNC_WAIT && g.swaps == 1 && g.defer == 2);
    CHECK(adreno_sync_decide(&g, &a, 2, 1, 990, 1040) == ADRENO_SYNC_WAIT && g.swaps == 2);   /* K11: same pointer, new ID */
    CHECK(adreno_sync_decide(&g, &b, 3, 1, 990, 1045) == ADRENO_SYNC_WAIT && g.swaps == 3 && g.since == 1045);
    CHECK(adreno_sync_decide(&g, &b, 3, 1, 990, 1095) == ADRENO_SYNC_FORCED && g.forced == 1 && !g.head && g.max_waited == 50);
    CHECK(adreno_sync_decide(&g, &b, 4, 1, 990, 1100) == ADRENO_SYNC_WAIT);
    CHECK(adreno_sync_decide(&g, &b, 4, 0, 0, 1120) == ADRENO_SYNC_GO && !g.head && g.max_waited == 50);
    CHECK(adreno_sync_decide(&g, &b, 5, 1, 10, 5000) == ADRENO_SYNC_GO && g.stale_seen == 1);   /* K2: a 4990-old mark */
    struct adreno_sync_gate off; adreno_sync_gate_init(&off, 0, 2000);
    CHECK(adreno_sync_decide(&off, &a, 1, 9, 990, 1000) == ADRENO_SYNC_GO && off.busy == 0);
    /* K9: the perf sync line at its caps, and parsed back */
    char line[512]; struct adreno_sync_summary big; memset(&big, 0xff, sizeof big);
    int n = adreno_perf_line_sync(line, sizeof line, ~0ull, &big);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    printf("sync perf line at caps: %d bytes\n", n);
    struct adreno_sync_summary s = {12, 5, 1, 33000, 2400, 14, 0, 0, 0};
    n = adreno_perf_line_sync(line, sizeof line, 9, &s);
    CHECK(!strcmp(line, "AdrenoDisplay: perf sync s=9 defer=12 swaps=5 forced=1 max_us=33000 marks=2400 busy=14 ovf=0 stale=0 unm=0"));
    printf("%s\n", line);
}

static void presentsync_scenarios(const char *dir)
{
    unsigned c0 = checks, f0 = failures, cc0 = cost_checks, cf0 = cost_failures;
    char path[4096]; snprintf(path, sizeof path, "%s/presentsync.json", dir);
    PJ = fopen(path, "w"); assert(PJ);
    fprintf(PJ, "{\"scenarios\":{");
    sync_units();
    const uint64_t M = MS;
    const struct pcase cases[] = {
        /* name          ws        gpu%  IB bins (ms)                         weights      lock% lock max  stuck  r */
        {"gpulag",       WS_SLOT,  60, {2 * M, 8 * M, 20 * M}, {8 * M, 20 * M, 50 * M}, {60, 30, 10}, 25, 10 * M, 0, 0, 0},
        {"gpulag",       WS_EVENT, 60, {2 * M, 8 * M, 20 * M}, {8 * M, 20 * M, 50 * M}, {60, 30, 10}, 25, 10 * M, 0, 0, 0},
        {"gpulag_quiet", WS_SLOT,  20, {1 * M, 1 * M, 1 * M}, {4 * M, 4 * M, 4 * M},    {100, 0, 0},   5, 2 * M,  0, 0, 0},
        {"gpulag_heavy", WS_SLOT, 100, {8 * M, 20 * M, 60 * M}, {20 * M, 60 * M, 108 * M}, {50, 40, 10}, 50, 30 * M, 0, 0, 0},
        {"gpulag_stuck", WS_SLOT,  60, {2 * M, 8 * M, 20 * M}, {8 * M, 20 * M, 50 * M}, {60, 30, 10}, 25, 10 * M, 300, 0, 0},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const struct pcase *c = &cases[i];
        struct pres p[4];
        for (int ps = 0; ps < 4; ps++) p[ps] = p_case(c, LP_LATCH, ps, 1200);
        const struct pres beam = p_case(c, LP_BEAM, PS_TODAY, 1200);
        const struct pres hold = p_case(c, LP_HOLD, PS_SK, 1200);
        const struct lres *today = &p[PS_TODAY].r, *k = &p[PS_K].r, *s = &p[PS_S].r, *sk = &p[PS_SK].r;
        const int stuck = c->stuck != 0, quiet = !strcmp(c->name, "gpulag_quiet"), heavy = !strcmp(c->name, "gpulag_heavy");
        /* K1: the gate never adds unfinished copies, and catches what is in the kext. Under heavy load the command
         * buffers back up in WindowServer's submission queue, where the kext cannot see them (K6): only S helps there. */
        CHECK(k->stale <= today->stale);
        if (!quiet && !stuck) COST(today->stale > 0);                                  /* the race reproduces */
        if (!quiet && !stuck && !heavy) COST(k->stale * 3 <= today->stale);           /* most of it caught by K alone */
        /* S1: with the plug-in waiting, no swap overtakes its frame; S+K the same, and K then has nothing to wait for */
        if (!stuck) {
            CHECK(s->stale == 0 && sk->stale == 0);
            CHECK(p[PS_SK].forced == 0);
            CHECK(hold.r.stale == 0 && hold.forced == 0);            /* K8: the hold's precopy with S+K */
        } else {
            /* K2: the 400 ms write: S gives up at 250 ms; K copies at its bound (counted), never waits longer */
            CHECK(p[PS_K].forced >= 1 && p[PS_SK].forced >= 1 && p[PS_S].s_bound >= 1);
            CHECK(p[PS_K].max_wait_us <= 50000 + 17000 && p[PS_SK].max_wait_us <= 50000 + 17000);
            CHECK(sk->stale <= p[PS_SK].forced);
        }
        /* S5: the frame-rate cost. Quiet loads lose nothing; under load the rate becomes what the GPU really delivers */
        if (quiet) COST(s->fps_x10 * 100 >= today->fps_x10 * 97 && sk->fps_x10 * 100 >= today->fps_x10 * 97);
        CHECK(sk->fps_x10 * 100 >= s->fps_x10 * 95);                 /* K costs nothing on top of S */
        printf("presentsync %s_%s: unfinished copies today %llu (beam %llu), K %llu, S %llu, S+K %llu, hold S+K %llu of %llu GPU "
               "frames; fps today %llu.%llu K %llu.%llu S %llu.%llu S+K %llu.%llu; input today %llu us, S+K %llu us\n",
               c->name, ws_name[c->ws], (unsigned long long)today->stale, (unsigned long long)beam.r.stale,
               (unsigned long long)k->stale, (unsigned long long)s->stale, (unsigned long long)sk->stale,
               (unsigned long long)hold.r.stale, (unsigned long long)p[PS_TODAY].gpu_frames,
               (unsigned long long)today->fps_x10 / 10, (unsigned long long)today->fps_x10 % 10,
               (unsigned long long)k->fps_x10 / 10, (unsigned long long)k->fps_x10 % 10,
               (unsigned long long)s->fps_x10 / 10, (unsigned long long)s->fps_x10 % 10,
               (unsigned long long)sk->fps_x10 / 10, (unsigned long long)sk->fps_x10 % 10,
               (unsigned long long)today->in_mean_us, (unsigned long long)sk->in_mean_us);
    }
    fprintf(PJ, "},\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", checks - c0, failures - f0,
            cost_checks - cc0, cost_failures - cf0);
    fclose(PJ);
    printf("{\"presentsync_checks\":%u,\"presentsync_failures\":%u,\"presentsync_cost_checks\":%u,\"presentsync_cost_failures\":%u}\n",
           checks - c0, failures - f0, cost_checks - cc0, cost_failures - cf0);
}

#if ADRENO_PIPELINE
/* ---- the IB pipeline (agents/gpu-pipeline FAILURE-MODES.md D1-D5, O4, U1) ----
 * P: the kext's pipeline (the submission returns at START, the marks last until the finish, the gate's bound 1.1 s),
 * with present-sync's S wait in the plug-in. Every present-sync case runs P next to S+K; then the b12v12 load shape
 * (13.4 ms of GPU time per frame at 915 MHz, about 5 ms of WindowServer CPU; the dvfs agent's sim-gpu-b12v12), flat
 * and spread, SLOT and EVENT, and CPU-bound. Rows: pipeline.json (presentsync.json is unchanged). */
static void pipe_units(void)
{
    char line[512]; struct adreno_pipe_summary big; memset(&big, 0xff, sizeof big);
    int n = adreno_perf_line_pipe(line, sizeof line, ~0ull, &big);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    printf("pipe perf line at caps: %d bytes\n", n);
    uint64_t was[ADRENO_PIPE_COUNTERS], now[ADRENO_PIPE_COUNTERS];
    for (unsigned i = 0; i < ADRENO_PIPE_COUNTERS; i++) { was[i] = 100 * i; now[i] = 100 * i + 3 * i + 1; }
    now[ADRENO_PIPE_C_GAP_US] = was[ADRENO_PIPE_C_GAP_US] + 600; now[ADRENO_PIPE_C_GAP_N] = was[ADRENO_PIPE_C_GAP_N] + 4;
    now[ADRENO_PIPE_C_MAX_US] = 21400;
    struct adreno_pipe_summary s; adreno_pipe_window(&s, 1u | 1u << 8, now, was);
    n = adreno_perf_line_pipe(line, sizeof line, 9, &s);
    CHECK(!strcmp(line, "AdrenoDisplay: perf pipe s=9 on=3 fl=1 ovl=4 imm=7 sync=10 fold=13 drain=16 tmr=19 polls=22 "
                        "spin_us=25 gap_us=150 max_ms=21 fail=37"));
    printf("%s\n", line);
}
static void pipeline_scenarios(const char *dir)
{
    unsigned c0 = checks, f0 = failures, cc0 = cost_checks, cf0 = cost_failures;
    char path[4096]; snprintf(path, sizeof path, "%s/pipeline.json", dir);
    PJ = fopen(path, "w"); assert(PJ);
    pfirst = 0;
    fprintf(PJ, "{\"scenarios\":{");
    pipe_units();
    const uint64_t M = MS;
    const struct pcase old[] = {   /* present-sync's cases, as there */
        {"gpulag",       WS_SLOT,  60, {2 * M, 8 * M, 20 * M}, {8 * M, 20 * M, 50 * M}, {60, 30, 10}, 25, 10 * M, 0, 0, 0},
        {"gpulag",       WS_EVENT, 60, {2 * M, 8 * M, 20 * M}, {8 * M, 20 * M, 50 * M}, {60, 30, 10}, 25, 10 * M, 0, 0, 0},
        {"gpulag_quiet", WS_SLOT,  20, {1 * M, 1 * M, 1 * M}, {4 * M, 4 * M, 4 * M},    {100, 0, 0},   5, 2 * M,  0, 0, 0},
        {"gpulag_heavy", WS_SLOT, 100, {8 * M, 20 * M, 60 * M}, {20 * M, 60 * M, 108 * M}, {50, 40, 10}, 50, 30 * M, 0, 0, 0},
        {"gpulag_stuck", WS_SLOT,  60, {2 * M, 8 * M, 20 * M}, {8 * M, 20 * M, 50 * M}, {60, 30, 10}, 25, 10 * M, 300, 0, 0},
    };
    for (unsigned i = 0; i < sizeof old / sizeof old[0]; i++) {
        const struct pcase *c = &old[i];
        const struct pres sk = p_case(c, LP_LATCH, PS_SK, 1200);
        const struct pres pp = p_case(c, LP_LATCH, PS_PIPE, 1200);
        const struct pres ph = p_case(c, LP_HOLD, PS_PIPE, 1200);
        /* D1 D2: no copy of an unfinished frame, nothing forced; the stuck 400 ms IB is held (1.1 s bound), not forced */
        CHECK(pp.r.stale == 0 && pp.forced == 0 && ph.r.stale == 0 && ph.forced == 0);
        if (c->stuck) CHECK(pp.max_wait_us >= 300000 && pp.max_wait_us < 1100000);
        CHECK(pp.r.fps_x10 * 100 >= sk.r.fps_x10 * 99);              /* never slower than S+K */
        printf("pipeline %s_%s: unfinished S+K %llu, P %llu (hold %llu); forced %llu; fps S+K %llu.%llu P %llu.%llu (hold %llu.%llu); "
               "input S+K %llu us, P %llu us; overlapped %llu of %llu\n", c->name, ws_name[c->ws],
               (unsigned long long)sk.r.stale, (unsigned long long)pp.r.stale, (unsigned long long)ph.r.stale,
               (unsigned long long)pp.forced, (unsigned long long)sk.r.fps_x10 / 10, (unsigned long long)sk.r.fps_x10 % 10,
               (unsigned long long)pp.r.fps_x10 / 10, (unsigned long long)pp.r.fps_x10 % 10,
               (unsigned long long)ph.r.fps_x10 / 10, (unsigned long long)ph.r.fps_x10 % 10,
               (unsigned long long)sk.r.in_mean_us, (unsigned long long)pp.r.in_mean_us, (unsigned long long)pp.overlapped,
               (unsigned long long)pp.gpu_frames);
    }
    /* the b12v12 shape: GPU bins mean 13.5 ms (9-14 ms 60%, 14-17 ms 35%, 17-30 ms 5%), CPU 4.5-5.5 ms; flat: 13.4 + 5.
     * Two WindowServer models: SLOT (input-latency's: a frame starts only with a free swap entry, which our tick frees
     * one tick after the copy; it reproduces the quiet desktop's q = P - R) and FREE (the next frame starts right after
     * the swap and waits for an entry only to swap; it reproduces b12v12's busy windows, 54.5 pps with S, the serial
     * bound 1000 / 18.4). And the what-if that matters for SLOT: the swap completed right after its copy. */
    const struct pcase b12[] = {
        {"b12v12",       WS_SLOT,  100, {9 * M, 14 * M, 17 * M}, {14 * M, 17 * M, 30 * M}, {60, 35, 5}, 10, 2 * M, 0, 4500 * US, 5500 * US},
        {"b12v12",       WS_FREE,  100, {9 * M, 14 * M, 17 * M}, {14 * M, 17 * M, 30 * M}, {60, 35, 5}, 10, 2 * M, 0, 4500 * US, 5500 * US},
        {"b12v12_flat",  WS_SLOT,  100, {13400 * US, 13400 * US, 13400 * US}, {13400 * US, 13400 * US, 13400 * US}, {100, 0, 0}, 0, 0, 0, 5 * M, 5 * M},
        {"b12v12_flat",  WS_FREE,  100, {13400 * US, 13400 * US, 13400 * US}, {13400 * US, 13400 * US, 13400 * US}, {100, 0, 0}, 0, 0, 0, 5 * M, 5 * M},
        {"b12v12_cpu16", WS_FREE,  100, {13400 * US, 13400 * US, 13400 * US}, {13400 * US, 13400 * US, 13400 * US}, {100, 0, 0}, 0, 0, 0, 16 * M, 16 * M},
        {"b12v12_gpu20", WS_FREE,  100, {20 * M, 20 * M, 20 * M}, {20 * M, 20 * M, 20 * M}, {100, 0, 0}, 0, 0, 0, 5 * M, 5 * M},
        {"b12v12_gpu8",  WS_FREE,  100, {8 * M, 8 * M, 8 * M}, {8 * M, 8 * M, 8 * M}, {100, 0, 0}, 0, 0, 0, 5 * M, 5 * M},
    };
    const double hz = 59.51;
    for (unsigned i = 0; i < sizeof b12 / sizeof b12[0]; i++) {
        const struct pcase *c = &b12[i];
        for (int copydone = 0; copydone < (c->ws == WS_SLOT ? 2 : 1); copydone++) {
            pcase_complete_at_copy = copydone;
            const struct pres today = p_case(c, LP_LATCH, PS_TODAY, 1200);
            const struct pres sk = p_case(c, LP_LATCH, PS_SK, 1200);
            const struct pres pp = p_case(c, LP_LATCH, PS_PIPE, 1200);
            const struct pres ph = p_case(c, LP_HOLD, PS_PIPE, 1200);
            pcase_complete_at_copy = 0;
            double gpu = 0, cpu = (double)(c->r_min + c->r_max) / 2e6;
            for (unsigned b = 0; b < 3; b++) gpu += (double)c->wt[b] / 100.0 * (double)(c->lo[b] + c->hi[b]) / 2e6;
            double bound = 1000.0 / (gpu > cpu ? gpu : cpu);
            if (bound > hz) bound = hz;
            const double serial = 1000.0 / (gpu + cpu);
            const int flat = c->lo[0] == c->hi[0];
            CHECK(pp.r.stale == 0 && pp.forced == 0 && ph.r.stale == 0 && ph.forced == 0);   /* D1 D2 */
            /* never slower than S+K (within the latch's noise: SLOT holds two frames whatever the kext does) */
            CHECK(pp.r.fps_x10 * 100 >= sk.r.fps_x10 * 97);
            if (c->ws == WS_FREE || copydone) {
                COST(sk.r.fps_x10 <= (uint64_t)((serial < hz ? serial : hz) * 10.0 * 1.02 + 1));   /* S+K: in series */
                if (gpu + cpu > 1000.0 / hz) CHECK(pp.r.fps_x10 > sk.r.fps_x10);                /* the overlap pays */
                /* GPU-bound: approaches min(60, 1000 / max(gpu, cpu)); a 16 ms CPU frame plus the swap wait is not */
                if (gpu >= cpu) COST(pp.r.fps_x10 >= (uint64_t)(bound * 10.0 * (flat ? 0.97 : 0.95)));
            }
            printf("pipeline %s_%s%s: GPU %.1f ms, CPU %.1f ms; fps today %llu.%llu (unfinished %llu), S+K %llu.%llu (serial "
                   "bound %.1f), P %llu.%llu (hold %llu.%llu), bound min(%.2f, 1000/max(gpu, cpu)) = %.1f; unfinished P %llu "
                   "forced %llu; input S+K %llu us, P %llu us (p95 %llu); GPU busy %llu%%\n", c->name, ws_name[c->ws],
                   copydone ? " (swap completed at its copy)" : "", gpu, cpu,
                   (unsigned long long)today.r.fps_x10 / 10, (unsigned long long)today.r.fps_x10 % 10,
                   (unsigned long long)today.r.stale, (unsigned long long)sk.r.fps_x10 / 10,
                   (unsigned long long)sk.r.fps_x10 % 10, serial, (unsigned long long)pp.r.fps_x10 / 10,
                   (unsigned long long)pp.r.fps_x10 % 10, (unsigned long long)ph.r.fps_x10 / 10,
                   (unsigned long long)ph.r.fps_x10 % 10, hz, bound, (unsigned long long)pp.r.stale,
                   (unsigned long long)pp.forced, (unsigned long long)sk.r.in_mean_us, (unsigned long long)pp.r.in_mean_us,
                   (unsigned long long)pp.r.in_p95_us, (unsigned long long)pp.gpu_busy_pct);
        }
    }
    fprintf(PJ, "},\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", checks - c0, failures - f0,
            cost_checks - cc0, cost_failures - cf0);
    fclose(PJ);
    printf("{\"pipeline_checks\":%u,\"pipeline_failures\":%u,\"pipeline_cost_checks\":%u,\"pipeline_cost_failures\":%u}\n",
           checks - c0, failures - f0, cost_checks - cc0, cost_failures - cf0);
}
#endif
#include "replay-adreno-pacing.c"
#endif
