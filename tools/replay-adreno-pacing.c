/* SPDX-License-Identifier: MIT */
/* Present pacing (agents/present-pacing FAILURE-MODES.md, written before the code): included at the end of
 * tools/replay-adreno-latency.c. Everything here is under -DADRENO_PRESENT_RELATCH=1 (with ADRENO_BEAM, ADRENO_LATCH,
 * ADRENO_PRESENT_SYNC and ADRENO_PIPELINE); without it this file adds nothing and every other output is unchanged.
 *
 * The world is the latency replay's (the A16 beam and scanout, the production present and beam gate, WindowServer's
 * SLOT/FREE models, the family queue, AdrenoDisplay's frame path with the late latch, the sync gate and the scanned
 * frames). New here, the b12v17 pipeline ("p2", lworld's p2 fields): one submit lock that every user reserves in time
 * order, with the nosparse cache maintenance inside it:
 * - a WindowServer submission enters the kext uq after its commit (the marks are set there), takes the lock, runs its
 *   TO_DEVICE (`b`), polls the flight to its final reply, STARTs, then finishes the older flight (its FROM_DEVICE `f`)
 *   and unlocks; S returns after the post;
 * - the completion timer (500 us + leeway) takes the lock for one POLL and finishes a final flight there;
 * - app IBs (Poisson arrivals) take the lock, run their TO_DEVICE, finish WindowServer's flight first, then their own IB
 *   synchronously (polled) and its FROM_DEVICE; or, with app_pipe (adreno_pipeline=2), become the flight;
 * - a flight's marks go at the post after the unlock that ends the critical section that finished it, or with EP1 at
 *   the end of its FROM_DEVICE.
 * The fixes: urgent completion polling (UR1), EP1-EP3, and the relatch (AdrenoDisplayRelatch.h, RL1-RL7), which runs in
 * every run: measuring only for "today".
 * Calibration: agents/present-pacing/analysis/b12v17-windows.txt (s=5/6 heavy, s=25-30 medium, s=31-36 light). */
#if ADRENO_PRESENT_RELATCH
#define P2_POST (20 * US)          /* from the unlock to the unmark in pipelinePost */
#define P2_POLL (3 * US)           /* one POLL under the lock */
#define P2_START (30 * US)         /* from the final reply to START (as pipeline_scenarios) */
#define P2_SPIN (200 * US)         /* a waiting submitter's IODelay backoff, at most */
#define P2_LEEWAY (50 * US)        /* the completion timer's leeway */
#define P2_ENTRY (500 * US)        /* EP3's POLLs come between TO_DEVICE entries: up to this much late */

static uint64_t p2_rnd(struct lworld *l, uint64_t lo, uint64_t hi) { return hi > lo ? lo + brnd(&l->w) % (hi - lo + 1) : lo; }
static uint64_t p2_bins(struct lworld *l, const uint64_t *lo, const uint64_t *hi, const unsigned *wt)
{
    const unsigned r = (unsigned)(brnd(&l->w) % 100);
    const unsigned b = r < wt[0] ? 0 : r < wt[0] + wt[1] ? 1 : 2;
    return p2_rnd(l, lo[b], hi[b]);
}
static uint64_t p2_exp(struct lworld *l, uint64_t mean)
{
    const double u = (double)((brnd(&l->w) & 0xffffffu) + 1u) / 16777217.0;
    return (uint64_t)(-log(u) * (double)mean) + 1;
}
/* a flight's marks: EP1 at the end of its FROM_DEVICE, else at the post after the unlock */
static void p2_marks(struct lworld *l, uint32_t id, uint64_t fin, uint64_t unlock)
{
    if (id && id < LMAX) l->fin_end[id] = l->early ? fin : unlock + P2_POST;
}
/* pipelineArm: only when a flight is on and the timer is not armed; the urgent period while the relatch waits */
static void p2_arm(struct lworld *l, uint64_t from)
{
    if (!l->fl_on || l->tmr_at != LINF) return;
    l->tmr_at = from + (l->urgent && l->urgent_period ? l->urgent_period : l->tmr_period) + p2_rnd(l, 0, P2_LEEWAY);
}
static void p2_timer(struct lworld *l)                       /* pipelineTimerFired */
{
    const uint64_t t0 = l->tmr_at;
    l->tmr_at = LINF;
    const uint64_t a = t0 > l->lock_free ? t0 : l->lock_free;
    if (!l->fl_on) return;                                   /* finished meanwhile: nothing to poll, not re-armed */
    l->c_polls++;
    if (l->fl_end <= a) {                                    /* final: FROM_DEVICE and the retirement under the lock */
        const uint64_t fin = a + P2_POLL + l->fl_f;
        p2_marks(l, l->fl_id, fin, fin);
        l->fl_on = 0; l->lock_free = fin; l->c_tmr++;
        return;
    }
    l->lock_free = a + P2_POLL;
    p2_arm(l, l->lock_free);
}
/* A submitter's TO_DEVICE of `b` from t: EP2 before it, EP3 inside it. A flight finished here: *done_id, *done_fin. */
static uint64_t p2_begin(struct lworld *l, uint64_t t, uint64_t b, uint32_t *done_id, uint64_t *done_fin)
{
    if (l->early && l->fl_on && l->fl_end <= t) {            /* EP2: one POLL; final: finish it first */
        t += P2_POLL + l->fl_f;
        *done_id = l->fl_id; *done_fin = t; l->fl_on = 0; l->c_pre++; l->c_polls++;
        return t + b;
    }
    if (l->early && l->assist && l->fl_on) {                 /* EP3: a POLL at most every `assist`, between entries */
        uint64_t poll = t + l->assist + p2_rnd(l, 0, P2_ENTRY);
        while (poll < l->fl_end && poll < t + b) { poll += l->assist + p2_rnd(l, 0, P2_ENTRY); l->c_polls++; }
        if (poll < t + b) {
            const uint64_t fin = poll + P2_POLL + l->fl_f;
            *done_id = l->fl_id; *done_fin = fin; l->fl_on = 0; l->c_ast++; l->c_polls++;
            return t + b + P2_POLL + l->fl_f;
        }
    }
    return t + b;
}
static void p2_ws_enter(struct lworld *l)                    /* submitIB for WindowServer (pipelined) */
{
    const uint32_t id = l->enter_id;
    uint64_t e = l->enter_at, t = 0;
    l->enter_at = LINF;
    /* a frame of two command buffers: the second's submission enters uq after the first returned; the swap's surface
     * stays marked until the last one's finish (the first's finish changes nothing for the display) */
    const unsigned n = l->multi_pct && brnd(&l->w) % 100 < l->multi_pct ? 2 : 1;
    for (unsigned k = 0; k < n; k++) {
        const int last = k + 1 == n;
        uint32_t done_id = 0, old_id = 0; uint64_t done_fin = 0, old_fin = 0, start;
        t = e > l->lock_free ? e : l->lock_free;
        t = p2_begin(l, t, p2_rnd(l, l->b_lo, l->b_hi), &done_id, &done_fin);
        if (l->fl_on) {                                      /* Q1: its final reply, START, then finish it */
            l->c_ovl++;
            if (l->fl_end > t) t = l->fl_end;
            t += p2_rnd(l, 0, P2_SPIN);
            start = t + P2_START;
            old_id = l->fl_id; old_fin = start + P2_POLL + l->fl_f;
            t = old_fin;
        } else {
            start = t + P2_START;
            t = start;
        }
        const uint64_t g = p2_bins(l, l->g_lo, l->g_hi, l->g_w);
        if (last) { l->ib_start[id] = start; l->ib_end[id] = start + g; l->fin_end[id] = LINF; }
        l->fl_on = 1; l->fl_id = last ? id : 0; l->fl_end = start + g; l->fl_f = p2_rnd(l, l->f_lo, l->f_hi);
        l->lock_free = t;
        p2_marks(l, done_id, done_fin, t);
        p2_marks(l, old_id, old_fin, t);
        p2_arm(l, t + P2_POST);
        e = t + P2_POST + p2_rnd(l, l->uq_min, l->uq_max);
    }
    l->ret_at[id] = t + P2_POST;
    l->render_done = l->ret_at[id];                          /* S: commitAndWaitUntilSubmitted returns */
    l->gpu_frames++;
}
static void p2_app(struct lworld *l)                         /* submitIB for another client */
{
    const uint64_t x = l->app_at;
    l->app_at = x + p2_exp(l, l->app_mean);
    l->c_apps++;
    uint64_t t = x > l->lock_free ? x : l->lock_free;
    uint32_t done_id = 0, old_id = 0; uint64_t done_fin = 0, old_fin = 0;
    t = p2_begin(l, t, l->app_b, &done_id, &done_fin);
    const uint64_t g = p2_bins(l, l->app_lo, l->app_hi, l->app_w);
    if (l->fl_on) {                                          /* the flight first (Q1) */
        if (l->fl_end > t) t = l->fl_end;
        t += p2_rnd(l, 0, P2_SPIN);
        old_id = l->fl_id; old_fin = t + P2_POLL + l->fl_f;
        t = old_fin; l->fl_on = 0; l->c_app++;
    }
    if (!l->app_pipe) {
        t += P2_START + g + p2_rnd(l, 0, P2_SPIN) + l->app_f;  /* its own IB, polled to the end, and its FROM_DEVICE */
    } else {                                                 /* adreno_pipeline=2: the app's IB is the flight */
        const uint64_t start = t + P2_START;
        if (old_id && !l->early) old_fin = start + P2_POLL + l->fl_f;   /* finished after START, as Q1 does */
        t = start;
        l->fl_on = 1; l->fl_id = 0; l->fl_end = start + g; l->fl_f = l->app_f;
    }
    l->lock_free = t;
    l->app_from = x; l->app_until = t + P2_POST;             /* G1: in the kext from its entry to its return */
    p2_marks(l, done_id, done_fin, t);
    p2_marks(l, old_id, old_fin, t);
    p2_arm(l, t + P2_POST);
}

/* ---- the relatch: AdrenoDisplay's relatchArmGated / relatchFireGated / relatchEndGated ---- */
static void p2_relatch_end(struct lworld *l, int tick)
{
    if (l->rl.pending) { if (tick) adreno_relatch_tick(&l->rl); else adreno_relatch_cancel(&l->rl); }
    l->rl_at = LINF; l->urgent = 0;
}
static void p2_relatch_sched(struct lworld *l)
{
    struct bworld *w = &l->w;
    const uint64_t poll = tb_ns(w, w->tb_off + l->rl.poll), d = l->rl.open ? poll : poll > MS ? poll : MS;
    l->rl_at = bfire(w, w->now, w->now + d - d / 9);         /* armed early by the slop (relatchScheduleGated) */
}
static void p2_relatch_arm(struct lworld *l)
{
    struct bworld *w = &l->w;
    if (!l->rl_on || !l->rl_cand || !l->qn || l->q[0].id != l->rl_cand || l->cur || l->h.enabled ||
        w->b.state != ADRENO_BEAM_LOCKED || !w->b.go_row0)
        return;
    adreno_relatch_arm(&l->rl, &w->b, (const void *)(uintptr_t)(l->rl_cand + 1u), l->rl_cand, w->b.go_row0, tb(w, w->now));
    if (l->rl.enabled) l->urgent = 1;
    p2_relatch_sched(l);
}
static void p2_relatch_poll(struct lworld *l)
{
    struct bworld *w = &l->w;
    l->rl_at = LINF;
    if (!l->rl.pending) return;
    if (l->cur || !l->qn || w->b.state != ADRENO_BEAM_LOCKED) { l->rl.gone++; p2_relatch_end(l, 0); return; }
    uint64_t now = 0;
    const uint64_t pos = adreno_beam_sample(&w->b, bio(w), &now);
    if (!pos || w->b.state != ADRENO_BEAM_LOCKED) { l->rl.gone++; p2_relatch_end(l, 0); return; }
    const uint32_t id = l->q[0].id;
    const uint32_t writers = (l->q[0].layers & 1) && id < LMAX && l->g_enter[id] && w->now >= l->g_enter[id] &&
                             w->now < l->fin_end[id];
    int d = adreno_relatch_check(&l->rl, (const void *)(uintptr_t)(id + 1u), id, pos, writers, now);
    if (d == ADRENO_RELATCH_GO && l_gate(l)) { adreno_relatch_gated(&l->rl); d = ADRENO_RELATCH_WAIT; }
    if (d == ADRENO_RELATCH_WAIT) { if (!l->rl.open) l->urgent = 0; p2_relatch_sched(l); return; }
    l->urgent = 0;
    if (d != ADRENO_RELATCH_GO) return;
    const uint64_t row0 = l->rl.row0, ovt = w->b.ovt, since = l->rl.since;
    w->b.go_row0 = row0;
    w->in_tick = 1;
    l_swap_begin(l, 1);
    w->in_tick = 0;
    const int copied = !w->b.go_row0 && l->cur && l->presented;
    w->b.go_row0 = 0;
    adreno_relatch_copied(&l->rl, copied, row0 > pos ? adreno_beam_ticks(&w->b, row0 - pos) : 0, now > since ? now - since : 0,
                          w->b.ovt - ovt);
}

/* ---- units: AdrenoDisplayRelatch.h ---- */
static uint64_t rl_ns(uint64_t x) { return x; }
static void relatch_units(void)
{
    static struct bworld g;
    bworld_init(&g, BEAM, 59.51, 67); scan_init(&g.s, 59.51, 3840); g.s.regs = a16_regs(); g.s.base = 1;
    bworld_start(&g);
    CHECK(g.b.state == ADRENO_BEAM_LOCKED);
    const uint64_t ms = tb_ms(&g), vt = g.b.t.vtotal;
    adreno_beam_latch(&g.b, 3 * ms);
    /* RL1: the deadline is the latch's limit less the head and the guard, over every phase; the slack's raise moves it */
    for (uint64_t ph = 0; ph < vt; ph += 41) {
        const uint64_t row0 = 100 * vt + g.b.t.a0 + ph % 7;
        const uint64_t last = adreno_relatch_last_pos(&g.b, row0, ms);
        CHECK(last + g.b.margin + 2 + adreno_beam_head(&g.b) + adreno_beam_lines(&g.b, ms) == row0);
        CHECK(adreno_relatch_last_pos(&g.b, row0, 0) > last);
        adreno_beam_slack_raise(&g.b);
        CHECK(adreno_relatch_last_pos(&g.b, row0, ms) < last);   /* after an overtake: earlier */
        adreno_beam_latch(&g.b, 3 * ms);
    }
    /* RL2 RL3: GO only released and before the deadline; WAIT while written; GONE on another pointer or ID; DONE in
     * measure mode; the histogram counts a release once */
    struct adreno_relatch r; adreno_relatch_init(&r, 1, 200 * ms / 1000, ms, ms);
    int a = 1, b = 2;
    adreno_relatch_arm(&r, &g.b, &a, 7, 1000000, 50 * ms);
    CHECK(r.pending && r.open && r.armed == 1 && r.last_pos < 1000000);
    CHECK(adreno_relatch_check(&r, &a, 7, r.last_pos - 100, 1, 51 * ms) == ADRENO_RELATCH_WAIT && r.polls == 1);
    adreno_relatch_gated(&r);
    CHECK(adreno_relatch_check(&r, &a, 7, r.last_pos - 50, 0, 52 * ms + 1) == ADRENO_RELATCH_GO && r.hist[2] == 1);
    adreno_relatch_copied(&r, 1, 3 * ms, 2 * ms, 0);
    CHECK(!r.pending && r.go == 1 && r.lead_min == 3 * ms && r.gated == 1);
    adreno_relatch_arm(&r, &g.b, &a, 8, 1000000, 60 * ms);
    CHECK(adreno_relatch_check(&r, &b, 8, 10, 0, 61 * ms) == ADRENO_RELATCH_GONE && r.gone == 1 && !r.pending);
    adreno_relatch_arm(&r, &g.b, &a, 9, 1000000, 70 * ms);
    CHECK(adreno_relatch_check(&r, &a, 10, 10, 0, 71 * ms) == ADRENO_RELATCH_GONE && r.gone == 2);
    adreno_relatch_arm(&r, &g.b, &a, 11, 1000000, 80 * ms);
    CHECK(adreno_relatch_check(&r, &a, 11, r.last_pos, 1, 84 * ms) == ADRENO_RELATCH_WAIT && !r.open && r.late == 1);
    CHECK(adreno_relatch_check(&r, &a, 11, r.last_pos + 99, 0, 87 * ms) == ADRENO_RELATCH_DONE && r.hist[5] == 1);
    adreno_relatch_arm(&r, &g.b, &a, 12, 1000000, 90 * ms);
    adreno_relatch_tick(&r);
    CHECK(!r.pending && r.hist[ADRENO_RELATCH_BINS - 1] == 1 && r.late == 2);
    struct adreno_relatch m; adreno_relatch_init(&m, 0, ms / 5, ms, ms);  /* measure only: never GO */
    adreno_relatch_arm(&m, &g.b, &a, 3, 1000000, 10 * ms);
    CHECK(adreno_relatch_check(&m, &a, 3, 5, 0, 10 * ms + 1) == ADRENO_RELATCH_DONE && m.hist[0] == 1 && !m.go);
    /* OP1: the perf relatch line at its caps, and parsed back */
    char line[512]; struct adreno_relatch_summary big; memset(&big, 0xff, sizeof big);
    int n = adreno_perf_line_relatch(line, sizeof line, ~0ull, &big);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    printf("relatch perf line at caps: %d bytes\n", n);
    struct adreno_relatch_summary s;
    const uint64_t early[ADRENO_RELATCH_EARLY_FIELDS] = {5, 6, 70, 80};
    adreno_relatch_summarize(&r, rl_ns, 7, early, &s);
    n = adreno_perf_line_relatch(line, sizeof line, 3, &s);
    CHECK(!strcmp(line, "AdrenoDisplay: perf relatch s=3 on=7 arm=5 go=1 late=2 gone=2 gate=1 polls=4 ovt=0 lead=3000/3000 "
                        "wait=2000 rel=0/0/1/0/0/1/0/1 ef=5/6/70 unm=80"));
    printf("%s\n", line);
    adreno_relatch_next_window(&r);
    CHECK(!r.armed && !r.go && !r.hist[2]);
}

/* ---- the scenarios ---- */
struct rcase {
    const char *name; int ws; uint64_t r_min, r_max; unsigned g_pct;
    uint64_t g_lo[3], g_hi[3]; unsigned g_w[3];               /* WindowServer's GPU per IB */
    uint64_t b_lo, b_hi, f_lo, f_hi;                          /* its TO_DEVICE and FROM_DEVICE */
    uint64_t app_mean, a_lo[3], a_hi[3]; unsigned a_w[3]; uint64_t a_b, a_f;   /* app IBs: mean gap, GPU, cache */
    unsigned stall_pct; uint64_t stall_min, stall_max;        /* copy stalls (the beam world's) */
    unsigned multi_pct;                                       /* frames with two command buffers */
};
enum { RP_TODAY = 0, RP_RELATCH, RP_RELATCH_NOURGENT, RP_EARLY, RP_EARLY_NOASSIST, RP_ALL, RP_ALL_PIPE2, RP_N };
static const char *const rp_name[] = {"today", "relatch", "relatch_nourgent", "early", "early_noassist", "all", "all_pipe2"};
struct rres {
    struct lres r;
    uint64_t copies, iv[5], over34_pm, cps_x10, defer, swaps, max_wait_us, gpu_frames, marked, apps;
    uint64_t ovl, tmr, pre, ast, app_fin, polls, rl_armed, rl_go, rl_late, rl_gone, rl_gated, rl_ovt, rl_polls, rl_lead_min_us;
    uint64_t hist[ADRENO_RELATCH_BINS];
#if ADRENO_PRESENT_EARLY_DONE
    struct adreno_early_done ed;                              /* the run's early completions and arrivals (not windowed) */
#endif
};
static FILE *RJ; static int rfirst;
#if ADRENO_PRESENT_EARLY_DONE
/* replay-adreno-early-done.c's knobs, all 0 for every row above (their outputs stay byte for byte as without the define):
 * the swap completed right after its copy (lworld complete_at_copy, AdrenoDisplay's adreno_present_early_done=1),
 * WindowServer's render spikes, and EP3's assist off (the deployed sparse kext compiles it out). */
static int rcase_copydone, rcase_noassist;
static unsigned rcase_spike_pct;
static uint64_t rcase_spike_min, rcase_spike_max, rcase_ed_hold;
#endif
static struct rres r_case(const struct rcase *c, int rp, unsigned swaps, uint64_t guard_us, unsigned seed, const char *tag)
{
    static struct lworld l;
    l_init(&l, LP_LATCH, c->ws, 59.51, 3840, 4242 + (uint64_t)c->g_pct * 13 + (uint64_t)c->ws * 5 + c->b_hi / US + seed * 7919);
    l.r_min = c->r_min; l.r_max = c->r_max;
    l.g_pct = c->g_pct; l.uq_min = 50 * US; l.uq_max = 500 * US;
    for (unsigned b = 0; b < 3; b++) {
        l.g_lo[b] = c->g_lo[b]; l.g_hi[b] = c->g_hi[b]; l.g_w[b] = c->g_w[b];
        l.app_lo[b] = c->a_lo[b]; l.app_hi[b] = c->a_hi[b]; l.app_w[b] = c->a_w[b];
    }
    l.s_wait = 1; l.k_gate = 1; l.pipe = 1; l.p2 = 1;
    adreno_sync_gate_init(&l.sg, 1100 * MS, 2000 * MS);
    l.b_lo = c->b_lo; l.b_hi = c->b_hi; l.f_lo = c->f_lo; l.f_hi = c->f_hi;
    l.app_mean = c->app_mean; l.app_b = c->a_b; l.app_f = c->a_f; l.app_pipe = rp == RP_ALL_PIPE2;
    const int relatch = rp == RP_RELATCH || rp == RP_RELATCH_NOURGENT || rp == RP_ALL || rp == RP_ALL_PIPE2;
    l.early = rp == RP_EARLY || rp == RP_EARLY_NOASSIST || rp == RP_ALL || rp == RP_ALL_PIPE2;
    l.assist = l.early && rp != RP_EARLY_NOASSIST ? 250 * US : 0;
    l.tmr_period = 500 * US; l.urgent_period = relatch && rp != RP_RELATCH_NOURGENT ? 100 * US : 0;
#if ADRENO_PRESENT_EARLY_DONE
    l.complete_at_copy = rcase_copydone; l.ed_hold = rcase_ed_hold;
    l.spike_pct = rcase_spike_pct; l.spike_min = rcase_spike_min; l.spike_max = rcase_spike_max;
    if (rcase_noassist) l.assist = 0;
#endif
    l.multi_pct = c->multi_pct;
    l.w.stall_pct = c->stall_pct; l.w.stall_min = c->stall_min; l.w.stall_max = c->stall_max;
    l.tmr_at = l.enter_at = l.rl_at = LINF;
    l_start(&l);
    l.app_at = c->app_mean ? l.w.now + p2_exp(&l, c->app_mean) : LINF;
    l.rl_on = 1;
    const uint64_t ms = tb_ms(&l.w);
    adreno_relatch_init(&l.rl, relatch, ms / 5, guard_us * ms / 1000, ms);
    l_run(&l, swaps);
    struct rres x; memset(&x, 0, sizeof x);
    x.r = l_summary(&l);
    /* copy intervals of WindowServer's swaps (the kext's pace buckets: <= 17, 20, 34, 50 ms, more) */
    uint64_t prev = 0, first = 0, last = 0, min_iv = UINT64_MAX;
    for (uint32_t k = 1; k < LMAX && k <= l.next_id; k++) {
        if (!l.copied[k]) continue;
        const uint64_t t = l.copy_ns[k];
        if (!first) first = t;
        last = t; x.copies++;
        if (prev && t > prev) {
            const uint64_t d = t - prev;
            if (d < min_iv) min_iv = d;
            x.iv[d <= 17 * MS ? 0 : d <= 20 * MS ? 1 : d <= 34 * MS ? 2 : d <= 50 * MS ? 3 : 4]++;
        }
        prev = t;
    }
    const uint64_t n = x.iv[0] + x.iv[1] + x.iv[2] + x.iv[3] + x.iv[4];
    x.over34_pm = n ? (x.iv[3] + x.iv[4]) * 1000 / n : 0;
    x.cps_x10 = last > first && x.copies > 1 ? (x.copies - 1) * 10000000000ull / (last - first) : 0;
    x.defer = l.sg.defer; x.swaps = l.sg.swaps; x.max_wait_us = l.sg.max_waited / 1000; x.gpu_frames = l.gpu_frames;
    x.marked = l.c_late_unmark; x.apps = l.c_apps; x.ovl = l.c_ovl; x.tmr = l.c_tmr; x.pre = l.c_pre; x.ast = l.c_ast;
    x.app_fin = l.c_app; x.polls = l.c_polls;
    x.rl_armed = l.rl.armed; x.rl_go = l.rl.go; x.rl_late = l.rl.late; x.rl_gone = l.rl.gone; x.rl_gated = l.rl.gated;
    x.rl_ovt = l.rl.ovt; x.rl_polls = l.rl.polls; x.rl_lead_min_us = tb_ns(&l.w, l.w.tb_off + l.rl.lead_min) / 1000;
    memcpy(x.hist, l.rl.hist, sizeof x.hist);
#if ADRENO_PRESENT_EARLY_DONE
    x.ed = l.ed;
#endif
    char name[128]; snprintf(name, sizeof name, "%s_%s_%s%s", c->name, ws_name[c->ws], rp_name[rp], tag ? tag : "");
    const struct lres *r = &x.r;
    fprintf(RJ, "%s\"%s\":{\"frames\":%llu,\"torn\":%llu,\"ovt\":%llu,\"beam_forced\":%llu,\"fps_x10\":%llu,\"copies_x10\":%llu,"
            "\"intervals\":[%llu,%llu,%llu,%llu,%llu],\"over34_permille\":%llu,\"q_us\":%llu,\"input_mean_us\":%llu,"
            "\"input_p95_us\":%llu,\"max_stall_ms\":%llu,\"order_errors\":%llu,\"deadlock\":%llu,\"unfinished\":%llu,"
            "\"copied_marked\":%llu,\"sync_defer\":%llu,\"sync_swaps\":%llu,\"sync_forced\":%llu,\"sync_max_wait_us\":%llu,"
            "\"gpu_frames\":%llu,\"app_ibs\":%llu,\"overlapped\":%llu,\"timer_finishes\":%llu,\"early_finishes\":%llu,"
            "\"assist_finishes\":%llu,\"app_finishes\":%llu,\"polls\":%llu,\"relatch\":{\"armed\":%llu,\"go\":%llu,"
            "\"late\":%llu,\"gone\":%llu,\"gated\":%llu,\"ovt\":%llu,\"polls\":%llu,\"lead_min_us\":%llu,"
            "\"release_ms_bins\":[%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu]}}",
            rfirst++ ? "," : "", name, (unsigned long long)r->frames, (unsigned long long)r->torn, (unsigned long long)r->ovt,
            (unsigned long long)r->forced, (unsigned long long)r->fps_x10, (unsigned long long)x.cps_x10,
            (unsigned long long)x.iv[0], (unsigned long long)x.iv[1], (unsigned long long)x.iv[2], (unsigned long long)x.iv[3],
            (unsigned long long)x.iv[4], (unsigned long long)x.over34_pm, (unsigned long long)r->q_us,
            (unsigned long long)r->in_mean_us, (unsigned long long)r->in_p95_us, (unsigned long long)r->max_stall_ms,
            (unsigned long long)r->order_errors, (unsigned long long)r->deadlock, (unsigned long long)r->stale,
            (unsigned long long)x.marked, (unsigned long long)x.defer, (unsigned long long)x.swaps,
            (unsigned long long)l.sg.forced, (unsigned long long)x.max_wait_us, (unsigned long long)x.gpu_frames,
            (unsigned long long)x.apps, (unsigned long long)x.ovl, (unsigned long long)x.tmr, (unsigned long long)x.pre,
            (unsigned long long)x.ast, (unsigned long long)x.app_fin, (unsigned long long)x.polls,
            (unsigned long long)x.rl_armed, (unsigned long long)x.rl_go, (unsigned long long)x.rl_late,
            (unsigned long long)x.rl_gone, (unsigned long long)x.rl_gated, (unsigned long long)x.rl_ovt,
            (unsigned long long)x.rl_polls, (unsigned long long)x.rl_lead_min_us, (unsigned long long)x.hist[0],
            (unsigned long long)x.hist[1], (unsigned long long)x.hist[2], (unsigned long long)x.hist[3],
            (unsigned long long)x.hist[4], (unsigned long long)x.hist[5], (unsigned long long)x.hist[6],
            (unsigned long long)x.hist[7]);
    printf("pacing %-34s fps %3llu.%llu copies/s %3llu.%llu >34ms %3llu.%llu%% iv %llu/%llu/%llu/%llu/%llu defer %4llu "
           "q %5llu us input %6llu us; ovl %llu tmr %llu pre %llu ast %llu app %llu/%llu; relatch %llu/%llu late %llu "
           "gate %llu ovt %llu lead %llu us; rel %llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu; torn %llu/%llu stall %llu ms%s%s\n",
           name, (unsigned long long)r->fps_x10 / 10, (unsigned long long)r->fps_x10 % 10,
           (unsigned long long)x.cps_x10 / 10, (unsigned long long)x.cps_x10 % 10,
           (unsigned long long)x.over34_pm / 10, (unsigned long long)x.over34_pm % 10,
           (unsigned long long)x.iv[0], (unsigned long long)x.iv[1], (unsigned long long)x.iv[2], (unsigned long long)x.iv[3],
           (unsigned long long)x.iv[4], (unsigned long long)x.defer, (unsigned long long)r->q_us,
           (unsigned long long)r->in_mean_us, (unsigned long long)x.ovl, (unsigned long long)x.tmr,
           (unsigned long long)x.pre, (unsigned long long)x.ast, (unsigned long long)x.app_fin, (unsigned long long)x.apps,
           (unsigned long long)x.rl_go, (unsigned long long)x.rl_armed, (unsigned long long)x.rl_late,
           (unsigned long long)x.rl_gated, (unsigned long long)x.rl_ovt, (unsigned long long)x.rl_lead_min_us,
           (unsigned long long)x.hist[0], (unsigned long long)x.hist[1], (unsigned long long)x.hist[2],
           (unsigned long long)x.hist[3], (unsigned long long)x.hist[4], (unsigned long long)x.hist[5],
           (unsigned long long)x.hist[6], (unsigned long long)x.hist[7], (unsigned long long)r->torn,
           (unsigned long long)r->ovt, (unsigned long long)r->max_stall_ms, r->deadlock ? " DEADLOCK" : "",
           r->order_errors ? " ORDER" : "");
    /* every run (RL1 RL2 RL4, D1 D2): counted tears only, nothing copied while marked or unfinished, nothing forced,
     * completions in order, no deadlock, most swaps shown */
    CHECK(r->torn <= r->ovt + r->forced);
    CHECK(r->stale == 0 && x.marked == 0 && l.sg.forced == 0);
    CHECK(r->order_errors == 0);
    CHECK(!r->deadlock);
    CHECK(r->shown > swaps / 2);
    CHECK(min_iv > 8 * MS);                                  /* RL4: one layer-0 copy per refresh at most */
    if (!relatch) CHECK(x.rl_go == 0);                       /* measure only */
    return x;
}

static void relatch_scenarios(const char *dir)
{
    unsigned c0 = checks, f0 = failures, cc0 = cost_checks, cf0 = cost_failures;
    char path[4096]; snprintf(path, sizeof path, "%s/relatch.json", dir);
    RJ = fopen(path, "w"); assert(RJ);
    fprintf(RJ, "{\"scenarios\":{");
    relatch_units();
    const uint64_t M = MS;
    /* b12v17 (analysis/b12v17-windows.txt; targets in brackets):
     * - heavy (s=5/6) [34-37 pps, 17-21% of intervals over 34 ms, deferrals 15-18% of copies, q 13.6-13.8 ms, ovl 11%]:
     *   half the frames carry an IB, WindowServer's IB 3.7-4.8 ms mean with a tail, nosparse cache 21 ms per IB with the
     *   lock held a third of the time: TO_DEVICE 10-20 ms, FROM_DEVICE 2-5 ms; 15-44 app IBs per 17 s (gtk max 25-36 ms);
     * - medium (s=25-30) [33-48 pps, 4.5-26%, deferrals 4-11%, q 8.4-12 ms, ovl 28-39%]: every frame, 1.5 flights per
     *   copy, 3 ms IBs, cache 7-7.5 ms per IB (TO 4-8, FROM 1-2), up to 109 app IBs per 18 s;
     * - light (s=31-36) [44-55 pps, 0.7-5%, deferrals 1-12%, q 5.9-9.9 ms]: one 1.2 ms IB per frame, cache 2.8-3.9 ms per
     *   IB, no app IB, WindowServer's frame later in the refresh (q);
     * - stalls: heavy with 5% of the copies stalling 1-6 ms in one chunk (RL1, tear-free). */
    const struct rcase cases[] = {
        {"b12v17_heavy", WS_SLOT, 2 * M, 6 * M, 50, {1 * M, 3 * M, 8 * M}, {3 * M, 8 * M, 25 * M}, {55, 35, 10},
         10 * M, 20 * M, 2 * M, 5 * M, 600 * M, {5 * M, 15 * M, 25 * M}, {15 * M, 25 * M, 36 * M}, {60, 30, 10}, 3 * M, 1 * M,
         0, 0, 0, 0},
        {"b12v17_heavy", WS_FREE, 2 * M, 6 * M, 50, {1 * M, 3 * M, 8 * M}, {3 * M, 8 * M, 25 * M}, {55, 35, 10},
         10 * M, 20 * M, 2 * M, 5 * M, 600 * M, {5 * M, 15 * M, 25 * M}, {15 * M, 25 * M, 36 * M}, {60, 30, 10}, 3 * M, 1 * M,
         0, 0, 0, 0},
        {"b12v17_medium", WS_SLOT, 4 * M, 8 * M, 100, {1 * M, 3 * M, 6 * M}, {3 * M, 6 * M, 15 * M}, {55, 35, 10},
         4 * M, 8 * M, 1 * M, 2 * M, 165 * M, {2 * M, 5 * M, 10 * M}, {5 * M, 10 * M, 20 * M}, {60, 30, 10}, 2 * M, 500 * US,
         0, 0, 0, 50},
        {"b12v17_medium", WS_FREE, 4 * M, 8 * M, 100, {1 * M, 3 * M, 6 * M}, {3 * M, 6 * M, 15 * M}, {55, 35, 10},
         4 * M, 8 * M, 1 * M, 2 * M, 165 * M, {2 * M, 5 * M, 10 * M}, {5 * M, 10 * M, 20 * M}, {60, 30, 10}, 2 * M, 500 * US,
         0, 0, 0, 50},
        {"b12v17_light", WS_SLOT, 7 * M, 11 * M, 100, {900 * US, 900 * US, 900 * US}, {1500 * US, 1500 * US, 1500 * US},
         {100, 0, 0}, 2 * M, 3500 * US, 500 * US, 1 * M, 0, {0, 0, 0}, {0, 0, 0}, {100, 0, 0}, 0, 0, 0, 0, 0, 0},
        {"b12v17_stalls", WS_SLOT, 2 * M, 6 * M, 50, {1 * M, 3 * M, 8 * M}, {3 * M, 8 * M, 25 * M}, {55, 35, 10},
         10 * M, 20 * M, 2 * M, 5 * M, 600 * M, {5 * M, 15 * M, 25 * M}, {15 * M, 25 * M, 36 * M}, {60, 30, 10}, 3 * M, 1 * M,
         5, 1 * M, 6 * M, 0},
    };
    const unsigned ncases = sizeof cases / sizeof cases[0];
    for (unsigned i = 0; i < ncases; i++) {
        const struct rcase *c = &cases[i];
        struct rres x[RP_N];
        for (int rp = 0; rp < RP_N; rp++) x[rp] = r_case(c, rp, 1500, 1000, 0, NULL);
        const struct rres *today = &x[RP_TODAY], *all = &x[RP_ALL];
        /* RL1: the relatch adds no torn frame over the latch's own (the stall world's tears are the latch's: noise +-2) */
        if (!c->stall_pct) CHECK(x[RP_RELATCH].r.torn == today->r.torn && all->r.torn == today->r.torn);
        /* never fewer copies; with deferrals to rescue, the relatch copies some and long intervals do not grow */
        if (!c->stall_pct) {
            COST(all->cps_x10 * 100 >= today->cps_x10 * 99);
            if (today->defer > 20) {
                COST(x[RP_RELATCH].rl_go > 0);
                COST(all->over34_pm <= today->over34_pm + 2);
            }
        }
        printf("pacing %s_%s: copies/s today %llu.%llu -> relatch %llu.%llu (no urgent %llu.%llu), early %llu.%llu "
               "(no assist %llu.%llu), all %llu.%llu (pipe2 %llu.%llu); >34 ms today %llu.%llu%% -> relatch %llu.%llu%%, early "
               "%llu.%llu%%, all %llu.%llu%%; deferrals today %llu, all %llu, relatched %llu of %llu\n",
               c->name, ws_name[c->ws], (unsigned long long)today->cps_x10 / 10, (unsigned long long)today->cps_x10 % 10,
               (unsigned long long)x[RP_RELATCH].cps_x10 / 10, (unsigned long long)x[RP_RELATCH].cps_x10 % 10,
               (unsigned long long)x[RP_RELATCH_NOURGENT].cps_x10 / 10, (unsigned long long)x[RP_RELATCH_NOURGENT].cps_x10 % 10,
               (unsigned long long)x[RP_EARLY].cps_x10 / 10, (unsigned long long)x[RP_EARLY].cps_x10 % 10,
               (unsigned long long)x[RP_EARLY_NOASSIST].cps_x10 / 10, (unsigned long long)x[RP_EARLY_NOASSIST].cps_x10 % 10,
               (unsigned long long)all->cps_x10 / 10, (unsigned long long)all->cps_x10 % 10,
               (unsigned long long)x[RP_ALL_PIPE2].cps_x10 / 10, (unsigned long long)x[RP_ALL_PIPE2].cps_x10 % 10,
               (unsigned long long)today->over34_pm / 10, (unsigned long long)today->over34_pm % 10,
               (unsigned long long)x[RP_RELATCH].over34_pm / 10, (unsigned long long)x[RP_RELATCH].over34_pm % 10,
               (unsigned long long)x[RP_EARLY].over34_pm / 10, (unsigned long long)x[RP_EARLY].over34_pm % 10,
               (unsigned long long)all->over34_pm / 10, (unsigned long long)all->over34_pm % 10,
               (unsigned long long)today->defer, (unsigned long long)all->defer, (unsigned long long)all->rl_go,
               (unsigned long long)all->rl_armed);
    }
    /* RL1, the guard: the stall world, three seeds, guards 0.5 / 1 / 1.5 / 2 ms against the latch alone (today): torn
     * frames and relatch copies that overtook */
    static const uint64_t guards[] = {500, 1000, 1500, 2000};
    uint64_t torn_today = 0;
    for (unsigned seed = 1; seed <= 3; seed++) torn_today += r_case(&cases[ncases - 1], RP_TODAY, 1500, 1000, seed, "_seed").r.torn;
    for (unsigned g = 0; g < sizeof guards / sizeof guards[0]; g++) {
        uint64_t torn = 0, ovt = 0, go = 0, cps = 0;
        for (unsigned seed = 1; seed <= 3; seed++) {
            char tag[48]; snprintf(tag, sizeof tag, "_guard%llu_seed%u", (unsigned long long)guards[g], seed);
            const struct rres x = r_case(&cases[ncases - 1], RP_ALL, 1500, guards[g], seed, tag);
            torn += x.r.torn; ovt += x.rl_ovt; go += x.rl_go; cps += x.cps_x10;
        }
        printf("pacing guard %llu us (stalls, 3 seeds): torn %llu (latch alone %llu), relatch copies %llu, of which overtook %llu; "
               "copies/s %llu.%llu\n", (unsigned long long)guards[g], (unsigned long long)torn, (unsigned long long)torn_today,
               (unsigned long long)go, (unsigned long long)ovt, (unsigned long long)cps / 30, (unsigned long long)cps / 3 % 10);
        if (guards[g] >= 1000) COST(torn <= torn_today + 3);
    }
    /* what-if (no checks): the heavy load with the light windows' cache cost (TO_DEVICE 2-3.5 ms, FROM_DEVICE 0.5-1 ms per
     * IB), i.e. what is left once WindowServer's nosparse maintenance is small; today and all */
    {
        struct rcase c = cases[0];
        c.name = "b12v17_heavy_smallcache"; c.b_lo = 2 * M; c.b_hi = 3500 * US; c.f_lo = 500 * US; c.f_hi = 1 * M;
        for (int ws = 0; ws < 2; ws++) {
            c.ws = ws ? WS_FREE : WS_SLOT;
            const struct rres t = r_case(&c, RP_TODAY, 1500, 1000, 0, NULL), a = r_case(&c, RP_ALL, 1500, 1000, 0, NULL);
            printf("pacing what-if %s_%s: copies/s today %llu.%llu -> all %llu.%llu; >34 ms today %llu.%llu%% -> all %llu.%llu%%\n",
                   c.name, ws_name[c.ws], (unsigned long long)t.cps_x10 / 10, (unsigned long long)t.cps_x10 % 10,
                   (unsigned long long)a.cps_x10 / 10, (unsigned long long)a.cps_x10 % 10,
                   (unsigned long long)t.over34_pm / 10, (unsigned long long)t.over34_pm % 10,
                   (unsigned long long)a.over34_pm / 10, (unsigned long long)a.over34_pm % 10);
        }
    }
    fprintf(RJ, "},\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", checks - c0, failures - f0,
            cost_checks - cc0, cost_failures - cf0);
    fclose(RJ);
    printf("{\"relatch_checks\":%u,\"relatch_failures\":%u,\"relatch_cost_checks\":%u,\"relatch_cost_failures\":%u}\n",
           checks - c0, failures - f0, cost_checks - cc0, cost_failures - cf0);
}
#if ADRENO_PRESENT_EARLY_DONE
#include "replay-adreno-early-done.c"
#endif
#endif
