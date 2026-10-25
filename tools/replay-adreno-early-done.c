/* SPDX-License-Identifier: MIT */
/* Early completion (gpu/adreno-kext/kext/src/AdrenoDisplayEarlyDone.h): included at the end of
 * tools/replay-adreno-pacing.c under -DADRENO_PRESENT_EARLY_DONE=1, after relatch_scenarios. Without the define this
 * file adds nothing; with it every other output is byte for byte the define-off build's (the knobs below are 0 there).
 *
 * The world is the present-pacing one (the A16 beam and latch, the sync gate, the relatch, the pipelined submit lock,
 * app IBs) with the deployed kext's switches: relatch and urgent polling on, early release EP1/EP2 on, EP3's assist off
 * (the sparse kext compiles it out). AdrenoDisplay's early completion is mirrored step for step in
 * replay-adreno-latency.c (l_present, l_swap_begin's arrival, l_tick); mode 1 completes every layer-0 swap at its copy,
 * mode 2 only while a late frame engaged it (hold 2 s).
 *
 * Calibration (the 2026-10-24 desktop runs):
 * - busy: installed-fresh-desktop-20261024-org2's 117 busy windows (gfx-probe load): 49.9 copies/s median, 18% of the
 *   ticks without a new swap, q 6.2 ms, one 1.35 ms IB per frame, TO_DEVICE + FROM_DEVICE 3.4 ms per IB (98 MiB). Only
 *   input-latency's SLOT WindowServer (two swaps outstanding, the next frame when one completes) reproduces that rate,
 *   with a render time of 5-9 ms and 20% of the frames 14-30 ms (FREE gives 57-59 copies/s for the same frames).
 * - busy_coherent: the same frames with b12v23's maintenance (--gpu-coherent: 1.05 ms and 40 MiB per IB);
 * - quiet: the cursor moving over an idle desktop, a layer-0 swap every refresh and no IB (b12v20/b12v21: 59.8/s);
 * - sporadic: next2c's idle windows (57.9/s): the quiet frames plus 5% of frames with an IB whose kext time is 13 ms
 *   (TO_DEVICE 7 ms over 208 MiB and 6 ms of preparation) and 3.4 ms of GPU;
 * - sporadic_coherent: the same with the coherent maintenance (the preparation stays: 6.5-8.5 ms in the kext).
 * The model has no guest-wide stalls, so its intervals over 34 ms stay under the hardware's (org2: 5.4%). */
static void early_done_scenarios(const char *dir)
{
    unsigned c0 = checks, f0 = failures, cc0 = cost_checks, cf0 = cost_failures;
    char path[4096]; snprintf(path, sizeof path, "%s/early-done.json", dir);
    RJ = fopen(path, "w"); assert(RJ); rfirst = 0;
    fprintf(RJ, "{\"scenarios\":{");
    const uint64_t M = MS;
    struct ecase { struct rcase c; unsigned spike_pct; uint64_t spike_min, spike_max; };
    const struct ecase cases[] = {
        {{"busy", WS_SLOT, 5 * M, 9 * M, 100, {900 * US, 1400 * US, 3 * M}, {1400 * US, 3 * M, 8 * M}, {75, 23, 2},
          2200 * US, 3400 * US, 500 * US, 1 * M, 1200 * M, {1 * M, 3 * M, 10 * M}, {3 * M, 10 * M, 30 * M}, {80, 15, 5},
          1 * M, 300 * US, 2, 1 * M, 6 * M, 3}, 20, 14 * M, 30 * M},
        {{"busy_coherent", WS_SLOT, 5 * M, 9 * M, 100, {900 * US, 1400 * US, 3 * M}, {1400 * US, 3 * M, 8 * M}, {75, 23, 2},
          400 * US, 900 * US, 300 * US, 700 * US, 1200 * M, {1 * M, 3 * M, 10 * M}, {3 * M, 10 * M, 30 * M}, {80, 15, 5},
          1 * M, 300 * US, 2, 1 * M, 6 * M, 3}, 20, 14 * M, 30 * M},
        {{"busy", WS_FREE, 5 * M, 9 * M, 100, {900 * US, 1400 * US, 3 * M}, {1400 * US, 3 * M, 8 * M}, {75, 23, 2},
          2200 * US, 3400 * US, 500 * US, 1 * M, 1200 * M, {1 * M, 3 * M, 10 * M}, {3 * M, 10 * M, 30 * M}, {80, 15, 5},
          1 * M, 300 * US, 2, 1 * M, 6 * M, 3}, 20, 14 * M, 30 * M},
        {{"quiet", WS_SLOT, 2 * M, 3600 * US, 0, {0, 0, 0}, {0, 0, 0}, {100, 0, 0},
          0, 0, 0, 0, 0, {0, 0, 0}, {0, 0, 0}, {100, 0, 0}, 0, 0, 0, 0, 0, 0}, 0, 0, 0},
        {{"sporadic", WS_SLOT, 2 * M, 3600 * US, 5, {3 * M, 3 * M, 3 * M}, {4 * M, 4 * M, 4 * M}, {100, 0, 0},
          12 * M, 14 * M, 1 * M, 2 * M, 0, {0, 0, 0}, {0, 0, 0}, {100, 0, 0}, 0, 0, 0, 0, 0, 0}, 0, 0, 0},
        {{"sporadic_coherent", WS_SLOT, 2 * M, 3600 * US, 5, {3 * M, 3 * M, 3 * M}, {4 * M, 4 * M, 4 * M}, {100, 0, 0},
          6500 * US, 8500 * US, 300 * US, 700 * US, 0, {0, 0, 0}, {0, 0, 0}, {100, 0, 0}, 0, 0, 0, 0, 0, 0}, 0, 0, 0},
    };
    const unsigned ncases = sizeof cases / sizeof cases[0];
    for (unsigned i = 0; i < ncases; i++) {
        const struct ecase *e = &cases[i];
        struct rres x[3];
        for (int mode = 0; mode < 3; mode++) {
            char tag[32]; snprintf(tag, sizeof tag, "_done%d", mode);
            rcase_noassist = 1; rcase_copydone = mode; rcase_ed_hold = 2000 * M;
            rcase_spike_pct = e->spike_pct; rcase_spike_min = e->spike_min; rcase_spike_max = e->spike_max;
            x[mode] = r_case(&e->c, RP_ALL, 1500, 1000, 0, tag);
        }
        rcase_noassist = 0; rcase_copydone = 0; rcase_ed_hold = 0; rcase_spike_pct = 0; rcase_spike_min = rcase_spike_max = 0;
        const struct rres *t = &x[0], *a = &x[1], *d = &x[2];
        /* mode 0 measures only: nothing completed at a copy; the others never complete without a copy */
        CHECK(t->ed.early == 0 && t->ed.engages == 0);
        CHECK(a->ed.early <= a->copies && d->ed.early <= d->copies);
        CHECK(a->ed.engages == 0);                            /* mode 1 has nothing to engage */
        /* never fewer copies than today (1% noise) */
        COST(a->cps_x10 * 100 >= t->cps_x10 * 99 && d->cps_x10 * 100 >= t->cps_x10 * 99);
        if (e->c.ws == WS_SLOT && t->ed.late * 50 > t->copies) {
            /* WindowServer late on more than 2% of the frames: both modes recover most of the missed refreshes */
            COST(a->cps_x10 >= t->cps_x10 + 30 && d->cps_x10 >= t->cps_x10 + 25);
            COST(d->ed.engages > 0 && d->ed.early > 0);
        }
        if (!t->ed.late) {
            /* nothing late: the adaptive mode never engages and the run is today's frame for frame */
            COST(d->ed.engages == 0 && d->ed.early == 0 && d->cps_x10 == t->cps_x10 && d->r.in_mean_us == t->r.in_mean_us);
        }
        char line[512];
        int n = adreno_perf_line_done(line, sizeof line, i + 1, &d->ed, 0);
        CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
        printf("early-done %s_%s: copies/s today %llu.%llu, always %llu.%llu, adaptive %llu.%llu; >34 ms %llu.%llu%% / "
               "%llu.%llu%% / %llu.%llu%%; late frames today %llu of %llu copies; input mean %llu / %llu / %llu us, "
               "p95 %llu / "
               "%llu / %llu us; q %llu / %llu / %llu us; adaptive engaged %llu times, %llu of %llu copies completed early\n",
               e->c.name, ws_name[e->c.ws], (unsigned long long)t->cps_x10 / 10, (unsigned long long)t->cps_x10 % 10,
               (unsigned long long)a->cps_x10 / 10, (unsigned long long)a->cps_x10 % 10,
               (unsigned long long)d->cps_x10 / 10, (unsigned long long)d->cps_x10 % 10,
               (unsigned long long)t->over34_pm / 10, (unsigned long long)t->over34_pm % 10,
               (unsigned long long)a->over34_pm / 10, (unsigned long long)a->over34_pm % 10,
               (unsigned long long)d->over34_pm / 10, (unsigned long long)d->over34_pm % 10,
               (unsigned long long)t->ed.late, (unsigned long long)t->copies,
               (unsigned long long)t->r.in_mean_us, (unsigned long long)a->r.in_mean_us, (unsigned long long)d->r.in_mean_us,
               (unsigned long long)t->r.in_p95_us, (unsigned long long)a->r.in_p95_us, (unsigned long long)d->r.in_p95_us,
               (unsigned long long)t->r.q_us, (unsigned long long)a->r.q_us, (unsigned long long)d->r.q_us,
               (unsigned long long)d->ed.engages, (unsigned long long)d->ed.early, (unsigned long long)d->copies);
        n = adreno_perf_line_done(line, sizeof line, i + 1, &t->ed, 0);
        printf("early-done %s_%s today's arrivals: %s\n", e->c.name, ws_name[e->c.ws], line);
    }
    fprintf(RJ, "},\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", checks - c0, failures - f0,
            cost_checks - cc0, cost_failures - cf0);
    fclose(RJ);
    printf("{\"early_done_checks\":%u,\"early_done_failures\":%u,\"early_done_cost_checks\":%u,"
           "\"early_done_cost_failures\":%u}\n",
           checks - c0, failures - f0, cost_checks - cc0, cost_failures - cf0);
}
