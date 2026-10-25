/* SPDX-License-Identifier: MIT */
/* Host test for gpu/adreno-kext/kext/src/AdrenoDisplayEarlyDone.h (AdrenoDisplay's early completion and arrival
 * measurements). No kext, no A16. Times are plain units with one millisecond = 1000.
 *
 *   cc -std=c11 -Wall -Wextra -Werror tools/test-adreno-early-done.c -o test && ./test
 *   (-DEARLY_DONE_HEADER='"<path>"' tests another copy of the header: tools/test-present-early-done.py runs mutants)
 *
 * Exit 0 when every check passes; each failure is printed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef EARLY_DONE_HEADER
#define EARLY_DONE_HEADER "../gpu/adreno-kext/kext/src/AdrenoDisplayEarlyDone.h"
#endif
#include EARLY_DONE_HEADER

static unsigned checks, failures;
#define CHECK(c) \
    do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

enum { MSU = 1000, PERIOD = 16667, HOLD = 2000 * MSU };

static struct adreno_early_done fresh(uint32_t mode)
{
    struct adreno_early_done e;
    adreno_early_init(&e, mode, PERIOD, HOLD, MSU);
    return e;
}

/* Modes: OFF never completes early, ALWAYS always, ADAPTIVE only once engaged; an unknown mode is OFF. */
static void modes(void)
{
    struct adreno_early_done off = fresh(ADRENO_EARLY_OFF), always = fresh(ADRENO_EARLY_ALWAYS);
    struct adreno_early_done adaptive = fresh(ADRENO_EARLY_ADAPTIVE), bad = fresh(7);
    CHECK(!adreno_early_active(&off, 1) && !adreno_early_active(&off, 1u << 30));
    CHECK(adreno_early_active(&always, 0) && adreno_early_active(&always, 123456789));
    CHECK(!adreno_early_active(&adaptive, 5 * MSU));
    CHECK(bad.mode == ADRENO_EARLY_OFF && !adreno_early_active(&bad, 5));
    struct adreno_early_done z = fresh(ADRENO_EARLY_ADAPTIVE);
    adreno_early_init(&z, ADRENO_EARLY_ADAPTIVE, PERIOD, HOLD, 0);
    CHECK(z.ms == 1);                                      /* never a zero millisecond (the bins divide by it) */
}

/* Arrivals: the offset after the last proceeding tick in 2 ms bins, the last bin open; none before the first tick. */
static void arrivals(void)
{
    struct adreno_early_done e = fresh(ADRENO_EARLY_OFF);
    CHECK(!adreno_early_arrival(&e, 5 * MSU, 1) && e.arrivals == 0);   /* no tick yet: nothing to measure from */
    adreno_early_tick(&e, 100 * MSU, 1, 1);
    const uint64_t offsets[] = {0, 1999, 2000, 7 * MSU, 15999, 16 * MSU, 40 * MSU};
    const unsigned bins[] = {0, 0, 1, 3, 7, 8, 8};
    for (unsigned i = 0; i < sizeof offsets / sizeof offsets[0]; i++) {
        struct adreno_early_done x = e;
        adreno_early_arrival(&x, 100 * MSU + offsets[i], 1);
        CHECK(x.arrivals == 1 && x.arr[bins[i]] == 1);
    }
    struct adreno_early_done x = e;
    CHECK(!adreno_early_arrival(&x, 99 * MSU, 1) && x.arrivals == 0);  /* before the tick (a clock race): ignored */
    CHECK(!adreno_early_arrival(&x, 105 * MSU, 0) && x.ahead == 1 && x.arrivals == 0);   /* behind another: ahead */
}

/* Late frames: a tick that had a frame and neither copied nor kept a layer-0 head, then an arrival within one refresh.
 * Not late: a served tick, an idle tick (no frame on screen), an arrival a refresh or more later, a second arrival. */
static void late_frames(void)
{
    struct adreno_early_done e = fresh(ADRENO_EARLY_OFF);
    adreno_early_tick(&e, 1000 * MSU, 1, 0);               /* missed */
    CHECK(adreno_early_arrival(&e, 1000 * MSU + 3 * MSU, 1) == 1);
    CHECK(e.late == 1 && e.lat[1] == 1 && e.engages == 0 && !adreno_early_active(&e, 1004 * MSU));
    CHECK(adreno_early_arrival(&e, 1000 * MSU + 5 * MSU, 1) == 0 && e.late == 1);   /* once per missed tick */
    const uint64_t lateness[] = {500, 2500, 6000, 9000, PERIOD - 1};
    const unsigned lbins[] = {0, 1, 2, 3, 3};
    for (unsigned i = 0; i < sizeof lateness / sizeof lateness[0]; i++) {
        struct adreno_early_done x = fresh(ADRENO_EARLY_OFF);
        adreno_early_tick(&x, 50 * MSU, 1, 0);
        CHECK(adreno_early_arrival(&x, 50 * MSU + lateness[i], 1) == 1 && x.lat[lbins[i]] == 1);
    }
    struct adreno_early_done x = fresh(ADRENO_EARLY_OFF);
    adreno_early_tick(&x, 50 * MSU, 1, 0);
    CHECK(adreno_early_arrival(&x, 50 * MSU + PERIOD, 1) == 0 && x.late == 0);      /* a refresh later: not this tick's */
    adreno_early_tick(&x, 80 * MSU, 1, 1);                 /* served: a copy, or a deferred head kept */
    CHECK(adreno_early_arrival(&x, 81 * MSU, 1) == 0 && x.late == 0);
    adreno_early_tick(&x, 90 * MSU, 0, 0);                 /* idle: nothing on screen for that refresh */
    CHECK(adreno_early_arrival(&x, 91 * MSU, 1) == 0 && x.late == 0);
    adreno_early_tick(&x, 100 * MSU, 1, 0);
    CHECK(adreno_early_arrival(&x, 101 * MSU, 0) == 0 && x.late == 0 && x.ahead == 1);   /* behind another: no late */
}

/* Adaptive: a late frame engages it for `hold`, every later late frame renews it, it ends by itself; ALWAYS and OFF
 * never count engagements. */
static void adaptive(void)
{
    struct adreno_early_done e = fresh(ADRENO_EARLY_ADAPTIVE);
    adreno_early_tick(&e, 10 * MSU, 1, 0);
    adreno_early_arrival(&e, 12 * MSU, 1);
    CHECK(e.engages == 1 && adreno_early_active(&e, 12 * MSU) && adreno_early_active(&e, 12 * MSU + HOLD - 1));
    CHECK(!adreno_early_active(&e, 12 * MSU + HOLD));
    adreno_early_tick(&e, 1000 * MSU, 1, 0);               /* renewed while engaged: not a new engagement */
    adreno_early_arrival(&e, 1001 * MSU, 1);
    CHECK(e.engages == 1 && adreno_early_active(&e, 1001 * MSU + HOLD - 1) && !adreno_early_active(&e, 1001 * MSU + HOLD));
    adreno_early_tick(&e, 5000 * MSU, 1, 0);               /* after it ended: a new engagement */
    adreno_early_arrival(&e, 5001 * MSU, 1);
    CHECK(e.engages == 2 && adreno_early_active(&e, 5002 * MSU));
    adreno_early_reset(&e);                                /* stop / mode set: nothing engaged, no tick */
    CHECK(!adreno_early_active(&e, 5002 * MSU) && e.last_tick == 0 && !e.tick_missed && e.mode == ADRENO_EARLY_ADAPTIVE);
    struct adreno_early_done a = fresh(ADRENO_EARLY_ALWAYS);
    adreno_early_tick(&a, 10 * MSU, 1, 0);
    adreno_early_arrival(&a, 11 * MSU, 1);
    CHECK(a.late == 1 && a.engages == 0);
}

/* Windows: counters start over, the tick state and an engagement carry across. */
static void windows(void)
{
    struct adreno_early_done e = fresh(ADRENO_EARLY_ADAPTIVE);
    adreno_early_tick(&e, 10 * MSU, 1, 0);
    adreno_early_arrival(&e, 11 * MSU, 1);
    adreno_early_completed(&e);
    adreno_early_tick(&e, 27 * MSU, 1, 0);
    adreno_early_next_window(&e);
    CHECK(!e.early && !e.late && !e.engages && !e.arrivals && !e.ahead && !e.arr[0] && !e.lat[0]);
    CHECK(e.last_tick == 27 * MSU && e.tick_missed && adreno_early_active(&e, 30 * MSU));
}

/* The perf done line: at most ADRENO_PERF_LINE_MAX bytes at every cap, and the exact text of a known window. */
static void perf_line(void)
{
    char line[512];
    struct adreno_early_done big;
    memset(&big, 0xff, sizeof big);
    int n = adreno_perf_line_done(line, sizeof line, ~0ull, &big, 1);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    printf("perf done line at caps: %d bytes\n", n);
    struct adreno_early_done e = fresh(ADRENO_EARLY_ADAPTIVE);
    adreno_early_tick(&e, 10 * MSU, 1, 0);
    adreno_early_arrival(&e, 13 * MSU, 1);
    adreno_early_completed(&e);
    adreno_early_tick(&e, 27 * MSU, 1, 1);
    adreno_early_arrival(&e, 36 * MSU, 1);
    adreno_early_arrival(&e, 37 * MSU, 0);
    n = adreno_perf_line_done(line, sizeof line, 42, &e, adreno_early_active(&e, 40 * MSU));
    CHECK(!strcmp(line, "AdrenoDisplay: perf done s=42 mode=2 on=1 done=1 late=1 eng=1 ahd=1 "
                        "arr=0/1/0/0/1/0/0/0/0 lat=0/1/0/0"));
    printf("%s\n", line);
}

int main(void)
{
    modes();
    arrivals();
    late_frames();
    adaptive();
    windows();
    perf_line();
    printf("{\"checks\":%u,\"failures\":%u}\n", checks, failures);
    return failures ? 1 : 0;
}
