/* SPDX-License-Identifier: MIT */
/* The kext's half of IO-coherent CB0 leaves (ADRENO_COHERENT_SKIP_MAINT): compat/adreno-coherent-skip.h's rules, driven the way AdrenoMemoryMap's cacheSubmission and cacheRange drive
 * them, against a model of the rest of the machine:
 *  - the CPU's data cache (64-byte lines: present, dirty) over DRAM, and each 16 KiB frame's CPU attribute (WB or
 *    NC). An NC store goes to DRAM and leaves any line alone; an NC frame can hold a stale clean line (speculation
 *    through a write-back alias), which a snooping GPU read would return;
 *  - the monitor: QUERY (state, epoch), plain ADRENO_GUEST_CACHE (DC CIVAC / DC IVAC on every line) and the coherent
 *    variant (refused unless ON; only non-WB frames maintained; x2 = their bytes), an SPTM attribute change (cleans
 *    the frame, moves the epoch);
 *  - the GPU: copies one buffer into another; with coherent leaves on a coherent machine its reads snoop the CPU's
 *    lines and its writes drop them, otherwise it sees DRAM only.
 * Every buffer class runs several command buffers (CPU writes the source, the kext maintains, the GPU copies, the kext
 * maintains, the CPU reads the destination), and every byte read back must be what the CPU wrote. The class rules
 * (PLAIN / CALL / SKIP per pass) are checked too.
 *
 *   clang -std=gnu11 -Icompat -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -DADRENO_COHERENT_SKIP_MAINT=1 tools/test-adreno-coherent-kext.c -o build/test-adreno-coherent-kext \
 *     && build/test-adreno-coherent-kext
 * Run from the tree root. No hardware client. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "adreno-coherent-skip.h"
#if !ADRENO_COHERENT_SKIP_MAINT
#error "build with -DADRENO_COHERENT_SKIP_MAINT=1"
#endif

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; printf("FAIL %d: %s\n", __LINE__, #x); } } while (0)

/* --- the machine ---------------------------------------------------------------------------------------------- */
#define FRAMES 8
#define FRAME 0x4000u
#define LINES (FRAMES * FRAME / 64)
static uint32_t dram[FRAMES * FRAME / 4], cache[FRAMES * FRAME / 4];
static uint8_t present[LINES], dirty[LINES], nc[FRAMES];
static struct {
    int coherent_hw;              /* the interconnect snoops coherent-leaf GPU accesses */
    unsigned state;               /* ADRENO_COHERENT_STATE_* */
    int old_monitor;              /* QUERY refused: a monitor without SNAP_ADRENO_COHERENT */
    uint64_t epoch, plain_calls, coherent_calls, maintained, refused;
} mon;

static void cpu_line_fill(unsigned line)
{
    if (!present[line]) { memcpy(&cache[line * 16], &dram[line * 16], 64); present[line] = 1; dirty[line] = 0; }
}
static void cpu_write(uint32_t off, uint32_t v)
{
    if (nc[off / FRAME]) { dram[off / 4] = v; return; }          /* NC: straight to DRAM, lines left alone */
    cpu_line_fill(off / 64);
    cache[off / 4] = v;
    dirty[off / 64] = 1;
}
static uint32_t cpu_read(uint32_t off)
{
    if (nc[off / FRAME]) return dram[off / 4];
    cpu_line_fill(off / 64);
    return cache[off / 4];
}
static void dc_civac(unsigned line) { if (present[line] && dirty[line]) memcpy(&dram[line * 16], &cache[line * 16], 64); present[line] = dirty[line] = 0; }
static void dc_ivac(unsigned line) { present[line] = dirty[line] = 0; }
/* A speculative fill through a write-back alias: a clean line with what DRAM holds now. */
static void speculate(uint32_t off) { unsigned line = off / 64; if (!present[line]) { memcpy(&cache[line * 16], &dram[line * 16], 64); present[line] = 1; } }
static int gpu_coherent(void) { return mon.state == ADRENO_COHERENT_STATE_ON && mon.coherent_hw; }
static uint32_t gpu_read(uint32_t off)
{
    unsigned line = off / 64;
    if (gpu_coherent() && present[line]) return cache[off / 4];   /* snooped: the line answers, stale or not */
    return dram[off / 4];
}
static void gpu_write(uint32_t off, uint32_t v)
{
    unsigned line = off / 64;
    if (gpu_coherent() && present[line]) { if (dirty[line]) memcpy(&dram[line * 16], &cache[line * 16], 64); present[line] = dirty[line] = 0; }
    dram[off / 4] = v;
}
/* An SPTM SH/AttrIndx change of one frame: cleaned to PoC before and after (sptm_attr_clean), the epoch moves. */
static void attr_change(unsigned frame, int to_nc)
{
    for (unsigned l = frame * FRAME / 64; l < (frame + 1) * FRAME / 64; l++) dc_civac(l);
    nc[frame] = (uint8_t)to_nc;
    mon.epoch++;
}

/* --- the monitor's calls ---------------------------------------------------------------------------------------- */
static void query(uint64_t r[4])
{
    if (mon.old_monitor) { r[0] = (uint64_t)-60; r[1] = r[2] = r[3] = 0; return; }   /* the fence handler refuses */
    r[0] = 0; r[1] = ADRENO_COHERENT_ABI | (uint64_t)mon.state << 8; r[2] = mon.epoch; r[3] = 14;
}
static void cache_call(uint32_t off, uint32_t bytes, uint64_t x3, uint64_t r[4])
{
    unsigned direction = (unsigned)(x3 & ~(uint64_t)ADRENO_CACHE_COHERENT);
    int coherent = !!(x3 & ADRENO_CACHE_COHERENT);
    if (coherent && mon.state != ADRENO_COHERENT_STATE_ON) { mon.refused++; r[0] = (uint64_t)-60; r[1] = r[2] = 0; return; }
    uint64_t maintained = 0;
    for (uint32_t at = off; at < off + bytes; at += 64) {
        if (coherent && !nc[at / FRAME]) continue;              /* the CPU's write-back frame: left alone */
        if (direction == ADRENO_CACHE_TO_DEVICE) dc_civac(at / 64); else dc_ivac(at / 64);
        maintained += 64;
    }
    if (coherent) { mon.coherent_calls++; mon.maintained += maintained; } else mon.plain_calls++;
    r[0] = 0; r[1] = bytes; r[2] = coherent ? maintained : 0; r[3] = 0;
}

/* --- the kext, as AdrenoMemoryMap drives the rules -------------------------------------------------------------- */
struct map { uint32_t off, bytes; int declared_wb; uint64_t verdict, maintained; unsigned how; };
static struct adreno_coherent_gate gate;
static int wanted;                                              /* the boot-arg adreno_coherent=1 */
static void refresh(void)                                        /* coherentRefresh: every kernel command */
{
    static int off_for_boot;
    if (!wanted || off_for_boot) return;
    uint64_t r[4];
    query(r);
    adreno_coherent_gate_reply(&gate, r[0], r[1], r[2], 0);
    if (!gate.on) off_for_boot = 1;
}
static int maintain(struct map *m, uint32_t off, uint32_t bytes, unsigned direction)   /* maintainCache */
{
    uint64_t r[4];
    cache_call(off, bytes, adreno_coherent_direction(m->how, direction), r);
    if (!adreno_coherent_reply_ok(m->how, bytes, r[0], r[1], r[2])) return -1;
    if (m->how == ADRENO_COHERENT_CALL) m->maintained += r[2];
    return 0;
}
static unsigned passes[3];
static int sync_map(struct map *m, unsigned direction)          /* cacheSubmission */
{
    m->how = direction ? adreno_coherent_choose(&gate, m->declared_wb, m->verdict) : ADRENO_COHERENT_PLAIN;
    m->maintained = 0;
    passes[m->how]++;
    if (m->how == ADRENO_COHERENT_SKIP) direction = 0;
    int result = 0;
    for (uint32_t at = 0; direction && at < m->bytes && !result; at += 0x4000)   /* 16 KiB chunks */
        result = maintain(m, m->off + at, m->bytes - at < 0x4000 ? m->bytes - at : 0x4000, direction);
    if (m->how == ADRENO_COHERENT_CALL) m->verdict = adreno_coherent_verdict(&gate, result, m->maintained);
    m->how = ADRENO_COHERENT_PLAIN;
    return result;
}
static void repin(struct map *m) { m->verdict = 0; }            /* pinBacking/unpinBacking */

/* One command buffer: the CPU writes `src` (with a stale clean line first in NC frames), TO_DEVICE on both maps, the
 * GPU copies src -> dst, FROM_DEVICE on dst, the CPU reads dst. Returns the words that differ from what was written,
 * or -1 when a maintenance call failed. */
static int command(struct map *src, struct map *dst, uint32_t seed)
{
    refresh();
    for (uint32_t i = 0; i < src->bytes; i += 4) {
        if (nc[(src->off + i) / FRAME]) speculate(src->off + i);
        cpu_write(src->off + i, seed + i);
    }
    for (uint32_t i = 0; i < dst->bytes; i += 64) (void)cpu_read(dst->off + i);   /* the CPU had looked at the target */
    if (sync_map(src, ADRENO_CACHE_TO_DEVICE) || sync_map(dst, ADRENO_CACHE_TO_DEVICE)) return -1;
    for (uint32_t i = 0; i < src->bytes; i += 4) gpu_write(dst->off + i, gpu_read(src->off + i));
    if (sync_map(dst, ADRENO_CACHE_FROM_DEVICE)) return -1;
    int bad = 0;
    for (uint32_t i = 0; i < src->bytes; i += 4) bad += cpu_read(dst->off + i) != seed + i;
    return bad;
}

static void reset(unsigned state, int coherent_hw)
{
    memset(dram, 0, sizeof dram); memset(cache, 0, sizeof cache); memset(present, 0, sizeof present);
    memset(dirty, 0, sizeof dirty); memset(nc, 0, sizeof nc); memset(&mon, 0, sizeof mon); memset(&gate, 0, sizeof gate);
    memset(passes, 0, sizeof passes);
    mon.state = state; mon.coherent_hw = coherent_hw; mon.epoch = 7; wanted = 1;
}
#define M(frame, wb) {(frame) * FRAME, 2 * FRAME, (wb), 0, 0, 0}

/* A Metal buffer (IOGPU memory, the CPU's write-back): the first pass verifies, later ones skip. */
static void test_writeback_buffer(void)
{
    reset(ADRENO_COHERENT_STATE_ON, 1);
    struct map a = M(0, 1), b = M(2, 1);
    for (unsigned n = 0; n < 4; n++) CHECK(command(&a, &b, 0x1000 * n) == 0);
    /* The first command verifies the source (TO_DEVICE) and the target (TO_DEVICE); its FROM_DEVICE already skips. */
    CHECK(a.verdict == 7 && b.verdict == 7 && passes[ADRENO_COHERENT_CALL] == 2 && passes[ADRENO_COHERENT_SKIP] == 10);
    CHECK(mon.maintained == 0 && mon.plain_calls == 0);
    printf("KEXT write-back: %u calls, %u skips, 0 bytes maintained\n", passes[ADRENO_COHERENT_CALL],
           passes[ADRENO_COHERENT_SKIP]);
}
/* A buffer the CPU maps write-combined (NC frames): every pass asks, the monitor maintains, never a verdict. */
static void test_wc_buffer(void)
{
    reset(ADRENO_COHERENT_STATE_ON, 1);
    nc[0] = nc[1] = 1;
    struct map a = M(0, 1), b = M(2, 1);
    for (unsigned n = 0; n < 4; n++) CHECK(command(&a, &b, 0x2000 * n) == 0);
    CHECK(a.verdict == 0 && passes[ADRENO_COHERENT_SKIP] == 7 && passes[ADRENO_COHERENT_CALL] == 5 &&
          mon.maintained == 4 * 2 * FRAME);
}
/* An IOSurface declared write-combine keeps today's maintenance, even when its frames are write-back now. */
static void test_wc_surface(void)
{
    reset(ADRENO_COHERENT_STATE_ON, 1);
    struct map a = M(0, 0), b = M(2, 1);
    for (unsigned n = 0; n < 3; n++) CHECK(command(&a, &b, 0x3000 * n) == 0);
    CHECK(a.verdict == 0 && mon.plain_calls == 3 * 2 && passes[ADRENO_COHERENT_PLAIN] == 3);
}
/* Write-back verified, then the frame turns NC (the monitor cleans it, the epoch moves): the next pass asks
 * again and the NC frame is maintained; a re-pin forgets the verdict too. */
static void test_epoch_and_repin(void)
{
    reset(ADRENO_COHERENT_STATE_ON, 1);
    struct map a = M(0, 1), b = M(2, 1);
    CHECK(command(&a, &b, 0x4000) == 0 && command(&a, &b, 0x5000) == 0 && a.verdict == 7);
    attr_change(0, 1);
    CHECK(command(&a, &b, 0x6000) == 0 && a.verdict == 0 && b.verdict == 8 && mon.maintained == FRAME);
    CHECK(command(&a, &b, 0x7000) == 0 && a.verdict == 0);
    attr_change(0, 0);
    CHECK(command(&a, &b, 0x8000) == 0 && a.verdict == 9);
    repin(&a);
    const unsigned calls = passes[ADRENO_COHERENT_CALL];
    CHECK(command(&a, &b, 0x9000) == 0 && passes[ADRENO_COHERENT_CALL] == calls + 1 && a.verdict == 9);
}
/* No ON answer means today's maintenance; nothing is asked of a monitor that said OFF or refused. */
static void test_off(void)
{
    static const struct { unsigned state; int old, wanted; const char *what; } cases[] = {
        {ADRENO_COHERENT_STATE_FAILED, 0, 1, "self-test failed"}, {ADRENO_COHERENT_STATE_INCONCLUSIVE, 0, 1, "no power"},
        {ADRENO_COHERENT_STATE_ON, 1, 1, "older monitor"}, {ADRENO_COHERENT_STATE_ON, 0, 0, "boot-arg absent"}};
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        reset(cases[i].state, 0);                                 /* a machine that is not coherent */
        mon.old_monitor = cases[i].old;
        wanted = cases[i].wanted;
        struct map a = M(0, 1), b = M(2, 1);
        for (unsigned n = 0; n < 3; n++) CHECK(command(&a, &b, 0x100 * n + i) == 0);
        CHECK(!gate.on && mon.coherent_calls == 0 && mon.refused == 0 && passes[ADRENO_COHERENT_SKIP] == 0);
    }
}
/* A gate that is not ON never sends the coherent flag; the monitor would refuse it anyway. */
static void test_rules(void)
{
    struct adreno_coherent_gate g;
    memset(&g, 0, sizeof g);
    adreno_coherent_gate_reply(&g, 0, ADRENO_COHERENT_ABI | ADRENO_COHERENT_STATE_ON << 8, 0, 0);
    CHECK(!g.on);                                                 /* epoch 0 is not an answer */
    adreno_coherent_gate_reply(&g, 0, 2 | ADRENO_COHERENT_STATE_ON << 8, 5, 0);
    CHECK(!g.on);                                                 /* another ABI */
    /* A debug monitor's forced ON counts only with the kext's own boot-arg; the flag alone never turns a state ON,
     * and the self-test's own flags (0xc000: today's leaves already snooped) are not the forced one. */
    const uint64_t forced = (uint64_t)ADRENO_COHERENT_DETAIL_FORCED << 16;
    adreno_coherent_gate_reply(&g, 0, ADRENO_COHERENT_ABI | ADRENO_COHERENT_STATE_ON << 8 | forced, 5, 0);
    CHECK(!g.on && g.forced && !g.epoch);
    adreno_coherent_gate_reply(&g, 0, ADRENO_COHERENT_ABI | ADRENO_COHERENT_STATE_ON << 8 | forced, 5, 1);
    CHECK(g.on && g.forced && g.epoch == 5);
    adreno_coherent_gate_reply(&g, 0, ADRENO_COHERENT_ABI | ADRENO_COHERENT_STATE_INCONCLUSIVE << 8 | forced, 5, 1);
    CHECK(!g.on);
    adreno_coherent_gate_reply(&g, 0, ADRENO_COHERENT_ABI | ADRENO_COHERENT_STATE_ON << 8 | 0xc000ull << 16, 5, 0);
    CHECK(g.on && !g.forced);
    adreno_coherent_gate_reply(&g, 0, ADRENO_COHERENT_ABI | ADRENO_COHERENT_STATE_ON << 8, 5, 1);
    CHECK(g.on && !g.forced);                                     /* the boot-arg changes nothing for a proved ON */
    adreno_coherent_gate_reply(&g, 0, ADRENO_COHERENT_ABI | ADRENO_COHERENT_STATE_ON << 8, 5, 0);
    CHECK(g.on && g.epoch == 5 && adreno_coherent_choose(&g, 1, 0) == ADRENO_COHERENT_CALL &&
          adreno_coherent_choose(&g, 1, 5) == ADRENO_COHERENT_SKIP && adreno_coherent_choose(&g, 1, 4) == ADRENO_COHERENT_CALL &&
          adreno_coherent_choose(&g, 0, 5) == ADRENO_COHERENT_PLAIN);
    CHECK(adreno_coherent_direction(ADRENO_COHERENT_CALL, 1) == (1 | ADRENO_CACHE_COHERENT) &&
          adreno_coherent_direction(ADRENO_COHERENT_PLAIN, 2) == 2);
    CHECK(adreno_coherent_reply_ok(ADRENO_COHERENT_CALL, 64, 0, 64, 64) && !adreno_coherent_reply_ok(ADRENO_COHERENT_CALL, 64, 0, 64, 65) &&
          !adreno_coherent_reply_ok(ADRENO_COHERENT_PLAIN, 64, 0, 64, 64) && !adreno_coherent_reply_ok(ADRENO_COHERENT_CALL, 64, 1, 64, 0));
    CHECK(adreno_coherent_verdict(&g, 0, 0) == 5 && !adreno_coherent_verdict(&g, 0, 64) && !adreno_coherent_verdict(&g, -1, 0));
    adreno_coherent_gate_reply(&g, (uint64_t)-60, 0, 0, 1);
    CHECK(!g.on && !g.epoch && adreno_coherent_choose(&g, 1, 5) == ADRENO_COHERENT_PLAIN);
}

int main(void)
{
    test_rules();
    test_writeback_buffer();
    test_wc_buffer();
    test_wc_surface();
    test_epoch_and_repin();
    test_off();
    if (failures) { printf("FAIL: %u of %u kext coherent checks\n", failures, checks); return 1; }
    printf("PASS: %u kext coherent checks\n", checks);
    return 0;
}
