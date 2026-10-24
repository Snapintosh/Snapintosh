#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Adreno GPU mappings resident across native unwire, and contiguous-run inserts
(docs/ADRENO-GPU-MAP-RESIDENCY-20261017.md). Offline: no hardware, no proxy.

    python3 tools/test-adreno-residency.py

Model: tools/test-adreno-residency.c links the real compat/adreno-resource.c under
ASan/UBSan against a model of IODARTMapper, the SPTM DART leaves and wiredcnt,
ADRENO_GUEST_UNMAP, descriptor wiring, a VM that moves anything unwired, and
native IOGPU wire/unwire. Its targeted scenarios cover runs, the budget, stale and
read-only backing, repeated unwire, final free and every injected failure; its
seeded workload runs the old and the new policy over the same submissions and
prints both counts, which this file compares. Weakened variants of the core must
each FAIL. The kext must build warning-free and route IOGPU's callbacks through
the new entry points with the verdicts the model uses; the existing resource
replays must still pass.

agents/gpu-va (FAILURE-MODES.md G0-G17): with -DADRENO_VA_RECLAIM=1 the same model
runs every scenario and workload with the kext's filler, scenarios 26-29, and the
pressure workload (PRESSURE rows): b12v5's pattern on a scaled DART, the base and
the reclaim build, residency off and on, with and without the filler. Weakened
reclaim cores must each FAIL; the perf va line must fit 250 bytes.
"""
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'compat/adreno-resource.c'
HARNESS = ROOT / 'tools/test-adreno-residency.c'
KEXT = ROOT / 'gpu/adreno-kext/kext'
MAP = KEXT / 'src/AdrenoMemoryMap.cpp'
OBJDUMP = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
FLAGS = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-DADRENO_RESOURCE_POOL=1',
         '-Wall', '-Wextra', '-Werror']
# agents/gpu-va-wide: `--va-wide` runs everything with the 16 GiB window (-DADRENO_VA_WIDE=1), which adds the across-4-GiB
# and top-of-window scenarios to 'scenarios'.
if '--va-wide' in sys.argv:
    sys.argv.remove('--va-wide')
    FLAGS.append('-DADRENO_VA_WIDE=1')
MiB = 1 << 20


def build(directory, core=CORE, extra=()):
    exe = Path(directory) / 'test-adreno-residency'
    subprocess.run(['cc', *FLAGS, *extra, '-Icompat', str(HARNESS), str(core), '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


# A mutant may leave a variable or parameter unused; that must not be why it fails.
MUTANT_FLAGS = ['-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-but-set-variable',
                '-Wno-unused-function']


def between(text, start, end='\n}\n'):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


# Each weakens one rule of docs/ADRENO-GPU-MAP-RESIDENCY-20261017.md; the model must notice.
MUTANTS = {
    'unpin while resident (rule 1)': (
        '            r->flags |= ADRENO_RESOURCE_RESIDENT;\n',
        '            r->flags |= ADRENO_RESOURCE_RESIDENT;\n            o->unpin(o->ctx);\n'),
    'reuse a stale descriptor (rule 2)': (
        '    if (r->flags & ADRENO_RESOURCE_RESIDENT) {\n        if (same) {',
        '    if (r->flags & ADRENO_RESOURCE_RESIDENT) {\n        if (1) {'),
    'skip the stale release (rule 2)': (
        '        int e = release(r, o, res);\n        if (e) return e;\n    } else if (!same) {',
        '        r->flags &= ~ADRENO_RESOURCE_RESIDENT;\n    } else if (!same) {'),
    'ignore the keep verdict (rules 2, 4)': (
        '    if (keep && res && res->budget',
        '    if (res && res->budget'),
    'no budget (rule 5)': (
        '        if (prior <= res->budget && r->length <= res->budget - prior) {',
        '        if (1) {'),
    'no uncharge on reuse (rule 5)': (
        '            uncharge(res, r->length, res ? &res->reused : 0);',
        '            if (res) __atomic_fetch_add(&res->reused, 1, __ATOMIC_RELAXED);'),
    'uncharge before the clear (rules 5, 12)': (
        '    if (!(r->flags & ADRENO_RESOURCE_PINNED)) return 0;\n    for (uint64_t offset = 0; offset < r->mapped_length;) {',
        '    if (!(r->flags & ADRENO_RESOURCE_PINNED)) return 0;\n'
        '    if ((r->flags & ADRENO_RESOURCE_RESIDENT) && res) {\n'
        '        __atomic_fetch_sub(&res->bytes, r->length, __ATOMIC_RELAXED);\n'
        '        r->flags &= ~ADRENO_RESOURCE_RESIDENT;\n    }\n'
        '    for (uint64_t offset = 0; offset < r->mapped_length;) {'),
    'no uncharge at final free (rule 8)': (
        '    if ((r->flags & ADRENO_RESOURCE_RESIDENT) && res) {\n        __atomic_fetch_sub(&res->bytes, r->length, __ATOMIC_RELAXED);\n    }\n',
        ''),
    'merge non-contiguous pages (rule 9)': (
        'while (bytes < limit && physical_page(r, o, offset + bytes) == pa + bytes) bytes += PAGE;',
        'while (bytes < limit && physical_page(r, o, offset + bytes)) bytes += PAGE;'),
    'partial run not cleared (rule 9)': (
        '        r->mapped_length = offset + bytes; /* include a possibly partial failed insertion */\n'
        '        if (o->insert(o->ctx, r->address, offset, pa, bytes)) {\n'
        '            e = ADRENO_RESOURCE_E_INSERT; goto unwind;\n        }\n',
        '        if (o->insert(o->ctx, r->address, offset, pa, bytes)) {\n'
        '            e = ADRENO_RESOURCE_E_INSERT; goto unwind;\n        }\n'
        '        r->mapped_length = offset + bytes;\n'),
    'runs cross a leaf table (rule 9)': (
        'uint64_t va = r->address + offset, limit = LEAF_SPAN - (va & (LEAF_SPAN - 1)), bytes = PAGE;',
        'uint64_t limit = LEAF_SPAN, bytes = PAGE;'),
    'runs longer than one SPTM list (rule 9)': (
        '    if (limit > RUN_PAGES * PAGE) limit = RUN_PAGES * PAGE;\n', ''),
    'charge a resident mapping twice (rule 13)': (
        '        r->flags == (ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED)) {',
        '        (r->flags & ADRENO_RESOURCE_PINNED)) {'),
    'old commit inserts runs (rule 15)': (
        'int adreno_resource_commit(struct adreno_resource *r, const struct adreno_resource_ops *o)\n{\n    return commit(r, o, 0);',
        'int adreno_resource_commit(struct adreno_resource *r, const struct adreno_resource_ops *o)\n{\n    return commit(r, o, ADRENO_COMMIT_RUNS);'),
    # Kext batch 8 (FAILURES-AND-DESIGN.md 2026-10-20): the bind/retire core and the pool.
    'free the DART range before the CB0 range (V1)': (
        '    if (unbind) unbind(ctx);                                     /* V1: the CB0 range first */\n'
        '    return settle(r, o, res, options, pool, 0);',
        '    int late = settle(r, o, res, options, pool, 0);\n    if (unbind) unbind(ctx);\n    return late;'),
    'pool a mapping without clearing it (D1)': (
        '        int e = release(r, o, res);\n        if (e) return e;\n        *r = (struct adreno_resource){0};',
        '        *r = (struct adreno_resource){0};'),
    'reuse a pooled range of another span (D4)': (
        '        if (p->span[i] == span && !(p->flags[i] & ADRENO_VA_POOL_SUSPECT) &&',
        '        if (p->span[i] >= span && !(p->flags[i] & ADRENO_VA_POOL_SUSPECT) &&'),
    'hand out a parked collision (V3)': (
        '        if (p->span[i] == span && !(p->flags[i] & ADRENO_VA_POOL_SUSPECT) &&',
        '        if (p->span[i] == span &&'),
    'no retry after a collision (V3)': (
        '        if (attempt + 1 < ADRENO_BIND_ATTEMPTS) POOL_BUMP(pool, retried);',
        '        return ADRENO_RESOURCE_E_BIND;'),
    'retry after a failed commit (V4)': (
        '        if (b != 1) {', '        if (b == 3) {'),
    'admit past the byte limit (D5)': (
        '    int ok = p->count < ADRENO_VA_POOL_SLOTS && same < ADRENO_VA_POOL_PER_SPAN && p->bytes <= p->limit_bytes &&\n'
        '             span <= p->limit_bytes - p->bytes;',
        '    int ok = p->count < ADRENO_VA_POOL_SLOTS && same < ADRENO_VA_POOL_PER_SPAN;'),
}


def run_model(directory, extra=()):
    """Build the harness (extra: more -D words, both translation units) and run it all: (result, counts, races,
    bursts)."""
    result = subprocess.run([str(build(directory, extra=extra)), 'all'], capture_output=True, text=True, timeout=900)
    counts, races, bursts = {}, [], {}
    for line in result.stdout.splitlines():
        if line.startswith('COUNTS '):
            row = json.loads(line[len('COUNTS '):])
            counts[row['policy']] = row
        elif line.startswith('RACE '):
            races.append(json.loads(line[len('RACE '):]))
        elif line.startswith('BURST '):
            row = json.loads(line[len('BURST '):])
            bursts[row['policy']] = row
        elif line.startswith('RECYCLE '):
            row = json.loads(line[len('RECYCLE '):])
            RECYCLES.setdefault(directory, {})[row['policy']] = row
        elif line.startswith('PRESSURE '):
            row = json.loads(line[len('PRESSURE '):])
            PRESSURES.setdefault(directory, {})[row['policy']] = row
    return result, counts, races, bursts


# Pacing work 2026-10-21: RECYCLE rows by model build directory (the recycled-arena workload, R1-R13).
RECYCLES = {}
# agents/gpu-va: PRESSURE rows by model build directory (the IOVA-pressure workload, G0-G17).
PRESSURES = {}


# Batch 9 (batch9/dart FAILURES-AND-DESIGN.md K1-K12): the arena class of the empty-reservation pool.
ARENA = ['-DADRENO_POOL_ARENA=1']


class Model(unittest.TestCase):
    EXTRA = []

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='adreno-residency-')
        cls.result, cls.counts, cls.races, cls.bursts = run_model(cls.scratch.name, cls.EXTRA)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def test_scenarios_and_workloads_pass(self):
        self.assertEqual(self.result.returncode, 0, self.result.stdout[-3000:] + self.result.stderr[-3000:])
        for part in ('scenarios', 'race', 'pool', 'workload', 'arena', 'burst', 'recycled'):
            self.assertIn('PASS ' + part, self.result.stdout)
        self.assertEqual(sorted(self.counts), sorted(['old', 'resident', 'resident+runs', 'runs, budget 0',
                                                      'resident+runs, 64 MiB', 'pool+runs, budget 0',
                                                      'pool+runs, resident', 'arena old',
                                                      'arena runs, budget 0', 'arena resident+runs',
                                                      'arena pool+runs, budget 0', 'arena pool+runs, resident',
                                                      'burst pool+runs, budget 0', 'recycled pool+runs, budget 0',
                                                      'recycled pool+runs, resident',
                                                      'recycled pool+runs, resident 64 MiB']))
        self.assertEqual(sorted(self.bursts), ['burst pool+runs, budget 0'])

    def test_residency_on_the_recycled_arenas(self):
        # Pacing work 2026-10-21 (R1-R13): the deployed collection's kext (pool + arena class, budget 0) against
        # residency on, under neon-v2's load. Every invariant was checked after every step (the run passed); here the
        # counts: what the guest pays per frame in DART inserts, clears and pins, and that nothing else got worse.
        rows = RECYCLES[self.scratch.name]
        zero, resident = rows['recycled pool+runs, budget 0'], rows['recycled pool+runs, resident']
        small = rows['recycled pool+runs, resident 64 MiB']
        self.assertEqual(zero['submissions'], resident['submissions'])
        self.assertGreater(zero['inserts_per_frame'], 20)                     # the churn the A16 shows
        self.assertLess(resident['inserts_per_frame'] * 20, zero['inserts_per_frame'])   # > 95% fewer inserts
        self.assertLess(resident['clears_per_frame'] * 10, zero['clears_per_frame'])     # > 90% fewer clears (token)
        self.assertLess(resident['pins_per_frame'] * 10, zero['pins_per_frame'])
        self.assertLessEqual(resident['peak_resident'], 512 * MiB)
        self.assertGreater(resident['reused'], 0)
        self.assertLessEqual(resident['write_refused'], zero['write_refused'])            # R6 unchanged or better
        # R5: a budget below the working set degrades towards budget 0, never past it.
        self.assertGreater(small['refused_budget'], 0)
        self.assertLessEqual(small['peak_resident'], 64 * MiB)
        self.assertLessEqual(small['inserts_per_frame'], zero['inserts_per_frame'])
        self.assertGreaterEqual(small['inserts_per_frame'], resident['inserts_per_frame'])
        # R7, R9: final frees still end in the pool or the same strict path; residency adds no native unmap.
        c0, c1 = self.counts['recycled pool+runs, budget 0'], self.counts['recycled pool+runs, resident']
        self.assertLessEqual(c1['native_unmap_calls'], c0['native_unmap_calls'])
        self.assertLessEqual(c1['native_frees'], c0['native_frees'])
        self.assertEqual(c1['pool_refused'], c0['pool_refused'])
        for name in ('pool+runs', 'arena pool+runs'):
            a, b = self.counts[name + ', budget 0'], self.counts[name + ', resident']
            self.assertLessEqual(b['native_unmap_calls'], a['native_unmap_calls'], name)
            self.assertLessEqual(b['map_pages'], a['map_pages'], name)
        print('\n' + '\n'.join('%-38s inserts/frame %7.2f clears/frame %6.2f pins/frame %6.2f tlbi/frame %6.2f '
                               'reused %6d refused %5d peak %4d MiB' % (
                                   name, row['inserts_per_frame'], row['clears_per_frame'], row['pins_per_frame'],
                                   row['tlbi_per_frame'], row['reused'], row['refused_budget'],
                                   row['peak_resident'] >> 20) for name, row in rows.items()))

    def test_burst_after_a_full_pool(self):
        # FAILURES-AND-DESIGN.md 1: spans never created again fill the general budget, then arenas complete in
        # bursts. Batch 8's rules refuse every arena then (v9: 13,257 refusals, each a 64-page recommit and a strict
        # native unmap); the arena class (K5) pools them all while fewer than its limit are in flight.
        row = self.bursts['burst pool+runs, budget 0']
        self.assertGreater(row['fill_refused'], 0)                      # the general budget is full ...
        self.assertGreater(row['fill_bytes'], (128 - 1) * MiB)          # ... to within one arena
        self.assertLess(row['peak_inflight'], 256)
        if self.EXTRA:
            self.assertEqual(row['burst_refused'], 0)
            self.assertEqual(row['burst_native_frees'], 0)
            self.assertEqual(row['burst_map_pages'], 64 * row['arenas'])    # one wire each, no recommit
            self.assertGreater(row['burst_takes'] * 10, row['arenas'] * 9)  # warm: arenas come from the pool
        else:
            self.assertGreater(row['burst_refused'] * 10, row['arenas'] * 9)
            self.assertEqual(row['burst_native_frees'], row['burst_refused'])
            self.assertEqual(row['burst_map_pages'], 64 * (row['arenas'] + row['burst_refused']))

    def test_residency_removes_the_rewire_churn(self):
        old, new = self.counts['old'], self.counts['resident']
        self.assertEqual(old['submissions'], new['submissions'])
        self.assertLess(new['map_pages'] * 100, old['map_pages'])          # > 99% fewer pages mapped
        self.assertLess(new['clears'] * 50, old['clears'])                 # > 98% fewer ADRENO_GUEST_UNMAP
        self.assertLess(new['tlbi'] * 20, old['tlbi'])
        self.assertLess(new['pins'] * 20, old['pins'])
        self.assertEqual(new['native_frees'], old['native_frees'])        # real frees are unchanged
        self.assertLessEqual(new['write_refused'], old['write_refused'])  # read-only fallbacks still retry
        self.assertGreater(new['reused'], 0)
        self.assertLessEqual(new['peak_resident'], 512 * MiB)

    def test_runs_never_add_sptm_calls(self):
        for name, row in self.counts.items():
            self.assertLessEqual(row['sptm_map_batch'], row['sptm_map_perpage'], name)
            self.assertEqual(row['sptm_map_perpage'], row['map_pages'], name)
        plain, runs = self.counts['resident'], self.counts['resident+runs']
        self.assertEqual(plain['map_pages'], runs['map_pages'])
        self.assertLess(runs['inserts'], plain['inserts'])
        self.assertEqual(runs['inserts'], runs['sptm_map_batch'])

    def test_budget_zero_is_the_old_release_path(self):
        old, zero = self.counts['old'], self.counts['runs, budget 0']
        for key in ('map_pages', 'clears', 'unmap_pages', 'tlbi', 'pins', 'unpins', 'native_frees'):
            self.assertEqual(zero[key], old[key], key)
        self.assertEqual(zero['retained'], 0)
        self.assertLess(zero['inserts'], old['inserts'])

    def test_a_small_budget_degrades_gracefully(self):
        old, small, full = self.counts['old'], self.counts['resident+runs, 64 MiB'], self.counts['resident+runs']
        self.assertLessEqual(small['peak_resident'], 64 * MiB)
        self.assertGreater(small['refused_budget'], 0)
        self.assertLess(full['map_pages'], small['map_pages'])
        self.assertLess(small['map_pages'], old['map_pages'])

    def test_release_order_removes_the_bind_race(self):
        # V1 (FAILURES-AND-DESIGN.md 1.3): a map created between the two halves of a release collides with the
        # dying map's CB0 range under the v8 order (DART first) and never under the batch-8 order (CB0 first).
        races = {row['policy']: row for row in self.races}
        self.assertEqual(sorted(races), ['old', 'pool', 'resident'])
        for name in ('old', 'resident'):
            self.assertEqual(races[name]['bind_failed'], races[name]['attempts'], name)
        self.assertEqual(races['pool']['bind_failed'], 0)
        self.assertEqual(races['pool']['bind_busy'], 0)

    def test_pool_halves_the_arena_maps(self):
        # 1.2: a fresh 1 MiB arena costs 128 page maps, one clear and one strict native unmap under the v8 kext;
        # with the pool, 64 maps, one clear and no native unmap (D2), and no DART reservation once warm.
        old, pool = self.counts['arena old'], self.counts['arena pool+runs, budget 0']
        self.assertEqual(old['arenas'], pool['arenas'])
        self.assertGreater(old['map_pages'], 126 * old['arenas'])
        self.assertLess(pool['map_pages'] * 100, old['map_pages'] * 51)
        self.assertGreaterEqual(old['native_frees'], old['arenas'])
        self.assertLess(pool['native_frees'] * 1000, pool['arenas'])
        self.assertLess(pool['reserves'] * 100, pool['arenas'])
        self.assertLessEqual(pool['clears'], old['clears'])
        self.assertLess(pool['pins'] * 100, old['pins'] * 51)
        self.assertEqual(pool['pool_refused'], 0)
        zero = self.counts['arena runs, budget 0']
        self.assertEqual(zero['map_pages'], old['map_pages'])      # runs alone change no page count
        # the generic workload keeps its page maps (its churn is rewire, residency's domain) and loses strict frees
        generic, plain = self.counts['pool+runs, budget 0'], self.counts['runs, budget 0']
        self.assertLessEqual(generic['map_pages'], plain['map_pages'])
        self.assertLess(generic['native_frees'], plain['native_frees'])

    def test_print_counts(self):
        rows = ['%-22s %10s %10s %10s %8s %8s %8s' % ('policy', 'map pages', 'perpage', 'batch', 'clears',
                                                      'tlbi', 'pins')]
        for name, row in self.counts.items():
            rows.append('%-22s %10d %10d %10d %8d %8d %8d' % (name, row['map_pages'], row['sptm_map_perpage'],
                        row['sptm_map_batch'], row['clears'], row['tlbi'], row['pins']))
        print('\n' + '\n'.join(rows))


class ArenaModel(Model):
    """Every Model check again with -DADRENO_POOL_ARENA=1, and against the build without it (K11: the class changes
    nothing but the admission of arena-span entries)."""
    EXTRA = ARENA

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.plain = tempfile.TemporaryDirectory(prefix='adreno-residency-plain-')
        cls.base_result, cls.base_counts, _, cls.base_bursts = run_model(cls.plain.name)

    @classmethod
    def tearDownClass(cls):
        cls.plain.cleanup()
        super().tearDownClass()

    def test_general_rules_unchanged(self):
        self.assertEqual(self.base_result.returncode, 0, self.base_result.stdout[-2000:])
        row, base = self.bursts['burst pool+runs, budget 0'], self.base_bursts['burst pool+runs, budget 0']
        for key in ('fill_puts', 'fill_refused', 'fill_native_frees', 'fill_bytes', 'fill_count', 'arenas',
                    'peak_inflight'):
            self.assertEqual(row[key], base[key], key)
        # The arena workload never fills the pool, so the class changes none of its counts.
        self.assertEqual(self.counts['arena pool+runs, budget 0'], self.base_counts['arena pool+runs, budget 0'])
        # No arena reaches a strict native free or a recommit in the burst: v9's refused puts are gone.
        self.assertEqual(row['burst_native_frees'], 0)
        self.assertLess(row['burst_map_pages'] * 100, base['burst_map_pages'] * 51)


# Kext batch 9 (FAILURES-AND-DESIGN.md K1-K12): weakened arena classes; each must fail under -DADRENO_POOL_ARENA=1.
ARENA_MUTANTS = {
    'arenas charged to the general budget (K5)': (
        '        uint64_t general = p->bytes - p->arena_count * p->arena_span;',
        '        uint64_t general = p->bytes;'),
    'the class past its limit (K2)': (
        '        ok = p->count < ADRENO_VA_POOL_SLOTS && p->arena_count < p->arena_limit &&',
        '        ok = p->count < ADRENO_VA_POOL_SLOTS &&'),
    'a parked collision joins the class (K6)': (
        '    return p->arena_span && span == p->arena_span && !(flags & ADRENO_VA_POOL_SUSPECT);',
        '    (void)flags;return p->arena_span && span == p->arena_span;'),
    'a take that keeps the class count (K7)': (
        '        p->arena_count -= (uint64_t)arena_entry(p, p->span[best], p->flags[best]);\n', ''),
}


class ArenaMutants(unittest.TestCase):
    def test_weakened_classes_fail(self):
        core = CORE.read_text()
        self.assertTrue(ARENA_MUTANTS)
        for name, (old, new) in ARENA_MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(core.count(old), 1, name)
                mutated = Path(d) / 'adreno-resource.c'
                mutated.write_text(core.replace(old, new))
                exe = build(d, mutated, MUTANT_FLAGS + ARENA)
                result = subprocess.run([str(exe), 'all'], capture_output=True, text=True, timeout=600)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertNotIn('PASS: all', result.stdout, name)


# agents/gpu-va (FAILURE-MODES.md G0-G17): the boot configuration's pool (arena class) with reclaim.
VA = ARENA + ['-DADRENO_VA_RECLAIM=1']
PACING_H = KEXT / 'src/AdrenoDisplayPacing.h'


class VAModel(unittest.TestCase):
    """The reclaim build against the base (arena) build, both running the pressure workload."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='adreno-residency-va-')
        cls.base = tempfile.TemporaryDirectory(prefix='adreno-residency-va-base-')
        cls.result, _, _, _ = run_model(cls.scratch.name, VA)
        cls.base_result, _, _, _ = run_model(cls.base.name, ARENA)
        cls.rows = PRESSURES.get(cls.scratch.name, {})
        cls.base_rows = PRESSURES.get(cls.base.name, {})

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        cls.base.cleanup()

    def test_every_scenario_and_workload_passes_with_reclaim(self):
        # Every earlier scenario and workload, with the filler, the gauge check (G10) and the lock check (G8) after
        # every step; scenarios 26-29 (G1-G3, G5, G7, G9, G12) are in 'pool'.
        self.assertEqual(self.result.returncode, 0, self.result.stdout[-3000:] + self.result.stderr[-3000:])
        for part in ('scenarios', 'race', 'pool', 'workload', 'arena', 'burst', 'recycled', 'pressure'):
            self.assertIn('PASS ' + part, self.result.stdout)
        self.assertEqual(self.base_result.returncode, 0, self.base_result.stdout[-3000:])
        self.assertEqual(sorted(self.rows), ['pressure no filler, budget 0', 'pressure no filler, resident',
                                             'pressure, budget 0', 'pressure, resident'])
        self.assertEqual(sorted(self.base_rows), ['pressure, budget 0', 'pressure, resident'])

    def test_residency_holds_no_iova(self):
        # G0: residency changes neither the DART's occupancy after any phase nor which allocations fail.
        for rows in (self.rows, self.base_rows):
            for prefix in sorted({name.rsplit(',', 1)[0] for name in rows}):
                zero, resident = rows[prefix + ', budget 0'], rows[prefix + ', resident']
                for key in ('held_trace', 'd_failures', 'e_failures', 'first_fail_pool_bytes', 'native_frees'):
                    self.assertEqual(zero[key], resident[key], (prefix, key))

    def test_the_base_fails_while_its_pool_parks(self):
        # The consoles' pattern: reserves refused ("VM exhausted") while the pool holds empty reservations.
        base = self.base_rows['pressure, budget 0']
        self.assertGreater(base['d_failures'], 0)
        self.assertGreater(base['first_fail_pool_bytes'], 8 * MiB)          # the general class still parked
        self.assertLess(base['first_fail_free_bytes'], base['first_fail_pool_bytes'])   # the pool parks more than is free
        self.assertEqual(base['exhausted'], 0)                               # no reclaim counters in the base

    def test_reclaim_removes_the_parking_failures(self):
        base, va = self.base_rows['pressure, budget 0'], self.rows['pressure, budget 0']
        self.assertEqual(va['d_failures'], 0)                                # G6
        self.assertGreater(va['reclaimed'], 0)
        self.assertGreater(va['drained_bytes'], 0)
        self.assertEqual(va['e_failures'], base['e_failures'])               # G7: overcommit fails in both ...
        self.assertGreater(va['reclaim_failed'], 0)                          # ... after a bounded reclaim
        self.assertEqual(va['lost'], 0)
        self.assertEqual(va['pressure_refused'], 4096)                       # G9: exactly ADRENO_VA_PRESSURE_PUTS ...
        self.assertGreater(va['f_puts'], 0)                                  # ... then the pool admits again
        self.assertLess(va['inserts'], base['inserts'])                      # a filled free: one insert per MiB
        self.assertLessEqual(va['pins'], base['pins'])                       # and no re-pin of a backing (G5)
        print('\n' + '\n'.join('%-34s fail D/E %3d/%d  pool at 1st fail %5.1f MiB  reclaim ok/fail %d/%d  drained %d '
                               '(%5.1f MiB)  filled %5d  pressure %4d  inserts %6d  pins %4d' % (
                                   ('va ' if src is self.rows else 'base ') + name, row['d_failures'], row['e_failures'],
                                   row['first_fail_pool_bytes'] / MiB, row['reclaimed'], row['reclaim_failed'],
                                   row['drained'], row['drained_bytes'] / MiB, row['filled_frees'],
                                   row['pressure_refused'], row['inserts'], row['pins'])
                               for src in (self.base_rows, self.rows) for name, row in sorted(src.items())))

    def test_no_filler_is_the_base(self):
        # G12: with the define but no filler, every count equals the base build's.
        for name in ('budget 0', 'resident'):
            va, base = dict(self.rows['pressure no filler, ' + name]), dict(self.base_rows['pressure, ' + name])
            self.assertEqual(va.pop('exhausted'), base['alloc_failed'], name)   # counted, nothing else done
            for row in (va, base):
                row.pop('policy'); row.pop('filler')
            base.pop('exhausted')
            self.assertEqual(va, base, name)

    def test_perf_va_line_fits(self):
        # G16: every field at the cap stays within ADRENO_PERF_LINE_MAX (250).
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'va-line.c'
            source.write_text('#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
                              '#include "AdrenoDisplayPacing.h"\nint main(void) { uint64_t v[ADRENO_PERF_VA_FIELDS];\n'
                              'char line[512]; for (unsigned i = 0; i < ADRENO_PERF_VA_FIELDS; i++) v[i] = ~0ULL;\n'
                              'int n = adreno_perf_line_va(line, sizeof line, ~0ULL, v);\n'
                              'printf("%d %s\\n", n, line); return n > ADRENO_PERF_LINE_MAX || (size_t)n != strlen(line); }\n')
            exe = Path(d) / 'va-line'
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-DADRENO_VA_RECLAIM=1',
                            '-I' + str(PACING_H.parent), str(source), '-o', str(exe)], check=True, capture_output=True)
            result = subprocess.run([str(exe)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertTrue(result.stdout.split(' ', 1)[1].startswith('AdrenoDisplay: perf va s=999999999 mib='))


# agents/gpu-va: weakened reclaim cores; each must fail under VA.
VA_MUTANTS = {
    'a drain takes a parked collision (G1)': (
        '        if ((p->flags[i] & ADRENO_VA_POOL_SUSPECT) || (fit && p->span[i] < fit)) continue;',
        '        if (fit && p->span[i] < fit) continue;'),
    'the last run is never filled (G2)': (
        '    for (uint64_t offset = 0; offset < span;) {\n        uint64_t va = address + offset, bytes = LEAF_SPAN',
        '    for (uint64_t offset = 0; offset + f->bytes < span;) {\n        uint64_t va = address + offset, bytes = LEAF_SPAN'),
    'a pinned reservation is filled (G3)': (
        '        if (filler_ok(pool->filler) && !(r->flags & ADRENO_RESOURCE_PINNED)) return filled_free(r, pool);',
        '        if (filler_ok(pool->filler)) return filled_free(r, pool);'),
    'a failed fill still frees natively (G2)': (
        '        if (f->insert(f->ctx, address, offset, f->pa, bytes)) return ADRENO_RESOURCE_E_INSERT;',
        '        if (f->insert(f->ctx, address, offset, f->pa, bytes)) break;'),
    'no retry after the drain (G6)': (
        '        e = adreno_resource_reserve(r, o, length);\n        if (e != ADRENO_RESOURCE_E_RESERVE || r->flags) break;',
        '        break;'),
    'a drain that keeps the class count (G1, K7)': (
        '        p->arena_count -= arena;                                 /* K7 for a drained entry */\n', ''),
    'pressure parks collisions too (G1)': (
        '    if (p->pressure && !(flags & ADRENO_VA_POOL_SUSPECT)) {',
        '    if (p->pressure) {'),
}


class VAMutants(unittest.TestCase):
    def test_weakened_reclaim_fails(self):
        core = CORE.read_text()
        for name, (old, new) in VA_MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(core.count(old), 1, name)
                mutated = Path(d) / 'adreno-resource.c'
                mutated.write_text(core.replace(old, new))
                exe = build(d, mutated, MUTANT_FLAGS + VA)
                result = subprocess.run([str(exe), 'all'], capture_output=True, text=True, timeout=900)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertNotIn('PASS: all', result.stdout, name)


class VAKext(unittest.TestCase):
    """The kext glue the model stands for (G4, G10, G12-G14, G16): source facts."""
    @classmethod
    def setUpClass(cls):
        cls.source = MAP.read_text()
        cls.display = read_source(KEXT / 'src/AdrenoDisplay.cpp')     # with its ordered parts

    def test_filler_is_read_only_and_never_released(self):
        insert = between(self.source, 'static int fillerInsert(')
        self.assertIn('iovmInsert(kIODMAMapReadAccess, address, offset, pa, size)', insert)
        self.assertNotIn('gFillerBuffer->complete', self.source)
        self.assertNotIn('gFillerBuffer->release', self.source)
        self.assertNotIn('OSSafeReleaseNULL(gFillerBuffer)', self.source)
        make = between(self.source, 'static const struct adreno_va_filler *fillerMake()\n{')
        self.assertIn('kIOMemoryPhysicallyContiguous', make)
        self.assertIn('return nullptr;', make)                            # G12: no filler, no reclaim
        pool = between(self.source, 'static struct adreno_va_pool *pool()')
        self.assertLess(pool.index('gPool.filler = fillerMake();'), pool.index('__atomic_store_n(&gPoolState, 2'))

    def test_gauge_follows_every_native_reserve_and_free(self):
        self.assertIn('vaHeld((int64_t)*span);', between(self.source, 'int AdrenoMemoryMap::reservePages('))
        self.assertIn('vaHeld(-(int64_t)length);', between(self.source, 'int AdrenoMemoryMap::freePages('))
        self.assertIn('vaHeld(-(int64_t)length);', between(self.source, 'static int fillerFree('))

    def test_every_change_is_behind_the_define(self):
        # G11: the define-off objects are compared section by section by agents/gpu-va/build/build-kext.sh; here,
        # every new identifier sits inside #if ADRENO_VA_RECLAIM.
        for text in (self.source, self.display, CORE.read_text()):
            depth, inside = 0, []
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith('#if'):
                    inside.append('ADRENO_VA_RECLAIM' in stripped)
                elif stripped.startswith('#endif'):
                    inside.pop()
                elif any(word in line for word in ('gFiller', 'vaHeld', 'pool_drain', 'reclaim(', 'filled_free',
                                                    'AdrenoGPUVACounters', 'fVaMark')):
                    self.assertTrue(any(inside), line)


class Mutants(unittest.TestCase):
    def test_weakened_cores_fail(self):
        core = CORE.read_text()
        for name, (old, new) in MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(core.count(old), 1, name)
                mutated = Path(d) / 'adreno-resource.c'
                mutated.write_text(core.replace(old, new))
                exe = build(d, mutated, MUTANT_FLAGS)        # must compile: it fails by behaviour
                result = subprocess.run([str(exe), 'all'], capture_output=True, text=True, timeout=600)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertNotIn('PASS: all', result.stdout, name)


class Kext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MAP.read_text()
        cls.scratch = tempfile.TemporaryDirectory(prefix='adreno-residency-kext-')
        env = dict(os.environ, OUT=cls.scratch.name)
        subprocess.run(['sh', str(KEXT / 'build.sh')], check=True, timeout=900, env=env, capture_output=True)
        cls.binary = Path(cls.scratch.name) / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'
        cls.text = subprocess.run([OBJDUMP, '-d', '-C', '--no-show-raw-insn', str(cls.binary)],
                                  capture_output=True, text=True, check=True).stdout

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def function(self, name):
        found = re.search(r'^[0-9a-f]+ <' + re.escape(name) + r'>:\n(.*?)(?=\n\n|\n[0-9a-f]+ <)', self.text,
                          re.S | re.M)
        self.assertIsNotNone(found, name)
        return found.group(1)

    def test_glue_matches_the_model(self):
        commit = between(self.source, 'bool AdrenoMemoryMap::commitIntoGPUPageTable()')
        self.assertIn('bool same = !fBacking || (nativeMemory() && nativeMemory()->get_iomd_ptr() == fBacking);', commit)
        self.assertIn('adreno_resource_rewire(&fResource, &ops, &gResidency, same, ADRENO_COMMIT_RUNS)', commit)
        release = between(self.source, 'void AdrenoMemoryMap::releaseFromGPUPageTable()')
        self.assertIn('adreno_resource_unwire(&fResource, &ops, &gResidency, backingKeepable())', release)
        keep = between(self.source, 'bool AdrenoMemoryMap::backingKeepable() const')
        self.assertIn('fBacking && memory && memory->get_iomd_ptr() == fBacking', keep)
        self.assertIn('!(fBackingDirection == kIODirectionOut &&', keep)
        self.assertIn('(fBacking->getDirection() & kIODirectionOutIn) != kIODirectionOut)', keep)
        free = between(self.source, 'bool AdrenoMemoryMap::releaseAddress()')
        self.assertIn('adreno_resource_free_with(&fResource, &ops, &gResidency, ADRENO_COMMIT_RUNS)', free)
        update = between(self.source, 'bool AdrenoMemoryMap::updateGPUPageTable()')
        self.assertIn('(fResource.flags & ADRENO_RESOURCE_RESIDENT)', update)
        self.assertIn('static struct adreno_residency gResidency = {kAdrenoResidentBudget, 0, 0, 0, 0, 0};', self.source)
        for old in ('adreno_resource_commit(', 'adreno_resource_release(', 'adreno_resource_free('):
            self.assertNotIn(old, self.source)
        header = (KEXT / 'src/AdrenoX2.h').read_text()
        self.assertIn('#define ADRENO_RESIDENT_BUDGET_MIB 512\n', header)

    def test_the_kext_still_inserts_and_clears_natively(self):
        insert = between(self.source, 'int AdrenoMemoryMap::insertPage(')
        self.assertIn('fMapper->iovmInsert(', insert)
        self.assertIn('address, offset, pa, size);', insert)                # a run's length reaches the mapper
        self.assertIn('ADRENO_GUEST_UNMAP', between(self.source, 'int AdrenoMemoryMap::clearPages('))

    def test_native_callbacks_reach_the_new_entry_points(self):
        for method, callee in (('AdrenoMemoryMap::commitIntoGPUPageTable()', 'adreno_resource_rewire'),
                               ('AdrenoMemoryMap::releaseFromGPUPageTable()', 'adreno_resource_unwire'),
                               ('AdrenoMemoryMap::releaseAddress()', 'adreno_resource_free_with')):
            body = self.function(method)
            self.assertRegex(body, r'\bbl\s+0x[0-9a-f]+ <_?' + callee + '>', method)
        for method in ('AdrenoMemoryMap::commitIntoGPUPageTable()', 'AdrenoMemoryMap::releaseFromGPUPageTable()',
                       'AdrenoMemoryMap::releaseAddress()'):
            self.assertNotRegex(self.function(method), r'<_?adreno_resource_(commit|release|free)>')


class Replays(unittest.TestCase):
    """The resource replays that link the core still pass: the old entry points are unchanged."""
    def test_existing_replays(self):
        shadow = ['compat/irq-forward.c', 'shadow/stage2.c', 'shadow/shadow.c', 'shadow/mmu.c']
        cases = {
            'tools/test-adreno.c': ['compat/adreno-submit.c', 'compat/adreno-resource.c', 'compat/adreno.c'],
            'tools/replay-adreno-resource-retention.c': ['compat/adreno-resource-list.c', 'compat/adreno-submit.c',
                                                         'compat/adreno-resource.c', 'compat/adreno.c'],
            'tools/replay-adreno-cache.c': ['compat/adreno-resource-list.c', 'compat/adreno-submit.c',
                                            'compat/adreno-resource.c', 'compat/adreno.c'],
        }
        for source, sources in cases.items():
            with self.subTest(source), tempfile.TemporaryDirectory() as d:
                exe = Path(d) / 'replay'
                subprocess.run(['cc', *FLAGS, '-Icompat', '-Ishadow', source, *sources, *shadow, '-o', str(exe)],
                               cwd=ROOT, check=True, timeout=300, capture_output=True)
                result = subprocess.run([str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=600)
                self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
                self.assertTrue(result.stdout.strip().splitlines()[-1].startswith('PASS'), result.stdout[-500:])


# agents/display-modeset: the head rule (compat/adreno-resource-tail.h, -DADRENO_RESIDENT_HEAD_OFFSET=1 with
# ADRENO_RESIDENT_REPIN). org2 and b12v23: WindowServer's 16 KiB buffer at a page-unaligned address under IOGPU's 32 KiB
# map, refused -83 at the onset of the Displays-pane glitch, then every composite listing it failed (-115).
TAIL = ROOT / 'compat/adreno-resource-tail.h'
REPIN = ['-DADRENO_RESIDENT_REPIN=1']
HEAD = REPIN + ['-DADRENO_RESIDENT_HEAD_OFFSET=1']
# Each weakens one head rule; scenario 33 (org2's buffer) or 34 (refusals, head-0 equivalence) must notice.
HEAD_MUTANTS = {
    'admission without the page bound': (
        '           logical <= adreno_tail_round_page(head + bytes);\n}', '           1;\n}'),
    'first page not moved back to its start': (
        'lead = offset ? 0 : head;', 'lead = 0;'),
    'last page not mapped whole': (
        '*length = span == bytes - at ? adreno_tail_round_page(head + bytes) - offset : span + lead;',
        '*length = span + lead;'),
    'a misplaced segment accepted': (
        'pa < lead || ((pa - lead) & (ADRENO_TAIL_PAGE - 1)))', 'pa < lead)'),
    'descriptor offset ignores the head': (
        '    return offset ? offset - head : 0;', '    return offset;'),
    'partial first line only invalidated': (
        '(stop < lead ? stop : lead) - start, ADRENO_CACHE_TO_DEVICE};',
        '(stop < lead ? stop : lead) - start, direction};'),
    'maintenance from the map start, not the first line': (
        '    const uint64_t start = offset > first ? offset : first;', '    const uint64_t start = offset;'),
    'client offset not moved by the head': ('    *map_offset = head + offset;', '    *map_offset = offset;'),
    'client range bounded by the map, not the descriptor': (
        'offset > bytes || len > bytes - offset) return 0;',
        'offset > bytes + head || len > bytes + head - offset) return 0;'),
}


def run_repin(directory, extra, header=None):
    """Build the model with `extra` (and a replacement adreno-resource-tail.h when given) and run its re-pin part."""
    include = []
    if header is not None:
        (Path(directory) / 'adreno-resource-tail.h').write_text(header)
        include = ['-I' + str(directory)]
    exe = Path(directory) / 'test-adreno-residency'
    subprocess.run(['cc', *FLAGS, *MUTANT_FLAGS, *extra, *include, '-Icompat', str(HARNESS), str(CORE), '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=300, capture_output=True)
    return subprocess.run([str(exe), 'repin'], capture_output=True, text=True, timeout=600)


class HeadOffset(unittest.TestCase):
    def test_org2_buffer_refused_without_the_rule(self):
        # The re-pin build alone: scenario 33 asserts the clean refusal (E_PIN) and a refused submission every round.
        with tempfile.TemporaryDirectory() as d:
            result = run_repin(d, REPIN)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertIn('PASS: repin', result.stdout)
        self.assertNotIn('PASS head', result.stdout)

    def test_org2_buffer_admitted_and_mapped_with_the_rule(self):
        with tempfile.TemporaryDirectory() as d:
            result = run_repin(d, HEAD)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertIn('PASS head', result.stdout)
        self.assertIn('PASS: repin', result.stdout)

    def test_weakened_head_rules_fail(self):
        header = TAIL.read_text()
        for name, (old, new) in HEAD_MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(header.count(old), 1, name)
                result = run_repin(d, HEAD, header.replace(old, new))
                self.assertNotEqual(result.returncode, 0, name)
                self.assertNotIn('PASS: repin', result.stdout, name)

    def test_kext_glue_uses_the_rule_behind_its_define(self):
        source = read_source(MAP)
        pin = between(source, 'int AdrenoMemoryMap::pinBacking(void *ctx)')
        self.assertIn('adreno_head_fit(bytes, map->fResource.logical_length)', pin)
        self.assertIn('map->admitHead(backing, direction, bytes, &head)', pin)
        self.assertLess(pin.index('backing->prepare(direction)'), pin.index('map->admitHead('))   # head known once wired
        physical = between(source, 'uint64_t AdrenoMemoryMap::physicalPage(')
        self.assertIn('adreno_head_run(offset, map->fBackingHead, map->fBackingBytes, pa, span, length)', physical)
        self.assertIn('adreno_head_descriptor_offset(offset, map->fBackingHead)', physical)
        admit = between(source, 'bool AdrenoMemoryMap::admitHead(')
        self.assertIn('adreno_head_admit(*head, bytes, fResource.logical_length)', admit)
        self.assertLess(admit.index('backing->complete(direction)'), admit.index('backing->release()'))
        for method in ('int AdrenoMemoryMap::resolveFill(', 'int AdrenoMemoryMap::resolveRange(',
                       'int AdrenoMemoryMap::cacheRange('):
            self.assertIn('headRange(offset,bytes,&at)', between(source, method), method)
        self.assertIn('adreno_head_cache(&fResource,fBackingHead,fBackingBytes,direction,0,fResource.logical_length',
                      between(source, 'int AdrenoMemoryMap::cacheSubmission('))
        self.assertIn('map->fBackingHead = 0;', between(source, 'int AdrenoMemoryMap::unpinBacking('))
        # Every head-rule identifier sits inside #if ADRENO_RESIDENT_HEAD_OFFSET (the define-off build is unchanged).
        words = ('fBackingHead', 'admitHead', 'headRange', 'headOffsetWanted', 'adreno_head_', 'kRepinHead', 'gHead')
        for name, text in (('AdrenoMemoryMap', source), ('AdrenoX2.h', (KEXT / 'src/AdrenoX2.h').read_text())):
            inside = []
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith('#if'):
                    inside.append('ADRENO_RESIDENT_HEAD_OFFSET' in stripped)
                elif stripped.startswith(('#elif', '#else')) and inside:
                    inside[-1] = 'ADRENO_RESIDENT_HEAD_OFFSET' in stripped and stripped.startswith('#elif')
                elif stripped.startswith('#endif'):
                    inside.pop()
                elif any(word in line for word in words) and not stripped.startswith('//'):
                    self.assertTrue(any(inside), name + ': ' + line)

    def test_desktop_profiles_build_the_rule_in_every_unit(self):
        profile = (KEXT / 'profiles/desktop-nocoherent.sh').read_text()
        common = re.search(r'^PROFILE_ALL="([^"]*)"', profile, re.M).group(1)
        self.assertIn('-DADRENO_RESIDENT_HEAD_OFFSET=1', common.split())
        self.assertIn('-DADRENO_RESIDENT_REPIN=1', common.split())
        self.assertIn('. "$D/profiles/desktop-nocoherent.sh"', (KEXT / 'profiles/desktop.sh').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
