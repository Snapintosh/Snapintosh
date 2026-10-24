#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""--view-reclaim, offline: the kernel view pool's reclaim against a monitor-shaped model, weakened implementations it
must reject, the consumers that index tables by position, the opt-in wiring and (on request) the monitor's identity
and size. No hardware.

    python3 tools/test-view-reclaim.py                                    # model, mutants, consumers, wiring
    python3 tools/test-view-reclaim.py --build --qualification QUAL.json  # + monitors: define absent, =0, =1

Model: tools/test-view-reclaim.c (ASan/UBSan, -DSNAP_VIEW_RECLAIM=1) fills the 256-table pool, releases, reclaims,
reuses the retired pages and checks every CPU's walk, publication and the no-store-before-TLBI rule (its header lists
them). Each MUTANTS entry weakens one property in a copy of shadow/sprr-view.c; the same program must FAIL on every one.
Consumers: tools/test-kernel-pperm-variants.c (reuse snapshot, publication rows, PPERM variant columns) with and
without the define.

Wiring: shadow/sprr-view.h defaults SNAP_VIEW_RECLAIM to 0 and every monitor use sits under it; installed-fresh
--view-reclaim appends the define last; the report record's place agrees between probes/xnuboot/report_layout.c and
tools/perf_counters.py, whose decoder refuses an inconsistent record.

--build: xnuboot with each --qualification's flags, define absent, =0 and =1: absent == =0 == the qualification's
monitor_sha256; =1 differs and fits the code budget (probes/run.py OUT_AT - CODE_AT), its headroom printed.
"""
from pathlib import Path
import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument('--build', action='store_true')
_ap.add_argument('--qualification', action='append', default=[])
_ap.add_argument('--out')
ARGS, REST = _ap.parse_known_args() if __name__ == '__main__' else (_ap.parse_args([]), [])
CC = ['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
      '-Wall', '-Wextra', '-Werror', '-Icompat', '-Ishadow']
VIEW = ['shadow/shadow.c', 'shadow/mmu.c']
MUTANTS = (
    ('selector2 tables retired', 'need=(UINT32_C(0x214)>>', 'need=(UINT32_C(0x210)>>'),
    ('retired pages dropped by the compaction',
     '        struct sprr_view_table t=v->tables[w];\n        v->tables[w++]=v->tables[n];v->tables[n]=t;',
     '        v->tables[w++]=v->tables[n];'),
    ('no room check before the adds', '    if(v->count+missing>SPRR_VIEW_TABLES)return 0;\n', '    (void)missing;\n'),
    ('a retired set reused before its invalidation', '    if(t->level)return 0;\n', '\n'),
    ('pages freed before the quiesce',
     '    v->count=w;\n    if(!quiesce(ctx))return -1;\n    for(unsigned n=w;n<count;n++)v->tables[n].level=0;',
     '    v->count=w;\n    for(unsigned n=w;n<count;n++)v->tables[n].level=0;\n    if(!quiesce(ctx))return -1;'),
    ('the quiesce before the unlinking',
     '    for(unsigned n=w;n<count;n++) {v->tables[n].source=0;v->tables[n].level=SPRR_VIEW_RETIRED;}\n'
     '    v->count=w;\n    if(!quiesce(ctx))return -1;',
     '    if(!quiesce(ctx))return -1;\n'
     '    for(unsigned n=w;n<count;n++) {v->tables[n].source=0;v->tables[n].level=SPRR_VIEW_RETIRED;}\n'
     '    v->count=w;'),
    ('an upper table kept for a retired child',
     'need=child>=0 && (v->tables[child].level!=level+1 || keep[child]);', 'need=child>=0;'),
    ('the root retired', '        int need=!level;\n', '        int need=0;\n'),
    ('retired sets never reused', '        uint64_t pa=t->copy[cpu] ? t->copy[cpu] : shadow_alloc_page(s);',
     '        uint64_t pa=shadow_alloc_page(s);'),
)


def work():
    return Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='view-reclaim-'))


def compile_run(test, view, binary, *defines):
    b = subprocess.run([*CC, *defines, test, str(view), *VIEW, '-o', str(binary)], cwd=ROOT,
                       capture_output=True, text=True)
    if b.returncode:
        return None, b.stderr[-2000:]
    r = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, text=True, timeout=1800)
    return r.returncode, (r.stdout + r.stderr)


class Model(unittest.TestCase):
    def test_model_passes(self):
        rc, out = compile_run('tools/test-view-reclaim.c', ROOT / 'shadow/sprr-view.c', work() / 'model',
                              '-DSNAP_VIEW_RECLAIM=1')
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn('PASS:', out)
        print('\n' + out.strip().splitlines()[-1], file=sys.stderr)

    def test_mutants_fail(self):
        source = (ROOT / 'shadow/sprr-view.c').read_text()
        out_dir = work()
        for n, (name, old, new) in enumerate(MUTANTS):
            self.assertEqual(source.count(old), 1, name)
            d = out_dir / f'mutant-{n}'
            d.mkdir(parents=True, exist_ok=True)
            (d / 'sprr-view.c').write_text(source.replace(old, new))
            rc, out = compile_run('tools/test-view-reclaim.c', (d / 'sprr-view.c').resolve(), (d / 't').resolve(),
                                  '-DSNAP_VIEW_RECLAIM=1')
            self.assertIsNotNone(rc, f'{name}: {out}')
            self.assertNotEqual(rc, 0, f'{name}: not caught')


class Consumers(unittest.TestCase):
    def test_variants_snapshot_publication(self):
        for defines in ([], ['-DSNAP_VIEW_RECLAIM=1']):
            rc, out = compile_run('tools/test-kernel-pperm-variants.c', ROOT / 'shadow/sprr-view.c',
                                  work() / f'variants{len(defines)}', *defines)
            self.assertEqual(rc, 0, out[-3000:])
            self.assertIn('PASS:', out)
            self.assertEqual('reclaim:' in out, bool(defines))


class Wiring(unittest.TestCase):
    def test_default_off(self):
        header = (ROOT / 'shadow/sprr-view.h').read_text()
        self.assertIn('#ifndef SNAP_VIEW_RECLAIM\n#define SNAP_VIEW_RECLAIM 0\n#endif', header)
        self.assertIn('#if SNAP_VIEW_RECLAIM\n#define SPRR_VIEW_TABLES 256u\n#else\n#define SPRR_VIEW_TABLES 128u\n#endif',
                      header)
        for path in ('probes/xnuboot/sptm_retype.c', 'probes/xnuboot/kernel_views.c', 'probes/xnuboot/report.c',
                     'probes/xnuboot/context.c'):
            stack = []
            for number, line in enumerate((ROOT / path).read_text().splitlines(), 1):
                d = line.strip()
                if d.startswith('#if'):
                    stack.append([d == '#if SNAP_VIEW_RECLAIM', False])
                elif d.startswith('#el') and stack:
                    stack[-1][1] = True
                elif d.startswith('#endif'):
                    stack.pop()
                elif re.search(r'kernel_views_prepare_change|kernel_view_reclaim|sprr_views_reclaim', line):
                    self.assertTrue(any(on and not other for on, other in stack), f'{path}:{number} unguarded')

    def test_cycle(self):
        from cycle_lib import installed_fresh as f
        import importlib.util
        spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        base = ['installed-fresh', '--prefix', 'x', '--variant', 'fast', '--check']
        self.assertFalse(cli.parse(base).view_reclaim)
        self.assertTrue(cli.parse(base + ['--view-reclaim']).view_reclaim)
        self.assertEqual(f.VIEW_RECLAIM_DEFINE, '-DSNAP_VIEW_RECLAIM=1')
        src = (ROOT / 'tools/cycle_lib/installed_fresh.py').read_text()
        body = src[src.index('def variant_flags('):]
        body = body[:body.index('\n    return flags\n')]
        self.assertTrue(body.rstrip().endswith('flags.append(VIEW_RECLAIM_DEFINE)'), 'the define is not appended last')
        self.assertNotIn('view_reclaim', f.boot_addition(types.SimpleNamespace(view_reclaim=True)))

    def test_report_record(self):
        import runpy
        pc = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        layout = (ROOT / 'probes/xnuboot/report_layout.c').read_text()
        expr = re.search(r'#define OUT_VIEW_RECLAIM \(OUT_THERMAL([^)]*)\)', layout).group(1)
        thermal = int(re.search(r'#define A16_THERMAL_REPORT_OFFSET (0x[0-9a-f]+)u',
                                (ROOT / 'compat/a16-thermal.h').read_text()).group(1), 16) // 8
        terms = re.findall(r'-\s*(\w+)', expr)
        self.assertEqual(''.join(re.findall(r'\S', expr)), ''.join('-' + t for t in terms))
        word = thermal - sum(6 if t == 'VIEW_RECLAIM_WORDS' else int(t) for t in terms)
        offset, size = pc['view_reclaim_spec']()
        self.assertEqual((offset, size), (16 + 8 * word, 64))
        good = struct.pack('<8Q', pc['VIEW_RECLAIM_MAGIC'], 48 << 32, 140, 256, 2, 9, 0, 256)
        self.assertEqual(pc['decode_view_reclaim'](good)['free'], 116)
        for bad in (dict(magic=0), dict(count=0), dict(count=257), dict(high=139), dict(retired=1), dict(cap=128)):
            w = [pc['VIEW_RECLAIM_MAGIC'], 48 << 32, 140, 256, 2, 9, 0, 256]
            w[0] = bad.get('magic', w[0]); w[2] = bad.get('count', w[2]); w[3] = bad.get('high', w[3])
            w[5] = bad.get('retired', w[5]); w[7] = bad.get('cap', w[7])
            with self.assertRaises(ValueError, msg=str(bad)):
                pc['decode_view_reclaim'](struct.pack('<8Q', *w))


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (minutes)')
class Build(unittest.TestCase):
    def test_monitor(self):
        import monitor_build_offline as mbo
        out = work() / 'monitors'
        run = (ROOT / 'probes/run.py').read_text()
        budget = int(re.search(r'^OUT_AT = (0x[0-9a-fA-F]+)', run, re.M).group(1), 16) - \
            int(re.search(r'^CODE_AT = (0x[0-9a-fA-F]+)', run, re.M).group(1), 16)
        results = {}
        for path in ARGS.qualification:
            record = json.loads(Path(path).read_text())
            name, blobs = Path(path).parent.name, {}
            for label, extra in (('default', []), ('off', ['-DSNAP_VIEW_RECLAIM=0']), ('on', ['-DSNAP_VIEW_RECLAIM=1'])):
                d = out / f'{name}-{label}'
                if d.exists():
                    shutil.rmtree(d)
                r = mbo.build(ROOT, d, list(record['flags']) + extra)
                blobs[label] = r['sha256']
                results[f'{name}-{label}'] = dict(bytes=r['bytes'], headroom=budget - r['bytes'], sha256=r['sha256'])
                self.assertGreater(budget - r['bytes'], 0, f'{name}-{label} exceeds the code budget')
            self.assertEqual(blobs['default'], record['monitor_sha256'], name)
            self.assertEqual(blobs['off'], blobs['default'], name)
            self.assertNotEqual(blobs['on'], blobs['default'], name)
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST])
