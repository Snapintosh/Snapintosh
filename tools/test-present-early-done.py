#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test for --present-early-done: AdrenoDisplay completes a layer-0 swap right after its scanout copy
(gpu/adreno-kext/kext/src/AdrenoDisplayEarlyDone.h, -DADRENO_PRESENT_EARLY_DONE=1, profile desktop-early-done). No A16.

- the header's unit test (tools/test-adreno-early-done.c, ASan/UBSan) passes, and fails on each deliberate mutant;
- the kext uses the feature only inside ADRENO_PRESENT_EARLY_DONE blocks, and the desktop-early-done profile differs from
  desktop-backlight only in AdrenoDisplay.o (built when the private *26A428.h headers are present, else SKIP);
- cycle.py: without the new flags the boot arguments and the AuxKC choice are what they were; with them, the boot-args,
  the refusals and the early-done collection (refused until pinned);
- the presentation replay: without the define every output is the define-off build's; with it, the earlier outputs are
  unchanged and early-done.json has no failure and no cost failure (--no-replay skips this part, about 40 s).
"""
import argparse
import contextlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEXT = ROOT / 'gpu/adreno-kext/kext'
HEADER = KEXT / 'src/AdrenoDisplayEarlyDone.h'
sys.path.insert(0, str(ROOT / 'tools'))
from cycle_lib import installed_fresh as fresh          # noqa: E402
from cycle_lib.common import Refused                    # noqa: E402

spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

CC = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined']
# (name, anchor in the header, replacement): each must make the unit test fail.
MUTANTS = [
    ('late counted twice', '    e->tick_missed = 0;                   /* one late frame per missed tick */\n', ''),
    ('late window too wide', 'const int late = e->tick_missed && d < e->period;',
     'const int late = e->tick_missed && d < 2 * e->period;'),
    ('idle ticks missed', 'e->tick_missed = had_frame && !served;', 'e->tick_missed = !served;'),
    ('no renewal', '        e->until = now + e->hold;', '        if (!e->until) e->until = now + e->hold;'),
    ('hold one tick long', 'e->until && now < e->until;', 'e->until && now <= e->until;'),
    ('ahead not counted', 'if (!alone) { e->ahead++; return 0; }', 'if (!alone) return 0;'),
    ('always is adaptive', 'if (e->mode == ADRENO_EARLY_ALWAYS) return 1;', ''),
    ('arrival bins of 1 ms', 'two = 2 * e->ms;', 'two = e->ms;'),
]
REPLAY_DEFINES = ['-DADRENO_BEAM=1', '-DADRENO_PRESENT_CURSOR_STAGE=1', '-DADRENO_LATCH=1', '-DADRENO_PRESENT_SYNC=1',
                  '-DADRENO_PIPELINE=1', '-DADRENO_PRESENT_RELATCH=1']
RUN_REPLAY = True


def run_unit(header=None, out=None):
    with tempfile.TemporaryDirectory() as d:
        binary = Path(d) / 'early-done'
        extra = [f'-DEARLY_DONE_HEADER="{header}"'] if header else []
        build = subprocess.run(CC + extra + [str(ROOT / 'tools/test-adreno-early-done.c'), '-o', str(binary)],
                               capture_output=True, text=True)
        if build.returncode:
            return 'build', build.stderr
        r = subprocess.run([str(binary)], capture_output=True, text=True, cwd=ROOT / 'tools')
        return r.returncode, r.stdout + r.stderr


def scope_violations(path, pattern, define):
    """Lines matching pattern outside every '#if...define' block (or in its #else)."""
    stack, bad = [], []
    for n, line in enumerate(path.read_text().split('\n'), 1):
        s = line.strip()
        if re.match(r'#\s*if', s):
            stack.append([define in s and not s.startswith('#ifndef'), s])
            continue
        if re.match(r'#\s*(else|elif)', s) and stack:
            stack[-1][0] = False
            continue
        if re.match(r'#\s*endif', s) and stack:
            stack.pop()
            continue
        if s.startswith('*') or s.startswith('/*') or s.startswith('//'):
            continue
        code = re.sub(r'//.*|/\*.*?(\*/|$)', '', s)
        if re.search(pattern, code) and not any(on for on, _ in stack) and not re.match(r'#\s*define', s):
            bad.append(f'{path.relative_to(ROOT)}:{n}: {s}')
    return bad


class Header(unittest.TestCase):
    def test_unit_passes(self):
        code, out = run_unit()
        self.assertEqual(code, 0, out)
        self.assertIn('"failures":0', out)

    def test_mutants_fail(self):
        text = HEADER.read_text()
        for name, old, new in MUTANTS:
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(text.count(old), 1, f'{name}: anchor not found once')
                mutant = Path(d) / 'AdrenoDisplayEarlyDone.h'
                mutant.write_text(text.replace(old, new))
                code, out = run_unit(mutant)
                self.assertNotEqual(code, 0, f'{name}: the unit test passed a mutant\n{out}')


class Kext(unittest.TestCase):
    def test_scope(self):
        bad = []
        for path in sorted((KEXT / 'src').rglob('*')):
            if path.suffix in ('.cpp', '.h') and path.name != 'AdrenoDisplayEarlyDone.h':
                bad += scope_violations(path, r'\bfEarly\b|\bfScreenHeld\b|adreno_early_|earlyDoneNowGated|'
                                              r'AdrenoDisplayEarlyDone\.h', 'ADRENO_PRESENT_EARLY_DONE')
        self.assertEqual(bad, [])

    def test_profile(self):
        text = (KEXT / 'profiles/desktop-early-done.sh').read_text()
        self.assertIn('. "$D/profiles/desktop-backlight.sh"', text)
        self.assertEqual(re.findall(r'^U_\w+=.*$', text, re.M),
                         ['U_AdrenoDisplay="$U_AdrenoDisplay -DADRENO_PRESENT_EARLY_DONE=1"'])

    def test_profile_build(self):
        if not list((KEXT / 'include').glob('*26A428.h')) or not shutil.which('xcrun'):
            self.skipTest('SKIP: the private *26A428.h headers or Xcode are not present')
        with tempfile.TemporaryDirectory() as d:
            outs = {}
            for profile in ('desktop-backlight', 'desktop-early-done'):
                out = Path(d) / profile
                r = subprocess.run(['sh', str(KEXT / 'build.sh')], capture_output=True, text=True,
                                   env=dict(os.environ, OUT=str(out), PROFILE=profile, ZERO_AR_DATE='1'))
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                outs[profile] = out
            a, b = outs['desktop-backlight'] / 'obj', outs['desktop-early-done'] / 'obj'
            differ = sorted(o.name for o in a.iterdir() if o.read_bytes() != (b / o.name).read_bytes())
            self.assertEqual(differ, ['AdrenoDisplay.o'])
            da = (outs['desktop-backlight'] / 'DEFINES.txt').read_text().split('\n')
            db = (outs['desktop-early-done'] / 'DEFINES.txt').read_text().split('\n')
            changed = [(x, y) for x, y in zip(da, db) if x != y]
            self.assertEqual(len(changed), 2)                  # the profile name and AdrenoDisplay's line
            self.assertTrue(changed[1][1].startswith('AdrenoDisplay: ') and
                            changed[1][1] == changed[1][0] + ' -DADRENO_PRESENT_EARLY_DONE=1')


def chain(**kw):
    base = dict(variant='fast', input=True, input_touchpad=True, input_ptp=True, present_dartpool=True,
                present_resident=True, present_beam=True, present_va_reclaim=True, gpu_va_wide=True,
                present_latch=True, edp_backlight=True)
    base.update(kw)
    return types.SimpleNamespace(**base)


class Cycle(unittest.TestCase):
    def test_default_unchanged(self):
        args = chain()
        self.assertEqual(fresh.selected(args)[1], fresh.INPUT_AUXKC_DESKTOP_BACKLIGHT)
        self.assertNotIn('adreno_present_early', fresh.boot_addition(args))
        next3 = json.loads((ROOT.parent.parent / 'run/desktop-run-args-next3.json').read_text()) \
            if (ROOT.parent.parent / 'run/desktop-run-args-next3.json').is_file() else None
        if next3:
            a = cli.parse(next3 + ['--check'])
            self.assertNotIn('adreno_present_early', fresh.boot_addition(a))
            self.assertEqual(fresh.selected(a)[1], fresh.INPUT_AUXKC_DESKTOP_BACKLIGHT)

    def test_boot_args(self):
        for mode in (0, 1, 2):
            self.assertTrue(fresh.boot_addition(chain(present_early_done=mode)).endswith(
                f' adreno_present_early_done={mode}'))
        self.assertTrue(fresh.boot_addition(chain(present_early_done=2, present_early_hold_ms=5000)).endswith(
            ' adreno_present_early_done=2 adreno_present_early_hold_ms=5000'))
        self.assertIn('adreno_present_early_done=0', fresh.boot_addition(chain(present_early_done=0,
                                                                                present_hold='on')))

    def test_refusals(self):
        for bad in (dict(present_early_done=3), dict(present_early_done=1, present_hold='on'),
                    dict(present_early_done=2, present_hold='on'), dict(present_early_done=1, present_early_hold_ms=500),
                    dict(present_early_hold_ms=500), dict(present_early_done=2, present_early_hold_ms=99),
                    dict(present_early_done=2, present_early_hold_ms=10001), dict(present_early_done=1, edp_backlight=False)):
            with self.subTest(bad), self.assertRaises(Refused):
                fresh.boot_addition(chain(**bad))
        with self.assertRaises(Refused):                   # without the --edp-backlight chain: no collection has it
            fresh.selected(types.SimpleNamespace(variant='fast', input=True, present_early_done=1))

    def test_collection(self):
        for kw in (dict(present_early_done=0), dict(present_early_done=2), dict(gpu_coherent=True)):
            with self.subTest(kw):
                if fresh.INPUT_AUXKC_DESKTOP_EARLY_DONE is None:
                    with self.assertRaises(Refused):
                        fresh.selected(chain(**kw))
                else:
                    self.assertEqual(fresh.selected(chain(**kw))[1:3], (fresh.INPUT_AUXKC_DESKTOP_EARLY_DONE,
                                                                        fresh.INPUT_AUXKC_DESKTOP_EARLY_DONE_SHA))
        # --gpu-coherent without --edp-backlight keeps its collection (the latch chain's)
        self.assertEqual(fresh.selected(chain(edp_backlight=False, gpu_coherent=True))[1],
                         fresh.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH)

    def test_cli(self):
        base = ['installed-fresh', '--prefix', 'x', '--variant', 'fast', '--check', '--edp-backlight']
        a = cli.parse(base + ['--present-early-done', '2', '--present-early-hold-ms', '3000'])
        self.assertEqual((a.present_early_done, a.present_early_hold_ms), (2, 3000))
        self.assertIsNone(cli.parse(base).present_early_done)
        with self.assertRaises(SystemExit), open(os.devnull, 'w') as quiet, contextlib.redirect_stderr(quiet):
            cli.parse(base + ['--present-early-done', '5'])


class Replay(unittest.TestCase):
    def test_replay(self):
        if not RUN_REPLAY:
            self.skipTest('SKIP: --no-replay')
        with tempfile.TemporaryDirectory() as d:
            outs = {}
            for name, extra in (('off', []), ('on', ['-DADRENO_PRESENT_EARLY_DONE=1'])):
                binary = Path(d) / f'replay-{name}'
                build = subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror'] +
                                       REPLAY_DEFINES + extra + ['tools/replay-adreno-presentation.c', '-o', str(binary)],
                                       cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(build.returncode, 0, build.stderr)
                out = Path(d) / name
                out.mkdir()
                r = subprocess.run([str(binary), str(out)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
                outs[name] = (out, r.stdout)
            off, on = outs['off'][0], outs['on'][0]
            for j in sorted(off.glob('*.json')):
                self.assertEqual(j.read_bytes(), (on / j.name).read_bytes(), f'{j.name} changed with the define')
            self.assertFalse((off / 'early-done.json').exists())
            result = json.loads((on / 'early-done.json').read_text())
            self.assertEqual((result['failures'], result['cost_failures']), (0, 0))
            self.assertGreater(result['checks'], 0)
            for line in outs['on'][1].split('\n'):
                if line.startswith('early-done ') and 'arrivals' not in line:
                    print(line)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--no-replay', action='store_true')
    known, rest = ap.parse_known_args()
    RUN_REPLAY = not known.no_replay
    unittest.main(argv=[sys.argv[0]] + rest)
