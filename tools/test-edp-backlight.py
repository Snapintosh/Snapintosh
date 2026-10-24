#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""--edp-backlight, offline: the monitor engine against a controller model, weakened engines it must reject, the
opt-in wiring, and (on request) the default-build identity of the monitor and the kext. No hardware.

    python3 tools/test-edp-backlight.py                                  # model, mutations, wiring (seconds)
    python3 tools/test-edp-backlight.py --build --qualification QUAL.json   # + monitors: define absent, =0, =1
    python3 tools/test-edp-backlight.py --kext-reference DIR             # + kext: default sections == DIR's

Model: tools/test-edp-backlight.c runs compat/edp-backlight.{h,c} against a model of the eDP controller's AUX FIFO and a
DPCD panel and must PASS (ASan/UBSan). Each MUTATIONS entry weakens one safety property in a copy of the engine; the
same program must FAIL on every one.

Wiring: probes/xnuboot.c defaults SNAP_EDP_BACKLIGHT to 0 and every monitor use sits under it; compat/edp-backlight.c is
linked only through probes/run.py OPTIONAL; the call number and event number are unique; the kext's backlight code sits
under ADRENO_BACKLIGHT; installed-fresh appends the define last, adds the boot-args, and refuses until the AuxKC is
pinned.

--build: xnuboot with each --qualification's flags, define absent, =0 and =1: absent == =0 == the qualification's
monitor_sha256; =1 differs and fits the code budget (probes/run.py OUT_AT - CODE_AT), its headroom printed.
--kext-reference: the default AdrenoX2 built from this tree has every section of DIR/AdrenoX2.kext's (a default build
of the base commit, tools/macho-sections.py), and PROFILE=desktop-backlight builds.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
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
_ap.add_argument('--kext-reference')
_ap.add_argument('--out')
ARGS, REST = _ap.parse_known_args() if __name__ == '__main__' else (_ap.parse_args([]), [])
ENGINE = ('compat/edp-backlight.h', 'compat/edp-backlight.c', 'compat/dpu-intf.h')
MUTATIONS = (
    ('no floor', 'compat/edp-backlight.h', '#define EDP_BL_FLOOR_PERMILLE       100u', '#define EDP_BL_FLOOR_PERMILLE       0u'),
    ('no clamp', 'compat/edp-backlight.c', 'uint32_t level = edp_bl_clamp(request, s->floor, s->max);',
     'uint32_t level = (uint32_t)request;'),
    ('mask bits dropped', 'compat/edp-backlight.c', ' << 1 | (status & EDP_INTR_MASK_BITS));', ' << 1);'),
    ('stale status kept', 'compat/edp-backlight.c', '    aux_ack(s, rd(s, AHB(EDP_AHB_INTR_STATUS)));', '    (void)0;'),
    ('reads writable', 'compat/edp-backlight.h', '(read ? sizeof ok / sizeof ok[0] : 3u)',
     '(read || 1 ? sizeof ok / sizeof ok[0] : 3u)'),
    ('AUX_CTRL writable', 'compat/edp-backlight.h', '(uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_PHY_INTR_CLEAR)};',
     '(uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_PHY_INTR_CLEAR), (uint32_t)(EDP_DP3_AUX_PA + EDP_AUX_CTRL)};'),
    ('timeout retried later', 'compat/edp-backlight.c', '{ s->timed_out = 1; goto fail; }', 'goto fail;'),
    ('no read-back', 'compat/edp-backlight.c', 'return back[0] == bytes[0] && (len < 2 || back[1] == bytes[1]) ? 0 : EDP_BL_E_VERIFY;',
     'return 0;'),
    ('no clock check', 'compat/edp-backlight.c',
     '        {(uint32_t)(DPU_DISPCC_PA + DPU_DISPCC_MDSS_AHB_CBCR), DPU_CBCR_CLK_OFF, 0, EDP_BL_DETAIL_CLOCK},\n', ''),
    ('mode bits clobbered', 'compat/edp-backlight.c',
     '(uint8_t)((s->mode_reg & ~DPCD_EDP_BL_MODE_MASK) | DPCD_EDP_BL_MODE_DPCD)', '(uint8_t)DPCD_EDP_BL_MODE_DPCD'),
    ('no failure limit', 'compat/edp-backlight.c', '++s->failures >= EDP_BL_MAX_FAILURES', '++s->failures >= 1000u'),
    ('AUX caps ignored', 'compat/edp-backlight.c', 'if (!(s->caps[2] & DPCD_EDP_BL_AUX_SET_CAP))', 'if (0)'),
)
CFLAGS = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
          '-fno-sanitize-recover=all']


def build_and_run(work, compat_dir):
    exe = work / 'test-edp-backlight'
    b = subprocess.run(['clang', *CFLAGS, f'-I{compat_dir}', str(ROOT / 'tools/test-edp-backlight.c'),
                        str(compat_dir / 'edp-backlight.c'), '-o', str(exe)], capture_output=True, text=True)
    if b.returncode:
        return 'build', b.stdout + b.stderr
    r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=120)
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
        code = re.sub(r'//.*|/\*.*?(\*/|$)', '', s)
        if s.startswith('*') or s.startswith('/*'):
            continue
        if re.search(pattern, code) and not any(on for on, _ in stack) and not re.match(r'#\s*define', s):
            bad.append(f'{path.relative_to(ROOT)}:{n}: {s}')
    return bad


class Model(unittest.TestCase):
    def test_engine_passes(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = build_and_run(Path(d), ROOT / 'compat')
        self.assertEqual(code, 0, out)
        self.assertIn('edp-backlight: PASS', out)

    def test_mutations_fail(self):
        for name, rel, old, new in MUTATIONS:
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                work = Path(d)
                compat = work / 'compat'
                compat.mkdir()
                for f in ENGINE:
                    shutil.copy(ROOT / f, compat / Path(f).name)
                target = compat / Path(rel).name
                text = target.read_text()
                self.assertEqual(text.count(old), 1, f'{name}: anchor not found once')
                target.write_text(text.replace(old, new))
                code, out = build_and_run(work, compat)
                self.assertNotEqual(code, 'build', f'{name}: mutation does not compile: {out[-400:]}')
                self.assertNotEqual(code, 0, f'{name}: the model accepted a weakened engine')


class Wiring(unittest.TestCase):
    def test_monitor_default_off_and_guarded(self):
        src = (ROOT / 'probes/xnuboot.c').read_text()
        self.assertIn('#ifndef SNAP_EDP_BACKLIGHT\n#define SNAP_EDP_BACKLIGHT 0\n#endif', src)
        bad = []
        for path in [ROOT / 'probes/xnuboot.c', *sorted((ROOT / 'probes/xnuboot').glob('*.c'))]:
            bad += scope_violations(path, r'edp_backlight|EDP_BL_|EV_EDP_BACKLIGHT|ADRENO_GUEST_BACKLIGHT',
                                    'SNAP_EDP_BACKLIGHT')
        self.assertEqual(bad, [])

    def test_optional_unit(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        import monitor_build_offline as mbo
        self.assertNotIn('compat/edp-backlight.c', mbo.multi_sources(ROOT, []))
        self.assertIn('compat/edp-backlight.c', mbo.multi_sources(ROOT, ['-DSNAP_EDP_BACKLIGHT=1']))

    def test_numbers_unique(self):
        calls = {}
        for h in sorted((ROOT / 'compat').glob('*.h')):
            for name, value in re.findall(r'#define (ADRENO_GUEST_\w+) (0x[0-9A-Fa-f]+)\b', h.read_text()):
                calls.setdefault(int(value, 16), set()).add(name)
        self.assertEqual({v: n for v, n in calls.items() if len(n) > 1}, {})
        self.assertEqual(calls[0x0001000C], {'ADRENO_GUEST_BACKLIGHT'})
        events = {}
        for name, value in re.findall(r'#define (EV_\w+) +(\d+)', (ROOT / 'probes/xnuboot/report_layout.c').read_text()):
            events.setdefault(int(value), set()).add(name)
        self.assertEqual({v: n for v, n in events.items() if len(n) > 1}, {})

    def test_kext_guarded(self):
        kext = ROOT / 'gpu/adreno-kext/kext/src'
        h = (kext / 'AdrenoDisplay.h').read_text()
        self.assertIn('#ifndef ADRENO_BACKLIGHT\n#define ADRENO_BACKLIGHT 0\n#endif', h)
        bad = []
        for path in (kext / 'AdrenoDisplay.h', kext / 'AdrenoDisplay.cpp'):
            bad += scope_violations(path, r'AdrenoBacklight|backlight|edp-backlight|fBacklight|set_brightness_gated',
                                    'ADRENO_BACKLIGHT')
        self.assertEqual(bad, [])

    def test_cycle(self):
        from cycle_lib import installed_fresh as f
        chain = dict(variant='fast', input=True, input_touchpad=True, input_ptp=True, present_dartpool=True,
                     present_resident=True, present_beam=True, present_va_reclaim=True, gpu_va_wide=True,
                     present_latch=True)
        self.assertEqual(f.selected(types.SimpleNamespace(**chain))[1], f.INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH)
        if f.INPUT_AUXKC_DESKTOP_BACKLIGHT is None:
            with self.assertRaises(BaseException):
                f.selected(types.SimpleNamespace(**chain, edp_backlight=True))
        else:
            self.assertEqual(f.selected(types.SimpleNamespace(**chain, edp_backlight=True))[1],
                             f.INPUT_AUXKC_DESKTOP_BACKLIGHT)
        with self.assertRaises(BaseException):
            f.selected(types.SimpleNamespace(variant='fast', input=True, edp_backlight=True))
        self.assertNotIn('adreno_backlight', f.boot_addition(types.SimpleNamespace()))
        self.assertTrue(f.boot_addition(types.SimpleNamespace(edp_backlight=True)).endswith(' adreno_backlight=1'))
        self.assertTrue(f.boot_addition(types.SimpleNamespace(edp_backlight=True, edp_backlight_mode=True)).endswith(
            ' adreno_backlight=1 adreno_backlight_mode=1'))
        with self.assertRaises(BaseException):
            f.boot_addition(types.SimpleNamespace(edp_backlight_mode=True))
        # From the command line, as a run's argument list reaches installed-fresh.
        import importlib.util
        spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        base = ['installed-fresh', '--prefix', 'x', '--variant', 'fast', '--check']
        self.assertNotIn('adreno_backlight=1', f.boot_addition(cli.parse(base)).split())
        words = f.boot_addition(cli.parse(base + ['--edp-backlight'])).split()
        self.assertIn('adreno_backlight=1', words)
        self.assertNotIn('adreno_backlight_mode=1', words)
        words = f.boot_addition(cli.parse(base + ['--edp-backlight', '--edp-backlight-mode'])).split()
        self.assertEqual(words[-2:], ['adreno_backlight=1', 'adreno_backlight_mode=1'])
        src = (ROOT / 'tools/cycle_lib/installed_fresh.py').read_text()
        body = src[src.index('def variant_flags('):]
        body = body[:body.index('\n    return flags\n')]
        # Only defines added after this one (tools/test-view-reclaim.py) may follow it.
        body = body.replace("\n    if getattr(args, 'view_reclaim', False):\n        flags.append(VIEW_RECLAIM_DEFINE)", '')
        self.assertTrue(body.rstrip().endswith('flags.append(EDP_BACKLIGHT_DEFINE)'), 'the define is not appended last')


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (minutes)')
class Build(unittest.TestCase):
    def test_monitor(self):
        import monitor_build_offline as mbo
        out = Path(ARGS.out) / 'monitors' if ARGS.out else Path(tempfile.mkdtemp(prefix='edp-backlight-build-'))
        run = (ROOT / 'probes/run.py').read_text()
        budget = int(re.search(r'^OUT_AT = (0x[0-9a-fA-F]+)', run, re.M).group(1), 16) - \
            int(re.search(r'^CODE_AT = (0x[0-9a-fA-F]+)', run, re.M).group(1), 16)
        results = {}
        for path in ARGS.qualification:
            record = json.loads(Path(path).read_text())
            name, blobs = Path(path).stem, {}
            for label, extra in (('default', []), ('off', ['-DSNAP_EDP_BACKLIGHT=0']), ('on', ['-DSNAP_EDP_BACKLIGHT=1'])):
                r = mbo.build(ROOT, out / f'{name}-{label}', list(record['flags']) + extra)
                blobs[label] = r['sha256']
                results[f'{name}-{label}'] = dict(bytes=r['bytes'], headroom=budget - r['bytes'], sha256=r['sha256'])
                self.assertGreater(budget - r['bytes'], 0, f'{name}-{label} exceeds the code budget')
            self.assertEqual(blobs['default'], record['monitor_sha256'], name)
            self.assertEqual(blobs['off'], blobs['default'], name)
            self.assertNotEqual(blobs['on'], blobs['default'], name)
        print(json.dumps(results, indent=1), file=sys.stderr)


@unittest.skipUnless(ARGS.kext_reference, 'pass --kext-reference DIR to build the kext')
class Kext(unittest.TestCase):
    def test_default_sections(self):
        out = Path(ARGS.out) / 'kext' if ARGS.out else Path(tempfile.mkdtemp(prefix='edp-backlight-kext-'))
        env = dict(os.environ, ZERO_AR_DATE='1')
        kext = ROOT / 'gpu/adreno-kext/kext/build.sh'
        for profile, dest in (('', out / 'default'), ('desktop-backlight', out / 'desktop-backlight')):
            e = dict(env, OUT=str(dest), **({'PROFILE': profile} if profile else {}))
            b = subprocess.run(['sh', str(kext)], env=e, capture_output=True, text=True)
            self.assertEqual(b.returncode, 0, b.stdout[-2000:] + b.stderr[-2000:])
        ref = Path(ARGS.kext_reference) / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'
        c = subprocess.run([sys.executable, str(ROOT / 'tools/macho-sections.py'), str(ref),
                            str(out / 'default/AdrenoX2.kext/Contents/MacOS/AdrenoX2')], capture_output=True, text=True)
        self.assertRegex(c.stdout, r'(\d+) of \1 sections identical', c.stdout)
        nm = subprocess.run(['nm', '-m', str(out / 'desktop-backlight/AdrenoX2.kext/Contents/MacOS/AdrenoX2')],
                            capture_output=True, text=True).stdout
        self.assertIn('__ZN13AdrenoDisplay20set_brightness_gatedEi', nm)
        self.assertIn('__ZN15AdrenoBacklight10gMetaClassE', nm)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
