#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The IOMFB call trace (-DADRENO_DISPLAY_TRACE_MODES=1, gpu/adreno-kext/kext/src/AdrenoDisplay/trace.cpp) and the
swap-geometry rule it logs (AdrenoDisplayCopy.h adreno_display_swap_geometry). Offline: no hardware.

    python3 tools/test-adreno-display-trace.py [-v]

- geometry: tools/test-adreno-display-present.c `geometry` runs the rule over the panel's mode and macOS's scaled
  resolutions of a 2880x1800 panel; weakened rules must fail.
- the trace is logging only: every traced IOMFB method forwards its arguments unchanged to IOMobileFramebufferLegacy and
  returns that result; every identifier it adds sits behind its define (the define-off kext is section-identical,
  checked with tools/macho-sections.py by the change's handoff, not here).
- ABI: tools/check-iomfb-vtable.py with the desktop profile's AdrenoDisplay defines plus the trace: every one of the 483
  slots keeps Apple's PAC diversity and binds to the right target, and every IOMFB symbol the overrides call is
  exported by the kernelcache. SKIP without the KDK or the J700 kernelcache (SNAP_KERNELCACHE, default
  downloads/extracted/j700ap/kernelcache.release.mac17p).
"""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_text import read_source  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'gpu/adreno-kext/kext/src'
HARNESS = ROOT / 'tools/test-adreno-display-present.c'
COPY = SRC / 'AdrenoDisplayCopy.h'
TRACE = SRC / 'AdrenoDisplay/trace.cpp'
HEADER = SRC / 'AdrenoDisplay.h'
PROFILE = ROOT / 'gpu/adreno-kext/kext/profiles/desktop-nocoherent.sh'
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk')
KC = Path(os.environ.get('SNAP_KERNELCACHE', ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'))
FLAGS = ['-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations']
DEFINE = 'ADRENO_DISPLAY_TRACE_MODES'

# Each weakens one clause of adreno_display_swap_geometry; the geometry cases must notice.
GEOMETRY_MUTANTS = {
    'scaling not seen': ('    if (sw != dw || sh != dh)\n', '    if (0)\n'),
    'placement judged by origin only': (
        '    if (dx || dy || dw < 0 || dh < 0 || (uint64_t)dw != panel_w || (uint64_t)dh != panel_h)\n',
        '    if (dx || dy)\n'),
    'source offset ignored': ('    if (sx || sy || sw < 0 || sh < 0 ||\n', '    if (sw < 0 || sh < 0 ||\n'),
    'surface size ignored': (
        '    if ((surface_w || surface_h) && (surface_w != panel_w || surface_h != panel_h))\n', '    if (0)\n'),
}


def geometry(header_text=None):
    """Build the present harness (against a replacement AdrenoDisplayCopy.h when given) and run `geometry`."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        harness = HARNESS
        if header_text is not None:
            # The harness includes ../gpu/adreno-kext/kext/src/<header>: mirror that layout around a copy.
            (d / 'tools').mkdir()
            (d / 'gpu/adreno-kext/kext/src').mkdir(parents=True)
            harness = d / 'tools' / HARNESS.name
            shutil.copy(HARNESS, harness)
            for h in SRC.glob('AdrenoDisplay*.h'):
                shutil.copy(h, d / 'gpu/adreno-kext/kext/src' / h.name)
            (d / 'gpu/adreno-kext/kext/src' / COPY.name).write_text(header_text)
        exe = d / 'present'
        # A mutant may leave a parameter unused; that must not be why it fails.
        extra = ['-Wno-unused-parameter'] if header_text is not None else []
        subprocess.run(['xcrun', 'clang', *FLAGS, *extra, str(harness), '-o', str(exe)], check=True,
                       capture_output=True, timeout=300)
        return subprocess.run([str(exe), 'geometry'], capture_output=True, text=True, timeout=120)


def body(text, signature):
    start = text.index(signature)
    return text[start:text.index('\n}\n', start)]


class Geometry(unittest.TestCase):
    def test_cases_pass(self):
        r = geometry()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        row = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(row['failures'], 0)
        self.assertGreaterEqual(row['geometry_cases'], 12)

    def test_weakened_rules_fail(self):
        text = COPY.read_text()
        for name, (old, new) in GEOMETRY_MUTANTS.items():
            with self.subTest(name):
                self.assertEqual(text.count(old), 1, name)
                r = geometry(text.replace(old, new))
                self.assertNotEqual(r.returncode, 0, name)


class TraceIsLoggingOnly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trace = TRACE.read_text()
        cls.header = HEADER.read_text()

    def overrides(self):
        block = self.header[self.header.index('#if ' + DEFINE + '\n    // The IOMFB call trace'):]
        block = block[:block.index('#endif')]
        return re.findall(r'virtual IOReturn (\w+)\(', block)

    def test_every_traced_method_forwards_and_returns_the_family_result(self):
        names = self.overrides()
        self.assertGreaterEqual(len(names), 20)
        for name in names:
            with self.subTest(name):
                fn = body(self.trace, f'IOReturn AdrenoDisplay::{name}(')
                signature = fn[:fn.index('\n{')]
                args = re.findall(r'\b(a[0-9]|properties|owningTask|securityID|type|handler)\b', signature)
                call = f'const IOReturn r = IOMobileFramebufferLegacy::{name}({", ".join(args)});'
                self.assertIn(call, fn)
                self.assertTrue(fn.rstrip().endswith('return r;'), name)
                self.assertEqual(fn.count('return'), 2 if name == 'setProperties' else 1, name)
        mode = body(self.trace, 'IOReturn AdrenoDisplay::set_digital_out_mode(')
        self.assertIn('const IOReturn r = digitalOutMode(colorID, timingID);', mode)

    def test_mode_set_body_is_the_untraced_one(self):
        modeset = (SRC / 'AdrenoDisplay/modeset.cpp').read_text()
        self.assertIn('#if ' + DEFINE + '\nIOReturn AdrenoDisplay::digitalOutMode(unsigned int colorID, unsigned int '
                      'timingID)', modeset)
        self.assertIn('#else\nIOReturn AdrenoDisplay::set_digital_out_mode(unsigned int colorID, unsigned int timingID)'
                      '\n#endif\n{', modeset)

    def test_every_trace_identifier_is_behind_the_define(self):
        words = ('traceSwapGeometryGated', 'traceWindowGated', 'digitalOutMode', 'TRACE_CALL', 'gTraceCalls',
                 'gTraceMark', 'traceCount', 'traceDue', 'adreno_display_swap_geometry')
        unit = read_source(SRC / 'AdrenoDisplay.cpp')
        for name, text in (('AdrenoDisplay unit', unit), ('AdrenoDisplay.h', self.header)):
            inside = []
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith('#if'):
                    inside.append(DEFINE in stripped)
                elif stripped.startswith('#el') and inside:
                    inside[-1] = DEFINE in stripped and stripped.startswith('#elif')
                elif stripped.startswith('#endif'):
                    inside.pop()
                elif any(w in line for w in words) and not stripped.startswith('//'):
                    self.assertTrue(any(inside), f'{name}: {line}')

    def test_the_desktop_profiles_build_the_trace(self):
        profile = PROFILE.read_text()
        display = re.search(r'^U_AdrenoDisplay="([^"]*)"', profile, re.M).group(1)
        self.assertIn('-D' + DEFINE + '=1', display.split())


class VTable(unittest.TestCase):
    def test_trace_keeps_apple_slots(self):
        if not KDK.is_dir() or not KC.is_file():
            self.skipTest(f'needs {KDK} and the J700 kernelcache ({KC}; set SNAP_KERNELCACHE)')
        env = dict(os.environ, D=str(PROFILE.parent.parent))
        defines = subprocess.run(['sh', '-c', f'. "{PROFILE}"; echo "$U_AdrenoDisplay"'], capture_output=True, text=True,
                                 env=env, check=True).stdout.split()
        args = []
        for d in [x[2:] for x in defines if x.startswith('-D')]:
            args += ['--display-define', d]
        self.assertIn(DEFINE + '=1', args)
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, str(ROOT / 'tools/check-iomfb-vtable.py'), '--kc', str(KC), '--out', out,
                            *args], capture_output=True, text=True, timeout=1800)
            report = json.loads((Path(out) / 'iomfb-vtable-check.json').read_text())
        display = report['classes']['AdrenoDisplay']
        self.assertEqual((display['slots'], display['errors'], len(display['extra_slots'])), (483, 0, 0))
        # The bundle links AdrenoDisplay.o alone, so the profile's references into AdrenoX2.o stay undefined there;
        # none of them may be an IOMFB or IOKit symbol the overrides call.
        missing = report['undefined_not_exported']
        self.assertFalse([m for m in missing if 'IOMobileFramebuffer' in m or 'IOService' in m or 'OSCollection' in m],
                         missing)


if __name__ == '__main__':
    unittest.main()
