#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test for cycle.py installed-fresh --adreno-cs-samplers. No A16 access.

Without the option the boot-argument addition is exactly what earlier attempts qualified; with it, it appends
adreno_cs_samplers=1 once. The other half of the contract is SnapAdreno's: the boot-arg name is the one AdrenoX2's
configureDevice reads, that read sits under ADRENO_IB_CS_SAMPLERS, and the desktop profiles build AdrenoX2 and
adreno-ib-command with that define (a kext without it ignores the boot-arg).
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from cycle_lib import installed_fresh as fresh          # noqa: E402

spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

BASE = ' '.join([fresh.TIMESYNC_FLAG, fresh.COMPRESSOR_SW_FLAG])
KEXT = ROOT / 'gpu/adreno-kext/kext'
BOOT_ARG = 'adreno_cs_samplers'
DEFINE = 'ADRENO_IB_CS_SAMPLERS'


def ns(**kw):
    return argparse.Namespace(**kw)


def profile_units(name):
    """{unit: defines} of a SnapAdreno profile, as build.sh sources it."""
    script = f'. "$D/profiles/{name}.sh"; set | grep "^U_"'
    out = subprocess.run(['sh', '-c', script], env=dict(os.environ, D=str(KEXT)), capture_output=True, text=True,
                         check=True).stdout
    units = {}
    for line in out.splitlines():
        unit, _, value = line.partition('=')
        units[unit[2:]] = value.strip('\'"').split()
    return units


class AdrenoCsSamplers(unittest.TestCase):
    def test_default_unchanged(self):
        self.assertEqual(fresh.boot_addition(ns()), BASE)
        self.assertEqual(fresh.boot_addition(ns(adreno_cs_samplers=False)), BASE)

    def test_flag_adds_the_boot_arg_once(self):
        self.assertEqual(fresh.boot_addition(ns(adreno_cs_samplers=True)), f'{BASE} {BOOT_ARG}=1')
        line = fresh.boot_addition(ns(console=True, single_user=True, adreno_cs_samplers=True, edp_backlight=True,
                                      input=True, input_fnkeys=3, resident_mib=1536))
        words = line.split()
        self.assertEqual(words.count(f'{BOOT_ARG}=1'), 1, line)
        for word in ('adreno_backlight=1', 'snap_i2c_fnkeys=3', 'adreno_resident_mib=1536', fresh.SINGLE_USER_FLAG):
            self.assertIn(word, words, line)

    def test_cli_reaches_args(self):
        base = ['installed-fresh', '--prefix', 'x', '--variant', 'fast', '--check']
        self.assertFalse(cli.parse(base).adreno_cs_samplers)
        self.assertTrue(cli.parse(base + ['--adreno-cs-samplers']).adreno_cs_samplers)

    def test_kext_reads_this_boot_arg_under_its_define(self):
        src = (KEXT / 'src/AdrenoX2/device.cpp').read_text()
        reads = re.findall(r'PE_parse_boot_argn\("(adreno_cs_samplers)"', src)
        self.assertEqual(reads, [BOOT_ARG])
        depth, guarded = [], None
        for line in src.splitlines():
            s = line.strip()
            if s.startswith('#if'):
                depth.append(DEFINE in s)
            elif s.startswith('#endif'):
                depth.pop()
            elif f'"{BOOT_ARG}"' in s and 'PE_parse_boot_argn' in s:
                guarded = any(depth)
        self.assertTrue(guarded, 'the boot-arg read is not under ADRENO_IB_CS_SAMPLERS')

    def test_desktop_profiles_build_the_opt_in(self):
        for name in ('desktop-nocoherent', 'desktop', 'desktop-backlight', 'desktop-next'):
            units = profile_units(name)
            for unit in ('AdrenoX2', 'adreno_ib_command'):
                self.assertIn(f'-D{DEFINE}=1', units.get(unit, []), f'{name} {unit}')


if __name__ == '__main__':
    unittest.main()
