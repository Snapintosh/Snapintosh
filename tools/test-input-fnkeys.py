#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test for cycle.py installed-fresh --input-fnkeys. No A16 access.

Without the option the boot-argument addition is exactly what earlier attempts qualified; with it, it appends
snap_i2c_fnkeys=FLAGS (decimal, as XNU's boot-arg parser reads any number), and refuses what SnapI2CHID's
hid_fnkeys_init would refuse (drivers/snap-i2c-hid/src/hid-keyboard.h) and a run without the input AuxKC.
"""
import argparse
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from cycle_lib import installed_fresh as fresh          # noqa: E402
from cycle_lib.common import Refused                    # noqa: E402

spec = importlib.util.spec_from_file_location('cycle_cli', ROOT / 'tools/cycle.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

BASE = ' '.join([fresh.TIMESYNC_FLAG, fresh.COMPRESSOR_SW_FLAG])


def ns(**kw):
    return argparse.Namespace(**kw)


class InputFnKeys(unittest.TestCase):
    def test_default_unchanged(self):
        self.assertEqual(fresh.boot_addition(ns()), BASE)
        self.assertEqual(fresh.boot_addition(ns(input=True, input_fnkeys=None)), BASE)

    def test_flags(self):
        for flags in (0x1, 0x2, 0x3, 0x5, 0x7, 0x9, 0x13, 0x17):
            self.assertEqual(fresh.boot_addition(ns(input=True, input_fnkeys=flags)), f'{BASE} snap_i2c_fnkeys={flags}')
        self.assertEqual(fresh.boot_addition(ns(input=True, console=True, input_fnkeys=3)),
                         ' '.join([BASE, fresh.CONSOLE_FLAG, 'snap_i2c_fnkeys=3']))

    def test_refusals(self):
        for flags in (0, -1, 0x20, 0x100, 0x19, 0x1f, 0x4, 0x6, 0x8, 0x10):
            with self.assertRaises(Refused, msg=hex(flags)):
                fresh.boot_addition(ns(input=True, input_fnkeys=flags))
        with self.assertRaises(Refused):
            fresh.boot_addition(ns(input_fnkeys=3))

    def test_cli_reaches_args(self):
        a = cli.parse(['installed-fresh', '--prefix', 'x', '--variant', 'fast', '--check', '--input', '--input-fnkeys',
                       '0x3'])
        self.assertEqual(a.input_fnkeys, 3)

    def test_cli_value_reaches_the_boot_args(self):
        base = ['installed-fresh', '--prefix', 'x', '--variant', 'fast', '--check', '--input']
        for text, value in (('0x3', 3), ('3', 3), ('0x13', 19), ('0b111', 7)):
            words = fresh.boot_addition(cli.parse(base + ['--input-fnkeys', text])).split()
            self.assertEqual([w for w in words if w.startswith('snap_i2c_fnkeys=')], [f'snap_i2c_fnkeys={value}'], text)
        self.assertFalse([w for w in fresh.boot_addition(cli.parse(base)).split() if w.startswith('snap_i2c_fnkeys')])


if __name__ == '__main__':
    unittest.main()
