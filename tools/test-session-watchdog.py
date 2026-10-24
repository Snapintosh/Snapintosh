#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""--watchdog and --session for installed-fresh desktop runs (tools/cycle_lib/installed_fresh.py).

The default stays the 1800 s watchdog with the kext's first-present stop. --watchdog admits 1800..7200 s, and the
boot preflight then requires the A16 on AC. --session drops the guest trigger, so the kext never requests a stop and
the run ends at the watchdog, the thermal guard or a host stop. No hardware is touched.
"""
import argparse
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'probes')]

from cycle_lib import installed_fresh as fresh   # noqa: E402
from cycle_lib.common import Refused             # noqa: E402
import early_stop                                # noqa: E402


def ns(**kw):
    return argparse.Namespace(**kw)


class Watchdog(unittest.TestCase):
    def test_default_is_unchanged(self):
        env = fresh.environment(ns())
        self.assertEqual(env['SNAP_WATCHDOG'], '1800')
        self.assertEqual(env['SNAP_EARLY_STOP'], 'guest,host')
        self.assertEqual(fresh.run_watchdog(ns()), 1800)
        self.assertEqual(fresh.environment(ns(console=True))['SNAP_EARLY_STOP'], 'guest,console')

    def test_two_hours(self):
        env = fresh.environment(ns(watchdog=7200, console=True))
        self.assertEqual(env['SNAP_WATCHDOG'], '7200')
        self.assertEqual(fresh.run_watchdog(ns(watchdog=7200)), 7200)

    def test_bounds(self):
        for value in (1799, 7201, 0, -1):
            with self.assertRaises(Refused):
                fresh.environment(ns(watchdog=value))

    def test_early_stop_delay_below_the_run_watchdog(self):
        env = fresh.environment(ns(watchdog=3000, early_stop_delay=2400))
        self.assertEqual(env['SNAP_EARLY_STOP_DELAY'], '2400')
        with self.assertRaises(Refused):
            fresh.environment(ns(early_stop_delay=1800))          # not below the default watchdog
        with self.assertRaises(Refused):
            fresh.environment(ns(watchdog=2000, early_stop_delay=2000))


class Session(unittest.TestCase):
    def test_session_has_no_guest_trigger(self):
        env = fresh.environment(ns(console=True, session=True, watchdog=7200, thermal_guard=True))
        self.assertEqual(env['SNAP_EARLY_STOP'], 'console,thermal')
        settings = early_stop.settings(env)
        self.assertFalse(settings.flags & early_stop.F_GUEST)
        self.assertTrue(settings.flags & early_stop.F_CONSOLE)

    def test_session_needs_console_and_no_delay(self):
        with self.assertRaises(Refused):
            fresh.environment(ns(session=True))
        with self.assertRaises(Refused):
            fresh.environment(ns(console=True, session=True, early_stop_delay=600))


if __name__ == '__main__':
    unittest.main()
