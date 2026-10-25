#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests for tools/cycle.py CLI subcommands and error diagnostics."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CycleCLITests(unittest.TestCase):
    def run_cycle(self, *args):
        cmd = [sys.executable, str(ROOT / 'tools/cycle.py'), *args]
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)

    def test_help(self):
        res = self.run_cycle('--help')
        self.assertEqual(res.returncode, 0)
        self.assertIn('dashboard', res.stdout)
        self.assertIn('init-pins', res.stdout)
        self.assertIn('status', res.stdout)

    def test_status_check(self):
        res = self.run_cycle('status', '--check')
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data.get('status'), 'STATUS_PLAN')
        self.assertFalse(data.get('hardware_access'))

    def test_status_pretty(self):
        res = self.run_cycle('status', '--check', '--pretty')
        self.assertEqual(res.returncode, 0)
        self.assertIn('Status: STATUS_PLAN', res.stdout)

    def test_dashboard_no_color(self):
        res = self.run_cycle('dashboard', '--no-color')
        self.assertEqual(res.returncode, 0)
        self.assertIn('Snapintosh A16 Cycle Dashboard', res.stdout)
        self.assertIn('Target Machine: ASUS Zenbook A16', res.stdout)
        self.assertIn('Hardware Concurrency', res.stdout)

    def test_next_command(self):
        res = self.run_cycle('next')
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.strip())

    def test_init_pins(self):
        res = self.run_cycle('init-pins')
        self.assertEqual(res.returncode, 0)
        pins = ROOT / 'tools/cycle_lib/pins.json'
        self.assertTrue(pins.exists())


if __name__ == '__main__':
    unittest.main()
