#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The q1n1 heap layout the loader uses (probes/run.py) after the monitor's
code reservation grew to 464 KiB: code, report, stopped-probe scratch, SMP
configuration page and work locator stay in that order without overlapping.
The 448 KiB step moved OUT_AT; the 464 KiB step moved CODE_AT down, because
the report must end where the stopped-probe scratch begins (secondary-runtime
collect writes it before the report is read). Host only; the monitor binary
itself does not depend on the reservation (the report address is passed to
xnuboot_setup)."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import monitor_work  # noqa: E402
import run  # noqa: E402


class HeapLayout(unittest.TestCase):
    def test_regions_in_order(self):
        self.assertEqual(run.OUT_AT - run.CODE_AT, 464 << 10)
        self.assertLessEqual(run.OUT_AT + run.REPORT_RESERVE, run.STOPPED_PROBE_AT)
        self.assertLess(run.STOPPED_PROBE_AT, run.SECONDARY_CONFIG_AT)
        self.assertEqual(run.OUT_HEADROOM, run.SECONDARY_CONFIG_AT - run.OUT_AT)
        self.assertLessEqual(run.SECONDARY_CONFIG_AT + 4096, run.WORK_AT)
        # The work locator host tools read from a stopped A16 is at WORK_AT.
        self.assertEqual(monitor_work.LOCATOR_OFFSET, run.WORK_AT)

    def test_only_the_code_start_moved(self):
        # The report's place and size, the SMP page and the work locator are
        # protocol with running stages and stopped-state tools.
        self.assertEqual((run.OUT_AT, run.SECONDARY_CONFIG_AT, run.WORK_AT, run.REPORT_RESERVE),
                         (0x470000, 0x4f0000, 0x500000, 0x10000))
        self.assertEqual(run.CODE_AT, 0x3fc000)

    def test_stopped_probes_use_the_scratch_after_the_report(self):
        # The probes run between the monitor's return and the report read
        # (tools/secondary-runtime.py collect) or on a stopped A16; their code
        # and output pages must stay clear of the code and report reservations.
        for name, pattern in (('probe-a16-cpus.py', r"heap_base'\]\+(0x[0-9a-f]+), info\['heap_base'\]\+(0x[0-9a-f]+)"),
                              ('probe-el2-memory.py', r"heap_base'\]\+(0x[0-9a-f]+), info\['heap_base'\]\+(0x[0-9a-f]+)")):
            text = (ROOT / 'tools' / name).read_text()
            found = [int(x, 16) for m in re.finditer(pattern, text) for x in m.groups()]
            self.assertTrue(found, name)
            for offset in found:
                self.assertGreaterEqual(offset, run.STOPPED_PROBE_AT, name)
                self.assertLess(offset, run.SECONDARY_CONFIG_AT, name)

    def test_below_the_code_only_a_fresh_stage_tool(self):
        # tools/qualify-txm-image4-native.py places 3 MiB at heap+0x100000,
        # up to 0x400000, which now covers the code reservation's first
        # 16 KiB. It requires a fresh stage: no resident monitor to keep.
        text = (ROOT / 'tools/qualify-txm-image4-native.py').read_text()
        self.assertIn('Requires a fresh stage', text)
        self.assertIn("work = (info['heap_base'] + 0x100000 + 0x3fff) & ~0x3fff", text)
        self.assertGreaterEqual(run.CODE_AT, 0x100000)
        self.assertEqual(run.CODE_AT % 0x4000, 0)

if __name__ == '__main__':
    unittest.main()
