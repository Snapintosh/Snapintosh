#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host test for tools/summarize-present-pacing.py on a synthetic console: two complete periodic windows (one busy, one
quiet, the quiet one with the early-completion perf done line), one incomplete window and one reject window, which
must both be left out."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('summarize', ROOT / 'tools/summarize-present-pacing.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def window(s, ib, pp, mean, tk, gtk, sub, cache, prep, go, defer, done=None, why='periodic'):
    lines = [
        f'AdrenoDisplay: perf why={why} s={s} presents=600 copies=600 win=600 mean_us=2000 max_us=3000 all_mean_us=2000 '
        'all_max_us=9000',
        f'AdrenoDisplay: perf pace s={s} pps=50.0 pp={pp} mean={mean} p95=34 tk={tk} late=700 off=0 gpu=1/2000 q=6000',
        f'AdrenoDisplay: perf vsync s={s} period_ns=16666666 grid=900/3000 early=1/100 skip=0 rs=0/0 lead=900 arm=1/0 '
        'unarmed=0 ticks=1',
        f'AdrenoDisplay: perf sync s={s} defer={defer} swaps={defer} forced=0 max_us=2000 marks=1 busy=1 ovf=0 stale=0 unm=0',
        f'AdrenoDisplay: perf pipe s={s} on=3 fl={ib} ovl=0 imm=0 sync=0 fold=0 drain=0 tmr=0 polls=0 spin_us=0 '
        'gap_us=0 max_ms=1 fail=0',
        f'AdrenoDisplay: perf relatch s={s} on=7 arm={go} go={go} late=0 gone=0 gate=0 polls=0 ovt=0 lead=0/0 wait=0 '
        'rel=0/0/0/0/0/0/0/0 ef=0/0/0 unm=0',
        f'AdrenoDisplay: perf map s={s} ins=0 pg=0/0/0 clr=0 sfree=0 pool=0/0/0/0 va=0/0/0/0 ib={ib}',
        f'AdrenoDisplay: perf gpu s={s} gtk={gtk}/0 sub_us={sub}/0 prep={prep} unw=0/0 cache={cache} res=0/0/0/0 '
        'mib=0/0',
    ]
    if done:
        lines.append(f'AdrenoDisplay: perf done s={s} {done}')
    return lines


class Summary(unittest.TestCase):
    def test_groups(self):
        text = '\n'.join(
            window(1, 600, '300/150/100/40/10', 20000, '600/400/180/20', 19200000, 1200000, '60000/60000/1800000',
                   '120000/600000', 60, 70) +
            window(2, 30, '500/90/10/0/0', 16900, '600/590/8/2', 192000, 30000, '3000/1000/30000', '3000/60000', 0, 1,
                   done='mode=2 on=1 done=5 late=2 eng=1 ahd=3 arr=1/2/3/4/5/6/7/8/9 lat=1/0/1/0') +
            window(3, 600, '1/0/0/0/0', 1, '1/1/0/0', 1, 1, '1/1/1', '1/1', 0, 0)[:3] +   # incomplete: left out
            window(4, 600, '1/0/0/0/0', 1, '1/1/0/0', 1, 1, '1/1/1', '1/1', 0, 0, why='reject'))
        out = tool.summarize(text, 200)
        busy, quiet = out['busy'], out['quiet']
        self.assertEqual((busy['windows'], quiet['windows']), (1, 1))
        self.assertEqual(busy['intervals_pct'], [50.0, 25.0, 16.7, 6.7, 1.7])
        self.assertEqual(busy['over34_pct'], 8.3)
        self.assertEqual((busy['ready_pct'], busy['missed_pct'], busy['true_miss_pct']), (66.7, 30.0, 20.0))
        self.assertAlmostEqual(busy['gpu_ms_ib_median'], 1.667, places=3)     # 1 s of host ticks over 600 IBs
        self.assertAlmostEqual(busy['sub_ms_ib_median'], 2.0, places=3)
        self.assertAlmostEqual(busy['cache_ms_ib_median'], 3.0, places=3)
        self.assertAlmostEqual(busy['cache_mib_ib_median'], 100.0, places=3)
        self.assertAlmostEqual(busy['prep_ms_ib_median'], 1.0, places=3)
        self.assertNotIn('done', busy)
        self.assertEqual(quiet['done'], dict(modes=[2], engaged_windows=1, early=5, late=2, engages=1, ahead=3,
                                             arrival_2ms_bins=[1, 2, 3, 4, 5, 6, 7, 8, 9], late_bins_2_4_8_more=[1, 0, 1, 0]))

    def test_empty(self):
        self.assertEqual(tool.summarize('nothing here'), dict(busy=None, quiet=None, busy_ibs=200))


if __name__ == '__main__':
    unittest.main()
