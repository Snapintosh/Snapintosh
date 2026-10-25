#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize a run's AdrenoDisplay perf windows: frame pacing and where a busy window's time went. Host only.

  python3 tools/summarize-present-pacing.py build/PREFIX/console.txt [--report build/PREFIX/report.bin] [--json]

A perf window is the set of "AdrenoDisplay: perf <kind> s=<n>" lines one perfLineGated call prints (600 layer-0
copies, AdrenoDisplay/stats.cpp). Windows are split into busy (at least --busy-ibs completed IBs, default 200: about
20 IBs a second) and quiet ones, and each group is reduced to:
- copies per second (median, min) and the copy intervals by the pace line's buckets (<= 17, <= 20, <= 34, <= 50,
  > 50 ms; <= 20 ms is on time, the tick firing late; 20-34 ms is one refresh shown twice; more is worse);
- the ticks: ready (a layer-0 copy started in the tick), missed (a frame was on screen, nothing new copied), idle;
  missed less the relatch's copies (the head the tick deferred, copied into the same frame) is the share of refreshes
  WindowServer did not deliver in time ("true misses");
- per IB: GPU time (the monitor's poll ticks at 19.2 MHz), the kext's submission time with the lock held, its cache
  maintenance time and bytes, its resource preparations; the copy time, the tick's lateness and q (swap to copy);
- with the early-completion kext (the perf done line): completions at the copy, late frames, engagements, and the
  arrival and lateness histograms summed over the group.
With --report, the GPU's time per clock from the DVFSREP1 record (tools/dvfs_report.py) is added."""
import argparse
import collections
import json
import re
import statistics
import sys
from pathlib import Path

HOST_HZ = 19_200_000                       # the monitor's IB tick counter (gtk)
NEED = ('why', 'pace', 'map', 'gpu', 'pipe', 'sync', 'vsync')


def windows(text):
    w = collections.defaultdict(dict)
    for line in text.split('\n'):
        m = re.search(r'AdrenoDisplay: perf why=(\w+) s=(\d+) (.*)', line)
        if m:
            w[int(m.group(2))]['why'] = dict(re.findall(r'(\w+)=(\S+)', m.group(3)), kind=m.group(1))
            continue
        m = re.search(r'AdrenoDisplay: perf (\w+) s=(\d+) (.*)', line)
        if m:
            w[int(m.group(2))][m.group(1)] = dict(re.findall(r'(\w+)=(\S+)', m.group(3)))
    return w


def ints(text):
    return [int(x) for x in text.split('/')]


def window_row(s, r):
    """One periodic window's numbers, or None (an incomplete or non-periodic window)."""
    if not all(k in r for k in NEED) or r['why'].get('kind') != 'periodic':
        return None
    p, mp, g, pi, sy, v = (r[k] for k in ('pace', 'map', 'gpu', 'pipe', 'sync', 'vsync'))
    pp, tk = ints(p['pp']), ints(p['tk'])
    span = sum(pp) * int(p['mean']) / 1e6
    ib = int(mp['ib'])
    gtk, sub, cache, prep = ints(g['gtk']), ints(g['sub_us']), ints(g['cache']), ints(g['prep'])
    relatch = r.get('relatch', {})
    row = dict(s=s, pps=float(p['pps']), span=span, ib=ib, buckets=pp, ticks=tk[0], ready=tk[1], missed=tk[2], idle=tk[3],
               relatched=int(relatch.get('go', 0)), defer=int(sy['defer']),
               gpu_ms_ib=gtk[0] / HOST_HZ * 1e3 / ib if ib else 0.0,
               gpu_busy=gtk[0] / HOST_HZ / span if span else 0.0,
               sub_ms_ib=sub[0] / 1e3 / ib if ib else 0.0, cache_ms_ib=cache[2] / 1e3 / ib if ib else 0.0,
               cache_mib_ib=cache[1] / ib if ib else 0.0, prep_ms_ib=prep[1] / 1e3 / ib if ib else 0.0,
               copy_us=int(r['why']['mean_us']), late_us=ints(v['grid'])[0], q_us=int(p['q']))
    if 'done' in r:
        d = r['done']
        row['done'] = dict(mode=int(d['mode']), on=int(d['on']), early=int(d['done']), late=int(d['late']),
                           engages=int(d['eng']), ahead=int(d['ahd']), arr=ints(d['arr']), lat=ints(d['lat']))
    return row


def group(rows):
    if not rows:
        return None
    ticks = sum(r['ticks'] for r in rows) or 1
    buckets = [sum(r['buckets'][i] for r in rows) for i in range(5)]
    intervals = sum(buckets) or 1
    med = lambda k: round(statistics.median(r[k] for r in rows), 3)
    out = dict(windows=len(rows), pps_median=med('pps'), pps_min=min(r['pps'] for r in rows),
               ticks_per_s=round(ticks / sum(r['span'] for r in rows), 2),
               ready_pct=round(100 * sum(r['ready'] for r in rows) / ticks, 1),
               missed_pct=round(100 * sum(r['missed'] for r in rows) / ticks, 1),
               true_miss_pct=round(100 * sum(r['missed'] - r['relatched'] for r in rows) / ticks, 1),
               deferred_pct=round(100 * sum(r['defer'] for r in rows) / ticks, 1),
               intervals_pct=[round(100 * b / intervals, 1) for b in buckets],
               over34_pct=round(100 * (buckets[3] + buckets[4]) / intervals, 1),
               ibs_per_s=round(sum(r['ib'] for r in rows) / sum(r['span'] for r in rows), 1))
    for k in ('gpu_ms_ib', 'gpu_busy', 'sub_ms_ib', 'cache_ms_ib', 'cache_mib_ib', 'prep_ms_ib', 'copy_us', 'late_us',
              'q_us'):
        out[k + '_median'] = med(k)
    done = [r['done'] for r in rows if 'done' in r]
    if done:
        out['done'] = dict(modes=sorted({d['mode'] for d in done}), engaged_windows=sum(1 for d in done if d['on']),
                           early=sum(d['early'] for d in done), late=sum(d['late'] for d in done),
                           engages=sum(d['engages'] for d in done), ahead=sum(d['ahead'] for d in done),
                           arrival_2ms_bins=[sum(d['arr'][i] for d in done) for i in range(len(done[0]['arr']))],
                           late_bins_2_4_8_more=[sum(d['lat'][i] for d in done) for i in range(len(done[0]['lat']))])
    return out


def summarize(text, busy_ibs=200):
    rows = [x for x in (window_row(s, r) for s, r in sorted(windows(text).items())) if x]
    return dict(busy=group([r for r in rows if r['ib'] >= busy_ibs]),
                quiet=group([r for r in rows if r['ib'] < busy_ibs]), busy_ibs=busy_ibs)


def gpu_clocks(report):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import dvfs_report
    raw = Path(report).read_bytes()
    decoded = dvfs_report.decode_block(raw[dvfs_report.OFFSET:dvfs_report.OFFSET + 8 * 190])   # as its main reads it
    gpu = decoded.get('gpu', {}) if isinstance(decoded, dict) else {}
    keep = ('status', 'ceiling_mhz', 'seconds_at_mhz', 'mean_mhz', 'errors', 'thermal')
    return {k: gpu[k] for k in keep if k in gpu}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('console', type=Path)
    ap.add_argument('--report', type=Path)
    ap.add_argument('--busy-ibs', type=int, default=200)
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    out = summarize(a.console.read_text(errors='replace'), a.busy_ibs)
    if a.report:
        out['gpu_clock'] = gpu_clocks(a.report)
    if a.json:
        print(json.dumps(out, indent=1))
        return
    for name in ('busy', 'quiet'):
        g = out[name]
        if not g:
            print(f'{name}: no windows')
            continue
        print(f"{name}: {g['windows']} windows, copies/s median {g['pps_median']} (min {g['pps_min']}), ticks/s "
              f"{g['ticks_per_s']}, IBs/s {g['ibs_per_s']}; ticks ready {g['ready_pct']}% missed {g['missed_pct']}% "
              f"(true misses {g['true_miss_pct']}%), deferred {g['deferred_pct']}%; intervals <=17/20/34/50/>50 ms "
              f"{'/'.join(str(x) for x in g['intervals_pct'])}%, over 34 ms {g['over34_pct']}%")
        print(f"  per IB: GPU {g['gpu_ms_ib_median']} ms (GPU busy {g['gpu_busy_median']}), submit {g['sub_ms_ib_median']} ms, "
              f"cache {g['cache_ms_ib_median']} ms / {g['cache_mib_ib_median']} MiB, preparation {g['prep_ms_ib_median']} ms; "
              f"copy {g['copy_us_median']} us, tick late {g['late_us_median']} us, q {g['q_us_median']} us")
        if 'done' in g:
            d = g['done']
            print(f"  early completion: modes {d['modes']}, engaged at {d['engaged_windows']} window ends, {d['early']} "
                  f"completions at the copy, {d['late']} late frames ({d['engages']} engagements), {d['ahead']} arrivals "
                  f"behind another; arrivals by 2 ms {d['arrival_2ms_bins']}, lateness <2/<4/<8/more "
                  f"{d['late_bins_2_4_8_more']}")
    if 'gpu_clock' in out:
        print(f"gpu clock: {json.dumps(out['gpu_clock'])}")


if __name__ == '__main__':
    main()
