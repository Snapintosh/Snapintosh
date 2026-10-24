#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare icon-pixels output from the guest's GPU with this Mac's reference, case by case.

icon-pixels (SnapMetal harness/icon-pixels.m, built by tools/build-icon-pixels.py) prints one checksummed line per case.
This reads two such outputs (lines whose CRC does not match, such as console noise or a torn line, are dropped and
counted) and prints PASS or FAIL per case with what is off:

    python3 tools/compare-icon-pixels.py REFERENCE.txt GUEST.txt [--tolerance 6] [--census-only] [--cases REGEX]
        [--json OUT.json]

synth cases (C lines). A case passes when its status is ok, no destination pixel kept the sentinel, both readbacks and
all repeats agree, and every sampled value (9 points, 16 middle-row samples, 64 tile means, per-stripe means) is within
--tolerance (8-bit units) of the reference in every channel. A failing case names the first matching explanation:
  ERROR / MISSING          the tool raised or never printed the case
  UNWRITTEN / PARTIAL      destination pixels still hold the sentinel: the dispatch never ran, or ran in part
  READBACK                 getBytes and a GPU blit of the same texture differ (CPU cache maintenance or coherency)
  NONDETERMINISTIC         repeats from identical inputs differ (synchronisation)
  BLACK / TRANSPARENT      the kernel read zeros (an unbound or null T#, a wrong T# slot, a wrong sampler)
  SWAP-RB                  red and blue exchanged (the T# SWAP field: WZYX vs WXYZ)
  SRGB-EXTRA / SRGB-MISSING  colour channels look decoded twice / not decoded (the T# SRGB bit vs CoreImage's own)
  INPUT-k                  multi-input cases: the stripe of input k (Metal texture index from the census) is wrong,
                           missing (transparent) or shows input j's content
  CHANNEL                  otherwise: which channels are off, by how much, and where (tiles)
Icon cases (I lines): coverage, mean colour and the 8x8 alpha/luminance grids against the reference: EMPTY, BLACK,
PARTIAL (alpha cells lost), WRONG-COLOUR, SHAPE.
K lines (census) are compared too: a different kernel or texture format set is reported as a note, since the pixel
comparison is then of different work. --census-only compares only status, census and diagnostics (for an output of
the plug-in device with intercepted commits, whose pixels were never computed).
Exit status: 0 every case passes, 1 a case fails, 2 unusable input.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import zlib

SENTINEL = '3ca55ac3'


def parse(path):
    """{'V': [...], 'C': {name: fields}, 'K': {name: line}, 'I': {...}, 'D': [...], 'E': [...], 'END': ..., 'noise': n}"""
    out = dict(V=[], C={}, K={}, I={}, D=[], E=[], W=[], END=None, noise=0, lines=0)
    for raw in Path(path).read_text(errors='replace').splitlines():
        raw = raw.strip()
        if not raw:
            continue
        body, sep, crc = raw.rpartition(' *')
        if not sep or not re.fullmatch(r'[0-9a-f]{8}', crc) or f'{zlib.crc32(body.encode()) & 0xffffffff:08x}' != crc:
            out['noise'] += 1
            continue
        out['lines'] += 1
        kind = body.split(' ', 1)[0]
        if kind in ('C', 'I'):
            words = body.split(' ')
            fields = dict(name=words[1], size=words[2])
            for w in words[3:]:
                k, eq, v = w.partition('=')
                if eq:
                    fields[k] = v
            out[kind][words[1]] = fields
        elif kind == 'K':
            words = body.split(' ', 2)
            out['K'][words[1]] = words[2] if len(words) > 2 else ''
        elif kind == 'END':
            out['END'] = body
        elif kind in out:
            out[kind].append(body)
    return out


def px(h):
    return [int(h[i:i + 2], 16) for i in (0, 2, 4, 6)]


def values(f):
    """Every sampled RGBA value of a C line, labelled by where it came from."""
    vals = []
    for i, h in enumerate(f.get('p', '').split(',')):
        if len(h) == 8:
            vals.append((f'point{i}', px(h)))
    for i, h in enumerate(f.get('g', '').split(',')):
        if len(h) == 8:
            vals.append((f'row{i}', px(h)))
    t = f.get('t', '')
    for i in range(len(t) // 8):
        vals.append((f'tile{i // 8},{i % 8}', px(t[8 * i:8 * i + 8])))
    return vals


def stripes(f):
    s = f.get('s')
    if not s:
        return None, None
    top, _, band = s.partition('/')
    return [px(h) for h in top.split(',')], [px(h) for h in band.split(',')]


def to_linear(v):
    c = v / 255.0
    return 255.0 * (c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)


def to_srgb(v):
    c = v / 255.0
    return 255.0 * (c * 12.92 if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055)


def close(a, b, tol, channels=range(4)):
    return all(abs(a[c] - b[c]) <= tol for c in channels)


def explain_values(ref, got, tol):
    """The explanation for sampled values that differ, from the most specific pattern to the generic one."""
    pairs = [(label, r, g) for (label, r), (_, g) in zip(ref, got)]
    bad = [(label, r, g) for label, r, g in pairs if not close(r, g, tol)]
    if not bad:
        return None
    if all(g == [0, 0, 0, 0] for _, _, g in bad):
        return 'TRANSPARENT: the kernel wrote transparent black where the reference has content (null or wrong T#, sampler)'
    if all(g[:3] == [0, 0, 0] for _, r, g in bad if max(r[:3]) > 24) and any(max(r[:3]) > 24 for _, r, _ in bad):
        return 'BLACK: colour channels read zero (unbound or null T#, wrong T# slot, or wrong format)'
    swapped = [(r, g) for _, r, g in pairs if abs(r[0] - r[2]) > 2 * tol]
    if swapped and all(abs(g[0] - r[2]) <= tol and abs(g[2] - r[0]) <= tol and abs(g[1] - r[1]) <= tol for r, g in swapped):
        return 'SWAP-RB: red and blue are exchanged (T# SWAP: WZYX for RGBA, WXYZ for BGRA)'
    mid = [(r, g) for _, r, g in bad if any(40 <= r[c] <= 215 for c in range(3))]

    def frac(fn):
        hits = [all(abs(g[c] - fn(r[c])) <= tol + 2 for c in range(3) if 40 <= r[c] <= 215) for r, g in mid]
        return sum(hits) / len(hits) if hits else 0.0
    if mid and frac(to_linear) >= 0.8:
        return 'SRGB-EXTRA: colour channels are darker as if sRGB-decoded once more (T# SRGB bit on top of the kernel\'s decode)'
    if mid and frac(to_srgb) >= 0.8:
        return 'SRGB-MISSING: colour channels are lighter as if never sRGB-decoded (T# SRGB bit absent)'
    names = 'RGBA'
    worst = [max(abs(r[c] - g[c]) for _, r, g in bad) for c in range(4)]
    off = [names[c] for c in range(4) if worst[c] > tol]
    zeroed = [names[c] for c in range(4) if all(g[c] == 0 for _, r, g in bad if r[c] > 24)
              and any(r[c] > 24 for _, r, _ in bad)]
    tiles = sorted({label for label, _, _ in bad if label.startswith('tile')})
    where = ''
    if tiles:
        rows = sorted({int(t[4:].split(',')[0]) for t in tiles})
        cols = sorted({int(t.split(',')[1]) for t in tiles})
        where = f'; {len(tiles)}/64 tiles off (rows {rows[0]}-{rows[-1]}, cols {cols[0]}-{cols[-1]})'
    first = bad[0]
    detail = f'channels {"".join(off)} off (max delta ' + ','.join(str(w) for w in worst) + ')'
    if zeroed:
        detail += f'; {"".join(zeroed)} reads 0'
    return f'CHANNEL: {detail}{where}; first at {first[0]}: reference {"".join(f"{x:02x}" for x in first[1])} guest ' \
           f'{"".join(f"{x:02x}" for x in first[2])}'


def texture_index_of_inputs(census):
    """'1=rgba8s:i5,2=rgba8s:i4,...' -> {5: 1, 4: 2, ...} (input k -> Metal texture index)."""
    out = {}
    for m in re.finditer(r'(\d+)=[a-z0-9]+:i(\d+)', census or ''):
        out.setdefault(int(m.group(2)), int(m.group(1)))
    return out


def compare_synth(name, r, g, rk, gk, tol, census_only):
    notes = []
    if gk is not None and rk is not None and gk != rk:
        notes.append(f'census differs: reference {rk[:160]} | guest {gk[:160]}')
    if g is None:
        return 'MISSING: the case printed no line (the tool stopped or the case was filtered)', notes
    if g.get('st') != 'ok':
        return f'ERROR: status {g.get("st")}', notes
    if census_only:
        if gk != rk:
            return 'CENSUS: CoreImage dispatched other kernels or bound other texture formats', notes
        return None, notes
    w, _, h = g['size'].partition('x')
    total = int(w) * int(h) if w.isdigit() and h.isdigit() else 0
    sent = int(g.get('sent', '0'))
    if total and sent >= total:
        return 'UNWRITTEN: no destination pixel was written (dispatch dropped or refused, or the GPU never ran it)', notes
    hashes = g.get('h', '').split(',')
    if sent:
        return f'PARTIAL: {sent} of {total} pixels still hold the sentinel (part of the dispatch never wrote)', notes
    if g.get('hb') not in ('na', hashes[0]):
        return 'READBACK: getBytes and the GPU blit of the same texture differ (CPU cache maintenance/coherency)', notes
    if len(set(hashes)) > 1:
        notes.append('repeats differ')
    if r is None:
        return 'MISSING-REFERENCE: the reference has no such case', notes
    if r['size'] != g['size']:
        return f'SIZE: {g["size"]} instead of {r["size"]}', notes
    rt, rb = stripes(r)
    gt, gb = stripes(g)
    if rt and gt:
        index = texture_index_of_inputs(rk)
        for k, (want, got) in enumerate(zip(rt, gt)):
            if close(want, got, tol):
                continue
            slot = f' (texture({index[k]}))' if k in index else ''
            if got[3] <= tol:
                return f'INPUT-{k}: stripe {k} is transparent: input {k}{slot} was not read', notes
            other = [j for j, o in enumerate(rt) if j != k and close(o, got, tol)]
            if other:
                return f'INPUT-{k}: stripe {k} shows input {other[0]}\'s colour: input {k}{slot} reads another texture', notes
            return f'INPUT-{k}: stripe {k} is {"".join(f"{x:02x}" for x in got)}, reference ' \
                   f'{"".join(f"{x:02x}" for x in want)} (input {k}{slot})', notes
        for k, (want, got) in enumerate(zip(rb, gb)):
            if not close(want, got, tol):
                return f'BLEND: the half-transparent band under stripe {k} is {"".join(f"{x:02x}" for x in got)}, ' \
                       f'reference {"".join(f"{x:02x}" for x in want)} (blend order or premultiplication)', notes
    why = explain_values(values(r), values(g), tol)
    if why:
        return why, notes
    if len(set(hashes)) > 1:
        return 'NONDETERMINISTIC: repeats from identical inputs differ (within tolerance of the reference at the samples)', notes
    return None, notes


def grid(s):
    return [int(c, 16) for c in s]


def compare_icon(name, r, g, rk, gk, tol):
    notes = []
    if g is None:
        return 'MISSING: the icon printed no line', notes
    if g.get('st') != 'ok':
        return f'ERROR: status {g.get("st")}', notes
    if r is None:
        return 'MISSING-REFERENCE: the reference has no such icon', notes
    if r.get('st') != 'ok':
        return f'REFERENCE-ERROR: the reference status is {r.get("st")}', notes
    rc, gc = int(r['cov']), int(g['cov'])
    if gc == 0 and rc > 0:
        return 'EMPTY: the icon has no visible pixel', notes
    rrgb, grgb = px(r['rgb'] + 'ff')[:3], px(g['rgb'] + 'ff')[:3]
    if max(grgb) < 0x10 and max(rrgb) >= 0x30:
        return f'BLACK: covered pixels are black (mean {g["rgb"]}, reference {r["rgb"]})', notes
    ra, ga = grid(r['ag']), grid(g['ag'])
    lost = [i for i, (a, b) in enumerate(zip(ra, ga)) if a >= 3 and b <= a - 3]
    if lost:
        return f'PARTIAL: {len(lost)} of 64 alpha cells lost (first row {lost[0] // 8} col {lost[0] % 8}; ' \
               f'coverage {gc} vs {rc} per mille)', notes
    if abs(gc - rc) > 30:
        return f'SHAPE: coverage {gc} vs reference {rc} per mille', notes
    if any(abs(a - b) > 2 * tol for a, b in zip(rrgb, grgb)):
        d = ','.join(f'{b - a:+d}' for a, b in zip(rrgb, grgb))
        return f'WRONG-COLOUR: mean colour {g["rgb"]} vs reference {r["rgb"]} (R,G,B delta {d})', notes
    rl, gl = grid(r['lg']), grid(g['lg'])
    off = [i for i, (a, b) in enumerate(zip(rl, gl)) if abs(a - b) > 1]
    if off or any(abs(a - b) > 1 for a, b in zip(ra, ga)):
        return f'SHAPE: {len(off)} luminance cells differ by more than one level', notes
    return None, notes


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('reference', type=Path)
    ap.add_argument('guest', type=Path)
    ap.add_argument('--tolerance', type=int, default=6, help='per-channel tolerance, 8-bit units (default 6)')
    ap.add_argument('--census-only', action='store_true')
    ap.add_argument('--cases', help='compare only the cases whose name matches this regular expression')
    ap.add_argument('--json', type=Path)
    a = ap.parse_args(argv)
    ref, got = parse(a.reference), parse(a.guest)
    if not ref['lines'] or not ref['V']:
        print(f'unusable reference {a.reference}: {ref["lines"]} valid lines')
        return 2
    if a.cases:
        keep = re.compile(a.cases)
        for kind in ('C', 'I'):
            for side in (ref, got):
                side[kind] = {n: f for n, f in side[kind].items() if keep.search(n)}
    rows = []
    for name in list(ref['C']) + [n for n in got['C'] if n not in ref['C']]:
        why, notes = compare_synth(name, ref['C'].get(name), got['C'].get(name), ref['K'].get(name), got['K'].get(name),
                                   a.tolerance, a.census_only)
        rows.append(dict(case=name, kind='synth', verdict='FAIL' if why else 'PASS', why=why, notes=notes))
    for name in list(ref['I']) + [n for n in got['I'] if n not in ref['I']]:
        why, notes = compare_icon(name, ref['I'].get(name), got['I'].get(name), ref['K'].get(name), got['K'].get(name),
                                  a.tolerance)
        rows.append(dict(case=name, kind='icon', verdict='FAIL' if why else 'PASS', why=why, notes=notes))
    # The plug-in's own record of work it would not encode (dropped: lenient builds, refused: strict ones).
    for d in got['D']:
        m = re.search(r' dropped=(\d+) refused=(\d+)', d)
        if m and (int(m.group(1)) or int(m.group(2))):
            rows.append(dict(case='plugin-diagnostics', kind='diag', verdict='FAIL', notes=[],
                             why=f'the plug-in dropped {m.group(1)} and refused {m.group(2)} pieces of work in this process '
                                 '(the D lines below name them)'))
    for row in rows:
        line = f'{row["verdict"]} {row["case"]}' + (f': {row["why"]}' if row['why'] else '')
        if row['notes']:
            line += ' [' + '; '.join(row['notes']) + ']'
        print(line)
    fails = [r for r in rows if r['verdict'] == 'FAIL']
    print(f'guest: {got["V"][0] if got["V"] else "no V line"}')
    print(f'guest lines {got["lines"]}, noise dropped {got["noise"]}, errors {len(got["E"])}, end {got["END"] or "absent"}')
    for d in got['D'][:7]:
        print(f'guest {d[:300]}')
    for w in got['W']:
        print(f'guest {w[:300]}')
    print(f'{"PASS" if not fails else "FAIL"}: {len(rows) - len(fails)} of {len(rows)} cases pass'
          + (f'; failing: {", ".join(r["case"] for r in fails[:20])}' if fails else ''))
    if a.json:
        a.json.write_text(json.dumps(dict(rows=rows, guest_v=got['V'], guest_d=got['D'], guest_end=got['END'],
                                          noise=got['noise']), indent=1) + '\n')
    if not got['V'] or not rows:
        return 2
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
