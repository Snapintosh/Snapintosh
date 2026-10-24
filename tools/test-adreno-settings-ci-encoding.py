#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The CoreImage compute shapes of the System Settings pane icons, decoded from the plug-in's packages (no GPU, no A16).

ADRENO_SETTINGS_ICONS (gpu/adreno-kext/plugin/AdrenoMetal/AdrenoDrawCommands/Compute.m): iconservicesagent's CoreImage
kernels sample RGBA8Unorm_sRGB (icns device and display images), RG8Unorm / RG16Float (grey+alpha document icons) and
composite several inputs in one kernel (folder, documents, app icons with effects). The harness (gpu/adreno-kext/plugin/harness/settings-ci-encoding.m) runs one
CoreImage kernel per sampled format and a two-input srcOver, twice: as the deployed kext answers (no
AdrenoIBComputeSamplers) and standing in for a kext that publishes AdrenoIBComputeSamplers = 8. Checks:
  - every single-input kernel is encoded, nothing omitted; its package's CS T# for the source texture has the format's
    FMT6, swap, own channel mapping and sRGB decode (Mesa fd6_format_table; A8 as the fragment sampler encodes it),
    linear tiling, the texture's size and a 64-byte-multiple pitch; the single shape keeps one sampler unit, a T# table of
    T#0 (null) + T#1 and SP_CS_CONFIG NTEX 1 / NSAMP 1 / NUAV 2 (with --cs-tables, a plug-in built with ADRENO_CS_TABLES:
    NTEX 2 / NSAMP 2 / NUAV 1, Mesa's counts);
  - the two-input kernel: without the property it is omitted, naming AdrenoIBComputeSamplers, and no package carries a
    CS sampler load of more than one unit; with it, it is encoded with a 3-entry T# table (null, the two inputs, each
    relocated READ to its own texture with its own format), a 2-unit sampler table of clamping samplers, SP_CS_TSIZE 3
    and SP_CS_CONFIG NTEX 3 / NSAMP 2 / NUAV 2 (--cs-tables: NTEX 3 / NSAMP 3 / NUAV 1, a third, zero, sampler entry);
  - a replaceRegion/getBytes round trip of each format returns the written bytes on the plug-in device and on this
    Mac's GPU (the CPU layout of the textures CoreImage uploads icons into);
  - every package replays through the production validator, except the two-input package, which that validator must
    refuse (the reason for the gate) and, with --cs-samplers-validator, this tree's validator built with
    ADRENO_IB_CS_SAMPLERS and opted in (a kext booted with adreno_cs_samplers=1) must admit.
--expect-before: the unchanged plug-in must fail at least one of these.

    python3 tools/test-adreno-settings-ci-encoding.py --bundle BUNDLE --output NEW-DIR [--expect-before]
        [--cs-samplers-validator] [--cs-tables]
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness/settings-ci-encoding.m'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T = load('targets', 'tools/test-adreno-targets.py')
P, hv = T.P, T.header_value
SB6_CS_TEX, SB6_CS_SHADER = hv('A8XX_E_SB6_CS_TEX'), hv('A8XX_E_SB6_CS_SHADER')
ST6_SHADER, ST6_CONSTANTS, ST6_UAV = hv('A8XX_E_ST6_SHADER'), hv('A8XX_E_ST6_CONSTANTS'), hv('A8XX_E_ST6_UAV')
CP_LOAD_STATE6_FRAG = P.R.CP_LOAD_STATE6_FRAG
REG_TSIZE, REG_CONFIG = hv('A8XX_REG_SP_CS_TSIZE'), hv('A8XX_REG_SP_CS_CONFIG')
# Metal format -> (TEX format, swap, the format's own channel mapping, sRGB decode, bytes per pixel)
EXPECT = {71: ('FMT6_8_8_8_8_UNORM', 'WZYX', 'XYZW', 1, 4), 81: ('FMT6_8_8_8_8_UNORM', 'WXYZ', 'XYZW', 1, 4),
          80: ('FMT6_8_8_8_8_UNORM', 'WXYZ', 'XYZW', 0, 4), 30: ('FMT6_8_8_UNORM', 'WZYX', 'XY01', 0, 2),
          65: ('FMT6_16_16_FLOAT', 'WZYX', 'XY01', 0, 4), 10: ('FMT6_8_UNORM', 'WZYX', 'X001', 0, 1),
          1: ('FMT6_8_UNORM', 'WZYX', '000X', 0, 1), 25: ('FMT6_16_FLOAT', 'WZYX', 'X001', 0, 2),
          20: ('FMT6_16_UNORM', 'WZYX', 'X001', 0, 2), 60: ('FMT6_16_16_UNORM', 'WZYX', 'XY01', 0, 4),
          110: ('FMT6_16_16_16_16_UNORM', 'WZYX', 'XYZW', 0, 8), 94: ('FMT6_10_10_10_2_UNORM', 'WXYZ', 'XYZW', 0, 4),
          90: ('FMT6_10_10_10_2_UNORM', 'WZYX', 'XYZW', 0, 4)}
SWZ = {'X': 'X', 'Y': 'Y', 'Z': 'Z', 'W': 'W', '0': 'ZERO', '1': 'ONE'}
GATE = '(AdrenoIBComputeSamplers)'
# (T# units, sampler units, TSIZE, NTEX, NSAMP, NUAV) of the single and two-input packages; --cs-tables selects Mesa's.
SHAPES = {False: ((2, 1, 2, 1, 1, 2), (3, 2, 3, 3, 2, 2)), True: ((2, 1, 2, 2, 2, 1), (3, 2, 3, 3, 3, 1))}
CS_TABLES = False
checks, failures = 0, []


def check(ok, what):
    global checks
    checks += 1
    if not ok:
        failures.append(what)
    return ok


def u32(pkg, at):
    return struct.unpack_from('<I', pkg['package'], at)[0]


def cs_state(pkg):
    """The CS texture/sampler/UAV loads of one package: {(block, type): (units, table byte offset)}, the T# entries'
    resource relocations {table offset + 64k: reloc}, and the last SP_CS_TSIZE / SP_CS_CONFIG values."""
    words = P.ib_words(pkg)
    regs, packets = P.walk_ib(words)
    by_lo = {r['lo']: r for r in pkg['relocs']}
    loads = {}
    for op, start, body in packets:
        if op != CP_LOAD_STATE6_FRAG or len(body) < 3:
            continue
        w0 = body[0]
        typ, block, units = (w0 >> 14) & 3, (w0 >> 18) & 0xf, w0 >> 22
        if block not in (SB6_CS_TEX, SB6_CS_SHADER):
            continue
        src = by_lo.get(4 * (start + 1))
        loads[(block, typ)] = (units, src['offset'] if src and src['kind'] == 2 else None)
    values = {off: words[at] for at, off in regs}
    return loads, by_lo, values.get(REG_TSIZE), values.get(REG_CONFIG)


def name_of(table, value):
    try:
        return T.enum(table, value)
    except KeyError:
        return f'{table}#{value}'


def tdesc(pkg, at):
    d = [u32(pkg, at + 4 * k) for k in range(16)]
    f = lambda w, desc, name: T.dfield(d[w], desc, name)
    return dict(fmt=name_of('a6xx_format', f(3, 'A8XX_TEX_MEMOBJ_3', 'FMT')),
                swap=name_of('a3xx_color_swap', f(3, 'A8XX_TEX_MEMOBJ_3', 'SWAP')),
                swiz=[f(3, 'A8XX_TEX_MEMOBJ_3', f'SWIZ_{c}') for c in 'XYZW'],
                srgb=f(4, 'A8XX_TEX_MEMOBJ_4', 'SRGB'), tile=f(4, 'A8XX_TEX_MEMOBJ_4', 'TILE_MODE'),
                width=f(2, 'A8XX_TEX_MEMOBJ_2', 'WIDTH'), height=f(2, 'A8XX_TEX_MEMOBJ_2', 'HEIGHT'),
                pitch=f(6, 'A8XX_TEX_MEMOBJ_6', 'TEX_LINE_OFFSET') // 8, words=d)


def packages(out, case):
    pk = []
    for c in case['commits']:
        f = out / c['dir'] / 'commands.bin'
        if f.is_file():
            pk += [(c['dir'], P.parse_package(cmd)) for k, cmd in P.kernel_commands(f.read_bytes()) if k == 0x1002]
    return pk


def check_texture(name, pkg, by_lo, table, slot, source):
    exp = EXPECT.get(source['format'])
    if not check(exp is not None, f'{name}: no expectation for format {source["format"]}'):
        return
    at = table + 64 * slot
    rel = by_lo.get(at)
    check(rel is not None and rel['kind'] == 1 and rel['resource_id'] == source['resource'] and rel['access'] == 1,
          f'{name}: T#{slot} is not relocated READ to the source texture {source["resource"]}: {rel}')
    d = tdesc(pkg, at)
    want_swiz = [T.SWIZ[SWZ[c]] for c in exp[2]]
    check((d['fmt'], d['swap'], d['swiz'], d['srgb'], d['tile']) == (exp[0], exp[1], want_swiz, exp[3], 0),
          f'{name}: T#{slot} {d["fmt"]} {d["swap"]} swiz {d["swiz"]} srgb {d["srgb"]} tile {d["tile"]}; '
          f'expected {exp[0]} {exp[1]} {want_swiz} srgb {exp[3]} linear')
    check((d['width'], d['height']) == (source['width'], source['height']) and d['pitch'] % 64 == 0 and
          d['pitch'] >= source['width'] * exp[4], f'{name}: T#{slot} size {d["width"]}x{d["height"]} pitch {d["pitch"]}')


def verify(out, report, gated, replays, proposal):
    multi_refused_by_main = []
    for case in report['cases']:
        name = case['name']
        multi = name == 'composite'
        omissions = [o for c in case['commits'] for o in ((c.get('work') or {}).get('omissions') or [])]
        # A strict build raises where a lenient one omits: the gated two-input kernel is then an exception naming it.
        strict_gate = multi and gated and case.get('status') == 'exception' and GATE in (case.get('exception') or '')
        check(case.get('status') == 'committed' or strict_gate, f'{name}: {case.get("status")} {case.get("exception")}')
        if multi and gated:
            check(strict_gate or (len(omissions) == 1 and GATE in (omissions[0].get('details') or {}).get('reason', '')),
                  f'{name}: without AdrenoIBComputeSamplers the two-input kernel must be omitted naming it: '
                  f'{[(o.get("details") or {}).get("reason") for o in omissions]}')
        else:
            check(not omissions, f'{name}: omitted: {[(o.get("details") or {}).get("reason") for o in omissions][:2]}')
        if not multi:
            rt = case.get('roundtrip') or {}
            check(rt.get('adreno') and rt.get('native'), f'{name}: replaceRegion/getBytes round trip {rt}')
        pks = packages(out, case)
        sampler_units = []
        for d, pkg in pks:
            loads, by_lo, tsize, config = cs_state(pkg)
            if (SB6_CS_TEX, ST6_SHADER) in loads:
                sampler_units.append(loads[(SB6_CS_TEX, ST6_SHADER)][0])
            if (SB6_CS_TEX, ST6_CONSTANTS) not in loads:
                continue
            units, table = loads[(SB6_CS_TEX, ST6_CONSTANTS)]
            samplers = loads.get((SB6_CS_TEX, ST6_SHADER), (0, None))[0]
            ntex = (config >> hv('A8XX_REG_SP_CS_CONFIG__NTEX__SHIFT')) & 0xff if config is not None else None
            nsamp = (config >> hv('A8XX_REG_SP_CS_CONFIG__NSAMP__SHIFT')) & 0x1f if config is not None else None
            nuav = (config >> hv('A8XX_REG_SP_CS_CONFIG__NUAV__SHIFT')) & 0x7f if config is not None else None
            check(table is not None, f'{name}: CS T# load without a package table')
            if table is None:
                continue
            single_shape, multi_shape = SHAPES[CS_TABLES]
            if not multi:
                check((units, samplers, tsize, ntex, nsamp, nuav) == single_shape,
                      f'{name}: single shape T# {units} samplers {samplers} TSIZE {tsize} NTEX {ntex} NSAMP {nsamp} NUAV {nuav}')
                check(not any(tdesc(pkg, table)['words']) and by_lo.get(table) is None, f'{name}: T#0 is not null')
                check_texture(name, pkg, by_lo, table, 1, case['sources'][0])
            else:
                check((units, samplers, tsize, ntex, nsamp, nuav) == multi_shape,
                      f'{name}: two-input shape T# {units} samplers {samplers} TSIZE {tsize} NTEX {ntex} NSAMP {nsamp} NUAV {nuav}')
                check(not any(tdesc(pkg, table)['words']) and by_lo.get(table) is None, f'{name}: T#0 is not null')
                kernel = case['kernels'][0]['textures'] if case.get('kernels') else {}
                by_res = {s['resource']: s for s in case['sources']}
                for slot in (1, 2):
                    bound = kernel.get(str(slot)) or {}
                    check(bound.get('resource') in by_res, f'{name}: texture({slot}) is not one of the sources: {bound}')
                    if bound.get('resource') in by_res:
                        check_texture(name, pkg, by_lo, table, slot, by_res[bound['resource']])
                st = loads[(SB6_CS_TEX, ST6_SHADER)][1]
                for k in range(2):
                    w = [u32(pkg, st + 16 * k + 4 * i) for i in range(4)]
                    wraps = [T.dfield(w[0], 'A8XX_TEX_SAMP_0', f'WRAP_{a}') for a in 'STR']
                    check(any(w) and all(name_of('a6xx_tex_clamp', x) in ('A6XX_TEX_CLAMP_TO_EDGE', 'A6XX_TEX_CLAMP_TO_BORDER')
                                         for x in wraps), f'{name}: sampler {k} words {w} wraps {wraps}')
                if CS_TABLES:
                    third = [u32(pkg, st + 32 + 4 * i) for i in range(4)]
                    check(not any(third), f'{name}: the third sampler entry (NSAMP 3) is not zero: {third}')
            for label, exe in replays:
                rd = out / f'replay-{label}' / d
                rd.mkdir(parents=True, exist_ok=True)
                (rd / 'commands.bin').write_bytes((out / d / 'commands.bin').read_bytes())
                try:
                    T_ds.replay(exe, rd, f'{label}:{d}', window=0x3a00000)
                    admitted = ''
                except Exception as error:
                    admitted = str(error) or 'refused'
                if multi and samplers > 1 and label == 'main':
                    multi_refused_by_main.append(bool(admitted))
                    check(bool(admitted), f'{d}: the production validator admitted a {samplers}-unit CS sampler load')
                elif multi and samplers > 1 and not proposal:
                    continue
                else:
                    check(not admitted, f'{d}: {label} kext validator: {admitted[:300]}')
        if gated or not multi:
            check(all(n <= 1 for n in sampler_units), f'{name}: a CS sampler load of {sampler_units} units without the property')
        if multi and not gated:
            check(any(n == 2 for n in sampler_units), f'{name}: no 2-unit CS sampler load: {sampler_units}')
    return multi_refused_by_main


T_ds = None


def main():
    global T_ds, CS_TABLES
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    ap.add_argument('--cs-tables', action='store_true', help='expect a plug-in built with ADRENO_CS_TABLES (Mesa\'s counts)')
    ap.add_argument('--cs-samplers-validator', action='store_true',
                    help='also replay through this tree\'s validator built with ADRENO_IB_CS_SAMPLERS and opted in')
    args = ap.parse_args()
    CS_TABLES = args.cs_tables
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    exe = out / 'settings-ci-encoding'
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', '-Wall', '-Werror', str(HARNESS), '-o', str(exe),
                    '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'CoreImage', '-framework', 'CoreGraphics',
                    '-framework', 'IOKit'], check=True)
    subprocess.run(['codesign', '-f', '-s', '-', str(exe)], check=True, capture_output=True)
    T_ds = load('depth_stencil', 'tools/test-adreno-depth-stencil.py')
    replays = []
    if not args.expect_before:
        replays.append(('main', T_ds.build_replay(out, guest_size=0x4000000, arena=0x3c00000, fixtures=160, capacity=320,
                                                  name='kernel-replay-64m', arena_pages=129)))
        if args.cs_samplers_validator:
            st = load('settings_icons', 'tools/test-adreno-settings-icons.py')
            replays.append(('cs-samplers', st.build_replay_at(T_ds, ROOT, out, 'kernel-replay-cs-samplers',
                                                              st.CS_SAMPLERS_DEFINES)))
    results = {}
    for label, units in (('deployed-kext', None), ('cs-samplers-8', 8)):
        cap = out / label
        env = dict(os.environ)
        env.pop('SETTINGS_ICONS_CS_SAMPLERS', None)
        if units:
            env['SETTINGS_ICONS_CS_SAMPLERS'] = str(units)
        r = subprocess.run([str(exe), str(args.bundle.resolve()), str(cap)], capture_output=True, text=True, env=env, timeout=600)
        (out / f'{label}.log').write_text(r.stdout + r.stderr)
        if not check(r.returncode == 0 and (cap / 'report.json').is_file(), f'{label}: harness exit {r.returncode}'):
            continue
        report = json.loads((cap / 'report.json').read_text())
        use = [x for x in replays if units or x[0] != 'cs-samplers']
        refused = verify(cap, report, gated=units is None, replays=use, proposal=args.cs_samplers_validator)
        results[label] = dict(cases=len(report['cases']), multi_refused_by_main=refused)
        if units and not args.expect_before:
            check(refused and all(refused), f'{label}: the production validator must refuse the two-input package (gate)')
    result = dict(checks=checks, failures=failures, runs=results, expect_before=args.expect_before,
                  validators=[label for label, _ in replays])
    (out / 'result.json').write_text(json.dumps(result, indent=1))
    if args.expect_before:
        if failures:
            print(f'PASS: the unchanged plug-in fails {len(failures)} of {checks} encoding checks (first: {failures[0][:200]}); '
                  f'{out / "result.json"}')
            return 0
        print(f'FAIL: the unchanged plug-in passed every encoding check; {out / "result.json"}')
        return 1
    if failures:
        for f in failures[:40]:
            print(f'FAIL {f[:400]}')
        print(f'FAIL: {len(failures)} of {checks} encoding checks; {out / "result.json"}')
        return 1
    runs = ', '.join(f'{k}: {v["cases"]} cases' for k, v in results.items())
    print(f'PASS: {checks} encoding checks ({runs}; validators {[label for label, _ in replays]}); {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
