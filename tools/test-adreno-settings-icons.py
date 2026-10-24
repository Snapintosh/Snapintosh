#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""System Settings pane icons through the plug-in device, against this Mac's GPU (no GPU submission, no A16).

ADRENO_SETTINGS_ICONS (gpu/adreno-kext/plugin/AdrenoMetal/AdrenoDrawCommands/Compute.m): the pane rows' icons
(AsyncIconImage) come from iconservicesagent's ISGenerationRequest -generateImage on the system default Metal device, are redrawn by the client on the CPU and drawn
by WindowServer's Core Animation. The harness (gpu/adreno-kext/plugin/harness/settings-icons.m) runs those stages for
every Settings extension icon, the device/display/storage/document type icons the panes show, the system apps' icons
(Login Items, Notifications, Privacy lists), named images from the Settings extensions' asset catalogs, MonitorPanel's
display previews and SF Symbols, twice: --host-caps (this Mac's GPU answering like the plug-in device: Apple's
reference, with pixels) and --adreno (the plug-in device as the system default; commits intercepted). Per case:
  - reference: this Mac's GPU produces a non-transparent image and draws it (else the case is invalid, and counted);
  - the plug-in run produces an image of the same pixel size;
  - every generate/display commit encodes work, omits nothing and fails no encoding; no exception, no pipeline error;
  - CoreImage dispatches as many kernels on the plug-in device as on this Mac's GPU (same work);
  - every commit's kernel commands replay through the production kext validator (and, with --validator-tree, through
    that tree's validator sources too).
--expect-before: the unchanged plug-in must fail at least one of these.
Multi-input CoreImage kernels need more than one CS sampler unit, which the validator admits only in a kext built with
ADRENO_IB_CS_SAMPLERS and booted with adreno_cs_samplers=1; an ADRENO_SETTINGS_ICONS plug-in encodes them only when the
kext publishes AdrenoIBComputeSamplers. --cs-samplers N stands in for such a kext (replay those packages with
--cs-samplers-validator, this tree's validator built and opted in that way, and --skip-main-validator);
--allow-kext-gated reports the kernels refused for want of the property without failing on them. --jobs runs that many
validator replays at once (each commit's replay is independent); --cases keeps the cases whose name matches a regex.

    python3 tools/test-adreno-settings-icons.py --bundle BUNDLE --output NEW-DIR [--expect-before] [--quick]
        [--cases REGEX] [--validator-tree TREE]... [--cs-samplers-validator] [--skip-main-validator]
        [--cs-samplers N] [--allow-kext-gated] [--reference HOST-CAPS-RUN-DIR] [--jobs N]
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness'
EXT = Path('/System/Library/ExtensionKit/Extensions')
# Type icons the panes show (About/Storage/Displays/Bluetooth/Network/Time Machine/Privacy rows, documents, folders).
TYPES = ['public.folder', 'public.plain-text', 'public.volume', 'public.display', 'public.disk-image', 'public.item',
         'public.image', 'public.movie', 'public.audio', 'com.apple.application-bundle', 'com.apple.network-neighborhood',
         'com.apple.storage-external', 'com.apple.generic-time-machine-disk', 'com.apple.macbookpro-16-space-gray',
         'com.apple.macbookair-13-2022-midnight', 'com.apple.imac-2021-blue', 'com.apple.macmini', 'com.apple.studio-display',
         'com.apple.pro-display-xdr', 'com.apple.cinema-display', 'com.apple.magic-mouse', 'com.apple.airpods-pro',
         'com.apple.iphone', 'com.apple.ipad', 'com.apple.application-icon.icloud', 'com.apple.application-icon.icloud-storage',
         'com.apple.graphic-icon.bluetooth', 'com.apple.graphic-icon.display', 'com.apple.graphic-icon.usb',
         'com.apple.graphic-icon.local-network', 'com.apple.graphic-icon.external-drive', 'com.apple.graphic-icon.privacy',
         'com.apple.graphic-icon.trackpad-and-mouse', 'com.apple.graphic-icon.icloud-backup']
LARGE_TYPES = ['com.apple.macbookpro-16-space-gray', 'com.apple.studio-display', 'public.display', 'com.apple.storage-external']
SYMBOLS = [('wifi', None), ('network', None), ('gear', None), ('externaldrive.fill', None), ('lock.fill', None),
           ('person.crop.circle.fill', 'palette'), ('battery.100percent', 'multicolor'), ('bell.badge.fill', 'multicolor'),
           ('sun.max.fill', 'multicolor'), ('speaker.wave.3.fill', None), ('display', None), ('keyboard', None),
           ('hand.raised.fill', None), ('cloud.fill', 'multicolor')]
MONITORPANEL = Path('/System/Library/PrivateFrameworks/MonitorPanel.framework/Versions/A/Resources')


def settings_extensions():
    out = []
    for info in sorted(EXT.glob('*.appex/Contents/Info.plist')):
        try:
            d = plistlib.loads(info.read_bytes())
        except Exception:
            continue
        if (d.get('EXAppExtensionAttributes') or {}).get('EXExtensionPointIdentifier') == 'com.apple.Settings.extension.ui':
            out.append(info.parents[1])
    return out


def asset_cases(exts, per_kind):
    """Named images of the Settings extensions' own asset catalogs, a few per (catalog, encoding)."""
    cases = []
    for ext in exts:
        car = ext / 'Contents/Resources/Assets.car'
        if not car.is_file():
            continue
        r = subprocess.run(['assetutil', '--info', str(car)], capture_output=True, text=True)
        try:
            rows = json.loads(r.stdout)[1:]
        except Exception:
            continue
        picked = {}
        for row in rows:
            if row.get('AssetType') not in ('Image', 'PackedImage', 'Icon Image', 'MultiSized Image', 'Vector'):
                continue
            if '/' in (row.get('Name') or '') or (row.get('Name') or '').startswith('ZZZZPackedAsset'):
                continue   # a layer of an icon stack or a packed-asset atlas, not a named image
            enc = row.get('Encoding') or row.get('AssetType')
            names = picked.setdefault(enc, [])
            if row.get('Name') and row['Name'] not in names and len(names) < per_kind:
                names.append(row['Name'])
        for enc, names in sorted(picked.items()):
            for n in names:
                cases.append(dict(name=f'asset-{ext.stem}-{enc}-{n}', kind='asset', path=str(ext), asset=n, size=32, scale=2))
    return cases


def make_cases(quick, only=None):
    exts = settings_extensions()
    cases = [dict(name=f'ext-{e.stem}', kind='bundle', path=str(e), size=20, scale=2) for e in exts]
    cases += [dict(name=f'type-{t}', kind='type', type=t, size=20, scale=2) for t in TYPES]
    cases += [dict(name=f'type64-{t}', kind='type', type=t, size=64, scale=2) for t in LARGE_TYPES]
    apps = sorted(Path('/System/Applications').glob('*.app')) + sorted(Path('/System/Applications/Utilities').glob('*.app'))
    apps += [Path('/Applications/Safari.app'), Path('/System/Library/CoreServices/Finder.app')]
    cases += [dict(name=f'app-{a.stem}', kind='bundle', path=str(a), size=20, scale=2) for a in apps if a.exists()]
    cases += asset_cases(exts, 1 if quick else 2)
    cases += [dict(name=f'file-{p.stem}', kind='file', path=str(p), size=64, scale=2) for p in sorted(MONITORPANEL.glob('*.tiff'))]
    for name, mode in SYMBOLS:
        c = dict(name=f'symbol-{name}' + (f'-{mode}' if mode else ''), kind='symbol', symbol=name, size=20, scale=2)
        if mode:
            c[mode] = True
        cases.append(c)
    if quick:
        keep = re.compile(r'ext-(General|Power|Headphone|TimeMachine|Displays)|type-public\.(folder|plain-text|display)$|'
                          r'type-com\.apple\.macbookpro|type64-com\.apple\.studio|app-(Safari|Calculator|Terminal)|asset-|file-|symbol-(wifi|battery)')
        cases = [c for c in cases if keep.search(c['name'])]
    if only:
        cases = [c for c in cases if re.search(only, c['name'])]
    names = [c['name'] for c in cases]
    assert len(names) == len(set(names)), 'duplicate case names'
    return cases


def load_ds():
    spec = importlib.util.spec_from_file_location('depth_stencil', ROOT / 'tools/test-adreno-depth-stencil.py')
    ds = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ds)
    return ds


# The validator of a kext built with ADRENO_IB_CS_SAMPLERS and booted with adreno_cs_samplers=1 (8 CS sampler units).
CS_SAMPLERS_DEFINES = ['-DADRENO_IB_CS_SAMPLERS=1', '-DIB_REPLAY_CS_SAMPLER_UNITS=8']


def build_replay_at(ds, root, out, name, defines=()):
    """ds.build_replay with the validator sources of a tree (this one or another) and extra defines."""
    sources = ['tools/test-adreno-ib-command.c', 'compat/adreno-ib-command.c', 'compat/adreno-ib.c', 'compat/adreno-fill-command.c',
               'compat/adreno-fill.c', 'compat/adreno-submit.c', 'compat/adreno-resource.c', 'compat/adreno-resource-list.c',
               'compat/adreno.c', 'compat/irq-forward.c', 'shadow/stage2.c', 'shadow/shadow.c', 'shadow/mmu.c']
    exe = out / name
    flags = ['clang', '-std=gnu11', '-Icompat', '-Ishadow', '-DGUEST_SIZE=0x4000000', '-DIB_ARENA_OFFSET=0x3c00000',
             '-DIB_FIXTURES=160', '-DIB_REPLAY_CAPACITY=320', '-DIB_ARENA_PAGES=129u', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             *defines]
    r = subprocess.run(flags + sources + ['-o', str(exe)], cwd=root, capture_output=True, text=True, timeout=300)
    (out / f'{name}-build.log').write_text(r.stdout + r.stderr)
    if r.returncode:
        raise SystemExit(f'FAIL: {name} build failed (see {out / (name + "-build.log")})')
    return exe


def run_harness(exe, lib, mode, bundle, out, cases_file, cs_samplers=None):
    env = dict(os.environ, OS_ACTIVITY_DT_MODE='1')
    env.pop('SETTINGS_ICONS_CS_SAMPLERS', None)
    if mode == '--adreno':
        env['DYLD_INSERT_LIBRARIES'] = str(lib)
        if cs_samplers:
            env['SETTINGS_ICONS_CS_SAMPLERS'] = str(cs_samplers)
    r = subprocess.run([str(exe), mode, str(bundle), str(out), str(cases_file)], capture_output=True, text=True, env=env, timeout=3600)
    log = r.stdout + r.stderr
    return r.returncode, log


def attribute(log):
    """os_log lines per case (the harness prints '@@case NAME STAGE' before each stage)."""
    per, current = {}, None
    for line in log.splitlines():
        if line.startswith('@@case '):
            current = line.split()[1]
            continue
        if current:
            per.setdefault(current, []).append(line)
    return per


def compute_counts(commits):
    enc = om = 0
    for c in commits:
        for e in ((c.get('work') or {}).get('encoders') or {}).values():
            if e.get('kind') == 'compute':
                enc += int(e.get('encoded') or 0)
                om += int(e.get('omitted') or 0)
    return enc, om


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    ap.add_argument('--quick', action='store_true', help='a representative subset (about 40 cases)')
    ap.add_argument('--cases', help='only the cases whose name matches this regular expression')
    ap.add_argument('--reference', type=Path, help='reuse a --host-caps run (its report.json) instead of running one')
    ap.add_argument('--validator-tree', type=Path, action='append', default=[], help='also replay through this tree\'s validator')
    ap.add_argument('--cs-samplers-validator', action='store_true',
                    help='also replay through this tree\'s validator built with ADRENO_IB_CS_SAMPLERS and opted in')
    ap.add_argument('--skip-main-validator', action='store_true', help='do not replay through this tree\'s production validator')
    ap.add_argument('--jobs', type=int, default=min(8, os.cpu_count() or 1), help='validator replays run at once')
    ap.add_argument('--cs-samplers', type=int, help='stand in for a kext publishing AdrenoIBComputeSamplers = N')
    ap.add_argument('--allow-kext-gated', action='store_true',
                    help='kernels refused only for want of AdrenoIBComputeSamplers are reported, not failed')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    build = subprocess.run(['sw_vers', '-buildVersion'], capture_output=True, text=True).stdout.strip()
    if build != '26A428':
        print(f'FAIL: host build {build}, not 26A428')
        return 1
    lib, exe = out / 'default-device-interpose.dylib', out / 'settings-icons'
    subprocess.run(['xcrun', 'clang', '-dynamiclib', '-arch', 'arm64e', str(HARNESS / 'default-device-interpose.m'), '-o', str(lib),
                    '-framework', 'Foundation', '-framework', 'Metal'], check=True)
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', '-Wall', '-Werror', str(HARNESS / 'settings-icons.m'),
                    '-o', str(exe), '-framework', 'AppKit', '-framework', 'QuartzCore', '-framework', 'Metal', '-framework', 'IOSurface',
                    '-framework', 'IOKit', '-framework', 'CoreGraphics'], check=True)
    for f in (lib, exe):
        subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
    cases = make_cases(args.quick, args.cases)
    cases_file = out / 'cases.json'
    cases_file.write_text(json.dumps(cases, indent=1))
    bundle = args.bundle.resolve()
    if args.reference:
        ref = json.loads((args.reference / 'report.json').read_text())
        ref_log = (args.reference.parent / 'host-caps.log').read_text() if (args.reference.parent / 'host-caps.log').is_file() else ''
    else:
        rc, ref_log = run_harness(exe, lib, '--host-caps', bundle, out / 'host-caps', cases_file)
        (out / 'host-caps.log').write_text(ref_log)
        if rc or not (out / 'host-caps/report.json').is_file():
            print(f'FAIL: host-caps harness exit {rc}; {out / "host-caps.log"}')
            return 1
        ref = json.loads((out / 'host-caps/report.json').read_text())
    rc, log = run_harness(exe, lib, '--adreno', bundle, out / 'adreno', cases_file, args.cs_samplers)
    (out / 'adreno.log').write_text(log)
    failures, checks, invalid = [], 0, []

    def check(ok, what):
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    check(rc == 0 and (out / 'adreno/report.json').is_file(), f'adreno harness exit {rc}')
    if failures:
        print(f'FAIL: {failures[0]}; {out / "adreno.log"}')
        return 1
    got = json.loads((out / 'adreno/report.json').read_text())
    refs = {c['name']: c for c in ref['cases']}
    lines = attribute(log)
    ds = load_ds()
    replays = []
    if not args.expect_before and not args.skip_main_validator:
        replays.append(('main', ds.build_replay(out, guest_size=0x4000000, arena=0x3c00000, fixtures=160, capacity=320,
                                                name='kernel-replay-64m', arena_pages=129)))
    if not args.expect_before:
        if args.cs_samplers_validator:
            replays.append(('cs-samplers', build_replay_at(ds, ROOT, out, 'kernel-replay-cs-samplers', CS_SAMPLERS_DEFINES)))
        for n, tree in enumerate(args.validator_tree):
            replays.append((f'tree{n}', build_replay_at(ds, tree.resolve(), out, f'kernel-replay-tree{n}')))
    gated, pending = {}, []
    summary, omitted_reasons = {}, {}
    for c in got['cases']:
        name = c['name']
        r = refs.get(name) or {}
        ref_img = r.get('client') or {}
        ref_ok = bool(r.get('client_coverage')) and all(f.get('changed_pixels', 0) > 0 for f in (r.get('display') or {}).get('frames', [{}]))
        if not ref_ok:
            invalid.append(name)
            continue
        img = c.get('client') or {}
        check(bool(img) and img.get('width') == ref_img.get('width') and img.get('height') == ref_img.get('height'),
              f'{name}: image {img.get("width")}x{img.get("height")}, reference {ref_img.get("width")}x{ref_img.get("height")}')
        check(not c.get('exception'), f'{name}: exception {c.get("exception")}')
        errors = [l for l in lines.get(name, []) if 'pipeline error: ' in l]
        check(not errors, f'{name}: pipeline errors {errors[:2]}')
        stages = c.get('stages') or {}
        row = {}
        for stage in ('generate', 'display'):
            commits = (stages.get(stage) or {}).get('commits', [])
            ref_census = ((r.get('stages') or {}).get(stage) or {}).get('census') or {}
            got_census = (stages.get(stage) or {}).get('census') or {}
            omissions = [o for x in commits for o in ((x.get('work') or {}).get('omissions') or [])]
            if args.allow_kext_gated:
                kept = [o for o in omissions if '(AdrenoIBComputeSamplers)' not in ((o.get('details') or {}).get('reason') or '')]
                if len(kept) != len(omissions):
                    gated[name] = sorted({((o.get('details') or {}).get('pipeline') or {}).get('entry', '?') for o in omissions
                                          if o not in kept})
                omissions = kept
            for o in omissions:
                d = o.get('details') or {}
                k = (d.get('reason') or '?')[:140]
                omitted_reasons.setdefault(k, set()).add(name)
            check(not omissions, f'{name}/{stage}: {len(omissions)} omitted: ' + '; '.join(sorted({(o.get("details") or {}).get("reason", "?")[:160] for o in omissions})[:2]))
            check(not any((x.get('work') or {}).get('encoding_failed') for x in commits), f'{name}/{stage}: an encoding failed')
            if stage == 'generate':
                # Same work: CoreImage dispatches the same kernels, as often, on the plug-in device as on this Mac's GPU
                # answering like it. (Other compute work, e.g. RenderBox's, may differ with the device and is not compared.)
                # Without a GPU a flattened icon stack is transparent and IconServices retries ("Central pixel is still
                # transparent even with retry"; os_log drops some of these lines under load), adding Lanczos passes:
                # extra kernels are allowed with that line or for an icon-stack flatten (RenderBox draws on this Mac).
                want = Counter(k for k in ref_census.get('kernels', []) if k.startswith('ci_'))
                have = Counter(k for k in got_census.get('kernels', []) if k.startswith('ci_'))
                retried = any('Central pixel is still transparent' in l for l in lines.get(name, [])) or ref_census.get('draws', 0) > 0
                check(not (want - have), f'{name}/generate: CoreImage kernels the plug-in did not run: {sorted((want - have).elements())[:3]}')
                check(not (have - want) or retried, f'{name}/generate: extra CoreImage kernels without a retry: '
                                                    f'{sorted((have - want).elements())[:3]}')
                enc, om = compute_counts(commits)
                check(enc + om == got_census.get('dispatches', 0), f'{name}/generate: {enc}+{om} compute dispatches in the work '
                                                                   f'reports, {got_census.get("dispatches")} counted')
            if stage == 'display':
                check(bool(commits), f'{name}/display: no commits')
            for label, rexe in replays:
                for x in commits:
                    d = out / 'adreno' / x['dir']
                    if not (d / 'commands.bin').is_file():
                        continue
                    # A commit without an IB package (an empty command buffer: one 0x1000 header) has nothing to admit.
                    if not any(kind == 0x1002 for kind, _ in ds.P.kernel_commands((d / 'commands.bin').read_bytes())):
                        continue
                    if label != 'main':
                        d2 = out / f'replay-{label}' / x['dir']
                        d2.mkdir(parents=True, exist_ok=True)
                        (d2 / 'commands.bin').write_bytes((d / 'commands.bin').read_bytes())
                        d = d2
                    pending.append((label, rexe, d, x['dir']))
            row[stage] = dict(commits=len(commits), omitted=len(omissions))
        summary[name] = row

    def replay_one(task):
        label, rexe, d, rel = task
        try:
            ds.replay(rexe, d, f'{label}:{rel}', window=0x3a00000)
            return ''
        except Exception as error:      # the replay module's own failure class
            return str(error) or 'refused'

    # Each replay reads only its own commit's capture and writes only its own replay directory.
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for (label, _rexe, _d, rel), admitted in zip(pending, pool.map(replay_one, pending)):
            check(not admitted, f'{rel}: {label} kext validator: {admitted[:300]}')
    check(len(invalid) <= max(3, len(got['cases']) // 10), f'{len(invalid)} cases without a reference image: {invalid[:8]}')
    result = dict(checks=checks, failures=failures, invalid=invalid, cases=len(got['cases']), summary=summary, kext_gated=gated,
                  cs_samplers=args.cs_samplers, validators=[label for label, _ in replays],
                  omitted_reasons={k: sorted(v) for k, v in omitted_reasons.items()}, expect_before=args.expect_before)
    (out / 'result.json').write_text(json.dumps(result, indent=1))
    if args.expect_before:
        if failures:
            print(f'PASS: the unchanged plug-in fails {len(failures)} of {checks} settings-icon checks '
                  f'({len(omitted_reasons)} omission reasons; first: {failures[0][:200]}); {out / "result.json"}')
            return 0
        print(f'FAIL: the unchanged plug-in passed every settings-icon check; {out / "result.json"}')
        return 1
    if failures:
        for f in failures[:60]:
            print(f'FAIL {f[:400]}')
        print(f'FAIL: {len(failures)} of {checks} settings-icon checks ({len(got["cases"])} cases, {len(invalid)} invalid); '
              f'{out / "result.json"}')
        return 1
    extra = f'; {len(gated)} cases with kernels awaiting AdrenoIBComputeSamplers: {sorted(gated)}' if gated else ''
    print(f'PASS: {checks} settings-icon checks, {len(got["cases"])} cases ({len(invalid)} without a reference image), '
          f'validators {[label for label, _ in replays]}{extra}; {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
