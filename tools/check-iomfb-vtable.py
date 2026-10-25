#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ABI check for IOMobileGraphicsFamily26A428.h subclasses (host only, no hardware).

1. Regenerates the header from the KDK + kernelcache (tools/gen-iomfb-header.py) and
   fails if the checked-in header drifted.
2. Compiles, with the flags of gpu/adreno-kext/kext/build.sh, a minimal stub subclass
   (only the nine pure virtuals) and gpu/adreno-kext/kext/src/AdrenoDisplay.cpp, and
   links both into one throw-away MH_KEXT_BUNDLE.
3. For each class, reads its vtable from the linked chained fixups and checks every
   one of the 483 inherited slots against Apple:
     - PAC: key IA, address diversity, and the diversity equal to the kernelcache's
       IOMobileFramebufferLegacy slot, except the four IOMobileFramebuffer pures the
       Legacy class re-declares (318 320 361 362), where it must equal the introducing
       IOMobileFramebuffer slot. Both must also equal AppleParavirtDisplay's slot.
     - target: an override must be named <Class>::<same method and signature as Apple's
       slot>; an inherited slot must bind to exactly the symbol AppleParavirtDisplay's
       vtable uses (an exported base implementation, or one of the header's inline
       bodies, whose instructions must match Apple's local copy).
4. Every undefined symbol of the bundle must be exported by the kernelcache
   (kernel, IOMobileGraphicsFamily, IOAVFamily, IOSurface, IOGPUFamily).

Writes <out>/iomfb-vtable-check.json (the full per-slot table) and exits 1 on any failure.
Usage: tools/check-iomfb-vtable.py [--out DIR] [--kc PATH] [--kdk PATH] [--no-display] [--display-define NAME[=V] ...]
--display-define (alias --define) compiles AdrenoDisplay.cpp, and only it, with that define too: a profile's
AdrenoDisplay set, or an opt-in override such as ADRENO_DISPLAY_TRACE_MODES=1 or ADRENO_BACKLIGHT=1 (whose
set_brightness_gated and swap_submit overrides must then pass the same slot check); without it the default build is checked.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEXT = ROOT / 'gpu/adreno-kext/kext'
HEADER = KEXT / 'include/IOMobileGraphicsFamily26A428.h'
_spec = importlib.util.spec_from_file_location('geniomfb', ROOT / 'tools/gen-iomfb-header.py')
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

REDECLARED = {318, 320, 361, 362}
EXPORT_BUNDLES = ('com.apple.kernel', 'com.apple.iokit.IOMobileGraphicsFamily',
                  'com.apple.iokit.IOAVFamily', 'com.apple.iokit.IOSurface',
                  'com.apple.iokit.IOGPUFamily', 'com.apple.iokit.IOGraphicsFamily')

STUB = r'''
#include "IOMobileGraphicsFamily26A428.h"
// Minimal concrete subclass: exactly the nine pure virtuals, nothing else.
class IOMFBVTableStub : public IOMobileFramebufferLegacy
{
    OSDeclareDefaultStructors(IOMFBVTableStub)
public:
    virtual IOReturn set_notify_tag_mask_gated(IOMFB_NotificationType, IOMFBNotifyRequest *, unsigned int) APPLE_KEXT_OVERRIDE { return 0; }
    virtual IOReturn supported_frame_info(unsigned int, unsigned int *, char (*)[64], unsigned int *) APPLE_KEXT_OVERRIDE { return 0; }
    virtual IOReturn factory_portal(void *, task *) APPLE_KEXT_OVERRIDE { return 0; }
    virtual IOReturn executeFactoryConfigurations_gated() APPLE_KEXT_OVERRIDE { return 0; }
    virtual void set_frame_info_notification_state_gated(IOMFBNotifyRequest *, bool) APPLE_KEXT_OVERRIDE {}
    virtual void do_swap_info_notify_gated(IOMFBNotifyRequest *, const IOMobileFramebufferLegacy::SwapInfoBlob *) APPLE_KEXT_OVERRIDE {}
    virtual IOReturn notify_swap_done_gated(unsigned int, ::SwapInfoBlob *, unsigned int *, unsigned int) APPLE_KEXT_OVERRIDE { return 0; }
    virtual void notify_crc_ready_gated(unsigned int) APPLE_KEXT_OVERRIDE {}
    virtual bool are_timings_enabled() const APPLE_KEXT_OVERRIDE { return false; }
};
OSDefineMetaClassAndStructors(IOMFBVTableStub, IOMobileFramebufferLegacy)
'''

KMOD = r'''
#include <mach/mach_types.h>
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(org.snapintosh.iomfbcheck, "1.0.0", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = 0;
__private_extern__ kmod_stop_func_t *_antimain = 0;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
'''


def sh(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f'command failed: {" ".join(map(str, cmd))}')
    return r.stdout


def compile_bundle(out, sources, extra=None):
    sdk = sh(['xcrun', '--show-sdk-path']).strip()
    kh = f'{sdk}/System/Library/Frameworks/Kernel.framework/Headers'
    common = ['-target', 'arm64e-apple-macos27.0', '-isysroot', sdk, '-mkernel', '-nostdinc',
              f'-I{kh}', f'-I{KEXT}/include', f'-I{KEXT}/../include', '-DKERNEL', '-DAPPLE', '-DNeXT',
              '-O2', '-g', '-Wall', '-Werror', '-Wno-unused-private-field', '-fno-common']
    cxx = common + ['-std=gnu++17', '-fapple-kext', '-fno-exceptions', '-fno-rtti',
                    '-Wno-inconsistent-missing-override']
    objs = []
    for src in sources:
        obj = out / (Path(src).stem + '.o')
        lang = cxx if str(src).endswith('.cpp') else common
        lang = lang + list((extra or {}).get(str(src), ()))
        sh(['xcrun', 'clang++' if str(src).endswith('.cpp') else 'clang'] + lang + ['-c', str(src), '-o', str(obj)])
        objs.append(str(obj))
    binary = out / 'IOMFBCheck'
    sh(['xcrun', 'clang++', '-target', 'arm64e-apple-macos27.0', '-isysroot', sdk, '-mkernel', '-nostdlib',
        '-Xlinker', '-kext', '-Xlinker', '-export_dynamic', '-o', str(binary)] + objs +
       [f'-L{sdk}/usr/lib', '-lkmodc++', '-lkmod', '-lcc_kext'])
    return binary


def kc_exports(kc):
    names = set()
    for bundle in EXPORT_BUNDLES:
        r = subprocess.run(['ipsw', 'macho', 'info', str(kc), '--fileset-entry', bundle, '--symbols'],
                           capture_output=True, text=True)
        text = re.sub(r'\x1b\[[0-9;]*m', '', r.stdout)
        names.update(re.findall(r'\) external\s+(_\S+)', text))
    return names


def norm_body(body):
    out = []
    for ins in body:
        ins = re.sub(r'0x[0-9a-f]+ <[^>]*>', 'ADDR', ins)
        ins = re.sub(r'\s+', ' ', ins).strip()
        out.append(ins)
    return out


def check_class(cls, binary, model, pv_ref, kcdivs, iomfb_divs, results):
    vt = binary.vtable(cls)
    slots = model['slots']
    legacy = model['vts']['IOMobileFramebufferLegacy']
    pv = model['pvvt']
    pv_fn = model['pv'].functions()
    mine_fn = binary.functions()
    errors = []
    if len(vt) < len(legacy):
        errors.append(f'{cls}: vtable has {len(vt)} slots, IOMobileFramebufferLegacy has {len(legacy)}')
    rows = []
    for i in range(min(len(vt), len(legacy))):
        _, target, div, local, addr_div, key = vt[i]
        want_div = kcdivs[i] if i not in REDECLARED else iomfb_divs[i]
        pv_name, pv_div = pv[i][1], pv[i][2]
        row = {'slot': i, 'target': target, 'div': div, 'kc_div': kcdivs[i], 'want_div': want_div,
               'pv_div': pv_div, 'pv_target': pv_name, 'local': local}
        bad = []
        if div != want_div:
            bad.append(f'diversity {div:#06x} != {want_div:#06x}')
        if div != pv_div:
            bad.append(f'diversity {div:#06x} != AppleParavirtDisplay {pv_div:#06x}')
        if key != 'IA' or not addr_div:
            bad.append(f'key {key} addrDiv {addr_div}')
        prefix = '%d%s' % (len(cls), cls)
        m = re.match(r'^__ZNK?(\d+)', target)
        tcls = target[m.end():m.end() + int(m.group(1))] if m else None
        if tcls == cls:
            # Our override: same method/signature as Apple's slot occupant.
            ref = pv_name if pv_name.startswith('__ZN20AppleParavirtDisplay') or \
                pv_name.startswith('__ZNK20AppleParavirtDisplay') else legacy[i][1]
            if ref == gen.PURE:
                ref = slots[i].mangled.get('IOMobileFramebufferLegacy') or slots[i].mangled[slots[i].introducer]
            if i in (0, 1):
                ok = target.endswith(('D1Ev', 'D0Ev')) and target[-4:] == ref[-4:]
            elif i == 7:
                ok = target.endswith('12getMetaClassEv')
            else:
                ok = gen.mangled_for(cls, ref) == target
            if not ok:
                bad.append(f'override {target} does not match Apple slot {ref}')
            row['kind'] = 'override'
        else:
            # Inherited: must be exactly what Apple's own subclass binds.
            ref = pv_name
            if pv_name.startswith(('__ZN20AppleParavirtDisplay', '__ZNK20AppleParavirtDisplay')):
                ref = legacy[i][1]            # PV overrides it; the base implementation is the reference
            if ref == gen.PURE:
                bad.append(f'pure virtual {slots[i].method} not implemented')
            elif target != ref:
                bad.append(f'inherits {target}, Apple binds {ref}')
            elif local:
                # An inline header body: compare instructions with Apple's local copy.
                apple = pv_fn.get(ref) or model['iomgf'].functions().get(ref)
                ours = mine_fn.get(target)
                if apple is None or ours is None or norm_body(apple) != norm_body(ours):
                    bad.append(f'inline body {target} differs from Apple\'s copy')
                row['kind'] = 'inline'
            else:
                row['kind'] = 'bind'
        if bad:
            errors.extend(f'{cls}[{i}] ' + b for b in bad)
            row['errors'] = bad
        rows.append(row)
    results[cls] = {'slots': len(vt), 'extra_slots': [v[1] for v in vt[len(legacy):]], 'rows': rows,
                    'errors': len([r for r in rows if 'errors' in r])}
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', type=Path, default=Path('/tmp/iomfb-vtable-check'))
    ap.add_argument('--kdk', type=Path, default=gen.DEFAULT_KDK)
    ap.add_argument('--kc', type=Path, default=gen.DEFAULT_KC)
    ap.add_argument('--no-display', action='store_true', help='check only the stub subclass')
    ap.add_argument('--display-define', '--define', dest='display_define', action='append', default=[],
                    metavar='NAME[=VALUE]',
                    help='a -D for AdrenoDisplay.cpp only, repeatable (e.g. a profile\'s AdrenoDisplay set, '
                         'ADRENO_DISPLAY_TRACE_MODES=1 or ADRENO_BACKLIGHT=1, whose overrides add slots to check)')
    args = ap.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    errors = []

    model = gen.build_model(args.kdk, args.kc, out / 'gen')
    text = gen.emit(model)
    if HEADER.read_text() != text:
        errors.append(f'{HEADER} differs from a fresh tools/gen-iomfb-header.py run')
    kcdivs = gen.kc_vtable_divs(args.kc, gen.IOMGF_BUNDLE, ('IOMobileFramebuffer', 'IOMobileFramebufferLegacy'))
    iomfb_divs = kcdivs['IOMobileFramebuffer'] + [None] * 200

    (out / 'IOMFBVTableStub.cpp').write_text(STUB)
    (out / 'kmod_info.c').write_text(KMOD)
    sources = [out / 'IOMFBVTableStub.cpp', out / 'kmod_info.c']
    classes = ['IOMFBVTableStub']
    if not args.no_display:
        sources.insert(1, KEXT / 'src/AdrenoDisplay.cpp')
        classes.append('AdrenoDisplay')
    binary_path = compile_bundle(out, sources, {str(KEXT / 'src/AdrenoDisplay.cpp'):
                                                ['-D' + d for d in args.display_define]})
    binary = gen.MachOKext(binary_path)

    results = {}
    for cls in classes:
        errors += check_class(cls, binary, model, model['pvvt'], kcdivs['IOMobileFramebufferLegacy'],
                              iomfb_divs, results)
        extra = results[cls]['extra_slots']
        if extra:
            errors.append(f'{cls}: {len(extra)} vtable slots beyond Apple\'s 483: {extra}')

    exports = kc_exports(args.kc)
    undef = sorted(set(l.split()[-1] for l in sh(['nm', '-u', str(binary_path)]).split('\n') if l.strip()))
    missing = [u for u in undef if u not in exports and not u.startswith('_OSKext')]
    if missing:
        errors.append(f'{len(missing)} undefined symbols not exported by the kernelcache: {missing}')

    report = {
        'header_sha256': hashlib.sha256(HEADER.read_bytes()).hexdigest(),
        'kernelcache': str(args.kc),
        'bundle_sha256': hashlib.sha256(binary_path.read_bytes()).hexdigest(),
        'classes': results, 'undefined': undef, 'undefined_not_exported': missing,
        'errors': errors, 'verdict': 'PASS' if not errors else 'FAIL',
    }
    (out / 'iomfb-vtable-check.json').write_text(json.dumps(report, indent=1))
    for cls in classes:
        r = results[cls]
        kinds = {}
        for row in r['rows']:
            kinds[row.get('kind', '?')] = kinds.get(row.get('kind', '?'), 0) + 1
        print(f'{cls}: {r["slots"]} slots, {r["errors"]} bad; ' +
              ', '.join(f'{k} {v}' for k, v in sorted(kinds.items())))
    print(f'undefined symbols: {len(undef)}, not exported by the kernelcache: {len(missing)}')
    for e in errors[:40]:
        print('FAIL', e)
    print(f'{report["verdict"]}  report: {out / "iomfb-vtable-check.json"}')
    return 0 if not errors else 1


if __name__ == '__main__':
    sys.exit(main())
