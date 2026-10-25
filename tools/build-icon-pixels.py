#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build and ad-hoc sign the icon-pixels guest tool (arm64e), without running it in the guest.

The tool (gpu/adreno-kext/plugin/harness/icon-pixels*.m, SnapMetal) runs the CoreImage kernels
of the System Settings pane icons on the default Metal device and prints checksummed lines per case; see its header.
Built like the other guest probes (tools/build-adreno-clear-probe.py): xcrun clang -arch arm64e for macOS 27, ad-hoc
signature, architecture and signature checked. Writes OUTPUT/icon-pixels and OUTPUT/build.json (size, SHA-256, CDHash,
compiler, command lines, source SHA-256s), and prints the record. OUTPUT must not exist.

    python3 tools/build-icon-pixels.py --output build/icon-pixels/tool-YYYYMMDD

The CDHash is the trust-cache row the guest needs only if its AMFI refuses an ad-hoc arm64e executable
(tools/run-icon-pixels.py checks that first and stops with this hint).
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness'
SOURCES = [HARNESS / 'icon-pixels.m', HARNESS / 'icon-pixels-census.m', HARNESS / 'icon-pixels-icons.m',
           HARNESS / 'icon-pixels.h']
FRAMEWORKS = ['Foundation', 'Metal', 'CoreImage', 'CoreGraphics', 'IOKit', 'AppKit', 'UniformTypeIdentifiers']


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = out / 'icon-pixels'
    sources = {str(p.relative_to(ROOT)): sha(p) for p in SOURCES}
    commands = []

    def run(name, argv):
        commands.append(argv)
        r = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / f'{name}.log').write_text(r.stdout)
        if r.returncode:
            raise SystemExit(f'{name} failed ({r.returncode}): {out / (name + ".log")}')
        return r.stdout
    compiler = run('compiler', ['xcrun', 'clang', '--version']).splitlines()[0]
    argv = ['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0', '-fobjc-arc', '-fobjc-arc-exceptions', '-O2',
            '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
            *[str(p.relative_to(ROOT)) for p in SOURCES if p.suffix == '.m'], '-o', str(binary)]
    for f in FRAMEWORKS:
        argv += ['-framework', f]
    # -x drops local symbols: a smaller binary is fewer console chunks to push.
    run('build', argv + ['-lz', '-Wl,-dead_strip', '-Wl,-x'])
    run('sign', ['codesign', '-f', '-s', '-', str(binary)])
    run('verify-signature', ['codesign', '--verify', '--strict', '--verbose=2', str(binary)])
    arch = run('architecture', ['lipo', '-archs', str(binary)]).strip()
    if arch != 'arm64e':
        raise SystemExit(f'architecture {arch}, not arm64e')
    signing = run('signature', ['codesign', '-dvvv', str(binary)])
    cdhash, = re.findall(r'^CDHash=([0-9a-f]+)$', signing, re.M)
    version = run('version', [str(binary), 'version']).splitlines()[0]
    if sources != {k: sha(ROOT / k) for k in sources}:
        raise SystemExit('a source changed during the build')
    record = dict(status='ICON_PIXELS_BUILT_NOT_RUN_ON_A16', binary=str(binary), bytes=binary.stat().st_size,
                  sha256=sha(binary), cdhash=cdhash, architecture=arch, compiler=compiler, host_version_line=version,
                  sources_sha256=sources, commands=commands,
                  trust_row=dict(name='icon-pixels', cdhash=cdhash, category=2, flags=0))
    (out / 'build.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps({k: record[k] for k in ('status', 'binary', 'bytes', 'sha256', 'cdhash')}, indent=1))


if __name__ == '__main__':
    main()
