#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install AdrenoMetal bundle files from the guest's own console shell.

docs/ADRENO-DEPTH-STENCIL-20261017.md (deployment); the tool and its checks: docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md
(Deployment). The guest writes its own Data volume, as every installed run does (--ans-writable); the host only types
into the console (tools/guest-console.py's protocol, one owner for the whole sequence). Since 2026-10-19
(docs/USERSPACE-GRAPHICS-20261019.md, compute runtime) a set of bundle files changes together: the executable, the
compiler runtime (a bsdiff of the 70 MB dylib, 632 KB to 1 MB, tools/bsdiff.c) and CodeResources (sent whole). Every new
Mach-O's CDHash is in the attempt's trust cache beside the old ones.

    python3 tools/deploy-guest-plugin.py --device udp://en6 --launch-record build/PREFIX-early-stop-launch.json \\
        --record SCRATCH/deploy.json [--continue-boot] [--restore]

Steps; every one is recorded, and any mismatch stops before the next write:
  1. a shell answers on the console (retried: in single-user mode launchd starts it early)
  2. the Data volume is mounted, by the single-user banner's steps when it is not
  3. each installed file is its base or already the new one; anything else refuses before any write; all new: 8
  4. for each file still at its base, its patch (or the whole file) is typed as base64 in short printf commands, one
     numbered file per chunk, each command acknowledged; one listing of every chunk's SHA-256 finds any chunk not held
     intact, which is resent (up to ROUNDS rounds); the joined text and the decoded bytes must match their SHA-256
  5. bspatch makes each new file beside /var/tmp; its SHA-256 must be the new one
  6. each installed file is copied to /var/db/Snapintosh/backup (SHA-256 checked), once
  7. install, the executable last: each copied into place under a temporary name with the installed file's owner and
     mode, then renamed over it; every installed SHA-256 (and each Mach-O's CDHash) must be the new one
  8. sync; with --continue-boot, `exit` (single-user mode continues to multi-user)
--restore puts each file's backup back where it differs from its base (steps 1-2, the backups' SHA-256, copy, rename).
--guest-root and --no-mount exist for the offline test (tools/test-deploy-guest-plugin.py).
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
# 2026-10-19 compute runtime set (docs/USERSPACE-GRAPHICS-20261019.md): v78 installed executable 7d3c8333 over the
# dockicons binary; the runtime dylib 2aca7392 and CodeResources a8f894d4 are unchanged since 2026-09-28 (metal-stage).
# Earlier sets stay in build/current-assets (metal-stage-graphics-20261019, -dockicons-20261017, ...) and every
# earlier CDHash stays trusted, so --restore (or an older set) still boots.
# v81 set (CoreImage compute shapes, lines): only the executable changes, over v79's 35e359e6; the runtime and
# CodeResources are v79's, already installed (their rows are skipped as new).
# v84 set (aligned IOSurface shadows, CoreImage fill): only the executable changed, over v81's 7660b284.
# v86 set (RenderBox icons): runtime v3 (air2ir3 pointer phis), its CodeResources and the executable, each over
# what v84 installed (runtime 9f33052e and CodeResources b48dd5ff from the compute set, executable bcd73081).
COMPUTE = ROOT / 'build/current-assets/metal-stage-compute-20261019'
CI = ROOT / 'build/current-assets/metal-stage-ci-20261019'
# v88 set (RenderBox custom effects): runtime v4, its CodeResources and the resealed executable over v86's icons set.
SHADOW = ROOT / 'build/current-assets/metal-stage-shadow-20261019'
ICONS = ROOT / 'build/current-assets/metal-stage-icons-20261019'
ASSETS = ROOT / 'build/current-assets/metal-stage-effects-20261019'
# Liquid Glass / corners set (docs/USERSPACE-GRAPHICS-20261019.md, "CoreAnimation's generic fallback"): only the
# executable changes, over the effects set's 00632e9d; the runtime and CodeResources are the effects set's, already
# installed (their rows are skipped as new).
GLASS = ROOT / 'build/current-assets/metal-stage-glass-20261019'
# 16-bit derivatives set (docs/USERSPACE-GRAPHICS-20261019.md, "Fix: derivatives of 16-bit values at 32 bits"): runtime
# v5 over the effects set's v4, its CodeResources, and the executable resealed for it over the glass set's b3c554ee.
DERIV = ROOT / 'build/current-assets/metal-stage-deriv-20261019'
# Mip levels set (docs/USERSPACE-GRAPHICS-20261019.md, "Fix: mip levels the GPU can sample"): only the executable
# changes, over the deriv set's 5624188c; runtime v5 and its CodeResources are the deriv set's, already installed.
MIPLEVELS = ROOT / 'build/current-assets/metal-stage-miplevels-20261019'
# Framebuffer fetch set (docs/USERSPACE-GRAPHICS-20261019.md, "Window corner wedges"): only the executable changes, over
# the mip levels set's 4a4fc437 (isFramebufferReadSupported YES); runtime v5 and its CodeResources stay installed.
FBFETCH = ROOT / 'build/current-assets/metal-stage-fbfetch-20261019'
# Compile speed set (docs/USERSPACE-GRAPHICS-20261019.md, "Speed: shader compile time"): runtime v6 over the deriv set's
# v5 (identical code, faster compiles), its CodeResources, and the framebuffer-fetch executable resealed for it.
COMPILESPEED = ROOT / 'build/current-assets/metal-stage-compilespeed-20261019'
# Speed batch (docs/USERSPACE-GRAPHICS-20261019.md, "Speed batch"): only the executable changes, over the compile
# speed set's d13c7a7b (the display copy cost in the stats line); runtime v6 and CodeResources stay installed.
PACING = ROOT / 'build/current-assets/metal-stage-pacing-20261019'
# UBO staging set (docs/USERSPACE-GRAPHICS-20261019.md, "Speed: CoreAnimation uniforms staged by the kilobyte"): only
# the executable changes, over the pacing set's 05439b9a; runtime v6 and CodeResources stay installed.
UBO = ROOT / 'build/current-assets/metal-stage-ubo-20261019'
# Drag speed set (docs/PLUGIN-DRAG-SPEED-20261020.md: per-program draw plans, staging arena pool, single-copy packages):
# only the executable changes, over the UBO set's 3365e015; runtime v6 and CodeResources stay installed.
DRAGSPEED = ROOT / 'build/current-assets/metal-stage-dragspeed-20261020'
# WindowServer abort set (docs/WINDOWSERVER-APL-ABORT-20261020.md): runtime v7 over the compile speed set's v6 (AIR 2.2
# texture reads, every call operand bounds-checked), its CodeResources, and the executable (CoreAnimation's APL filter
# off) resealed for it over the drag speed set's 1df76024.
WSABORT = ROOT / 'build/current-assets/metal-stage-wsabort-20261020'
# Arena trim set (docs/PLUGIN-ARENA-TRIM-20261021.md: UBO staging arenas that give back GPU address space): only the
# executable changes, over the WindowServer abort set's 52ed694b; runtime v7 and its CodeResources stay installed.
ARENATRIM = ROOT / 'build/current-assets/metal-stage-arenatrim-20261021'
# Combined set (agents/present-sync + agents/gfx-correctness + agents/turnip-audit: commitAndWaitUntilSubmitted waits for
# the kernel submission, GPU mipmap generation, integer render targets and textures, BR-thread blit/compute passes,
# render passes split across packages): only the executable changes, over the arena trim set's 496e79db; runtime v7 and
# its CodeResources stay installed.
COMBINED = ROOT / 'build/current-assets/metal-stage-combined-20261021'
# gpu-perf set (agents/gpu-perf: unaligned constant buffers read from a per-command-buffer mirror copied once before the
# first pass that needs it, instead of a CP_MEMCPY with CCU/UCHE flushes and two WFIs inside the pass per binding; GPU
# work counters in the diagnostics stats line): only the executable changes, over the combined set's 043dbf2d; runtime
# v7 and its CodeResources stay installed.
GPUPERF = ROOT / 'build/current-assets/metal-stage-gpuperf-20261021'
# Pipeline set (agents/gpu-pipeline: gpu-perf's source plus gpu-pipeline-plugin.patch built with -DADRENO_PIPELINE=1;
# IOSurface shadows wait for the command buffers using them on the GPU): only the executable changes, over gpu-perf's
# 9cd9a4c6; runtime v7 and its CodeResources stay installed.
PIPELINE = ROOT / 'build/current-assets/metal-stage-pipeline-20261021'
# Pipeline2 set (agents/gpu-pipeline: the pipeline source plus gpu-perf's blit-chunk-over-gpuperf.patch, buffer copies
# as CP_MEMCPYs of at most 1 MiB): only the executable changes, over gpu-perf's 9cd9a4c6 (what the guest runs);
# runtime v7 and its CodeResources stay installed.
PIPELINE2 = ROOT / 'build/current-assets/metal-stage-pipeline2-20261021'
# Mirror-slab set (agents/gpu-perf FAILURE-MODES.md R: UBO mirror regions from a few 1 MiB slabs allocated once per device
# and never released, instead of staging arenas that the pool frees after 300 ms idle and the next frame allocates
# again; b12v16's SPTM UPDATE_DISJOINT_MULTIPAGE x13): only the executable changes, over pipeline2's 8f712c36; runtime v7
# and its CodeResources stay installed.
MIRRORSLAB = ROOT / 'build/current-assets/metal-stage-mirrorslab-20261021'
# Settings-icons set (SnapMetal ADRENO_SETTINGS_ICONS, built with ADRENO_LENIENT=1 ADRENO_PIPELINE=1 and runtime v7:
# CoreImage compute kernels that sample sRGB and grey+alpha images, iconservicesagent's icns, device and document icons
# inside System Settings panes; multi-input kernels only when the kext publishes AdrenoIBComputeSamplers): only the
# executable changes, over the mirror-slab 758535d9; runtime v7 and its CodeResources stay installed.
SETTINGSICONS = ROOT / 'build/current-assets/metal-stage-settingsicons-20261024'
# Iconfix set (SnapMetal icon-pixels-next: ADRENO_SETTINGS_ICONS plus ADRENO_CS_TABLES, built with ADRENO_LENIENT=1
# ADRENO_PIPELINE=1 and runtime v7: CoreImage's compute kernels get Mesa's SP_CS_CONFIG texture/sampler/UAV counts):
# only the executable changes, over the settings-icons 378ff525; runtime v7 and its CodeResources stay installed.
ICONFIX = ROOT / 'build/current-assets/metal-stage-iconfix-20261024'
PREVIOUS = ASSETS
ORIGINAL = ROOT / 'build/current-assets/metal-stage/AdrenoMetal.bundle/Contents'
CONTENTS = 'System/Volumes/Data/Library/GPUBundles/AdrenoMetal.bundle/Contents'
FILES = [   # installed in this order: the executable last
    dict(name='libAdrenoCompiler.dylib', path=f'{CONTENTS}/Frameworks/libAdrenoCompiler.dylib',
         base=COMPILESPEED / 'libAdrenoCompiler.dylib', new=WSABORT / 'libAdrenoCompiler.dylib',
         patch=WSABORT / 'libAdrenoCompiler-059fcc6e.bsdiff', cdhash='ab4ccbd4806696e30cbe8ca6f8ff271e89cea7cd'),
    dict(name='CodeResources', path=f'{CONTENTS}/_CodeSignature/CodeResources',
         base=COMPILESPEED / 'CodeResources', new=WSABORT / 'CodeResources', patch=None, cdhash=None),
    dict(name='AdrenoMetal', path=f'{CONTENTS}/MacOS/AdrenoMetal', base=SETTINGSICONS / 'AdrenoMetal',
         new=ICONFIX / 'AdrenoMetal', patch=ICONFIX / 'AdrenoMetal-378ff525.bsdiff',
         cdhash='11d5ff9ae3c796ef3ac5c9fec5853e0f8deaec7b'),
]
PLUGIN, BASE, NEW, NEW_CDHASH = FILES[-1]['path'], FILES[-1]['base'], FILES[-1]['new'], FILES[-1]['cdhash']
WORK = 'System/Volumes/Data/private/var/tmp/snapintosh-plugin'
BACKUP = 'System/Volumes/Data/private/var/db/Snapintosh/backup'
MOUNT = '/sbin/mount -P 1; /usr/libexec/init_data_protection; /sbin/mount -P 2'
CHUNK = 512                    # base64 characters per command: the whole line stays far below MAX_CANON (1024)
ROUNDS = 3                     # resend rounds for chunks the guest does not hold intact
sha = lambda data: hashlib.sha256(data).hexdigest()

spec = importlib.util.spec_from_file_location('guest_console', ROOT / 'tools/guest-console.py')
assert spec and spec.loader
gc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gc)


class Refused(Exception):
    pass


class Shell:
    def __init__(self, args):
        session = gc.session_of(argparse.Namespace(session=args.session, launch_record=args.launch_record))
        self.link = gc.Link(device=args.device, target=args.target)
        self.console = gc.Console(self.link, session, int(args.owner, 16), False, args.wait_ms / 1000, None, None)
        self.poll_s, self.steps = args.poll_ms / 1000, []

    def run(self, step, command, timeout=60, ok=(0,)):
        started = time.monotonic()
        result = gc.run_command(self.console, command, timeout, self.poll_s, False)
        row: dict = dict(step=step, command=command if len(command) < 300 else command[:120] + '...',
                         seconds=round(time.monotonic() - started, 3))
        if result is None:
            row.update(status=None, error=(self.console.error or {}).get('status_text', 'no end marker'))
            self.steps.append(row)
            raise Refused(f'{step}: no answer ({row["error"]})')
        status, text = result
        row.update(status=status, output=text.decode('utf-8', 'replace')[-2000:])
        if step != 'chunk':
            self.steps.append(row)
        if status not in ok:
            raise Refused(f'{step}: exit status {status}: {row["output"][-300:]}')
        return text.decode('utf-8', 'replace')

    def digest(self, step, path):
        text = self.run(step, f'shasum -a 256 {shlex.quote(path)}')
        words = [line.split()[0] for line in text.splitlines() if line.strip().endswith(path)]
        if len(words) != 1:
            raise Refused(f'{step}: no digest for {path}: {text[-300:]}')
        return words[0]

    def type_exit(self):
        self.console.type(b'exit\r')
        deadline = time.monotonic() + 5
        while self.console.pending and time.monotonic() < deadline:
            self.console.exchange()


def wait_for_shell(shell, attempts, timeout):
    for n in range(attempts):
        try:
            if 'snapintosh-ready' in shell.run('shell', 'echo snapintosh-ready', timeout=timeout):
                return n + 1
        except Refused:
            if shell.console.error:
                raise
    raise Refused(f'no shell answered in {attempts} attempts')


def mount_data(shell, args):
    if args.no_mount:
        return 'skipped (--no-mount)'
    mounted = shell.run('data-check', "/sbin/mount | grep -c ' on /System/Volumes/Data ' || true")
    if mounted.strip().splitlines()[-1:] == ['0']:
        shell.run('data-mount', MOUNT, timeout=180)
        mounted = shell.run('data-check', "/sbin/mount | grep -c ' on /System/Volumes/Data ' || true")
    if mounted.strip().splitlines()[-1:] != ['1']:
        raise Refused(f'the Data volume is not mounted: {mounted[-200:]}')
    return 'mounted'


def transfer(shell, args, work, f):
    """One file's payload, typed as base64 chunks, joined, decoded and (for a patch) applied: work/NAME.new."""
    d = f'{work}/{f["name"]}'
    text = f['text']
    shell.run('work', f'mkdir -p {shlex.quote(d)}/chunks')
    chunks = {f'c.{n:05d}': text[at:at + CHUNK] for n, at in enumerate(range(0, len(text), CHUNK))}
    todo, rounds, started = list(chunks), [], time.monotonic()
    for round_ in range(ROUNDS):
        for name in todo:
            if round_ == 0 and f'{f["name"]}/{name}' in args.test_skip_chunk:
                continue                                  # the offline test's stand-in for a lost chunk
            shell.run('chunk', f"printf '%s' '{chunks[name]}' > {shlex.quote(d)}/chunks/{name}", timeout=30)
        # Listings of at most 50 chunks (about 3.7 KB each): one listing of 1,646 (122 KB) outran the console's
        # ring and lost lines on the stand-in although every chunk was intact.
        held = {}
        for group in sorted({(name[:5], name[5] < '5') for name in todo}):
            pattern = f'{group[0]}[{"0-4" if group[1] else "5-9"}]?'
            listing = shell.run('chunk-list', f'cd {shlex.quote(d)}/chunks && shasum -a 256 {pattern} 2>/dev/null',
                                timeout=60, ok=(0, 1))
            held.update({words[1]: words[0] for words in (line.split() for line in listing.splitlines())
                         if len(words) == 2 and words[1] in chunks})
        todo = [name for name in todo if held.get(name) != sha(chunks[name].encode())]
        rounds.append(dict(resend=len(todo), names=todo[:20]))
        if not todo:
            break
    if todo:
        raise Refused(f'{f["name"]}: {len(todo)} chunks still not intact after {ROUNDS} rounds: {todo[:10]}')
    shell.run('join', f'cd {shlex.quote(d)}/chunks && cat c.* > {shlex.quote(d)}/payload.b64', timeout=120)
    if shell.digest('base64', f'{d}/payload.b64') != sha(text.encode()):
        raise Refused(f'{f["name"]}: the typed base64 differs')
    shell.run('decode', f'base64 -D -i {shlex.quote(d)}/payload.b64 -o {shlex.quote(d)}/payload')
    if shell.digest('payload', f'{d}/payload') != f['payload_sha256']:
        raise Refused(f'{f["name"]}: the decoded payload differs')
    if f['patch']:
        shell.run('bspatch', f'bspatch {shlex.quote(f["path"])} {shlex.quote(work)}/{f["name"]}.new {shlex.quote(d)}/payload',
                  timeout=600)
    else:
        shell.run('copy', f'cp {shlex.quote(d)}/payload {shlex.quote(work)}/{f["name"]}.new')
    if shell.digest('candidate', f'{work}/{f["name"]}.new') != f['new_sha256']:
        raise Refused(f'{f["name"]}: the new file differs')
    return dict(name=f['name'], chunks=len(chunks), rounds=rounds, seconds=round(time.monotonic() - started, 1))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument('--device')
    where.add_argument('--target', help='host:port of a stand-in (the offline test)')
    ap.add_argument('--launch-record')
    ap.add_argument('--session')
    ap.add_argument('--record', type=Path, required=True)
    ap.add_argument('--owner', default='5eedc0de51', help='hex console owner, fixed for the whole sequence')
    ap.add_argument('--continue-boot', action='store_true', help='type exit after the install (single-user mode)')
    ap.add_argument('--restore', action='store_true', help='put the backed-up binary back')
    ap.add_argument('--guest-root', default='/', help='prefix of every guest path (the offline test)')
    ap.add_argument('--no-mount', action='store_true', help='skip the Data volume step (the offline test)')
    ap.add_argument('--attempts', type=int, default=30)
    ap.add_argument('--poll-ms', type=int, default=50)
    ap.add_argument('--wait-ms', type=int, default=150)
    ap.add_argument('--test-skip-chunk', action='append', default=[], help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.record.exists():
        print(f'{args.record} exists', file=sys.stderr)
        return 64
    root = args.guest_root.rstrip('/') + '/'
    work, backup = root + WORK, root + BACKUP
    files = []
    for f in FILES:
        base, new = f['base'].read_bytes(), f['new'].read_bytes()
        payload = f['patch'].read_bytes() if f['patch'] else new
        files.append(dict(name=f['name'], path=root + f['path'], base_sha256=sha(base), new_sha256=sha(new),
                          payload_sha256=sha(payload), payload_bytes=len(payload), patch=bool(f['patch']),
                          text=base64.b64encode(payload).decode(), cdhash=f['cdhash'],
                          backup=f'{backup}/{f["name"]}-{sha(base)[:8]}'))
    exe = files[-1]
    record: dict = dict(schema='snapintosh-deploy-guest-plugin-v2', started=time.time(), restore=args.restore,
                        base_sha256=exe['base_sha256'], new_sha256=exe['new_sha256'], new_cdhash=exe['cdhash'],
                        plugin=exe['path'], backup=exe['backup'], status='RUNNING',
                        files=[{k: v for k, v in f.items() if k != 'text'} for f in files])
    shell = Shell(args)
    try:
        record['shell_attempts'] = wait_for_shell(shell, args.attempts, 20)
        record['data'] = mount_data(shell, args)
        for f, row in zip(files, record['files']):
            f['installed'] = row['installed_before'] = shell.digest('installed', f['path'])
        record['installed_before'] = exe['installed']
        if args.restore:
            for f in files:
                if f['installed'] == f['base_sha256']:
                    continue
                if shell.digest('backup', f['backup']) != f['base_sha256']:
                    raise Refused(f'the backup of {f["name"]} is not its base')
                shell.run('restore', f'cp -p {shlex.quote(f["backup"])} {shlex.quote(f["path"])}.restore && '
                                     f'mv -f {shlex.quote(f["path"])}.restore {shlex.quote(f["path"])}')
        else:
            other = [f['name'] for f in files if f['installed'] not in (f['base_sha256'], f['new_sha256'])]
            if other:
                raise Refused(f'installed {", ".join(other)} neither the base nor the new one; nothing written')
            todo = [f for f in files if f['installed'] == f['base_sha256']]
            record['already_installed'] = not todo
            if todo:
                shell.run('work', f'rm -rf {shlex.quote(work)} && mkdir -p {shlex.quote(work)}')
            started, record['transfers'] = time.monotonic(), []
            for f in todo:
                record['transfers'].append(transfer(shell, args, work, f))
            record['transfer_seconds'] = round(time.monotonic() - started, 1)
            record['chunks'] = sum(t['chunks'] for t in record['transfers'])
            record['rounds'] = record['transfers'][-1]['rounds'] if record['transfers'] else []
            for f in todo:
                shell.run('backup', f'mkdir -p {shlex.quote(backup)} && (test -e {shlex.quote(f["backup"])} || '
                                    f'cp -p {shlex.quote(f["path"])} {shlex.quote(f["backup"])})')
                if shell.digest('backup', f['backup']) != f['base_sha256']:
                    raise Refused(f'the backup of {f["name"]} is not its base')
            for f in todo:
                owner_mode = shell.run('stat', f"stat -f '%u:%g %Lp' {shlex.quote(f['path'])}").split()
                if len(owner_mode) < 2:
                    raise Refused(f'no owner and mode for {f["path"]}')
                f['owner_mode'] = owner_mode[-2:]
            record['owner_mode'] = exe.get('owner_mode')
            for f in todo:
                user_group, mode = f['owner_mode']
                temp = f'{f["path"]}.snapintosh-new'
                shell.run('install', f'cp {shlex.quote(work)}/{f["name"]}.new {shlex.quote(temp)} && '
                                     f'chown {user_group} {shlex.quote(temp)} && chmod {mode} {shlex.quote(temp)} && '
                                     f'mv -f {shlex.quote(temp)} {shlex.quote(f["path"])}')
        for f, row in zip(files, record['files']):
            row['installed_after'] = shell.digest('installed', f['path'])
            want = f['base_sha256'] if args.restore else f['new_sha256']
            if row['installed_after'] != want:
                raise Refused(f'installed {f["name"]} is {row["installed_after"]}, expected {want}')
            if not args.restore and f['cdhash']:
                cd = shell.run('cdhash', f"codesign -dvvv {shlex.quote(f['path'])} 2>&1 | grep '^CDHash='")
                row['installed_cdhash'] = cd.strip().splitlines()[-1].split('=', 1)[-1] if cd.strip() else None
                if row['installed_cdhash'] != f['cdhash']:
                    raise Refused(f'installed {f["name"]} CDHash {row["installed_cdhash"]}, expected {f["cdhash"]}')
        record['installed_after'] = record['files'][-1]['installed_after']
        record['installed_cdhash'] = record['files'][-1].get('installed_cdhash')
        shell.run('sync', 'sync')
        record['status'] = 'RESTORED' if args.restore else 'INSTALLED'
        if args.continue_boot:
            shell.type_exit()
            record['continued_boot'] = True
        return 0
    except Refused as error:
        record['status'] = 'REFUSED'
        record['error'] = str(error)
        return 1
    finally:
        record['steps'] = shell.steps
        record['console'] = shell.console.record() if hasattr(shell.console, 'record') else None
        record['finished'] = time.time()
        args.record.write_text(json.dumps(record, indent=2, sort_keys=True))
        print(json.dumps(dict(status=record['status'], error=record.get('error'), record=str(args.record),
                              installed_after=record.get('installed_after'),
                              transfer_seconds=record.get('transfer_seconds'))))


if __name__ == '__main__':
    sys.exit(main())
