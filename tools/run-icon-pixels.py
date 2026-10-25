#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run icon-pixels in the A16 guest from its root console shell, fetch its lines and compare them with this Mac's.

During a --console desktop boot, once the multi-user root shell answers, as the only console client (pass the run's
--owner). Writes nothing outside the guest's /private/var/tmp/icon-pixels (and, with --move-icon-caches, renames the
icon caches aside). Every console command's output stays under about 4 KB.

    python3 tools/run-icon-pixels.py --device udp://enN --launch-record build/PREFIX-early-stop-launch.json \\
        --owner HEX --tool build/icon-pixels/TOOL/icon-pixels --output NEW-DIR \\
        [--reference-synth REF.txt] [--reference-icons REF.txt] [--steps push,version,synth,icons,diag] \\
        [--move-icon-caches TAG] [--ab-env VAR=VALUE] [--synth-timeout 1200]

Steps (--steps picks and orders them; each is recorded in OUTPUT/run.json):
  push     the tool as base64 in 512-character printf chunks (tools/deploy-guest-plugin.py's transfer: one numbered file
           per chunk, a SHA-256 listing finds chunks not held intact and resends them), joined, decoded, its SHA-256
           checked, then installed as /private/var/tmp/icon-pixels/icon-pixels (mode 755)
  version  `icon-pixels version`: the binary executes (an ad-hoc arm64e executable; if the guest's AMFI kills it, the
           step stops and names the trust-cache row build-icon-pixels.py recorded) and finds the plug-in device
  synth    `icon-pixels synth --repeat 2` as root: CoreImage kernels on synthetic inputs, on the plug-in device
  synth-ab the same with --ab-env VAR=VALUE in the tool's environment, into synth-ab.txt (a plug-in built with a
           per-process switch, such as ADRENO_CS_TABLES=0, then compares both encodings in one boot)
  icons    `icon-pixels icons --source gen` as root (IconServices' generator in-process, on the plug-in device), then,
           as the console user in that user's bootstrap context (launchctl asuser UID sudo -u #UID),
           `icon-pixels icons --source ws` (NSWorkspace, through iconservicesagent and its caches)
  recache  with --move-icon-caches TAG: rename the IconServices store, every user's com.apple.iconservices and
           com.apple.iconservicesagent caches and the Dock's com.apple.dock.iconcache to NAME.TAG (reversible: mv back),
           restart iconservicesd (launchctl kickstart -k), stop every iconservicesagent, the Dock and System Settings, so
           the next icons drawn are rendered again with the installed plug-in. Put it before `icons`
  diag     the plug-in's diagnostics: per-process files /private/var/tmp/adreno-*.log (counts, distinct drop/refusal
           reasons), and the unified log subsystem org.snapintosh.adreno for iconservicesagent and System Settings
Each output file is fetched 3 lines per command; every line carries a CRC, so console noise is dropped and a block that
came back short is fetched again (up to 4 times). Then tools/compare-icon-pixels.py against the references.
Offline (the console stand-in, tools/test-icon-pixels.py): --target 127.0.0.1:PORT --session HEX --guest-root DIR.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
REMOTE = '/private/var/tmp/icon-pixels'
BLOCK = 3
STEPS = 'push,version,synth,icons,diag'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid(line):
    body, sep, crc = line.strip().rpartition(' *')
    return bool(sep) and re.fullmatch(r'[0-9a-f]{8}', crc or '') is not None and \
        f'{zlib.crc32(body.encode()) & 0xffffffff:08x}' == crc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument('--device')
    where.add_argument('--target', help='host:port of the console stand-in (offline test)')
    ap.add_argument('--launch-record')
    ap.add_argument('--session')
    ap.add_argument('--owner', required=True, help='hex console owner of this run (one owner for every console step)')
    ap.add_argument('--tool', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--steps', default=STEPS)
    ap.add_argument('--reference-synth', type=Path)
    ap.add_argument('--reference-icons', type=Path)
    ap.add_argument('--move-icon-caches', metavar='TAG')
    ap.add_argument('--ab-env', metavar='VAR=VALUE', help='the environment of the synth-ab step')
    ap.add_argument('--synth-args', default='--repeat 2')
    ap.add_argument('--icons-args', default='--size 20 --scale 2')
    ap.add_argument('--synth-timeout', type=int, default=1200)
    ap.add_argument('--icons-timeout', type=int, default=600)
    ap.add_argument('--guest-root', default='/', help='prefix of every guest path (offline test)')
    ap.add_argument('--console-user', help='uid for the ws icons (default: the owner of /dev/console)')
    ap.add_argument('--poll-ms', type=int, default=50)
    ap.add_argument('--wait-ms', type=int, default=150)
    ap.add_argument('--attempts', type=int, default=30)
    a = ap.parse_args(argv)
    steps = [s for s in a.steps.split(',') if s]
    unknown = set(steps) - {'push', 'version', 'synth', 'synth-ab', 'icons', 'recache', 'diag'}
    if unknown or ('recache' in steps) != bool(a.move_icon_caches) or ('synth-ab' in steps) != bool(a.ab_env):
        ap.error(f'unknown steps {sorted(unknown)}, or recache without --move-icon-caches TAG, or synth-ab without '
                 '--ab-env VAR=VALUE (or the reverse)')
    if a.ab_env and not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}=[A-Za-z0-9._-]{0,64}', a.ab_env):
        ap.error('--ab-env is one VAR=VALUE (upper-case name; letters, digits, dot, dash, underscore)')
    # Offline the "guest" shell is this Mac's: never restart its processes, never ask its sudo for a password.
    if a.target and 'recache' in steps:
        ap.error('recache restarts the shell machine\'s icon services, Dock and System Settings: only with --device')
    if a.target and 'icons' in steps and a.console_user is None:
        ap.error('offline, pass --console-user (0 skips the NSWorkspace icons)')
    if a.move_icon_caches and not re.fullmatch(r'[A-Za-z0-9._-]{1,48}', a.move_icon_caches):
        ap.error('the cache tag is letters, digits, dot, dash and underscore')
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    deploy = load('deploy', ROOT / 'tools/deploy-guest-plugin.py')
    tool = a.tool.read_bytes()
    tool_sha = hashlib.sha256(tool).hexdigest()
    build = a.tool.resolve().parent / 'build.json'
    trust_row = json.loads(build.read_text()).get('trust_row') if build.is_file() else None
    args = argparse.Namespace(session=a.session, launch_record=a.launch_record, device=a.device, target=a.target,
                              owner=a.owner, wait_ms=a.wait_ms, poll_ms=a.poll_ms, test_skip_chunk=[])
    root = a.guest_root.rstrip('/')
    remote = root + REMOTE
    exe = f'{remote}/icon-pixels'
    rec = dict(schema='snapintosh-icon-pixels-run-v1', started=time.time(), tool=str(a.tool), tool_sha256=tool_sha,
               tool_bytes=len(tool), remote=remote, steps=steps, status='RUNNING')
    shell = deploy.Shell(args)

    def fetch(name, path):
        """The file's lines, BLOCK per command, checksummed; written to OUTPUT/NAME."""
        count = shell.run(f'{name}-lines', f"awk 'END{{print NR}}' {shlex.quote(path)}", ok=(0, 1))
        m = re.search(r'^(\d+)\s*$', count, re.M)
        lines = int(m.group(1)) if m else 0
        kept, refetched, t0 = [], 0, time.monotonic()
        for first in range(1, lines + 1, BLOCK):
            last = min(lines, first + BLOCK - 1)
            want = last - first + 1
            good = []
            for _ in range(5):
                text = shell.run('fetch', f"sed -n '{first},{last}p' {shlex.quote(path)}", timeout=60, ok=(0, 1))
                good = [l.strip() for l in text.splitlines() if valid(l)]
                if len(good) >= want:
                    break
                refetched += 1
            kept += good[:want]
        (out / name).write_text('\n'.join(kept) + ('\n' if kept else ''))
        rec[name] = dict(lines=lines, fetched=len(kept), refetched_blocks=refetched,
                         seconds=round(time.monotonic() - t0, 1))
        return kept

    def run_tool(name, command, timeout):
        t0 = time.monotonic()
        res = shell.run(name, f'cd {shlex.quote(remote)} && {command} > {name}.txt 2> {name}.err; echo rc=$?; '
                              f"awk 'END{{print NR}}' {name}.txt; tail -c 600 {name}.err", timeout=timeout, ok=(0, 1))
        m = re.search(r'rc=(\d+)\s+(\d+)', res)
        rec[f'{name}_rc'] = int(m.group(1)) if m else None
        rec[f'{name}_seconds'] = round(time.monotonic() - t0, 1)
        rec[f'{name}_stderr_tail'] = res[res.find('rc='):][-700:] if 'rc=' in res else res[-700:]
        return fetch(f'{name}.txt', f'{remote}/{name}.txt')

    try:
        rec['shell_attempts'] = deploy.wait_for_shell(shell, a.attempts, 20)
        for step in steps:
            if step == 'push':
                shell.run('work', f'mkdir -p {shlex.quote(remote)} && rm -rf {shlex.quote(remote)}/push')
                t0 = time.monotonic()
                f = dict(name='icon-pixels', text=base64.b64encode(tool).decode(), payload_sha256=tool_sha,
                         new_sha256=tool_sha, patch=False, path=None)
                rec['push'] = deploy.transfer(shell, args, f'{remote}/push', f)
                shell.run('install', f'cp {shlex.quote(remote)}/push/icon-pixels.new {shlex.quote(exe)}.new && '
                                     f'chmod 755 {shlex.quote(exe)}.new && mv -f {shlex.quote(exe)}.new {shlex.quote(exe)} && '
                                     f'rm -rf {shlex.quote(remote)}/push')
                if shell.digest('installed', exe) != tool_sha:
                    raise deploy.Refused('the installed tool differs from the one pushed')
                rec['push_seconds'] = round(time.monotonic() - t0, 1)
            elif step == 'version':
                res = shell.run('version', f'{shlex.quote(exe)} version 2>&1; echo rc=$?', timeout=120, ok=(0, 1))
                m = re.search(r'rc=(\d+)', res)
                rec['version_rc'] = int(m.group(1)) if m else None
                rec['version'] = [l.strip() for l in res.splitlines() if valid(l)]
                if rec['version_rc'] != 0 or not any(l.startswith('V ') for l in rec['version']):
                    hint = (f' If it was killed (rc 137, "Killed: 9"), the guest refuses the ad-hoc signature: add the row '
                            f'{json.dumps(trust_row)} to the next run\'s trust additions.' if trust_row else '')
                    raise deploy.Refused(f'icon-pixels does not run: {res[-300:]!r}.{hint}')
            elif step == 'synth':
                run_tool('synth', f'./icon-pixels synth {a.synth_args}', a.synth_timeout)
            elif step == 'synth-ab':
                run_tool('synth-ab', f'env {a.ab_env} ./icon-pixels synth {a.synth_args}', a.synth_timeout)
            elif step == 'icons':
                run_tool('icons-gen', f'./icon-pixels icons --source gen {a.icons_args}', a.icons_timeout)
                uid = a.console_user or shell.run('console-user', 'stat -f %u /dev/console').strip().splitlines()[-1]
                rec['console_user'] = uid
                if uid.isdigit() and uid != '0':
                    run_tool('icons-ws', f'launchctl asuser {uid} sudo -u "#{uid}" ./icon-pixels icons --source ws '
                                         f'{a.icons_args}', a.icons_timeout)
                else:
                    rec['icons_ws'] = f'skipped: /dev/console belongs to {uid!r} (no logged-in user)'
            elif step == 'recache':
                tag = a.move_icon_caches
                paths = (f'{root}/Library/Caches/com.apple.iconservices.store '
                         f'{root}/private/var/folders/*/*/C/com.apple.iconservices '
                         f'{root}/private/var/folders/*/*/C/com.apple.iconservicesagent '
                         f'{root}/private/var/folders/*/*/C/com.apple.dock.iconcache')
                rec['recache'] = shell.run('recache', (
                    f'for p in {paths}; do if [ -e "$p" ]; then mv "$p" "$p.{tag}" && echo "moved $p" || echo "FAILED $p"; '
                    f'fi; done; launchctl kickstart -k system/com.apple.iconservices.iconservicesd 2>&1 | tail -1; '
                    f'killall iconservicesagent Dock "System Settings" 2>&1 | tail -3; echo recache-done'),
                    timeout=120, ok=(0, 1))[-3000:]
            elif step == 'diag':
                rec['diag_files'] = shell.run('diag-files', (
                    f'ls {root}/private/var/tmp/ | grep -c "^adreno-.*\\.log$"; '
                    f'ls -t {root}/private/var/tmp/ | grep "^adreno-.*\\.log$" | head -12'), ok=(0, 1))[-1500:]
                rec['diag_reasons'] = shell.run('diag-reasons', (
                    f'cat {root}/private/var/tmp/adreno-*.log 2>/dev/null | grep -E "dropped:|refused:|zero texture" | '
                    f'sed -E "s/^.*(dropped:|refused:|zero texture:)/\\1/" | cut -c1-200 | sort | uniq -c | sort -rn | '
                    f'head -15'),
                    timeout=120, ok=(0, 1))[-3500:]
                rec['diag_unified'] = shell.run('diag-unified', (
                    'log show --last 60m --style compact --predicate \'subsystem == "org.snapintosh.adreno" AND '
                    '(process == "iconservicesagent" OR process == "System Settings")\' 2>/dev/null | '
                    'grep -E "dropped|refused|not built|zero texture|failed" | cut -c1-220 | tail -15'),
                    timeout=600, ok=(0, 1))[-3500:]
        rec['status'] = 'DONE'
    except deploy.Refused as error:
        rec['status'] = 'REFUSED'
        rec['error'] = str(error)
    finally:
        rec['commands'] = [s for s in shell.steps if s['step'] not in ('chunk', 'fetch')]
        rec['finished'] = time.time()
        (out / 'run.json').write_text(json.dumps(rec, indent=1) + '\n')
    compares = {}
    for name, ref, cases in (('synth.txt', a.reference_synth, '.'), ('synth-ab.txt', a.reference_synth, '.'),
                             ('icons-gen.txt', a.reference_icons, '^gen-'),
                             ('icons-ws.txt', a.reference_icons, '^ws-')):
        if ref and (out / name).is_file():
            r = subprocess.run([sys.executable, str(ROOT / 'tools/compare-icon-pixels.py'), str(ref), str(out / name),
                                '--cases', cases, '--json', str(out / f'{name}.compare.json')], capture_output=True, text=True)
            (out / f'{name}.compare.txt').write_text(r.stdout + r.stderr)
            compares[name] = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else f'exit {r.returncode}'
            print(r.stdout[-2500:])
    summary = {k: v for k, v in rec.items() if k not in ('commands', 'push')}
    summary['compare'] = compares
    print(json.dumps(summary, indent=1)[-4000:])
    return 0 if rec['status'] == 'DONE' else 1


if __name__ == '__main__':
    sys.exit(main())
