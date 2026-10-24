#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""icon-pixels offline: the tool on this Mac's GPU, the comparison's diagnoses, and the console procedure end to end.

    python3 tools/test-icon-pixels.py --output NEW-DIR [--bundle ADRENO-BUNDLE] [--skip-console] [--noise-rate 40]

1. tools/build-icon-pixels.py builds the tool; it runs `synth` on this Mac's GPU twice (deterministic: identical C
   lines) and against tools/icon-pixels-reference-synth.txt (the committed synthetic reference, made with --host-caps
   on the deployed plug-in): every case must PASS, or the reference is stale for this Mac's macOS/CoreImage.
2. With --bundle (an ADRENO_SETTINGS_ICONS plug-in bundle with its compiler runtime): `synth --plugin BUNDLE
   --cs-samplers 8` (the plug-in device, commits intercepted) must dispatch exactly the kernels and texture formats
   of the reference (compare --census-only PASS) with nothing dropped or refused; without the CS sampler stand-in the
   multi-input kernels must be dropped (the deployed-kext gate) and the comparison must say so.
3. Fault injection: guest outputs derived from the reference, each with one fault the comparison must name: red/blue
   swapped, an extra or a missing sRGB decode, transparent output, a zeroed channel, an unwritten and a partially
   written destination, differing readbacks, differing repeats, a missing or foreign input stripe (with its texture
   index), a broken blend band, an empty/black/partial/recoloured icon, console noise; and a perturbation within
   tolerance that must still PASS.
4. Unless --skip-console: tools/run-icon-pixels.py over the console stand-in (tools/test-console-link.py: q1n1's
   console handler, the monitor's console link, /bin/sh on a pty, request/reply loss and mid-line console noise)
   pushes the tool, runs `version`, a few synth cases (also with --ab-env), two generated icons and the diag step,
   fetches every line and compares them with a direct run of the same cases: identical C and K lines. (recache and
   the NSWorkspace icons act on the shell's own machine, so the runner refuses them offline.)
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'tools/icon-pixels-reference-synth.txt'
checks, failures = 0, []


def check(ok, what):
    global checks
    checks += 1
    if not ok:
        failures.append(what)
        print('FAIL', what)
    return ok


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seal(body):
    return f'{body} *{zlib.crc32(body.encode()) & 0xffffffff:08x}'


def body(line):
    return line.rpartition(' *')[0]


def kind_lines(text, kinds):
    return [l for l in text.splitlines() if l[:2] in kinds]


def edit(lines, case, fn, kind='C'):
    """A copy of lines with case's line rewritten by fn(fields dict in order) and resealed."""
    out = []
    for l in lines:
        b = body(l)
        words = b.split(' ')
        if len(words) > 2 and words[0] == kind and words[1] == case:
            head, fields = words[:3], {}
            order = []
            for w in words[3:]:
                k, _, v = w.partition('=')
                fields[k] = v
                order.append(k)
            fn(fields)
            l = seal(' '.join(head + [f'{k}={fields[k]}' for k in order if k in fields]))
        out.append(l)
    return out


def map_pixels(fields, fn, keys=('p', 'g', 't', 's')):
    """Apply fn([r,g,b,a]) -> [r,g,b,a] to every RRGGBBAA value in the sampled fields."""
    def one(h):
        v = fn([int(h[i:i + 2], 16) for i in (0, 2, 4, 6)])
        return ''.join(f'{max(0, min(255, int(round(x)))):02x}' for x in v)
    for k in keys:
        if k not in fields:
            continue
        if k == 't':
            t = fields['t']
            fields['t'] = ''.join(one(t[i:i + 8]) for i in range(0, len(t), 8))
        elif k == 's':
            top, _, band = fields['s'].partition('/')
            fields['s'] = ','.join(one(h) for h in top.split(',')) + '/' + ','.join(one(h) for h in band.split(','))
        else:
            fields[k] = ','.join(one(h) for h in fields[k].split(','))


def run_compare(cmp_, ref_lines, guest_lines, out, name, *extra):
    ref, guest = out / f'{name}.ref.txt', out / f'{name}.guest.txt'
    ref.write_text('\n'.join(ref_lines) + '\n')
    guest.write_text('\n'.join(guest_lines) + '\n')
    r = subprocess.run([sys.executable, str(ROOT / 'tools/compare-icon-pixels.py'), str(ref), str(guest), *extra],
                       capture_output=True, text=True)
    (out / f'{name}.compare.txt').write_text(r.stdout + r.stderr)
    verdicts = {}
    for l in r.stdout.splitlines():
        m = re.match(r'(PASS|FAIL) (\S+?)(?:: (.*))?$', l)
        if m and m.group(2) not in ('of',):
            verdicts[m.group(2)] = (m.group(1), m.group(3) or '')
    return r.returncode, verdicts, r.stdout


def fault_injection(out, ref_lines, icon_lines):
    cmp_ = None
    lines = ref_lines + icon_lines
    rc, v, text = run_compare(cmp_, lines, lines, out, 'identical')
    check(rc == 0 and all(x[0] == 'PASS' for x in v.values()), f'identical output must pass: {text[-300:]}')

    def expect(name, guest, case, verdict_prefix, contains=None):
        rc, v, text = run_compare(cmp_, lines, guest, out, name)
        got = v.get(case, ('MISSING', ''))
        ok = got[0] == 'FAIL' and got[1].startswith(verdict_prefix) and (contains is None or contains in got[1])
        check(ok and rc == 1, f'{name}: {case} must FAIL with {verdict_prefix}{" ... " + contains if contains else ""}; '
                              f'got {got} rc {rc}')
        others = [c for c, x in v.items() if c != case and x[0] == 'FAIL']
        check(not others, f'{name}: only {case} may fail; also {others[:5]}')

    from_srgb = lambda c: 255 * ((c / 255) / 12.92 if c / 255 <= 0.04045 else ((c / 255 + 0.055) / 1.055) ** 2.4)
    to_srgb = lambda c: 255 * ((c / 255) * 12.92 if c / 255 <= 0.0031308 else 1.055 * (c / 255) ** (1 / 2.4) - 0.055)
    expect('swap', edit(lines, 'tex-rgba8-lin', lambda f: map_pixels(f, lambda p: [p[2], p[1], p[0], p[3]])),
           'tex-rgba8-lin', 'SWAP-RB')
    expect('srgb-extra', edit(lines, 'tex-rgba8-lin', lambda f: map_pixels(f, lambda p: [from_srgb(p[0]), from_srgb(p[1]),
                                                                                          from_srgb(p[2]), p[3]])),
           'tex-rgba8-lin', 'SRGB-EXTRA')
    expect('srgb-missing', edit(lines, 'tex-rgba8s-lin', lambda f: map_pixels(f, lambda p: [to_srgb(p[0]), to_srgb(p[1]),
                                                                                             to_srgb(p[2]), p[3]])),
           'tex-rgba8s-lin', 'SRGB-MISSING')
    expect('transparent', edit(lines, 'tex-bgra8-near', lambda f: map_pixels(f, lambda p: [0, 0, 0, 0])),
           'tex-bgra8-near', 'TRANSPARENT')
    expect('green-zero', edit(lines, 'tex-rg8-lin', lambda f: map_pixels(f, lambda p: [p[0], 0, p[2], p[3]])),
           'tex-rg8-lin', 'CHANNEL', 'G reads 0')
    expect('unwritten', edit(lines, 'tex-rg16f-lin', lambda f: f.update(sent='16384')), 'tex-rg16f-lin', 'UNWRITTEN')
    expect('partial', edit(lines, 'tex-r8-lin', lambda f: f.update(sent='512')), 'tex-r8-lin', 'PARTIAL')
    expect('readback', edit(lines, 'tex-a8-lin', lambda f: f.update(hb='0123456789abcdef')), 'tex-a8-lin', 'READBACK')
    expect('repeats', edit(lines, 'fill', lambda f: f.update(h=f['h'].split(',')[0] + ',0123456789abcdef')),
           'fill', 'NONDETERMINISTIC')

    def stripe(k, fn):
        def apply(f):
            top, _, band = f['s'].partition('/')
            t = top.split(',')
            t[k] = fn(t)
            f['s'] = ','.join(t) + '/' + band
        return apply
    expect('input-missing', edit(lines, 'multi-4', stripe(2, lambda t: '00000000')), 'multi-4', 'INPUT-2', 'texture(2)')
    expect('input-foreign', edit(lines, 'multi-6', stripe(5, lambda t: t[1])), 'multi-6', 'INPUT-5', "input 1's colour")

    def band(f):
        top, _, b = f['s'].partition('/')
        f['s'] = top + '/' + ','.join('10203040' for _ in b.split(','))
    expect('blend', edit(lines, 'mixed-3', band), 'mixed-3', 'BLEND')
    expect('missing-case', [l for l in lines if not body(l).startswith('C cg-ga8 ')], 'cg-ga8', 'MISSING')
    expect('error', edit(lines, 'cg-ga16f', lambda f: f.update(st='exception')), 'cg-ga16f', 'ERROR')
    # Perturbation within tolerance (+-3 on every channel, alternating) must still pass.
    flip = [1]

    def jitter(p):
        flip[0] = -flip[0]
        return [x + 3 * flip[0] for x in p]
    rc, v, text = run_compare(cmp_, lines, edit(lines, 'tex-rgba16f-lin', lambda f: map_pixels(f, jitter)), out, 'jitter')
    check(v.get('tex-rgba16f-lin', ('?',))[0] == 'PASS', f'jitter within tolerance must pass: {v.get("tex-rgba16f-lin")}')
    # Console noise and a torn line are dropped (counted), the rest still compares.
    noisy = []
    for i, l in enumerate(lines):
        noisy.append(l)
        if i % 5 == 0:
            noisy.append('AdrenoDisplay: perf pace s=1 pps=59.8 late=0 gpu=1/4357')
    torn = [l if not body(l).startswith('C fill ') else l[:-3] for l in noisy]
    rc, v, text = run_compare(cmp_, lines, torn, out, 'noise')
    check(v.get('fill', ('?',))[0] == 'FAIL' and 'MISSING' in v.get('fill', ('', ''))[1] and
          sum(1 for x in v.values() if x[0] == 'FAIL') == 1 and 'noise dropped' in text,
          f'noise: only the torn fill line is lost: {[c for c, x in v.items() if x[0] == "FAIL"]}')
    if icon_lines:
        icon = next(body(l).split(' ')[1] for l in icon_lines if body(l).startswith('I gen-folder '))
        expect('icon-empty', edit(lines, icon, lambda f: f.update(cov='0', rgb='000000', a='00', ag='0' * 64, lg='8' * 64),
                                  kind='I'), icon, 'EMPTY')
        expect('icon-black', edit(lines, icon, lambda f: f.update(rgb='020202'), kind='I'), icon, 'BLACK')
        expect('icon-partial', edit(lines, icon, lambda f: f.update(ag='0' * 32 + f['ag'][32:]), kind='I'), icon, 'PARTIAL')
        expect('icon-colour', edit(lines, icon, lambda f: f.update(rgb=f['rgb'][4:6] + f['rgb'][2:4] + f['rgb'][0:2]),
                                   kind='I'), icon, 'WRONG-COLOUR')


def console_end_to_end(out, tool, noise_rate):
    cl = load('consolelink', ROOT / 'tools/test-console-link.py')
    binary = cl.build(out)
    cases = 'tex-rgba8s-lin|tex-rg8-near|multi-3|fill'
    direct = subprocess.run([str(tool), 'synth', '--repeat', '1', '--cases', cases], capture_output=True, text=True,
                            timeout=600)
    (out / 'console-direct.txt').write_text(direct.stdout)
    noise = out / 'noise.txt'
    noise.write_text(''.join(f'AdrenoDisplay: perf pace s={i} pps=59.8 late=0 gpu=1/4357\n' for i in range(200)))
    guest = out / 'guest'
    (guest / 'private/var/tmp').mkdir(parents=True)
    h = cl.Harness(binary, out, 'console', '--duration', 1500, '--shell', "PS1='sh-3.2# ' exec /bin/sh -i",
                   '--loss', 0.03, '--reply-loss', 0.03, '--seed', 47, '--poll-ms', 20,
                   '--noise', noise, '--noise-rate', noise_rate)
    try:
        r = subprocess.run([sys.executable, str(ROOT / 'tools/run-icon-pixels.py'), '--target', f'127.0.0.1:{h.port}',
                            '--session', f'{cl.SESSION:x}', '--owner', '5eedc0de51', '--guest-root', str(guest),
                            '--tool', str(tool), '--output', str(out / 'console-run'),
                            '--steps', 'push,version,synth,synth-ab,icons,diag', '--console-user', '0',
                            '--ab-env', 'ADRENO_CS_TABLES=0',
                            '--synth-args', f"--repeat 1 --cases '{cases}'",
                            '--icons-args', "--cases 'gen-(home|folder)'", '--poll-ms', '20', '--wait-ms', '60',
                            '--attempts', '5'],
                           capture_output=True, text=True, timeout=1500, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        (out / 'console-run.log').write_text(r.stdout + r.stderr)
    finally:
        h.process.terminate()
        h.process.wait(timeout=30)
    check(r.returncode == 0, f'run-icon-pixels exit {r.returncode}: {r.stdout[-300:]} {r.stderr[-300:]}')
    rec = json.loads((out / 'console-run/run.json').read_text()) if (out / 'console-run/run.json').is_file() else {}
    check(rec.get('status') == 'DONE' and rec.get('synth_rc') == 0 and rec.get('version_rc') == 0,
          f'console run: status {rec.get("status")} {rec.get("error")} synth rc {rec.get("synth_rc")}')
    got = (out / 'console-run/synth.txt').read_text() if (out / 'console-run/synth.txt').is_file() else ''
    # Identical but for the elapsed-time field.
    same = lambda text: [re.sub(r' ms=\d+$', '', body(l)) for l in kind_lines(text, ('C ', 'K '))]
    want = same(direct.stdout)
    check(same(got) == want and len(want) == 8,
          f'fetched C/K lines differ from a direct run ({len(same(got))} vs {len(want)} lines)')
    ab = (out / 'console-run/synth-ab.txt').read_text() if (out / 'console-run/synth-ab.txt').is_file() else ''
    check(same(ab) == want and rec.get('synth-ab_rc') == 0, f'synth-ab lines differ from a direct run ({len(same(ab))} lines)')
    icons = (out / 'console-run/icons-gen.txt').read_text() if (out / 'console-run/icons-gen.txt').is_file() else ''
    check(len(kind_lines(icons, ('I ',))) == 2 and all(' st=ok ' in l for l in kind_lines(icons, ('I ',))),
          f'icons step: {kind_lines(icons, ("I ",))}')
    check('skipped' in str(rec.get('icons_ws')) and 'diag_reasons' in rec and 'diag_unified' in rec,
          f'icons-ws skipped offline and the diag step ran: {rec.get("icons_ws")}')
    return dict(push_seconds=rec.get('push_seconds'), synth=rec.get('synth.txt'), chunks=(rec.get('push') or {}).get('chunks'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--bundle', type=Path, help='an ADRENO_SETTINGS_ICONS AdrenoMetal.bundle with its compiler runtime')
    ap.add_argument('--skip-console', action='store_true')
    ap.add_argument('--noise-rate', type=int, default=40)
    a = ap.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    if a.bundle:
        a.bundle = a.bundle.resolve()
    r = subprocess.run([sys.executable, str(ROOT / 'tools/build-icon-pixels.py'), '--output', str(out / 'tool')],
                       capture_output=True, text=True)
    if not check(r.returncode == 0, f'build: {r.stdout[-300:]} {r.stderr[-300:]}'):
        return 1
    tool = out / 'tool/icon-pixels'
    runs = []
    for n in range(2):
        r = subprocess.run([str(tool), 'synth'] + (['--host-caps', str(a.bundle)] if a.bundle else []),
                           capture_output=True, text=True, timeout=600)
        (out / f'host-synth-{n}.txt').write_text(r.stdout)
        check(r.returncode == 0, f'host synth run {n} exit {r.returncode}: {r.stderr[-300:]}')
        runs.append(r.stdout)
    pixels = lambda text: [re.sub(r' ms=\d+$', '', body(l)) for l in kind_lines(text, ('C ',))]
    check(pixels(runs[0]) and pixels(runs[0]) == pixels(runs[1]), 'two runs on this Mac\'s GPU must print the same pixels')
    rc = subprocess.run([sys.executable, str(ROOT / 'tools/compare-icon-pixels.py'), str(REFERENCE), str(out / 'host-synth-0.txt'),
                         '--tolerance', '0'], capture_output=True, text=True)
    (out / 'reference-check.txt').write_text(rc.stdout)
    check(rc.returncode == 0, f'this Mac no longer reproduces {REFERENCE.name} exactly: {rc.stdout.strip().splitlines()[-1:]}')
    if a.bundle:
        for units, label in (('8', 'cs8'), (None, 'cs1')):
            argv = [str(tool), 'synth', '--plugin', str(a.bundle)] + (['--cs-samplers', units] if units else [])
            p = subprocess.run(argv, capture_output=True, text=True, timeout=900)
            (out / f'plugin-{label}.txt').write_text(p.stdout)
            check(p.returncode == 0, f'plug-in synth ({label}) exit {p.returncode}: {p.stderr[-300:]}')
            c = subprocess.run([sys.executable, str(ROOT / 'tools/compare-icon-pixels.py'), str(REFERENCE),
                                str(out / f'plugin-{label}.txt'), '--census-only'], capture_output=True, text=True)
            (out / f'plugin-{label}.compare.txt').write_text(c.stdout)
            if units:
                check(c.returncode == 0, f'plug-in census (8 CS sampler units) differs: {c.stdout.strip().splitlines()[-1:]}')
            else:
                dropped = re.search(r'dropped=(\d+)', p.stdout)
                check(c.returncode == 1 and dropped and int(dropped.group(1)) > 0 and 'plugin-diagnostics' in c.stdout,
                      'without AdrenoIBComputeSamplers the multi-input kernels must be dropped and reported')
    ref_lines = [l for l in REFERENCE.read_text().splitlines() if l.strip()]
    icons = subprocess.run([str(tool), 'icons', '--size', '20'], capture_output=True, text=True, timeout=600)
    icon_lines = [l for l in icons.stdout.splitlines() if l.startswith(('I ', 'K gen-', 'K ws-'))]
    check(icons.returncode == 0 and len([l for l in icon_lines if l.startswith('I ')]) >= 10,
          f'icons on this Mac: exit {icons.returncode}, {len(icon_lines)} lines')
    (out / 'faults').mkdir()
    fault_injection(out / 'faults', ref_lines, icon_lines)
    console = None
    if not a.skip_console:
        console = console_end_to_end(out, tool, a.noise_rate)
    result = dict(checks=checks, failures=failures, console=console, tool=json.loads((out / 'tool/build.json').read_text()))
    (out / 'result.json').write_text(json.dumps(result, indent=1) + '\n')
    print(f'{"PASS" if not failures else "FAIL"}: {checks} checks ({len(failures)} failed); {out / "result.json"}')
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
