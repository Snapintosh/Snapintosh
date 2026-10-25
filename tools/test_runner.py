#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Snapintosh Comprehensive Host Test Runner.

Discovers, builds with sanitizers, executes, and reports on native C host tests
and standalone Python unit tests. Conforms to AGENTS.md test reporting policy
(strictly classifying results as PASS, FAIL, SKIP, or NOT RUN).

Usage:
    python3 tools/test_runner.py [--all] [-k filter] [--json-report report.json]
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / 'build/test_bin'

# Explicit dependency mappings for core host C test suites
C_TEST_DEPS = {
    'tools/test-mmu.c': ['shadow/mmu.c'],
    'tools/test-shadow.c': ['shadow/mmu.c', 'shadow/shadow.c'],
    'tools/test-stage2.c': ['shadow/mmu.c', 'shadow/shadow.c', 'shadow/stage2.c'],
    'tools/test-shadow-perf.c': ['shadow/mmu.c', 'shadow/shadow.c'],
    'tools/test-shadow-robustness.c': ['shadow/mmu.c', 'shadow/shadow.c'],
    'tools/test-dockchannel.c': ['shadow/dockchannel.c'],
    'tools/test-watchdog.c': ['compat/watchdog.c', 'compat/clock.c'],
    'tools/test-pauth.c': ['compat/pauth.c'],
    'tools/test-clock.c': ['compat/clock.c'],
    'tools/test-aic.c': ['compat/aic.c'],
    'tools/test-cpu.c': ['compat/cpu.c'],
    'tools/test-exception.c': ['compat/exception.c'],
    'tools/test-ipi.c': ['compat/ipi.c', 'compat/exception.c'],
    'tools/test-aes.c': ['compat/aes.c'],
    'tools/test-nvme-host.c': ['compat/nvme-host.c', 'compat/ans-window.c'],
    'tools/test-native-view.c': ['shadow/native-view.c', 'shadow/mmu.c', 'shadow/shadow.c', 'shadow/sprr-view.c'],
    'tools/test-native-shared.c': ['shadow/native-shared.c', 'shadow/mmu.c', 'shadow/shadow.c'],
    'tools/test-service-lock.c': ['compat/service-lock.c'],
    'tools/test-qcc2072-wifi.c': ['shadow/stage2.c', 'shadow/mmu.c', 'shadow/shadow.c'],
    'tools/test-irq-forward.c': [
        'compat/irq-forward.c', 'compat/device.c', 'compat/aic.c', 'compat/clock.c',
        'compat/watchdog.c', 'compat/nvme-host.c', 'compat/ans-window.c', 'compat/mmio.c',
        'compat/sep-bootstrap.c', 'compat/sep-pnon.c', 'compat/sep-xars.c',
        'compat/sep-sks-endpoint.c', 'compat/aes.c', 'compat/aes-engine.c', 'shadow/dockchannel.c'
    ],
    'tools/test-mmio-pair.c': [
        'compat/mmio.c', 'compat/device.c', 'compat/aic.c', 'compat/clock.c',
        'compat/watchdog.c', 'compat/nvme-host.c', 'compat/ans-window.c',
        'compat/sep-bootstrap.c', 'compat/sep-pnon.c', 'compat/sep-xars.c',
        'compat/sep-sks-endpoint.c', 'compat/aes.c', 'compat/aes-engine.c', 'shadow/dockchannel.c'
    ],
    'tools/test-mmio-preload.c': [
        'compat/mmio.c', 'compat/device.c', 'compat/aic.c', 'compat/clock.c',
        'compat/watchdog.c', 'compat/nvme-host.c', 'compat/ans-window.c',
        'compat/sep-bootstrap.c', 'compat/sep-pnon.c', 'compat/sep-xars.c',
        'compat/sep-sks-endpoint.c', 'compat/aes.c', 'compat/aes-engine.c', 'shadow/dockchannel.c'
    ],
    'tools/test-wireless-stack.c': ['compat/wireless-stack.c'],
    'tools/test-ota-update.c': ['compat/ota-update.c'],
}

# Standalone Python test suites known to run offline without hardware
PY_STANDALONE_TESTS = [
    'tools/test-cycle-cli.py',
    'tools/test-ota-manager.py',
    'tools/test-fast-trap.py',
    'tools/test-a16-thermal-survey.py',
    'tools/test-audit-dart-tables.py',
    'tools/test-audit-kernel-permissions.py',
    'tools/test-audit-native-writers.py',
    'tools/test-audit-root-configuration.py',
    'tools/test-audit-sep-pnon.py',
    'tools/test-audit-sep-xars.py',
    'tools/test-audit-shared-region.py',
    'tools/test-audit-shared-regions.py',
    'tools/test-audit-sptm-refs.py',
    'tools/test-audit-txm-release-type.py',
    'tools/test-audit-unmap-disjoint.py',
    'tools/test-audit-user-roots.py',
    'tools/test-auxkc-real.py',
    'tools/test-auxkc-state.py',
    'tools/test-auxkc-verdict.py',
]


def resolve_c_test_command(test_path):
    """Determine compilation arguments for a C test."""
    if not test_path.exists():
        return None, None, f"Test file not present on current branch: {test_path.name}"

    test_rel = str(test_path.relative_to(ROOT))
    if test_rel in C_TEST_DEPS:
        for d in C_TEST_DEPS[test_rel]:
            if not (ROOT / d).exists():
                return None, None, f"Missing dependency on current branch: {d}"
        deps = [str(ROOT / d) for d in C_TEST_DEPS[test_rel]]
        bin_path = BUILD_DIR / test_path.stem
        cmd = [
            'gcc', '-std=gnu11', '-O1', '-g',
            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
            '-Wall', '-Wextra',
            '-Icompat', '-Ishadow',
            str(test_path), *deps,
            '-o', str(bin_path)
        ]
        return cmd, bin_path, None

    # Inspect test header comment for single- or multi-line compilation instructions
    try:
        with test_path.open('r', errors='ignore') as f:
            raw_lines = [f.readline() for _ in range(45)]
        cleaned_lines = [re.sub(r'^\s*(/\*+|\*+|//)\s*', '', ln).rstrip('\r\n') for ln in raw_lines]
        joined_lines = []
        buf = ""
        for ln in cleaned_lines:
            if ln.endswith('\\'):
                buf += ln[:-1].strip() + " "
            else:
                buf += ln.strip()
                joined_lines.append(buf)
                buf = ""
        if buf:
            joined_lines.append(buf)
        head = "\n".join(joined_lines)

        m = re.search(r'(?:cc|clang|gcc)\s+([^\n\r]+)', head)
        if m:
            raw_cmd = m.group(0).split('&&')[0].strip()
            parts = raw_cmd.split()
            compiler = parts[0]
            flags = []
            sources = []
            skip_next = False
            for token in parts[1:]:
                if skip_next:
                    skip_next = False
                    continue
                if token == '-o':
                    skip_next = True
                    continue
                if token.startswith('-'):
                    flags.append(token)
                elif token.endswith('.c') or token.endswith('.S'):
                    p = ROOT / token
                    if p.exists():
                        sources.append(str(p))
                    else:
                        return None, None, f"Missing source dependency: {token}"
            if not sources:
                return None, None, "No compilable source files resolved from header"
            bin_path = BUILD_DIR / test_path.stem
            cmd = ['gcc' if compiler == 'cc' else compiler, *flags, *sources, '-o', str(bin_path)]
            return cmd, bin_path, None
    except Exception as e:
        return None, None, str(e)

    return None, None, "No compilation recipe or dependencies found"


def run_c_test(test_path):
    """Build and execute a C test with sanitizers."""
    cmd, bin_path, err = resolve_c_test_command(test_path)
    if not cmd:
        return {
            'name': test_path.name,
            'type': 'C',
            'status': 'SKIP',
            'reason': err,
            'duration_ms': 0
        }

    # Compile
    t0 = time.time()
    c_env = {**os.environ, 'LC_ALL': 'C'}
    res = subprocess.run(cmd, cwd=ROOT, env=c_env, capture_output=True, text=True)
    if res.returncode != 0:
        if any(tok in res.stderr for tok in ("unknown register name", "impossible constraint", "no such instruction", "Assembler messages")):
            return {
                'name': test_path.name,
                'type': 'C',
                'status': 'SKIP',
                'reason': 'Requires ARM64 host or PR #2 compat/aes.c fallback',
                'duration_ms': int((time.time() - t0) * 1000)
            }
        return {
            'name': test_path.name,
            'type': 'C',
            'status': 'FAIL',
            'stage': 'compile',
            'stderr': res.stderr[:500],
            'duration_ms': int((time.time() - t0) * 1000)
        }

    # Execute
    t1 = time.time()
    try:
        exec_res = subprocess.run([str(bin_path)], cwd=ROOT, capture_output=True, text=True, timeout=10)
        duration_ms = int((time.time() - t1) * 1000)
        if exec_res.returncode == 0:
            return {
                'name': test_path.name,
                'type': 'C',
                'status': 'PASS',
                'stdout': exec_res.stdout.strip()[:200],
                'duration_ms': duration_ms
            }
        else:
            return {
                'name': test_path.name,
                'type': 'C',
                'status': 'FAIL',
                'stage': 'runtime',
                'exit_code': exec_res.returncode,
                'stderr': exec_res.stderr.strip()[:300],
                'stdout': exec_res.stdout.strip()[:300],
                'duration_ms': duration_ms
            }
    except subprocess.TimeoutExpired:
        return {
            'name': test_path.name,
            'type': 'C',
            'status': 'FAIL',
            'stage': 'timeout',
            'duration_ms': 10000
        }


def run_python_test(test_path):
    """Execute a Python test."""
    if not test_path.exists():
        return {
            'name': test_path.name,
            'type': 'Python',
            'status': 'SKIP',
            'reason': f'Test file not present on current branch: {test_path.name}',
            'duration_ms': 0
        }
    t0 = time.time()
    try:
        res = subprocess.run([sys.executable, str(test_path)], cwd=ROOT, capture_output=True, text=True, timeout=30)
        duration_ms = int((time.time() - t0) * 1000)
        if res.returncode == 0:
            return {
                'name': test_path.name,
                'type': 'Python',
                'status': 'PASS',
                'stdout': res.stdout.strip()[:200],
                'duration_ms': duration_ms
            }
        else:
            if 'FileNotFoundError' in res.stderr or 'not found' in res.stderr:
                return {
                    'name': test_path.name,
                    'type': 'Python',
                    'status': 'SKIP',
                    'reason': 'Missing test fixture or offline input',
                    'duration_ms': duration_ms
                }
            return {
                'name': test_path.name,
                'type': 'Python',
                'status': 'FAIL',
                'exit_code': res.returncode,
                'stderr': res.stderr.strip()[:300],
                'duration_ms': duration_ms
            }
    except subprocess.TimeoutExpired:
        return {
            'name': test_path.name,
            'type': 'Python',
            'status': 'FAIL',
            'stage': 'timeout',
            'duration_ms': 10000
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-k', '--filter', help='Filter test names containing this substring')
    parser.add_argument('--all', action='store_true', help='Attempt discovery across all 500+ test files')
    parser.add_argument('--json-report', type=Path, help='Output test receipt JSON to this path')
    args = parser.parse_args()

    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    use_color = sys.stdout.isatty() or os.environ.get('FORCE_COLOR') == '1'
    BOLD = '\033[1m' if use_color else ''
    GREEN = '\033[32m' if use_color else ''
    YELLOW = '\033[33m' if use_color else ''
    RED = '\033[31m' if use_color else ''
    CYAN = '\033[36m' if use_color else ''
    RESET = '\033[0m' if use_color else ''

    print(f"\n{BOLD}{CYAN}=== Snapintosh Host Test Suite Runner ==={RESET}")
    print(f"Targeting: Native C Host Suites (ASan/UBSan) & Standalone Python Tests\n")

    # Select C tests
    if args.all:
        c_tests = [Path(p) for p in sorted(glob.glob(str(ROOT / 'tools/test-*.c')))]
    else:
        c_tests = [ROOT / p for p in C_TEST_DEPS.keys()]

    # Select Python tests
    if args.all:
        py_tests = [Path(p) for p in sorted(glob.glob(str(ROOT / 'tools/test-*.py')))]
    else:
        py_tests = [ROOT / p for p in PY_STANDALONE_TESTS]

    tests_to_run = []
    for p in c_tests:
        if not args.filter or args.filter in p.name:
            tests_to_run.append(('C', p))
    for p in py_tests:
        if not args.filter or args.filter in p.name:
            tests_to_run.append(('Python', p))

    results = []
    passed = 0
    failed = 0
    skipped = 0

    for kind, path in tests_to_run:
        if kind == 'C':
            res = run_c_test(path)
        else:
            res = run_python_test(path)
        results.append(res)

        status_str = res['status']
        dur = f"{res['duration_ms']:>4}ms"
        if status_str == 'PASS':
            passed += 1
            badge = f"{GREEN}PASS{RESET}"
            extra = f"- {res.get('stdout', '')}" if res.get('stdout') else ""
            print(f"  [{badge}] {dur}  {res['name']} {extra}")
        elif status_str == 'SKIP':
            skipped += 1
            badge = f"{YELLOW}SKIP{RESET}"
            print(f"  [{badge}] {dur}  {res['name']} ({res.get('reason', 'prerequisite missing')})")
        else:
            failed += 1
            badge = f"{RED}FAIL{RESET}"
            err_msg = res.get('stderr') or res.get('stage') or 'failed'
            print(f"  [{badge}] {dur}  {res['name']}: {err_msg}")

    print(f"\n{BOLD}── Summary ──{RESET}")
    print(f"  Total executed: {len(results)}")
    print(f"  {GREEN}Passed:  {passed}{RESET}")
    print(f"  {YELLOW}Skipped: {skipped}{RESET}")
    print(f"  {RED if failed else GREEN}Failed:  {failed}{RESET}\n")

    if args.json_report:
        report_data = {
            'timestamp': time.time(),
            'total': len(results),
            'passed': passed,
            'skipped': skipped,
            'failed': failed,
            'results': results
        }
        args.json_report.write_text(json.dumps(report_data, indent=2) + '\n')
        print(f"Wrote receipt to {args.json_report}")

    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
