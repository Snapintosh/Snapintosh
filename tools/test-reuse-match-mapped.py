#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_REUSE_MATCH_MAPPED (shadow/sprr-reuse.h): the kernel refresh's exact
reuse proof reads each copied source table through class_table_read and
compares it in one pass, instead of one kernel_table_read callback per word.

    python3 tools/test-reuse-match-mapped.py [--build --flags RUN/launch.json [--out DIR] [--expect SHA256]]

Offline. Runs, from fresh output paths:
  1. source checks: the define defaults to 0, kernel_refresh_impl calls the
     mapped form only under it, the prerequisites are refused by #error, and
     the monitor's kernel_table_read / class_table_read keep the bounds the
     equivalence argument (the header's mode 1) relies on;
  2. tools/test-reuse-match-mapped.c, sanitized: equal verdicts and states;
  3. mutants of the mapped form, each of which must FAIL the differential;
  4. --build: the monitor with the given run's flags, absent == =0 (and
     --expect pins it), =1 differs and fits the code reservation.

Failure inventory: the header's modes 1-5.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
HEADER = (ROOT / 'shadow/sprr-reuse.h').read_text()
TEST_C = 'tools/test-reuse-match-mapped.c'
LINKED = ['shadow/sprr-view.c', 'shadow/shadow.c', 'shadow/mmu.c']
BUDGET = 0x470000 - 0x3fc000          # probes/run.py OUT_AT - CODE_AT


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--flags', help='a run launch.json (its "flags") or a JSON list of compile flags')
    ap.add_argument('--out')
    ap.add_argument('--expect', help='SHA-256 the default monitor must have')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    if args.build and not args.flags:
        ap.error('--build needs --flags')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, flags=None, out=None, expect=None), [])


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def compile_test(directory, shadow_dir=None):
    exe = Path(directory) / 'test-reuse-match-mapped'
    shadow = [f'-I{shadow_dir}'] if shadow_dir else ['-Ishadow']
    linked = [str(Path(shadow_dir) / Path(p).name) for p in LINKED] if shadow_dir else LINKED
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-DSNAP_REUSE_MATCH_MAPPED=1',
                    '-Icompat', *shadow, TEST_C, *linked, '-o', str(exe)],
                   cwd=ROOT, check=True, timeout=300, capture_output=True)
    return exe


def mutated_shadow(directory, old, new):
    """A copy of shadow/ with one replacement in sprr-reuse.h, beside a compat
    link so the headers' ../compat includes resolve."""
    d = Path(directory)
    shutil.copytree(ROOT / 'shadow', d / 'shadow')
    os.symlink(ROOT / 'compat', d / 'compat')
    path = d / 'shadow' / 'sprr-reuse.h'
    text = path.read_text()
    if text.count(old) != 1:
        raise AssertionError(f'mutant anchor not unique: {old!r}')
    path.write_text(text.replace(old, new))
    return d / 'shadow'


MAPPED = between(HEADER, 'static inline int sprr_reuse_match_mapped(', '\n}\n')
MUTANTS = {
    'short compare': ('for(unsigned i=0;i<512;i+=8)', 'for(unsigned i=0;i<504;i+=8)'),
    'refused page trusted': ('        if(!w) {\n            for(unsigned i=0;i<512;i++) {',
                             '        if(!w) {continue;\n            for(unsigned i=0;i<512;i++) {'),
    'partial mismatch ignored': ('        if(diff)return 0;', '        if(diff&1)return 0;'),
    'fallback error uncounted': (
        '                if(s->read(s->ctx,b->source+8UL*i,&word)) {r->errors++;r->valid=0;return -1;}\n'
        '                if(r->words[n][i]!=word)return 0;\n            }\n            continue;',
        '                if(s->read(s->ctx,b->source+8UL*i,&word))return -1;\n'
        '                if(r->words[n][i]!=word)return 0;\n            }\n            continue;'),
    'hit not counted': ('        if(diff)return 0;\n    }\n    r->hits++;return 1;', '        if(diff)return 0;\n    }\n    return 1;'),
}


class Source(unittest.TestCase):
    def test_header(self):
        self.assertIn('#ifndef SNAP_REUSE_MATCH_MAPPED\n#define SNAP_REUSE_MATCH_MAPPED 0\n#endif\n'
                      '#if SNAP_REUSE_MATCH_MAPPED\n', HEADER)
        for old, _ in MUTANTS.values():
            self.assertEqual(HEADER.count(old), 1, old)

    def test_monitor(self):
        refresh = between(SOURCE, 'static int kernel_refresh_impl(struct context *c)', '\n}\n')
        self.assertIn('#if SNAP_TOKEN_TRIM\n    int match=token_trim_match(c,reuse,&s,pp);\n'
                      '#elif SNAP_REUSE_MATCH_MAPPED\n', refresh)
        self.assertIn('    int match=sprr_reuse_match_mapped(reuse,&c->kernel_views,&s,pp,class_table_read,c);\n'
                      '#else\n    int match=sprr_reuse_match(reuse,&c->kernel_views,&s,pp);\n#endif', refresh)
        self.assertEqual(SOURCE.count('sprr_reuse_match_mapped('), 1)
        self.assertIn('#if SNAP_REUSE_MATCH_MAPPED && (!SNAP_KERNEL_VIEW_REUSE || !SNAP_CLASS_PROOF_MAPPED || '
                      'SNAP_TOKEN_TRIM)\n#error', SOURCE)
        # The bounds the equivalence relies on (header mode 1).
        self.assertIn('static int kernel_table_read(void *ctx,uint64_t pa,uint64_t *out)\n{\n'
                      '    struct context *c=ctx;\n'
                      '    if((pa&7) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<8)return -1;\n'
                      '    return mem_read(ctx,pa,out);\n}', SOURCE)
        self.assertIn('static const volatile uint64_t *class_table_read(void *ctx,uint64_t pa)\n{\n'
                      '    struct context *c=ctx;\n'
                      '    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096)return 0;\n'
                      '    return (const volatile uint64_t *)pa;\n}', SOURCE)
        self.assertIn('static int mem_read(void *ctx, uint64_t pa, uint64_t *out)\n{\n    (void)ctx;\n'
                      '    *out = *(volatile uint64_t *)pa;\n    return 0;\n}', SOURCE)


class Differential(unittest.TestCase):
    def test_equal_verdicts(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([str(compile_test(d))], capture_output=True, text=True, timeout=600)
        print(result.stdout.strip(), file=sys.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS:', result.stdout)

    def test_mutants_fail(self):
        for name, (old, new) in MUTANTS.items():
            with self.subTest(mutant=name), tempfile.TemporaryDirectory() as d:
                shadow = mutated_shadow(d, old, new)
                result = subprocess.run([str(compile_test(d, shadow))], capture_output=True, text=True,
                                        timeout=600)
                self.assertNotEqual(result.returncode, 0, f'mutant {name} passed')


@unittest.skipUnless(ARGS.build, 'pass --build --flags RUN/launch.json to compile the monitor')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        import monitor_build_offline as mb  # noqa: E402
        data = json.loads(Path(ARGS.flags).read_text())
        flags = list(data['flags'] if isinstance(data, dict) else data)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='reuse-mapped-build-'))
        results = {label: mb.build(ROOT, out / label, flags + extra)
                   for label, extra in (('default', []), ('off', ['-DSNAP_REUSE_MATCH_MAPPED=0']),
                                        ('on', ['-DSNAP_REUSE_MATCH_MAPPED=1']))}
        for r in results.values():
            r['headroom'] = BUDGET - r['bytes']
        self.assertEqual(results['default'], results['off'])
        self.assertNotEqual(results['default']['sha256'], results['on']['sha256'])
        self.assertGreater(results['on']['headroom'], 0)
        if ARGS.expect:
            self.assertEqual(results['default']['sha256'], ARGS.expect)
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
