#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build probes/xnuboot exactly as probes/run.py build('xnuboot') does, offline.

    python3 tools/monitor_build_offline.py TREE OUT FLAGS_JSON [EXTRA_DEFINE ...]

TREE is a Snapintosh checkout (its ../q1n1/platform/uefi must exist), OUT a
fresh directory, FLAGS_JSON a file holding the ordered compile flag list (for
example a run's launch.json, whose "flags" key is used). Extra defines are
appended after the run's flags, the way cycle.py appends opt-in defines.

The source list, include directories, compiler, linker and objcopy steps are
read from TREE/probes/run.py (MULTI['xnuboot'], FLAGS order irrelevant: the
given flags replace FLAGS exactly as installed_fresh.prepare does). run.py is
parsed, not imported, so no q1n1 proxy module is loaded. Prints one JSON line.
"""
import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

LLVM = Path('/opt/homebrew/opt/llvm/bin')
LLD = '/opt/homebrew/opt/lld/bin/ld.lld' if Path('/opt/homebrew/opt/lld/bin/ld.lld').exists() else 'ld.lld'


def run_py_literal(tree, name):
    mod = ast.parse((tree / 'probes/run.py').read_text())
    for node in mod.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    return None


def multi_sources(tree, flags=()):
    multi = run_py_literal(tree, 'MULTI')
    if multi is None:
        raise SystemExit('no MULTI in run.py')
    # run.py's OPTIONAL units: linked only when their define is in the flags (run.py optional_sources).
    optional = run_py_literal(tree, 'OPTIONAL') or {}
    return multi['xnuboot'] + [rel for define, rel in optional.get('xnuboot', ()) if define in flags]


def build(tree, out, flags):
    tree = Path(tree).resolve()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    objs = []
    for rel in multi_sources(tree, flags):
        src = tree / rel
        obj = out / (src.stem + '-' + src.suffix.lstrip('.') + '.o')
        subprocess.run([str(LLVM / 'clang'), *flags, f'-I{tree / "shadow"}',
                        f'-I{tree.parent / "q1n1/platform/uefi"}', '-c', str(src), '-o', str(obj)],
                       check=True)
        objs.append(str(obj))
    elf = out / 'xnuboot.elf'
    subprocess.run([LLD, '-T', str(tree / 'probes' / 'probe.ld'), '-o', str(elf), *objs], check=True)
    binary = out / 'xnuboot.bin'
    subprocess.run([str(LLVM / 'llvm-objcopy'), '-O', 'binary', str(elf), str(binary)], check=True)
    blob = binary.read_bytes()
    return dict(bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
                elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest())


def main():
    tree, out, flags_json, *extra = sys.argv[1:]
    data = json.loads(Path(flags_json).read_text())
    flags = data['flags'] if isinstance(data, dict) else data
    result = build(tree, out, list(flags) + extra)
    result.update(tree=str(tree), out=str(out), extra=extra)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
