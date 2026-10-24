#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-order audit of the kernel-ops-perf control flow in probes/xnuboot.c.

The monitor transaction code cannot run on the host. These checks pin the
orderings the correctness argument depends on, so a later edit that breaks one
fails here instead of on hardware:
- no runtime transaction cleans the whole arena any more, and every arena note
  site also reports to the transaction sentinel;
- a PPERM transaction proves its snapshot before invalidating it, invalidates
  before any private write, and repins only after its invalidation point;
- root installation issues a deferred TLBI on every failure exit and ends with
  its all-VMID invalidation;
- only user-root UPDATE_DISJOINT skips the kernel refresh, and it keeps the TLBI.
"""
from pathlib import Path
import re
import runpy
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
source = read_source(ROOT / 'probes/xnuboot.c')
function = runpy.run_path(str(ROOT / 'tools/test-guard-step.py'))['function']
checks = 0


def check(ok, what):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(what)


def body(signature):
    return function(source, signature)


def enclosing(index):
    """Name of the top-level function containing a source offset."""
    names = [(m.start(), m.group(1)) for m in
             re.finditer(r'^static [^\n;]*?\b(\w+)\([^;{]*\)\s*\{', source, re.M)]
    names += [(m.start(), m.group(1)) for m in re.finditer(r'^\w[^\n;]*?\b(\w+)\([^;{]*\)\s*\{', source, re.M)]
    best = max((n for n in names if n[0] <= index), key=lambda n: n[0])
    return best[1]


# Whole-arena publication survives only in construction, the lockdown seal and
# the flag-off fallbacks.
sites = [m.start() for m in re.finditer(r'publish\(c->work_base, ?c->next_table\)', source)]
owners = sorted(enclosing(i) for i in sites)
check(owners == sorted(['transaction_publish', 'const_region_seal', 'user_root_install',
                        'vcpu_arch_prepare']), f'whole-arena publications remain in {owners}')
for name in ('transaction_publish', 'user_root_install'):
    text = body(f'static {"int" if name == "transaction_publish" else "void"} {name}(')
    check(re.search(r'#else\s*\n\s*publish\(c->work_base, ?c->next_table\)', text),
          f'{name} keeps the whole-arena clean only as the flag-off fallback')
monitor = body('static int monitor_call_impl(')
# UPDATE_DISJOINT and its MULTIPAGE groups share update_disjoint_call.
for case in ('SPTM_FN_UPDATE_DISJOINT', 'SPTM_FN_UPDATE_DISJOINT_MULTIPAGE'):
    start = monitor.index(f'case {case}:')
    text = monitor[start:monitor.index('break;\n    }', start)]
    check('update_disjoint_call(c,' in text and 'publish(c->work_base' not in text,
          f'{case} goes through update_disjoint_call')
helper = body('static int update_disjoint_call(')
for case, text in [('update_disjoint_call', helper)] + [
        (case, monitor[monitor.index(f'case {case}:'):
                       monitor.index('break;\n    }', monitor.index(f'case {case}:'))])
        for case in ('SPTM_FN_UPDATE_REGION', 'SPTM_FN_UNMAP_REGION', 'SPTM_FN_SLIDE_REGION')]:
    check('transaction_publish(c)' in text and 'publish(c->work_base' not in text,
          f'{case} publishes through the transaction bitmap')
    check(text.index('transaction_publish(c)') < text.rindex('shadow_tlb_sync(c)'),
          f'{case} publishes before its invalidation')
for name in ('sptm_retype_rozone', 'sptm_retype_user_exec'):
    text = body(f'static int {name}(')
    check(text.index('sptm_papt_commit') < text.index('transaction_publish(c)') <
          text.rindex('shadow_tlb_sync(c)'), f'{name}: commit, publish, then invalidate')

# Batched barriers: page cleans carry no barrier; one dsb ish follows the whole
# flush before any TLBI (transaction end, and the installation sequence).
lines = body('static int publish_page_lines(')
check('dc civac' in lines and 'dsb' not in lines, 'page clean without its own barrier')
txn = body('static int transaction_publish(')
check(re.search(r'txn_publish_flush\([^;]*publish_page_lines[^;]*\);\s*__asm__ volatile\("dsb ish"', txn),
      'transaction flush completes with one dsb ish')
install_text = body('static void user_root_install(')
tail = install_text[install_text.index('root_publish_flush(&c->root_publish'):]
check(re.search(r'#endif\s*/\*[^*]*(\*[^/][^*]*)*\*/\s*__asm__ volatile\("dsb ish; msr tcr_el1', tail) and
      'page)(void *,uint64_t)=publish_page_lines;' in install_text and 'dsb ish" ::: "memory");\n        install_failed' in tail,
      'installation: batched cleans complete at the sequence\'s leading dsb ish')

# Every arena note is paired with the sentinel observer, in the same block.
notes = [m.start() for m in re.finditer(r'root_publish_note\(&c->root_publish', source)]
observes = [m.start() for m in re.finditer(r'txn_publish_observe\(&c->txn_publish', source)]
check(len(notes) == len(observes) == 3, 'three arena note sites, each observed')
for n, o in zip(notes, observes):
    check(n < o and source.count('\n', n, o) <= 4 and '#endif' in source[n:o],
          'observer follows its note site')

# PPERM transaction ordering.
impl = body('static int kernel_change_pperm_impl(')
order = ['sprr_reuse_current', 'sprr_reuse_invalidate', 'pperm_tpro_preflight',
         'sprr_views_verify_cpu', 'kernel_sync_view', 'user_refresh_pperm', 'kernel_publish_cpu',
         'tlbi alle1is', 'sprr_reuse_repin']
positions = [impl.index(token) for token in order]
check(positions == sorted(positions), 'PPERM proof, invalidate, write, publish, TLBI, repin order')
publish_h = (ROOT / 'shadow/sprr-publish.h').read_text()
check('SPRR_KERNEL_VIEW_PPERM' in impl and 'sprr_publish_row_empty(ps,cpu)' in impl and
      'return !p->pending[cpu][0] && !p->pending[cpu][1];' in publish_h,
      'skip requires the unchanged kernel permission bit and no pending publication')
check(re.search(r'if\(invalidate\) \{\s*__asm__ volatile\("dsb ishst; tlbi alle1is', impl),
      'the PPERM TLBI is omitted only when the caller folds it')
check(body('static int kernel_change_pperm(void *ctx').count('kernel_change_pperm_timed(ctx,pperm,1)') == 1,
      'register-trap PPERM writes always invalidate')

# Root installation: deferred TLBI on every failure exit, final all-VMID TLBI.
install = body('static void user_root_install(')
after = install[install.index('deferred=1'):]
returns = [m.start() for m in re.finditer(r'return;', after)]
for r in returns:
    check(after[max(0, r - 40):r].rstrip().endswith('install_failed(c,deferred);'),
          'every failure exit after deferral flushes')
check(install.rindex('tlbi alle1is') > install.rindex('root_publish_flush'),
      'installation ends with publication then its all-VMID TLBI')
check('kernel_change_pperm_timed(c,SPRR_PPERM_INITIAL,!defer)' in install and
      'user_install_view(c,guest_root,shadow,!defer)' in install, 'only installation defers')
failed = body('static void install_failed(')
check('tlbi alle1is' in failed and 'if(deferred)' in failed, 'failure exit issues the deferred TLBI')
view = body('static uint64_t user_install_view(struct context *c,uint64_t root')
check('if(invalidate)user_tlb_sync(c);' in view, 'install view folds only its own final TLBI')

# User UPDATE_DISJOINT: kernel refresh skipped only on the user-only branch;
# kernel and mixed user+kernel calls keep it.
text = body('static int update_disjoint_call(')
check(re.search(r'if\(user && !kernel\)user_update_kernel_skip\(c\);\s*else\s*#endif\s*shadow_tlb_sync\(c\);',
                text), 'kernel and mixed UPDATE_DISJOINT keep their refresh')
skip = body('static void user_update_kernel_skip(')
check('tlbi alle1is' in skip and 'sprr_views_verify_cpu' in skip and 'kernel_view_failed=1' in skip,
      'user skip keeps the TLBI and verifies all kernel views on samples')
print(f'PASS: {checks} kernel-ops-perf source-order checks')
