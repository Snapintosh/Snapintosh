#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the monitor's appended perf state (compat/perf-state.h).

Every monitor build appends `struct perf_state perf` to struct context (zero
unless SNAP_FAST_VCPU_TRAPS, SNAP_SYSREG_CENSUS, SNAP_INCREMENTAL_PUBLISH,
SNAP_CANONICAL_VIEW_FAST, SNAP_VECTOR_BRANCH or SNAP_FAST_CROSSINGS fills
it). The layout comes from Clang's target
record dump of probes/xnuboot.c; pass the build.json build_defines anyway so
the dump matches the resident monitor exactly. Reading the bytes is a
stopped-machine capture:
    offset, size = perf_counters.read_spec(build_defines)
    raw = proxy.readmem(work + offset, size, live=True)   # read twice, compare
    print(json.dumps(perf_counters.decode(raw, build_defines), indent=1))
or offline:  tools/perf_counters.py --raw FILE.bin --defines -DSNAP_...=1 ...
A SNAP_FAST_EL0_SYSREG / SNAP_SERVICE_SUBCLASS monitor's exit profile is in
report.bin:  tools/perf_counters.py --report report.bin --defines ... [--hz HZ]
A SNAP_FINE_LOCKS monitor's converted-call profile follows it in report.bin
(decoded with the same command, under "fine"), and the token-cost record of
SNAP_NEST_FAST/DETACH_FAST/ROOT_INDEX/OTHER_PROFILE/GATE_WAIT after that
(under "token_costs"), and a SNAP_FAST_TIMER_IRQ monitor's per-CPU IRQ outcomes
after the last of these (under "fast_irq"); a SNAP_FAST_IPI monitor's IPI-register
outcomes just below the thermal block (under "fast_ipi").
Nothing here contacts hardware.
"""
from pathlib import Path
import argparse
import json
import re
import runpy
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ('none', 'pacga', 'key', 'counter', 'esr', 'far', 'ignore', 'timer', 'sprr', 'zero',
           'timer_write', 'idle_poll')
# Log bits: PACGA 0, ignored registers 1..7 and 14..26 (compat/fast-trap.h),
# the exception boundary 8..13 (compat/fast-vector.h).
LOG_BITS = (1 << 27) - 1
NAMES = {
    (3, 0, 13, 0, 1): 'CONTEXTIDR_EL1', (3, 0, 5, 2, 0): 'ESR_EL1', (3, 0, 6, 0, 0): 'FAR_EL1',
    (3, 0, 2, 1, 0): 'APIAKeyLo_EL1', (3, 0, 2, 1, 1): 'APIAKeyHi_EL1',
    (3, 0, 2, 1, 2): 'APIBKeyLo_EL1', (3, 0, 2, 1, 3): 'APIBKeyHi_EL1',
    (3, 0, 2, 2, 0): 'APDAKeyLo_EL1', (3, 0, 2, 2, 1): 'APDAKeyHi_EL1',
    (3, 0, 2, 2, 2): 'APDBKeyLo_EL1', (3, 0, 2, 2, 3): 'APDBKeyHi_EL1',
    (3, 0, 2, 3, 0): 'APGAKeyLo_EL1', (3, 0, 2, 3, 1): 'APGAKeyHi_EL1',
    (3, 4, 15, 1, 0): 'KERNKeyLo_EL1', (3, 4, 15, 1, 1): 'KERNKeyHi_EL1',
    (3, 4, 15, 0, 4): 'APCTL_EL1', (3, 4, 15, 13, 6): 'JAPIBKeyLo_EL1',
    (3, 4, 15, 13, 7): 'JAPIBKeyHi_EL1', (3, 2, 15, 0, 0): 'PMC0', (3, 2, 15, 1, 0): 'PMC1',
    (3, 4, 15, 11, 7): 'CNTVCT_ALIAS', (3, 4, 15, 10, 6): 'CNTVCTSS_ALIAS',
    (3, 3, 14, 0, 2): 'CNTVCT_EL0', (3, 3, 14, 0, 6): 'CNTVCTSS_EL0',
    (3, 1, 15, 0, 5): 'CNTV_CTL_ALIAS', (3, 1, 15, 15, 4): 'CNTV_TVAL_ALIAS',
    (3, 6, 15, 1, 5): 'SPRR_UPERM', (3, 6, 15, 1, 6): 'SPRR_PPERM',
    (3, 5, 15, 0, 0): 'IPI_RR_LOCAL', (3, 5, 15, 0, 1): 'IPI_RR_GLOBAL', (3, 5, 15, 1, 1): 'IPI_SR',
    (3, 0, 1, 0, 0): 'SCTLR_EL1', (3, 0, 2, 0, 0): 'TTBR0_EL1', (3, 0, 2, 0, 1): 'TTBR1_EL1',
    (3, 0, 2, 0, 2): 'TCR_EL1', (3, 6, 15, 8, 3): 'ASPSR_EL1', (3, 6, 15, 2, 5): 'AFPCR_EL0',
    (3, 4, 15, 1, 3): 'AMX_STATE_T_EL1', (3, 4, 15, 12, 0): 'ACFG_EL1',
    (3, 1, 15, 0, 0): 'PMCR0', (3, 7, 15, 6, 4): 'UPMSR',
}


def _records(source, defines, extra_headers=()):
    text = subprocess.run(
        ['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
         '-Ishadow', '-Icompat', *defines, '-Xclang', '-fdump-record-layouts',
         '-fsyntax-only', *extra_headers, str(source)],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    records = {}
    for block in text.split('*** Dumping AST Record Layout'):
        match = re.search(r'^\s*0 \| struct (\w+)\n', block, re.M)
        if match and match[1] not in records:
            records[match[1]] = block
    return records


def _offset(block, field):
    found = re.findall(r'^\s*(\d+) \|   \S.* ' + re.escape(field) + r'$', block, re.M)
    if len(found) != 1:
        raise ValueError(f'ambiguous or missing field {field}')
    return int(found[0])


def _size(block):
    return int(re.search(r'\[sizeof=(\d+),', block)[1])


def layout(defines=()):
    """Offsets and sizes under the monitor's build defines."""
    defines = [d for d in defines if d.startswith('-D')]
    records = _records(ROOT / 'probes/xnuboot.c', defines)
    if 'perf_state' not in records:
        raise ValueError('this monitor source has no appended perf state')
    perf, census, fast = records['perf_state'], records['sysreg_census_cpu'], records['fast_trap_cpu']
    slots = (_offset(census, 'count') - _offset(census, 'key')) // 8
    fields = ('sysreg', 'declined', 'first', 'logged', 'branches', 'entries', 'returns', 'reserved')
    return dict(context_offset=_offset(records['context'], 'perf'), size=_size(perf),
                fast=_offset(perf, 'fast'), census=_offset(perf, 'census'),
                root_index=_offset(perf, 'root_index'), canonical=_offset(perf, 'canonical'),
                fast_stride=_size(records['fast_trap_cpu']), census_stride=_size(census),
                census_slots=slots, census_key=_offset(census, 'key'),
                census_count=_offset(census, 'count'), census_total=_offset(census, 'total'),
                fast_classes=(_offset(fast, 'sysreg') - _offset(fast, 'handled')) // 8,
                fast_handled=_offset(fast, 'handled'), **{'fast_' + f: _offset(fast, f) for f in fields})


def read_spec(defines):
    lay = layout(defines)
    return lay['context_offset'], lay['size']


def register(key):
    iss = key - 1
    tup = ((iss >> 20) & 3, (iss >> 14) & 7, (iss >> 10) & 15, (iss >> 1) & 15, (iss >> 17) & 7)
    name = NAMES.get(tup, 'S%d_%d_C%d_C%d_%d' % tup)
    return name + (' read' if iss & 1 else ' write')


def decode(raw, defines=None, lay=None):
    lay = lay or layout(defines)
    if len(raw) != lay['size']:
        raise ValueError(f'expected {lay["size"]} bytes, got {len(raw)}')
    q = lambda off, n=1: struct.unpack_from(f'<{n}Q', raw, off)
    out = dict(fast=[], census=[])
    for cpu in range(6):
        base = lay['fast'] + cpu * lay['fast_stride']
        if lay['fast_classes'] != len(CLASSES):
            raise ValueError(f'monitor has {lay["fast_classes"]} fast classes, decoder knows {len(CLASSES)}')
        handled = q(base + lay['fast_handled'], lay['fast_classes'])
        sysreg, declined, first, logged, branches, entries, returns, reserved = (
            q(base + lay['fast_' + f])[0] for f in ('sysreg', 'declined', 'first', 'logged', 'branches',
                                                    'entries', 'returns', 'reserved'))
        if handled[0] or reserved or logged & ~LOG_BITS or first > declined:
            raise ValueError(f'fast cpu{cpu}: inconsistent fast-path counters')
        out['fast'].append(dict(cpu=cpu, handled=dict(zip(CLASSES[1:], handled[1:])),
                                total=sum(handled[1:]), sysreg=sysreg, declined=declined,
                                first=first, logged=logged, branches=branches,
                                entries=entries, returns=returns))
    for cpu in range(6):
        base = lay['census'] + cpu * lay['census_stride']
        slots = lay['census_slots']
        keys, counts = q(base + lay['census_key'], slots), q(base + lay['census_count'], slots)
        total, other, pacga, stored = q(base + lay['census_total'], 4)
        if any(bool(k) != bool(c) for k, c in zip(keys, counts)) or stored != sum(1 for k in keys if k):
            raise ValueError(f'census cpu{cpu}: occupied slots disagree with their counts')
        rows = sorted(((c, register(k)) for k, c in zip(keys, counts) if k), reverse=True)
        if sum(c for c, _ in rows) + other != total:
            raise ValueError(f'census cpu{cpu}: slot counts do not add up to the total')
        out['census'].append(dict(cpu=cpu, total=total, other=other, pacga=pacga, slots=slots,
                                  top=[dict(register=n, count=c) for c, n in rows]))
    names = ('count', 'overflow', 'notes', 'appended', 'overflows', 'max_count', 'flushes',
             'listed', 'scanned', 'verified', 'mismatches', 'txn_flushes', 'txn_listed',
             'txn_scanned')
    out['root_index'] = dict(zip(names, q(lay['root_index'], len(names))))
    names = ('calls', 'passed', 'leaves', 'walks', 'span_walks', 'sampled', 'mismatches')
    out['canonical_view'] = dict(zip(names, q(lay['canonical'], len(names))))
    fast = sum(r['total'] for r in out['fast'])
    out['summary'] = dict(fast_traps=fast, fast_sysreg=sum(r['sysreg'] for r in out['fast']),
                          declined=sum(r['declined'] for r in out['fast']),
                          fast_entries=sum(r['entries'] for r in out['fast']),
                          fast_returns=sum(r['returns'] for r in out['fast']),
                          vector_branches=sum(r['branches'] for r in out['fast']),
                          index_mismatches=out['root_index']['mismatches'],
                          canonical_mismatches=out['canonical_view']['mismatches'])
    return out


# The exit profile (compat/perf-state.h struct exit_profile): only in a monitor
# built with SNAP_FAST_EL0_SYSREG and/or SNAP_SERVICE_SUBCLASS. It lies past
# the define-free context size, so context.bin does not hold it; xnuboot_report
# copies it into report.bin behind a magic word and a word of build bits | size
# << 32, at probes/run.py EARLY_STOP_OFFSET + 8 * EARLY_STOP_STATE_WORDS.
EXIT_MAGIC = 0x31464f5250544958          # "XITPROF1"
EXIT_TIMING = CLASSES[1:] + ('kernel_fault', 'user_sync', 'timer_entry', 'device_entry',
                             'kernel_return', 'user_return', 'el0_sysreg')
EXIT_COUNT_SHIFT = 36
EL0_OUTCOMES = ('counter', 'uperm', 'declined_word', 'declined_guard')
SUB_NAMES = ('other', 'vector', 'el0_counter', 'el0_uperm', 'el0_uperm_write', 'call_other')
_RUN = {}


def _run():
    if not _RUN:
        _RUN.update(runpy.run_path(str(ROOT / 'probes/run.py'), run_name='perf_counters_run'))
    return _RUN


def exit_layout(defines=()):
    """The exit profile's offsets under the monitor's build defines."""
    records = _records(ROOT / 'probes/xnuboot.c', [d for d in defines if d.startswith('-D')])
    if 'exit_profile' not in records:
        raise ValueError('this monitor build has no exit profile '
                         '(SNAP_FAST_EL0_SYSREG and SNAP_SERVICE_SUBCLASS are off)')
    ep, sub, cpu = records['exit_profile'], records['service_sub_profile'], records['fast_exit_cpu']
    context = records['context']
    return dict(size=_size(ep), sub=_offset(ep, 'sub'), cpu=_offset(ep, 'cpu'), cpu_stride=_size(cpu),
                buckets=(_offset(sub, 'current') - _offset(sub, 'buckets')) // 24,
                current=_offset(sub, 'current'), el0=_offset(cpu, 'el0'), timing=_offset(cpu, 'timing'),
                classes=(_offset(cpu, 'slow') - _offset(cpu, 'timing')) // 8, slow=_offset(cpu, 'slow'),
                max=_offset(cpu, 'max'), context_offset=_offset(context, 'exit_profile'),
                context_size=_size(context))


def exit_profile_spec(defines):
    """(byte offset in report.bin, byte length) of the exit profile record."""
    words = int(re.search(r'#define EARLY_STOP_STATE_WORDS (\d+)',
                          (ROOT / 'compat/early-stop.h').read_text())[1])
    return _run()['EARLY_STOP_OFFSET'] + 8 * words, 16 + exit_layout(defines)['size']


def _sub_name(tag, endpoints):
    if tag < len(SUB_NAMES):
        return SUB_NAMES[tag]
    endpoint = tag - len(SUB_NAMES)
    return f'endpoint {endpoint:#04x} ' + endpoints.get(endpoint, 'not in SPTM\'s dispatch table')


def decode_exit_profile(record, defines=None, lay=None, cpus=None, perf=None, hz=None):
    """Decode the exit profile record (exit_profile_spec's bytes of report.bin).

    cpus: decoded service profiles (speed-test decoded.json "cpus") to check
    that the sub-class buckets refine EC 0x20 (hold exactly; entries and wait
    less the cancelled acquisitions). perf: decode()'s result, to check the
    exit counts against the fast-path counters. hz adds seconds."""
    lay = lay or exit_layout(defines)
    if len(record) != 16 + lay['size']:
        raise ValueError(f'expected {16 + lay["size"]} bytes, got {len(record)}')
    magic, bits = struct.unpack_from('<2Q', record, 0)
    if magic != EXIT_MAGIC or bits >> 32 != lay['size'] or bits & 0xfffffffc:
        raise ValueError('no exit profile record here (magic or size word differs)')
    el0_on, sub_on = bool(bits & 1), bool(bits & 2)
    body = record[16:]
    q = lambda off, n=1: struct.unpack_from(f'<{n}Q', body, off)
    if lay['classes'] != len(EXIT_TIMING):
        raise ValueError(f'monitor has {lay["classes"]} exit classes, decoder knows {len(EXIT_TIMING)}')
    try:
        endpoints = _run()['SPTM_ENDPOINTS']
    except Exception:   # names only
        endpoints = {}
    sub = []
    for tag in range(lay['buckets']):
        entries, wait, hold = q(lay['sub'] + 24 * tag, 3)
        if not entries and (wait or hold):
            raise ValueError(f'sub-class {tag}: time without entries')
        if entries:
            row = dict(tag=tag, name=_sub_name(tag, endpoints), entries=entries, wait_ticks=wait,
                       hold_ticks=hold)
            if hz:
                row.update(wait_seconds=wait / hz, hold_seconds=hold / hz,
                           hold_us_each=hold / hz / entries * 1e6)
            sub.append(row)
    current = list(body[lay['sub'] + lay['current']:][:8])
    out = dict(el0_sysreg=el0_on, subclass=sub_on, current=current,
               sub=sorted(sub, key=lambda r: r['hold_ticks'], reverse=True), cpus=[])
    tick_mask = (1 << EXIT_COUNT_SHIFT) - 1
    totals = {name: [0, 0] for name in EXIT_TIMING}
    for cpu in range(6):
        base = lay['cpu'] + cpu * lay['cpu_stride']
        el0 = dict(zip(EL0_OUTCOMES, q(base + lay['el0'], 4)))
        words = q(base + lay['timing'], lay['classes'])
        slow, longest = q(base + lay['slow'])[0], q(base + lay['max'])[0]
        timing = {}
        for name, word in zip(EXIT_TIMING, words):
            exits, ticks = word >> EXIT_COUNT_SHIFT, word & tick_mask
            if ticks > exits * longest:
                raise ValueError(f'exit cpu{cpu} {name}: ticks exceed exits x the longest exit')
            if exits:
                timing[name] = dict(exits=exits, ticks=ticks)
                totals[name][0] += exits
                totals[name][1] += ticks
        if (not el0_on and any(el0.values())) or (not sub_on and (timing or slow or longest)):
            raise ValueError(f'exit cpu{cpu}: counters of a define the build lacks')
        out['cpus'].append(dict(cpu=cpu, el0=el0, timing=timing, slow=slow, max_ticks=longest))
    if not sub_on and (sub or any(current)):
        raise ValueError('sub-class buckets in a build without SNAP_SERVICE_SUBCLASS')
    summary = dict(el0={k: sum(c['el0'][k] for c in out['cpus']) for k in EL0_OUTCOMES},
                   sub_entries=sum(r['entries'] for r in sub), sub_hold_ticks=sum(r['hold_ticks'] for r in sub),
                   sub_wait_ticks=sum(r['wait_ticks'] for r in sub),
                   slow=sum(c['slow'] for c in out['cpus']),
                   max_ticks=max(c['max_ticks'] for c in out['cpus']),
                   timing={name: dict(exits=e, ticks=t, mean_ticks=t / e) for name, (e, t) in totals.items() if e})
    if hz:
        for row in summary['timing'].values():
            row['mean_ns'] = row['mean_ticks'] / hz * 1e9
    if cpus is not None and sub_on:
        rows = [b for c in cpus if not c.get('idle') for b in c['buckets'] if b['category'] == 0x20]
        entries, wait, hold = (sum(b[k] for b in rows) for k in ('entries', 'wait_ticks', 'hold_ticks'))
        cancelled = sum(c.get('cancelled', 0) for c in cpus if not c.get('idle'))
        if (hold != summary['sub_hold_ticks'] or not 0 <= entries - summary['sub_entries'] <= cancelled or
                wait < summary['sub_wait_ticks']):
            raise ValueError('sub-class buckets do not refine the EC 0x20 profile')
        summary['ec20'] = dict(entries=entries, wait_ticks=wait, hold_ticks=hold)
    if perf is not None:
        for cpu, (fast, ours) in enumerate(zip(perf['fast'], out['cpus'])):
            for cls, handled in fast['handled'].items():
                if ours['timing'].get(cls, {}).get('exits', 0) > handled:
                    raise ValueError(f'exit cpu{cpu} {cls}: more timed exits than handled')
            crossed = sum(ours['timing'].get(n, {}).get('exits', 0) for n in EXIT_TIMING[len(CLASSES) - 1:])
            emulated = ours['el0']['counter'] + ours['el0']['uperm']
            if crossed > fast['entries'] + fast['returns'] or emulated > fast['entries']:
                raise ValueError(f'exit cpu{cpu}: more boundary exits than the fast path counted')
    out['summary'] = summary
    return out


# SNAP_FINE_LOCKS (compat/fine-lock.h struct fine_profile, docs/FINE-LOCKS-20261017.md):
# each CPU's converted-call profile, right after the exit profile record in
# report.bin, behind "FINELCK1" and a word of SNAP_FINE_SWITCH | SNAP_FAST_PAUTH_CALLS << 1 |
# profile bytes << 32. SNAP_FAST_PAUTH_CALLS appends the two pointer-call buckets; SNAP_TOKEN_TRIM
# (compat/token-trim.h, which requires the pointer calls) or SNAP_DART_CONVERTED (compat/dart-converted.h, its
# part B on its own) the two Adreno DART buckets after them, and bit 2.
FINE_MAGIC = 0x314b434c454e4946          # "FINELCK1"
FINE_CALLS = ('update_disjoint', 'map_page', 'unmap_region', 'switch_hit', 'switch_kernel')
FINE_PAUTH_CALLS = ('pauth', 'pauth_batch')
FINE_DART_CALLS = ('dart_map', 'dart_unmap')
FINE_DECLINES = ('gate', 'state', 'shape', 'root', 'arena', 'engine', 'alloc', 'inactive', 'switch')
# SNAP_SPTM_FINE (agents/sptm-locks, compat/fine-lock.h): five more kinds after every earlier one and two more
# decline reasons, and header bit 3.
FINE_SPTM_CALLS = ('unmap_disjoint', 'update_region', 'retype', 'kernel_map', 'kernel_unmap')
FINE_SPTM_DECLINES = ('frame', 'copied')
# SNAP_ANS_CONVERTED (agents/nvme-async, compat/fine-lock.h): the virtual ANS2's converted MMIO doorbells and
# table-6 MAP/UNMAP_PAGES after every earlier kind, the busy decline after every earlier reason, and header bit 4.
FINE_ANS_CALLS = ('ans_mmio', 'ans_sptm')
FINE_ANS_DECLINES = ('busy',)
FINE_BUCKET = ('entries', 'gate_wait', 'stripe_wait', 'aux_wait', 'hold', 'contended')


def fine_layout(defines=()):
    records = _records(ROOT / 'probes/xnuboot.c', [d for d in defines if d.startswith('-D')])
    if 'fine_profile' not in records:
        raise ValueError('this monitor build has no fine profile (SNAP_FINE_LOCKS is off)')
    prof, bucket = records['fine_profile'], records['fine_bucket']
    lay = dict(size=_size(prof), call=_offset(prof, 'call'), declined=_offset(prof, 'declined'),
               aux_entries=_offset(prof, 'aux_entries'), aux_contended=_offset(prof, 'aux_contended'),
               failures=_offset(prof, 'failures'), bucket=_size(bucket))
    buckets = (lay['declined'] - lay['call']) // lay['bucket']
    sptm = '-DSNAP_SPTM_FINE=1' in defines
    ans = '-DSNAP_ANS_CONVERTED=1' in defines
    layouts = (FINE_CALLS, FINE_CALLS + FINE_PAUTH_CALLS, FINE_CALLS + FINE_PAUTH_CALLS + FINE_DART_CALLS)
    if sptm:
        layouts = tuple(names + FINE_SPTM_CALLS for names in layouts)
    if ans:
        layouts = tuple(names + FINE_ANS_CALLS for names in layouts)
    lay['calls'] = next((names for names in layouts if len(names) == buckets), ())
    lay['declines'] = FINE_DECLINES + (FINE_SPTM_DECLINES if sptm else ()) + (FINE_ANS_DECLINES if ans else ())
    if not lay['calls'] or \
            (lay['aux_entries'] - lay['declined']) // 8 != len(lay['declines']) or lay['bucket'] != 8 * len(FINE_BUCKET):
        raise ValueError('fine profile layout differs from the decoder')
    return lay


def fine_profile_spec(defines):
    """(byte offset in report.bin, byte length) of the fine profile record."""
    offset, size = exit_profile_spec(defines)
    return offset + size, 16 + 6 * fine_layout(defines)['size']


def decode_fine_profile(record, defines=None, lay=None, hz=None):
    lay = lay or fine_layout(defines)
    if len(record) != 16 + 6 * lay['size']:
        raise ValueError(f'expected {16 + 6 * lay["size"]} bytes, got {len(record)}')
    magic, bits = struct.unpack_from('<2Q', record, 0)
    if magic != FINE_MAGIC or bits >> 32 != lay['size'] or bits & 0xffffffe0:
        raise ValueError('no fine profile record here (magic or size word differs)')
    names = lay.get('calls', FINE_CALLS)
    declines = lay.get('declines', FINE_DECLINES)
    ans = names[-len(FINE_ANS_CALLS):] == FINE_ANS_CALLS
    if bool(bits & 16) != ans:
        raise ValueError('fine profile: the SNAP_ANS_CONVERTED bit and the bucket layout disagree')
    if ans:
        names = names[:-len(FINE_ANS_CALLS)]
    sptm = names[-len(FINE_SPTM_CALLS):] == FINE_SPTM_CALLS
    if bool(bits & 8) != sptm:
        raise ValueError('fine profile: the SNAP_SPTM_FINE bit and the bucket layout disagree')
    if sptm:
        names = names[:-len(FINE_SPTM_CALLS)]
    if bool(bits & 2) != (names[len(FINE_CALLS):len(FINE_CALLS) + len(FINE_PAUTH_CALLS)] == FINE_PAUTH_CALLS):
        raise ValueError('fine profile: the SNAP_FAST_PAUTH_CALLS bit and the bucket layout disagree')
    if bool(bits & 4) != (names[-len(FINE_DART_CALLS):] == FINE_DART_CALLS):
        raise ValueError('fine profile: the DART bit (SNAP_TOKEN_TRIM or SNAP_DART_CONVERTED) and the bucket layout disagree')
    if sptm:
        names = names + FINE_SPTM_CALLS
    if ans:
        names = names + FINE_ANS_CALLS
    out = dict(switch=bool(bits & 1), pauth=bool(bits & 2), cpus=[], calls={},
               declined={k: 0 for k in declines})
    if bits & 4:
        out['dart'] = True
    if sptm:
        out['sptm_fine'] = True
    if ans:
        out['ans_converted'] = True
    totals = {name: dict.fromkeys(FINE_BUCKET, 0) for name in names}
    for cpu in range(6):
        base = 16 + cpu * lay['size']
        calls = {}
        for i, name in enumerate(names):
            row = dict(zip(FINE_BUCKET, struct.unpack_from('<6Q', record, base + lay['call'] + i * lay['bucket'])))
            if not row['entries'] and any(row[k] for k in FINE_BUCKET[1:]):
                raise ValueError(f'fine cpu{cpu} {name}: time without entries')
            if row['contended'] > row['entries']:
                raise ValueError(f'fine cpu{cpu} {name}: more contended than entries')
            if row['entries']:
                calls[name] = row
                for k in FINE_BUCKET:
                    totals[name][k] += row[k]
        declined = dict(zip(declines, struct.unpack_from(f'<{len(declines)}Q', record,
                                                          base + lay['declined'])))
        for k, v in declined.items():
            out['declined'][k] += v
        aux, aux_contended, failures = struct.unpack_from('<3Q', record, base + lay['aux_entries'])
        if aux_contended > aux:
            raise ValueError(f'fine cpu{cpu}: more contended aux entries than entries')
        out['cpus'].append(dict(cpu=cpu, calls=calls, declined=declined, aux_entries=aux,
                                aux_contended=aux_contended, failures=failures))
    for name, row in totals.items():
        if row['entries']:
            if hz:
                row.update({k + '_seconds': row[k] / hz for k in FINE_BUCKET[1:5]},
                           hold_us_each=row['hold'] / hz / row['entries'] * 1e6)
            out['calls'][name] = row
    return out


# SNAP_NEST_FAST, SNAP_DETACH_FAST, SNAP_ROOT_INDEX, SNAP_OTHER_PROFILE and
# SNAP_GATE_WAIT (compat/token-costs.h struct token_costs_report,
# docs/TOKEN-COSTS-20261018.md): one define-free record behind "TOKCOST1" and a
# word of define bits | bytes << 32, after the fine profile (or the exit
# profile without SNAP_FINE_LOCKS). A part whose define is off reads zero.
# Bit 5 (SNAP_PHASE_FAIR_GATE, compat/service-lock.h, only with bit 4) adds
# gate[4..6]: converted calls that entered ahead of a queued writer, token
# drains that waited, and their ticks.
TOKEN_MAGIC = 0x3154534f434b4f54         # "TOKCOST1"
TOKEN_DEFINES = ('-DSNAP_NEST_FAST=1', '-DSNAP_DETACH_FAST=1', '-DSNAP_ROOT_INDEX=1',
                 '-DSNAP_OTHER_PROFILE=1', '-DSNAP_GATE_WAIT=1')
TOKEN_WORDS = 96
NEST_FIELDS = ('nest_tables', 'nest_hits', 'nest_scans', 'nest_records', 'nest_walked',
               'unnest_tables', 'unnest_hits', 'unnest_scans', 'unnest_records', 'unnest_walked',
               'sampled', 'mismatches', 'detach_fast', 'detach_slow',
               'unnest_counted')   # SNAP_UNNEST_4K_FAST (compat/nest-fast.h 3); a reserved zero without it
INDEX_FIELDS = ('built', 'live', 'full', 'lookups', 'scans', 'audits', 'mismatches', 'notes', 'builds')
OTHER_CLASSES = ('txm35', 'txm36', 'txm37', 'txm', 'dart_map_table', 'dart_map', 'dart_unmap',
                 'dart_enable', 'dart_control', 'ans_sart', 'ans_nvme', 'uat', 'cputrace',
                 'endpoint_high', 'dispatch', 'unknown')
GATE_FIELDS = ('waited', 'wait_ticks', 'timeouts', 'stopped')
PHASE_GATE_FIELDS = ('phase_entries', 'drains', 'drain_ticks')


def token_costs_spec(defines):
    """(byte offset in report.bin, byte length) of the token-cost record."""
    offset, size = fine_profile_spec(defines) if '-DSNAP_FINE_LOCKS=1' in defines else exit_profile_spec(defines)
    return offset + size, 16 + 8 * TOKEN_WORDS


def decode_token_costs(record, hz=None, call_other=None):
    """call_other: the exit profile's call_other row, which the other-call
    classes must sum to exactly (entries, wait and hold) when they are on."""
    if len(record) != 16 + 8 * TOKEN_WORDS:
        raise ValueError(f'expected {16 + 8 * TOKEN_WORDS} bytes, got {len(record)}')
    magic, bits = struct.unpack_from('<2Q', record, 0)
    if magic != TOKEN_MAGIC or bits >> 32 != 8 * TOKEN_WORDS or bits & 0xffffffc0 or not bits & 0x1f or \
            (bits & 0x20 and not bits & 0x10):
        raise ValueError('no token-cost record here (magic or size word differs)')
    w = struct.unpack_from(f'<{TOKEN_WORDS}Q', record, 16)
    on = dict(zip(('nest_fast', 'detach_fast', 'root_index', 'other_profile', 'gate_wait'),
                  (bool(bits >> i & 1) for i in range(5))))
    if bits & 0x20:
        on['phase_fair_gate'] = True   # only when set, so earlier records decode exactly as before
    out = dict(defines=on)
    if on['nest_fast'] or on['detach_fast']:
        nest = dict(zip(NEST_FIELDS, w[0:len(NEST_FIELDS)]))
        if nest['mismatches']:
            raise ValueError('nest-fast: a sampled rescan disagreed with a retained verdict')
        if nest['nest_hits'] + nest['nest_scans'] > nest['nest_tables'] or \
                nest['unnest_hits'] + nest['unnest_scans'] > nest['unnest_tables'] or \
                nest['nest_records'] > nest['nest_scans'] or nest['unnest_records'] > nest['unnest_scans'] or \
                nest['unnest_counted'] > nest['unnest_hits']:
            raise ValueError('nest-fast: inconsistent table accounting')
        out['nest'] = nest
    if on['root_index']:
        index = dict(zip(INDEX_FIELDS, w[16:16 + len(INDEX_FIELDS)]))
        if index['mismatches']:
            raise ValueError('root index: a sampled scan disagreed with the index')
        out['root_index'] = index
    if on['other_profile']:
        other, total = {}, [0, 0, 0]
        for i, name in enumerate(OTHER_CLASSES):
            entries, wait, hold = w[32 + 3 * i:35 + 3 * i]
            if not entries and (wait or hold):
                raise ValueError(f'other-call {name}: time without entries')
            total = [total[0] + entries, total[1] + wait, total[2] + hold]
            if entries:
                row = dict(entries=entries, wait_ticks=wait, hold_ticks=hold)
                if hz:
                    row.update(wait_seconds=wait / hz, hold_seconds=hold / hz, hold_us_each=hold / hz / entries * 1e6)
                other[name] = row
        if call_other is not None and total != [call_other['entries'], call_other['wait_ticks'],
                                                call_other['hold_ticks']]:
            raise ValueError('other-call classes do not sum to the call_other bucket')
        out['other'] = dict(sorted(other.items(), key=lambda kv: kv[1]['hold_ticks'], reverse=True))
    if on['gate_wait']:
        gate = dict(zip(GATE_FIELDS, w[80:80 + len(GATE_FIELDS)]))
        if on.get('phase_fair_gate'):
            gate.update(zip(PHASE_GATE_FIELDS, w[84:84 + len(PHASE_GATE_FIELDS)]))
            if gate['phase_entries'] > gate['waited'] or (gate['drain_ticks'] and not gate['drains']):
                raise ValueError('phase-fair gate: phase entries exceed waited entries, or drain time without drains')
        if hz:
            gate['wait_seconds'] = gate['wait_ticks'] / hz
            if 'drain_ticks' in gate:
                gate['drain_seconds'] = gate['drain_ticks'] / hz
        out['gate'] = gate
    return out


# SNAP_FAST_TIMER_IRQ (compat/fast-timer-irq.h struct fast_irq_cpu, probes/xnuboot.c OUT_FAST_IRQ): each CPU's
# IRQ-entry outcomes and lock-free tick time, behind "FASTIRQ1" and a word of SNAP_WFI_RESUME | per-CPU bytes
# << 32, after the last exit-profile record (the token costs, else the fine profile, else the exit profile).
FAST_IRQ_MAGIC = 0x3151524954534146       # "FASTIRQ1"
FAST_IRQ_DEFINE = '-DSNAP_FAST_TIMER_IRQ=1'
FAST_IRQ_CPU0_DEFINE = '-DSNAP_FAST_TIMER_IRQ_CPU0=1'   # docs/SPEED-BATCH4-20261020.md
FAST_IRQ_RESULTS = ('handled', 'cpu0', 'not_timer', 'state', 'device', 'deadline', 'other')


def fast_irq_layout(defines=()):
    records = _records(ROOT / 'probes/xnuboot.c', [d for d in defines if d.startswith('-D')])
    if 'fast_irq_cpu' not in records:
        raise ValueError('this monitor build has no fast timer-IRQ counters (SNAP_FAST_TIMER_IRQ is off)')
    r = records['fast_irq_cpu']
    lay = dict(size=_size(r), result=_offset(r, 'result'), resumed=_offset(r, 'resumed'), ticks=_offset(r, 'ticks'),
               max=_offset(r, 'max'), reserved=_offset(r, 'reserved'))
    if (lay['resumed'] - lay['result']) // 8 != len(FAST_IRQ_RESULTS) or lay['size'] != 128:
        raise ValueError('fast timer-IRQ counter layout differs from the decoder')
    return lay


def fast_irq_spec(defines):
    """(byte offset in report.bin, byte length) of the fast timer-IRQ record."""
    if any(d in defines for d in TOKEN_DEFINES):
        offset, size = token_costs_spec(defines)
    elif '-DSNAP_FINE_LOCKS=1' in defines:
        offset, size = fine_profile_spec(defines)
    else:
        offset, size = exit_profile_spec(defines)
    return offset + size, 16 + 6 * fast_irq_layout(defines)['size']


def decode_fast_irq(record, defines=None, lay=None, hz=None, cpus=None):
    """cpus: decoded service profiles (speed-test decoded.json "cpus"): each CPU's
    category-64 (IRQ) entries must equal its IRQ entries the fast tick declined."""
    lay = lay or fast_irq_layout(defines)
    if len(record) != 16 + 6 * lay['size']:
        raise ValueError(f'expected {16 + 6 * lay["size"]} bytes, got {len(record)}')
    magic, bits = struct.unpack_from('<2Q', record, 0)
    if magic != FAST_IRQ_MAGIC or bits >> 32 != lay['size'] or bits & 0xfffffffe:
        raise ValueError('no fast timer-IRQ record here (magic or size word differs)')
    wfi = bool(bits & 1)
    out = dict(wfi_resume=wfi, cpus=[])
    totals = dict.fromkeys(FAST_IRQ_RESULTS, 0)
    for cpu in range(6):
        base = 16 + cpu * lay['size']
        result = dict(zip(FAST_IRQ_RESULTS, struct.unpack_from(f'<{len(FAST_IRQ_RESULTS)}Q', record,
                                                               base + lay['result'])))
        resumed, ticks, longest = (struct.unpack_from('<Q', record, base + lay[k])[0]
                                   for k in ('resumed', 'ticks', 'max'))
        reserved = struct.unpack_from(f'<{(lay["size"] - lay["reserved"]) // 8}Q', record, base + lay['reserved'])
        if any(reserved):
            raise ValueError(f'fast irq cpu{cpu}: reserved words are not zero')
        # SNAP_FAST_TIMER_IRQ_CPU0: vCPU 0 also takes the tick while nothing of its own is due.
        cpu0_quiet = FAST_IRQ_CPU0_DEFINE in (defines or ())
        if ((not cpu0_quiet and sum(result.values()) != result['cpu0']) if cpu == 0 else result['cpu0']):
            raise ValueError(f'fast irq cpu{cpu}: vCPU 0 declines every IRQ as cpu0, no other CPU does')
        if resumed > result['handled'] or (resumed and not wfi) or ticks > result['handled'] * longest or \
                (not result['handled'] and (ticks or longest)):
            raise ValueError(f'fast irq cpu{cpu}: inconsistent handled-tick counters')
        locked = sum(result.values()) - result['handled']
        row = dict(cpu=cpu, result=result, locked=locked, resumed=resumed, ticks=ticks, max_ticks=longest)
        if hz and result['handled']:
            row.update(seconds=ticks / hz, mean_ns=ticks / hz / result['handled'] * 1e9)
        out['cpus'].append(row)
        for k, v in result.items():
            totals[k] += v
    if cpus is not None:
        for c in cpus:
            if c.get('idle'):
                continue
            slot = c.get('slot', c.get('cpu'))
            entries = sum(b['entries'] for b in c['buckets'] if b['category'] == 64)
            if entries != out['cpus'][slot]['locked']:
                raise ValueError(f'fast irq cpu{slot}: {entries} locked IRQ entries in the service profile, '
                                 f'{out["cpus"][slot]["locked"]} declined here')
    handled = totals['handled']
    out['summary'] = dict(result=totals, locked=sum(totals.values()) - handled,
                          resumed=sum(c['resumed'] for c in out['cpus']),
                          ticks=sum(c['ticks'] for c in out['cpus']),
                          max_ticks=max(c['max_ticks'] for c in out['cpus']))
    if hz and handled:
        out['summary'].update(seconds=out['summary']['ticks'] / hz,
                              mean_ns=out['summary']['ticks'] / hz / handled * 1e9)
    return out


# SNAP_FAST_IPI (compat/fast-ipi.h struct fast_ipi_cpu, probes/xnuboot.c OUT_FAST_IPI): each CPU's IPI-register
# outcomes and lock-free time, behind "FASTIPI1" and a word of per-CPU bytes << 32, at a fixed place just below the
# thermal block (report.bin byte 16 + 8 * OUT_THERMAL = 16 + A16_THERMAL_REPORT_OFFSET, tools/a16_thermal.py).
FAST_IPI_MAGIC = 0x3149504954534146       # "FASTIPI1"
FAST_IPI_DEFINE = '-DSNAP_FAST_IPI=1'
FAST_IPI_RESULTS = ('sr_read', 'sr_write', 'request_local', 'request_global', 'state', 'refused', 'target')
FAST_IPI_HANDLED = 4


def fast_ipi_layout(defines=()):
    records = _records(ROOT / 'probes/xnuboot.c', [d for d in defines if d.startswith('-D')])
    if 'fast_ipi_cpu' not in records:
        raise ValueError('this monitor build has no fast IPI counters (SNAP_FAST_IPI is off)')
    r = records['fast_ipi_cpu']
    lay = dict(size=_size(r), result=_offset(r, 'result'), ticks=_offset(r, 'ticks'), max=_offset(r, 'max'),
               reserved=_offset(r, 'reserved'))
    if (lay['ticks'] - lay['result']) // 8 != len(FAST_IPI_RESULTS) or lay['size'] != 128:
        raise ValueError('fast IPI counter layout differs from the decoder')
    return lay


def fast_ipi_spec(defines):
    """(byte offset in report.bin, byte length) of the fast IPI record."""
    thermal = int(re.search(r'#define A16_THERMAL_REPORT_OFFSET (0x[0-9a-f]+)u',
                            (ROOT / 'compat/a16-thermal.h').read_text())[1], 16)
    size = 16 + 6 * fast_ipi_layout(defines)['size']
    return 16 + thermal - size, size


def decode_fast_ipi(record, defines=None, lay=None, hz=None):
    lay = lay or fast_ipi_layout(defines)
    if len(record) != 16 + 6 * lay['size']:
        raise ValueError(f'expected {16 + 6 * lay["size"]} bytes, got {len(record)}')
    magic, bits = struct.unpack_from('<2Q', record, 0)
    if magic != FAST_IPI_MAGIC or bits != lay['size'] << 32:
        raise ValueError('no fast IPI record here (magic or size word differs)')
    out = dict(cpus=[])
    totals = dict.fromkeys(FAST_IPI_RESULTS, 0)
    for cpu in range(6):
        base = 16 + cpu * lay['size']
        result = dict(zip(FAST_IPI_RESULTS, struct.unpack_from(f'<{len(FAST_IPI_RESULTS)}Q', record,
                                                               base + lay['result'])))
        ticks, longest = (struct.unpack_from('<Q', record, base + lay[k])[0] for k in ('ticks', 'max'))
        reserved = struct.unpack_from(f'<{(lay["size"] - lay["reserved"]) // 8}Q', record, base + lay['reserved'])
        if any(reserved):
            raise ValueError(f'fast ipi cpu{cpu}: reserved words are not zero')
        handled = sum(result[k] for k in FAST_IPI_RESULTS[:FAST_IPI_HANDLED])
        if ticks > handled * longest or (not handled and (ticks or longest)):
            raise ValueError(f'fast ipi cpu{cpu}: inconsistent handled counters')
        row = dict(cpu=cpu, result=result, handled=handled, declined=sum(result.values()) - handled,
                   ticks=ticks, max_ticks=longest)
        if hz and handled:
            row.update(seconds=ticks / hz, mean_ns=ticks / hz / handled * 1e9)
        out['cpus'].append(row)
        for k, v in result.items():
            totals[k] += v
    handled = sum(c['handled'] for c in out['cpus'])
    out['summary'] = dict(result=totals, handled=handled, declined=sum(totals.values()) - handled,
                          ticks=sum(c['ticks'] for c in out['cpus']),
                          max_ticks=max(c['max_ticks'] for c in out['cpus']))
    if hz and handled:
        out['summary'].update(seconds=out['summary']['ticks'] / hz,
                              mean_ns=out['summary']['ticks'] / hz / handled * 1e9)
    return out


# SNAP_DART_MEMO (compat/sptm-dart-memo.h struct sptm_dart_memo_stats, then live; probes/xnuboot.c OUT_DART_MEMO):
# behind "DARTMEM1" and a word of stats bytes << 32, at a fixed place: the 11 words below the 98 that SNAP_FAST_IPI's
# record takes just under the thermal block (report.bin byte 16 + 8 * OUT_THERMAL, tools/a16_thermal.py).
DART_MEMO_MAGIC = 0x314d454d54524144      # "DARTMEM1"
DART_MEMO_DEFINE = '-DSNAP_DART_MEMO=1'
DART_MEMO_STATS = ('lookups', 'hits', 'misses', 'records', 'invalidations', 'flushes', 'sampled', 'mismatches')


def dart_memo_spec():
    """(byte offset in report.bin, byte length) of the DART memo record."""
    thermal = int(re.search(r'#define A16_THERMAL_REPORT_OFFSET (0x[0-9a-f]+)u',
                            (ROOT / 'compat/a16-thermal.h').read_text())[1], 16)
    size = 8 * (2 + len(DART_MEMO_STATS) + 1)
    return 16 + thermal - 8 * 98 - size, size


def decode_dart_memo(record):
    if len(record) != 8 * (3 + len(DART_MEMO_STATS)):
        raise ValueError(f'expected {8 * (3 + len(DART_MEMO_STATS))} bytes, got {len(record)}')
    words = struct.unpack(f'<{3 + len(DART_MEMO_STATS)}Q', record)
    if words[0] != DART_MEMO_MAGIC or words[1] != (8 * len(DART_MEMO_STATS)) << 32:
        raise ValueError('no DART memo record here (magic or size word differs)')
    out = dict(zip(DART_MEMO_STATS, words[2:2 + len(DART_MEMO_STATS)]))
    out['live'] = words[-1]
    if out['hits'] + out['misses'] != out['lookups'] or out['sampled'] > out['hits'] or \
            out['mismatches'] > out['sampled'] or out['records'] < out['live']:
        raise ValueError('inconsistent DART memo counters')
    out['hit_rate'] = out['hits'] / out['lookups'] if out['lookups'] else 0.0
    return out


# SNAP_TOKEN_TRIM (compat/token-trim.h struct token_trim_stats; probes/xnuboot.c OUT_TOKEN_TRIM): the kernel
# refresh's witnessed reuse hits and the converted Adreno DART calls' device lock, behind "TOKTRIM1" and a word of
# stats bytes << 32, at a fixed place: the 18 words just below the DART memo's slot (used or not).
TOKEN_TRIM_MAGIC = 0x314d4952544b4f54     # "TOKTRIM1"
TOKEN_TRIM_DEFINE = '-DSNAP_TOKEN_TRIM=1'
TOKEN_TRIM_STATS = ('asks', 'witnessed', 'sampled', 'mismatches', 'stale', 'unproven', 'proofs',
                    'dart_maps', 'dart_unmaps', 'dart_declines', 'device_entries', 'device_contended',
                    'device_wait')
TOKEN_TRIM_WORDS = 16


def token_trim_spec():
    """(byte offset in report.bin, byte length) of the token-trim record."""
    offset, _ = dart_memo_spec()
    size = 8 * (2 + TOKEN_TRIM_WORDS)
    return offset - size, size


def decode_token_trim(record, hz=None):
    if len(record) != 8 * (2 + TOKEN_TRIM_WORDS):
        raise ValueError(f'expected {8 * (2 + TOKEN_TRIM_WORDS)} bytes, got {len(record)}')
    words = struct.unpack(f'<{2 + TOKEN_TRIM_WORDS}Q', record)
    if words[0] != TOKEN_TRIM_MAGIC or words[1] != (8 * TOKEN_TRIM_WORDS) << 32:
        raise ValueError('no token-trim record here (magic or size word differs)')
    out = dict(zip(TOKEN_TRIM_STATS, words[2:2 + len(TOKEN_TRIM_STATS)]))
    if any(words[2 + len(TOKEN_TRIM_STATS):]):
        raise ValueError('token-trim: reserved words are not zero')
    # Every ask is answered by the witness alone, by a sampled witness answer, or by the exact path (stale or
    # unproven); a sampled one counts as witnessed too. A mismatch is terminal in the monitor: the run stopped on it.
    if out['witnessed'] + out['stale'] + out['unproven'] != out['asks'] or out['sampled'] > out['witnessed'] or \
            out['mismatches'] > out['sampled'] or out['device_contended'] > out['device_entries'] or \
            out['dart_maps'] + out['dart_unmaps'] + out['dart_declines'] > out['device_entries'] or \
            (out['device_wait'] and not out['device_contended']):
        raise ValueError('inconsistent token-trim counters')
    if out['mismatches']:
        raise ValueError(f'token-trim: {out["mismatches"]} witnessed answers disagreed with the exact compare')
    out['witness_rate'] = out['witnessed'] / out['asks'] if out['asks'] else 0.0
    if hz:
        out['device_wait_seconds'] = out['device_wait'] / hz
    return out


# SNAP_ADRENO_IB_ASYNC (compat/adreno-ib.h struct adreno_ib_flight; probes/xnuboot.c OUT_IB_ASYNC): the IB flight as
# the stop left it (after the stop drained it) and its counters, behind "IBASYNC1" and a word of flight bytes << 32 |
# ADRENO_IB_POLL_DIVISOR, at a fixed place: the 38 words just below the token-trim slot (used or not).
IB_ASYNC_MAGIC = 0x31434e5953414249       # "IBASYNC1"
IB_ASYNC_DEFINE = '-DSNAP_ADRENO_IB_ASYNC=1'
IB_ASYNC_FIELDS = ('active', 'marker', 'start', 'va', 'dwords', 'bytes', 'wptr', 'reads', 'tlbi_base',
                   'tlbi_timeout_base', 'last_marker', 'last_status', 'last_ticks', 'last_wptr',
                   'starts', 'flights', 'polls', 'poll_pending', 'finished', 'abandoned', 'stopped', 'ok', 'gpu_errors',
                   'uncertain', 'idle', 'mismatched', 'poll_refused', 'refused', 'tlbi', 'tlbi_timeouts', 'max_ticks',
                   'sum_ticks', 'max_reads')
IB_ASYNC_WORDS = 36


def ib_async_spec():
    """(byte offset in report.bin, byte length) of the IB async record."""
    offset, _ = token_trim_spec()
    size = 8 * (2 + IB_ASYNC_WORDS)
    return offset - size, size


# SNAP_ADRENO_RECOVER (agents/gpu-recovery): the flight's three reserved words count flights past the soft budget, flights
# ended by hang evidence, and the GPU resets (compat/adreno-ib.h).
IB_ASYNC_RECOVER_FIELDS = ('recover_overdue', 'recover_evidence', 'recover_resets')


def decode_ib_async(record, hz=None, recover=False):
    if len(record) != 8 * (2 + IB_ASYNC_WORDS):
        raise ValueError(f'expected {8 * (2 + IB_ASYNC_WORDS)} bytes, got {len(record)}')
    words = struct.unpack(f'<{2 + IB_ASYNC_WORDS}Q', record)
    if words[0] != IB_ASYNC_MAGIC or words[1] >> 32 != 8 * IB_ASYNC_WORDS or not words[1] & 0xffffffff:
        raise ValueError('no IB async record here (magic or size word differs)')
    out = dict(zip(IB_ASYNC_FIELDS, words[2:2 + len(IB_ASYNC_FIELDS)]))
    if recover:
        out.update(zip(IB_ASYNC_RECOVER_FIELDS, words[2 + len(IB_ASYNC_FIELDS):]))
    elif any(words[2 + len(IB_ASYNC_FIELDS):]):
        raise ValueError('IB async: reserved words are not zero')
    out['last_status'] = struct.unpack('<q', struct.pack('<Q', out['last_status']))[0]
    out['poll_divisor'] = words[1] & 0xffffffff
    # Every flight ended exactly once (the stop drains the last one), with one of three outcomes; every POLL got
    # exactly one of five answers.
    ended = out['finished'] + out['abandoned'] + out['stopped']
    if out['active'] or out['flights'] != ended or out['ok'] + out['gpu_errors'] + out['uncertain'] != ended or \
            out['flights'] > out['starts'] or \
            out['poll_pending'] + out['finished'] + out['idle'] + out['mismatched'] + out['poll_refused'] != out['polls'] or \
            out['sum_ticks'] < out['max_ticks'] or (ended and not out['max_reads']):
        raise ValueError('inconsistent IB async counters')
    out['start_final'] = out['starts'] - out['flights']
    out['polls_per_flight'] = out['polls'] / out['flights'] if out['flights'] else 0.0
    if hz:
        out['max_flight_ms'] = 1e3 * out['max_ticks'] / hz
        out['mean_flight_ms'] = 1e3 * out['sum_ticks'] / hz / out['flights'] if out['flights'] else 0.0
        out['budget_ms'] = 1e3 / out['poll_divisor']
    return out


# SNAP_VIEW_RECLAIM (shadow/sprr-view.h; probes/xnuboot.c OUT_VIEW_RECLAIM): the kernel views' pool -- tables in use,
# the highest count, reclaims that retired tables and how many, refusals that found nothing to retire, the capacity --
# behind "VIEWRCL1" and a word of value bytes << 32, at a fixed place: the 8 words just below the IB async slot
# (used or not).
VIEW_RECLAIM_MAGIC = 0x314c435257454956   # "VIEWRCL1"
VIEW_RECLAIM_DEFINE = '-DSNAP_VIEW_RECLAIM=1'
VIEW_RECLAIM_FIELDS = ('count', 'high_water', 'reclaims', 'retired', 'full', 'capacity')


def view_reclaim_spec():
    """(byte offset in report.bin, byte length) of the view reclaim record."""
    offset, _ = ib_async_spec()
    size = 8 * (2 + len(VIEW_RECLAIM_FIELDS))
    return offset - size, size


def decode_view_reclaim(record):
    n = len(VIEW_RECLAIM_FIELDS)
    if len(record) != 8 * (2 + n):
        raise ValueError(f'expected {8 * (2 + n)} bytes, got {len(record)}')
    words = struct.unpack(f'<{2 + n}Q', record)
    if words[0] != VIEW_RECLAIM_MAGIC or words[1] != (8 * n) << 32:
        raise ValueError('no view reclaim record here (magic or size word differs)')
    out = dict(zip(VIEW_RECLAIM_FIELDS, words[2:]))
    # The root is never retired; every reclaim retires at least one table.
    if not 1 <= out['count'] <= out['high_water'] <= out['capacity'] or out['capacity'] != 256 or \
            out['retired'] < out['reclaims']:
        raise ValueError('inconsistent view reclaim counters')
    out['free'] = out['capacity'] - out['count']
    return out


def decode_report(report, defines, hz=None):
    """report.bin's records for a SNAP_FAST_EL0_SYSREG / SNAP_SERVICE_SUBCLASS monitor: the exit profile,
    then (as its defines have them) the converted-call profile, the token costs, the fast IRQ and fast IPI
    outcomes, the DART memo, the token-trim record, the IB flight and the kernel views' pool."""
    offset, size = exit_profile_spec(defines)
    out = decode_exit_profile(report[offset:offset + size], defines, hz=hz)
    if '-DSNAP_FINE_LOCKS=1' in defines:
        offset, size = fine_profile_spec(defines)
        out['fine'] = decode_fine_profile(report[offset:offset + size], defines, hz=hz)
    if any(d in defines for d in TOKEN_DEFINES):
        offset, size = token_costs_spec(defines)
        row = next((r for r in out['sub'] if r['name'] == 'call_other'), None)
        out['token_costs'] = decode_token_costs(report[offset:offset + size], hz=hz,
            call_other=row or dict(entries=0, wait_ticks=0, hold_ticks=0))
    if FAST_IRQ_DEFINE in defines:
        offset, size = fast_irq_spec(defines)
        out['fast_irq'] = decode_fast_irq(report[offset:offset + size], defines, hz=hz)
    if FAST_IPI_DEFINE in defines:
        offset, size = fast_ipi_spec(defines)
        out['fast_ipi'] = decode_fast_ipi(report[offset:offset + size], defines, hz=hz)
    if DART_MEMO_DEFINE in defines:
        offset, size = dart_memo_spec()
        out['dart_memo'] = decode_dart_memo(report[offset:offset + size])
    if TOKEN_TRIM_DEFINE in defines:
        offset, size = token_trim_spec()
        out['token_trim'] = decode_token_trim(report[offset:offset + size], hz=hz)
    if IB_ASYNC_DEFINE in defines:
        offset, size = ib_async_spec()
        out['ib_async'] = decode_ib_async(report[offset:offset + size], hz=hz,
                                          recover=any(d.startswith('-DSNAP_ADRENO_RECOVER=') for d in defines))
    if VIEW_RECLAIM_DEFINE in defines:
        offset, size = view_reclaim_spec()
        out['view_reclaim'] = decode_view_reclaim(report[offset:offset + size])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', type=Path, help='perf_state bytes read from the stopped target')
    ap.add_argument('--report', type=Path, help='report.bin: decode its exit profile record')
    ap.add_argument('--defines', nargs='*', default=[], help='the monitor build_defines')
    ap.add_argument('--hz', type=float, help='the host counter frequency (params clock_host_hz), for seconds')
    # argparse takes a value starting with '-' for an option: collect -D... words here.
    args, rest = ap.parse_known_args()
    if any(not r.startswith('-D') for r in rest):
        ap.error(f'unrecognized arguments: {" ".join(r for r in rest if not r.startswith("-D"))}')
    defines = args.defines + rest
    if args.report:
        print(json.dumps(decode_report(args.report.read_bytes(), defines, hz=args.hz), indent=1))
        return
    if not args.raw:
        print(json.dumps(dict(zip(('context_offset', 'size'), read_spec(defines)))))
        return
    print(json.dumps(decode(args.raw.read_bytes(), defines), indent=1))


if __name__ == '__main__':
    main()
