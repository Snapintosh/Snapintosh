# SPDX-License-Identifier: MIT
"""Six-CPU BaseSystem RAM-disk speed test: control versus fast monitor, stock kernel.

Design and failure inventory: docs/SPEED-TEST-RAMDISK-20261016.md. No SSD, GPU,
AuxKC, TXM helper, HVC call-entry patch or retirement. Each variant starts from a
cold q1n1 boot plus one chainload (generation >= 1, SError guard). One definite
main P_CALL return is required before stopped-state capture; an uncertain P_CALL
quarantines the run without further target I/O. Raw stopped-state bytes are
retained before decoding, so a decoder gap never loses the run.
"""
import ast
import contextlib
import datetime
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import runpy
import struct
import sys
import time
from source_text import source_files

from .common import need, image_base, battery_minimum
from .bootstrap_smoke import (IDENTITY, WitnessProxy, digest, load, modules, sha, source_paths,
                              write)

PROFILE = 'j700ap-26A428-bootfb-xars-uniform'
FIRMWARE = 'downloads/extracted/j700ap'
RAMDISK = FIRMWARE + '/basesystem-26A428.apfs'
ROOT_HASH = FIRMWARE + '/basesystem-26A428.root-hash'
WATCHDOG = 600
GUEST_MIB = 8192
PHYS_BASE = 0x8c0000000
# The last boot-route script that spelled its settings out
# (build/run-bootfb-nub-guardstep-20260923.py, git history), with this test's watchdog.
ENV = {'SNAP_SMP': '1', 'SNAP_GUEST_MIB': str(GUEST_MIB), 'SNAP_PHYS_BASE': hex(PHYS_BASE),
       'SNAP_REQUIRE_PRELOAD': '1', 'SNAP_NATIVE_CALLS': '1', 'SNAP_WATCHDOG': str(WATCHDOG)}
CENSUS = '-DSNAP_SYSREG_CENSUS=1'
VARIANTS = ('control', 'fast')
ISC_ROLES = {256: 'xART', 16: 'Preboot', 320: 'Hardware'}
# launchd's own log lines carry the guest's UTC wall clock, seeded from the
# host at upload (build/<prefix>-rtc-seed.json).
STAMP = re.compile(rb'^com\.apple\.xpc\.launchd\|(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6}) ', re.M)
MILESTONES = {'windowserver': rb'Successfully spawned WindowServer\[\d+\]',
              'loginwindow': rb'Successfully spawned loginwindow\[\d+\]'}


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 24), b''):
            h.update(chunk)
    return h.hexdigest()


def build_layout(root, flags):
    """The monitor context layout of a build (tools/monitor_layout.py with its -D flags). Several structures
    change size with the defines (SNAP_UNNEST_4K_FAST: struct sptm_root_memo by 0xf8000 bytes), so a context
    is sized, captured and decoded with its own build's layout; the define-free one put console_log 0xf8000
    bytes early (inside root_memo) and retained the context 0xf8000 bytes short."""
    return runpy.run_path(str(root / 'tools/monitor_layout.py'))['MonitorLayout'](flags)


def console_text(context, layout, total):
    """The console as kept: console_log (the first bytes, never overwritten),
    then the console_tail ring's bytes beyond it, with any gap between marked."""
    head_cap, ring_cap = layout.length('context', 'console_log'), layout.length('context', 'console_tail')
    # A capture retained short (the define-free size, before build_layout) still decodes when the kept console
    # lies inside it; never read past the bytes retained.
    need(layout.offset('context', 'console_log') + min(total, head_cap) <= len(context),
         f'context.bin holds {len(context)} bytes, short of the kept console_log '
         f'({layout.offset("context", "console_log")} + {min(total, head_cap)})')
    head = context[layout.offset('context', 'console_log'):][:min(total, head_cap)]
    if total <= head_cap:
        return head, dict(complete=True, kept=len(head), lost=0)
    ring = context[layout.offset('context', 'console_tail'):][:ring_cap]
    start = max(head_cap, total - ring_cap)
    tail = bytes(ring[i % ring_cap] for i in range(start, total))
    lost = start - head_cap
    gap = b'\n[... %d console bytes not kept ...]\n' % lost if lost else b''
    return head + gap + tail, dict(complete=False, kept=len(head) + len(tail), lost=lost)


def milestones(text, epoch_us):
    """Seconds from the RTC seed to the first launchd line, each spawn in
    MILESTONES and the last launchd line; None when not in the kept console."""
    def at(match):
        if not match:
            return None
        stamp = STAMP.match(text, text.rfind(b'\n', 0, match.start()) + 1)
        if not stamp:
            return None
        utc = datetime.datetime.strptime(stamp[1].decode(), '%Y-%m-%d %H:%M:%S.%f')
        return round(utc.replace(tzinfo=datetime.timezone.utc).timestamp() - epoch_us / 1e6, 6)
    stamps = list(STAMP.finditer(text))
    out = dict(launchd_first=at(stamps[0]) if stamps else None)
    out.update({name: at(re.search(pattern, text)) for name, pattern in MILESTONES.items()})
    out['launchd_last'] = at(stamps[-1]) if stamps else None
    return out


def recipe(root):
    """ADDED and FAST exactly as tools/build-fast-traps-monitor.py defines them."""
    tree = ast.parse((root / 'tools/build-fast-traps-monitor.py').read_text())
    lists = {target.id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
             for target in node.targets if isinstance(target, ast.Name) and target.id in ('ADDED', 'FAST')}
    need(set(lists) == {'ADDED', 'FAST'}, 'fast-traps recipe lists not found')
    return lists['ADDED'], lists['FAST']


def flag_sets(root):
    """Both variants from one recipe; they may differ by exactly the fast defines."""
    base = json.loads((root / 'config/monitor-flags.json').read_text())['flags']
    added, fast = recipe(root)
    names = tuple(f.split('=')[0] for f in [*added, *fast, CENSUS, '-DSNAP_SPTM_HVC_CALLS=1'])
    need(not any(f.startswith(names) for f in base), 'the base recipe already carries a speed-test define')
    need('-DSNAP_NATIVE_CALLS=1' in base and '-DSNAP_SERVICE_PROFILE=1' in base, 'base recipe lacks native calls or profile')
    sets = dict(control=[*base, *added, CENSUS], fast=[*base, *added, *fast, CENSUS])
    need(set(sets['control']) < set(sets['fast']) and set(sets['fast']) - set(sets['control']) == set(fast),
         'variants differ by more than the fast defines')
    need(all(len(f) == len(set(f)) for f in sets.values()), 'duplicate build flags')
    return sets, fast


# docs/SPEED-BATCH4-20261020.md: the fast variant also carries every installed-route monitor option that applies to
# the stock kernel on this route, through installed_fresh.variant_flags (its prerequisite checks and flag order),
# then the batch-4 defines. Kernel patches (user-4k, sysreg-zero, refmod-skip and what needs them: user-hw-walk,
# fine-hw), the GPU (dart-memo, dart-wiredcnt, ib-budget-1s), input, TXM (txm-aspace-wide), CPU placement
# (prime-secondaries) and diagnostics (panic-serve, s2-fault-retry, idreg-mmfr3) stay out.
FAST_OPTIONS = ('wfi_resume', 'fast_timer_irq', 'aes_bitslice', 'fast_ipi', 'fast_el0_sysreg', 'service_subclass',
                'root_miss_fast', 'update_disjoint_fast', 'root_cache_wide', 'update_check_sparse',
                'kernel_pperm_fast', 'unmap_mixed', 'fine_locks', 'fine_switch', 'fair_token', 'nest_fast',
                'detach_fast', 'root_index', 'other_profile', 'gate_wait', 'fast_pauth_calls',
                'fast_timer_irq_cpu0', 'native_pacga')


# Batch-5 opt-ins on top of FAST_OPTIONS (--token-trim, --pauth-el0-live, --lean-traps 1|2) and batch 6's --el0-memo
# (with --pauth-el0-live) and --unnest-4k-fast (docs/UNNEST-4K-FAST-20261020.md; the stock kernel's 16K roots never
# take it), and batch 7's --phase-fair-gate (FAST_OPTIONS carries its --fine-locks, --fair-token and --gate-wait),
# named at prepare and recorded in the qualification's options, so a fast run can be compared with and without them.
# Batch 8's --fine-switch-hw (SNAP_FINE_SWITCH_HW) needs --user-hw-walk, which stays out of FAST_OPTIONS with the
# kernel patch it needs, so it is installed-fresh only and not an option here.
OPT_IN =('token_trim', 'pauth_el0_live', 'lean_traps', 'el0_memo', 'unnest_4k_fast', 'phase_fair_gate')


def options_of(args):
    """The opt-ins given: {name: True} for the flags, lean_traps: its level."""
    return {name: getattr(args, name) for name in OPT_IN if getattr(args, name, None)}


def speed_sets(root, options=None):
    """This test's variants: the recipe's control, and its fast set plus FAST_OPTIONS and the opt-ins in options,
    which variant_flags appends last. flag_sets stays the base recipe that installed-fresh builds on."""
    from types import SimpleNamespace
    from .installed_fresh import variant_flags
    options = dict(options or {})
    need(set(options) <= set(OPT_IN), f'unknown speed-test options {sorted(set(options) - set(OPT_IN))}')
    sets, _ = flag_sets(root)
    fast = variant_flags(sets, SimpleNamespace(**{name: True for name in FAST_OPTIONS}, **options), 'fast')
    need(len(fast) == len(set(fast)), 'duplicate build flags')
    need(set(sets['control']) < set(fast), 'the fast variant lost a control flag')
    return dict(control=sets['control'], fast=fast), [f for f in fast if f not in sets['control']]


def isc_roles(path):
    """{role: name} of a raw APFS image's volumes, read from its latest checkpoint."""
    with Path(path).open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as m:
        need(m[32:36] == b'NXSB', f'{path} is not a raw APFS container')
        bs = struct.unpack_from('<I', m, 36)[0]
        block = lambda n: m[n * bs:(n + 1) * bs]
        desc_blocks, = struct.unpack_from('<I', m, 104)
        desc_base, = struct.unpack_from('<q', m, 112)
        need(not desc_blocks >> 31, 'non-contiguous checkpoint descriptor area')
        best = max((b for b in (block(desc_base + i) for i in range(desc_blocks)) if b[32:36] == b'NXSB'),
                   key=lambda b: struct.unpack_from('<Q', b, 16)[0])
        xid = struct.unpack_from('<Q', best, 16)[0]
        want = {o for o in struct.unpack_from('<100Q', best, 184)[:struct.unpack_from('<I', best, 180)[0]] if o}
        tree = struct.unpack_from('<Q', block(struct.unpack_from('<Q', best, 160)[0]), 48)[0]
        found, frontier = {}, [tree]
        while frontier:
            node = block(frontier.pop())
            flags, level, nkeys = struct.unpack_from('<HHI', node, 32)
            toff, tlen = struct.unpack_from('<HH', node, 40)
            keys, values = 56 + toff + tlen, bs - (40 if flags & 1 else 0)
            for i in range(nkeys):
                k, v = struct.unpack_from('<HH', node, 56 + toff + 4 * i)
                oid, entry_xid = struct.unpack_from('<QQ', node, keys + k)
                if level:
                    frontier.append(struct.unpack_from('<Q', node, values - v)[0])
                elif oid in want and entry_xid <= xid and entry_xid >= found.get(oid, (0,))[0]:
                    found[oid] = (entry_xid, struct.unpack_from('<Q', node, values - v + 8)[0])
        need(set(found) == want, 'ISC object map does not resolve every volume')
        roles = {}
        for _, paddr in found.values():
            volume = block(paddr)
            need(volume[32:36] == b'APSB', 'ISC volume superblock missing')
            roles[struct.unpack_from('<H', volume, 964)[0]] = volume[704:960].split(b'\0')[0].decode()
        return roles


@contextlib.contextmanager
def environment(prefix):
    old = dict(os.environ)
    for key in list(os.environ):
        if key.startswith('SNAP_'):
            del os.environ[key]
    os.environ.update(ENV, SNAP_SMP_REPORT_PREFIX=prefix)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def inputs(root, isc):
    return {str(root / RAMDISK): file_sha(root / RAMDISK), str(root / ROOT_HASH): file_sha(root / ROOT_HASH),
            str(isc): file_sha(isc)}


def prepare(ws, args, dest):
    need(args.variant in VARIANTS, 'prepare needs --variant control|fast')
    need(args.isc_image, 'prepare needs --isc-image')
    need(not dest.exists(), f'preserve previous run: {dest}')
    root = ws.root
    runner, layout, _ = modules(root)
    options = options_of(args)
    need(not options or args.variant == 'fast', f'{", ".join(sorted(options))}: fast variant only')
    sets, fast = speed_sets(root, options)
    flags = sets[args.variant]
    isc = Path(args.isc_image).resolve()
    roles = isc_roles(isc)
    need(roles.keys() == ISC_ROLES.keys(), f'ISC image roles {sorted(roles)}, need {sorted(ISC_ROLES)}')
    sources = {str(p): sha(p) for p in source_paths(root)}
    bound = inputs(root, isc)
    dest.mkdir()
    runner.FLAGS[:] = flags
    with environment(args.prefix), (dest / 'prepare.log').open('x') as stream, contextlib.redirect_stdout(stream):
        blob = runner.build('xnuboot', dest)
        xb = load('speed_image', root / 'probes/xnuboot.py')
        xb.configure_guest(PROFILE, root / FIRMWARE)
        need(not xb.check_profile(), 'firmware profile rejected')
        need(xb.GUEST_PROFILE.adreno is None and xb.GUEST_PROFILE.ans_boot is None and
             xb.GUEST_PROFILE.installed_root is None and not xb.GUEST_PROFILE.aux_collection_linked,
             'speed-test profile reaches devices outside its scope')
        # The run places the guest where the target says memory is free; offline,
        # the declared base and the run's own size arithmetic stand in for it.
        span = GUEST_MIB << 20
        import monitor_work
        xb.place(PHYS_BASE, span + xb.bootstrap_reserve(span) + monitor_work.WORK_SIZE, guest_span=span)
        built = xb.build(str(xb.DEFAULT_KERNELCACHE), ramdisk=str(root / RAMDISK), root_hash=str(root / ROOT_HASH),
                         ramdisk_mode='iokit', isc_image=str(isc))
        need(built['native_calls'] and not built.get('sptm_hvc_calls'), 'not the stock kernel through native calls')
        need(built.get('ramdisk_root_range') and built.get('ramdisk_isc_range'), 'image lacks the RAM disk or ISC')
        image = dict(profile=PROFILE, kernel_sha256=sha(xb.DEFAULT_KERNELCACHE),
                     firmware_sha256=xb.GUEST_PROFILE.hashes(root / FIRMWARE),
                     entry=hex(built['entry']), chunks=len(built['chunks']),
                     ramdisk_root_range=[hex(x) for x in built['ramdisk_root_range']],
                     ramdisk_isc_range=[hex(x) for x in built['ramdisk_isc_range']],
                     qualification='offline image at the declared base; hardware placement captured at upload')
    need(all(sha(p) == h for p, h in sources.items()), 'sources changed during preparation')
    record = dict(schema='snapintosh-speed-test-v1', status='OFFLINE_PREPARED_NOT_BOOTED',
                  prefix=args.prefix, variant=args.variant, device=args.device or ws.device,
                  profile=PROFILE, watchdog_seconds=WATCHDOG, environment=ENV,
                  flags=flags, fast_defines=fast if args.variant == 'fast' else [],
                  isc_image=str(isc), isc_roles={str(k): v for k, v in sorted(roles.items())}, inputs_sha256=bound,
                  source_sha256=sources, monitor_sha256=digest(blob), monitor_bytes=len(blob),
                  elf_sha256=sha(dest / 'xnuboot.elf'), context_bytes=build_layout(root, flags).size('context'),
                  context_layout='build-defines', image=image,
                  qualification='six-CPU RAM-disk performance comparison on the stock kernel; '
                                'not GUI, installed-system or baseline qualification')
    if options:
        record['options'] = options   # only when given, so earlier records keep their exact shape
    write(dest / 'qualification.json', record)
    return record


def check(ws, args, dest):
    path = dest / 'qualification.json'
    need(path.is_file(), 'run --prepare first')
    record = json.loads(path.read_text())
    need(record['schema'] == 'snapintosh-speed-test-v1' and record['prefix'] == args.prefix, 'wrong qualification')
    need(record['device'] == (args.device or ws.device), 'device differs from preparation')
    need(record['environment'] == ENV and record['profile'] == PROFILE, 'speed-test scope changed')
    options = record.get('options', {})
    need(options == options_of(args), f'options differ from the preparation: prepared {options}, '
                                      f'given {options_of(args)}')
    need(record['flags'] == speed_sets(ws.root, options)[0][record['variant']],
         'variant flags differ from the recipe')
    for name, expected in record['source_sha256'].items():
        need(sha(name) == expected, f'source changed: {name}')
    need(record['isc_image'] in record['inputs_sha256'], 'ISC image is not a bound input')
    for name, expected in record['inputs_sha256'].items():
        need(file_sha(name) == expected, f'input changed: {name}')
    need(sha(dest / 'xnuboot.bin') == record['monitor_sha256'] and sha(dest / 'xnuboot.elf') == record['elf_sha256'],
         'prepared monitor changed')
    need(not (dest / 'launch.json').exists(), 'this attempt already has a launch record; never rerun it')
    from guestprofile import get_profile
    need(get_profile(PROFILE).hashes(ws.root / FIRMWARE) == record['image']['firmware_sha256'], 'firmware inputs changed')
    return record


class SpeedWitness(WitnessProxy):
    """The smoke's witness, for a main call that carries the five secondaries and
    keeps the runner's watchdog-derived deadline."""
    SECONDARIES = True
    MAIN_TIMEOUT = None


def capture(proxy, info, runner, layout, dest, record):
    """Retain the stopped state's raw bytes first, then decode them."""
    out, work, work_size, params, host_cpus = proxy.main_args
    artifacts = {}
    def retain(name, address, size):
        data = proxy.readmem(address, size)
        (dest / name).write_bytes(data)
        artifacts[name] = dict(address=hex(address), bytes=size, sha256=digest(data))
        return data
    retain('report.bin', out, runner.OUT_HEADROOM)
    retain('context.bin', work, layout.size('context'))
    retain('params.bin', params, layout.size('params'))
    import monitor_work
    locator = retain('work-locator.bin', monitor_work.locator_address(info), monitor_work.LOCATOR_SIZE)
    need(monitor_work.decode_locator(locator, info, monitor_work.firmware_free(proxy, info)) == (work, work_size),
         'stopped work locator differs from actual main-call reservation')
    need(digest(proxy.readmem(info['heap_base'] + runner.CODE_AT, record['monitor_bytes'])) == record['monitor_sha256'],
         'resident monitor changed')
    after = proxy.bootinfo()
    need({k: after[k] for k in IDENTITY} == {k: info[k] for k in IDENTITY}, 'resident firmware identity changed')
    guard = proxy.serror_state()
    record.update(after_serror=guard, after_exception_count=proxy.get_exc_count(), host_cpus=host_cpus)
    write(dest / 'preservation.json', dict(schema='snapintosh-speed-test-preservation-v1',
          actual_main_call_return=True, artifacts=artifacts, runtime_retired=False,
          qualified_scope='six-CPU RAM-disk performance comparison'))
    record.update(captures=artifacts, preservation_sha256=sha(dest / 'preservation.json'),
                  terminal='STOPPED_PRESERVED_NO_RETIREMENT')


def decode(ws, dest, record):
    """Lock profile, fast-path counters, census and console from the retained bytes."""
    root = ws.root
    # Layouts come from the current sources, so a capture decodes only with the
    # sources it was built from (the 48-slot census predates SYSREG-CENSUS-20261016).
    monitor = [str(p.relative_to(Path(root).resolve())) for p in source_files(root / 'probes/xnuboot.c')]
    for name in ('compat/fast-trap.h', 'compat/perf-state.h', *monitor, 'tools/perf_counters.py'):
        path = str(root / name)
        need(record['source_sha256'].get(path) in (None, sha(path)),
             f'{name} differs from the run\'s build; decode it from the commit it was built from')
    layout = build_layout(root, record['flags'])
    profile = runpy.run_path(str(root / 'tools/capture-service-profile.py'), run_name='speed_profile')
    perf = runpy.run_path(str(root / 'tools/perf_counters.py'), run_name='speed_perf')
    crash_ring = runpy.run_path(str(root / 'tools/user_crash_ring.py'), run_name='speed_crashes')
    context = (dest / 'context.bin').read_bytes()
    params = (dest / 'params.bin').read_bytes()
    report = (dest / 'report.bin').read_bytes()
    word = lambda name, data=context, kind='context': struct.unpack_from('<Q', data, layout.offset(kind, name))[0]
    hz = word('clock_host_hz', params, 'params')
    stride = layout.size('service_profile')
    start = layout.offset('context', 'service_profile')
    cpus = []
    for slot in range(6):
        raw = context[start + slot * stride:start + (slot + 1) * stride]
        acquired = struct.unpack_from('<Q', raw, layout.offset('service_profile', 'acquired'))[0]
        if not struct.unpack_from('<Q', raw, layout.offset('service_profile', 'attempts'))[0]:
            cpus.append(dict(slot=slot, idle=True))
            continue
        cpus.append(dict(slot=slot, **profile['decode'](raw, layout, hz, acquired)))
    offset, size = perf['read_spec'](record['flags'])
    counters = perf['decode'](context[offset:offset + size], record['flags'])
    total = word('console_tail_bytes')
    ring_cap = layout.length('context', 'console_tail')
    kept = min(total, ring_cap)
    ring = context[layout.offset('context', 'console_tail'):][:ring_cap]
    first = (total - kept) % ring_cap
    console = (ring[first:] + ring[:first])[:kept]
    (dest / 'console-tail.txt').write_text(console.decode('utf-8', errors='replace'))
    text, kept_info = console_text(context, layout, total)
    (dest / 'console.txt').write_bytes(text)
    seed = dest.parent / f'{dest.name}-rtc-seed.json'
    epoch_us = json.loads(seed.read_text())['epoch_us'] if seed.is_file() else None
    marks = dict(kept_info, epoch_us=epoch_us, seconds=milestones(text, epoch_us) if epoch_us else None)
    busy = [c for c in cpus if not c.get('idle')]
    # A run that stopped before any vCPU took the service lock (installed-fresh-20261018-v48: an EL2 fault in
    # preparation) has no profile; it still decodes, with no rates.
    wall = max((c['elapsed_seconds'] for c in busy), default=0.0)
    rate = lambda part, whole: part / whole if whole else None
    buckets = {}
    for c in busy:
        for b in c['buckets']:
            row = buckets.setdefault(b['name'], dict(entries=0, wait_seconds=0.0, hold_seconds=0.0))
            row['entries'] += b['entries']
            row['wait_seconds'] += b['wait_seconds']
            row['hold_seconds'] += b['hold_seconds']
    # One ring per guest CPU; 'user_crashes' alone is only CPU0's header word.
    ring_bytes, ring_at = crash_ring['RING_BYTES'], layout.offset('context', 'user_crashes')
    crashes = [crash_ring['decode_ring'](context[ring_at + cpu * ring_bytes:ring_at + (cpu + 1) * ring_bytes], cpu)
               for cpu in range(crash_ring['GUEST_CPUS'])]
    crash_kinds = {}
    for ring in crashes:
        for row in ring['rows']:
            key = f"{row.get('kind')}/{row.get('signal') or row.get('exception')}"
            crash_kinds[key] = crash_kinds.get(key, 0) + 1
    locked = sum(c['attempts'] for c in busy)
    fast = counters['summary']['fast_traps']
    elapsed = sum(c['elapsed_seconds'] for c in busy)
    summary = dict(
        variant=record['variant'], exit_code=record.get('exit_code'),
        exit_name=record.get('exit_name'), cpus_active=len(busy), wall_seconds=wall,
        traps_total=locked + fast, traps_locked=locked, traps_fast=fast,
        lock_busy_fraction=rate(sum(c['hold_seconds'] for c in busy), wall),
        lock_wait_cpu_seconds=sum(c['wait_seconds'] for c in busy),
        lock_hold_cpu_seconds=sum(c['hold_seconds'] for c in busy),
        outside_lock_fraction=rate(sum(c['outside_instrumented_seconds'] for c in busy), elapsed),
        traps_per_second=rate(locked + fast, wall),
        buckets=dict(sorted(buckets.items(), key=lambda kv: -kv[1]['hold_seconds'])),
        census_sysreg=sum(c['total'] for c in counters['census']),
        census_pacga=sum(c['pacga'] for c in counters['census']),
        fast_path=counters['summary'], report_header=list(struct.unpack_from('<10Q', report)),
        guest_progress={name: word(name) for name in ('traps', 'events', 'steps', 'calls')},
        user_crashes_recorded=sum(ring['recorded'] for ring in crashes), user_crash_kinds=crash_kinds,
        console_bytes=total, milestones=marks,
        boundary='outside_lock_fraction includes guest execution, entry/exit and unmeasured monitor work: '
                 'an upper bound on the guest share, not guest-only time.')
    exits = None
    if '-DSNAP_SERVICE_SUBCLASS=1' in record['flags']:
        # report.bin's exit profile (docs/SPEED-BATCH4-20261020.md): every lock-free exit's round trip, the
        # token's sub-classes and, with fine locks, the converted calls, whose gate and stripe waits are
        # monitor waiting outside the token. monitor_cpu_seconds adds them all; the guest share estimate is
        # what is left (still an upper bound: the hardware exception entry and ERET are not measured).
        exits = perf['decode_report'](report, record['flags'], hz=hz)
        timing = exits['summary']['timing']
        fast_exit_seconds = sum(t['ticks'] for t in timing.values()) / hz
        fine = {}
        for name, row in (exits.get('fine') or {}).get('calls', {}).items():
            fine[name] = dict(entries=row['entries'], gate_wait_seconds=row['gate_wait'] / hz,
                              stripe_wait_seconds=(row['stripe_wait'] + row['aux_wait']) / hz,
                              hold_seconds=row['hold'] / hz)
        converted_wait = sum(r['gate_wait_seconds'] + r['stripe_wait_seconds'] for r in fine.values())
        converted_hold = sum(r['hold_seconds'] for r in fine.values())
        irq = exits.get('fast_irq')
        irq_seconds = sum(c.get('seconds', 0.0) for c in irq['cpus']) if irq else 0.0
        monitor = summary['lock_wait_cpu_seconds'] + summary['lock_hold_cpu_seconds'] + converted_wait + \
            converted_hold + fast_exit_seconds + irq_seconds
        summary.update(
            exit_timing={k: dict(exits=t['exits'], mean_ns=t.get('mean_ns'), cpu_seconds=t['ticks'] / hz)
                         for k, t in timing.items() if t['exits']},
            el0_sysreg=exits['summary']['el0'],
            token_sub=[dict(name=r['name'], entries=r['entries'], wait_seconds=r['wait_seconds'],
                            hold_seconds=r['hold_seconds']) for r in
                       sorted(exits['sub'], key=lambda r: -(r['wait_seconds'] + r['hold_seconds']))[:12]],
            converted_calls=fine, converted_wait_cpu_seconds=converted_wait,
            converted_hold_cpu_seconds=converted_hold, fast_exit_cpu_seconds=fast_exit_seconds,
            fast_irq=[dict(cpu=c['cpu'], handled=c['result']['handled'], locked=c['locked'],
                           resumed=c['resumed'], seconds=c.get('seconds', 0.0)) for c in irq['cpus']] if irq else None,
            monitor_cpu_seconds=monitor, guest_share_estimate=rate(elapsed - monitor, elapsed),
            token_costs=exits.get('token_costs'), fast_ipi=(exits.get('fast_ipi') or {}).get('summary'))
        if exits.get('token_trim'):
            summary['token_trim'] = exits['token_trim']   # SNAP_TOKEN_TRIM runs only
        if exits.get('view_reclaim'):
            summary['view_reclaim'] = exits['view_reclaim']   # SNAP_VIEW_RECLAIM runs only
    write(dest / 'decoded.json', dict(cpus=cpus, perf=counters, host_hz=hz, exits=exits))
    write(dest / 'summary.json', summary)
    return summary


def boot(ws, args, dest, qualification):
    need(args.qualification_sha256 == sha(dest / 'qualification.json'), 'boot needs the exact qualification SHA256')
    need(args.generation and args.generation >= 1, 'boot needs --generation N >= 1 (a chainloaded stage)')
    runner, layout, admission = modules(ws.root)
    # The build's layout for the private context: run.py sizes the table window with runner.FLAGS and the
    # capture retains the whole context (layout stays define-free for the predecessor's service words).
    runner.FLAGS[:] = qualification['flags']
    context = build_layout(ws.root, qualification['flags'])
    need(qualification.get('context_layout') != 'build-defines' or
         qualification['context_bytes'] == context.size('context'), 'the build\'s context size changed since prepare')
    record = dict(schema='snapintosh-speed-test-launch-v1', status='PREFLIGHT', started=time.time(),
                  qualification_sha256=args.qualification_sha256, variant=qualification['variant'],
                  flags=qualification['flags'], monitor_sha256=qualification['monitor_sha256'],
                  monitor_bytes=qualification['monitor_bytes'], source_sha256=qualification['source_sha256'],
                  uploads=[], calls=[], pid=os.getpid())
    path = dest / 'launch.json'
    write(path, record)
    proxy = witness = info = None
    try:
        admission.other_clients(args.device or ws.device)
        # --after-quiesce PREFIX (docs/SPEED-BATCH4-20261020.md): the installed route's admission of a parked,
        # preserved predecessor in this q1n1 boot (installed_fresh.previous_quiesce, predecessor_stop, admit):
        # its captures and graceful GPU quiesce re-verified, and its resident work locator accepted only while
        # the work area it names still holds its parked stop. Without it, any resident locator refuses.
        after = getattr(args, 'after_quiesce', None)
        predecessor = None
        if after:
            from .installed_fresh import previous_quiesce, predecessor_stop
            record['after_quiesce'] = previous_quiesce(ws, ws.root, after)
            predecessor = predecessor_stop(ws.root, after, layout)
        proxy = runner.connect(args.device or ws.device, tries=1)
        # A chainloaded stage publishes its host call service; the empty (or the predecessor's parked) work
        # locator, not call_service, is what says no guest is present.
        from .installed_fresh import admit
        info = admit(proxy, record, args.generation, runner, predecessor)
        record['bootinfo'] = info
        guard = proxy.serror_state()
        need(not any(guard[k] for k in ('before', 'during', 'unconsumed')) and not proxy.get_exc_count(),
             'host exceptions before boot')
        witness = SpeedWitness(proxy, path, record, info['heap_base'] + runner.CODE_AT)
        need(info['battery_call'] and info['battery_result'], 'firmware has no live battery helper')
        status = witness.call(info['battery_call'], 0, 0, 0, 0, 0, timeout=12)
        battery = proxy.live_battery_record(info['battery_result'])
        record['battery'] = battery
        # The project's battery policy (cycle_lib.common.battery_minimum: pins.json default, SNAP_BATTERY_MINIMUM).
        minimum = record['battery_minimum_without_ac'] = battery_minimum(None)
        need(status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= minimum),
             f'battery preflight refused: below {minimum}% without AC')
        record['status'] = 'BOOTING'
        write(path, record)
        root = ws.root
        with environment(args.prefix), (dest / 'boot.log').open('x') as stream, \
                contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            record['exit_code'] = runner.run(witness, (dest / 'xnuboot.bin').read_bytes(), 'xnuboot',
                                            args.device or ws.device,
                dict(guest_profile=PROFILE, firmware_dir=str(root / FIRMWARE), console_mode='serial',
                     ramdisk=str(root / RAMDISK), root_hash=str(root / ROOT_HASH), ramdisk_mode='iokit',
                     isc_image=qualification['isc_image']))
        record['exit_name'] = runner.EXIT_NAMES.get(record['exit_code'])
    except BaseException as error:
        record['error'] = repr(error)
        record['status'] = 'FAILED'
        raise
    finally:
        try:
            if witness and witness.quarantined:
                record['status'] = 'NATIVE_QUARANTINE_NO_FURTHER_TARGET_IO'
            elif witness and witness.unknown:
                record['status'] = 'UNKNOWN_CALL_OUTCOME_NO_FURTHER_TARGET_IO'
            elif witness and witness.control_guard.frozen:
                record['status'] = 'CONTROL_FAILURE_NO_FURTHER_TARGET_IO'
            elif witness and witness.main_returned:
                capture(witness, info, runner, context, dest, record)
                record['status'] = 'STOPPED_PRESERVED'
            elif record['status'] != 'FAILED':
                record['status'] = 'NO_GUEST_CALL'
        except BaseException as error:
            record['capture_error'] = repr(error)
            record['status'] = 'STOPPED_CAPTURE_FAILED'
            raise
        finally:
            record['finished'] = time.time()
            write(path, record)
            if proxy:
                proxy.link.close()
    if record['status'] == 'STOPPED_PRESERVED':
        try:
            record['summary'] = decode(ws, dest, record)
        except Exception as error:   # an observer gap, never a guest result; the raw bytes are retained
            record['decode_error'] = repr(error)
        write(path, record)
    return record


COMPARED = ('wall_seconds', 'traps_total', 'traps_locked', 'traps_fast', 'traps_per_second',
            'lock_busy_fraction', 'lock_wait_cpu_seconds', 'lock_hold_cpu_seconds', 'outside_lock_fraction',
            'census_sysreg', 'census_pacga')


def compare(ws, prefixes):
    runs = []
    for prefix in prefixes:
        need(re.fullmatch('[a-z0-9-]+', prefix), 'invalid prefix')
        path = ws.root / 'build' / prefix / 'summary.json'
        need(path.is_file(), f'{prefix} has no decoded summary')
        runs.append(json.loads(path.read_text()))
    variants = [r['variant'] for r in runs]
    need(variants in (['control', 'fast'], ['fast', 'control'], ['fast', 'fast']),
         'compare one control and one fast run, or two fast runs (earlier first)')
    # Two fast runs (a batch against the one before it): "control" is the earlier, given first.
    control, fast = runs if variants == ['fast', 'fast'] else \
        sorted(runs, key=lambda r: VARIANTS.index(r['variant']))
    rows = {k: dict(control=control[k], fast=fast[k],
                    change=(fast[k] - control[k]) / control[k] if control[k] and fast[k] is not None else None)
            for k in COMPARED}
    same_window = control['exit_code'] == fast['exit_code'] and abs(control['wall_seconds'] - fast['wall_seconds']) < 30
    # Seconds from the RTC seed to each boot milestone, where both runs kept it.
    marks = [((r.get('milestones') or {}).get('seconds') or {}) for r in (control, fast)]
    rows.update({f'milestone_{k}': dict(control=marks[0].get(k), fast=marks[1].get(k),
                                         change=(marks[1][k] - marks[0][k]) / marks[0][k]
                                         if marks[0].get(k) and marks[1].get(k) is not None else None)
                 for k in ('launchd_first', 'windowserver', 'loginwindow')})
    result = dict(schema='snapintosh-speed-test-compare-v1', prefixes=list(prefixes), metrics=rows,
                  roles=dict(control=prefixes[0] if variants == ['fast', 'fast'] else 'control variant',
                             fast=prefixes[1] if variants == ['fast', 'fast'] else 'fast variant'),
                  exits=dict(control=control['exit_name'], fast=fast['exit_name']), same_window=same_window,
                  boundary='n=1 per variant; differences under about 10% need a repeat. '
                           + ('' if same_window else 'The runs stopped at different points: compare rates, not totals.'))
    out = ws.root / 'build' / f'speed-test-compare-{prefixes[0]}-vs-{prefixes[1]}.json'
    need(not out.exists(), f'preserve the existing comparison: {out}')
    write(out, result)
    return result


def main(ws, args):
    sys.path.insert(0, str(ws.root / 'probes'))
    if args.compare:
        print(json.dumps(compare(ws, args.compare), indent=2))
        return 0
    need(args.prefix and re.fullmatch('[a-z0-9-]+', args.prefix), 'invalid or missing --prefix')
    dest = ws.root / 'build' / args.prefix
    if args.decode:
        record = json.loads((dest / 'launch.json').read_text())
        need(record.get('status') == 'STOPPED_PRESERVED', 'decode needs a preserved stopped run')
        need(sha(dest / 'preservation.json') == record['preservation_sha256'], 'preservation record changed')
        print(json.dumps(decode(ws, dest, record), indent=2))
        return 0
    if args.prepare:
        prepare(ws, args, dest)
    record = check(ws, args, dest)
    if args.boot:
        with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            record = boot(ws, args, dest, record)
        print(json.dumps({k: record.get(k) for k in ('status', 'exit_code', 'exit_name', 'summary',
                                                     'decode_error', 'preservation_sha256')}, indent=2))
        return 0 if record.get('status') == 'STOPPED_PRESERVED' else 1
    print(json.dumps(dict(status='OFFLINE_READY_NOT_BOOTED', variant=record['variant'],
                          qualification=str(dest / 'qualification.json'),
                          sha256=sha(dest / 'qualification.json'), hardware_access=False), indent=2))
    return 0
