#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run a Snapintosh probe on the A16 through q1n1's proxy.

The probes are flat AArch64 blobs uploaded with P_CALL, so they execute at EL2
on the real machine with q1n1 as the harness. Discover a responding CDC/NCM
link automatically, or select a serial path or udp://enN with --device.

  python3 probes/run.py idregs
  python3 probes/run.py tgran16
"""
import argparse
import os
import runpy
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from bootcontract import HostRuntime
from xnuboot_terminal import require_xnuboot_terminal
from devicemodel import MODEL_MAX, RESET_WORDS
import monitor_work
from monitor_work import resident_work
Q1N1 = ROOT.parent / 'q1n1'
sys.path.insert(0, str(Q1N1 / 'tools'))
import q1n1proxy as q1n1                                            # noqa: E402

LLVM = Path('/opt/homebrew/opt/llvm/bin')
# q1n1's Makefile resolves the linker the same way: lld from its own keg
# when present, otherwise whatever is on PATH.
LLD = str(Path('/opt/homebrew/opt/lld/bin/ld.lld')) \
    if Path('/opt/homebrew/opt/lld/bin/ld.lld').exists() else 'ld.lld'
DEFAULT_DEVICE = None
FIRMWARE = '/opt/homebrew/share/qemu/edk2-aarch64-code.fd'


class Qemu:
    """q1n1 under QEMU, as a control.

    A probe that reports "feature absent" on one machine proves nothing on its
    own -- the probe could simply be wrong. Running the identical blob on an
    emulated CPU that HAS the feature is what separates those two cases, so
    every negative result here should be paired with a run under --qemu.
    """

    def __init__(self, root):
        self.esp = root / 'build' / 'qemu-esp'
        self.esp.mkdir(parents=True, exist_ok=True)
        payload = root.parent / 'q1n1' / 'build' / 'uefi' / 'q1n1.efi'
        if not payload.exists():
            raise SystemExit(f'build q1n1 first: make -C {root.parent / "q1n1"} uefi')
        shutil.copyfile(payload, self.esp / 'q1n1.efi')
        (self.esp / 'startup.nsh').write_text('fs0:\nq1n1.efi --uart-proxy\n')
        self.sock = f'/tmp/snapintosh-proxy-{os.getpid()}.sock'
        self.log = root / 'build' / 'qemu.log'
        self.proc = None

    def __enter__(self):
        Path(self.sock).unlink(missing_ok=True)
        self.proc = subprocess.Popen(
            ['qemu-system-aarch64', '-machine', 'virt,virtualization=on,gic-version=3',
             # 4 GiB because xnuboot needs half a gigabyte of contiguous free
             # physical memory for the image, its tables and the handoff, and
             # virt starts RAM at 0x40000000. -cpu max is what supplies FEAT_NV2.
             '-accel', 'tcg', '-cpu', 'max', '-smp', '1', '-m', '4G',
             '-bios', FIRMWARE, '-drive', f'format=raw,file=fat:rw:{self.esp}',
             # q1n1 refuses to run without a framebuffer; ramfb is what the
             # q1n1 QEMU harness uses.
             '-device', 'ramfb',
             '-display', 'none', '-monitor', 'none', '-nic', 'none', '-no-reboot',
             '-chardev', f'socket,id=s,path={self.sock},server=on,wait=off',
             '-serial', 'chardev:s'],
            stdout=subprocess.DEVNULL, stderr=open(self.log, 'w'))
        return self.sock

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is not None:
            print(f'qemu exited early ({self.proc.returncode}); see {self.log}')
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        Path(self.sock).unlink(missing_ok=True)


def connect(path=None, tries=60):
    """A live socket is not a live proxy: QEMU creates the socket immediately,
    long before q1n1 has booted through firmware to the proxy loop. Retry until
    a request actually comes back."""
    last = None
    for attempt in range(tries):
        try:
            # The shared reader discovers either A16 controller, handshakes
            # CDC/NCM/socket candidates, resets checksum negotiation, and
            # closes failed links. Only discovery is retried; never P_CALL.
            return q1n1.connect(device=path)
        except (OSError, RuntimeError) as error:
            last = error
            if attempt + 1 < tries:
                time.sleep(1.0)
    raise SystemExit(f'no q1n1 proxy on {path or "automatically discovered links"}: {last}')


# Probes that are more than one translation unit. They link against the shadow
# MMU sources and use probe.ld to keep the entry stub at offset 0, since a
# P_CALL blob is branched to at its front.
MULTI = {'pauth-address': ['probes/pauth-address.S','compat/pauth-native.S'],
         'pauth-sign-address': ['probes/pauth-sign-address.S','compat/pauth-native-sign.S'],
         'shadowmmu': ['probes/shadowmmu.S', 'probes/shadowmmu.c',
                       'shadow/mmu.c', 'shadow/shadow.c'],
         'xnuboot': ['probes/xnuboot.S', 'probes/xnuboot.c',
                     'probes/secondary.S', 'probes/secondary.c', 'compat/cpu-release.c',
                     'shadow/mmu.c', 'shadow/shadow.c', 'shadow/stage2.c', 'shadow/sprr-view.c', 'shadow/native-view.c', 'shadow/native-shared.c',
                     'shadow/dockchannel.c', 'compat/sptm.c', 'compat/sptm-unmap.c', 'compat/sptm-papt.c',
                     'compat/txm.c', 'compat/txm-copy.c', 'compat/txm-native.c', 'compat/uat.c', 'compat/pauth.c', 'compat/pauth-user.c',
                     'compat/pauth-domain.c','compat/pauth-switch.S',
                     'compat/pauth-batch.c','compat/pauth-pointer.c','compat/pauth-native.S','compat/pauth-native-sign.S',
                      'compat/exception.c', 'compat/panic-state.c', 'compat/cpu.c', 'compat/cpu-runtime.c', 'compat/service-lock.c', 'compat/sptm-update.c', 'compat/sptm-refs.c',
                     'compat/sptm-slide.c', 'compat/sptm-user.c', 'compat/sptm-root.c', 'compat/clock.c', 'compat/ipi.c',
                     'compat/device.c', 'compat/aic.c', 'compat/watchdog.c', 'compat/dart.c',
                     'compat/mmio.c', 'compat/sptm-dart.c', 'compat/aes.c', 'compat/aes-engine.c',
                     'compat/sep-bootstrap.c', 'compat/sep-pnon.c', 'compat/sep-xars.c',
                     'compat/sep-sks.c', 'compat/sep-sks-endpoint.c', '../q1n1/platform/uefi/sha256.c',
                     'compat/adreno.c', 'compat/adreno-fill.c', 'compat/adreno-ib.c', 'compat/irq-forward.c', 'compat/ans.c', 'compat/ans-window.c', 'compat/nvme-host.c', 'compat/early-stop.c', 'compat/a16-thermal.c', 'probes/memory.S']}
# Units linked only when their opt-in define is in FLAGS, after MULTI's, so a build without the define links exactly
# the objects it always did and its ELF stays byte-identical.
OPTIONAL = {'xnuboot': (('-DSNAP_ADRENO_COHERENT=1', 'compat/adreno-coherent.c'),
                        ('-DSNAP_EDP_BACKLIGHT=1', 'compat/edp-backlight.c'))}


def optional_sources(name, flags):
    return [rel for define, rel in OPTIONAL.get(name, ()) if define in flags]


FLAGS = ['--target=aarch64-unknown-none-elf', '-ffreestanding', '-fno-pic',
         '-mgeneral-regs-only', '-O1', '-Wall', '-Wextra', '-Werror',
         '-fno-stack-protector', '-mcmodel=tiny']


def build(name, out_dir):
    """Build a probe to a flat blob whose entry is at offset 0."""
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / f'{name}.bin'
    def payload():
        blob=binary.read_bytes()
        # Direct callers of build() may use P_CALL without run()'s later guard.
        # A single-file .text.entry probe otherwise extracts an empty .text
        # and silently calls whatever executable bytes were already resident.
        if not blob or len(blob)>OUT_AT-CODE_AT:
            raise ValueError(f'{name}: probe payload outside reserved code size ({len(blob)} bytes)')
        return blob
    if name in MULTI:
        objs = []
        for rel in MULTI[name] + optional_sources(name, FLAGS):
            src = ROOT / rel
            obj = out_dir / (src.stem + '-' + src.suffix.lstrip('.') + '.o')
            subprocess.run([str(LLVM / 'clang'), *FLAGS, f'-I{ROOT / "shadow"}',
                            f'-I{ROOT.parent / "q1n1/platform/uefi"}',
                            '-c', str(src), '-o', str(obj)], check=True)
            objs.append(str(obj))
        elf = out_dir / f'{name}.elf'
        subprocess.run([LLD, '-T', str(ROOT / 'probes' / 'probe.ld'),
                        '-o', str(elf), *objs], check=True)
        subprocess.run([str(LLVM / 'llvm-objcopy'), '-O', 'binary', str(elf), str(binary)],
                       check=True)
        return payload()

    source = next(p for p in (ROOT / 'probes').iterdir()
                  if p.stem == name and p.suffix in ('.S', '.c'))
    obj = out_dir / f'{name}.o'
    subprocess.run([str(LLVM / 'clang'), *FLAGS, '-c', str(source), '-o', str(obj)], check=True)
    subprocess.run([str(LLVM / 'llvm-objcopy'), '-O', 'binary', '--only-section=.text',
                    str(obj), str(binary)], check=True)
    return payload()


# The report's geometry, matching probes/xnuboot.c's EVENT_MAX and CONSOLE_MAX.
#
# These were spelled out as literal 64s in five places -- the console's offset,
# the log's length, the slice bound, and two structure offsets derived from
# them -- so growing the log meant finding all five and getting all five right.
# Two of them are offsets into a buffer the probe writes from the other side, so
# a miss does not fault: it reads the console as events, or the counters as
# register snapshots, and prints the result with a straight face.
# tools/test-classify.py rebuilds the same arithmetic independently and refuses
# a mismatch, which is what has caught this class of mistake before.
EVENT_MAX = 512
EVENT_WORDS = 6
CONSOLE_MAX = 1024
# Where the log starts, in bytes from `out`: eight report words, past the
# sixteen the C side's pointer sits above the host's.
LOG_OFFSET = 16 + 8 * 8
LOG_BYTES = EVENT_MAX * EVENT_WORDS * 8
CONSOLE_OFFSET = LOG_OFFSET + LOG_BYTES

# Where the report sits in q1n1's heap, and how much room it has.
#
# Spelled out because the report just grew eightfold and the headroom stopped
# being obviously sufficient. The probe writes this buffer from EL2 with the
# MMU configured its own way; a report that ran past OUT_HEADROOM would not
# fault, it would write into the shadow tables the hardware is walking, and the
# failure would look like a page-table bug anywhere in the run.
# tools/test-classify.py checks the whole report fits.
# 464 KiB for probe code since SNAP_VIEW_RECLAIM: the next1 qualification's
# monitor (--edp-backlight) was 458,552 bytes, 200 short of the previous
# 448 KiB, and the reclaim adds 1,352 (with VIEWRCL1). CODE_AT moves down
# 16 KiB instead of OUT_AT up: the report ends exactly where the stopped-probe
# scratch begins (heap+0x480000, tools/probe-a16-cpus.py), which
# tools/secondary-runtime.py collect writes after the monitor returns and
# before this file reads the report, so a higher report would lose its tail
# (thermal and DVFS records). Below CODE_AT nothing in q1n1's heap is in use
# during a run; the only other user of that range is the fresh-stage
# qualification of tools/qualify-txm-image4-native.py (heap+0x100000, 3 MiB).
# 448 KiB came from native tables 3b (phase 3b's monitor is 320,526 bytes and
# the lock-free trap paths add 6,288, over the previous 320 KiB, itself raised
# from 256 KiB for the ANS2 M2 monitor, docs/ANS2-M2-20260925.md) by moving
# OUT_AT. The report, SECONDARY_CONFIG_AT and WORK_AT are unchanged, the
# monitor binary does not depend on its load address, and every consumer reads
# the code through run.CODE_AT and the report through run.OUT_AT
# (tools/test-monitor-reservation.py).
CODE_AT = 0x3fc000
OUT_AT = 0x470000          # heap_base + this; 464 KiB reserved for probe code
REPORT_RESERVE = 0x10000   # includes metrics for all 24 descriptor slots
STOPPED_PROBE_AT = 0x480000     # stopped-probe scratch, from the report's end (tools/probe-a16-cpus.py)
SECONDARY_CONFIG_AT = 0x4f0000  # the SMP secondaries' configuration page (tools/secondary-runtime.py)
WORK_AT = 0x500000         # generic probe scratch; xnuboot stores its work locator here
# The report must end before the next thing in the heap, the SMP configuration page.
OUT_HEADROOM = SECONDARY_CONFIG_AT - OUT_AT

# The registers the probe traps, by (op0, op1, CRn, CRm, op2) -- the same
# encoding the ESR's ISS carries, and the same SR_* constants xnuboot.c defines.
# A name here is the difference between "S3_0_C2_C0_2, eighteen accesses" and
# "the kernel is reprogramming TCR_EL1 eighteen times".
SYSREGS = {
    (3, 0, 1, 0, 0): 'SCTLR_EL1', (3, 0, 2, 0, 0): 'TTBR0_EL1',
    (3, 0, 2, 0, 1): 'TTBR1_EL1', (3, 0, 2, 0, 2): 'TCR_EL1',
    (3, 0, 10, 2, 0): 'MAIR_EL1', (3, 6, 15, 2, 7): 'AMXIDR_EL1',
    (3, 0, 11, 1, 2): 'CONST_LOWER', (3, 0, 11, 1, 3): 'CONST_UPPER',
    (3, 6, 15, 8, 0): 'GXF_STATUS_EL1',
    (3, 0, 5, 2, 0): 'ESR_EL1', (3, 0, 6, 0, 0): 'FAR_EL1',
    (3, 0, 2, 3, 0): 'APGAKEYLO_EL1', (3, 0, 2, 3, 1): 'APGAKEYHI_EL1',
    (3, 5, 15, 0, 0): 'IPI_RR_LOCAL_EL1', (3, 5, 15, 0, 1): 'IPI_RR_GLOBAL_EL1',
    (3, 5, 15, 1, 1): 'IPI_SR_EL1',
    (3, 6, 15, 1, 5): 'SPRR_UPERM_EL0', (3, 6, 15, 1, 6): 'SPRR_PPERM_EL1',
    (3, 6, 15, 3, 0): 'SPRR_UMPRR_EL1', (3, 6, 15, 3, 1): 'SPRR_PMPRR_EL1',
}

EVENTS = {1: 'monitor call', 2: 'stage-2 fault', 3: 'XNU took an exception',
          4: 'sysreg', 5: 'other', 6: 'watchdog: guest still running',
          7: 'handoff field', 8: 'dispatch command',
          9: 'XNU: fatal exception', 10: 'MAP_PAGE failed',
          11: 'MAP_PAGE outside our memory',
          12: 'SError: the bus refused an access', 13: 'IRQ/FIQ, not the timer',
          # 14 was 'MAP_PAGE withheld from the hardware'. Nothing withholds
          # now, and the number is left unused rather than reassigned so an
          # old transcript keeps its meaning.
          15: 'MAP_PAGE onto a device the tree names',
          16: 'device access with no model',
          17: 'RETYPE', 18: 'RETYPE rejected',
          19: 'MAP_TABLE', 20: 'table operation rejected',
          21: 'UNMAP_REGION', 22: 'UNMAP rejected',
          23: 'MAP_PAGE needs table expansion',
          24: 'kernel exception return', 25: 'exception return rejected',
          26: 'UPDATE_DISJOINT rejected', 27: 'UPDATE_REGION rejected',
          28: 'mapping references rejected', 29: 'SLIDE_REGION rejected',
          30: 'TXM request rejected',
          31: 'SLIDE_REGION completed', 32: 'clock request rejected',
          33: 'guest timer FIQ', 34: 'virtual device operation rejected',
          35: 'guest AIC IRQ', 36: 'virtual device reset request',
          37: 'IPI request rejected', 38: 'CPU monitor contract rejected',
          39: 'SPRR permission operation rejected',
          40: 'user exception return', 41: 'first EL0 instruction verified',
          42: 'EL0 execution witness rejected', 43: 'panic-state contract rejected',
          44: 'native writer breakpoint rejected',
          45: 'linked AuxKC leaf gained EL1 execute',
          46: 'trapped Adreno block touched', 47: 'Adreno SMMU fault or mirror refusal',
          48: 'guest HVC to TrustZone', 49: 'monitor Adreno test fence',
          50: 'virtual ANS2 refusal', 51: 'guest Adreno IB',
          52: 'early stop: deadline reached', 53: 'early stop request',
          54: 'shared-region group records exhausted',
          55: 'stage-2 fault retried',
          57: 'QCC2072 command register written for the guest',
          58: 'Adreno GPU recovery (SNAP_ADRENO_RECOVER)',
          59: 'Adreno IO-coherency self-test (SNAP_ADRENO_COHERENT)'}

SPRR_FAILURES = {2:'invalid SPRR register state',
                 3:'permission change needs a shadow transaction',
                 4:'SPRR control-register write is not implemented',
                 5:'private kernel permission view transaction failed'}

IPI_FAILURES = {2:'invalid IPI state or CPU affinity',3:'IPI request register is write-only',
                4:'target CPU has no executing guest backend',5:'unsupported IPI register bits'}
CPU_FAILURES = {1:'invalid CPU registry state',2:'unknown guest CPU affinity',
                3:'CPU not registered',4:'invalid CPU slot',5:'invalid per-CPU result area'}

DEVICE_FAILURES = {1: 'outside device window', 2: 'invalid device configuration',
                   3: 'unknown register', 4: 'read-only register',
                   5: 'unsupported access width, alignment or syndrome',
                   6: 'unsupported register value or event index'}

CLOCK_FAILURES = {
    2: 'counter is read-only',
    3: 'unsupported clock/timer control bits or event bit index',
    4: 'requested timer register or mode has no implemented clock/interrupt backend',
    5: 'clock backend failed',
}

RETYPE_FAILURES = {
    1: 'invalid monitor memory configuration',
    2: 'page is unaligned or outside XNU allocator memory',
    3: 'unsupported frame-type transition',
    4: 'unsupported monitor operation options',
    5: 'frame metadata or page is not accessible',
    6: 'current type disagrees with the shared frame map',
    7: 'frame has in-flight state or data references',
    8: 'unsupported or malformed page table',
    9: 'parent table is missing',
    10: 'table is already present',
    11: 'shadow mapping preflight or publication failed',
    12: 'mapping reference count would underflow or overflow',
}

# Why a device access stopped the run, from probes/xnuboot.c's MMIO_STOP_*.
#
# Each of these is a thing to go and model, and the event carries everything
# needed to do it: which window, which offset, and -- through the ESR -- how
# wide the access was and which way it went. A modelled access is never logged;
# there is one per character of the kernel's output and the log holds 64
# entries, so the counters carry those instead.
MMIO_STOPS = {
    1: 'the window is one we model, but this offset is not',
    2: 'ISS.ISV clear -- a pair or writeback form, so the syndrome does not say '
       'which registers moved and emulating it would be a guess',
    3: 'an instruction fetch from a device page',
    4: 'the stage-1 table walk faulted into a device page, so the syndrome '
       'describes the access that provoked the walk, not the walk',
    5: 'the tree declares device windows that are not the shape the model was '
       'written against',
}

# The windows, in the order /arm-io/dockchannel-uart's `reg` lists them, which
# is the order the loader derives them in and the order they arrive in params.
MMIO_WINDOWS = {0: 'dockchannel data/config (0x10000)',
                1: 'dockchannel irq (0x1000)'}


# A refused virtual-device access, placed the way the registry names it.
# The kind and IPA alone make every such stop a lookup; with the node, the
# window offset and the decoded direction/width/register it is one line of
# triage. The SEP mailbox's service stage reports an unrecognised submitted
# message through the same result code as an unknown register, so that one
# case is named for what it is.
def device_stop_where(models, ipa, esr, kind, reason):
    model = next((m for m in models if m.base <= ipa < m.base + m.span), None)
    iss = esr & 0x1ffffff
    write = (iss >> 6) & 1
    if (esr >> 26) == 0x24 and (iss >> 24) & 1:
        size = 1 << ((iss >> 22) & 3)
        reg = (iss >> 16) & 31
        access = (f'{"write" if write else "read"} of {size} byte'
                  f'{"s" if size > 1 else ""} {"from" if write else "into"} '
                  f'{"xzr" if reg == 31 else f"x{reg}"}')
    elif (esr >> 26) == 0x24:
        access = (f'{"write" if write else "read"} with no syndrome '
                  f'(pair or writeback form, decoded from the instruction)')
    else:
        access = f'exception class {esr >> 26:#x}'
    if model is None or model.kind != kind:
        return f' ({access})', ''
    offset = ipa - model.base
    note = ''
    if kind == 45 and reason == 3 and write and offset in (0x8800, 0x8808):
        note = ('; the transport accepted the pair, then the virtual SEP '
                'service did not recognise the submitted message')
    return f' ({model.node} +{offset:#x}, {access})', note


def s2_owner_words(ipa, inventory):
    """Which guest-tree window an unanswered IPA lies in, tightest first.

    Same rule as xnuboot.owner_of: windows nest (pmgr contains the console),
    and only the smallest containing one names the device that was touched.
    An absent-IPA stop inside a named window is a driver reaching hardware
    the virtual board does not back: model it, or defer the node."""
    best = None
    for base, size, who in inventory:
        if base <= ipa < base + size and (best is None or size < best[2]):
            best = (who, base, size)
    if best is None:
        return ''
    who, base, size = best
    return f'; inside the guest tree\'s {who} window +{ipa - base:#x} of {size:#x}, which no virtual model answers'


COHERENT_STATES = {0: 'NOT_RUN', 1: 'ON', 2: 'FAILED', 3: 'TIMEOUT', 4: 'REFUSED', 5: 'INCONCLUSIVE',
                   6: 'GPU_ERROR'}   # compat/adreno-guest.h ADRENO_COHERENT_STATE_*
COHERENT_PHASES = {1: 'CPU->GPU control', 2: 'GPU->CPU control', 3: 'CPU->GPU', 4: 'GPU->CPU',
                   5: 'DC IVAC probe (retired)'}   # compat/adreno-coherent.h ADRENO_COHERENT_PHASE_*


def coherent_event_lines(pc, a, b, c):
    """EV_GPU_COHERENT (59) in words: probes/xnuboot.c records pc = the CPU->GPU control's PMU passes, a = state << 32
    | detail, b = passed | the GPU->CPU control's PMU passes << 16, c = the controls' stale words. A forced ON (a
    debug monitor, SNAP_ADRENO_COHERENT_FORCE) is said first and loudly: nothing was proven."""
    state, detail = a >> 32, a & 0xffff
    lines = []
    if detail & 0x2000:
        lines.append('*** FORCED ON WITHOUT THE SELF-TEST (SNAP_ADRENO_COHERENT_FORCE, debug only): GPU write-back '
                     'maintenance skipped UNPROVEN ***')
    phase = (detail >> 8) & 0x1f
    where = '' if state in (1, 4) or not phase else (
        f', at {COHERENT_PHASES.get(phase, f"phase {phase}")}'
        + (f' round {(detail >> 4) & 15} case {detail & 15}' if phase in (3, 4) else ''))
    today = [d for bit, d in ((0x8000, 'CPU->GPU'), (0x4000, 'GPU->CPU')) if detail & bit]
    lines.append(f'state {COHERENT_STATES.get(state, state)} detail {detail:#x}{where}, {b & 0xffff} coherent '
                 f'iterations passed' + (f"; today's leaves already coherent {' and '.join(today)}" if today else '')
                 + (f' (REFUSED precondition {detail})' if state == 4 else ''))
    if state != 4 and not detail & 0x2000:
        for name, stale, pmu in (('CPU->GPU', c >> 32, pc), ('GPU->CPU', c & 0xffffffff, b >> 16)):
            lines.append(f'{name} control: {stale} stale words; PMU refills: witness miss {pmu & 0xffff}, '
                         f'resident {(pmu >> 16) & 0xffff}, witness after {(pmu >> 32) & 0xffff}')
    return lines


def mmio_stop_words(a, esr):
    """One device access that had no answer, in words."""
    reason, window, offset = (a >> 48) & 0xffff, (a >> 32) & 0xffff, a & 0xffffffff
    iss = esr & 0x1ffffff
    if (esr >> 26) == 0x24 and (iss >> 24) & 1:
        size = 1 << ((iss >> 22) & 3)
        direction = 'write' if (iss >> 6) & 1 else 'read'
        access = f'{direction} of {size} byte{"s" if size > 1 else ""}'
    elif (esr >> 26) == 0x20:
        access = 'instruction fetch'
    else:
        access = 'write' if (iss >> 6) & 1 else 'read'
    where = MMIO_WINDOWS.get(window, f'window {window}')
    return (f'window {window} ({where}) +{offset:#x}, {access}; '
            f'{MMIO_STOPS.get(reason, f"reason {reason}")}')

# Monitor call routing, from tools/kc-analyze.py against this kernelcache.
#
# Keyed by (domain, table), not by table alone. Domain was dropped here for the
# same reason the dispatch command was: everything seen so far was domain 0, so
# the field looked like a constant. It is not -- domain 2 table 0 is TXM and
# domain 3 table 0 is the cL4 ringgate, and both would have printed as
# "XNU_BOOTSTRAP" under a table-only lookup.
TABLES = {(0, 0): 'XNU_BOOTSTRAP', (0, 3): 'T8110_DART', (0, 5): 'SART',
          (0, 6): 'NVME', (0, 7): 'UAT', (0, 9): 'CPUTRACE', (0, 10): 'HIB',
          (0, 11): 'GEN3_DART', (0, 13): 'T6000_DART',
          (2, 0): 'TXM_XNU', (3, 0): 'cL4 ringgate'}


def route_name(domain, table):
    return TABLES.get((domain, table), f'domain {domain} table {table}')

# x16 bits 63:56: which kind of call this is, not which endpoint.
#
# Only command 0 is an endpoint call. The others were invisible here until the
# transcript started printing the raw x16 -- they decode to domain 0, table 0,
# endpoint 0, which reads as LOCKDOWN, and that is how four distinct calls came
# to share one line and one answer. SPTM's dispatch_cmd_handler
# (0xfffffff0270f2270) takes this field with `lsr x20, x0, #56` and rejects
# anything at 7 or above; XNU is its calling domain 1, and the handler table at
# 0xfffffff02701f4f8 has entries for that row at 0, 4, 5 and 6, with 2
# special-cased ahead of the lookup. Apple does not name the individual
# commands anywhere in the binary -- the panic path prints "dispatch_cmd_id(%u)"
# as a number -- so neither do we. What each one *does* is recorded instead,
# because that came out of the kernel's own trampolines.
DISPATCH_CMDS = {
    0: 'endpoint call',
    2: 'returns normally (stub ends in ret)',
    4: 'does not return to the call site',
    5: 'does not return; SPTM enters domain 2 (TXM)',
    6: 'does not return; SPTM enters domain 3 (SK)',
}

# How a run ended.
#
# The exit code is the only thing a caller that is not reading the transcript
# ever sees, so every distinct way of stopping gets its own, and none of them
# is zero. Until this run has a checkpoint it can claim to have reached, EXIT_OK
# is unreachable by construction -- entering the kernel, answering monitor
# calls, being taken back by the watchdog and acknowledging an endpoint we have
# not written are all stops, and a harness that cannot tell them apart from
# success cannot be used to judge whether a change helped.
EXIT_OK = 0             # reached the checkpoint that defines this milestone
EXIT_UNCLASSIFIED = 1   # stopped for a reason this function does not recognise
EXIT_LOADER = 2         # the host could not build or place the image
EXIT_PREPARE = 3        # EL2 refused to set the guest up; the kernel never ran
EXIT_EL2_FAULT = 4      # the monitor itself faulted
EXIT_NO_ENTRY = 5       # prepared, but the guest never started
EXIT_GUEST_EXC = 6      # stopped at a guest exception or unmapped stage-2 access
EXIT_UNSUPPORTED = 7    # the kernel asked for something not implemented
EXIT_PANIC = 8          # the kernel panicked, in words
EXIT_WATCHDOG = 9       # the guest was still running when its time ran out
EXIT_SERROR = 10        # the interconnect refused an access the guest made
EXIT_GUEST_RESET = 11   # a virtual device requested guest reset
EXIT_EARLY_STOP = 12    # stopped before the budget on an admitted early-stop request

EXIT_NAMES = {
    EXIT_OK: 'milestone reached',
    EXIT_UNCLASSIFIED: 'stopped, unclassified',
    EXIT_LOADER: 'loader failure',
    EXIT_PREPARE: 'guest preparation failed',
    EXIT_EL2_FAULT: 'EL2 fault',
    EXIT_NO_ENTRY: 'never entered',
    EXIT_GUEST_EXC: 'guest exception',
    EXIT_UNSUPPORTED: 'unsupported operation',
    EXIT_PANIC: 'guest panic',
    EXIT_WATCHDOG: 'watchdog',
    EXIT_SERROR: 'SError',
    EXIT_GUEST_RESET: 'guest reset request',
    EXIT_EARLY_STOP: 'early stop on request',
}

EV_MONITOR, EV_S2_FAULT, EV_GUEST_EXC, EV_WATCHDOG = 1, 2, 3, 6
EV_DISPATCH_CMD, EV_PANIC_ENTRY, EV_MAP_FAILED = 8, 9, 10
EV_MAP_OUTSIDE = 11
EV_SERROR, EV_ASYNC = 12, 13
EV_MMIO_STOP = 16
EV_DEVICE_RESET = 36
EV_EARLY_STOP, EV_EARLY_STOP_REQUEST = 52, 53

# Why xnuboot_prepare() refused to enter the guest. Every negative code
# xnuboot.c can return is here, at module scope so the suite can check that
# none is missing: three of them were added to the probe and never named, so a
# prepare that failed on the TTBR0 shadow printed a bare "-8" -- a number with
# no story, on the one path where the run produced nothing else to read.
PREPARE_FAILURES = {
    -28: 'A16 thermal preflight refused; inspect the thermal report',
    -1: 'no room for the shadow root',
    -2: 'the 16K walk failed',
    -3: 'no room for the stage-2 root',
    -4: 'could not protect a monitor page',
    -5: 'could not protect the vectors',
    -6: 'the hardware refused the shadow for the entry point (that walk reads '
        'the shadow through the read-only work-area range of stage 2; if this '
        'is new, that range is the suspect)',
    -7: 'could not protect a watched handoff page',
    -8: 'no room for the TTBR0 shadow root -- the low regime, which is what the '
        'hardware walks for addresses the kernel treats as physical',
    -9: 'the TTBR0 walk failed over the reserve at low_base',
    -10: 'the stage-2 range list is empty, unaligned, past 36 bits or overlaps '
         'itself; nothing was mapped',
    -11: 'the stage-2 map could not be written (out of work area)',
    -12: 'the write-watch page is outside guest memory, unaligned, or could not be protected',
    -13: 'SLIDE_REGION shadow destination could not be reserved',
    -14: 'virtual device registry has unsupported geometry or overlaps mapped memory',
    -15: 'clock adapter requires valid rates, matching host frequency and FEAT_ECV',
    -16: 'CPU affinity or six per-CPU result areas do not match the boot contract',
    -19: 'the host secondary configuration was refused (magic, regime, layout; mask bit 0, a relocated vCPU 0, '
         'needs a monitor built with -DSNAP_BOOT_RELOCATE=1)',
    -21: 'static trust-cache payload, reservation or read-only protection is invalid',
    -27: 'SNAP_USER_HW_WALK_S2RO: the stage-2 trees could not be pre-split to level 3 over guest RAM '
         '(out of work area)',
    # Stage 4 (compat/adreno.h): adoption of q1n1's GPU, before the guest runs.
    -60: 'Adreno params invalid, or the arena overlaps guest memory, or SPI 0x14C is Secure',
    -61: 'Adreno CX GDSC is off: run the q1n1 bring-up and adopt again',
    -62: 'Adreno GX is off (GMU_PWR_CLK_STATUS): OOB GPU_SET no longer held',
    -63: 'Adreno SMMU context bank 0 is not the one q1n1 adopted',
    -64: 'Adreno CB0 root entries 1..3 are in use: the mirror window is not free',
    -65: 'Adreno SQE is not running',
    -66: 'Adreno ring pointers disagree with the adoption record, or the fenced WPTR write was dropped',
    -67: 'an Adreno SMMU fault is already recorded',
    -68: 'the Adreno did not write the monitor test fence within 50 ms',
    -71: 'Adreno GX-side GBIF is halted (a previous quiesce): q1n1 quiesce --write, redo cp-fence, adopt again',
    -72: 'Adreno guest fence target is absent, outside native byte bounds or mismatched with its writable SMMU mirror',
    -73: 'Adreno native DART unmap failed or left a live leaf; retain resource backing and reservation',
    # SNAP_BOOT_RELOCATE (compat/boot-relocate.h): vCPU 0 never entered on its relocated CPU; the secondary
    # result's boot_relocation row holds record 0 (on_result, phase, error, id_differences).
    -80: 'vCPU 0 relocation: the target CPU was not OFF, or PSCI CPU_ON refused it',
    -81: 'vCPU 0 relocation: the target CPU turned OFF without reaching the monitor (secondary_entry refused it)',
    -82: 'vCPU 0 relocation: the target CPU stopped before guest entry (record 0 error: 0x100 GIC, 0x103 '
         'registers, 0x104/0x105 FP, 0x107 an ID register the shared preparation used differs, 0x108 '
         'CNTVOFF_EL2 or CNTFRQ_EL0 differs from q1n1\'s CPU)',
}
# Which vector an asynchronous exception arrived at, from probes/xnuboot.S.
ASYNC_VECTORS = {0: 'IRQ', 1: 'FIQ', 2: 'SError'}
# EV_ASYNC's kind: a vector, or probes/xnuboot.c ASYNC_IRQ_OTHER (SNAP_FAST_TIMER_IRQ), an
# IRQ whose lock-free acknowledge returned, and completed, another INTID than the timer's 26.
ASYNC_KINDS = {**ASYNC_VECTORS, 3: 'IRQ (its lock-free acknowledge returned another INTID than the timer\'s)'}
# compat/adreno.h block classes (EV_GPU_TRAP c).
ADRENO_BLOCKS = {1: 'passthrough window', 2: 'CX_MISC (read-only)', 3: 'GMU_GX', 4: 'RDVM',
                 5: 'GMU_AO', 6: 'RSCC', 7: 'SMMU aperture', 8: 'GX clock controller', 9: 'GMU',
                 10: 'GPUCC', 11: 'CX_MISC', 12: 'SMMU', 13: 'hole'}

# A stage-2 fault's syndrome, in words. EC 0x24 is a data abort and 0x20 an
# instruction abort from EL1; both carry the fault status in ISS[5:0], whose
# top bits say the kind and whose low two say the level. A data abort with
# ISS.ISV set also names the access -- size, register, direction -- which is
# what a device model needs and what makes the next step cheap without
# decoding the instruction at the PC. ISV clear (pair loads, writeback forms)
# is said as such, because then the PC is the only way to know.
FSC_KINDS = {0: 'address size fault', 1: 'translation fault',
             2: 'access flag fault', 3: 'permission fault'}
FSC_OTHER = {0x10: 'synchronous external abort', 0x21: 'alignment fault',
             0x30: 'TLB conflict', 0x35: 'unsupported atomic update'}


def s2_fault_words(ipa, esr):
    ec, iss = esr >> 26, esr & 0x1ffffff
    fsc = iss & 0x3f
    if fsc >> 2 in FSC_KINDS:
        kind = f'stage-2 {FSC_KINDS[fsc >> 2]} at level {fsc & 3}'
    else:
        kind = FSC_OTHER.get(fsc, f'fault status {fsc:#04x}')
    if ec == 0x20:
        access = 'instruction fetch'
    elif ec == 0x24:
        direction = 'write' if (iss >> 6) & 1 else 'read'
        if (iss >> 24) & 1:                                  # ISV
            size = 1 << ((iss >> 22) & 3)
            reg = (iss >> 16) & 0x1f
            width = 'x' if (iss >> 15) & 1 else 'w'
            access = (f'{direction} of {size} byte{"s" if size > 1 else ""}, '
                      f'{width}{reg}')
            if (iss >> 21) & 1:
                access += ', sign-extended'
        else:
            access = (f'{direction}, ISV clear -- a pair or writeback form; '
                      f'the instruction at the PC says the rest')
    else:
        return f'EC {ec:#x}, not an abort from EL1 (ESR {esr:#x})'
    if (iss >> 7) & 1:
        access += ', on the stage-1 table walk (S1PTW: the IPA is a table page)'
    if not ipa:
        return (f'{kind}; {access}; IPA unknown -- the stage-1 walk failed and '
                f'HPFAR read zero')
    return f'{kind}; {access}'


def s2_where_words(ipa, ranges):
    """The IPA against the map: inside a range it is that range's permission
    that refused it; in none, the address does not exist for the guest."""
    if not ipa:
        return 'nowhere we can name'
    for lo, hi, access, what in ranges:
        if lo <= ipa < hi:
            return f'inside the {what} range {lo:#x}..{hi:#x} ({access})'
    return 'in no range of the stage-2 map: a device, or memory we did not declare'
SPTM_FN_MAP_PAGE = 2   # matches probes/xnuboot.c

# classify()'s last resort, as a constant because conclude() has to tell it
# apart from the other unclassified verdicts. EXIT_UNCLASSIFIED is reached both
# when nothing was found and when something was found that is not modelled -- a
# stray IRQ, a fault word that cannot be a syndrome -- and only the first of
# those is a run whose story is the events it lost.
NOTHING_RECOGNISED = ('the run ended without reaching a checkpoint and '
                      'without a recognised stop')


def is_syndrome(word):
    """Could this word be an ESR at all?

    The fault slot in the report is a syndrome and nothing else, but it used to
    be overwritten with the exception-return trampoline XNU registers -- a
    kernel code address -- so classify() read "is it non-zero" and answered
    "a fault was recorded", printing a return address under the label ESR.

    ESR puts EC in bits 31:26 and leaves everything above bit 36 clear; a kernel
    virtual address on this machine has the top sixteen bits set, so the two
    shapes cannot be confused once anything looks. EC zero is "unknown reason",
    which nothing here records, so it is refused too."""
    return bool(word) and (word >> 36) == 0 and ((word >> 26) & 0x3f) != 0


def verdict(code, reason):
    """Print how the run ended and hand back the exit code, in one place so a
    stop cannot be reported in the transcript and lost on the way out."""
    print(f'\n== {EXIT_NAMES[code].upper()} (exit {code}) ==\n   {reason}')
    return code


def console_panic(console):
    """A panic announcement, not incidental words such as gPanicBase."""
    return next((line for line in console.splitlines()
                 if line.lstrip().lower().startswith(
                     ('panic:', 'panic(', 'nested panic detected -'))), '')


def early_stop_module():
    """tools/early_stop.py: the record decoder and the SNAP_EARLY_STOP* settings."""
    import importlib.util
    if str(ROOT/'tools') not in sys.path: sys.path.insert(0,str(ROOT/'tools'))
    spec = importlib.util.spec_from_file_location('early_stop', ROOT / 'tools/early_stop.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def early_stop_reason(record, log):
    """The verdict sentence for EXIT_EARLY_STOP, from the report record or,
    without one, from the EV_EARLY_STOP entry (a = source << 32 | reason)."""
    names = early_stop_module()
    if record:
        source, reason, detail = record['source'], record['reason'], record['detail']
        delay, text = record['accepted_delay'], record.get('text', '')
    else:
        entry = next(event for event in log if event[0] == EV_EARLY_STOP)
        source, reason, detail, delay, text = entry[2] >> 32, entry[2] & 0xffffffff, entry[3], entry[4], ''
    said = f', "{text}"' if text else ''
    return (f'stopped early on a {names.SOURCES.get(source, source)} request: '
            f'{names.reason_name(source, reason)}{said} (detail {detail:#x}, {delay}s after it was '
            f'accepted) through the watchdog\'s own stop; RAM is retained as at a budget stop')


def classify(entered, fault, console, log, tally=None, dropped=0,
             last_event=None, models=(), inventory=()):
    """Why did this run stop? Returns (exit code, one-line reason).

    `tally` is the probe's counters when they are available. They refuse
    verdicts the run's own arithmetic contradicts, and they supply every count
    that appears in a reason -- never a verdict of their own -- because the log
    can be truncated and collapses repeats while the counters can do neither.

    `dropped` is how many events the log had no room for. It suppresses exactly
    the inferences that read the log's TAIL, and nothing else. The log fills
    from the front, so what survives an overflow is the START of the run: a
    MAP_PAGE we refused, a panic announcement, a stage-2 fault are facts sitting
    in that head, and losing the tail does not un-record them. Only "the last
    event was a monitor call, so that is where it stopped" stops being available,
    because with a tail missing the last surviving event is not the last one.

    `last_event` is the probe's terminal word: the last event it recorded, kept
    outside the ring and so never dropped. When it is present it is what the
    tail branches read, and truncation stops mattering to them.

    Ordered most specific first, and every branch is reading something the run
    actually recorded rather than inferring from what it did not.

    The unsupported-endpoint case is the subtle one. xnuboot.c logs every call
    before dispatching it, and when the dispatch finds an endpoint it has not
    implemented in strict mode it logs the call a second time and stops -- so a
    run whose last event is a monitor call stopped because of that call.

    This used to argue that no terminal word was needed, because "every other
    way of stopping records its own terminal event". That was true of the
    PROBE and false of the REPORT, and the difference is the whole bug: the
    events are recorded, and then the 64-entry log drops them. A run that
    overflows has no tail to read, so the tail branches were unavailable
    exactly when the boot got far enough to reach them -- which is how a run
    that made 390 monitor calls ended "stopped, unclassified ... the run
    stopped for a reason nothing recorded". No log size fixes that; a longer
    log only moves the point where it starts lying. The terminal word does."""
    if not entered:
        return EXIT_NO_ENTRY, 'the guest never started'

    if tally:
        owner = tally.get('service_owner', 0)
        stop = tally.get('service_stop', 0)
        faults = tally.get('service_faults', ())
        lifecycle = tally.get('service_lifecycle')
        reusable = tally.get('service_reusable')
        bad_lifecycle = ((lifecycle is not None or reusable is not None) and
                         (lifecycle not in (1 << 63, (1 << 63) | 3) or
                          reusable != 1 or not stop))
        if owner or any(faults) or bad_lifecycle or (stop and
                ((stop >> 32) != 1 or not 1 <= (stop & 0xffffffff) <= 6)):
            return EXIT_EL2_FAULT, (f'monitor service lock failure: owner token {owner}, '
                                   f'stop {stop:#x}, CPU faults {tuple(faults)}, '
                                   f'lifecycle {lifecycle}, reusable {reusable}')

    # Where the tail comes from. With the terminal word it is a fact about how
    # the run ended; without one it is an inference from the log's last row,
    # and truncation takes even that away. Everything that reads `kinds` is a
    # fact about what happened either way.
    if last_event is not None:
        tail, last = last_event, last_event[0]
    else:
        tail = log[-1] if log else None
        last = None if dropped else (tail[0] if tail else None)
    # The out-of-ring terminal event is also evidence. Otherwise a fault or
    # watchdog after log saturation becomes "unclassified" despite its record.
    if last_event is not None and last_event not in log:
        log = [*log, last_event]
    kinds = {event[0] for event in log}

    # An SError outranks everything for the same reason the watchdog does: it
    # ends the run from outside whatever the guest was doing, so no verdict read
    # off the log's tail describes how it actually stopped. It used to BE the
    # watchdog verdict -- one vector served IRQ, FIQ and SError alike -- and the
    # two readings are opposites: "the kernel needed longer" against "the kernel
    # touched something the interconnect refused to answer".
    if EV_SERROR in kinds:
        entry = next(event for event in log if event[0] == EV_SERROR)
        pc, esr = entry[1], entry[2]
        return EXIT_SERROR, (
            f'the guest took an SError at pc {pc:#x} -- ESR_EL2 {esr:#x} '
            f'(EC {esr >> 26:#x}, IDS {(esr >> 24) & 1}, DFSC {esr & 0x3f:#04x}) '
            f'-- an access the interconnect refused, not a kernel that needed '
            f'more time')
    if EV_DEVICE_RESET in kinds:
        entry = next(event for event in log if event[0] == EV_DEVICE_RESET)
        bitmap=entry[2] | (entry[3]<<64)
        return EXIT_GUEST_RESET, (f'virtual device requested guest reset at pc {entry[1]:#x}; '
                                  f'model bitmap {bitmap:#x}; host reset was not issued')
    # An admitted early stop (compat/early-stop.h) ends the run through the
    # watchdog's own path before the budget. The report's record says so even
    # when the log saturated and the terminal word moved on. A panic the kernel
    # announced first is still the finding, exactly as for the watchdog.
    early = (tally or {}).get('early_stop') or {}
    if EV_EARLY_STOP in kinds or early.get('outcome') == 1:
        if (first := console_panic(console)):
            return EXIT_PANIC, (f'the kernel panicked before the early stop took effect: '
                                f'{first.strip()[:120]}')
        return EXIT_EARLY_STOP, early_stop_reason(early, log)
    if EV_WATCHDOG in kinds:
        if (first := console_panic(console)):
            return EXIT_PANIC, (f'the kernel panicked before the watchdog recovered '
                                f'control: {first.strip()[:120]}')
        return EXIT_WATCHDOG, ('the guest was still running when its time ran '
                               'out, which is not the same as getting anywhere')
    # An IRQ or FIQ with the comparator not fired. Named, not modelled: nothing
    # here routes any interrupt but the EL2 physical timer to EL2, so what
    # raised this is something the project does not yet know about. Calling it a
    # recognised stop would be the same confident falsehood in the other
    # direction, so the code stays unclassified and the sentence carries the
    # fact.
    if EV_ASYNC in kinds:
        entry = next(event for event in log if event[0] == EV_ASYNC)
        pc, which = entry[1], entry[2]
        return EXIT_UNCLASSIFIED, (
            f'an {ASYNC_KINDS.get(which, which)} was taken to EL2 at guest pc '
            f'{pc:#x} with the EL2 physical timer not fired -- nothing here '
            f'routes any other interrupt to EL2, so what raised it is unknown')
    # Words beat syndromes: if the kernel managed to say what it thought went
    # wrong, that is the finding, and the exception that carried it is detail.
    # A map we refused, named. Checked before the console because a panic
    # downstream of our own error should say so: "pmap_enter failed" is the
    # kernel's symptom, and our MAP_PAGE returning an error is the cause. The
    # panic text is kept in the reason either way.
    if EV_MAP_FAILED in kinds:
        entry = next(event for event in log if event[0] == EV_MAP_FAILED)
        reason, va, detail = entry[2] & 0xff, entry[3], entry[4]
        # From the probe's own counter, never from counting log lines. record()
        # collapses repeats by (kind, pc, a), so N failures at N addresses can
        # arrive as one entry, and an overflowed log drops the rest outright --
        # counting entries would under-report both ways. The log count is the
        # fallback only when there is no tally, which is how the offline tests
        # call this. `entry` is genuinely the first: the log fills from the
        # front, so the head is the beginning of the run.
        counted = (tally or {}).get('map_failures')
        failures = counted if counted else sum(
            1 for event in log if event[0] == EV_MAP_FAILED)
        why = MAP_FAILURES.get(reason, f'reason {reason}, unrecognised')
        said = ''
        if (line := console_panic(console)):
            said = f'; the kernel then panicked: {line.strip()[:90]}'
        return EXIT_UNSUPPORTED, (
            f'MAP_PAGE returned an error {failures} time'
            f'{"" if failures == 1 else "s"}, first at va {va:#x} '
            f'(detail {detail:#x}): {why}{said}')
    if last == 34:
        _, pc, packed, ipa, esr = tail[:5]
        kind, reason = packed >> 32, packed & 0xffffffff
        where, note = device_stop_where(models, ipa, esr, kind, reason)
        return EXIT_UNSUPPORTED, (
            f'virtual device model {kind} rejected access at {pc:#x}, '
            f'IPA {ipa:#x}{where}, ESR {esr:#x}: '
            f'{DEVICE_FAILURES.get(reason, f"unknown device error {reason}")}{note}')
    if last == 50:
        # compat/ans.h: a = ANS_E_* << 32 | model kind (MMIO) or table << 8 |
        # endpoint (SPTM); b, c = IPA and ESR, or x0 and x1.
        import ansstate
        _, pc, packed, b, c = tail[:5]
        reason, where = packed >> 32, packed & 0xffffffff
        name = ansstate.ERRORS[reason] if reason < len(ansstate.ERRORS) else f'error {reason}'
        site = (f'model {where}, IPA {b:#x}, ESR {c:#x}' if where in (49, 50) else
                f'SPTM table {where >> 8} endpoint {where & 0xff}, x0 {b:#x}, x1 {c:#x}')
        return EXIT_UNSUPPORTED, f'the virtual ANS2 refused ({name}) at {pc:#x}: {site}'
    if last == 39:
        _, pc, reason, iss, value = tail[:5]
        return EXIT_UNSUPPORTED, (
            f'SPRR permission operation rejected at {pc:#x}, ISS {iss:#x}, value {value:#x}: '
            f'{SPRR_FAILURES.get(reason, f"unknown SPRR error {reason}")}')
    if last == 43:
        return EXIT_UNSUPPORTED, (f'panic-state contract stopped at {tail[1]:#x}: '
            f'command {tail[2]:#x}, owner {tail[3]:#x}, CPU {tail[4]}')
    if last == 44:
        return EXIT_UNSUPPORTED, (f'native writer breakpoint rejected at {tail[1]:#x}: '
            f'ESR {tail[2]:#x}, instruction PA {tail[3]:#x}, word {tail[4]:#x}')
    if last == 46:
        return EXIT_UNSUPPORTED, (f'the guest touched a trapped Adreno block at {tail[1]:#x}: '
            f'IPA {tail[2]:#x} ({ADRENO_BLOCKS.get(tail[4], tail[4])}), {s2_fault_words(tail[2], tail[3])}')
    if last == 48 and tail[4] == (1 << 64) - 1:
        return EXIT_UNSUPPORTED, (f'the guest made an HVC the monitor does not forward at {tail[1]:#x}: '
            f'x0 {tail[2]:#x}, x1 {tail[3]:#x}')
    if last == 47 and tail[2] >> 63:
        return EXIT_UNSUPPORTED, (f'the Adreno SMMU mirror refused at {tail[1]:#x}: '
            f'{tail[2] - (1 << 64)}, IOVA {tail[3]:#x}, endpoint {tail[4]}')
    if last == 38:
        _, pc, reason, endpoint, argument = tail[:5]
        return EXIT_UNSUPPORTED, (
            f'CPU monitor contract rejected at {pc:#x}, endpoint {endpoint:#x}, argument {argument:#x}: '
            f'{CPU_FAILURES.get(reason, f"unknown CPU error {reason}")}')
    if last == 37:
        _, pc, reason, iss, value = tail[:5]
        return EXIT_UNSUPPORTED, (
            f'IPI request rejected at {pc:#x}, ISS {iss:#x}, value {value:#x}: '
            f'{IPI_FAILURES.get(reason, f"unknown IPI error {reason}")}')
    if last == 32:
        _, pc, reason, iss, value = tail[:5]
        return EXIT_UNSUPPORTED, (
            f'clock request rejected at {pc:#x}, ISS {iss:#x}, value {value:#x}: '
            f'{CLOCK_FAILURES.get(reason, f"unknown clock error {reason}")}')
    if last == 54:
        _, pc, full, root, groups = tail[:5]
        return EXIT_UNSUPPORTED, (
            f'shared-region group records exhausted at {pc:#x}, root {root:#x}: all {groups} records '
            f'are in use (full {full}); SNAP_NATIVE_SHARED cannot mirror another nested level-3 table')
    if last in (18, 20, 22, 26, 27, 28, 29, 30):
        _, pc, reason, pa, new_type = tail[:5]
        return EXIT_UNSUPPORTED, (
            f'{ {18: "RETYPE", 20: "SPTM table/root operation", 22: "UNMAP_REGION", 26: "UPDATE_DISJOINT", 27: "UPDATE_REGION", 28: "mapping references", 29: "SLIDE_REGION", 30: "TXM request"}[last]} rejected at {pc:#x}, '
            f'address {pa:#x}, requested value {new_type:#x}: '
            f'{RETYPE_FAILURES.get(reason, f"unknown error {reason}")}')
    if (first := console_panic(console)):
        return EXIT_PANIC, f'the kernel panicked: {first.strip()[:120]}'
    # XNU saying so itself, which beats us inferring it from a syndrome. This
    # call is made on the way out of a fatal exception, before panic() has run,
    # so it fires even when no panic string is ever produced.
    if EV_PANIC_ENTRY in kinds:
        entry = next(event for event in log if event[0] == EV_PANIC_ENTRY)
        caller, elr, esr = entry[2], entry[3], entry[4]
        if caller == WEDGE_CALLER:
            return EXIT_PANIC, (
                f'XNU wedged: an integrity check failed at ELR_EL1 {elr:#x} '
                f'(ESR {esr:#x}) and it is spinning on wfe forever, so nothing '
                f'after that call runs whatever we answer')
        return EXIT_PANIC, (
            f'XNU announced a fatal exception from {caller:#x} '
            f'({PANIC_CALLERS.get(caller, "an unrecognised path")}), '
            f'ELR_EL1 {elr:#x} ESR_EL1 {esr:#x} (EC {esr >> 26:#x})')
    if last == EV_GUEST_EXC:
        return EXIT_GUEST_EXC, 'the probe stopped at entry to the guest exception handler'
    if last == 25:
        return EXIT_UNSUPPORTED, (f'unsupported exception return at {tail[1]:#x}: '
                                  f'target {tail[2]:#x}, SPSR {tail[3]:#x}, '
                                  f'instruction {tail[4]:#x}')
    if last == 42:
        return EXIT_UNSUPPORTED, (f'EL0 execution witness rejected at {tail[1]:#x}: '
                                  f'entry {tail[2]:#x}, X0 {tail[3]:#x}, '
                                  f'physical SPSR {tail[4]:#x}')
    # A device we model, at a register we do not. Checked before the plain
    # stage-2 fault because it is the more specific of the two: the address is
    # already known to be a device window the kernel's own tree names, and the
    # event carries the offset, which is the thing the next iteration needs.
    if EV_MMIO_STOP in kinds:
        entry = next(event for event in log if event[0] == EV_MMIO_STOP)
        pc, a, esr = entry[1], entry[2], entry[3]
        return EXIT_UNSUPPORTED, (
            f'the kernel used a device register we do not model: '
            f'{mmio_stop_words(a, esr)}, at pc {pc:#x}')
    if EV_S2_FAULT in kinds:
        entry = next(event for event in log if event[0] == EV_S2_FAULT)
        pc, ipa, esr = entry[1], entry[2], entry[3]
        return EXIT_GUEST_EXC, (
            f'the kernel touched an intermediate address stage 2 does not give '
            f'it: IPA {f"{ipa:#x}" if ipa else "unknown"} '
            f'({s2_fault_words(ipa, esr)}) at pc {pc:#x}'
            f'{s2_owner_words(ipa, inventory) if ipa else ""}')
    # A call that is not an endpoint call at all. Checked before EV_MONITOR
    # because the guest records both for one of these -- the call, then the
    # refusal -- and the refusal is the more specific of the two.
    if last == EV_DISPATCH_CMD:
        cmd, _, x16 = tail[2], tail[3], tail[4]
        return EXIT_UNSUPPORTED, (
            f'the kernel made dispatch command {cmd:#x} (x16 {x16:#018x}), which '
            f'is not an endpoint call and is not implemented')
    if last == EV_MONITOR:
        x16 = tail[2]
        cmd, domain = (x16 >> 56) & 0xff, (x16 >> 48) & 0xff
        table, fn = (x16 >> 32) & 0xffff, x16 & 0xffffffff
        name = route_name(domain, table)
        if cmd:
            return EXIT_UNSUPPORTED, (
                f'the kernel made dispatch command {cmd:#x} (x16 {x16:#018x}), '
                f'which is not an endpoint call and is not implemented')
        # Never claim an endpoint is unimplemented when this same run counted
        # completions of it. That sentence was emitted for MAP_PAGE after 379
        # successful calls, off a truncated log, and it is exactly the kind of
        # confident falsehood the transcript must not contain. The check is two
        # lines and does not depend on anyone reading the log.
        completed = (tally or {}).get('map_pages', 0)
        if domain == 0 and table == 0 and fn == SPTM_FN_MAP_PAGE and completed:
            return EXIT_UNCLASSIFIED, (
                f'the last event is a {name} endpoint {fn:#x} call, but this run '
                f'completed {completed} of them -- the log does not reach the '
                f'real ending, so no cause can be named from it')
        return EXIT_UNSUPPORTED, (f'the kernel asked for {name} endpoint {fn:#x}, '
                                  f'which is not implemented')
    if fault:
        # The slot carries a syndrome. Anything else in it is a bug on the
        # probe's side, and saying so is better than decoding a code address as
        # an ESR -- which is what this branch did for every run after XNU
        # registered its exception-return trampoline.
        if not is_syndrome(fault):
            return EXIT_UNCLASSIFIED, (
                f'the run ended without a recognised stop, and the fault word '
                f'holds {fault:#x}, which is not a syndrome -- so nothing here '
                f'may report it as one')
        return EXIT_GUEST_EXC, (f'a fault was recorded (ESR {fault:#x}, '
                                f'EC {fault >> 26:#x})')
    # Nothing above matched. With the terminal word we can still say WHAT the
    # run was doing when it stopped, even though we cannot say why -- and that
    # is the difference between "the run stopped for a reason nothing recorded"
    # and a sentence somebody can act on. The code stays unclassified, because
    # naming the last event is not the same as recognising the stop.
    if last_event is not None:
        kind, pc, a, b, c = last_event[:5]
        return EXIT_UNCLASSIFIED, (
            f'the run stopped in a way this does not model; the last thing it '
            f'recorded was "{EVENTS.get(kind, kind)}" at pc {pc:#x} '
            f'(a {a:#x}, b {b:#x}, c {c:#x}) -- the terminal word, which the '
            f'log cannot drop')
    # Nothing above matched and there is no terminal word either, so the run
    # ended in a way this does not model. Saying so is the point: the
    # alternative is calling it success.
    return EXIT_UNCLASSIFIED, NOTHING_RECOGNISED


def conclude(entered, fault, console, log, tally=None, dropped=0,
             panic_said=None, last_event=None, models=(), inventory=()):
    """The verdict for a finished run, log loss and all.

    An overflowed log used to skip classify() entirely and report only the loss.
    That threw away everything the surviving head held -- including MAP_PAGE
    failures, which is what the last two commits exist to surface -- and as the
    boot gets longer, overflow stops being the edge case and becomes the normal
    one. So: classify from what survived, with the tail inferences suppressed,
    and fall back to the loss report only when what survived names nothing."""
    code, why = classify(entered, fault, console, log, tally, dropped,
                         last_event, models, inventory)
    if panic_said and code in (EXIT_GUEST_EXC, EXIT_PANIC, EXIT_UNCLASSIFIED):
        code, why = EXIT_PANIC, f'the kernel panicked: {panic_said.strip()[:240]}'
    if not dropped:
        return code, why
    # With a terminal word the ending is not in doubt, whichever branch named
    # it: either a fact from the surviving head, or the last event itself. What
    # the loss costs is the middle of the run, and that is what this says.
    if last_event is not None:
        return code, (f'{why}  ({dropped} events did not fit the {len(log)}-entry '
                      f'log; the run\'s last event is recorded outside it, so '
                      f'how it ended is known and what led there is not)')
    if why == NOTHING_RECOGNISED:
        # Nothing in the head named a cause, so the loss is the finding -- and
        # XNU's panic record, which memory holds and truncation cannot reach,
        # is the better answer when there is one. Keyed on what was found and
        # not on the exit code, because a stray IRQ and a fault word that is not
        # a syndrome are both unclassified AND both facts the head still holds.
        return truncated(dropped, len(log), panic_said)
    # A fact from the head. It stands, and the loss is disclosed beside it so
    # nobody reads it as a complete account of how the run ended.
    return code, (f'{why}  ({dropped} events did not fit the {len(log)}-entry '
                  f'log, so this is what the surviving head names, not '
                  f'necessarily the last thing that happened)')


FOUR_GIB = 1 << 32


def free_region(proxy, info, need, xb_align=0x2000000, required_base=None, exclude=()):
    """The largest free physical span the target reports, big enough for `need`.

    q1n1 publishes the UEFI memory map it captured before ExitBootServices, so
    the target can be asked where its memory is instead of being told. What it
    reports is where firmware said RAM was; what q1n1 then took out of it --
    its own image, heap, DMA buffer and staging area -- is in the bootinfo, and
    is carved back out here, because the map was taken before those existed.

    Under 4 GiB is preferred but not required: it lets TCR_EL1.IPS stay at 0 and
    keeps the stage-2 identity map to 36 bits.

    `exclude` is [(low, high)] carved out as well: reservations made for this
    launch only (the QCC2072 arena, probes/qcc2072wifi.RESERVATION)."""
    free = monitor_work.firmware_free(proxy, info)
    for low, high in exclude:
        free = [piece for start, end in free
                for piece in ((start, min(end, low)), (max(start, high), end)) if piece[0] < piece[1]]
    best = None
    for start, end in free:
        # On the 32 MiB grid, both ends. XNU rounds the top of DRAM up to a
        # 32 MiB boundary (0xfffffe000ba7a7ec), so a region that ends anywhere
        # else has arithmetic pointing just past it.
        start = (start + xb_align - 1) // xb_align * xb_align
        end = end // xb_align * xb_align
        if required_base is not None:
            if required_base % xb_align or not start <= required_base < end:
                continue
            start = required_base
        if end - start < need:
            continue
        score = (end - start >= need and start + need <= FOUR_GIB, end - start)
        if best is None or score > best[0]:
            best = (score, start, end)
    return None if best is None else (best[1], best[2])


def check_panel_control(proxy):
    """Require panel ownership before a large upload, retaining its old state."""
    try:
        previous = proxy.fb_console(False)
        if previous not in (0, 1):
            raise ValueError('q1n1 returned an invalid panel ownership state')
        if previous and proxy.fb_console(True) != 0:
            raise ValueError('q1n1 did not retain the panel ownership transition')
    except q1n1.ProxyRemoteError as error:
        raise ValueError('resident q1n1 rejected panel ownership; RAM-chainload '
                         'the latest q1n1 stage before running XNU') from error


# q1n1's call service (q1n1 platform/uefi/call-service.h), bootinfo words 66
# and 67. Read directly, so an older tools/q1n1proxy.py field list still finds
# them; its state record starts with magic, version and size.
CALL_SERVICE_WORD = 66
CALL_STATE_MAGIC = 0x4c4c4143314e3151            # "Q1N1CALL"


def call_service(proxy, info):
    """(entry, state) of the running q1n1 stage's call service, or (0, 0)."""
    base = info['address']
    size = struct.unpack('<Q', proxy.readmem(base + 16, 8))[0]
    if size < (CALL_SERVICE_WORD + 2) * 8:
        return 0, 0
    entry, state = struct.unpack('<2Q', proxy.readmem(base + CALL_SERVICE_WORD * 8, 16))
    if not entry:
        return 0, 0
    image, span = info['image_base'], info['image_size']
    if entry & 3 or not image <= entry < image + span or not image <= state < image + span - 24:
        raise ValueError(f'call service {entry:#x}/{state:#x} lies outside the running q1n1 image')
    magic, version, length = struct.unpack('<3Q', proxy.readmem(state, 24))
    if magic != CALL_STATE_MAGIC or version != 1 or length < 24 or length > 4096:
        raise ValueError('q1n1 call-service record has the wrong magic, version or size')
    return entry, state


def host_stop_link(proxy):
    """The host trigger reaches q1n1 only as a UDP datagram on the USB-NCM
    link the proxy itself uses (the stop port beside the proxy's). Over CDC or
    a socket nothing could deliver one, so a launch there must not claim it."""
    endpoint = str(getattr(proxy, 'endpoint', '') or '')
    if not endpoint.startswith('udp://') or not endpoint[6:]:
        raise ValueError('the host trigger needs the proxy on USB-NCM (udp://INTERFACE), not '
                         + (endpoint or 'an unnamed link'))
    return endpoint


def run_xnuboot(proxy, info, code, guest_profile='j700ap-26A428',
                firmware_dir=None, kernelcache=None, console_mode='auto',
                relay_panel=False, ramdisk=None, root_hash=None, ramdisk_mode='md0', isc_image=None,
                graphics_boot=False, auxkc=None, trust_additions=None, ans_disk=None, ans_writable=False,
                code_size=None):
    """Put a stock kernelcache in memory and enter it at EL1.

    The image, its 16K page tables and the handoff are all built and checked on
    the host first (probes/xnuboot.py); this uploads them and makes the call."""
    import importlib.util
    import preload
    try:
        cached_files = preload.resident_cache(proxy, info)
    except ValueError as error:
        return verdict(EXIT_LOADER, f'invalid EFI asset cache: {error}')
    spec = importlib.util.spec_from_file_location('xnuboot', ROOT / 'probes/xnuboot.py')
    xb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(xb)
    try:
        xb.configure_guest(guest_profile, firmware_dir)
        # SNAP_TXM_ASPACE_WIDE=1 goes with a -DSNAP_TXM_ASPACE_WIDE=1 monitor
        # (compat/txm.h A2); unset keeps the 8-page layout. Before place().
        xb.configure_txm_arena()
        # SNAP_ADRENO_VA_WIDE=1 goes with a -DADRENO_VA_WIDE=1 monitor and kext and a q1n1
        # `cp-fence/adopt --va-wide` CB0 (agents/gpu-va-wide); unset keeps the 3 GiB window. Before place().
        if xb.configure_adreno_va_wide() and xb.GUEST_PROFILE.adreno is None:
            raise ValueError(f'{xb.ADRENO_VA_WIDE_ENV}=1 needs an Adreno profile')
        if xb.GUEST_PROFILE.sep_asc and xb.GUEST_PROFILE.sep_asc.pnon_recovery and (
                not ramdisk or not root_hash or ramdisk_mode!='iokit'):
            raise ValueError('ordinary-recovery pnon requires the hash-bound IOKit BaseSystem root')
        host = HostRuntime.from_q1n1(info, with_framebuffer=
                                    not bool(os.environ.get('SNAP_NO_FB')))
        if console_mode == 'auto':
            console_mode = 'panel' if host.framebuffer else 'serial'
        if graphics_boot:
            if console_mode!='panel' or not host.framebuffer or relay_panel:
                raise ValueError('--graphics-boot requires a native framebuffer and panel route')
            xb.VIDEO_DISPLAY_MODE=1
            xb.BOOT_CMDLINE=' '.join(arg for arg in xb.BOOT_CMDLINE.split() if arg!='-v')
        if relay_panel and host.framebuffer:
            raise ValueError('--relay-panel requires SNAP_NO_FB=1; host drawing '
                             'cannot share a framebuffer measurement')
        xb.HOST_TIMEBASE_HZ = host.timer_hz
        kernelcache = kernelcache or xb.DEFAULT_KERNELCACHE
    except ValueError as error:
        return verdict(EXIT_LOADER, str(error))
    # The QCC2072 Wi-Fi passthrough (probes/qcc2072wifi.py), opt-in: its three
    # inputs, staged and hash-checked by cycle.py installed-fresh --prepare,
    # read before anything is placed. Without SNAP_QCC2072_WIFI nothing here runs.
    qcc_inputs = None
    xb.QCC2072_WIFI = None
    # --present-beam's read-only DPU INTF_5 page (probes/displaytiming.py), opt-in: the loader half of a
    # -DSNAP_DISPLAY_TIMING=1 monitor. Without SNAP_DISPLAY_TIMING nothing here runs.
    xb.DISPLAY_TIMING = None
    if os.environ.get('SNAP_DISPLAY_TIMING'):
        if os.environ['SNAP_DISPLAY_TIMING'] != '1':
            return verdict(EXIT_LOADER, 'SNAP_DISPLAY_TIMING must be 1')
        import displaytiming
        xb.DISPLAY_TIMING = displaytiming.SPEC
    if os.environ.get('SNAP_QCC2072_WIFI'):
        import qcc2072wifi
        try:
            if os.environ['SNAP_QCC2072_WIFI'] != '1':
                raise ValueError('SNAP_QCC2072_WIFI must be 1')
            qcc_inputs = qcc2072wifi.load_inputs(os.environ[qcc2072wifi.INPUTS_ENV])
        except (KeyError, OSError, ValueError) as error:
            return verdict(EXIT_LOADER, f'QCC2072 inputs refused: {error!r}')

    # The profile, before anything is built. Every address in xnuboot.py was
    # read out of one specific set of firmware images, and none of them are
    # re-derived at run time -- so a firmware swap does not fail, it produces a
    # full transcript describing a machine that does not exist. Checking four
    # hashes costs under a second of a run that spends fifty on the upload.
    bad = xb.check_profile(kernelcache=kernelcache)
    if bad:
        return verdict(EXIT_LOADER,
                       f'firmware does not match profile {xb.PROFILE_NAME}: '
                       + '; '.join(bad))
    print(f'  profile {xb.PROFILE_NAME} ({xb.PROFILE_TARGET}, {xb.PROFILE_BUILD}), '
          f'firmware verified')
    print(f'  host adapter {host.adapter}, timer {host.timer_hz} Hz; '
          f'guest counter {xb.TIMEBASE_HZ} Hz; guest ABI {xb.GUEST_PROFILE.abi}')
    if host.framebuffer:
        try:
            check_panel_control(proxy)
        except ValueError as error:
            return verdict(EXIT_LOADER, str(error))

    # Full-install M2: the virtual ANS2's RAM disk, pinned by the profile and
    # checked whole (both GPT copies, the APFS container geometry) before any
    # placement. It reaches the guest only through the monitor's controller.
    ans_image = None
    ans_window = xb.GUEST_PROFILE.ans_boot is not None and xb.GUEST_PROFILE.ans_boot.window
    if ans_writable and (not ans_window or not xb.GUEST_PROFILE.installed_root):
        return verdict(EXIT_LOADER, '--ans-writable requires an installed SSD window profile')
    if ans_window and ans_disk:
        return verdict(EXIT_LOADER, '--ans-disk does not apply to the SSD window profile')
    if xb.GUEST_PROFILE.ans_boot is not None and not ans_window:
        import ansdisk
        import hashlib
        spec = xb.GUEST_PROFILE.ans_boot
        try:
            if not ans_disk:
                raise ValueError('an ANS2 profile needs --ans-disk '
                                 '(build/build-ans-test-disk-20260925.py)')
            ans_image = Path(ans_disk).read_bytes()
            if (len(ans_image) != spec.disk_bytes or
                    hashlib.sha256(ans_image).hexdigest() != spec.disk_sha256):
                raise ValueError(f'{ans_disk} is not the disk profile {xb.PROFILE_NAME} pins')
            ansdisk.inspect(ans_image)
        except (OSError, ValueError) as error:
            return verdict(EXIT_LOADER, f'virtual ANS2 disk refused: {error}')
        print(f'  virtual ANS2 disk {ans_disk}: {len(ans_image) >> 20} MiB, 4 KiB LBAs, '
              f'sha256 {spec.disk_sha256[:16]}... (profile pin)')
    elif ans_disk:
        return verdict(EXIT_LOADER, '--ans-disk needs a profile with a virtual ANS2')
    # How much memory the guest gets, stated rather than inherited from whatever
    # the firmware left free. See xnuboot.DEFAULT_GUEST_MIB.
    guest_span = int(os.environ.get('SNAP_GUEST_MIB', xb.DEFAULT_GUEST_MIB)) << 20
    want = os.environ.get('SNAP_PHYS_BASE')
    try:
        # Ask for the reserve too. The kernel puts a structure above the
        # DRAM we declare, so the free span has to extend past the
        # declaration by that much.
        need = guest_span + xb.bootstrap_reserve(guest_span) + monitor_work.WORK_SIZE
        if xb.GUEST_PROFILE.ans_boot is not None:
            need += xb.ans_reservation()[1] + ((1 << 20) if ans_window else 0)   # window: 1 MiB alignment
        if xb.ADRENO_VA_WIDE:
            import adreno
            need += adreno.pool_reservation_bytes() + adreno.POOL_RESERVATION_ALIGN   # its 64 KiB alignment
        region = free_region(proxy, info, need, xb.REGION_ALIGN,
                             required_base=int(want, 0) if want else None,
                             **({'exclude': [qcc2072wifi.RESERVATION]} if qcc_inputs else {}))
        if region is None:
            # Not a warning. Carrying on with the default placement runs the
            # image somewhere the target did not say was free, and whatever
            # happens next is evidence about the wrong machine.
            return verdict(EXIT_LOADER,
                           f'no free region of {need >> 20} MiB in the '
                           f"target's memory map")
        start, end = region
        xb.place(start, end - start, guest_span=guest_span)
        work = (xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN + 65535) & ~65535
        work_size = monitor_work.WORK_SIZE
        monitor_work.validate_region(work, work_size, xb.PHYS_BASE,
                                     xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN, info, [region])
        print(f'  layout placed at {start:#x} .. {xb.REGION_END:#x} '
              f'({xb.REGION_SPAN >> 20} MiB guest, of {(end - start) >> 20} '
              f'MiB free, {xb.BOOTSTRAP_SPAN >> 20} MiB held back above it)')
        print(f'  monitor work arena {work:#x} .. {work + work_size:#x} '
              f'({work_size >> 20} MiB, separate from guest and q1n1 heap)')
        ans_range = xb.ans_reservation()
        monitor_end = work + work_size
        if ans_range:
            monitor_work.validate_ans(*ans_range, work, work_size, info, [region])
            monitor_end = ans_range[0] + ans_range[1]
            print(f'  virtual ANS2 reservation {ans_range[0]:#x} .. {monitor_end:#x} '
                  + ('(state, GPT head/tail, SSD params and its 1 MiB DMA window; outside stage 2)'
                     if ans_window else
                     f'(state, reserved page, {len(ans_image) >> 20} MiB disk; outside stage 2)'))
        gpu_pool = xb.gpu_pool_reservation()
        if gpu_pool:
            monitor_work.validate_gpu_pool(*gpu_pool, monitor_end, info, [region])
            monitor_end = gpu_pool[0] + gpu_pool[1]
            print(f'  GPU table reservation {gpu_pool[0]:#x} .. {monitor_end:#x} (ADRENO_VA_WIDE: 15 level-2 and '
                  '7680 level-3 tables for GPU VA [1 GiB, 16 GiB); outside stage 2)')
    except (ValueError, SystemExit) as error:
        return verdict(EXIT_LOADER, f'could not place the layout: {error}')

    # Full-install M6: q1n1 takes the SSD over with its queues in the reservation's DMA window,
    # checks the partition and its window header through its own reads, and leaves it running for
    # the monitor (q1n1 tools/nvme_m3.py adopt mode). Nothing else writes that 1 MiB afterwards.
    ans_window_parts = None
    if ans_window:
        import argparse as _argparse
        import answindow
        import nvme_m3
        spec = xb.GUEST_PROFILE.ans_boot
        adopt = dict(tool='nvme_m3', format=1, mode='adopt', stopped=None)
        try:
            status = nvme_m3.run(proxy, _argparse.Namespace(
                adopt_dma=ans_range[0] + answindow.WINDOW_DMA, partition_guid=spec.window_guid,
                survey=None, timed_mib=0), adopt)
            adopt['exit_code'] = status
            if status:
                raise ValueError(f'adopt exited {status}')
            head = adopt['window_armed']['header']
            desc = answindow.layout(spec.disk_bytes, head['isc_offset'], head['isc_region'],
                                    head['container_offset'])
            import uuid as _uuid
            overlays = answindow.overlays(desc, *(_uuid.UUID(g) for g in spec.window_gpt))
            params = answindow.nvmeh_params(adopt, ans_range[0], host.timer_hz, writable=ans_writable)
            adopt['guest_writable'] = ans_writable
            adopt['guest_params_hex'] = params.hex()
            ans_window_parts = (overlays[0], overlays[1], params)
        except (nvme_m3.Stop, ValueError, KeyError) as error:
            adopt['stopped'] = adopt['stopped'] or dict(reason=str(error))
            return verdict(EXIT_LOADER, f'SSD window refused: {error}')
        finally:
            prefix = os.environ.get('SNAP_SMP_REPORT_PREFIX')
            if prefix:
                import json as _json
                with (ROOT/'build'/f'{prefix}-nvme-adopt.json').open('x') as output:
                    _json.dump(adopt, output, indent=1)
        armed = adopt['window_armed']
        print(f'  SSD window armed: partition {armed["partition"]} LBA {armed["first_lba"]}..'
              f'{armed["last_lba"]}, header {armed["header"]["provisioned"]}, '
              f'queues left running at {ans_range[0] + answindow.WINDOW_DMA:#x}, '
              f'guest {"read/write with FUA and Flush" if ans_writable else "read-only"}')

    # Also guard explicit SNAP_PHYS_BASE placement. The normal allocator only
    # chooses conventional memory; the cache and its table are LoaderData.
    cache_ranges = [(f['base'], f['allocation']) for f in cached_files]
    if info.get('preload_table'):
        cache_ranges.append((info['preload_table'], (info['preload_size']+4095)&~4095))
    if any(xb.PHYS_BASE < base+size and base < monitor_end
           for base, size in cache_ranges):
        return verdict(EXIT_LOADER, 'guest or monitor placement overlaps reserved EFI asset cache')
    # Stage 4: the GPU q1n1 powered, adopted from `a16gpu.py adopt`. The record
    # must describe this q1n1 stage and its arena, and the arena must miss the
    # guest, the monitor, the EFI asset cache and the panel.
    xb.ADRENO_RECORD = None
    if xb.GUEST_PROFILE.adreno is not None:
        import adreno
        path = os.environ.get('SNAP_ADRENO_ADOPT')
        if not path:
            return verdict(EXIT_LOADER, 'an Adreno profile needs SNAP_ADRENO_ADOPT '
                           '(q1n1 tools/a16gpu.py adopt --record FILE, just before the launch)')
        try:
            record = adreno.load_adoption(path, info, xb.ADRENO_VA_WIDE)
            adreno.check_disjoint(record, [(xb.PHYS_BASE, monitor_end - xb.PHYS_BASE),
                                           *cache_ranges,
                                           (info.get('fb_base', 0), info.get('fb_size', 0))])
            if xb.ADRENO_VA_WIDE:
                adreno.check_pool_reservation(record, xb.gpu_pool_reservation()[0],
                                              [(xb.PHYS_BASE, xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN - xb.PHYS_BASE),
                                               *cache_ranges, (info.get('fb_base', 0), info.get('fb_size', 0))])
        except (OSError, ValueError, KeyError) as error:
            return verdict(EXIT_LOADER, f'Adreno adoption refused: {error}')
        xb.ADRENO_RECORD = record
        print(f'  Adreno adopted from q1n1 generation {record["stage_generation"]}: arena '
              f'{record["arena"]["base"]:#x}+{record["arena"]["size"]:#x}, ring wptr '
              f'{record["ring"]["wptr"]}, CB0 TTBR0 {record["cb0"]["ttbr0"]:#x}, '
              f'TZ init {"done" if record.get("tz_init_done") else "not made"}')

    # The QCC2072 Wi-Fi admission, live and before the image is built: the
    # reservation in this boot's free memory and clear of every placement, the
    # arena in the PCIe SMMU's identity stage 2, the endpoint in PBL with its
    # command register at memory decode only. The record binds this stage's
    # generation and a fresh cookie. Retained as PREFIX-qcc2072-admission.json.
    qcc_record = None
    if qcc_inputs:
        import json as _json
        import secrets
        qcc_record = dict(status='ADMITTING', stage_generation=info['stage_generation'])
        try:
            occupied = [(xb.PHYS_BASE, monitor_end - xb.PHYS_BASE), *cache_ranges,
                        (info.get('fb_base', 0), info.get('fb_size', 0))]
            if xb.ADRENO_RECORD:
                occupied.append((xb.ADRENO_RECORD['arena']['base'], xb.ADRENO_RECORD['arena']['size']))
            qcc_record.update(qcc2072wifi.admit(proxy, info, monitor_work.firmware_free(proxy, info), occupied))
            spec = qcc2072wifi.Spec(info['stage_generation'] or 1, secrets.randbits(63) | 1,
                                    xb.PHYS_BASE, (1 << 36) - xb.PHYS_BASE)
            xb.QCC2072_WIFI = qcc2072wifi.grant(spec, qcc_inputs)
            qcc_record.update(status='ADMITTED', generation=spec.generation, cookie=hex(spec.cookie),
                              guest=[hex(spec.guest_pa), hex(spec.guest_bytes)],
                              record_hex=xb.QCC2072_WIFI.record.hex(),
                              inputs={n: qcc2072wifi.SHA(d) for n, d in qcc_inputs.items()})
        except (KeyError, OSError, ValueError) as error:
            qcc_record.update(status='REFUSED', error=repr(error))
        prefix = os.environ.get('SNAP_SMP_REPORT_PREFIX')
        if prefix:
            with (ROOT / 'build' / f'{prefix}-qcc2072-admission.json').open('x') as output:
                _json.dump(qcc_record, output, indent=1)
        if qcc_record['status'] != 'ADMITTED':
            return verdict(EXIT_LOADER, f'QCC2072 admission refused: {qcc_record["error"]}')
        print(f'  QCC2072 admitted: command {qcc_record["command_before"]} -> {qcc_record["command_after"]}, '
              f'BHI EE {qcc_record["mhi"].get("BHI_EXECENV")}, SMMU S2 {qcc_record["smmu"]["s2ttb"]} maps '
              f'the arena identity RW, record generation {spec.generation}')

    # The panel, from the machine in front of us. Giving XNU the real thing is
    # what turns our transcript of its console into its own console.
    #
    # On by default; SNAP_NO_FB reproduces the original serial-only baseline.
    # The host adapter has already validated its geometry and allocation.
    if host.framebuffer:
        if not info.get('fb_base'):
            return verdict(EXIT_LOADER,
                           'SNAP_FB was asked for but q1n1 reports no framebuffer')
        # Bytes per pixel from GOP's own PixelFormat, not from dividing the
        # allocation by the geometry. The allocation is whatever the firmware
        # rounded up to; on a panel whose fb_size has slack, that division
        # silently produced a depth the hardware does not use. Formats 0
        # (RGBX8888) and 1 (BGRX8888) are the two 32-bit ones. Format 2 is a
        # bitmask and 3 is blt-only, and boot_args.Video has no way to say
        # either, so those are refused rather than guessed at.
        fmt = info.get('fb_format', 0)
        if fmt not in (0, 1):
            return verdict(EXIT_LOADER,
                           f'GOP pixel format {fmt} is not one boot_args.Video '
                           f'can describe (0 = RGBX8888, 1 = BGRX8888)')
        depth = 4
        xb.FRAMEBUFFER = host.framebuffer.boot_video()
        print(f'  panel {info["fb_width"]}x{info["fb_height"]}x{depth * 8} '
              f'({"RGB" if fmt == 0 else "BGR"}) at {info["fb_base"]:#x} '
              f'handed to XNU')
    else:
        print('  serial-only baseline (SNAP_NO_FB); panel withheld')
    if console_mode == 'panel':
        if not host.framebuffer:
            return verdict(EXIT_LOADER, '--console panel requires a framebuffer')
        xb.BOOT_CMDLINE = xb.BOOT_CMDLINE.replace('serial=3', 'serial=2')
    print(f'  console route {console_mode}; host relay {"on" if relay_panel else "off"}')
    if graphics_boot:
        print('  native graphics boot handoff, verbose text disabled; this is not GUI qualification')
    if os.environ.get('SNAP_PROVOKE'):
        xb.PROVOKE = os.environ['SNAP_PROVOKE']
        print(f'  provoking a panic: withholding {xb.PROVOKE}')
    if os.environ.get('SNAP_WATCH'):
        xb.WATCH_OFF = False
    # Early stop (compat/early-stop.h, tools/early_stop.py): off unless
    # SNAP_EARLY_STOP names a trigger. The guest trigger needs our Adreno kext;
    # the host trigger needs a q1n1 stage that publishes its call service.
    early_names = early_stop_module()
    early_call = (0, 0)
    try:
        early = early_names.settings()
        if early is not None:
            if early.thermal:
                runpy.run_path(str(ROOT/'tools/a16_thermal.py'))['admit_target'](info)
            if early.guest and xb.GUEST_PROFILE.adreno is None:
                raise ValueError('the guest trigger needs an Adreno profile; its kext sends the request')
            if early.host:
                host_stop_link(proxy)
                early_call = call_service(proxy, info)
                if not early_call[0]:
                    raise ValueError('this q1n1 stage publishes no call service; chainload one that does')
            early_words = early.params_words(*early_call)
    except (OSError, ValueError, RuntimeError) as error:
        return verdict(EXIT_LOADER, f'early stop refused: {error}')
    xb.EARLY_STOP = early
    print('building the image and its address space...')
    try:
        built = xb.build(str(kernelcache), ramdisk=ramdisk, root_hash=root_hash,
                         ramdisk_mode=ramdisk_mode, isc_image=isc_image,
                         auxkc=auxkc, trust_additions=trust_additions)
    except (OSError, ValueError, SystemExit) as error:
        # Includes the frame table outgrowing its arena, which is what a
        # too-large automatic region currently produces.
        return verdict(EXIT_LOADER, f'could not build the image: {error}')
    if os.environ.get('SNAP_NO_PROTECT'):
        # A control: with nothing marked execute-never, a fault on the very
        # first fetch cannot be the stage-2 protection and has to be stage 1.
        # The vector page stays protected even here: it is the only thing that
        # turns a fault XNU takes into a report instead of a hang.
        built['stub_pa'] = []
        built['chunks'][xb.PARAMS_PA] = xb.params_blob(built)
        print('  control run: no pages protected')
    chunks = dict(built['chunks'])
    if os.environ.get('SNAP_TXM_NATIVE'):
        import txmnative
        try:
            if not xb.GUEST_PROFILE.installed_root or not built['trust_cache'][0]:
                raise ValueError('native Image4 is qualified only for the installed J700 profile')
            native_work = work + work_size - txmnative.WORK_BYTES
            built['txm_native'], native_record = txmnative.install(proxy, info,
                os.environ['SNAP_TXM_NATIVE'], chunks[xb.DEVICETREE_PA], native_work)
            prefix = os.environ.get('SNAP_SMP_REPORT_PREFIX')
            if not prefix:
                raise ValueError('native Image4 requires a source-bound run prefix')
            import json as _json
            with (ROOT / 'build' / f'{prefix}-txm-native.json').open('x') as output:
                _json.dump(native_record, output, indent=2)
            print(f'  native Image4: qualified helper, private workspace {native_work:#x}, actual boot tree')
        except (OSError, ValueError) as error:
            return verdict(EXIT_LOADER, f'native Image4 refused: {error}')
    for pa, page in built['tables'].chunks():
        chunks[pa] = bytes(page)

    total = sum(len(b) for b in chunks.values())
    print(f'  {len(chunks)} chunks, {total / (1 << 20):.1f} MiB, entry '
          f'{built["entry"]:#x}')
    # Re-uploading 115 MiB costs ~47s an iteration, and the bring-up loop is one
    # iteration per endpoint. SNAP_FAST re-sends only what XNU can have dirtied
    # -- the data segments, the tables and the handoff -- and leaves the text
    # alone. Wrong only if XNU writes its own text, which it does not.
    if os.environ.get('SNAP_PERMISSIVE'):
        built['permissive'] = True
        built['chunks'][xb.PARAMS_PA] = xb.params_blob(built)
        chunks[xb.PARAMS_PA] = built['chunks'][xb.PARAMS_PA]
        print('  permissive: unimplemented endpoints are acknowledged')
    built['watchdog'] = int(os.environ.get('SNAP_WATCHDOG', '2'))
    if early is not None:
        built['early_stop'] = early_words
        print(f'  early stop on: {"guest " if early.guest else ""}{"host " if early.host else ""}'
              f'trigger{", two-way console (tools/guest-console.py)" if early.console else ""}, '
              f'default delay {early.delay}s, bound {early.max_delay}s'
              + (f', q1n1 polled every {early.poll_ms} ms, session {early.session:#018x}'
                 if early.host else ''))
    if os.environ.get('SNAP_WATCH_WRITE'):
        built['write_watch_va'] = int(os.environ['SNAP_WATCH_WRITE'], 0)
        print(f'  stop before writes to the 4K page at {built["write_watch_va"]:#x}')
    if os.environ.get('SNAP_SKIP_UNDEF'):
        # Step over encodings this silicon does not implement, and count them.
        # Opt-in: a run that only gets further because of this is not a run that
        # works, and the counter is what keeps the two apart.
        built['skip_undef'] = True
        built['chunks'][xb.PARAMS_PA] = xb.params_blob(built)
        chunks[xb.PARAMS_PA] = built['chunks'][xb.PARAMS_PA]
        print('  stepping over unimplemented instruction encodings')
    if os.environ.get('SNAP_LET_PANIC'):
        built['let_panic'] = True
        built['chunks'][xb.PARAMS_PA] = xb.params_blob(built)
        chunks[xb.PARAMS_PA] = built['chunks'][xb.PARAMS_PA]
        print('  faults resume into XNU\'s own handler, so it can panic in words')
    # Serialize after all runtime overrides, including the watchdog. Otherwise
    # a watchdog-only run silently keeps build()'s two-second default.
    try:
        chunks[xb.PARAMS_PA] = xb.params_blob(built)
    except ValueError as error:
        return verdict(EXIT_LOADER, str(error))
    if os.environ.get('SNAP_FAST'):
        keep = {}
        for name, vmaddr, vmsize, _, filesize in built['image'].segments:
            if filesize and ('DATA' in name or name == '__LINKEDIT'):
                keep[xb.IMAGE_PA + (vmaddr - built['vmin'])] = True
        chunks = {pa: b for pa, b in chunks.items()
                  if pa in keep or pa >= xb.HANDOFF_PA}
        print(f'  fast path: {len(chunks)} chunks')
    # Recheck APF metadata against resources known only after host discovery.
    # Do this before uploading, not after an inconsistent tree has been sent.
    out = info['heap_base'] + OUT_AT
    secondary_api = None
    host_cpus = 0
    if os.environ.get('SNAP_SMP') == '1':
        secondary_api = runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))
        try:
            # The uploaded image's size: a monitor built outside build/ (cycle.py
            # speed-test) must not be measured by whatever build/xnuboot.bin holds.
            host_cpus = secondary_api['prepare'](proxy,info,code,
                code_size or (ROOT/'build/xnuboot.bin').stat().st_size,
                work,work_size,guest_profile)
        except ValueError as error:
            return verdict(EXIT_LOADER,str(error))
    # The monitor's own context size: FLAGS are the build's (cycle.py sets them before
    # building and before booting). A define-free size is short by whatever the build's
    # defines add (SNAP_UNNEST_4K_FAST: 0xf8000 bytes), which put the last part of the
    # private context inside the guest-readable table window below.
    monitor_layout=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout'](FLAGS)
    table_start=(work+monitor_layout.size('context')+4095)&~4095
    table_end = built['txm_native'][1] if built.get('txm_native') else work+work_size
    s2_ranges = xb.stage2_ranges(work=(table_start, table_end-table_start))
    try:
        xb.validate_apf_memory(built['dart_apf_slices'],
                               [(lo, hi-lo) for lo, hi, _, _ in s2_ranges]+[(work,work_size)])
    except ValueError as error:
        return verdict(EXIT_LOADER, str(error))
    cached_disk = None
    # The EFI cache contains the original authenticated BaseSystem, including
    # when it occupies one partition in a larger GPT RAM disk.
    disk_range = built.get('ramdisk_root_range')
    if disk_range and not os.environ.get('SNAP_NO_PRELOAD'):
        import hashlib
        disk_pa, disk_size = disk_range
        matches = [f for f in cached_files if f['size'] == disk_size]
        if matches:
            digest = hashlib.sha256(chunks[disk_pa]).hexdigest()
            cached_disk = next((f for f in matches if f['sha256'] == digest), None)
    if os.environ.get('SNAP_REQUIRE_PRELOAD') and cached_disk is None:
        return verdict(EXIT_LOADER, 'required matching EFI RAMDisk cache is unavailable')
    start = time.time()
    if cached_disk:
        try:
            preload.copy_cached(proxy, info, cached_disk, disk_pa, disk_size)
        except ValueError as error:
            return verdict(EXIT_LOADER, f'EFI RAMDisk cache refused: {error}')
        del chunks[disk_pa]
        print(f'  SSD preload: verified and copied {disk_size / (1 << 20):.1f} MiB '
              f'locally in {time.time() - start:.1f}s; no BaseSystem USB upload')
    if built.get('ramdisk_isc_range'):
        import bootmedia
        isc_pa, isc_size = built['ramdisk_isc_range']
        sent = bootmedia.upload_auxiliary(proxy, isc_pa, chunks[isc_pa])
        del chunks[isc_pa]
        print(f'  ISC initialized {isc_size >> 20} MiB locally; '
              f'uploaded {sent / (1 << 20):.2f} MiB of nonzero blocks')
    for pa, blob in sorted(chunks.items()):
        proxy.writemem(pa, blob)
    if ans_range and ans_window:
        # Everything below the SSD's DMA window: state and firmware page zero, the synthesized
        # GPT's head and tail, the SSD params (state zero). The queues q1n1 left running in the
        # DMA window are not touched.
        import answindow
        import bootmedia
        head, tail, params = ans_window_parts
        base = ans_range[0]
        payload = bytearray(answindow.WINDOW_DMA)
        payload[answindow.WINDOW_HEAD:answindow.WINDOW_HEAD + len(head)] = head
        payload[answindow.WINDOW_TAIL:answindow.WINDOW_TAIL + len(tail)] = tail
        payload[answindow.WINDOW_NVMEH:answindow.WINDOW_NVMEH + len(params)] = params
        sent = bootmedia.upload_auxiliary(proxy, base, bytes(payload))
        checks = [(answindow.WINDOW_HEAD, 3 * 4096), (answindow.WINDOW_TAIL + len(tail) - 5 * 4096, 5 * 4096),
                  (answindow.WINDOW_NVMEH, 0x140)]
        if any(proxy.readmem(base + off, n) != bytes(payload[off:off + n]) for off, n in checks):
            return verdict(EXIT_LOADER, 'virtual ANS2 window reservation did not verify')
        print(f'  virtual ANS2 window placed; uploaded {sent / (1 << 20):.2f} MiB of nonzero blocks, '
              f'GPT and SSD params read back')
    elif ans_range:
        # Every byte of the reservation is written: the state page and the
        # reserved page zero (the monitor's prepare resets the state), the
        # disk, then zero to the end. Only nonzero 64 KiB blocks cross USB.
        import bootmedia
        from devicemodel import ANS_DISK_OFFSET
        base, span = ans_range
        payload = (bytes(ANS_DISK_OFFSET) + ans_image +
                   bytes(span - ANS_DISK_OFFSET - len(ans_image)))
        sent = bootmedia.upload_auxiliary(proxy, base, payload)
        edges = [(ANS_DISK_OFFSET, 4096), (ANS_DISK_OFFSET + 4096, 4096),
                 (ANS_DISK_OFFSET + len(ans_image) - 4096, 4096)]
        if any(proxy.readmem(base + off, n) != payload[off:off + n] for off, n in edges):
            return verdict(EXIT_LOADER, 'virtual ANS2 disk upload did not verify')
        print(f'  virtual ANS2 disk placed; uploaded {sent / (1 << 20):.2f} MiB of nonzero '
              f'blocks, GPT headers read back')
    if qcc_record is not None:
        # Every byte of the QCC2072 arena (the firmware container, the board ELF and
        # the regulatory database at the record's offsets, zero elsewhere) and of
        # the control page's guest page, cleaned and invalidated to PoC, read back.
        import bootmedia
        try:
            qcc_record['upload'] = qcc2072wifi.upload(proxy, xb.QCC2072_WIFI, qcc_inputs,
                                                      bootmedia.upload_auxiliary)
        except ValueError as error:
            return verdict(EXIT_LOADER, f'QCC2072 arena refused: {error}')
        print(f'  QCC2072 arena {qcc2072wifi.DMA_PA:#x} +64 MiB and control page {qcc2072wifi.CONTROL_PA:#x} '
              f'written ({qcc_record["upload"]["sent_bytes"] / (1 << 20):.2f} MiB nonzero), cleaned to PoC, '
              f'record {qcc_record["upload"]["record_sha256"][:16]} read back')
    # The image is code, and the caches have to agree with memory before
    # anything fetches from it.
    proxy.flush_code(xb.IMAGE_PA, built['mapped'])
    print(f'  uploaded in {time.time() - start:.1f}s')

    # The shadow is 4K where the guest's tables are 16K, so it needs four leaf
    # entries per guest page -- and the physical aperture added half a gigabyte
    # of linear mapping, which is most of the leaves. 4 MiB was enough before it
    # existed and is not now; the failure is legible (prepare returns -1/-2/-3)
    # but it costs a round trip, and q1n1's heap is 64 MiB.
    # The stage-2 map, stated before the run so a stop with an address can be
    # read against it: what the guest may touch, and that nothing else exists.
    # The probe builds the same list from its params and its work area.
    for lo, hi, access, what in s2_ranges:
        print(f'  stage 2            {lo:#x} .. {hi:#x}  {access}  {what}')
    print('  stage 2            everything else absent: a touch stops the run '
          'with its IPA')
    # Framebuffer ownership is witnessed inside the probe, with q1n1's UI
    # suspended. Serial row samples outside that interval add no guest-write
    # evidence and can fail before entry or prevent reading a completed report.
    if host.framebuffer:
        proxy.fb_console(False)
        print('  q1n1 status drawing paused; XNU retains panel ownership after return')
    # Allow the guest watchdog to stop every CPU and publish its report before
    # the host gives up waiting. A fixed 600s timeout races a 600s guest run.
    call_timeout = max(600, built['watchdog'] + 60)
    monitor_work.publish_work(proxy, info, work, work_size, xb.PHYS_BASE,
                              xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN)
    if any(m.kind==48 for m in built['device_models']):
        import hashlib, json
        from devicemodel import seed_rtc_models
        # Image upload is complete. The virtual UTC epoch is sampled here and
        # starts advancing when the timed device registry initializes. Record
        # that boundary; this is not a precision-synchronized physical RTC.
        epoch_us=time.time_ns()//1000
        built['device_models']=seed_rtc_models(built['device_models'],epoch_us)
        parameters=xb.params_blob(built)
        proxy.writemem(built['params_pa'],parameters)
        if proxy.readmem(built['params_pa'],len(parameters))!=parameters:
            raise RuntimeError('RTC seed parameter readback mismatch')
        prefix=os.environ.get('SNAP_SMP_REPORT_PREFIX')
        if not prefix or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in prefix):
            raise RuntimeError('RTC qualification requires a fresh report prefix')
        path=ROOT/'build'/f'{prefix}-rtc-seed.json'
        with path.open('x') as output:
            json.dump(dict(epoch_us=epoch_us,after_upload=True,
                           parameter_sha256=hashlib.sha256(parameters).hexdigest(),
                           pre_call_host_us=time.time_ns()//1000,
                           boundary='UTC sampled before call; counter origin at device registry start'),output,indent=2)
        print(f'  virtual RTC seeded from host UTC: {epoch_us} microseconds since Unix epoch')
    early_prefix = os.environ.get('SNAP_SMP_REPORT_PREFIX')
    if early is not None and early_prefix:
        # Before the call: tools/request-stop.py --launch-record binds a host
        # request to this session, and collectors find the settings here.
        import json as early_json
        with (ROOT/'build'/f'{early_prefix}-early-stop-launch.json').open('x') as output:
            early_json.dump(dict(early.record(), call_service=f'{early_call[0]:#x}',
                           call_state=f'{early_call[1]:#x}', watchdog_s=built['watchdog'],
                           stage_generation=info['stage_generation']), output, indent=2)
    result = proxy.call(code, out, work, work_size, built['params_pa'], host_cpus,
                        timeout=call_timeout)
    require_xnuboot_terminal(result)  # before any report/peer/ANS read or cleanup
    if qcc_record is not None:
        # The card may still master the bus. The launcher turns that off once the
        # stopped state is preserved (cycle_lib/installed_fresh.py qcc2072_stop),
        # never before: a proxy fault here would freeze the capture.
        print('  QCC2072: bus mastering is left to the launcher, after preservation')
    if secondary_api:
        secondary_result=secondary_api['collect'](proxy,work,work_size)
        print('  physical secondary result:',secondary_result)
    if ans_range:
        # The monitor's own record of the virtual ANS2 (compat/ans.h), read
        # from the reservation after the stop. Observation only.
        import ansstate, json
        try:
            state = ansstate.decode(proxy.readmem(ans_range[0], ansstate.SIZE))
            print('  virtual ANS2:', ansstate.describe(state))
            physical_nvme = None
            if ans_window:
                physical_nvme = answindow.decode_nvmeh(proxy.readmem(ans_range[0]+answindow.WINDOW_NVMEH,0x120))
                print('  physical NVMe:', physical_nvme['state'])
            prefix = os.environ.get('SNAP_SMP_REPORT_PREFIX')
            if prefix:
                with (ROOT/'build'/f'{prefix}-ans.json').open('x') as output:
                    json.dump(dict(reservation=list(ans_range), state=state,
                                   physical_nvme=physical_nvme), output, indent=2)
        except (OSError, ValueError) as error:
            print('  virtual ANS2 state unreadable:', error)

    status, entered = struct.unpack('<2Q', proxy.readmem(out, 16))
    report = struct.unpack('<8Q', proxy.readmem(out + 16, 64))
    s_root, leaves, traps, events, steps, s2_root, fault, calls = report
    monitor_calls, console_len = calls & 0xffffffff, calls >> 32
    fb_span, fb_before_hash, fb_after_hash = struct.unpack('<3Q',
        proxy.readmem(out + FRAMEBUFFER_WITNESS_OFFSET, 24))
    if fb_span:
        print(f'  framebuffer during guest execution: {fb_span} bytes, '
              f'hash {fb_before_hash:016x} -> {fb_after_hash:016x}, '
              f'{"CHANGED" if fb_before_hash != fb_after_hash else "unchanged"}; '
              'q1n1 UI suspended for both reads')
    aborts, steps = steps & 0xffffffff, steps >> 32

    if xb.GUEST_PROFILE.adreno is not None:
        # Not `counters`: that name is the report function this one calls later (Stage 4 run 1
        # lost the end of its report to a TypeError when the local shadowed it).
        gpu_flow = runpy.run_path(str(ROOT / 'tools/adreno_counters.py'))
        decoded = gpu_flow['decode'](proxy.readmem(out + GPU_FLOW_OFFSET, gpu_flow['SIZE']))
        for line in gpu_flow['summary'](decoded):
            print(f'  {line}')
    # The early-stop record (OUT_EARLY_STOP): zero words on an ordinary launch.
    early_record = early_names.decode(proxy.readmem(out + EARLY_STOP_OFFSET, early_names.SIZE))
    for line in early_names.summary(early_record, host.timer_hz):
        print(f'  {line}')
    if '-DSNAP_VIEW_RECLAIM=1' in FLAGS:
        perf = runpy.run_path(str(ROOT/'tools/perf_counters.py'))
        offset, size = perf['view_reclaim_spec']()
        try:
            views = perf['decode_view_reclaim'](proxy.readmem(out + offset, size))
            print(f"  kernel views: {views['count']} of {views['capacity']} tables (high water "
                  f"{views['high_water']}), {views['reclaims']} reclaims retired {views['retired']}, "
                  f"{views['full']} refused with nothing to retire")
        except ValueError as error:
            print('  kernel views record unreadable:', error)
    thermal_record = None
    if early is not None and early.thermal:
        thermal_names = runpy.run_path(str(ROOT/'tools/a16_thermal.py'))
        thermal_record = thermal_names['decode'](proxy.readmem(out+thermal_names['REPORT_OFFSET'],thermal_names['SIZE']))
        print('  '+thermal_names['summary'](thermal_record,host.timer_hz))
    if early is not None and early_prefix:
        call_state = None
        if early_call[1]:
            length = struct.unpack('<Q', proxy.readmem(early_call[1] + 16, 8))[0]
            if 24 <= length <= 4096 and not length % 8:
                call_state = proxy.readmem(early_call[1], length).hex()
        import json as early_json
        with (ROOT/'build'/f'{early_prefix}-early-stop.json').open('x') as output:
            early_json.dump(dict(settings=early.record(), record=early_record,
                                 q1n1_call_state_hex=call_state, thermal=thermal_record), output, indent=2)
    if status and status >> 63:
        names = PREPARE_FAILURES
        code_ = status - (1 << 64)
        print(f'\nFAILED before entry: {names.get(code_, code_)}')
        print(f'  shadow root (4K)   {s_root:#x}   leaves {leaves}')
        print(f'  stage-2 root       {s2_root:#x}')
        if code_ == -6:
            print(f'  entry              {built["entry"]:#x}')
            print(f'  PAR_EL1            {fault:#x}  {par_report(fault)}')
        return verdict(EXIT_PREPARE, names.get(code_, f'prepare returned {code_}'))
    if status:
        elr, far = read_bad_regs(proxy, out)
        print(f'\nEL2 FAULT  ESR {status:#x} (EC {status >> 26:#x} '
              f'FSC {status & 0x3f:#04x})')
        print(f'  at ELR_EL2         {elr:#x}   (inside the probe)')
        print(f'  reaching for       {far:#x}   FAR_EL2')
        return verdict(EXIT_EL2_FAULT,
                       f'the monitor faulted at {elr:#x} reaching for {far:#x}, '
                       f'ESR {status:#x} (EC {status >> 26:#x})')

    print(f'  shadow root (4K)   {s_root:#x}   leaves {leaves}')
    print(f'  stage-2 root       {s2_root:#x}   monitor calls answered '
          f'{monitor_calls}')
    print(f'  entered            {"yes" if entered else "NO"}')
    print(f'  sysreg traps       {traps}   aborts {aborts}   steps {steps}')
    returns, signatures, return_pc = struct.unpack('<3Q',
        proxy.readmem(out + EXCEPTION_FLOW_OFFSET, 3 * 8))
    print(f'  kernel ERET returns {returns}; PACGA operations {signatures}; '
          f'last return target {return_pc:#x}')
    updates, update_entries, regions, region_entries = struct.unpack('<4Q',
        proxy.readmem(out + UPDATE_FLOW_OFFSET, 4 * 8))
    print(f'  UPDATE_DISJOINT completed {updates} calls, {update_entries} entries')
    print(f'  UPDATE_REGION completed {regions} calls, {region_entries} entries')
    slides, slide_pages, slide_cursor = struct.unpack('<3Q',
        proxy.readmem(out + UPDATE_FLOW_OFFSET + 4 * 8, 3 * 8))
    print(f'  SLIDE_REGION completed {slides} calls, {slide_pages} pages; '
          f'next destination {slide_cursor:#x}')
    ticks, first_tick, last_tick, writes, guest_ctl, hz, host_ctl, saved_ctl = struct.unpack(
        '<8Q', proxy.readmem(out + CLOCK_FLOW_OFFSET, 8 * 8))
    print(f'  clock {ticks} reads, {first_tick:#x} -> {last_tick:#x}, {hz} Hz; '
          f'CNTKCTL {writes} writes, guest {guest_ctl:#x}, hardware {host_ctl:#x}, '
          f'restored {saved_ctl:#x}')
    tr, tw, irqs, asserts, clears, vectors, ctl, deadline, irq_pc, budget, repairs = struct.unpack(
        '<11Q', proxy.readmem(out + TIMER_FLOW_OFFSET, 11 * 8))
    print(f'  deadline timer {tr} reads, {tw} writes, {irqs} host IRQs; '
          f'VF {asserts} sets/{clears} clears, {vectors} guest FIQ vector entries; '
          f'CTL {ctl:#x}, deadline {deadline:#x}, last IRQ PC {irq_pc:#x}, budget {budget:#x}')
    print(f'  stepped guest exception contexts repaired {repairs}')
    pending, requests, reads, acks, coalesced, target, request_pc, ack_pc = struct.unpack(
        '<8Q',proxy.readmem(out+IPI_FLOW_OFFSET,8*8))
    print(f'  fast IPI: {requests} requests, {reads} status reads, {acks} pending acknowledgements, '
          f'{coalesced} coalesced; pending {pending}, last target {target:#x}; '
          f'request PC {request_pc:#x}, acknowledge PC {ack_pc:#x}')
    mask, registrations, ids, outputs, active, affinity, slot, reserved = struct.unpack(
        '<8Q',proxy.readmem(out+CPU_FLOW_OFFSET,8*8))
    print(f'  CPU registry: mask {mask:#x}, {registrations} registrations, {ids} ID queries, '
          f'{outputs} result-area queries; active slot {active}, last affinity {affinity:#x}, '
          f'last slot {slot}, reserved {reserved}')
    for row in struct.iter_unpack('<12Q',proxy.readmem(out+VCPU_FLOW_OFFSET,6*12*8)):
        (address, index, mpidr, prepared, ttbr1, timer_reads, ipi_requests, exceptions,
         stage2_root, vttbr, guards, open_guards) = row
        print(f'  vCPU {index}: bank {address:#x}, MPIDR {mpidr:#x}, prepared {prepared}, '
              f'TTBR1 {ttbr1:#x}, timer reads {timer_reads}, IPI requests {ipi_requests}, '
              f'exceptions {exceptions}; stage2 {stage2_root:#x}, VTTBR {vttbr:#x}, '
              f'guards {guards}, open {open_guards}')
    tlb_syncs, root_checks, root_busy = struct.unpack('<3Q',proxy.readmem(out+SHARED_FLOW_OFFSET,24))
    print(f'  shared translation state: {tlb_syncs} all-VMID invalidations, '
          f'{root_checks} root-liveness checks, {root_busy} busy/invalid refusals')
    service_values = struct.unpack('<16Q',proxy.readmem(out+SERVICE_FLOW_OFFSET,16*8))
    service_owner, service_stop = service_values[:2]
    service_acquires, service_faults = service_values[2:14:2], service_values[3:14:2]
    service_lifecycle, service_reusable = service_values[14:]
    print(f'  service lock: owner {service_owner}, stop {service_stop:#x}; '
          f'acquisitions {service_acquires}, faults {service_faults}')
    print(f'  executor lifecycle: {service_lifecycle:#x}, memory reusable {service_reusable}')
    storage_values=struct.unpack('<31Q',proxy.readmem(out+RUNTIME_STORAGE_OFFSET,31*8))
    for cpu in range(6):
        vncr,output,stack_low,stack_high,hcr=storage_values[cpu*5:(cpu+1)*5]
        print(f'  CPU{cpu} runtime storage: VNCR {vncr:#x}, output {output:#x}, '
              f'EL2 stack [{stack_low:#x}, {stack_high:#x}), HCR {hcr:#x}')
    print(f'  active hardware VNCR_EL2: {storage_values[30]:#x}')
    (physical_hz, virtual_hz, saved_cnthctl, guest_cnthctl, wfe, wakes, early,
     architectural, raw_first, raw_last, virtual_first, virtual_last) = struct.unpack(
        '<12Q', proxy.readmem(out + CLOCK_ADAPTER_OFFSET, 12*8))
    print(f'  clock adapter {physical_hz} -> {virtual_hz} Hz; '
          f'WFE {wfe} traps, {wakes} event wakes, {early} early wakes; '
          f'architectural virtual reads {architectural}; '
          f'CNTHCTL guest {guest_cnthctl:#x}, saved {saved_cnthctl:#x}')
    scaled = physical_hz and all(g == ((h * virtual_hz // physical_hz) & ((1 << 64)-1))
                               for h, g in ((raw_first, virtual_first), (raw_last, virtual_last)))
    print(f'  counter conversion: physical {raw_first:#x} -> {raw_last:#x}, '
          f'guest {virtual_first:#x} -> {virtual_last:#x}; exact samples {bool(scaled)}')
    pending, irq_sets, irq_clears, irq_vectors, aic_events = struct.unpack(
        '<5Q', proxy.readmem(out + AIC_FLOW_OFFSET, 5*8))
    print(f'  AIC IRQ pending {pending}; VI {irq_sets} sets/{irq_clears} clears; '
          f'{irq_vectors} guest IRQ vector entries, {aic_events} acknowledged events')
    models = built.get('device_models', ())
    wd_words = RESET_WORDS + 3*MODEL_MAX
    wd_state = struct.unpack(f'<{wd_words}Q', proxy.readmem(out + WATCHDOG_FLOW_OFFSET, wd_words*8))
    reset_bitmap=sum(word<<(64*i) for i,word in enumerate(wd_state[:RESET_WORDS]))
    print(f'  virtual device reset bitmap {reset_bitmap:#x}')
    dev_notifications, trace_queries = struct.unpack('<2Q',
        proxy.readmem(out + OPTIONAL_FLOW_OFFSET, 16))
    print(f'  optional monitor services: {dev_notifications} developer-mode notifications; '
          f'CPUTRACE reservation address/size queries '
          f'{trace_queries & 0xffffffff}/{trace_queries >> 32} (counts saturate at 32 bits)')
    device_words = 1 + 2*MODEL_MAX
    device_counts = struct.unpack(f'<{device_words}Q',
                                 proxy.readmem(out + DEVICE_FLOW_OFFSET, device_words * 8))
    if device_counts[0] != len(models):
        return verdict(EXIT_UNCLASSIFIED, 'virtual device registry report count mismatch')
    for i, model in enumerate(models):
        print(f'  virtual device {model.kind} {model.node} [{model.base:#x}, '
              f'{model.base+model.span:#x}): {device_counts[1+2*i]} reads, '
              f'{device_counts[2+2*i]} writes')
        if model.kind == 5:
            cur_ctl, bite_reset, sample = wd_state[RESET_WORDS+3*i:RESET_WORDS+3*(i+1)]
            print(f'    WD1 current {cur_ctl & 0xffffffff}, bite {bite_reset & 0xffffffff}, '
                  f'control {cur_ctl >> 32:#x}, reset {bite_reset >> 32}, sample {sample:#x}')
    async_words = struct.unpack('<37Q', proxy.readmem(out + ASYNC_REGS_OFFSET, 37 * 8))
    if async_words[0]:
        stop_kind = {1: 'asynchronous', 2: 'monitor', 3: 'stage-2'}.get(async_words[0], 'unknown')
        print(f'  {stop_kind} stop PC {async_words[34]:#x}, '
              f'SP {async_words[32]:#x}, PSTATE {async_words[33]:#x}')
        dump_gprs(async_words[1:32])
    exc_return = read_exc_return(proxy, out)
    if exc_return:
        print(f'  exception return   {exc_return:#x}   (registered by XNU; this '
              f'is NOT a fault)')

    # Post-mortem. The guest is gone but its memory is not, and the proxy can
    # read it: every kernel VA in the image is IMAGE_PA + (va - vmin), because
    # that mapping is linear by construction. This is much cheaper than
    # reasoning backwards from a disassembly about what a global ended up
    # holding -- the machine already knows.
    def peek(va, n=8):
        if built['vmin'] <= va and va + n <= built['image'].vmax:
            pa = built['image_pa'] + (va - built['vmin'])
            raw = proxy.readmem(pa, n)
        else:
            # Panic va_lists move onto dynamically allocated kernel stacks.
            # Linear image arithmetic on those VAs can issue arbitrary
            # physical reads. Walk the live guest tables within owned RAM.
            from guestmemory import read_16k
            root = read_guest_sysregs(proxy, out)['TTBR1_EL1'] & 0x0000ffffffffc000
            raw = read_16k(proxy.readmem, root, xb.PHYS_BASE,
                           xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN, va, n)
        return int.from_bytes(raw, 'little')

    print('\n--- what SPTM handed over, as XNU stored it ---')
    gate = peek(0xFFFFFE0007EC0238, 1)
    count_ptr, table_ptr = peek(0xFFFFFE0007EC0240), peek(0xFFFFFE0007EC0248)
    print(f'  handoff consumed   {gate}')
    print(f'  region count ptr   {count_ptr:#x}')
    print(f'  region table ptr   {table_ptr:#x}')
    ap = proxy.readmem(xb.HANDOFF_PA + xb.REGIONS_OFFSET, 0x28)
    n = int.from_bytes(ap[:4], 'little')
    print(f'  aperture           {n} region(s)')
    regions = []
    # SLIDE_REGION splits the original aperture into more than eight ranges.
    # Keep the monitor's 50-entry bound; truncating at eight also broke the
    # diagnostic VA-to-PA lookup for table pointers in the final RAM range.
    if n > 50:
        print('  invalid region count: exceeds the monitor ABI limit of 50')
    for r in range(min(n, 50)):
        entry = proxy.readmem(xb.HANDOFF_PA + xb.REGIONS_OFFSET + 0x10 + r * 0x18, 0x18)
        base = int.from_bytes(entry[0:8], 'little')
        virt = int.from_bytes(entry[8:16], 'little')
        pages = int.from_bytes(entry[16:20], 'little')
        regions.append((base, virt, pages << 14))
        print(f'    phys {base:#x} .. {base + (pages << 14):#x}  ->  va {virt:#x}')

    # XNU's own panic record, read back off the machine.
    #
    # 0xe7ffdeff is not an instruction we failed to emulate: it is XNU's
    # TRAP_DEBUGGER poison word (osfmk/kern/debug.c), executed on purpose from
    # DebuggerTrapWithState() once the kernel has already decided to panic. The
    # hardware reports EC 0 because no CPU implements it -- that is the point.
    # So the interesting value is not the instruction, it is the record the
    # kernel filled in just before trapping, which is still in memory.
    #
    # x23 at the trap is &debugger_state[cpu]; with x8 == 0 that is the percpu
    # base itself. Field offsets are read out of the stores in the trap site.
    DEBUGGER_STATE = 0xFFFFFE000C6F4140
    # +0x20 is db_panic_args, and it is read out of the same stores as the rest:
    #
    #   stp x1, x2, [x23, #0x10]    ; db_message, db_panic_str
    #   stp x3, x5, [x23, #0x20]    ; <-- x3 is the va_list*
    #   stp x7, x8, [x23, #0x30]    ; db_panic_caller
    #
    # which matches DebuggerTrapWithState's argument order. Without it the
    # record gives the shape of the complaint and not the complaint: reading
    # "pmap_enter failed, map_addr=%#lx, phys_page=%u" tells you nothing about
    # which mapping.
    FIELDS = ((0x08, 'db_current_op'), (0x10, 'db_message'),
              (0x18, 'db_panic_str'), (0x20, 'db_panic_args'),
              (0x30, 'db_panic_caller'), (0x44, 'db_op_return'))

    def peekstr(va, limit=256):
        """Follow a kernel VA to a C string, if it is one of ours to read."""
        if not built['vmin'] <= va < built['image'].vmax:
            return None
        limit = min(limit, built['image'].vmax - va)
        try:
            pa = xb.IMAGE_PA + (va - built['vmin'])
            raw = proxy.readmem(pa, limit)
        except Exception:
            return None
        end = raw.find(b'\0')
        raw = raw[:end if end >= 0 else limit]
        return raw.decode('utf-8', 'replace') if raw else ''

    print("\n--- XNU's panic record (debugger_state) ---")
    panic_said = None
    try:
        for off, name in FIELDS:
            width = 4 if off == 0x44 else 8
            v = peek(DEBUGGER_STATE + off, width)
            line = f'  +{off:#04x} {name:<16} {v:#x}'
            if name in ('db_message', 'db_panic_str') and v:
                s = peekstr(v)
                if s:
                    line += f'   "{s}"'
            print(line)
    except Exception as exc:
        print(f'  could not read it: {exc}')

    # And the arguments, which are what turn the format string into a sentence.
    #
    # db_panic_args is an AAPCS va_list, whose first word is the pointer to the
    # stack argument block -- so one dereference reaches the values the call
    # site pushed. Both fields are zero for a panic that never formatted, so
    # this is guarded on the pointer rather than on having panicked.
    try:
        fmt_va = peek(DEBUGGER_STATE + 0x18)
        args_va = peek(DEBUGGER_STATE + 0x20)
        if fmt_va and args_va:
            block = peek(args_va)
            words = [peek(block + 8 * n) for n in range(8)]
            print(f'\n  db_panic_args        {args_va:#x} -> block {block:#x}')
            for n, w in enumerate(words):
                s = peekstr(w, 64) if 0xfffffe0000000000 <= w else None
                extra = f'   "{s}"' if s and s.isprintable() and s else ''
                print(f'    arg[{n}]  {w:#018x}  ({w}){extra}')
            said = format_panic(peekstr(fmt_va), words, peekstr)
            panic_said = said or peekstr(fmt_va)
            if said:
                print(f'\n  == {said}')
    except Exception as exc:
        print(f'  could not read the panic arguments: {exc}')

    # The audited debugger trap can stop before debugger_state receives the
    # format pointer. Its entry registers retain that pointer and va_list.
    # Decode only this profile's known trap/opcode shape, never arbitrary x2/x3.
    if panic_said is None:
        raw = proxy.readmem(out + GUEST_REGS_OFFSET, GUEST_REGS_BYTES)
        count = struct.unpack_from('<Q', raw)[0]
        if count:
            words = struct.unpack_from(f'<{GUEST_REGS_WORDS}Q', raw, 8)
            if words[33] == xb.GUEST_PROFILE.panic_trap_pc and words[0] == 1:
                try:
                    fmt = peekstr(words[2])
                    if built['vmin'] <= words[3] < built['image'].vmax - 8:
                        block = peek(words[3])
                        if built['vmin'] <= block < built['image'].vmax - 64:
                            args = [peek(block + 8 * n) for n in range(8)]
                            panic_said = format_panic(fmt, args, peekstr)
                            if panic_said:
                                print(f'  captured panic trap: {panic_said}')
                except (OSError, ValueError, TypeError):
                    pass

    # Which structure XNU is actually reading the seed out of.
    #
    # The panic comes from a length test: x21 = *(0xfffffe0007ebf100), and
    # [x21+0x178] must be >= 8. The consuming code wants an 8-byte tag
    # "randseed" at +0x6c and the seed bytes at +0x74. Whether x21 is our
    # boot_args is a measurement, not an inference -- so take it.
    SEED_GLOBAL = 0xFFFFFE0007EBF100
    print('\n--- the randseed structure XNU reads ---')
    try:
        ptr = peek(SEED_GLOBAL)
        ba_pa = xb.HANDOFF_PA + 0x1000
        ba_va = built.get('bootargs_va')
        print(f'  *{SEED_GLOBAL:#x}      {ptr:#x}')
        print(f'  our boot_args        pa {ba_pa:#x}'
              + (f'  va {ba_va:#x}' if ba_va else ''))
        print(f'  same structure?      '
              f'{"yes" if ba_va and ptr == ba_va else "NO -- x21 is not our boot_args"}')
        # Is that structure the copy of our SPTM handoff? Compare bytes.
        dst = proxy.readmem(xb.IMAGE_PA + (ptr - built['vmin']), 64)
        src = proxy.readmem(xb.HANDOFF_PA, 64)
        print(f'  structure[0:16]      {dst[:16].hex()}')
        print(f'  our handoff[0:16]    {src[:16].hex()}')
        print(f'  is our handoff?      '
              f'{"yes" if dst == src else "no -- different bytes"}')
        for off in (0x6c, 0x74, 0x178):
            b = proxy.readmem(xb.IMAGE_PA + (ptr - built['vmin']) + off, 16)
            print(f'  +{off:#05x}  {b.hex()}  {b[:8]!r}')
    except Exception as exc:
        print(f'  could not read it: {exc}')

    # The walk that kills this run, from the inside.
    #
    # 0xfffffe000ba7aa00 loads a fixed VA into x20 and walks it through a root
    # taken from *(*(__DATA_CONST+0x6e0) + 0x3f60). That global is zero in the
    # image on disk, so whatever fills it in does so while the kernel runs --
    # which means the only way to see it is to read it back afterwards. The
    # guest is gone but its memory is not.
    WALK_VA = 0xfffffecfffcfc000
    ROOT_GLOBAL = 0xfffffe0007da06e0
    print('\n--- the walk at 0xfffffe000ba7ab68 ---')
    holder = peek(ROOT_GLOBAL)
    print(f'  root global        {ROOT_GLOBAL:#x} -> {holder:#x}')
    # peek() only knows image addresses. Anything the kernel stores as an
    # aperture VA has to come back through the region table, the same way the
    # kernel's own phystokv would run it -- backwards.
    def kvtophys(va):
        for base, virt, span in regions:
            if virt <= va < virt + span:
                return base + (va - virt)
        return None

    if not holder:
        print('    still zero: the kernel never filled it in, so the walk started '
              'from nothing')
    else:
        pa = kvtophys(holder)
        if pa is None:
            print('    that is not an aperture address, so it is not one of ours')
        else:
            print(f'    = physical {pa:#x}, which is our table arena'
                  if pa == built['tables'].root else f'    = physical {pa:#x}')
            entry = int.from_bytes(proxy.readmem(pa + 0x3f60, 8), 'little')
            print(f'  [+0x3f60] (index {0x3f60 // 8})  {entry:#018x}'
                  f'{"" if entry else "   <-- zero"}')

    # And the same walk through the tables we built, which is what the guest's
    # TTBR1 points at. A zero here is us not having filled the entry in.
    offset = (WALK_VA - xb.KERNEL_BASE) & ((1 << (64 - xb.T1SZ)) - 1)
    table = built['tables'].root
    print(f'  walking {WALK_VA:#x} through our own root {table:#x}')
    for level in range(xb.start_level(), 4):
        i = xb.index(level, offset)
        entry = int.from_bytes(proxy.readmem(table + i * 8, 8), 'little')
        note = '' if entry & 1 else '   <-- zero, the walk stops here'
        print(f'    level {level} index {i:5d}  entry {entry:#018x}{note}')
        if not entry & 1:
            break
        table = entry & 0x0000FFFFFFFFC000

    # The early physical allocator, read back.
    #
    # Every page pmap_steal_memory maps is the word at 0xfffffe0007da0858
    # (avail_start), unchanged: 0xfffffe000ba12440 masks it to 46 bits and
    # 0xfffffe000ba627c8 ORs it into the PTE. avail_start is written once, at
    # the end of arm_vm_init (0xfffffe000ba7aba4), as the rounded cursor at
    # 0xfffffe0007da06c8; the cursor is seeded from handoff +0x18
    # (0xfffffe000c244814 stores it at 0xfffffe0007d9fd60, 0xfffffe000ba7947c
    # loads it) and is moved only by pmap_bootstrap's own allocations -- a
    # page, 0x30000 for ptd descriptors, and the ASID bitmap. Offline that
    # chain ends a few hundred KiB above +0x18; the hardware maps 12 GiB.
    # arm_vm_init also stores {seed, cursor - seed} at 0xfffffe000c6c0068 as it
    # returns, which is the cursor frozen at that moment. Reading the chain
    # back says which link holds the 12 GiB number, and that is the question.
    ALLOCATOR = (
        ('handoff copy +0x18',        0xfffffe0007da0278 + 0x18, 8),
        ('seed',                      0xfffffe0007d9fd60, 8),
        ('cursor',                    0xfffffe0007da06c8, 8),
        ('avail_start',               0xfffffe0007da0858, 8),
        ('avail_end',                 0xfffffe0007da06e8, 8),
        ('arm_vm_init: seed',         0xfffffe000c6c0068, 8),
        ('arm_vm_init: cursor - seed', 0xfffffe000c6c0070, 8),
        ('virtual_space_start',       0xfffffe000c738320, 8),
        ('free pages (u32)',          0xfffffe000c817344, 4),
        ('vm_pages array (VA)',       0xfffffe0007e2c010, 8),
    )
    PHYSICAL = ('handoff copy +0x18', 'seed', 'cursor', 'avail_start',
                'avail_end', 'arm_vm_init: seed')
    print('\n--- the early physical allocator, as the kernel left it ---')
    ours = struct.unpack_from('<Q', built['chunks'][xb.HANDOFF_PA],
                              xb.SPTM_AVAIL_START)[0]
    print(f'  {"our handoff +0x18":<30} {ours:#x}')
    try:
        for name, va, width in ALLOCATOR:
            v = peek(va, width)
            note = ''
            if name in PHYSICAL:
                inside = xb.PHYS_BASE <= v < xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN
                note = '   inside our memory' if inside else '   OUTSIDE our memory'
            print(f'  {name:<30} {v:#x}{note}')
    except Exception as exc:
        print(f'  could not read it: {exc}')

    kprintf_gate(peek, built)
    video_console_state(peek, built)
    guest_sysregs(proxy, out, built)

    guest_registers(proxy, out)
    panic_entry(proxy, out)
    counters(proxy, out)
    endpoint_calls(proxy, out, monitor_calls)
    map_ranges(proxy, out, xb, built,
               read_counters(proxy, out).get('map_outside'))

    console = ''
    if console_len:
        text = proxy.readmem(out + CONSOLE_OFFSET,
                             min(console_len, CONSOLE_MAX))
        console = text.decode('utf-8', 'replace')
        print('\n--- XNU console ---')
        print(console)
        print('-------------------')

    # An explicitly requested diagnostic relay, excluded from guest panel runs.
    if console and relay_panel:
        try:
            import importlib.util as _il
            _s = _il.spec_from_file_location('fbconsole', ROOT / 'probes/fbconsole.py')
            fbconsole = _il.module_from_spec(_s)
            _s.loader.exec_module(fbconsole)
            # Say what this is. XNU's own video console is a different thing
            # -- initialize_screen, its font, its layout -- and it cannot run
            # this early, which is the whole meaning of "panicked very early
            # before serial init". What is on the panel here is the early
            # SPTM_FN_SERIAL_PUTC stream, XNU's words relayed and drawn by the
            # host. Useful precisely because it covers the phase where the
            # kernel has no console of its own; not a substitute for the one it
            # will draw once PE_init_platform runs.
            header = 'XNU early console (SPTM serial, relayed) - Snapdragon X2E'
            n = fbconsole.show(proxy, info, console, header=header)
            print(f'  drawn on the A16: {n:,} bytes to {info["fb_base"]:#x}')
        except Exception as error:                      # noqa: BLE001
            print(f'  (could not draw on the panel: {error})')
    raw = proxy.readmem(out + LOG_OFFSET, LOG_BYTES)
    # Collected rather than printed straight through: the verdict is decided by
    # what is in here, and deciding it from the same list the transcript shows
    # means the two cannot disagree.
    log = [struct.unpack_from('<6Q', raw, n * EVENT_WORDS * 8)
           for n in range(min(events, EVENT_MAX))]
    print(f'\n{events} events:')
    for n in range(len(log)):
        kind, pc, a, b, c, repeats = log[n]
        label = EVENTS.get(kind, kind)
        if repeats:
            label += f' x{repeats + 1}'
        if kind == 11:
            # a = the PTE's output address, b = the VA, c = the whole PTE.
            #
            # The call completes, the guest's table is written, and the
            # mapping IS installed in the hardware's. It used to say "MAPPED
            # ANYWAY", then for a while the mapping was withheld and a second
            # line said so; neither is true now. Under the narrowed stage-2 map
            # these addresses are absent, so installing means the access traps
            # to EL2 with its address rather than faulting inside XNU's own
            # handler. The span table below says which device each of these
            # belongs to. Attributes are decoded here rather than in the probe
            # because the raw PTE is what was recorded and the host can say
            # more about it.
            attrs = c & 0xfff
            print(f'  {n:>2} {label:<22} pc {pc:#x}  va {b:#x} -> pa {a:#x}  '
                  f'({a / (1 << 30):.2f} GiB)')
            print(f'     pte {c:#018x}  attrs {attrs:#05x}  '
                  f'AttrIndx {(c >> 2) & 7}  SH {(c >> 8) & 3}  AP {(c >> 6) & 3}'
                  f'   outside the memory we declared, and installed -- so a '
                  f'touch of it stops at EL2 with its address')
        elif kind == 12:
            # a = ESR_EL2, b = ESR_EL1, c = ELR_EL1. EC 0x2f is SError. IDS
            # (bit 24) set means the rest is implementation defined, so the
            # AET/EA/DFSC decode below is only meaningful when it is clear.
            print(f'  {n:>2} {label:<22} guest pc {pc:#x}  ESR_EL2 {a:#x} '
                  f'(EC {a >> 26:#x}  IDS {(a >> 24) & 1}  AET {(a >> 10) & 7}  '
                  f'EA {(a >> 9) & 1}  DFSC {a & 0x3f:#04x})')
            print(f'     ESR_EL1 {b:#x}  ELR_EL1 {c:#x}   the bus refused an '
                  f'access -- this is NOT the timer expiring')
        elif kind == 13:
            # a = which vector, b = ESR_EL1, c = ELR_EL1.
            print(f'  {n:>2} {label:<22} guest pc {pc:#x}  '
                  f'{ASYNC_KINDS.get(a, a)} with the EL2 timer not fired  '
                  f'ESR_EL1 {b:#x}  ELR_EL1 {c:#x}')
        elif kind == 10:
            # a = reason, with the level a walk stopped at in bits 15:8.
            # b = the VA being mapped, c = detail, whose meaning is per reason.
            reason, level = a & 0xff, (a >> 8) & 0xff
            why = MAP_FAILURES.get(reason, f'reason {reason}, unrecognised')
            detail = {2: 'last table reached', 3: 'entry', 4: 'entry',
                      5: 'the PTE we were given', 6: 'next free shadow table',
                      7: 'shadow root', 8: 'what the shadow resolves to',
                      9: 'the PTE we were given', 10: 'the leaf base',
                      11: 'the root we were handed'}
            print(f'  {n:>2} {label:<22} pc {pc:#x}  va {b:#x}  MAP_PAGE FAILED: '
                  f'{why}')
            print(f'     {detail.get(reason, "detail")} {c:#x}'
                  + (f'   stopped at level {level}' if reason == 2 else ''))
        elif kind == 9:
            # a = x30 (which fatal path), b = ELR_EL1, c = ESR_EL1.
            where = PANIC_CALLERS.get(a, 'an unrecognised fatal path')
            print(f'  {n:>2} {label:<22} pc {pc:#x}  from {a:#x} -- {where}')
            print(f'     ELR_EL1 {b:#x}  ESR_EL1 {c:#x} '
                  f'(EC {c >> 26:#x} FSC {c & 0x3f:#04x})')
        elif kind == 8:
            # a = dispatch command, b = domain, c = the raw x16.
            what = DISPATCH_CMDS.get(a, 'unknown to us')
            print(f'  {n:>2} {label:<22} pc {pc:#x}  x16 {c:#018x}  '
                  f'command {a:#x} -- not an endpoint call ({what}); '
                  f'domain {b:#x}   NOT ANSWERED')
        elif kind == 1:
            # The whole x16, because three of its four fields used to be
            # invisible here and the top one is what distinguishes four
            # different calls that all read as endpoint 0.
            cmd, domain = (a >> 56) & 0xff, (a >> 48) & 0xff
            table, endpoint = (a >> 32) & 0xffff, a & 0xffffffff
            name = route_name(domain, table)
            note = ''
            if cmd != 0:
                print(f'  {n:>2} {label:<22} pc {pc:#x}  x16 {a:#018x}  '
                      f'command {cmd:#x}, not an endpoint call')
                continue
            # Table 7 endpoint 13 exists in this kernelcache -- 14 UAT stubs,
            # endpoints 0..13 -- and m1n1-j700's private.h stops at 12, with
            # uat_handle_table7() returning 0 for anything past its max. So the
            # one reference implementation for this SoC answers this call by
            # ignoring it. Flag it rather than let it look handled.
            if table == 7 and endpoint >= 13:
                note = '   <-- past the last named UAT endpoint'
            print(f'  {n:>2} {label:<22} pc {pc:#x}  x16 {a:#018x}  {name} '
                  f'endpoint {endpoint:#x}  x0 {b:#x}  x1 {c:#x}{note}')
        elif kind == 2:
            # a = IPA (0: unrecoverable), b = ESR_EL2, c = the guest VA. The
            # run stopped here; the IPA is the answer and the rest is what makes
            # the next step cheap.
            print(f'  {n:>2} {label:<22} pc {pc:#x}  IPA {a:#x}  va {c:#x}  '
                  f'ESR {b:#x}')
            print(f'     {s2_fault_words(a, b)}')
            print(f'     {s2_where_words(a, s2_ranges)}')
        elif kind == 17:
            print(f'  {n:>2} {label:<22} pc {pc:#x}  PA {a:#x}  '
                  f'type {b >> 32:#x} -> {b & 0xffffffff:#x}  options {c:#x}')
        elif kind == 18:
            print(f'  {n:>2} {label:<22} pc {pc:#x}  PA {b:#x}  '
                  f'new type {c:#x}: {RETYPE_FAILURES.get(a, a)}')
        elif kind == 16:
            # a = (reason << 48) | (window << 32) | offset, b = ESR_EL2,
            # c = the IPA. The run stopped here and this names the register to
            # model next.
            print(f'  {n:>2} {label:<22} pc {pc:#x}  IPA {c:#x}  ESR {b:#x}')
            print(f'     {mmio_stop_words(a, b)}')
        elif kind == 3:
            print(f'  {n:>2} {label:<22} at {c:#x}  ESR_EL1 {a:#x} '
                  f'(EC {a >> 26:#x} FSC {a & 0x3f:#04x} {"write" if (a >> 6) & 1 else "read"})'
                  f'  FAR_EL1 {b:#x}  from {pc:#x}')
        elif kind == 7:
            which = 'x2 (SPTM handoff)' if a < 0x1000 else 'x1'
            print(f'  {n:>2} {label:<22} {which} +{a & 0xfff:#05x}  pc {pc:#x}  '
                  f'{"write" if (b >> 6) & 1 else "read"}')
        elif kind == 6:
            print(f'  {n:>2} {label:<22} pc {pc:#x}  ESR_EL1 {a:#x} '
                  f'(EC {a >> 26:#x} FSC {a & 0x3f:#04x})  FAR_EL1 {b:#x}  '
                  f'ELR_EL1 {c:#x}')
        elif kind == 4:
            op0, op2 = (a >> 20) & 3, (a >> 17) & 7
            op1, crn = (a >> 14) & 7, (a >> 10) & 0xf
            crm, rd = (a >> 1) & 0xf, 'read' if a & 1 else 'write'
            name = SYSREGS.get((op0, op1, crn, crm, op2), '')
            # These collapse by register now, not by (pc, ISS): the direction
            # and the destination register belong to the first access, and the
            # count covers every access to that register that followed. Saying
            # "read" for a run of eighteen that included writes would be the
            # label lying about what it counted.
            what = f'{rd}' if not repeats else f'{repeats + 1} accesses, first a {rd}'
            print(f'  {n:>2} {label:<22} pc {pc:#x}  '
                  f'S{op0}_{op1}_C{crn}_C{crm}_{op2}'
                  f'{" " + name if name else ""}  {what}')
        elif kind == 5 and pc in (8, 11, 19, 22):
            print(f'  {n:>2} {"guest registers":<22} x{pc} {a:#x}  '
                  f'x{pc + 1} {b:#x}  x{pc + 2} {c:#x}')
        elif kind == 5 and pc == 0:
            # What this CPU says about itself, read once at setup. This used to
            # print as "other pc 0x0" followed by three bare hex words, which is
            # a line nobody can read and nobody did. XNU configures SME
            # unconditionally on this board, so whether the silicon has it
            # decides whether that is deniable or has to be emulated.
            print(f'  {n:>2} {"this CPU, as it reports itself":<22}')
            print(f'     MIDR_EL1        {c:#018x}  '
                  f'implementer {(c >> 24) & 0xff:#x} part {(c >> 4) & 0xfff:#x}')
            print(f'     ID_AA64PFR0_EL1 {a:#018x}')
            print(f'     ID_AA64PFR1_EL1 {b:#018x}  '
                  f'SME {(b >> 24) & 0xf}'
                  f'{"" if (b >> 24) & 0xf else "  -- this silicon has no SME"}')
        elif kind == 5 and pc == 1:
            # Whether this silicon has FEAT_NV2, which decides whether XNU can
            # be run at all without pretending to be something it is not: it
            # writes EL2 registers, and NV2 is what redirects those into memory
            # instead of leaving them undefined.
            nv, frac = (a >> 24) & 0xf, (b >> 24) & 0xf
            has = nv == 2 or (nv == 1 and frac)
            print(f'  {n:>2} {"nested virtualization":<22}')
            print(f'     ID_AA64MMFR2_EL1 {a:#018x}  NV {nv}')
            print(f'     ID_AA64MMFR4_EL1 {b:#018x}  NV_frac {frac}')
            print(f'     ID_AA64MMFR0_EL1 {c:#018x}  '
                  f'{"FEAT_NV2 present" if has else "NO FEAT_NV2"}')
        elif kind == 5 and pc == 2:
            # SNAP_IDREG_MMFR3 (opt-in), one per vCPU: whether this core has
            # stage-1 permission indirection or overlays (the hardware analogues
            # of Apple's SPRR and TPRO), and its AF/dirty and PAN features.
            print(f'  {n:>2} {"permission features":<22} vCPU {c}')
            print(f'     ID_AA64MMFR3_EL1 {a:#018x}  S1PIE {(a >> 8) & 15}  S1POE {(a >> 16) & 15}')
            print(f'     ID_AA64MMFR1_EL1 {b:#018x}  HAFDBS {b & 15}  HPDS {(b >> 12) & 15}  '
                  f'PAN {(b >> 20) & 15}')
        elif kind == 5 and pc == 3:
            # SNAP_LEAN_TRAPS=2, one per vCPU: whether FEAT_FGT replaced
            # HCR_EL2.TVM/TRVM on this CPU (compat/lean-trap.h).
            state = {1: 'active: ESR/FAR reads and CONTEXTIDR writes untrapped',
                     2: 'declined: no FEAT_FGT', 3: 'declined: MMFR3 adds TVM registers',
                     4: 'declined: FGT registers did not read back', 5: 'declined: saved by another CPU'}
            print(f'  {n:>2} {"fine-grained traps":<22} vCPU {c & 0xff}  '
                  f'{state.get(c >> 8, f"status {c >> 8}")}')
            print(f'     HFGRTR_EL2 {a:#018x}  HFGWTR_EL2 {b:#018x}')
        elif kind == 59:
            print(f'  {n:>2} {label:<22} pc {pc:#x}  {a:#x} {b:#x} {c:#x}')
            for line in coherent_event_lines(pc, a, b, c):
                print(f'     {line}')
        else:
            print(f'  {n:>2} {label:<22} pc {pc:#x}  {a:#x} {b:#x} {c:#x}')

    # A run that overflowed the log has a last event we cannot see, and
    # classifying off a truncated tail reports the wrong stop with full
    # confidence -- which it did, naming "endpoint 0x2 not implemented" for a
    # run that completed 379 of them.
    #
    # `events > len(log)` was supposed to catch that and could not: the probe's
    # record() returned without incrementing once the log was full, so `events`
    # capped at the log size and the two were always equal. The probe now counts
    # what it dropped, and that count is the honest test. The old comparison is
    # kept as well, because it costs nothing and covers a short read.
    tally = read_counters(proxy, out)
    tally.update(service_owner=service_owner,service_stop=service_stop,service_faults=service_faults,
                 service_lifecycle=service_lifecycle,service_reusable=service_reusable,
                 early_stop=early_record)
    dropped = tally['log_dropped'] or max(0, events - len(log))
    # The terminal word. Printed whether or not the log overflowed, because it
    # is also the cheapest check that the log's tail and the probe's own last
    # record agree -- and on a run that fitted they must.
    last_event = read_last_event(proxy, out)
    if last_event is not None:
        kind, pc, a, b, c = last_event[:5]
        print(f'\nlast event (outside the log, never dropped):\n'
              f'  {EVENTS.get(kind, kind):<26} pc {pc:#x}  {a:#x} {b:#x} {c:#x}')
        last_event, hpfar = stage2_stop_hpfar(last_event)
        if hpfar is not None:
            print(f'  {"hardware IPA (HPFAR_EL2)":<26} {hpfar_ipa(hpfar, c, b):#x}  (HPFAR_EL2 {hpfar:#x}; '
                  f'the IPA above is the stage-1 re-walk\'s)')
        if log and log[-1][:5] != last_event[:5] and not dropped:
            print('  NOTE: the log\'s last entry is not this one, and nothing '
                  'was dropped -- the two should agree')
    try:
        inventory = xb.device_inventory(built['dt'])
    except (KeyError, SystemExit, ValueError):
        inventory = ()           # the verdict never depends on naming the window
    return verdict(*conclude(entered, fault, console, log, tally, dropped,
                             panic_said, last_event, models, inventory))


# The guest's register file at an exception, written by probes/xnuboot.c.
#
# Byte offset from `out`, matching OUT_GUEST_REGS there: the C side's pointer is
# 16 bytes above the host's (probes/xnuboot.S, OUT_REPORT), and the area sits
# past the console so nothing already parsed moved.
#
#   out + 4176   how many exceptions were captured (0 = none, nothing below)
#   out + 4184   first exception:  x0..x30, selected SP, SPSR_EL1, PC, ESR_EL1
#   out + 4464   last exception:   the same 35 words
GUEST_REGS_OFFSET = CONSOLE_OFFSET + CONSOLE_MAX
GUEST_REGS_WORDS = 36
GUEST_REGS_BYTES = (1 + 2 * GUEST_REGS_WORDS) * 8
# Appended after those two: the frame at XNU's panic-entry call.
PANIC_REGS_OFFSET = GUEST_REGS_OFFSET + GUEST_REGS_BYTES
PANIC_REGS_BYTES = (1 + GUEST_REGS_WORDS) * 8

# Where dispatch command 0x2 was called from, by return address. x30 is the one
# register that says which of XNU's six fatal paths this is, and one of them
# decides whether anything afterwards runs at all.
PANIC_CALLERS = {
    0xfffffe000b86ebc0: ('the wedge: an integrity check failed. XNU goes to '
                         '`wfe` and branches to itself forever, so NOTHING '
                         'after this call runs, whatever we answer'),
    0xfffffe000b86faa4: 'synchronous exception vector',
    0xfffffe000b86f80c: 'synchronous exception vector',
    0xfffffe000b86f6a8: 'synchronous exception vector',
    0xfffffe000b8c1b4c: 'handle_debugger_trap (DBOP_PANIC or DBOP_DEBUGGER)',
    0xfffffe000b8c13bc: 'a fatal path this project has not named yet',
}

# Which callee-saved register holds what, per call site.
#
# There is no single convention, and assuming one gets a register labelled with
# another's meaning. Two shapes:
#
# The EL1h vectors (0xfffffe000b86fa90, 0xfffffe000b86f7f8) do
#   mov x25, x0 ; mrs x26, ELR_EL1 ; mrs x27, ESR_EL1 ; mrs x28, FAR_EL1
#
# The kernel-mode continuation (0xfffffe000b86f61c) does
#   mrs x25, ELR_EL1 ... mov x26, x0 ; mov x27, x1(ESR) ; mov x28, x2(FAR)
#
# so x25 and x26 swap roles between them. x27 is ESR and x28 is FAR on both,
# which is why those two can be read anywhere this table has an entry.
#
# The other three call sites latch nothing: at 0xfffffe000b8c13ac x26 is a
# per-CPU pointer, and the wedge at 0xfffffe000b86ebbc sets none of them.
# Printing those as a fault would be a pointer wearing the label "faulting
# address", so sites absent from this table get no register decode at all.
PANIC_LATCH_CALLERS = {
    0xfffffe000b86faa4: {25: 'saved_state', 26: 'ELR', 27: 'ESR', 28: 'FAR'},
    0xfffffe000b86f80c: {25: 'saved_state', 26: 'ELR', 27: 'ESR', 28: 'FAR'},
    0xfffffe000b86f6a8: {25: 'ELR', 26: 'saved_state', 27: 'ESR', 28: 'FAR'},
}

# The one caller that makes everything after it moot.
WEDGE_CALLER = 0xfffffe000b86ebc0

# Why a MAP_PAGE failed. All six branches used to return one status and record
# nothing, so a failed map read exactly like a working one and pmap panicking
# afterwards had six candidate causes.
MAP_FAILURES = {
    1: 'T1SZ gives no valid starting level -- the regime is wrong, not the map',
    2: 'a table in the walk is absent; this is the one MAP_TABLE exists to fix',
    3: 'the level-3 entry could not be read',
    4: 'the level-3 entry could not be written',
    5: 'written, but reading it back through the guest tables disagreed',
    6: 'the 4K shadow refused the leaf, usually its table arena being exhausted',
    7: 'the shadow accepted the leaf and then does not resolve the address -- '
       'the insert reported success without inserting',
    8: 'the shadow resolves the address to the wrong physical page',
    9: "the guest's own tables say this address is unmapped, so the shadow was "
       'about to be left stale',
    10: 'shadow_insert accepted the leaf and inserted nothing -- usually the '
        'clip and the leaf being in different address spaces',
    11: 'the page-table root we were handed is not inside the memory we own, '
        'so walking it at EL2 would have faulted with nothing to name it',
    12: 'selector2 needs a private CPU permission path; only the ROZONE RETYPE transaction is admitted',
}

# Counters the event log cannot carry, because it holds 64 entries and
# collapses repeats.
COUNTERS_OFFSET = PANIC_REGS_OFFSET + PANIC_REGS_BYTES
COUNTER_KEYS = ('map_pages', 'map_failures', 'dispatch_cmds', 'panic_calls',
                'undef_skipped', 'map_outside', 'log_dropped',
                'console_dropped', 'ranges_dropped', 'map_device',
                'mmio_reads', 'mmio_writes', 'uart_tx')
# And after them, one word that is not a counter: the exception-return
# trampoline XNU registers. It lives here because it used to live in the fault
# slot, where it made every run look like a run that recorded a fault.
EXC_RETURN_OFFSET = COUNTERS_OFFSET + len(COUNTER_KEYS) * 8
# And after that, ELR_EL2 and FAR_EL2 as the `bad` vector found them. ESR alone
# says an EL2 fault happened and what kind; these say where in the probe and
# what address it was reaching for.
BAD_REGS_OFFSET = EXC_RETURN_OFFSET + 8
# And after that, the terminal word: the last event the probe recorded, in the
# shape of a log entry and held outside the ring, so a run whose log overflowed
# can still say what it was doing when it stopped.
LAST_EVENT_OFFSET = BAD_REGS_OFFSET + 16
# And after that, one counter per endpoint plus one for everything else.
ENDPOINT_BUCKETS = 64
ENDPOINTS_OFFSET = LAST_EVENT_OFFSET + 6 * 8

# SPTM's own names for its endpoints, from its dispatch table in __DATA_CONST
# (51 entries; tools/sptm-dispatch.py prints it out of
# downloads/extracted/j700ap/sptm.t8140.release). The gaps are holes in Apple's
# numbering, not endpoints this monitor refuses, so they are absent rather than
# named "unknown" -- a call to one would be a genuine surprise and should read
# as one.
SPTM_ENDPOINTS = {
    0x00: 'LOCKDOWN', 0x01: 'RETYPE', 0x02: 'MAP_PAGE', 0x03: 'MAP_TABLE',
    0x04: 'UNMAP_TABLE', 0x05: 'UPDATE_REGION', 0x06: 'UPDATE_DISJOINT',
    0x07: 'UNMAP_REGION', 0x08: 'UNMAP_DISJOINT',
    0x09: 'CONFIGURE_SHAREDREGION', 0x0a: 'NEST_REGION',
    0x0b: 'UNNEST_REGION', 0x0c: 'CONFIGURE_ROOT', 0x0d: 'SWITCH_ROOT',
    0x0e: 'REGISTER_CPU', 0x0f: 'FIXUPS_COMPLETE',
    0x10: 'SIGN_USER_POINTER', 0x11: 'AUTH_USER_POINTER',
    0x12: 'REGISTER_EXC_RETURN', 0x13: 'CPU_ID', 0x14: 'SLIDE_REGION',
    0x15: 'UPDATE_DISJOINT_MULTIPAGE', 0x18: 'GUEST_VA_TO_IPA',
    0x19: 'GUEST_STAGE1_TLBOP', 0x1a: 'GUEST_STAGE2_TLBOP',
    0x1b: 'GUEST_DISPATCH', 0x1c: 'GUEST_EXIT', 0x1e: 'HIB_BEGIN',
    0x1f: 'HIB_VERIFY_HASH_NON_WIRED', 0x20: 'HIB_FINALIZE_NON_WIRED',
    0x21: 'IOFILTER_PROTECTED_WRITE', 0x27: 'SET_SHARED_REGION',
    0x28: 'BATCH_SIGN_USER_POINTER', 0x29: 'SURT_ALLOC', 0x2a: 'SURT_FREE',
    0x2b: 'CONDEMN_LEAF_TABLE', 0x2c: 'UNCONDEMN_LEAF_TABLE',
    0x2d: 'SPTM_SERIAL_PUTC', 0x2e: 'SPTM_SERIAL_DISABLE',
    0x32: 'OUTPUT_AREA',
}


def read_endpoint_calls(proxy, out):
    """How many calls each endpoint took, and how many went elsewhere.

    Returns (per-endpoint list of 64, other). The log cannot answer this: it
    collapses repeats and then drops what does not fit, so an endpoint called
    four hundred times and one called once look the same in it."""
    words = struct.unpack(f'<{ENDPOINT_BUCKETS + 1}Q',
                          proxy.readmem(out + ENDPOINTS_OFFSET,
                                        (ENDPOINT_BUCKETS + 1) * 8))
    return list(words[:ENDPOINT_BUCKETS]), words[ENDPOINT_BUCKETS]


def endpoint_calls(proxy, out, monitor_calls=None):
    """The per-endpoint tally, printed, with the arithmetic checked.

    The sum is the point as much as the breakdown: the last run made 390
    monitor calls and the transcript could account for 385, and nothing in it
    could say where the other five went. Here the columns add up or they are
    said not to."""
    per, other = read_endpoint_calls(proxy, out)
    total = sum(per) + other
    if not total:
        return
    print('\nmonitor calls by endpoint:')
    for fn, count in enumerate(per):
        if count:
            name = SPTM_ENDPOINTS.get(fn, 'not in SPTM\'s dispatch table')
            print(f'  {fn:#04x}  {name:<30} {count}')
    if other:
        print(f'        {"another domain, table or command":<30} {other}')
    print(f'        {"= total calls to the dispatcher":<30} {total}')
    # The one number the probe counts twice by two different routes. A
    # disagreement means a call path that increments one and not the other,
    # which is exactly the kind of gap these counters exist to close.
    if monitor_calls is not None and monitor_calls != total:
        print(f'  NOTE: the report says {monitor_calls} calls were answered and '
              f'these columns total {total}; the difference is calls that '
              f'reached the dispatcher and were not answered')


# The out-of-memory mappings, as spans. Slots of {va, pa, pages, attrs} after a
# count and a count of what did not fit.
MAP_RANGES = 128
MAP_RANGE_WORDS = 4
RANGES_OFFSET = ENDPOINTS_OFFSET + (ENDPOINT_BUCKETS + 1) * 8
# And after that, the guest's translation registers as the probe last saw them.
GUEST_SYSREGS_OFFSET = RANGES_OFFSET + (2 + MAP_RANGES * MAP_RANGE_WORDS) * 8
GUEST_SYSREG_NAMES = ('TTBR0_EL1', 'TTBR1_EL1', 'TCR_EL1', 'MAIR_EL1',
                      'SCTLR_EL1')
FRAMEBUFFER_WITNESS_OFFSET = GUEST_SYSREGS_OFFSET + 5 * 8
ASYNC_REGS_OFFSET = FRAMEBUFFER_WITNESS_OFFSET + 3 * 8
EXCEPTION_FLOW_OFFSET = ASYNC_REGS_OFFSET + (1 + GUEST_REGS_WORDS) * 8
UPDATE_FLOW_OFFSET = EXCEPTION_FLOW_OFFSET + 3 * 8
CLOCK_FLOW_OFFSET = UPDATE_FLOW_OFFSET + (4 + 3) * 8
TIMER_FLOW_OFFSET = CLOCK_FLOW_OFFSET + 8 * 8
DEVICE_FLOW_OFFSET = TIMER_FLOW_OFFSET + 11 * 8
CLOCK_ADAPTER_OFFSET = DEVICE_FLOW_OFFSET + (1 + 2*MODEL_MAX) * 8
AIC_FLOW_OFFSET = CLOCK_ADAPTER_OFFSET + 12 * 8
WATCHDOG_FLOW_OFFSET = AIC_FLOW_OFFSET + 5 * 8
OPTIONAL_FLOW_OFFSET = WATCHDOG_FLOW_OFFSET + (RESET_WORDS + 3*MODEL_MAX) * 8
IPI_FLOW_OFFSET = OPTIONAL_FLOW_OFFSET + 2 * 8
CPU_FLOW_OFFSET = IPI_FLOW_OFFSET + 8 * 8
VCPU_FLOW_OFFSET = CPU_FLOW_OFFSET + 8 * 8
SHARED_FLOW_OFFSET = VCPU_FLOW_OFFSET + 6 * 12 * 8
SERVICE_FLOW_OFFSET = SHARED_FLOW_OFFSET + 3 * 8
RUNTIME_STORAGE_OFFSET = SERVICE_FLOW_OFFSET + 16 * 8
GPU_FLOW_OFFSET = RUNTIME_STORAGE_OFFSET + (6 * 5 + 1) * 8   # OUT_GPU_FLOW
EARLY_STOP_OFFSET = GPU_FLOW_OFFSET + 45 * 8                 # OUT_EARLY_STOP, after ADRENO_STATE_WORDS


def uploaded(built, va, n=8):
    """What the loader PUT at `va`, read back out of the chunks it uploaded.

    The other half of a readback: `peek` says what is there now, this says what
    was there before the guest ran, and the pair is what turns a byte into a
    statement about whether anything wrote it.

    Chunks are keyed by the physical address they start at and are as long as
    the segment they came from, so the one wanted is the one whose range covers
    the address -- not the one whose key equals it. Chunks overlap and are
    uploaded sorted, which is why this takes the LAST containing chunk: that is
    the one whose bytes survive on the target."""
    pa = built['image_pa'] + (va - built['vmin'])
    found = None
    for base, blob in sorted(built['chunks'].items()):
        if base <= pa and pa + n <= base + len(blob):
            found = int.from_bytes(blob[pa - base:pa - base + n], 'little')
    if found is None:
        raise KeyError(f'{va:#x} (physical {pa:#x}) is in no uploaded chunk')
    return found


def read_guest_sysregs(proxy, out):
    """The guest's TTBR0, TTBR1, TCR, MAIR and SCTLR, as a dict by name."""
    words = struct.unpack(f'<{len(GUEST_SYSREG_NAMES)}Q',
                          proxy.readmem(out + GUEST_SYSREGS_OFFSET,
                                        len(GUEST_SYSREG_NAMES) * 8))
    return dict(zip(GUEST_SYSREG_NAMES, words))


def read_map_ranges(proxy, out):
    """The span table: (list of (va, pa, pages, attrs), how many did not fit)."""
    words = struct.unpack(f'<{2 + MAP_RANGES * MAP_RANGE_WORDS}Q',
                          proxy.readmem(out + RANGES_OFFSET,
                                        (2 + MAP_RANGES * MAP_RANGE_WORDS) * 8))
    count, dropped = words[0], words[1]
    spans = [tuple(words[2 + MAP_RANGE_WORDS * n:2 + MAP_RANGE_WORDS * (n + 1)])
             for n in range(min(count, MAP_RANGES))]
    return spans, dropped


def map_ranges(proxy, out, xb, built, outside=None):
    """The device surface the kernel asked for, printed with the tree's names.

    The log keeps five of these and a counter keeps the total; neither says
    which devices, nor how much of each. A span does, at a fixed cost, and the
    physical base resolves back through the guest's own device tree -- which is
    the only authority on what lives at an address this machine has nothing
    at."""
    spans, dropped = read_map_ranges(proxy, out)
    if not spans and not dropped:
        return
    inventory = xb.device_inventory(built['dt'])
    print('\nmappings onto addresses outside the memory we declared:')
    pages = 0
    for va, pa, n, attrs in spans:
        pages += n
        owner = xb.owner_of(pa, inventory)
        if owner:
            who, base, size = owner
            where = f'{who} +{pa - base:#x} of {size:#x}'
        else:
            where = 'no node of the guest tree claims this address'
        print(f'  va {va:#x} -> pa {pa:#x}  {n:>4} page'
              f'{"" if n == 1 else "s"} of 16K   {where}')
        print(f'     attrs {attrs:#05x}  AttrIndx {(attrs >> 2) & 7}  '
              f'SH {(attrs >> 8) & 3}  AP {(attrs >> 6) & 3}')
    if dropped:
        print(f'  and {dropped} span{"" if dropped == 1 else "s"} that did not '
              f'fit the {MAP_RANGES}-slot table -- the surface is WIDER than '
              f'what is printed above')
    print(f'  {len(spans)} span{"" if len(spans) == 1 else "s"}, {pages} pages '
          f'in total')
    # The table and the counter are written at the same place for one reason:
    # so this has to hold. If it does not, one of them is counting something
    # the other is not, and a device surface is the wrong thing to be vague
    # about.
    if outside is not None and not dropped and pages != outside:
        print(f'  NOTE: the counter says {outside} such mappings and these '
              f'spans hold {pages}; nothing was dropped, so the two should '
              f'agree exactly')


def read_bad_regs(proxy, out):
    """ELR_EL2 and FAR_EL2 at the fault, or (0, 0) if none was taken."""
    return struct.unpack('<2Q', proxy.readmem(out + BAD_REGS_OFFSET, 16))


def stage2_stop_hpfar(last_event):
    """SNAP_S2_FAULT_RETRY (compat/s2-fault-retry.h): a stage-2 stop's terminal word carries
    HPFAR_EL2 in its sixth word, which is otherwise always zero (the slot holds one event, so
    it never counts repeats). (the event with that word zeroed, HPFAR) -- or (event, None)."""
    if last_event is None or last_event[0] != EV_S2_FAULT or not last_event[5]:
        return last_event, None
    return (*last_event[:5], 0), last_event[5]


def hpfar_ipa(hpfar, far, esr):
    """compat/s2-fault-retry.h s2_retry_hpfar_ipa: HPFAR_EL2.FIPA plus FAR's page offset,
    which is not the address's when the stage-1 walk faulted (S1PTW: a table page)."""
    page = ((hpfar & 0x00000ffffffffff0) >> 4) << 12
    return page | (0 if (esr >> 7) & 1 else far & 0xfff)


def read_last_event(proxy, out):
    """The last event recorded, or None if the probe never recorded one.

    Kind zero is the empty slot: every EV_* is one or more, so the word is
    self-describing and a run that recorded nothing is not confused with a
    short read."""
    row = struct.unpack('<6Q', proxy.readmem(out + LAST_EVENT_OFFSET, 48))
    return row if row[0] else None
COUNTER_NAMES = ('MAP_PAGE completed', 'MAP_PAGE failed',
                 'dispatch commands refused', 'fatal-exception announcements',
                 'undefined instructions skipped',
                 'MAP_PAGE PTEs outside our memory',
                 'events the log had no room for',
                 'console bytes the buffer had no room for',
                 'out-of-memory spans the table had no room for',
                 'MAP_PAGE mappings onto device windows',
                 'device registers read', 'device registers written',
                 "bytes XNU put on its own serial line")


def read_exc_return(proxy, out):
    """The trampoline XNU registered, from the word that is only ever that."""
    return struct.unpack('<Q', proxy.readmem(out + EXC_RETURN_OFFSET, 8))[0]


def read_counters(proxy, out):
    """The raw tallies, as a dict the classifier can consult."""
    values = struct.unpack(f'<{len(COUNTER_KEYS)}Q',
                           proxy.readmem(out + COUNTERS_OFFSET,
                                         len(COUNTER_KEYS) * 8))
    return dict(zip(COUNTER_KEYS, values))


def counters(proxy, out):
    """The tallies, printed only when there is something to say."""
    values = struct.unpack(f'<{len(COUNTER_KEYS)}Q',
                           proxy.readmem(out + COUNTERS_OFFSET,
                                         len(COUNTER_KEYS) * 8))
    if not any(values):
        return
    print('\ncounters:')
    for name, value in zip(COUNTER_NAMES, values):
        if value:
            print(f'  {name:<32} {value}')


# The kprintf gate, by address, in kernelcache.release.mac17p.
#
# Measured addresses, not derived ones: they came out of a disassembly of THIS
# binary and nothing at run time re-finds them. Named at module scope so a test
# can pin them, because a digit wrong here reads some other __DATA_CONST byte
# and prints a confident number about the wrong variable -- and both of these
# ship as values (0x01 and null) common enough nearby that a wrong address
# would not look wrong.
#
# mac17j and mac17g are different binaries of the same source and every one of
# these addresses is different in them. The device boots mac17p.
KPRINTF_GATE = 0xfffffe0007ebf160   # two SECURITY_READ_ONLY_LATE gate bytes
PE_KPUTC = 0xfffffe0007ebf220       # the console function pointer they guard


def video_console_state(peek, built):
    """A profile-scoped memory witness, independent of silent kprintf gates."""
    witness = built.get('video_console_witness')
    if witness is None:
        print('\n--- no audited video-console witness for this guest profile ---')
        return None
    print('\n--- XNU video-console state (guest memory) ---')
    state = witness.read(peek)          # failure must not look like a valid witness
    print(f'  vinfo {state["width"]}x{state["height"]}x{state["depth"]}, '
          f'stride {state["stride"]}, PA {state["physical_base"]:#x}, '
          f'VA {state["mapped_va"]:#x}')
    fb = built.get('framebuffer')
    expected = (fb[0], fb[1], fb[2], fb[3], fb[4]) if fb else None
    actual = tuple(state[k] for k in ('physical_base', 'width', 'height', 'stride', 'depth'))
    state['geometry_matches'] = expected is not None and actual == expected
    print(f'  geometry matches handover: {state["geometry_matches"]}; '
          f'graphics mode byte {state["graphics_mode"]}; acquired byte {state["acquired"]}')
    if not state['acquired']:
        print('  mapped/configured is not acquired: XNU has not acquired its video console')
    else:
        print('  acquired; this state alone does not prove glyphs were drawn')
    return state


def kprintf_gate(peek, built):
    """The two SECURITY_READ_ONLY_LATE bytes that decide whether kprintf
    reaches a wire, and the function pointer behind them, live against the
    values the loader uploaded."""
    # Why kprintf is silent, measured rather than argued.
    #
    # The story. XNU's kprintf reaches a wire only if three things hold where
    # it is called (0xfffffe000b91c930 and 0xfffffe000b91c9f4, identical):
    # a flag in w8 is set, bit 0 of the byte at 0xfffffe0007ebf160 is CLEAR,
    # and the function pointer PE_kputc at 0xfffffe0007ebf220 is non-null.
    # `tbnz w9, #0` on that byte branches PAST the call, so 1 means silence.
    #
    # Both gate bytes ship as 1 in kernelcache.release.mac17p, and that is the
    # whole question. Byte 0xfffffe0007ebf160 has one writer in the image, a
    # strb at 0xfffffe000c24f8e8, 0x34 bytes after the str that sets PE_kputc
    # -- one function arms both. Byte 0xfffffe0007ebf161 has ONE reader, an
    # ldrb at 0xfffffe000c1eff50 inside serial init, and NO writer anywhere in
    # the image: scanned for every adrp+store form against that page, there is
    # nothing that can clear it. If that holds it is permanently 1 and the
    # branch it guards is permanently taken.
    #
    # What this measures is the LIVE bytes at the stop, against the image's
    # shipped 01 01 00 00. Byte .160 clearing to 0 means PE_init_printf ran and
    # kprintf should have reached the wire, so silence has another cause; .160
    # still 1 means it never ran. .161 is expected to be 1 forever, and it
    # being 0 would refute the "no writer" reading outright.
    #
    # This decides whether docs/PLAN-HISTORY-20260922.md's witness 3 is reachable as written: both of
    # initialize_screen's diagnostics go through kprintf, and a permanently
    # closed gate sends them to os_log and never to us.
    print('\n--- why kprintf is or is not on the wire ---')
    try:
        live = peek(KPRINTF_GATE, 4)
        shipped = uploaded(built, KPRINTF_GATE, 4)
        for i, (what, why) in enumerate((
                ('gate byte +0x160', 'kprintf is suppressed while bit 0 is set; '
                 'one writer in the image, with PE_kputc'),
                ('gate byte +0x161', 'read once, in serial init; NO writer '
                 'found anywhere in the image'),
                ('byte +0x162', 'not part of the kprintf gate; shown for context'),
                ('byte +0x163', 'not part of the kprintf gate; shown for context'))):
            now, was = (live >> (8 * i)) & 0xff, (shipped >> (8 * i)) & 0xff
            moved = '' if now == was else f'  <-- CHANGED from {was:#04x}'
            print(f'  {what:<20} {now:#04x} (image ships {was:#04x}){moved}')
            if i < 2:
                print(f'     {why}')
        kputc = peek(PE_KPUTC)
        print(f'  {"PE_kputc":<20} {kputc:#018x}'
              f'{"   still null: no console function was ever installed" if not kputc else ""}')
        if not (live & 1) and kputc:
            print('     +0x160 is clear and PE_kputc is installed; this alone '
                  'does not prove a kprintf call reached the wire')
            if live & 0x100:
                print('     +0x161 remains set: the serial-init gate is still '
                      'closed; do not infer that both gates are open')
        elif live & 1:
            print('     bit 0 of +0x160 is set, so every kprintf call branches '
                  'past PE_kputc: witness 3 cannot arrive this way')
    except Exception as exc:                            # noqa: BLE001
        print(f'  could not read it: {exc}')


def guest_sysregs(proxy, out, built):
    """The guest's translation registers, and whether MAIR moved."""
    # And the guest's own MAIR, which is the hardware check on a static claim.
    #
    # The loader publishes the 0x0c0d00ff01a040ff SPTM's common start leaves
    # for XNU, because there is no `msr MAIR_EL1` anywhere in this kernelcache.
    # If that reading of 120 MiB of image is wrong, this word comes back as
    # something else.
    try:
        sysregs = read_guest_sysregs(proxy, out)
        print('\n--- the guest\'s translation registers, as we last saw them ---')
        for name, value in sysregs.items():
            note = ''
            if name == 'MAIR_EL1':
                note = ('   unchanged: XNU never wrote it, as the image said'
                        if value == built['mair'] else
                        f'   CHANGED from the {built["mair"]:#018x} we published '
                        f'-- something wrote MAIR and the image scan missed it')
            print(f'  {name:<12} {value:#018x}{note}')
    except Exception as exc:                            # noqa: BLE001
        print(f'  could not read the guest sysregs: {exc}')


def guest_registers(proxy, out):
    """Print the guest's registers as of its exceptions, if any were captured.

    Two snapshots: the first exception explains the run, and every later one is
    usually XNU's own panic path, whose registers belong to the handler rather
    than to the code that failed. When only one was seen they are the same and
    only one is printed."""
    raw = proxy.readmem(out + GUEST_REGS_OFFSET, GUEST_REGS_BYTES)
    count = struct.unpack_from('<Q', raw, 0)[0]
    if not count:
        return

    def snapshot(index):
        base = 8 + index * GUEST_REGS_WORDS * 8
        words = struct.unpack_from(f'<{GUEST_REGS_WORDS}Q', raw, base)
        return (words[:31], words[31], words[32], words[33], words[34],
                words[35])

    shown = [('first', 0)] if count == 1 else [('first', 0), ('last', 1)]
    print(f'\nguest registers at {count} exception{"" if count == 1 else "s"}:')
    for label, index in shown:
        x, sp, spsr, pc, esr, far = snapshot(index)
        head = '' if count == 1 else f' ({label})'
        print(f'  PC {pc:#018x}   ESR_EL1 {esr:#x} (EC {esr >> 26:#x} '
              f'FSC {esr & 0x3f:#04x})   FAR_EL1 {far:#018x}')
        print(f'  SP {sp:#018x}   SPSR_EL1 {spsr:#x}{head}')
        dump_gprs(x)


def dump_gprs(x, indent='    '):
    for row in range(0, 31, 4):
        cells = ' '.join(f'x{n:<2} {x[n]:#018x}'
                         for n in range(row, min(row + 4, 31)))
        print(f'{indent}{cells}')


def panic_entry(proxy, out):
    """The frame at XNU's panic-entry call, dispatch command 0x2.

    XNU makes this call on its way out of a fatal exception, before panic() has
    run and before any panic record exists -- so this is the earliest point at
    which the fault can be read, and often the only one."""
    raw = proxy.readmem(out + PANIC_REGS_OFFSET, PANIC_REGS_BYTES)
    count = struct.unpack_from('<Q', raw, 0)[0]
    if not count:
        return
    words = struct.unpack_from(f'<{GUEST_REGS_WORDS}Q', raw, 8)
    x, sp, spsr, pc, esr, far = (words[:31], words[31], words[32],
                                 words[33], words[34], words[35])

    print(f'\nXNU announced a fatal exception {count} time'
          f'{"" if count == 1 else "s"} (dispatch command 0x2):')

    caller = x[30]
    where = PANIC_CALLERS.get(caller)
    print(f'  called from  {caller:#018x}  '
          f'{where if where else "a site this project has not seen before"}')

    # EL1's own registers, read at EL2 when the call arrived. These do not
    # depend on which caller it was: XNU copies them, it does not rewrite them.
    print(f'  ELR_EL1 {pc:#018x}   ESR_EL1 {esr:#x} '
          f'(EC {esr >> 26:#x} FSC {esr & 0x3f:#04x} '
          f'{"write" if (esr >> 6) & 1 else "read"})')
    print(f'  FAR_EL1 {far:#018x}   SP {sp:#018x}   SPSR_EL2 {spsr:#x}')

    # And the latched copies, with each register given the role this caller
    # actually assigns it -- x25 and x26 swap between the two shapes.
    roles = PANIC_LATCH_CALLERS.get(caller)
    if roles:
        cells = [f'x{n} {x[n]:#018x} ({roles[n]})' for n in sorted(roles)]
        print(f'  latched      {cells[0]}  {cells[1]}')
        print(f'               {cells[2]}  {cells[3]}')
    else:
        print('  x25/x26/x27/x28 are NOT the fault here -- this caller does '
              'not latch them,')
        print('  so they hold unrelated values and are left undecoded above.')
    dump_gprs(x, '  ')


def truncated(dropped, capacity, panic_said):
    """How to report a run whose event log overflowed.

    The log is the only thing truncation damages. XNU's panic record is read out
    of memory after the run, so it cannot overflow and it is not inferred from
    anything -- if the kernel wrote down why it stopped, that answer survives
    intact and is strictly better than refusing to answer.

    So the guard suppresses verdicts INFERRED FROM THE LOG and leaves the ones
    that come from the record. A truncated log means we cannot say which monitor
    call was last; it does not mean we cannot read what the kernel wrote."""
    lost = (f'{dropped} events did not fit the {capacity}-entry log, so no '
            f'monitor-call cause can be named from it')
    if panic_said:
        return EXIT_PANIC, (
            f'the kernel panicked: {panic_said.strip()[:160]}  '
            f'(read from the panic record, which memory holds and truncation '
            f'cannot reach; {lost})')
    return EXIT_UNCLASSIFIED, (
        f'{lost}, and the panic record is empty -- so the run stopped for a '
        f'reason nothing recorded')


def format_panic(fmt, words, peekstr):
    """Substitute a panic's arguments into its format string.

    The kernel pushes each argument into an 8-byte stack slot, so the words are
    consumed one per conversion in order. This is deliberately forgiving: a
    conversion it does not know stops the substitution and returns what it had,
    because half a sentence plus the raw words printed above is honest, and a
    confidently wrong sentence is the failure mode this whole exercise exists to
    avoid.

    Returns None when there is nothing useful to say."""
    if not fmt:
        return None
    out, i, arg = [], 0, 0
    while i < len(fmt):
        ch = fmt[i]
        if ch != '%':
            out.append(ch)
            i += 1
            continue
        i += 1
        if i < len(fmt) and fmt[i] == '%':
            out.append('%')
            i += 1
            continue
        # flags, width, precision, length -- skipped, they only affect padding
        while i < len(fmt) and fmt[i] in '-+ #0123456789.*':
            i += 1
        length = ''
        while i < len(fmt) and fmt[i] in 'hlLqjzt':
            length += fmt[i]
            i += 1
        if i >= len(fmt):
            break
        conv = fmt[i]
        i += 1
        if arg >= len(words):
            return None                      # ran out; do not invent
        value = words[arg]
        arg += 1
        if conv == 's':
            text = peekstr(value, 128)
            out.append(f'"{text}"' if text else f'<{value:#x}>')
        elif conv == 'c':
            out.append(chr(value & 0xff))
        elif conv in 'xX':
            out.append(f'{value:x}' if conv == 'x' else f'{value:X}')
        elif conv == 'p':
            out.append(f'{value:#x}')
        elif conv in 'di':
            width = 64 if length else 32
            v = value & ((1 << width) - 1)
            if v >= 1 << (width - 1):
                v -= 1 << width
            out.append(str(v))
        elif conv == 'u':
            out.append(str(value & (0xFFFFFFFFFFFFFFFF if length else 0xFFFFFFFF)))
        else:
            # Unknown conversion: stop rather than guess at how many words it ate.
            out.append(f'%{length}{conv}<unformatted>')
            break
    return ''.join(out).strip()


def par_report(par):
    """PAR_EL1: bit 0 set means the walk faulted."""
    if par & 1:
        return f'FAULT  (FST {(par >> 1) & 0x3f:#04x})'
    return f'ok  PA {par & 0x000ffffffffff000:#x}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('probe', choices=['idregs', 'tgran16', 'tid3', 'shadowmmu',
                                      'xnuboot'])
    ap.add_argument('--device', default=DEFAULT_DEVICE,
                    help='serial/socket path or udp://enN (default: discover CDC/NCM)')
    ap.add_argument('--guest-profile', default='j700ap-26A428')
    ap.add_argument('--firmware-dir')
    ap.add_argument('--kernelcache', help='must match the selected guest profile')
    ap.add_argument('--ramdisk', help='raw APFS root image, reserved in guest RAM')
    ap.add_argument('--ramdisk-mode', choices=('md0', 'iokit'), default='md0',
                    help='BSD memory device or native IOKit RAM-image attachment')
    ap.add_argument('--root-hash', help='raw root-hash payload, bound by the guest profile to --ramdisk')
    ap.add_argument('--isc-image', help='fresh auxiliary raw APFS ISC image; requires IOKit mode')
    ap.add_argument('--auxkc', help='kmutil-linked AuxKC (build/build-auxkc.py) for a linked-collection profile')
    ap.add_argument('--trust-additions', help='JSON CDHash rows for an augmented trust-cache profile')
    ap.add_argument('--ans-disk', help='4 KiB-LBA GPT disk for a virtual ANS2 profile '
                    '(build/build-ans-test-disk-20260925.py)')
    ap.add_argument('--ans-writable', action='store_true',
                    help='enable persistent guest writes inside the installed SSD window')
    ap.add_argument('--console', dest='console_mode', choices=['auto', 'serial', 'panel'],
                    default='auto',
                    help='auto uses the native panel console when a framebuffer is available, '
                         'otherwise serial; use serial for UART capture')
    ap.add_argument('--relay-panel', action='store_true',
                    help='draw captured serial output; requires SNAP_NO_FB=1')
    ap.add_argument('--graphics-boot',action='store_true',
                    help='native graphics-mode boot handoff without -v; requires the panel route')
    ap.add_argument('--qemu', action='store_true',
                    help='run against q1n1 in QEMU (-cpu max) instead of hardware')
    args = ap.parse_args()
    if args.probe == 'xnuboot':
        from guestprofile import get_profile
        try:
            get_profile(args.guest_profile)
        except ValueError as error:
            ap.error(str(error))
    boot_options = {key: getattr(args, key) for key in
                    ('guest_profile', 'firmware_dir', 'kernelcache',
                     'console_mode', 'relay_panel', 'ramdisk', 'root_hash', 'ramdisk_mode', 'isc_image',
                     'graphics_boot', 'auxkc', 'trust_additions', 'ans_disk', 'ans_writable')}

    blob = build(args.probe, ROOT / 'build')
    if args.qemu:
        with Qemu(ROOT) as sock:
            proxy = connect(sock)
            try:
                return run(proxy, blob, args.probe, 'QEMU -cpu max', boot_options)
            finally:
                proxy.link.close()
    proxy = connect(args.device)
    try:
        return run(proxy, blob, args.probe, proxy.endpoint, boot_options)
    finally:
        proxy.link.close()


def run(proxy, blob, probe, where, boot_options=None):
    # Check before any target operation: growing the runtime must never let
    # report initialization overwrite its executable image.
    if not blob or len(blob) > OUT_AT - CODE_AT:
        raise ValueError('probe image exceeds its reserved code region')
    info = proxy.bootinfo()
    print(f'{where}: q1n1 generation {info["stage_generation"]}, EL{info["current_el"]}, '
          f'heap {info["heap_base"]:#x}+{info["heap_size"] >> 20}M')

    code = info['heap_base'] + CODE_AT
    out = info['heap_base'] + OUT_AT
    # 16K aligned, and clear of both code and the output buffer.
    table = (out + 0x20000 + 0x3fff) & ~0x3fff
    proxy.writemem(code, blob)
    proxy.flush_code(code, len(blob))

    if probe == 'xnuboot':
        return run_xnuboot(proxy, info, code, code_size=len(blob), **(boot_options or {}))

    if probe == 'shadowmmu':
        work = (info['heap_base'] + 0x500000 + 0xffff) & ~0xffff
        stage = int(os.environ.get('SNAP_STAGE', '0'))
        proxy.call(code, out, work, 0x200000, stage)
        magic, ttbr_back = struct.unpack('<2Q', proxy.readmem(out, 16))
        g_ttbr, g_tcr, s_root, traps, builds, leaves, par_code, par_test = struct.unpack(
            '<8Q', proxy.readmem(out + 16, 64))
        expect, test_va, entered = struct.unpack('<3Q', proxy.readmem(out + 80, 24))
        f_esr, f_elr, f_far = struct.unpack('<3Q', proxy.readmem(out + 104, 24))
        (stub_pa, stub_calls, stub_result, stub_arg, steps, neighbour,
         oslsr, mdcr, mdscr, s_root1, leaves1, par_k,
         kernel, kernel_want) = struct.unpack('<14Q', proxy.readmem(out + 128, 112))
        aborts, steps = steps & 0xffffffff, steps >> 32
        if f_esr:
            print(f'  EL2 FAULT  ESR {f_esr:#x} (EC {f_esr >> 26:#x})  '
                  f'ELR {f_elr:#x}  FAR {f_far:#x}')
        # shadowmmu_selftest returns int, so the verdict is 32-bit.
        verdict = (entered & 0xffffffff)
        if verdict >= (1 << 31):
            verdict -= (1 << 32)
        if stage == 0:
            names = {0: 'ok', -1: 'prepare: out of work area', -2: 'no shadow root',
                     -3: 'shadow_build failed', -4: 'shadow walk failed',
                     -5: 'test VA unmapped in the shadow', -6: 'wrong data at the mapped PA',
                     -7: 'code walk failed', -8: 'code not identity-mapped in the shadow',
                     -9: 'hardware refused the shadow for the guest PC',
                     -10: 'hardware refused the shadow for the test VA'}
            print(f'  EL2 selftest       {names.get(verdict, verdict)}')
            par0 = lambda v: ('not attempted' if v == 0 else
                              f'FAULT (FST {(v >> 1) & 0x3f:#04x})' if v & 1 else
                              f'ok PA {v & 0x000ffffffffff000:#x}')
            print(f'  hw walk guest PC   {par0(par_code)}')
            print(f'  hw walk test VA    {par0(par_test)}')
        else:
            print(f'  guest entered      {"yes" if entered else "NO"}')
        print(f'  guest TTBR0 (16K)  {g_ttbr:#x}   TCR {g_tcr:#x}  TG0 {(g_tcr >> 14) & 3}')
        print(f'  shadow root (4K)   {s_root:#x}   leaves {leaves}')
        if s_root1 or stage >= 8:
            print(f'  upper-half shadow  {s_root1:#x}   leaves {leaves1}')
        guest_fault = builds >> 32
        print(f'  sysreg traps       {traps}   shadow builds {builds & 0xffffffff}')
        if guest_fault:
            print(f'  guest EL1 fault    ESR {guest_fault:#x} (EC {guest_fault >> 26:#x}, '
                  f'FSC {guest_fault & 0x3f:#04x})')
        print(f'  guest read {magic:#018x} from VA {test_va:#x}, wanted {expect:#018x}')
        print(f'  guest read back TTBR0 {ttbr_back:#x}')
        if stage == 0:
            return 0 if verdict == 0 else 1
        
        par = lambda v: ('not attempted' if v == 0 else
                         f'FAULT (FST {(v >> 1) & 0x3f:#04x})' if v & 1 else
                         f'ok PA {v & 0x000ffffffffff000:#x}')
        print(f'  hw walk of guest PC  {par(par_code)}')
        print(f'  hw walk of test VA   {par(par_test)}')
        if stage >= 8:
            print(f'  hw walk of kernel VA {par(par_k)}')
            print(f'  kernel-half load   {kernel:#018x}, wanted {kernel_want:#018x}')
        # Stage 6 arms the monitor-call interception: one page of the blob is
        # execute-never at stage 2, so the guest's call into it is answered by
        # EL2. STUB_REPLY and the argument are fixed in the probe.
        want = (0x5150 + 0x504d0000) if stage >= 6 else 0
        if stage >= 6:
            print(f'  stub page          {stub_pa:#x}  calls {stub_calls}')
            print(f'  stub call          EL2 saw x0 {stub_arg:#x}, guest got '
                  f'{stub_result:#x}, wanted {want:#x}')
        if stage >= 7:
            print(f'  neighbour          {neighbour:#x}, wanted 0x1235   '
                  f'({aborts} aborts, {steps} single-steps)')
            print(f'  debug state        OSLSR {oslsr:#x} (OS lock '
                  f'{"held" if oslsr & 2 else "clear"})  MDCR_EL2 {mdcr:#x} '
                  f'(TDE {(mdcr >> 8) & 1})  MDSCR_EL1 {mdscr:#x} (SS {mdscr & 1})')
        if not entered:
            print('\nFAILED: never reached the guest (no room in the work area?)')
        elif (builds & 0xffffffff) < 1:
            print('\nFAILED: the shadow was not built when the guest enabled its MMU.')
        elif magic != expect:
            print('\nFAILED: the load through the guest VA did not resolve.')
        elif ttbr_back != g_ttbr:
            print('\nFAILED: TRVM leaked the shadow root to the guest.')
        elif stage >= 6 and stub_calls != 1:
            print(f'\nFAILED: the stub page was entered {stub_calls} times, wanted 1 '
                  '-- stage 2 did not make it execute-never.')
        elif stage >= 6 and stub_result != want:
            print('\nFAILED: the guest got the wrong answer from the stub '
                  f'({stub_result:#x}); the page executed instead of trapping.')
        elif stage >= 8 and kernel != kernel_want:
            print(f'\nFAILED: the load through the kernel-half VA returned '
                  f'{kernel:#x}; TTBR1 is not being shadowed correctly.')
        elif stage >= 7 and neighbour != 0x1235:
            print(f'\nFAILED: ordinary code on the protected page returned '
                  f'{neighbour:#x}; the single-step fallback did not run it.')
        elif stage >= 7 and steps != aborts:
            print(f'\nFAILED: {aborts} aborts but {steps} steps. The page was '
                  'unprotected and never protected again -- the right answer for '
                  'the wrong reason, because the step exception never fired.')
        elif stage >= 8:
            print(f'\nA GUEST RAN WITH 16K PAGE TABLES IN BOTH HALVES. It resolved '
                  f'{test_va:#x} through TTBR0 and a kernel address through TTBR1 '
                  f'({leaves} + {leaves1} leaves re-translated), and its monitor call '
                  'was answered by EL2. That is every translation mechanism XNU needs '
                  'to be entered.')
        elif stage >= 7:
            print(f'\nA GUEST RAN WITH 16K PAGE TABLES; its call into {stub_pa:#x} was '
                  'answered by EL2, and ordinary code on that same execute-never page '
                  f'still ran, one instruction per step ({aborts} aborts, {steps} steps). '
                  "That is both halves of what XNU's monitor-call pages need.")
        elif stage >= 6:
            print(f'\nA GUEST RAN WITH 16K PAGE TABLES, and its call into {stub_pa:#x} '
                  'was answered by EL2 without the page ever executing. That is the '
                  "mechanism XNU's SPTM call stubs need, since `genter` is an "
                  'undefined encoding on this silicon.')
        else:
            print(f'\nA GUEST RAN WITH 16K PAGE TABLES. TCR_EL1.TG0={(g_tcr >> 14) & 3} '
                  f'(16K) never reached the MMU; {leaves} leaves were re-translated into '
                  f'a 4K shadow at {s_root:#x}, and the guest resolved {test_va:#x} '
                  f'through its own tables.')
    elif probe == 'tid3':
        proxy.call(code, out)
        real, seen, isar2, traps, esr, elr = struct.unpack('<6Q', proxy.readmem(out, 48))
        tg = lambda v: (v >> 20) & 0xf
        tg2 = lambda v: (v >> 32) & 0xf
        print(f'  EL2 sees  MMFR0 {real:#018x}  TGran16 {tg(real):#x}  TGran16_2 {tg2(real):#x}')
        print(f'  guest sees MMFR0 {seen:#018x}  TGran16 {tg(seen):#x}  TGran16_2 {tg2(seen):#x}')
        print(f'  guest ISAR2 {isar2:#018x}   traps taken {traps}')
        if esr:
            print(f'  UNEXPECTED exception ESR {esr:#x} ELR {elr:#x}')
            return 1
        untouched = (real & ~0x0000000f00f00000) == (seen & ~0x0000000f00f00000)
        if traps < 2:
            print('\nFAILED: the reads did not trap, so TID3 is not in effect.')
        elif tg(seen) != 2 or tg2(seen) != 2:
            print('\nFAILED: the guest did not see the forged granule.')
        elif not untouched:
            print('\nFAILED: fields other than TGran16 changed; the guest would see '
                  'an inconsistent machine.')
        elif isar2 != 0 and tg(real) != 2:
            print(f'\nTID3 WORKS. The guest believes in 16K pages on hardware that '
                  f'reports TGran16 {tg(real):#x}, and every other field is unchanged.')
        else:
            print('\nTID3 works, but this CPU already has 16K so the forgery is not '
                  'observable here — run it on the A16 for the real result.')
    elif probe == 'tgran16':
        proxy.call(code, out, table)
        hcr, a, b, c, d, mmfr0, expect = struct.unpack('<7Q', proxy.readmem(out, 56))
        print(f'HCR_EL2 {hcr:#018x}  (TGE {(hcr >> 27) & 1}, VM {hcr & 1})')
        print(f'  A  4K  entry0 mapped, VA 0x1000      {par_report(a)}')
        print(f'  B  4K  empty table,   VA 0x1000      {par_report(b)}')
        print(f'  C  4K  entry1 mapped, VA 0x2001000   {par_report(c)}')
        print(f'  D  16K entry1 mapped, VA 0x2001000   {par_report(d)}')
        print(f'ID_AA64MMFR0_EL1 {mmfr0:#018x}  '
              f'TGran16 {(mmfr0 >> 20) & 0xf:#x}  TGran16_2 {(mmfr0 >> 32) & 0xf:#x}')
        ok_a, faulted_b, faulted_c = not (a & 1), bool(b & 1), bool(c & 1)
        got = d & 0x000ffffffffff000
        if not ok_a:
            print('\nINCONCLUSIVE: the 4K control did not resolve, so the harness '
                  'is wrong. Fix that before reading anything else.')
        elif not faulted_b:
            print('\nINCONCLUSIVE: the empty table did not fault, so SCTLR_EL1.M '
                  'was not in effect and every trial would pass regardless.')
        elif not faulted_c:
            print('\nINCONCLUSIVE: 4K resolved an address only 16K should reach, '
                  'so the discriminator does not discriminate.')
        elif d & 1:
            print('\n16K DOES NOT WALK. The controls are sound and the granule '
                  'fell back or faulted, so ID_AA64MMFR0_EL1 is telling the '
                  'truth: XNU cannot run on this silicon in any mode.')
        elif got == expect:
            advertised = (mmfr0 >> 20) & 0xf
            agrees = ('which matches ID_AA64MMFR0_EL1' if advertised in (1, 2)
                      else 'even though ID_AA64MMFR0_EL1 says it is absent -- the '
                           'register understates the hardware, like the Huawei '
                           'PAuth case')
            print(f'\n16K WALKS, resolving {got:#x}, an address the 4K '
                  f'interpretation faults on -- {agrees}.')
        else:
            print(f'\nUNEXPECTED: resolved {got:#x}, wanted {expect:#x}. '
                  'Do not draw a conclusion from this.')
    else:
        proxy.call(code, out)
        names = ['MIDR', 'PFR0', 'PFR1', 'ISAR0', 'ISAR1', 'ISAR2',
                 'MMFR0', 'MMFR1', 'MMFR2', 'DFR0', 'CurrentEL', 'MPIDR']
        for name, value in zip(names, struct.unpack('<12Q', proxy.readmem(out, 96))):
            print(f'{name:10s} {value:#018x}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
