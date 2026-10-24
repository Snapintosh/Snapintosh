#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One generic A16 boot cycle: status, launch, capture, preserve, retire, storage, next.

Replaces the per-generation preserve-genN / retire-genN / run-*-candidate /
collect-* / capture-*-genN / storage-genN scripts. Every value those scripts pinned
in their source now comes from a candidate manifest (candidates/*.json), from the
run's own records, or from tools/cycle_lib/pins.json, and is verified when used.

Every subcommand has --check (for launch: --check-inputs), which performs every
validation except hardware access and writes nothing. Only one hardware client may
run at a time; the hardware modes refuse while another one is running. Never
interrupt an in-flight P_CALL. See docs/CYCLE-TOOL-20260928.md.
"""
import sys

sys.dont_write_bytecode = True

import argparse
import json
import os
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cycle_lib.common import Refused, Workspace  # noqa: E402


def emit(result):
    print(json.dumps(result, indent=None if isinstance(result, dict) and len(json.dumps(result)) < 400 else 2,
                     default=lambda o: hex(o) if isinstance(o, int) else str(o)), flush=True)


def render_dashboard(ws, no_color=False):
    use_color = (sys.stdout.isatty() or os.environ.get('FORCE_COLOR') == '1') and not no_color
    BOLD = '\033[1m' if use_color else ''
    CYAN = '\033[36m' if use_color else ''
    GREEN = '\033[32m' if use_color else ''
    YELLOW = '\033[33m' if use_color else ''
    RESET = '\033[0m' if use_color else ''

    from cycle_lib import status
    from cycle_lib.common import PINS_PATH, hardware_clients

    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                  Snapintosh A16 Cycle Dashboard                  ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════╝{RESET}\n")

    is_custom = PINS_PATH.name == 'pins.json'
    pins_label = f"{GREEN}pins.json (Custom configured){RESET}" if is_custom else f"{YELLOW}pins.example.json (Default template){RESET}"
    print(f"  {BOLD}Configuration:{RESET} {pins_label}")
    print(f"  {BOLD}Target Machine:{RESET} ASUS Zenbook A16 (UX3607OA / X2E-96-100)")
    print(f"  {BOLD}Guest Target:{RESET}   Apple macOS 27 (26A428 stock J700 kernel)")

    expect = status.expected(ws)
    print(f"\n{BOLD}── Workspace State ──{RESET}")
    if expect:
        gen = expect.get('generation', 'unknown')
        img_base = expect.get('image_base', 'unknown')
        print(f"  {BOLD}Expected Generation:{RESET} {GREEN}{gen}{RESET} (slot {img_base})")
        if 'launch' in expect:
            print(f"  {BOLD}Last Launch Record:{RESET}   {Path(expect['launch']).name}")
        if 'retirement' in expect:
            print(f"  {BOLD}Last Retirement:{RESET}     {Path(expect['retirement']).name}")
    else:
        print(f"  {YELLOW}No completed launch or retirement records in build/{RESET}")

    clients = hardware_clients(ws)
    print(f"\n{BOLD}── Hardware Concurrency ──{RESET}")
    if clients:
        print(f"  {YELLOW}⚠ Active clients:{RESET} {len(clients)} process(es) holding hardware lock:")
        for c in clients:
            print(f"    - PID {c['pid']}: {c['command']}")
    else:
        print(f"  {GREEN}✓ Hardware link available{RESET} (0 active clients)")

    print(f"\n{BOLD}── Recommended Next Step ──{RESET}")
    next_cmd = status.next_step(ws)
    for line in next_cmd.strip().splitlines():
        if line.startswith('#'):
            print(f"  {YELLOW}{line}{RESET}")
        else:
            print(f"  {BOLD}{CYAN}> {line}{RESET}")
    print("")


def render_pretty_status(res):
    print(f"\nStatus: {res.get('status')}")
    if 'stage_generation' in res:
        print(f"Generation: {res.get('stage_generation')} (EL{res.get('current_el', '?')})")
        print(f"Image Base: {res.get('image_base')}")
    if 'battery' in res:
        bat = res['battery']
        print(f"Battery:    {bat.get('percent')}% (AC: {bat.get('ac')}, Plausible: {bat.get('plausible')})")
    if 'hardware_clients' in res:
        print(f"Clients:    {len(res['hardware_clients'])} active")
    print("")


def parse(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='command', required=True)

    p = sub.add_parser('status', help='one read-only proxy query: generation, EL, image base, SError, battery')
    p.add_argument('--check', action='store_true')
    p.add_argument('--battery-minimum', type=int)
    p.add_argument('--pretty', action='store_true', help='human-readable formatted output')

    p = sub.add_parser('dashboard', help='visual summary of current workspace, A16 records, and next step')
    p.add_argument('--no-color', action='store_true', help='disable ANSI color output')

    p = sub.add_parser('init-pins', help='initialize or inspect tools/cycle_lib/pins.json from example template')
    p.add_argument('--force', action='store_true', help='overwrite existing pins.json')

    p = sub.add_parser('capture', help='run the stopped-state steps a finished launch still needs')
    p.add_argument('--prefix', required=True)
    p.add_argument('--candidate', help='manifest (needed when the launch record has no cycle bindings)')
    p.add_argument('--set', dest='capture_set', choices=['standard', 'early-boot'],
                   help='default: standard for exits 7/9/12, early-boot for exit 6')
    p.add_argument('--step', help='run exactly this one missing (or failed) step of the set, nothing else')
    p.add_argument('--replace', metavar='PATH=FILE@COMMIT',
                   help='run the steps that use the runtime root\'s PATH with FILE, exactly its COMMIT (bounded)')
    p.add_argument('--unqualified', action='store_true',
                   help='the audit correctly refused this stop: record the refusal, evidence and a read-only witness')
    p.add_argument('--evidence', action='append', default=[], metavar='FILE[@COMMIT]',
                   help='with --unqualified: a file that explains the refusal (repeatable)')
    p.add_argument('--check', action='store_true')

    p = sub.add_parser('preserve', help='copy a captured run\'s evidence aside; prints the preservation hash')
    p.add_argument('--prefix', required=True)
    p.add_argument('--candidate', help='manifest to record with the evidence')
    p.add_argument('--set', dest='capture_set', choices=['standard', 'early-boot'])
    p.add_argument('--document', action='append', default=[], help='extra living document (copied, not re-verified)')
    p.add_argument('--unqualified', action='store_true',
                   help='preserve a stop recorded with capture --unqualified (qualified: false)')
    p.add_argument('--check', action='store_true')

    p = sub.add_parser('retire', help='quiesce, chainload the other stage slot, confirm generation+1 idle')
    p.add_argument('--prefix', required=True, help='the stopped run (or, with --idle, a label for the idle generation)')
    p.add_argument('--preservation-sha256')
    p.add_argument('--stages-from', help='candidate manifest whose "stages" pair to chainload (default: pins.json)')
    p.add_argument('--idle', action='store_true', help='no guest ran at this generation')
    p.add_argument('--loader-failure', action='store_true',
                   help='the launch prepared the GPU, then its loader refused before the upload: no guest ran')
    p.add_argument('--after-retirement', help='with --idle: the retirement record that produced this generation')
    p.add_argument('--retirement-sha256', help='with --idle: SHA-256 of --after-retirement')
    p.add_argument('--bind', action='append', default=[], help='record this file\'s hash in the retirement (repeatable)')
    p.add_argument('--check', action='store_true')

    p = sub.add_parser('launch', help='boot a candidate manifest through the pinned run-sks-transport-candidate.py')
    p.add_argument('--candidate', required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-inputs', action='store_true')
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--boot', action='store_true')
    mode.add_argument('--boot-child', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--battery-minimum', type=int, help='required charge without AC (default 80, floor 50)')
    p.add_argument('--compare-adapter', help=argparse.SUPPRESS)

    p = sub.add_parser('bootstrap-smoke', help='fresh generation0 RAM-only 5s HVC XNU integration smoke')
    p.add_argument('--prefix', required=True)
    p.add_argument('--device')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--boot', action='store_true')
    p.add_argument('--qualification-sha256', help='required for boot; hash printed by prepare/check')
    for name in ('image-base', 'image-size', 'heap-base', 'heap-size'):
        p.add_argument('--' + name, required=True, type=lambda value: int(value, 0))

    p = sub.add_parser('speed-test', help='six-CPU RAM-disk control/fast monitor comparison on the stock kernel')
    p.add_argument('--prefix')
    p.add_argument('--variant', choices=['control', 'fast'], help='prepare: which monitor')
    p.add_argument('--isc-image', help='prepare: three-role ISC image (docs/SPEED-TEST-RAMDISK-20261016.md)')
    p.add_argument('--device')
    p.add_argument('--generation', type=int, help='boot: the idle chainloaded generation the A16 must be at')
    p.add_argument('--qualification-sha256', help='required for boot; hash printed by prepare/check')
    p.add_argument('--after-quiesce', metavar='PREFIX',
                   help='boot: PREFIX (an installed-fresh run) stopped, was preserved and quiesced its GPU in this '
                        'q1n1 boot; admit its parked work locator instead of requiring a cold boot (as installed-fresh '
                        '--after-quiesce: captures, quiesce and parked service words re-verified)')
    p.add_argument('--token-trim', action='store_true',
                   help='with --variant fast: the fast recipe plus SNAP_TOKEN_TRIM (compat/token-trim.h, batch 5) '
                        'through installed_fresh.variant_flags; recorded in the qualification, so give it to '
                        'prepare, check and boot alike')
    p.add_argument('--pauth-el0-live', action='store_true',
                   help='fast variant only: also SNAP_PAUTH_EL0_LIVE (the lock-free EL0 reads return to EL0 with the '
                        'process\'s PAC bank still installed), through installed-fresh\'s variant_flags; recorded at '
                        'prepare, and give it to every later mode of the attempt')
    p.add_argument('--el0-memo', action='store_true',
                   help='with --pauth-el0-live: also SNAP_EL0_MEMO (batch 6: the lock-free EL0 read\'s fetch from a '
                        'per-vCPU memo of the PC page\'s translation, re-read and unchanged, and the user return\'s PAC '
                        'derivation through a second-level cache), through installed-fresh\'s variant_flags; recorded '
                        'at prepare, and give it to every later mode of the attempt')
    p.add_argument('--unnest-4k-fast', action='store_true',
                   help='fast variant only: also SNAP_UNNEST_4K_FAST (docs/UNNEST-4K-FAST-20261020.md), through '
                        'installed-fresh\'s variant_flags; it acts on 4K user roots only, which the stock kernel does '
                        'not make (the speed test then measures only its wider memo witness); recorded at prepare, '
                        'and give it to every later mode of the attempt')
    p.add_argument('--phase-fair-gate', action='store_true',
                   help='fast variant only: also SNAP_PHASE_FAIR_GATE (compat/service-lock.h, batch 6), a phase-fair '
                        'gate for the converted calls (one token holder\'s wait, not the token\'s queue), through '
                        'installed-fresh\'s variant_flags; recorded at prepare, and give it to every later mode')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--boot', action='store_true')
    mode.add_argument('--decode', action='store_true', help='re-decode a preserved run offline')
    mode.add_argument('--compare', nargs=2, metavar='PREFIX', help='one control and one fast run, offline')
    p.add_argument('--lean-traps', nargs='?', const=1, type=int, choices=(1, 2),
                   help='opt-in monitor define SNAP_LEAN_TRAPS (compat/lean-trap.h; --variant fast with '
                        '--root-cache-wide): 1 (the default value) emulates the adjacent MRS after a lock-free '
                        'ESR/FAR/PMC read in the same trap and makes the lock-free exits cheaper; 2 also uses FEAT_FGT '
                        'instead of HCR_EL2.TVM/TRVM so ESR_EL1/FAR_EL1 reads stop trapping (needs SCR_EL3.FGTEn, '
                        'unrecorded: a refusal shows at prepare, before guest entry); prepare only; check reads it from the qualification')

    p = sub.add_parser('installed-fresh', help='one installed-SSD boot with our Adreno kext and Metal plug-in, '
                       'admitted from current sources (docs/INSTALLED-FRESH-ADMISSION-20261016.md)')
    p.add_argument('--prefix')
    p.add_argument('--variant', choices=['control', 'fast'], help='prepare: which monitor')
    p.add_argument('--device')
    p.add_argument('--generation', type=int, help='boot: the idle chainloaded generation the A16 must be at')
    p.add_argument('--qualification-sha256', help='required for boot; hash printed by prepare/check')
    p.add_argument('--console', action='store_true',
                   help='the two-way console (tools/guest-console.py): SNAP_EARLY_STOP=guest,console and '
                        'snapintosh_shell=1; give it to every mode of the attempt')
    p.add_argument('--single-user', action='store_true',
                   help='with --console: also -s, so launchd starts a single-user shell on the console')
    p.add_argument('--input-touchpad', action='store_true',
                   help='with --input: also the touchpad (the -input-touchpad profile); refused until '
                        'probes/i2cinput.py TOUCHPAD_QUALIFIED; give it to every mode of the attempt')
    p.add_argument('--input-ptp', action='store_true',
                   help='opt-in input AuxKC (needs --input --input-touchpad; instead of --present-vsync60, whose '
                        'AdrenoX2 it carries; with --present-dartpool, INPUT_AUXKC_PTP_DARTPOOL, that one\'s '
                        'AdrenoX2): INPUT_AUXKC_PTP, a SnapI2CHID that switches the touchpad to Precision '
                        'Touchpad mode (two-finger scroll with momentum, tap-to-click, the trackpad scroll identity; '
                        'today\'s mouse mode if the device refuses); docs/A16-INPUT-PTP-20261020.md; give it to every '
                        'mode of the attempt')
    p.add_argument('--input', action='store_true',
                   help='the built-in keyboard (docs/A16-INPUT-INSTALLED-20261017.md): the -input profile '
                        '(SnapI2CHID node, IC20 GENI page at stage 2), -DSNAP_I2C_INPUT=1 and the AdrenoX2 + '
                        'SnapI2CHID AuxKC; give it to every mode of the attempt')
    p.add_argument('--wfi-resume', action='store_true',
                   help='opt-in monitor define SNAP_WFI_RESUME (compat/wfi-resume.h): the monitor\'s host-only 1 ms '
                        'ticks send an idle vCPU straight back to its WFI; give it to every mode of the attempt')
    p.add_argument('--dart-memo', action='store_true',
                   help='opt-in monitor define SNAP_DART_MEMO (docs/DART-MEMO-20261019.md; with --root-cache-wide): DART '
                        'MAP/UNMAP/MAP_TABLE and DMA translation reuse a table\'s verdict instead of re-scanning its '
                        '2,048 descriptors while nothing published has touched it; counters in report.bin; give it '
                        'to every mode of the attempt')
    p.add_argument('--fast-timer-irq', action='store_true',
                   help='opt-in monitor define SNAP_FAST_TIMER_IRQ (compat/fast-timer-irq.h; fast variant with '
                        '--root-cache-wide and --service-subclass): vCPUs 1-5 handle their EL2 timer tick (the 1 ms IPI '
                        'poll) without the service token, vCPU 0 and every due device, stop or budget keep the locked '
                        'tick; counters in report.bin (tools/perf_counters.py --report); give it to every mode')
    p.add_argument('--fast-ipi', action='store_true',
                   help='opt-in monitor define SNAP_FAST_IPI (docs/FAST-IPI-20261019.md; fast variant with '
                        '--root-cache-wide): the Apple IPI registers (IPI_RR_LOCAL/GLOBAL, IPI_SR) are handled without '
                        'the service token, with atomic posts and acknowledgements; counters in report.bin '
                        '(tools/perf_counters.py --report); give it to every mode of the attempt')
    p.add_argument('--aes-bitslice', action='store_true',
                   help='opt-in monitor define SNAP_AES_BITSLICE (docs/AES-BITSLICE-20261019.md): the PAC key '
                        'derivation\'s software AES runs as a constant-time bitsliced cipher instead of aes_block\'s '
                        'per-byte GF(2^8) inversions, same keys; give it to every mode of the attempt')
    p.add_argument('--guest-net', action='store_true',
                   help='opt-in guest network (docs/GUEST-NETWORK-20261019.md; needs --input): monitor define '
                        'SNAP_GUEST_NET, launch word net (q1n1 POLL2 every 5 ms) and the net AuxKC, whose '
                        'SnapintoshVirtualEthernet attaches a ring; the Mac side is tools/guest-net.py; give it to '
                        'every mode of the attempt')
    p.add_argument('--present-damage', action='store_true',
                   help='opt-in input AuxKC (needs --input; not with --guest-net): INPUT_AUXKC_DAMAGE, the maint '
                        'collection\'s AdrenoX2 with AdrenoDisplay.o rebuilt so the layer-0 present maintains the '
                        'source in one pass with one barrier, reads each row once and writes only rows whose '
                        'signature changed (plus a rolling refresh), and publishes the read/maintenance/write split, '
                        'damage counts, the source cache mode and mapping attribute in AdrenoDisplayStats; give it to '
                        'every mode of the attempt')
    p.add_argument('--present-cached-read', action='store_true',
                   help='opt-in input AuxKC (needs --input; instead of --present-damage, whose present it includes): '
                        'INPUT_AUXKC_CACHED_READ, AdrenoDisplay.o built with -DADRENO_PRESENT_CACHED_READ=1. The '
                        'layer-0 source is mapped with kIOMapCopybackCache, which on 26A428 converts the whole '
                        'write-combined framebuffer object to write-back (every mapping, through SPTM); the kext uses '
                        'it only after proving the conversion global, keeps the per-line CIVAC before every read, and '
                        'counts CachedRead* in AdrenoDisplayStats; give it to every mode of the attempt')
    p.add_argument('--present-gpumap', action='store_true',
                   help='opt-in input AuxKC (needs --input; instead of --present-cached-read, whose present it includes): '
                        'INPUT_AUXKC_GPUMAP (kext batch 8): frame pacing in the perf output (five lines of at most 250 '
                        'bytes, joined by s=), the native GPU VA released before its DART reservation and collisions '
                        'retried elsewhere, and a pool of empty DART reservations so a final free no longer recommits '
                        'every page; residency budget 0; give it to every mode of the attempt')
    p.add_argument('--present-vsync60', action='store_true',
                   help='opt-in input AuxKC (needs --input; instead of --present-gpumap, whose kext it extends): '
                        'INPUT_AUXKC_VSYNC60, the frame tick on an absolute 16,666,667 ns grid (wakeAtTime, armed early '
                        'by the timer coalescing slop; stalls skip grid points, a long idle re-syncs) and a perf vsync '
                        'line with the grid error; give it to every mode of the attempt')
    p.add_argument('--present-dartpool', action='store_true',
                   help='opt-in input AuxKC (needs --input; instead of --present-vsync60, whose kext it extends): '
                        'INPUT_AUXKC_DARTPOOL (kext batch 9): the pool of empty DART reservations keeps the plug-in\'s '
                        '1 MiB UBO staging arenas in a class of their own (256 entries outside the 128 MiB the other '
                        'spans share), so a full pool no longer strict-frees them (v9: 13,257 refusals, 64 page maps '
                        'and one DART UNMAP each); give it to every mode of the attempt')
    p.add_argument('--present-resident', action='store_true',
                   help='opt-in input AuxKC (needs --present-dartpool --input-ptp, whose collection it extends): '
                        'INPUT_AUXKC_PTP_DARTPOOL_RESIDENT, GPU mappings resident across IOGPU\'s unwire within 512 MiB '
                        '(no DART re-insert or clear per command buffer for reused memory) and a perf gpu line; give it '
                        'to every mode of the attempt')
    p.add_argument('--present-beam', action='store_true',
                   help='opt-in tear-free presentation (agents/tear-free; needs --present-resident --present-dartpool '
                        '--input-ptp): INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM (AdrenoDisplay reads the eDP interface\'s '
                        'line counter, ticks on the real vblank and races each copy ahead of the scanout; cursor rows '
                        'without write-combined readback; no redundant source clean) and monitor define '
                        'SNAP_DISPLAY_TIMING (the INTF_5 page read-only at stage 2); give it to every mode of the attempt')
    p.add_argument('--present-va-reclaim', action='store_true',
                   help='opt-in input AuxKC (agents/gpu-va; needs --present-beam --present-resident --present-dartpool '
                        '--input-ptp, whose AdrenoX2 it extends): INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA, the GPU VA '
                        'window reclaims the empty-reservation pool when the DART refuses a reservation (b11v1/b12v4/'
                        'b12v5: "VM exhausted"), frees released reservations through a pinned filler instead of '
                        're-pinning their backing, and prints a perf va line; kext only, no monitor define; give it to '
                        'every mode of the attempt')
    p.add_argument('--gpu-va-wide', action='store_true',
                   help='opt-in GPU VA window [1 GiB, 16 GiB) instead of [1 GiB, 4 GiB) (agents/gpu-va-wide; needs '
                        '--present-va-reclaim and its chain): q1n1 cp-fence/adopt --va-wide (CB0 T0SZ 30), monitor '
                        'define ADRENO_VA_WIDE (tables in a 30.06 MiB monitor reservation), SNAP_ADRENO_VA_WIDE '
                        '(dart-adreno vm-size, GPU node gpu-va-bits) and INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE; '
                        'give it to every mode of the attempt')
    p.add_argument('--gpu-x290', action='store_true',
                   help='opt-in (agents/gpu-x290 X1-X11): q1n1 cp-fence --x290 on every cp-fence step: refuses unless the '
                        'slice fuse reads 0xf (chip id 0x44070041, X2-90) after the TZ GPU init, and adds Linux\'s '
                        'a8xx_set_ubwc_config for glymur (UBWC 5.0, swizzle 2/3 off, highest bank bit 16), which the '
                        'default hw_init skips; the GMEM protect stays 0x15000000; give it to every mode of the attempt')
    p.add_argument('--gpu-x290-survey', action='store_true',
                   help='opt-in (agents/gpu-x290): after the cp-fence steps (and llcc-gpu), the read-only q1n1 '
                        'a16gpu.py x290-survey (slice fuse, chip id, GMEM range and protect, UBWC and clock-gating state); '
                        'writes nothing; give it to every mode of the attempt')
    p.add_argument('--adreno-fill-br', action='store_true',
                   help='opt-in monitor define SNAP_ADRENO_FILL_BR (agents/gpu-x290 F1-F5, turnip-audit item 3): FILL32 '
                        'runs on the BR thread (CP_THREAD_CONTROL(BR | SYNC_THREADS), CP_WAIT_MEM_WRITES before the '
                        'marker, BOTH after) and completes only with RBBM idle; give it to every mode of the attempt')
    p.add_argument('--adreno-fence-br', action='store_true',
                   help='opt-in monitor define SNAP_ADRENO_FENCE_BR (agents/gpu-x290 F7): the monitor and guest fences '
                        'run on the BR thread after CP_WAIT_FOR_IDLE (BOTH after) and complete only with RBBM idle; give '
                        'it to every mode of the attempt')
    p.add_argument('--present-latch', action='store_true',
                   help='opt-in touch-to-photon latency (agents/input-latency; needs --gpu-va-wide and its chain): '
                        'INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH. AdrenoDisplay latches a swap 3 ms before '
                        'row 0 leaves instead of before the vblank, and defers a fresh copy one latch while a GPU '
                        'submission is in the kext. SnapI2CHID polls every 4 ms while touched, timed from the previous '
                        'poll\'s start. The release hold is off by default since b12v11. Kext only; give it to every '
                        'mode of the attempt')
    p.add_argument('--present-latch-us', type=int, default=None,
                   help='with --present-latch: guest boot-arg adreno_latch_us, the slack kept before row 0 (default '
                        '3000; 0 = the beam kext\'s aim before the vblank)')
    p.add_argument('--present-hold', choices=('on', 'off'), default=None,
                   help='with --present-latch: guest boot-arg adreno_hold (default off since b12v11: on completes the swap '
                        'on screen just before the next latch and copies the pending one early; b12v11 showed early '
                        'copies of frames whose IB had not finished)')
    p.add_argument('--present-gate-us', type=int, default=None,
                   help='with --present-latch: guest boot-arg adreno_gate_us, the age under which a layer-0 swap is not '
                        'copied while a GPU submission is in the kext (default 4000; 0 = no gate)')
    p.add_argument('--present-pipeline', type=int, choices=(0, 1, 2), default=None,
                   help='with --present-latch and a pipeline AdrenoX2 (agents/gpu-pipeline): guest boot-arg '
                        'adreno_pipeline: 0 every IB submission returns after the GPU finished it (as before), 1 '
                        'WindowServer\'s return once queued to the GPU (the kext\'s default), 2 every client\'s')
    p.add_argument('--present-pipeline-poll-us', type=int, default=None,
                   help='with --present-latch: guest boot-arg adreno_pipeline_poll_us, the completion timer\'s period '
                        'while an IB is in flight and nobody waits for it (default 500; 50..5000)')
    p.add_argument('--present-hold-margin-us', type=int, default=None,
                   help='with --present-latch: guest boot-arg adreno_hold_margin_us, added to the measured render time '
                        '(default 1500)')
    p.add_argument('--input-active-us', type=int, default=None,
                   help='with --present-latch: guest boot-arg snap_i2c_active_us, the poll period while touched '
                        '(default 4000; 0 = the configured 8 ms throughout)')
    p.add_argument('--hide-amx', action='store_true',
                   help='clear the application AMX-version capability field; preserves kernel AMXIDR '
                        'and does not expose SME; give it to every mode of the attempt')
    p.add_argument('--qcc2072-wifi', action='store_true',
                   help='opt-in QCC2072 Wi-Fi passthrough (probes/qcc2072wifi.py; needs --input): monitor define '
                        'SNAP_QCC2072_WIFI, BAR0/BAR2/read-only ECAM page, the 64 MiB DMA arena at 0xdc000000 and a '
                        'read-only control page at stage 2, the /arm-io/snap-qcc2072 node, the three firmware inputs '
                        'staged at prepare, a live admission at boot (UEFI map, PCIe SMMU stage 2, endpoint in PBL, '
                        'command = memory decode), bus mastering off once the stop is preserved and again at '
                        '--quiesce; give it to every mode of the attempt')
    p.add_argument('--qcc2072-auxkc', metavar='DIR',
                   help='with --qcc2072-wifi: a tools/build-qcc2072-native.py output linked over this route\'s input '
                        'collection (its native-wifi.kc boots instead of that collection)')
    p.add_argument('--qcc2072-auxkc-sha256', metavar='SHA256',
                   help='with --qcc2072-wifi: the expected SHA-256 of DIR/native-wifi.kc')
    p.add_argument('--fast-el0-sysreg', action='store_true',
                   help='opt-in monitor define SNAP_FAST_EL0_SYSREG (fast variant only): EL0 counter-alias and SPRR '
                        'UPERM reads are answered without the service lock; give it to every mode of the attempt')
    p.add_argument('--service-subclass', action='store_true',
                   help='opt-in monitor define SNAP_SERVICE_SUBCLASS: per-sub-class lock hold and exit timing, read '
                        'from report.bin with tools/perf_counters.py --report; give it to every mode of the attempt')
    p.add_argument('--dart-wiredcnt', action='store_true',
                   help='opt-in monitor define SNAP_DART_WIREDCNT (compat/dart-wiredcnt.h): the kext\'s monitor unmap '
                        'also lowers XNU\'s IOMMU-table count, ending the pmap_ref_iommu_table overflow; give it to '
                        'every mode of the attempt')
    p.add_argument('--panic-serve', action='store_true',
                   help='opt-in monitor define SNAP_PANIC_SERVE: after XNU\'s panic entry, ordinary calls are served '
                        'instead of stopping, so the panic string reaches the console; give it to every mode')
    p.add_argument('--root-miss-fast', action='store_true',
                   help='opt-in monitor define SNAP_ROOT_MISS_FAST (compat/root-miss.h): cheaper root-cache misses '
                        'and least-recently-installed eviction; give it to every mode of the attempt')
    p.add_argument('--update-disjoint-fast', action='store_true',
                   help='opt-in monitor define SNAP_UPDATE_DISJOINT_FAST (compat/update-fast.h); give it to every mode')
    p.add_argument('--root-cache-wide', action='store_true',
                   help='opt-in monitor define SNAP_ROOT_CACHE_WIDE (compat/root-wide.h): 192 cached user roots instead '
                        'of 64; give it to every mode of the attempt')
    p.add_argument('--update-check-sparse', action='store_true',
                   help='opt-in monitor define SNAP_UPDATE_CHECK_SPARSE: the user-update kernel-copy check every 1024 '
                        'skips instead of 64 (weaker audit); give it to every mode of the attempt')
    p.add_argument('--kernel-pperm-fast', action='store_true',
                   help='opt-in monitor define SNAP_KERNEL_PPERM_FAST (shadow/sprr-class-fast.h): incremental kernel '
                        'class proof; give it to every mode of the attempt')
    p.add_argument('--ib-budget-1s', action='store_true',
                   help='opt-in monitor define ADRENO_IB_POLL_DIVISOR=1: wait up to 1 s (not 100 ms) for an IB to '
                        'retire before latching the GPU uncertain; give it to every mode of the attempt')
    p.add_argument('--unmap-mixed', action='store_true',
                   help='opt-in monitor define SNAP_UNMAP_MIXED (compat/sptm-user.h): an UNMAP_DISJOINT list with user '
                        'and kernel records runs as one transaction (v39 stop); give it to every mode of the attempt')
    p.add_argument('--txm-aspace-wide', action='store_true',
                   help='opt-in monitor define SNAP_TXM_ASPACE_WIDE (compat/txm.h) with the loader\'s matching 64-page '
                        'arena (SNAP_TXM_ASPACE_WIDE=1): 4096 TXM address spaces instead of 512 (v47 stop); give it '
                        'to every mode of the attempt')
    p.add_argument('--fine-locks', action='store_true',
                   help='opt-in monitor define SNAP_FINE_LOCKS (compat/fine-lock.h, docs/FINE-LOCKS-20261017.md): user '
                        'MAP_PAGE, UNMAP_REGION and UPDATE_DISJOINT under per-root stripes instead of the service '
                        'token (fast variant with --root-cache-wide --update-disjoint-fast --service-subclass); give '
                        'it to every mode of the attempt')
    p.add_argument('--fine-switch', action='store_true',
                   help='with --fine-locks: also SNAP_FINE_SWITCH, SWITCH_ROOT cache hits off the token; give it to '
                        'every mode of the attempt')
    p.add_argument('--fair-token', action='store_true',
                   help='opt-in monitor define SNAP_FAIR_TOKEN (compat/service-lock.h): the service token granted in '
                        'arrival order, needed before vCPUs span clusters; give it to every mode of the attempt')
    p.add_argument('--nest-fast', action='store_true',
                   help='opt-in monitor define SNAP_NEST_FAST (compat/nest-fast.h, docs/TOKEN-COSTS-20261018.md): '
                        'NEST_REGION/UNNEST_REGION answer nested shared tables from the SWITCH_ROOT memo; give it to '
                        'every mode of the attempt')
    p.add_argument('--detach-fast', action='store_true',
                   help='opt-in monitor define SNAP_DETACH_FAST (compat/nest-fast.h): UNMAP_TABLE of an empty level-3 '
                        'table proves both trees empty table by table; give it to every mode of the attempt')
    p.add_argument('--root-index', action='store_true',
                   help='opt-in monitor define SNAP_ROOT_INDEX (compat/root-index.h): TXM35/36/37 and USER_ROOT '
                        'constructors find root records through an index, not a frame-map scan; give it to every mode')
    p.add_argument('--other-profile', action='store_true',
                   help='opt-in monitor define SNAP_OTHER_PROFILE (compat/token-costs.h): the call_other bucket split '
                        'by call (TXM35/36/37, DART map/unmap, ANS, ...); give it to every mode of the attempt')
    p.add_argument('--gate-wait', action='store_true',
                   help='with --fine-locks: SNAP_GATE_WAIT, a converted call waits out a long token hold (up to '
                        '5 ms) instead of declining after 2^16 yields; give it to every mode of the attempt')
    p.add_argument('--fine-hw', action='store_true',
                   help='with --fine-locks and --user-hw-walk: SNAP_FINE_HW (docs/FINE-HW-WALK-20261019.md), MAP_PAGE '
                        'and UNMAP_REGION on hardware-walk roots run as converted calls under the root\'s stripe '
                        'instead of the service token; give it to every mode of the attempt')
    p.add_argument('--fast-pauth-calls', action='store_true',
                   help='with --fine-locks: SNAP_FAST_PAUTH_CALLS, SIGN/AUTH_USER_POINTER and BATCH_SIGN_USER_POINTER '
                        'run as converted calls (this CPU\'s signing state, the gate shared, no stripe) instead of '
                        'under the service token; give it to every mode of the attempt')
    p.add_argument('--native-pacga', action='store_true',
                   help='opt-in monitor define SNAP_NATIVE_PACGA (docs/SPEED-BATCH4-20261020.md): the kernel\'s PACGA '
                        'runs natively under its own GA key (HCR_EL2.API for EL1; kernel address keys stay off, '
                        'processes keep their banks) instead of trapping; give it to every mode of the attempt')
    p.add_argument('--fast-timer-irq-cpu0', action='store_true',
                   help='with --fast-timer-irq: SNAP_FAST_TIMER_IRQ_CPU0, vCPU 0\'s tick without the service token while '
                        'its host poll, thermal sample and GPU tick are not due (a locked tick at least every 8 ms); '
                        'give it to every mode of the attempt')
    p.add_argument('--token-trim', action='store_true',
                   help='with --fine-locks and --fast-pauth-calls: SNAP_TOKEN_TRIM (compat/token-trim.h, batch 5), the '
                        'kernel refresh proves its view reuse from the table memo\'s write witness (sampled exact '
                        'compare) and the Adreno DART\'s MAP/UNMAP run as converted calls under a device lock instead '
                        'of the service token; give it to every mode of the attempt')
    p.add_argument('--pauth-el0-live', action='store_true',
                   help='with --variant fast and --fast-el0-sysreg: SNAP_PAUTH_EL0_LIVE, the lock-free EL0 reads '
                        '(SPRR_UPERM, the ordered counter alias) return to EL0 with the process\'s PAC bank still '
                        'installed instead of a full bank leave and enter; give it to every mode of the attempt')
    p.add_argument('--el0-memo', action='store_true',
                   help='with --pauth-el0-live and --root-cache-wide: SNAP_EL0_MEMO (batch 6, compat/el0-memo.h), the '
                        'lock-free EL0 read answers its instruction fetch from a per-vCPU memo of the PC page\'s '
                        'translation (every descriptor, the frame type and the word re-read and unchanged; stale after '
                        'any root install) without the repeat read, and the user return derives its PAC bank through a '
                        '128-entry second-level cache; give it to every mode of the attempt')
    p.add_argument('--lean-traps', nargs='?', const=1, type=int, choices=(1, 2),
                   help='opt-in monitor define SNAP_LEAN_TRAPS (compat/lean-trap.h; --variant fast with '
                        '--root-cache-wide): 1 (the default value) emulates the adjacent MRS after a lock-free '
                        'ESR/FAR/PMC read in the same trap and makes the lock-free exits cheaper; 2 also uses FEAT_FGT '
                        'instead of HCR_EL2.TVM/TRVM so ESR_EL1/FAR_EL1 reads stop trapping (needs SCR_EL3.FGTEn, '
                        'unrecorded: a refusal shows at prepare, before guest entry); give it to every mode of the attempt')
    p.add_argument('--phase-fair-gate', action='store_true',
                   help='with --fine-locks, --fair-token and --gate-wait: SNAP_PHASE_FAIR_GATE (compat/service-lock.h, '
                        'batch 6), a phase-fair gate: a converted call that finds a token holder waits for that holder '
                        'only, not for the token\'s whole queue, and the holder drains only the converted calls that '
                        'arrived before it; give it to every mode of the attempt')
    p.add_argument('--class-proof-wide', action='store_true',
                   help='opt-in monitor define SNAP_CLASS_PROOF_WIDE (shadow/sprr-view.h): the kernel TPRO class proof '
                        'walks up to the arena\'s 61,440 tables instead of 8,192 (installed-fresh-20261020-v3 stopped at '
                        'the cap); give it to every mode of the attempt')
    p.add_argument('--unnest-4k-fast', action='store_true',
                   help='with --nest-fast: SNAP_UNNEST_4K_FAST (compat/nest-fast.h 3, docs/UNNEST-4K-FAST-20261020.md), '
                        'UNNEST_REGION on 4K user roots (--kernel-user-4k) answers nested shared tables and their leaf '
                        'counts from the SWITCH_ROOT memo instead of checking every leaf (v5: 923,675 calls held the '
                        'token 122.9 s); give it to every mode of the attempt')
    p.add_argument('--fine-switch-hw', action='store_true',
                   help='with --fine-switch and --user-hw-walk: SNAP_FINE_SWITCH_HW (batch 8), a SWITCH_ROOT to a '
                        'hardware-walk root whose record already exists runs as a converted call under the old '
                        'root\'s and the target\'s stripes instead of the service token (v8: 15.6M such switches held '
                        'the token 126.8 s and waited 243.6 s); give it to every mode of the attempt')
    p.add_argument('--dart-converted', action='store_true',
                   help='with --fine-locks and --fast-pauth-calls: SNAP_DART_CONVERTED (batch 9, '
                        'compat/dart-converted.h), the Adreno DART\'s MAP/UNMAP run as converted calls (gate shared, '
                        'a device lock, the SMMU TLB invalidation complete before the call returns) instead of under '
                        'the service token: --token-trim\'s part B on its own (v9: 3.85M maps held the token 49.3 s '
                        'and waited 87.7 s); not with --token-trim; give it to every mode of the attempt')
    p.add_argument('--sptm-fine', action='store_true',
                   help='with --fine-locks, --fine-hw and --user-hw-walk: SNAP_SPTM_FINE (agents/sptm-locks), user '
                        'UNMAP_DISJOINT and UPDATE_REGION and the hardware-walk update events (a replacing MAP_PAGE, '
                        'UPDATE_DISJOINT records on hardware-walk roots) run as converted calls under their roots\' '
                        'stripes instead of the service token; give it to every mode of the attempt')
    p.add_argument('--sptm-fine-retype', action='store_true',
                   help='with --sptm-fine: SNAP_SPTM_FINE_RETYPE, private per-frame locks and RETYPE 11->20, 20->11 '
                        'and 11->11 as converted calls (word-wise zeroing on both paths); give it to every mode')
    p.add_argument('--sptm-fine-kernel', action='store_true',
                   help='with --sptm-fine: SNAP_SPTM_FINE_KERNEL, kernel-root MAP_PAGE and UNMAP_REGION outside every '
                        'kernel-view copy source run as converted calls under one kernel lock, with a by-VA '
                        'invalidation instead of a kernel refresh and TLBI ALLE1IS; give it to every mode')
    p.add_argument('--audit-sparse', action='store_true',
                   help='with --variant fast and --kernel-pperm-fast: SNAP_AUDIT_SPARSE (compat/audit-sparse.h), four '
                        'sampled self-audits under the service token (the TPRO class-proof hit verification, ~7 ms each; '
                        'the kernel refresh, variant swap and PPERM-reuse skip verifications) run 1 in 1024 events '
                        'instead of 1 in 64 (neon-v2: about 58 s of 264.6 s token hold); a weaker audit, the audited '
                        'mechanisms unchanged; give it to every mode of the attempt')
    p.add_argument('--reuse-match-mapped', action='store_true',
                   help='SNAP_REUSE_MATCH_MAPPED (shadow/sprr-reuse.h): the kernel refresh\'s exact reuse proof reads '
                        'each copied source table through one bounded page mapping instead of one callback per word '
                        '(same verdicts; neon-v2: 797,113 proofs in 41.1 s of token hold); not with --token-trim; give '
                        'it to every mode of the attempt')
    p.add_argument('--el0-wfe', action='store_true',
                   help='SNAP_EL0_WFE: SCTLR_EL1.nTWE as 26A428\'s SPTM installs it, so EL0 WFE no longer traps to '
                        'EL1, where XNU\'s handle_wf_trap raises SIGILL (launchd\'s death in libdispatch '
                        '_dispatch_wait_for_enqueuer: v41, v88, v16, desktop-v1); give it to every mode of the attempt')
    p.add_argument('--el0-cache-maint', action='store_true',
                   help='SNAP_EL0_CACHE_MAINT: SCTLR_EL1.UCI as SPTM installs it, so EL0 DC CVAU/CVAC/CIVAC and IC IVAU '
                        '(sys_icache_invalidate) no longer trap to EL1, where handle_msr_trap raises SIGILL; give it to '
                        'every mode of the attempt')
    p.add_argument('--present-maint', action='store_true',
                   help='guest boot-arg adreno_present_maint=1: AdrenoDisplay keeps its layer-0 clean+invalidate pass '
                        'even while the beam is LOCKED (tear-free fix2 skips it then); for b12v8\'s stale bands; '
                        'give it to every mode of the attempt')
    p.add_argument('--spmi-scratch', action='store_true',
                   help='SNAP_SPMI_SCRATCH: the emulated SPMI controller also serves the PMU scratch-pad registers '
                        '(f700-f7ff, 8f80-8fff) from RAM, so AppleDialogSPMIPMU::_readRegs stops failing with e00002bc '
                        'and flooding the console with parity errors (agents/cache-maint/spmi); give it to every mode')
    p.add_argument('--user-crash-wide', action='store_true',
                   help='SNAP_USER_CRASH_WIDE: the EL0 crash ring also records WFI/WFE, MSR/MRS/SYS, SIMD, SVE, SME, '
                        'BTI, PAC-trap and FP-exception entries (XNU turns each into SIGILL, SIGFPE or a panic), with '
                        'the faulting instruction word; give it to every mode of the attempt')
    p.add_argument('--ib-async', action='store_true',
                   help='SNAP_ADRENO_IB_ASYNC (compat/adreno-ib.h): ADRENO_GUEST_IB_START/_POLL, so an IB\'s GPU '
                        'execution no longer holds the global service token (v14: 613 s of 1,800 s; 68-190 ms '
                        'stalls); a kext built with ADRENO_IB_ASYNC finds them by IB_POLL(0) and uses them, any other '
                        'kext keeps the synchronous IB; counters in report.bin (IBASYNC1); give it to every mode of '
                        'the attempt')
    p.add_argument('--gpu-recover', choices=('soft', 'reset'),
                   help='with --ib-async, opt-in (agents/gpu-recovery): SNAP_ADRENO_RECOVER. soft (1): the IB budget '
                        'becomes soft (counted overdue, ended early only on hang evidence) up to a hard limit '
                        '(--ib-hard-seconds, default 3 s), and ADRENO_GUEST_RECOVER lets a kext built with '
                        'ADRENO_GPU_RECOVER un-latch once the GPU is proven idle; reset (2): also the CP soft reset at '
                        'EL2 for a hung, faulted or error-retired IB (RBBM_SW_RESET_CMD and q1n1\'s replayed hw_init, '
                        'compat/adreno-recover-table.h, which must match the cp-fence steps); counters in IBASYNC1, '
                        'EV_GPU_RECOVER per attempt; give it to every mode of the attempt')
    p.add_argument('--ib-hard-seconds', type=int, choices=range(1, 5), metavar='1..4',
                   help='with --gpu-recover: the hard IB limit in seconds (ADRENO_IB_HARD_SECONDS, default 3; IOGPU '
                        'waits 5 s for the GPU); give it to every mode of the attempt')
    p.add_argument('--nvme-async', action='store_true',
                   help='with --root-cache-wide: SNAP_ANS_ASYNC (agents/nvme-async), the virtual ANS2 queues each SSD '
                        'command at its doorbell and reaps it without waiting, at later ANS accesses and at the owning '
                        'vCPU\'s EL2 deadline, instead of busy-polling the SSD under the service token (b12v5: 207k '
                        'commands, 36.8 s of hold); counters in the ANS state\'s async block; give it to every mode')
    p.add_argument('--nvme-converted', action='store_true',
                   help='with --nvme-async and --fine-locks: SNAP_ANS_CONVERTED, the I/O SQ/CQ doorbells and table-6 '
                        'MAP/UNMAP_PAGES run as converted calls under an ANS device lock (fine profile ans_mmio, '
                        'ans_sptm); give it to every mode of the attempt')
    p.add_argument('--attr-clean-defer', action='store_true',
                   help='with --root-cache-wide: SNAP_ATTR_CLEAN_DEFER, the second cache clean of an attribute change '
                        '(attr_clean_finish) runs after the token is released, before the calling vCPU resumes '
                        '(UPDATE_DISJOINT_MULTIPAGE held the token up to 82.5 ms); give it to every mode of the attempt')
    p.add_argument('--multipage-fast', action='store_true',
                   help='with --attr-clean-defer and --root-cache-wide: SNAP_MULTIPAGE_FAST (agents/sptm-locks/'
                        'multipage), UPDATE_DISJOINT_MULTIPAGE\'s aperture steps cleaned before the token is taken, '
                        'kernel-view copy words patched instead of a full view re-sync per frame, and one '
                        'publication, refresh and TLBI per run of headers (b12v16: 14,880 calls held the token 7.79 ms '
                        'each); give it to every mode of the attempt')
    p.add_argument('--let-panic', action='store_true',
                   help='SNAP_LET_PANIC: XNU\'s own EL1 exceptions (its panic debugger trap) resume into its handler '
                        'instead of stopping the run, so the panic text reaches the console; give it to every mode')
    p.add_argument('--thermal-guard', action='store_true',
                   help='SNAP_EARLY_STOP gains thermal (docs/A16-THERMAL-GUARD-20261018.md): the monitor samples the A16 TSENS '
                        'sensors every 250 ms and stops the run at 60 C, on invalid sensors or missed polls; give it to every '
                        'mode of the attempt')
    p.add_argument('--gpu-opp-mhz', type=int, choices=[915],
                   help='installed-fresh: the GPU\'s hfi step lists OPPs up to this clock and votes for it (915: RPMh NOM, '
                        '16.5 GB/s; the user approved this mid OPP on 2026-10-19) instead of the lowest (310 MHz); '
                        'give it to every mode of the attempt')
    p.add_argument('--gpu-dvfs', action='store_true',
                   help='installed-fresh, opt-in (agents/dvfs): SNAP_GPU_DVFS, the monitor votes the GPU between 310 MHz '
                        'and --gpu-dvfs-ceiling (default 1700 MHz, the highest OPP every A16 rail can carry): the '
                        'ceiling before the doorbell of the first IB of a burst, held 1.5 s after the last GPU '
                        'activity, clamped from 75 C on the non-CPU sensors and from 88 C on the hottest; the hfi step '
                        'lists the OPPs up to the ceiling and starts at 310 MHz; needs --thermal-guard and '
                        '--root-cache-wide; not with --gpu-opp-mhz; give it to every mode of the attempt')
    p.add_argument('--gpu-dvfs-ceiling', type=int, metavar='MHZ',
                   help='with --gpu-dvfs: the highest GPU OPP in the hfi step\'s table (310, 410, 572, 760, 820, 915, '
                        '1070, 1185, 1350, 1550 or 1700; default 1700). Changes only the hfi step\'s --max-opps: the '
                        'monitor image is the same for every ceiling. 1850 is refused (no MX corner on the A16); give '
                        'it to every mode of the attempt')
    p.add_argument('--gpu-dvfs-hold', type=int, metavar='MS',
                   help='with --gpu-dvfs: hold the ceiling this long after the last GPU activity (300..5000, default '
                        '1500; SNAP_GPU_DVFS_HOLD_MS); give it to every mode of the attempt')
    p.add_argument('--gpu-dvfs-defer', action='store_true',
                   help='with --gpu-dvfs: never vote while an async IB is in flight (SNAP_GPU_DVFS_MIDFLIGHT=0, the '
                        'b12v4 rule); the fallback if mid-flight votes misbehave; give it to every mode of the attempt')
    p.add_argument('--cpu-dvfs', action='store_true',
                   help='installed-fresh, opt-in (agents/dvfs): SNAP_CPU_DVFS, the monitor sets the SCMI performance '
                        'level of each CPU cluster that runs vCPUs, from busy samples of its EL2 tick: floor = the '
                        'firmware\'s boot level, ceiling = the highest non-boost level, a thermal clamp from 75 C, '
                        'restored at the stop; needs --thermal-guard, --root-cache-wide and --wfi-resume; give it to '
                        'every mode of the attempt')
    p.add_argument('--cpu-dvfs-ceiling', type=int, metavar='LEVEL',
                   help='with --cpu-dvfs: a lower hard ceiling (SCMI level index 1..19; PDP1/2 19 = 4.454 GHz, 17 = '
                        '4.128 GHz); give it to every mode of the attempt')
    p.add_argument('--ddr-vote', action='store_true',
                   help='installed-fresh, opt-in (agents/dvfs): before the GPU steps, q1n1 a16gpu.py ddr-vote holds DDR '
                        'and the interconnect at the BCM maximum from apps drv-2 (SH0/MC0 0x3fff, SH1/ACV on); quiesce '
                        'sends the explicit restore vote; give it to every mode of the attempt')
    p.add_argument('--llcc', action='store_true',
                   help='installed-fresh, opt-in (agents/dvfs): before the GPU steps, q1n1 a16gpu.py llcc-activate '
                        'configures and activates the LLCC slices CPUSS, GPU and GPUHTW (llcc-qcom.c on glymur; all '
                        'three read deactivated after UEFI); after cp-fence llcc-gpu points the GPU\'s traffic at the GPU '
                        'slice; quiesce deactivates them; give it to every mode of the attempt')
    p.add_argument('--llcc-table', choices=('linux', 'windows'),
                   help='with --llcc: the slice values (default linux: glymur_data; windows: the A16 Windows driver '
                        'table for its bank count); give it to every mode of the attempt')
    p.add_argument('--bw-probe', action='store_true',
                   help='with --ddr-vote and/or --llcc: tools/measure-a16-memory-bandwidth.py on q1n1\'s boot CPU before '
                        'and after each (build/PREFIX/bw-before.json, bw-after.json, bw-after-llcc.json; 64 MiB streams '
                        'and an 8/16/32 MiB chase sweep); give it to every mode of the attempt')
    p.add_argument('--zone-log', metavar='ZONE',
                   help='XNU zone corruption logging for one zone (boot-arg zlog1=ZONE): a use-after-free panic in it '
                        'then prints the allocation and free backtraces; give it to every mode of the attempt')
    p.add_argument('--zone-log-records', type=int, metavar='N',
                   help='with --zone-log: records kept (boot-arg zrecs=N); give it to every mode of the attempt')
    p.add_argument('--early-stop-delay', type=int, metavar='SECONDS',
                   help='seconds from the kext\'s first-present or plug-in-failure stop request to the stop (default '
                        '600); below the 1800 s watchdog; give it to every mode of the attempt')
    p.add_argument('--prime-secondaries', action='store_true',
                   help='opt-in: run all six vCPUs on Prime cluster 1 (SNAP_SMP_PRIME=1 and monitor define '
                        'SNAP_BOOT_RELOCATE: vCPU 0 moves off q1n1\'s cluster-0 CPU) instead of the lower-power '
                        'cluster 0; give it to every mode of the attempt')
    p.add_argument('--kernel-sysreg-zero', action='store_true',
                   help='opt-in kernel patch (probes/sysregzero.py): the system-register reads the monitor answers with '
                        '0 become MOVZ #0 and its dropped writes NOP; give it to every mode of the attempt')
    p.add_argument('--kernel-user-4k', action='store_true',
                   help='opt-in kernel patch (probes/user4k.py): every user pmap is created 4K (SPTM format 1), '
                        'as Apple\'s psa_4k spawn switch does, and 4K maps stay off VM guard objects (their slab '
                        'index underflows in a 4K map: v56/v58); with --user-hw-walk the hardware walks XNU\'s own '
                        'user tables; give it to every mode of the attempt')
    p.add_argument('--user-hw-walk', action='store_true',
                   help='opt-in monitor define SNAP_USER_HW_WALK (compat/user-hw-walk.h): 4K user roots run on XNU\'s '
                        'own tables (TPRO through monitor copies), page-table frames read-only at stage 2; 16K roots '
                        'keep the shadow path; give it to every mode of the attempt')
    p.add_argument('--idreg-mmfr3', action='store_true',
                   help='opt-in monitor define SNAP_IDREG_MMFR3: every vCPU records ID_AA64MMFR3/MMFR1 (S1PIE, S1POE) '
                        'at setup; give it to every mode of the attempt')
    p.add_argument('--s2-fault-retry', action='store_true',
                   help='opt-in monitor define SNAP_S2_FAULT_RETRY (compat/s2-fault-retry.h): a guest stage-2 '
                        'translation fault whose hardware IPA (HPFAR) is guest RAM the CPU\'s own tree maps is '
                        'snapshotted (HPFAR, VTTBR/VTCR/HCR, both walks; tools/s2-retry-dump.py) and retried instead of '
                        'stopping, bounded (the same access 3 times in a row or over 1000 a second per vCPU stops); '
                        'every stage-2 stop prints HPFAR\'s IPA; give it to every mode of the attempt')
    p.add_argument('--s2-fault-retry-stage1', action='store_true',
                   help='opt-in monitor define SNAP_S2_FAULT_RETRY_STAGE1, with --s2-fault-retry: also retry a fault '
                        'whose HPFAR IPA is not mapped but whose stage-1 re-walk\'s is (a stale stage-1 translation, '
                        'which may already have written the wrong page); without it that case stops; give it to every '
                        'mode of the attempt')
    p.add_argument('--kernel-refmod-skip', action='store_true',
                   help='opt-in kernel patch (probes/refmodskip.py): XNU\'s NOFLUSH page-aging reference clears '
                        '(vm_page_balance_inactive, vm_fault_deactivate_behind) become NOP, removing their SPTM '
                        'UPDATE_DISJOINT calls and the Access flag faults that follow; give it to every mode of the attempt')
    p.add_argument('--after-quiesce', metavar='PREFIX',
                   help='boot: the GPU was prepared and gracefully quiesced by PREFIX in this boot; admit a second '
                        'cycle instead of requiring a cold boot (PREFIX captures and quiesce are re-verified)')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--boot', action='store_true')
    mode.add_argument('--quiesce', action='store_true', help='after preservation: graceful GPU quiesce')

    p = sub.add_parser('storage', help='read persistence / snapshot the SSD at an idle generation')
    p.add_argument('--prefix', required=True, help='the retired run whose SSD state is read')
    p.add_argument('mode', choices=['persistence', 'snapshot'])
    p.add_argument('--out', help='snapshot directory (default build/PREFIX-snapshot-v1)')
    p.add_argument('--package', help='SSD package.json when it is not the delta-v1 beside the launch image')
    p.add_argument('--check', action='store_true')

    sub.add_parser('next', help='print the exact next command for the current records')

    p = sub.add_parser('observe', help=argparse.SUPPRESS)
    p.add_argument('kind', choices=['collector', 'ring', 'native', 'crash'])
    p.add_argument('--launch', required=True)
    p.add_argument('--candidate')
    p.add_argument('--replace')

    p = sub.add_parser('substituted', help=argparse.SUPPRESS)
    p.add_argument('--launch', required=True)
    p.add_argument('--replace', required=True)

    argv = list(sys.argv[1:] if argv is None else argv)
    rest = []
    if '--' in argv:   # observe KIND --launch P -- <the observer's own arguments>
        rest = argv[argv.index('--') + 1:]
        argv = argv[:argv.index('--')]
    args = ap.parse_args(argv)
    args.rest = rest
    return args


def main(argv=None):
    args = parse(argv)
    ws = Workspace(Path(__file__).resolve().parents[1])
    try:
        if args.command == 'preserve':
            from cycle_lib import preserve
            emit(preserve.preserve(ws, args.prefix, args.check, args.capture_set, args.document,
                                   args.candidate and str(Path(args.candidate).resolve()), args.unqualified))
        elif args.command == 'retire':
            from cycle_lib import retire
            stages = None
            if args.stages_from:
                from cycle_lib import launch
                stages = launch.Manifest(ws, args.stages_from).stages
            idle = None
            if args.idle:
                if not (args.after_retirement and args.retirement_sha256):
                    raise Refused('--idle needs --after-retirement and --retirement-sha256')
                idle = dict(after_retirement=str(Path(args.after_retirement).resolve()),
                            retirement_sha256=args.retirement_sha256)
            emit(retire.retire(ws, args.prefix, args.preservation_sha256, args.check, stages, idle, args.bind,
                               args.loader_failure))
        elif args.command == 'capture':
            from cycle_lib import capture
            return capture.main(ws, args)
        elif args.command == 'launch':
            from cycle_lib import launch
            return launch.main(ws, args)
        elif args.command == 'bootstrap-smoke':
            from cycle_lib import bootstrap_smoke
            return bootstrap_smoke.main(ws, args)
        elif args.command == 'speed-test':
            from cycle_lib import speed_test
            return speed_test.main(ws, args)
        elif args.command == 'installed-fresh':
            from cycle_lib import installed_fresh
            return installed_fresh.main(ws, args)
        elif args.command == 'status':
            from cycle_lib import status
            res = status.status(ws, args.check, args.battery_minimum)
            if getattr(args, 'pretty', False):
                render_pretty_status(res)
            else:
                emit(res)
        elif args.command == 'dashboard':
            render_dashboard(ws, args.no_color)
            return 0
        elif args.command == 'init-pins':
            pins_path = ws.root / 'tools/cycle_lib/pins.json'
            example_path = ws.root / 'tools/cycle_lib/pins.example.json'
            if pins_path.exists() and not args.force:
                print(f"pins.json already exists at {pins_path}. Use --force to overwrite.", flush=True)
                return 0
            pins_path.write_bytes(example_path.read_bytes())
            print(f"✓ Initialized {pins_path} from pins.example.json. Set device UDP interface for your machine.", flush=True)
            return 0
        elif args.command == 'next':
            from cycle_lib import status
            print(status.next_step(ws), flush=True)
        elif args.command == 'storage':
            from cycle_lib import storage
            return storage.main(ws, args)
        elif args.command == 'observe':
            from cycle_lib import observers
            return observers.observe(ws, args)
        elif args.command == 'substituted':
            from cycle_lib import substitute
            return substitute.run_step(ws, args)
    except Refused as refusal:
        print(json.dumps(dict(status='REFUSED', command=args.command, reason=str(refusal))), flush=True)
        return 1
    except Exception as error:  # any other failure also stops before the next step
        traceback.print_exc()
        print(json.dumps(dict(status='REFUSED', command=args.command, reason=f'{type(error).__name__}: {error}')),
              flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
