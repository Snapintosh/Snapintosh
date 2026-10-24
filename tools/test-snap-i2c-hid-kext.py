#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SnapI2CHID, offline: the real kext build, its ABI against the J700 kernel, and its host tests.

    python3 tools/test-snap-i2c-hid-kext.py                  # builds drivers/snap-i2c-hid in a temp dir
    python3 tools/test-snap-i2c-hid-kext.py --kext K.kext    # checks an already built bundle (an asset)

No hardware. docs/A16-INPUT-INSTALLED-20261017.md. Checks, in order:

 1. Bundle: arm64e MH_KEXT_BUNDLE, `_kmod_info`, ad hoc signature verifies strictly, and the one
    personality (SnapI2CHIDBus on AppleARMIODevice, IONameMatch snapintosh,geni-i2c-hid) with no
    OSBundleRequireExplicitLoad in the source plist (the AuxKC autoload step owns that flag).
 2. Imports: every undefined symbol is exported by a library the plist declares, read from the
    26A428 KDK (the com.apple.kpi.* symbol sets and IOHIDFamily's arm64e slice, UUID
    CFD459AA, the J700 kernel collection's). A private-KPI symbol (thread_call_cancel_wait, which
    kmutil refused on 2026-10-17) fails here first.
 3. ABI: SnapI2CHIDDevice's vtable against the KDK's __ZTV11IOHIDDevice, slot by slot by method
    name; only the driver's own overrides differ, and IOHIDDevice's one pure virtual
    (newReportDescriptor) is overridden.
 4. No CNTFRQ_EL0 access (probes/clockcontract.py: the guest counter is scaled).
 5. Source contract: every register offset lies in the first 4 KiB page, the page the monitor
    maps (compat/i2c-input.h); the only registers written are the tools' set.
 6. The transport and state machine (tools/test-snap-i2c-hid.c, ASan/UBSan) on the fixture,
    whose bytes are checked against the digests the evidence documents recorded (the evidence
    JSON files themselves were lost in the 2026-09-30 cleanup).
 7. The IOKit glue (tools/test-snap-i2c-hid-start.cpp): the real SnapI2CHID.cpp against host
    stand-ins and a GENI model behind its MMIO hook, one process per failure scenario (including a
    previous run's leftover controller after a panic and a chainload, v39, and the Precision
    Touchpad switch behind its feature hook, docs/A16-INPUT-PTP-20261020.md), then mutations of the
    driver that must fail it.
 8. With -DSNAP_I2C_HID_LATENCY=1: every scenario, the latency ones, and their mutations.
 9. With -DSNAP_I2C_HID_FNKEYS=1 (the keyboard's Fn-key layer, hid-keyboard.h): the transport test
    with its Fn-key groups, mutations of hid-keyboard.c it must catch, every glue scenario plus the
    Fn-key ones (alone and with SNAP_I2C_HID_LATENCY, the desktop-fnkeys profile's pair), and
    mutations of the glue.
"""
from pathlib import Path
import argparse
import hashlib
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'drivers/snap-i2c-hid'
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions')
HID_UUID = 'CFD459AA-995B-3198-B76A-FFC8AC5D00FB'
KPI = {'com.apple.kpi.mach': 'Mach', 'com.apple.kpi.iokit': 'IOKit',
       'com.apple.kpi.libkern': 'Libkern', 'com.apple.kpi.bsd': 'BSDKernel',
       'com.apple.kpi.unsupported': 'Unsupported'}
OVERRIDES = {'D1Ev', 'D0Ev', '12getMetaClassEv', '4freeEv', '11handleStartEP9IOService',
             '18newTransportStringEv', '16newProductStringEv', '17newVendorIDNumberEv',
             '18newProductIDNumberEv', '16newVersionNumberEv',
             '19newReportDescriptorEPP18IOMemoryDescriptor',
             '9getReportEP18IOMemoryDescriptor15IOHIDReportTypej',
             '9setReportEP18IOMemoryDescriptor15IOHIDReportTypej',
             '19newLocationIDNumberEv', '23newReportIntervalNumberEv',
             # Y1: an event driver opening or closing the device (installed-fresh-desktop-20261021-v2).
             '10handleOpenEP9IOServicejPv', '11handleCloseEP9IOServicej'}
# The multitouch device (hid-mt2.c): IOHIDDevice's identity and report methods, the manufacturer string, no open hooks.
MT_OVERRIDES = (OVERRIDES - {'10handleOpenEP9IOServicejPv', '11handleCloseEP9IOServicej'}) | {'21newManufacturerStringEv'}
# docs/A16-INPUT-DRIVER-20260928.md and docs/A16-HID-REPORT-DESCRIPTOR-20260928.md.
HID_DESCRIPTOR_HEX = '1e00000190000200030040000400200005000600050b424b000000000000'
REPORT_SHA = '0887190d374bd8f4ff9e5278af8e7831fc149714b1f681860cc87a9c27cbaacb'
GET_REPORT_54_HEX = '0000360000000000000000'
TPAD_DESCRIPTOR_HEX = '1e000001fc02020003003400040042000500060008281902010500000000'
TPAD_REPORT_SHA = '9be79d75e9bdca087d2d01a6d34fff00d74ac6eeda7110e5dfff0198002b6789'
WRITABLE = {'GENI_I2C_TX_TRANS_LEN', 'GENI_I2C_RX_TRANS_LEN', 'GENI_M_CMD0', 'GENI_M_CMD_CTRL',
            'GENI_M_IRQ_EN', 'GENI_M_IRQ_CLEAR', 'GENI_TX_FIFO'}
SCENARIOS = ('no-address', 'bad-address', 'no-descriptor-register', 'no-window', 'short-window',
             'unaligned-window', 'config-refused', 'busy-refused', 'fifo-refused', 'error-refused',
             'never-completes', 'wedged-no-mmio', 'own-idle-leftover', 'own-error-leftover',
             'own-mid-transaction', 'own-hung-cancel', 'own-hung-abort', 'own-stuck', 'own-tx-leftover',
             'hid-diagnostics', 'keyboard-service', 'pointer-service', 'ptp-service', 'ptp-publish-armed',
             'ptp-publish-unverified', 'ptp-publish-refused', 'ptp-publish-readback', 'ptp-reinit', 'keyboard-no-ptp',
             'yield-open-close', 'mt-handover', 'mt-other-driver', 'mt-requests', 'latency-waits')
# agents/input-latency FAILURE-MODES.md T1-T4, with -DSNAP_I2C_HID_LATENCY=1 only (test_8_latency).
LATENCY_SCENARIOS = ('latency-bootarg', 'latency-active', 'latency-slow-transfer', 'latency-slop')
LATENCY_MUTATIONS = (
    ('schedule from the end of the step', 'uint64_t base = fDeadlineUs ? fDeadlineUs : startUs;', 'uint64_t base = now;'),
    ('no gap after a long step', '        next = now + gap;                                  /* T2 */', '        (void)gap;'),
    ('round the wire time up', '        IOSleep(us / 1000u);\n    if (us % 1000u)\n        IODelay(us % 1000u);',
     '        IOSleep((us + 999u) / 1000u);\n    else if (us % 1000u)\n        IODelay(us % 1000u);'),
    ('stay active forever', 'now - fLastReportUs < SNAP_I2C_HID_ACTIVE_HOLD_US', 'now - fLastReportUs < ~0ull'),
    ('never become active', 'fLastReportUs = now ? now : 1;', '(void)0;'),
    ('an uncapped lead', '    if (lead > cap)\n        lead = cap;                                        /* T3 */', '    (void)cap;'),
    ('ignore the boot-arg', '(void)PE_parse_boot_argn("snap_i2c_active_us", &active, sizeof(active));', '(void)0;'),
)
# The keyboard's Fn-key layer, with -DSNAP_I2C_HID_FNKEYS=1 only (test_9_fnkeys).
FNKEYS_FLAG = '-DSNAP_I2C_HID_FNKEYS=1'
FNKEYS_SCENARIOS = ('fnkeys-off', 'fnkeys-translate', 'fnkeys-raw-log', 'fnkeys-yield', 'fnkeys-host-lock',
                    'fnkeys-bootarg', 'fnkeys-rejected')
# (description, old, new) in src/hid-keyboard.c: each must fail tools/test-snap-i2c-hid.c's Fn-key groups.
FNKEYS_C_MUTATIONS = (
    ('swap brightness up and down', '*usage = up ? 0x0004u : 0x0005u;', '*usage = up ? 0x0005u : 0x0004u;'),
    ('pass report 55\'s brightness through', 'if (page == HID_KBD_PAGE_CONSUMER && frow[i].consumer == usage)', 'if (0)'),
    ('map microphone mute to System Speaker Mute', '0x00a9},        /* F10', '0x00a7},        /* F10'),
    ('release as the mapping now, not as pressed',
     '    *op = h->out_page;\n    *ou = h->out_usage;\n    memset(h, 0, sizeof(*h));',
     '    memset(h, 0, sizeof(*h));\n    remap(c->fn, page, usage, op, ou);'),
    ('raw-log every key', '#define BAND_FIRST      0x3au', '#define BAND_FIRST      0x04u'),
    ('take any modifier for a chord', '#define MODS_GUI        0x88u', '#define MODS_GUI        0xffu'),
    ('take 0xFF for a code', 'r[1 + i] && r[1 + i] != 0xffu &&', 'r[1 + i] &&'),
    ('flip the lock without HID_FNKEYS_HOST_LOCK', 'if (v == VENDOR_FN_ESC && (fn->flags & HID_FNKEYS_HOST_LOCK)) {',
     'if (v == VENDOR_FN_ESC) {'),
    ('flip the lock again while Fn+Esc is held', '        if (contains(fn->vendor, HID_FNKEYS_VENDOR_SLOTS, v))\n            continue;',
     '        if (contains(fn->vendor, HID_FNKEYS_VENDOR_SLOTS, v) && v != VENDOR_FN_ESC)\n            continue;'),
    ('accept report 90 at any length', 'if (len != HID_KBD_VENDOR_BYTES) {', 'if (len < 2u) {'),
    ('translate without HID_FNKEYS_TRANSLATE', '    if (!translate)\n        return;\n    if (page == HID_KBD_PAGE_KEYBOARD)',
     '    if (page == HID_KBD_PAGE_KEYBOARD)'),
    ('dispatch reports 54 and 55 while yielded',
     '    if (fn->yielded)\n        return result == HID_KBD_EVENTS ? HID_KBD_IGNORED : result;\n', ''),
    ('never drop a raw-log line', 'if (!rate->tokens || rate->lines >= HID_FNKEYS_RATE_LIFETIME) {', 'if (0) {'),
    ('no lifetime cap', 'if (!rate->tokens || rate->lines >= HID_FNKEYS_RATE_LIFETIME) {', 'if (!rate->tokens) {'),
    ('accept unknown flags', 'if (flags & ~HID_FNKEYS_KNOWN)\n        return HID_FNKEYS_REFUSED_BITS;', ''),
)
# (description, old, new) in SnapI2CHID.cpp's unit: each must fail one of FNKEYS_SCENARIOS.
FNKEYS_MUTATIONS = (
    ('on without the boot-arg', 'hid_fnkeys_init(&fFn, given ? flags : 0u);', 'hid_fnkeys_init(&fFn, given ? flags : 1u);'),
    ('drop report 90 while yielded',
     '            (void)hid_fnkeys_translate(&fFn, &fState, report, len, emit, this, note, this);', '            (void)0;'),
    ('keep dispatching reports 54 and 55 after yielding', '        fFn.yielded = 1;', '        (void)0;'),
    ('release held hotkeys raw when yielding', '        hid_fnkeys_release_keyboard(&fFn, &fState, emit, this);',
     '        hid_kbd_release_all(&fState, emit, this);'),
    ('stop without releasing report 90', '        hid_fnkeys_release_all(&fFn, &fState, emit, this);',
     '        hid_kbd_release_all(&fState, emit, this);'),
    ('log past the rate limit', '    if (!hid_fnkeys_rate_allow(&fRate, uptimeUs(now)))\n        return false;',
     '    (void)hid_fnkeys_rate_allow(&fRate, uptimeUs(now));'),
    ('never name refused inputs', '        fKeyboard->noteRejected(fDev->rejected, fDev->rejected_len);', '        (void)0;'),
    ('show a refused keyboard report\'s bytes', '    if (input[2] == HID_KBD_REPORT_KEYS) {', '    if (0) {'),
    ('name refused inputs without the raw log', '    if (!rawLog() || len < 3u || !mayLog())', '    if (len < 3u || !mayLog())'),
)
STANDIN_HEADERS = ('IOKit/IOBufferMemoryDescriptor.h', 'IOKit/IOCommandGate.h', 'IOKit/IOLib.h',
                   'IOKit/IOService.h', 'IOKit/IOTimerEventSource.h', 'IOKit/IOWorkLoop.h',
                   'IOKit/hid/IOHIDDevice.h', 'IOKit/hid/IOHIDDeviceKeys.h', 'IOKit/hid/IOHIDKeys.h',
                   'kern/clock.h', 'kern/thread_call.h', 'libkern/c++/OSData.h', 'IOKit/hidevent/IOHIDEventService.h',
                   'IOKit/IOUserClient.h', 'pexpert/pexpert.h')
# (description, old, new): each turns a refusal into acceptance; the harness must catch every one.
MUTATIONS = (
    ('accept an unaligned window', '(fRegs->getPhysicalAddress() & (GENI_WINDOW_BYTES - 1))', '0'),
    ('accept a short window', 'fRegs->getLength() < GENI_WINDOW_BYTES ||', ''),
    ('accept a node without an address', '!readU32("snapintosh,hid-address", &address) ||', ''),
    ('ignore a refused controller', 'if (r != GENI_I2C_OK) {\n        /* The registers', 'if (0) {\n        /* The registers'),
    ('keep polling after a failure', 'if (fStopping || !fDev)\n        return;',
     'if (fStopping || !fDev)\n        return;\n    fTimer->setTimeoutUS(8000);'),
    ('enable the engine interrupt', '(void)readU32("snapintosh,irq-policy", &fPolicy);', 'fPolicy = 0;'),
    # docs/A16-INPUT-PTP-20261020.md: F1/F2/F16 (a refused switch must leave mouse mode) and F10.
    ('arm touchpad mode after a refused switch',
     'fPtpArmed = setup.result == HID_PTP_ENABLED || setup.result == HID_PTP_ENABLED_UNVERIFIED;', 'fPtpArmed = true;'),
    ('never re-apply the switch after a re-initialisation',
     'reinit = fDev->stats.reinits != fPtpReinits;', 'reinit = false;'),
    ('never re-apply the switch after mouse-mode reports', 'fBus->fPtpReapply = true;', '(void)0;'),
    ('give the trackpad identity in mouse mode', '    if (ptp)\n        addTrackpadScrollIdentity(props);',
     '    addTrackpadScrollIdentity(props);'),
    ('send report 4 to the mouse path', 'if (fPtpArmed && report[0] == fEngine.l.report_id) {', 'if (0) {'),
    # Y1-Y5 (installed-fresh-desktop-20261021-v2: the touchpad yielded to DriverKit's generic driver).
    ('publish the raw device of an armed touchpad', 'if (ptp) {\n        hid = nullptr;', 'if (0) {\n        hid = nullptr;'),
    ('let user clients take the device', 'if (ok && client && !OSDynamicCast(IOUserClient, client))',
     'if (ok && client)'),
    ('never give the device back', '        if (fKeyboard)\n            fKeyboard->resume();', ''),
    ('count a second open of one client', '        return;                                          /* already held',
     '        if (open) continue;\n        return;                                          /* already held'),
    # M1-M4, M14 (the gestures agent's FAILURE-MODES.md): the multitouch device and the handover.
    ('hand over without a frames consumer', 'fPointer->handover((bits & SnapI2CHIDMultitouch::kStackConsumer) != 0);',
     'fPointer->handover((bits & SnapI2CHIDMultitouch::kStackDevice) != 0);'),
    ('take any driver for Apple\'s', 'if (strncmp(driver->getMetaClass()->getClassName(), "AppleMultitouch", 15) != 0) {',
     'if (0) {'),
    ('never send the empty frame', '        fMT->kick();\n', ''),
    ('leave the reply buffer\'s length', '        if (b)\n            b->setLength(n);\n', ''),
    ('send no frame to the multitouch device', '        self->fBus->fMT->frame(c, n, buttons, scan, has_scan);', '        (void)0;'),
)
ARGS, REST = None, []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def thin(fat, out):
    """The arm64e (subtype 2, kernel ABI) slice of a fat KDK binary; lipo will not name it."""
    data = fat.read_bytes()
    magic, count = struct.unpack('>II', data[:8])
    assert magic == 0xcafebabe, fat
    for i in range(count):
        cpu, sub, off, size, _ = struct.unpack('>iiIII', data[8 + 20 * i:28 + 20 * i])
        if cpu == 0x0100000c and sub & 0xffffff == 2:
            out.write_bytes(data[off:off + size])
            return out
    raise AssertionError(f'{fat}: no arm64e slice')


def symbols(path):
    """{address: name} and {name: address} of defined symbols."""
    by_addr, by_name = {}, {}
    for line in run('nm', '-n', '-m', str(path)).stdout.splitlines():
        m = re.match(r'([0-9a-f]{16}) \(\S+,\S+\) (?:non-)?external (?:\[.*?\] )?(\S+)', line)
        if m:
            by_addr.setdefault(int(m[1], 16), m[2])
            by_name[m[2]] = int(m[1], 16)
    return by_addr, by_name


def fixups(path):
    out = {}
    for line in run('xcrun', 'dyld_info', '-fixups', str(path)).stdout.splitlines():
        m = re.match(r'\s+\S+\s+\S+\s+0x([0-9A-F]+)\s+(\S+)\s+(.*)', line)
        if m:
            target = m[3]
            out[int(m[1], 16)] = (re.search(r'/(\S+)', target)[1] if 'bind' in m[2]
                                  else int(re.match(r'0x([0-9A-F]+)', target)[1], 16))
    return out


def vtable(path, name):
    by_addr, by_name = symbols(path)
    fix = fixups(path)
    base = by_name[name]
    end = min(a for a in by_addr if a > base)
    slots = []
    for at in range(base + 16, end, 8):
        target = fix.get(at)
        slots.append(target if not isinstance(target, int) else by_addr.get(target, hex(target)))
    return slots


def method(name):
    """The mangled method without its class: __ZNK11IOHIDDevice16newProductStringEv -> newProductStringEv."""
    if name is None:
        return None
    m = re.match(r'__ZNK?\d+(?:IOHIDDevice|SnapI2CHIDDevice|SnapI2CHIDMultitouch)(.*)', name)
    return m[1] if m else name


def c_array(text, name):
    m = re.search(r'\b%s\[\d*\] = \{(.*?)\};' % re.escape(name), text, re.S)
    return bytes(int(v, 16) for v in re.findall(r'0x([0-9a-f]{2})\b', m[1]))


def build_standin(work):
    inc = work / 'standin'
    for header in STANDIN_HEADERS:
        (inc / header).parent.mkdir(parents=True, exist_ok=True)
        (inc / header).write_text('#include "test-snap-i2c-hid-standin.h"\n')
    return inc


def compile_harness(work, driver_cpp, tag, flags=(), c_flags=()):
    """c_flags: defines the hardware-independent units also take (SNAP_I2C_HID_FNKEYS: hid-keyboard.c); their
    objects are cached per define set."""
    out = work / f'start-{tag}'
    src = DRIVER / 'src'
    objs = []
    suffix = ''.join('-' + f.lstrip('-D').split('=')[0].lower() for f in c_flags)
    for name in ('geni-i2c', 'hid-rdesc', 'i2c-hid', 'hid-keyboard', 'hid-pointer', 'hid-ptp', 'hid-mt2'):
        obj = work / f'{name}{suffix}.o'
        if not obj.exists():
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra',
                            '-Werror', *c_flags, f'-I{src}', '-c', str(src / f'{name}.c'), '-o', str(obj)], check=True)
        objs.append(str(obj))
    harness = work / f'harness-{tag}.cpp'
    text = (ROOT / 'tools/test-snap-i2c-hid-start.cpp').read_text()
    harness.write_text(text.replace('"../drivers/snap-i2c-hid/src/SnapI2CHID.cpp"', f'"{driver_cpp}"')
                       .replace('"test-snap-i2c-hid-standin.h"', f'"{ROOT / "tools/test-snap-i2c-hid-standin.h"}"')
                       .replace('"test-snap-i2c-hid-fixture.h"', f'"{ROOT / "tools/test-snap-i2c-hid-fixture.h"}"'))
    result = run('clang++', '-std=gnu++17', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra',
                 '-Werror', '-Wno-unused-parameter', *flags, f'-I{work / "standin"}', f'-I{ROOT / "tools"}', f'-I{src}',
                 str(harness), *objs, '-o', str(out))
    assert result.returncode == 0, result.stderr[-3000:]
    return out


class Kext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='snap-i2c-hid-kext-'))
        if ARGS.kext:
            cls.kext = Path(ARGS.kext).resolve()
        else:
            built = run('sh', str(DRIVER / 'build.sh'), env=dict(os.environ, OUT=str(cls.work / 'out')))
            assert built.returncode == 0, built.stderr
            cls.kext = cls.work / 'out/SnapI2CHID.kext'
        cls.binary = cls.kext / 'Contents/MacOS/SnapI2CHID'
        cls.plist = plistlib.loads((cls.kext / 'Contents/Info.plist').read_bytes())
        cls.hid = thin(KDK / 'IOHIDFamily.kext/Contents/MacOS/IOHIDFamily', cls.work / 'IOHIDFamily.arm64e')
        build_standin(cls.work)

    def test_1_bundle(self):
        self.assertIn('Mach-O 64-bit kext bundle arm64e', run('file', str(self.binary)).stdout)
        self.assertEqual(run('codesign', '--verify', '--strict', str(self.kext)).returncode, 0)
        self.assertIn('_kmod_info', run('nm', '-g', str(self.binary)).stdout)
        p = self.plist
        self.assertEqual(p['CFBundleIdentifier'], 'org.snapintosh.driver.SnapI2CHID')
        # One personality: the keyboard event service is started by the bus, not matched (v41: a
        # cross-bundle IOHIDEventDriver personality never attached under IOMatchDefer-era 26A428).
        self.assertEqual(set(p['IOKitPersonalities']), {'SnapI2CHIDBus'})
        exported = run('nm', '-g', '-U', str(self.hid)).stdout
        for symbol in ('__ZN17IOHIDEventService10gMetaClassE', '__ZN17IOHIDEventService5startEP9IOService',
                       '__ZN17IOHIDEventService21dispatchKeyboardEventEyjjjj'):
            self.assertIn(symbol, exported)
        personality = p['IOKitPersonalities']['SnapI2CHIDBus']
        self.assertEqual((personality['IOClass'], personality['IOProviderClass'], personality['IONameMatch']),
                         ('SnapI2CHIDBus', 'AppleARMIODevice', 'snapintosh,geni-i2c-hid'))
        loader = ROOT / 'probes/i2cinput.py'
        if loader.is_file():
            self.assertIn("MATCH = 'snapintosh,geni-i2c-hid'", loader.read_text())
        self.assertNotIn('OSBundleRequireExplicitLoad', p)
        self.assertIn('com.apple.iokit.IOHIDFamily', p['OSBundleLibraries'])
        self.assertEqual((self.kext / 'Contents/Info.plist').read_bytes(), (DRIVER / 'Info.plist').read_bytes())

    def test_2_imports(self):
        exported = {}
        for library in self.plist['OSBundleLibraries']:
            if library == 'com.apple.iokit.IOHIDFamily':
                names = {line.split()[-1] for line in run('nm', '-g', '-U', str(self.hid)).stdout.splitlines()}
                self.assertIn(HID_UUID, run('dwarfdump', '--uuid', str(self.hid)).stdout)
            else:
                kext = KDK / 'System.kext/PlugIns' / (KPI[library] + '.kext') / KPI[library]
                # Symbol sets list exports as undefined or indirect entries: "U _name", "I _name (indirect for ...)".
                names = {m[1] for m in re.finditer(r'^\s*\S*\s+[UIT]\s+(_\S+)', run('nm', '-arch', 'arm64e', str(kext)).stdout, re.M)}
            for name in names:
                exported.setdefault(name, library)
        undefined = [line.split()[-1] for line in run('nm', '-u', str(self.binary)).stdout.split()
                     if line.startswith('_')]
        missing = sorted(u for u in undefined if u not in exported)
        self.assertEqual(missing, [], 'imports no declared library exports (private KPI?)')

    def test_3_vtable_event_service(self):
        theirs = vtable(self.hid, '__ZTV17IOHIDEventService')
        for name, symbol, count in (('SnapI2CHIDKeyboard', '__ZTV18SnapI2CHIDKeyboard', 18),
                                    ('SnapI2CHIDPointer', '__ZTV17SnapI2CHIDPointer', 17)):
            ours = vtable(self.binary, symbol)
            self.assertEqual(len(ours), len(theirs), f'{name} vtable length')
            cls = lambda n: n and re.sub(r'^(__ZNK?)\d+(IOHIDEventService|' + name + r'|IOService)', r'\1C', n)
            overridden = set()
            for slot, (t, o) in enumerate(zip(theirs, ours)):
                if o and name in o:
                    overridden.add(cls(o))
                self.assertEqual(cls(t), cls(o), f'{name} slot {slot}: kernel {t}, kext {o}')
            self.assertEqual(len(overridden), count, name)
        exported = run('nm', '-g', '-U', str(self.hid)).stdout
        for symbol in ('__ZN17IOHIDEventService28dispatchRelativePointerEventEyiijj',
                       '__ZN17IOHIDEventService24dispatchScrollWheelEventEyiiij',
                       '__ZN17IOHIDEventService37dispatchRelativePointerEventWithFixedEyiijj',
                       '__ZN17IOHIDEventService33dispatchScrollWheelEventWithFixedEyiiij'):
            self.assertIn(symbol, exported)

    def test_3_vtable(self):
        theirs = vtable(self.hid, '__ZTV11IOHIDDevice')
        for cls, symbol, want in (('SnapI2CHIDDevice', '__ZTV16SnapI2CHIDDevice', OVERRIDES),
                                  ('SnapI2CHIDMultitouch', '__ZTV20SnapI2CHIDMultitouch', MT_OVERRIDES)):
            ours = vtable(self.binary, symbol)
            self.assertEqual(len(ours), len(theirs), f'{cls} vtable length')
            overridden, pure = set(), []
            for slot, (t, o) in enumerate(zip(theirs, ours)):
                if o and cls in o:
                    overridden.add(method(o))
                if t == '___cxa_pure_virtual':
                    pure.append(slot)
                    self.assertIn(cls, o or '', f'{cls}: pure virtual slot {slot} not overridden')
                    continue
                self.assertEqual(method(t), method(o), f'{cls} slot {slot}: kernel {t}, kext {o}')
            self.assertEqual(overridden, want, cls)
            self.assertEqual(len(pure), 1)

    def test_4_no_counter_frequency(self):
        dump = run('/opt/homebrew/opt/llvm/bin/llvm-objdump', '-d', '--no-show-raw-insn', str(self.binary)).stdout
        self.assertNotIn('cntfrq_el0', dump.lower())
        self.assertGreater(dump.count('\n'), 1000)

    def test_5_register_contract(self):
        header = (DRIVER / 'src/geni-i2c.h').read_text()
        offsets = {n: int(v, 16) for n, v in re.findall(r'#define (GENI_\w+)\s+(0x[0-9a-f]+)u\b', header)
                   if not n.startswith(('GENI_IRQ', 'GENI_PACKING', 'GENI_TX_FIFO_WC', 'GENI_RX_FIFO_WC'))}
        self.assertEqual(offsets.pop('GENI_WINDOW_BYTES'), 0x1000)
        self.assertTrue(offsets and all(v + 4 <= 0x1000 for v in offsets.values()), offsets)
        source = (DRIVER / 'src/geni-i2c.c').read_text()
        written = set(re.findall(r'\bwr\(c, (GENI_\w+)', source))
        self.assertEqual(written, WRITABLE)
        glue = read_source(DRIVER / 'src/SnapI2CHID.cpp')
        self.assertEqual(glue.count('SNAP_I2C_HID_MMIO_READ(self->fBase, offset)'), 1, 'MMIO only through ioRead32')
        self.assertEqual(glue.count('SNAP_I2C_HID_MMIO_WRITE(self->fBase, offset, value)'), 1, 'and ioWrite32')
        self.assertEqual(len(re.findall(r'\bfBase\b', glue)), 5, 'no other use of the mapped window')

    def test_6_transport(self):
        fixture = (ROOT / 'tools/test-snap-i2c-hid-fixture.h').read_text()
        self.assertEqual(c_array(fixture, 'a16_eckb_hid_desc').hex(), HID_DESCRIPTOR_HEX)
        self.assertEqual(hashlib.sha256(c_array(fixture, 'a16_eckb_report_desc')).hexdigest(), REPORT_SHA)
        self.assertEqual(c_array(fixture, 'a16_eckb_get_report_54').hex(), GET_REPORT_54_HEX)
        # The touchpad's, from tools/qualify-a16-touchpad.py descriptors on generation 33 (v47).
        self.assertEqual(c_array(fixture, 'a16_tpad_hid_desc').hex(), TPAD_DESCRIPTOR_HEX)
        self.assertEqual(hashlib.sha256(c_array(fixture, 'a16_tpad_report_desc')).hexdigest(), TPAD_REPORT_SHA)
        out = self.work / 'test-snap-i2c-hid'
        sources = ['tools/test-snap-i2c-hid.c'] + [f'drivers/snap-i2c-hid/src/{n}.c'
                                                   for n in ('geni-i2c', 'hid-rdesc', 'i2c-hid', 'hid-keyboard', 'hid-pointer',
                                                             'hid-ptp', 'hid-mt2')]
        subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra',
                        '-Werror', '-Idrivers/snap-i2c-hid/src', *sources, '-o', str(out)], cwd=ROOT, check=True)
        result = run(str(out), cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertRegex(result.stdout, r'\b\d+ checks passed')

    def test_7_glue(self):
        harness = compile_harness(self.work, DRIVER / 'src/SnapI2CHID.cpp', 'real')
        for scenario in SCENARIOS:
            result = run(str(harness), scenario)
            self.assertEqual(result.returncode, 0, f'{scenario}: {result.stdout[-1500:]}{result.stderr[-1500:]}')
            self.assertIn(f'PASS {scenario}', result.stdout)
        survivors = []
        text = read_source(DRIVER / 'src/SnapI2CHID.cpp')
        for n, (what, old, new) in enumerate(MUTATIONS):
            self.assertEqual(text.count(old), 1, what)
            mutant = self.work / f'mutant-{n}.cpp'
            mutant.write_text(text.replace(old, new))
            binary = compile_harness(self.work, mutant, f'mutant-{n}')
            if all(run(str(binary), s).returncode == 0 for s in SCENARIOS):
                survivors.append(what)
        self.assertEqual(survivors, [], 'mutations the harness did not catch')

    def test_8_latency(self):
        # agents/input-latency T1-T6: the glue built with -DSNAP_I2C_HID_LATENCY=1 passes every scenario (T6) and the
        # latency ones, and every mutation of its scheduling is caught.
        flags = ('-DSNAP_I2C_HID_LATENCY=1',)
        harness = compile_harness(self.work, DRIVER / 'src/SnapI2CHID.cpp', 'latency', flags)
        for scenario in SCENARIOS + LATENCY_SCENARIOS:
            result = run(str(harness), scenario)
            self.assertEqual(result.returncode, 0, f'{scenario}: {result.stdout[-1500:]}{result.stderr[-1500:]}')
            self.assertIn(f'PASS {scenario}', result.stdout)
        survivors = []
        text = read_source(DRIVER / 'src/SnapI2CHID.cpp')
        for n, (what, old, new) in enumerate(LATENCY_MUTATIONS):
            self.assertEqual(text.count(old), 1, what)
            mutant = self.work / f'latency-mutant-{n}.cpp'
            mutant.write_text(text.replace(old, new))
            binary = compile_harness(self.work, mutant, f'latency-mutant-{n}', flags)
            if all(run(str(binary), s).returncode == 0 for s in LATENCY_SCENARIOS + ('latency-waits',)):
                survivors.append(what)
        self.assertEqual(survivors, [], 'latency mutations the harness did not catch')

    def test_9_fnkeys(self):
        # The keyboard's Fn-key layer (hid-keyboard.h): the transport test with its Fn-key groups, then every mutation
        # of hid-keyboard.c it must catch; the glue with the define passes every scenario (built in and off by
        # default, the keyboard is today's) and the Fn-key ones, also with SNAP_I2C_HID_LATENCY (the desktop-fnkeys
        # profile's pair); every mutation of the glue is caught.
        src = DRIVER / 'src'
        units = [src / f'{n}.c' for n in ('geni-i2c', 'hid-rdesc', 'i2c-hid', 'hid-pointer', 'hid-ptp', 'hid-mt2')]

        def transport(keyboard_c, tag):
            out = self.work / f'test-snap-i2c-hid-{tag}'
            built = run('cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
                        FNKEYS_FLAG, f'-I{src}', str(ROOT / 'tools/test-snap-i2c-hid.c'), *map(str, units),
                        str(keyboard_c), '-o', str(out))
            if built.returncode:
                return built
            return run(str(out), cwd=ROOT)

        result = transport(src / 'hid-keyboard.c', 'fnkeys')
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertRegex(result.stdout, r"\b\d+ checks passed \(34 groups and the Fn-key layer's 8\)")
        text = (src / 'hid-keyboard.c').read_text()
        survivors = []
        for n, (what, old, new) in enumerate(FNKEYS_C_MUTATIONS):
            self.assertEqual(text.count(old), 1, what)
            mutant = self.work / f'fnkeys-c-mutant-{n}' / 'hid-keyboard.c'
            mutant.parent.mkdir(exist_ok=True)
            mutant.write_text(text.replace(old, new))
            if transport(mutant, f'fnkeys-c-mutant-{n}').returncode == 0:
                survivors.append(what)
        self.assertEqual(survivors, [], 'hid-keyboard.c mutations the transport test did not catch')

        for tag, flags, scenarios in (('fnkeys', (FNKEYS_FLAG,), SCENARIOS + FNKEYS_SCENARIOS),
                                      ('fnkeys-latency', (FNKEYS_FLAG, '-DSNAP_I2C_HID_LATENCY=1'),
                                       SCENARIOS + LATENCY_SCENARIOS + FNKEYS_SCENARIOS)):
            harness = compile_harness(self.work, DRIVER / 'src/SnapI2CHID.cpp', tag, flags, (FNKEYS_FLAG,))
            for scenario in scenarios:
                result = run(str(harness), scenario)
                self.assertEqual(result.returncode, 0, f'{tag} {scenario}: {result.stdout[-1500:]}{result.stderr[-1500:]}')
                self.assertIn(f'PASS {scenario}', result.stdout)
        survivors = []
        text = read_source(DRIVER / 'src/SnapI2CHID.cpp')
        for n, (what, old, new) in enumerate(FNKEYS_MUTATIONS):
            self.assertEqual(text.count(old), 1, what)
            mutant = self.work / f'fnkeys-mutant-{n}.cpp'
            mutant.write_text(text.replace(old, new))
            binary = compile_harness(self.work, mutant, f'fnkeys-mutant-{n}', (FNKEYS_FLAG,), (FNKEYS_FLAG,))
            if all(run(str(binary), s).returncode == 0 for s in FNKEYS_SCENARIOS):
                survivors.append(what)
        self.assertEqual(survivors, [], 'Fn-key glue mutations the harness did not catch')


def main():
    global ARGS, REST
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--kext', help='an already built SnapI2CHID.kext (default: build one)')
    ARGS, REST = ap.parse_known_args()
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)


if __name__ == '__main__':
    main()
