# SPDX-License-Identifier: MIT
"""cycle.py installed-fresh: one installed-SSD boot admitted from current sources.

docs/INSTALLED-FRESH-ADMISSION-20261016.md. The historical admission chain
(baseline launch, predecessor retirement and preservation, image, SSD and TXM
qualifications) was deleted in the 2026-09-30 cleanup and is not recreated.
Every input here is regenerated and checked against an independent pin (the
profile's firmware and root-hash pins, txmnative.IMAGE_SHA, the retained trust
cache), or is a retained asset bound by its recorded SHA-256. The device, GPU
and SSD state are re-observed on hardware. Nothing here writes the SSD; the
guest writes only inside its APFS container in the window (--ans-writable).
"""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys
import time
import zipfile

from .common import need, image_base, PINS, serror_clear, PARKED_SERVICE_WORD, battery_minimum
from .bootstrap_smoke import IDENTITY, digest, load, modules, sha, source_paths, write
from . import speed_test as st

PROFILE = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks-quiet'
FIRMWARE = st.FIRMWARE
IPSW = 'downloads/UniversalMac_27.0_26A428_Restore.ipsw'
# The display8 build that last reached AdrenoMTLDevice (docs/WORKSPACE-CLEANUP-20260930.md).
# The display8 collection with one instruction changed: the colour element's colorimetry 16 (Default
# RGB) became 10 (sRGB), as AdrenoDisplay.cpp now says (tools/patch-auxkc-colorimetry.py; source
# collection 4c8770c7, booted through 2026-10-17). docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md.
# Rollback: AUXKC_SRGB, booted through v32.
AUXKC_SRGB = 'build/current-assets/auxkc-srgb-20261017/adreno.kc'
AUXKC_SRGB_SHA = 'c25f2f2cc8ad054e063021970a19edb66e7948e7962f93ee6d47433c640da302'
# From v33: relinked from current kext source (tools/build-auxkc-user.py; build/build-auxkc.py pin). The
# display8 code plus the sRGB element (now in source), the en0 naming thread, and read-only backing
# (AdrenoMemoryMap::pinBacking: a descriptor wired for device reads is prepared Out and mapped no-write;
# v32 dropped 68 submissions on kIOReturnNotWritable). docs/ADRENO-DEPTH-STENCIL-20261017.md, v32.
# kmutil marks AuxKC kexts OSBundleRequireExplicitLoad=true, which hides their personalities, and this
# route has no kernelmanagerd to load them: v33 booted the raw relink (c48b0ed0) and AdrenoX2 never
# started. tools/auxkc-autoload.py flips that one token (docs/ADRENO-AUXKC-AUTOLOAD-20260926.md).
# Rollback: AUXKC_READONLY (kext 7ec040b4), booted v33-v39.
AUXKC_READONLY = 'build/current-assets/auxkc-readonly-autoload-20261017/adreno.kc'
AUXKC_READONLY_SHA = '2cffa096f5b70838120c32381b01ea98d03f53d390afda2ac18503eb4ef2b439'
# Then GPU mappings resident across IOGPU's unwire within 512 MiB, and contiguous-run inserts
# (docs/ADRENO-GPU-MAP-RESIDENCY-20261017.md; v39: 1.09M one-page DART maps, 99% unmapped again).
# Kext 604216d0, relinked, autoloaded and pinned as above.
AUXKC = 'build/current-assets/auxkc-resident-20261017/adreno.kc'
AUXKC_SHA = '284f052f4af61114e4f3d13bc33146d336e5c149f17237bf2b65995e23f984b3'
KEXT_BUNDLE = 'org.snapintosh.driver.AdrenoX2'
# --input (docs/A16-INPUT-INSTALLED-20261017.md): the quiet profile plus the built-in keyboard's
# SnapI2CHID node and GENI page, a monitor with -DSNAP_I2C_INPUT=1, and this collection: the default
# AuxKC's AdrenoX2.kext input (7ec040b4) relinked with SnapI2CHID (tools/build-auxkc-user.py), both
# explicit-load flags cleared by tools/auxkc-autoload.py, pinned by build/build-auxkc.py.
INPUT_PROFILE = PROFILE + '-input'
INPUT_TOUCHPAD_PROFILE = INPUT_PROFILE + '-touchpad'      # --input --input-touchpad; needs TOUCHPAD_QUALIFIED
# From v40: SnapI2CHID recovers its own leftover controller after a panic and a chainload (v39 refused it
# busy); docs/A16-INPUT-INSTALLED-20261017.md section 10. Rollback: auxkc-input-20261017 (09f79749), v38-v39.
# Then the same SnapI2CHID (6d79e8c1) with the resident-mapping AdrenoX2 (604216d0); rollback: the
# recover collection auxkc-input-recover-20261017 (94f19597).
# From v41: the GPU-residency AdrenoX2 (604216d0) with SnapI2CHID's keyboard event-driver personality (26A428's
# generic ones are IOMatchDefer; v40's reports made no key events) and HID-stack diagnostics;
# docs/A16-INPUT-INSTALLED-20261017.md section 11. Rollback: auxkc-input-resident-20261017 (ddeb0658).
# v42 isolation: the same SnapI2CHID (keyboard event-driver personality) with the pre-residency AdrenoX2 (7ec040b4):
# v41 (residency 604216d0 + refmod-skip) lost launchd to SIGILL. Residency build: auxkc-input-hidfix-20261017 (98a240e9).
# From v43: SnapI2CHID's own keyboard event service (SnapI2CHIDKeyboard, an IOHIDEventService the bus starts and
# feeds; v41's cross-bundle IOHIDEventDriver personality never attached) with the pre-residency AdrenoX2 (7ec040b4);
# docs/A16-INPUT-INSTALLED-20261017.md section 12. v46 typed at the login window.
# From v48: the same plus HID country code 33 (US) and SnapI2CHIDPointer, the touchpad's mouse-mode pointer service
# (used only by --input-touchpad, refused until TOUCHPAD_QUALIFIED); section 13. Rollback: auxkc-input-kbd-20261017
# (7ff4e128).
# From v48: the real touchpad (2808:0219, generation 33) declares a 64-byte vendor input report 6 beside
# wMaxInputLength 52, which the old rule (every declared input report must fit) failed in report-descriptor;
# SnapI2CHID now needs only one input report to fit (section 14). Rollback: auxkc-input-tpd-20261017 (9c85e798).
# From 2026-10-18: the same SnapI2CHID with the cursor AdrenoX2 (851b9900): 7ec040b4's objects relinked with
# AdrenoDisplay.o rebuilt to composite the hardware-cursor layer and advertise CursorPlane=1
# (docs/ADRENO-DISPLAY-CURSOR-20261018.md). Rollback: auxkc-input-tpd2-20261018 (6b8ce322), below.
# 2026-10-19: the cursor collection's 7ec040b4 objects relinked with the current AdrenoDisplay.o (composed-row cursor
# publication, docs/GRAPHICS-CORRECTNESS-20261018.md; same undefined symbols as the cursor build). SnapI2CHID unchanged.
# The cursor collection remains for rollback as INPUT_AUXKC_CURSOR.
INPUT_AUXKC_PRESENT = 'build/current-assets/auxkc-input-present-20261019/adreno-input.kc'
INPUT_AUXKC_PRESENT_SHA = 'ee7bb6d5b9f8f5b5383e6585285a2176968c62ef7f27e0acf4097935a8c2e3e6'
# v81: the present collection's objects with adreno-ib-command.o rebuilt (CS storage tables of 1-8 slots in
# RGBA32F/RGBA16F/RGBA8/BGRA8, CS T# loads of 1-8 units; docs/USERSPACE-GRAPHICS-20261019.md). Rollback: PRESENT.
# Speed batch (docs/USERSPACE-GRAPHICS-20261019.md, "Speed batch"): the ci collection's objects with AdrenoDisplay.o
# rebuilt (frame tick armed before the layer-0 copy; copy cost published as CopyTimed/CopyMicros/CopyMaxMicros).
# Rollback: INPUT_AUXKC_CI.
# Then (same section): AdrenoDisplay.o rebuilt again to time the source-row cache maintenance separately
# (CopyMaintMicros). Rollback: INPUT_AUXKC_PACING.
INPUT_AUXKC = 'build/current-assets/auxkc-input-maint-20261019/adreno-input.kc'
INPUT_AUXKC_SHA = 'bd479cb1b02d342c4ff6df7b12dddf934d0ea3c6bfb7a421b985a48e83eeabba'
INPUT_AUXKC_PACING = 'build/current-assets/auxkc-input-pacing-20261019/adreno-input.kc'
INPUT_AUXKC_PACING_SHA = '0fe87092130668aabfb9538885742a87a4806bddf31fc82b6adce2bdfc7856a4'
INPUT_AUXKC_CI = 'build/current-assets/auxkc-input-ci-20261019/adreno-input.kc'
INPUT_AUXKC_CI_SHA = '8889bf2e216d2aa621a0ab5a67ff073a152a1cae2a7f439206476e309b30fad7'
# --present-damage (opt-in, 2026-10-20): INPUT_AUXKC's objects with AdrenoDisplay.o rebuilt. The layer-0 present
# maintains every source row in one pass with one DSB SY, reads each row once into a cacheable stage and writes only
# rows whose 128-bit signature changed, plus every cursor row and a rolling refresh of ceil(H/64) rows per present
# (WindowServer 26A428 sends no IOMFB dirty region). AdrenoDisplayStats adds CopyBarrier/Read/Hash/WriteMicros,
# CopyRows{Compared,Written,Skipped,Refreshed}, LastCacheMode, SourceAttr and SwapDirtyFlagged. SnapI2CHID and the
# other 11 objects are the maint collection's. Built offline; not booted. Default unchanged (INPUT_AUXKC).
INPUT_AUXKC_DAMAGE = 'build/current-assets/auxkc-input-damage-20261020/adreno-input.kc'
INPUT_AUXKC_DAMAGE_SHA = '18f6d15bcee238b434efd81e2c09b5a72774860efda4f3b7fbda50bbb69254cd'
# --present-cached-read (opt-in, 2026-10-20): the damage collection with AdrenoDisplay.o built with
# -DADRENO_PRESENT_CACHED_READ=1. The layer-0 map asks kIOMapCopybackCache; 26A428's memoryReferenceMap applies the mode
# to the surface's VM object (vm_object_change_wimg_mode, SPTM UPDATE_DISJOINT_MULTIPAGE), so the write-combined IOMFB
# framebuffer becomes write-back for every mapping. The kext reads through it only after both probes walk to write-back
# (no mismatched alias), keeps the per-line CIVAC and barrier, and counts CachedRead{Conversions,Fallbacks,Mismatch,
# Reverted}. Built offline; not booted. Default unchanged (INPUT_AUXKC).
INPUT_AUXKC_CACHED_READ = 'build/current-assets/auxkc-input-cachedread-20261020/adreno-input.kc'
INPUT_AUXKC_CACHED_READ_SHA = '8c735000ac55ca7b549c1c9a6f65b05a7880955c144199ca78d402195643d37b'
# --present-gpumap (opt-in, kext batch 8, 2026-10-20; FAILURES-AND-DESIGN.md in that batch): the cached-read collection
# with AdrenoX2.o, AdrenoMemoryMap.o, adreno-resource.o and AdrenoDisplay.o rebuilt. Frame pacing on the perf output (now
# five lines of at most 250 bytes: why/split/src/pace/map), the native CB0 range released before the DART reservation
# (no more "native VA bind failed" races), a collision retried at a fresh address, and a pool of empty DART reservations
# so a final free no longer recommits every page for a strict unmap (the 1 MiB UBO arenas: 128 -> 64 page maps each).
# Residency budget 0 (every unwire clears, as since v42). Built offline; not booted. Default unchanged (INPUT_AUXKC).
INPUT_AUXKC_GPUMAP = 'build/current-assets/auxkc-input-gpumap-20261020/adreno-input.kc'
INPUT_AUXKC_GPUMAP_SHA = '0ce6467c67ed77abc240a267729fa2352a9ee8d0437ede524097898903545caf'
# --present-vsync60 (opt-in, 2026-10-20; FAILURES-AND-DESIGN-VSYNC.md in that work): the gpumap collection with only
# AdrenoDisplay.o rebuilt with -DADRENO_VSYNC60=1. The frame tick runs on an absolute 16,666,667 ns grid
# (IOTimerEventSource::wakeAtTime at the next grid point, armed early by the 26A428 timer's coalescing slop) instead of
# setTimeoutMS(16) relative to each tick (v9: 16 ms + ~1.8 ms, median 55.3 Hz). A stall skips missed grid points, an idle
# of more than four periods re-syncs to now + one period, and a sixth perf line reports the grid error. Built offline;
# not booted. Default unchanged (INPUT_AUXKC).
INPUT_AUXKC_VSYNC60 = 'build/current-assets/auxkc-input-vsync60-20261020/adreno-input.kc'
INPUT_AUXKC_VSYNC60_SHA = '8cb1b11b67b910915fdd8abf86d839325a124bd21f93cbb1f0edaea96e60fc34'
# --present-dartpool (opt-in, kext batch 9, 2026-10-20; batch9/dart FAILURES-AND-DESIGN.md K1-K12): the vsync60
# collection with AdrenoMemoryMap.o and adreno-resource.o rebuilt with -DADRENO_POOL_ARENA=1. The pool of empty DART
# reservations gets a class for the plug-in's 1 MiB UBO staging arenas (256 entries, outside the 128 MiB the other spans
# share): v9's never-reused spans filled that budget for good, so 13,257 arenas were refused and each recommitted 64
# pages for a strict unmap. Built offline; not booted. Default unchanged (INPUT_AUXKC).
INPUT_AUXKC_DARTPOOL = 'build/current-assets/auxkc-input-dartpool-20261020/adreno-input.kc'
INPUT_AUXKC_DARTPOOL_SHA = '3f1fe10b3684def919293dca99d6937f03d571ddedf131d6a6c20344ed52fe3c'
# --input-ptp (opt-in, 2026-10-20; docs/A16-INPUT-PTP-20261020.md): the vsync60 collection's AdrenoX2 (9822b918, the
# same bundle byte for byte) with a SnapI2CHID that switches the touchpad to Precision Touchpad mode at publish (Input
# Mode 3, Surface/Button Switch on, readback), parses the multi-contact report from the device's own descriptor and
# dispatches one-finger pointer, clicks, tap-to-click and phased two-finger scroll with momentum, under the trackpad
# scroll identity. A refused or unparseable switch leaves today's mouse mode. Needs --input --input-touchpad; implies
# --present-vsync60's AdrenoX2 (not --present-dartpool's). Built offline; not booted. Default unchanged (INPUT_AUXKC).
INPUT_AUXKC_PTP = 'build/current-assets/auxkc-input-ptp-20261020/adreno-input.kc'
INPUT_AUXKC_PTP_SHA = 'dc2673f3f5bf3abd4b37203d7c6744784a521380ee739c6ad47bdd0d2f5f2824'
# --input-ptp --present-dartpool together: the dartpool collection's AdrenoX2 (d8fe1363, byte for byte) with the
# --input-ptp SnapI2CHID (0850513d, byte for byte), linked, packaged and pinned the same way. Built offline; not booted.
INPUT_AUXKC_PTP_DARTPOOL = 'build/current-assets/auxkc-input-ptp-dartpool-20261020/adreno-input.kc'
INPUT_AUXKC_PTP_DARTPOOL_SHA = '19cd50515998699d27fc5d1f3ffb326d32fee9be8fadbb3564bdb7ace4ada199'
# --present-resident (opt-in, pacing work 2026-10-21, failure modes R1-R13/P1-P7 in its report): the ptp-dartpool
# collection with AdrenoX2.o, AdrenoMemoryMap.o and AdrenoDisplay.o rebuilt with -DADRENO_RESIDENT_BUDGET_MIB=512
# -DADRENO_PERF_GPU=1: GPU mappings stay resident across IOGPU's unwire within 512 MiB (no per-command-buffer DART
# re-insert or clear for reused memory: the plug-in's recycled staging arenas, WindowServer's surfaces), and a seventh
# perf line splits each window's GPU execution, submission, preparation, cache maintenance and residency. Linked
# 2026-10-21 (operator-20261021-wifi/build-resident-mt.sh) with AdrenoX2 fd7efe94 and the gestures stage-2 SnapI2CHID
# (b3d7fd99: the yield fix plus the Apple multitouch device, agents/gestures). Built offline; not booted.
# Batch 12 (2026-10-21): the same collection with AdrenoX2 5bbd4901 = resident+perfgpu plus asynchronous IB completion
# (-DADRENO_IB_ASYNC=1, agents/async-ib; pairs with --ib-async, falls back to the synchronous IB without it) and sparse
# cache maintenance (-DADRENO_CACHE_SPARSE=1, agents/cache-maint); SnapI2CHID b3d7fd99 unchanged. Built offline by
# operator-20261021-wifi/build-b12-sparse.sh; not booted. Rollback (b11v1, booted clean): auxkc-input-ptp-dartpool-
# resident-20261021, f226d667232445d59113bb6ea349bfdde44759f4b8de272f6042ce453542f61a.
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT = 'build/current-assets/auxkc-input-ptp-dartpool-resident-async-sparse-20261021/adreno-input.kc'
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_SHA = 'cdb153fa35e16e8d64e148c083f34222774c11cb347d84bb81a69bbcc5e5a0e7'
# --present-beam (opt-in, agents/tear-free 2026-10-21, FAILURE-MODES.md A-F): tear-free presentation on the panel's real
# scanout. The collection is the resident one with agents/tear-free/build/kext-final's AdrenoX2 (async-ib + cache-sparse
# configuration; AdrenoDisplay.o with -DADRENO_BEAM=1 -DADRENO_PRESENT_CURSOR_STAGE=1 -DADRENO_PRESENT_SKIP_MAINT=1) and
# the same SnapI2CHID; the monitor gets -DSNAP_DISPLAY_TIMING=1 and the launch SNAP_DISPLAY_TIMING=1 (both or neither):
# the eDP interface's INTF_5 page (0x0ae3a000) read-only Device at stage 2, its params block and two GPU-node properties
# (probes/displaytiming.py, compat/display-timing.h). Built offline; not booted. None until linked and pinned: refused.
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM = ('build/current-assets/auxkc-input-ptp-dartpool-resident-beam2-20261021/'
                                          'adreno-input.kc')
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_SHA = '255fd55db9742fd09375d88680809ff4324ef1d460bfd04df88ae0cb51aa33fd'  # AdrenoX2 a8ed75f9 (tear-free fix2: Device attr 0b0000dd0x accepted, skip-maint only while LOCKED); b12v4 ran 63b15c6d (beam refused, attr 0x1)
DISPLAY_TIMING_DEFINE = '-DSNAP_DISPLAY_TIMING=1'
# --present-va-reclaim (opt-in, agents/gpu-va 2026-10-21, FAILURE-MODES.md G0-G17): the --present-beam collection with
# agents/gpu-va/build/kext-va's AdrenoX2 (tear-free kext-final's configuration plus -DADRENO_VA_RECLAIM=1 in
# AdrenoMemoryMap.o, AdrenoDisplay.o and adreno-resource.o): a refused DART reservation drains the pool of empty
# reservations and retries, later frees go back to the DART for a while, a released reservation is strict-freed over a
# pinned read-only filler instead of re-pinning its backing (b11v1's 47 frozen releases), and a perf va line reports the
# window's occupancy. Same SnapI2CHID, same monitor (no define); pairs with --present-beam's SNAP_DISPLAY_TIMING. Built
# offline; not booted. None until linked and pinned: refused.
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA = 'build/current-assets/auxkc-input-ptp-dartpool-resident-beam-va-20261021/adreno-input.kc'
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_SHA = 'beaaf19f45fa4f49b0791fd13191a0e7c12bbece035dd334bf2aef511cf4e4ff'  # AdrenoX2 2fa57c97 (beam fix2 + ADRENO_VA_RECLAIM), operator-20261021-wifi/build-b12-va.sh
# --gpu-va-wide (opt-in, agents/gpu-va-wide 2026-10-21, FAILURE-MODES.md V1-V18): the GPU VA window [1 GiB, 16 GiB)
# instead of [1 GiB, 4 GiB), every party together: q1n1 `cp-fence --va-wide` and `adopt --va-wide` (CB0 T0SZ 30), the
# monitor define ADRENO_VA_WIDE (16 CB0 root entries, virtual DART slots 32..511, tables preallocated in a 30.06 MiB
# monitor-private reservation above the ANS2 one), the loader's SNAP_ADRENO_VA_WIDE (dart-adreno vm-size 0x3_c000_0000,
# GPU node snapintosh,gpu-va-bits = 34, params pool word) and the --present-va-reclaim collection relinked with
# agents/gpu-va-wide's AdrenoX2 (that kext's defines plus -DADRENO_VA_WIDE=1 in every unit). Built offline; not booted.
# None until linked and pinned: refused.
GPU_VA_WIDE_DEFINE = '-DADRENO_VA_WIDE=1'
# b12v9 A/B (2026-10-21): the same configuration without ADRENO_CACHE_SPARSE (AdrenoX2 9b61d748), for b12v8's
# stale bands / flicker. Rollback (b12v8, with cache-sparse): auxkc-input-ptp-dartpool-resident-beam-va-wide-20261021,
# eaebd3d8191a9a62e51bb3994c63dc5ee864a945a0ed685e9614d83827a8576b.
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE = 'build/current-assets/auxkc-input-ptp-dartpool-resident-beam-va-wide-nosparse-20261021/adreno-input.kc'
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_SHA = 'a2674b9e4ff8107dbe352a4acf307b07c493461c78df4497398d4624d8d344d4'  # AdrenoX2 9b61d748 (no cache-sparse)
# --present-latch (opt-in, agents/input-latency 2026-10-21, FAILURE-MODES.md L1-L9 H1-H11 T1-T9): touch-to-photon latency.
# The --gpu-va-wide collection relinked with:
# - agents/input-latency's AdrenoX2: gpu-va-wide's defines plus -DADRENO_LATCH=1 in AdrenoDisplay.o. The beam tick fires
#   late in the panel's 2040-line blank, 3 ms before row 0, instead of before the vblank. The swap on screen is
#   completed just before the next latch, and the pending swap is copied at the latch, so WindowServer renders just in
#   time instead of a frame ahead. Built twice: on b13148e0 (kext-latch) and on the nosparse 9b61d748 (kext-latch-nosparse).
#   Since b12v11 (frames copied before their IB finished, ibaft 17-87 a window): the hold is off by default, and a layer-0
#   swap first seen less than 4 ms ago waits one latch while a GPU submission is in the kext (AdrenoX2.o counts them).
#   b12v11's collection (b68c9539, below) is the first build; latch2 (agents/input-latency build-auxkc-latch.sh) is the fix.
# - its SnapI2CHID: stage B plus -DSNAP_I2C_HID_LATENCY=1. Polls are timed from the previous poll's start, every 4 ms
#   while a report came in the last 0.5 s, and wire time is waited to the microsecond.
# Kext only: no monitor define, no loader change. Tunable with guest boot-args (--present-latch-us, --present-hold,
# --present-hold-margin-us, --input-active-us). Built offline; not booted. None until linked and pinned: refused.
# b12v12 (2026-10-21): input-latency's latch2 (hold off, copy gate) plus present-sync's -DADRENO_PRESENT_SYNC=1, nosparse
# (AdrenoX2 66992b5b, SnapI2CHID d90e0199). b12v11 ran b68c9539 (latch with hold: ibaft=36, 31.7 pps).
# b12v14 (2026-10-21): gpu-pipeline's kext (AdrenoX2 7dc009e2 = present-sync nosparse + ADRENO_PIPELINE; latch2, hold off).
# Rollback: latch2-sync-nosparse (f930bc2154ebea37b7c19be785ee4dafe7c1a360f20cd78541e67d4a54c51968), b12v12/b12v13.
# b12v16 fallback (2026-10-21): the pipeline kext (272bcccb, AdrenoX2 7dc009e2) panicked in b12v15 (IOGPUFamily data abort
# called from AdrenoX2), so back to present-sync's latch2-sync-nosparse (AdrenoX2 66992b5b, ran clean in b12v12/b12v13).
# Pipeline candidate: auxkc-...-latch2-pipe-nosparse-20261021, 272bcccbb4334ea6d090d9e24aa2b08c189e18eedfb389687b491a78f30a5f83.
# b12v17 (2026-10-21): fixed pipeline (AdrenoX2 71c94a4a, IOGPU initEvent static) + GPU recovery level 1
# (-DADRENO_GPU_RECOVER=1): AdrenoX2 73b4b8da, agents/gpu-recovery/build/build-auxkc-recover.sh VARIANT=pipe.
# Boot with --present-latch --present-pipeline 1 --ib-async --gpu-recover soft. Rollback: latch2-sync-nosparse
# f930bc2154ebea37b7c19be785ee4dafe7c1a360f20cd78541e67d4a54c51968 (b12v12/b12v13/b12v16, no pipeline).
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH = 'build/current-assets/org-desktop-nocoherent-20261023/adreno-input.kc'
INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH_SHA = 'ccf0c8f4da4f63fbe25c2b74d728030452fea1ab23fcab162d108dc0e36d1592'
# b12v23 (2026-10-23): + IO-coherent maintenance skipping (AdrenoX2 c66edb6b = SnapAdreno PROFILE=desktop at its profiles
# commit; SnapI2CHID d90e0199 = PROFILE=desktop); boot with --gpu-coherent. Previous: cursor 43bed810 (AdrenoX2
# 981e0b88 = PROFILE=desktop-nocoherent), b12v19c-b12v20. tools/build-auxkc-desktop.sh NAME rebuilds a collection from
# this checkout and prints the two lines to put here (its bytes differ from these: see the script).
# b12v19c: + aligned live-scanout copies (agents/cursor-fix; b12v19r panicked on the shake-to-locate cursor). Previous: repin 2ec76b70...
# b12v19r: + resident re-pin kext b2686dfb (agents/resident-evict). Previous: relatch-sparse 1cd18fa5...
# b12v19: relatch + cache-sparse kext 2cd7ef66 (agents/b12v19-kext). Rollback b12v18: relatch-nosparse 65243492...
# b12v18: relatch kext 128667ac (agents/present-pacing). Rollback: latch2-pipe2-recover-nosparse, 2cb7b6cc...
# --edp-backlight (opt-in, agents/brightness): the --present-latch collection with an AdrenoX2 that carries
# -DADRENO_BACKLIGHT=1 in AdrenoDisplay.o (the AdrenoBacklight service CoreBrightness drives). Pinned: next-20261024,
# the org next build (KEXT_PROFILE=desktop-next I2C_PROFILE=desktop-fnkeys tools/build-auxkc-desktop.sh, umbrella
# 8f9eeb5, SnapAdreno e1cf072, SnapI2CHID f0b7984; compat/, the kext and SnapI2CHID are unchanged since): AdrenoX2 =
# desktop-nocoherent (no --gpu-coherent) plus AdrenoBacklight taking the panel brightness from the swap record
# (AdrenoDisplay::swap_submit, source swap; levels 41..2047, nits proportional), the head rule (adreno_head_offset),
# the IOMFB call trace and the CS sampler opt-in (adreno_cs_samplers); SnapI2CHID = desktop plus the Fn-key layer
# (snap_i2c_fnkeys), section-identical to next2-20261024's. Every addition stays off without its boot-arg except the
# head rule (adreno_head_offset=0 turns it off). A --gpu-coherent run wants a KEXT_PROFILE=desktop-backlight collection
# here instead. Rollback: next2-20261024 (cc07dfd3, the force-brightness-control path next2c ran) and next-20261024
# (57965a84); without --edp-backlight the latch collection above (org-desktop-nocoherent-20261023, ccf0c8f4) is used.
INPUT_AUXKC_DESKTOP_BACKLIGHT = 'build/current-assets/swap-path-20261024/adreno-input.kc'
INPUT_AUXKC_DESKTOP_BACKLIGHT_SHA = '9e916a4185bc609178fe80a3110e020d9f3167625da7a76a9bc9ff22412743d5'
# --edp-backlight with --gpu-coherent or --present-early-done: the --edp-backlight collection rebuilt from
# SnapAdreno's desktop-early-done profile, i.e. desktop-backlight (desktop's IO-coherent maintenance skipping plus
# AdrenoBacklight) plus -DADRENO_PRESENT_EARLY_DONE=1 in AdrenoDisplay.o (src/AdrenoDisplayEarlyDone.h: a layer-0 swap
# completed right after its scanout copy, boot-arg adreno_present_early_done 1 always / 2 while WindowServer is behind,
# 0 measures only; the perf done line), and SnapI2CHID desktop-fnkeys. Link it with
# KEXT_PROFILE=desktop-early-done I2C_PROFILE=desktop-fnkeys tools/build-auxkc-desktop.sh NAME (sudo for kmutil's staging)
# and put the two lines it prints here. Every addition is inert without its switch (the monitor's coherent ON with
# adreno_coherent=1; adreno_backlight=1; adreno_present_early_done), so the collection also serves --edp-backlight runs
# without them. early-done-20261025: umbrella 822226c, SnapAdreno a2d43d0, SnapI2CHID f0b7984 (AdrenoX2 24f9e767).
INPUT_AUXKC_DESKTOP_EARLY_DONE = 'build/current-assets/early-done-20261025/adreno-input.kc'
INPUT_AUXKC_DESKTOP_EARLY_DONE_SHA = '9aff1d3e0fc1fd0625b83165738b90196249e053d6cc149e609f6a608bd7a6d1'
# --guest-net: INPUT_AUXKC's objects with SnapintoshVirtualEthernet's datapath (docs/GUEST-NETWORK-20261019.md).
# None until that collection is built and pinned; --guest-net refuses meanwhile.
INPUT_AUXKC_NET = None
INPUT_AUXKC_NET_SHA = None
INPUT_AUXKC_CURSOR = 'build/current-assets/auxkc-input-cursor-20261018/adreno-input.kc'
INPUT_AUXKC_CURSOR_SHA = '61c2b3c7d54989d83e0407ed188ab5f4e35f12cd1eac19b65bc47d685ece93de'
INPUT_AUXKC_TPD2 = 'build/current-assets/auxkc-input-tpd2-20261018/adreno-input.kc'
INPUT_AUXKC_TPD2_SHA = '6b8ce3226dedfea08745eef0ff41b7c006740f930e18b74c6718f84a7dfab109'
# The v43 SnapI2CHID (keyboard only, no pointer) with the GPU-residency AdrenoX2 (604216d0, suspected in v41's
# launchd SIGILL): swap these two
# into INPUT_AUXKC/INPUT_AUXKC_SHA to boot it.
INPUT_AUXKC_RESIDENT = 'build/current-assets/auxkc-input-kbd-resident-20261017/adreno-input.kc'
INPUT_AUXKC_RESIDENT_SHA = '92f878759ec07ed62cd4fdae532e4cff3fa2738e6ca2baec85eb75c7772a7b35'
INPUT_BUNDLES = sorted([KEXT_BUNDLE, 'org.snapintosh.driver.SnapI2CHID'])
INPUT_DEFINE = '-DSNAP_I2C_INPUT=1'      # compat/i2c-input.h
# --qcc2072-wifi (opt-in, 2026-10-21; probes/qcc2072wifi.py, compat/qcc2072-wifi.h): the QCC2072's BAR0, BAR2 and
# read-only ECAM page, its 64 MiB DMA arena at 0xdc000000 and a read-only control page at stage 2, the
# /arm-io/snap-qcc2072 node, a monitor with -DSNAP_QCC2072_WIFI=1 and SNAP_QCC2072_WIFI=1 in the launch (both or
# neither). The collection is the route's input collection relinked with SnapintoshQCC2072 by
# tools/build-qcc2072-native.py --baseline <its directory>, named by --qcc2072-auxkc DIR and --qcc2072-auxkc-sha256.
QCC2072_WIFI_DEFINE = '-DSNAP_QCC2072_WIFI=1'
QCC2072_BUNDLE = 'org.snapintosh.driver.SnapintoshQCC2072'
QCC2072_AUXKC_STATUS = 'NATIVE_WIFI_AUXKC_LINKED_RUNTIME_UNQUALIFIED'
QCC2072_INPUTS = 'qcc2072-inputs'        # under the attempt's directory: the three staged, hash-checked inputs
# The retained metal-stage rows plus the target-format plug-in's CDHash (docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md),
# so the installed plug-in (b2600ed7) and its replacement (99cb0965) both load. The payload is the loader's own
# trust_cache_spec of these rows; it reproduces the retained metal-stage payload from the retained rows.
# 2026-10-17 depth/stencil (docs/ADRENO-DEPTH-STENCIL-20261017.md): the rows above plus the depth/stencil plug-in's
# CDHash (60da7066), so 9f6d28df/b2600ed7, dc0816af/99cb0965 and the new binary all load (rollback keeps booting).
# 2026-10-17 lossless '&BGA' surfaces, sampler clamps, A8/16-bit unorm/32-bit float sampling
# (docs/ADRENO-DEPTH-STENCIL-20261017.md): the rows above plus 9c0a6006, so every earlier plug-in still loads.
# 2026-10-17 framebuffer fetch (docs/ADRENO-DEPTH-STENCIL-20261017.md, "Plug-in: framebuffer fetch"): the rows above
# plus fef9f3d3, so every earlier plug-in still loads.
# 2026-10-17 BGR10A2/RGB10A2 targets and 'l10r' surfaces (ControlCenter's status items, v35): the rows above plus
# 417894e7, so every earlier plug-in still loads.
# 2026-10-17 unbound or unread textures, samplers and buffers (v38: com.apple.dock.extra's icon draws, loginwindow): the
# rows above plus c64b78c4, so every earlier plug-in still loads.
# 2026-10-19 userspace graphics plug-in (docs/USERSPACE-GRAPHICS-20261019.md): the rows above plus cefae7f6, so every
# earlier plug-in still loads. The previous set (dockicons, c64b78c4) remains for rollback as ADDITIONS_DOCKICONS.
# 2026-10-19 compute runtime set (docs/USERSPACE-GRAPHICS-20261019.md): the graphics rows plus executable 3a35a474 and
# the rebuilt compiler runtime d3431892; the graphics set (cefae7f6) remains for rollback as ADDITIONS_GRAPHICS.
# v81 (CoreImage compute shapes, lines): the compute rows plus executable a77ac8d8; the compute set (3a35a474,
# d3431892) remains for rollback as ADDITIONS_COMPUTE.
# v84 (aligned IOSurface shadows, CoreImage fill): the ci rows plus executable 18382aa6; the ci set (a77ac8d8) remains
# for rollback as ADDITIONS_CI.
# v86 (RenderBox icons): the shadow rows plus executable 5cf27b37 and runtime v3 910d3b8d; the shadow set (18382aa6)
# remains for rollback as ADDITIONS_SHADOW.
# v88 (RenderBox custom effects): the icons rows plus executable 8b9f0f7c and runtime v4 a282c8ef; the icons set
# (5cf27b37, 910d3b8d) remains for rollback as ADDITIONS_ICONS.
# 2026-10-19 Liquid Glass / corners (docs/USERSPACE-GRAPHICS-20261019.md, "CoreAnimation's generic fallback"): the
# effects rows plus executable 9e8d6f01 (CA_DISABLE_GENERIC_SHADERS without framebuffer fetch); the effects set
# (8b9f0f7c) remains for rollback as ADDITIONS_EFFECTS.
# 16-bit derivatives set (docs/USERSPACE-GRAPHICS-20261019.md, "Fix: derivatives of 16-bit values at 32 bits"): the
# glass rows plus runtime v5 (e29f47d0) and the executable resealed for it (a0178daf). The glass set (plug-in 9e8d6f01,
# runtime v4) remains for rollback as ADDITIONS_GLASS.
# Mip levels set (docs/USERSPACE-GRAPHICS-20261019.md, "Fix: mip levels the GPU can sample"): the deriv rows plus the
# executable 03c706d4 (multi-level T#s, the GPU's level pitches); the deriv set (a0178daf, runtime v5) remains for
# rollback as ADDITIONS_DERIV.
# Framebuffer fetch set (docs/USERSPACE-GRAPHICS-20261019.md, "Window corner wedges"): the mip levels rows plus the
# executable 537a9702 (isFramebufferReadSupported YES); the mip levels set (03c706d4) remains for rollback as
# ADDITIONS_MIPLEVELS.
# Compile speed set (docs/USERSPACE-GRAPHICS-20261019.md, "Speed: shader compile time"): the fbfetch rows plus runtime
# v6 (5e63dca7) and the executable resealed for it (213f1073); the fbfetch set remains for rollback as ADDITIONS_FBFETCH.
# Speed batch set (docs/USERSPACE-GRAPHICS-20261019.md, "Speed batch"): the compile speed rows plus the executable
# f4200c28 (display copy cost in the stats line); the compile speed set remains for rollback as ADDITIONS_COMPILESPEED.
# UBO staging set (docs/USERSPACE-GRAPHICS-20261019.md, "Speed: CoreAnimation uniforms staged by the kilobyte"): the
# pacing rows plus the executable 90bf8b14; the pacing set remains for rollback as ADDITIONS_PACING.
# Drag speed set (docs/PLUGIN-DRAG-SPEED-20261020.md): the UBO rows plus the executable a2ae66df (per-program draw
# plans, bulk dword writes, recycled staging arenas); the UBO set remains for rollback as ADDITIONS_UBO.
# WindowServer abort set (docs/WINDOWSERVER-APL-ABORT-20261020.md): the drag speed rows plus runtime v7 (ab4ccbd4: AIR 2.2
# texture reads, bounds-checked call operands) and the executable resealed for it (f605a348: CoreAnimation's APL filter
# off); the drag speed set remains for rollback as ADDITIONS_DRAGSPEED.
# Arena trim set (docs/PLUGIN-ARENA-TRIM-20261021.md): the WindowServer abort rows plus the executable 3566f23f (UBO
# staging arenas that give back GPU address space); the WindowServer abort set remains for rollback as ADDITIONS_WSABORT.
# Combined set (agents/present-sync, agents/gfx-correctness, agents/turnip-audit): the arena trim rows plus the executable
# 24c391f4 (commitAndWaitUntilSubmitted waits for the kernel submission, GPU mipmap generation, integer render targets and
# textures, BR-thread blit/compute passes, render-pass split); the arena trim set remains for rollback as
# ADDITIONS_ARENATRIM.
# gpu-perf set (agents/gpu-perf): the combined rows plus the executable 07149eed (per-command-buffer UBO mirror, GPU work
# counters); the combined set remains for rollback as ADDITIONS_COMBINED.
# Pipeline set (agents/gpu-pipeline): gpu-perf's rows plus the executable 1848e9a6 (gpu-perf's source built with
# -DADRENO_PIPELINE=1: IOSurface shadows wait for the command buffers using them on the GPU, needed once the kext returns
# WindowServer's submissions while their IB is in flight); gpu-perf's set remains for rollback as ADDITIONS_GPUPERF.
# Pipeline2 set (agents/gpu-pipeline): the pipeline rows plus the executable c291173b (pipeline + gpu-perf's blit chunks:
# no CP_MEMCPY over 1 MiB, after b12v13's 4 MiB copy latched the GPU); the pipeline set remains as ADDITIONS_PIPELINE.
# Mirror-slab set (agents/gpu-perf FAILURE-MODES.md R): the pipeline2 rows plus the executable 933060b2 (UBO mirror regions
# from slabs allocated once and never released); the pipeline2 set remains for rollback as ADDITIONS_PIPELINE2.
# Settings-icons set (SnapMetal ADRENO_SETTINGS_ICONS): the mirror-slab rows plus the executable c76a4677 (CoreImage
# compute kernels sampling sRGB and grey+alpha images; multi-input kernels behind AdrenoIBComputeSamplers), deployed by
# tools/deploy-guest-plugin.py; the mirror-slab set remains for rollback as ADDITIONS_MIRRORSLAB.
# Iconfix set (SnapMetal icon-pixels-next, ADRENO_CS_TABLES): the settings-icons rows plus the executable 11d5ff9a
# (CoreImage compute kernels get SP_CS_CONFIG NTEX = NSAMP = their T#/S# count, as Mesa programs them;
# ADRENO_CS_TABLES=0 in a process's environment keeps the settings-icons counts), deployed by
# tools/deploy-guest-plugin.py, and the icon-pixels probe 25f07e86 that tools/run-icon-pixels.py pushes; the
# settings-icons set remains for rollback as ADDITIONS_SETTINGSICONS.
ADDITIONS = 'build/current-assets/metal-stage-iconfix-20261024/trust-additions.json'
ADDITIONS_SHA = '501a90b6e6fe79b346bcb81c1bddee315ae9fbe3d369ff6b5f44b115aeecc4de'
TRUST_PAYLOAD = 'build/current-assets/metal-stage-iconfix-20261024/trustcache.payload'
TRUST_SHA = '7857aabcda2814974193c24dbc3245312c3ba02d1de46848b8be60a332571af0'
ADDITIONS_SETTINGSICONS = 'build/current-assets/metal-stage-settingsicons-20261024/trust-additions.json'
ADDITIONS_SETTINGSICONS_SHA = 'cdc784df778f7544fac5b2c774c3b6ee49cc70a15670301f3c4515dfed5562ff'
TRUST_PAYLOAD_SETTINGSICONS = 'build/current-assets/metal-stage-settingsicons-20261024/trustcache.payload'
TRUST_SHA_SETTINGSICONS = '247598bc2b4b48c31124e6dde3b83a52b41aa59355f697416cec0e8420926636'
ADDITIONS_MIRRORSLAB = 'build/current-assets/metal-stage-mirrorslab-20261021/trust-additions.json'
ADDITIONS_MIRRORSLAB_SHA = '4802847aef13e6e46ebc50cd03b1e35ebafe929d5ae46f44f4de6a8d4fb64ae7'
TRUST_PAYLOAD_MIRRORSLAB = 'build/current-assets/metal-stage-mirrorslab-20261021/trustcache.payload'
TRUST_SHA_MIRRORSLAB = 'fb429aa20cea252f321d3b4ff18d7bc9425c10babb391d370315c9de5b4ff50f'
ADDITIONS_PIPELINE2 = 'build/current-assets/metal-stage-pipeline2-20261021/trust-additions.json'
ADDITIONS_PIPELINE2_SHA = 'eb035ef6ff2a380ece5ace3eddd9d9bc1365d9a8a478ba25ede795d8ccf5e119'
TRUST_PAYLOAD_PIPELINE2 = 'build/current-assets/metal-stage-pipeline2-20261021/trustcache.payload'
TRUST_SHA_PIPELINE2 = '2a6667e6607f00f5c77a43ccd91dbee382da9ec5160af5327813932aee2096e4'
ADDITIONS_PIPELINE = 'build/current-assets/metal-stage-pipeline-20261021/trust-additions.json'
ADDITIONS_PIPELINE_SHA = 'c764a692e94bc81185782032731025942221f278aae89a32fbb12f5f823632c5'
TRUST_PAYLOAD_PIPELINE = 'build/current-assets/metal-stage-pipeline-20261021/trustcache.payload'
TRUST_SHA_PIPELINE = 'd299050b828075d14a5f6c308a982e2c82678f0559c199fc54a160a5ccbe327d'
ADDITIONS_GPUPERF = 'build/current-assets/metal-stage-gpuperf-20261021/trust-additions.json'
ADDITIONS_GPUPERF_SHA = 'bd9946715ea5fd3e104649baaf5c6fb23c2d44e5e9649b836ec6d3ac259cd5d6'
TRUST_PAYLOAD_GPUPERF = 'build/current-assets/metal-stage-gpuperf-20261021/trustcache.payload'
TRUST_SHA_GPUPERF = '2abfb483845b156e1f67917a887ceac53b0ca49dc5ef4b413a143a207a1ca72d'
ADDITIONS_COMBINED = 'build/current-assets/metal-stage-combined-20261021/trust-additions.json'
ADDITIONS_COMBINED_SHA = '50cfd8625b9612fe60a7c1b76f05fda70acfe39627ff35c8c285cedd65d8e3ae'
TRUST_PAYLOAD_COMBINED = 'build/current-assets/metal-stage-combined-20261021/trustcache.payload'
TRUST_SHA_COMBINED = 'f03d27cf7964c875716901c0e0c271e5d21940dd6c9965dd00f592832403c5bc'
ADDITIONS_ARENATRIM = 'build/current-assets/metal-stage-arenatrim-20261021/trust-additions.json'
ADDITIONS_ARENATRIM_SHA = '4deb533398368a760ad6508705f21db97e65ecc60210abf7e427b9c5598632be'
TRUST_PAYLOAD_ARENATRIM = 'build/current-assets/metal-stage-arenatrim-20261021/trustcache.payload'
TRUST_SHA_ARENATRIM = 'd0d673120e04f3215e60cd2570e2294e39c1600406ac45add9e9122ccdd829ac'
ADDITIONS_WSABORT = 'build/current-assets/metal-stage-wsabort-20261020/trust-additions.json'
ADDITIONS_WSABORT_SHA = '3f8eedc22c69cd8340a2d6d3cbefc4cd8f2b42d22845220c3135a2ac02963163'
TRUST_PAYLOAD_WSABORT = 'build/current-assets/metal-stage-wsabort-20261020/trustcache.payload'
TRUST_SHA_WSABORT = '439d438c80546a5a31ce9a110bb8c022fe872ec806b23804f4aeb79630c1f973'
ADDITIONS_DRAGSPEED = 'build/current-assets/metal-stage-dragspeed-20261020/trust-additions.json'
ADDITIONS_DRAGSPEED_SHA = 'd70ca1af87a2f39b83574f8fc711ea00e0132ae938c9bbc88c4e3ee576f11ee9'
TRUST_PAYLOAD_DRAGSPEED = 'build/current-assets/metal-stage-dragspeed-20261020/trustcache.payload'
TRUST_SHA_DRAGSPEED = '50d0ddc2247f49496084e95b8b0c6058f09b6e2741a15f9d7db5d221de8ca4b4'
ADDITIONS_UBO = 'build/current-assets/metal-stage-ubo-20261019/trust-additions.json'
ADDITIONS_UBO_SHA = 'ea32f781d6317137d942b5888e8c4a4796b85dbe3a9ead3ffe90cdd8374c4aca'
TRUST_PAYLOAD_UBO = 'build/current-assets/metal-stage-ubo-20261019/trustcache.payload'
TRUST_SHA_UBO = '71b51c49975f26a97a4c02d3c7bb8ead3b7b0d333fc89614efd25a9b4a5070a1'
ADDITIONS_PACING = 'build/current-assets/metal-stage-pacing-20261019/trust-additions.json'
ADDITIONS_PACING_SHA = '36307882ee8a602a6708890c8c2a1e7955d40e3a3008b0f18bb0f954b720c91f'
TRUST_PAYLOAD_PACING = 'build/current-assets/metal-stage-pacing-20261019/trustcache.payload'
TRUST_SHA_PACING = '7edc4548cadc32758de124e7e4d1ff632aea2c2886ba044ac2b9f452a5da4d19'
ADDITIONS_COMPILESPEED = 'build/current-assets/metal-stage-compilespeed-20261019/trust-additions.json'
ADDITIONS_COMPILESPEED_SHA = 'ca579f1895cc9a5193072ca9f6b04ede896845541774b74037c91c3290301175'
TRUST_PAYLOAD_COMPILESPEED = 'build/current-assets/metal-stage-compilespeed-20261019/trustcache.payload'
TRUST_SHA_COMPILESPEED = 'f059c641fa2a08fd7b4a9431f3e82627c01f6b6f2f7affb0b1f103f75ed48491'
ADDITIONS_FBFETCH = 'build/current-assets/metal-stage-fbfetch-20261019/trust-additions.json'
ADDITIONS_FBFETCH_SHA = '10aef973d5320f4c6bc08a3662c13e505840262c3b691ec2d61c1690b532dcb9'
TRUST_PAYLOAD_FBFETCH = 'build/current-assets/metal-stage-fbfetch-20261019/trustcache.payload'
TRUST_SHA_FBFETCH = '1b09653c2e4bf5517b82d976d4121de8ec5d1458b4177824b762daeb92b3b6df'
ADDITIONS_MIPLEVELS = 'build/current-assets/metal-stage-miplevels-20261019/trust-additions.json'
ADDITIONS_MIPLEVELS_SHA = 'e32d83a3fdf6d5f5f2f0ec2756804c2982d24fb6344242f84324f2b8fa024dc6'
TRUST_PAYLOAD_MIPLEVELS = 'build/current-assets/metal-stage-miplevels-20261019/trustcache.payload'
TRUST_SHA_MIPLEVELS = 'fe6896ebb974a97a0758a60e7883c660c2b05ea1f75cddbfa7debf0ee192da97'
ADDITIONS_DERIV = 'build/current-assets/metal-stage-deriv-20261019/trust-additions.json'
ADDITIONS_DERIV_SHA = '14a505a987fddf7ca10f985886cdd809cfb289fc9001de83b87fa4228913caa5'
TRUST_PAYLOAD_DERIV = 'build/current-assets/metal-stage-deriv-20261019/trustcache.payload'
TRUST_SHA_DERIV = '735d2fe083eee2a2f4ef2940cbc132ab0b3192ed509a7c83ec440ae468d099f7'
ADDITIONS_GLASS = 'build/current-assets/metal-stage-glass-20261019/trust-additions.json'
ADDITIONS_GLASS_SHA = 'ac0bccbacb6d854169dba07cdaff08d62f47016b3b1a7b8530eb79f250435d72'
TRUST_PAYLOAD_GLASS = 'build/current-assets/metal-stage-glass-20261019/trustcache.payload'
TRUST_SHA_GLASS = 'da671e4c98117da6a9bdb36a4d7147951eece30ced281de40e6c17f3a2cfa8db'
ADDITIONS_EFFECTS = 'build/current-assets/metal-stage-effects-20261019/trust-additions.json'
ADDITIONS_EFFECTS_SHA = 'a87c0465b7e912b16ebfacd905584064439a244a787257292e5535fe359c40e3'
TRUST_PAYLOAD_EFFECTS = 'build/current-assets/metal-stage-effects-20261019/trustcache.payload'
TRUST_SHA_EFFECTS = 'e0fa2043c92e6f539cd27632dad70eb1a55cf72ddfd1ad7478929c49bd012bcd'
ADDITIONS_ICONS = 'build/current-assets/metal-stage-icons-20261019/trust-additions.json'
ADDITIONS_ICONS_SHA = 'd1a90f804ec5a8c3de24aed28d7c6fc7032dbcf957b6b9cf24a948d20238227c'
ADDITIONS_SHADOW = 'build/current-assets/metal-stage-shadow-20261019/trust-additions.json'
ADDITIONS_SHADOW_SHA = '63eb4e3315567d530c838bd2d4a35b9d77f65e8d8dec6adac51235c9e1c16059'
ADDITIONS_CI = 'build/current-assets/metal-stage-ci-20261019/trust-additions.json'
ADDITIONS_CI_SHA = 'c811ba71dda4896fae6634311800bce5d49116ac001e8ff445cf0883e21c5d6d'
ADDITIONS_COMPUTE = 'build/current-assets/metal-stage-compute-20261019/trust-additions.json'
ADDITIONS_COMPUTE_SHA = 'c58926605b314eb37405f118ad98ecac1069f8c5276de9388c26b4ef9afc5077'
ADDITIONS_GRAPHICS = 'build/current-assets/metal-stage-graphics-20261019/trust-additions.json'
ADDITIONS_GRAPHICS_SHA = '6785043c1a0c09e78076b27760c9a74a5fd312bf608d837ce3af7f695c7523cf'
ADDITIONS_DOCKICONS = 'build/current-assets/metal-stage-dockicons-20261017/trust-additions.json'
ADDITIONS_DOCKICONS_SHA = 'b454cd4bf54bb04c667f20d1594684e79f27464250220cfc4b420723ec5b0edc'
BRIDGE = ('tools/txm-image4-bridge.S', 'tools/txm-image4-bridge.ld')
LLVM = '/opt/homebrew/opt/llvm/bin'
# Only this prefix of the window header's SHA-256 survives (git 140bcfe, the
# gen72 point-size apply's header-after); the boot records the full value.
WINDOW_HEADER_PREFIX = '7016b991'
TIMESYNC_FLAG = '-timesync_bringup'
# 26A428's metacompressor runs Apple's WKdm compression instruction (0x00200820 at vm_compressor_algorithms.c:557)
# unless this boot-arg sets its software flag; the A16 has no such instruction, so the first compression under
# memory pressure panicked ("Undefined kernel instruction", v38). Not a kernel patch: the kernel's own switch.
COMPRESSOR_SW_FLAG = '-vm_compressor_wk_sw'
BASE_CMDLINE = '-v debug=0x8 serial=3 cluster_power=0 wdt=-1'
WATCHDOG = 1800
# --watchdog: a desktop session may run up to two hours (owner's decision, 2026-10-24), only on AC.
WATCHDOG_MAX = 7200
DISPLAY_SLOT = '/device-tree/arm-io/adreno-display'
# The installed launches' environment lived only in deleted launch records: the
# speed test's six-CPU settings without its RAM-disk preload requirement, plus
# the installed route's per-run keys (set at boot).
ENV = {'SNAP_SMP': '1', 'SNAP_GUEST_MIB': str(st.GUEST_MIB), 'SNAP_PHYS_BASE': hex(st.PHYS_BASE),
       'SNAP_NATIVE_CALLS': '1', 'SNAP_WATCHDOG': str(WATCHDOG), 'SNAP_EARLY_STOP': 'guest,host',
       'SNAP_EARLY_STOP_DELAY': '600', 'SNAP_EARLY_STOP_MAX_DELAY': '600'}
SCHEMA = 'snapintosh-installed-fresh-v1'
# The two-way console (docs/GUEST-SHELL-DESIGN-20261016.md), opt-in per attempt:
# the console rides on the host poll, the console-shell job runs only with
# snapintosh_shell=1, and -s asks launchd for a single-user shell first.
CONSOLE_FLAG = 'snapintosh_shell=1'
SINGLE_USER_FLAG = '-s'


# Opt-in monitor defines on top of the variant's recipe, given to every mode of the attempt.
WFI_RESUME_DEFINE = '-DSNAP_WFI_RESUME=1'     # compat/wfi-resume.h: host-only EL2 ticks return an idle vCPU to its WFI
# compat/fast-timer-irq.h SNAP_FAST_TIMER_IRQ: vCPUs 1-5 take their EL2 timer tick without the service token (v89:
# 2.07M secondary ticks waited 87.1 s for it); needs the fast set's fast-trap admission, --root-cache-wide (its
# counters) and --service-subclass (it reports after the exit profile)
FAST_TIMER_IRQ_DEFINE = '-DSNAP_FAST_TIMER_IRQ=1'
# docs/DART-MEMO-20261019.md: compat/sptm-dart-memo.h SNAP_DART_MEMO, DART table verdicts so MAP/UNMAP (every GPU
# memory mapping) skip the 2,048-descriptor scan per level (v90: 1.6M maps at 21.6 us under the token); needs
# --root-cache-wide (the memo and its counters)
DART_MEMO_DEFINE = '-DSNAP_DART_MEMO=1'
# docs/AES-BITSLICE-20261019.md: compat/aes-bitslice.h SNAP_AES_BITSLICE, the PAC key derivation's software AES as a
# bitsliced cipher (v90: 790,926 derive-cache misses at about 325 µs each, inside 282 s of user returns); any variant
AES_BITSLICE_DEFINE = '-DSNAP_AES_BITSLICE=1'
# docs/FAST-IPI-20261019.md: compat/fast-ipi.h SNAP_FAST_IPI, the Apple IPI registers without the service token (v90:
# 3.96M of the 5.88M locked sysreg traps, which waited 183.6 s for it); needs the fast set's fast-trap admission and
# --root-cache-wide (its counters)
FAST_IPI_DEFINE = '-DSNAP_FAST_IPI=1'
# compat/fast-vector.h fast_el0_sysreg: EL0 counter-alias and SPRR UPERM reads answered off the service lock (fast only)
FAST_EL0_SYSREG_DEFINE = '-DSNAP_FAST_EL0_SYSREG=1'
# compat/service-profile.h service_sub_*: service-lock hold and exit timing per sub-class (instrumentation)
SERVICE_SUBCLASS_DEFINE = '-DSNAP_SERVICE_SUBCLASS=1'
# compat/dart-wiredcnt.h: ADRENO_GUEST_UNMAP subtracts the leaves it clears from XNU's IOMMU-table count (v29-v32 leak)
DART_WIREDCNT_DEFINE = '-DSNAP_DART_WIREDCNT=1'
# probes/xnuboot.c monitor_call_impl: after XNU's PANIC_ENTRY, serve ordinary calls so the panic string gets printed
PANIC_SERVE_DEFINE = '-DSNAP_PANIC_SERVE=1'
# compat/root-miss.h: a root-cache miss reuses the memo's shared-table verdicts, and a full cache evicts the
# least recently installed inactive root (v34: 49,783 rebuilds at about 8 ms, 73% of lock hold)
ROOT_MISS_FAST_DEFINE = '-DSNAP_ROOT_MISS_FAST=1'
# compat/update-fast.h: no TLBI for an access-flag-clear old leaf; the six-CPU kernel-copy check in one pass
UPDATE_DISJOINT_FAST_DEFINE = '-DSNAP_UPDATE_DISJOINT_FAST=1'
# shadow/sprr-class-fast.h: incremental kernel class proof on a PPERM/TPRO cache miss (v34: 153 s of lock hold)
KERNEL_PPERM_FAST_DEFINE = '-DSNAP_KERNEL_PPERM_FAST=1'
# compat/adreno-guest.h: a 1 s IB completion budget instead of 100 ms (v38 latched UNCERTAIN on one IB, no fault)
IB_BUDGET_1S_DEFINE = '-DADRENO_IB_POLL_DIVISOR=1u'
# compat/root-wide.h: 192 cached user roots instead of 64, state in monitor arena pages (v34: 64 roots
# reused within 0.4 s, so the full cache rebuilt one every 8 ms)
ROOT_CACHE_WIDE_DEFINE = '-DSNAP_ROOT_CACHE_WIDE=1'
# probes/xnuboot.c user_update_kernel_skip: the six-CPU kernel-copy check every 1024 skips instead of 64 (weaker audit)
UPDATE_CHECK_SPARSE_DEFINE = '-DSNAP_UPDATE_CHECK_SPARSE=1'
# compat/sptm-user.h SNAP_UNMAP_MIXED: an UNMAP_DISJOINT list naming user and kernel roots for one frame runs as
# one transaction (v39 stopped with BAD_CONFIG on a user-first one)
UNMAP_MIXED_DEFINE = '-DSNAP_UNMAP_MIXED=1'
# compat/boot-relocate.h SNAP_BOOT_RELOCATE: vCPU 0 runs on a physical CPU other than q1n1's (--prime-secondaries puts
# all six vCPUs on Prime cluster 1; a cross-cluster layout starved vCPU 0 at the service lock in v26)
BOOT_RELOCATE_DEFINE = '-DSNAP_BOOT_RELOCATE=1'
# compat/txm.h SNAP_TXM_ASPACE_WIDE: 4096 TXM address spaces instead of 512 (v47: 512 live 15 minutes after login),
# with the loader's matching 64-page arena (SNAP_TXM_ASPACE_WIDE=1 in the launch environment, below)
TXM_ASPACE_WIDE_DEFINE = '-DSNAP_TXM_ASPACE_WIDE=1'
# compat/fine-lock.h SNAP_FINE_LOCKS (docs/FINE-LOCKS-20261017.md): user MAP_PAGE, UNMAP_REGION and
# UPDATE_DISJOINT run under per-root stripes instead of the service token; SNAP_FINE_SWITCH adds SWITCH_ROOT
# cache hits. The monitor refuses to build outside the fast installed flag set (root-cache-wide,
# update-disjoint-fast, service-subclass and the native-table defaults).
FINE_LOCKS_DEFINE = '-DSNAP_FINE_LOCKS=1'
FINE_SWITCH_DEFINE = '-DSNAP_FINE_SWITCH=1'
# compat/service-lock.h SNAP_FAIR_TOKEN: the service token granted in arrival order (a ticket queue), so a CPU
# re-acquiring from its own cache cannot pass a waiter in another cluster (v26's one-second SERVICE_TIMEOUT).
FAIR_TOKEN_DEFINE = '-DSNAP_FAIR_TOKEN=1'
# compat/user-hw-walk.h SNAP_USER_HW_WALK: 4K (format 1) user roots run on XNU's own tables, UMPRR18 roots on
# monitor copies of their TPRO paths; page-table frames read-only at stage 2. Pair with --kernel-user-4k.
USER_HW_WALK_DEFINE = '-DSNAP_USER_HW_WALK=1'
# probes/xnuboot.c SNAP_IDREG_MMFR3: every vCPU records ID_AA64MMFR3/MMFR1 (S1PIE, S1POE) at setup
IDREG_MMFR3_DEFINE = '-DSNAP_IDREG_MMFR3=1'
# compat/s2-fault-retry.h SNAP_S2_FAULT_RETRY: a guest stage-2 translation fault on guest RAM that the CPU's own
# stage-2 tree maps is snapshotted (HPFAR, VTTBR/VTCR/HCR, both walks) and retried after TLBI VMALLS12E1 instead of
# stopping the run; the same access three times in a row or over 1000 a second per vCPU still stops (v62/v63/v65)
S2_FAULT_RETRY_DEFINE = '-DSNAP_S2_FAULT_RETRY=1'
# compat/s2-fault-retry.h SNAP_S2_FAULT_RETRY_STAGE1 (needs the above): also retry a fault whose hardware IPA (HPFAR)
# is not mapped but whose stage-1 re-walk's is. Off, that case stops: a stale stage-1 translation that did not fault
# may already have written the wrong page, and the guest writes the real install's disk.
S2_FAULT_RETRY_STAGE1_DEFINE = '-DSNAP_S2_FAULT_RETRY_STAGE1=1'
# docs/TOKEN-COSTS-20261018.md: the token's next costs. compat/nest-fast.h SNAP_NEST_FAST (NEST/UNNEST answer
# shared tables from the SWITCH_ROOT memo) and SNAP_DETACH_FAST (UNMAP_TABLE of an empty table, table by table);
# compat/root-index.h SNAP_ROOT_INDEX (TXM35/36/37 and root constructors without frame-map scans);
# compat/token-costs.h SNAP_OTHER_PROFILE (call_other split by call) and SNAP_GATE_WAIT (a converted call
# waits out a long token hold instead of declining). All need the fast set with --root-cache-wide and
# --service-subclass; NEST_FAST also the memo (installed defaults), GATE_WAIT --fine-locks.
NEST_FAST_DEFINE = '-DSNAP_NEST_FAST=1'
DETACH_FAST_DEFINE = '-DSNAP_DETACH_FAST=1'
ROOT_INDEX_DEFINE = '-DSNAP_ROOT_INDEX=1'
OTHER_PROFILE_DEFINE = '-DSNAP_OTHER_PROFILE=1'
GATE_WAIT_DEFINE = '-DSNAP_GATE_WAIT=1'
# docs/FINE-HW-WALK-20261019.md: compat/fine-lock.h SNAP_FINE_HW, converted MAP_PAGE and UNMAP_REGION on
# hardware-walk roots; needs --fine-locks and --user-hw-walk.
FINE_HW_DEFINE = '-DSNAP_FINE_HW=1'
# compat/fine-lock.h SNAP_FAST_PAUTH_CALLS: SIGN/AUTH_USER_POINTER and BATCH_SIGN_USER_POINTER as converted calls
# (this CPU's signing state only, the gate shared, no stripe) instead of under the service token (v89: 1.66 M
# SIGN calls waited 14.7 s for the token); needs --fine-locks. Appended last: earlier flag orders are unchanged.
FAST_PAUTH_CALLS_DEFINE = '-DSNAP_FAST_PAUTH_CALLS=1'
# docs/GUEST-NETWORK-20261019.md: compat/guest-net-link.h SNAP_GUEST_NET, the guest's paravirtual NIC on the host
# poll (ADRENO_GUEST_NET, q1n1 POLL2); with the launch word net (SNAP_EARLY_STOP) and the net AuxKC below.
GUEST_NET_DEFINE = '-DSNAP_GUEST_NET=1'
# docs/SPEED-BATCH4-20261020.md: SNAP_NATIVE_PACGA, the kernel's PACGA without a trap (the guest GA key in APGAKey
# and HCR_EL2.API for EL1; kernel address keys stay off), and SNAP_FAST_TIMER_IRQ_CPU0, vCPU 0's tick without the
# token while none of its own duties is due (needs --fast-timer-irq). Appended after every earlier flag.
NATIVE_PACGA_DEFINE = '-DSNAP_NATIVE_PACGA=1'
FAST_TIMER_IRQ_CPU0_DEFINE = '-DSNAP_FAST_TIMER_IRQ_CPU0=1'
# Batch 5 (compat/token-trim.h): SNAP_TOKEN_TRIM, the kernel refresh's reuse proof from the table memo's write
# witness and the Adreno DART's MAP/UNMAP as converted calls; needs --variant fast with the installed defaults'
# SNAP_KERNEL_VIEW_REUSE and SNAP_USER_TREE_MEMO, --fine-locks, --fast-pauth-calls, --root-cache-wide and
# --service-subclass. Appended after every earlier flag.
TOKEN_TRIM_DEFINE = '-DSNAP_TOKEN_TRIM=1'
# probes/xnuboot.c SNAP_PAUTH_EL0_LIVE: the EL0 reads --fast-el0-sysreg answers lock-free (SPRR_UPERM, the ordered
# counter alias; installed-fresh-20261020-v3: 112.0M at 938 ns) return to EL0 with the process's PAC bank still
# installed, without the bank leave and enter (compat/pauth-switch.S pauth_switch_live). Needs --variant fast and
# --fast-el0-sysreg. Appended after every earlier flag.
PAUTH_EL0_LIVE_DEFINE = '-DSNAP_PAUTH_EL0_LIVE=1'
# compat/lean-trap.h SNAP_LEAN_TRAPS: fewer and cheaper lock-free sysreg exits. 1: run-ahead over adjacent MRS the
# lock-free path answers (one trap per FAR/ESR or PMC0/PMC1 pair), a division-free counter conversion; 2: also
# FEAT_FGT in place of HCR_EL2.TVM/TRVM, so ESR_EL1/FAR_EL1 reads and CONTEXTIDR_EL1 writes stop trapping (needs
# SCR_EL3.FGTEn, unrecorded). Needs the fast set and --root-cache-wide. Appended after every earlier flag.
LEAN_TRAPS_DEFINE = '-DSNAP_LEAN_TRAPS={}'
# shadow/sprr-view.h SNAP_CLASS_PROOF_WIDE: the kernel class proof's walk limit is the arena's page count instead of
# 8,192 tables (installed-fresh-20261020-v3 stopped when the kernel shadow reached 8,192). Any variant.
CLASS_PROOF_WIDE_DEFINE = '-DSNAP_CLASS_PROOF_WIDE=1'
# Batch 6 (compat/el0-memo.h) SNAP_EL0_MEMO: the lock-free EL0 read answers its instruction fetch from a per-vCPU memo
# of the PC page's translation, kept from an agreeing double read and re-read on every hit (every descriptor of both
# walks, the code frame's type, the word), without the root-cache scan or the repeat read (installed-fresh-20261020-v3:
# 112.0M reads at 938 ns); the user return derives its PAC bank through a 128-entry second level behind the 8-entry
# memo (v3: 1.22M derivations at ~15 us). Needs --pauth-el0-live and --root-cache-wide. Appended after every earlier
# flag.
EL0_MEMO_DEFINE = '-DSNAP_EL0_MEMO=1'
# compat/nest-fast.h 3 SNAP_UNNEST_4K_FAST (docs/UNNEST-4K-FAST-20261020.md): UNNEST_REGION on 4K user roots (the
# kernel-user-4k route) answers nested shared tables and their leaf counts from the SWITCH_ROOT memo, which batch 4's
# SNAP_NEST_FAST does for 16K roots only (v5: 923,675 UNNESTs, 122.9 s of token hold, every table walked). Needs
# --nest-fast. Appended after every earlier flag.
UNNEST_4K_FAST_DEFINE = '-DSNAP_UNNEST_4K_FAST=1'
# Batch 6 (compat/service-lock.h): SNAP_PHASE_FAIR_GATE, a phase-fair L0 gate: a converted call that finds a token
# holder waits for that holder only (installed-fresh-20261020-v5: converted MAP_PAGE waited 524 s at the gate for 63 s
# of hold), and the holder drains only the converted calls that arrived before it. Needs --fine-locks, --fair-token
# (writers keep the token's FIFO) and --gate-wait (the bounded wait that withdraws). Appended after every earlier flag.
PHASE_FAIR_GATE_DEFINE = '-DSNAP_PHASE_FAIR_GATE=1'
# Batch 8 (compat/fine-lock.h): SNAP_FINE_SWITCH_HW, a SWITCH_ROOT to a hardware-walk root whose record already exists
# as a converted call under the old root's and the target's stripes (installed-fresh-20261020-v8: 15.6M such switches
# held the token 126.8 s and waited 243.6 s; SNAP_FINE_SWITCH converts cache hits only, and these roots have none).
# Needs --fine-switch and --user-hw-walk. Appended after every earlier flag.
FINE_SWITCH_HW_DEFINE = '-DSNAP_FINE_SWITCH_HW=1'
# Batch 9 (compat/dart-converted.h): SNAP_DART_CONVERTED, the Adreno DART's MAP/UNMAP as converted calls (gate shared,
# a device lock) instead of the service token: batch 5's --token-trim part B on its own, without its kernel-view
# witness (installed-fresh-20261020-v9: 3.85M DART maps held the token 49.3 s and waited 87.7 s). Needs --variant fast,
# --fine-locks and --fast-pauth-calls; refused with --token-trim (which converts the same calls). Appended after every
# earlier flag.
DART_CONVERTED_DEFINE = '-DSNAP_DART_CONVERTED=1'
# agents/sptm-locks (compat/fine-lock.h): SNAP_SPTM_FINE converts user UNMAP_DISJOINT and UPDATE_REGION and the
# hardware-walk update events; SNAP_SPTM_FINE_RETYPE adds private frame locks and the page-table frame lifecycle
# RETYPEs; SNAP_SPTM_FINE_KERNEL the kernel root's MAP_PAGE and UNMAP_REGION outside the kernel views' copy sources.
# Each needs the one before it; SNAP_SPTM_FINE needs --fine-locks, --fine-hw and --user-hw-walk. Appended after every
# earlier flag.
SPTM_FINE_DEFINE = '-DSNAP_SPTM_FINE=1'
SPTM_FINE_RETYPE_DEFINE = '-DSNAP_SPTM_FINE_RETYPE=1'
SPTM_FINE_KERNEL_DEFINE = '-DSNAP_SPTM_FINE_KERNEL=1'
# compat/audit-sparse.h SNAP_AUDIT_SPARSE: four sampled self-audits under the service token (the TPRO class-proof hit
# verification, ~7 ms each; the kernel refresh's reuse-hit verification; the exact kernel-variant swap and PPERM-reuse
# skip verifications) run 1 in 1024 events instead of 1 in 64 (installed-fresh-neon-20261021-v2: about 58 s of the
# 264.6 s token hold, and the multi-ms holds behind its 15,035 gate timeouts). A weaker audit accepted for speed.
# Needs --variant fast and --kernel-pperm-fast (with the installed defaults' view reuse, PPERM reuse and variants).
# Appended after every earlier flag.
AUDIT_SPARSE_DEFINE = '-DSNAP_AUDIT_SPARSE=1'
# shadow/sprr-reuse.h SNAP_REUSE_MATCH_MAPPED: the kernel refresh's exact reuse proof reads each copied source table
# through class_table_read and compares it in one pass instead of one kernel_table_read callback per word (neon-v2:
# 797,113 reuse hits, 41.1 s of nested token hold with the 1-in-64 verification; host 71 -> 13 us per proof). Same
# verdicts. Needs SNAP_KERNEL_VIEW_REUSE and SNAP_CLASS_PROOF_MAPPED (the installed defaults); not with --token-trim.
# Appended after every earlier flag.
REUSE_MATCH_MAPPED_DEFINE = '-DSNAP_REUSE_MATCH_MAPPED=1'
# probes/xnuboot.c SNAP_EL0_WFE: SCTLR_EL1.nTWE in the installed SCTLR_EL1, as 26A428's SPTM installs it. Without it
# every EL0 WFE traps to EL1 and XNU's handle_wf_trap raises SIGILL: launchd died there (libdispatch
# _dispatch_wait_for_enqueuer+12) in installed-fresh-20261017-v41, -20261019-v88, -20261020-v16 and
# -desktop-20261021-v1. Any variant. Appended after every earlier flag.
EL0_WFE_DEFINE = '-DSNAP_EL0_WFE=1'
# probes/xnuboot.c SNAP_EL0_CACHE_MAINT: SCTLR_EL1.UCI, the other EL0 permission SPTM grants: EL0 DC CVAU/CVAC/CIVAC
# and IC IVAU (sys_icache_invalidate) no longer trap to EL1, where handle_msr_trap raises SIGILL. Any variant.
# Appended after every earlier flag.
EL0_CACHE_MAINT_DEFINE = '-DSNAP_EL0_CACHE_MAINT=1'
# compat/user-crash.h SNAP_USER_CRASH_WIDE: the crash ring also records the EL0 classes XNU turns into SIGILL, SIGFPE
# or a panic that it missed (0x01 WFI/WFE among them: launchd's SIGILL left no row), each exception row with its
# instruction word. Needs SNAP_USER_CRASH_RING (the base recipe's). Appended after every earlier flag.
USER_CRASH_WIDE_DEFINE = '-DSNAP_USER_CRASH_WIDE=1'
# compat/pmu-rtc.h SNAP_SPMI_SCRATCH: the PMU scratch-pad registers the guest's AppleDialogSPMIPMU polls are served from
# 384 bytes of RAM instead of refused (b11v1: 22-27% of console bytes were its retries and parity errors). Any variant.
# Appended after every earlier flag.
SPMI_SCRATCH_DEFINE = '-DSNAP_SPMI_SCRATCH=1'
# compat/adreno-ib.h SNAP_ADRENO_IB_ASYNC: ADRENO_GUEST_IB_START (0x00010008) and ADRENO_GUEST_IB_POLL (0x00010009). The
# synchronous ADRENO_GUEST_IB busy-polls the GPU at EL2 inside the global service token, so every other vCPU's locked
# traps wait for the GPU (v14: GPU calls held the token 613 s of 1,800 s; 68-190 ms single holds). START rings the IB and
# spins at most 20 us; POLL is one completion pass; the guest waits between them. The flight lives in monitor arena
# pages (root_ext, so --root-cache-wide) and is reported behind IBASYNC1 (tools/perf_counters.py decode_ib_async).
# Without an ADRENO_IB_ASYNC kext nothing calls them. Failure modes: agents/async-ib/FAILURE-MODES.md. Any variant.
# Appended after every earlier flag.
IB_ASYNC_DEFINE = '-DSNAP_ADRENO_IB_ASYNC=1'
# agents/gpu-x290 (FAILURE-MODES.md F1-F10; turnip-audit FINDINGS item 3). The ring is in CP_THREAD_CONTROL(BOTH) after
# every IB, so FILL32 and the fences (compat/adreno-fill.c, compat/adreno.c fence_at) run their CP_MEM_WRITEs on both CP
# threads, and FILL32 counts as done when its marker lands, without RBBM idle. SNAP_ADRENO_FILL_BR (--adreno-fill-br):
# CP_THREAD_CONTROL(BR | SYNC_THREADS), the fill, CP_WAIT_MEM_WRITES, the marker, CP_THREAD_CONTROL(BOTH); completion
# also needs RBBM idle. SNAP_ADRENO_FENCE_BR (--adreno-fence-br): the same for the fences, with CP_WAIT_FOR_IDLE before
# the write. Any variant. Appended after every earlier flag; off, the monitor is byte-identical.
ADRENO_FILL_BR_DEFINE = '-DSNAP_ADRENO_FILL_BR=1'
ADRENO_FENCE_BR_DEFINE = '-DSNAP_ADRENO_FENCE_BR=1'
# agents/nvme-async (FAILURE-MODES.md). b12v5: the virtual ANS2's doorbell submitted to the SSD and busy-polled it under
# the service token (207k commands, 36.8 s of hold, mean 177.5 us), and every other vCPU's trap waited behind it.
# SNAP_ANS_ASYNC (--nvme-async): the doorbell queues the command and the SSD command is reaped without waiting, at later
# ANS accesses and at the owning vCPU's EL2 deadline (compat/ans.h); needs --root-cache-wide. SNAP_ANS_CONVERTED
# (--nvme-converted): the I/O doorbells and table-6 MAP/UNMAP_PAGES as converted calls under an ANS device lock
# (fine profile bit 4); needs --nvme-async, --variant fast and --fine-locks. SNAP_ATTR_CLEAN_DEFER (--attr-clean-defer):
# the second cache clean of an attribute change after the token is released (UPDATE_DISJOINT_MULTIPAGE held the token up
# to 82.5 ms); needs --root-cache-wide. Appended after every earlier flag.
ANS_ASYNC_DEFINE = '-DSNAP_ANS_ASYNC=1'
ANS_CONVERTED_DEFINE = '-DSNAP_ANS_CONVERTED=1'
ATTR_CLEAN_DEFER_DEFINE = '-DSNAP_ATTR_CLEAN_DEFER=1'
# agents/sptm-locks/multipage (FAILURE-MODES.md P1-P18): SNAP_MULTIPAGE_FAST (--multipage-fast). b12v16:
# UPDATE_DISJOINT_MULTIPAGE held the token 7.79 ms per call (14,880 calls, 116 s; max 118.5 ms), 82 % of it full
# kernel-view re-syncs (a changed aperture leaf in a copied table) and 12 % reuse proofs, one per frame. The aperture
# steps' first cleans run before the token is taken, a same-class AttrIndx change skips both cleans, a changed word of
# a copied table is patched into the copies and the reuse snapshot, and a run of headers is published, refreshed and
# invalidated once. Needs --attr-clean-defer (the second clean off the token) and --root-cache-wide; refused with
# --token-trim. Appended after every earlier flag.
MULTIPAGE_FAST_DEFINE = '-DSNAP_MULTIPAGE_FAST=1'
# SNAP_ADRENO_COHERENT (--gpu-coherent). b12v19/b12v20 spend about
# 16.7 ms of CPU cache maintenance per IB (214 MiB with cache-sparse). At prepare the monitor proves, with CP_MEMCPY
# jobs of at most 1 MiB in both directions (and non-coherent controls first), that GPU accesses through AttrIndx 1 /
# SH IS leaves snoop the CPU's caches; only then are CB0's mirror leaves IO-coherent, and ADRENO_GUEST_COHERENT tells
# the kext so. Its state is in root_ext (--root-cache-wide); its scratch is the q1n1 arena's Stage 4 pool region,
# free only with --gpu-va-wide. The guest boot-arg adreno_coherent=1 opts the kext in. Appended after every earlier
# flag.
GPU_COHERENT_DEFINE = '-DSNAP_ADRENO_COHERENT=1'
# --gpu-coherent-force: debug only, an A/B rendering check of skipped maintenance before the self-test can prove
# anything. The monitor reports ON with ADRENO_COHERENT_DETAIL_FORCED and runs no job; the kext accepts that only with
# its own boot-arg adreno_coherent_force=1. Appended after GPU_COHERENT_DEFINE.
GPU_COHERENT_FORCE_DEFINE = '-DSNAP_ADRENO_COHERENT_FORCE=1'
# --edp-backlight (agents/brightness): compat/edp-backlight.h SNAP_EDP_BACKLIGHT, ADRENO_GUEST_BACKLIGHT QUERY/SET of the
# panel's DPCD backlight level over the eDP controller's AUX channel. Only the AUX transport registers and DPCD
# 0x721-0x723 are written, the level is clamped to [10% of full scale, the panel's maximum], and any failure leaves the
# brightness as it was. The kext half is INPUT_AUXKC_DESKTOP_BACKLIGHT and the guest boot-arg adreno_backlight=1 the
# flag adds. Monitor define only (no loader change). Appended after every earlier flag; off, the monitor is
# byte-identical.
EDP_BACKLIGHT_DEFINE = '-DSNAP_EDP_BACKLIGHT=1'
# --view-reclaim (agents/view-reclaim): shadow/sprr-view.h SNAP_VIEW_RECLAIM, a 256-table kernel view pool and the
# reclaim of copies no protected leaf needs when a protecting RETYPE finds it full (next1 stopped at 128, exit 7).
# Monitor define only (no loader change). Appended after every earlier flag; off, the monitor is byte-identical.
VIEW_RECLAIM_DEFINE = '-DSNAP_VIEW_RECLAIM=1'
# agents/dvfs (FAILURE-MODES.md): opt-in governors on vCPU 0's locked tick, state at the end of root_ext (so
# --root-cache-wide), report DVFSREP1 after the thermal record, restored at the stop; both need --thermal-guard (they
# never write without the guard's readings). compat/cpu-dvfs.h SNAP_CPU_DVFS: SCMI PERF LEVEL_SET fastchannels of the
# PDP domains that host vCPUs, from the EL2 tick's WFI classification (needs --wfi-resume), floor = firmware's boot
# level, ceiling = the sustained (highest non-boost) level or --cpu-dvfs-ceiling. compat/gpu-dvfs.h SNAP_GPU_DVFS: HFI
# GX_BW_PERF_VOTE between OPP 1 (310 MHz) and OPP 6 (915 MHz, the approved mid OPP) from the monitor's own IB
# times (race to idle, votes also while an async IB is in flight unless --gpu-dvfs-defer); the hfi step lists six
# OPPs and still starts at OPP 1. Appended after every earlier flag.
# agents/gpu-recovery (FAILURE-MODES.md R1-R30). b12v13: one IB past the 1 s budget latched the GPU off for the boot
# (127k failed submissions). compat/adreno-ib.h SNAP_ADRENO_RECOVER (--gpu-recover soft|reset, needs --ib-async): 1 the
# budget becomes soft up to ADRENO_IB_HARD_SECONDS (--ib-hard-seconds, default 3) and ADRENO_GUEST_RECOVER QUERY/SETTLE
# un-latch an ADRENO_GPU_RECOVER kext once the GPU is proven idle; 2 also the CP soft reset at EL2 (q1n1's hw_init
# replayed from compat/adreno-recover-table.h, which prepare checks against the cp-fence steps and q1n1's sources).
# Appended after every earlier flag; off, the monitor is byte-identical.
GPU_RECOVER_DEFINE = '-DSNAP_ADRENO_RECOVER={}'
IB_HARD_SECONDS_DEFINE = '-DADRENO_IB_HARD_SECONDS={}u'
GPU_RECOVER_LEVELS = {'soft': 1, 'reset': 2}
RECOVER_TABLE = 'compat/adreno-recover-table.h'
CPU_DVFS_DEFINE = '-DSNAP_CPU_DVFS=1'
CPU_DVFS_CEILING_DEFINE = '-DSNAP_CPU_DVFS_CEILING={}'
GPU_DVFS_DEFINE = '-DSNAP_GPU_DVFS=1'
GPU_DVFS_DEFER_DEFINE = '-DSNAP_GPU_DVFS_MIDFLIGHT=0'
GPU_DVFS_HOLD_DEFINE = '-DSNAP_GPU_DVFS_HOLD_MS={}'


def selected(args):
    """(profile, AuxKC, its pinned SHA-256, its bundles): the default route, or --input's; with --qcc2072-wifi
    the same route's input collection relinked with SnapintoshQCC2072 (tools/build-qcc2072-native.py)."""
    profile, aux, aux_sha, bundles = route_selected(args)
    if not getattr(args, 'qcc2072_wifi', False):
        need(not getattr(args, 'qcc2072_auxkc', None) and not getattr(args, 'qcc2072_auxkc_sha256', None),
             '--qcc2072-auxkc/--qcc2072-auxkc-sha256 need --qcc2072-wifi')
        return profile, aux, aux_sha, bundles
    need(getattr(args, 'input', False), '--qcc2072-wifi needs --input (its collection is the input route\'s, relinked)')
    folder, want = getattr(args, 'qcc2072_auxkc', None), getattr(args, 'qcc2072_auxkc_sha256', None)
    need(folder and want, '--qcc2072-wifi needs --qcc2072-auxkc DIR (tools/build-qcc2072-native.py --output DIR '
                          f'--baseline {Path(aux).parent} --expected-baseline-sha256 {aux_sha}) and '
                          '--qcc2072-auxkc-sha256 (its native-wifi.kc)')
    folder = Path(folder).resolve()
    receipt = json.loads((folder / 'build.json').read_text())
    want_bundles = sorted([*bundles, QCC2072_BUNDLE])
    need(receipt.get('status') == QCC2072_AUXKC_STATUS, f'{folder}: not a completed native Wi-Fi link')
    need(receipt.get('baseline_collection_sha256') == aux_sha,
         f'{folder}: linked over {receipt.get("baseline_collection_sha256")}, not this route\'s {aux_sha} ({aux})')
    need(receipt.get('bundle_identifiers') == want_bundles, f'{folder}: bundles differ from {want_bundles}')
    kc = folder / 'native-wifi.kc'
    need((receipt.get('outputs') or {}).get('native-wifi.kc') == want and st.file_sha(kc) == want,
         f'{kc} is not the --qcc2072-auxkc-sha256 collection its receipt records')
    return profile, str(kc), want, want_bundles


def route_selected(args):
    """(profile, AuxKC, its pinned SHA-256, its bundles): the default route, or --input's."""
    touchpad = getattr(args, 'input_touchpad', False)
    need(not touchpad or getattr(args, 'input', False), '--input-touchpad needs --input')
    damage = getattr(args, 'present_damage', False)
    cached = getattr(args, 'present_cached_read', False)
    gpumap = getattr(args, 'present_gpumap', False)
    vsync60 = getattr(args, 'present_vsync60', False)
    dartpool = getattr(args, 'present_dartpool', False)
    ptp = getattr(args, 'input_ptp', False)
    need(not ptp or (getattr(args, 'input', False) and touchpad),
         '--input-ptp needs --input --input-touchpad (it drives the touchpad node)')
    need(not (ptp and (damage or cached or gpumap or vsync60)),
         '--input-ptp already includes --present-vsync60\'s AdrenoX2 (and so --present-gpumap\'s), or with '
         '--present-dartpool that one\'s: give one of them')
    need(not damage or getattr(args, 'input', False), '--present-damage needs --input (its AdrenoX2 is in the input AuxKC)')
    need(not cached or getattr(args, 'input', False),
         '--present-cached-read needs --input (its AdrenoX2 is in the input AuxKC)')
    need(not gpumap or getattr(args, 'input', False), '--present-gpumap needs --input (its AdrenoX2 is in the input AuxKC)')
    need(not vsync60 or getattr(args, 'input', False), '--present-vsync60 needs --input (its AdrenoX2 is in the input AuxKC)')
    need(not dartpool or getattr(args, 'input', False),
         '--present-dartpool needs --input (its AdrenoX2 is in the input AuxKC)')
    need(not (dartpool and (damage or cached or gpumap or vsync60)),
         '--present-dartpool already includes --present-vsync60\'s (and so --present-gpumap\'s) kext: give one of them')
    resident = getattr(args, 'present_resident', False)
    need(not resident or (dartpool and ptp),
         '--present-resident needs --present-dartpool --input-ptp (it is that collection with residency and the perf '
         'gpu line)')
    beam = getattr(args, 'present_beam', False)
    need(not beam or resident,
         '--present-beam needs --present-resident --present-dartpool --input-ptp (its AdrenoX2 extends that collection)')
    va_reclaim = getattr(args, 'present_va_reclaim', False)
    need(not va_reclaim or beam,
         '--present-va-reclaim needs --present-beam --present-resident --present-dartpool --input-ptp (its AdrenoX2 '
         'extends that collection)')
    va_wide = getattr(args, 'gpu_va_wide', False)
    need(not va_wide or va_reclaim,
         '--gpu-va-wide needs --present-va-reclaim --present-beam --present-resident --present-dartpool --input-ptp (its '
         'AdrenoX2 is that collection\'s with ADRENO_VA_WIDE)')
    latch = getattr(args, 'present_latch', False)
    need(not latch or va_wide,
         '--present-latch needs --gpu-va-wide and its chain (its AdrenoX2 is that collection\'s with ADRENO_LATCH, its '
         'SnapI2CHID stage B with SNAP_I2C_HID_LATENCY)')
    edp_backlight = getattr(args, 'edp_backlight', False)
    need(not edp_backlight or latch,
         '--edp-backlight needs --present-latch and its chain (its AdrenoX2 is that collection\'s with ADRENO_BACKLIGHT)')
    early = getattr(args, 'present_early_done', None)
    need(early is None or edp_backlight,
         '--present-early-done needs --edp-backlight and its chain (its AdrenoX2 is the early-done collection)')
    need(not (vsync60 and (damage or cached or gpumap)),
         '--present-vsync60 already includes --present-gpumap\'s (and so --present-cached-read\'s) kext: give one of them')
    need(not (damage and cached), '--present-cached-read already includes --present-damage\'s present: give one of them')
    need(not (gpumap and (damage or cached)),
         '--present-gpumap already includes --present-cached-read\'s (and --present-damage\'s) present: give one of them')
    if getattr(args, 'input', False):
        if getattr(args, 'guest_net', False):
            need(not damage and not cached and not gpumap and not vsync60 and not dartpool and not ptp,
                 '--present-damage/--present-cached-read/--present-gpumap/--present-vsync60/--present-dartpool/'
                 '--input-ptp and --guest-net each select their own input AuxKC')
            need(INPUT_AUXKC_NET is not None, '--guest-net: no net AuxKC is pinned yet (INPUT_AUXKC_NET)')
            return ((INPUT_TOUCHPAD_PROFILE if touchpad else INPUT_PROFILE), INPUT_AUXKC_NET, INPUT_AUXKC_NET_SHA,
                    INPUT_BUNDLES)
        if damage:
            return ((INPUT_TOUCHPAD_PROFILE if touchpad else INPUT_PROFILE), INPUT_AUXKC_DAMAGE,
                    INPUT_AUXKC_DAMAGE_SHA, INPUT_BUNDLES)
        if cached:
            return ((INPUT_TOUCHPAD_PROFILE if touchpad else INPUT_PROFILE), INPUT_AUXKC_CACHED_READ,
                    INPUT_AUXKC_CACHED_READ_SHA, INPUT_BUNDLES)
        if gpumap:
            return ((INPUT_TOUCHPAD_PROFILE if touchpad else INPUT_PROFILE), INPUT_AUXKC_GPUMAP,
                    INPUT_AUXKC_GPUMAP_SHA, INPUT_BUNDLES)
        if vsync60:
            return ((INPUT_TOUCHPAD_PROFILE if touchpad else INPUT_PROFILE), INPUT_AUXKC_VSYNC60,
                    INPUT_AUXKC_VSYNC60_SHA, INPUT_BUNDLES)
        if dartpool and ptp and resident and beam and va_reclaim and va_wide and latch and edp_backlight and (
                getattr(args, 'gpu_coherent', False) or early is not None):
            need(INPUT_AUXKC_DESKTOP_EARLY_DONE is not None and INPUT_AUXKC_DESKTOP_EARLY_DONE_SHA is not None,
                 '--edp-backlight with --gpu-coherent or --present-early-done: its AuxKC is not pinned yet '
                 '(INPUT_AUXKC_DESKTOP_EARLY_DONE_SHA; KEXT_PROFILE=desktop-early-done I2C_PROFILE=desktop-fnkeys '
                 'tools/build-auxkc-desktop.sh NAME links it)')
            return (INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_DESKTOP_EARLY_DONE, INPUT_AUXKC_DESKTOP_EARLY_DONE_SHA,
                    INPUT_BUNDLES)
        if dartpool and ptp and resident and beam and va_reclaim and va_wide and latch and edp_backlight:
            need(INPUT_AUXKC_DESKTOP_BACKLIGHT is not None and INPUT_AUXKC_DESKTOP_BACKLIGHT_SHA is not None,
                 '--edp-backlight: its AuxKC is not pinned yet (INPUT_AUXKC_DESKTOP_BACKLIGHT_SHA; '
                 'KEXT_PROFILE=desktop-backlight tools/build-auxkc-desktop.sh NAME links it)')
            return (INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_DESKTOP_BACKLIGHT, INPUT_AUXKC_DESKTOP_BACKLIGHT_SHA,
                    INPUT_BUNDLES)
        if dartpool and ptp and resident and beam and va_reclaim and va_wide and latch:
            need(INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH is not None and
                 INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH_SHA is not None,
                 '--present-latch: its AuxKC is not pinned yet (INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH_SHA; '
                 'agents/input-latency/LATENCY-BUDGET.md section 7 links it)')
            return (INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH,
                    INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH_SHA, INPUT_BUNDLES)
        if dartpool and ptp and resident and beam and va_reclaim and va_wide:
            need(INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE is not None and
                 INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_SHA is not None,
                 '--gpu-va-wide: its AuxKC is not pinned yet (INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_SHA; '
                 'agents/gpu-va-wide/HARDWARE-STEPS.md links it)')
            return (INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE,
                    INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_SHA, INPUT_BUNDLES)
        if dartpool and ptp and resident and beam and va_reclaim:
            need(INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA is not None and
                 INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_SHA is not None,
                 '--present-va-reclaim: its AuxKC is not pinned yet (INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_SHA)')
            return (INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA,
                    INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_SHA, INPUT_BUNDLES)
        if dartpool and ptp and resident and beam:
            need(INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_SHA is not None,
                 '--present-beam: its AuxKC is not pinned yet (INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_SHA)')
            return (INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM,
                    INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_SHA, INPUT_BUNDLES)
        if dartpool and ptp and resident:
            need(INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_SHA is not None,
                 '--present-resident: its AuxKC is not pinned yet (INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_SHA)')
            return (INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_PTP_DARTPOOL_RESIDENT, INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_SHA,
                    INPUT_BUNDLES)
        if dartpool and ptp:
            return INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_PTP_DARTPOOL, INPUT_AUXKC_PTP_DARTPOOL_SHA, INPUT_BUNDLES
        if dartpool:
            return ((INPUT_TOUCHPAD_PROFILE if touchpad else INPUT_PROFILE), INPUT_AUXKC_DARTPOOL,
                    INPUT_AUXKC_DARTPOOL_SHA, INPUT_BUNDLES)
        if ptp:
            need(INPUT_AUXKC_PTP_SHA is not None, '--input-ptp: its AuxKC is not pinned yet (INPUT_AUXKC_PTP_SHA)')
            return INPUT_TOUCHPAD_PROFILE, INPUT_AUXKC_PTP, INPUT_AUXKC_PTP_SHA, INPUT_BUNDLES
        return (INPUT_TOUCHPAD_PROFILE if touchpad else INPUT_PROFILE), INPUT_AUXKC, INPUT_AUXKC_SHA, INPUT_BUNDLES
    return PROFILE, AUXKC, AUXKC_SHA, [KEXT_BUNDLE]


def variant_flags(sets, args, variant=None):
    variant = variant or args.variant
    flags = list(sets[variant])
    if getattr(args, 'wfi_resume', False):
        flags.append(WFI_RESUME_DEFINE)
    if getattr(args, 'fast_timer_irq', False):
        need(variant == 'fast' and '-DSNAP_FAST_VCPU_TRAPS=1' in flags and '-DSNAP_FAST_TIMER_WRITE=1' in flags and
             getattr(args, 'root_cache_wide', False) and getattr(args, 'service_subclass', False),
             '--fast-timer-irq needs --variant fast (SNAP_FAST_VCPU_TRAPS, SNAP_FAST_TIMER_WRITE), --root-cache-wide '
             'and --service-subclass')
        flags.append(FAST_TIMER_IRQ_DEFINE)
    if getattr(args, 'dart_memo', False):
        need(getattr(args, 'root_cache_wide', False), '--dart-memo needs --root-cache-wide')
        flags.append(DART_MEMO_DEFINE)
    if getattr(args, 'aes_bitslice', False):
        flags.append(AES_BITSLICE_DEFINE)
    if getattr(args, 'fast_ipi', False):
        need(variant == 'fast' and '-DSNAP_FAST_VCPU_TRAPS=1' in flags and getattr(args, 'root_cache_wide', False),
             '--fast-ipi needs --variant fast (SNAP_FAST_VCPU_TRAPS) and --root-cache-wide')
        flags.append(FAST_IPI_DEFINE)
    if getattr(args, 'fast_el0_sysreg', False):
        need(variant == 'fast', '--fast-el0-sysreg needs --variant fast')
        flags.append(FAST_EL0_SYSREG_DEFINE)
    if getattr(args, 'service_subclass', False):
        flags.append(SERVICE_SUBCLASS_DEFINE)
    if getattr(args, 'dart_wiredcnt', False):
        flags.append(DART_WIREDCNT_DEFINE)
    if getattr(args, 'panic_serve', False):
        flags.append(PANIC_SERVE_DEFINE)
    if getattr(args, 'root_miss_fast', False):
        flags.append(ROOT_MISS_FAST_DEFINE)
    if getattr(args, 'update_disjoint_fast', False):
        flags.append(UPDATE_DISJOINT_FAST_DEFINE)
    if getattr(args, 'root_cache_wide', False):
        flags.append(ROOT_CACHE_WIDE_DEFINE)
    if getattr(args, 'update_check_sparse', False):
        flags.append(UPDATE_CHECK_SPARSE_DEFINE)
    if getattr(args, 'input', False):
        flags.append(INPUT_DEFINE)
    if getattr(args, 'kernel_pperm_fast', False):
        flags.append(KERNEL_PPERM_FAST_DEFINE)
    if getattr(args, 'ib_budget_1s', False):
        flags.append(IB_BUDGET_1S_DEFINE)
    if getattr(args, 'unmap_mixed', False):
        flags.append(UNMAP_MIXED_DEFINE)
    if getattr(args, 'prime_secondaries', False):
        flags.append(BOOT_RELOCATE_DEFINE)
    if getattr(args, 'txm_aspace_wide', False):
        flags.append(TXM_ASPACE_WIDE_DEFINE)
    if getattr(args, 'fine_locks', False) or getattr(args, 'fine_switch', False):
        need(variant == 'fast' and getattr(args, 'root_cache_wide', False) and
             getattr(args, 'update_disjoint_fast', False) and getattr(args, 'service_subclass', False),
             '--fine-locks/--fine-switch need --variant fast, --root-cache-wide, --update-disjoint-fast and '
             '--service-subclass')
        flags.append(FINE_LOCKS_DEFINE)
    if getattr(args, 'fine_switch', False):
        flags.append(FINE_SWITCH_DEFINE)
    if getattr(args, 'fair_token', False):
        flags.append(FAIR_TOKEN_DEFINE)
    if getattr(args, 'user_hw_walk', False):
        flags.append(USER_HW_WALK_DEFINE)
    if getattr(args, 'fine_hw', False):
        need(getattr(args, 'fine_locks', False) and getattr(args, 'user_hw_walk', False),
             '--fine-hw needs --fine-locks and --user-hw-walk')
        flags.append(FINE_HW_DEFINE)
    if getattr(args, 'idreg_mmfr3', False):
        flags.append(IDREG_MMFR3_DEFINE)
    if getattr(args, 's2_fault_retry', False):
        flags.append(S2_FAULT_RETRY_DEFINE)
    if getattr(args, 's2_fault_retry_stage1', False):
        need(getattr(args, 's2_fault_retry', False), '--s2-fault-retry-stage1 needs --s2-fault-retry')
        flags.append(S2_FAULT_RETRY_STAGE1_DEFINE)
    costs = [(name, define) for name, define in (('nest_fast', NEST_FAST_DEFINE), ('detach_fast', DETACH_FAST_DEFINE),
                                                ('root_index', ROOT_INDEX_DEFINE),
                                                ('other_profile', OTHER_PROFILE_DEFINE),
                                                ('gate_wait', GATE_WAIT_DEFINE))
             if getattr(args, name, False)]
    if costs:
        need(variant == 'fast' and getattr(args, 'root_cache_wide', False) and getattr(args, 'service_subclass', False),
             '--nest-fast/--detach-fast/--root-index/--other-profile/--gate-wait need --variant fast, '
             '--root-cache-wide and --service-subclass')
        need(not getattr(args, 'gate_wait', False) or getattr(args, 'fine_locks', False),
             '--gate-wait needs --fine-locks')
        flags.extend(define for _, define in costs)
    if getattr(args, 'fast_pauth_calls', False):
        need(getattr(args, 'fine_locks', False), '--fast-pauth-calls needs --fine-locks')
        flags.append(FAST_PAUTH_CALLS_DEFINE)
    if getattr(args, 'guest_net', False):
        # Appended last, so every earlier flag order is unchanged.
        need(getattr(args, 'input', False), '--guest-net needs --input (its NIC is in the input AuxKC)')
        flags.append(GUEST_NET_DEFINE)
    if getattr(args, 'fast_timer_irq_cpu0', False):
        need(getattr(args, 'fast_timer_irq', False), '--fast-timer-irq-cpu0 needs --fast-timer-irq')
        flags.append(FAST_TIMER_IRQ_CPU0_DEFINE)
    if getattr(args, 'native_pacga', False):
        flags.append(NATIVE_PACGA_DEFINE)
    if getattr(args, 'token_trim', False):
        need(variant == 'fast' and '-DSNAP_KERNEL_VIEW_REUSE=1' in flags and '-DSNAP_USER_TREE_MEMO=1' in flags and
             getattr(args, 'fine_locks', False) and getattr(args, 'fast_pauth_calls', False) and
             getattr(args, 'root_cache_wide', False) and getattr(args, 'service_subclass', False),
             '--token-trim needs --variant fast (SNAP_KERNEL_VIEW_REUSE, SNAP_USER_TREE_MEMO), --fine-locks, '
             '--fast-pauth-calls, --root-cache-wide and --service-subclass')
        flags.append(TOKEN_TRIM_DEFINE)
    if getattr(args, 'pauth_el0_live', False):
        need(variant == 'fast' and '-DSNAP_FAST_CROSSINGS=1' in flags and FAST_EL0_SYSREG_DEFINE in flags,
             '--pauth-el0-live needs --variant fast (SNAP_FAST_CROSSINGS) and --fast-el0-sysreg')
        flags.append(PAUTH_EL0_LIVE_DEFINE)
    lean = getattr(args, 'lean_traps', None)
    if lean:
        need(lean in (1, 2), '--lean-traps is 1 (run-ahead, cheaper exits) or 2 (also FEAT_FGT)')
        need(variant == 'fast' and '-DSNAP_FAST_VCPU_TRAPS=1' in flags and getattr(args, 'root_cache_wide', False),
             '--lean-traps needs --variant fast (SNAP_FAST_VCPU_TRAPS) and --root-cache-wide')
        flags.append(LEAN_TRAPS_DEFINE.format(lean))
    if getattr(args, 'class_proof_wide', False):
        flags.append(CLASS_PROOF_WIDE_DEFINE)
    if getattr(args, 'el0_memo', False):
        need(PAUTH_EL0_LIVE_DEFINE in flags and getattr(args, 'root_cache_wide', False),
             '--el0-memo needs --pauth-el0-live and --root-cache-wide')
        flags.append(EL0_MEMO_DEFINE)
    if getattr(args, 'unnest_4k_fast', False):
        need(NEST_FAST_DEFINE in flags and '-DSNAP_ROOT_VALIDATE_MEMO=1' in flags,
             '--unnest-4k-fast needs --nest-fast (and its SWITCH_ROOT memo, SNAP_ROOT_VALIDATE_MEMO)')
        flags.append(UNNEST_4K_FAST_DEFINE)
    if getattr(args, 'phase_fair_gate', False):
        need(getattr(args, 'fine_locks', False) and getattr(args, 'fair_token', False) and
             getattr(args, 'gate_wait', False),
             '--phase-fair-gate needs --fine-locks, --fair-token and --gate-wait')
        flags.append(PHASE_FAIR_GATE_DEFINE)
    if getattr(args, 'fine_switch_hw', False):
        need(getattr(args, 'fine_switch', False) and getattr(args, 'user_hw_walk', False),
             '--fine-switch-hw needs --fine-switch and --user-hw-walk')
        flags.append(FINE_SWITCH_HW_DEFINE)
    if getattr(args, 'dart_converted', False):
        need(variant == 'fast' and getattr(args, 'fine_locks', False) and getattr(args, 'fast_pauth_calls', False),
             '--dart-converted needs --variant fast, --fine-locks and --fast-pauth-calls')
        need(not getattr(args, 'token_trim', False),
             '--dart-converted and --token-trim convert the same Adreno DART calls (--token-trim\'s part B): give one')
        flags.append(DART_CONVERTED_DEFINE)
    if getattr(args, 'audit_sparse', False):
        need(variant == 'fast' and KERNEL_PPERM_FAST_DEFINE in flags and '-DSNAP_KERNEL_VIEW_REUSE=1' in flags and
             '-DSNAP_KERNEL_PPERM_REUSE=1' in flags and '-DSNAP_KERNEL_PPERM_VARIANTS=1' in flags,
             '--audit-sparse needs --variant fast and --kernel-pperm-fast (SNAP_KERNEL_VIEW_REUSE, '
             'SNAP_KERNEL_PPERM_REUSE, SNAP_KERNEL_PPERM_VARIANTS)')
        flags.append(AUDIT_SPARSE_DEFINE)
    if getattr(args, 'reuse_match_mapped', False):
        need('-DSNAP_KERNEL_VIEW_REUSE=1' in flags and '-DSNAP_CLASS_PROOF_MAPPED=1' in flags,
             '--reuse-match-mapped needs SNAP_KERNEL_VIEW_REUSE and SNAP_CLASS_PROOF_MAPPED')
        need(not getattr(args, 'token_trim', False),
             '--reuse-match-mapped and --token-trim answer the same kernel reuse proof: give one')
        flags.append(REUSE_MATCH_MAPPED_DEFINE)
    if getattr(args, 'qcc2072_wifi', False):
        # Appended after every earlier flag; the loader half is SNAP_QCC2072_WIFI (environment()).
        need(getattr(args, 'input', False), '--qcc2072-wifi needs --input')
        flags.append(QCC2072_WIFI_DEFINE)
    if getattr(args, 'el0_wfe', False):
        flags.append(EL0_WFE_DEFINE)
    if getattr(args, 'el0_cache_maint', False):
        flags.append(EL0_CACHE_MAINT_DEFINE)
    if getattr(args, 'user_crash_wide', False):
        need('-DSNAP_USER_CRASH_RING=1' in flags, '--user-crash-wide needs the crash ring (SNAP_USER_CRASH_RING)')
        flags.append(USER_CRASH_WIDE_DEFINE)
    if getattr(args, 'spmi_scratch', False):
        flags.append(SPMI_SCRATCH_DEFINE)
    if getattr(args, 'ib_async', False):
        need(getattr(args, 'root_cache_wide', False),
             '--ib-async needs --root-cache-wide (the flight lives in root_ext\'s monitor arena pages)')
        flags.append(IB_ASYNC_DEFINE)
    recover, hard = getattr(args, 'gpu_recover', None), getattr(args, 'ib_hard_seconds', None)
    need(hard is None or recover, '--ib-hard-seconds needs --gpu-recover')
    if recover:
        need(getattr(args, 'ib_async', False), '--gpu-recover needs --ib-async (it ends asynchronous IB flights)')
        flags.append(GPU_RECOVER_DEFINE.format(GPU_RECOVER_LEVELS[recover]))
        if hard is not None:
            need(1 <= hard <= 4, '--ib-hard-seconds is 1..4 (IOGPU waits 5 s for the GPU)')
            flags.append(IB_HARD_SECONDS_DEFINE.format(hard))
    ceiling = getattr(args, 'cpu_dvfs_ceiling', None)
    need(ceiling is None or getattr(args, 'cpu_dvfs', False), '--cpu-dvfs-ceiling needs --cpu-dvfs')
    if getattr(args, 'cpu_dvfs', False) or getattr(args, 'gpu_dvfs', False):
        need(getattr(args, 'thermal_guard', False),
             '--cpu-dvfs/--gpu-dvfs need --thermal-guard (the governors clamp on its readings and stay off without it)')
        need(getattr(args, 'root_cache_wide', False), '--cpu-dvfs/--gpu-dvfs need --root-cache-wide (state in root_ext)')
    if getattr(args, 'cpu_dvfs', False):
        need(WFI_RESUME_DEFINE in flags, '--cpu-dvfs needs --wfi-resume (the EL2 tick\'s busy/idle classification)')
        flags.append(CPU_DVFS_DEFINE)
        if ceiling is not None:
            need(1 <= ceiling <= 19, '--cpu-dvfs-ceiling is a level index 1..19 (each domain also stops at its own '
                                     'sustained level: PDP0 20, PDP1/2 19; boost levels are never requested)')
            flags.append(CPU_DVFS_CEILING_DEFINE.format(ceiling))
    need(not getattr(args, 'gpu_dvfs_defer', False) or getattr(args, 'gpu_dvfs', False),
         '--gpu-dvfs-defer needs --gpu-dvfs')
    hold = getattr(args, 'gpu_dvfs_hold', None)
    need(hold is None or getattr(args, 'gpu_dvfs', False), '--gpu-dvfs-hold needs --gpu-dvfs')
    if getattr(args, 'gpu_dvfs', False):
        need(not getattr(args, 'gpu_opp_mhz', None), '--gpu-dvfs and --gpu-opp-mhz both choose the GPU clock: give one')
        flags.append(GPU_DVFS_DEFINE)
        if getattr(args, 'gpu_dvfs_defer', False):
            flags.append(GPU_DVFS_DEFER_DEFINE)
        if hold is not None:
            need(300 <= hold <= 5000, '--gpu-dvfs-hold is 300..5000 ms')
            flags.append(GPU_DVFS_HOLD_DEFINE.format(hold))
    if getattr(args, 'present_beam', False):
        # Appended after every earlier flag; the loader half is SNAP_DISPLAY_TIMING (environment()).
        flags.append(DISPLAY_TIMING_DEFINE)
    need(not (getattr(args, 'sptm_fine_retype', False) or getattr(args, 'sptm_fine_kernel', False)) or
         getattr(args, 'sptm_fine', False), '--sptm-fine-retype and --sptm-fine-kernel need --sptm-fine')
    if getattr(args, 'sptm_fine', False):
        need(variant == 'fast' and getattr(args, 'fine_locks', False) and getattr(args, 'fine_hw', False) and
             getattr(args, 'user_hw_walk', False) and '-DSNAP_UPDATE_DISJOINT_FAST=1' in flags,
             '--sptm-fine needs --variant fast, --fine-locks, --fine-hw, --user-hw-walk and --update-disjoint-fast')
        flags.append(SPTM_FINE_DEFINE)
        if getattr(args, 'sptm_fine_retype', False):
            flags.append(SPTM_FINE_RETYPE_DEFINE)
        if getattr(args, 'sptm_fine_kernel', False):
            flags.append(SPTM_FINE_KERNEL_DEFINE)
    if getattr(args, 'gpu_va_wide', False):
        # Last; the loader half is SNAP_ADRENO_VA_WIDE (environment()), the q1n1 half gpu_steps' and boot()'s --va-wide.
        need('-DSNAP_ROOT_CACHE_WIDE=1' in flags or '-DSNAP_DART_WIREDCNT=1' not in flags,
             '--gpu-va-wide with SNAP_DART_WIREDCNT keeps its wide pin bitmap in root_ext: needs --root-cache-wide')
        flags.append(GPU_VA_WIDE_DEFINE)
    need(not getattr(args, 'nvme_converted', False) or getattr(args, 'nvme_async', False),
         '--nvme-converted needs --nvme-async (a converted doorbell must never wait for the SSD)')
    if getattr(args, 'nvme_async', False):
        need(getattr(args, 'root_cache_wide', False), '--nvme-async needs --root-cache-wide (its schedule is in root_ext)')
        flags.append(ANS_ASYNC_DEFINE)
        if getattr(args, 'nvme_converted', False):
            need(variant == 'fast' and getattr(args, 'fine_locks', False),
                 '--nvme-converted needs --variant fast and --fine-locks')
            flags.append(ANS_CONVERTED_DEFINE)
    if getattr(args, 'attr_clean_defer', False):
        need(getattr(args, 'root_cache_wide', False),
             '--attr-clean-defer needs --root-cache-wide (each CPU\'s deferred list is in root_ext)')
        flags.append(ATTR_CLEAN_DEFER_DEFINE)
    if getattr(args, 'adreno_fill_br', False):
        flags.append(ADRENO_FILL_BR_DEFINE)
    if getattr(args, 'adreno_fence_br', False):
        flags.append(ADRENO_FENCE_BR_DEFINE)
    if getattr(args, 'multipage_fast', False):
        need(getattr(args, 'attr_clean_defer', False) and getattr(args, 'root_cache_wide', False) and
             '-DSNAP_KERNEL_VIEW_REUSE=1' in flags and '-DSNAP_TOKEN_TRIM=1' not in flags,
             '--multipage-fast needs --attr-clean-defer and --root-cache-wide (and the kernel view reuse snapshot), '
             'not --token-trim')
        flags.append(MULTIPAGE_FAST_DEFINE)
    if getattr(args, 'gpu_coherent', False):
        need(GPU_VA_WIDE_DEFINE in flags and '-DSNAP_ROOT_CACHE_WIDE=1' in flags,
             '--gpu-coherent needs --gpu-va-wide (its self-test scratch is the arena\'s Stage 4 pool region) and '
             '--root-cache-wide (its state is in root_ext)')
        flags.append(GPU_COHERENT_DEFINE)
    if getattr(args, 'gpu_coherent_force', False):
        need(getattr(args, 'gpu_coherent', False), '--gpu-coherent-force needs --gpu-coherent: it forces that '
             'self-test\'s outcome')
        flags.append(GPU_COHERENT_FORCE_DEFINE)
    if getattr(args, 'edp_backlight', False):
        flags.append(EDP_BACKLIGHT_DEFINE)
    if getattr(args, 'view_reclaim', False):
        flags.append(VIEW_RECLAIM_DEFINE)
    return flags


def run_watchdog(args):
    """The run's watchdog in seconds: --watchdog, else WATCHDOG. Above WATCHDOG the boot preflight requires AC."""
    value = getattr(args, 'watchdog', None)
    if value is None:
        return WATCHDOG
    need(WATCHDOG <= value <= WATCHDOG_MAX, f'--watchdog must be {WATCHDOG}..{WATCHDOG_MAX} s')
    return value


def environment(args):
    """ENV, or with --console the console on the same poll; --kernel-sysreg-zero, --kernel-refmod-skip and
    --kernel-user-4k add the opt-in kernel patches."""
    env = dict(ENV, SNAP_EARLY_STOP='guest,console') if getattr(args, 'console', False) else dict(ENV)
    watchdog = run_watchdog(args)
    env['SNAP_WATCHDOG'] = str(watchdog)
    if getattr(args, 'session', False):
        # A desktop session: the kext gets no first-present stop request (probes/adreno.py advertises it only for the
        # guest trigger), so the run lasts until the watchdog, the thermal guard or a host stop (tools/request-stop.py).
        need(getattr(args, 'console', False), '--session needs --console (the host poll that request-stop.py uses)')
        need(getattr(args, 'early_stop_delay', None) is None, '--session has no first-present stop: drop --early-stop-delay')
        env['SNAP_EARLY_STOP'] = 'console'
    if getattr(args, 'hide_amx', False):
        env['SNAP_HIDE_AMX'] = '1'
    if getattr(args, 'guest_net', False):
        # The guest network rides on the host poll (tools/early_stop.py net: F_HOST | F_NET, 5 ms polls).
        env['SNAP_EARLY_STOP'] = env['SNAP_EARLY_STOP'] + ',net'
    if getattr(args, 'thermal_guard', False):
        # docs/A16-THERMAL-GUARD-20261018.md: TSENS sampled every 250 ms on CPU0's timer path, a 60 C ceiling, per-sensor
        # validity grace and a missed-poll bound stop the run (thermal implies the host poll). A launch parameter.
        env['SNAP_EARLY_STOP'] = env['SNAP_EARLY_STOP'] + ',thermal'
    if getattr(args, 'kernel_sysreg_zero', False):
        env['SNAP_KERNEL_SYSREG_ZERO'] = '1'
    if getattr(args, 'kernel_refmod_skip', False):
        env['SNAP_KERNEL_REFMOD_SKIP'] = '1'
    if getattr(args, 'kernel_user_4k', False):
        env['SNAP_KERNEL_USER_4K'] = '1'
    if getattr(args, 'prime_secondaries', False):
        env['SNAP_SMP_PRIME'] = '1'
    if getattr(args, 'txm_aspace_wide', False):
        # probes/xnuboot.py configure_txm_arena: the loader half of TXM_ASPACE_WIDE_DEFINE (both or neither).
        env['SNAP_TXM_ASPACE_WIDE'] = '1'
    if getattr(args, 'qcc2072_wifi', False):
        # probes/run.py: the loader half of QCC2072_WIFI_DEFINE (live admission, arena, node, appended params);
        # boot() adds SNAP_QCC2072_INPUTS, the attempt's staged inputs.
        env['SNAP_QCC2072_WIFI'] = '1'
    if getattr(args, 'present_beam', False):
        # probes/run.py: the loader half of DISPLAY_TIMING_DEFINE (params block, stage-2 row, GPU-node properties).
        env['SNAP_DISPLAY_TIMING'] = '1'
    if getattr(args, 'gpu_va_wide', False):
        # probes/xnuboot.py configure_adreno_va_wide: the loader half of GPU_VA_WIDE_DEFINE (both or neither).
        env['SNAP_ADRENO_VA_WIDE'] = '1'
    if getattr(args, 'let_panic', False):
        # probes/run.py SNAP_LET_PANIC: EL1 exceptions (XNU's debugger trap on panic) resume into XNU's own
        # handler instead of stopping, so the panic string is printed (v29 and v35 stopped silently at
        # DebuggerTrapWithState). A launch parameter, not a monitor define.
        env['SNAP_LET_PANIC'] = '1'
    delay = getattr(args, 'early_stop_delay', None)
    if delay is not None:
        # The kext's first-present / plug-in-failure stop fires this long after its request (default 600 s);
        # it must leave the watchdog the last word.
        need(60 <= delay < watchdog, f'--early-stop-delay must be 60..{watchdog - 1} s')
        env['SNAP_EARLY_STOP_DELAY'] = env['SNAP_EARLY_STOP_MAX_DELAY'] = str(delay)
    return env


# XNU zone corruption logging (osfmk/kern/zalloc.c: zlog1=<zone name> records every allocation and free of that zone
# with backtraces, zrecs=<n> records; a use-after-free panic then prints the culprit's stacks). Zone names are XNU's
# own (heap prefix, '.' for spaces), so only that alphabet is admitted.
ZONE_LOG_NAME = re.compile(r'[A-Za-z0-9_.]{1,64}')


def boot_addition(args):
    """What the boot appends to BASE_CMDLINE: TimeSync, software WKdm compression, the console's flags and any
    zone-corruption logging."""
    console, single = getattr(args, 'console', False), getattr(args, 'single_user', False)
    need(console or not single, '--single-user needs --console: its shell is on the console')
    zone, records = getattr(args, 'zone_log', None), getattr(args, 'zone_log_records', None)
    need(records is None or zone is not None, '--zone-log-records needs --zone-log')
    extra = []
    if getattr(args, 'present_maint', False):
        extra.append('adreno_present_maint=1')
    if getattr(args, 'adreno_cs_samplers', False):
        extra.append('adreno_cs_samplers=1')      # read only by an ADRENO_IB_CS_SAMPLERS AdrenoX2 (configureDevice)
    if getattr(args, 'gpu_coherent', False):
        extra.append('adreno_coherent=1')   # the kext still skips only after the monitor's self-test said ON
    if getattr(args, 'gpu_coherent_force', False):
        extra.append('adreno_coherent_force=1')   # and, debug only, after a forced ON (no self-test)
    need(not getattr(args, 'edp_backlight_mode', False) or getattr(args, 'edp_backlight', False),
         '--edp-backlight-mode needs --edp-backlight')
    if getattr(args, 'edp_backlight', False):
        extra.append('adreno_backlight=1')        # the kext publishes its service only after the monitor's QUERY
    if getattr(args, 'edp_backlight_mode', False):
        extra.append('adreno_backlight_mode=1')   # and may switch a panel left in PWM mode to DPCD control
    resident_mib = getattr(args, 'resident_mib', None)
    if resident_mib is not None:
        need(0 <= resident_mib <= 4096, '--resident-mib must be 0..4096')
        extra.append(f'adreno_resident_mib={resident_mib}')
    # --present-latch's guest boot-args (AdrenoDisplay start_hardware, SnapI2CHIDBus::start); none without the flag.
    latch_us, hold = getattr(args, 'present_latch_us', None), getattr(args, 'present_hold', None)
    margin_us, active_us = getattr(args, 'present_hold_margin_us', None), getattr(args, 'input_active_us', None)
    gate_us = getattr(args, 'present_gate_us', None)
    pipeline, poll_us = getattr(args, 'present_pipeline', None), getattr(args, 'present_pipeline_poll_us', None)
    need(getattr(args, 'present_latch', False) or (latch_us, hold, margin_us, active_us, gate_us) == (None,) * 5,
         '--present-latch-us/--present-hold/--present-hold-margin-us/--present-gate-us/--input-active-us need '
         '--present-latch')
    need(getattr(args, 'present_latch', False) or (pipeline, poll_us) == (None, None),
         '--present-pipeline/--present-pipeline-poll-us need --present-latch (its AuxKC carries the pipeline AdrenoX2)')
    if pipeline is not None:
        extra.append(f'adreno_pipeline={pipeline}')
    if poll_us is not None:
        need(50 <= poll_us <= 5000, '--present-pipeline-poll-us must be 50..5000')
        extra.append(f'adreno_pipeline_poll_us={poll_us}')
    if latch_us is not None:
        need(0 <= latch_us <= 9000, '--present-latch-us must be 0..9000 (0: the beam kext\'s aim)')
        extra.append(f'adreno_latch_us={latch_us}')
    if hold is not None:
        extra.append(f'adreno_hold={1 if hold == "on" else 0}')
    if margin_us is not None:
        need(0 <= margin_us <= 16000, '--present-hold-margin-us must be 0..16000')
        extra.append(f'adreno_hold_margin_us={margin_us}')
    if gate_us is not None:
        need(0 <= gate_us <= 16000, '--present-gate-us must be 0..16000')
        extra.append(f'adreno_gate_us={gate_us}')
    if active_us is not None:
        need(active_us == 0 or 2000 <= active_us <= 100000, '--input-active-us must be 0 or 2000..100000')
        extra.append(f'snap_i2c_active_us={active_us}')
    # --present-early-done: AdrenoDisplay's early completion (src/AdrenoDisplayEarlyDone.h), read only by the
    # desktop-early-done AdrenoX2 that --edp-backlight then selects; the kext turns it off with the release hold.
    early, early_hold = getattr(args, 'present_early_done', None), getattr(args, 'present_early_hold_ms', None)
    need(early is None or getattr(args, 'edp_backlight', False),
         '--present-early-done needs --edp-backlight (the early-done collection is that chain\'s)')
    need(early is None or early in (0, 1, 2), '--present-early-done is 0 (measure only), 1 (always) or 2 (while behind)')
    need(early_hold is None or early == 2, '--present-early-hold-ms needs --present-early-done 2')
    need(not early or hold != 'on', '--present-early-done 1/2 and --present-hold on exclude each other (the hold '
                                    'keeps the swap current until its release)')
    if early is not None:
        extra.append(f'adreno_present_early_done={early}')
    if early_hold is not None:
        need(100 <= early_hold <= 10000, '--present-early-hold-ms must be 100..10000')
        extra.append(f'adreno_present_early_hold_ms={early_hold}')
    # --input-fnkeys: the keyboard's Fn-key layer (drivers/snap-i2c-hid/src/hid-keyboard.h HID_FNKEYS_*), read by a
    # SnapI2CHID built with SNAP_I2C_HID_FNKEYS; the same sets the kext refuses are refused here.
    fnkeys = getattr(args, 'input_fnkeys', None)
    if fnkeys is not None:
        need(getattr(args, 'input', False), '--input-fnkeys needs --input (the SnapI2CHID AuxKC)')
        need(0 < fnkeys <= 0x1f and not fnkeys & ~0x1f, '--input-fnkeys must be 0x1..0x1f (hid-keyboard.h HID_FNKEYS_*)')
        need((fnkeys >> 3) & 3 != 3, '--input-fnkeys: brightness encoding 3 (0x18) does not exist')
        need(not fnkeys & 0x4 or fnkeys & 0x1, '--input-fnkeys: the host Fn-lock (0x4) needs translation (0x1)')
        need(fnkeys & 0x3, '--input-fnkeys: give translation (0x1) or the raw log (0x2)')
        extra.append(f'snap_i2c_fnkeys={fnkeys}')
    if zone is not None:
        need(ZONE_LOG_NAME.fullmatch(zone), f'--zone-log {zone!r}: XNU zone names are [A-Za-z0-9_.], at most 64')
        extra.append(f'zlog1={zone}')
        if records is not None:
            need(1 <= records <= 65536, '--zone-log-records must be 1..65536')
            extra.append(f'zrecs={records}')
    return ' '.join([TIMESYNC_FLAG, COMPRESSOR_SW_FLAG] + ([CONSOLE_FLAG] if console else []) +
                    ([SINGLE_USER_FLAG] if single else []) + extra)


# After a cold boot every RPMh TCS reads empty, so gmu-boot's first MX/CX vote on the
# fresh arena is the operator's decision (it stops at B1 otherwise, as
# installed-fresh-20261016-v3 did). The Stage 3, 4, P6/P7 and 6 runbooks take it as NOM:
# "MX/CX voted NOM (index 5) with --rail-vote-unseen --rail-level nom, link unaffected"
# (q1n1/docs/A16-ADRENO-STAGE3.md). The pinned launcher ran only on warm-chainloaded
# generations whose arena already carried that vote, so it never passed these.
COLD_BOOT_VOTE = ['--rail-vote-unseen', '--rail-level', 'nom']


def launcher_steps(root):
    """(name, arguments) of the established preparation, read from the pinned base launcher."""
    base = root.parent / PINS['base_launcher']['path']
    need(sha(base) == PINS['base_launcher']['sha256'], f'{base} changed')
    for node in ast.parse(base.read_text()).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) == 'STEPS':
            return [tuple(step) for step in ast.literal_eval(node.value)]
    need(False, 'base launcher has no STEPS')


# --gpu-opp-mhz (docs/USERSPACE-GRAPHICS-20261019.md, "Speed batch"): the hfi step's perf table lists the speed bin's
# OPPs up to that clock and its GX_BW_PERF_VOTE asks for it (q1n1 a16gpu_stage3.py --max-opps/--perf-opp). 915 MHz is
# the 6th OPP (RPMh 256, NOM, 16.5 GB/s). Without the option the steps are the launcher's, byte for byte.
GPU_OPP_ARGS = {915: ['--max-opps', '6', '--perf-opp', '6']}
# --gpu-dvfs: the perf and bandwidth tables list OPPs 1..6 (310..915 MHz) and the first vote stays OPP 1; the monitor's
# governor (compat/gpu-dvfs.h) then votes within them.
GPU_DVFS_HFI_ARGS = ['--max-opps', '6', '--perf-opp', '1']   # b12-era table (915 MHz top); kept for reference
# agents/dvfs section 9 (user approval 2026-10-21: every OPP up to the chip maximum, thermal guard on): the hfi step's
# table runs up to --gpu-dvfs-ceiling. q1n1 adreno_x2.py GPU_OPPS, speed bin 1 (fuse 388): all 12 rows; the A16's
# cmd-db mx.lvl tops out at 452, so 1850 MHz (456) has no MX corner and q1n1 refuses it (rail_refusal): 1700 is the
# default and the maximum. The monitor reads the table size from the host record (hfi_opps): no rebuild per ceiling.
GPU_DVFS_CEILINGS_MHZ = (310, 410, 572, 760, 820, 915, 1070, 1185, 1350, 1550, 1700)
GPU_DVFS_CEILING_DEFAULT = 1700


def gpu_dvfs_hfi_args(ceiling_mhz=None):
    ceiling = GPU_DVFS_CEILING_DEFAULT if ceiling_mhz is None else ceiling_mhz
    need(ceiling != 1850, '--gpu-dvfs-ceiling 1850: the A16 cmd-db mx.lvl tops out at RPMh 452, so 1850 MHz (456) has '
                          'no MX corner; refused rather than under-voted (q1n1 a16gpu_stage3.rail_refusal)')
    need(ceiling in GPU_DVFS_CEILINGS_MHZ, f'--gpu-dvfs-ceiling is one of {GPU_DVFS_CEILINGS_MHZ} (MHz)')
    return ['--max-opps', str(GPU_DVFS_CEILINGS_MHZ.index(ceiling) + 1), '--perf-opp', '1']
# --ddr-vote (agents/dvfs lever 1, q1n1 tools/a16gpu_ddr.py): before the GPU steps, apps drv-2 votes SH0/MC0 at the
# BCM clamp with SH1/ACV on (what Linux holds until icc_sync_state); quiesce sends the explicit restore vote (the GPU
# OPP-1 row). --bw-probe: tools/measure-a16-memory-bandwidth.py before and after that vote, in this launcher's session.
DDR_VOTE_ARGS = ['ddr-vote', '--write', '--level', 'max']
DDR_RESTORE_ARGS = ['ddr-restore', '--write']
BW_PROBE = dict(bytes=64 << 20, passes=6, sweep=[8 << 20, 16 << 20, 32 << 20])
# --llcc (agents/dvfs FAILURE-MODES.md section 6, q1n1 tools/a16gpu_llcc.py): after the DDR vote and before the GPU steps,
# configure and activate the LLCC slices CPUSS (1), GPU (9) and GPUHTW (11) as llcc-qcom.c does (Linux glymur table, or
# --llcc-table windows: the A16 Windows driver's), with the probe before and after; after cp-fence, llcc-gpu points the
# GPU's GBIF traffic at the GPU slice (a8xx_llc_activate); quiesce deactivates the slices this boot activated.
LLCC_SLICES = 'cpuss,gpu,gpuhtw'
LLCC_GPU_STEP = ('llcc_gpu', ['llcc-gpu', '--write'])
# agents/gpu-x290 (FAILURE-MODES.md X1-X11). --gpu-x290: q1n1 `cp-fence --x290` on every cp-fence of the GMU boot (C0
# proves the 4-slice X2-90 from the fuse before anything is written; C3 adds a8xx_set_ubwc_config for glymur; a resumed
# call checks the block is there). --gpu-x290-survey: the read-only `x290-survey` after the cp-fence steps.
X290_SURVEY_STEP = ('x290_survey', ['x290-survey'])


def llcc_plan(args):
    """The qualification's 'llcc' entry: None without --llcc (the record then has no such key)."""
    table = getattr(args, 'llcc_table', None)
    if not getattr(args, 'llcc', False):
        need(table is None, '--llcc-table needs --llcc')
        return None
    return dict(activate=['llcc-activate', '--write', '--slices', LLCC_SLICES, '--table', table or 'linux'],
                deactivate=['llcc-deactivate', '--write'],
                probe=dict(BW_PROBE) if getattr(args, 'bw_probe', False) else None)


def ddr_plan(args):
    """The qualification's 'ddr' entry: None without --ddr-vote (the record then has no such key)."""
    if not getattr(args, 'ddr_vote', False):
        need(not getattr(args, 'bw_probe', False) or getattr(args, 'llcc', False),
             '--bw-probe measures around the DDR vote or the LLCC activation: it needs --ddr-vote or --llcc')
        return None
    return dict(vote=DDR_VOTE_ARGS, restore=DDR_RESTORE_ARGS,
                probe=dict(BW_PROBE) if getattr(args, 'bw_probe', False) else None)


def bandwidth_tool(root):
    """tools/measure-a16-memory-bandwidth.py as a module (its stub build, measure and summary)."""
    import runpy
    return runpy.run_path(str(root / 'tools/measure-a16-memory-bandwidth.py'), run_name='bw_probe')


def bandwidth_probe(root, runner, device, dest, label, generation, plan):
    """--bw-probe: one single-core EL2 measurement (FAILURE-MODES.md P1-P10) in this launcher's own session, before
    any guest is loaded; the record is build/PREFIX/bw-LABEL.json. Returns what launch.json keeps."""
    import types
    tool = bandwidth_tool(root)
    blob = tool['build_stub']()
    need(tool['sha'](blob) == plan['stub_sha256'], 'the bandwidth stub differs from the preparation')
    memory_blob = tool['build_memory_probe']()
    out = dest / f'bw-{label}.json'
    need(not out.exists(), f'{out} exists; captures are never overwritten')
    record = dict(schema='snapintosh-memory-bandwidth-v1', label=label, started=time.time(),
                  bytes_each=plan['bytes'], passes=plan['passes'], stub_sha256=plan['stub_sha256'],
                  qualification='single core (q1n1 boot CPU), EL2, MMU and caches on; not a multi-core figure')
    proxy = runner.connect(device, tries=1)
    try:
        info = proxy.bootinfo()
        need(info['current_el'] == 2 and info['stage_generation'] == generation, 'not the admitted EL2 generation')
        record['serror_before'] = proxy.serror_state()
        need(serror_clear(record['serror_before']), 'SError before the bandwidth probe')
        tool['measure'](proxy, info, blob, memory_blob,
                        types.SimpleNamespace(bytes=plan['bytes'], passes=plan['passes'], buffer_pa=None, qemu=False,
                                              sweep=plan.get('sweep') or []),
                        record, lambda: write(out, record), timer_hz=info['timer_hz'])
        record['serror_after'] = proxy.serror_state()
        need(serror_clear(record['serror_after']), 'SError during the bandwidth probe')
        record['status'] = 'MEASURED'
    except BaseException as error:
        record['status'] = 'FAILED'
        record['error'] = repr(error)
        raise
    finally:
        write(out, record)
        proxy.link.close()
    return dict(path=str(out), sha256=st.file_sha(out), best=tool['summary'](record))


def recover_table_check(root, steps, args):
    """--gpu-recover reset replays compat/adreno-recover-table.h after a CP soft reset: it must be the generator's output
    for the q1n1 sources this run's GPU steps use (their sha256 in ADRENO_RECOVER_TABLE_INPUTS) and the same cp-fence
    options (--x290 changes hw_init); tools/gen-adreno-recover-table.py regenerates it."""
    if getattr(args, 'gpu_recover', None) != 'reset':
        return None
    text = (root / RECOVER_TABLE).read_text()
    inputs = re.search(r'#define ADRENO_RECOVER_TABLE_INPUTS "([^"]*)"', text)
    options = re.search(r'#define ADRENO_RECOVER_TABLE_CP_FENCE_OPTIONS "([^"]*)"', text)
    need(inputs and options, f'{RECOVER_TABLE}: no generator record (regenerate it)')
    tools = root.parent / 'q1n1' / 'tools'
    for item in inputs.group(1).split():
        name, digest = item.split(':')
        need(st.file_sha(tools / name) == digest, f'{RECOVER_TABLE} was generated from another q1n1 {name}: '
                                                  'run tools/gen-adreno-recover-table.py')
    x290 = any(arguments[0] == 'cp-fence' and '--x290' in arguments for _, arguments in steps)
    need((options.group(1) == '--x290') == x290, f'{RECOVER_TABLE} was generated for cp-fence '
                                                 f'"{options.group(1)}", the run\'s cp-fence has{"" if x290 else " no"} --x290')
    return {'table_sha256': st.file_sha(root / RECOVER_TABLE), 'inputs': inputs.group(1), 'cp_fence': options.group(1)}


def gpu_steps(root, args=None):
    """The launcher's steps with the runbooks' first rail vote, for a cold-booted arena, and the opt-in GPU OPP."""
    steps = launcher_steps(root)
    need(dict(steps).get('gmu') == ['gmu-boot', '--write'], 'launcher gmu step changed')
    need(dict(steps).get('hfi') == ['hfi', '--write'], 'launcher hfi step changed')
    opp = GPU_OPP_ARGS[args.gpu_opp_mhz] if getattr(args, 'gpu_opp_mhz', None) else []
    need(getattr(args, 'gpu_dvfs_ceiling', None) is None or getattr(args, 'gpu_dvfs', False),
         '--gpu-dvfs-ceiling needs --gpu-dvfs')
    if getattr(args, 'gpu_dvfs', False):
        need(not opp, '--gpu-dvfs and --gpu-opp-mhz both choose the GPU clock: give one')
        opp = gpu_dvfs_hfi_args(getattr(args, 'gpu_dvfs_ceiling', None))
    extra = {'gmu': COLD_BOOT_VOTE, 'hfi': opp}
    result = [(name, [*arguments, *extra.get(name, [])]) for name, arguments in steps]
    if getattr(args, 'gpu_va_wide', False):
        # q1n1 cp-fence --va-wide: CB0 T0SZ 30, on every cp-fence of the GMU boot (C1 programs it, the others refuse a
        # CB0 without it). boot() gives adopt the same flag from the preparation's SNAP_ADRENO_VA_WIDE.
        need(any(arguments[0] == 'cp-fence' for _, arguments in result), 'launcher has no cp-fence step')
        result = [(name, [*arguments, '--va-wide'] if arguments[0] == 'cp-fence' else arguments)
                  for name, arguments in result]
    if getattr(args, 'gpu_x290', False):
        need(any(arguments[0] == 'cp-fence' for _, arguments in result), 'launcher has no cp-fence step')
        result = [(name, [*arguments, '--x290'] if arguments[0] == 'cp-fence' else arguments)
                  for name, arguments in result]
    if getattr(args, 'llcc', False):
        result.append(LLCC_GPU_STEP)   # after cp-fence (GX on), before adopt
    if getattr(args, 'gpu_x290_survey', False):
        result.append(X290_SURVEY_STEP)   # read-only, after every GPU write step, before adopt
    return result


def root_hash_payload(root):
    """The SystemVolume root hash, extracted from the IPSW and checked against the
    profile's component and payload pins and the manifest's SHA-384."""
    from guestprofile import get_profile
    spec = get_profile(PROFILE).installed_root
    with zipfile.ZipFile(root / IPSW) as archive:
        manifest = plistlib.loads(archive.read('BuildManifest.plist'))
        need(manifest['ProductBuildVersion'] == '26A428', 'IPSW build differs')
        paths = {i['Manifest'][spec.component]['Info']['Path']: i['Manifest'][spec.component]['Digest']
                 for i in manifest['BuildIdentities'] if spec.component in i['Manifest']}
        found = [(p, d, archive.read(p)) for p, d in paths.items()]
    found = [(p, d, data) for p, d, data in found if hashlib.sha256(data).hexdigest() == spec.component_sha256]
    need(len(found) == 1, 'IPSW has no single SystemVolume component with the profile hash')
    path, manifest_digest, data = found[0]
    need(hashlib.sha384(data).digest() == manifest_digest, 'root-hash component differs from its manifest')
    payload = load('extract_firmware', root / 'tools/extract-firmware.py').im4p_payload(data)
    need(len(payload) == spec.payload_bytes and digest(payload) == spec.payload_sha256,
         'extracted root hash differs from the profile pin')
    return path, payload


def txm_helper(root, dest):
    """The native TXM helper, relocated from the firmware TXM with the bridge built from source."""
    import txmnative
    out = dest / 'txm-bridge'
    out.mkdir()
    subprocess.run([f'{LLVM}/clang', '--target=aarch64-unknown-none-elf', '-c', str(root / BRIDGE[0]),
                    '-o', str(out / 'bridge.o')], check=True)
    subprocess.run(['ld.lld', '-T', str(root / BRIDGE[1]), '-o', str(out / 'bridge.elf'), str(out / 'bridge.o')],
                   check=True)
    subprocess.run([f'{LLVM}/llvm-objcopy', '-O', 'binary', str(out / 'bridge.elf'), str(out / 'bridge.bin')],
                   check=True)
    bridge = (out / 'bridge.bin').read_bytes()
    need(digest(bridge) == txmnative.BRIDGE_SHA, 'bridge differs from the qualified bridge')
    flat, fixes, patches = txmnative.relocate((root / FIRMWARE / 'txm.macosx.release').read_bytes(),
                                              txmnative.HELPER_BASE, bridge)
    need(len(flat) == txmnative.IMAGE_BYTES and digest(flat) == txmnative.IMAGE_SHA,
         'relocated helper differs from the image qualified on the A16')
    (dest / 'image4.bin').write_bytes(flat)
    return dict(bridge_sha256=digest(bridge), image_sha256=digest(flat), fixups=len(fixes), patches=len(patches))


def image_checks(root, dest, layout, root_hash, sysreg_zero=False, args=None, refmod_skip=False, user_4k=False,
                 context_layout=None):
    """The complete guest image, built offline with a synthetic GPU adoption."""
    import adreno
    import monitor_work
    import txmnative
    from appledt import DeviceTree
    profile_name, aux, _, _ = selected(args)
    xb = load('installed_image', root / 'probes/xnuboot.py')
    xb.configure_guest(profile_name, root / FIRMWARE)
    xb.configure_txm_arena(bool(getattr(args, 'txm_aspace_wide', False)))
    need(not xb.check_profile(kernelcache=xb.DEFAULT_KERNELCACHE), 'firmware profile rejected')
    need(xb.BOOT_CMDLINE == BASE_CMDLINE, 'boot command line differs from the TimeSync base')
    profile = xb.GUEST_PROFILE
    need(profile.installed_root and profile.adreno and profile.ans_boot and profile.aux_collection_linked,
         'profile is not the installed Adreno route')
    wide = bool(getattr(args, 'gpu_va_wide', False))
    xb.configure_adreno_va_wide(wide)
    span = st.GUEST_MIB << 20
    xb.place(st.PHYS_BASE, span + xb.bootstrap_reserve(span) + monitor_work.WORK_SIZE, guest_span=span)
    xb.ADRENO_RECORD = adreno.fixture_record(wide=wide)
    beam = bool(getattr(args, 'present_beam', False))
    import displaytiming
    xb.DISPLAY_TIMING = displaytiming.SPEC if beam else None
    qcc = bool(getattr(args, 'qcc2072_wifi', False))
    if qcc:
        # The offline admission (generation 1, a fixed cookie) over the attempt's staged inputs; the boot's
        # record is made live by probes/run.py.
        import qcc2072wifi
        xb.QCC2072_WIFI = qcc2072wifi.grant(qcc2072wifi.fixture_spec(st.PHYS_BASE),
                                            qcc2072wifi.load_inputs(dest / QCC2072_INPUTS))
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        built = xb.build(str(xb.DEFAULT_KERNELCACHE), root_hash=str(root_hash), auxkc=str(root / aux),
                         trust_additions=str(root / ADDITIONS), sysreg_zero=bool(sysreg_zero),
                         refmod_skip=bool(refmod_skip), user_4k=bool(user_4k),
                         hide_amx=bool(getattr(args, 'hide_amx', False)))
    need(bool(built.get('kernel_sysreg_zero')) == bool(sysreg_zero), 'kernel sysreg-zero patch state differs from the request')
    need(bool(built.get('kernel_refmod_skip')) == bool(refmod_skip), 'kernel refmod-skip patch state differs from the request')
    need(bool(built.get('kernel_user_4k')) == bool(user_4k), 'kernel user-4k patch state differs from the request')
    need(bool(built.get('hide_amx')) == bool(getattr(args, 'hide_amx', False)),
         'application AMX capability patch state differs from the request')
    (dest / 'image-build.log').write_text(log.getvalue())
    chunks = built['chunks']
    tree = chunks[xb.DEVICETREE_PA]
    dt = DeviceTree(tree)
    need(dt.serialize() == tree, 'device tree does not round-trip')
    need(dt.nodes['/device-tree/chosen/asmb']['lp-sip0'].value == (2).to_bytes(8, 'little'), 'lp-sip0 is not 2')
    need(adreno.GPU_NODE in dt.nodes and adreno.DART_NODE in dt.nodes, 'no Adreno GPU or DART node')
    for capability in ('guest-fence-abi', 'guest-unmap-abi', 'guest-cache-abi', 'guest-fill32-abi', 'guest-ib-abi'):
        need(dt.nodes[adreno.GPU_NODE]['snapintosh,' + capability].value == (1).to_bytes(4, 'little'),
             f'GPU node lacks {capability}')
    slots = [child for child in dt.children['/device-tree/arm-io']
             if bytes(dt.get(child, 'device_type') or b'').rstrip(b'\0') in (b'display-subsystem', b'ext-display-subsystem')]
    need(slots == [DISPLAY_SLOT], f'display slots {slots}, expected {DISPLAY_SLOT}')
    for path in ('/device-tree/arm-io/dispext0', '/device-tree/arm-io/dcpext', '/device-tree/arm-io/dcpext-expert'):
        need(not any(n == path or n.startswith(path + '/') for n in dt.nodes), f'external display node {path}')
    trust = xb.trust_cache_spec(root / ADDITIONS).load(root / FIRMWARE)
    need(digest(trust) == TRUST_SHA and trust == (root / TRUST_PAYLOAD).read_bytes(), 'trust cache differs')
    need(sum(trust in raw for raw in chunks.values()) == 1, 'trust cache is not uploaded exactly once')
    aux_va, (aux_pa, aux_span) = built['auxkc_va_range'], built['auxkc_range']
    words = struct.unpack_from('<4Q', chunks[built['params_pa']], layout.offset('params', 'auxkc'))
    need(words == (aux_va[0], aux_va[1], aux_pa, aux_pa + aux_span), 'params do not carry the AuxKC range')
    ans = xb.ans_reservation()
    adreno.check_disjoint(xb.ADRENO_RECORD, [(xb.PHYS_BASE, ans[0] + ans[1] - xb.PHYS_BASE)])
    window = struct.unpack('<Q', bytes(dt.get(adreno.DART_NODE, 'vm-size')))[0]
    need(window == adreno.window_end(wide) - adreno.WINDOW_BASE, f'dart-adreno vm-size {window:#x} for gpu_va_wide={wide}')
    need((adreno.GPU_VA_BITS_PROPERTY in dt.nodes[adreno.GPU_NODE]) == wide,
         f'{adreno.GPU_VA_BITS_PROPERTY} on the GPU node only with --gpu-va-wide')
    gpu_words = struct.unpack_from(f'<{adreno.PARAMS_WORDS}Q', chunks[built['params_pa']], layout.offset('params', 'gpu'))
    pool = xb.gpu_pool_reservation()
    if wide:
        # agents/gpu-va-wide V5: the params pool word is the monitor-private reservation, above the ANS2 one, clear of
        # the guest, the work arena, the ANS2 reservation and the q1n1 arena.
        need(pool is not None and pool[0] >= ans[0] + ans[1] and gpu_words[8] == pool[0],
             'params pool word is not the GPU table reservation')
        need(gpu_words[6] & 0x3F == adreno.CB0_T0SZ_WIDE, 'params CB0 TCR is not T0SZ 30')
        adreno.check_disjoint(xb.ADRENO_RECORD, [(xb.PHYS_BASE, pool[0] + pool[1] - xb.PHYS_BASE)])
        adreno.check_pool_reservation(xb.ADRENO_RECORD, pool[0], [(xb.PHYS_BASE, ans[0] + ans[1] - xb.PHYS_BASE)])
        for lo, hi, _, what in xb.stage2_ranges():
            need(not (lo < pool[0] + pool[1] and pool[0] < hi), f'the GPU table reservation is in stage 2 ({what})')
    else:
        need(pool is None and gpu_words[8] == xb.ADRENO_RECORD['pool']['pa'], 'params pool word is not the arena pool')
    trailing = trailing_triples = 0
    if qcc:
        import qcc2072wifi
        trailing, trailing_triples = 8 * qcc2072wifi.PARAMS_WORDS, len(qcc2072wifi.WINDOWS)
    if beam:
        trailing += 8 * displaytiming.PARAMS_WORDS        # no arm-io ranges triple: the kext maps by address
    extra = (input_checks(xb, dt, chunks[built['params_pa']], layout, trailing, trailing_triples)
             if getattr(args, 'input', False) else {})
    need(bool(extra) or not any(n.startswith('/device-tree/arm-io/i2c-hid') for n in dt.nodes),
         'an input node outside --input')
    if qcc:
        extra.update(qcc2072_checks(xb, dt, chunks[built['params_pa']], layout,
                                    8 * displaytiming.PARAMS_WORDS if beam else 0))
    if beam:
        extra.update(display_timing_checks(xb, dt, chunks[built['params_pa']], layout, qcc))
    need(beam or not any(k.startswith('snapintosh,dpu-intf') for k in dt.nodes[adreno.GPU_NODE]),
         'DPU INTF properties on the GPU node outside --present-beam')
    need(qcc or not any(n == '/device-tree/arm-io/snap-qcc2072' for n in dt.nodes), 'a QCC2072 node outside --qcc2072-wifi')
    # The table arena lies between the context and the TXM helper's 3 MiB at the top: the build's context
    # (st.build_layout), not the define-free one.
    arena = monitor_work.WORK_SIZE - txmnative.WORK_BYTES - (((context_layout or layout).size('context') + 4095) & ~4095)
    need(arena >= 128 << 20, f'table arena {arena >> 20} MiB is too small')
    (dest / 'device-tree.bin').write_bytes(tree)
    return dict(profile=profile_name, kernel_sha256=sha(xb.DEFAULT_KERNELCACHE),
                firmware_sha256=profile.hashes(root / FIRMWARE), entry=hex(built['entry']),
                chunks=[dict(address=hex(a), bytes=len(b), sha256=digest(b)) for a, b in sorted(chunks.items())],
                upload_bytes=sum(len(b) for b in chunks.values()), display_slots=slots,
                trust_cache_sha256=digest(trust), device_tree_sha256=digest(tree),
                auxkc_range=[hex(aux_pa), hex(aux_span)], table_arena_bytes=arena,
                **({'gpu_va_wide': dict(window=[hex(adreno.WINDOW_BASE), hex(adreno.window_end(True))],
                                        pool=[hex(pool[0]), hex(pool[1])], pool_bytes=hex(adreno.pool_bytes(True)))}
                   if wide else {}),
                kernel_sysreg_zero=built.get('kernel_sysreg_zero'),
                **({'kernel_refmod_skip': built['kernel_refmod_skip']} if refmod_skip else {}),
                **({'kernel_user_4k': built['kernel_user_4k']} if user_4k else {}),
                **({'hide_amx': built['hide_amx']} if getattr(args, 'hide_amx', False) else {}), **extra,
                qualification='offline image at the declared base with a synthetic GPU adoption; '
                              'hardware placement and the real adoption are captured at boot')


def input_checks(xb, dt, params, layout, trailing=0, trailing_triples=0):
    """--input's nodes, ranges triples, appended params words and stage-2 rows, against probes/i2cinput.py:
    the keyboard, and with --input-touchpad the touchpad too. `trailing` bytes of a later params block and
    `trailing_triples` later arm-io ranges triples (both --qcc2072-wifi's) may follow the input's."""
    import struct
    import i2cinput
    spec = xb.GUEST_PROFILE.i2c_input
    devices = spec.devices() if spec is not None else ()
    need(devices in ((i2cinput.KEYBOARD,), (i2cinput.KEYBOARD, i2cinput.TOUCHPAD)),
         'input profile is not the keyboard, or the keyboard and the touchpad')
    triples = list(struct.iter_unpack('<3Q', bytes(dt.nodes['/device-tree/arm-io']['ranges'].value)))
    triples = triples[:len(triples) - trailing_triples]
    for d, triple in zip(devices, triples[-len(devices):]):
        node = dt.nodes.get(d.node)
        need(node is not None, f'no {d.node}')
        value = lambda k: bytes(node[k].value)
        need(value('compatible') == i2cinput.MATCH.encode() + b'\0' and 'interrupts' not in node and
             value('reg') == struct.pack('<QQ', i2cinput.CHILD_OFFSET + d.pa, i2cinput.PAGE) and
             value('snapintosh,hid-address') == struct.pack('<I', d.address) and
             value('snapintosh,hid-descriptor-reg') == struct.pack('<I', d.descriptor_register) and
             value('snapintosh,hid-vendor-product') == struct.pack('<2I', d.vendor, d.product) and
             value('snapintosh,irq-policy') == struct.pack('<I', 1), f'{d.node} differs from probes/i2cinput.py')
        need(triple == (i2cinput.CHILD_OFFSET + d.pa, d.pa, i2cinput.QUP_SPAN),
             f'{d.node}: its ranges triple is not among the appended last ones')
    # MonitorLayout reads xnuboot.c without build defines: the appended block starts at its params size.
    words = list(struct.unpack_from(f'<{i2cinput.PARAMS_WORDS}Q', params, layout.size('params')))
    rows = [(d.pa, d.pa + i2cinput.PAGE) for d in devices]
    need(len(params) == layout.size('params') + 8 * i2cinput.PARAMS_WORDS + trailing and i2cinput.rows(words) == rows,
         'params do not end with the input block')
    need([(lo, hi) for lo, hi, _, _ in xb.stage2_ranges() if (lo, hi) in rows] == rows, 'stage 2 lacks an input page')
    return dict(input=dict(nodes=[d.node for d in devices], params_words=[hex(w) for w in words],
                           stage2=[[hex(lo), hex(hi)] for lo, hi in rows], define=INPUT_DEFINE))


def qcc2072_checks(xb, dt, params, layout, trailing=0):
    """--qcc2072-wifi's node, its five ranges triples (appended last), the provider record in the node, the params
    block appended after struct params and the input block, and the five stage-2 rows, against
    probes/qcc2072wifi.py and the attempt's staged inputs."""
    import qcc2072wifi as q
    grant = xb.QCC2072_WIFI
    need(grant is not None, 'no QCC2072 admission in the image')
    node = dt.nodes.get(q.NODE)
    need(node is not None, f'no {q.NODE}')
    value = lambda k: bytes(node[k].value)
    reg = b''.join(struct.pack('<QQ', q.CHILD_OFFSET + pa, size) for _, pa, size, *_ in q.WINDOWS)
    need(sorted(node) == sorted(['name', 'compatible', 'reg', q.ADMISSION]) and 'interrupts' not in node and
         value('name') == b'snap-qcc2072\0' and value('compatible') == q.MATCH.encode() + b'\0' and
         value('reg') == reg and value(q.ADMISSION) == grant.record, f'{q.NODE} differs from probes/qcc2072wifi.py')
    words = struct.unpack('<32Q', grant.record)
    need(words[:4] == (q.RECORD_MAGIC, 1, 256, 1) and words[6:19] == (
             q.PCI_ID, q.PCI_SUBSYSTEM, q.SID, q.PROOFS, q.BAR0_PA, q.BAR0_BYTES, q.BAR2_PA, q.BAR2_BYTES, q.ECAM_PA,
             q.DMA_PA, q.DMA_PA, q.DMA_BYTES, q.CONTROL_PA) and words[28:] == (64, 0, 0, 0),
         'the provider record differs from the allow-list')
    triples = list(struct.iter_unpack('<3Q', bytes(dt.nodes['/device-tree/arm-io']['ranges'].value)))
    need(triples[-len(q.WINDOWS):] == q.triples(), 'the QCC2072 ranges triples are not the appended last ones')
    need(dt.children['/device-tree/arm-io'].count(q.NODE) == 1, 'the QCC2072 node is not one arm-io child')
    block = list(struct.unpack_from(f'<{q.PARAMS_WORDS}Q', params, len(params) - trailing - 8 * q.PARAMS_WORDS))
    rows = q.rows(block)
    import i2cinput
    extra_input = 8 * i2cinput.PARAMS_WORDS if xb.GUEST_PROFILE.i2c_input is not None else 0
    need(len(params) == layout.size('params') + extra_input + 8 * q.PARAMS_WORDS + trailing and rows is not None,
         'params do not end with the QCC2072 block')
    need([(lo, hi) for lo, hi, _, _ in xb.stage2_ranges() if (lo, hi) in rows] == rows, 'stage 2 lacks a QCC2072 window')
    return dict(qcc2072_wifi=dict(node=q.NODE, record_sha256=q.SHA(grant.record), params_words=[hex(w) for w in block],
                                  stage2=[[hex(lo), hex(hi), access] for lo, hi, access, _ in q.stage2_ranges(grant)],
                                  ranges=[[hex(x) for x in t] for t in q.triples()], define=QCC2072_WIFI_DEFINE,
                                  qualification='offline fixture admission (generation 1, fixed cookie); the boot '
                                                'admits live and draws a fresh cookie'))


def display_timing_checks(xb, dt, params, layout, qcc=False):
    """--present-beam's params block (appended last, after any input and QCC2072 blocks), its read-only stage-2 row and
    the two GPU-node properties, against probes/displaytiming.py."""
    import adreno
    import displaytiming as d
    need(xb.DISPLAY_TIMING is not None, 'no display timing in the image')
    gpu = dt.nodes[adreno.GPU_NODE]
    need(bytes(gpu[d.ABI_PROPERTY].value) == struct.pack('<I', d.ABI) and
         bytes(gpu[d.PA_PROPERTY].value) == struct.pack('<Q', d.INTF_PA), 'the GPU node\'s DPU INTF properties differ')
    block = list(struct.unpack_from(f'<{d.PARAMS_WORDS}Q', params, len(params) - 8 * d.PARAMS_WORDS))
    import i2cinput
    import qcc2072wifi
    before = (8 * i2cinput.PARAMS_WORDS if xb.GUEST_PROFILE.i2c_input is not None else 0) + \
             (8 * qcc2072wifi.PARAMS_WORDS if qcc else 0)
    need(len(params) == layout.size('params') + before + 8 * d.PARAMS_WORDS and d.rows(block) is not None,
         'params do not end with the display timing block')
    rows = [(lo, hi, access) for lo, hi, access, _ in xb.stage2_ranges() if (lo, hi) == (d.INTF_PA, d.INTF_PA + d.PAGE)]
    need(rows == [(d.INTF_PA, d.INTF_PA + d.PAGE, 'ro')], 'stage 2 lacks the read-only DPU INTF page')
    return dict(display_timing=dict(node=adreno.GPU_NODE, properties=[d.ABI_PROPERTY, d.PA_PROPERTY],
                                    params_words=[hex(w) for w in block], stage2=[hex(d.INTF_PA), hex(d.INTF_PA + d.PAGE),
                                    'ro'], define=DISPLAY_TIMING_DEFINE))


def qcc2072_stop(proxy):
    """After preservation: the QCC2072's bus mastering off (memory decode stays on), read back. Never raises, so a
    preserved stop stays preserved; a failure is recorded instead (the next Wi-Fi attempt needs a cold boot anyway:
    the card's firmware is left running)."""
    try:
        import qcc2072wifi
        return dict(qcc2072wifi.stop(proxy), at=time.time())
    except Exception as error:   # the record says what happened; --quiesce tries again
        return dict(error=repr(error), bus_master_off=None, at=time.time())


def inputs(root, dest, args=None):
    _, aux, _, _ = selected(args)
    paths = [root / aux, root / (aux + '.json'), root / ADDITIONS, root / TRUST_PAYLOAD,
             dest / 'root-hash.payload', dest / 'image4.bin', *(root / b for b in BRIDGE)]
    if getattr(args, 'qcc2072_wifi', False):
        import qcc2072wifi
        paths += [Path(aux).parent / 'build.json', *(dest / QCC2072_INPUTS / n for n in qcc2072wifi.INPUTS)]
    return {str(p): st.file_sha(p) for p in paths}


def prepare(ws, args, dest):
    need(args.variant in st.VARIANTS, 'prepare needs --variant control|fast')
    need(not dest.exists(), f'preserve previous attempt: {dest}')
    root = ws.root
    runner, layout, _ = modules(root)
    sys.path.insert(0, str(root / 'probes'))
    import auxkc
    sets, fast = st.flag_sets(root)
    flags = variant_flags(sets, args)
    sources = {str(p): sha(p) for p in source_paths(root)}
    profile_name, aux, aux_sha, bundles = selected(args)
    from guestprofile import get_profile as profile_of
    spec = profile_of(profile_name).i2c_input
    if spec is not None:
        try:
            spec.require_qualified()               # --input-touchpad: refused before anything is built
        except ValueError as error:
            need(False, str(error))
    need(st.file_sha(root / aux) == aux_sha, 'retained AuxKC changed')
    need(not re.search(rb'OSBundleRequireExplicitLoad</key>\s*<true/>', (root / aux).read_bytes()),
         'AuxKC kext requires an explicit load: run tools/auxkc-autoload.py on it')
    need(sha(root / ADDITIONS) == ADDITIONS_SHA, 'retained trust additions changed')
    _, pin = auxkc.load(root / aux, sha(root / FIRMWARE / 'kernelcache.release.mac17p'))
    need(pin['sha256'] == aux_sha and pin['bundles'] == bundles, 'AuxKC pin differs')
    component, payload = root_hash_payload(root)
    steps = gpu_steps(root, args)
    recover_table = recover_table_check(root, steps, args)
    ddr, llcc = ddr_plan(args), llcc_plan(args)
    for plan in (ddr, llcc):
        if plan and plan['probe']:
            plan['probe']['stub_sha256'] = bandwidth_tool(root)['sha'](bandwidth_tool(root)['build_stub']())
    dest.mkdir()
    (dest / 'root-hash.payload').write_bytes(payload)
    qcc_inputs = None
    if getattr(args, 'qcc2072_wifi', False):
        # The three inputs the provider verifies, copied here hash-checked: the boot reads only these.
        import qcc2072wifi
        try:
            qcc_inputs = qcc2072wifi.stage_inputs(dest / QCC2072_INPUTS)
        except (OSError, ValueError) as error:
            need(False, f'QCC2072 inputs refused: {error}')
    helper = txm_helper(root, dest)
    runner.FLAGS[:] = flags
    with st.environment(args.prefix), (dest / 'prepare.log').open('x') as stream, contextlib.redirect_stdout(stream):
        blob = runner.build('xnuboot', dest)
    context = st.build_layout(root, flags)
    image = image_checks(root, dest, layout, dest / 'root-hash.payload',
                         sysreg_zero=getattr(args, 'kernel_sysreg_zero', False), args=args,
                         refmod_skip=getattr(args, 'kernel_refmod_skip', False),
                         user_4k=getattr(args, 'kernel_user_4k', False), context_layout=context)
    need(all(sha(p) == h for p, h in sources.items()), 'sources changed during preparation')
    record = dict(schema=SCHEMA, status='OFFLINE_PREPARED_NOT_BOOTED', prefix=args.prefix, variant=args.variant,
                  device=args.device or ws.device, profile=profile_name, watchdog_seconds=run_watchdog(args), environment=environment(args),
                  flags=flags, fast_defines=fast if args.variant == 'fast' else [], gpu_steps=steps,
                  root_hash_component=component, txm_helper=helper, auxkc_pin=pin,
                  window_header_prefix=WINDOW_HEADER_PREFIX, boot_argument_addition=boot_addition(args),
                  inputs_sha256=inputs(root, dest, args), source_sha256=sources,
                  monitor_sha256=digest(blob), monitor_bytes=len(blob), elf_sha256=sha(dest / 'xnuboot.elf'),
                  context_bytes=context.size('context'), context_layout='build-defines', image=image,
                  **({'qcc2072_inputs': qcc_inputs} if qcc_inputs else {}),
                  **({'gpu_recover_table': recover_table} if recover_table else {}),
                  **({'ddr': ddr} if ddr else {}),
                  **({'llcc': llcc} if llcc else {}),
                  qualification='installed-SSD boot with our Adreno kext and Metal plug-in, admitted from '
                                'current sources and retained assets; not a cycle.py launch baseline')
    write(dest / 'qualification.json', record)
    return record


def check(ws, args, dest):
    path = dest / 'qualification.json'
    need(path.is_file(), 'run --prepare first')
    record = json.loads(path.read_text())
    need(record['schema'] == SCHEMA and record['prefix'] == args.prefix, 'wrong qualification')
    need(record['device'] == (args.device or ws.device), 'device differs from preparation')
    need(record['environment'] == environment(args) and record['profile'] == selected(args)[0] and
         record['boot_argument_addition'] == boot_addition(args), 'installed-fresh scope changed')
    # The profile is the same for every input collection, so the pinned AuxKC itself is compared: a boot without
    # the preparation's --present-damage (or --guest-net) would otherwise load another collection.
    need(record['auxkc_pin']['sha256'] == selected(args)[2],
         'the AuxKC differs from the preparation (give --present-damage/--present-cached-read/--present-gpumap/'
         '--present-vsync60/--present-dartpool/--present-resident/--present-beam/--present-va-reclaim/--gpu-va-wide/'
         '--present-latch/--edp-backlight/'
         '--input-ptp/--guest-net to every mode)')
    need(record['flags'] == variant_flags(st.flag_sets(ws.root)[0], args, record['variant']), 'variant flags differ from the recipe')
    need(record['gpu_steps'] == [list(s) for s in gpu_steps(ws.root, args)], 'GPU steps differ from the pinned launcher')
    plan = ddr_plan(args)
    recorded = record.get('ddr')
    need((plan is None) == (recorded is None) and (plan is None or (
        recorded['vote'] == plan['vote'] and recorded['restore'] == plan['restore'] and
        bool(recorded['probe']) == bool(plan['probe']))),
         'the DDR vote/probe differ from the preparation (give --ddr-vote/--bw-probe to every mode)')
    plan, recorded = llcc_plan(args), record.get('llcc')
    need((plan is None) == (recorded is None) and (plan is None or (
        recorded['activate'] == plan['activate'] and recorded['deactivate'] == plan['deactivate'] and
        bool(recorded['probe']) == bool(plan['probe']))),
         'the LLCC activation/probe differ from the preparation (give --llcc/--llcc-table/--bw-probe to every mode)')
    for name, expected in record['source_sha256'].items():
        need(sha(name) == expected, f'source changed: {name}')
    for name, expected in record['inputs_sha256'].items():
        need(st.file_sha(name) == expected, f'input changed: {name}')
    need(sha(dest / 'xnuboot.bin') == record['monitor_sha256'] and sha(dest / 'xnuboot.elf') == record['elf_sha256'],
         'prepared monitor changed')
    need(not (dest / 'launch.json').exists(), 'this attempt already has a launch record; never rerun it')
    from guestprofile import get_profile
    need(get_profile(selected(args)[0]).hashes(ws.root / FIRMWARE) == record['image']['firmware_sha256'],
         'firmware inputs changed')
    return record


HOST_IDENTITY = ('magic', 'version', 'arena_base')
# Every host-record field that names something live (an SMMU table, a booted GMU, an HFI or OOB session, a
# started CP, the ring, a hardware init, an SQE probe, P6/P7 state, a mapped framebuffer). A graceful quiesce
# releases all of them; the history counters (hfi_seq, fence_seq/value, rsc_cx/mx votes, tz_ok, pdc_sleep)
# stay, and a16gpu's steps account for them on a second cycle (votes already sent are not resent).
LIVE_TOKENS = ('gmu_ttbr', 'gpu_ttbr', 'boot_token', 'hfi_token', 'oob_token', 'cp_token', 'rb_wptr',
               'hwinit_token', 'sqe_probe', 'p67_token', 'fb_mapped')


def gpu_unprepared(status):
    """A read-only a16gpu status of a GPU nothing has prepared in this generation.
    q1n1 publishes a host record for its EFI-reserved arena at every boot; until a
    preparation step runs, every token in it is zero (seen on the A16 after a cold
    boot, installed-fresh-20261016-v2). So: no live GMU, and either no arena record
    or one whose tokens are all zero."""
    if (status.get('gmu') or {}).get('live') or 'order' not in status or status.get('stopped'):
        return False
    host = status.get('host_record')
    if host is None:
        return 'missing' in status.get('arena', {})
    tokens = {k: v for k, v in host.items() if k not in HOST_IDENTITY}
    return bool(tokens) and all(int(v, 16) == 0 for v in tokens.values())


def gpu_quiesced_after_use(status):
    """A read-only a16gpu status of a GPU that a previous attempt in this boot prepared and then quiesced
    gracefully: no live GMU, not stopped, the arena host record present with every live token released.
    q1n1's Stage 3 run 2 brought the GPU up again after such a quiesce on this A16 (A16-ADRENO-STAGE3.md)."""
    if (status.get('gmu') or {}).get('live') or 'order' not in status or status.get('stopped'):
        return False
    host = status.get('host_record')
    if not host or any(k not in host for k in LIVE_TOKENS):
        return False
    return all(int(host[k], 16) == 0 for k in LIVE_TOKENS)


def previous_quiesce(ws, root, prefix):
    """The attempt that last used the GPU in this boot (--after-quiesce): its captures verified, its GPU
    quiesced gracefully with no SError. Returns what the launch record keeps."""
    dest = root / 'build' / prefix
    launch = json.loads((dest / 'launch.json').read_text())
    need(launch['status'] in ('STOPPED_PRESERVED', 'FAILED', 'NO_GUEST_CALL'), f'{prefix}: stop state {launch["status"]}')
    if launch['status'] == 'STOPPED_PRESERVED':
        record = (dest / 'preservation.json').read_bytes()
        need(hashlib.sha256(record).hexdigest() == launch['preservation_sha256'], f'{prefix}: preservation record changed')
        for name, artifact in json.loads(record)['artifacts'].items():
            need(st.file_sha(dest / name) == artifact['sha256'], f'{prefix}: preserved {name} changed')
    quiet = json.loads((ws.q / 'build/a16-gpu' / f'{prefix}-quiesce.json').read_text())
    need(quiet.get('quiesce') == 'graceful' and not quiet.get('stopped') and serror_clear(quiet['serror_guard']['after']),
         f'{prefix}: the GPU was not quiesced gracefully')
    return dict(prefix=prefix, status=launch['status'], preservation_sha256=launch.get('preservation_sha256'),
                quiesce_sha256=st.file_sha(ws.q / 'build/a16-gpu' / f'{prefix}-quiesce.json'))


def a16gpu(ws, device, out, arguments, environment):
    """One a16gpu.py client; its record must not exist and must end unstopped."""
    log = out.with_suffix('.log')
    need(not out.exists() and not log.exists(), f'{out.name} already exists')
    # q1n1's build/ is untracked, so a fresh checkout has no build/a16-gpu/ yet.
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('x') as stream:
        result = subprocess.run([sys.executable, 'tools/a16gpu.py', '--device', device, '--out', str(out), *arguments],
                                cwd=ws.q, env=environment, stdout=stream, stderr=subprocess.STDOUT)
    record = json.loads(out.read_text()) if out.is_file() else {}
    return result.returncode, record


@contextlib.contextmanager
def boot_hooks(root, dest, record):
    """The two changes the base launcher made to the loader, made here explicitly:
    -timesync_bringup on the command line of the one xnuboot module run.py loads,
    and the SSD window header check plus APFS checkpoints when the window is armed."""
    import importlib.util
    sys.path.insert(0, str(root.parent / 'q1n1/tools'))
    import nvme_m3
    original_spec, original_arm = importlib.util.spec_from_file_location, nvme_m3.arm_window
    loader = (root / 'probes/xnuboot.py').resolve()
    injected = []

    def bound_spec(name, location, *a, **k):
        spec = original_spec(name, location, *a, **k)
        if name == 'xnuboot' and Path(location).resolve() == loader:
            need(not injected, 'the guest loader must be loaded exactly once')
            exec_module = spec.loader.exec_module

            def load_module(module):
                exec_module(module)
                need(module.BOOT_CMDLINE == BASE_CMDLINE, 'boot command line differs from the TimeSync base')
                module.BOOT_CMDLINE += ' ' + record['boot_argument_addition']
                injected.append(module.BOOT_CMDLINE)
                record['boot_cmdline'] = module.BOOT_CMDLINE
            spec.loader.exec_module = load_module
        return spec

    def checked_arm(nvme, guid, report):
        first, last = original_arm(nvme, guid, report)
        raw = nvme.read(first + nvme_m3.HEADER_OFF // nvme.lba_bytes, 4096 // nvme.lba_bytes)
        header = hashlib.sha256(raw).hexdigest()
        record['window_header_sha256'] = header
        need(header.startswith(WINDOW_HEADER_PREFIX), f'SSD window header {header[:16]} is not the last applied one')
        checkpoints = load('apfs_checkpoints', root / 'tools/apfs-checkpoints.py').capture(
            nvme, first, report['window_armed']['header'], dest / 'apfs-before.json')
        record['apfs_before'] = {n: x['latest_xid'] for n, x in checkpoints['containers'].items()}
        return first, last
    importlib.util.spec_from_file_location, nvme_m3.arm_window = bound_spec, checked_arm
    try:
        yield injected
    finally:
        importlib.util.spec_from_file_location, nvme_m3.arm_window = original_spec, original_arm


def refused_by_thermal_before_gpu(dest, launch):
    """True when the preserved run proves its monitor refused at a thermal checkpoint of xnuboot_prepare
    before GPU preparation (docs/INSTALLED-FRESH-ADMISSION-20261016.md, 2026-10-19): no guest, no
    secondary or relocated CPU (each launch follows the last checkpoint), and the monitor never adopted
    the GPU, so the work area holds no live CPU although the service word never parked. Evidence: exit 3,
    the report's prepare status -28 with nothing entered, a thermal report, and a GPU flow status of 0.
    The preservation record and what it binds are checked before they are read."""
    import a16_thermal
    if launch.get('status') != 'STOPPED_PRESERVED' or launch.get('exit_code') != 3 or \
            (launch.get('summary') or {}).get('cpus_active') != 0:
        return False
    record = (dest / 'preservation.json').read_bytes()
    if hashlib.sha256(record).hexdigest() != launch.get('preservation_sha256'):
        return False
    artifacts = json.loads(record)['artifacts']
    for name in ('report.bin', 'context.bin', 'work-locator.bin'):
        if name not in artifacts or st.file_sha(dest / name) != artifacts[name]['sha256']:
            return False
    report = (dest / 'report.bin').read_bytes()
    status, entered = struct.unpack_from('<2Q', report, 0)
    thermal = a16_thermal.decode(report[a16_thermal.REPORT_OFFSET:a16_thermal.REPORT_OFFSET + a16_thermal.SIZE])
    code = Path(__file__).resolve().parents[2]      # the decoders, wherever the run's records are
    runner = modules(code)[0]
    gpu = load('adreno_counters', code / 'tools/adreno_counters.py')
    flow = gpu.decode(report[runner.GPU_FLOW_OFFSET:runner.GPU_FLOW_OFFSET + gpu.SIZE])
    return status == (1 << 64) - 28 and entered == 0 and bool(thermal) and flow['status'] == 0


def predecessor_stop(root, prefix, layout):
    """What a parked predecessor left (--after-quiesce): its preserved work locator and the service words of
    its preserved context, which must still be the parked stop (cycle.py retire's native-stop criterion),
    or, for a predecessor refused by a thermal check before GPU preparation, the never-parked words it preserved.
    A predecessor whose loader refused before the guest call parked nothing: None, so admit() requires an
    empty locator."""
    dest = root / 'build' / prefix
    launch = json.loads((dest / 'launch.json').read_text())
    if launch['status'] == 'NO_GUEST_CALL' and not (dest / 'context.bin').exists():
        return None
    services = layout.offset('context', 'services')
    words = struct.unpack_from('<8Q', (dest / 'context.bin').read_bytes(), services)
    need(words[2] == PARKED_SERVICE_WORD or refused_by_thermal_before_gpu(dest, launch),
         f'{prefix}: preserved service word is not a parked stop')
    boot = launch['bootinfo']
    return dict(prefix=prefix, locator=(dest / 'work-locator.bin').read_bytes(), services_offset=services, words=words,
                boot={k: boot[k] for k in ('heap_base', 'image_base', 'stage_generation')})


def admit(proxy, record, generation, runner, predecessor=None):
    """The live preflight: EL2 generation N at its slot, SError guard, no guest, no host exception. A resident
    locator is admitted only for --after-quiesce, and only when it is the predecessor's preserved locator and the
    work area it names still holds the predecessor's parked service words: every secondary of that run went to
    PSCI CPU_OFF before its primary returned (xnuboot.c secondary_collect), so its work area holds no live CPU."""
    import monitor_work
    info = proxy.bootinfo()
    need(info['current_el'] == 2 and info['stage_generation'] == generation,
         f'requires EL2 generation {generation}; found {info["stage_generation"]} at EL{info["current_el"]}')
    need(info['image_base'] == image_base(generation), 'stage is not in the slot its generation selects')
    need(proxy.stage_features() & 1, 'stage has no SError guard')
    locator = proxy.readmem(monitor_work.locator_address(info), monitor_work.LOCATOR_SIZE)
    if locator not in (bytes(len(locator)), bytes([0xaf]) * len(locator)):
        need(predecessor is not None, 'a guest locator already occupies this stage')
        need(locator == predecessor['locator'], f'the resident locator is not {predecessor["prefix"]}\'s preserved one')
        # The locator binds the q1n1 heap and the stage generation that wrote it: the same q1n1 boot (heap
        # unchanged, so no reset since) at the predecessor's generation.
        need(predecessor['boot']['heap_base'] == info['heap_base'], f'{predecessor["prefix"]} ran in another q1n1 boot')
        work, size = monitor_work.decode_locator(locator, dict(info, **predecessor['boot']),
                                                 monitor_work.firmware_free(proxy, info))
        at = work + predecessor['services_offset']
        raw = proxy.readmem(at, 64)
        need(struct.unpack('<8Q', raw) == tuple(predecessor['words']) and proxy.readmem(at, 64) == raw,
             f'{predecessor["prefix"]}\'s live service words are not its preserved parked stop')
        record.setdefault('predecessor_stop', dict(prefix=predecessor['prefix'], work=hex(work), bytes=size,
                                                   locator_sha256=hashlib.sha256(locator).hexdigest(),
                                                   service_hex=raw.hex()))
    guard = proxy.serror_state()
    need(serror_clear(guard) and not proxy.get_exc_count(), 'host exceptions before boot')
    return info


def boot(ws, args, dest, qualification):
    need(args.qualification_sha256 == sha(dest / 'qualification.json'), 'boot needs the exact qualification SHA256')
    need(args.generation and args.generation >= 1, 'boot needs --generation N >= 1 (a chainloaded stage)')
    root, device = ws.root, args.device or ws.device
    runner, layout, admission = modules(root)
    # The build's layout for the private context (st.build_layout): run.py sizes the guest-readable table window
    # with runner.FLAGS and the capture retains the whole context. layout stays define-free for the params blocks
    # and the predecessor's service words, which sit before every define-dependent field.
    runner.FLAGS[:] = qualification['flags']
    context = st.build_layout(root, qualification['flags'])
    need(qualification.get('context_layout') != 'build-defines' or
         qualification['context_bytes'] == context.size('context'), 'the build\'s context size changed since prepare')
    gpu_dir = ws.q / 'build/a16-gpu'
    out = lambda name: gpu_dir / f'{args.prefix}-{name}.json'
    record = dict(schema='snapintosh-installed-fresh-launch-v1', status='PREFLIGHT', started=time.time(),
                  qualification_sha256=args.qualification_sha256, variant=qualification['variant'],
                  boot_argument_addition=qualification['boot_argument_addition'],
                  flags=qualification['flags'], monitor_sha256=qualification['monitor_sha256'],
                  monitor_bytes=qualification['monitor_bytes'], source_sha256=qualification['source_sha256'],
                  uploads=[], calls=[], gpu={}, pid=os.getpid())
    path = dest / 'launch.json'
    write(path, record)
    proxy = witness = info = None
    gpu_env = dict(os.environ, A16_GPU_FW_DIR=str(root / 'gpu/adreno/gpu-bringup-q1n1/fw'))
    try:
        admission.other_clients(device)
        proxy = runner.connect(device, tries=1)
        after = getattr(args, 'after_quiesce', None)
        predecessor = predecessor_stop(root, after, layout) if after else None
        record['bootinfo'] = first = admit(proxy, record, args.generation, runner, predecessor)
        proxy.link.close()
        proxy = None
        plan = qualification.get('ddr')
        if plan:
            # agents/dvfs lever 1, before anything of the GPU's: the probe, the DDR vote, the probe again.
            record['ddr'] = dict(restore=plan['restore'])
            if plan['probe']:
                record['ddr']['probe_before'] = bandwidth_probe(root, runner, device, dest, 'before', args.generation,
                                                                plan['probe'])
                write(path, record)
            record['ddr']['attempted'] = True         # quiesce sends the restore even after an uncertain vote
            write(path, record)
            code, step = a16gpu(ws, device, out('ddr'), plan['vote'], gpu_env)
            record['ddr']['vote'] = dict(exit=code, stopped=step.get('stopped'),
                                         sha256=st.file_sha(out('ddr')) if out('ddr').is_file() else None,
                                         sent=(step.get('ddr') or {}).get('sent'))
            write(path, record)
            need(code == 0 and step.get('stopped') is None, f'DDR vote stopped: {step.get("stopped")}')
            if plan['probe']:
                record['ddr']['probe_after'] = bandwidth_probe(root, runner, device, dest, 'after', args.generation,
                                                               plan['probe'])
                write(path, record)
        llcc = qualification.get('llcc')
        if llcc:
            # agents/dvfs section 6, still before anything of the GPU's: the LLCC slices, bracketed by the probe.
            record['llcc'] = dict(deactivate=llcc['deactivate'])
            if llcc['probe'] and not (plan and plan['probe']):
                record['llcc']['probe_before'] = bandwidth_probe(root, runner, device, dest, 'before', args.generation,
                                                                 llcc['probe'])
            record['llcc']['attempted'] = True        # quiesce deactivates what the record shows activated
            write(path, record)
            code, step = a16gpu(ws, device, out('llcc'), llcc['activate'], gpu_env)
            slices = ((step.get('llcc') or {}).get('slices') or {})
            record['llcc']['activate'] = dict(exit=code, stopped=step.get('stopped'),
                                              sha256=st.file_sha(out('llcc')) if out('llcc').is_file() else None,
                                              version=(step.get('llcc') or {}).get('version'),
                                              banks=(step.get('llcc') or {}).get('banks'),
                                              activated=[n for n, e in slices.items() if e.get('activated')],
                                              skipped=[n for n, e in slices.items() if e.get('skipped')])
            write(path, record)
            need(code == 0 and step.get('stopped') is None, f'LLCC activation stopped: {step.get("stopped")}')
            if llcc['probe']:
                record['llcc']['probe_after'] = bandwidth_probe(root, runner, device, dest, 'after-llcc',
                                                                args.generation, llcc['probe'])
                write(path, record)
        # The GPU, read-only, then the established preparation: one client at a time.
        code, status = a16gpu(ws, device, out('status'), ['status'], gpu_env)
        record['gpu']['status'] = dict(exit=code, record=str(out('status')))
        if after:
            record['gpu']['after_quiesce'] = previous_quiesce(ws, root, after)
            need(code == 0 and (gpu_unprepared(status) or gpu_quiesced_after_use(status)),
                 'the GPU holds live state; quiesce it gracefully first')
            record['gpu']['gate'] = 'cold' if gpu_unprepared(status) else 'after-quiesce'
        else:
            need(code == 0 and gpu_unprepared(status), 'the GPU is already prepared in this generation; quiesce, cold boot')
            record['gpu']['gate'] = 'cold'
        write(path, record)
        for name, arguments in qualification['gpu_steps']:
            code, step = a16gpu(ws, device, out(name), arguments, gpu_env)
            record['gpu'][name] = dict(exit=code, stopped=step.get('stopped'), sha256=st.file_sha(out(name)))
            write(path, record)
            need(code == 0 and step.get('stopped') is None, f'GPU step {name} stopped: {step.get("stopped")}')
            if name == 'guard':
                need(step['serror_guard']['present'], 'GPU guard step found no SError guard')
        adoption = out('adopt').with_name(f'{args.prefix}-adopt-record.json')
        va_wide = qualification['environment'].get('SNAP_ADRENO_VA_WIDE') == '1'   # --gpu-va-wide's q1n1 half
        # --gpu-coherent's q1n1 half: adopt also proves CB0 MAIR0/CBAR read-only (the record is the same).
        coherent = ['--coherent'] if GPU_COHERENT_DEFINE in qualification['flags'] else []
        code, _ = a16gpu(ws, device, out('adopt'), ['adopt', '--record', str(adoption), *(['--va-wide'] if va_wide else []),
                                                    *coherent], gpu_env)
        need(code == 0 and adoption.is_file(), 'GPU adoption refused')
        record['gpu']['adoption'] = dict(path=str(adoption), sha256=st.file_sha(adoption))
        proxy = runner.connect(device, tries=1)
        info = admit(proxy, record, args.generation, runner, predecessor)
        need({k: info[k] for k in IDENTITY} == {k: first[k] for k in IDENTITY},
             'stage identity changed during GPU preparation')
        import adreno
        adreno.load_adoption(json.loads(adoption.read_text()), info, va_wide)
        witness = st.SpeedWitness(proxy, path, record, info['heap_base'] + runner.CODE_AT)
        need(info['battery_call'] and info['battery_result'], 'firmware has no live battery helper')
        status = witness.call(info['battery_call'], 0, 0, 0, 0, 0, timeout=12)
        battery = proxy.live_battery_record(info['battery_result'])
        record['battery'] = battery
        # The project's battery policy (cycle_lib.common.battery_minimum: pins.json default, SNAP_BATTERY_MINIMUM).
        minimum = record['battery_minimum_without_ac'] = battery_minimum(None)
        need(status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= minimum),
             f'battery preflight refused: below {minimum}% without AC')
        long_run = int(qualification['environment'].get('SNAP_WATCHDOG', WATCHDOG)) > WATCHDOG
        need(battery['ac'] or not long_run, f'battery preflight refused: a watchdog above {WATCHDOG} s needs AC')
        record['status'] = 'BOOTING'
        write(path, record)
        # The resident stage binds to its own ELF (probes/stagebind.py): the regular q1n1 build, or the gadget-NCM
        # stage tools/a16-link-rearm.py arms after a reset (q1n1 build/uefi-gadget-ncm, Q1N1_GADGET_NCM) when built.
        stage_builds = [ws.q / 'build/uefi'] + [p for p in [ws.q / 'build/uefi-gadget-ncm'] if p.is_dir()]
        settings = dict(qualification['environment'], SNAP_SMP_REPORT_PREFIX=args.prefix, SNAP_ADRENO_ADOPT=str(adoption),
                        SNAP_TXM_NATIVE=str(dest / 'image4.bin'),
                        SNAP_STAGE_BUILDS=os.pathsep.join(str(p) for p in stage_builds))
        if settings.get('SNAP_QCC2072_WIFI'):
            # probes/run.py reads the prepared, hash-pinned inputs (check() re-verified them above).
            settings['SNAP_QCC2072_INPUTS'] = str(dest / QCC2072_INPUTS)
        record['environment'] = settings
        saved = dict(os.environ)
        try:
            for key in [k for k in os.environ if k.startswith('SNAP_')]:
                del os.environ[key]
            os.environ.update(settings)
            with boot_hooks(root, dest, record), (dest / 'boot.log').open('x') as stream, \
                    contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                record['exit_code'] = runner.run(witness, (dest / 'xnuboot.bin').read_bytes(), 'xnuboot', device,
                    dict(guest_profile=qualification['profile'], firmware_dir=str(root / FIRMWARE), console_mode='serial',
                         root_hash=str(dest / 'root-hash.payload'), auxkc=str(root / selected(args)[1]),
                         trust_additions=str(root / ADDITIONS), ans_writable=True))
        finally:
            os.environ.clear()
            os.environ.update(saved)
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
                st.capture(witness, info, runner, context, dest, record)
                record['status'] = 'STOPPED_PRESERVED'
                if (record.get('environment') or {}).get('SNAP_QCC2072_WIFI'):
                    record['qcc2072_stop'] = qcc2072_stop(witness)
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
            record['summary'] = st.decode(ws, dest, record)
        except Exception as error:   # an observer gap, never a guest result; the raw bytes are retained
            record['decode_error'] = repr(error)
        write(path, record)
    return record


CHECKSUM_FREEZE = 'link.readmem failed: ProxyError: read data checksum error at '


def host_read_freeze(launch):
    """A control failure whose only unknown is one host-side read (docs/INSTALLED-FRESH-ADMISSION-20261016.md,
    v75): the guard froze on a link read checksum error with nothing native in flight, every call returned,
    none was the guest call, and the monitor never returned an exit code. Any other freeze stays unknown."""
    guard = launch.get('control_guard') or {}
    calls = launch.get('calls') or []
    return (launch.get('status') == 'CONTROL_FAILURE_NO_FURTHER_TARGET_IO' and guard.get('frozen') is True and
            guard.get('native_inflight') is None and str(guard.get('reason', '')).startswith(CHECKSUM_FREEZE) and
            all(c.get('returned') is True and c.get('main_guest') is False for c in calls) and
            'exit_code' not in launch)


def quiesce(ws, args, dest):
    """After preservation: the graceful GPU quiesce the preparation requires."""
    launch = json.loads((dest / 'launch.json').read_text())
    # Any GPU write step (everything but the read-only status) leaves the GPU to quiesce,
    # including a preparation that stopped partway.
    need(any(name != 'status' for name in launch.get('gpu', {})), 'nothing prepared the GPU in this attempt')
    need(launch['status'] in ('STOPPED_PRESERVED', 'FAILED', 'NO_GUEST_CALL') or host_read_freeze(launch),
         'stop state unknown; recover it first')
    root, device = ws.root, args.device or ws.device
    runner, _, admission = modules(root)
    admission.other_clients(device)
    out = ws.q / 'build/a16-gpu' / f'{args.prefix}-quiesce.json'
    code, quiet = a16gpu(ws, device, out, ['quiesce', '--write'],
                         dict(os.environ, A16_GPU_FW_DIR=str(root / 'gpu/adreno/gpu-bringup-q1n1/fw')))
    need(code == 0 and quiet.get('quiesce') == 'graceful' and not quiet.get('stopped'), 'quiescence was not graceful')
    need(serror_clear(quiet['serror_guard']['after']), 'SError after quiescence')
    write(dest / 'quiesce.json', dict(path=str(out), sha256=st.file_sha(out), quiesce='graceful'))
    if (launch.get('environment') or {}).get('SNAP_QCC2072_WIFI'):
        # --qcc2072-wifi: bus mastering off again (boot() did it after preservation; this confirms it).
        proxy = runner.connect(device, tries=1)
        try:
            stopped = qcc2072_stop(proxy)
        finally:
            proxy.link.close()
        write(dest / 'qcc2072-quiesce.json', stopped)
        need(stopped.get('bus_master_off') is True, f'QCC2072 bus mastering not confirmed off: {stopped}')
    ddr = launch.get('ddr') or {}
    if ddr.get('attempted'):
        # --ddr-vote: the explicit restore vote (a16gpu_ddr.py: the GPU OPP-1 row); a cold boot resets RPMh anyway.
        restore = ws.q / 'build/a16-gpu' / f'{args.prefix}-ddr-restore.json'
        code, restored = a16gpu(ws, device, restore, ddr['restore'], dict(os.environ))
        write(dest / 'ddr-restore.json', dict(path=str(restore), exit=code,
                                              sha256=st.file_sha(restore) if restore.is_file() else None,
                                              stopped=restored.get('stopped'),
                                              sent=(restored.get('ddr') or {}).get('sent')))
        need(code == 0 and restored.get('stopped') is None, f'DDR restore vote stopped: {restored.get("stopped")}')
    llcc = launch.get('llcc') or {}
    ours = (llcc.get('activate') or {}).get('activated') or []
    if llcc.get('attempted') and not ours and (llcc.get('activate') or {}).get('exit') != 0:
        # An activation that stopped partway: which slices it left active is in its q1n1 record, not here.
        ours = LLCC_SLICES.split(',')
    if llcc.get('attempted') and ours:
        # --llcc: the slices this boot activated, back to deactivated (after the GPU's quiesce: no GPU traffic).
        record = ws.q / 'build/a16-gpu' / f'{args.prefix}-llcc-deactivate.json'
        code, done = a16gpu(ws, device, record, [*llcc['deactivate'], '--slices', ','.join(ours)], dict(os.environ))
        write(dest / 'llcc-deactivate.json', dict(path=str(record), exit=code, slices=ours,
                                                  sha256=st.file_sha(record) if record.is_file() else None,
                                                  stopped=done.get('stopped')))
        need(code == 0 and done.get('stopped') is None, f'LLCC deactivation stopped: {done.get("stopped")}')
    return quiet


def main(ws, args):
    need(args.prefix and re.fullmatch('[a-z0-9-]+', args.prefix), 'invalid or missing --prefix')
    dest = ws.root / 'build' / args.prefix
    sys.path.insert(0, str(ws.root / 'probes'))
    if args.prepare:
        prepare(ws, args, dest)
    if args.prepare or args.check or args.boot:
        record = check(ws, args, dest)
    if args.boot or args.quiesce:
        import fcntl
        with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.boot:
                result = boot(ws, args, dest, record)
                print(json.dumps({k: result.get(k) for k in ('status', 'exit_code', 'exit_name', 'error',
                                                             'capture_error', 'decode_error', 'preservation_sha256')},
                                 indent=2))
                return 0 if result.get('status') == 'STOPPED_PRESERVED' else 1
            quiet = quiesce(ws, args, dest)
            print(json.dumps(dict(status='GPU_QUIESCED', quiesce=quiet.get('quiesce')), indent=2))
            return 0
    print(json.dumps(dict(status='OFFLINE_READY_NOT_BOOTED', variant=record['variant'],
                          qualification=str(dest / 'qualification.json'),
                          sha256=sha(dest / 'qualification.json'), hardware_access=False), indent=2))
    return 0
