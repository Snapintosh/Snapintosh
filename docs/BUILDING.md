# Building

All builds run on a Mac. Nothing here touches the A16; booting is covered in
[RUNNING.md](RUNNING.md). Run every command from the repository root unless
stated otherwise.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| macOS 27 with Xcode | The macOS 27 SDK and `xcrun clang`, for the arm64e kexts and the plug-in |
| Kernel Debug Kit for 26A428 | Installed at `/Library/Developer/KDKs/KDK_27.0_26A428.kdk`. `kmutil` links AuxKCs against it, and `tools/kc-symbolicate.py` uses its symbols |
| Python 3 | For every host tool |
| Homebrew `llvm`, `meson`, `ninja` | For the air2ir3 shader compiler and its Mesa build. The scripts expect LLVM at `/opt/homebrew/opt/llvm` |
| Submodules | Clone with `git clone --recurse-submodules`, or run `git submodule update --init` in an existing checkout. The kext, plug-in, shader compiler and two drivers live in their own repositories (see the README's Repositories section) |
| q1n1 | A checkout of [q1n1](https://github.com/Snapintosh/q1n1) next to this repository, at `../q1n1`. Several tools import its proxy client and helpers from there |

## 1. Apple inputs

The repository ships no Apple files. Fetch the macOS 27 (26A428) restore image
and extract the J700 boot set:

```sh
python3 tools/fetch-ipsw.py <ipsw-url> downloads/UniversalMac_27.0_26A428_Restore.ipsw
python3 tools/extract-firmware.py downloads/UniversalMac_27.0_26A428_Restore.ipsw j700ap
```

`fetch-ipsw.py` resumes interrupted downloads. `extract-firmware.py` reads
`BuildManifest.plist`, picks the `j700ap` identity, and unwraps its kernelcache,
device tree, TXM, iBoot and SEP images into `downloads/extracted/j700ap/`
(`--output` to change it). Every later step is pinned against these exact
images.

Install the 26A428 KDK from Apple's developer downloads.

The GPU and Wi-Fi firmware is supplied on the q1n1 side. See q1n1's
documentation and the "Bring your own Apple software" section of the
[README](../README.md).

### Generated inputs that are not in the repository

Some build inputs are derived from Apple software. They are not distributed,
so you generate them from your own copies.

**Apple class-layout headers.** The kexts subclass private Apple IOKit
classes. They need headers that reconstruct those class layouts for build
26A428:

| Header | Directory | How to produce it |
| --- | --- | --- |
| `IOMobileGraphicsFamily26A428.h` | `gpu/adreno-kext/kext/include/` | `python3 tools/gen-iomfb-header.py --kc downloads/extracted/j700ap/kernelcache.release.mac17p` (reads the KDK at its default path; `--kdk` changes it) |
| `IOGPUFamily26A428.h` | `gpu/adreno-kext/kext/include/` | reconstruct from your KDK; step-by-step recipe in [AGENTS.md](../AGENTS.md#recipe-a-header-for-a-private-apple-c-class-arm64e) |
| `IO80211Controller26A428.h`, `IO80211Interface26A428.h`, `IO80211WorkQueue26A428.h`, `IOSkywalkLifecycle26A428.h` | `drivers/snap-qcc2072/include/` | reconstruct from your KDK; step-by-step recipe in [AGENTS.md](../AGENTS.md#recipe-a-header-for-a-private-apple-c-class-arm64e), using the output of `drivers/snap-qcc2072/re/recover-controller-abi.py` |

`gpu/adreno-kext/kext/build.sh` and `drivers/snap-qcc2072/build.sh` stop with
an error that names any missing header.

**air2ir3 reference inputs.** These are needed only for the compiler's
on-device comparison tests:

- `gpu/air2ir3/tools/a16ref/probes.air` is built by
  `gpu/air2ir3/tools/a16ref/build-probes-air.sh`.
- The pinned shader sets (`tools/a16ref/render-shaders.pinned.json` and
  `tools/p7ref/p7-shaders*.json` under `gpu/air2ir3/`) are compiled from Apple's
  shaders. Generate them locally with q1n1's `tools/a16gpu-render/` and
  `gpu/air2ir3/tools/p7ref/make-p7-shaders.sh`.

**Machine pins.** `tools/cycle_lib/pins.json` holds per-machine values and is
not committed. Copy `tools/cycle_lib/pins.example.json` to
`tools/cycle_lib/pins.json`, and set `device` (`udp://enN`, the Mac's NCM
interface) and the q1n1 stage hashes for your build.

## 2. The shader compiler (air2ir3)

```sh
cd gpu/air2ir3
tools/mesa-setup.sh       # clone Mesa at the pinned revision, apply patches/, configure
tools/mesa-ninja.sh       # build only the Mesa libraries air2ir3 links
src/build.sh all          # air2ir3, libair2ir3.a and the test tools
```

`MESA_URL` can point `mesa-setup.sh` at a local mirror. Its tests and inputs
are in [gpu/air2ir3/README.md](../gpu/air2ir3/README.md).

## 3. The kexts

Each build script writes to `$OUT`, or to a default `out/` directory next to
it:

```sh
OUT=build/adrenox2 sh gpu/adreno-kext/kext/build.sh      # AdrenoX2.kext (with AdrenoDisplay)
OUT=build/snapi2chid sh drivers/snap-i2c-hid/build.sh    # SnapI2CHID.kext
OUT=build/qcc2072 sh drivers/snap-qcc2072/build.sh       # SnapintoshQCC2072.kext (refuses an existing OUT)
```

The kext builds use only the SDK's Kernel.framework. Undefined IOGPUFamily,
IOHIDFamily and kernel symbols are resolved when the AuxKC is linked. The
AdrenoX2 build accepts feature defines (for example `ADRENO_BEAM`,
`ADRENO_PIPELINE`, `ADRENO_PRESENT_SYNC`). The boot tool selects the matching
build for each run flag.

The deployed desktop kexts are build profiles: per-unit define sets kept in
each component's `profiles/` folder. Without `PROFILE` the builds are unchanged.

```sh
PROFILE=desktop sh gpu/adreno-kext/kext/build.sh              # AdrenoX2 with IO-coherent skipping (--gpu-coherent)
PROFILE=desktop-nocoherent sh gpu/adreno-kext/kext/build.sh   # the same without coherency
PROFILE=desktop sh drivers/snap-i2c-hid/build.sh              # SnapI2CHID with input-latency polling
```

A profile writes `DEFINES.txt` beside the kext. Compare a build with a deployed
kext using `python3 tools/macho-sections.py <deployed> <built>`: the sections
match, while the file bytes also carry object paths, object times and a UUID.

## 4. Linking an AuxKC

`kmutil` silently drops kexts that are not owned by `root:wheel`, and it still
exits 0. `build/kmutil-auxkc.sh` stages root-owned copies and then checks that
the output holds exactly the requested bundles:

```sh
sudo build/kmutil-auxkc.sh build/aux/aux.kc build/adrenox2/AdrenoX2.kext build/snapi2chid/SnapI2CHID.kext
python3 build/build-auxkc.py pin --kc build/aux/aux.kc --guest-profile <profile> \
    --bundle org.snapintosh.driver.AdrenoX2 --bundle <other-bundle-id>
```

`pin` admits the collection and writes `aux.kc.json`, which the loader
requires. `python3 build/build-auxkc.py link --out <dir> --kext <kext> ...` runs
stage, link and pin in one step. `tools/build-auxkc-user.py` links raw
collections the same way. It runs `kmutil` as you and uses ordinary `sudo`
(it prompts unless a sudo session is cached) only to stage and clean the
root-owned copies.

`tools/build-auxkc-desktop.sh NAME` builds the desktop collection from this
checkout: both kexts with their `desktop` profiles (`KEXT_PROFILE=desktop-nocoherent`
for AdrenoX2 without coherency), then `tools/build-auxkc-user.py`,
`tools/auxkc-autoload.py` and `build/build-auxkc.py pin`. It writes
`build/current-assets/NAME/`, prints the sha256 of every output and the two
`tools/cycle_lib/installed_fresh.py` lines that pin the collection, and with
`REFERENCE=<folder>` compares both kexts with a deployed collection's.

To link the Wi-Fi controller into an existing guest collection, while keeping
its graphics and input bundles:

```sh
python3 tools/build-qcc2072-native.py --output build/native-wifi \
    --baseline <base-collection> --expected-baseline-sha256 <sha256>
```

## 5. The Metal plug-in

```sh
OUT=build/plugin sh gpu/adreno-kext/plugin/build.sh
```

This builds `AdrenoMetal.bundle` (arm64e, like every IOGPU plug-in) and a small
host test harness (`regtest`). Optional environment variables:

- `ADRENO_LENIENT=1` drops a pass the encoder refuses instead of failing the
  command buffer. Use it for deployment; the tests use the strict default.
- `ADRENO_PIPELINE=1` builds for the desktop AdrenoX2's IB pipeline (IOSurface
  shadows wait for the GPU). The deployed plug-ins use it with `ADRENO_LENIENT=1`.
- `ADRENO_SETTINGS_ICONS=1` encodes the CoreImage kernels of the icons inside
  System Settings panes: sampled sRGB and grey+alpha textures, and multi-input
  kernels once AdrenoX2 publishes `AdrenoIBComputeSamplers` (its
  `ADRENO_IB_CS_SAMPLERS`, opted in with the guest boot-arg
  `adreno_cs_samplers=1`). `tools/test-adreno-settings-icons.py` and
  `tools/test-adreno-settings-ci-encoding.py` test it.

`ADRENO_PIPELINE` and `ADRENO_SETTINGS_ICONS` take 0 or 1; 0 or unset leaves the
build byte for byte as without them.
- `ADRENO_SHADER_CACHE_PACK=<file>` links a precompiled shader pack into the
  bundle.
- `ADRENO_COMPILER_RUNTIME=<dir>` bundles the air2ir3 runtime
  (`libAdrenoCompiler.dylib`).

`tools/build-adreno-arm64e-mesa.py` builds the patched Mesa compiler libraries
as arm64e, for the compiler runtime that runs inside the guest.

The harnesses in `gpu/adreno-kext/plugin/harness/` run the plug-in on the Mac
against an interposed Metal device, which is how most rendering work is tested
before it reaches the A16.

## 6. The monitor and guest image

The EL2 monitor (`compat/`, `shadow/`) and the loader (`probes/xnuboot.*`) are
built by the boot tool's prepare step. That step compiles the monitor with the
defines selected by the run flags and records the hashes of every input:

```sh
python3 tools/cycle.py installed-fresh --prepare --variant fast --prefix <run-prefix> [run flags...]
python3 tools/cycle.py installed-fresh --check   --variant fast --prefix <run-prefix> [run flags...]
```

`--check` repeats every validation without touching hardware, and prints the
qualification hash that `--boot` requires. See [RUNNING.md](RUNNING.md).

## 7. Host tests

The native suites link the real monitor sources against models. They need no
firmware and no hardware. Each C test carries its build line in its header,
for example:

```sh
mkdir -p build
cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow \
   tools/test-shadow.c shadow/mmu.c shadow/shadow.c -o build/test-shadow && build/test-shadow
cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow \
   tools/test-mmu.c shadow/mmu.c -o build/test-mmu && build/test-mmu

python3 tools/test-cycle.py       # the boot-cycle tool's checks and refusals
python3 tools/test-classify.py    # how a run's ending maps to an exit code
python3 tools/test-profile.py     # the boot profile and the physical layout
```

`test-shadow` walks the 16 KiB guest tables and the 4 KiB shadow at the same
address and compares the two. It does not check against hand-written
expectations.

`tools/qemu-sptm-oracle/setup.sh` builds jprx's qemu-sptm with an SPTM-call
tracer. `tools/qemu-sptm-oracle/run.sh <out> [seconds]` then boots Apple's real
SPTM/TXM with the same kernelcache and records how it behaves, as ground truth
for the monitor's implementation. The tracer patch is GPL-2.0-or-later.

There is no CI. Everything is built and run by hand.
