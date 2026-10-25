# Running

This document walks through one boot of the installed macOS on the A16, driven
from the Mac with `tools/cycle.py`. Placeholders are in angle brackets.

> Read the warning in the [README](../README.md) first. A run programs the GPU,
> clocks and memory-bandwidth votes, and the guest writes the internal SSD.

## Before the first run

- q1n1 is installed on the A16 as a UEFI boot entry, and macOS 27 is installed
  on the internal NVMe. See q1n1's `docs/A16-INSTALL.md` and
  [FULL-INSTALL.md](FULL-INSTALL.md).
- The Apple inputs are extracted and the components are built
  ([BUILDING.md](BUILDING.md)).
- The A16 is connected to the Mac by USB-C, and preferably on AC power. Every
  hardware mode refuses to start below the battery threshold
  (`--battery-minimum` can raise it, never lower it).
- Find the Mac-side network interface that q1n1's USB NCM link created (for
  example with `ifconfig`). Pass it to every hardware command as
  `--device udp://<interface>`. The name changes with the USB port.
- On q1n1's gadget-NCM link (the one `a16-link-rearm.py arm` brings back after
  a reset, q1n1's `docs/A16-USB-REARM.md`), run with `Q1N1_UDP_RETRIES=2` in
  the environment. A memory write that loses a datagram is then
  resynchronised and repeated by q1n1's Link, and the control guard records
  each loss (`transport_loss`, `transport_loss_recovered` in the launch
  record's `control_guard` events) instead of freezing the session. Any other
  transport failure, and a write that still fails, freezes it as before.
- Create `tools/cycle_lib/pins.json` from `tools/cycle_lib/pins.example.json`
  and fill in the device and stage hashes ([BUILDING.md](BUILDING.md)).

## The cycle

`tools/cycle.py` runs one boot as a fixed sequence. Each mode records what it
did under `build/<run-prefix>*`, checks the records of the previous step, and
refuses when the machine is not in the state that step expects. Every mode has
an offline `--check` that validates everything without touching hardware. At
any point,

```sh
python3 tools/cycle.py next
```

prints the exact next command for the current records.

### 1. Cold boot into q1n1

Power the A16 on into q1n1, or from the Mac:

```sh
python3 ../q1n1/tools/a16ctl.py boot q1n1
python3 tools/cycle.py status
```

`status` makes one read-only proxy query: the generation, the exception level,
the image base, any SError, and the battery.

### 2. Move to an idle, chainloaded generation

A boot runs on a freshly chainloaded q1n1 generation, never on the cold-booted
one:

```sh
python3 tools/cycle.py retire --idle --prefix <label>
```

This chainloads the other stage slot and confirms that the next generation is
idle. Use the generation number it reports below.

### 3. Prepare and check

```sh
python3 tools/cycle.py installed-fresh --prepare --variant fast --prefix <run-prefix> \
    --device udp://<interface> [run flags...]
python3 tools/cycle.py installed-fresh --check --variant fast --prefix <run-prefix> \
    --device udp://<interface> [run flags...]
```

`--prepare` builds the monitor with the defines the run flags select, and
assembles the guest image, the AuxKC and the q1n1 GPU steps. Every input is
pinned by SHA-256: the AuxKC and plug-in builds the flags refer to, and the
Apple images. A missing or different input is refused. `--check` repeats all
validation offline and prints the **qualification hash**. Give the same run
flags to every mode of a run.

`--variant` picks the monitor: `fast` (lock-free fast paths) or `control`
(the reference monitor).

### 4. Boot

```sh
python3 tools/cycle.py installed-fresh --boot --variant fast --prefix <run-prefix> \
    --device udp://<interface> --generation <N> --qualification-sha256 <hash> [run flags...]
```

The boot runs these steps:

1. a read-only GPU status check;
2. q1n1's GPU power-up steps (and the DDR and LLCC votes, if requested);
3. the monitor's adoption of the GPU;
4. the start of the guest.

It then follows the guest until it stops, and captures the stopped state.
Only one hardware client may run at a time. Never interrupt a running boot,
and never start a second client against it.

While the guest runs:

```sh
# a live console (with --console); --stream only watches, --run sends one command
python3 tools/guest-console.py --device udp://<interface> \
    --launch-record build/<run-prefix>-early-stop-launch.json
# ask the guest to stop early, for example once the desktop is up
python3 tools/request-stop.py --device udp://<interface> --reason "<text>"
```

The guest also stops on its own: on a kernel panic, when the thermal guard
trips (`--thermal-guard`), at the early-stop delay after the first present
(`--early-stop-delay`), or at the watchdog.

The watchdog is 1800 s unless `--watchdog SECONDS` sets it, up to 7200. Above
1800 s the boot preflight requires the A16 on AC. For a desktop session to use,
`--console --session --watchdog 7200` drops the kext's first-present stop, so
the run lasts until the watchdog (exit 9), the thermal guard, or
`tools/request-stop.py`.

### 5. Preserve, quiesce, retire

```sh
python3 tools/cycle.py preserve --prefix <run-prefix>              # prints the preservation hash
python3 tools/cycle.py installed-fresh --quiesce --prefix <run-prefix> --device udp://<interface> [run flags...]
python3 tools/cycle.py retire --prefix <run-prefix> --preservation-sha256 <hash>
python3 tools/inspect-logs.py --prefix <run-prefix>                # decode the run's logs
```

- Preserve the evidence before anything else touches the machine.
- Quiesce the GPU gracefully after every run that used it. Never initialise
  a GPU that is still running.
- `retire` chainloads the next generation, ready for the next run.
- To start a new run from scratch, cold boot instead.

## Run flags

Every monitor, kext and q1n1 feature is opt-in, with one flag each. To list
them all, with the requirements between flags:

```sh
python3 tools/cycle.py installed-fresh --help
```

The flags fall into these groups:

| Group | Examples |
| --- | --- |
| Console and early stop | `--console`, `--single-user`, `--early-stop-delay`, `--let-panic`, `--panic-serve` |
| Input | `--input`, `--input-touchpad`, `--input-ptp`, `--input-active-us`, `--input-fnkeys` |
| Present path | `--present-dartpool`, `--present-resident`, `--present-beam`, `--present-va-reclaim`, `--present-maint`, `--present-latch`, `--present-pipeline`, `--present-early-done` |
| GPU | `--ib-async`, `--gpu-recover`, `--gpu-va-wide`, `--gpu-coherent`, `--resident-mib`, `--adreno-fill-br`, `--adreno-fence-br`, `--adreno-cs-samplers`, `--gpu-x290-survey` |
| Panel brightness | `--edp-backlight`, `--edp-backlight-mode` |
| Clocks and bandwidth | `--thermal-guard`, `--gpu-dvfs`, `--gpu-dvfs-ceiling`, `--cpu-dvfs`, `--ddr-vote`, `--llcc`, `--bw-probe` |
| Storage | `--nvme-async`, `--nvme-converted` |
| Wi-Fi | `--qcc2072-wifi`, `--qcc2072-auxkc`, `--qcc2072-auxkc-sha256` |
| Kernel view pool | `--view-reclaim` |
| Monitor performance | `--fine-locks`, `--root-cache-wide`, `--user-hw-walk`, `--fast-timer-irq`, `--fast-ipi`, `--lean-traps`, `--sptm-fine`, and others |
| Kernel patches | `--kernel-sysreg-zero`, `--kernel-user-4k`, `--kernel-refmod-skip` ([KERNEL-PATCHES.md](KERNEL-PATCHES.md)) |

The desktop configuration that currently performs best combines all of these
groups:

```
--variant fast --wfi-resume --fast-timer-irq --dart-memo --aes-bitslice --fast-ipi
--fast-el0-sysreg --service-subclass --dart-wiredcnt --panic-serve --root-miss-fast
--update-disjoint-fast --root-cache-wide --update-check-sparse --input --kernel-pperm-fast
--ib-budget-1s --unmap-mixed --prime-secondaries --txm-aspace-wide --fine-locks
--fine-switch --fair-token --user-hw-walk --fine-hw --s2-fault-retry --fast-pauth-calls
--fast-timer-irq-cpu0 --native-pacga --pauth-el0-live --class-proof-wide --el0-memo
--unnest-4k-fast --phase-fair-gate --fine-switch-hw --dart-converted --nest-fast
--detach-fast --root-index --other-profile --gate-wait --lean-traps 1 --input-touchpad
--input-ptp --present-dartpool --console --kernel-sysreg-zero --kernel-refmod-skip
--kernel-user-4k --let-panic --early-stop-delay 1500 --hide-amx --audit-sparse
--reuse-match-mapped --present-resident --el0-wfe --el0-cache-maint --user-crash-wide
--ib-async --thermal-guard --cpu-dvfs --gpu-dvfs --ddr-vote --bw-probe --spmi-scratch
--present-beam --llcc --present-va-reclaim --gpu-va-wide --sptm-fine --present-maint
--nvme-async --nvme-converted --attr-clean-defer --present-latch --adreno-fill-br
--adreno-fence-br --gpu-x290-survey --gpu-dvfs-ceiling 1185
--present-pipeline 1 --gpu-recover soft
```

The present-path flags select specific AdrenoX2 builds. Each needs the flags
before it in its chain, and `--prepare` reports any missing prerequisite.

Compared with that list, the b12v20 desktop run adds `--multipage-fast
--resident-mib 1536` and uses `--gpu-dvfs-ceiling 1700`; b12v23 also adds
`--gpu-coherent` and drops `--other-profile`. `--resident-mib` sets the residency budget of a re-pin
AdrenoX2 (boot-arg `adreno_resident_mib`). `--gpu-coherent` needs `--gpu-va-wide`
and `--root-cache-wide`: the monitor runs a bounded CPU/GPU coherency self-test at
GPU prepare (event `EV_GPU_COHERENT` in the report) and only then maps CB0's
mirror IO-coherent; the desktop-profile AdrenoX2 skips cache maintenance only
after that test passed and with the boot-arg `adreno_coherent=1` the flag adds.
The flag also runs q1n1's `a16gpu adopt --coherent`, which needs a q1n1 checkout
that has that option. `--gpu-coherent-force` is a debug build without the
self-test, for A/B rendering checks only.

`--edp-backlight` (needs `--present-latch` and its chain) lets macOS set the
panel's brightness. The monitor gets `SNAP_EDP_BACKLIGHT`: its
`ADRENO_GUEST_BACKLIGHT` call writes the panel's DPCD backlight level over the
eDP controller's AUX channel, touching only the AUX transport registers and
DPCD `0x721`-`0x723`, clamping the level to between 2% of full scale and the
panel's maximum, and stopping for the boot on any failure with the brightness
left as it was (`compat/edp-backlight.h`, event `EV_EDP_BACKLIGHT`). The guest
gets the AuxKC pinned as `INPUT_AUXKC_DESKTOP_BACKLIGHT`, whose AdrenoX2 has the
`AdrenoBacklight` service, and the boot-arg `adreno_backlight=1`. The service
lets WindowServer bind the panel's framebuffer to a brightness control;
CoreBrightness's nits then arrive in the swaps WindowServer submits (as on a
DCP Mac), and AdrenoDisplay hands each new value to the service, which logs
`SET <level> from swap` (the path and its evidence are in the kext's
`src/AdrenoBacklight.h`). The service maps nits to a level proportionally, the
top level being `adreno_backlight_max_nits` (default 500) and the darkest
request `adreno_backlight_min_nits` (default 5, raised to the 2% floor's ~10
nits); either boot-arg moves the curve without rebuilding the monitor. The
collection is built with
`KEXT_PROFILE=desktop-next I2C_PROFILE=desktop-fnkeys tools/build-auxkc-desktop.sh
NAME` for a monitor without `--gpu-coherent` (`desktop-next` is
`desktop-nocoherent` plus the service). With `--gpu-coherent` or
`--present-early-done` the run takes the collection pinned as
`INPUT_AUXKC_DESKTOP_EARLY_DONE` instead (`KEXT_PROFILE=desktop-early-done
I2C_PROFILE=desktop-fnkeys tools/build-auxkc-desktop.sh NAME`; `desktop-early-done` is
`desktop-backlight`, the coherent `desktop` plus the service, with early
completion), and is refused until that collection is pinned. `--edp-backlight-mode` lets the first change switch a panel left in
PWM-pin mode to DPCD control. `tools/survey-edp-aux.py` checks, read-only from
q1n1, that the clocks and the AUX controller the call needs are on.
`tools/test-edp-backlight.py` is the offline test.

`--present-early-done MODE` (needs `--edp-backlight` and its chain) adds the
guest boot-arg `adreno_present_early_done=MODE` for the `desktop-early-done`
AdrenoX2 (`src/AdrenoDisplayEarlyDone.h` in the kext). AdrenoDisplay then
completes a layer-0 swap right after its scanout copy instead of at the next
frame tick. WindowServer keeps at most two swaps outstanding, so completing at
the copy frees one of its entries a refresh earlier and a frame that runs past
one refresh can still make the next latch; WindowServer may then run up to one
frame further ahead. `1` completes at every copy, `2` only while WindowServer
is late (for `--present-early-hold-ms`, default 2000, after each late frame),
`0` only measures. Every mode adds one `AdrenoDisplay: perf done` line per perf
window: completions at the copy, late frames, engagements, and histograms of
WindowServer's arrivals after each tick and of each late frame's lateness. It
excludes `--present-hold on`. `tools/test-present-early-done.py` is the offline
test (with the presentation replay's early-done scenarios).

`--view-reclaim` gives the monitor `SNAP_VIEW_RECLAIM`. The kernel's per-CPU
private page-table copies (`shadow/sprr-view.h`) hold 256 tables instead of
128, and when a protecting RETYPE (read-only zone, TXM) finds them full, the
copies that no selector2 or selector4 leaf needs any more are retired: every
CPU's copies are synced back to the shared tables, published and invalidated
before their pages are reused. Without it, a desktop session stops with exit 7
(RETYPE to ROZONE refused) once the read-only zone has grown past about 120
frames (installed-fresh-desktop-20261024-next1: after 1,104 s). The report's
`VIEWRCL1` record (and `summary.json` `view_reclaim`) has the count, its
high-water mark and the reclaims. `tools/test-view-reclaim.py` is the offline
test.

`--input-fnkeys FLAGS` (needs `--input`) adds the guest boot-arg
`snap_i2c_fnkeys=FLAGS` for SnapI2CHID's keyboard Fn-key layer, which only a
SnapI2CHID built with `PROFILE=desktop-fnkeys` has (`I2C_PROFILE=desktop-fnkeys
tools/build-auxkc-desktop.sh NAME`); other builds ignore it. `0x1` turns the
keyboard's ASUS hotkey report into the usages macOS's keyboards send, `0x2` logs
what the F-row sends (rate-limited, never a key that types a character), `0x4`
(with `0x1`) swaps F1-F12 and their hotkeys in the host on Fn+Esc, and
`0x8`/`0x10` pick another brightness encoding
(`drivers/snap-i2c-hid/src/hid-keyboard.h`). The sets the kext would refuse are
refused at prepare. `tools/test-input-fnkeys.py` is the offline test.

## Installing a new Metal plug-in

The plug-in lives on the guest's system. To replace it, boot with `--console
--single-user`, then install the new bundle from the guest's own console shell
before the boot continues to multi-user:

```sh
python3 tools/deploy-guest-plugin.py --device udp://<interface> \
    --launch-record build/<run-prefix>-early-stop-launch.json --record <record.json> --continue-boot
```

The tool checks every file against its expected base before writing anything,
keeps backups, and can put them back with `--restore`.

A plug-in that changes how icons render has no visible effect until the icons
already rendered are dropped: IconServices keeps them in
`/Library/Caches/com.apple.iconservices.store` and in each user's cache folder
(`com.apple.iconservices`, `com.apple.iconservicesagent`), and the Dock keeps its
own `com.apple.dock.iconcache` there. Rename them aside from the single-user
shell, after the install and before the boot continues: run the tool without
`--continue-boot`, rename the caches with `tools/guest-console.py --run` under the
same `--owner`, then run the tool again with `--continue-boot` (it finds the files
installed and only continues the boot).

The kext side of the icons inside System Settings panes, `ADRENO_IB_CS_SAMPLERS`
in the desktop AdrenoX2 profiles, is off unless the guest boots with
`adreno_cs_samplers=1`, which `tools/cycle.py installed-fresh --adreno-cs-samplers`
adds (`tools/test-adreno-cs-samplers.py`). An AdrenoX2 built without the define
ignores the boot-arg.

## Checking icon pixels on the GPU

The encoding tests check the plug-in's packets, not what the Adreno GPU makes of
them. `icon-pixels` (SnapMetal `harness/icon-pixels*.m`, built and ad-hoc signed
by `tools/build-icon-pixels.py`) runs the CoreImage kernels of the Settings
icons in the guest on generated inputs (`synth`) and renders a few system icons
(`icons`), printing CRC-sealed text lines that `tools/compare-icon-pixels.py`
compares with this Mac's, naming what is off: unwritten or partial output,
readback or repeat differences, swapped channels, sRGB decode, a missing input
of a multi-input kernel. During a `--console` boot, once the multi-user shell
answers, as the run's only console client:

```sh
python3 tools/run-icon-pixels.py --device udp://<interface> \
    --launch-record build/<run-prefix>-early-stop-launch.json --owner <hex> \
    --tool <build-dir>/icon-pixels --output <new-dir> \
    --reference-synth tools/icon-pixels-reference-synth.txt --reference-icons <local icons reference>
```

It pushes the tool in checked base64 chunks to `/private/var/tmp/icon-pixels`,
runs it as root and, for the NSWorkspace icons, as the console user in that
user's bootstrap context, fetches the output three lines per command, collects
the plug-in's diagnostics, and compares. `--steps` picks steps; `recache` with
`--move-icon-caches TAG` renames the icon caches aside in multi-user and
restarts iconservicesd, iconservicesagent, the Dock and System Settings. The
synthetic reference is committed; the icons reference summarises Apple's icons
and stays local (`icon-pixels icons --host-caps <plug-in bundle>` on this Mac).
`tools/test-icon-pixels.py` is the offline test (fault injection and the whole
console procedure over the stand-in).

## Exit codes

A boot reports why the guest stopped:

| Code | Meaning |
| --- | --- |
| 1 | stopped for a reason the classifier does not model |
| 2 | loader failure: the image could not be built or placed |
| 3 | guest preparation failed; the kernel never ran |
| 4 | the monitor itself faulted at EL2 |
| 5 | prepared, but the guest never started |
| 6 | the kernel took an exception it did not survive |
| 7 | a monitor operation failed or reached an unsupported contract |
| 8 | the kernel panicked |
| 9 | the guest was still running when the watchdog expired |
| 10 | an SError was recorded |
| 11 | a virtual device requested a guest reset |
| 12 | stopped early: on request, at a guest milestone, on the thermal guard, or on a host abort |

A desktop session normally ends with 12. A host-side failure that leaves no
stop report is not a guest exit code. Wait out the watchdog, then recover the
real stop state with `cycle.py capture`.

## Other modes

- `cycle.py speed-test` compares the `control` and `fast` monitors on the
  stock kernel with a RAM-disk BaseSystem, six CPUs and a trap census.
- `cycle.py bootstrap-smoke` is a five-second, RAM-only, single-CPU
  integration check.
- `cycle.py storage` reads persistence from, or snapshots, the SSD at an idle
  generation.
