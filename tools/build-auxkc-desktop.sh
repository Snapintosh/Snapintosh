#!/bin/bash
# SPDX-License-Identifier: MIT
# Build the A16 desktop AuxKC from this checkout: AdrenoX2 (SnapAdreno, PROFILE=desktop unless KEXT_PROFILE says
# otherwise) and SnapI2CHID (PROFILE=desktop unless I2C_PROFILE says otherwise), linked the way the deployed desktop
# collections were:
#   1. tools/build-auxkc-user.py   kmutil links both kexts against the J700 kernelcache and the KDK
#   2. tools/auxkc-autoload.py     marks both bundles to autoload and writes packaging.json
#   3. build/build-auxkc.py pin    admits the collection for the installed desktop guest profile (<kc>.json)
# then prints every output's sha256 and the two tools/cycle_lib/installed_fresh.py lines that pin the collection.
#
#   tools/build-auxkc-desktop.sh NAME
#     NAME          the collection's folder, build/current-assets/NAME/ (must not exist)
#   Environment:
#     KEXT_PROFILE  SnapAdreno profile (gpu/adreno-kext/kext/profiles/), default desktop; desktop-nocoherent for a
#                   monitor without --gpu-coherent
#     I2C_PROFILE   SnapI2CHID profile (drivers/snap-i2c-hid/profiles/), default desktop; desktop-fnkeys for the
#                   keyboard's Fn-key layer (boot it with tools/cycle.py --input-fnkeys)
#     REFERENCE     optional folder holding AdrenoX2.kext and SnapI2CHID.kext to compare with, section by section
#                   (tools/macho-sections.py): for example a deployed collection's folder
#     ZERO_AR_DATE  exported as 1 unless set: object times in the kexts' debug maps are zeroed, so two builds in the
#                   same checkout produce the same kext bytes
#
# The collection's bytes are not reproducible even from identical kexts: its prelink info records each kext's
# _PrelinkBundlePath in build-auxkc-user.py's temporary staging folder, whose name is random. Against a deployed
# collection, expect differences only there and in what the kexts' UUIDs determine (each kext's LC_UUID and
# OSBundleUUID, the collection's UUID and _PrelinkKCID, the receipt's per-kext digests); compare the kexts with
# REFERENCE for the substance.
#
# Local inputs, never committed: gpu/adreno-kext/kext/include/*26A428.h (AGENTS.md, "Rebuilding What Is Not
# Distributed"), downloads/extracted/j700ap (the J700 restore-image kernelcache), the KDK at
# /Library/Developer/KDKs/KDK_27.0_26A428.kdk, and GNU tar at /opt/homebrew/bin/gtar (build-auxkc-user.py runs it
# under sudo for temporary root-owned kext copies only; sudo asks for a password unless one is cached or allowed).
# The kexts are built under build/auxkc-desktop-NAME/ and copied into the collection's folder.
set -euo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)
NAME=${1:?usage: tools/build-auxkc-desktop.sh NAME}
case "$NAME" in */*|.*|'') echo "error: NAME is a folder name under build/current-assets" >&2; exit 2;; esac
KEXT_PROFILE=${KEXT_PROFILE:-desktop}
I2C_PROFILE=${I2C_PROFILE:-desktop}
export ZERO_AR_DATE=${ZERO_AR_DATE:-1}
export PYTHONDONTWRITEBYTECODE=1
DEST=$R/build/current-assets/$NAME
WORK=$R/build/auxkc-desktop-$NAME
GUEST_PROFILE=j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks
BUNDLES=(--bundle org.snapintosh.driver.AdrenoX2 --bundle org.snapintosh.driver.SnapI2CHID)
[ ! -e "$DEST" ] || { echo "error: $DEST exists; a collection is built once" >&2; exit 2; }
rm -rf "$WORK"; mkdir -p "$WORK"

OUT=$WORK/adrenox2 PROFILE=$KEXT_PROFILE sh "$R/gpu/adreno-kext/kext/build.sh" > "$WORK/adrenox2.log" 2>&1 ||
    { tail -20 "$WORK/adrenox2.log" >&2; exit 1; }
OUT=$WORK/snapi2chid PROFILE=$I2C_PROFILE sh "$R/drivers/snap-i2c-hid/build.sh" > "$WORK/snapi2chid.log" 2>&1 ||
    { tail -20 "$WORK/snapi2chid.log" >&2; exit 1; }

mkdir -p "$DEST"
cp -Rp "$WORK/adrenox2/AdrenoX2.kext" "$DEST/AdrenoX2.kext"
cp -Rp "$WORK/snapi2chid/SnapI2CHID.kext" "$DEST/SnapI2CHID.kext"
cp "$WORK/adrenox2/DEFINES.txt" "$DEST/AdrenoX2-DEFINES.txt"
cp "$WORK/snapi2chid/DEFINES.txt" "$DEST/SnapI2CHID-DEFINES.txt"
{   # which sources: the umbrella and both submodules, with uncommitted changes flagged
    for d in . gpu/adreno-kext/kext drivers/snap-i2c-hid; do
        printf '%s %s%s\n' "$d" "$(git -C "$R/$d" rev-parse HEAD)" \
            "$(git -C "$R/$d" diff --quiet HEAD -- && echo '' || echo ' (uncommitted changes)')"
    done
    echo "AdrenoX2 profile $KEXT_PROFILE, SnapI2CHID profile $I2C_PROFILE, ZERO_AR_DATE=$ZERO_AR_DATE"
} > "$DEST/sources.txt"

cd "$R"
python3 tools/build-auxkc-user.py "$DEST/adreno-input.raw.kc" "$DEST/AdrenoX2.kext" "$DEST/SnapI2CHID.kext"
RAW=$(shasum -a 256 "$DEST/adreno-input.raw.kc" | cut -d' ' -f1)
python3 tools/auxkc-autoload.py "$DEST/adreno-input.raw.kc" "$DEST/adreno-input.kc" --expected-sha256 "$RAW" \
    "${BUNDLES[@]}" --record "$DEST/packaging.json"
python3 build/build-auxkc.py pin --kc "$DEST/adreno-input.kc" --guest-profile "$GUEST_PROFILE" "${BUNDLES[@]}"

shasum -a 256 "$DEST/adreno-input.kc" "$DEST/adreno-input.raw.kc" "$DEST/adreno-input.kc.json" \
    "$DEST/AdrenoX2.kext/Contents/MacOS/AdrenoX2" "$DEST/SnapI2CHID.kext/Contents/MacOS/SnapI2CHID"
status=0
if [ -n "${REFERENCE:-}" ]; then
    for b in AdrenoX2.kext/Contents/MacOS/AdrenoX2 SnapI2CHID.kext/Contents/MacOS/SnapI2CHID; do
        echo "== $b against $REFERENCE"
        python3 "$R/tools/macho-sections.py" "$REFERENCE/$b" "$DEST/$b" | tee "$WORK/compare.txt"
        tail -1 "$WORK/compare.txt" | grep -q '^\([0-9]*\) of \1 sections identical' || status=1
    done
fi
KC_SHA=$(shasum -a 256 "$DEST/adreno-input.kc" | cut -d' ' -f1)
echo "tools/cycle_lib/installed_fresh.py pin lines:"
echo "INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH = 'build/current-assets/$NAME/adreno-input.kc'"
echo "INPUT_AUXKC_PTP_DARTPOOL_RESIDENT_BEAM_VA_WIDE_LATCH_SHA = '$KC_SHA'"
exit $status
