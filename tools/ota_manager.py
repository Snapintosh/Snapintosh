#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Snapintosh Host OTA Bundle Generator, Cryptographic Signer & A/B Slot Inspector.
Generates signed incremental binary delta bundles (DLT1) and manages host A/B state.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path
from typing import Dict, Any, Tuple

OTA_DELTA_MAGIC = 0x31544C44  # "DLT1"
OTA_DELTA_OP_END = 0
OTA_DELTA_OP_COPY = 1
OTA_DELTA_OP_ADD = 2


def encode_delta(base: bytes, target: bytes) -> bytes:
    """Encode a compact DLT1 binary delta patch from `base` to `target`."""
    out = bytearray(struct.pack("<II", OTA_DELTA_MAGIC, len(target)))
    t_idx = 0
    lit_start = 0
    min_match = 16
    base_len = len(base)
    target_len = len(target)

    while t_idx < target_len:
        best_off = 0
        best_len = 0

        if t_idx < base_len and target[t_idx] == base[t_idx]:
            end = min(target_len, base_len)
            length = 0
            while t_idx + length < end and target[t_idx + length] == base[t_idx + length]:
                length += 1
            if length >= min_match:
                best_off = t_idx
                best_len = length

        if best_len >= min_match:
            if t_idx > lit_start:
                lit = target[lit_start:t_idx]
                out.append(OTA_DELTA_OP_ADD)
                out.extend(struct.pack("<I", len(lit)))
                out.extend(lit)
            out.append(OTA_DELTA_OP_COPY)
            out.extend(struct.pack("<II", best_off, best_len))
            t_idx += best_len
            lit_start = t_idx
        else:
            t_idx += 1

    if t_idx > lit_start:
        lit = target[lit_start:t_idx]
        out.append(OTA_DELTA_OP_ADD)
        out.extend(struct.pack("<I", len(lit)))
        out.extend(lit)

    out.append(OTA_DELTA_OP_END)
    return bytes(out)


def apply_delta(base: bytes, patch: bytes) -> bytes:
    """Apply a DLT1 binary delta patch to `base` and return the reconstructed target."""
    if len(patch) < 9:
        raise ValueError("Truncated delta header")
    magic, expected_size = struct.unpack_from("<II", patch, 0)
    if magic != OTA_DELTA_MAGIC:
        raise ValueError("Invalid delta magic")

    out = bytearray()
    pos = 8
    saw_end = False

    while pos < len(patch):
        op = patch[pos]
        pos += 1
        if op == OTA_DELTA_OP_END:
            saw_end = True
            break
        if op == OTA_DELTA_OP_COPY:
            if pos + 8 > len(patch):
                raise ValueError("Truncated COPY op")
            src_off, copy_len = struct.unpack_from("<II", patch, pos)
            pos += 8
            if src_off + copy_len > len(base) or len(out) + copy_len > expected_size:
                raise ValueError("COPY out of bounds")
            out.extend(base[src_off : src_off + copy_len])
        elif op == OTA_DELTA_OP_ADD:
            if pos + 4 > len(patch):
                raise ValueError("Truncated ADD op")
            (add_len,) = struct.unpack_from("<I", patch, pos)
            pos += 4
            if pos + add_len > len(patch) or len(out) + add_len > expected_size:
                raise ValueError("ADD out of bounds")
            out.extend(patch[pos : pos + add_len])
            pos += add_len
        else:
            raise ValueError(f"Unknown delta op {op:#x}")

    if not saw_end or len(out) != expected_size:
        raise ValueError("Incomplete delta stream")
    return bytes(out)


def sign_bundle(manifest_body: Dict[str, Any], key: bytes) -> str:
    canonical = json.dumps(manifest_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def verify_bundle(bundle: Dict[str, Any], key: bytes) -> bool:
    if "manifest" not in bundle or "signature" not in bundle:
        return False
    expected = sign_bundle(bundle["manifest"], key)
    return hmac.compare_digest(expected, bundle["signature"])


def create_signed_delta_bundle(
    base_bytes: bytes,
    target_bytes: bytes,
    version: int,
    min_version: int,
    key: bytes,
) -> Tuple[Dict[str, Any], bytes]:
    patch = encode_delta(base_bytes, target_bytes)
    manifest = {
        "format": "SNAPOTA-BUNDLE-1",
        "is_delta": True,
        "version": version,
        "min_version": min_version,
        "base_size": len(base_bytes),
        "target_size": len(target_bytes),
        "patch_size": len(patch),
        "base_sha256": hashlib.sha256(base_bytes).hexdigest(),
        "target_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
    }
    sig = sign_bundle(manifest, key)
    return {"manifest": manifest, "signature": sig}, patch


def main() -> int:
    parser = argparse.ArgumentParser(description="Snapintosh OTA Bundle & Delta Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("delta", help="Create a signed incremental delta bundle")
    p_gen.add_argument("--base", required=True, type=Path)
    p_gen.add_argument("--target", required=True, type=Path)
    p_gen.add_argument("--version", required=True, type=int)
    p_gen.add_argument("--min-version", default=1, type=int)
    p_gen.add_argument("--key", required=True)
    p_gen.add_argument("--out-manifest", required=True, type=Path)
    p_gen.add_argument("--out-patch", required=True, type=Path)

    args = parser.parse_args()
    if args.cmd == "delta":
        bundle, patch = create_signed_delta_bundle(
            args.base.read_bytes(),
            args.target.read_bytes(),
            args.version,
            args.min_version,
            args.key.encode("utf-8"),
        )
        args.out_manifest.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        args.out_patch.write_bytes(patch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
