#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for the Snapintosh Python OTA delta & bundle tool."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ota_manager  # noqa: E402


class TestOtaManager(unittest.TestCase):
    def test_delta_roundtrip_and_compression(self) -> None:
        base = bytes((i * 19 + 7) & 0xFF for i in range(16384))
        target = bytearray(base)
        target[512:544] = b"SNAPINTOSH-OTA-V2-PATCH-PAYLOAD!"
        target_bytes = bytes(target)

        key = b"snapintosh-root-key-2026"
        bundle, patch = ota_manager.create_signed_delta_bundle(
            base, target_bytes, version=200, min_version=100, key=key
        )
        self.assertTrue(ota_manager.verify_bundle(bundle, key))
        self.assertFalse(ota_manager.verify_bundle(bundle, b"wrong-key"))
        self.assertLess(len(patch), 128)

        reconstructed = ota_manager.apply_delta(base, patch)
        self.assertEqual(reconstructed, target_bytes)

    def test_reject_corrupt_delta(self) -> None:
        base = b"A" * 256
        with self.assertRaises(ValueError):
            ota_manager.apply_delta(base, b"BADMAGIC1234")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestOtaManager)
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    print("PASS: test-ota-manager.py (2 checks)")
