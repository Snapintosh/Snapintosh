// SPDX-License-Identifier: MIT
#ifndef SNAPINTOSH_OTA_UPDATE_H
#define SNAPINTOSH_OTA_UPDATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Snapintosh Secure A/B OTA Update, Incremental Delta & Auto-Rollback Engine
 *
 * Designed for bare-metal hypervisor and compatibility-layer updates:
 * - Dual-slot A/B partition scheme (Slot A = 0, Slot B = 1)
 * - Power-loss resilient Primary + Backup Boot Control Blocks (BCB) protected
 *   by monotonic generation numbers and CRC-32C checksums
 * - FIPS 180-4 SHA-256 + cryptographic manifest signature verification with
 *   constant-time comparison and monotonic anti-rollback floor enforcement
 * - Incremental binary delta engine (SNAPDLT1: COPY from base + ADD literal)
 * - Automatic rollback on post-update kernel panic (early_stop) or watchdog
 *   timeout before boot confirmation
 * ============================================================================ */

#define OTA_META_MAGIC          UINT64_C(0x3141544F50414E53) /* "SNAPOTA1" */
#define OTA_MANIFEST_MAGIC      UINT32_C(0x4D414E31)         /* "1NAM" */
#define OTA_DELTA_MAGIC         UINT32_C(0x31544C44)         /* "DLT1" */

#define OTA_SLOT_COUNT          2u
#define OTA_SLOT_A              0u
#define OTA_SLOT_B              1u
#define OTA_SLOT_INVALID        0xFFu

#define OTA_MAX_BOOT_TRIES      3u
#define OTA_MAX_SLOT_BYTES      (64u * 1024u) /* Per-slot buffer in test/compat storage */
#define OTA_SHA256_BYTES        32u
#define OTA_SIG_BYTES           64u
#define OTA_KEY_BYTES           32u

enum ota_status {
    OTA_OK                  =  0,
    OTA_ERR_INVALID_ARG     = -1,
    OTA_ERR_CORRUPT_META    = -2,
    OTA_ERR_BAD_SIGNATURE   = -3,
    OTA_ERR_BAD_HASH        = -4,
    OTA_ERR_ROLLBACK        = -5,
    OTA_ERR_DELTA_FORMAT    = -6,
    OTA_ERR_BOUNDS          = -7,
    OTA_ERR_POWER_LOSS      = -8,
    OTA_ERR_NO_BOOTABLE     = -9,
};

enum ota_slot_state {
    OTA_SLOT_STATE_EMPTY      = 0,
    OTA_SLOT_STATE_STAGED     = 1,
    OTA_SLOT_STATE_TRIAL      = 2,
    OTA_SLOT_STATE_ACTIVE     = 3,
    OTA_SLOT_STATE_UNBOOTABLE = 4,
};

enum ota_failure_reason {
    OTA_FAIL_NONE             = 0,
    OTA_FAIL_KERNEL_PANIC     = 1,
    OTA_FAIL_WATCHDOG_TIMEOUT = 2,
    OTA_FAIL_HASH_MISMATCH    = 3,
    OTA_FAIL_TRIES_EXHAUSTED  = 4,
};

enum ota_power_loss_fault {
    OTA_FAULT_NONE                  = 0,
    OTA_FAULT_DURING_SLOT_WRITE     = 1,
    OTA_FAULT_CORRUPT_PRIMARY_META  = 2,
    OTA_FAULT_CORRUPT_BACKUP_META   = 3,
};

enum ota_delta_op_type {
    OTA_DELTA_OP_END  = 0,
    OTA_DELTA_OP_COPY = 1, /* Copy [src_offset, src_offset + length) from base slot */
    OTA_DELTA_OP_ADD  = 2, /* Insert `length` literal bytes from patch stream */
};

struct ota_slot_info {
    uint8_t  slot_id;
    uint8_t  state;               /* enum ota_slot_state */
    uint8_t  tries_remaining;
    uint8_t  boot_successful;
    uint32_t priority;
    uint64_t version;
    uint32_t image_size;
    uint32_t last_failure_reason; /* enum ota_failure_reason */
    uint8_t  sha256[OTA_SHA256_BYTES];
};

struct ota_boot_meta {
    uint64_t magic;
    uint64_t generation;
    uint64_t rollback_version_floor;
    uint8_t  active_slot;
    uint8_t  reserved[7];
    struct ota_slot_info slots[OTA_SLOT_COUNT];
    uint32_t rollback_count;
    uint32_t crc32c;
};

struct ota_manifest {
    uint32_t magic;
    uint32_t is_delta;
    uint64_t version;
    uint64_t min_version;
    uint32_t base_size;
    uint32_t target_size;
    uint8_t  base_sha256[OTA_SHA256_BYTES];
    uint8_t  target_sha256[OTA_SHA256_BYTES];
    uint8_t  signature[OTA_SIG_BYTES];
};

struct ota_storage {
    struct ota_boot_meta primary_meta;
    struct ota_boot_meta backup_meta;
    uint8_t slot_data[OTA_SLOT_COUNT][OTA_MAX_SLOT_BYTES];
};

struct ota_context {
    struct ota_storage *storage;
    struct ota_boot_meta meta;
    uint8_t public_root_key[OTA_KEY_BYTES];
    uint8_t current_boot_slot;
    uint8_t recovered_from_backup;
    uint8_t fault_injection_mode; /* enum ota_power_loss_fault */
};

/* Cryptographic & integrity primitives */
uint32_t ota_crc32c(const void *data, size_t len);
void ota_sha256(const void *data, size_t len, uint8_t out_digest[OTA_SHA256_BYTES]);
int ota_sign_manifest(struct ota_manifest *manifest, const uint8_t root_key[OTA_KEY_BYTES]);
int ota_verify_manifest(const struct ota_manifest *manifest, const uint8_t root_key[OTA_KEY_BYTES]);

/* A/B Manager lifecycle & power-loss recovery */
int ota_init(struct ota_context *ctx,
             struct ota_storage *storage,
             const uint8_t root_key[OTA_KEY_BYTES]);
int ota_format_storage(struct ota_context *ctx,
                       const void *initial_image,
                       uint32_t image_size,
                       uint64_t initial_version);
int ota_persist_meta(struct ota_context *ctx);

/* Full & Incremental Delta Update Application */
int ota_stage_full_update(struct ota_context *ctx,
                          const struct ota_manifest *manifest,
                          const void *payload,
                          uint32_t payload_size);
int ota_encode_delta(const uint8_t *base_img,
                     uint32_t base_size,
                     const uint8_t *target_img,
                     uint32_t target_size,
                     uint8_t *out_patch,
                     uint32_t max_patch_size,
                     uint32_t *out_patch_size);
int ota_stage_delta_update(struct ota_context *ctx,
                           const struct ota_manifest *manifest,
                           const uint8_t *delta_patch,
                           uint32_t patch_size);

/* Bootloader Slot Selection, Confirmation & Automatic Rollback */
int ota_select_boot_slot(struct ota_context *ctx, uint8_t *out_slot);
int ota_mark_boot_successful(struct ota_context *ctx);
int ota_notify_kernel_panic(struct ota_context *ctx, uint8_t *out_fallback_slot);
int ota_notify_watchdog_timeout(struct ota_context *ctx, uint8_t *out_fallback_slot);

#ifdef __cplusplus
}
#endif

#endif /* SNAPINTOSH_OTA_UPDATE_H */
