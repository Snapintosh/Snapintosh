// SPDX-License-Identifier: MIT
//
// Host unit and fault-injection test suite for the Snapintosh A/B OTA Update,
// Incremental Delta, Power-Loss Recovery, and Automatic Rollback Engine.
//
// Build and run from repository root:
//   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror -Icompat tools/test-ota-update.c compat/ota-update.c -o test-ota-update && ./test-ota-update

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ota-update.h"

static int checks_run = 0;

#define CHECK(expr)                                                           \
    do {                                                                      \
        checks_run++;                                                         \
        if (!(expr)) {                                                        \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr); \
            exit(1);                                                          \
        }                                                                     \
    } while (0)

static void build_synthetic_firmware(uint8_t *buf, uint32_t size, uint64_t version) {
    for (uint32_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 31u + 17u) & 0xFFu);
    /* Embed version banner at offset 128 */
    if (size >= 160) {
        memcpy(buf + 128, "SNAPINTOSH-FW-VER:", 18);
        for (int b = 0; b < 8; b++)
            buf[146 + b] = (uint8_t)((version >> (b * 8)) & 0xFFu);
    }
}

static void prepare_manifest(struct ota_manifest *m,
                             uint32_t is_delta,
                             uint64_t version,
                             uint64_t min_version,
                             const uint8_t *base_img,
                             uint32_t base_size,
                             const uint8_t *target_img,
                             uint32_t target_size,
                             const uint8_t root_key[OTA_KEY_BYTES]) {
    memset(m, 0, sizeof(*m));
    m->is_delta = is_delta;
    m->version = version;
    m->min_version = min_version;
    m->base_size = base_size;
    m->target_size = target_size;
    if (base_img && base_size > 0)
        ota_sha256(base_img, base_size, m->base_sha256);
    ota_sha256(target_img, target_size, m->target_sha256);
    CHECK(ota_sign_manifest(m, root_key) == OTA_OK);
}

static void test_crypto_primitives(void) {
    /* FIPS 180-4 SHA-256 vector: "abc" */
    const uint8_t expected_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t digest[32];
    ota_sha256("abc", 3, digest);
    CHECK(memcmp(digest, expected_abc, 32) == 0);

    /* Castagnoli CRC-32C vector: "123456789" -> 0xE3069283 */
    uint32_t crc = ota_crc32c("123456789", 9);
    CHECK(crc == 0xE3069283u);
}

static void test_ab_delta_powerloss_and_rollback(void) {
    struct ota_storage *storage = calloc(1, sizeof(*storage));
    CHECK(storage != NULL);

    uint8_t root_key[OTA_KEY_BYTES];
    memcpy(root_key, "SNAPINTOSH_OTA_ROOT_SIGNING_KEY!", OTA_KEY_BYTES);

    uint8_t fw_v1[8192];
    uint8_t fw_v2[8192];
    uint8_t fw_v3[8192];
    uint8_t fw_v4[8192];
    build_synthetic_firmware(fw_v1, sizeof(fw_v1), 100);
    build_synthetic_firmware(fw_v2, sizeof(fw_v2), 200);
    build_synthetic_firmware(fw_v3, sizeof(fw_v3), 300);
    build_synthetic_firmware(fw_v4, sizeof(fw_v4), 400);

    struct ota_context ctx;
    CHECK(ota_init(&ctx, storage, root_key) == OTA_ERR_CORRUPT_META);
    CHECK(ota_format_storage(&ctx, fw_v1, sizeof(fw_v1), 100) == OTA_OK);
    CHECK(ctx.meta.active_slot == OTA_SLOT_A);
    CHECK(ctx.meta.rollback_version_floor == 100);

    /* 1. Reject forged signature & tampered payload */
    struct ota_manifest m_v2_full;
    prepare_manifest(&m_v2_full, 0, 200, 100, NULL, 0, fw_v2, sizeof(fw_v2), root_key);
    m_v2_full.signature[15] ^= 0x01;
    CHECK(ota_stage_full_update(&ctx, &m_v2_full, fw_v2, sizeof(fw_v2)) == OTA_ERR_BAD_SIGNATURE);
    m_v2_full.signature[15] ^= 0x01; /* Restore valid signature */

    uint8_t corrupt_fw[8192];
    memcpy(corrupt_fw, fw_v2, sizeof(fw_v2));
    corrupt_fw[4096] ^= 0xFF;
    CHECK(ota_stage_full_update(&ctx, &m_v2_full, corrupt_fw, sizeof(corrupt_fw)) == OTA_ERR_BAD_HASH);

    /* 2. Power-loss fault injection during slot write leaves Slot A active and intact */
    ctx.fault_injection_mode = OTA_FAULT_DURING_SLOT_WRITE;
    CHECK(ota_stage_full_update(&ctx, &m_v2_full, fw_v2, sizeof(fw_v2)) == OTA_ERR_POWER_LOSS);
    ctx.fault_injection_mode = OTA_FAULT_NONE;

    uint8_t boot_slot = OTA_SLOT_INVALID;
    CHECK(ota_select_boot_slot(&ctx, &boot_slot) == OTA_OK);
    CHECK(boot_slot == OTA_SLOT_A);

    /* 3. Power-loss fault injection on Primary BCB -> self-heals from Backup BCB */
    ctx.fault_injection_mode = OTA_FAULT_CORRUPT_PRIMARY_META;
    CHECK(ota_persist_meta(&ctx) == OTA_ERR_POWER_LOSS);
    ctx.fault_injection_mode = OTA_FAULT_NONE;

    struct ota_context recovered_ctx;
    CHECK(ota_init(&recovered_ctx, storage, root_key) == OTA_OK);
    CHECK(recovered_ctx.recovered_from_backup == 1);
    ctx = recovered_ctx;

    /* 4. Incremental Delta Update (v1 -> v2) onto Slot B */
    uint8_t delta_patch[8192];
    uint32_t patch_size = 0;
    CHECK(ota_encode_delta(fw_v1, sizeof(fw_v1), fw_v2, sizeof(fw_v2),
                           delta_patch, sizeof(delta_patch), &patch_size) == OTA_OK);
    /* Only 8 bytes changed between v1 and v2 -> delta patch must be < 128 bytes (< 2% of 8 KiB) */
    CHECK(patch_size < 128u);

    struct ota_manifest m_v2_delta;
    prepare_manifest(&m_v2_delta, 1, 200, 100, fw_v1, sizeof(fw_v1), fw_v2, sizeof(fw_v2), root_key);
    CHECK(ota_stage_delta_update(&ctx, &m_v2_delta, delta_patch, patch_size) == OTA_OK);
    CHECK(ctx.meta.slots[OTA_SLOT_B].state == OTA_SLOT_STATE_TRIAL);
    CHECK(ctx.meta.slots[OTA_SLOT_B].tries_remaining == OTA_MAX_BOOT_TRIES);
    CHECK(memcmp(storage->slot_data[OTA_SLOT_B], fw_v2, sizeof(fw_v2)) == 0);

    /* 5. Boot into Trial Slot B (v2), then simulate a Kernel Panic -> auto-rollback to Slot A (v1) */
    CHECK(ota_select_boot_slot(&ctx, &boot_slot) == OTA_OK);
    CHECK(boot_slot == OTA_SLOT_B);
    CHECK(ctx.meta.slots[OTA_SLOT_B].tries_remaining == OTA_MAX_BOOT_TRIES - 1u);

    uint8_t fallback_slot = OTA_SLOT_INVALID;
    CHECK(ota_notify_kernel_panic(&ctx, &fallback_slot) == OTA_OK);
    CHECK(fallback_slot == OTA_SLOT_A);
    CHECK(ctx.meta.slots[OTA_SLOT_B].state == OTA_SLOT_STATE_UNBOOTABLE);
    CHECK(ctx.meta.slots[OTA_SLOT_B].last_failure_reason == OTA_FAIL_KERNEL_PANIC);
    CHECK(ctx.meta.rollback_count == 1);

    /* Next reboot selects known-good Slot A */
    CHECK(ota_select_boot_slot(&ctx, &boot_slot) == OTA_OK);
    CHECK(boot_slot == OTA_SLOT_A);

    /* 6. Stage v3 on Slot B, exhaust all 3 trial boots without confirmation -> auto-rollback */
    struct ota_manifest m_v3_full;
    prepare_manifest(&m_v3_full, 0, 300, 100, NULL, 0, fw_v3, sizeof(fw_v3), root_key);
    CHECK(ota_stage_full_update(&ctx, &m_v3_full, fw_v3, sizeof(fw_v3)) == OTA_OK);

    for (unsigned attempt = 0; attempt < OTA_MAX_BOOT_TRIES; attempt++) {
        CHECK(ota_select_boot_slot(&ctx, &boot_slot) == OTA_OK);
        CHECK(boot_slot == OTA_SLOT_B);
    }
    /* 4th reboot: tries_remaining == 0 -> marks Slot B UNBOOTABLE and rolls back to Slot A */
    CHECK(ota_select_boot_slot(&ctx, &boot_slot) == OTA_OK);
    CHECK(boot_slot == OTA_SLOT_A);
    CHECK(ctx.meta.slots[OTA_SLOT_B].state == OTA_SLOT_STATE_UNBOOTABLE);
    CHECK(ctx.meta.slots[OTA_SLOT_B].last_failure_reason == OTA_FAIL_TRIES_EXHAUSTED);
    CHECK(ctx.meta.rollback_count == 2);

    /* 7. Stage v4 via delta (v1 -> v4), boot Slot B, confirm healthy boot, verify anti-rollback */
    uint32_t patch_v4_size = 0;
    CHECK(ota_encode_delta(fw_v1, sizeof(fw_v1), fw_v4, sizeof(fw_v4),
                           delta_patch, sizeof(delta_patch), &patch_v4_size) == OTA_OK);
    struct ota_manifest m_v4_delta;
    prepare_manifest(&m_v4_delta, 1, 400, 100, fw_v1, sizeof(fw_v1), fw_v4, sizeof(fw_v4), root_key);
    CHECK(ota_stage_delta_update(&ctx, &m_v4_delta, delta_patch, patch_v4_size) == OTA_OK);

    CHECK(ota_select_boot_slot(&ctx, &boot_slot) == OTA_OK);
    CHECK(boot_slot == OTA_SLOT_B);
    CHECK(ota_mark_boot_successful(&ctx) == OTA_OK);
    CHECK(ctx.meta.active_slot == OTA_SLOT_B);
    CHECK(ctx.meta.slots[OTA_SLOT_B].state == OTA_SLOT_STATE_ACTIVE);
    CHECK(ctx.meta.rollback_version_floor == 400);

    /* Attempting to stage older v3 (version 300 < floor 400) must be rejected with OTA_ERR_ROLLBACK */
    CHECK(ota_stage_full_update(&ctx, &m_v3_full, fw_v3, sizeof(fw_v3)) == OTA_ERR_ROLLBACK);

    free(storage);
}

int main(void) {
    test_crypto_primitives();
    test_ab_delta_powerloss_and_rollback();
    printf("PASS: %d OTA A/B update, incremental delta, power-loss & rollback checks verified\n",
           checks_run);
    return 0;
}
