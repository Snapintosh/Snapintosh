// SPDX-License-Identifier: MIT
#include "ota-update.h"
#include <stddef.h>
#include <string.h>

/* ============================================================================
 * 1. CRC-32C (Castagnoli) & FIPS 180-4 SHA-256 + Constant-Time Signatures
 * ============================================================================ */

uint32_t ota_crc32c(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0x82F63B78u & mask);
        }
    }
    return ~crc;
}

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8)  |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void ota_sha256(const void *data, size_t len, uint8_t out_digest[OTA_SHA256_BYTES]) {
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    const uint8_t *bytes = (const uint8_t *)data;
    size_t offset = 0;

    while (len - offset >= 64) {
        sha256_transform(state, bytes + offset);
        offset += 64;
    }

    uint8_t tail[128];
    memset(tail, 0, sizeof(tail));
    size_t rem = len - offset;
    if (rem > 0 && bytes != NULL)
        memcpy(tail, bytes + offset, rem);
    tail[rem] = 0x80u;

    size_t total_blocks = (rem >= 56) ? 2u : 1u;
    uint64_t bit_len = (uint64_t)len * 8ULL;
    size_t len_pos = total_blocks * 64u - 8u;
    for (int i = 0; i < 8; i++)
        tail[len_pos + i] = (uint8_t)(bit_len >> (56 - i * 8));

    sha256_transform(state, tail);
    if (total_blocks == 2u)
        sha256_transform(state, tail + 64);

    for (int i = 0; i < 8; i++) {
        out_digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        out_digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out_digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out_digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

static int ota_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff != 0;
}

static void ota_compute_manifest_sig(const struct ota_manifest *m,
                                     const uint8_t root_key[OTA_KEY_BYTES],
                                     uint8_t out_sig[OTA_SIG_BYTES]) {
    uint8_t buf[OTA_KEY_BYTES + offsetof(struct ota_manifest, signature) + 4];
    size_t body_len = offsetof(struct ota_manifest, signature);

    memcpy(buf, root_key, OTA_KEY_BYTES);
    memcpy(buf + OTA_KEY_BYTES, m, body_len);
    buf[OTA_KEY_BYTES + body_len + 0] = 'S';
    buf[OTA_KEY_BYTES + body_len + 1] = 'I';
    buf[OTA_KEY_BYTES + body_len + 2] = 'G';
    buf[OTA_KEY_BYTES + body_len + 3] = '1';
    ota_sha256(buf, OTA_KEY_BYTES + body_len + 4, out_sig);

    buf[OTA_KEY_BYTES + body_len + 3] = '2';
    ota_sha256(buf, OTA_KEY_BYTES + body_len + 4, out_sig + 32);
}

int ota_sign_manifest(struct ota_manifest *manifest, const uint8_t root_key[OTA_KEY_BYTES]) {
    if (!manifest || !root_key)
        return OTA_ERR_INVALID_ARG;
    manifest->magic = OTA_MANIFEST_MAGIC;
    ota_compute_manifest_sig(manifest, root_key, manifest->signature);
    return OTA_OK;
}

int ota_verify_manifest(const struct ota_manifest *manifest, const uint8_t root_key[OTA_KEY_BYTES]) {
    if (!manifest || !root_key)
        return OTA_ERR_INVALID_ARG;
    if (manifest->magic != OTA_MANIFEST_MAGIC)
        return OTA_ERR_BAD_SIGNATURE;

    uint8_t expected[OTA_SIG_BYTES];
    ota_compute_manifest_sig(manifest, root_key, expected);
    if (ota_ct_memcmp(expected, manifest->signature, OTA_SIG_BYTES) != 0)
        return OTA_ERR_BAD_SIGNATURE;
    return OTA_OK;
}

/* ============================================================================
 * 2. Power-Loss Resilient Metadata Persistence & Recovery
 * ============================================================================ */

static int ota_meta_is_valid(const struct ota_boot_meta *m) {
    if (!m || m->magic != OTA_META_MAGIC || m->active_slot >= OTA_SLOT_COUNT)
        return 0;
    uint32_t expected_crc = ota_crc32c(m, offsetof(struct ota_boot_meta, crc32c));
    return m->crc32c == expected_crc;
}

int ota_persist_meta(struct ota_context *ctx) {
    if (!ctx || !ctx->storage)
        return OTA_ERR_INVALID_ARG;

    ctx->meta.magic = OTA_META_MAGIC;
    ctx->meta.generation++;
    ctx->meta.crc32c = ota_crc32c(&ctx->meta, offsetof(struct ota_boot_meta, crc32c));

    /* Write Primary BCB first */
    ctx->storage->primary_meta = ctx->meta;
    if (ctx->fault_injection_mode == OTA_FAULT_CORRUPT_PRIMARY_META) {
        /* Simulate torn write / power cut mid-sector on primary metadata */
        ctx->storage->primary_meta.crc32c ^= 0xDEADBEEFu;
        return OTA_ERR_POWER_LOSS;
    }

    /* Then commit Backup BCB */
    ctx->storage->backup_meta = ctx->meta;
    if (ctx->fault_injection_mode == OTA_FAULT_CORRUPT_BACKUP_META) {
        ctx->storage->backup_meta.crc32c ^= 0xBADCAFE0u;
        return OTA_ERR_POWER_LOSS;
    }

    return OTA_OK;
}

int ota_init(struct ota_context *ctx,
             struct ota_storage *storage,
             const uint8_t root_key[OTA_KEY_BYTES]) {
    if (!ctx || !storage || !root_key)
        return OTA_ERR_INVALID_ARG;

    memset(ctx, 0, sizeof(*ctx));
    ctx->storage = storage;
    memcpy(ctx->public_root_key, root_key, OTA_KEY_BYTES);
    ctx->current_boot_slot = OTA_SLOT_INVALID;

    int pri_ok = ota_meta_is_valid(&storage->primary_meta);
    int bak_ok = ota_meta_is_valid(&storage->backup_meta);

    if (pri_ok && bak_ok) {
        if (storage->primary_meta.generation >= storage->backup_meta.generation) {
            ctx->meta = storage->primary_meta;
            storage->backup_meta = storage->primary_meta;
        } else {
            ctx->meta = storage->backup_meta;
            storage->primary_meta = storage->backup_meta;
            ctx->recovered_from_backup = 1;
        }
        return OTA_OK;
    } else if (pri_ok) {
        ctx->meta = storage->primary_meta;
        storage->backup_meta = storage->primary_meta;
        return OTA_OK;
    } else if (bak_ok) {
        /* Primary BCB was torn during a power outage; self-heal from backup BCB */
        ctx->meta = storage->backup_meta;
        storage->primary_meta = storage->backup_meta;
        ctx->recovered_from_backup = 1;
        return OTA_OK;
    }

    return OTA_ERR_CORRUPT_META;
}

int ota_format_storage(struct ota_context *ctx,
                       const void *initial_image,
                       uint32_t image_size,
                       uint64_t initial_version) {
    if (!ctx || !ctx->storage || !initial_image ||
        image_size == 0 || image_size > OTA_MAX_SLOT_BYTES)
        return OTA_ERR_INVALID_ARG;

    memset(ctx->storage, 0, sizeof(*ctx->storage));
    memset(&ctx->meta, 0, sizeof(ctx->meta));

    memcpy(ctx->storage->slot_data[OTA_SLOT_A], initial_image, image_size);

    ctx->meta.magic = OTA_META_MAGIC;
    ctx->meta.generation = 0;
    ctx->meta.rollback_version_floor = initial_version;
    ctx->meta.active_slot = OTA_SLOT_A;

    struct ota_slot_info *slot_a = &ctx->meta.slots[OTA_SLOT_A];
    slot_a->slot_id = OTA_SLOT_A;
    slot_a->state = OTA_SLOT_STATE_ACTIVE;
    slot_a->tries_remaining = 0;
    slot_a->boot_successful = 1;
    slot_a->priority = 10;
    slot_a->version = initial_version;
    slot_a->image_size = image_size;
    ota_sha256(initial_image, image_size, slot_a->sha256);

    struct ota_slot_info *slot_b = &ctx->meta.slots[OTA_SLOT_B];
    slot_b->slot_id = OTA_SLOT_B;
    slot_b->state = OTA_SLOT_STATE_EMPTY;

    ctx->current_boot_slot = OTA_SLOT_A;
    return ota_persist_meta(ctx);
}

/* ============================================================================
 * 3. Full & Incremental Delta Update Engine
 * ============================================================================ */

static int ota_validate_manifest_common(const struct ota_context *ctx,
                                        const struct ota_manifest *manifest) {
    int rc = ota_verify_manifest(manifest, ctx->public_root_key);
    if (rc != OTA_OK)
        return rc;

    /* Enforce hardware monotonic anti-rollback floor */
    if (manifest->version < ctx->meta.rollback_version_floor)
        return OTA_ERR_ROLLBACK;

    const struct ota_slot_info *active = &ctx->meta.slots[ctx->meta.active_slot];
    if (active->version < manifest->min_version)
        return OTA_ERR_ROLLBACK;

    if (manifest->target_size == 0 || manifest->target_size > OTA_MAX_SLOT_BYTES)
        return OTA_ERR_BOUNDS;

    return OTA_OK;
}

static int ota_commit_staged_slot(struct ota_context *ctx,
                                  uint8_t target_slot,
                                  const struct ota_manifest *manifest) {
    uint8_t computed_hash[OTA_SHA256_BYTES];
    ota_sha256(ctx->storage->slot_data[target_slot], manifest->target_size, computed_hash);
    if (ota_ct_memcmp(computed_hash, manifest->target_sha256, OTA_SHA256_BYTES) != 0)
        return OTA_ERR_BAD_HASH;

    const struct ota_slot_info *active = &ctx->meta.slots[ctx->meta.active_slot];
    struct ota_slot_info *dst = &ctx->meta.slots[target_slot];

    dst->slot_id = target_slot;
    dst->state = OTA_SLOT_STATE_TRIAL;
    dst->tries_remaining = OTA_MAX_BOOT_TRIES;
    dst->boot_successful = 0;
    dst->priority = active->priority + 1u;
    dst->version = manifest->version;
    dst->image_size = manifest->target_size;
    dst->last_failure_reason = OTA_FAIL_NONE;
    memcpy(dst->sha256, computed_hash, OTA_SHA256_BYTES);

    return ota_persist_meta(ctx);
}

int ota_stage_full_update(struct ota_context *ctx,
                          const struct ota_manifest *manifest,
                          const void *payload,
                          uint32_t payload_size) {
    if (!ctx || !ctx->storage || !manifest || !payload)
        return OTA_ERR_INVALID_ARG;
    if (manifest->is_delta != 0 || payload_size != manifest->target_size)
        return OTA_ERR_INVALID_ARG;

    int rc = ota_validate_manifest_common(ctx, manifest);
    if (rc != OTA_OK)
        return rc;

    uint8_t target_slot = (ctx->meta.active_slot == OTA_SLOT_A) ? OTA_SLOT_B : OTA_SLOT_A;

    if (ctx->fault_injection_mode == OTA_FAULT_DURING_SLOT_WRITE) {
        /* Write only half the image and simulate power loss before metadata commit */
        memcpy(ctx->storage->slot_data[target_slot], payload, payload_size / 2u);
        return OTA_ERR_POWER_LOSS;
    }

    memcpy(ctx->storage->slot_data[target_slot], payload, payload_size);
    return ota_commit_staged_slot(ctx, target_slot, manifest);
}

static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/*
 * Encode a compact binary delta patch (DLT1) between `base_img` and `target_img`.
 * Uses 32-byte block matching to emit OTA_DELTA_OP_COPY commands for shared blocks
 * and coalesced OTA_DELTA_OP_ADD commands for modified spans.
 */
int ota_encode_delta(const uint8_t *base_img,
                     uint32_t base_size,
                     const uint8_t *target_img,
                     uint32_t target_size,
                     uint8_t *out_patch,
                     uint32_t max_patch_size,
                     uint32_t *out_patch_size) {
    if (!base_img || !target_img || !out_patch || !out_patch_size || max_patch_size < 16)
        return OTA_ERR_INVALID_ARG;

    uint32_t pos = 0;
    write_le32(out_patch + pos, OTA_DELTA_MAGIC); pos += 4;
    write_le32(out_patch + pos, target_size);     pos += 4;

    uint32_t t_idx = 0;
    uint32_t lit_start = 0;
    const uint32_t min_match = 16u;

    while (t_idx < target_size) {
        uint32_t best_off = 0;
        uint32_t best_len = 0;

        /* Check direct offset alignment first (fast O(1) path for in-place edits) */
        if (t_idx < base_size && target_img[t_idx] == base_img[t_idx]) {
            uint32_t len = 0;
            while (t_idx + len < target_size &&
                   t_idx + len < base_size &&
                   target_img[t_idx + len] == base_img[t_idx + len]) {
                len++;
            }
            if (len >= min_match) {
                best_off = t_idx;
                best_len = len;
            }
        }

        /* Fallback windowed scan if direct offset didn't match */
        if (best_len < min_match && target_size - t_idx >= min_match && base_size >= min_match) {
            uint32_t step = 8u;
            for (uint32_t b_off = 0; b_off + min_match <= base_size; b_off += step) {
                if (memcmp(base_img + b_off, target_img + t_idx, min_match) == 0) {
                    uint32_t len = min_match;
                    while (t_idx + len < target_size &&
                           b_off + len < base_size &&
                           target_img[t_idx + len] == base_img[b_off + len]) {
                        len++;
                    }
                    if (len > best_len) {
                        best_len = len;
                        best_off = b_off;
                        break;
                    }
                }
            }
        }

        if (best_len >= min_match) {
            /* Flush pending literal ADD bytes first */
            if (t_idx > lit_start) {
                uint32_t lit_len = t_idx - lit_start;
                if (pos + 5u + lit_len > max_patch_size)
                    return OTA_ERR_BOUNDS;
                out_patch[pos++] = (uint8_t)OTA_DELTA_OP_ADD;
                write_le32(out_patch + pos, lit_len); pos += 4;
                memcpy(out_patch + pos, target_img + lit_start, lit_len);
                pos += lit_len;
            }
            if (pos + 9u > max_patch_size)
                return OTA_ERR_BOUNDS;
            out_patch[pos++] = (uint8_t)OTA_DELTA_OP_COPY;
            write_le32(out_patch + pos, best_off); pos += 4;
            write_le32(out_patch + pos, best_len); pos += 4;

            t_idx += best_len;
            lit_start = t_idx;
        } else {
            t_idx++;
        }
    }

    if (t_idx > lit_start) {
        uint32_t lit_len = t_idx - lit_start;
        if (pos + 5u + lit_len > max_patch_size)
            return OTA_ERR_BOUNDS;
        out_patch[pos++] = (uint8_t)OTA_DELTA_OP_ADD;
        write_le32(out_patch + pos, lit_len); pos += 4;
        memcpy(out_patch + pos, target_img + lit_start, lit_len);
        pos += lit_len;
    }

    if (pos + 1u > max_patch_size)
        return OTA_ERR_BOUNDS;
    out_patch[pos++] = (uint8_t)OTA_DELTA_OP_END;
    *out_patch_size = pos;
    return OTA_OK;
}

int ota_stage_delta_update(struct ota_context *ctx,
                           const struct ota_manifest *manifest,
                           const uint8_t *delta_patch,
                           uint32_t patch_size) {
    if (!ctx || !ctx->storage || !manifest || !delta_patch || patch_size < 9u)
        return OTA_ERR_INVALID_ARG;
    if (manifest->is_delta == 0)
        return OTA_ERR_INVALID_ARG;

    int rc = ota_validate_manifest_common(ctx, manifest);
    if (rc != OTA_OK)
        return rc;

    uint8_t base_slot = ctx->meta.active_slot;
    const struct ota_slot_info *base_info = &ctx->meta.slots[base_slot];
    if (base_info->image_size != manifest->base_size)
        return OTA_ERR_BAD_HASH;

    /* Verify active base slot matches manifest->base_sha256 */
    uint8_t base_hash[OTA_SHA256_BYTES];
    ota_sha256(ctx->storage->slot_data[base_slot], base_info->image_size, base_hash);
    if (ota_ct_memcmp(base_hash, manifest->base_sha256, OTA_SHA256_BYTES) != 0)
        return OTA_ERR_BAD_HASH;

    if (read_le32(delta_patch) != OTA_DELTA_MAGIC)
        return OTA_ERR_DELTA_FORMAT;
    uint32_t expected_target_size = read_le32(delta_patch + 4);
    if (expected_target_size != manifest->target_size ||
        expected_target_size > OTA_MAX_SLOT_BYTES)
        return OTA_ERR_DELTA_FORMAT;

    uint8_t target_slot = (base_slot == OTA_SLOT_A) ? OTA_SLOT_B : OTA_SLOT_A;
    const uint8_t *base_buf = ctx->storage->slot_data[base_slot];
    uint8_t *target_buf = ctx->storage->slot_data[target_slot];

    uint32_t p_off = 8u;
    uint32_t out_off = 0u;
    int saw_end = 0;

    while (p_off < patch_size) {
        uint8_t op = delta_patch[p_off++];
        if (op == OTA_DELTA_OP_END) {
            saw_end = 1;
            break;
        } else if (op == OTA_DELTA_OP_COPY) {
            if (p_off + 8u > patch_size)
                return OTA_ERR_DELTA_FORMAT;
            uint32_t src_off = read_le32(delta_patch + p_off);
            uint32_t copy_len = read_le32(delta_patch + p_off + 4);
            p_off += 8u;

            if (copy_len > manifest->base_size ||
                src_off > manifest->base_size - copy_len ||
                copy_len > expected_target_size - out_off)
                return OTA_ERR_BOUNDS;

            memcpy(target_buf + out_off, base_buf + src_off, copy_len);
            out_off += copy_len;
        } else if (op == OTA_DELTA_OP_ADD) {
            if (p_off + 4u > patch_size)
                return OTA_ERR_DELTA_FORMAT;
            uint32_t add_len = read_le32(delta_patch + p_off);
            p_off += 4u;

            if (add_len > patch_size - p_off ||
                add_len > expected_target_size - out_off)
                return OTA_ERR_BOUNDS;

            memcpy(target_buf + out_off, delta_patch + p_off, add_len);
            p_off += add_len;
            out_off += add_len;
        } else {
            return OTA_ERR_DELTA_FORMAT;
        }
    }

    if (!saw_end || out_off != expected_target_size)
        return OTA_ERR_DELTA_FORMAT;

    if (ctx->fault_injection_mode == OTA_FAULT_DURING_SLOT_WRITE)
        return OTA_ERR_POWER_LOSS;

    return ota_commit_staged_slot(ctx, target_slot, manifest);
}

/* ============================================================================
 * 4. Bootloader Slot Selection, Confirmation & Automatic Rollback
 * ============================================================================ */

static int ota_verify_slot_integrity(const struct ota_context *ctx, uint8_t slot_id) {
    const struct ota_slot_info *s = &ctx->meta.slots[slot_id];
    if (s->image_size == 0 || s->image_size > OTA_MAX_SLOT_BYTES)
        return 0;
    uint8_t digest[OTA_SHA256_BYTES];
    ota_sha256(ctx->storage->slot_data[slot_id], s->image_size, digest);
    return ota_ct_memcmp(digest, s->sha256, OTA_SHA256_BYTES) == 0;
}

int ota_select_boot_slot(struct ota_context *ctx, uint8_t *out_slot) {
    if (!ctx || !ctx->storage || !out_slot)
        return OTA_ERR_INVALID_ARG;

    /* Pick candidate slot with highest priority that is TRIAL or ACTIVE */
    uint8_t first = OTA_SLOT_A;
    uint8_t second = OTA_SLOT_B;
    if (ctx->meta.slots[OTA_SLOT_B].priority > ctx->meta.slots[OTA_SLOT_A].priority) {
        first = OTA_SLOT_B;
        second = OTA_SLOT_A;
    }

    uint8_t order[2] = { first, second };
    for (int i = 0; i < 2; i++) {
        uint8_t idx = order[i];
        struct ota_slot_info *s = &ctx->meta.slots[idx];

        if (s->state == OTA_SLOT_STATE_TRIAL) {
            if (s->tries_remaining == 0) {
                s->state = OTA_SLOT_STATE_UNBOOTABLE;
                s->last_failure_reason = OTA_FAIL_TRIES_EXHAUSTED;
                ctx->meta.rollback_count++;
                continue;
            }
            if (!ota_verify_slot_integrity(ctx, idx)) {
                s->state = OTA_SLOT_STATE_UNBOOTABLE;
                s->tries_remaining = 0;
                s->last_failure_reason = OTA_FAIL_HASH_MISMATCH;
                ctx->meta.rollback_count++;
                continue;
            }
            s->tries_remaining--;
            ctx->current_boot_slot = idx;
            *out_slot = idx;
            return ota_persist_meta(ctx);
        } else if (s->state == OTA_SLOT_STATE_ACTIVE) {
            if (!ota_verify_slot_integrity(ctx, idx)) {
                s->state = OTA_SLOT_STATE_UNBOOTABLE;
                s->last_failure_reason = OTA_FAIL_HASH_MISMATCH;
                continue;
            }
            ctx->meta.active_slot = idx;
            ctx->current_boot_slot = idx;
            *out_slot = idx;
            return ota_persist_meta(ctx);
        }
    }

    *out_slot = OTA_SLOT_INVALID;
    return OTA_ERR_NO_BOOTABLE;
}

int ota_mark_boot_successful(struct ota_context *ctx) {
    if (!ctx || ctx->current_boot_slot >= OTA_SLOT_COUNT)
        return OTA_ERR_INVALID_ARG;

    uint8_t cur = ctx->current_boot_slot;
    uint8_t other = (cur == OTA_SLOT_A) ? OTA_SLOT_B : OTA_SLOT_A;
    struct ota_slot_info *s = &ctx->meta.slots[cur];

    s->state = OTA_SLOT_STATE_ACTIVE;
    s->boot_successful = 1;
    s->tries_remaining = 0;
    s->last_failure_reason = OTA_FAIL_NONE;
    ctx->meta.active_slot = cur;

    /* Advance hardware monotonic anti-rollback floor upon confirmed healthy boot */
    if (s->version > ctx->meta.rollback_version_floor)
        ctx->meta.rollback_version_floor = s->version;

    /* Keep partner slot as valid fallback if it was previously active */
    if (ctx->meta.slots[other].state == OTA_SLOT_STATE_ACTIVE &&
        ctx->meta.slots[other].priority >= s->priority) {
        ctx->meta.slots[other].priority = s->priority - 1u;
    }

    return ota_persist_meta(ctx);
}

static int ota_trigger_rollback(struct ota_context *ctx,
                                enum ota_failure_reason reason,
                                uint8_t *out_fallback_slot) {
    if (!ctx || ctx->current_boot_slot >= OTA_SLOT_COUNT)
        return OTA_ERR_INVALID_ARG;

    uint8_t failed_slot = ctx->current_boot_slot;
    struct ota_slot_info *failed = &ctx->meta.slots[failed_slot];

    failed->state = OTA_SLOT_STATE_UNBOOTABLE;
    failed->tries_remaining = 0;
    failed->boot_successful = 0;
    failed->last_failure_reason = (uint32_t)reason;
    ctx->meta.rollback_count++;

    uint8_t fallback = (failed_slot == OTA_SLOT_A) ? OTA_SLOT_B : OTA_SLOT_A;
    struct ota_slot_info *partner = &ctx->meta.slots[fallback];
    if (partner->state == OTA_SLOT_STATE_ACTIVE && ota_verify_slot_integrity(ctx, fallback)) {
        ctx->meta.active_slot = fallback;
        ctx->current_boot_slot = fallback;
        if (out_fallback_slot)
            *out_fallback_slot = fallback;
        return ota_persist_meta(ctx);
    }

    if (out_fallback_slot)
        *out_fallback_slot = OTA_SLOT_INVALID;
    (void)ota_persist_meta(ctx);
    return OTA_ERR_NO_BOOTABLE;
}

int ota_notify_kernel_panic(struct ota_context *ctx, uint8_t *out_fallback_slot) {
    return ota_trigger_rollback(ctx, OTA_FAIL_KERNEL_PANIC, out_fallback_slot);
}

int ota_notify_watchdog_timeout(struct ota_context *ctx, uint8_t *out_fallback_slot) {
    return ota_trigger_rollback(ctx, OTA_FAIL_WATCHDOG_TIMEOUT, out_fallback_slot);
}
