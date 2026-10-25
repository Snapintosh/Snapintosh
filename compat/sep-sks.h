/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Volatile native startup configuration only. No keys or device-state identity. */
#define SEP_SKS_ENV_BYTES 1036U
#define SEP_SKS_WIRE_MAX 0x4000U
#define SEP_SKS_GET_CAPABILITIES 0x4dU
#define SEP_SKS_SET_ENVIRONMENT 0x2aU

struct sep_sks_wire_state {
    uint64_t updates;
    uint32_t environment_valid;
    uint8_t environment[SEP_SKS_ENV_BYTES];
};

/* Nonzero results are explicit failures, not named Apple firmware error enums.
 * The native wrapper propagates nonzero transport status without decoding OOL.
 * A later mailbox adapter must verify that mapping before advertising SKS. */
enum sep_sks_wire_result { SEP_SKS_SUCCESS, SEP_SKS_REFUSED, SEP_SKS_MALFORMED,
                           SEP_SKS_NO_SPACE, SEP_SKS_BAD_STATE };

/* Validate a complete native request and produce a complete native reply.
 * Inputs and output/state must be disjoint and fully owned by the caller.
 * On failure, only *reply_bytes is set to zero; reply and state stay unchanged.
 * Zero-initialize state before first use. This is not an endpoint/DMA adapter. */
enum sep_sks_wire_result sep_sks_wire(struct sep_sks_wire_state *state,
    uint32_t command, const uint8_t *request, uint32_t request_bytes,
    uint8_t *reply, uint32_t reply_capacity, uint32_t *reply_bytes);

void q1n1_sha256(const void *data, uint64_t len, uint8_t digest[32]);
