/* SPDX-License-Identifier: MIT */
/*
 * Verification Suite for Snapintosh Wireless Stack:
 *   1. NIST P-256 (secp256r1) ECDH (RFC 5903 Section 8.1) & Bluetooth Core Spec
 *      v5.4 Vol 3 Part H Appendix D (D.2 f4, D.3 f5, D.4 f6, D.5 g2) test vectors,
 *      off-curve point rejection, private scalar validation, and secret-key dependence.
 *   2. End-to-End QCC2072 WMI + macOS 26A428 WCL Scan, Scan Abort, 19-state WMI
 *      Association, setCIPHER_KEY (PTK + GTK + PORT_AUTHORIZE), and Leave Network.
 *   3. QCC2072 WMI Power Management (BMPS / IMPS / WoWLAN), 802.11ax TWT,
 *      802.11r FT Roaming (KDF-SHA-256 + WMI_VDEV_INSTALL_KEY), and A-MPDU rings.
 *   4. Bluetooth 5.4 HCI / L2CAP SMP LE Secure Connections + Continuity AirDrop BLE.
 *   5. Apple Wireless Direct Link (AWDL OUI 00:17:F2) PSF/MIF, Master Election & IPv6.
 *
 * Build & Run:
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *      -Wno-misleading-indentation -Icompat -Idrivers/snap-qcc2072/src \
 *      tools/test-wireless-stack.c compat/wireless-stack.c \
 *      drivers/snap-qcc2072/src/native-rsn.c \
 *      drivers/snap-qcc2072/src/native-station.c \
 *      drivers/snap-qcc2072/src/native-wcl-event.c \
 *      drivers/snap-qcc2072/src/native-wcl-key.c \
 *      drivers/snap-qcc2072/src/native-wcl-scan.c \
 *      drivers/snap-qcc2072/src/native-wpa2.c \
 *      drivers/snap-qcc2072/src/native-wpa2-crypto.c \
 *      drivers/snap-qcc2072/src/qcc2072-wmi.c \
 *      drivers/snap-qcc2072/src/qcc2072-scan.c \
 *      drivers/snap-qcc2072/src/qcc2072-assoc.c \
 *      drivers/snap-qcc2072/src/qcc2072-connect.c \
 *      -o /tmp/test-wireless-stack && /tmp/test-wireless-stack
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wireless-stack.h"

static int g_tests_run = 0;
static int g_checks_passed = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "\n[FAIL] %s:%d: assertion failed: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    g_checks_passed++; \
} while (0)

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ==========================================================================
 * 1. NIST P-256 ECDH (RFC 5903) & BT Core Spec v5.4 Appendix D Test Vectors
 * ========================================================================== */
static void test_p256_ecdh_and_bt_spec_vectors(void)
{
    printf("[1/6] Testing NIST P-256 ECDH (RFC 5903) & BT 5.4 Spec f4/f5/f6/g2 vectors...\n");
    g_tests_run++;

    /* RFC 5903 Section 8.1: 256-bit Random ECP Group (NIST P-256 / secp256r1) */
    static const uint8_t rfc5903_sk_i[32] = {
        0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F,
        0x70, 0xA2, 0x92, 0xDA, 0xA2, 0x31, 0x6D, 0xE5,
        0x44, 0xE9, 0xAA, 0xB8, 0xAF, 0xE8, 0x40, 0x49,
        0xC6, 0x2A, 0x9C, 0x57, 0x86, 0x2D, 0x14, 0x33
    };
    static const uint8_t rfc5903_pk_i[64] = {
        /* g^i X */
        0xDA, 0xD0, 0xB6, 0x53, 0x94, 0x22, 0x1C, 0xF9,
        0xB0, 0x51, 0xE1, 0xFE, 0xCA, 0x57, 0x87, 0xD0,
        0x98, 0xDF, 0xE6, 0x37, 0xFC, 0x90, 0xB9, 0xEF,
        0x94, 0x5D, 0x0C, 0x37, 0x72, 0x58, 0x11, 0x80,
        /* g^i Y */
        0x52, 0x71, 0xA0, 0x46, 0x1C, 0xDB, 0x82, 0x52,
        0xD6, 0x1F, 0x1C, 0x45, 0x6F, 0xA3, 0xE5, 0x9A,
        0xB1, 0xF4, 0x5B, 0x33, 0xAC, 0xCF, 0x5F, 0x58,
        0x38, 0x9E, 0x05, 0x77, 0xB8, 0x99, 0x0B, 0xB3
    };
    static const uint8_t rfc5903_sk_r[32] = {
        0xC6, 0xEF, 0x9C, 0x5D, 0x78, 0xAE, 0x01, 0x2A,
        0x01, 0x11, 0x64, 0xAC, 0xB3, 0x97, 0xCE, 0x20,
        0x88, 0x68, 0x5D, 0x8F, 0x06, 0xBF, 0x9B, 0xE0,
        0xB2, 0x83, 0xAB, 0x46, 0x47, 0x6B, 0xEE, 0x53
    };
    static const uint8_t rfc5903_pk_r[64] = {
        /* g^r X */
        0xD1, 0x2D, 0xFB, 0x52, 0x89, 0xC8, 0xD4, 0xF8,
        0x12, 0x08, 0xB7, 0x02, 0x70, 0x39, 0x8C, 0x34,
        0x22, 0x96, 0x97, 0x0A, 0x0B, 0xCC, 0xB7, 0x4C,
        0x73, 0x6F, 0xC7, 0x55, 0x44, 0x94, 0xBF, 0x63,
        /* g^r Y */
        0x56, 0xFB, 0xF3, 0xCA, 0x36, 0x6C, 0xC2, 0x3E,
        0x81, 0x57, 0x85, 0x4C, 0x13, 0xC5, 0x8D, 0x6A,
        0xAC, 0x23, 0xF0, 0x46, 0xAD, 0xA3, 0x0F, 0x83,
        0x53, 0xE7, 0x4F, 0x33, 0x03, 0x98, 0x72, 0xAB
    };
    static const uint8_t rfc5903_shared_z[32] = {
        0xD6, 0x84, 0x0F, 0x6B, 0x42, 0xF6, 0xED, 0xAF,
        0xD1, 0x31, 0x16, 0xE0, 0xE1, 0x25, 0x65, 0x20,
        0x2F, 0xEF, 0x8E, 0x9E, 0xCE, 0x7D, 0xCE, 0x03,
        0x81, 0x24, 0x64, 0xD0, 0x4B, 0x94, 0x42, 0xDE
    };

    uint8_t pk_i[64], pk_r[64], z_ir[32], z_ri[32];
    CHECK(bt_p256_valid_private_key(rfc5903_sk_i) == 1);
    CHECK(bt_p256_valid_private_key(rfc5903_sk_r) == 1);
    CHECK(bt_p256_public_key(rfc5903_sk_i, pk_i) == WL_OK);
    CHECK(bt_p256_public_key(rfc5903_sk_r, pk_r) == WL_OK);
    CHECK(memcmp(pk_i, rfc5903_pk_i, 64) == 0);
    CHECK(memcmp(pk_r, rfc5903_pk_r, 64) == 0);
    CHECK(bt_p256_valid_public_key(pk_i) == 1);
    CHECK(bt_p256_valid_public_key(pk_r) == 1);

    CHECK(bt_p256_ecdh(rfc5903_sk_i, pk_r, z_ir) == WL_OK);
    CHECK(bt_p256_ecdh(rfc5903_sk_r, pk_i, z_ri) == WL_OK);
    CHECK(memcmp(z_ir, rfc5903_shared_z, 32) == 0);
    CHECK(memcmp(z_ri, rfc5903_shared_z, 32) == 0);

    /* Reject invalid private keys (d = 0, d = n) and off-curve public keys */
    uint8_t zero_sk[32] = {0};
    static const uint8_t order_n_sk[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    };
    CHECK(bt_p256_valid_private_key(zero_sk) == 0);
    CHECK(bt_p256_valid_private_key(order_n_sk) == 0);
    CHECK(bt_p256_public_key(zero_sk, pk_i) == WL_ERR_CRYPTO);
    CHECK(bt_p256_public_key(order_n_sk, pk_i) == WL_ERR_CRYPTO);

    uint8_t bad_pk[64];
    memcpy(bad_pk, rfc5903_pk_r, 64);
    bad_pk[63] ^= 0x01; /* Perturb Y coordinate off curve */
    CHECK(bt_p256_valid_public_key(bad_pk) == 0);
    CHECK(bt_p256_ecdh(rfc5903_sk_i, bad_pk, z_ir) == WL_ERR_CRYPTO);

    /* Bluetooth Core Spec v5.4 Vol 3 Part H Appendix D.2: f4 test vector */
    static const uint8_t d2_u[32] = {
        0x20, 0xB0, 0x03, 0xD2, 0xF2, 0x97, 0xBE, 0x2C,
        0x5E, 0x2C, 0x83, 0xA7, 0xE9, 0xF9, 0xA5, 0xB9,
        0xEF, 0xF4, 0x91, 0x11, 0xAC, 0xF4, 0xFD, 0xDB,
        0xCC, 0x03, 0x01, 0x48, 0x0E, 0x35, 0x9D, 0xE6
    };
    static const uint8_t d2_v[32] = {
        0x55, 0x18, 0x8B, 0x3D, 0x32, 0xF6, 0xBB, 0x9A,
        0x90, 0x0A, 0xFC, 0xFB, 0xEE, 0xD4, 0xE7, 0x2A,
        0x59, 0xCB, 0x9A, 0xC2, 0xF1, 0x9D, 0x7C, 0xFB,
        0x6B, 0x4F, 0xDD, 0x49, 0xF4, 0x7F, 0xC5, 0xFD
    };
    static const uint8_t d2_x[16] = {
        0xD5, 0xCB, 0x84, 0x54, 0xD1, 0x77, 0x73, 0x3E,
        0xFF, 0xFF, 0xB2, 0xEC, 0x71, 0x2B, 0xAE, 0xAB
    };
    static const uint8_t d2_expected[16] = {
        0xF2, 0xC9, 0x16, 0xF1, 0x07, 0xA9, 0xBD, 0x1C,
        0xF1, 0xED, 0xA1, 0xBE, 0xA9, 0x74, 0x87, 0x2D
    };
    uint8_t f4_out[16];
    CHECK(bt_smp_f4(d2_u, d2_v, d2_x, 0x00, f4_out) == WL_OK);
    CHECK(memcmp(f4_out, d2_expected, 16) == 0);

    /* Bluetooth Core Spec v5.4 Vol 3 Part H Appendix D.3: f5 test vector */
    static const uint8_t d3_w[32] = {
        0xEC, 0x02, 0x34, 0xA3, 0x57, 0xC8, 0xAD, 0x05,
        0x34, 0x10, 0x10, 0xA6, 0x0A, 0x39, 0x7D, 0x9B,
        0x99, 0x79, 0x6B, 0x13, 0xB4, 0xF8, 0x66, 0xF1,
        0x86, 0x8D, 0x34, 0xF3, 0x73, 0xBF, 0xA6, 0x98
    };
    static const uint8_t d3_n1[16] = {
        0xD5, 0xCB, 0x84, 0x54, 0xD1, 0x77, 0x73, 0x3E,
        0xFF, 0xFF, 0xB2, 0xEC, 0x71, 0x2B, 0xAE, 0xAB
    };
    static const uint8_t d3_n2[16] = {
        0xA6, 0xE8, 0xE7, 0xCC, 0x25, 0xA7, 0x5F, 0x6E,
        0x21, 0x65, 0x83, 0xF7, 0xFF, 0x3D, 0xC4, 0xCF
    };
    static const uint8_t d3_a1[7] = { 0x00, 0x56, 0x12, 0x37, 0x37, 0xBF, 0xCE };
    static const uint8_t d3_a2[7] = { 0x00, 0xA7, 0x13, 0x70, 0x2D, 0xCF, 0xC1 };
    static const uint8_t d3_mackey_exp[16] = {
        0x29, 0x65, 0xF1, 0x76, 0xA1, 0x08, 0x4A, 0x02,
        0xFD, 0x3F, 0x6A, 0x20, 0xCE, 0x63, 0x6E, 0x20
    };
    static const uint8_t d3_ltk_exp[16] = {
        0x69, 0x86, 0x79, 0x11, 0x69, 0xD7, 0xCD, 0x23,
        0x98, 0x05, 0x22, 0xB5, 0x94, 0x75, 0x0A, 0x38
    };
    uint8_t f5_mac[16], f5_ltk[16];
    CHECK(bt_smp_f5(d3_w, d3_n1, d3_n2, d3_a1, d3_a2, f5_mac, f5_ltk) == WL_OK);
    CHECK(memcmp(f5_mac, d3_mackey_exp, 16) == 0);
    CHECK(memcmp(f5_ltk, d3_ltk_exp, 16) == 0);

    /* Bluetooth Core Spec v5.4 Vol 3 Part H Appendix D.4: f6 test vector */
    static const uint8_t d4_r[16] = {
        0x12, 0xA3, 0x34, 0x3B, 0xB4, 0x53, 0xBB, 0x54,
        0x08, 0xDA, 0x42, 0xD2, 0x0C, 0x2D, 0x0F, 0xC8
    };
    static const uint8_t d4_iocap[3] = { 0x01, 0x01, 0x02 };
    static const uint8_t d4_expected[16] = {
        0xE3, 0xC4, 0x73, 0x98, 0x9C, 0xD0, 0xE8, 0xC5,
        0xD2, 0x6C, 0x0B, 0x09, 0xDA, 0x95, 0x8F, 0x61
    };
    uint8_t f6_out[16];
    CHECK(bt_smp_f6(d3_mackey_exp, d3_n1, d3_n2, d4_r, d4_iocap, d3_a1, d3_a2, f6_out) == WL_OK);
    CHECK(memcmp(f6_out, d4_expected, 16) == 0);

    /* Bluetooth Core Spec v5.4 Vol 3 Part H Appendix D.5: g2 test vector */
    uint32_t g2_val = 0;
    CHECK(bt_smp_g2(d2_u, d2_v, d3_n1, d3_n2, &g2_val) == WL_OK);
    CHECK(g2_val == (0x2F9ED5BAU % 1000000U));
}

/* ==========================================================================
 * 2. QCC2072 WMI + macOS 26A428 WCL Scan, Abort, Assoc, Key & Leave Path
 * ========================================================================== */
static void boot_qcc2072_wmi(struct wifi_qcc2072_ctrl *ctrl, const uint8_t sta_mac[6])
{
    /* 1. WMI_SERVICE_READY_EVENTID (0x1): tag 32 (128B) + tag 16 (128B bitmap) */
    uint8_t ev_svc[4 + 4 + 128 + 4 + 128];
    memset(ev_svc, 0, sizeof(ev_svc));
    put_le32(ev_svc + 0, 1U);
    put_le32(ev_svc + 4, (32U << 16) | 128U);
    put_le32(ev_svc + 8 + 36, 2U);   /* num_rf_chains = 2 */
    put_le32(ev_svc + 8 + 76, 64U);  /* max_scan_channels = 64 */
    put_le32(ev_svc + 136, (16U << 16) | 128U);
    /* Enable bit 77 (EXT_MSG): word = 77 / 4 = 19, bit = 77 % 4 = 1 */
    put_le32(ev_svc + 140 + 19 * 4, 1U << 1);
    CHECK(wifi_qcc2072_admit_wmi(ctrl, ev_svc, sizeof(ev_svc), 110ULL) == WL_OK);

    /* 2. WMI_SERVICE_READY_EXT_EVENTID (0x4009) structured for both wmi.c & assoc.c */
    uint8_t ev_ext[256];
    memset(ev_ext, 0, sizeof(ev_ext));
    size_t pos = 0;
    put_le32(ev_ext + pos, 0x4009U); pos += 4;
    put_le32(ev_ext + pos, (428U << 16) | 76U); pos += 4;
    put_le32(ev_ext + pos + 0, 1U); /* default_conc_scan_config_bits / preferred hw mode */
    pos += 76;
    /* WMI_TAG_ARRAY_STRUCT (18) for hw_mode_caps (1 entry of tag 0x211, 12B) */
    put_le32(ev_ext + pos, (18U << 16) | 16U); pos += 4;
    put_le32(ev_ext + pos, (0x211U << 16) | 12U); pos += 4;
    put_le32(ev_ext + pos + 0, 1U); /* hw_mode_id = 1 */
    put_le32(ev_ext + pos + 4, 1U); /* phy_id_map = 1 */
    pos += 12;
    /* WMI_TAG_ARRAY_STRUCT (18) for mac_phy_caps (1 entry of tag 0x210, 88B) */
    put_le32(ev_ext + pos, (18U << 16) | 92U); pos += 4;
    put_le32(ev_ext + pos, (0x210U << 16) | 88U); pos += 4;
    put_le32(ev_ext + pos + 0, 1U);  /* hw_mode_id = 1 */
    put_le32(ev_ext + pos + 4, 0U);  /* pdev_id = 0 */
    put_le32(ev_ext + pos + 16, 3U); /* supported_bands = 2G | 5G */
    put_le32(ev_ext + pos + 20, 6U); /* ampdu_density */
    put_le32(ev_ext + pos + 28, 0x11EFU); /* ht_cap_info_2g */
    put_le32(ev_ext + pos + 48, 3U); /* tx_chain_mask_2g */
    put_le32(ev_ext + pos + 52, 3U); /* rx_chain_mask_2g */
    put_le32(ev_ext + pos + 60, 0x11EFU); /* ht_cap_info_5g */
    put_le32(ev_ext + pos + 80, 3U); /* tx_chain_mask_5g */
    put_le32(ev_ext + pos + 84, 3U); /* rx_chain_mask_5g */
    pos += 88;
    CHECK(wifi_qcc2072_admit_wmi(ctrl, ev_ext, pos, 120ULL) == WL_OK);

    /* Verify WMI_INIT_CMDID (0x1, 332B) was automatically emitted */
    uint32_t cmd_id = 0;
    uint8_t cmd_buf[2040];
    size_t cmd_len = wifi_qcc2072_pop_wmi_tx(ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id);
    CHECK(cmd_len == 332U && cmd_id == 1U);

    /* 3. WMI_READY_EVENTID (0x2, tag 35, 52B) */
    uint8_t ev_rdy[4 + 4 + 52];
    memset(ev_rdy, 0, sizeof(ev_rdy));
    put_le32(ev_rdy + 0, 2U);
    put_le32(ev_rdy + 4, (35U << 16) | 52U);
    memcpy(ev_rdy + 8 + 24, sta_mac, 6);
    CHECK(wifi_qcc2072_admit_wmi(ctrl, ev_rdy, sizeof(ev_rdy), 130ULL) == WL_OK);

    /* 4. WMI_REG_CHAN_LIST_CC_EVENTID (0x3a001, tag 609, 56B + 2 rules of tag 608) */
    uint8_t ev_reg[4 + 4 + 56 + 4 + 32];
    memset(ev_reg, 0, sizeof(ev_reg));
    put_le32(ev_reg + 0, 0x3a001U);
    put_le32(ev_reg + 4, (609U << 16) | 56U);
    ev_reg[8 + 8] = 'F';
    ev_reg[8 + 9] = 'R';
    put_le32(ev_reg + 8 + 12, 1U);  /* domain_code */
    put_le32(ev_reg + 8 + 48, 1U);  /* num_2g_reg_rules = 1 */
    put_le32(ev_reg + 8 + 52, 1U);  /* num_5g_reg_rules = 1 */
    put_le32(ev_reg + 64, (18U << 16) | 32U);
    /* Rule 0: 2402..2472 MHz, 40 MHz BW, 20 dBm */
    put_le32(ev_reg + 68, (608U << 16) | 12U);
    put_le32(ev_reg + 72, 2402U | (2472U << 16));
    put_le32(ev_reg + 76, 40U | (20U << 16));
    /* Rule 1: 5170..5250 MHz, 80 MHz BW, 23 dBm */
    put_le32(ev_reg + 84, (608U << 16) | 12U);
    put_le32(ev_reg + 88, 5170U | (5250U << 16));
    put_le32(ev_reg + 92, 80U | (23U << 16));
    CHECK(wifi_qcc2072_admit_wmi(ctrl, ev_reg, sizeof(ev_reg), 140ULL) == WL_OK);
    CHECK(ctrl->station_admitted == 1 && ctrl->station.admitted == 1);
    CHECK(ctrl->station.pending.type == 0U);
    CHECK((ctrl->station.ready.capabilities & SNAP_STATION_CAP_PRIVATE_SCAN) != 0);
    CHECK((ctrl->station.ready.capabilities & SNAP_STATION_CAP_CONNECT) != 0);
}

static void test_qcc2072_wcl_scan_assoc_key_leave(void)
{
    printf("[2/6] Testing QCC2072 WMI + macOS 26A428 WCL Scan, Abort, Assoc, Key & Leave...\n");
    g_tests_run++;

    struct wifi_qcc2072_ctrl ctrl;
    const uint8_t sta_mac[6] = { 0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    const uint8_t ap_bssid[6] = { 0x60, 0x38, 0xE0, 0xAA, 0xBB, 0xCC };
    CHECK(wifi_ctrl_init(&ctrl, sta_mac) == WL_OK);
    boot_qcc2072_wmi(&ctrl, sta_mac);

    /* 1. Build macOS 26A428 setWCL_SCAN_REQ (0x1550 bytes) with private_mac = 1 */
    uint8_t wcl_scan[SNAP_WCL_SCAN_26A428_BYTES];
    memset(wcl_scan, 0, sizeof(wcl_scan));
    put_le32(wcl_scan + 0x00, 1U);     /* version = 1 */
    wcl_scan[0x04] = 1U;               /* private_mac = 1 */
    put_le32(wcl_scan + 0x08, 30U);    /* home_away_ms */
    put_le32(wcl_scan + 0x10, 2U);     /* bss_type = infrastructure */
    put_le32(wcl_scan + 0x1c, 10U);    /* ssid_bytes = 10 */
    memcpy(wcl_scan + 0x20, "Snapintosh", 10);
    put_le32(wcl_scan + 0x40, 1U);     /* mode = active */
    put_le32(wcl_scan + 0x48, 40U);    /* active_dwell_ms */
    put_le32(wcl_scan + 0x4c, 110U);   /* passive_dwell_ms */
    put_le32(wcl_scan + 0x54, 1U);     /* channel_count = 1 */
    put_le32(wcl_scan + 0x58, 1U);     /* chan version = 1 */
    put_le32(wcl_scan + 0x5c, 6U);     /* channel 6 (2437 MHz) */
    put_le32(wcl_scan + 0x60, 0x8U);   /* 2.4 GHz */

    CHECK(wifi_qcc2072_wcl_scan_req(&ctrl, wcl_scan, sizeof(wcl_scan), 200ULL) == WL_OK);
    CHECK(ctrl.station.pending.type == SNAP_STATION_SCAN);

    /* Verify WMI_SCAN_CHAN_LIST (0x3003), WMI_VDEV_CREATE (0x5001), WMI_START_SCAN (0x3001) */
    uint32_t cmd_id = 0;
    uint8_t cmd_buf[2040];
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 && cmd_id == 0x3003U);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 && cmd_id == 0x5001U);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 && cmd_id == 0x3001U);

    /* 2. Inject WMI_MGMT_RX_EVENTID (0x7001) with 802.11 Beacon on Ch 6 (2437 MHz) */
    uint8_t beacon[128];
    size_t b_len = 0;
    memset(beacon, 0, sizeof(beacon));
    put_le16(beacon + 0, 0x0080U); /* Beacon */
    memset(beacon + 4, 0xFF, 6);
    memcpy(beacon + 10, ap_bssid, 6);
    memcpy(beacon + 16, ap_bssid, 6);
    put_le16(beacon + 32, 100U);   /* beacon_interval */
    put_le16(beacon + 34, 0x0431U);/* capability (ESS | Privacy | ShortSlot) */
    b_len = 36;
    /* IE 0: SSID "Snapintosh" */
    beacon[b_len++] = 0; beacon[b_len++] = 10;
    memcpy(beacon + b_len, "Snapintosh", 10); b_len += 10;
    /* IE 1: Supported Rates */
    beacon[b_len++] = 1; beacon[b_len++] = 4;
    beacon[b_len++] = 0x82; beacon[b_len++] = 0x84; beacon[b_len++] = 0x8B; beacon[b_len++] = 0x96;
    /* IE 3: DS Parameter Set (Channel 6) */
    beacon[b_len++] = 3; beacon[b_len++] = 1; beacon[b_len++] = 6;
    /* IE 48: WPA2-PSK CCMP RSN Element */
    memcpy(beacon + b_len, snap_rsn_own, SNAP_RSN_OWN_LENGTH);
    b_len += SNAP_RSN_OWN_LENGTH;

    size_t aligned_b = (b_len + 3U) & ~3U;
    uint8_t ev_bcn[4 + 4 + 68 + 4 + 128];
    memset(ev_bcn, 0, sizeof(ev_bcn));
    put_le32(ev_bcn + 0, 0x7001U);
    put_le32(ev_bcn + 4, (44U << 16) | 68U);
    put_le32(ev_bcn + 8 + 0, 6U);             /* channel = 6 */
    put_le32(ev_bcn + 8 + 4, 42U);            /* snr = 42 (-53 dBm) */
    put_le32(ev_bcn + 8 + 16, (uint32_t)b_len);
    put_le32(ev_bcn + 8 + 64, 2437U);         /* chan_freq = 2437 MHz */
    put_le32(ev_bcn + 76, (17U << 16) | (uint32_t)aligned_b);
    memcpy(ev_bcn + 80, beacon, b_len);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_bcn, 80U + aligned_b, 210ULL) == WL_OK);

    /* Verify WCL_SCAN_RESULT (0xc9) queued */
    uint32_t wcl_msg = 0;
    size_t wcl_bytes = 0;
    uint8_t wcl_payload[SNAP_WCL_EVENT_MAX_BYTES];
    CHECK(wifi_qcc2072_pop_wcl_event(&ctrl, &wcl_msg, wcl_payload,
                                     sizeof(wcl_payload), &wcl_bytes) == WL_OK);
    CHECK(wcl_msg == 0xc9U && wcl_bytes > SNAP_WCL_BEACON_META_BYTES);

    /* 3. Inject WMI_SCAN_EVENTID (0x3001, COMPLETED) */
    uint8_t ev_scan_done[4 + 4 + 28];
    memset(ev_scan_done, 0, sizeof(ev_scan_done));
    put_le32(ev_scan_done + 0, 0x3001U);
    put_le32(ev_scan_done + 4, (36U << 16) | 28U);
    put_le32(ev_scan_done + 8 + 0, QCC2072_SCAN_COMPLETED);
    put_le32(ev_scan_done + 8 + 12, 1U);
    put_le32(ev_scan_done + 8 + 16, QCC2072_SCAN_ID);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_scan_done, sizeof(ev_scan_done), 220ULL) == WL_OK);
    CHECK(ctrl.station.pending.type == 0U);
    CHECK(wifi_qcc2072_pop_wcl_event(&ctrl, &wcl_msg, wcl_payload,
                                     sizeof(wcl_payload), &wcl_bytes) == WL_OK);
    CHECK(wcl_msg == 0xedU && wcl_bytes == 4U);

    /* 4. Test Scan Abort: start a new scan and abort via setWCL_SCAN_ABORT */
    CHECK(wifi_qcc2072_wcl_scan_req(&ctrl, wcl_scan, sizeof(wcl_scan), 230ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 && cmd_id == 0x3001U);
    CHECK(wifi_qcc2072_wcl_scan_abort(&ctrl, 235ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == WIFI_WMI_STOP_SCAN_CMDID);
    CHECK(wifi_qcc2072_pop_wcl_event(&ctrl, &wcl_msg, wcl_payload,
                                     sizeof(wcl_payload), &wcl_bytes) == WL_OK);
    CHECK(wcl_msg == 0xedU);
    CHECK(ctrl.station.pending.type == 0U);

    /* 5. Submit macOS 26A428 setWCL_ASSOCIATE (0x268 bytes) */
    uint8_t wcl_assoc[SNAP_WCL_ASSOC_26A428_BYTES];
    memset(wcl_assoc, 0, sizeof(wcl_assoc));
    put_le32(wcl_assoc + 0x00, 1U);
    put_le32(wcl_assoc + 0x04, 10U);
    memcpy(wcl_assoc + 0x08, "Snapintosh", 10);
    memcpy(wcl_assoc + 0x28, ap_bssid, 6);
    put_le16(wcl_assoc + 0x2e, 2437U);
    uint8_t pmk[32];
    memset(pmk, 0x42, sizeof(pmk));

    CHECK(wifi_qcc2072_wcl_associate(&ctrl, wcl_assoc, sizeof(wcl_assoc), pmk, 300ULL) == WL_OK);
    CHECK(ctrl.station.pending.type == SNAP_STATION_CONNECT);

    /* Drain initial pdev/vdev params + PEER_CREATE (0x6001) */
    int saw_peer_create = 0;
    while (wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0) {
        if (cmd_id == QCC2072_ASSOC_CMD_PEER_CREATE) saw_peer_create = 1;
    }
    CHECK(saw_peer_create == 1);

    /* Inject HTT_T2H_MSG_TYPE_PEER_MAP (0x03) -> triggers 17x REO + VDEV_START (0x5003) */
    uint8_t htt_map[16] = { 0x03, 0x00, 0x01, 0x00 };
    memcpy(htt_map + 4, ap_bssid, 6);
    CHECK(wifi_qcc2072_htt_event(&ctrl, htt_map, sizeof(htt_map), 310ULL) == WL_OK);

    int saw_vdev_start = 0;
    while (wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0) {
        if (cmd_id == QCC2072_ASSOC_CMD_VDEV_START) saw_vdev_start = 1;
    }
    CHECK(saw_vdev_start == 1);

    /* Inject WMI_VDEV_START_RESP_EVENTID (0x5001, tag 40, 40B) -> triggers Auth MGMT_TX_SEND */
    uint8_t ev_vstart[4 + 4 + 40];
    memset(ev_vstart, 0, sizeof(ev_vstart));
    put_le32(ev_vstart + 0, 0x5001U);
    put_le32(ev_vstart + 4, (40U << 16) | 40U);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_vstart, sizeof(ev_vstart), 320ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_MGMT_TX_SEND);
    uint32_t auth_desc_id = get_le32(cmd_buf + 12);

    /* Inject WMI_MGMT_TX_COMPLETION (0x7006, tag 423, 20B) + Auth Response (0x7001) */
    uint8_t ev_tx_done[4 + 4 + 20];
    memset(ev_tx_done, 0, sizeof(ev_tx_done));
    put_le32(ev_tx_done + 0, 0x7006U);
    put_le32(ev_tx_done + 4, (423U << 16) | 20U);
    put_le32(ev_tx_done + 8, auth_desc_id);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_tx_done, sizeof(ev_tx_done), 325ULL) == WL_OK);

    uint8_t auth_resp[32];
    memset(auth_resp, 0, sizeof(auth_resp));
    put_le16(auth_resp + 0, 0x00B0U); /* Authentication */
    memcpy(auth_resp + 4, sta_mac, 6);
    memcpy(auth_resp + 10, ap_bssid, 6);
    memcpy(auth_resp + 16, ap_bssid, 6);
    put_le16(auth_resp + 24, 0U); /* Open System */
    put_le16(auth_resp + 26, 2U); /* Auth transaction = 2 */
    put_le16(auth_resp + 28, 0U); /* Status = 0 (Success) */

    uint8_t ev_auth_rx[4 + 4 + 68 + 4 + 32];
    memset(ev_auth_rx, 0, sizeof(ev_auth_rx));
    put_le32(ev_auth_rx + 0, 0x7001U);
    put_le32(ev_auth_rx + 4, (44U << 16) | 68U);
    put_le32(ev_auth_rx + 8 + 0, 6U);
    put_le32(ev_auth_rx + 8 + 16, 30U);
    put_le32(ev_auth_rx + 8 + 64, 2437U);
    put_le32(ev_auth_rx + 76, (17U << 16) | 32U);
    memcpy(ev_auth_rx + 80, auth_resp, 30U);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_auth_rx, sizeof(ev_auth_rx), 330ULL) == WL_OK);

    /* Verify AssocReq MGMT_TX_SEND (0x7008) emitted */
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_MGMT_TX_SEND);
    uint32_t assoc_desc_id = get_le32(cmd_buf + 12);

    put_le32(ev_tx_done + 8, assoc_desc_id);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_tx_done, sizeof(ev_tx_done), 335ULL) == WL_OK);

    /* Inject Association Response (0x0010, AID=1, Status=0) */
    uint8_t assoc_resp[40];
    memset(assoc_resp, 0, sizeof(assoc_resp));
    put_le16(assoc_resp + 0, 0x0010U); /* Assoc Response */
    memcpy(assoc_resp + 4, sta_mac, 6);
    memcpy(assoc_resp + 10, ap_bssid, 6);
    memcpy(assoc_resp + 16, ap_bssid, 6);
    put_le16(assoc_resp + 24, 0x0431U);
    put_le16(assoc_resp + 26, 0U);      /* Status = 0 */
    put_le16(assoc_resp + 28, 0xC001U); /* AID = 1 */
    assoc_resp[30] = 1; assoc_resp[31] = 4;
    assoc_resp[32] = 0x82; assoc_resp[33] = 0x84; assoc_resp[34] = 0x8B; assoc_resp[35] = 0x96;

    uint8_t ev_assoc_rx[4 + 4 + 68 + 4 + 36];
    memset(ev_assoc_rx, 0, sizeof(ev_assoc_rx));
    put_le32(ev_assoc_rx + 0, 0x7001U);
    put_le32(ev_assoc_rx + 4, (44U << 16) | 68U);
    put_le32(ev_assoc_rx + 8 + 0, 6U);
    put_le32(ev_assoc_rx + 8 + 16, 36U);
    put_le32(ev_assoc_rx + 8 + 64, 2437U);
    put_le32(ev_assoc_rx + 76, (17U << 16) | 36U);
    memcpy(ev_assoc_rx + 80, assoc_resp, 36U);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_assoc_rx, sizeof(ev_assoc_rx), 340ULL) == WL_OK);

    /* Drain BSS params + PEER_ASSOC (0x6005) */
    int saw_peer_assoc = 0;
    while (wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0) {
        if (cmd_id == QCC2072_ASSOC_CMD_PEER_ASSOC) saw_peer_assoc = 1;
    }
    CHECK(saw_peer_assoc == 1);

    /* Inject WMI_PEER_ASSOC_CONF_EVENTID (0x6006, tag 434, 12B) -> ASSOCIATED! */
    uint8_t ev_pconf[4 + 4 + 12];
    memset(ev_pconf, 0, sizeof(ev_pconf));
    put_le32(ev_pconf + 0, 0x6006U);
    put_le32(ev_pconf + 4, (434U << 16) | 12U);
    put_le32(ev_pconf + 8, 0U); /* vdev_id = 0 */
    memcpy(ev_pconf + 12, ap_bssid, 6);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_pconf, sizeof(ev_pconf), 350ULL) == WL_OK);
    CHECK(ctrl.station.associated == 1);
    CHECK(ctrl.station.connected == 0);

    /* Verify WCL_ASSOC_DONE (0x08) event emitted */
    CHECK(wifi_qcc2072_pop_wcl_event(&ctrl, &wcl_msg, wcl_payload,
                                     sizeof(wcl_payload), &wcl_bytes) == WL_OK);
    CHECK(wcl_msg == SNAP_WCL_EVENT_ASSOC_DONE);
    while (wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0) {}

    /* 6. Submit setCIPHER_KEY (0x94 bytes) for PTK (pairwise) and GTK (group) */
    uint8_t wcl_ptk[SNAP_WCL_KEY_26A428_BYTES];
    memset(wcl_ptk, 0, sizeof(wcl_ptk));
    put_le32(wcl_ptk + 0x04, 16U); /* key_length = 16 */
    put_le32(wcl_ptk + 0x08, 5U);  /* cipher = CCMP-128 */
    put_le16(wcl_ptk + 0x0c, 13U); /* flags = 13 (pairwise PTK) */
    put_le16(wcl_ptk + 0x0e, 0U);  /* key_index = 0 */
    memset(wcl_ptk + 0x10, 0xAA, 16);
    memcpy(wcl_ptk + 0x5c, ap_bssid, 6);
    CHECK(wifi_qcc2072_wcl_cipher_key(&ctrl, wcl_ptk, sizeof(wcl_ptk), 360ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_VDEV_INSTALL_KEY);

    uint8_t ev_key_done[4 + 4 + 24];
    memset(ev_key_done, 0, sizeof(ev_key_done));
    put_le32(ev_key_done + 0, 0x5003U);
    put_le32(ev_key_done + 4, (42U << 16) | 24U);
    put_le32(ev_key_done + 8, 0U); /* vdev_id = 0 */
    memcpy(ev_key_done + 12, ap_bssid, 6);
    put_le32(ev_key_done + 20, 0U); /* key_idx = 0 */
    put_le32(ev_key_done + 24, QCC2072_ASSOC_KEY_PAIRWISE);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_key_done, sizeof(ev_key_done), 365ULL) == WL_OK);

    /* Group GTK install -> automatically triggers PORT_AUTHORIZE! */
    uint8_t wcl_gtk[SNAP_WCL_KEY_26A428_BYTES];
    memset(wcl_gtk, 0, sizeof(wcl_gtk));
    put_le32(wcl_gtk + 0x04, 16U); /* key_length = 16 */
    put_le32(wcl_gtk + 0x08, 5U);  /* cipher = CCMP-128 */
    put_le16(wcl_gtk + 0x0c, 10U); /* flags = 10 (group GTK) */
    put_le16(wcl_gtk + 0x0e, 1U);  /* key_index = 1 */
    memset(wcl_gtk + 0x10, 0xBB, 16);
    memset(wcl_gtk + 0x5c, 0xFF, 6);
    CHECK(wifi_qcc2072_wcl_cipher_key(&ctrl, wcl_gtk, sizeof(wcl_gtk), 370ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_VDEV_INSTALL_KEY);

    put_le32(ev_key_done + 20, 1U); /* key_idx = 1 */
    put_le32(ev_key_done + 24, QCC2072_ASSOC_KEY_GROUP);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_key_done, sizeof(ev_key_done), 375ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_PEER_SET_PARAM);
    CHECK(ctrl.station.connected == 1);
    CHECK(ctrl.station.authorized == 1);

    /* Verify WCL_LINK_CHANGED (0x01) and WCL_BSSID_CHANGED (0x03) events */
    CHECK(wifi_qcc2072_pop_wcl_event(&ctrl, &wcl_msg, wcl_payload,
                                     sizeof(wcl_payload), &wcl_bytes) == WL_OK);
    CHECK(wcl_msg == SNAP_WCL_EVENT_LINK_CHANGED);
    CHECK(wifi_qcc2072_pop_wcl_event(&ctrl, &wcl_msg, wcl_payload,
                                     sizeof(wcl_payload), &wcl_bytes) == WL_OK);
    CHECK(wcl_msg == SNAP_WCL_EVENT_BSSID_CHANGED);

    /* 7. Leave Network (setWCL_LEAVE_NETWORK): Deauth TX -> PTK/GTK delete -> VDEV_STOP -> PEER_DELETE */
    CHECK(wifi_qcc2072_wcl_leave(&ctrl, 3U, 400ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_MGMT_TX_SEND);
    uint32_t deauth_desc_id = get_le32(cmd_buf + 12);
    put_le32(ev_tx_done + 8, deauth_desc_id);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_tx_done, sizeof(ev_tx_done), 402ULL) == WL_OK);

    /* PTK delete completion */
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_VDEV_INSTALL_KEY);
    put_le32(ev_key_done + 20, 0U);
    put_le32(ev_key_done + 24, QCC2072_ASSOC_KEY_PAIRWISE);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_key_done, sizeof(ev_key_done), 404ULL) == WL_OK);

    /* GTK delete completion -> emits VDEV_DOWN + VDEV_STOP */
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_VDEV_INSTALL_KEY);
    put_le32(ev_key_done + 20, 1U);
    put_le32(ev_key_done + 24, QCC2072_ASSOC_KEY_GROUP);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_key_done, sizeof(ev_key_done), 406ULL) == WL_OK);

    int saw_vdev_stop = 0;
    while (wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0) {
        if (cmd_id == QCC2072_ASSOC_CMD_VDEV_STOP) saw_vdev_stop = 1;
    }
    CHECK(saw_vdev_stop == 1);

    uint8_t ev_vstopped[4 + 4 + 4];
    put_le32(ev_vstopped + 0, 0x5002U);
    put_le32(ev_vstopped + 4, (41U << 16) | 4U);
    put_le32(ev_vstopped + 8, 0U);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_vstopped, sizeof(ev_vstopped), 410ULL) == WL_OK);
    CHECK(wifi_qcc2072_pop_wmi_tx(&ctrl, cmd_buf, sizeof(cmd_buf), &cmd_id) > 0 &&
          cmd_id == QCC2072_ASSOC_CMD_PEER_DELETE);

    uint8_t ev_pdel[4 + 4 + 12];
    memset(ev_pdel, 0, sizeof(ev_pdel));
    put_le32(ev_pdel + 0, 0x6007U);
    put_le32(ev_pdel + 4, (451U << 16) | 12U);
    put_le32(ev_pdel + 8, 0U);
    memcpy(ev_pdel + 12, ap_bssid, 6);
    CHECK(wifi_qcc2072_admit_wmi(&ctrl, ev_pdel, sizeof(ev_pdel), 415ULL) == WL_OK);

    uint8_t htt_unmap[12] = { 0x04, 0x00, 0x01, 0x00 };
    memcpy(htt_unmap + 4, ap_bssid, 6);
    CHECK(wifi_qcc2072_htt_event(&ctrl, htt_unmap, sizeof(htt_unmap), 420ULL) == WL_OK);
    CHECK(ctrl.station.associated == 0 && ctrl.station.connected == 0);
}

/* ==========================================================================
 * 3. QCC2072 Power Management, 802.11ax TWT, 802.11r FT & A-MPDU Aggregation
 * ========================================================================== */
static void test_qcc2072_pm_twt_ft_ampdu(void)
{
    printf("[3/6] Testing QCC2072 WMI Power-Save, 802.11ax TWT, 802.11r FT & A-MPDU...\n");
    g_tests_run++;

    struct wifi_qcc2072_ctrl ctrl;
    const uint8_t sta_mac[6] = { 0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    CHECK(wifi_ctrl_init(&ctrl, sta_mac) == WL_OK);
    CHECK(wifi_ctrl_validate_stage2_window(&ctrl, 0xdc000000ULL, 0x100000U) == WL_OK);
    CHECK(wifi_ctrl_validate_stage2_window(&ctrl, 0x70000000ULL, 0x1000U) == WL_ERR_BOUNDS);

    CHECK(wifi_ctrl_tick_idle(&ctrl, 60, 0) == WL_OK);
    CHECK(ctrl.pm_state == WIFI_PM_BMPS);
    CHECK(ctrl.last_wmi_cmd_id == WIFI_WMI_STA_PS_MODE_CMDID);

    CHECK(wifi_ctrl_negotiate_twt(&ctrl, 1, 100, 10, 8, 1000000ULL) == WL_OK);
    CHECK(ctrl.last_wmi_cmd_id == WIFI_WMI_TWT_ADD_DIALOG_CMDID);

    /* 802.11r FT Roaming with KDF-SHA-256 + WMI_VDEV_INSTALL_KEY (0x5009) */
    ctrl.ft.mobility_domain[0] = 0xA1;
    ctrl.ft.mobility_domain[1] = 0xB2;
    memcpy(ctrl.ft.r0kh_id, "r0kh.snapintosh.local", 21);
    ctrl.ft.r0kh_id_len = 21;
    memset(ctrl.ft.xxkey, 0x5A, 32);

    struct wifi_bss_candidate cands[2];
    memset(cands, 0, sizeof(cands));
    cands[0].bssid[5] = 0x01; cands[0].channel_mhz = 2437; cands[0].rssi_dbm = -75;
    cands[1].bssid[5] = 0x02; cands[1].channel_mhz = 5975; cands[1].rssi_dbm = -55;
    cands[1].snr_db = 38; cands[1].he_mcs_max = 11; cands[1].ft_supported = 1;
    cands[1].mobility_domain[0] = 0xA1; cands[1].mobility_domain[1] = 0xB2;

    struct wifi_bss_candidate best;
    CHECK(wifi_ctrl_select_roam_candidate(&ctrl, cands, 2, &best) == WL_OK);
    CHECK(best.channel_mhz == 5975);

    uint8_t anonce[32], snonce[32];
    memset(anonce, 0x11, 32);
    memset(snonce, 0x22, 32);
    CHECK(wifi_ctrl_roam_ft(&ctrl, &best, anonce, snonce) == WL_OK);
    CHECK(ctrl.ft.keys_derived == 1 && ctrl.ft.roam_count == 1);
    CHECK(ctrl.last_wmi_cmd_id == QCC2072_ASSOC_CMD_VDEV_INSTALL_KEY);

    uint32_t sf = 0, bytes = 0, acked = 0;
    CHECK(wifi_ampdu_push(&ctrl.tx_agg, 0xdc010000ULL, 1500, 1) == WL_OK);
    CHECK(wifi_ampdu_push(&ctrl.tx_agg, 0xdc011000ULL, 1500, 1) == WL_OK);
    CHECK(wifi_ampdu_flush(&ctrl.tx_agg, &sf, &bytes) == WL_OK && sf == 2);
    CHECK(wifi_ampdu_ack_bitmap(&ctrl.tx_agg, 0, 0x3ULL, &acked) == WL_OK && acked == 2);
}

/* ==========================================================================
 * 4. Bluetooth 5.4 LE Secure Connections SMP (P-256 ECDH + Private Key Proof)
 * ========================================================================== */
static void test_bt_smp_p256_pairing_and_security(void)
{
    printf("[4/6] Testing Bluetooth 5.4 LE Secure Connections SMP (P-256 ECDH)...\n");
    g_tests_run++;

    struct bt_stack_state init_bt, resp_bt;
    const uint8_t init_mac[6] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    const uint8_t resp_mac[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    CHECK(bt_stack_init(&init_bt, init_mac) == WL_OK);
    CHECK(bt_stack_init(&resp_bt, resp_mac) == WL_OK);
    uint8_t hci_cmd[16], hci_evt[32];
    size_t hci_cmd_len = 0, hci_evt_len = 0;
    CHECK(bt_hci_build_cmd(BT_HCI_OP_RESET, NULL, 0,
                           hci_cmd, sizeof(hci_cmd), &hci_cmd_len) == WL_OK);
    CHECK(bt_hci_process_cmd_GenerateEvt(&init_bt, hci_cmd, hci_cmd_len,
                                         hci_evt, sizeof(hci_evt), &hci_evt_len) == WL_OK);
    CHECK(bt_hci_process_cmd_GenerateEvt(&resp_bt, hci_cmd, hci_cmd_len,
                                         hci_evt, sizeof(hci_evt), &hci_evt_len) == WL_OK);
    CHECK(bt_hci_inject_le_conn_complete(&init_bt, 0x0040, resp_mac) == WL_OK);
    CHECK(bt_hci_inject_le_conn_complete(&resp_bt, 0x0040, init_mac) == WL_OK);

    static const uint8_t sk_a[32] = {
        0x3F, 0x49, 0xF6, 0xD4, 0xA3, 0xC5, 0x5F, 0x38,
        0x74, 0xC9, 0xB3, 0xE3, 0xD2, 0x10, 0x3F, 0x50,
        0x4A, 0xFF, 0x60, 0x7B, 0xEB, 0x40, 0xB7, 0x99,
        0x58, 0x99, 0xB8, 0xA6, 0xCD, 0x3C, 0x1A, 0xBD
    };
    static const uint8_t sk_b[32] = {
        0x55, 0x18, 0x8B, 0x3D, 0x32, 0xF6, 0xBB, 0x9A,
        0x90, 0x0A, 0xFC, 0xFB, 0xEE, 0xD4, 0xE7, 0x2A,
        0x59, 0xCB, 0x9A, 0xC2, 0xF1, 0x9D, 0x7C, 0xFB,
        0x6B, 0x4F, 0xDD, 0x49, 0xF4, 0x7F, 0xC5, 0xFD
    };
    uint8_t na[16], nb[16];
    memset(na, 0xA5, 16);
    memset(nb, 0x5A, 16);

    CHECK(bt_smp_set_local_keypair(&init_bt, sk_a, na) == WL_OK);
    CHECK(bt_smp_set_local_keypair(&resp_bt, sk_b, nb) == WL_OK);

    uint8_t msg1[128], msg2[128];
    size_t len1 = 0, len2 = 0;

    /* Step 1: Pairing Request -> Pairing Response */
    CHECK(bt_smp_start_pairing(&init_bt, 1, msg1, sizeof(msg1), &len1) == WL_OK);
    CHECK(bt_smp_start_pairing(&resp_bt, 0, msg2, sizeof(msg2), &len2) == WL_OK);
    CHECK(bt_smp_step(&resp_bt, msg1, len1, msg2, sizeof(msg2), &len2) == WL_OK);

    /* Step 2: Pairing Response -> Initiator sends P-256 Public Key (PKa = sk_a * G) */
    CHECK(bt_smp_step(&init_bt, msg2, len2, msg1, sizeof(msg1), &len1) == WL_OK);

    /* Security proof: off-curve peer public key is rejected with WL_ERR_CRYPTO */
    struct bt_stack_state bad_resp = resp_bt;
    uint8_t corrupt_pk[128];
    memcpy(corrupt_pk, msg1, len1);
    corrupt_pk[len1 - 1] ^= 0x01;
    CHECK(bt_smp_step(&bad_resp, corrupt_pk, len1, msg2, sizeof(msg2), &len2) == WL_ERR_CRYPTO);
    CHECK(bad_resp.smp.state == BT_SMP_STATE_FAILED);

    /* Step 3: Responder validates PKa on curve, computes ECDH(sk_b, PKa), sends PKb */
    CHECK(bt_smp_step(&resp_bt, msg1, len1, msg2, sizeof(msg2), &len2) == WL_OK);

    /* Step 4: Initiator validates PKb on curve, computes ECDH(sk_a, PKb) */
    CHECK(bt_smp_step(&init_bt, msg2, len2, msg1, sizeof(msg1), &len1) == WL_OK);
    CHECK(memcmp(init_bt.smp.dhkey, resp_bt.smp.dhkey, 32) == 0);

    /* Construct Responder Cb = f4(PKb_x, PKa_x, Nb, 0) wrapped in L2CAP SMP */
    uint8_t cb_l2cap[21] = { 17, 0, 0x06, 0x00, BT_SMP_CMD_PAIRING_CONFIRM };
    bt_smp_compute_confirm(resp_bt.smp.local_pk, init_bt.smp.local_pk, nb, 0, &cb_l2cap[5]);

    /* Step 5: Initiator receives Cb -> sends Na */
    CHECK(bt_smp_step(&init_bt, cb_l2cap, sizeof(cb_l2cap), msg1, sizeof(msg1), &len1) == WL_OK);

    /* Step 6: Responder receives Na -> derives f5(DHKey), wipes sk_b, sends Nb */
    CHECK(bt_smp_step(&resp_bt, msg1, len1, msg2, sizeof(msg2), &len2) == WL_OK);
    CHECK(resp_bt.smp.has_private_key == 0);

    /* Step 7: Initiator receives Nb -> verifies Cb, derives f5(DHKey), wipes sk_a, sends Ea */
    CHECK(bt_smp_step(&init_bt, msg2, len2, msg1, sizeof(msg1), &len1) == WL_OK);
    CHECK(init_bt.smp.has_private_key == 0);

    /* Step 8: Responder verifies Ea -> PAIRED, sends Eb -> Initiator verifies Eb -> PAIRED */
    CHECK(bt_smp_step(&resp_bt, msg1, len1, msg2, sizeof(msg2), &len2) == WL_OK);
    CHECK(bt_smp_step(&init_bt, msg2, len2, msg1, sizeof(msg1), &len1) == WL_OK);

    CHECK(init_bt.smp.state == BT_SMP_STATE_PAIRED);
    CHECK(resp_bt.smp.state == BT_SMP_STATE_PAIRED);
    CHECK(memcmp(init_bt.smp.ltk, resp_bt.smp.ltk, 16) == 0);
    CHECK(init_bt.smp.numeric_passkey == resp_bt.smp.numeric_passkey);
}

/* ==========================================================================
 * 5. Apple Continuity AirDrop BLE Advertisements
 * ========================================================================== */
static void test_ble_airdrop_continuity(void)
{
    printf("[5/6] Testing Apple Continuity AirDrop BLE advertisement codec...\n");
    g_tests_run++;

    struct apple_ble_airdrop_adv adv_in, adv_out;
    memset(&adv_in, 0, sizeof(adv_in));
    adv_in.airdrop_version = 0x01;
    adv_in.hash_apple_id = 0xABCD;
    adv_in.hash_phone = 0x1234;
    adv_in.hash_email = 0x5678;
    adv_in.hash_icloud = 0x9E0F;

    uint8_t buf[32];
    size_t len = 0;
    CHECK(bt_encode_airdrop_ble_adv(&adv_in, buf, sizeof(buf), &len) == WL_OK);
    CHECK(len == 27U);
    CHECK(bt_decode_airdrop_ble_adv(buf, len, &adv_out) == WL_OK);
    CHECK(adv_out.hash_apple_id == 0xABCD && adv_out.hash_phone == 0x1234);
    CHECK(adv_out.hash_email == 0x5678 && adv_out.hash_icloud == 0x9E0F);
}

/* ==========================================================================
 * 6. Apple Wireless Direct Link (AWDL) Action Frame, Election & IPv6 Data
 * ========================================================================== */
static void test_awdl_protocol(void)
{
    printf("[6/6] Testing AWDL PSF/MIF Action frames, Master Election & IPv6 data...\n");
    g_tests_run++;

    struct awdl_state node_a, node_b;
    const uint8_t mac_a[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const uint8_t mac_b[6] = { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    CHECK(awdl_init(&node_a, mac_a, 100) == WL_OK);
    CHECK(awdl_init(&node_b, mac_b, 250) == WL_OK);

    uint8_t mif[256];
    size_t mif_len = 0;
    CHECK(awdl_encode_action_frame(&node_b, AWDL_FRAME_MIF, mif, sizeof(mif), &mif_len) == WL_OK);
    CHECK(awdl_process_action_frame(&node_a, mif, mif_len, -45, 320) == WL_OK);
    CHECK(node_a.is_master == 0 && node_a.master_metric == 250);
    CHECK(memcmp(node_a.master_mac, mac_b, 6) == 0);

    uint8_t ipv6_pkt[48];
    memset(ipv6_pkt, 0x60, sizeof(ipv6_pkt));
    uint8_t data_frame[128];
    size_t df_len = 0;
    CHECK(awdl_encode_data_frame(&node_a, mac_b, ipv6_pkt, sizeof(ipv6_pkt), 7,
                                 data_frame, sizeof(data_frame), &df_len) == WL_OK);

    uint8_t rx_mac[6], rx_ipv6[16];
    const uint8_t *rx_payload = NULL;
    size_t rx_len = 0;
    CHECK(awdl_decode_data_frame(&node_b, data_frame, df_len, rx_mac, rx_ipv6,
                                 &rx_payload, &rx_len) == WL_OK);
    CHECK(memcmp(rx_mac, mac_a, 6) == 0);
    CHECK(memcmp(rx_ipv6, node_a.self_ipv6, 16) == 0);
    CHECK(rx_len == sizeof(ipv6_pkt) && memcmp(rx_payload, ipv6_pkt, sizeof(ipv6_pkt)) == 0);
}

int main(void)
{
    printf("=== Snapintosh Wireless Stack Verification Suite ===\n");
    test_p256_ecdh_and_bt_spec_vectors();
    test_qcc2072_wcl_scan_assoc_key_leave();
    test_qcc2072_pm_twt_ft_ampdu();
    test_bt_smp_p256_pairing_and_security();
    test_ble_airdrop_continuity();
    test_awdl_protocol();
    printf("=== ALL %d TEST SUITES PASSED (%d assertions verified) ===\n",
           g_tests_run, g_checks_passed);
    return 0;
}
