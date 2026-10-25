/* SPDX-License-Identifier: MIT */
/* Implementation of the Snapintosh Wireless Stack:
 *   - QCC2072 Wi-Fi Power Management, WoWLAN, 802.11k/v/r Fast Roaming, A-MPDU
 *   - Bluetooth 5.4 HCI / L2CAP / LE Secure Connections SMP / AirDrop BLE Beacon
 *   - AirDrop Apple Wireless Direct Link (AWDL) Synchronization, Election & Data
 */
#include "wireless-stack.h"
#include <string.h>

/* Little-endian unaligned helpers (safe under UBSan on all architectures). */
static uint16_t rd16_le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void wr32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

/* Deterministic SipHash/ARX PRF mixing primitive for key derivation and SMP
 * confirm/check generation in freestanding environments without OpenSSL. */
static void crypto_prf_mix(const uint8_t *key, size_t key_len,
                           const uint8_t *label, size_t label_len,
                           const uint8_t *ctx, size_t ctx_len,
                           uint8_t *out, size_t out_len)
{
    uint64_t s0 = 0x736f6d6570736575ULL;
    uint64_t s1 = 0x646f72616e646f6dULL;
    uint64_t s2 = 0x6c7967656e657261ULL;
    uint64_t s3 = 0x7465646279746573ULL;

    for (size_t i = 0; i < key_len; i++) {
        s0 ^= ((uint64_t)key[i] << ((i & 7u) * 8u));
        s1 = (s1 << 13) | (s1 >> 51);
        s0 += s1;
        s2 ^= s0;
    }
    for (size_t i = 0; i < label_len; i++) {
        s2 ^= ((uint64_t)label[i] << ((i & 7u) * 8u));
        s3 = (s3 << 17) | (s3 >> 47);
        s2 += s3;
        s0 ^= s2;
    }
    for (size_t i = 0; i < ctx_len; i++) {
        s1 ^= ((uint64_t)ctx[i] << ((i & 7u) * 8u));
        s0 = (s0 << 21) | (s0 >> 43);
        s1 += s0;
        s3 ^= s1;
    }

    for (size_t off = 0; off < out_len; off++) {
        if ((off & 7u) == 0) {
            s0 += s1; s2 += s3;
            s1 = ((s1 << 13) | (s1 >> 51)) ^ s0;
            s3 = ((s3 << 16) | (s3 >> 48)) ^ s2;
            s0 = (s0 << 32) | (s0 >> 32);
            s2 += s1; s0 += s3;
        }
        out[off] = (uint8_t)((s0 ^ s2) >> ((off & 7u) * 8u));
    }
}

/* Constant-time byte comparison to prevent timing side-channels on MACs/tags. */
static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* =========================================================================
 * 1. QCC2072 Wi-Fi Power Management, Fast Roaming & A-MPDU Aggregation
 * ========================================================================= */

int wifi_ctrl_init(struct wifi_qcc2072_ctrl *ctrl, uint16_t mdid, int8_t roam_trigger_dbm)
{
    if (!ctrl || roam_trigger_dbm >= -30 || roam_trigger_dbm <= -100)
        return WL_ERR_PARAM;
    memset(ctrl, 0, sizeof(*ctrl));
    ctrl->pm_state = WIFI_PM_ACTIVE;
    ctrl->mobility_domain = mdid;
    ctrl->roam_trigger_dbm = roam_trigger_dbm;
    ctrl->roam_hysteresis_db = 8;
    ctrl->current_rssi_dbm = -50;
    return WL_OK;
}

int wifi_ctrl_set_pm(struct wifi_qcc2072_ctrl *ctrl, enum wifi_pm_state target, uint32_t wowlan_mask)
{
    if (!ctrl) return WL_ERR_NULL;
    if (target < WIFI_PM_ACTIVE || target > WIFI_PM_WOWLAN_D3HOT)
        return WL_ERR_PARAM;
    if (wowlan_mask & ~WIFI_WOWLAN_WAKE_ALL)
        return WL_ERR_PARAM;
    /* BMPS and WoWLAN D3hot require an active BSS association; IMPS requires
     * the station to be unassociated or idle. */
    if ((target == WIFI_PM_BMPS || target == WIFI_PM_WOWLAN_D3HOT) && !ctrl->associated)
        return WL_ERR_STATE;
    if (target == WIFI_PM_WOWLAN_D3HOT && wowlan_mask == 0)
        return WL_ERR_PARAM;
    ctrl->pm_state = target;
    ctrl->wowlan_mask = (target == WIFI_PM_WOWLAN_D3HOT) ? wowlan_mask : 0;
    return WL_OK;
}

int wifi_ctrl_configure_twt(struct wifi_qcc2072_ctrl *ctrl, uint8_t flow_id,
                            uint32_t wake_duration_us, uint64_t wake_interval_us)
{
    if (!ctrl) return WL_ERR_NULL;
    if (flow_id > 7 || !wake_duration_us || !wake_interval_us ||
        wake_duration_us >= wake_interval_us)
        return WL_ERR_PARAM;
    if (!ctrl->associated) return WL_ERR_STATE;
    ctrl->twt.dialog_token++;
    ctrl->twt.flow_id = flow_id;
    ctrl->twt.enabled = 1;
    ctrl->twt.implicit = 1;
    ctrl->twt.wake_duration_us = wake_duration_us;
    ctrl->twt.wake_interval_us = wake_interval_us;
    return WL_OK;
}

int wifi_ctrl_wake_trigger(struct wifi_qcc2072_ctrl *ctrl, uint32_t wake_reason_bit)
{
    if (!ctrl) return WL_ERR_NULL;
    if (!wake_reason_bit || (wake_reason_bit & (wake_reason_bit - 1)) ||
        (wake_reason_bit & ~WIFI_WOWLAN_WAKE_ALL))
        return WL_ERR_PARAM;
    if (ctrl->pm_state != WIFI_PM_WOWLAN_D3HOT && ctrl->pm_state != WIFI_PM_BMPS)
        return WL_ERR_STATE;
    if (ctrl->pm_state == WIFI_PM_WOWLAN_D3HOT && !(ctrl->wowlan_mask & wake_reason_bit))
        return WL_ERR_STATE;
    ctrl->pm_state = WIFI_PM_ACTIVE;
    ctrl->wake_events++;
    return WL_OK;
}

int wifi_ctrl_validate_dma_ring(struct wifi_qcc2072_ctrl *ctrl, uint64_t ring_pa,
                                uint32_t desc_count, uint32_t desc_stride)
{
    if (!ctrl) return WL_ERR_NULL;
    if (!desc_count || !desc_stride || (desc_stride & 7u) || (ring_pa & 63u))
        return WL_ERR_PARAM;
    uint64_t total_bytes = (uint64_t)desc_count * (uint64_t)desc_stride;
    uint64_t arena_lo = QCC2072_WIFI_DMA_PA;
    uint64_t arena_hi = QCC2072_WIFI_DMA_PA + QCC2072_WIFI_DMA_BYTES;
    if (ring_pa < arena_lo || ring_pa >= arena_hi || total_bytes > arena_hi - ring_pa)
        return WL_ERR_DMA_RANGE;
    ctrl->dma_validated_descriptors += desc_count;
    return WL_OK;
}

int wifi_ctrl_add_roam_candidate(struct wifi_qcc2072_ctrl *ctrl, const uint8_t bssid[6],
                                 uint16_t channel, int8_t rssi_dbm, int8_t snr_db,
                                 uint16_t mdid, uint8_t ft_capable)
{
    if (!ctrl || !bssid || !channel) return WL_ERR_PARAM;
    int slot = -1;
    for (unsigned i = 0; i < WIFI_ROAM_CANDIDATES_MAX; i++) {
        if (ctrl->candidates[i].valid && !memcmp(ctrl->candidates[i].bssid, bssid, 6)) {
            slot = (int)i;
            break;
        }
        if (!ctrl->candidates[i].valid && slot < 0)
            slot = (int)i;
    }
    if (slot < 0) return WL_ERR_BOUNDS;
    struct wifi_roam_candidate *c = &ctrl->candidates[slot];
    memcpy(c->bssid, bssid, 6);
    c->channel = channel;
    c->rssi_dbm = rssi_dbm;
    c->snr_db = snr_db;
    c->mdid = mdid;
    c->ft_capable = ft_capable ? 1u : 0u;
    c->valid = 1;
    return WL_OK;
}

int wifi_ft_derive_keys(struct wifi_ft_keys *keys, const uint8_t msk[32],
                        uint16_t mdid, const uint8_t r0kh_id[16], const uint8_t r1kh_id[6],
                        const uint8_t sta_mac[6], const uint8_t bssid[6],
                        const uint8_t snonce[32], const uint8_t anonce[32])
{
    if (!keys || !msk || !r0kh_id || !r1kh_id || !sta_mac || !bssid || !snonce || !anonce)
        return WL_ERR_NULL;
    memset(keys, 0, sizeof(*keys));
    keys->mdid = mdid;
    memcpy(keys->r0kh_id, r0kh_id, 16);
    memcpy(keys->r1kh_id, r1kh_id, 6);
    memcpy(keys->snonce, snonce, 32);
    memcpy(keys->anonce, anonce, 32);

    /* IEEE 802.11r-2008 8.5.1.5.3: Derive PMK-R0 from MSK, MDID, R0KH-ID, S0KH-ID */
    uint8_t r0_ctx[2 + 16 + 6];
    wr16_le(r0_ctx, mdid);
    memcpy(r0_ctx + 2, r0kh_id, 16);
    memcpy(r0_ctx + 18, sta_mac, 6);
    crypto_prf_mix(msk, 32, (const uint8_t *)"FT-R0", 5, r0_ctx, sizeof(r0_ctx), keys->pmk_r0, 32);

    /* Derive PMK-R1 from PMK-R0, R1KH-ID, S1KH-ID */
    uint8_t r1_ctx[6 + 6];
    memcpy(r1_ctx, r1kh_id, 6);
    memcpy(r1_ctx + 6, sta_mac, 6);
    crypto_prf_mix(keys->pmk_r0, 32, (const uint8_t *)"FT-R1", 5, r1_ctx, sizeof(r1_ctx), keys->pmk_r1, 32);

    /* Derive PTK (48 bytes: KCK || KEK || TK) from PMK-R1, SNonce, ANonce, BSSID, STA */
    uint8_t ptk_ctx[32 + 32 + 6 + 6];
    memcpy(ptk_ctx, snonce, 32);
    memcpy(ptk_ctx + 32, anonce, 32);
    memcpy(ptk_ctx + 64, bssid, 6);
    memcpy(ptk_ctx + 70, sta_mac, 6);
    crypto_prf_mix(keys->pmk_r1, 32, (const uint8_t *)"FT-PTK", 6, ptk_ctx, sizeof(ptk_ctx), keys->ptk, 48);
    keys->valid = 1;
    return WL_OK;
}

int wifi_ctrl_evaluate_roam(struct wifi_qcc2072_ctrl *ctrl, const uint8_t msk[32],
                            const uint8_t sta_mac[6], uint8_t out_target_bssid[6])
{
    if (!ctrl || !msk || !sta_mac || !out_target_bssid) return WL_ERR_NULL;
    if (!ctrl->associated) return WL_ERR_STATE;
    if (ctrl->current_rssi_dbm > ctrl->roam_trigger_dbm)
        return WL_ERR_NOT_FOUND; /* Signal still strong; stay on current BSS */

    int best_idx = -1;
    int16_t best_score = (int16_t)ctrl->current_rssi_dbm + (int16_t)ctrl->roam_hysteresis_db;

    for (unsigned i = 0; i < WIFI_ROAM_CANDIDATES_MAX; i++) {
        const struct wifi_roam_candidate *c = &ctrl->candidates[i];
        if (!c->valid || !memcmp(c->bssid, ctrl->current_bssid, 6))
            continue;
        if (!c->ft_capable || c->mdid != ctrl->mobility_domain)
            continue;
        int16_t score = (int16_t)c->rssi_dbm + (c->snr_db > 20 ? 4 : 0);
        if (score >= best_score) {
            best_score = score;
            best_idx = (int)i;
        }
    }
    if (best_idx < 0) return WL_ERR_NOT_FOUND;

    const struct wifi_roam_candidate *target = &ctrl->candidates[best_idx];
    uint8_t r0kh[16] = "SNAP-QCC2072-R0";
    uint8_t snonce[32], anonce[32];
    memset(snonce, 0x5a, sizeof(snonce));
    memset(anonce, 0xa5, sizeof(anonce));
    snonce[0] = (uint8_t)(ctrl->roam_count + 1);
    anonce[0] = (uint8_t)target->channel;

    int err = wifi_ft_derive_keys(&ctrl->ft_keys, msk, ctrl->mobility_domain,
                                  r0kh, target->bssid, sta_mac, target->bssid,
                                  snonce, anonce);
    if (err != WL_OK) return err;

    memcpy(ctrl->current_bssid, target->bssid, 6);
    memcpy(out_target_bssid, target->bssid, 6);
    ctrl->current_channel = target->channel;
    ctrl->current_rssi_dbm = target->rssi_dbm;
    ctrl->roam_count++;
    return WL_OK;
}

int wifi_ampdu_setup_tid(struct wifi_qcc2072_ctrl *ctrl, uint8_t tid, uint16_t ssn, uint16_t win_size)
{
    if (!ctrl) return WL_ERR_NULL;
    if (tid >= 8 || !win_size || win_size > WIFI_AMPDU_WINDOW_MAX || (ssn & ~0xfffu))
        return WL_ERR_PARAM;
    struct wifi_ampdu_tid *t = &ctrl->tid[tid];
    memset(t, 0, sizeof(*t));
    t->ssn = ssn;
    t->window_size = win_size;
    return WL_OK;
}

int wifi_ampdu_rx_Update(struct wifi_qcc2072_ctrl *ctrl, uint8_t tid, uint16_t seq_num,
                         uint32_t *flushed_out)
{
    if (!ctrl || !flushed_out) return WL_ERR_NULL;
    *flushed_out = 0;
    if (tid >= 8 || (seq_num & ~0xfffu)) return WL_ERR_PARAM;
    struct wifi_ampdu_tid *t = &ctrl->tid[tid];
    if (!t->window_size) return WL_ERR_STATE;

    uint16_t delta = (uint16_t)((seq_num - t->ssn) & 0xfffu);
    if (delta >= 2048u) {
        /* Behind the current window: duplicate frame */
        t->rx_duplicates++;
        return WL_OK;
    }
    if (delta >= t->window_size) {
        /* Advance window so seq_num sits at the top edge */
        uint16_t shift = (uint16_t)(delta - t->window_size + 1u);
        uint32_t flushed = 0;
        for (uint16_t s = 0; s < shift && s < t->window_size; s++) {
            if (t->bitmap[0] & 1ULL) flushed++;
            for (unsigned w = 0; w < WIFI_AMPDU_BITMAP_WORDS - 1; w++)
                t->bitmap[w] = (t->bitmap[w] >> 1) | (t->bitmap[w + 1] << 63);
            t->bitmap[WIFI_AMPDU_BITMAP_WORDS - 1] >>= 1;
        }
        if (shift >= t->window_size)
            memset(t->bitmap, 0, sizeof(t->bitmap));
        t->ssn = (uint16_t)((t->ssn + shift) & 0xfffu);
        delta = (uint16_t)((seq_num - t->ssn) & 0xfffu);
        *flushed_out += flushed;
    }

    unsigned word = delta / 64u;
    uint64_t bit = 1ULL << (delta % 64u);
    if (t->bitmap[word] & bit) {
        t->rx_duplicates++;
        return WL_OK;
    }
    t->bitmap[word] |= bit;
    if (delta == 0)
        t->rx_in_order++;
    else
        t->rx_reordered++;

    /* Slide contiguous in-order prefix from bit 0 */
    while (t->bitmap[0] & 1ULL) {
        for (unsigned w = 0; w < WIFI_AMPDU_BITMAP_WORDS - 1; w++)
            t->bitmap[w] = (t->bitmap[w] >> 1) | (t->bitmap[w + 1] << 63);
        t->bitmap[WIFI_AMPDU_BITMAP_WORDS - 1] >>= 1;
        t->ssn = (uint16_t)((t->ssn + 1u) & 0xfffu);
        (*flushed_out)++;
    }
    return WL_OK;
}

/* =========================================================================
 * 2. Bluetooth 5.4 Controller & Host Stack (HCI / L2CAP / SMP / AirDrop BLE)
 * ========================================================================= */

int bt_stack_init(struct bt_stack_state *bt, const uint8_t bdaddr[6])
{
    if (!bt || !bdaddr) return WL_ERR_NULL;
    memset(bt, 0, sizeof(*bt));
    memcpy(bt->local_bdaddr, bdaddr, 6);
    bt->ctrl_state = BT_CTRL_OFF;
    return WL_OK;
}

int bt_hci_process_command(struct bt_stack_state *bt, const uint8_t *cmd_buf, size_t cmd_len,
                           uint8_t *evt_out, size_t evt_cap, size_t *evt_len_out)
{
    if (!bt || !cmd_buf || !evt_out || !evt_len_out) return WL_ERR_NULL;
    *evt_len_out = 0;
    /* H4 Command packet: [0x01][opcode_lo][opcode_hi][param_len][params...] */
    if (cmd_len < 4 || cmd_buf[0] != BT_HCI_PKT_CMD)
        return WL_ERR_FORMAT;
    uint16_t opcode = rd16_le(cmd_buf + 1);
    uint8_t plen = cmd_buf[3];
    if (cmd_len != (size_t)4u + plen)
        return WL_ERR_BOUNDS;
    if (evt_cap < 15)
        return WL_ERR_BOUNDS;

    /* Default Command Complete Event (0x0e): [0x04][0x0e][len][num_cmd=1][op_lo][op_hi][status=0] */
    evt_out[0] = BT_HCI_PKT_EVT;
    evt_out[1] = 0x0eu; /* Command Complete */
    evt_out[2] = 4u;
    evt_out[3] = 1u;
    wr16_le(evt_out + 4, opcode);
    evt_out[6] = 0x00u; /* Status: Success */
    *evt_len_out = 7u;

    switch (opcode) {
    case BT_HCI_OP_RESET:
        bt->ctrl_state = BT_CTRL_READY;
        bt->ext_adv_enabled = 0;
        bt->ext_scan_enabled = 0;
        bt->active_conn_handle = 0;
        memset(&bt->smp, 0, sizeof(bt->smp));
        break;
    case BT_HCI_OP_READ_LOCAL_VER:
        if (bt->ctrl_state == BT_CTRL_OFF) return WL_ERR_STATE;
        evt_out[2] = 12u;
        evt_out[7] = 0x0du; /* HCI Version: Bluetooth Core 5.4 (0x0d) */
        wr16_le(evt_out + 8, 0x0001u);
        evt_out[10] = 0x0du; /* LMP Version 5.4 */
        wr16_le(evt_out + 11, 0x001du); /* Qualcomm Company ID */
        wr16_le(evt_out + 13, 0x2072u); /* QCC2072 Subversion */
        *evt_len_out = 15u;
        break;
    case BT_HCI_OP_LE_SET_EXT_ADV:
        if (bt->ctrl_state == BT_CTRL_OFF || plen < 1) return WL_ERR_STATE;
        bt->ext_adv_enabled = cmd_buf[4] ? 1u : 0u;
        if (bt->ext_adv_enabled && bt->ctrl_state == BT_CTRL_READY)
            bt->ctrl_state = BT_CTRL_ADVERTISING;
        break;
    case BT_HCI_OP_LE_SET_EXT_SCAN:
        if (bt->ctrl_state == BT_CTRL_OFF || plen < 2) return WL_ERR_STATE;
        bt->ext_scan_enabled = cmd_buf[4] ? 1u : 0u;
        break;
    case BT_HCI_OP_LE_CREATE_CONN:
        if (bt->ctrl_state == BT_CTRL_OFF || plen < 6) return WL_ERR_STATE;
        bt->ctrl_state = BT_CTRL_CONNECTED;
        bt->active_conn_handle = 0x0040u;
        bt->smp.state = BT_SMP_IDLE;
        break;
    default:
        evt_out[6] = 0x01u; /* Unknown HCI Command */
        return WL_ERR_PARAM;
    }

    bt->hci_cmds_processed++;
    return WL_OK;
}

void bt_smp_compute_confirm(const uint8_t rand16[16], const uint8_t pk_x[32],
                            const uint8_t preq[7], const uint8_t prsp[7],
                            uint8_t out_confirm[16])
{
    uint8_t ctx[32 + 7 + 7];
    memcpy(ctx, pk_x, 32);
    memcpy(ctx + 32, preq, 7);
    memcpy(ctx + 39, prsp, 7);
    crypto_prf_mix(rand16, 16, (const uint8_t *)"SMP-F4", 6, ctx, sizeof(ctx), out_confirm, 16);
}

void bt_smp_compute_dhkey_check(const uint8_t dhkey[32], const uint8_t rand_local[16],
                                const uint8_t rand_peer[16], const uint8_t preq[7],
                                const uint8_t prsp[7], uint8_t out_check[16])
{
    uint8_t ctx[16 + 16 + 7 + 7];
    memcpy(ctx, rand_local, 16);
    memcpy(ctx + 16, rand_peer, 16);
    memcpy(ctx + 32, preq, 7);
    memcpy(ctx + 39, prsp, 7);
    crypto_prf_mix(dhkey, 32, (const uint8_t *)"SMP-F6", 6, ctx, sizeof(ctx), out_check, 16);
}

int bt_l2cap_process_acl(struct bt_stack_state *bt, uint16_t conn_handle,
                         const uint8_t *l2cap_frame, size_t frame_len,
                         uint8_t *rsp_out, size_t rsp_cap, size_t *rsp_len_out)
{
    if (!bt || !l2cap_frame || !rsp_out || !rsp_len_out) return WL_ERR_NULL;
    *rsp_len_out = 0;
    if (bt->ctrl_state != BT_CTRL_CONNECTED || conn_handle != bt->active_conn_handle)
        return WL_ERR_STATE;
    if (frame_len < 4) return WL_ERR_FORMAT;

    uint16_t payload_len = rd16_le(l2cap_frame);
    uint16_t cid = rd16_le(l2cap_frame + 2);
    if (frame_len != (size_t)4u + payload_len || payload_len == 0)
        return WL_ERR_BOUNDS;

    const uint8_t *pdu = l2cap_frame + 4;
    bt->acl_frames_routed++;

    if (cid != BT_L2CAP_CID_SMP) {
        /* Echo signaling/ATT acknowledgment header cleanly */
        if (rsp_cap < 6) return WL_ERR_BOUNDS;
        wr16_le(rsp_out, 2u);
        wr16_le(rsp_out + 2, cid);
        rsp_out[4] = pdu[0];
        rsp_out[5] = 0x00u;
        *rsp_len_out = 6u;
        return WL_OK;
    }

    uint8_t smp_cmd = pdu[0];
    struct bt_smp_session *s = &bt->smp;

    switch (smp_cmd) {
    case BT_SMP_CMD_PAIRING_REQ:
        if (payload_len != 7 || rsp_cap < 11) return WL_ERR_FORMAT;
        /* Require Secure Connections (AuthReq bit 3 = 0x08) and key size >= 16 */
        if (!(pdu[3] & 0x08u) || pdu[4] != 16u) {
            s->state = BT_SMP_FAILED;
            return WL_ERR_HANDSHAKE;
        }
        memcpy(s->preq, pdu, 7);
        s->prsp[0] = BT_SMP_CMD_PAIRING_RSP;
        s->prsp[1] = 0x03u; /* NoInputNoOutput */
        s->prsp[2] = 0x00u; /* OOB not present */
        s->prsp[3] = 0x0du; /* Bonding + MITM + Secure Connections */
        s->prsp[4] = 16u;   /* Max encryption key size 16 */
        s->prsp[5] = 0x07u; /* Initiator key dist */
        s->prsp[6] = 0x07u; /* Responder key dist */
        s->state = BT_SMP_PAIRING_REQ_RCV;
        wr16_le(rsp_out, 7u);
        wr16_le(rsp_out + 2, BT_L2CAP_CID_SMP);
        memcpy(rsp_out + 4, s->prsp, 7);
        *rsp_len_out = 11u;
        return WL_OK;

    case BT_SMP_CMD_PUBLIC_KEY:
        if (s->state != BT_SMP_PAIRING_REQ_RCV || payload_len != 65 || rsp_cap < 69)
            return WL_ERR_HANDSHAKE;
        memcpy(s->peer_pk, pdu + 1, 64);
        /* Reject invalid all-zero peer public key */
        {
            uint8_t zero[64] = {0};
            if (ct_memeq(s->peer_pk, zero, 64)) {
                s->state = BT_SMP_FAILED;
                return WL_ERR_CRYPTO;
            }
        }
        crypto_prf_mix(bt->local_bdaddr, 6, (const uint8_t *)"SMP-PK", 6, s->preq, 7, s->local_pk, 64);
        crypto_prf_mix(bt->local_bdaddr, 6, (const uint8_t *)"SMP-RN", 6, s->local_pk, 64, s->local_rand, 16);
        crypto_prf_mix(s->local_pk, 64, (const uint8_t *)"ECDH", 4, s->peer_pk, 64, s->dhkey, 32);
        s->state = BT_SMP_PUBLIC_KEY_EXCH;

        wr16_le(rsp_out, 65u);
        wr16_le(rsp_out + 2, BT_L2CAP_CID_SMP);
        rsp_out[4] = BT_SMP_CMD_PUBLIC_KEY;
        memcpy(rsp_out + 5, s->local_pk, 64);
        *rsp_len_out = 69u;
        return WL_OK;

    case BT_SMP_CMD_PAIRING_CONFIRM:
        if (s->state != BT_SMP_PUBLIC_KEY_EXCH || payload_len != 17 || rsp_cap < 21)
            return WL_ERR_HANDSHAKE;
        memcpy(s->peer_confirm, pdu + 1, 16);
        s->state = BT_SMP_CONFIRM_EXCH;

        wr16_le(rsp_out, 17u);
        wr16_le(rsp_out + 2, BT_L2CAP_CID_SMP);
        rsp_out[4] = BT_SMP_CMD_PAIRING_CONFIRM;
        bt_smp_compute_confirm(s->local_rand, s->local_pk, s->preq, s->prsp, rsp_out + 5);
        *rsp_len_out = 21u;
        return WL_OK;

    case BT_SMP_CMD_PAIRING_RANDOM:
        if (s->state != BT_SMP_CONFIRM_EXCH || payload_len != 17 || rsp_cap < 21)
            return WL_ERR_HANDSHAKE;
        memcpy(s->peer_rand, pdu + 1, 16);
        /* Verify peer's earlier commitment against its revealed random */
        {
            uint8_t expected_confirm[16];
            bt_smp_compute_confirm(s->peer_rand, s->peer_pk, s->preq, s->prsp, expected_confirm);
            if (!ct_memeq(expected_confirm, s->peer_confirm, 16)) {
                s->state = BT_SMP_FAILED;
                return WL_ERR_CRYPTO;
            }
        }
        s->state = BT_SMP_RANDOM_EXCH;
        wr16_le(rsp_out, 17u);
        wr16_le(rsp_out + 2, BT_L2CAP_CID_SMP);
        rsp_out[4] = BT_SMP_CMD_PAIRING_RANDOM;
        memcpy(rsp_out + 5, s->local_rand, 16);
        *rsp_len_out = 21u;
        return WL_OK;

    case BT_SMP_CMD_DHKEY_CHECK:
        if (s->state != BT_SMP_RANDOM_EXCH || payload_len != 17 || rsp_cap < 21)
            return WL_ERR_HANDSHAKE;
        {
            uint8_t expected_ea[16];
            bt_smp_compute_dhkey_check(s->dhkey, s->peer_rand, s->local_rand,
                                       s->preq, s->prsp, expected_ea);
            if (!ct_memeq(expected_ea, pdu + 1, 16)) {
                s->state = BT_SMP_FAILED;
                return WL_ERR_CRYPTO;
            }
        }
        /* Derive Long Term Key (LTK) */
        crypto_prf_mix(s->dhkey, 32, (const uint8_t *)"SMP-F5-LTK", 10,
                       s->peer_rand, 16, s->ltk, 16);
        s->state = BT_SMP_PAIRED;
        bt->smp_handshakes_completed++;

        wr16_le(rsp_out, 17u);
        wr16_le(rsp_out + 2, BT_L2CAP_CID_SMP);
        rsp_out[4] = BT_SMP_CMD_DHKEY_CHECK;
        bt_smp_compute_dhkey_check(s->dhkey, s->local_rand, s->peer_rand,
                                   s->preq, s->prsp, rsp_out + 5);
        *rsp_len_out = 21u;
        return WL_OK;

    default:
        s->state = BT_SMP_FAILED;
        return WL_ERR_HANDSHAKE;
    }
}

int bt_airdrop_encode_ble_adv(const struct bt_airdrop_beacon *beacon,
                              uint8_t *out_adv, size_t cap, size_t *out_len)
{
    if (!beacon || !out_adv || !out_len) return WL_ERR_NULL;
    *out_len = 0;
    /* Apple Continuity AirDrop BLE AD structure:
     * [len=22][type=0xff Manufacturer][0x4c 0x00 Apple][0x05 AirDrop][len=18]
     * [zeros 8B][tx_pwr][ch][4x uint16 hashes = 8B] = 23 bytes total. */
    if (cap < 23) return WL_ERR_BOUNDS;
    out_adv[0] = 22u;
    out_adv[1] = 0xffu;
    wr16_le(out_adv + 2, BT_APPLE_COMPANY_ID);
    out_adv[4] = BT_CONTINUITY_TYPE_AIRDROP;
    out_adv[5] = 17u;
    memset(out_adv + 6, 0, 7);
    out_adv[13] = (uint8_t)beacon->tx_power_dbm;
    out_adv[14] = beacon->awdl_Trigger_channel;
    for (unsigned i = 0; i < BT_AIRDROP_HASH_COUNT; i++)
        wr16_le(out_adv + 15 + i * 2, beacon->contact_hashes[i]);
    *out_len = 23u;
    return WL_OK;
}

int bt_airdrop_decode_ble_adv(struct bt_stack_state *bt, const uint8_t *adv, size_t len,
                              struct bt_airdrop_beacon *out_beacon)
{
    if (!bt || !adv || !out_beacon) return WL_ERR_NULL;
    if (len < 23 || adv[0] != 22u || adv[1] != 0xffu)
        return WL_ERR_FORMAT;
    if (rd16_le(adv + 2) != BT_APPLE_COMPANY_ID ||
        adv[4] != BT_CONTINUITY_TYPE_AIRDROP || adv[5] != 17u)
        return WL_ERR_FORMAT;
    memset(out_beacon, 0, sizeof(*out_beacon));
    out_beacon->tx_power_dbm = (int8_t)adv[13];
    out_beacon->awdl_Trigger_channel = adv[14];
    for (unsigned i = 0; i < BT_AIRDROP_HASH_COUNT; i++)
        out_beacon->contact_hashes[i] = rd16_le(adv + 15 + i * 2);
    bt->airdrop_beacons_decoded++;
    return WL_OK;
}

/* =========================================================================
 * 3. AirDrop & Apple Wireless Direct Link (AWDL) Protocol Stack
 * ========================================================================= */

static void derive_ipv6_eui64(const uint8_t mac[6], uint8_t ipv6[16])
{
    memset(ipv6, 0, 16);
    ipv6[0] = 0xfeu;
    ipv6[1] = 0x80u;
    ipv6[8]  = (uint8_t)(mac[0] ^ 0x02u);
    ipv6[9]  = mac[1];
    ipv6[10] = mac[2];
    ipv6[11] = 0xffu;
    ipv6[12] = 0xfeu;
    ipv6[13] = mac[3];
    ipv6[14] = mac[4];
    ipv6[15] = mac[5];
}

int awdl_init(struct awdl_state *awdl, const uint8_t self_mac[6], uint32_t self_metric)
{
    if (!awdl || !self_mac || !self_metric) return WL_ERR_PARAM;
    memset(awdl, 0, sizeof(*awdl));
    memcpy(awdl->self_mac, self_mac, 6);
    memcpy(awdl->top_master, self_mac, 6);
    awdl->self_metric = self_metric;
    awdl->top_master_metric = self_metric;
    awdl->distance_to_master = 0;
    awdl->max_tree_depth = 3;
    awdl->aw_period_tu = 16;
    awdl->eaw_slots = 4;

    /* Standard dual-band social + high-throughput 5 GHz channel sequence:
     * interleaves social channel 6 (2.4G), 44 (5G low), and 149 (5G high). */
    static const uint8_t default_seq[AWDL_CHAN_SEQ_LEN] = {
        6, 44, 44, 149, 149, 44, 44, 6,
        149, 149, 149, 149, 44, 44, 149, 149
    };
    memcpy(awdl->channel_seq, default_seq, AWDL_CHAN_SEQ_LEN);
    return WL_OK;
}

uint16_t awdl_current_channel(const struct awdl_state *awdl, uint64_t now_tu)
{
    if (!awdl || !awdl->aw_period_tu) return AWDL_SOCIAL_CH_5G_HIGH;
    uint64_t slot = (now_tu / awdl->aw_period_tu) % AWDL_CHAN_SEQ_LEN;
    return awdl->channel_seq[slot];
}

int awdl_encode_action_frame(struct awdl_state *awdl, uint8_t subtype, uint32_t phy_tx_us,
                             uint8_t *buf, size_t cap, size_t *out_len)
{
    if (!awdl || !buf || !out_len) return WL_ERR_NULL;
    *out_len = 0;
    if (subtype != AWDL_SUBTYPE_PSF && subtype != AWDL_SUBTYPE_MIF)
        return WL_ERR_PARAM;
    /* 16B hdr + Sync TLV (11B) + Election TLV (21B) + ChanSeq TLV (21B) + Service TLV (11B) = 80B */
    if (cap < 80) return WL_ERR_BOUNDS;

    struct awdl_action_hdr hdr = {
        .category = 0x7fu,
        .oui = {AWDL_OUI_0, AWDL_OUI_1, AWDL_OUI_2},
        .type = AWDL_VENDOR_TYPE,
        .version = 0x10u,
        .subtype = subtype,
        .reserved = 0u,
        .phy_tx_time = phy_tx_us,
        .target_tx_time = phy_tx_us + 200u,
    };
    memcpy(buf, &hdr, sizeof(hdr));
    size_t pos = sizeof(hdr);

    /* 1. Synchronization Parameters TLV (Type 0x04, Len 8) */
    buf[pos] = AWDL_TLV_SYNC_PARAMS;
    wr16_le(buf + pos + 1, 8u);
    buf[pos + 3] = awdl->channel_seq[awdl->current_slot % AWDL_CHAN_SEQ_LEN];
    wr16_le(buf + pos + 4, awdl->tx_seq_num);
    wr16_le(buf + pos + 6, awdl->aw_period_tu);
    wr16_le(buf + pos + 8, awdl->eaw_slots);
    buf[pos + 10] = 0u;
    pos += 11u;

    /* 2. Election Parameters TLV (Type 0x05, Len 18) */
    buf[pos] = AWDL_TLV_ELECTION_PARAMS;
    wr16_le(buf + pos + 1, 18u);
    buf[pos + 3] = awdl->distance_to_master;
    buf[pos + 4] = awdl->max_tree_depth;
    memcpy(buf + pos + 5, awdl->top_master, 6);
    wr32_le(buf + pos + 11, awdl->top_master_metric);
    wr32_le(buf + pos + 15, awdl->self_metric);
    buf[pos + 19] = 0u;
    buf[pos + 20] = 0u;
    pos += 21u;

    /* 3. Channel Sequence TLV (Type 0x06, Len 18) */
    buf[pos] = AWDL_TLV_CHAN_SEQ;
    wr16_le(buf + pos + 1, 18u);
    buf[pos + 3] = AWDL_CHAN_SEQ_LEN - 1u;
    buf[pos + 4] = 0u; /* step_count */
    memcpy(buf + pos + 5, awdl->channel_seq, AWDL_CHAN_SEQ_LEN);
    pos += 21u;

    /* 4. AirDrop Service Parameters TLV (Type 0x14, Len 8) */
    buf[pos] = AWDL_TLV_SERVICE_PARAMS;
    wr16_le(buf + pos + 1, 8u);
    memcpy(buf + pos + 3, "_airdrop", 8);
    pos += 11u;

    *out_len = pos;
    if (subtype == AWDL_SUBTYPE_PSF)
        awdl->psf_sent++;
    else
        awdl->mif_sent++;
    return WL_OK;
}

void awdl_elect_master(struct awdl_state *awdl)
{
    if (!awdl) return;
    memcpy(awdl->top_master, awdl->self_mac, 6);
    awdl->top_master_metric = awdl->self_metric;
    awdl->distance_to_master = 0;

    for (unsigned i = 0; i < AWDL_MAX_PEERS; i++) {
        const struct awdl_peer *p = &awdl->peers[i];
        if (!p->in_use) continue;
        if (p->distance_to_master >= awdl->max_tree_depth)
            continue;
        /* Higher metric wins; tie-breaker is lexicographically larger MAC */
        int better = (p->master_metric > awdl->top_master_metric) ||
                     (p->master_metric == awdl->top_master_metric &&
                      memcmp(p->top_master, awdl->top_master, 6) > 0);
        if (better) {
            memcpy(awdl->top_master, p->top_master, 6);
            awdl->top_master_metric = p->master_metric;
            awdl->distance_to_master = (uint8_t)(p->distance_to_master + 1u);
        }
    }
}

int awdl_parse_action_frame(struct awdl_state *awdl, const uint8_t peer_mac[6],
                            const uint8_t *buf, size_t len, uint32_t rx_timestamp_us)
{
    if (!awdl || !peer_mac || !buf) return WL_ERR_NULL;
    if (len < sizeof(struct awdl_action_hdr)) return WL_ERR_FORMAT;

    struct awdl_action_hdr hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    if (hdr.category != 0x7fu || hdr.oui[0] != AWDL_OUI_0 ||
        hdr.oui[1] != AWDL_OUI_1 || hdr.oui[2] != AWDL_OUI_2 ||
        hdr.type != AWDL_VENDOR_TYPE || hdr.version != 0x10u ||
        (hdr.subtype != AWDL_SUBTYPE_PSF && hdr.subtype != AWDL_SUBTYPE_MIF))
        return WL_ERR_FORMAT;

    /* Parse TLVs with strict bounds validation before mutating peer state */
    size_t pos = sizeof(hdr);
    int has_election = 0;
    uint8_t dist = 0;
    uint8_t top_master[6] = {0};
    uint32_t master_metric = 0, self_metric = 0;
    uint8_t airdrop_capable = 0;
    uint8_t chan_seq[AWDL_CHAN_SEQ_LEN];
    int has_chan_seq = 0;

    while (pos < len) {
        if (len - pos < 3) return WL_ERR_BOUNDS;
        uint8_t tlv_type = buf[pos];
        uint16_t tlv_len = rd16_le(buf + pos + 1);
        pos += 3u;
        if (tlv_len > len - pos) return WL_ERR_BOUNDS;

        const uint8_t *v = buf + pos;
        if (tlv_type == AWDL_TLV_ELECTION_PARAMS) {
            if (tlv_len < 16) return WL_ERR_FORMAT;
            dist = v[0];
            memcpy(top_master, v + 2, 6);
            master_metric = rd32_le(v + 8);
            self_metric = rd32_le(v + 12);
            has_election = 1;
        } else if (tlv_type == AWDL_TLV_CHAN_SEQ) {
            if (tlv_len < 2 + AWDL_CHAN_SEQ_LEN) return WL_ERR_FORMAT;
            memcpy(chan_seq, v + 2, AWDL_CHAN_SEQ_LEN);
            has_chan_seq = 1;
        } else if (tlv_type == AWDL_TLV_SERVICE_PARAMS) {
            if (tlv_len >= 8 && !memcmp(v, "_airdrop", 8))
                airdrop_capable = 1;
        }
        pos += tlv_len;
    }

    if (!has_election) return WL_ERR_FORMAT;

    int slot = -1;
    for (unsigned i = 0; i < AWDL_MAX_PEERS; i++) {
        if (awdl->peers[i].in_use && !memcmp(awdl->peers[i].mac, peer_mac, 6)) {
            slot = (int)i;
            break;
        }
        if (!awdl->peers[i].in_use && slot < 0)
            slot = (int)i;
    }
    if (slot < 0) return WL_ERR_BOUNDS;

    struct awdl_peer *p = &awdl->peers[slot];
    memcpy(p->mac, peer_mac, 6);
    p->in_use = 1;
    p->airdrop_capable = airdrop_capable;
    p->distance_to_master = dist;
    memcpy(p->top_master, top_master, 6);
    p->master_metric = master_metric;
    p->self_metric = self_metric;
    p->clock_drift_us = (int32_t)(rx_timestamp_us - hdr.phy_tx_time);
    p->last_seen_tu = rx_timestamp_us / 1024u;
    derive_ipv6_eui64(peer_mac, p->ipv6_link_local);

    awdl->frames_received++;
    awdl_elect_master(awdl);
    if (has_chan_seq && memcmp(awdl->top_master, awdl->self_mac, 6) != 0)
        memcpy(awdl->channel_seq, chan_seq, AWDL_CHAN_SEQ_LEN);

    return WL_OK;
}

int awdl_encapsulate_data(struct awdl_state *awdl, const uint8_t dst_mac[6],
                          const uint8_t *ipv6_payload, size_t payload_len,
                          uint8_t *out_frame, size_t out_cap, size_t *out_len)
{
    if (!awdl || !dst_mac || !ipv6_payload || !out_frame || !out_len)
        return WL_ERR_NULL;
    *out_len = 0;
    if (!payload_len || payload_len > 1500u) return WL_ERR_PARAM;
    /* 14B Ethernet-II / AWDL bridge header + 8B AWDL Data Header + payload */
    if (out_cap < 22u + payload_len) return WL_ERR_BOUNDS;

    memcpy(out_frame, dst_mac, 6);
    memcpy(out_frame + 6, awdl->self_mac, 6);
    wr16_le(out_frame + 12, AWDL_ETHERTYPE);
    /* AWDL 8-byte data header: [0x04][0x00][seq_lo][seq_hi][0x00][0x00][ethertype_ipv6] */
    out_frame[14] = 0x04u;
    out_frame[15] = 0x00u;
    wr16_le(out_frame + 16, awdl->tx_seq_num++);
    wr16_le(out_frame + 18, 0u);
    wr16_le(out_frame + 20, IPV6_ETHERTYPE);
    memcpy(out_frame + 22, ipv6_payload, payload_len);

    *out_len = 22u + payload_len;
    awdl->data_bytes_transferred += payload_len;
    return WL_OK;
}

int awdl_decapsulate_data(struct awdl_state *awdl, const uint8_t *frame, size_t frame_len,
                          uint8_t src_mac_out[6], const uint8_t **ipv6_payload_out,
                          size_t *payload_len_out)
{
    if (!awdl || !frame || !src_mac_out || !ipv6_payload_out || !payload_len_out)
        return WL_ERR_NULL;
    if (frame_len <= 22u) return WL_ERR_FORMAT;
    if (rd16_le(frame + 12) != AWDL_ETHERTYPE || frame[14] != 0x04u ||
        rd16_le(frame + 20) != IPV6_ETHERTYPE)
        return WL_ERR_FORMAT;

    memcpy(src_mac_out, frame + 6, 6);
    *ipv6_payload_out = frame + 22;
    *payload_len_out = frame_len - 22u;
    awdl->data_bytes_transferred += *payload_len_out;
    return WL_OK;
}
