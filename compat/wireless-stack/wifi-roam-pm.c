/* SPDX-License-Identifier: MIT */
/*
 * QCC2072 Power Management, 802.11ax TWT, 802.11r FT Roaming & A-MPDU Aggregation
 *
 * Included in order by compat/wireless-stack.c; not compiled standalone.
 */

int wifi_ctrl_init(struct wifi_qcc2072_ctrl *ctrl, const uint8_t sta_mac[6])
{
    if (!ctrl || !sta_mac) return WL_ERR_NULL;
    memset(ctrl, 0, sizeof(*ctrl));
    ctrl->magic = WIFI_QCC2072_MAGIC;
    ctrl->pm_state = WIFI_PM_ACTIVE;
    memcpy(ctrl->sta_mac, sta_mac, 6);
    ctrl->dtim_period = 1;
    ctrl->listen_interval_beacons = 1;
    ctrl->current_channel_mhz = 5220;
    ctrl->current_rssi_dbm = -48;
    ctrl->roam_trigger_rssi_dbm = -72;
    ctrl->inactivity_timeout_ms = 50;
    ctrl->stage2_bar_gpa = QCC2072_WIFI_BAR_GPA;
    ctrl->stage2_dma_gpa = QCC2072_WIFI_DMA_GPA;

    ctrl->tx_agg.tid = 5;
    ctrl->tx_agg.window_size = WIFI_AMPDU_MAX_SUBFRAMES;
    memcpy(ctrl->ft.sta_mac, sta_mac, 6);

    ctrl->session_generation = 1ULL;
    ctrl->owner_cookie = 0x51433230323641ULL;
    ctrl->now_ms = 100ULL;

    struct qcc2072_wmi_config wmi_cfg = {
        ctrl, wifi_wmi_validate_owner, wifi_wmi_admit_datapath
    };
    if (qcc2072_wmi_init(&ctrl->wmi, &wmi_cfg, ctrl->session_generation,
                         ctrl->owner_cookie, ctrl->now_ms, 60000U) != 0)
        return WL_ERR_INVALID;

    ctrl->assoc_mgmt_buf.cpu = ctrl->assoc_mgmt_arena;
    ctrl->assoc_mgmt_buf.capacity = sizeof(ctrl->assoc_mgmt_arena);
    ctrl->assoc_mgmt_buf.iova = (uint32_t)QCC2072_WIFI_DMA_IOVA;
    ctrl->assoc_mgmt_buf.physical = QCC2072_WIFI_DMA_GPA;
    struct qcc2072_assoc_hooks hooks = {
        ctrl, ctrl->assoc_mgmt_buf, wifi_assoc_dma_sync, wifi_assoc_reo_queue, NULL
    };
    if (qcc2072_assoc_init(&ctrl->assoc, &hooks) != 0)
        return WL_ERR_INVALID;

    static const struct snap_station_ops st_ops = {
        wifi_station_submit_cb,
        wifi_station_cancel_cb,
        wifi_station_stop_cb,
        wifi_station_event_cb,
        wifi_station_control_cb
    };
    snap_station_init(&ctrl->station, &st_ops, ctrl);
    return WL_OK;
}

int wifi_ctrl_validate_stage2_window(const struct wifi_qcc2072_ctrl *ctrl,
                                     uint64_t ring_iova, size_t ring_bytes)
{
    if (!ctrl || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    if (ring_bytes == 0 || ring_bytes > QCC2072_WIFI_DMA_BYTES) return WL_ERR_BOUNDS;
    if (ring_iova < QCC2072_WIFI_DMA_IOVA) return WL_ERR_BOUNDS;
    uint64_t offset = ring_iova - QCC2072_WIFI_DMA_IOVA;
    if (offset > QCC2072_WIFI_DMA_BYTES - ring_bytes) return WL_ERR_BOUNDS;
    uint64_t gpa = ctrl->stage2_dma_gpa + offset;
    if (gpa < QCC2072_WIFI_DMA_GPA ||
        gpa + ring_bytes > QCC2072_WIFI_DMA_GPA + QCC2072_WIFI_DMA_BYTES)
        return WL_ERR_BOUNDS;
    return WL_OK;
}

int wifi_ctrl_set_pm(struct wifi_qcc2072_ctrl *ctrl, enum wifi_pm_state target_state)
{
    if (!ctrl || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    uint8_t cmd[64];
    size_t n = 0;

    switch (target_state) {
    case WIFI_PM_ACTIVE:
        ctrl->pm_state = WIFI_PM_ACTIVE;
        ctrl->dtim_period = 1;
        ctrl->listen_interval_beacons = 1;
        ctrl->idle_elapsed_ms = 0;
        /* Emit WMI_PDEV_SET_PARAM(IDLE_PS_CONFIG=0) + WMI_STA_POWERSAVE_MODE(0) */
        n = qcc2072_assoc_pdev_set_param(cmd, sizeof(cmd), WIFI_QCC2072_PDEV_ID,
                                         QCC2072_ASSOC_PDEV_PARAM_IDLE_PS_CONFIG, 0U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        n = qcc2072_assoc_sta_ps_mode(cmd, sizeof(cmd), 0U, 0U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        return WL_OK;

    case WIFI_PM_BMPS:
        ctrl->pm_state = WIFI_PM_BMPS;
        ctrl->dtim_period = 3;
        ctrl->listen_interval_beacons = 3;
        /* Emit WMI_STA_POWERSAVE_PARAM (rx_wake_policy=1, tx_wake=1, pspoll=0)
         * followed by WMI_VDEV_SET_PARAM(DTIM_POLICY=2) and WMI_STA_POWERSAVE_MODE(1). */
        n = qcc2072_assoc_sta_ps_param(cmd, sizeof(cmd), 0U,
                                       QCC2072_ASSOC_STA_PS_PARAM_RX_WAKE_POLICY, 1U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        n = qcc2072_assoc_sta_ps_param(cmd, sizeof(cmd), 0U,
                                       QCC2072_ASSOC_STA_PS_PARAM_TX_WAKE_THRESHOLD, 1U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        n = qcc2072_assoc_vdev_set_param(cmd, sizeof(cmd), 0U,
                                         QCC2072_ASSOC_VDEV_PARAM_DTIM_POLICY, 2U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        n = qcc2072_assoc_sta_ps_mode(cmd, sizeof(cmd), 0U, 1U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        return WL_OK;

    case WIFI_PM_IMPS:
        ctrl->pm_state = WIFI_PM_IMPS;
        ctrl->dtim_period = 0;
        ctrl->listen_interval_beacons = 0;
        n = qcc2072_assoc_pdev_set_param(cmd, sizeof(cmd), WIFI_QCC2072_PDEV_ID,
                                         QCC2072_ASSOC_PDEV_PARAM_IDLE_PS_CONFIG, 1U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        return WL_OK;

    case WIFI_PM_WOWLAN_D3HOT:
        ctrl->pm_state = WIFI_PM_WOWLAN_D3HOT;
        ctrl->dtim_period = 5;
        ctrl->listen_interval_beacons = 5;
        ctrl->wowlan_wake_triggers = 0x0FU;
        n = qcc2072_assoc_vdev_set_param(cmd, sizeof(cmd), 0U,
                                         QCC2072_ASSOC_VDEV_PARAM_DTIM_POLICY, 2U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        n = qcc2072_assoc_sta_ps_mode(cmd, sizeof(cmd), 0U, 1U);
        if (n) wifi_enqueue_wmi(ctrl, cmd, n);
        return WL_OK;

    case WIFI_PM_D3COLD:
        ctrl->pm_state = WIFI_PM_D3COLD;
        return WL_OK;

    default:
        return WL_ERR_INVALID;
    }
}

int wifi_ctrl_tick_idle(struct wifi_qcc2072_ctrl *ctrl, uint32_t elapsed_ms, int has_traffic)
{
    if (!ctrl || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    if (has_traffic) {
        ctrl->idle_elapsed_ms = 0;
        if (ctrl->pm_state == WIFI_PM_BMPS || ctrl->pm_state == WIFI_PM_IMPS)
            return wifi_ctrl_set_pm(ctrl, WIFI_PM_ACTIVE);
        return WL_OK;
    }
    ctrl->idle_elapsed_ms += elapsed_ms;
    if (ctrl->pm_state == WIFI_PM_ACTIVE &&
        ctrl->idle_elapsed_ms >= ctrl->inactivity_timeout_ms)
        return wifi_ctrl_set_pm(ctrl, WIFI_PM_BMPS);
    return WL_OK;
}

int wifi_ctrl_negotiate_twt(struct wifi_qcc2072_ctrl *ctrl, uint8_t dialog_id,
                            uint16_t mantissa, uint8_t exp, uint8_t min_wake_dur,
                            uint64_t current_tsf)
{
    if (!ctrl || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    if (mantissa == 0 || exp > 31 || min_wake_dur == 0) return WL_ERR_INVALID;

    uint64_t interval_us = (uint64_t)mantissa << exp;
    uint64_t wake_dur_us = (uint64_t)min_wake_dur * 256ULL;
    if (wake_dur_us >= interval_us) return WL_ERR_INVALID;

    ctrl->twt.dialog_id = dialog_id;
    ctrl->twt.wake_duration_unit = 0;
    ctrl->twt.min_wake_duration = min_wake_dur;
    ctrl->twt.negotiation_type = 0;
    ctrl->twt.wake_interval_mantissa = mantissa;
    ctrl->twt.wake_interval_exp = exp;
    ctrl->twt.implicit_twt = 1;
    ctrl->twt.unannounced = 1;
    ctrl->twt.trigger_enabled = 1;
    ctrl->twt.wake_interval_us = interval_us;
    ctrl->twt.target_wake_time_tsf = current_tsf + interval_us;

    uint8_t cmd[64];
    size_t n = qcc2072_wmi_twt_enable(cmd, sizeof(cmd), WIFI_QCC2072_PDEV_ID);
    if (n) wifi_enqueue_wmi(ctrl, cmd, n);
    const uint8_t *peer = ctrl->station.associated ? ctrl->station.peer : ctrl->ft.current_bssid;
    n = qcc2072_wmi_twt_add_dialog(cmd, sizeof(cmd), 0U, peer, &ctrl->twt);
    if (n) wifi_enqueue_wmi(ctrl, cmd, n);
    return WL_OK;
}

/*
 * IEEE 802.11r-2008 / 802.11-2020 Section 12.7.1.6 Fast BSS Transition Key Hierarchy
 * Uses standard IEEE 802.11 KDF-SHA-256 (HMAC-SHA-256 counter mode):
 *   1. PMK-R0 = L(KDF-SHA-256(XXKey, "FT-R0", R0-Key-Data, 384), 0, 256)
 *      PMK-R0Name = Truncate-128(SHA-256("FT-R0N" || R0-Key-Data || R0-Salt))
 *   2. PMK-R1 = KDF-SHA-256(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID, 256)
 *      PMK-R1Name = Truncate-128(SHA-256("FT-R1N" || PMK-R0Name || R1KH-ID || S1KH-ID))
 *   3. PTK = KDF-SHA-256(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || STA-ADDR, 384)
 */
int wifi_ft_derive_keys(struct wifi_ft_roam_ctx *ft)
{
    if (!ft || ft->r0kh_id_len == 0 || ft->r0kh_id_len > WIFI_FT_R0KH_ID_MAX_LEN)
        return WL_ERR_INVALID;

    uint8_t r0_ctx[64];
    size_t r0_len = 0;
    memcpy(r0_ctx + r0_len, ft->mobility_domain, WIFI_FT_MOBILITY_DOMAIN_LEN);
    r0_len += WIFI_FT_MOBILITY_DOMAIN_LEN;
    r0_ctx[r0_len++] = ft->r0kh_id_len;
    memcpy(r0_ctx + r0_len, ft->r0kh_id, ft->r0kh_id_len);
    r0_len += ft->r0kh_id_len;
    memcpy(r0_ctx + r0_len, ft->sta_mac, 6);
    r0_len += 6;

    uint8_t r0_out[48];
    wl_kdf_sha256(ft->xxkey, "FT-R0", r0_ctx, r0_len, r0_out, 384U);
    memcpy(ft->pmk_r0, r0_out, WIFI_FT_PMK_LEN);

    uint8_t r0n_in[96], digest[32];
    memcpy(r0n_in, "FT-R0N", 6);
    memcpy(r0n_in + 6, r0_ctx, r0_len);
    memcpy(r0n_in + 6 + r0_len, r0_out + 32, 16);
    wl_sha256(r0n_in, 22U + r0_len, digest);
    memcpy(ft->pmk_r0_name, digest, 16);

    uint8_t r1_ctx[12];
    memcpy(r1_ctx, ft->r1kh_id, WIFI_FT_R1KH_ID_LEN);
    memcpy(r1_ctx + WIFI_FT_R1KH_ID_LEN, ft->sta_mac, 6);
    wl_kdf_sha256(ft->pmk_r0, "FT-R1", r1_ctx, sizeof(r1_ctx), ft->pmk_r1, 256U);

    uint8_t r1n_in[34];
    memcpy(r1n_in, "FT-R1N", 6);
    memcpy(r1n_in + 6, ft->pmk_r0_name, 16);
    memcpy(r1n_in + 22, r1_ctx, 12);
    wl_sha256(r1n_in, sizeof(r1n_in), digest);
    memcpy(ft->pmk_r1_name, digest, 16);

    uint8_t ptk_ctx[76];
    memcpy(ptk_ctx, ft->snonce, 32);
    memcpy(ptk_ctx + 32, ft->anonce, 32);
    memcpy(ptk_ctx + 64, ft->target_bssid, 6);
    memcpy(ptk_ctx + 70, ft->sta_mac, 6);
    wl_kdf_sha256(ft->pmk_r1, "FT-PTK", ptk_ctx, sizeof(ptk_ctx), ft->ptk, 384U);

    wl_crypto_zero(r0_out, sizeof(r0_out));
    wl_crypto_zero(digest, sizeof(digest));
    ft->keys_derived = 1;
    return WL_OK;
}

int wifi_ctrl_select_roam_candidate(const struct wifi_qcc2072_ctrl *ctrl,
                                    const struct wifi_bss_candidate *candidates,
                                    size_t count,
                                    struct wifi_bss_candidate *best_out)
{
    if (!ctrl || !candidates || !best_out || count == 0) return WL_ERR_NULL;

    int32_t best_score = -100000;
    size_t best_idx = count;

    for (size_t i = 0; i < count; ++i) {
        const struct wifi_bss_candidate *c = &candidates[i];
        if (c->rssi_dbm < -85) continue;
        int32_t score = (int32_t)c->rssi_dbm * 4 + (int32_t)c->snr_db * 2;
        if (c->channel_mhz >= 5955) score += 45;
        else if (c->channel_mhz >= 5180) score += 25;
        score -= (int32_t)c->channel_utilization / 4;
        if (c->ft_supported &&
            memcmp(c->mobility_domain, ctrl->ft.mobility_domain,
                   WIFI_FT_MOBILITY_DOMAIN_LEN) == 0)
            score += 30;
        score += (int32_t)c->he_mcs_max * 2;
        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    if (best_idx == count) return WL_ERR_INVALID;
    *best_out = candidates[best_idx];
    return WL_OK;
}

int wifi_ctrl_roam_ft(struct wifi_qcc2072_ctrl *ctrl,
                      const struct wifi_bss_candidate *target,
                      const uint8_t anonce[32], const uint8_t snonce[32])
{
    if (!ctrl || !target || !anonce || !snonce) return WL_ERR_NULL;
    if (!target->ft_supported) return WL_ERR_UNSUPPORTED;
    if (memcmp(target->mobility_domain, ctrl->ft.mobility_domain,
               WIFI_FT_MOBILITY_DOMAIN_LEN) != 0)
        return WL_ERR_INVALID;

    memcpy(ctrl->ft.target_bssid, target->bssid, 6);
    memcpy(ctrl->ft.r1kh_id, target->r1kh_id, WIFI_FT_R1KH_ID_LEN);
    memcpy(ctrl->ft.anonce, anonce, 32);
    memcpy(ctrl->ft.snonce, snonce, 32);

    int rc = wifi_ft_derive_keys(&ctrl->ft);
    if (rc != WL_OK) return rc;

    memcpy(ctrl->ft.current_bssid, target->bssid, 6);
    ctrl->current_channel_mhz = target->channel_mhz;
    ctrl->current_rssi_dbm = target->rssi_dbm;
    ctrl->ft.roam_count++;

    /* Emit QCC2072 WMI_VDEV_INSTALL_KEY_CMDID (0x5009) with the derived CCMP-128 TK (PTK+32) */
    uint8_t key_cmd[128];
    size_t n = qcc2072_assoc_install_key(key_cmd, sizeof(key_cmd), 0U, target->bssid,
                                         0U, QCC2072_ASSOC_KEY_PAIRWISE,
                                         QCC2072_ASSOC_CIPHER_AES_CCM,
                                         ctrl->ft.ptk + 32, 16U);
    if (n) wifi_enqueue_wmi(ctrl, key_cmd, n);
    return WL_OK;
}

int wifi_ampdu_push(struct wifi_ampdu_aggregator *agg, uint64_t payload_iova,
                    uint16_t length, uint8_t qos_flags)
{
    if (!agg) return WL_ERR_NULL;
    if (length == 0 || length > 11454) return WL_ERR_INVALID;
    if (agg->subframe_count >= WIFI_AMPDU_MAX_SUBFRAMES) return WL_ERR_NOSPC;
    if (agg->total_bytes + length > WIFI_AMPDU_MAX_BYTES) return WL_ERR_NOSPC;

    struct wifi_ampdu_subframe *sf = &agg->subframes[agg->subframe_count++];
    sf->payload_iova = payload_iova;
    sf->length = length;
    sf->seq_num = agg->next_seq & 0x0FFFU;
    sf->tid = agg->tid;
    sf->flags = qos_flags | 0x01U;
    sf->delimiter_crc = (uint16_t)((length ^ (sf->seq_num << 4) ^ 0x4EU) & 0xFFFFU);

    agg->next_seq = (agg->next_seq + 1U) & 0x0FFFU;
    uint32_t padded_len = ((uint32_t)length + 4U + 3U) & ~3U;
    agg->total_bytes += padded_len;
    return WL_OK;
}

int wifi_ampdu_flush(struct wifi_ampdu_aggregator *agg, uint32_t *out_subframes,
                     uint32_t *out_bytes)
{
    if (!agg) return WL_ERR_NULL;
    if (out_subframes) *out_subframes = agg->subframe_count;
    if (out_bytes) *out_bytes = agg->total_bytes;

    if (agg->subframe_count > 0) {
        agg->bursts_flushed++;
        agg->bytes_transmitted += agg->total_bytes;
    }
    agg->subframe_count = 0;
    agg->total_bytes = 0;
    return WL_OK;
}

int wifi_ampdu_ack_bitmap(struct wifi_ampdu_aggregator *agg, uint16_t ssn,
                          uint64_t bitmap, uint32_t *out_acked)
{
    if (!agg) return WL_ERR_NULL;
    agg->ssn = ssn & 0x0FFFU;
    agg->block_ack_bitmap = bitmap;
    uint32_t count = 0;
    uint64_t b = bitmap;
    while (b) {
        b &= (b - 1ULL);
        count++;
    }
    if (out_acked) *out_acked = count;
    return WL_OK;
}
