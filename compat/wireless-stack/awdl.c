/* SPDX-License-Identifier: MIT */
/*
 * Apple Wireless Direct Link (AWDL) & AirDrop 802.11 Protocol Engine
 *
 * Implements Apple Vendor-Specific 802.11 Action frames (OUI 00:17:F2),
 * Periodic Synchronization Frame (PSF) / Master Indication Frame (MIF)
 * generation, Synchronization / Election / Channel Sequence / Data Path TLVs,
 * deterministic Master Election, social channel hopping (channels 6, 44, 149),
 * and RFC 4291 EUI-64 IPv6 link-local (fe80::/64) data-frame encapsulation.
 *
 * Included in order by compat/wireless-stack.c; not compiled standalone.
 */

static const uint8_t k_awdl_bssid[6] = { 0x00, 0x25, 0x00, 0xFF, 0x94, 0x73 };
static const uint8_t k_awdl_mcast[6] = { 0x00, 0x17, 0xF2, 0x00, 0x00, 0x01 };

void awdl_derive_ipv6_link_local(const uint8_t mac[6], uint8_t ipv6_out[16])
{
    if (!mac || !ipv6_out) return;
    memset(ipv6_out, 0, 16);
    ipv6_out[0]  = 0xFE;
    ipv6_out[1]  = 0x80;
    ipv6_out[8]  = (uint8_t)(mac[0] ^ 0x02U);
    ipv6_out[9]  = mac[1];
    ipv6_out[10] = mac[2];
    ipv6_out[11] = 0xFF;
    ipv6_out[12] = 0xFE;
    ipv6_out[13] = mac[3];
    ipv6_out[14] = mac[4];
    ipv6_out[15] = mac[5];
}

int awdl_init(struct awdl_state *awdl, const uint8_t self_mac[6], uint16_t self_metric)
{
    if (!awdl || !self_mac) return WL_ERR_NULL;
    memset(awdl, 0, sizeof(*awdl));
    awdl->magic = AWDL_STATE_MAGIC;
    memcpy(awdl->self_mac, self_mac, 6);
    memcpy(awdl->bssid, k_awdl_bssid, 6);
    memcpy(awdl->master_mac, self_mac, 6);
    memcpy(awdl->top_master_mac, self_mac, 6);
    awdl->is_master = 1;
    awdl->distance_to_master = 0;
    awdl->self_metric = self_metric;
    awdl->master_metric = self_metric;
    awdl->aw_seq_number = 0;
    awdl->aw_period_tu = AWDL_AW_PERIOD_TU;
    awdl->presence_mode = 4;
    awdl->current_step = 0;

    static const uint8_t default_seq[AWDL_CHAN_SEQ_LEN] = {
        AWDL_CHAN_SOCIAL_24G,    AWDL_CHAN_SOCIAL_24G,
        AWDL_CHAN_SOCIAL_5G_LOW, AWDL_CHAN_SOCIAL_5G_LOW,
        AWDL_CHAN_SOCIAL_5G_LOW, AWDL_CHAN_SOCIAL_5G_LOW,
        AWDL_CHAN_SOCIAL_5G_HIGH, AWDL_CHAN_SOCIAL_5G_HIGH,
        AWDL_CHAN_SOCIAL_5G_HIGH, AWDL_CHAN_SOCIAL_5G_HIGH,
        AWDL_CHAN_SOCIAL_24G,    AWDL_CHAN_SOCIAL_24G,
        AWDL_CHAN_SOCIAL_5G_LOW, AWDL_CHAN_SOCIAL_5G_LOW,
        AWDL_CHAN_SOCIAL_5G_HIGH, AWDL_CHAN_SOCIAL_5G_HIGH
    };
    memcpy(awdl->channel_seq, default_seq, AWDL_CHAN_SEQ_LEN);
    awdl_derive_ipv6_link_local(self_mac, awdl->self_ipv6);
    return WL_OK;
}

uint8_t awdl_step_channel(struct awdl_state *awdl, uint16_t advance_aw_slots)
{
    if (!awdl || awdl->magic != AWDL_STATE_MAGIC) return AWDL_CHAN_SOCIAL_24G;
    awdl->aw_seq_number = (uint16_t)(awdl->aw_seq_number + advance_aw_slots);
    awdl->current_step = (uint8_t)((awdl->current_step + advance_aw_slots) % AWDL_CHAN_SEQ_LEN);
    return awdl->channel_seq[awdl->current_step];
}

static int awdl_compare_node(uint16_t metric_a, const uint8_t mac_a[6],
                             uint16_t metric_b, const uint8_t mac_b[6])
{
    if (metric_a > metric_b) return 1;
    if (metric_a < metric_b) return -1;
    int cmp = memcmp(mac_a, mac_b, 6);
    if (cmp > 0) return 1;
    if (cmp < 0) return -1;
    return 0;
}

void awdl_run_election(struct awdl_state *awdl)
{
    if (!awdl || awdl->magic != AWDL_STATE_MAGIC) return;

    uint16_t best_metric = awdl->self_metric;
    uint8_t  best_mac[6];
    uint8_t  best_dist = 0;

    memcpy(best_mac, awdl->self_mac, 6);

    for (size_t i = 0; i < AWDL_MAX_PEERS; i++) {
        const struct awdl_peer *p = &awdl->peers[i];
        if (!p->valid) continue;

        uint16_t cand_metric = p->master_metric >= p->self_metric ? p->master_metric : p->self_metric;
        const uint8_t *cand_mac = p->master_metric >= p->self_metric ? p->master_mac : p->mac;

        if (awdl_compare_node(cand_metric, cand_mac, best_metric, best_mac) > 0) {
            best_metric = cand_metric;
            memcpy(best_mac, cand_mac, 6);
            best_dist = (uint8_t)(p->distance_to_master + 1U);
        }
    }

    awdl->master_metric = best_metric;
    memcpy(awdl->master_mac, best_mac, 6);
    memcpy(awdl->top_master_mac, best_mac, 6);
    awdl->distance_to_master = best_dist;
    awdl->is_master = (best_dist == 0) ? 1 : 0;
}

static size_t awdl_write_tlv(uint8_t *buf, uint8_t type,
                             const uint8_t *val, uint16_t len)
{
    buf[0] = type;
    wl_write_le16(&buf[1], len);
    if (len > 0 && val)
        memcpy(&buf[3], val, len);
    return 3U + (size_t)len;
}

int awdl_encode_action_frame(struct awdl_state *awdl, uint8_t subtype,
                             uint8_t *out_buf, size_t out_cap, size_t *out_len)
{
    if (!awdl || !out_buf || !out_len || awdl->magic != AWDL_STATE_MAGIC)
        return WL_ERR_NULL;
    if (subtype != AWDL_FRAME_PSF && subtype != AWDL_FRAME_MIF)
        return WL_ERR_INVALID;
    if (out_cap < 160) return WL_ERR_NOSPC;

    size_t pos = 0;

    /* 1. IEEE 802.11 Action Frame Header (24 bytes) */
    wl_write_le16(&out_buf[0], 0x00D0U); /* Type=Mgmt(0), Subtype=Action(13) */
    wl_write_le16(&out_buf[2], 0x0000U); /* Duration */
    memcpy(&out_buf[4], k_awdl_mcast, 6);
    memcpy(&out_buf[10], awdl->self_mac, 6);
    memcpy(&out_buf[16], awdl->bssid, 6);
    wl_write_le16(&out_buf[22], (uint16_t)((awdl->tx_action_frames & 0x0FFFU) << 4));
    pos = 24;

    /* 2. Apple AWDL Action Header (16 bytes) */
    out_buf[pos++] = 127; /* Category: Vendor-Specific */
    out_buf[pos++] = AWDL_OUI_0;
    out_buf[pos++] = AWDL_OUI_1;
    out_buf[pos++] = AWDL_OUI_2;
    out_buf[pos++] = AWDL_VENDOR_TYPE;
    out_buf[pos++] = AWDL_VERSION;
    out_buf[pos++] = subtype;
    out_buf[pos++] = 0x00; /* Reserved */
    uint32_t tx_tu = (uint32_t)awdl->aw_seq_number * (uint32_t)awdl->aw_period_tu;
    wl_write_le32(&out_buf[pos], tx_tu * 1024U);
    wl_write_le32(&out_buf[pos + 4], tx_tu * 1024U + 25U);
    pos += 8;

    /* 3. Synchronization Parameters TLV (Type 0x04, Payload 18 bytes) */
    uint8_t sync_val[18];
    memset(sync_val, 0, sizeof(sync_val));
    sync_val[0] = awdl->channel_seq[awdl->current_step];
    wl_write_le16(&sync_val[1], awdl->aw_seq_number);
    wl_write_le16(&sync_val[3], awdl->aw_period_tu);
    sync_val[5] = (uint8_t)awdl->aw_period_tu;
    wl_write_le16(&sync_val[6], awdl->aw_period_tu);
    sync_val[8] = (uint8_t)awdl->presence_mode;
    sync_val[9] = awdl->current_step;
    memcpy(&sync_val[10], awdl->master_mac, 6);
    pos += awdl_write_tlv(&out_buf[pos], AWDL_TLV_SYNC_PARAMS, sync_val, sizeof(sync_val));

    /* 4. Election Parameters TLV (Type 0x05, Payload 21 bytes) */
    uint8_t elec_val[21];
    memset(elec_val, 0, sizeof(elec_val));
    elec_val[3] = awdl->distance_to_master;
    memcpy(&elec_val[5], awdl->master_mac, 6);
    wl_write_le32(&elec_val[11], awdl->master_metric);
    wl_write_le32(&elec_val[15], awdl->self_metric);
    pos += awdl_write_tlv(&out_buf[pos], AWDL_TLV_ELECTION_PARAMS, elec_val, sizeof(elec_val));

    /* 5. Channel Sequence TLV (Type 0x06, Payload 20 bytes) */
    uint8_t cseq_val[20];
    cseq_val[0] = AWDL_CHAN_SEQ_LEN - 1;
    cseq_val[1] = 0;
    cseq_val[2] = 0;
    cseq_val[3] = 3;
    memcpy(&cseq_val[4], awdl->channel_seq, AWDL_CHAN_SEQ_LEN);
    pos += awdl_write_tlv(&out_buf[pos], AWDL_TLV_CHAN_SEQ, cseq_val, sizeof(cseq_val));

    /* 6. Data Path State TLV (Type 0x0C, Payload 24 bytes: country + self_mac + ipv6) */
    uint8_t dpath_val[24];
    memset(dpath_val, 0, sizeof(dpath_val));
    dpath_val[0] = 'X';
    dpath_val[1] = '0';
    memcpy(&dpath_val[2], awdl->self_mac, 6);
    memcpy(&dpath_val[8], awdl->self_ipv6, 16);
    pos += awdl_write_tlv(&out_buf[pos], AWDL_TLV_DATA_PATH_STATE, dpath_val, sizeof(dpath_val));

    /* 7. Version TLV (Type 0x15, Payload 2 bytes) */
    uint8_t ver_val[2] = { AWDL_VERSION, 0x04 };
    pos += awdl_write_tlv(&out_buf[pos], AWDL_TLV_VERSION, ver_val, sizeof(ver_val));

    awdl->tx_action_frames++;
    *out_len = pos;
    return WL_OK;
}

static struct awdl_peer *awdl_find_or_alloc_peer(struct awdl_state *awdl, const uint8_t mac[6])
{
    struct awdl_peer *free_slot = NULL;
    for (size_t i = 0; i < AWDL_MAX_PEERS; i++) {
        if (awdl->peers[i].valid) {
            if (memcmp(awdl->peers[i].mac, mac, 6) == 0)
                return &awdl->peers[i];
        } else if (!free_slot) {
            free_slot = &awdl->peers[i];
        }
    }
    if (free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->valid = 1;
        memcpy(free_slot->mac, mac, 6);
        awdl_derive_ipv6_link_local(mac, free_slot->ipv6_link_local);
    }
    return free_slot;
}

int awdl_process_action_frame(struct awdl_state *awdl,
                              const uint8_t *frame, size_t frame_len,
                              int8_t rssi_dbm, uint32_t now_tu)
{
    if (!awdl || !frame || awdl->magic != AWDL_STATE_MAGIC) return WL_ERR_NULL;
    if (frame_len < 40) return WL_ERR_BOUNDS;

    uint16_t fc = wl_read_le16(&frame[0]);
    if ((fc & 0x00FFU) != 0x00D0U) return WL_ERR_INVALID;

    const uint8_t *src_mac = &frame[10];
    const uint8_t *bssid   = &frame[16];
    if (memcmp(bssid, k_awdl_bssid, 6) != 0)
        return WL_ERR_INVALID;

    const uint8_t *act = &frame[24];
    if (act[0] != 127 ||
        act[1] != AWDL_OUI_0 ||
        act[2] != AWDL_OUI_1 ||
        act[3] != AWDL_OUI_2 ||
        act[4] != AWDL_VENDOR_TYPE)
        return WL_ERR_INVALID;

    uint8_t subtype = act[6];
    if (subtype != AWDL_FRAME_PSF && subtype != AWDL_FRAME_MIF)
        return WL_ERR_UNSUPPORTED;

    struct awdl_peer *peer = awdl_find_or_alloc_peer(awdl, src_mac);
    if (!peer) return WL_ERR_NOSPC;
    peer->rssi_dbm = rssi_dbm;
    peer->last_seen_tu = now_tu;

    uint8_t peer_chan_seq[AWDL_CHAN_SEQ_LEN];
    int has_chan_seq = 0;
    uint16_t peer_aw_seq = awdl->aw_seq_number;
    uint8_t peer_step = awdl->current_step;
    int has_sync = 0;

    size_t pos = 40;
    while (pos + 3 <= frame_len) {
        uint8_t tlv_type = frame[pos];
        uint16_t tlv_len = wl_read_le16(&frame[pos + 1]);
        pos += 3;
        if (pos + (size_t)tlv_len > frame_len)
            return WL_ERR_BOUNDS;

        const uint8_t *v = &frame[pos];
        switch (tlv_type) {
        case AWDL_TLV_SYNC_PARAMS:
            if (tlv_len >= 16) {
                peer_aw_seq = wl_read_le16(&v[1]);
                peer_step = (uint8_t)(v[9] % AWDL_CHAN_SEQ_LEN);
                has_sync = 1;
            }
            break;

        case AWDL_TLV_ELECTION_PARAMS:
            if (tlv_len >= 19) {
                peer->distance_to_master = v[3];
                memcpy(peer->master_mac, &v[5], 6);
                peer->master_metric = (uint16_t)wl_read_le32(&v[11]);
                peer->self_metric   = (uint16_t)wl_read_le32(&v[15]);
            }
            break;

        case AWDL_TLV_CHAN_SEQ:
            if (tlv_len >= 4U + AWDL_CHAN_SEQ_LEN) {
                memcpy(peer_chan_seq, &v[4], AWDL_CHAN_SEQ_LEN);
                has_chan_seq = 1;
            }
            break;

        case AWDL_TLV_DATA_PATH_STATE:
            if (tlv_len >= 24) {
                memcpy(peer->ipv6_link_local, &v[8], 16);
            }
            break;

        default:
            break;
        }
        pos += (size_t)tlv_len;
    }

    awdl->rx_action_frames++;
    awdl_run_election(awdl);
    if (!awdl->is_master && memcmp(src_mac, awdl->master_mac, 6) == 0) {
        if (has_sync) {
            awdl->aw_seq_number = peer_aw_seq;
            awdl->current_step = peer_step;
        }
        if (has_chan_seq)
            memcpy(awdl->channel_seq, peer_chan_seq, AWDL_CHAN_SEQ_LEN);
    }
    return WL_OK;
}

int awdl_encode_data_frame(struct awdl_state *awdl,
                           const uint8_t dst_mac[6],
                           const uint8_t *payload, size_t payload_len,
                           uint16_t seq_num,
                           uint8_t *out_buf, size_t out_cap, size_t *out_len)
{
    if (!awdl || !dst_mac || !payload || !out_buf || !out_len ||
        awdl->magic != AWDL_STATE_MAGIC)
        return WL_ERR_NULL;
    if (payload_len == 0) return WL_ERR_INVALID;
    size_t total = 26U + 8U + 8U + payload_len;
    if (out_cap < total) return WL_ERR_NOSPC;

    /* 802.11 QoS Data Header (26 bytes) */
    wl_write_le16(&out_buf[0], 0x0088U);
    wl_write_le16(&out_buf[2], 0x0000U);
    memcpy(&out_buf[4], dst_mac, 6);
    memcpy(&out_buf[10], awdl->self_mac, 6);
    memcpy(&out_buf[16], awdl->bssid, 6);
    wl_write_le16(&out_buf[22], (uint16_t)((seq_num & 0x0FFFU) << 4));
    wl_write_le16(&out_buf[24], 0x0000U);

    /* LLC / SNAP with Apple OUI 00:17:F2 and PID 0x0800 (AWDL Data) */
    out_buf[26] = 0xAA;
    out_buf[27] = 0xAA;
    out_buf[28] = 0x03;
    out_buf[29] = AWDL_OUI_0;
    out_buf[30] = AWDL_OUI_1;
    out_buf[31] = AWDL_OUI_2;
    wl_write_be16(&out_buf[32], 0x0800U);

    /* AWDL Data Subheader (8 bytes) */
    wl_write_le16(&out_buf[34], 0x0403U);
    wl_write_le16(&out_buf[36], seq_num);
    wl_write_le16(&out_buf[38], 0x0000U);
    wl_write_be16(&out_buf[40], 0x86DDU);

    memcpy(&out_buf[42], payload, payload_len);
    awdl->tx_data_frames++;
    *out_len = total;
    return WL_OK;
}

int awdl_decode_data_frame(struct awdl_state *awdl,
                           const uint8_t *frame, size_t frame_len,
                           uint8_t src_mac_out[6],
                           uint8_t src_ipv6_out[16],
                           const uint8_t **payload_out, size_t *payload_len_out)
{
    if (!awdl || !frame || !src_mac_out || !src_ipv6_out ||
        !payload_out || !payload_len_out || awdl->magic != AWDL_STATE_MAGIC)
        return WL_ERR_NULL;
    if (frame_len <= 42U) return WL_ERR_BOUNDS;

    uint16_t fc = wl_read_le16(&frame[0]);
    if ((fc & 0x00FFU) != 0x0088U) return WL_ERR_INVALID;
    if (memcmp(&frame[16], k_awdl_bssid, 6) != 0) return WL_ERR_INVALID;

    if (frame[26] != 0xAA || frame[27] != 0xAA || frame[28] != 0x03 ||
        frame[29] != AWDL_OUI_0 || frame[30] != AWDL_OUI_1 ||
        frame[31] != AWDL_OUI_2)
        return WL_ERR_INVALID;

    uint16_t ethertype = wl_read_be16(&frame[40]);
    if (ethertype != 0x86DDU) return WL_ERR_UNSUPPORTED;

    memcpy(src_mac_out, &frame[10], 6);
    awdl_derive_ipv6_link_local(src_mac_out, src_ipv6_out);
    *payload_out = &frame[42];
    *payload_len_out = frame_len - 42U;
    awdl->rx_data_frames++;
    return WL_OK;
}
