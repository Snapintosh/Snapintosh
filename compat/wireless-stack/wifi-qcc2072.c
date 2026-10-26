/* SPDX-License-Identifier: MIT */
/*
 * QCC2072 Wi-Fi 6E/7 WMI & macOS 26A428 WCL Scan, Association, Key & Power-Save Bridge
 *
 * Connects compat/wireless-stack directly to drivers/snap-qcc2072/src/:
 *   - snap_station (macOS station state machine)
 *   - snap_wcl_scan_submit, snap_wcl_event_bss, snap_wcl_event_scan_done, snap_wcl_key_submit
 *   - qcc2072_wmi, qcc2072_scan_*, qcc2072_assoc, qcc2072_connect
 *
 * Included in order by compat/wireless-stack.c; not compiled standalone.
 */

enum {
    WIFI_SCAN_IDLE      = 0,
    WIFI_SCAN_CHAN_LIST = 1,
    WIFI_SCAN_VDEV      = 2,
    WIFI_SCAN_START     = 3,
    WIFI_SCAN_RUNNING   = 4
};

#define WIFI_QCC2072_PDEV_ID   1U
#define QCC2072_WIFI_BAR_GPA   0x78000000ULL
#define QCC2072_WIFI_DMA_GPA   0xdc000000ULL
#define QCC2072_WIFI_DMA_IOVA  0xdc000000ULL
#define QCC2072_WIFI_DMA_BYTES 0x04000000ULL

static void wifi_enqueue_wmi(struct wifi_qcc2072_ctrl *ctrl, const uint8_t *frame, size_t len)
{
    if (!ctrl || !frame || len < 4 || len > 2040U) return;
    memcpy(ctrl->last_wmi_cmd, frame, len);
    ctrl->last_wmi_cmd_len = len;
    ctrl->last_wmi_cmd_id = wl_read_le32(frame) & 0xFFFFFFU;
    if (ctrl->wmi_tx_count >= WIFI_WMI_QUEUE_DEPTH) {
        ctrl->wmi_tx_head = (uint8_t)((ctrl->wmi_tx_head + 1U) % WIFI_WMI_QUEUE_DEPTH);
        ctrl->wmi_tx_count--;
    }
    uint8_t slot = ctrl->wmi_tx_tail;
    memcpy(ctrl->wmi_tx_queue[slot], frame, len);
    ctrl->wmi_tx_len[slot] = (uint16_t)len;
    ctrl->wmi_tx_tail = (uint8_t)((slot + 1U) % WIFI_WMI_QUEUE_DEPTH);
    ctrl->wmi_tx_count++;
}

static void wifi_enqueue_wcl(struct wifi_qcc2072_ctrl *ctrl, uint32_t message,
                             const uint8_t *payload, size_t bytes)
{
    if (!ctrl || (!payload && bytes) || bytes > SNAP_WCL_EVENT_MAX_BYTES) return;
    if (ctrl->wcl_count >= WIFI_WCL_QUEUE_DEPTH) {
        ctrl->wcl_head = (uint8_t)((ctrl->wcl_head + 1U) % WIFI_WCL_QUEUE_DEPTH);
        ctrl->wcl_count--;
    }
    struct wifi_wcl_queued_event *ev = &ctrl->wcl_queue[ctrl->wcl_tail];
    ev->message = message;
    ev->bytes = (uint16_t)bytes;
    if (bytes) memcpy(ev->payload, payload, bytes);
    ctrl->wcl_tail = (uint8_t)((ctrl->wcl_tail + 1U) % WIFI_WCL_QUEUE_DEPTH);
    ctrl->wcl_count++;
}

size_t wifi_qcc2072_pop_wmi_tx(struct wifi_qcc2072_ctrl *ctrl, uint8_t *out,
                               size_t cap, uint32_t *cmd_id)
{
    if (!ctrl || !ctrl->wmi_tx_count) return 0;
    uint8_t slot = ctrl->wmi_tx_head;
    size_t len = ctrl->wmi_tx_len[slot];
    if (out && cap < len) return 0;
    if (cmd_id) *cmd_id = wl_read_le32(ctrl->wmi_tx_queue[slot]) & 0xFFFFFFU;
    if (out) memcpy(out, ctrl->wmi_tx_queue[slot], len);
    ctrl->wmi_tx_head = (uint8_t)((slot + 1U) % WIFI_WMI_QUEUE_DEPTH);
    ctrl->wmi_tx_count--;
    return len;
}

int wifi_qcc2072_pop_wcl_event(struct wifi_qcc2072_ctrl *ctrl, uint32_t *message,
                               uint8_t *out, size_t cap, size_t *bytes)
{
    if (!ctrl || !message || !bytes) return WL_ERR_NULL;
    if (!ctrl->wcl_count) return WL_ERR_STATE;
    uint8_t slot = ctrl->wcl_head;
    const struct wifi_wcl_queued_event *ev = &ctrl->wcl_queue[slot];
    if (out && cap < ev->bytes) return WL_ERR_NOSPC;
    *message = ev->message;
    *bytes = ev->bytes;
    if (out && ev->bytes) memcpy(out, ev->payload, ev->bytes);
    ctrl->wcl_head = (uint8_t)((slot + 1U) % WIFI_WCL_QUEUE_DEPTH);
    ctrl->wcl_count--;
    return WL_OK;
}

/* WMI_STOP_SCAN_CMDID (0x3002), tag 78 (WMI_TAG_STOP_SCAN_CMD, 32-byte fixed struct) */
size_t qcc2072_scan_stop(uint8_t *out, size_t cap, uint32_t vdev_id,
                         uint32_t scan_id, uint32_t req_id)
{
    if (!out || cap < 36U) return 0;
    memset(out, 0, 36U);
    wl_write_le32(out + 0, WIFI_WMI_STOP_SCAN_CMDID);
    wl_write_le32(out + 4, (78U << 16) | 28U);
    wl_write_le32(out + 8, req_id);
    wl_write_le32(out + 12, scan_id);
    wl_write_le32(out + 16, 0U); /* REQ_TYPE_ALL */
    wl_write_le32(out + 20, vdev_id);
    wl_write_le32(out + 32, WIFI_QCC2072_PDEV_ID);
    return 36U;
}

/* WMI_TWT_ENABLE_CMDID (0x3e001), tag 0x318 (WMI_TAG_TWT_ENABLE_CMD, 32-byte struct) */
size_t qcc2072_wmi_twt_enable(uint8_t *out, size_t cap, uint32_t pdev_id)
{
    if (!out || cap < 36U) return 0;
    memset(out, 0, 36U);
    wl_write_le32(out + 0, WIFI_WMI_TWT_ENABLE_CMDID);
    wl_write_le32(out + 4, (0x318U << 16) | 28U);
    wl_write_le32(out + 8, pdev_id);
    wl_write_le32(out + 12, 10U); /* sta_cong_timer_ms */
    wl_write_le32(out + 20, 256U); /* default_slot_size */
    wl_write_le32(out + 24, 50U);  /* congestion_thresh_setup */
    return 36U;
}

/* WMI_TWT_ADD_DIALOG_CMDID (0x3e003), tag 0x31a (WMI_TAG_TWT_ADD_DIALOG_CMD, 56-byte struct) */
size_t qcc2072_wmi_twt_add_dialog(uint8_t *out, size_t cap, uint32_t vdev_id,
                                  const uint8_t peer_mac[6],
                                  const struct wifi_twt_config *twt)
{
    if (!out || !peer_mac || !twt || cap < 60U) return 0;
    memset(out, 0, 60U);
    wl_write_le32(out + 0, WIFI_WMI_TWT_ADD_DIALOG_CMDID);
    wl_write_le32(out + 4, (0x31aU << 16) | 52U);
    wl_write_le32(out + 8, vdev_id);
    memcpy(out + 12, peer_mac, 6);
    wl_write_le32(out + 20, twt->dialog_id);
    wl_write_le32(out + 24, (uint32_t)twt->wake_interval_us);
    wl_write_le32(out + 28, twt->wake_interval_mantissa);
    uint32_t dur_us = (uint32_t)twt->min_wake_duration * (twt->wake_duration_unit ? 1024U : 256U);
    wl_write_le32(out + 32, dur_us);
    uint32_t flags = (uint32_t)twt->negotiation_type |
                     ((uint32_t)twt->trigger_enabled << 8) |
                     ((uint32_t)twt->unannounced << 9);
    wl_write_le32(out + 40, flags);
    return 60U;
}

/* --------------------------------------------------------------------------
 * QCC2072 WMI & Station Callbacks inside struct wifi_qcc2072_ctrl
 * -------------------------------------------------------------------------- */
static int wifi_wmi_validate_owner(void *ctx, uint64_t generation, uint64_t cookie)
{
    const struct wifi_qcc2072_ctrl *ctrl = (const struct wifi_qcc2072_ctrl *)ctx;
    if (!ctrl || generation != ctrl->session_generation || cookie != ctrl->owner_cookie)
        return QCC2072_SESSION_STALE;
    return 0;
}

static int wifi_wmi_admit_datapath(void *ctx, uint64_t generation, uint64_t cookie)
{
    return wifi_wmi_validate_owner(ctx, generation, cookie);
}

static int wifi_assoc_dma_sync(void *ctx, const struct qcc2072_dma_buffer *b,
                               size_t off, size_t len, uint32_t dir)
{
    const struct wifi_qcc2072_ctrl *ctrl = (const struct wifi_qcc2072_ctrl *)ctx;
    (void)dir;
    if (!ctrl || !b || off > b->capacity || len > b->capacity - off)
        return QCC2072_DMA_INVALID;
    return 0;
}

static int wifi_assoc_reo_queue(void *ctx, const uint8_t mac[6], uint32_t peer_id,
                                unsigned tid, uint64_t *queue_addr)
{
    const struct wifi_qcc2072_ctrl *ctrl = (const struct wifi_qcc2072_ctrl *)ctx;
    (void)mac; (void)peer_id;
    if (!ctrl || !queue_addr || tid >= QCC2072_ASSOC_REO_TIDS)
        return QCC2072_INVALID_ARGUMENT;
    *queue_addr = ctrl->stage2_dma_gpa + 0x20000ULL + (uint64_t)tid * 1024ULL;
    return 0;
}

static unsigned wifi_scan_channels(const struct wifi_qcc2072_ctrl *ctrl,
                                   struct qcc2072_scan_channel *out)
{
    if (!ctrl) return 0;
    if (ctrl->wmi.reg_seen && ctrl->wmi.reg_rule_count)
        return qcc2072_scan_channels_from_rules(ctrl->wmi.reg_rules,
                                                ctrl->wmi.reg_rule_count,
                                                out, QCC2072_SCAN_MAX_CHANNELS);
    return qcc2072_scan_default_channels(out, QCC2072_SCAN_MAX_CHANNELS);
}

static int wifi_resolve_channel(void *ctx, uint32_t version, uint32_t channel,
                                uint32_t flags, uint16_t *mhz)
{
    const struct wifi_qcc2072_ctrl *ctrl = (const struct wifi_qcc2072_ctrl *)ctx;
    if (!ctrl || !mhz || version != 1U) return SNAP_STATION_INVALID;
    if (flags & 0x2000U) return SNAP_STATION_UNSUPPORTED;
    int g2 = (flags & 0x8U) != 0, g5 = (flags & 0x10U) != 0;
    if (g2 && g5) return SNAP_STATION_INVALID;
    if (!g2 && !g5) { g2 = (channel >= 1U && channel <= 14U); g5 = !g2; }
    unsigned f = g2 ? (channel == 14U ? 2484U : 2407U + 5U * channel) : 5000U + 5U * channel;
    struct qcc2072_scan_channel all[QCC2072_SCAN_MAX_CHANNELS];
    unsigned n = wifi_scan_channels(ctrl, all);
    for (unsigned i = 0; i < n; ++i) {
        if (all[i].mhz == f) {
            *mhz = (uint16_t)f;
            return SNAP_STATION_OK;
        }
    }
    return SNAP_STATION_UNSUPPORTED;
}

static void wifi_scan_step(struct wifi_qcc2072_ctrl *ctrl)
{
    if (!ctrl || !ctrl->scan_stage || ctrl->scan_stage == WIFI_SCAN_RUNNING)
        return;
    struct qcc2072_scan_channel all[QCC2072_SCAN_MAX_CHANNELS];
    unsigned count = wifi_scan_channels(ctrl, all);
    if (!count) return;
    uint8_t cmd[2040];
    while (ctrl->scan_stage && ctrl->scan_stage != WIFI_SCAN_RUNNING) {
        size_t bytes = 0;
        if (ctrl->scan_stage == WIFI_SCAN_CHAN_LIST) {
            bytes = qcc2072_scan_chan_list(cmd, sizeof(cmd), WIFI_QCC2072_PDEV_ID, all, count);
            if (!bytes) break;
            wifi_enqueue_wmi(ctrl, cmd, bytes);
            ctrl->chan_list_sent = 1;
            ctrl->chan_list_revision = ctrl->wmi.reg_revision;
            ctrl->scan_stage = ctrl->vdev_created ? WIFI_SCAN_START : WIFI_SCAN_VDEV;
        } else if (ctrl->scan_stage == WIFI_SCAN_VDEV) {
            uint32_t chains = ctrl->wmi.rf_chains ? ctrl->wmi.rf_chains : 2U;
            bytes = qcc2072_scan_vdev_create(cmd, sizeof(cmd), 0U, WIFI_QCC2072_PDEV_ID,
                                             ctrl->sta_mac, chains);
            if (!bytes) break;
            wifi_enqueue_wmi(ctrl, cmd, bytes);
            ctrl->vdev_created = 1;
            ctrl->scan_stage = WIFI_SCAN_START;
        } else if (ctrl->scan_stage == WIFI_SCAN_START) {
            uint16_t channels[QCC2072_SCAN_MAX_CHANNELS];
            unsigned n = ctrl->active_scan_req.channel_count;
            if (n) {
                for (unsigned i = 0; i < n; ++i)
                    channels[i] = ctrl->active_scan_req.channels_mhz[i];
            } else {
                for (n = 0; n < count; ++n)
                    channels[n] = all[n].mhz;
            }
            struct qcc2072_scan_start_args a = {
                0U, channels, n, 1U,
                ctrl->active_scan_req.ssid_length,
                ctrl->active_scan_req.ssid
            };
            bytes = qcc2072_scan_start(cmd, sizeof(cmd), &a);
            if (!bytes) break;
            wifi_enqueue_wmi(ctrl, cmd, bytes);
            ctrl->scan_stage = WIFI_SCAN_RUNNING;
            ctrl->scan_deadline_ms = ctrl->now_ms + QCC2072_SCAN_MAX_TIME_MS + 5000ULL;
        }
    }
}

static void wifi_assoc_step(struct wifi_qcc2072_ctrl *ctrl)
{
    if (!ctrl) return;
    for (unsigned pass = 0; pass < 2U; ++pass) {
        for (unsigned guard = 0; guard < 32U; ++guard) {
            const uint8_t *frame = NULL;
            size_t len = 0;
            if (ctrl->assoc.state == QCC2072_ASSOC_IDLE ||
                ctrl->assoc.state == QCC2072_ASSOC_WEDGED)
                break;
            int rc = qcc2072_assoc_poll(&ctrl->assoc, ctrl->now_ms, &frame, &len);
            if (rc || !len || !frame) break;
            wifi_enqueue_wmi(ctrl, frame, len);
            if (qcc2072_assoc_sent(&ctrl->assoc, ctrl->now_ms)) break;
            if (ctrl->assoc.vdev_created) ctrl->vdev_created = 1;
        }
        struct qcc2072_assoc_notice n;
        while (qcc2072_assoc_take_notice(&ctrl->assoc, &n)) {
            struct snap_station_event e;
            memset(&e, 0, sizeof(e));
            e.generation = ctrl->session_generation;
            e.transaction = n.transaction;
            e.status = n.status;
            switch (n.type) {
            case QCC2072_ASSOC_N_ASSOCIATED:
                e.type = SNAP_STATION_ASSOCIATED;
                break;
            case QCC2072_ASSOC_N_CONNECTED:
                e.type = SNAP_STATION_CONNECTED;
                break;
            case QCC2072_ASSOC_N_CONTROL_DONE:
                e.type = SNAP_STATION_CONTROL_DONE;
                e.link_transaction = n.link_transaction;
                break;
            case QCC2072_ASSOC_N_CANCELLED:
                e.type = SNAP_STATION_CANCEL_ACK;
                e.status = SNAP_STATION_OK;
                break;
            case QCC2072_ASSOC_N_DISCONNECTED:
                e.type = SNAP_STATION_DISCONNECTED;
                break;
            default:
                e.type = SNAP_STATION_ERROR;
                if (!e.status) e.status = SNAP_STATION_NOT_READY;
                break;
            }
            (void)snap_station_event(&ctrl->station, &e);
            if (e.type == SNAP_STATION_CONTROL_DONE &&
                ctrl->station.authorized && !ctrl->station.connected) {
                struct snap_station_event conn_ev;
                memset(&conn_ev, 0, sizeof(conn_ev));
                conn_ev.generation = ctrl->session_generation;
                conn_ev.transaction = ctrl->station.link_transaction;
                conn_ev.type = SNAP_STATION_CONNECTED;
                (void)snap_station_event(&ctrl->station, &conn_ev);
            }
        }
        if (ctrl->station.associated && ctrl->station.secure &&
            ctrl->station.pairwise_key && ctrl->station.group_keys &&
            !ctrl->station.authorized && !ctrl->station.control.type &&
            ctrl->assoc.prog_kind == 0) {
            struct snap_station_control auth;
            memset(&auth, 0, sizeof(auth));
            auth.generation = ctrl->session_generation;
            auth.transaction = ++ctrl->next_transaction;
            auth.link_transaction = ctrl->station.link_transaction;
            auth.type = SNAP_STATION_PORT_AUTHORIZE;
            if (snap_station_control_submit(&ctrl->station, &auth) == SNAP_STATION_OK)
                continue;
        }
        break;
    }
}

static int wifi_station_submit_cb(void *ctx, const struct snap_station_request *r)
{
    struct wifi_qcc2072_ctrl *ctrl = (struct wifi_qcc2072_ctrl *)ctx;
    if (!ctrl || !r) return SNAP_STATION_INVALID;
    if (r->generation != ctrl->session_generation) return SNAP_STATION_STALE;
    if (r->type == SNAP_STATION_SCAN) {
        if (ctrl->scan_stage) return SNAP_STATION_BUSY;
        if (ctrl->assoc.state != QCC2072_ASSOC_IDLE &&
            ctrl->assoc.state != QCC2072_ASSOC_AUTHORIZED)
            return SNAP_STATION_BUSY;
        ctrl->active_scan_req = *r;
        ctrl->scan_transaction = r->transaction;
        if (ctrl->chan_list_revision != ctrl->wmi.reg_revision)
            ctrl->chan_list_sent = 0;
        ctrl->scan_stage = !ctrl->chan_list_sent ? WIFI_SCAN_CHAN_LIST :
                           !ctrl->vdev_created ? WIFI_SCAN_VDEV : WIFI_SCAN_START;
        wifi_scan_step(ctrl);
        return SNAP_STATION_OK;
    }
    if (r->type == SNAP_STATION_CONNECT) {
        if (ctrl->scan_stage) return SNAP_STATION_BUSY;
        const struct snap_station_bss *b = NULL;
        for (unsigned i = 0; i < 32U; ++i) {
            if (ctrl->bss_cache[i].frequency_mhz &&
                memcmp(ctrl->bss_cache[i].bssid, r->bssid, 6) == 0) {
                b = &ctrl->bss_cache[i];
                break;
            }
        }
        if (!b) return SNAP_STATION_NOT_READY;
        if (r->channel_count > 1U ||
            (r->channel_count == 1U && r->channels_mhz[0] != b->frequency_mhz))
            return SNAP_STATION_INVALID;
        struct qcc2072_scan_channel all[QCC2072_SCAN_MAX_CHANNELS];
        unsigned n = wifi_scan_channels(ctrl, all), idx = 0;
        while (idx < n && all[idx].mhz != b->frequency_mhz) ++idx;
        if (idx == n) return SNAP_STATION_UNSUPPORTED;
        struct qcc2072_assoc_connect_args *c = &ctrl->connect_args;
        memset(c, 0, sizeof(*c));
        c->transaction = r->transaction;
        c->vdev_id = 0U;
        c->pdev_id = WIFI_QCC2072_PDEV_ID;
        c->flags = (ctrl->vdev_created ? QCC2072_ASSOC_F_VDEV_CREATED : 0U) |
                   QCC2072_ASSOC_F_ETH_OFFLOAD;
        memcpy(c->own_mac, ctrl->sta_mac, 6);
        memcpy(c->bssid, r->bssid, 6);
        c->ssid_length = r->ssid_length;
        memcpy(c->ssid, r->ssid, r->ssid_length);
        c->freq_mhz = b->frequency_mhz;
        c->beacon_interval_tu = b->beacon_interval_tu;
        c->capability = b->capability;
        c->max_power_dbm = (int8_t)(all[idx].max_power_half_db / 2U);
        c->max_reg_power_dbm = c->max_power_dbm;
        c->passive = (all[idx].passive || all[idx].dfs) ? 1U : 0U;
        for (unsigned at = 0; at + 2U <= r->ie_length &&
                              at + 2U + r->ies[at + 1] <= r->ie_length;
             at += 2U + r->ies[at + 1]) {
            if (r->ies[at] == 48U && r->ies[at + 1] + 2U <= sizeof(c->rsn)) {
                c->rsn_length = (uint8_t)(r->ies[at + 1] + 2U);
                memcpy(c->rsn, r->ies + at, c->rsn_length);
                break;
            }
        }
        c->ie_length = b->ie_length;
        memcpy(c->ies, b->ies, b->ie_length);
        int rc = qcc2072_assoc_connect(&ctrl->assoc, ctrl->now_ms, c);
        if (rc == SNAP_STATION_OK) {
            ctrl->assoc_transaction = r->transaction;
            ctrl->current_channel_mhz = b->frequency_mhz;
            ctrl->current_rssi_dbm = (int8_t)b->rssi_dbm;
            memcpy(ctrl->ft.current_bssid, b->bssid, 6);
            wifi_assoc_step(ctrl);
        }
        return rc;
    }
    return SNAP_STATION_UNSUPPORTED;
}

static int wifi_station_cancel_cb(void *ctx, uint64_t generation, uint64_t transaction)
{
    struct wifi_qcc2072_ctrl *ctrl = (struct wifi_qcc2072_ctrl *)ctx;
    if (!ctrl || generation != ctrl->session_generation) return SNAP_STATION_STALE;
    if (ctrl->scan_stage && transaction == ctrl->scan_transaction) {
        uint8_t stop_cmd[36];
        size_t n = qcc2072_scan_stop(stop_cmd, sizeof(stop_cmd), 0U,
                                     QCC2072_SCAN_ID, QCC2072_SCAN_REQ_ID);
        if (n) wifi_enqueue_wmi(ctrl, stop_cmd, n);
        ctrl->scan_stage = WIFI_SCAN_IDLE;
        return SNAP_STATION_OK;
    }
    if (ctrl->assoc.state == QCC2072_ASSOC_CONNECTING) {
        int rc = qcc2072_assoc_cancel(&ctrl->assoc, ctrl->now_ms, transaction);
        if (rc == SNAP_STATION_OK) wifi_assoc_step(ctrl);
        return rc;
    }
    return SNAP_STATION_NOT_READY;
}

static int wifi_station_stop_cb(void *ctx, uint64_t generation)
{
    struct wifi_qcc2072_ctrl *ctrl = (struct wifi_qcc2072_ctrl *)ctx;
    if (!ctrl || generation != ctrl->session_generation) return SNAP_STATION_STALE;
    ctrl->scan_stage = WIFI_SCAN_IDLE;
    (void)qcc2072_assoc_abort(&ctrl->assoc);
    return SNAP_STATION_OK;
}

static int wifi_station_control_cb(void *ctx, const struct snap_station_control *c)
{
    struct wifi_qcc2072_ctrl *ctrl = (struct wifi_qcc2072_ctrl *)ctx;
    if (!ctrl || !c) return SNAP_STATION_INVALID;
    if (c->generation != ctrl->session_generation) return SNAP_STATION_STALE;
    return qcc2072_assoc_control(&ctrl->assoc, ctrl->now_ms, c);
}

/* Encodes macOS 26A428 WCL link notifications (0x08 ASSOC_DONE, 0x03 BSSID, 0x01 LINK) */
int snap_wcl_event_link_encode(const struct snap_station *station,
                               const struct snap_station_event *event,
                               uint8_t *out, size_t capacity,
                               uint32_t *message, size_t *bytes)
{
    if (!station || !event || !out || !message || !bytes)
        return SNAP_STATION_INVALID;
    if (capacity < SNAP_WCL_EVENT_LINK_BYTES)
        return SNAP_STATION_INVALID;
    memset(out, 0, SNAP_WCL_EVENT_LINK_BYTES);
    if (event->type == SNAP_STATION_ASSOCIATED) {
        *message = SNAP_WCL_EVENT_ASSOC_DONE;
        wl_write_le32(out + 0, 1U); /* version 1 */
        wl_write_le32(out + 4, (uint32_t)event->status);
        memcpy(out + 8, station->peer, 6);
        *bytes = SNAP_WCL_EVENT_LINK_BYTES;
        return SNAP_STATION_OK;
    }
    if (event->type == SNAP_STATION_CONNECTED) {
        *message = SNAP_WCL_EVENT_LINK_CHANGED;
        wl_write_le32(out + 0, 1U); /* version 1 */
        wl_write_le32(out + 4, 1U); /* link state = UP */
        memcpy(out + 8, station->peer, 6);
        *bytes = SNAP_WCL_EVENT_LINK_BYTES;
        return SNAP_STATION_OK;
    }
    if (event->type == SNAP_STATION_DISCONNECTED || event->type == SNAP_STATION_ERROR) {
        *message = SNAP_WCL_EVENT_LINK_CHANGED;
        wl_write_le32(out + 0, 1U); /* version 1 */
        wl_write_le32(out + 4, 0U); /* link state = DOWN */
        wl_write_le32(out + 8, (uint32_t)event->status);
        *bytes = SNAP_WCL_EVENT_LINK_BYTES;
        return SNAP_STATION_OK;
    }
    return SNAP_STATION_UNSUPPORTED;
}

static void wifi_station_event_cb(void *ctx, const struct snap_station_event *e)
{
    struct wifi_qcc2072_ctrl *ctrl = (struct wifi_qcc2072_ctrl *)ctx;
    if (!ctrl || !e) return;
    qcc2072_connect_station_event(&ctrl->connect, e);
    uint8_t payload[SNAP_WCL_EVENT_MAX_BYTES];
    uint32_t msg = 0;
    size_t bytes = 0;
    if (e->type == SNAP_STATION_BSS || e->type == SNAP_STATION_SCAN_DONE) {
        struct snap_station_event ev_copy = *e;
        if (ev_copy.type == SNAP_STATION_BSS &&
            ev_copy.bss.rssi_dbm < 0 && ev_copy.bss.rssi_dbm >= -127)
            ev_copy.bss.observed |= SNAP_STATION_BSS_RSSI;
        if (snap_wcl_event_encode(&ev_copy, payload, sizeof(payload), &msg, &bytes) == SNAP_STATION_OK)
            wifi_enqueue_wcl(ctrl, msg, payload, bytes);
        return;
    }
    if (e->type == SNAP_STATION_CANCEL_ACK && e->transaction == ctrl->scan_transaction) {
        struct snap_station_event done_ev;
        memset(&done_ev, 0, sizeof(done_ev));
        done_ev.generation = e->generation;
        done_ev.transaction = e->transaction;
        done_ev.type = SNAP_STATION_SCAN_DONE;
        if (snap_wcl_event_encode(&done_ev, payload, sizeof(payload), &msg, &bytes) == SNAP_STATION_OK)
            wifi_enqueue_wcl(ctrl, msg, payload, bytes);
        ctrl->scan_transaction = 0;
        return;
    }
    if (e->type == SNAP_STATION_ASSOCIATED ||
        e->type == SNAP_STATION_CONNECTED ||
        e->type == SNAP_STATION_DISCONNECTED ||
        (e->type == SNAP_STATION_ERROR && e->transaction == ctrl->assoc_transaction)) {
        if (snap_wcl_event_link_encode(&ctrl->station, e, payload, sizeof(payload),
                                       &msg, &bytes) == SNAP_STATION_OK) {
            wifi_enqueue_wcl(ctrl, msg, payload, bytes);
            if (e->type == SNAP_STATION_CONNECTED) {
                uint8_t bssid_msg[SNAP_WCL_EVENT_LINK_BYTES] = {0};
                wl_write_le32(bssid_msg + 0, 1U);
                memcpy(bssid_msg + 4, ctrl->station.peer, 6);
                wl_write_le16(bssid_msg + 12, ctrl->current_channel_mhz);
                wifi_enqueue_wcl(ctrl, SNAP_WCL_EVENT_BSSID_CHANGED,
                                 bssid_msg, sizeof(bssid_msg));
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * macOS 26A428 WCL Associate & Leave Bridges
 * -------------------------------------------------------------------------- */
/*
 * WCL associate candidate layout (SNAP_WCL_ASSOC_26A428_BYTES = 0x268 bytes):
 *   +0x00: uint32_t version (1)
 *   +0x04: uint32_t ssid_length (1..32)
 *   +0x08: uint8_t  ssid[32]
 *   +0x28: uint8_t  bssid[6] (unicast or all-zero to select strongest cached BSS for SSID)
 *   +0x2e: uint16_t channel_mhz (optional, 0 = use cached BSS frequency)
 */
int snap_wcl_assoc_submit(struct snap_station *station, const void *request,
                          size_t bytes, uint64_t *next_transaction,
                          const struct snap_station_bss *bss_cache,
                          unsigned bss_capacity)
{
    const uint8_t *p = (const uint8_t *)request;
    if (!station || !p || !next_transaction || bytes < 0x30U || *next_transaction == UINT64_MAX)
        return SNAP_STATION_INVALID;
    if (wl_read_le32(p + 0x00) != 1U)
        return SNAP_STATION_INVALID;
    uint32_t ssid_len = wl_read_le32(p + 0x04);
    if (!ssid_len || ssid_len > 32U)
        return SNAP_STATION_INVALID;
    const uint8_t *ssid = p + 0x08;
    const uint8_t *want_bssid = p + 0x28;
    uint16_t want_mhz = wl_read_le16(p + 0x2e);
    int has_bssid = (want_bssid[0] | want_bssid[1] | want_bssid[2] |
                     want_bssid[3] | want_bssid[4] | want_bssid[5]) != 0;
    const struct snap_station_bss *best = NULL;
    if (bss_cache && bss_capacity) {
        for (unsigned i = 0; i < bss_capacity; ++i) {
            const struct snap_station_bss *b = &bss_cache[i];
            if (!b->frequency_mhz) continue;
            if (has_bssid) {
                if (memcmp(b->bssid, want_bssid, 6) == 0) {
                    best = b;
                    break;
                }
            } else if (b->ssid_length == ssid_len &&
                       memcmp(b->ssid, ssid, ssid_len) == 0 &&
                       (!want_mhz || b->frequency_mhz == want_mhz)) {
                if (!best || b->rssi_dbm > best->rssi_dbm)
                    best = b;
            }
        }
    }
    if (!best && !has_bssid)
        return SNAP_STATION_NOT_READY;
    struct snap_station_request req;
    memset(&req, 0, sizeof(req));
    req.transaction = *next_transaction + 1ULL;
    req.type = SNAP_STATION_CONNECT;
    req.ssid_length = (uint8_t)ssid_len;
    memcpy(req.ssid, ssid, ssid_len);
    memcpy(req.bssid, best ? best->bssid : want_bssid, 6);
    uint16_t freq = best ? best->frequency_mhz : want_mhz;
    if (freq) {
        req.channel_count = 1U;
        req.channels_mhz[0] = freq;
    }
    int rsn_present = 1;
    if (best) {
        const uint8_t *rsn = NULL;
        size_t rsn_len = 0;
        rsn_present = (snap_rsn_find(best->ies, best->ie_length, &rsn, &rsn_len, NULL, NULL) == SNAP_RSN_OK);
    }
    if (rsn_present) {
        req.ie_length = SNAP_RSN_OWN_LENGTH;
        memcpy(req.ies, snap_rsn_own, SNAP_RSN_OWN_LENGTH);
    }
    int rc = snap_station_submit(station, &req);
    if (rc == SNAP_STATION_OK)
        *next_transaction = req.transaction;
    return rc;
}

int snap_wcl_leave_submit(struct snap_station *station, uint16_t reason,
                          uint64_t *next_transaction)
{
    if (!station || !next_transaction || *next_transaction == UINT64_MAX)
        return SNAP_STATION_INVALID;
    if (station->associated) {
        struct snap_station_control c;
        memset(&c, 0, sizeof(c));
        c.generation = station->generation;
        c.transaction = *next_transaction + 1ULL;
        c.link_transaction = station->link_transaction;
        c.type = SNAP_STATION_LINK_DISCONNECT;
        c.reason = reason ? reason : 3U;
        int rc = snap_station_control_submit(station, &c);
        if (rc == SNAP_STATION_OK)
            *next_transaction = c.transaction;
        return rc;
    }
    if (station->pending.type == SNAP_STATION_CONNECT)
        return snap_station_cancel(station, station->pending.transaction);
    return SNAP_STATION_NOT_READY;
}

/* --------------------------------------------------------------------------
 * High-Level QCC2072 + macOS WCL Operations on struct wifi_qcc2072_ctrl
 * -------------------------------------------------------------------------- */
int wifi_qcc2072_admit_wmi(struct wifi_qcc2072_ctrl *ctrl, const uint8_t *ev,
                           size_t len, uint64_t now_ms)
{
    if (!ctrl || !ev || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    ctrl->now_ms = now_ms;
    struct qcc2072_wmi_event out;
    int rc = qcc2072_wmi_receive(&ctrl->wmi, ctrl->session_generation,
                                 ctrl->owner_cookie, now_ms, 0x100U, ev, len, &out);
    if (rc) return WL_ERR_INVALID;
    (void)qcc2072_assoc_wmi_event(&ctrl->assoc, now_ms, ev, len);

    if (ctrl->wmi.state == QCC2072_WMI_INIT_ELIGIBLE) {
        uint8_t init_cmd[332];
        size_t init_len = 0;
        if (qcc2072_wmi_init_command(&ctrl->wmi, now_ms, init_cmd,
                                     sizeof(init_cmd), &init_len) == 0 && init_len)
            wifi_enqueue_wmi(ctrl, init_cmd, init_len);
    }

    if (!ctrl->station_admitted &&
        ctrl->wmi.state == QCC2072_WMI_READY &&
        ctrl->wmi.reg_seen) {
        struct snap_station_ready ready;
        if (qcc2072_wmi_snapshot(&ctrl->wmi, &ready) == 0 &&
            (ready.observed & SNAP_STATION_READY_ALL) == SNAP_STATION_READY_ALL) {
            ready.capabilities = SNAP_STATION_CAP_SCAN |
                                 SNAP_STATION_CAP_PRIVATE_SCAN |
                                 ((ctrl->assoc.caps.service_ready && ctrl->assoc.caps.ext_ready)
                                  ? SNAP_STATION_CAP_CONNECT : 0U);
            if (snap_station_admit(&ctrl->station, &ready) == SNAP_STATION_OK) {
                ctrl->station_admitted = 1;
                memcpy(ctrl->sta_mac, ready.mac, 6);
                memcpy(ctrl->ft.sta_mac, ready.mac, 6);
            }
        }
    }

    if (ctrl->scan_stage == WIFI_SCAN_RUNNING) {
        if (out.kind == QCC2072_WMI_EVENT_BSS) {
            struct snap_station_event se;
            memset(&se, 0, sizeof(se));
            se.generation = ctrl->session_generation;
            se.transaction = ctrl->scan_transaction;
            se.type = SNAP_STATION_BSS;
            se.bss = out.bss;
            se.bss.rssi_dbm = (int16_t)((int32_t)out.snr - 95);
            unsigned slot = 32U;
            for (unsigned i = 0; i < 32U; ++i) {
                if (ctrl->bss_cache[i].frequency_mhz &&
                    memcmp(ctrl->bss_cache[i].bssid, se.bss.bssid, 6) == 0) {
                    slot = i;
                    break;
                }
            }
            for (unsigned i = 0; i < 32U && slot == 32U; ++i) {
                if (!ctrl->bss_cache[i].frequency_mhz) slot = i;
            }
            if (slot < 32U) ctrl->bss_cache[slot] = se.bss;
            (void)snap_station_event(&ctrl->station, &se);
        } else if (out.kind == QCC2072_WMI_EVENT_SCAN &&
                   out.scan_id == QCC2072_SCAN_ID && out.vdev_id == 0U) {
            if (out.scan_type & QCC2072_SCAN_COMPLETED) {
                struct snap_station_event se;
                memset(&se, 0, sizeof(se));
                se.generation = ctrl->session_generation;
                se.transaction = ctrl->scan_transaction;
                se.type = SNAP_STATION_SCAN_DONE;
                ctrl->scan_stage = WIFI_SCAN_IDLE;
                ctrl->scan_transaction = 0;
                (void)snap_station_event(&ctrl->station, &se);
            }
        }
    }

    wifi_assoc_step(ctrl);
    return WL_OK;
}

int wifi_qcc2072_htt_event(struct wifi_qcc2072_ctrl *ctrl, const uint8_t *ev,
                           size_t len, uint64_t now_ms)
{
    if (!ctrl || !ev || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    ctrl->now_ms = now_ms;
    int rc = qcc2072_assoc_htt_event(&ctrl->assoc, now_ms, ev, len);
    if (rc) return WL_ERR_INVALID;
    wifi_assoc_step(ctrl);
    return WL_OK;
}

int wifi_qcc2072_wcl_scan_req(struct wifi_qcc2072_ctrl *ctrl, const void *wcl_req,
                              size_t bytes, uint64_t now_ms)
{
    if (!ctrl || !wcl_req || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    ctrl->now_ms = now_ms;
    uint64_t tx = ctrl->next_transaction + 1ULL;
    int rc = snap_wcl_scan_submit(&ctrl->station, wcl_req, bytes, tx,
                                  wifi_resolve_channel, ctrl);
    if (rc != SNAP_STATION_OK) return WL_ERR_INVALID;
    ctrl->next_transaction = tx;
    return WL_OK;
}

int wifi_qcc2072_wcl_scan_abort(struct wifi_qcc2072_ctrl *ctrl, uint64_t now_ms)
{
    if (!ctrl || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    if (!ctrl->station.pending.type || !ctrl->scan_transaction)
        return WL_ERR_STATE;
    ctrl->now_ms = now_ms;
    uint64_t tx = ctrl->scan_transaction;
    int rc = snap_station_cancel(&ctrl->station, tx);
    if (rc != SNAP_STATION_OK) return WL_ERR_STATE;
    struct snap_station_event ack;
    memset(&ack, 0, sizeof(ack));
    ack.generation = ctrl->session_generation;
    ack.transaction = tx;
    ack.type = SNAP_STATION_CANCEL_ACK;
    ack.status = SNAP_STATION_OK;
    (void)snap_station_event(&ctrl->station, &ack);
    return WL_OK;
}

int wifi_qcc2072_wcl_associate(struct wifi_qcc2072_ctrl *ctrl, const void *wcl_assoc,
                               size_t bytes, const uint8_t pmk[32], uint64_t now_ms)
{
    if (!ctrl || !wcl_assoc || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    ctrl->now_ms = now_ms;
    int rc = snap_wcl_assoc_submit(&ctrl->station, wcl_assoc, bytes,
                                   &ctrl->next_transaction, ctrl->bss_cache, 32U);
    if (rc != SNAP_STATION_OK) return WL_ERR_INVALID;
    if (pmk) {
        (void)qcc2072_connect_arm(&ctrl->connect, ctrl->next_transaction,
                                  ctrl->station.peer, ctrl->sta_mac, pmk);
    }
    return WL_OK;
}

int wifi_qcc2072_wcl_cipher_key(struct wifi_qcc2072_ctrl *ctrl, const void *wcl_key,
                                size_t bytes, uint64_t now_ms)
{
    if (!ctrl || !wcl_key || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    ctrl->now_ms = now_ms;
    int rc = snap_wcl_key_submit(&ctrl->station, wcl_key, bytes, ++ctrl->next_transaction);
    if (rc != SNAP_STATION_OK) return WL_ERR_INVALID;
    wifi_assoc_step(ctrl);
    return WL_OK;
}

int wifi_qcc2072_wcl_leave(struct wifi_qcc2072_ctrl *ctrl, uint16_t reason,
                           uint64_t now_ms)
{
    if (!ctrl || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    ctrl->now_ms = now_ms;
    int rc = snap_wcl_leave_submit(&ctrl->station, reason, &ctrl->next_transaction);
    if (rc != SNAP_STATION_OK) return WL_ERR_STATE;
    wifi_assoc_step(ctrl);
    return WL_OK;
}

int wifi_qcc2072_poll(struct wifi_qcc2072_ctrl *ctrl, uint64_t now_ms)
{
    if (!ctrl || ctrl->magic != WIFI_QCC2072_MAGIC) return WL_ERR_NULL;
    ctrl->now_ms = now_ms;
    if (ctrl->scan_stage == WIFI_SCAN_RUNNING && now_ms >= ctrl->scan_deadline_ms) {
        struct snap_station_event err;
        memset(&err, 0, sizeof(err));
        err.generation = ctrl->session_generation;
        err.transaction = ctrl->scan_transaction;
        err.type = SNAP_STATION_ERROR;
        err.status = SNAP_STATION_CANCELLED;
        ctrl->scan_stage = WIFI_SCAN_IDLE;
        ctrl->scan_transaction = 0;
        (void)snap_station_event(&ctrl->station, &err);
    }
    wifi_scan_step(ctrl);
    wifi_assoc_step(ctrl);
    return WL_OK;
}
