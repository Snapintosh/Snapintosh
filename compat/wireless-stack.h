/* SPDX-License-Identifier: MIT */
/* Native Wireless Mediation & Protocol Engine for ASUS Zenbook A16 (QCC2072):
 *   1. Wi-Fi (QCC2072 / ath12k family): Power management (Active, BMPS, IMPS,
 *      WoWLAN D3hot wake filters, Target Wake Time), IEEE 802.11k/v/r Fast BSS
 *      Transition (FT) roaming with PMK-R0/PMK-R1 key derivation, and high-
 *      throughput A-MPDU BlockAck reorder/coalescing within the stage-2 DMA
 *      arena (QCC2072_WIFI_DMA_PA: 0xdc000000..0xe0000000).
 *   2. Bluetooth 5.4: HCI H4/command/event/ACL state machine, L2CAP fixed-channel
 *      router (Signaling, ATT, SMP), LE Secure Connections SMP pairing handshake
 *      without state/confirm errors, and Apple Continuity AirDrop BLE beacon
 *      discovery framing (Company ID 0x004C, Continuity Type 0x05).
 *   3. AirDrop / Apple Wireless Direct Link (AWDL): IEEE 802.11 Action Frame
 *      (OUI 00:17:F2, Type 0x08) PSF/MIF parser and encoder, Master Election
 *      and Synchronization Tree, 2.4/5/6 GHz social/data channel sequence
 *      scheduler (channels 6, 44, 149), bounds-checked TLV engine, and LLC/SNAP
 *      IPv6 link-local data path encapsulation.
 *
 * Opt-in gate: -DSNAP_WIRELESS_STACK=1 (default 0 leaves default monitor build
 * bit-for-bit identical).
 */
#ifndef SNAP_COMPAT_WIRELESS_STACK_H
#define SNAP_COMPAT_WIRELESS_STACK_H

#include <stdint.h>
#include <stddef.h>
#include "qcc2072-wifi.h"

#ifndef SNAP_WIRELESS_STACK
#define SNAP_WIRELESS_STACK 0
#endif

/* -------------------------------------------------------------------------
 * 1. QCC2072 Wi-Fi Power Management, Fast Roaming (802.11k/v/r) & A-MPDU
 * ------------------------------------------------------------------------- */
enum wifi_pm_state {
    WIFI_PM_UNINITIALIZED = 0,
    WIFI_PM_ACTIVE        = 1, /* Full MIMO active, lowest latency */
    WIFI_PM_BMPS          = 2, /* Beacon Mode Power Save (DTIM wake) */
    WIFI_PM_IMPS          = 3, /* Idle Mode Power Save (unassociated radio sleep) */
    WIFI_PM_WOWLAN_D3HOT  = 4, /* PCIe L1.2 / D3hot with wake pattern offload */
};

#define WIFI_WOWLAN_WAKE_MAGIC_PKT  (1u << 0)
#define WIFI_WOWLAN_WAKE_ARP_NS     (1u << 1)
#define WIFI_WOWLAN_WAKE_DISASSOC   (1u << 2)
#define WIFI_WOWLAN_WAKE_AWDL_SYNC  (1u << 3)
#define WIFI_WOWLAN_WAKE_ALL        0x0fu

#define WIFI_ROAM_CANDIDATES_MAX    8u
#define WIFI_AMPDU_WINDOW_MAX       256u
#define WIFI_AMPDU_BITMAP_WORDS     (WIFI_AMPDU_WINDOW_MAX / 64u)

struct wifi_twt_agreement {
    uint8_t  dialog_token;
    uint8_t  flow_id;          /* 0..7 */
    uint8_t  enabled;
    uint8_t  implicit;
    uint32_t wake_duration_us; /* Nominal minimum wake duration */
    uint64_t wake_interval_us; /* Target wake interval */
};

struct wifi_roam_candidate {
    uint8_t  bssid[6];
    uint16_t channel;          /* e.g. 6, 36, 44, 149 */
    int8_t   rssi_dbm;         /* Observed beacon/probe RSSI */
    int8_t   snr_db;
    uint16_t mdid;             /* Mobility Domain ID (802.11r) */
    uint8_t  ft_capable;       /* 1 if BSS advertises FT-over-Air/DS */
    uint8_t  valid;
};

struct wifi_ft_keys {
    uint16_t mdid;
    uint8_t  r0kh_id[16];
    uint8_t  r1kh_id[6];
    uint8_t  snonce[32];
    uint8_t  anonce[32];
    uint8_t  pmk_r0[32];
    uint8_t  pmk_r1[32];
    uint8_t  ptk[48];          /* KCK (16) + KEK (16) + TK (16) */
    uint8_t  valid;
};

struct wifi_ampdu_tid {
    uint16_t ssn;              /* Starting Sequence Number (12-bit mod 4096) */
    uint16_t window_size;      /* 1..WIFI_AMPDU_WINDOW_MAX */
    uint64_t bitmap[WIFI_AMPDU_BITMAP_WORDS];
    uint64_t rx_in_order;
    uint64_t rx_reordered;
    uint64_t rx_duplicates;
    uint64_t tx_aggregated;
};

struct wifi_qcc2072_ctrl {
    enum wifi_pm_state pm_state;
    uint32_t wowlan_mask;
    uint8_t  associated;
    uint8_t  current_bssid[6];
    uint16_t current_channel;
    int8_t   current_rssi_dbm;
    int8_t   roam_trigger_dbm; /* Default -72 dBm; hysteresis +8 dB */
    uint8_t  roam_hysteresis_db;
    uint16_t mobility_domain;
    struct wifi_twt_agreement twt;
    struct wifi_roam_candidate candidates[WIFI_ROAM_CANDIDATES_MAX];
    struct wifi_ft_keys ft_keys;
    struct wifi_ampdu_tid tid[8];
    uint64_t roam_count;
    uint64_t wake_events;
    uint64_t dma_validated_descriptors;
} __attribute__((aligned(64)));

enum wireless_status {
    WL_OK              = 0,
    WL_ERR_NULL        = -1,
    WL_ERR_PARAM       = -2,
    WL_ERR_STATE       = -3,
    WL_ERR_BOUNDS      = -4,
    WL_ERR_DMA_RANGE   = -5,
    WL_ERR_CRYPTO      = -6,
    WL_ERR_HANDSHAKE   = -7,
    WL_ERR_NOT_FOUND   = -8,
    WL_ERR_FORMAT      = -9,
};

int wifi_ctrl_init(struct wifi_qcc2072_ctrl *ctrl, uint16_t mdid, int8_t roam_trigger_dbm);
int wifi_ctrl_set_pm(struct wifi_qcc2072_ctrl *ctrl, enum wifi_pm_state target, uint32_t wowlan_mask);
int wifi_ctrl_configure_twt(struct wifi_qcc2072_ctrl *ctrl, uint8_t flow_id,
                            uint32_t wake_duration_us, uint64_t wake_interval_us);
int wifi_ctrl_wake_trigger(struct wifi_qcc2072_ctrl *ctrl, uint32_t wake_reason_bit);
int wifi_ctrl_validate_dma_ring(struct wifi_qcc2072_ctrl *ctrl, uint64_t ring_pa,
                                uint32_t desc_count, uint32_t desc_stride);
int wifi_ctrl_add_roam_candidate(struct wifi_qcc2072_ctrl *ctrl, const uint8_t bssid[6],
                                 uint16_t channel, int8_t rssi_dbm, int8_t snr_db,
                                 uint16_t mdid, uint8_t ft_capable);
int wifi_ft_derive_keys(struct wifi_ft_keys *keys, const uint8_t msk[32],
                        uint16_t mdid, const uint8_t r0kh_id[16], const uint8_t r1kh_id[6],
                        const uint8_t sta_mac[6], const uint8_t bssid[6],
                        const uint8_t snonce[32], const uint8_t anonce[32]);
int wifi_ctrl_evaluate_roam(struct wifi_qcc2072_ctrl *ctrl, const uint8_t msk[32],
                            const uint8_t sta_mac[6], uint8_t out_target_bssid[6]);
int wifi_ampdu_setup_tid(struct wifi_qcc2072_ctrl *ctrl, uint8_t tid, uint16_t ssn, uint16_t win_size);
int wifi_ampdu_rx_Update(struct wifi_qcc2072_ctrl *ctrl, uint8_t tid, uint16_t seq_num,
                         uint32_t *flushed_out);

/* -------------------------------------------------------------------------
 * 2. Bluetooth 5.4 Controller & Host Stack (HCI / L2CAP / SMP / AirDrop BLE)
 * ------------------------------------------------------------------------- */
#define BT_HCI_PKT_CMD              0x01u
#define BT_HCI_PKT_ACL              0x02u
#define BT_HCI_PKT_EVT              0x04u

#define BT_HCI_OP_RESET             0x0c03u
#define BT_HCI_OP_READ_LOCAL_VER    0x1001u
#define BT_HCI_OP_LE_SET_EXT_ADV    0x2036u
#define BT_HCI_OP_LE_SET_EXT_SCAN   0x2042u
#define BT_HCI_OP_LE_CREATE_CONN    0x2043u

#define BT_L2CAP_CID_ATT            0x0004u
#define BT_L2CAP_CID_LE_SIGNAL      0x0005u
#define BT_L2CAP_CID_SMP            0x0006u

#define BT_SMP_CMD_PAIRING_REQ      0x01u
#define BT_SMP_CMD_PAIRING_RSP      0x02u
#define BT_SMP_CMD_PAIRING_CONFIRM  0x03u
#define BT_SMP_CMD_PAIRING_RANDOM   0x04u
#define BT_SMP_CMD_PAIRING_FAILED   0x05u
#define BT_SMP_CMD_PUBLIC_KEY       0x0cu
#define BT_SMP_CMD_DHKEY_CHECK      0x0du

#define BT_APPLE_COMPANY_ID         0x004cu
#define BT_CONTINUITY_TYPE_AIRDROP  0x05u
#define BT_AIRDROP_HASH_COUNT       4u

enum bt_controller_state {
    BT_CTRL_OFF        = 0,
    BT_CTRL_RESETTING  = 1,
    BT_CTRL_READY      = 2,
    BT_CTRL_ADVERTISING = 3,
    BT_CTRL_CONNECTED  = 4,
};

enum bt_smp_state {
    BT_SMP_IDLE            = 0,
    BT_SMP_PAIRING_REQ_RCV = 1,
    BT_SMP_PUBLIC_KEY_EXCH = 2,
    BT_SMP_CONFIRM_EXCH    = 3,
    BT_SMP_RANDOM_EXCH     = 4,
    BT_SMP_PAIRED          = 5,
    BT_SMP_FAILED          = 6,
};

struct bt_smp_session {
    enum bt_smp_state state;
    uint8_t preq[7];
    uint8_t prsp[7];
    uint8_t local_pk[64];
    uint8_t peer_pk[64];
    uint8_t local_rand[16];
    uint8_t peer_rand[16];
    uint8_t peer_confirm[16];
    uint8_t ltk[16];
    uint8_t dhkey[32];
};

struct bt_airdrop_beacon {
    uint16_t contact_hashes[BT_AIRDROP_HASH_COUNT]; /* SHA-256 truncated 16-bit identity hashes */
    int8_t   tx_power_dbm;
    uint8_t  awdl_Trigger_channel;
};

struct bt_stack_state {
    enum bt_controller_state ctrl_state;
    uint8_t  local_bdaddr[6];
    uint8_t  ext_adv_enabled;
    uint8_t  ext_scan_enabled;
    uint16_t active_conn_handle;
    struct bt_smp_session smp;
    uint64_t hci_cmds_processed;
    uint64_t acl_frames_routed;
    uint64_t smp_handshakes_completed;
    uint64_t airdrop_beacons_decoded;
} __attribute__((aligned(64)));

int bt_stack_init(struct bt_stack_state *bt, const uint8_t bdaddr[6]);
int bt_hci_process_command(struct bt_stack_state *bt, const uint8_t *cmd_buf, size_t cmd_len,
                           uint8_t *evt_out, size_t evt_cap, size_t *evt_len_out);
int bt_l2cap_process_acl(struct bt_stack_state *bt, uint16_t conn_handle,
                         const uint8_t *l2cap_frame, size_t frame_len,
                         uint8_t *rsp_out, size_t rsp_cap, size_t *rsp_len_out);
void bt_smp_compute_confirm(const uint8_t rand16[16], const uint8_t pk_x[32],
                            const uint8_t preq[7], const uint8_t prsp[7],
                            uint8_t out_confirm[16]);
void bt_smp_compute_dhkey_check(const uint8_t dhkey[32], const uint8_t rand_local[16],
                                const uint8_t rand_peer[16], const uint8_t preq[7],
                                const uint8_t prsp[7], uint8_t out_check[16]);
int bt_airdrop_encode_ble_adv(const struct bt_airdrop_beacon *beacon,
                              uint8_t *out_adv, size_t cap, size_t *out_len);
int bt_airdrop_decode_ble_adv(struct bt_stack_state *bt, const uint8_t *adv, size_t len,
                              struct bt_airdrop_beacon *out_beacon);

/* -------------------------------------------------------------------------
 * 3. AirDrop & Apple Wireless Direct Link (AWDL) Protocol Stack
 * ------------------------------------------------------------------------- */
#define AWDL_OUI_0                  0x00u
#define AWDL_OUI_1                  0x17u
#define AWDL_OUI_2                  0xf2u
#define AWDL_VENDOR_TYPE            0x08u

#define AWDL_SUBTYPE_PSF            0x00u /* Periodic Synchronization Frame */
#define AWDL_SUBTYPE_MIF            0x03u /* Master Indication Frame */

#define AWDL_TLV_SYNC_PARAMS        0x04u
#define AWDL_TLV_ELECTION_PARAMS    0x05u
#define AWDL_TLV_CHAN_SEQ           0x06u
#define AWDL_TLV_ENHANCED_DATA_RATE 0x07u
#define AWDL_TLV_DATA_PATH_STATE    0x0cu
#define AWDL_TLV_ARPA               0x10u
#define AWDL_TLV_SERVICE_PARAMS     0x14u
#define AWDL_TLV_VERSION            0x15u

#define AWDL_CHAN_SEQ_LEN           16u
#define AWDL_MAX_PEERS              16u
#define AWDL_SOCIAL_CH_2G           6u
#define AWDL_SOCIAL_CH_5G_LOW       44u
#define AWDL_SOCIAL_CH_5G_HIGH      149u

#define AWDL_ETHERTYPE              0x8847u
#define IPV6_ETHERTYPE              0x86ddu

struct awdl_action_hdr {
    uint8_t  category;       /* 0x7f (127: Vendor-Specific) */
    uint8_t  oui[3];         /* 00:17:f2 */
    uint8_t  type;           /* 0x08 (AWDL) */
    uint8_t  version;        /* 0x10 (v1.0) */
    uint8_t  subtype;        /* AWDL_SUBTYPE_PSF or AWDL_SUBTYPE_MIF */
    uint8_t  reserved;
    uint32_t phy_tx_time;    /* Little-endian TSF microseconds */
    uint32_t target_tx_time;
} __attribute__((packed));
_Static_assert(sizeof(struct awdl_action_hdr) == 16, "AWDL action header is 16 bytes");

struct awdl_peer {
    uint8_t  mac[6];
    uint8_t  in_use;
    uint8_t  airdrop_capable;
    uint32_t master_metric;
    uint32_t self_metric;
    uint8_t  distance_to_master;
    uint8_t  top_master[6];
    uint8_t  ipv6_link_local[16]; /* fe80::... derived from EUI-64 or ARPA TLV */
    int32_t  clock_drift_us;
    uint64_t last_seen_tu;
};

struct awdl_state {
    uint8_t  self_mac[6];
    uint8_t  top_master[6];
    uint32_t self_metric;
    uint32_t top_master_metric;
    uint8_t  distance_to_master;
    uint8_t  max_tree_depth;
    uint16_t aw_period_tu;        /* Availability Window period in TU (default 16 TU) */
    uint16_t eaw_slots;           /* Extension AW slots for active AirDrop transfer */
    uint8_t  channel_seq[AWDL_CHAN_SEQ_LEN];
    uint8_t  current_slot;
    uint16_t tx_seq_num;
    struct awdl_peer peers[AWDL_MAX_PEERS];
    uint64_t psf_sent;
    uint64_t mif_sent;
    uint64_t frames_received;
    uint64_t data_bytes_transferred;
} __attribute__((aligned(64)));

int awdl_init(struct awdl_state *awdl, const uint8_t self_mac[6], uint32_t self_metric);
uint16_t awdl_current_channel(const struct awdl_state *awdl, uint64_t now_tu);
int awdl_encode_action_frame(struct awdl_state *awdl, uint8_t subtype, uint32_t phy_tx_us,
                             uint8_t *buf, size_t cap, size_t *out_len);
int awdl_parse_action_frame(struct awdl_state *awdl, const uint8_t peer_mac[6],
                            const uint8_t *buf, size_t len, uint32_t rx_timestamp_us);
void awdl_elect_master(struct awdl_state *awdl);
int awdl_encapsulate_data(struct awdl_state *awdl, const uint8_t dst_mac[6],
                          const uint8_t *ipv6_payload, size_t payload_len,
                          uint8_t *out_frame, size_t out_cap, size_t *out_len);
int awdl_decapsulate_data(struct awdl_state *awdl, const uint8_t *frame, size_t frame_len,
                          uint8_t src_mac_out[6], const uint8_t **ipv6_payload_out,
                          size_t *payload_len_out);

#endif /* SNAP_COMPAT_WIRELESS_STACK_H */
