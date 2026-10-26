/* SPDX-License-Identifier: MIT */
/*
 * Wireless Protocol & Hardware Integration Stack for Snapintosh
 * Target SoC: Qualcomm Snapdragon X2 Elite (X2E-96-100) / FastConnect 6900 (QCC2072)
 * Target OS:  macOS 27 (Tahoe, build 26A428)
 *
 * Subsystems:
 *   1. QCC2072 Wi-Fi 6E/7 WMI & macOS 26A428 WCL Scan, Association, Key & PM Bridge
 *      - Connected directly to drivers/snap-qcc2072/src/ (snap_station, native-wcl-*,
 *        qcc2072-wmi, qcc2072-scan, qcc2072-assoc, qcc2072-connect)
 *      - Emits real ath12k/QCC2072 WMI TLV commands for scan, association, key install,
 *        BMPS/IMPS/WoWLAN power save, and 802.11ax TWT dialogs
 *      - IEEE 802.11r Fast BSS Transition (FT) key hierarchy via IEEE 802.11 KDF-SHA-256
 *   2. Bluetooth 5.4 HCI / L2CAP & LE Secure Connections (SMP)
 *      - True NIST P-256 (secp256r1) ECDH key exchange with 256-bit private key scalar
 *        validation (1 <= d < n), public key generation (P = d*G), peer point on-curve
 *        verification (y^2 = x^3 - 3x + b mod p), and shared secret Z = X(d * Q_peer)
 *      - Standard Bluetooth Core Spec v5.4 Vol 3 Part H f4, f5, f6, g2 functions
 *        built on FIPS-197 AES-128 and RFC 4493 AES-128-CMAC
 *   3. AirDrop / Apple Wireless Direct Link (AWDL) & Continuity BLE Discovery
 *      - IEEE 802.11 Vendor-Specific Action Frame (OUI 00:17:F2) PSF / MIF framing
 *      - Master Election, social channel hopping (6 / 44 / 149), and EUI-64 IPv6 routing
 */
#ifndef SNAPINTOSH_WIRELESS_STACK_H
#define SNAPINTOSH_WIRELESS_STACK_H

#include <stddef.h>
#include <stdint.h>

#if defined(__has_include)
#if __has_include("native-station.h")
#include "native-station.h"
#include "native-wcl-scan.h"
#include "native-wcl-event.h"
#include "native-wcl-key.h"
#include "native-rsn.h"
#include "native-wpa2.h"
#include "qcc2072-wmi.h"
#include "qcc2072-scan.h"
#include "qcc2072-assoc.h"
#include "qcc2072-connect.h"
#else
#include "../drivers/snap-qcc2072/src/native-station.h"
#include "../drivers/snap-qcc2072/src/native-wcl-scan.h"
#include "../drivers/snap-qcc2072/src/native-wcl-event.h"
#include "../drivers/snap-qcc2072/src/native-wcl-key.h"
#include "../drivers/snap-qcc2072/src/native-rsn.h"
#include "../drivers/snap-qcc2072/src/native-wpa2.h"
#include "../drivers/snap-qcc2072/src/qcc2072-wmi.h"
#include "../drivers/snap-qcc2072/src/qcc2072-scan.h"
#include "../drivers/snap-qcc2072/src/qcc2072-assoc.h"
#include "../drivers/snap-qcc2072/src/qcc2072-connect.h"
#endif
#else
#include "../drivers/snap-qcc2072/src/native-station.h"
#include "../drivers/snap-qcc2072/src/native-wcl-scan.h"
#include "../drivers/snap-qcc2072/src/native-wcl-event.h"
#include "../drivers/snap-qcc2072/src/native-wcl-key.h"
#include "../drivers/snap-qcc2072/src/native-rsn.h"
#include "../drivers/snap-qcc2072/src/native-wpa2.h"
#include "../drivers/snap-qcc2072/src/qcc2072-wmi.h"
#include "../drivers/snap-qcc2072/src/qcc2072-scan.h"
#include "../drivers/snap-qcc2072/src/qcc2072-assoc.h"
#include "../drivers/snap-qcc2072/src/qcc2072-connect.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Common Status Codes
 * ========================================================================== */
enum wireless_status {
    WL_OK               =  0,
    WL_ERR_NULL         = -1,
    WL_ERR_INVALID      = -2,
    WL_ERR_STATE        = -3,
    WL_ERR_BOUNDS       = -4,
    WL_ERR_CRYPTO       = -5,
    WL_ERR_NOSPC        = -6,
    WL_ERR_UNSUPPORTED  = -7,
    WL_ERR_TIMEOUT      = -8
};

/* ==========================================================================
 * Standard Cryptographic Primitives (FIPS-197, RFC 4493, FIPS 180-4, P-256)
 * ========================================================================== */

void wl_aes128_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void wl_aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16]);
void wl_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);
void wl_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len, uint8_t mac[32]);
void wl_kdf_sha256(const uint8_t key[32], const char *label,
                   const uint8_t *context, size_t context_len,
                   uint8_t *out, size_t out_bits);

/* NIST P-256 (secp256r1) Elliptic Curve Diffie-Hellman (big-endian coordinates) */
int bt_p256_valid_private_key(const uint8_t private_key[32]);
int bt_p256_valid_public_key(const uint8_t public_key[64]);
int bt_p256_public_key(const uint8_t private_key[32], uint8_t public_key[64]);
int bt_p256_ecdh(const uint8_t private_key[32], const uint8_t peer_public_key[64],
                 uint8_t dhkey[32]);

/* Bluetooth Core Spec v5.4 Vol 3 Part H Section 2.2 Cryptographic Toolbox */
int bt_smp_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
              uint8_t z, uint8_t out[16]);
int bt_smp_f5(const uint8_t w[32], const uint8_t n1[16], const uint8_t n2[16],
              const uint8_t a1[7], const uint8_t a2[7],
              uint8_t mac_key[16], uint8_t ltk[16]);
int bt_smp_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
              const uint8_t r[16], const uint8_t iocap[3],
              const uint8_t a1[7], const uint8_t a2[7], uint8_t out[16]);
int bt_smp_g2(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
              const uint8_t y[16], uint32_t *out_passkey);

/* ==========================================================================
 * 1. QCC2072 Wi-Fi Power Management, Fast Roaming & macOS WCL Driver Bridge
 * ========================================================================== */

enum wifi_pm_state {
    WIFI_PM_UNINIT       = 0,
    WIFI_PM_ACTIVE       = 1, /* Full MIMO active (HE-MCS11 / EHT, 0 ms wake latency) */
    WIFI_PM_BMPS         = 2, /* Beacon Mode Power Save (DTIM1/DTIM3 + Target Wake Time) */
    WIFI_PM_IMPS         = 3, /* Idle Mode Power Save (unassociated PLL/RF gated) */
    WIFI_PM_WOWLAN_D3HOT = 4, /* PCIe L1.2 + D3hot with ARP/NS/Wake-packet offload */
    WIFI_PM_D3COLD       = 5  /* Deep suspend, state retained in host carveout */
};

/* QCC2072 WMI command IDs for scan stop, power management, and 802.11ax TWT */
#define WIFI_WMI_STOP_SCAN_CMDID        0x3002U
#define WIFI_WMI_PDEV_SET_PARAM_CMDID   0x4003U
#define WIFI_WMI_VDEV_SET_PARAM_CMDID   0x5008U
#define WIFI_WMI_STA_PS_MODE_CMDID      0x9001U
#define WIFI_WMI_STA_PS_PARAM_CMDID     0x9002U
#define WIFI_WMI_TWT_ENABLE_CMDID       0x3e001U
#define WIFI_WMI_TWT_ADD_DIALOG_CMDID   0x3e003U

/* macOS 26A428 WCL link-state notification messages (IO80211InfraProtocol::postMessage) */
#define SNAP_WCL_EVENT_LINK_CHANGED     0x01U
#define SNAP_WCL_EVENT_BSSID_CHANGED    0x03U
#define SNAP_WCL_EVENT_ASSOC_DONE       0x08U
#define SNAP_WCL_EVENT_LINK_BYTES       16U
#define SNAP_WCL_ASSOC_26A428_BYTES     0x268U

/* IEEE 802.11ax Target Wake Time (TWT) negotiation parameters */
struct wifi_twt_config {
    uint8_t  dialog_id;
    uint8_t  wake_duration_unit;    /* 0 = 256 us, 1 = 1024 us (1 TU) */
    uint8_t  min_wake_duration;     /* In units of wake_duration_unit */
    uint8_t  negotiation_type;      /* 0 = Individual TWT, 1 = Broadcast TWT */
    uint16_t wake_interval_mantissa;
    uint8_t  wake_interval_exp;     /* Wake interval = mantissa * (2 ^ exp) us */
    uint8_t  implicit_twt;
    uint8_t  unannounced;           /* Unannounced TWT (reduces PS-Poll overhead) */
    uint8_t  trigger_enabled;       /* Trigger-enabled TWT (UL OFDMA trigger frames) */
    uint16_t reserved;
    uint64_t target_wake_time_tsf;  /* Agreed initial TSF wake point */
    uint64_t wake_interval_us;      /* Computed interval in microseconds */
};

/* IEEE 802.11k/v/r Fast BSS Transition (FT) roaming context */
#define WIFI_FT_MOBILITY_DOMAIN_LEN 2
#define WIFI_FT_R0KH_ID_MAX_LEN     48
#define WIFI_FT_R1KH_ID_LEN         6
#define WIFI_FT_PMK_LEN             32
#define WIFI_FT_PTK_LEN             48 /* KCK (16B) + KEK (16B) + TK (16B) */

struct wifi_bss_candidate {
    uint8_t  bssid[6];
    uint16_t channel_mhz;
    int8_t   rssi_dbm;
    int8_t   snr_db;
    uint8_t  channel_utilization; /* 0..255 from 802.11k Beacon Report / QBSS Load */
    uint8_t  he_mcs_max;          /* 0..11 (HE-MCS11) */
    uint16_t beacon_interval_tu;
    uint8_t  ft_supported;        /* Advertises MDIE + FTIE */
    uint8_t  mobility_domain[WIFI_FT_MOBILITY_DOMAIN_LEN];
    uint8_t  r1kh_id[WIFI_FT_R1KH_ID_LEN];
};

struct wifi_ft_roam_ctx {
    uint8_t  mobility_domain[WIFI_FT_MOBILITY_DOMAIN_LEN];
    uint8_t  r0kh_id[WIFI_FT_R0KH_ID_MAX_LEN];
    uint8_t  r0kh_id_len;
    uint8_t  r1kh_id[WIFI_FT_R1KH_ID_LEN];
    uint8_t  sta_mac[6];
    uint8_t  current_bssid[6];
    uint8_t  target_bssid[6];
    uint8_t  snonce[32];
    uint8_t  anonce[32];
    uint8_t  xxkey[32];           /* Master key from 802.1X / SAE */
    uint8_t  pmk_r0[WIFI_FT_PMK_LEN];
    uint8_t  pmk_r0_name[16];
    uint8_t  pmk_r1[WIFI_FT_PMK_LEN];
    uint8_t  pmk_r1_name[16];
    uint8_t  ptk[WIFI_FT_PTK_LEN];
    uint32_t roam_count;
    uint8_t  keys_derived;
};

/* High-throughput A-MPDU / BlockAck Tx/Rx aggregation ring state */
#define WIFI_AMPDU_MAX_SUBFRAMES 64
#define WIFI_AMPDU_MAX_BYTES     262144U /* 256 KiB per A-MPDU burst */

struct wifi_ampdu_subframe {
    uint64_t payload_iova;
    uint16_t length;
    uint16_t seq_num;       /* 12-bit 802.11 sequence number (0..4095) */
    uint8_t  tid;           /* Traffic Identifier (0..7, e.g. TID 5=VI, TID 6=VO) */
    uint8_t  flags;         /* Bit 0: QoS, Bit 1: AMSDU-in-AMPDU, Bit 2: EOSP */
    uint16_t delimiter_crc;
};

struct wifi_ampdu_aggregator {
    uint8_t  tid;
    uint8_t  subframe_count;
    uint16_t ssn;           /* BlockAck Starting Sequence Number */
    uint16_t next_seq;
    uint16_t window_size;   /* Up to 64 (802.11n/ac) or 256 (802.11ax) */
    uint32_t total_bytes;
    uint64_t block_ack_bitmap;
    uint64_t bursts_flushed;
    uint64_t bytes_transmitted;
    struct wifi_ampdu_subframe subframes[WIFI_AMPDU_MAX_SUBFRAMES];
};

#define WIFI_WMI_QUEUE_DEPTH 32
#define WIFI_WCL_QUEUE_DEPTH 16

struct wifi_wcl_queued_event {
    uint32_t message;
    uint16_t bytes;
    uint8_t  payload[SNAP_WCL_EVENT_MAX_BYTES];
};

/* Unified QCC2072 Wi-Fi controller state connected to snap_station & QCC2072 WMI/assoc */
struct wifi_qcc2072_ctrl {
    uint32_t magic;
    enum wifi_pm_state pm_state;
    uint8_t  sta_mac[6];
    uint8_t  dtim_period;         /* 1..10 (default 3 in BMPS) */
    uint8_t  listen_interval_beacons;
    uint16_t current_channel_mhz;
    int8_t   current_rssi_dbm;
    int8_t   roam_trigger_rssi_dbm; /* Default -72 dBm */
    uint32_t inactivity_timeout_ms;
    uint32_t idle_elapsed_ms;
    uint32_t wowlan_wake_triggers;  /* Bitmask: MagicPacket=1, ARP=2, NS=4, AWDL=8 */
    uint64_t stage2_bar_gpa;
    uint64_t stage2_dma_gpa;
    struct wifi_twt_config twt;
    struct wifi_ft_roam_ctx ft;
    struct wifi_ampdu_aggregator tx_agg;

    /* Real QCC2072 driver & macOS WCL station state machines */
    struct snap_station station;
    struct qcc2072_wmi wmi;
    struct qcc2072_assoc assoc;
    struct qcc2072_connect connect;
    uint8_t  assoc_mgmt_arena[QCC2072_ASSOC_MGMT_DMA_BYTES] __attribute__((aligned(16)));
    struct qcc2072_dma_buffer assoc_mgmt_buf;
    struct snap_station_bss bss_cache[32];
    struct snap_station_request active_scan_req;
    struct qcc2072_assoc_connect_args connect_args;
    uint64_t session_generation;
    uint64_t owner_cookie;
    uint64_t now_ms;
    uint64_t next_transaction;
    uint64_t scan_transaction;
    uint64_t assoc_transaction;
    uint8_t  scan_stage;
    uint8_t  chan_list_sent;
    uint8_t  vdev_created;
    uint8_t  station_admitted;
    uint32_t chan_list_revision;
    uint64_t scan_deadline_ms;

    /* Outgoing WMI TLV command queue & last emitted command */
    uint8_t  wmi_tx_queue[WIFI_WMI_QUEUE_DEPTH][2040];
    uint16_t wmi_tx_len[WIFI_WMI_QUEUE_DEPTH];
    uint8_t  wmi_tx_head;
    uint8_t  wmi_tx_tail;
    uint8_t  wmi_tx_count;
    uint32_t last_wmi_cmd_id;
    uint8_t  last_wmi_cmd[2040];
    size_t   last_wmi_cmd_len;

    /* Outgoing macOS 26A428 WCL postMessage queue (0xc9, 0xed, 0x08, 0x03, 0x01) */
    struct wifi_wcl_queued_event wcl_queue[WIFI_WCL_QUEUE_DEPTH];
    uint8_t  wcl_head;
    uint8_t  wcl_tail;
    uint8_t  wcl_count;
};

#define WIFI_QCC2072_MAGIC 0x51433230U /* 'QC20' */

int wifi_ctrl_init(struct wifi_qcc2072_ctrl *ctrl, const uint8_t sta_mac[6]);
int wifi_ctrl_validate_stage2_window(const struct wifi_qcc2072_ctrl *ctrl,
                                     uint64_t ring_iova, size_t ring_bytes);
int wifi_ctrl_set_pm(struct wifi_qcc2072_ctrl *ctrl, enum wifi_pm_state target_state);
int wifi_ctrl_tick_idle(struct wifi_qcc2072_ctrl *ctrl, uint32_t elapsed_ms, int has_traffic);
int wifi_ctrl_negotiate_twt(struct wifi_qcc2072_ctrl *ctrl, uint8_t dialog_id,
                            uint16_t mantissa, uint8_t exp, uint8_t min_wake_dur,
                            uint64_t current_tsf);

int wifi_ft_derive_keys(struct wifi_ft_roam_ctx *ft);
int wifi_ctrl_select_roam_candidate(const struct wifi_qcc2072_ctrl *ctrl,
                                    const struct wifi_bss_candidate *candidates,
                                    size_t count,
                                    struct wifi_bss_candidate *best_out);
int wifi_ctrl_roam_ft(struct wifi_qcc2072_ctrl *ctrl,
                      const struct wifi_bss_candidate *target,
                      const uint8_t anonce[32], const uint8_t snonce[32]);

int wifi_ampdu_push(struct wifi_ampdu_aggregator *agg, uint64_t payload_iova,
                    uint16_t length, uint8_t qos_flags);
int wifi_ampdu_flush(struct wifi_ampdu_aggregator *agg, uint32_t *out_subframes,
                     uint32_t *out_bytes);
int wifi_ampdu_ack_bitmap(struct wifi_ampdu_aggregator *agg, uint16_t ssn,
                          uint64_t bitmap, uint32_t *out_acked);

/* QCC2072 WMI & macOS 26A428 WCL Scan + Association Bridge API */
size_t qcc2072_scan_stop(uint8_t *out, size_t cap, uint32_t vdev_id,
                         uint32_t scan_id, uint32_t req_id);
size_t qcc2072_wmi_twt_enable(uint8_t *out, size_t cap, uint32_t pdev_id);
size_t qcc2072_wmi_twt_add_dialog(uint8_t *out, size_t cap, uint32_t vdev_id,
                                  const uint8_t peer_mac[6],
                                  const struct wifi_twt_config *twt);

int snap_wcl_assoc_submit(struct snap_station *station, const void *request,
                          size_t bytes, uint64_t *next_transaction,
                          const struct snap_station_bss *bss_cache,
                          unsigned bss_capacity);
int snap_wcl_leave_submit(struct snap_station *station, uint16_t reason,
                          uint64_t *next_transaction);
int snap_wcl_event_link_encode(const struct snap_station *station,
                               const struct snap_station_event *event,
                               uint8_t *out, size_t capacity,
                               uint32_t *message, size_t *bytes);

int wifi_qcc2072_admit_wmi(struct wifi_qcc2072_ctrl *ctrl, const uint8_t *ev,
                           size_t len, uint64_t now_ms);
int wifi_qcc2072_htt_event(struct wifi_qcc2072_ctrl *ctrl, const uint8_t *ev,
                           size_t len, uint64_t now_ms);
int wifi_qcc2072_wcl_scan_req(struct wifi_qcc2072_ctrl *ctrl, const void *wcl_req,
                              size_t bytes, uint64_t now_ms);
int wifi_qcc2072_wcl_scan_abort(struct wifi_qcc2072_ctrl *ctrl, uint64_t now_ms);
int wifi_qcc2072_wcl_associate(struct wifi_qcc2072_ctrl *ctrl, const void *wcl_assoc,
                               size_t bytes, const uint8_t pmk[32], uint64_t now_ms);
int wifi_qcc2072_wcl_cipher_key(struct wifi_qcc2072_ctrl *ctrl, const void *wcl_key,
                                size_t bytes, uint64_t now_ms);
int wifi_qcc2072_wcl_leave(struct wifi_qcc2072_ctrl *ctrl, uint16_t reason,
                           uint64_t now_ms);
int wifi_qcc2072_poll(struct wifi_qcc2072_ctrl *ctrl, uint64_t now_ms);
size_t wifi_qcc2072_pop_wmi_tx(struct wifi_qcc2072_ctrl *ctrl, uint8_t *out,
                               size_t cap, uint32_t *cmd_id);
int wifi_qcc2072_pop_wcl_event(struct wifi_qcc2072_ctrl *ctrl, uint32_t *message,
                               uint8_t *out, size_t cap, size_t *bytes);

/* ==========================================================================
 * 2. Bluetooth 5.4 HCI / L2CAP & LE Secure Connections (SMP)
 * ========================================================================== */

/* HCI Packet Indicators (UART H4 / USB / PCIe BT transport) */
#define BT_HCI_PKT_CMD              0x01
#define BT_HCI_PKT_ACL              0x02
#define BT_HCI_PKT_SCO              0x03
#define BT_HCI_PKT_EVENT            0x04
#define BT_HCI_PKT_ISO              0x05 /* Bluetooth 5.2+ LE Audio Isochronous */

/* Standard HCI Opcodes (OGF << 10 | OCF) */
#define BT_HCI_OP_RESET                     0x0C03
#define BT_HCI_OP_READ_LOCAL_VERSION        0x1001
#define BT_HCI_OP_READ_BD_ADDR              0x1009
#define BT_HCI_OP_LE_SET_EXT_ADV_PARAMS     0x2036
#define BT_HCI_OP_LE_SET_EXT_ADV_DATA       0x2037
#define BT_HCI_OP_LE_SET_EXT_ADV_ENABLE     0x2039
#define BT_HCI_OP_LE_SET_EXT_SCAN_PARAMS    0x2041
#define BT_HCI_OP_LE_SET_EXT_SCAN_ENABLE    0x2042
#define BT_HCI_OP_LE_EXT_CREATE_CONN        0x2043

/* HCI Event Codes */
#define BT_HCI_EVT_CMD_COMPLETE             0x0E
#define BT_HCI_EVT_CMD_STATUS               0x0F
#define BT_HCI_EVT_LE_META                  0x3E
#define BT_HCI_LE_META_CONN_COMPLETE        0x01
#define BT_HCI_LE_META_EXT_ADV_REPORT       0x0D

/* L2CAP Fixed CIDs */
#define BT_L2CAP_CID_ATT                    0x0004
#define BT_L2CAP_CID_LE_SIGNALING           0x0005
#define BT_L2CAP_CID_SMP                    0x0006

/* Bluetooth SMP Command Codes (Core Spec v5.4 Vol 3 Part H) */
#define BT_SMP_CMD_PAIRING_REQ              0x01
#define BT_SMP_CMD_PAIRING_RSP              0x02
#define BT_SMP_CMD_PAIRING_CONFIRM          0x03
#define BT_SMP_CMD_PAIRING_RANDOM           0x04
#define BT_SMP_CMD_PAIRING_FAILED           0x05
#define BT_SMP_CMD_PUBLIC_KEY               0x0C
#define BT_SMP_CMD_DHKEY_CHECK              0x0D

/* SMP AuthReq Flags */
#define BT_SMP_AUTH_BONDING                 0x01
#define BT_SMP_AUTH_MITM                    0x04
#define BT_SMP_AUTH_SC                      0x08 /* LE Secure Connections */
#define BT_SMP_AUTH_KEYPRESS                0x10
#define BT_SMP_AUTH_CT2                     0x20 /* H7 Cross-Transport Key Derivation */

enum bt_smp_state {
    BT_SMP_STATE_IDLE               = 0,
    BT_SMP_STATE_WAIT_RSP           = 1,
    BT_SMP_STATE_WAIT_PUBKEY        = 2,
    BT_SMP_STATE_WAIT_CONFIRM       = 3,
    BT_SMP_STATE_WAIT_RANDOM        = 4,
    BT_SMP_STATE_WAIT_DHKEY_CHECK   = 5,
    BT_SMP_STATE_PAIRED             = 6,
    BT_SMP_STATE_FAILED             = 7
};

struct bt_smp_session {
    enum bt_smp_state state;
    uint8_t  is_initiator;
    uint8_t  io_cap;
    uint8_t  auth_req;
    uint8_t  max_key_size;      /* Must be 16 for LE Secure Connections */
    uint8_t  preq[7];           /* Pairing Request PDU bytes */
    uint8_t  prsp[7];           /* Pairing Response PDU bytes */
    uint8_t  local_addr[7];     /* AddrType (1B) || BD_ADDR (6B, big-endian) */
    uint8_t  peer_addr[7];      /* AddrType (1B) || BD_ADDR (6B, big-endian) */
    uint8_t  local_sk[32];      /* Secret P-256 private scalar d (1 <= d < n) */
    uint8_t  has_private_key;   /* 1 while local_sk holds a valid P-256 scalar */
    uint8_t  local_pk[64];      /* P-256 Public Key (X: 32B, Y: 32B), P = d * G */
    uint8_t  peer_pk[64];       /* Peer P-256 Public Key (validated on curve) */
    uint8_t  local_rand[16];    /* Local 128-bit nonce (Na / Nb) */
    uint8_t  peer_rand[16];     /* Peer 128-bit nonce (Nb / Na) */
    uint8_t  peer_confirm[16];  /* Received Ca / Cb */
    uint8_t  dhkey[32];         /* ECDH shared secret Z = X(local_sk * peer_pk) */
    uint8_t  mac_key[16];       /* Derived 128-bit MacKey from f5 */
    uint8_t  ltk[16];           /* Derived 128-bit Long Term Key from f5 */
    uint32_t numeric_passkey;   /* 6-digit passkey from g2 (000000..999999) */
};

/* Apple Continuity BLE Advertisement (Company ID 0x004C) for AirDrop */
#define APPLE_BLE_COMPANY_ID        0x004C
#define APPLE_CONT_TYPE_AIRDROP     0x05
#define APPLE_CONT_AIRDROP_LEN      18

struct apple_ble_airdrop_adv {
    uint8_t  zeros[8];
    uint8_t  airdrop_version;
    uint16_t hash_apple_id;
    uint16_t hash_phone;
    uint16_t hash_email;
    uint16_t hash_icloud;
    uint8_t  zero_pad;
};

struct bt_stack_state {
    uint32_t magic;
    uint8_t  controller_ready;
    uint8_t  local_bdaddr[6];
    uint8_t  le_ext_adv_enabled;
    uint8_t  le_ext_scan_enabled;
    uint16_t active_conn_handle;
    uint8_t  peer_bdaddr[6];
    uint8_t  peer_addr_type;
    struct bt_smp_session smp;
    uint32_t hci_cmd_count;
    uint32_t hci_evt_count;
};

#define BT_STACK_MAGIC 0x42543534U /* 'BT54' */

int bt_stack_init(struct bt_stack_state *bt, const uint8_t bdaddr[6]);
int bt_hci_build_cmd(uint16_t opcode, const uint8_t *params, uint8_t param_len,
                     uint8_t *out_buf, size_t out_cap, size_t *out_len);
int bt_hci_process_cmd_GenerateEvt(struct bt_stack_state *bt,
                                   const uint8_t *cmd_pkt, size_t cmd_len,
                                   uint8_t *evt_buf, size_t evt_cap, size_t *evt_len);
int bt_hci_inject_le_conn_complete(struct bt_stack_state *bt, uint16_t handle,
                                   const uint8_t peer_bdaddr[6]);

int bt_smp_set_local_keypair(struct bt_stack_state *bt,
                             const uint8_t private_key[32],
                             const uint8_t random_nonce[16]);
int bt_smp_start_pairing(struct bt_stack_state *bt, int is_initiator,
                         uint8_t *out_l2cap, size_t out_cap, size_t *out_len);
int bt_smp_step(struct bt_stack_state *bt,
                const uint8_t *in_l2cap, size_t in_len,
                uint8_t *out_l2cap, size_t out_cap, size_t *out_len);
void bt_smp_compute_confirm(const uint8_t pk_initiator[64],
                            const uint8_t pk_responder[64],
                            const uint8_t rand_val[16],
                            uint8_t z, uint8_t out_confirm[16]);
void bt_smp_compute_dhkey_check(const uint8_t mac_key[16],
                                const uint8_t n1[16], const uint8_t n2[16],
                                const uint8_t r[16], const uint8_t iocap[3],
                                const uint8_t a1[7], const uint8_t a2[7],
                                uint8_t out_check[16]);

int bt_encode_airdrop_ble_adv(const struct apple_ble_airdrop_adv *adv,
                              uint8_t *out_buf, size_t out_cap, size_t *out_len);
int bt_decode_airdrop_ble_adv(const uint8_t *in_buf, size_t in_len,
                              struct apple_ble_airdrop_adv *out_adv);

/* ==========================================================================
 * 3. AirDrop / Apple Wireless Direct Link (AWDL) Protocol Stack
 * ========================================================================== */

#define AWDL_OUI_0                  0x00
#define AWDL_OUI_1                  0x17
#define AWDL_OUI_2                  0xF2
#define AWDL_VENDOR_TYPE            0x08
#define AWDL_VERSION                0x10 /* v1.0 */

/* AWDL Action Frame Subtypes */
#define AWDL_FRAME_PSF              0x00 /* Periodic Synchronization Frame */
#define AWDL_FRAME_MIF              0x03 /* Master Indication Frame */

/* AWDL TLV Types */
#define AWDL_TLV_SYNC_PARAMS        0x04
#define AWDL_TLV_ELECTION_PARAMS    0x05
#define AWDL_TLV_CHAN_SEQ           0x06
#define AWDL_TLV_ENHANCED_DATA_RATE 0x09
#define AWDL_TLV_DATA_PATH_STATE    0x0C
#define AWDL_TLV_ARPA               0x10
#define AWDL_TLV_VERSION            0x15

/* AWDL Social Channels (2.4 GHz Ch 6, 5 GHz Ch 44 UNII-1, 5 GHz Ch 149 UNII-3) */
#define AWDL_CHAN_SOCIAL_24G        6
#define AWDL_CHAN_SOCIAL_5G_LOW     44
#define AWDL_CHAN_SOCIAL_5G_HIGH    149
#define AWDL_CHAN_SEQ_LEN           16
#define AWDL_AW_PERIOD_TU           16  /* 16 TU = 16.384 ms Availability Window */
#define AWDL_MAX_PEERS              16

struct awdl_peer {
    uint8_t  valid;
    uint8_t  mac[6];
    uint8_t  distance_to_master;
    uint16_t master_metric;
    uint16_t self_metric;
    uint8_t  master_mac[6];
    uint8_t  ipv6_link_local[16]; /* fe80::/64 derived from AWDL virtual MAC */
    int8_t   rssi_dbm;
    uint32_t last_seen_tu;
};

struct awdl_state {
    uint32_t magic;
    uint8_t  self_mac[6];
    uint8_t  bssid[6];            /* Fixed AWDL BSSID: 00:25:00:ff:94:73 */
    uint8_t  master_mac[6];
    uint8_t  top_master_mac[6];
    uint8_t  is_master;
    uint8_t  distance_to_master;  /* 0 if self is master */
    uint16_t self_metric;         /* Election metric (higher wins, tie-break by MAC) */
    uint16_t master_metric;
    uint16_t aw_seq_number;
    uint16_t aw_period_tu;        /* 16 TU */
    uint16_t presence_mode;       /* 4 = extension factor */
    uint8_t  current_step;        /* 0..15 in channel sequence */
    uint8_t  channel_seq[AWDL_CHAN_SEQ_LEN];
    uint8_t  self_ipv6[16];       /* fe80::... link-local IPv6 for AirDrop HTTPS */
    uint32_t tx_action_frames;
    uint32_t rx_action_frames;
    uint32_t tx_data_frames;
    uint32_t rx_data_frames;
    struct awdl_peer peers[AWDL_MAX_PEERS];
};

#define AWDL_STATE_MAGIC 0x4157444CU /* 'AWDL' */

int awdl_init(struct awdl_state *awdl, const uint8_t self_mac[6], uint16_t self_metric);
void awdl_derive_ipv6_link_local(const uint8_t mac[6], uint8_t ipv6_out[16]);
uint8_t awdl_step_channel(struct awdl_state *awdl, uint16_t advance_aw_slots);

int awdl_encode_action_frame(struct awdl_state *awdl, uint8_t subtype,
                             uint8_t *out_buf, size_t out_cap, size_t *out_len);
int awdl_process_action_frame(struct awdl_state *awdl,
                              const uint8_t *frame, size_t frame_len,
                              int8_t rssi_dbm, uint32_t now_tu);
void awdl_run_election(struct awdl_state *awdl);

int awdl_encode_data_frame(struct awdl_state *awdl,
                           const uint8_t dst_mac[6],
                           const uint8_t *payload, size_t payload_len,
                           uint16_t seq_num,
                           uint8_t *out_buf, size_t out_cap, size_t *out_len);
int awdl_decode_data_frame(struct awdl_state *awdl,
                           const uint8_t *frame, size_t frame_len,
                           uint8_t src_mac_out[6],
                           uint8_t src_ipv6_out[16],
                           const uint8_t **payload_out, size_t *payload_len_out);

#ifdef __cplusplus
}
#endif

#endif /* SNAPINTOSH_WIRELESS_STACK_H */
