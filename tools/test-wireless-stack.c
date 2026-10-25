/* SPDX-License-Identifier: MIT
 * Unit and integration test suite for the Snapintosh Wireless Stack:
 *   1. QCC2072 Wi-Fi Power Management, TWT, WoWLAN, 802.11r Fast Roaming, A-MPDU
 *   2. Bluetooth 5.4 HCI, L2CAP, LE Secure Connections SMP, AirDrop BLE Beacons
 *   3. AirDrop Apple Wireless Direct Link (AWDL) Sync, Election, Hopping & Data
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *    -Icompat -Ishadow tools/test-wireless-stack.c compat/wireless-stack.c -o build/test-wireless-stack
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wireless-stack.h"

static unsigned g_checks = 0;

#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_wifi_pm_roaming_and_ampdu(void)
{
    struct wifi_qcc2072_ctrl wifi;
    CHECK(wifi_ctrl_init(NULL, 0x4142, -72) == WL_ERR_PARAM);
    CHECK(wifi_ctrl_init(&wifi, 0x4142, -10) == WL_ERR_PARAM);
    CHECK(wifi_ctrl_init(&wifi, 0x4142, -72) == WL_OK);
    CHECK(wifi.pm_state == WIFI_PM_ACTIVE);

    /* Unassociated BMPS/WoWLAN transitions must fail closed */
    CHECK(wifi_ctrl_set_pm(&wifi, WIFI_PM_BMPS, 0) == WL_ERR_STATE);
    CHECK(wifi_ctrl_set_pm(&wifi, WIFI_PM_IMPS, 0) == WL_OK);
    CHECK(wifi.pm_state == WIFI_PM_IMPS);

    /* Simulate association to initial BSS */
    wifi.associated = 1;
    const uint8_t bss1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x01};
    memcpy(wifi.current_bssid, bss1, 6);
    wifi.current_channel = 44;
    wifi.current_rssi_dbm = -55;

    /* TWT negotiation & WoWLAN D3hot wake filter transitions */
    CHECK(wifi_ctrl_configure_twt(&wifi, 0, 8192, 65536) == WL_OK);
    CHECK(wifi.twt.enabled == 1 && wifi.twt.wake_duration_us == 8192);
    CHECK(wifi_ctrl_set_pm(&wifi, WIFI_PM_WOWLAN_D3HOT, 0) == WL_ERR_PARAM);
    CHECK(wifi_ctrl_set_pm(&wifi, WIFI_PM_WOWLAN_D3HOT,
                           WIFI_WOWLAN_WAKE_MAGIC_PKT | WIFI_WOWLAN_WAKE_AWDL_SYNC) == WL_OK);
    /* Masked wake reason must not wake the radio */
    CHECK(wifi_ctrl_wake_trigger(&wifi, WIFI_WOWLAN_WAKE_ARP_NS) == WL_ERR_STATE);
    /* Enabled AWDL wake reason transitions cleanly back to ACTIVE */
    CHECK(wifi_ctrl_wake_trigger(&wifi, WIFI_WOWLAN_WAKE_AWDL_SYNC) == WL_OK);
    CHECK(wifi.pm_state == WIFI_PM_ACTIVE && wifi.wake_events == 1);

    /* Stage-2 DMA ring validation within QCC2072_WIFI_DMA_PA (0xdc000000..0xe0000000) */
    CHECK(wifi_ctrl_validate_dma_ring(&wifi, QCC2072_WIFI_DMA_PA, 512, 32) == WL_OK);
    CHECK(wifi_ctrl_validate_dma_ring(&wifi, QCC2072_WIFI_DMA_PA - 0x1000, 512, 32) == WL_ERR_DMA_RANGE);
    CHECK(wifi_ctrl_validate_dma_ring(&wifi, QCC2072_WIFI_DMA_PA + QCC2072_WIFI_DMA_BYTES - 64,
                                      16, 32) == WL_ERR_DMA_RANGE);

    /* IEEE 802.11k/v/r Fast BSS Transition (FT) Roaming */
    const uint8_t bss2[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x02};
    const uint8_t bss3[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x03};
    const uint8_t sta[6]  = {0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5};
    uint8_t msk[32];
    memcpy(msk, "0123456789abcdef0123456789abcdef", 32);
    uint8_t roamed_to[6] = {0};

    CHECK(wifi_ctrl_add_roam_candidate(&wifi, bss2, 149, -68, 25, 0x4142, 1) == WL_OK);
    CHECK(wifi_ctrl_add_roam_candidate(&wifi, bss3, 149, -52, 32, 0x4142, 1) == WL_OK);

    /* While RSSI (-55 dBm) > trigger (-72 dBm), do not roam */
    CHECK(wifi_ctrl_evaluate_roam(&wifi, msk, sta, roamed_to) == WL_ERR_NOT_FOUND);

    /* Drop RSSI to -76 dBm: should select bss3 (-52 dBm, highest SNR) and derive FT keys */
    wifi.current_rssi_dbm = -76;
    CHECK(wifi_ctrl_evaluate_roam(&wifi, msk, sta, roamed_to) == WL_OK);
    CHECK(memcmp(roamed_to, bss3, 6) == 0);
    CHECK(wifi.current_channel == 149 && wifi.roam_count == 1 && wifi.ft_keys.valid == 1);

    /* High-Throughput A-MPDU BlockAck Reorder Window */
    uint32_t flushed = 0;
    CHECK(wifi_ampdu_setup_tid(&wifi, 0, 100, 64) == WL_OK);
    /* Receive out-of-order frames 101 and 102 before 100 */
    CHECK(wifi_ampdu_rx_Update(&wifi, 0, 101, &flushed) == WL_OK && flushed == 0);
    CHECK(wifi_ampdu_rx_Update(&wifi, 0, 102, &flushed) == WL_OK && flushed == 0);
    /* Duplicate 101 must be counted and not flush */
    CHECK(wifi_ampdu_rx_Update(&wifi, 0, 101, &flushed) == WL_OK && flushed == 0);
    CHECK(wifi.tid[0].rx_duplicates == 1);
    /* Now frame 100 arrives: flushes 100, 101, 102 in order */
    CHECK(wifi_ampdu_rx_Update(&wifi, 0, 100, &flushed) == WL_OK && flushed == 3);
    CHECK(wifi.tid[0].ssn == 103);
}

static void test_bluetooth_hci_smp_and_airdrop_ble(void)
{
    struct bt_stack_state bt;
    const uint8_t bdaddr[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    CHECK(bt_stack_init(&bt, bdaddr) == WL_OK);

    uint8_t evt[32];
    size_t evt_len = 0;

    /* Commands before HCI_Reset must fail closed */
    const uint8_t read_ver_cmd[] = {BT_HCI_PKT_CMD, 0x01, 0x10, 0x00};
    CHECK(bt_hci_process_command(&bt, read_ver_cmd, sizeof(read_ver_cmd), evt, sizeof(evt), &evt_len) == WL_ERR_STATE);

    /* HCI_Reset */
    const uint8_t reset_cmd[] = {BT_HCI_PKT_CMD, 0x03, 0x0c, 0x00};
    CHECK(bt_hci_process_command(&bt, reset_cmd, sizeof(reset_cmd), evt, sizeof(evt), &evt_len) == WL_OK);
    CHECK(bt.ctrl_state == BT_CTRL_READY && evt_len == 7 && evt[6] == 0x00);

    /* HCI_Read_Local_Version_Information -> Bluetooth 5.4 (0x0d), QCC2072 (0x2072) */
    CHECK(bt_hci_process_command(&bt, read_ver_cmd, sizeof(read_ver_cmd), evt, sizeof(evt), &evt_len) == WL_OK);
    CHECK(evt_len == 15 && evt[7] == 0x0d && evt[13] == 0x72 && evt[14] == 0x20);

    /* Enable LE Extended Advertising & Scanning + Create Connection */
    const uint8_t adv_cmd[]  = {BT_HCI_PKT_CMD, 0x36, 0x20, 0x01, 0x01};
    const uint8_t scan_cmd[] = {BT_HCI_PKT_CMD, 0x42, 0x20, 0x02, 0x01, 0x00};
    const uint8_t conn_cmd[] = {BT_HCI_PKT_CMD, 0x43, 0x20, 0x06, 1, 2, 3, 4, 5, 6};
    CHECK(bt_hci_process_command(&bt, adv_cmd, sizeof(adv_cmd), evt, sizeof(evt), &evt_len) == WL_OK);
    CHECK(bt.ctrl_state == BT_CTRL_ADVERTISING);
    CHECK(bt_hci_process_command(&bt, scan_cmd, sizeof(scan_cmd), evt, sizeof(evt), &evt_len) == WL_OK);
    CHECK(bt_hci_process_command(&bt, conn_cmd, sizeof(conn_cmd), evt, sizeof(evt), &evt_len) == WL_OK);
    CHECK(bt.ctrl_state == BT_CTRL_CONNECTED && bt.active_conn_handle == 0x0040);

    /* Complete LE Secure Connections SMP Pairing Handshake without errors */
    uint8_t rsp[128];
    size_t rsp_len = 0;

    /* Step 1: Pairing Request (SC=1, key_size=16) */
    const uint8_t preq_frame[] = {
        7, 0, 0x06, 0x00, /* L2CAP len=7, CID=0x0006 (SMP) */
        BT_SMP_CMD_PAIRING_REQ, 0x04, 0x00, 0x0d, 16, 0x07, 0x07
    };
    CHECK(bt_l2cap_process_acl(&bt, 0x0040, preq_frame, sizeof(preq_frame), rsp, sizeof(rsp), &rsp_len) == WL_OK);
    CHECK(rsp_len == 11 && rsp[4] == BT_SMP_CMD_PAIRING_RSP && bt.smp.state == BT_SMP_PAIRING_REQ_RCV);

    /* Step 2: Public Key Exchange */
    uint8_t pk_frame[4 + 65];
    pk_frame[0] = 65; pk_frame[1] = 0; pk_frame[2] = 0x06; pk_frame[3] = 0x00;
    pk_frame[4] = BT_SMP_CMD_PUBLIC_KEY;
    for (unsigned i = 0; i < 64; i++) pk_frame[5 + i] = (uint8_t)(0x11 + i);
    CHECK(bt_l2cap_process_acl(&bt, 0x0040, pk_frame, sizeof(pk_frame), rsp, sizeof(rsp), &rsp_len) == WL_OK);
    CHECK(rsp_len == 69 && rsp[4] == BT_SMP_CMD_PUBLIC_KEY && bt.smp.state == BT_SMP_PUBLIC_KEY_EXCH);

    /* Step 3: Pairing Confirm */
    uint8_t peer_rand[16];
    for (unsigned i = 0; i < 16; i++) peer_rand[i] = (uint8_t)(0xa0 + i);
    uint8_t cfm_frame[4 + 17];
    cfm_frame[0] = 17; cfm_frame[1] = 0; cfm_frame[2] = 0x06; cfm_frame[3] = 0x00;
    cfm_frame[4] = BT_SMP_CMD_PAIRING_CONFIRM;
    bt_smp_compute_confirm(peer_rand, pk_frame + 5, bt.smp.preq, bt.smp.prsp, cfm_frame + 5);
    CHECK(bt_l2cap_process_acl(&bt, 0x0040, cfm_frame, sizeof(cfm_frame), rsp, sizeof(rsp), &rsp_len) == WL_OK);
    CHECK(rsp_len == 21 && rsp[4] == BT_SMP_CMD_PAIRING_CONFIRM && bt.smp.state == BT_SMP_CONFIRM_EXCH);

    /* Step 4: Pairing Random */
    uint8_t rnd_frame[4 + 17];
    rnd_frame[0] = 17; rnd_frame[1] = 0; rnd_frame[2] = 0x06; rnd_frame[3] = 0x00;
    rnd_frame[4] = BT_SMP_CMD_PAIRING_RANDOM;
    memcpy(rnd_frame + 5, peer_rand, 16);
    CHECK(bt_l2cap_process_acl(&bt, 0x0040, rnd_frame, sizeof(rnd_frame), rsp, sizeof(rsp), &rsp_len) == WL_OK);
    CHECK(rsp_len == 21 && rsp[4] == BT_SMP_CMD_PAIRING_RANDOM && bt.smp.state == BT_SMP_RANDOM_EXCH);

    /* Step 5: DHKey Check -> Paired! */
    uint8_t dh_frame[4 + 17];
    dh_frame[0] = 17; dh_frame[1] = 0; dh_frame[2] = 0x06; dh_frame[3] = 0x00;
    dh_frame[4] = BT_SMP_CMD_DHKEY_CHECK;
    bt_smp_compute_dhkey_check(bt.smp.dhkey, peer_rand, bt.smp.local_rand,
                               bt.smp.preq, bt.smp.prsp, dh_frame + 5);
    CHECK(bt_l2cap_process_acl(&bt, 0x0040, dh_frame, sizeof(dh_frame), rsp, sizeof(rsp), &rsp_len) == WL_OK);
    CHECK(rsp_len == 21 && rsp[4] == BT_SMP_CMD_DHKEY_CHECK && bt.smp.state == BT_SMP_PAIRED);
    CHECK(bt.smp_handshakes_completed == 1);

    /* AirDrop BLE Proximity Beacon encode/decode */
    struct bt_airdrop_beacon beacon_in = {
        .contact_hashes = {0x1234, 0x5678, 0x9abc, 0xdef0},
        .tx_power_dbm = -12,
        .awdl_Trigger_channel = 149
    };
    struct bt_airdrop_beacon beacon_out;
    uint8_t adv_buf[32];
    size_t adv_len = 0;
    CHECK(bt_airdrop_encode_ble_adv(&beacon_in, adv_buf, sizeof(adv_buf), &adv_len) == WL_OK);
    CHECK(adv_len == 23);
    CHECK(bt_airdrop_decode_ble_adv(&bt, adv_buf, adv_len, &beacon_out) == WL_OK);
    CHECK(beacon_out.tx_power_dbm == -12 && beacon_out.awdl_Trigger_channel == 149);
    CHECK(beacon_out.contact_hashes[0] == 0x1234 && beacon_out.contact_hashes[3] == 0xdef0);
}

static void test_airdrop_awdl_engine(void)
{
    struct awdl_state node_a, node_b;
    const uint8_t mac_a[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};
    const uint8_t mac_b[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02};

    CHECK(awdl_init(&node_a, mac_a, 100) == WL_OK);
    CHECK(awdl_init(&node_b, mac_b, 250) == WL_OK); /* Node B has higher master metric */

    /* Verify channel sequence hopping across 6, 44, 149 */
    CHECK(awdl_current_channel(&node_a, 0) == 6);
    CHECK(awdl_current_channel(&node_a, 16) == 44);
    CHECK(awdl_current_channel(&node_a, 48) == 149);

    /* Node B encodes a Periodic Synchronization Frame (PSF) and Node A receives it */
    uint8_t psf_buf[128];
    size_t psf_len = 0;
    CHECK(awdl_encode_action_frame(&node_b, AWDL_SUBTYPE_PSF, 10000, psf_buf, sizeof(psf_buf), &psf_len) == WL_OK);
    CHECK(psf_len == 80 && node_b.psf_sent == 1);

    CHECK(awdl_parse_action_frame(&node_a, mac_b, psf_buf, psf_len, 10045) == WL_OK);
    /* Node A must elect Node B as top master with distance 1 and clock drift 45 us */
    CHECK(memcmp(node_a.top_master, mac_b, 6) == 0);
    CHECK(node_a.top_master_metric == 250 && node_a.distance_to_master == 1);
    CHECK(node_a.peers[0].in_use == 1 && node_a.peers[0].airdrop_capable == 1);
    CHECK(node_a.peers[0].clock_drift_us == 45);
    CHECK(node_a.peers[0].ipv6_link_local[0] == 0xfe && node_a.peers[0].ipv6_link_local[1] == 0x80);

    /* Reject truncated/corrupted TLV frames safely */
    CHECK(awdl_parse_action_frame(&node_a, mac_b, psf_buf, 20, 10050) == WL_ERR_BOUNDS);

    /* AirDrop IPv6 Data Path encapsulation & decapsulation */
    const uint8_t ipv6_pkt[64] = {0x60, 0x00, 0x00, 0x00, 0x00, 24, 0x06, 0x40};
    uint8_t wire_frame[128];
    size_t wire_len = 0;
    CHECK(awdl_encapsulate_data(&node_a, mac_b, ipv6_pkt, sizeof(ipv6_pkt),
                                wire_frame, sizeof(wire_frame), &wire_len) == WL_OK);
    CHECK(wire_len == 22 + sizeof(ipv6_pkt));

    uint8_t rx_src[6] = {0};
    const uint8_t *rx_payload = NULL;
    size_t rx_payload_len = 0;
    CHECK(awdl_decapsulate_data(&node_b, wire_frame, wire_len,
                                rx_src, &rx_payload, &rx_payload_len) == WL_OK);
    CHECK(memcmp(rx_src, mac_a, 6) == 0);
    CHECK(rx_payload_len == sizeof(ipv6_pkt) && memcmp(rx_payload, ipv6_pkt, sizeof(ipv6_pkt)) == 0);
}

int main(void)
{
    test_wifi_pm_roaming_and_ampdu();
    test_bluetooth_hci_smp_and_airdrop_ble();
    test_airdrop_awdl_engine();
    printf("PASS: %u Wi-Fi QCC2072, Bluetooth 5.4 SMP, and AirDrop AWDL checks verified\n", g_checks);
    return 0;
}
