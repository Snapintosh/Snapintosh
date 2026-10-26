/* SPDX-License-Identifier: MIT */
/*
 * Bluetooth 5.4 HCI / L2CAP & LE Secure Connections (SMP) Engine
 *
 * Uses NIST P-256 (secp256r1) ECDH key exchange (bt_p256_public_key,
 * bt_p256_valid_public_key, bt_p256_ecdh) and RFC 4493 AES-128-CMAC
 * Bluetooth Core Spec v5.4 cryptographic toolbox functions (f4, f5, f6, g2).
 *
 * Included in order by compat/wireless-stack.c; not compiled standalone.
 */

static void bt_smp_wipe_secrets(struct bt_smp_session *s)
{
    if (!s) return;
    wl_crypto_zero(s->local_sk, sizeof(s->local_sk));
    s->has_private_key = 0;
    wl_crypto_zero(s->dhkey, sizeof(s->dhkey));
    wl_crypto_zero(s->mac_key, sizeof(s->mac_key));
    wl_crypto_zero(s->ltk, sizeof(s->ltk));
}

int bt_smp_set_local_keypair(struct bt_stack_state *bt,
                             const uint8_t private_key[32],
                             const uint8_t random_nonce[16])
{
    if (!bt || !private_key || bt->magic != BT_STACK_MAGIC)
        return WL_ERR_NULL;
    if (!bt_p256_valid_private_key(private_key))
        return WL_ERR_CRYPTO;
    uint8_t pub[64];
    int rc = bt_p256_public_key(private_key, pub);
    if (rc != WL_OK)
        return rc;
    memcpy(bt->smp.local_sk, private_key, 32);
    memcpy(bt->smp.local_pk, pub, 64);
    bt->smp.has_private_key = 1;
    if (random_nonce)
        memcpy(bt->smp.local_rand, random_nonce, 16);
    return WL_OK;
}

int bt_stack_init(struct bt_stack_state *bt, const uint8_t bdaddr[6])
{
    if (!bt || !bdaddr) return WL_ERR_NULL;
    memset(bt, 0, sizeof(*bt));
    bt->magic = BT_STACK_MAGIC;
    memcpy(bt->local_bdaddr, bdaddr, 6);
    bt->smp.state = BT_SMP_STATE_IDLE;
    bt->smp.io_cap = 0x01; /* DisplayYesNo (Numeric Comparison) */
    bt->smp.auth_req = BT_SMP_AUTH_BONDING | BT_SMP_AUTH_MITM |
                       BT_SMP_AUTH_SC | BT_SMP_AUTH_CT2;
    bt->smp.max_key_size = 16;
    bt->smp.local_addr[0] = 0x00;
    memcpy(bt->smp.local_addr + 1, bdaddr, 6);
    bt->smp.peer_addr[0] = 0x00;

    /* Derive a valid default ephemeral P-256 private scalar d in [1, n-1] and nonce */
    uint8_t sk[32], nonce_digest[32];
    wl_hmac_sha256((const uint8_t *)"Snapintosh-BT54-P256-SK", 23U, bdaddr, 6U, sk);
    sk[0] &= 0x7FU;
    sk[31] |= 0x01U;
    wl_hmac_sha256((const uint8_t *)"Snapintosh-BT54-NONCE", 21U, bdaddr, 6U, nonce_digest);
    int rc = bt_smp_set_local_keypair(bt, sk, nonce_digest);
    wl_crypto_zero(sk, sizeof(sk));
    wl_crypto_zero(nonce_digest, sizeof(nonce_digest));
    return rc;
}

int bt_hci_build_cmd(uint16_t opcode, const uint8_t *params, uint8_t param_len,
                     uint8_t *out_buf, size_t out_cap, size_t *out_len)
{
    if (!out_buf || !out_len) return WL_ERR_NULL;
    if (param_len > 0 && !params) return WL_ERR_NULL;
    size_t needed = 4U + (size_t)param_len;
    if (out_cap < needed) return WL_ERR_NOSPC;

    out_buf[0] = BT_HCI_PKT_CMD;
    wl_write_le16(&out_buf[1], opcode);
    out_buf[3] = param_len;
    if (param_len > 0)
        memcpy(&out_buf[4], params, param_len);
    *out_len = needed;
    return WL_OK;
}

int bt_hci_process_cmd_GenerateEvt(struct bt_stack_state *bt,
                                   const uint8_t *cmd_pkt, size_t cmd_len,
                                   uint8_t *evt_buf, size_t evt_cap, size_t *evt_len)
{
    if (!bt || !cmd_pkt || !evt_buf || !evt_len) return WL_ERR_NULL;
    if (bt->magic != BT_STACK_MAGIC) return WL_ERR_INVALID;
    if (cmd_len < 4 || cmd_pkt[0] != BT_HCI_PKT_CMD) return WL_ERR_INVALID;

    uint16_t opcode = wl_read_le16(&cmd_pkt[1]);
    uint8_t plen = cmd_pkt[3];
    if (cmd_len < 4U + (size_t)plen) return WL_ERR_BOUNDS;

    bt->hci_cmd_count++;
    if (evt_cap < 14) return WL_ERR_NOSPC;

    evt_buf[0] = BT_HCI_PKT_EVENT;
    evt_buf[1] = BT_HCI_EVT_CMD_COMPLETE;
    evt_buf[3] = 0x01; /* Num_HCI_Command_Packets */
    wl_write_le16(&evt_buf[4], opcode);
    evt_buf[6] = 0x00; /* Status = Success */

    switch (opcode) {
    case BT_HCI_OP_RESET:
        bt->controller_ready = 1;
        bt->le_ext_adv_enabled = 0;
        bt->le_ext_scan_enabled = 0;
        evt_buf[2] = 4;
        *evt_len = 7;
        break;
    case BT_HCI_OP_READ_BD_ADDR:
        evt_buf[2] = 10;
        memcpy(&evt_buf[7], bt->local_bdaddr, 6);
        *evt_len = 13;
        break;
    case BT_HCI_OP_READ_LOCAL_VERSION:
        evt_buf[2] = 12;
        evt_buf[7] = 0x0D; /* HCI_Version 5.4 (0x0D) */
        wl_write_le16(&evt_buf[8], 0x2072);
        evt_buf[10] = 0x0D; /* LMP_Version 5.4 */
        wl_write_le16(&evt_buf[11], 0x001D); /* Qualcomm Company ID */
        wl_write_le16(&evt_buf[13], 0x6900);
        *evt_len = 15;
        break;
    case BT_HCI_OP_LE_SET_EXT_ADV_ENABLE:
        if (plen < 1) return WL_ERR_INVALID;
        bt->le_ext_adv_enabled = cmd_pkt[4] ? 1 : 0;
        evt_buf[2] = 4;
        *evt_len = 7;
        break;
    case BT_HCI_OP_LE_SET_EXT_SCAN_ENABLE:
        if (plen < 1) return WL_ERR_INVALID;
        bt->le_ext_scan_enabled = cmd_pkt[4] ? 1 : 0;
        evt_buf[2] = 4;
        *evt_len = 7;
        break;
    case BT_HCI_OP_LE_SET_EXT_ADV_PARAMS:
    case BT_HCI_OP_LE_SET_EXT_ADV_DATA:
    case BT_HCI_OP_LE_SET_EXT_SCAN_PARAMS:
        evt_buf[2] = 4;
        *evt_len = 7;
        break;
    default:
        evt_buf[6] = 0x01; /* Unknown HCI Command */
        evt_buf[2] = 4;
        *evt_len = 7;
        break;
    }

    bt->hci_evt_count++;
    return WL_OK;
}

int bt_hci_inject_le_conn_complete(struct bt_stack_state *bt, uint16_t handle,
                                   const uint8_t peer_bdaddr[6])
{
    if (!bt || !peer_bdaddr || bt->magic != BT_STACK_MAGIC) return WL_ERR_NULL;
    if (!bt->controller_ready) return WL_ERR_STATE;
    bt->active_conn_handle = handle;
    memcpy(bt->peer_bdaddr, peer_bdaddr, 6);
    bt->smp.peer_addr[0] = bt->peer_addr_type;
    memcpy(bt->smp.peer_addr + 1, peer_bdaddr, 6);
    bt->hci_evt_count++;
    return WL_OK;
}

/*
 * Bluetooth Core Spec v5.4 Vol 3 Part H Section 2.2.6 / 2.3.5.6.2:
 *   Cb = f4(PKb_x, PKa_x, Nb, 0) = AES-CMAC_Nb(PKb_x || PKa_x || 0)
 * Note: the caller passes (pk_first, pk_second, rand_val, z, out_confirm).
 */
void bt_smp_compute_confirm(const uint8_t pk_initiator[64],
                            const uint8_t pk_responder[64],
                            const uint8_t rand_val[16],
                            uint8_t z, uint8_t out_confirm[16])
{
    if (!pk_initiator || !pk_responder || !rand_val || !out_confirm) return;
    (void)bt_smp_f4(pk_initiator, pk_responder, rand_val, z, out_confirm);
}

/*
 * Bluetooth Core Spec v5.4 Vol 3 Part H Section 2.2.8 / 2.3.5.6.5:
 *   Ea/Eb = f6(MacKey, N1, N2, R, IOcap, A1, A2)
 */
void bt_smp_compute_dhkey_check(const uint8_t mac_key[16],
                                const uint8_t n1[16], const uint8_t n2[16],
                                const uint8_t r[16], const uint8_t iocap[3],
                                const uint8_t a1[7], const uint8_t a2[7],
                                uint8_t out_check[16])
{
    if (!mac_key || !n1 || !n2 || !r || !iocap || !a1 || !a2 || !out_check) return;
    (void)bt_smp_f6(mac_key, n1, n2, r, iocap, a1, a2, out_check);
}

static int l2cap_wrap_smp(const uint8_t *smp_pdu, size_t smp_len,
                          uint8_t *out_l2cap, size_t out_cap, size_t *out_len)
{
    if (out_cap < 4U + smp_len) return WL_ERR_NOSPC;
    wl_write_le16(&out_l2cap[0], (uint16_t)smp_len);
    wl_write_le16(&out_l2cap[2], BT_L2CAP_CID_SMP);
    memcpy(&out_l2cap[4], smp_pdu, smp_len);
    *out_len = 4U + smp_len;
    return WL_OK;
}

int bt_smp_start_pairing(struct bt_stack_state *bt, int is_initiator,
                         uint8_t *out_l2cap, size_t out_cap, size_t *out_len)
{
    if (!bt || !out_l2cap || !out_len) return WL_ERR_NULL;
    if (bt->magic != BT_STACK_MAGIC) return WL_ERR_INVALID;
    if (!bt->smp.has_private_key || !bt_p256_valid_private_key(bt->smp.local_sk))
        return WL_ERR_CRYPTO;

    struct bt_smp_session *s = &bt->smp;
    s->is_initiator = is_initiator ? 1 : 0;

    if (is_initiator) {
        s->preq[0] = BT_SMP_CMD_PAIRING_REQ;
        s->preq[1] = s->io_cap;
        s->preq[2] = 0x00; /* OOB data not present */
        s->preq[3] = s->auth_req;
        s->preq[4] = s->max_key_size;
        s->preq[5] = 0x0F; /* Initiator Key Distribution: EncKey|IdKey|Sign|LinkKey */
        s->preq[6] = 0x0F; /* Responder Key Distribution */
        s->state = BT_SMP_STATE_WAIT_RSP;
        return l2cap_wrap_smp(s->preq, 7, out_l2cap, out_cap, out_len);
    } else {
        s->state = BT_SMP_STATE_IDLE;
        *out_len = 0;
        return WL_OK;
    }
}

int bt_smp_step(struct bt_stack_state *bt,
                const uint8_t *in_l2cap, size_t in_len,
                uint8_t *out_l2cap, size_t out_cap, size_t *out_len)
{
    if (!bt || !in_l2cap || !out_l2cap || !out_len) return WL_ERR_NULL;
    if (bt->magic != BT_STACK_MAGIC) return WL_ERR_INVALID;
    if (in_len < 5) return WL_ERR_BOUNDS;

    uint16_t pdu_len = wl_read_le16(&in_l2cap[0]);
    uint16_t cid = wl_read_le16(&in_l2cap[2]);
    if (cid != BT_L2CAP_CID_SMP || in_len < 4U + (size_t)pdu_len || pdu_len < 1)
        return WL_ERR_INVALID;

    const uint8_t *pdu = &in_l2cap[4];
    uint8_t cmd = pdu[0];
    struct bt_smp_session *s = &bt->smp;
    uint8_t reply[68];
    *out_len = 0;

    switch (cmd) {
    case BT_SMP_CMD_PAIRING_REQ:
        if (s->is_initiator || pdu_len != 7) return WL_ERR_STATE;
        if (!(pdu[3] & BT_SMP_AUTH_SC) || pdu[4] < 16) {
            bt_smp_wipe_secrets(s);
            s->state = BT_SMP_STATE_FAILED;
            return WL_ERR_CRYPTO;
        }
        memcpy(s->preq, pdu, 7);
        s->prsp[0] = BT_SMP_CMD_PAIRING_RSP;
        s->prsp[1] = s->io_cap;
        s->prsp[2] = 0x00;
        s->prsp[3] = s->auth_req;
        s->prsp[4] = s->max_key_size;
        s->prsp[5] = 0x0F;
        s->prsp[6] = 0x0F;
        s->state = BT_SMP_STATE_WAIT_PUBKEY;
        return l2cap_wrap_smp(s->prsp, 7, out_l2cap, out_cap, out_len);

    case BT_SMP_CMD_PAIRING_RSP:
        if (!s->is_initiator || s->state != BT_SMP_STATE_WAIT_RSP || pdu_len != 7)
            return WL_ERR_STATE;
        if (!(pdu[3] & BT_SMP_AUTH_SC) || pdu[4] < 16) {
            bt_smp_wipe_secrets(s);
            s->state = BT_SMP_STATE_FAILED;
            return WL_ERR_CRYPTO;
        }
        memcpy(s->prsp, pdu, 7);
        reply[0] = BT_SMP_CMD_PUBLIC_KEY;
        memcpy(&reply[1], s->local_pk, 64);
        s->state = BT_SMP_STATE_WAIT_PUBKEY;
        return l2cap_wrap_smp(reply, 65, out_l2cap, out_cap, out_len);

    case BT_SMP_CMD_PUBLIC_KEY:
        if (s->state != BT_SMP_STATE_WAIT_PUBKEY || pdu_len != 65)
            return WL_ERR_STATE;
        if (!s->has_private_key || !bt_p256_valid_private_key(s->local_sk)) {
            bt_smp_wipe_secrets(s);
            s->state = BT_SMP_STATE_FAILED;
            return WL_ERR_CRYPTO;
        }
        memcpy(s->peer_pk, &pdu[1], 64);
        /* Validate peer P-256 point on curve and compute ECDH Z = X(local_sk * peer_pk) */
        if (bt_p256_ecdh(s->local_sk, s->peer_pk, s->dhkey) != WL_OK) {
            bt_smp_wipe_secrets(s);
            s->state = BT_SMP_STATE_FAILED;
            return WL_ERR_CRYPTO;
        }
        if (!s->is_initiator) {
            reply[0] = BT_SMP_CMD_PUBLIC_KEY;
            memcpy(&reply[1], s->local_pk, 64);
            s->state = BT_SMP_STATE_WAIT_RANDOM;
            return l2cap_wrap_smp(reply, 65, out_l2cap, out_cap, out_len);
        } else {
            s->state = BT_SMP_STATE_WAIT_CONFIRM;
            return WL_OK;
        }

    case BT_SMP_CMD_PAIRING_CONFIRM:
        if (!s->is_initiator || s->state != BT_SMP_STATE_WAIT_CONFIRM || pdu_len != 17)
            return WL_ERR_STATE;
        memcpy(s->peer_confirm, &pdu[1], 16);
        reply[0] = BT_SMP_CMD_PAIRING_RANDOM;
        memcpy(&reply[1], s->local_rand, 16);
        s->state = BT_SMP_STATE_WAIT_RANDOM;
        return l2cap_wrap_smp(reply, 17, out_l2cap, out_cap, out_len);

    case BT_SMP_CMD_PAIRING_RANDOM: {
        if (s->state != BT_SMP_STATE_WAIT_RANDOM || pdu_len != 17)
            return WL_ERR_STATE;
        memcpy(s->peer_rand, &pdu[1], 16);

        const uint8_t *pk_a = s->is_initiator ? s->local_pk : s->peer_pk;
        const uint8_t *pk_b = s->is_initiator ? s->peer_pk : s->local_pk;
        const uint8_t *na   = s->is_initiator ? s->local_rand : s->peer_rand;
        const uint8_t *nb   = s->is_initiator ? s->peer_rand : s->local_rand;
        const uint8_t *a1   = s->is_initiator ? s->local_addr : s->peer_addr;
        const uint8_t *a2   = s->is_initiator ? s->peer_addr : s->local_addr;

        if (s->is_initiator) {
            uint8_t expected_cb[16];
            bt_smp_compute_confirm(pk_b, pk_a, nb, 0, expected_cb);
            if (wl_ct_memcmp(expected_cb, s->peer_confirm, 16) != 0) {
                bt_smp_wipe_secrets(s);
                s->state = BT_SMP_STATE_FAILED;
                return WL_ERR_CRYPTO;
            }
        }

        /* Compute 6-digit Numeric Comparison value g2(PKa, PKb, Na, Nb) */
        (void)bt_smp_g2(pk_a, pk_b, na, nb, &s->numeric_passkey);

        /* Derive MacKey and LTK via f5(DHKey, Na, Nb, A1, A2) */
        (void)bt_smp_f5(s->dhkey, na, nb, a1, a2, s->mac_key, s->ltk);

        /* Forward secrecy: zeroize ephemeral P-256 private scalar once f5 completes */
        wl_crypto_zero(s->local_sk, sizeof(s->local_sk));
        s->has_private_key = 0;

        if (!s->is_initiator) {
            reply[0] = BT_SMP_CMD_PAIRING_RANDOM;
            memcpy(&reply[1], s->local_rand, 16);
            s->state = BT_SMP_STATE_WAIT_DHKEY_CHECK;
            return l2cap_wrap_smp(reply, 17, out_l2cap, out_cap, out_len);
        } else {
            uint8_t r_zero[16] = {0};
            uint8_t iocap_a[3] = { s->preq[1], s->preq[2], s->preq[3] };
            reply[0] = BT_SMP_CMD_DHKEY_CHECK;
            bt_smp_compute_dhkey_check(s->mac_key, s->local_rand, s->peer_rand,
                                       r_zero, iocap_a, a1, a2, &reply[1]);
            s->state = BT_SMP_STATE_WAIT_DHKEY_CHECK;
            return l2cap_wrap_smp(reply, 17, out_l2cap, out_cap, out_len);
        }
    }

    case BT_SMP_CMD_DHKEY_CHECK: {
        if (s->state != BT_SMP_STATE_WAIT_DHKEY_CHECK || pdu_len != 17)
            return WL_ERR_STATE;
        uint8_t r_zero[16] = {0};
        uint8_t expected_e[16];
        const uint8_t *peer_iocap_src = s->is_initiator ? &s->prsp[1] : &s->preq[1];
        uint8_t peer_iocap[3] = { peer_iocap_src[0], peer_iocap_src[1], peer_iocap_src[2] };
        bt_smp_compute_dhkey_check(s->mac_key, s->peer_rand, s->local_rand,
                                   r_zero, peer_iocap, s->peer_addr, s->local_addr, expected_e);
        if (wl_ct_memcmp(expected_e, &pdu[1], 16) != 0) {
            bt_smp_wipe_secrets(s);
            s->state = BT_SMP_STATE_FAILED;
            return WL_ERR_CRYPTO;
        }

        s->state = BT_SMP_STATE_PAIRED;
        if (!s->is_initiator) {
            uint8_t own_iocap[3] = { s->prsp[1], s->prsp[2], s->prsp[3] };
            reply[0] = BT_SMP_CMD_DHKEY_CHECK;
            bt_smp_compute_dhkey_check(s->mac_key, s->local_rand, s->peer_rand,
                                       r_zero, own_iocap, s->local_addr, s->peer_addr,
                                       &reply[1]);
            return l2cap_wrap_smp(reply, 17, out_l2cap, out_cap, out_len);
        }
        return WL_OK;
    }

    default:
        bt_smp_wipe_secrets(s);
        s->state = BT_SMP_STATE_FAILED;
        return WL_ERR_UNSUPPORTED;
    }
}

int bt_encode_airdrop_ble_adv(const struct apple_ble_airdrop_adv *adv,
                              uint8_t *out_buf, size_t out_cap, size_t *out_len)
{
    if (!adv || !out_buf || !out_len) return WL_ERR_NULL;
    if (out_cap < 27) return WL_ERR_NOSPC;

    out_buf[0] = 0x02;
    out_buf[1] = 0x01;
    out_buf[2] = 0x1A;

    out_buf[3] = 23;
    out_buf[4] = 0xFF;
    wl_write_le16(&out_buf[5], APPLE_BLE_COMPANY_ID);
    out_buf[7] = APPLE_CONT_TYPE_AIRDROP;
    out_buf[8] = APPLE_CONT_AIRDROP_LEN;

    memset(&out_buf[9], 0, 8);
    out_buf[17] = adv->airdrop_version;
    wl_write_be32(&out_buf[18], ((uint32_t)adv->hash_apple_id << 16) | adv->hash_phone);
    wl_write_be32(&out_buf[22], ((uint32_t)adv->hash_email << 16) | adv->hash_icloud);
    out_buf[26] = 0x00;

    *out_len = 27;
    return WL_OK;
}

int bt_decode_airdrop_ble_adv(const uint8_t *in_buf, size_t in_len,
                              struct apple_ble_airdrop_adv *out_adv)
{
    if (!in_buf || !out_adv) return WL_ERR_NULL;
    size_t offset = 0;

    while (offset < in_len) {
        uint8_t ad_len = in_buf[offset];
        if (ad_len == 0) break;
        if (offset + 1U + (size_t)ad_len > in_len) return WL_ERR_BOUNDS;

        uint8_t ad_type = in_buf[offset + 1];
        if (ad_type == 0xFF && ad_len >= 23) {
            uint16_t company = wl_read_le16(&in_buf[offset + 2]);
            uint8_t cont_type = in_buf[offset + 4];
            uint8_t cont_len = in_buf[offset + 5];
            if (company == APPLE_BLE_COMPANY_ID &&
                cont_type == APPLE_CONT_TYPE_AIRDROP &&
                cont_len == APPLE_CONT_AIRDROP_LEN) {
                const uint8_t *p = &in_buf[offset + 6];
                memset(out_adv, 0, sizeof(*out_adv));
                memcpy(out_adv->zeros, p, 8);
                out_adv->airdrop_version = p[8];
                uint32_t hi = wl_read_be32(&p[9]);
                uint32_t lo = wl_read_be32(&p[13]);
                out_adv->hash_apple_id = (uint16_t)(hi >> 16);
                out_adv->hash_phone    = (uint16_t)(hi & 0xFFFFU);
                out_adv->hash_email    = (uint16_t)(lo >> 16);
                out_adv->hash_icloud   = (uint16_t)(lo & 0xFFFFU);
                out_adv->zero_pad      = p[17];
                return WL_OK;
            }
        }
        offset += 1U + (size_t)ad_len;
    }
    return WL_ERR_INVALID;
}
