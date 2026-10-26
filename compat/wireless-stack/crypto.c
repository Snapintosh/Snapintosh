/* SPDX-License-Identifier: MIT */
/*
 * Cryptographic primitives for QCC2072 Wi-Fi 802.11r FT and Bluetooth 5.4 SMP:
 *   - FIPS-197 AES-128 block cipher
 *   - RFC 4493 AES-128-CMAC
 *   - FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA-256, IEEE 802.11-2020 KDF-SHA-256
 *   - NIST P-256 (secp256r1) ECDH key generation, curve validation & shared secret
 *   - Bluetooth Core Spec v5.4 Vol 3 Part H Section 2.2 f4, f5, f6, g2
 *
 * Included in order by compat/wireless-stack.c; not compiled standalone.
 */

static inline uint16_t wl_read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline void wl_write_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
}

static inline uint32_t wl_read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void wl_write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static inline uint16_t wl_read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void wl_write_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFFU);
    p[1] = (uint8_t)(v & 0xFFU);
}

static inline uint32_t wl_read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline void wl_write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFFU);
    p[1] = (uint8_t)((v >> 16) & 0xFFU);
    p[2] = (uint8_t)((v >> 8) & 0xFFU);
    p[3] = (uint8_t)(v & 0xFFU);
}

static void wl_crypto_zero(void *v, size_t n)
{
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) *p++ = 0;
}

static int wl_ct_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    return (int)diff;
}

/* --------------------------------------------------------------------------
 * FIPS-197 AES-128 & RFC 4493 AES-128-CMAC
 * -------------------------------------------------------------------------- */
static const uint8_t wl_aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t wl_gf_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bU));
}

void wl_aes128_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[176], s[16], rcon = 1;
    if (!key || !in || !out) return;
    memcpy(rk, key, 16);
    for (unsigned i = 16; i < 176; i += 4) {
        uint8_t t[4] = { rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1] };
        if ((i & 15U) == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t)(wl_aes_sbox[t[1]] ^ rcon);
            t[1] = wl_aes_sbox[t[2]];
            t[2] = wl_aes_sbox[t[3]];
            t[3] = wl_aes_sbox[u];
            rcon = wl_gf_xtime(rcon);
        }
        for (unsigned j = 0; j < 4; ++j)
            rk[i + j] = (uint8_t)(rk[i - 16 + j] ^ t[j]);
    }
    for (unsigned i = 0; i < 16; ++i)
        s[i] = (uint8_t)(in[i] ^ rk[i]);
    for (unsigned r = 1; r <= 10; ++r) {
        uint8_t t[16];
        for (unsigned i = 0; i < 16; ++i)
            t[i] = wl_aes_sbox[s[i]];
        s[0]  = t[0];  s[1]  = t[5];  s[2]  = t[10]; s[3]  = t[15];
        s[4]  = t[4];  s[5]  = t[9];  s[6]  = t[14]; s[7]  = t[3];
        s[8]  = t[8];  s[9]  = t[13]; s[10] = t[2];  s[11] = t[7];
        s[12] = t[12]; s[13] = t[1];  s[14] = t[6];  s[15] = t[11];
        if (r < 10) {
            for (unsigned c = 0; c < 16; c += 4) {
                uint8_t a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
                uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                s[c]     ^= (uint8_t)(x ^ wl_gf_xtime((uint8_t)(a0 ^ a1)));
                s[c + 1] ^= (uint8_t)(x ^ wl_gf_xtime((uint8_t)(a1 ^ a2)));
                s[c + 2] ^= (uint8_t)(x ^ wl_gf_xtime((uint8_t)(a2 ^ a3)));
                s[c + 3] ^= (uint8_t)(x ^ wl_gf_xtime((uint8_t)(a3 ^ a0)));
            }
        }
        for (unsigned i = 0; i < 16; ++i)
            s[i] ^= rk[r * 16 + i];
    }
    memcpy(out, s, 16);
    wl_crypto_zero(rk, sizeof(rk));
}

static void wl_cmac_subkey(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t next = (uint8_t)(in[i] >> 7);
        out[i] = (uint8_t)((in[i] << 1) | carry);
        carry = next;
    }
    if (carry)
        out[15] ^= 0x87U;
}

void wl_aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16])
{
    uint8_t z[16] = {0}, l[16], k1[16], k2[16], x[16] = {0}, m_last[16];
    if (!key || (!msg && len) || !mac) return;
    wl_aes128_encrypt(key, z, l);
    wl_cmac_subkey(l, k1);
    wl_cmac_subkey(k1, k2);
    size_t n = len ? (len + 15U) / 16U : 1U;
    int complete = (len > 0 && (len & 15U) == 0);
    for (size_t i = 0; i < n - 1U; ++i) {
        for (unsigned j = 0; j < 16; ++j)
            x[j] ^= msg[i * 16U + j];
        wl_aes128_encrypt(key, x, x);
    }
    memset(m_last, 0, 16);
    size_t rem = len - (n - 1U) * 16U;
    if (complete) {
        for (unsigned j = 0; j < 16; ++j)
            m_last[j] = (uint8_t)(msg[(n - 1U) * 16U + j] ^ k1[j]);
    } else {
        for (size_t j = 0; j < rem; ++j)
            m_last[j] = msg[(n - 1U) * 16U + j];
        m_last[rem] = 0x80U;
        for (unsigned j = 0; j < 16; ++j)
            m_last[j] ^= k2[j];
    }
    for (unsigned j = 0; j < 16; ++j)
        x[j] ^= m_last[j];
    wl_aes128_encrypt(key, x, mac);
    wl_crypto_zero(l, sizeof(l));
    wl_crypto_zero(k1, sizeof(k1));
    wl_crypto_zero(k2, sizeof(k2));
}

#if !defined(__aarch64__)
#include "aes.h"
static uint8_t wl_aes_inv(uint8_t a)
{
    uint8_t v = 1;
    for (unsigned i = 0; i < 8; ++i) {
        if (i) {
            uint8_t m = 0, x = v, y = a;
            for (unsigned b = 0; b < 8; ++b) {
                m ^= x & (uint8_t)(0U - (y & 1U));
                x = wl_gf_xtime(x);
                y >>= 1;
            }
            v = m;
        }
        uint8_t sq = 0, x = a, y = a;
        for (unsigned b = 0; b < 8; ++b) {
            sq ^= x & (uint8_t)(0U - (y & 1U));
            x = wl_gf_xtime(x);
            y >>= 1;
        }
        a = sq;
    }
    return v;
}
static uint8_t wl_aes_unsub(uint8_t x)
{
    uint8_t r = (uint8_t)(((x << 1) | (x >> 7)) ^ ((x << 3) | (x >> 5)) ^ ((x << 6) | (x >> 2)) ^ 5U);
    return wl_aes_inv(r);
}
void aes_clear(void *memory, size_t size) { wl_crypto_zero(memory, size); }
int aes_expand(struct aes_key *key, const uint8_t *bytes, size_t size)
{
    if (!key || !bytes || size != 16U) return 0;
    memset(key, 0, sizeof(*key));
    key->rounds = 10U;
    memcpy(key->round_key, bytes, 16);
    uint8_t rcon = 1;
    for (unsigned i = 16; i < 176; i += 4) {
        uint8_t t[4] = { key->round_key[i - 4], key->round_key[i - 3],
                         key->round_key[i - 2], key->round_key[i - 1] };
        if ((i & 15U) == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t)(wl_aes_sbox[t[1]] ^ rcon);
            t[1] = wl_aes_sbox[t[2]];
            t[2] = wl_aes_sbox[t[3]];
            t[3] = wl_aes_sbox[u];
            rcon = wl_gf_xtime(rcon);
        }
        for (unsigned j = 0; j < 4; ++j)
            key->round_key[i + j] = (uint8_t)(key->round_key[i - 16 + j] ^ t[j]);
    }
    return 1;
}
int aes_block(const struct aes_key *key, const uint8_t input[16], uint8_t output[16], int decrypt)
{
    if (!key || !input || !output || key->rounds != 10U) return 0;
    if (!decrypt) {
        wl_aes128_encrypt(key->round_key, input, output);
        return 1;
    }
    uint8_t s[16], t[16];
    memcpy(s, input, 16);
    for (unsigned i = 0; i < 16; ++i) s[i] ^= key->round_key[160 + i];
    for (unsigned round = 1; round <= 10; ++round) {
        for (unsigned c = 0; c < 4; ++c)
            for (unsigned r = 0; r < 4; ++r)
                t[c * 4 + r] = s[((c + 4 - r) & 3U) * 4 + r];
        for (unsigned i = 0; i < 16; ++i)
            s[i] = (uint8_t)(wl_aes_unsub(t[i]) ^ key->round_key[(10 - round) * 16 + i]);
        if (round < 10) {
            for (unsigned c = 0; c < 4; ++c) {
                uint8_t *p = s + c * 4;
                uint8_t u = wl_gf_xtime(wl_gf_xtime(p[0] ^ p[2]));
                uint8_t v = wl_gf_xtime(wl_gf_xtime(p[1] ^ p[3]));
                p[0] ^= u; p[2] ^= u; p[1] ^= v; p[3] ^= v;
                uint8_t all = p[0] ^ p[1] ^ p[2] ^ p[3], first = p[0];
                p[0] ^= all ^ wl_gf_xtime(p[0] ^ p[1]);
                p[1] ^= all ^ wl_gf_xtime(p[1] ^ p[2]);
                p[2] ^= all ^ wl_gf_xtime(p[2] ^ p[3]);
                p[3] ^= all ^ wl_gf_xtime(p[3] ^ first);
            }
        }
    }
    memcpy(output, s, 16);
    wl_crypto_zero(s, sizeof(s));
    wl_crypto_zero(t, sizeof(t));
    return 1;
}
#endif

/* --------------------------------------------------------------------------
 * FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA-256 & IEEE 802.11 KDF-SHA-256
 * -------------------------------------------------------------------------- */
static const uint32_t wl_sha256_k[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static inline uint32_t wl_rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32U - n));
}

static void wl_sha256_block(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = wl_read_be32(block + i * 4U);
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t s0 = wl_rotr32(w[i - 15], 7) ^ wl_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = wl_rotr32(w[i - 2], 17) ^ wl_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t s1 = wl_rotr32(e, 6) ^ wl_rotr32(e, 11) ^ wl_rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + s1 + ch + wl_sha256_k[i] + w[i];
        uint32_t s0 = wl_rotr32(a, 2) ^ wl_rotr32(a, 13) ^ wl_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void wl_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    uint32_t h[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    uint8_t pad[128];
    if ((!data && len) || !digest) return;
    size_t off = 0;
    while (len - off >= 64U) {
        wl_sha256_block(h, data + off);
        off += 64U;
    }
    size_t rem = len - off;
    memset(pad, 0, sizeof(pad));
    if (rem) memcpy(pad, data + off, rem);
    pad[rem] = 0x80U;
    size_t total = (rem < 56U) ? 64U : 128U;
    uint64_t bits = (uint64_t)len * 8ULL;
    wl_write_be32(pad + total - 8U, (uint32_t)(bits >> 32));
    wl_write_be32(pad + total - 4U, (uint32_t)bits);
    wl_sha256_block(h, pad);
    if (total == 128U) wl_sha256_block(h, pad + 64U);
    for (unsigned i = 0; i < 8; ++i)
        wl_write_be32(digest + i * 4U, h[i]);
}

void wl_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len, uint8_t mac[32])
{
    uint8_t k_pad[64], tk[32], inner[32];
    uint8_t buf[512];
    if ((!key && key_len) || (!data && data_len) || !mac) return;
    if (key_len > 64U) {
        wl_sha256(key, key_len, tk);
        key = tk;
        key_len = 32U;
    }
    memset(k_pad, 0, 64U);
    if (key_len) memcpy(k_pad, key, key_len);
    for (unsigned i = 0; i < 64U; ++i)
        buf[i] = (uint8_t)(k_pad[i] ^ 0x36U);
    size_t copy_len = data_len > (sizeof(buf) - 64U) ? (sizeof(buf) - 64U) : data_len;
    if (copy_len) memcpy(buf + 64U, data, copy_len);
    wl_sha256(buf, 64U + copy_len, inner);
    for (unsigned i = 0; i < 64U; ++i)
        buf[i] = (uint8_t)(k_pad[i] ^ 0x5cU);
    memcpy(buf + 64U, inner, 32U);
    wl_sha256(buf, 96U, mac);
    wl_crypto_zero(k_pad, sizeof(k_pad));
    wl_crypto_zero(tk, sizeof(tk));
    wl_crypto_zero(inner, sizeof(inner));
}

/* IEEE 802.11-2020 Section 12.7.1.7.3 KDF-Hash-Length (SHA-256) */
void wl_kdf_sha256(const uint8_t key[32], const char *label,
                   const uint8_t *context, size_t context_len,
                   uint8_t *out, size_t out_bits)
{
    uint8_t msg[384], block[32];
    if (!key || !label || (!context && context_len) || !out) return;
    size_t label_len = strlen(label);
    size_t out_bytes = (out_bits + 7U) / 8U;
    size_t iterations = (out_bytes + 31U) / 32U;
    size_t produced = 0;
    for (uint16_t i = 1; i <= (uint16_t)iterations; ++i) {
        size_t pos = 0;
        wl_write_le16(msg + pos, i); pos += 2;
        if (pos + label_len <= sizeof(msg)) {
            memcpy(msg + pos, label, label_len);
            pos += label_len;
        }
        if (pos + context_len <= sizeof(msg) - 2U) {
            memcpy(msg + pos, context, context_len);
            pos += context_len;
        }
        wl_write_le16(msg + pos, (uint16_t)out_bits); pos += 2;
        wl_hmac_sha256(key, 32U, msg, pos, block);
        size_t take = (out_bytes - produced < 32U) ? (out_bytes - produced) : 32U;
        memcpy(out + produced, block, take);
        produced += take;
    }
    wl_crypto_zero(block, sizeof(block));
}

/* --------------------------------------------------------------------------
 * NIST P-256 (secp256r1) Elliptic Curve Cryptography (FIPS 186-4)
 * Field prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 * Curve order: n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 * Curve eq:    y^2 = x^3 - 3x + b (mod p)
 * -------------------------------------------------------------------------- */
typedef struct { uint32_t v[8]; } p256_fe;

static const p256_fe P256_P = {{
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU
}};
static const p256_fe P256_N = {{
    0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU
}};
static const p256_fe P256_B = {{
    0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U,
    0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U
}};
static const p256_fe P256_GX = {{
    0xD898C296U, 0xF4A13945U, 0x2DEB33A0U, 0x77037D81U,
    0x63A440F2U, 0xF8BCE6E5U, 0xE12C4247U, 0x6B17D1F2U
}};
static const p256_fe P256_GY = {{
    0x37BF51F5U, 0xCBB64068U, 0x6B315ECEU, 0x2BCE3357U,
    0x7C0F9E16U, 0x8EE7EB4AU, 0xFE1A7F9BU, 0x4FE342E2U
}};

static int p256_cmp(const p256_fe *a, const p256_fe *b)
{
    for (int i = 7; i >= 0; --i) {
        if (a->v[i] > b->v[i]) return 1;
        if (a->v[i] < b->v[i]) return -1;
    }
    return 0;
}

static int p256_is_zero(const p256_fe *a)
{
    uint32_t x = 0;
    for (int i = 0; i < 8; ++i) x |= a->v[i];
    return x == 0;
}

static void p256_from_be(p256_fe *r, const uint8_t b[32])
{
    for (int i = 0; i < 8; ++i)
        r->v[7 - i] = wl_read_be32(b + i * 4);
}

static void p256_to_be(uint8_t b[32], const p256_fe *a)
{
    for (int i = 0; i < 8; ++i)
        wl_write_be32(b + i * 4, a->v[7 - i]);
}

static uint64_t p256_raw_add(p256_fe *r, const p256_fe *a, const p256_fe *b)
{
    uint64_t c = 0;
    for (int i = 0; i < 8; ++i) {
        c += (uint64_t)a->v[i] + b->v[i];
        r->v[i] = (uint32_t)c;
        c >>= 32;
    }
    return c;
}

static uint64_t p256_raw_sub(p256_fe *r, const p256_fe *a, const p256_fe *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t av = a->v[i], bv = (uint64_t)b->v[i] + borrow;
        if (av >= bv) {
            r->v[i] = (uint32_t)(av - bv);
            borrow = 0;
        } else {
            r->v[i] = (uint32_t)((1ULL << 32) + av - bv);
            borrow = 1;
        }
    }
    return borrow;
}

static void p256_fe_add(p256_fe *r, const p256_fe *a, const p256_fe *b)
{
    uint64_t c = p256_raw_add(r, a, b);
    if (c || p256_cmp(r, &P256_P) >= 0)
        p256_raw_sub(r, r, &P256_P);
}

static void p256_fe_sub(p256_fe *r, const p256_fe *a, const p256_fe *b)
{
    if (p256_raw_sub(r, a, b))
        p256_raw_add(r, r, &P256_P);
}

/* FIPS 186-4 Section D.1.2.3 NIST P-256 fast Solinas reduction */
static void p256_fe_mul(p256_fe *r, const p256_fe *a, const p256_fe *b)
{
    uint64_t prod[16] = {0};
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t t = prod[i + j] + (uint64_t)a->v[i] * b->v[j] + carry;
            prod[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        prod[i + 8] = carry;
    }
    int64_t c[8];
    for (int i = 0; i < 8; ++i) c[i] = (int64_t)prod[i];
    int64_t c8  = (int64_t)prod[8],  c9  = (int64_t)prod[9],
            c10 = (int64_t)prod[10], c11 = (int64_t)prod[11],
            c12 = (int64_t)prod[12], c13 = (int64_t)prod[13],
            c14 = (int64_t)prod[14], c15 = (int64_t)prod[15];
    c[0] += c8 + c9 - c11 - c12 - c13 - c14;
    c[1] += c9 + c10 - c12 - c13 - c14 - c15;
    c[2] += c10 + c11 - c13 - c14 - c15;
    c[3] += 2 * c11 + 2 * c12 + c13 - c15 - c8 - c9;
    c[4] += 2 * c12 + 2 * c13 + c14 - c9 - c10;
    c[5] += 2 * c13 + 2 * c14 + c15 - c10 - c11;
    c[6] += 3 * c14 + 2 * c15 + c13 - c8 - c9;
    c[7] += 3 * c15 + c8 - c10 - c11 - c12 - c13;
    int64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        c[i] += carry;
        r->v[i] = (uint32_t)((uint64_t)c[i] & 0xFFFFFFFFULL);
        carry = c[i] >> 32;
    }
    while (carry < 0) {
        carry += (int64_t)p256_raw_add(r, r, &P256_P);
    }
    while (carry > 0) {
        carry -= (int64_t)p256_raw_sub(r, r, &P256_P);
    }
    if (p256_cmp(r, &P256_P) >= 0)
        p256_raw_sub(r, r, &P256_P);
}

static void p256_fe_sqr(p256_fe *r, const p256_fe *a)
{
    p256_fe_mul(r, a, a);
}

/* Fermat inversion a^(p-2) mod p */
static void p256_fe_inv(p256_fe *r, const p256_fe *a)
{
    static const uint32_t pm2[8] = {
        0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
        0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU
    };
    p256_fe res = {{1, 0, 0, 0, 0, 0, 0, 0}}, base = *a;
    for (int i = 0; i < 8; ++i) {
        uint32_t w = pm2[i];
        for (int b = 0; b < 32; ++b) {
            if (w & (1U << b))
                p256_fe_mul(&res, &res, &base);
            p256_fe_sqr(&base, &base);
        }
    }
    *r = res;
}

typedef struct {
    p256_fe x, y;
    int infinity;
} p256_point;

static void p256_point_double(p256_point *r, const p256_point *p)
{
    if (p->infinity || p256_is_zero(&p->y)) {
        r->infinity = 1;
        return;
    }
    p256_fe t1, t2, lambda, x3, y3;
    p256_fe_sqr(&t1, &p->x);
    p256_fe_add(&t2, &t1, &t1);
    p256_fe_add(&t1, &t2, &t1);
    p256_fe three = {{3, 0, 0, 0, 0, 0, 0, 0}};
    p256_fe_sub(&t1, &t1, &three);
    p256_fe_add(&t2, &p->y, &p->y);
    p256_fe_inv(&t2, &t2);
    p256_fe_mul(&lambda, &t1, &t2);
    p256_fe_sqr(&x3, &lambda);
    p256_fe_sub(&x3, &x3, &p->x);
    p256_fe_sub(&x3, &x3, &p->x);
    p256_fe_sub(&t1, &p->x, &x3);
    p256_fe_mul(&y3, &lambda, &t1);
    p256_fe_sub(&y3, &y3, &p->y);
    r->x = x3;
    r->y = y3;
    r->infinity = 0;
}

static void p256_point_add(p256_point *r, const p256_point *p, const p256_point *q)
{
    if (p->infinity) { *r = *q; return; }
    if (q->infinity) { *r = *p; return; }
    if (p256_cmp(&p->x, &q->x) == 0) {
        if (p256_cmp(&p->y, &q->y) == 0)
            p256_point_double(r, p);
        else
            r->infinity = 1;
        return;
    }
    p256_fe t1, t2, lambda, x3, y3;
    p256_fe_sub(&t1, &q->y, &p->y);
    p256_fe_sub(&t2, &q->x, &p->x);
    p256_fe_inv(&t2, &t2);
    p256_fe_mul(&lambda, &t1, &t2);
    p256_fe_sqr(&x3, &lambda);
    p256_fe_sub(&x3, &x3, &p->x);
    p256_fe_sub(&x3, &x3, &q->x);
    p256_fe_sub(&t1, &p->x, &x3);
    p256_fe_mul(&y3, &lambda, &t1);
    p256_fe_sub(&y3, &y3, &p->y);
    r->x = x3;
    r->y = y3;
    r->infinity = 0;
}

static void p256_scalar_mul(p256_point *r, const p256_fe *k, const p256_point *p)
{
    p256_point acc;
    acc.infinity = 1;
    p256_point addend = *p;
    for (int i = 0; i < 8; ++i) {
        uint32_t w = k->v[i];
        for (int b = 0; b < 32; ++b) {
            if (w & (1U << b))
                p256_point_add(&acc, &acc, &addend);
            p256_point_double(&addend, &addend);
        }
    }
    *r = acc;
}

int bt_p256_valid_private_key(const uint8_t private_key[32])
{
    if (!private_key) return 0;
    p256_fe d;
    p256_from_be(&d, private_key);
    return !p256_is_zero(&d) && p256_cmp(&d, &P256_N) < 0;
}

int bt_p256_valid_public_key(const uint8_t public_key[64])
{
    if (!public_key) return 0;
    p256_fe x, y, lhs, rhs, three_x;
    p256_from_be(&x, public_key);
    p256_from_be(&y, public_key + 32);
    if (p256_cmp(&x, &P256_P) >= 0 || p256_cmp(&y, &P256_P) >= 0)
        return 0;
    p256_fe_sqr(&lhs, &y);
    p256_fe_sqr(&rhs, &x);
    p256_fe_mul(&rhs, &rhs, &x);
    p256_fe_add(&three_x, &x, &x);
    p256_fe_add(&three_x, &three_x, &x);
    p256_fe_sub(&rhs, &rhs, &three_x);
    p256_fe_add(&rhs, &rhs, &P256_B);
    return p256_cmp(&lhs, &rhs) == 0;
}

int bt_p256_public_key(const uint8_t private_key[32], uint8_t public_key[64])
{
    if (!private_key || !public_key) return WL_ERR_NULL;
    if (!bt_p256_valid_private_key(private_key)) return WL_ERR_CRYPTO;
    p256_fe d;
    p256_from_be(&d, private_key);
    p256_point g = { P256_GX, P256_GY, 0 }, pub;
    p256_scalar_mul(&pub, &d, &g);
    wl_crypto_zero(&d, sizeof(d));
    if (pub.infinity) return WL_ERR_CRYPTO;
    p256_to_be(public_key, &pub.x);
    p256_to_be(public_key + 32, &pub.y);
    return WL_OK;
}

int bt_p256_ecdh(const uint8_t private_key[32], const uint8_t peer_public_key[64],
                 uint8_t dhkey[32])
{
    if (!private_key || !peer_public_key || !dhkey) return WL_ERR_NULL;
    if (!bt_p256_valid_private_key(private_key) ||
        !bt_p256_valid_public_key(peer_public_key))
        return WL_ERR_CRYPTO;
    p256_fe d;
    p256_point peer, shared;
    p256_from_be(&d, private_key);
    p256_from_be(&peer.x, peer_public_key);
    p256_from_be(&peer.y, peer_public_key + 32);
    peer.infinity = 0;
    p256_scalar_mul(&shared, &d, &peer);
    wl_crypto_zero(&d, sizeof(d));
    if (shared.infinity) return WL_ERR_CRYPTO;
    p256_to_be(dhkey, &shared.x);
    wl_crypto_zero(&shared, sizeof(shared));
    return WL_OK;
}

/* --------------------------------------------------------------------------
 * Bluetooth Core Spec v5.4 Vol 3 Part H Section 2.2 Cryptographic Toolbox
 * -------------------------------------------------------------------------- */

/* Section 2.2.6: f4(U, V, X, Z) = AES-CMAC_X(U || V || Z) */
int bt_smp_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
              uint8_t z, uint8_t out[16])
{
    uint8_t msg[65];
    if (!u || !v || !x || !out) return WL_ERR_NULL;
    memcpy(msg, u, 32);
    memcpy(msg + 32, v, 32);
    msg[64] = z;
    wl_aes128_cmac(x, msg, sizeof(msg), out);
    return WL_OK;
}

/* Section 2.2.7: f5(W, N1, N2, A1, A2) -> MacKey (counter 0) & LTK (counter 1) */
int bt_smp_f5(const uint8_t w[32], const uint8_t n1[16], const uint8_t n2[16],
              const uint8_t a1[7], const uint8_t a2[7],
              uint8_t mac_key[16], uint8_t ltk[16])
{
    static const uint8_t salt[16] = {
        0x6C,0x88,0x83,0x91,0xAA,0xF5,0xA5,0x38,
        0x60,0x37,0x0B,0xDB,0x5A,0x60,0x83,0xBE
    };
    uint8_t t[16], msg[53];
    if (!w || !n1 || !n2 || !a1 || !a2 || !mac_key || !ltk) return WL_ERR_NULL;
    wl_aes128_cmac(salt, w, 32, t);
    msg[0] = 0x00;
    msg[1] = 0x62; msg[2] = 0x74; msg[3] = 0x6C; msg[4] = 0x65; /* "btle" */
    memcpy(msg + 5, n1, 16);
    memcpy(msg + 21, n2, 16);
    memcpy(msg + 37, a1, 7);
    memcpy(msg + 44, a2, 7);
    msg[51] = 0x01; msg[52] = 0x00; /* Length = 256 bits */
    wl_aes128_cmac(t, msg, sizeof(msg), mac_key);
    msg[0] = 0x01;
    wl_aes128_cmac(t, msg, sizeof(msg), ltk);
    wl_crypto_zero(t, sizeof(t));
    return WL_OK;
}

/* Section 2.2.8: f6(W, N1, N2, R, IOcap, A1, A2) = AES-CMAC_W(N1||N2||R||IOcap||A1||A2) */
int bt_smp_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
              const uint8_t r[16], const uint8_t iocap[3],
              const uint8_t a1[7], const uint8_t a2[7], uint8_t out[16])
{
    uint8_t msg[65];
    if (!w || !n1 || !n2 || !r || !iocap || !a1 || !a2 || !out) return WL_ERR_NULL;
    memcpy(msg, n1, 16);
    memcpy(msg + 16, n2, 16);
    memcpy(msg + 32, r, 16);
    memcpy(msg + 48, iocap, 3);
    memcpy(msg + 51, a1, 7);
    memcpy(msg + 58, a2, 7);
    wl_aes128_cmac(w, msg, sizeof(msg), out);
    return WL_OK;
}

/* Section 2.2.9: g2(U, V, X, Y) = AES-CMAC_X(U || V || Y) mod 10^6 */
int bt_smp_g2(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
              const uint8_t y[16], uint32_t *out_passkey)
{
    uint8_t msg[80], mac[16];
    if (!u || !v || !x || !y || !out_passkey) return WL_ERR_NULL;
    memcpy(msg, u, 32);
    memcpy(msg + 32, v, 32);
    memcpy(msg + 64, y, 16);
    wl_aes128_cmac(x, msg, sizeof(msg), mac);
    *out_passkey = wl_read_be32(mac + 12) % 1000000U;
    return WL_OK;
}
