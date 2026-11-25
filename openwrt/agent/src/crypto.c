#define _POSIX_C_SOURCE 200809L
#include "nort_crypto.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/base64.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include <psa/crypto.h>
#endif

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

static secp256k1_context *g_secp_ctx = NULL;

int nort_crypto_init(void) {
#if defined(MBEDTLS_PSA_CRYPTO_C)
    if (psa_crypto_init() != PSA_SUCCESS) {
        return -1;
    }
#endif
    if (!g_secp_ctx) {
        g_secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!g_secp_ctx) return -1;
        uint8_t seed[32];
        if (nort_random_bytes(seed, sizeof(seed)) == 0) {
            (void)secp256k1_context_randomize(g_secp_ctx, seed);
            memset(seed, 0, sizeof(seed));
        }
    }
    return 0;
}

void nort_crypto_cleanup(void) {
    if (g_secp_ctx) {
        secp256k1_context_destroy(g_secp_ctx);
        g_secp_ctx = NULL;
    }
}

int nort_random_bytes(uint8_t *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, out + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

int nort_consttime_eq(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

void nort_hex_encode(const uint8_t *in, size_t len, char *out_hex) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2] = hex[(in[i] >> 4) & 0x0f];
        out_hex[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out_hex[len * 2] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int nort_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex) return -1;
    size_t len = strlen(hex);
    if (len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int nort_sha256(const uint8_t *in, size_t len, uint8_t out32[32]) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    return mbedtls_sha256(in, len, out32, 0) == 0 ? 0 : -1;
#else
    return mbedtls_sha256_ret(in, len, out32, 0) == 0 ? 0 : -1;
#endif
}

int nort_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk32[32]) {
    static const uint8_t zero_salt[32] = {0};
    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return -1;
    return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk32) == 0 ? 0 : -1;
}

int nort_hkdf_expand(const uint8_t prk32[32], const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || okm_len > 255 * 32) return -1;

    uint8_t t[32];
    size_t t_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md, 1) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }

    while (offset < okm_len) {
        if (mbedtls_md_hmac_starts(&ctx, prk32, 32) != 0 ||
            (t_len > 0 && mbedtls_md_hmac_update(&ctx, t, t_len) != 0) ||
            (info_len > 0 && mbedtls_md_hmac_update(&ctx, info, info_len) != 0) ||
            mbedtls_md_hmac_update(&ctx, &counter, 1) != 0 ||
            mbedtls_md_hmac_finish(&ctx, t) != 0) {
            mbedtls_md_free(&ctx);
            return -1;
        }
        t_len = 32;
        size_t copy_len = okm_len - offset;
        if (copy_len > 32) copy_len = 32;
        memcpy(okm + offset, t, copy_len);
        offset += copy_len;
        counter++;
    }
    mbedtls_md_free(&ctx);
    return 0;
}

static uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

#define QR(a, b, c, d) \
    do { \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d, 8);  \
        c += d; b ^= c; b = rotl32(b, 7);  \
    } while (0)

void nort_chacha20_transform(
    const uint8_t key32[32],
    const uint8_t nonce12[12],
    uint32_t initial_counter,
    const uint8_t *in,
    uint8_t *out,
    size_t len
) {
    uint32_t state[16];
    uint32_t working[16];
    uint8_t keystream[64];

    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) state[4 + i] = load32_le(key32 + i * 4);
    state[12] = initial_counter;
    state[13] = load32_le(nonce12);
    state[14] = load32_le(nonce12 + 4);
    state[15] = load32_le(nonce12 + 8);

    size_t offset = 0;
    while (offset < len) {
        memcpy(working, state, sizeof(state));
        for (int r = 0; r < 10; r++) {
            QR(working[0], working[4], working[8], working[12]);
            QR(working[1], working[5], working[9], working[13]);
            QR(working[2], working[6], working[10], working[14]);
            QR(working[3], working[7], working[11], working[15]);
            QR(working[0], working[5], working[10], working[15]);
            QR(working[1], working[6], working[11], working[12]);
            QR(working[2], working[7], working[8], working[13]);
            QR(working[3], working[4], working[9], working[14]);
        }
        for (int i = 0; i < 16; i++) {
            store32_le(keystream + i * 4, working[i] + state[i]);
        }
        size_t chunk = len - offset;
        if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] = (uint8_t)(in[offset + i] ^ keystream[i]);
        }
        offset += chunk;
        state[12]++;
    }
    memset(working, 0, sizeof(working));
    memset(keystream, 0, sizeof(keystream));
}

int nort_secp256k1_xonly_pubkey(const uint8_t priv32[32], uint8_t xonly_pub32[32]) {
    if (!g_secp_ctx && nort_crypto_init() != 0) return -1;
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(g_secp_ctx, &kp, priv32)) return -1;
    secp256k1_xonly_pubkey xpub;
    int ok = secp256k1_keypair_xonly_pub(g_secp_ctx, &xpub, NULL, &kp);
    memset(&kp, 0, sizeof(kp));
    if (!ok) return -1;
    return secp256k1_xonly_pubkey_serialize(g_secp_ctx, xonly_pub32, &xpub) ? 0 : -1;
}

int nort_secp256k1_gen_keypair(uint8_t priv32[32], uint8_t xonly_pub32[32]) {
    if (!g_secp_ctx && nort_crypto_init() != 0) return -1;
    for (int i = 0; i < 64; i++) {
        if (nort_random_bytes(priv32, 32) != 0) return -1;
        if (secp256k1_ec_seckey_verify(g_secp_ctx, priv32)) {
            return nort_secp256k1_xonly_pubkey(priv32, xonly_pub32);
        }
    }
    return -1;
}

static int ecdh_raw_x_hashfp(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)y32;
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}

int nort_secp256k1_ecdh_raw_x(const uint8_t priv32[32], const uint8_t peer_xonly_pub32[32], uint8_t shared_x32[32]) {
    if (!g_secp_ctx && nort_crypto_init() != 0) return -1;
    uint8_t compressed[33];
    compressed[0] = 0x02;
    memcpy(compressed + 1, peer_xonly_pub32, 32);

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(g_secp_ctx, &pub, compressed, sizeof(compressed))) {
        return -1;
    }
    return secp256k1_ecdh(g_secp_ctx, shared_x32, &pub, priv32, ecdh_raw_x_hashfp, NULL) ? 0 : -1;
}

int nort_schnorr_sign(const uint8_t msg_hash32[32], const uint8_t priv32[32], uint8_t sig64[64]) {
    if (!g_secp_ctx && nort_crypto_init() != 0) return -1;
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(g_secp_ctx, &kp, priv32)) return -1;
    uint8_t aux[32];
    if (nort_random_bytes(aux, sizeof(aux)) != 0) {
        memset(&kp, 0, sizeof(kp));
        return -1;
    }
    int ok = secp256k1_schnorrsig_sign32(g_secp_ctx, sig64, msg_hash32, &kp, aux);
    memset(&kp, 0, sizeof(kp));
    memset(aux, 0, sizeof(aux));
    return ok ? 0 : -1;
}

int nort_schnorr_verify(const uint8_t msg_hash32[32], const uint8_t sig64[64], const uint8_t xonly_pub32[32]) {
    if (!g_secp_ctx && nort_crypto_init() != 0) return -1;
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_xonly_pubkey_parse(g_secp_ctx, &xpub, xonly_pub32)) return -1;
    return secp256k1_schnorrsig_verify(g_secp_ctx, sig64, msg_hash32, 32, &xpub) ? 0 : -1;
}

size_t nort_nip44_calc_padded_len(size_t unpadded_len) {
    if (unpadded_len < 1 || unpadded_len > 65535) return 0;
    if (unpadded_len <= 32) return 32;

    size_t v = unpadded_len - 1;
    size_t next_power = 1;
    while (next_power <= v) {
        next_power <<= 1;
    }
    size_t chunk = (next_power <= 256) ? 32 : (next_power / 8);
    return chunk * (((unpadded_len - 1) / chunk) + 1);
}

int nort_nip44_conversation_key(const uint8_t priv32[32], const uint8_t peer_xonly_pub32[32], uint8_t conv_key32[32]) {
    uint8_t shared_x[32];
    if (nort_secp256k1_ecdh_raw_x(priv32, peer_xonly_pub32, shared_x) != 0) return -1;
    static const uint8_t salt[] = "nip44-v2";
    int rc = nort_hkdf_extract(salt, sizeof(salt) - 1, shared_x, sizeof(shared_x), conv_key32);
    memset(shared_x, 0, sizeof(shared_x));
    return rc;
}

static int nip44_hmac_aad(const uint8_t hmac_key[32], const uint8_t nonce32[32], const uint8_t *cipher, size_t cipher_len, uint8_t out_mac[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return -1;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md, 1) != 0 ||
        mbedtls_md_hmac_starts(&ctx, hmac_key, 32) != 0 ||
        mbedtls_md_hmac_update(&ctx, nonce32, 32) != 0 ||
        mbedtls_md_hmac_update(&ctx, cipher, cipher_len) != 0 ||
        mbedtls_md_hmac_finish(&ctx, out_mac) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }
    mbedtls_md_free(&ctx);
    return 0;
}

int nort_nip44_encrypt_with_nonce(
    const char *plaintext,
    size_t plaintext_len,
    const uint8_t conv_key32[32],
    const uint8_t nonce32[32],
    char **out_b64
) {
    size_t padded_len = nort_nip44_calc_padded_len(plaintext_len);
    if (padded_len == 0) return -1;

    uint8_t okm[76];
    if (nort_hkdf_expand(conv_key32, nonce32, 32, okm, sizeof(okm)) != 0) return -1;
    const uint8_t *chacha_key = okm;
    const uint8_t *chacha_nonce = okm + 32;
    const uint8_t *hmac_key = okm + 44;

    size_t cipher_len = 2 + padded_len;
    uint8_t *padded = calloc(1, cipher_len);
    size_t raw_len = 1 + 32 + cipher_len + 32;
    uint8_t *raw = malloc(raw_len);
    if (!padded || !raw) {
        free(padded);
        free(raw);
        memset(okm, 0, sizeof(okm));
        return -1;
    }

    padded[0] = (uint8_t)((plaintext_len >> 8) & 0xff);
    padded[1] = (uint8_t)(plaintext_len & 0xff);
    memcpy(padded + 2, plaintext, plaintext_len);

    raw[0] = 2;
    memcpy(raw + 1, nonce32, 32);
    nort_chacha20_transform(chacha_key, chacha_nonce, 0u, padded, raw + 33, cipher_len);

    int rc = nip44_hmac_aad(hmac_key, nonce32, raw + 33, cipher_len, raw + 33 + cipher_len);
    memset(padded, 0, cipher_len);
    free(padded);
    memset(okm, 0, sizeof(okm));
    if (rc != 0) {
        free(raw);
        return -1;
    }

    size_t b64_cap = ((raw_len + 2) / 3) * 4 + 4;
    char *b64 = malloc(b64_cap);
    if (!b64) {
        free(raw);
        return -1;
    }
    size_t b64_len = 0;
    if (mbedtls_base64_encode((unsigned char *)b64, b64_cap, &b64_len, raw, raw_len) != 0) {
        free(raw);
        free(b64);
        return -1;
    }
    b64[b64_len] = '\0';
    free(raw);
    *out_b64 = b64;
    return 0;
}

int nort_nip44_encrypt(const char *plaintext, size_t plaintext_len, const uint8_t conv_key32[32], char **out_b64) {
    uint8_t nonce[32];
    if (nort_random_bytes(nonce, sizeof(nonce)) != 0) return -1;
    return nort_nip44_encrypt_with_nonce(plaintext, plaintext_len, conv_key32, nonce, out_b64);
}

int nort_nip44_decrypt(const char *payload_b64, const uint8_t conv_key32[32], char **out_plaintext, size_t *out_len) {
    if (!payload_b64 || payload_b64[0] == '\0' || payload_b64[0] == '#') return -1;
    size_t b64_len = strlen(payload_b64);
    size_t raw_cap = b64_len;
    uint8_t *raw = malloc(raw_cap);
    if (!raw) return -1;

    size_t raw_len = 0;
    if (mbedtls_base64_decode(raw, raw_cap, &raw_len, (const unsigned char *)payload_b64, b64_len) != 0) {
        free(raw);
        return -1;
    }
    if (raw_len < 99 || raw_len > 65603 || raw[0] != 2) {
        free(raw);
        return -1;
    }

    const uint8_t *nonce = raw + 1;
    const uint8_t *cipher = raw + 33;
    size_t cipher_len = raw_len - 65;
    const uint8_t *mac = raw + raw_len - 32;

    uint8_t okm[76];
    if (nort_hkdf_expand(conv_key32, nonce, 32, okm, sizeof(okm)) != 0) {
        free(raw);
        return -1;
    }

    uint8_t expected_mac[32];
    if (nip44_hmac_aad(okm + 44, nonce, cipher, cipher_len, expected_mac) != 0 ||
        !nort_consttime_eq(mac, expected_mac, 32)) {
        memset(okm, 0, sizeof(okm));
        free(raw);
        return -1;
    }

    uint8_t *padded = malloc(cipher_len);
    if (!padded) {
        memset(okm, 0, sizeof(okm));
        free(raw);
        return -1;
    }
    nort_chacha20_transform(okm, okm + 32, 0u, cipher, padded, cipher_len);
    memset(okm, 0, sizeof(okm));
    free(raw);

    if (cipher_len < 2) {
        free(padded);
        return -1;
    }
    size_t unpadded_len = ((size_t)padded[0] << 8) | (size_t)padded[1];
    size_t expected_padded = nort_nip44_calc_padded_len(unpadded_len);
    if (expected_padded == 0 || cipher_len != 2 + expected_padded) {
        memset(padded, 0, cipher_len);
        free(padded);
        return -1;
    }

    char *plain = malloc(unpadded_len + 1);
    if (!plain) {
        memset(padded, 0, cipher_len);
        free(padded);
        return -1;
    }
    memcpy(plain, padded + 2, unpadded_len);
    plain[unpadded_len] = '\0';
    memset(padded, 0, cipher_len);
    free(padded);

    *out_plaintext = plain;
    if (out_len) *out_len = unpadded_len;
    return 0;
}

/* --- NIP-19 Bech32 --- */

static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod(const uint8_t *values, size_t len) {
    static const uint32_t gen[5] = {0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffffu) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            if ((top >> j) & 1u) chk ^= gen[j];
        }
    }
    return chk;
}

static int convert_bits(const uint8_t *in, size_t in_len, int from_bits, int to_bits, bool pad, uint8_t *out, size_t *out_len) {
    int acc = 0, bits = 0;
    int maxv = (1 << to_bits) - 1;
    size_t idx = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << from_bits) | in[i];
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            out[idx++] = (uint8_t)((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) out[idx++] = (uint8_t)((acc << (to_bits - bits)) & maxv);
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0) {
        return -1;
    }
    *out_len = idx;
    return 0;
}

static int bech32_encode_32(const char *hrp, const uint8_t data32[32], char *out, size_t out_cap) {
    size_t hrp_len = strlen(hrp);
    uint8_t conv[64];
    size_t conv_len = 0;
    if (convert_bits(data32, 32, 8, 5, true, conv, &conv_len) != 0) return -1;
    if (out_cap < hrp_len + 1 + conv_len + 6 + 1) return -1;

    uint8_t vals[128];
    size_t vlen = 0;
    for (size_t i = 0; i < hrp_len; i++) vals[vlen++] = (uint8_t)(hrp[i] >> 5);
    vals[vlen++] = 0;
    for (size_t i = 0; i < hrp_len; i++) vals[vlen++] = (uint8_t)(hrp[i] & 31);
    memcpy(vals + vlen, conv, conv_len);
    vlen += conv_len;
    memset(vals + vlen, 0, 6);
    vlen += 6;

    uint32_t mod = bech32_polymod(vals, vlen) ^ 1u;
    size_t pos = 0;
    memcpy(out + pos, hrp, hrp_len);
    pos += hrp_len;
    out[pos++] = '1';
    for (size_t i = 0; i < conv_len; i++) out[pos++] = BECH32_CHARSET[conv[i]];
    for (int i = 0; i < 6; i++) out[pos++] = BECH32_CHARSET[(mod >> (5 * (5 - i))) & 31];
    out[pos] = '\0';
    return 0;
}

static int bech32_decode_32(const char *bech, const char *expected_hrp, uint8_t out32[32]) {
    if (!bech) return -1;
    size_t len = strlen(bech);
    size_t hrp_len = strlen(expected_hrp);
    if (len < hrp_len + 1 + 6 || len > 120) return -1;

    for (size_t i = 0; i < hrp_len; i++) {
        if (tolower((unsigned char)bech[i]) != expected_hrp[i]) return -1;
    }
    if (bech[hrp_len] != '1') return -1;

    size_t data_len = len - hrp_len - 1;
    uint8_t data[96];
    if (data_len > sizeof(data) || data_len < 7) return -1;

    for (size_t i = 0; i < data_len; i++) {
        char ch = (char)tolower((unsigned char)bech[hrp_len + 1 + i]);
        const char *found = strchr(BECH32_CHARSET, ch);
        if (!found) return -1;
        data[i] = (uint8_t)(found - BECH32_CHARSET);
    }

    uint8_t vals[128];
    size_t vlen = 0;
    for (size_t i = 0; i < hrp_len; i++) vals[vlen++] = (uint8_t)(expected_hrp[i] >> 5);
    vals[vlen++] = 0;
    for (size_t i = 0; i < hrp_len; i++) vals[vlen++] = (uint8_t)(expected_hrp[i] & 31);
    memcpy(vals + vlen, data, data_len);
    vlen += data_len;

    if (bech32_polymod(vals, vlen) != 1u) return -1;

    uint8_t decoded[64];
    size_t dec_len = 0;
    if (convert_bits(data, data_len - 6, 5, 8, false, decoded, &dec_len) != 0 || dec_len != 32) return -1;
    memcpy(out32, decoded, 32);
    return 0;
}

int nort_bech32_encode_npub(const uint8_t pub32[32], char *out_npub, size_t out_cap) {
    return bech32_encode_32("npub", pub32, out_npub, out_cap);
}

int nort_bech32_encode_nsec(const uint8_t priv32[32], char *out_nsec, size_t out_cap) {
    return bech32_encode_32("nsec", priv32, out_nsec, out_cap);
}

int nort_bech32_decode_npub(const char *npub, uint8_t pub32[32]) {
    return bech32_decode_32(npub, "npub", pub32);
}

int nort_bech32_decode_nsec(const char *nsec, uint8_t priv32[32]) {
    return bech32_decode_32(nsec, "nsec", priv32);
}

/* --- NORT-1 PFS Tunnel AES-256-GCM --- */

static void write_u64_be(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

static uint64_t read_u64_be(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

int nort_tunnel_crypto_init(
    nort_tunnel_crypto_t *tc,
    bool is_router,
    const uint8_t local_eph_priv32[32],
    const uint8_t remote_eph_xonly_pub32[32],
    const uint8_t client_id_pub32[32],
    const uint8_t router_id_pub32[32],
    const char *session_id,
    const uint8_t client_eph_pub32[32],
    const uint8_t router_eph_pub32[32]
) {
    memset(tc, 0, sizeof(*tc));
    tc->is_router = is_router;
    tc->session_id_len = strlen(session_id);
    tc->session_id = strdup(session_id);
    if (!tc->session_id) return -1;

    uint8_t shared_x[32];
    if (nort_secp256k1_ecdh_raw_x(local_eph_priv32, remote_eph_xonly_pub32, shared_x) != 0) {
        free(tc->session_id);
        tc->session_id = NULL;
        return -1;
    }

    size_t tlen = 6 + 32 + 32 + tc->session_id_len + 32 + 32;
    uint8_t *tbuf = malloc(tlen);
    if (!tbuf) {
        memset(shared_x, 0, sizeof(shared_x));
        free(tc->session_id);
        tc->session_id = NULL;
        return -1;
    }
    size_t off = 0;
    memcpy(tbuf + off, "NORT-1", 6); off += 6;
    memcpy(tbuf + off, client_id_pub32, 32); off += 32;
    memcpy(tbuf + off, router_id_pub32, 32); off += 32;
    memcpy(tbuf + off, session_id, tc->session_id_len); off += tc->session_id_len;
    memcpy(tbuf + off, client_eph_pub32, 32); off += 32;
    memcpy(tbuf + off, router_eph_pub32, 32);

    uint8_t transcript_hash[32];
    uint8_t prk[32];
    int rc = nort_sha256(tbuf, tlen, transcript_hash);
    free(tbuf);
    if (rc == 0) rc = nort_hkdf_extract(transcript_hash, 32, shared_x, 32, prk);
    memset(shared_x, 0, sizeof(shared_x));

    static const uint8_t info_c2r[] = "nort-c2r-aes256gcm";
    static const uint8_t info_r2c[] = "nort-r2c-aes256gcm";
    if (rc == 0) rc = nort_hkdf_expand(prk, info_c2r, sizeof(info_c2r) - 1, tc->key_c2r, 32);
    if (rc == 0) rc = nort_hkdf_expand(prk, info_r2c, sizeof(info_r2c) - 1, tc->key_r2c, 32);
    memset(prk, 0, sizeof(prk));

    if (rc != 0) {
        free(tc->session_id);
        tc->session_id = NULL;
        return -1;
    }

    pthread_mutex_init(&tc->tx_lock, NULL);
    pthread_mutex_init(&tc->rx_lock, NULL);
    return 0;
}

int nort_tunnel_crypto_seal(
    nort_tunnel_crypto_t *tc,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **out_envelope,
    size_t *out_len
) {
    pthread_mutex_lock(&tc->tx_lock);
    uint64_t seq = ++tc->tx_seq;
    pthread_mutex_unlock(&tc->tx_lock);

    uint8_t dir = tc->is_router ? NORT_DIR_ROUTER_TO_CLIENT : NORT_DIR_CLIENT_TO_ROUTER;
    const uint8_t *key = tc->is_router ? tc->key_r2c : tc->key_c2r;

    uint8_t nonce[12] = {0};
    write_u64_be(nonce + 4, seq);

    size_t aad_len = tc->session_id_len + 9;
    uint8_t *aad = malloc(aad_len);
    size_t env_len = 9 + plaintext_len + 16;
    uint8_t *env = malloc(env_len);
    if (!aad || !env) {
        free(aad);
        free(env);
        return -1;
    }

    memcpy(aad, tc->session_id, tc->session_id_len);
    aad[tc->session_id_len] = dir;
    write_u64_be(aad + tc->session_id_len + 1, seq);

    env[0] = dir;
    write_u64_be(env + 1, seq);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(
            &gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len,
            nonce, sizeof(nonce), aad, aad_len,
            plaintext, env + 9, 16, env + 9 + plaintext_len);
    }
    mbedtls_gcm_free(&gcm);
    free(aad);

    if (rc != 0) {
        free(env);
        return -1;
    }
    *out_envelope = env;
    *out_len = env_len;
    return 0;
}

int nort_tunnel_crypto_open(
    nort_tunnel_crypto_t *tc,
    const uint8_t *envelope,
    size_t envelope_len,
    uint8_t **out_plaintext,
    size_t *out_len
) {
    if (envelope_len < 9 + 16) return -1;

    uint8_t dir = envelope[0];
    uint64_t seq = read_u64_be(envelope + 1);
    uint8_t expected_dir = tc->is_router ? NORT_DIR_CLIENT_TO_ROUTER : NORT_DIR_ROUTER_TO_CLIENT;
    if (dir != expected_dir) return -1;
    const uint8_t *key = tc->is_router ? tc->key_c2r : tc->key_r2c;

    uint8_t nonce[12] = {0};
    write_u64_be(nonce + 4, seq);

    size_t aad_len = tc->session_id_len + 9;
    uint8_t *aad = malloc(aad_len);
    size_t cipher_len = envelope_len - 9 - 16;
    uint8_t *plain = malloc(cipher_len > 0 ? cipher_len : 1);
    if (!aad || !plain) {
        free(aad);
        free(plain);
        return -1;
    }
    memcpy(aad, tc->session_id, tc->session_id_len);
    aad[tc->session_id_len] = dir;
    write_u64_be(aad + tc->session_id_len + 1, seq);

    pthread_mutex_lock(&tc->rx_lock);
    if (seq == 0 || seq <= tc->last_rx_seq) {
        pthread_mutex_unlock(&tc->rx_lock);
        free(aad);
        free(plain);
        return -1;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(
            &gcm, cipher_len,
            nonce, sizeof(nonce), aad, aad_len,
            envelope + 9 + cipher_len, 16,
            envelope + 9, plain);
    }
    mbedtls_gcm_free(&gcm);
    free(aad);

    if (rc != 0) {
        pthread_mutex_unlock(&tc->rx_lock);
        free(plain);
        return -1;
    }
    tc->last_rx_seq = seq;
    pthread_mutex_unlock(&tc->rx_lock);

    *out_plaintext = plain;
    *out_len = cipher_len;
    return 0;
}

void nort_tunnel_crypto_free(nort_tunnel_crypto_t *tc) {
    if (!tc) return;
    free(tc->session_id);
    memset(tc->key_c2r, 0, sizeof(tc->key_c2r));
    memset(tc->key_r2c, 0, sizeof(tc->key_r2c));
    pthread_mutex_destroy(&tc->tx_lock);
    pthread_mutex_destroy(&tc->rx_lock);
    memset(tc, 0, sizeof(*tc));
}
