#ifndef NORT_CRYPTO_H
#define NORT_CRYPTO_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NORT_DIR_CLIENT_TO_ROUTER 0x01
#define NORT_DIR_ROUTER_TO_CLIENT 0x02

int nort_crypto_init(void);
void nort_crypto_cleanup(void);

int nort_random_bytes(uint8_t *out, size_t len);
int nort_consttime_eq(const void *a, const void *b, size_t len);

void nort_hex_encode(const uint8_t *in, size_t len, char *out_hex);
int nort_hex_decode(const char *hex, uint8_t *out, size_t out_len);

int nort_sha256(const uint8_t *in, size_t len, uint8_t out32[32]);
int nort_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk32[32]);
int nort_hkdf_expand(const uint8_t prk32[32], const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

void nort_chacha20_transform(
    const uint8_t key32[32],
    const uint8_t nonce12[12],
    uint32_t initial_counter,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

int nort_secp256k1_xonly_pubkey(const uint8_t priv32[32], uint8_t xonly_pub32[32]);
int nort_secp256k1_gen_keypair(uint8_t priv32[32], uint8_t xonly_pub32[32]);
int nort_secp256k1_ecdh_raw_x(const uint8_t priv32[32], const uint8_t peer_xonly_pub32[32], uint8_t shared_x32[32]);
int nort_schnorr_sign(const uint8_t msg_hash32[32], const uint8_t priv32[32], uint8_t sig64[64]);
int nort_schnorr_verify(const uint8_t msg_hash32[32], const uint8_t sig64[64], const uint8_t xonly_pub32[32]);

size_t nort_nip44_calc_padded_len(size_t unpadded_len);
int nort_nip44_conversation_key(const uint8_t priv32[32], const uint8_t peer_xonly_pub32[32], uint8_t conv_key32[32]);
int nort_nip44_encrypt_with_nonce(
    const char *plaintext,
    size_t plaintext_len,
    const uint8_t conv_key32[32],
    const uint8_t nonce32[32],
    char **out_b64
);
int nort_nip44_encrypt(const char *plaintext, size_t plaintext_len, const uint8_t conv_key32[32], char **out_b64);
int nort_nip44_decrypt(const char *payload_b64, const uint8_t conv_key32[32], char **out_plaintext, size_t *out_len);

int nort_bech32_encode_npub(const uint8_t pub32[32], char *out_npub, size_t out_cap);
int nort_bech32_encode_nsec(const uint8_t priv32[32], char *out_nsec, size_t out_cap);
int nort_bech32_decode_npub(const char *npub, uint8_t pub32[32]);
int nort_bech32_decode_nsec(const char *nsec, uint8_t priv32[32]);

typedef struct {
    char *session_id;
    size_t session_id_len;
    bool is_router;
    uint8_t key_c2r[32];
    uint8_t key_r2c[32];
    pthread_mutex_t tx_lock;
    uint64_t tx_seq;
    pthread_mutex_t rx_lock;
    uint64_t last_rx_seq;
} nort_tunnel_crypto_t;

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
);

int nort_tunnel_crypto_seal(
    nort_tunnel_crypto_t *tc,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **out_envelope,
    size_t *out_len
);

int nort_tunnel_crypto_open(
    nort_tunnel_crypto_t *tc,
    const uint8_t *envelope,
    size_t envelope_len,
    uint8_t **out_plaintext,
    size_t *out_len
);

void nort_tunnel_crypto_free(nort_tunnel_crypto_t *tc);

#ifdef __cplusplus
}
#endif

#endif
