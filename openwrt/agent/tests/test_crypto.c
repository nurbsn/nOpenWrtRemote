#include "nort_crypto.h"
#include "nort_framing.h"
#include "nort_nostr.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_chacha20_rfc8439(void) {
    uint8_t key[32], nonce[12], expected[114];
    assert(nort_hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32) == 0);
    assert(nort_hex_decode("000000000000004a00000000", nonce, 12) == 0);
    assert(nort_hex_decode(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d", expected, sizeof(expected)) == 0);

    const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t out[114];
    nort_chacha20_transform(key, nonce, 1u, (const uint8_t *)pt, out, sizeof(expected));
    assert(memcmp(out, expected, sizeof(expected)) == 0);
}

static void test_nip44_padding_and_roundtrip(void) {
    assert(nort_nip44_calc_padded_len(1) == 32);
    assert(nort_nip44_calc_padded_len(32) == 32);
    assert(nort_nip44_calc_padded_len(33) == 64);
    assert(nort_nip44_calc_padded_len(256) == 256);
    assert(nort_nip44_calc_padded_len(257) == 320);
    assert(nort_nip44_calc_padded_len(513) == 640);
    assert(nort_nip44_calc_padded_len(10000) == 10240);
    assert(nort_nip44_calc_padded_len(65535) == 65536);

    uint8_t skA[32], pkA[32], skB[32], pkB[32], skC[32], pkC[32];
    assert(nort_secp256k1_gen_keypair(skA, pkA) == 0);
    assert(nort_secp256k1_gen_keypair(skB, pkB) == 0);
    assert(nort_secp256k1_gen_keypair(skC, pkC) == 0);

    uint8_t convAB[32], convBA[32], convCA[32];
    assert(nort_nip44_conversation_key(skA, pkB, convAB) == 0);
    assert(nort_nip44_conversation_key(skB, pkA, convBA) == 0);
    assert(memcmp(convAB, convBA, 32) == 0);

    const char *msg = "{\"type\":\"tunnel_open\",\"session_id\":\"abc123\"}";
    char *enc = NULL;
    assert(nort_nip44_encrypt(msg, strlen(msg), convAB, &enc) == 0);

    char *dec = NULL;
    size_t dec_len = 0;
    assert(nort_nip44_decrypt(enc, convBA, &dec, &dec_len) == 0);
    assert(dec_len == strlen(msg) && strcmp(dec, msg) == 0);

    assert(nort_nip44_conversation_key(skC, pkA, convCA) == 0);
    char *bad_dec = NULL;
    assert(nort_nip44_decrypt(enc, convCA, &bad_dec, NULL) != 0);

    /* Tamper base64 payload */
    size_t elen = strlen(enc);
    enc[elen - 2] = (enc[elen - 2] == 'A') ? 'B' : 'A';
    assert(nort_nip44_decrypt(enc, convBA, &bad_dec, NULL) != 0);

    free(enc);
    free(dec);
}

static void test_bech32_and_schnorr(void) {
    uint8_t sk[32], pk[32], dec_pk[32], dec_sk[32];
    assert(nort_secp256k1_gen_keypair(sk, pk) == 0);

    char npub[96], nsec[96];
    assert(nort_bech32_encode_npub(pk, npub, sizeof(npub)) == 0);
    assert(nort_bech32_encode_nsec(sk, nsec, sizeof(nsec)) == 0);
    assert(nort_bech32_decode_npub(npub, dec_pk) == 0);
    assert(nort_bech32_decode_nsec(nsec, dec_sk) == 0);
    assert(memcmp(pk, dec_pk, 32) == 0);
    assert(memcmp(sk, dec_sk, 32) == 0);

    npub[strlen(npub) - 1] = (npub[strlen(npub) - 1] == 'q') ? 'p' : 'q';
    assert(nort_bech32_decode_npub(npub, dec_pk) != 0);

    char *evt_json = NULL;
    assert(nort_nostr_sign_event(sk, 24135, "[[\"p\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]]", "hello+nostr/==", 1764090000, &evt_json) == 0);

    nort_nostr_event_t evt;
    assert(nort_nostr_verify_event(evt_json, &evt) == 0);
    nort_nostr_event_free(&evt);
    free(evt_json);
}

static void test_tunnel_crypto_and_framing(void) {
    uint8_t c_id[32], r_id[32], c_eph_s[32], c_eph_p[32], r_eph_s[32], r_eph_p[32];
    assert(nort_random_bytes(c_id, 32) == 0);
    assert(nort_random_bytes(r_id, 32) == 0);
    assert(nort_secp256k1_gen_keypair(c_eph_s, c_eph_p) == 0);
    assert(nort_secp256k1_gen_keypair(r_eph_s, r_eph_p) == 0);

    const char *sid = "0123456789abcdef0123456789abcdef";
    nort_tunnel_crypto_t client, router;
    assert(nort_tunnel_crypto_init(&client, false, c_eph_s, r_eph_p, c_id, r_id, sid, c_eph_p, r_eph_p) == 0);
    assert(nort_tunnel_crypto_init(&router, true, r_eph_s, c_eph_p, c_id, r_id, sid, c_eph_p, r_eph_p) == 0);

    uint8_t *env1 = NULL, *plain1 = NULL;
    size_t env1_len = 0, plain1_len = 0;
    assert(nort_tunnel_crypto_seal(&client, (const uint8_t *)"hello-openwrt", 13, &env1, &env1_len) == 0);
    assert(nort_tunnel_crypto_open(&router, env1, env1_len, &plain1, &plain1_len) == 0);
    assert(plain1_len == 13 && memcmp(plain1, "hello-openwrt", 13) == 0);

    /* Replay must fail */
    uint8_t *replay = NULL;
    assert(nort_tunnel_crypto_open(&router, env1, env1_len, &replay, &plain1_len) != 0);

    /* Reverse direction + tamper rejection */
    uint8_t *renv = NULL, *rplain = NULL;
    size_t renv_len = 0, rplain_len = 0;
    assert(nort_tunnel_crypto_seal(&router, (const uint8_t *)"ok", 2, &renv, &renv_len) == 0);
    renv[renv_len - 1] ^= 0x01;
    assert(nort_tunnel_crypto_open(&client, renv, renv_len, &rplain, &rplain_len) != 0);

    free(env1);
    free(plain1);
    free(renv);

    uint8_t *fbuf = NULL;
    size_t flen = 0;
    assert(nort_frame_encode(NORT_FRAME_HTTP_REQ_META, 42u, (const uint8_t *)"{}", 2, &fbuf, &flen) == 0);
    nort_frame_t df;
    assert(nort_frame_decode(fbuf, flen, &df) == 0);
    assert(df.type == NORT_FRAME_HTTP_REQ_META && df.stream_id == 42u && df.payload_len == 2);
    nort_frame_free(&df);
    free(fbuf);

    nort_tunnel_crypto_free(&client);
    nort_tunnel_crypto_free(&router);
}

int main(void) {
    assert(nort_crypto_init() == 0);
    test_chacha20_rfc8439();
    test_nip44_padding_and_roundtrip();
    test_bech32_and_schnorr();
    test_tunnel_crypto_and_framing();
    nort_crypto_cleanup();
    printf("All C11 NORT-1 crypto & framing tests PASSED.\n");
    return 0;
}
