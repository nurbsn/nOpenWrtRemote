#define _POSIX_C_SOURCE 200809L
#include "nort_nostr.h"
#include "nort_crypto.h"
#include "nort_tunnel.h"
#include "nort_ws.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

static bool is_lower_hex_range(const char *s, size_t min_len, size_t max_len) {
    if (!s) return false;
    size_t n = strlen(s);
    if (n < min_len || n > max_len) return false;
    for (size_t i = 0; i < n; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    }
    return true;
}

int nort_nostr_compute_event_id(
    const char *pub_hex,
    int64_t created_at,
    int kind,
    const char *tags_json,
    const char *content,
    char out_id_hex[65]
) {
    struct json_object *arr = json_object_new_array();
    struct json_object *tags = tags_json ? json_tokener_parse(tags_json) : json_object_new_array();
    if (!tags || !json_object_is_type(tags, json_type_array)) {
        if (tags) json_object_put(tags);
        tags = json_object_new_array();
    }

    json_object_array_add(arr, json_object_new_int(0));
    json_object_array_add(arr, json_object_new_string(pub_hex));
    json_object_array_add(arr, json_object_new_int64(created_at));
    json_object_array_add(arr, json_object_new_int(kind));
    json_object_array_add(arr, tags);
    json_object_array_add(arr, json_object_new_string(content ? content : ""));

    const char *canonical = json_object_to_json_string_ext(
        arr, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);

    uint8_t hash[32];
    int rc = nort_sha256((const uint8_t *)canonical, strlen(canonical), hash);
    json_object_put(arr);
    if (rc != 0) return -1;

    nort_hex_encode(hash, 32, out_id_hex);
    return 0;
}

int nort_nostr_sign_event(
    const uint8_t priv32[32],
    int kind,
    const char *tags_json,
    const char *content,
    int64_t created_at,
    char **out_event_json
) {
    uint8_t pub32[32];
    if (nort_secp256k1_xonly_pubkey(priv32, pub32) != 0) return -1;
    char pub_hex[65];
    nort_hex_encode(pub32, 32, pub_hex);

    if (created_at <= 0) created_at = (int64_t)time(NULL);

    char id_hex[65];
    if (nort_nostr_compute_event_id(pub_hex, created_at, kind, tags_json, content, id_hex) != 0) return -1;

    uint8_t id_bytes[32], sig_bytes[64];
    nort_hex_decode(id_hex, id_bytes, 32);
    if (nort_schnorr_sign(id_bytes, priv32, sig_bytes) != 0) return -1;
    char sig_hex[129];
    nort_hex_encode(sig_bytes, 64, sig_hex);

    struct json_object *evt = json_object_new_object();
    struct json_object *tags = tags_json ? json_tokener_parse(tags_json) : json_object_new_array();
    if (!tags) tags = json_object_new_array();

    json_object_object_add(evt, "id", json_object_new_string(id_hex));
    json_object_object_add(evt, "pubkey", json_object_new_string(pub_hex));
    json_object_object_add(evt, "created_at", json_object_new_int64(created_at));
    json_object_object_add(evt, "kind", json_object_new_int(kind));
    json_object_object_add(evt, "tags", tags);
    json_object_object_add(evt, "content", json_object_new_string(content ? content : ""));
    json_object_object_add(evt, "sig", json_object_new_string(sig_hex));

    const char *s = json_object_to_json_string_ext(evt, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    *out_event_json = strdup(s);
    json_object_put(evt);
    return *out_event_json ? 0 : -1;
}

int nort_nostr_verify_event(const char *event_json, nort_nostr_event_t *out_evt) {
    memset(out_evt, 0, sizeof(*out_evt));
    struct json_object *obj = json_tokener_parse(event_json);
    if (!obj || !json_object_is_type(obj, json_type_object)) {
        if (obj) json_object_put(obj);
        return -1;
    }

    struct json_object *jid, *jpub, *jts, *jkind, *jtags, *jcontent, *jsig;
    if (!json_object_object_get_ex(obj, "id", &jid) ||
        !json_object_object_get_ex(obj, "pubkey", &jpub) ||
        !json_object_object_get_ex(obj, "created_at", &jts) ||
        !json_object_object_get_ex(obj, "kind", &jkind) ||
        !json_object_object_get_ex(obj, "tags", &jtags) ||
        !json_object_object_get_ex(obj, "content", &jcontent) ||
        !json_object_object_get_ex(obj, "sig", &jsig)) {
        json_object_put(obj);
        return -1;
    }

    const char *id = json_object_get_string(jid);
    const char *pub = json_object_get_string(jpub);
    const char *sig = json_object_get_string(jsig);
    const char *content = json_object_get_string(jcontent);
    const char *tags_str = json_object_to_json_string_ext(jtags, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    int64_t ts = json_object_get_int64(jts);
    int kind = json_object_get_int(jkind);

    if (!is_lower_hex_range(id, 64, 64) || !is_lower_hex_range(pub, 64, 64) || !is_lower_hex_range(sig, 128, 128)) {
        json_object_put(obj);
        return -1;
    }

    char expected_id[65];
    if (nort_nostr_compute_event_id(pub, ts, kind, tags_str, content, expected_id) != 0 ||
        strcmp(expected_id, id) != 0) {
        json_object_put(obj);
        return -1;
    }

    uint8_t id_b[32], pub_b[32], sig_b[64];
    nort_hex_decode(id, id_b, 32);
    nort_hex_decode(pub, pub_b, 32);
    nort_hex_decode(sig, sig_b, 64);

    if (nort_schnorr_verify(id_b, sig_b, pub_b) != 0) {
        json_object_put(obj);
        return -1;
    }

    snprintf(out_evt->id, sizeof(out_evt->id), "%s", id);
    snprintf(out_evt->pubkey, sizeof(out_evt->pubkey), "%s", pub);
    snprintf(out_evt->sig, sizeof(out_evt->sig), "%s", sig);
    out_evt->created_at = ts;
    out_evt->kind = kind;
    out_evt->tags_json = strdup(tags_str);
    out_evt->content = strdup(content ? content : "");
    json_object_put(obj);
    return 0;
}

void nort_nostr_event_free(nort_nostr_event_t *evt) {
    if (!evt) return;
    free(evt->tags_json);
    free(evt->content);
    memset(evt, 0, sizeof(*evt));
}

static bool mark_req_seen(nort_agent_t *agent, const char *req_id, int64_t now) {
    pthread_mutex_lock(&agent->replay_lock);
    for (size_t i = 0; i < NORT_SEEN_RING_SIZE; i++) {
        if (agent->seen[i].req_id[0] != '\0' &&
            now - agent->seen[i].ts <= 120 &&
            strcmp(agent->seen[i].req_id, req_id) == 0) {
            pthread_mutex_unlock(&agent->replay_lock);
            return false;
        }
    }
    snprintf(agent->seen[agent->seen_idx].req_id, sizeof(agent->seen[0].req_id), "%s", req_id);
    agent->seen[agent->seen_idx].ts = now;
    agent->seen_idx = (agent->seen_idx + 1) % NORT_SEEN_RING_SIZE;
    pthread_mutex_unlock(&agent->replay_lock);
    return true;
}

static bool validate_tunnel_url(nort_config_t *cfg, const char *raw_url) {
    if (!raw_url) return false;
    const char *p = NULL;
    bool is_ws_local = false;
    if (strncmp(raw_url, "wss://", 6) == 0) {
        p = raw_url + 6;
    } else if (strncmp(raw_url, "ws://", 5) == 0) {
        p = raw_url + 5;
        is_ws_local = true;
    } else {
        return false;
    }

    const char *slash = strchr(p, '/');
    if (!slash) return false;
    size_t auth_len = (size_t)(slash - p);
    if (auth_len == 0 || auth_len >= 192) return false;

    char host[192];
    memcpy(host, p, auth_len);
    host[auth_len] = '\0';
    char *colon = strrchr(host, ':');
    if (colon) *colon = '\0';

    if (is_ws_local && strcmp(host, "127.0.0.1") != 0) return false;
    if (!nort_config_is_tunnel_host_allowed(cfg, host)) return false;

    if (strncmp(slash, "/tunnel/", 8) != 0) return false;
    const char *sid = slash + 8;
    const char *q = strchr(sid, '?');
    size_t sid_len = q ? (size_t)(q - sid) : strlen(sid);
    if (sid_len < 32 || sid_len > 64) return false;
    for (size_t i = 0; i < sid_len; i++) {
        if (!((sid[i] >= '0' && sid[i] <= '9') || (sid[i] >= 'a' && sid[i] <= 'f'))) return false;
    }
    return true;
}

static void on_tunnel_done(void *user_data) {
    nort_agent_t *agent = (nort_agent_t *)user_data;
    pthread_mutex_lock(&agent->status_lock);
    if (agent->active_tunnels > 0) agent->active_tunnels--;
    pthread_mutex_unlock(&agent->status_lock);
}

static void handle_incoming_event(nort_agent_t *agent, nort_ws_t *ws, const char *evt_json) {
    nort_nostr_event_t evt;
    if (nort_nostr_verify_event(evt_json, &evt) != 0) return;

    int64_t now = (int64_t)time(NULL);
    if (evt.kind != NORT_KIND_REQUEST || llabs(now - evt.created_at) > 60) {
        nort_nostr_event_free(&evt);
        return;
    }

    uint8_t peer_pub[32];
    nort_hex_decode(evt.pubkey, peer_pub, 32);

    uint8_t conv_key[32];
    if (nort_nip44_conversation_key(agent->priv_key, peer_pub, conv_key) != 0) {
        nort_nostr_event_free(&evt);
        return;
    }

    char *plain = NULL;
    if (nort_nip44_decrypt(evt.content, conv_key, &plain, NULL) != 0) {
        memset(conv_key, 0, sizeof(conv_key));
        nort_nostr_event_free(&evt);
        return;
    }

    struct json_object *req = json_tokener_parse(plain);
    free(plain);
    if (!req || !json_object_is_type(req, json_type_object)) {
        if (req) json_object_put(req);
        memset(conv_key, 0, sizeof(conv_key));
        nort_nostr_event_free(&evt);
        return;
    }

    struct json_object *jtype = NULL, *jv = NULL, *jreq_id = NULL;
    if (!json_object_object_get_ex(req, "type", &jtype) ||
        !json_object_object_get_ex(req, "v", &jv) ||
        !json_object_object_get_ex(req, "req_id", &jreq_id) ||
        json_object_get_int(jv) != 1) {
        json_object_put(req);
        memset(conv_key, 0, sizeof(conv_key));
        nort_nostr_event_free(&evt);
        return;
    }

    const char *type = json_object_get_string(jtype);
    const char *req_id = json_object_get_string(jreq_id);
    if (!req_id || req_id[0] == '\0' || !mark_req_seen(agent, req_id, now)) {
        json_object_put(req);
        memset(conv_key, 0, sizeof(conv_key));
        nort_nostr_event_free(&evt);
        return;
    }

    struct json_object *reply = json_object_new_object();
    json_object_object_add(reply, "v", json_object_new_int(1));
    json_object_object_add(reply, "req_id", json_object_new_string(req_id));

    if (strcmp(type, "pair_request") == 0) {
        json_object_object_add(reply, "type", json_object_new_string("pair_ack"));
        struct json_object *jsec = NULL, *jdev = NULL;
        const char *sec = json_object_object_get_ex(req, "secret", &jsec) ? json_object_get_string(jsec) : "";
        const char *dev = json_object_object_get_ex(req, "device_name", &jdev) ? json_object_get_string(jdev) : "Android";

        bool pair_ok = false;
        const char *err_msg = NULL;

        pthread_mutex_lock(&agent->pair_lock);
        if (!agent->pair_active || now > agent->pair_expires_at) {
            agent->pair_active = false;
            err_msg = "no active pairing session or expired";
        } else if (strlen(sec) != strlen(agent->pair_secret) ||
                   !nort_consttime_eq(sec, agent->pair_secret, strlen(agent->pair_secret))) {
            err_msg = "invalid pairing secret";
        } else {
            agent->pair_active = false;
            memset(agent->pair_secret, 0, sizeof(agent->pair_secret));
            pair_ok = true;
        }
        pthread_mutex_unlock(&agent->pair_lock);

        if (pair_ok) {
            char peer_npub[96];
            if (nort_bech32_encode_npub(peer_pub, peer_npub, sizeof(peer_npub)) == 0 &&
                nort_config_add_or_update_peer(agent->cfg, peer_npub, evt.pubkey, dev ? dev : "Android") == 0) {
                json_object_object_add(reply, "ok", json_object_new_boolean(1));
                json_object_object_add(reply, "router_name", json_object_new_string(agent->cfg->router_name));
                json_object_object_add(reply, "error", NULL);
            } else {
                json_object_object_add(reply, "ok", json_object_new_boolean(0));
                json_object_object_add(reply, "error", json_object_new_string("failed to persist peer"));
            }
        } else {
            json_object_object_add(reply, "ok", json_object_new_boolean(0));
            json_object_object_add(reply, "error", json_object_new_string(err_msg));
        }
    } else if (strcmp(type, "tunnel_open") == 0) {
        json_object_object_add(reply, "type", json_object_new_string("tunnel_ack"));
        struct json_object *jsid = NULL, *jurl = NULL, *jtok = NULL, *jeph = NULL;
        const char *sid = json_object_object_get_ex(req, "session_id", &jsid) ? json_object_get_string(jsid) : "";
        const char *turl = json_object_object_get_ex(req, "relay_tunnel_url", &jurl) ? json_object_get_string(jurl) : "";
        const char *rtok = json_object_object_get_ex(req, "router_token", &jtok) ? json_object_get_string(jtok) : "";
        const char *ceph = json_object_object_get_ex(req, "client_eph_pub", &jeph) ? json_object_get_string(jeph) : "";

        json_object_object_add(reply, "session_id", json_object_new_string(sid));

        uint8_t client_eph[32];
        if (!nort_config_is_peer_authorized(agent->cfg, evt.pubkey)) {
            json_object_object_add(reply, "ok", json_object_new_boolean(0));
            json_object_object_add(reply, "error", json_object_new_string("peer not paired"));
        } else if (!validate_tunnel_url(agent->cfg, turl)) {
            json_object_object_add(reply, "ok", json_object_new_boolean(0));
            json_object_object_add(reply, "error", json_object_new_string("blocked relay_tunnel_url"));
        } else if (!is_lower_hex_range(rtok, 32, 128) || nort_hex_decode(ceph, client_eph, 32) != 0) {
            json_object_object_add(reply, "ok", json_object_new_boolean(0));
            json_object_object_add(reply, "error", json_object_new_string("invalid tunnel parameters"));
        } else {
            uint8_t r_eph_priv[32], r_eph_pub[32];
            nort_tunnel_crypto_t *tc = calloc(1, sizeof(*tc));
            if (!tc || nort_secp256k1_gen_keypair(r_eph_priv, r_eph_pub) != 0 ||
                nort_tunnel_crypto_init(tc, true, r_eph_priv, client_eph, peer_pub, agent->pub_key, sid, client_eph, r_eph_pub) != 0) {
                free(tc);
                json_object_object_add(reply, "ok", json_object_new_boolean(0));
                json_object_object_add(reply, "error", json_object_new_string("tunnel crypto init failed"));
            } else {
                char full_url[1024];
                snprintf(full_url, sizeof(full_url), "%s?role=router&token=%s", turl, rtok);

                pthread_mutex_lock(&agent->status_lock);
                agent->active_tunnels++;
                pthread_mutex_unlock(&agent->status_lock);

                if (nort_tunnel_start_session(full_url, tc, agent->cfg->local_target, agent->cfg->allow_full_luci,
                                              &agent->running, on_tunnel_done, agent) != 0) {
                    on_tunnel_done(agent);
                    nort_tunnel_crypto_free(tc);
                    free(tc);
                    json_object_object_add(reply, "ok", json_object_new_boolean(0));
                    json_object_object_add(reply, "error", json_object_new_string("failed starting tunnel thread"));
                } else {
                    char r_eph_hex[65];
                    nort_hex_encode(r_eph_pub, 32, r_eph_hex);
                    json_object_object_add(reply, "ok", json_object_new_boolean(1));
                    json_object_object_add(reply, "router_eph_pub", json_object_new_string(r_eph_hex));
                    json_object_object_add(reply, "error", NULL);
                }
            }
            memset(r_eph_priv, 0, sizeof(r_eph_priv));
        }
    } else {
        json_object_put(reply);
        json_object_put(req);
        memset(conv_key, 0, sizeof(conv_key));
        nort_nostr_event_free(&evt);
        return;
    }

    const char *reply_str = json_object_to_json_string_ext(reply, JSON_C_TO_STRING_PLAIN);
    char *enc = NULL;
    if (nort_nip44_encrypt(reply_str, strlen(reply_str), conv_key, &enc) == 0) {
        char tags[256];
        snprintf(tags, sizeof(tags), "[[\"p\",\"%s\"],[\"e\",\"%s\"]]", evt.pubkey, evt.id);
        char *signed_evt = NULL;
        if (nort_nostr_sign_event(agent->priv_key, NORT_KIND_RESPONSE, tags, enc, 0, &signed_evt) == 0) {
            size_t msg_cap = strlen(signed_evt) + 16;
            char *msg = malloc(msg_cap);
            if (msg) {
                int mlen = snprintf(msg, msg_cap, "[\"EVENT\",%s]", signed_evt);
                (void)nort_ws_send_text(ws, msg, (size_t)mlen);
                free(msg);
            }
            free(signed_evt);
        }
        free(enc);
    }

    json_object_put(reply);
    json_object_put(req);
    memset(conv_key, 0, sizeof(conv_key));
    nort_nostr_event_free(&evt);
}

typedef struct {
    nort_agent_t *agent;
    size_t relay_idx;
} relay_worker_arg_t;

static void *relay_worker_fn(void *arg) {
    relay_worker_arg_t *w = (relay_worker_arg_t *)arg;
    nort_agent_t *agent = w->agent;
    size_t idx = w->relay_idx;
    free(w);

    const char *relay_url = agent->cfg->relays[idx];
    int backoff_sec = 2;

    while (agent->running) {
        nort_ws_t *ws = NULL;
        if (nort_ws_connect(relay_url, 15000, &ws) == 0) {
            pthread_mutex_lock(&agent->status_lock);
            agent->relay_connected[idx] = true;
            pthread_mutex_unlock(&agent->status_lock);
            backoff_sec = 2;

            char req_msg[256];
            int rlen = snprintf(req_msg, sizeof(req_msg),
                                "[\"REQ\",\"nort-c\",{\"kinds\":[%d],\"#p\":[\"%s\"]}]",
                                NORT_KIND_REQUEST, agent->pub_hex);
            (void)nort_ws_send_text(ws, req_msg, (size_t)rlen);

            while (agent->running) {
                uint8_t opcode = 0;
                uint8_t *payload = NULL;
                size_t plen = 0;
                if (nort_ws_recv(ws, &opcode, &payload, &plen, 45000) != 0) {
                    /* Send ping on timeout or break if closed */
                    if (nort_ws_send_text(ws, "ping", 4) != 0) break;
                    continue;
                }
                if (opcode == NORT_WS_OP_CLOSE) {
                    free(payload);
                    break;
                }
                if (opcode == NORT_WS_OP_TEXT && payload) {
                    if (strcmp((char *)payload, "pong") != 0) {
                        struct json_object *arr = json_tokener_parse((char *)payload);
                        if (arr && json_object_is_type(arr, json_type_array) && json_object_array_length(arr) >= 3) {
                            const char *mtype = json_object_get_string(json_object_array_get_idx(arr, 0));
                            if (mtype && strcmp(mtype, "EVENT") == 0) {
                                const char *evt_json = json_object_to_json_string_ext(
                                    json_object_array_get_idx(arr, 2),
                                    JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
                                handle_incoming_event(agent, ws, evt_json);
                            }
                        }
                        if (arr) json_object_put(arr);
                    }
                }
                free(payload);
            }

            pthread_mutex_lock(&agent->status_lock);
            agent->relay_connected[idx] = false;
            pthread_mutex_unlock(&agent->status_lock);
            nort_ws_close(ws);
        }

        for (int s = 0; s < backoff_sec && agent->running; s++) sleep(1);
        if (backoff_sec < 30) backoff_sec *= 2;
    }
    return NULL;
}

int nort_agent_init(nort_agent_t *agent, nort_config_t *cfg, const uint8_t priv32[32]) {
    memset(agent, 0, sizeof(*agent));
    agent->cfg = cfg;
    memcpy(agent->priv_key, priv32, 32);
    if (nort_secp256k1_xonly_pubkey(priv32, agent->pub_key) != 0) return -1;
    nort_hex_encode(agent->pub_key, 32, agent->pub_hex);
    if (nort_bech32_encode_npub(agent->pub_key, agent->npub, sizeof(agent->npub)) != 0) return -1;

    pthread_mutex_init(&agent->pair_lock, NULL);
    pthread_mutex_init(&agent->replay_lock, NULL);
    pthread_mutex_init(&agent->status_lock, NULL);
    return 0;
}

int nort_agent_start(nort_agent_t *agent) {
    agent->running = true;
    agent->relay_thread_count = 0;
    for (size_t i = 0; i < agent->cfg->relay_count; i++) {
        relay_worker_arg_t *arg = malloc(sizeof(*arg));
        if (!arg) continue;
        arg->agent = agent;
        arg->relay_idx = i;
        if (pthread_create(&agent->relay_threads[agent->relay_thread_count], NULL, relay_worker_fn, arg) == 0) {
            agent->relay_thread_count++;
        } else {
            free(arg);
        }
    }
    return 0;
}

void nort_agent_stop(nort_agent_t *agent) {
    agent->running = false;
    for (size_t i = 0; i < agent->relay_thread_count; i++) {
        pthread_join(agent->relay_threads[i], NULL);
    }
    pthread_mutex_destroy(&agent->pair_lock);
    pthread_mutex_destroy(&agent->replay_lock);
    pthread_mutex_destroy(&agent->status_lock);
    memset(agent->priv_key, 0, sizeof(agent->priv_key));
}

static void url_encode(const char *src, char *dst, size_t cap) {
    static const char hex[] = "0123456789ABCDEF";
    size_t d = 0;
    for (; *src && d + 4 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            dst[d++] = (char)c;
        } else {
            dst[d++] = '%';
            dst[d++] = hex[(c >> 4) & 0x0f];
            dst[d++] = hex[c & 0x0f];
        }
    }
    dst[d] = '\0';
}

int nort_agent_start_pairing(nort_agent_t *agent, char **out_json) {
    uint8_t sec_raw[16];
    if (nort_random_bytes(sec_raw, sizeof(sec_raw)) != 0) return -1;
    char sec_hex[33];
    nort_hex_encode(sec_raw, sizeof(sec_raw), sec_hex);
    int64_t expires = (int64_t)time(NULL) + 300;

    pthread_mutex_lock(&agent->pair_lock);
    agent->pair_active = true;
    snprintf(agent->pair_secret, sizeof(agent->pair_secret), "%s", sec_hex);
    agent->pair_expires_at = expires;
    pthread_mutex_unlock(&agent->pair_lock);

    const char *primary_relay = agent->cfg->relay_count > 0 ? agent->cfg->relays[0] : "wss://relay.gfmm.eu";
    char enc_relay[512], enc_name[256], enc_lan[128], pair_uri[1200];
    url_encode(primary_relay, enc_relay, sizeof(enc_relay));
    url_encode(agent->cfg->router_name, enc_name, sizeof(enc_name));
    url_encode(agent->cfg->lan_ip, enc_lan, sizeof(enc_lan));

    snprintf(pair_uri, sizeof(pair_uri),
             "nopenwrt://pair?v=1&npub=%s&relay=%s&secret=%s&name=%s&lan=%s",
             agent->npub, enc_relay, sec_hex, enc_name, enc_lan);

    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "pair_uri", json_object_new_string(pair_uri));
    json_object_object_add(obj, "expires_at", json_object_new_int64(expires));
    json_object_object_add(obj, "ttl_sec", json_object_new_int(300));
    *out_json = strdup(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
    json_object_put(obj);
    return *out_json ? 0 : -1;
}

char *nort_agent_status_json(nort_agent_t *agent) {
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "running", json_object_new_boolean(agent->running ? 1 : 0));
    json_object_object_add(obj, "router_name", json_object_new_string(agent->cfg->router_name));
    json_object_object_add(obj, "npub", json_object_new_string(agent->npub));
    json_object_object_add(obj, "pubkey_hex", json_object_new_string(agent->pub_hex));

    struct json_object *relays = json_object_new_array();
    pthread_mutex_lock(&agent->status_lock);
    int active_tuns = agent->active_tunnels;
    for (size_t i = 0; i < agent->cfg->relay_count; i++) {
        struct json_object *r = json_object_new_object();
        json_object_object_add(r, "url", json_object_new_string(agent->cfg->relays[i]));
        json_object_object_add(r, "connected", json_object_new_boolean(agent->relay_connected[i] ? 1 : 0));
        json_object_array_add(relays, r);
    }
    pthread_mutex_unlock(&agent->status_lock);

    json_object_object_add(obj, "relays", relays);
    json_object_object_add(obj, "active_tunnels", json_object_new_int(active_tuns));

    pthread_mutex_lock(&agent->cfg->lock);
    int pcount = (int)agent->cfg->peer_count;
    pthread_mutex_unlock(&agent->cfg->lock);
    json_object_object_add(obj, "paired_count", json_object_new_int(pcount));

    char *out = strdup(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
    json_object_put(obj);
    return out;
}

char *nort_agent_peers_json(nort_agent_t *agent) {
    struct json_object *obj = json_object_new_object();
    struct json_object *arr = json_object_new_array();

    pthread_mutex_lock(&agent->cfg->lock);
    for (size_t i = 0; i < agent->cfg->peer_count; i++) {
        struct json_object *p = json_object_new_object();
        json_object_object_add(p, "npub", json_object_new_string(agent->cfg->peers[i].npub));
        json_object_object_add(p, "pub_hex", json_object_new_string(agent->cfg->peers[i].pub_hex));
        json_object_object_add(p, "name", json_object_new_string(agent->cfg->peers[i].name));
        json_object_object_add(p, "added_at", json_object_new_int64(agent->cfg->peers[i].added_at));
        json_object_array_add(arr, p);
    }
    pthread_mutex_unlock(&agent->cfg->lock);

    json_object_object_add(obj, "peers", arr);
    char *out = strdup(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
    json_object_put(obj);
    return out;
}
