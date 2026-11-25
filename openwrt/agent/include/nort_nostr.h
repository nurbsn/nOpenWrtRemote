#ifndef NORT_NOSTR_H
#define NORT_NOSTR_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "nort_config.h"

#define NORT_KIND_REQUEST  24135
#define NORT_KIND_RESPONSE 24136
#define NORT_SEEN_RING_SIZE 256

typedef struct {
    char id[65];
    char pubkey[65];
    int64_t created_at;
    int kind;
    char *tags_json;
    char *content;
    char sig[129];
} nort_nostr_event_t;

typedef struct {
    char req_id[96];
    int64_t ts;
} nort_seen_req_t;

typedef struct {
    nort_config_t *cfg;
    uint8_t priv_key[32];
    uint8_t pub_key[32];
    char pub_hex[65];
    char npub[96];

    volatile bool running;

    pthread_mutex_t pair_lock;
    bool pair_active;
    char pair_secret[65];
    int64_t pair_expires_at;

    pthread_mutex_t replay_lock;
    nort_seen_req_t seen[NORT_SEEN_RING_SIZE];
    size_t seen_idx;

    pthread_mutex_t status_lock;
    bool relay_connected[NORT_MAX_RELAYS];
    int active_tunnels;

    pthread_t relay_threads[NORT_MAX_RELAYS];
    size_t relay_thread_count;
} nort_agent_t;

int nort_agent_init(nort_agent_t *agent, nort_config_t *cfg, const uint8_t priv32[32]);
int nort_agent_start(nort_agent_t *agent);
void nort_agent_stop(nort_agent_t *agent);

int nort_agent_start_pairing(nort_agent_t *agent, char **out_json);
char *nort_agent_status_json(nort_agent_t *agent);
char *nort_agent_peers_json(nort_agent_t *agent);

int nort_nostr_compute_event_id(
    const char *pub_hex,
    int64_t created_at,
    int kind,
    const char *tags_json,
    const char *content,
    char out_id_hex[65]
);
int nort_nostr_sign_event(
    const uint8_t priv32[32],
    int kind,
    const char *tags_json,
    const char *content,
    int64_t created_at,
    char **out_event_json
);
int nort_nostr_verify_event(const char *event_json, nort_nostr_event_t *out_evt);
void nort_nostr_event_free(nort_nostr_event_t *evt);

#endif
