#ifndef NORT_CONFIG_H
#define NORT_CONFIG_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NORT_MAX_RELAYS 8
#define NORT_MAX_HOSTS 16
#define NORT_MAX_PEERS 64

typedef struct {
    char npub[96];
    char pub_hex[65];
    char name[128];
    int64_t added_at;
} nort_peer_t;

typedef struct {
    pthread_mutex_t lock;
    char config_path[256];
    char key_path[256];
    bool enabled;
    char router_name[128];
    char lan_ip[64];
    char local_target[256];
    bool allow_full_luci;
    char relays[NORT_MAX_RELAYS][256];
    size_t relay_count;
    char allowed_tunnel_hosts[NORT_MAX_HOSTS][128];
    size_t allowed_host_count;
    nort_peer_t peers[NORT_MAX_PEERS];
    size_t peer_count;
} nort_config_t;

int nort_config_load_or_create_key(const char *key_path, uint8_t priv32[32]);
int nort_config_load_uci(nort_config_t *cfg, const char *config_path, const char *key_path);
int nort_config_save_uci(nort_config_t *cfg);
void nort_config_free(nort_config_t *cfg);

bool nort_config_is_peer_authorized(nort_config_t *cfg, const char *pub_hex);
int nort_config_add_or_update_peer(nort_config_t *cfg, const char *npub, const char *pub_hex, const char *name);
int nort_config_revoke_peer(nort_config_t *cfg, const char *npub_or_hex, bool *removed);
bool nort_config_is_tunnel_host_allowed(nort_config_t *cfg, const char *host);

#endif
