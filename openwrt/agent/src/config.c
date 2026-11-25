#define _POSIX_C_SOURCE 200809L
#include "nort_config.h"
#include "nort_crypto.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int mkdir_p(const char *dir, mode_t mode) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

int nort_config_load_or_create_key(const char *key_path, uint8_t priv32[32]) {
    FILE *f = fopen(key_path, "r");
    if (f) {
        char buf[128] = {0};
        if (fgets(buf, sizeof(buf), f)) {
            size_t n = strlen(buf);
            while (n > 0 && isspace((unsigned char)buf[n - 1])) buf[--n] = '\0';
            if (nort_hex_decode(buf, priv32, 32) == 0) {
                fclose(f);
                return 0;
            }
        }
        fclose(f);
        return -1;
    }

    char path_copy[256];
    snprintf(path_copy, sizeof(path_copy), "%s", key_path);
    const char *dir = dirname(path_copy);
    if (mkdir_p(dir, 0700) != 0) return -1;

    uint8_t pub[32];
    if (nort_secp256k1_gen_keypair(priv32, pub) != 0) return -1;

    int fd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;

    char hex[66];
    nort_hex_encode(priv32, 32, hex);
    hex[64] = '\n';
    ssize_t wr = write(fd, hex, 65);
    memset(hex, 0, sizeof(hex));
    close(fd);
    return wr == 65 ? 0 : -1;
}

static char *trim_ws(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
    return s;
}

static void strip_quotes(char *s) {
    size_t len = strlen(s);
    if (len >= 2 && ((s[0] == '\'' && s[len - 1] == '\'') || (s[0] == '"' && s[len - 1] == '"'))) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static void set_defaults(nort_config_t *cfg, const char *config_path, const char *key_path) {
    memset(cfg, 0, sizeof(*cfg));
    pthread_mutex_init(&cfg->lock, NULL);
    snprintf(cfg->config_path, sizeof(cfg->config_path), "%s", config_path);
    snprintf(cfg->key_path, sizeof(cfg->key_path), "%s", key_path);
    cfg->enabled = true;
    if (gethostname(cfg->router_name, sizeof(cfg->router_name) - 1) != 0 || cfg->router_name[0] == '\0') {
        snprintf(cfg->router_name, sizeof(cfg->router_name), "OpenWrt");
    }
    snprintf(cfg->lan_ip, sizeof(cfg->lan_ip), "192.168.1.1");
    snprintf(cfg->local_target, sizeof(cfg->local_target), "http://127.0.0.1:80");
    cfg->allow_full_luci = true;
    snprintf(cfg->relays[0], sizeof(cfg->relays[0]), "wss://relay.gfmm.eu");
    cfg->relay_count = 1;
    snprintf(cfg->allowed_tunnel_hosts[0], sizeof(cfg->allowed_tunnel_hosts[0]), "relay.gfmm.eu");
    cfg->allowed_host_count = 1;
}

int nort_config_load_uci(nort_config_t *cfg, const char *config_path, const char *key_path) {
    set_defaults(cfg, config_path, key_path);

    FILE *f = fopen(config_path, "r");
    if (!f) return 0;

    cfg->relay_count = 0;
    cfg->allowed_host_count = 0;

    int section = 0; /* 1=agent, 2=peer */
    nort_peer_t cur_peer;
    bool has_peer = false;
    memset(&cur_peer, 0, sizeof(cur_peer));

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim_ws(line);
        if (s[0] == '\0' || s[0] == '#') continue;

        if (strncmp(s, "config ", 7) == 0) {
            if (has_peer && cur_peer.npub[0] != '\0' && cfg->peer_count < NORT_MAX_PEERS) {
                uint8_t pub[32];
                if (nort_bech32_decode_npub(cur_peer.npub, pub) == 0) {
                    nort_hex_encode(pub, 32, cur_peer.pub_hex);
                    cfg->peers[cfg->peer_count++] = cur_peer;
                }
            }
            has_peer = false;
            memset(&cur_peer, 0, sizeof(cur_peer));
            char *type = trim_ws(s + 7);
            char *sp = strpbrk(type, " \t");
            if (sp) *sp = '\0';
            strip_quotes(type);
            if (strcmp(type, "agent") == 0) section = 1;
            else if (strcmp(type, "peer") == 0) { section = 2; has_peer = true; }
            else section = 0;
            continue;
        }

        bool is_opt = strncmp(s, "option ", 7) == 0;
        bool is_list = strncmp(s, "list ", 5) == 0;
        if (!is_opt && !is_list) continue;

        char *rest = trim_ws(s + (is_opt ? 7 : 5));
        char *sep = strpbrk(rest, " \t");
        if (!sep) continue;
        *sep = '\0';
        char *key = rest;
        char *val = trim_ws(sep + 1);
        strip_quotes(val);

        if (section == 1 && is_opt) {
            if (strcmp(key, "enabled") == 0) cfg->enabled = (strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0);
            else if (strcmp(key, "router_name") == 0) snprintf(cfg->router_name, sizeof(cfg->router_name), "%s", val);
            else if (strcmp(key, "lan_ip") == 0) snprintf(cfg->lan_ip, sizeof(cfg->lan_ip), "%s", val);
            else if (strcmp(key, "local_target") == 0) snprintf(cfg->local_target, sizeof(cfg->local_target), "%s", val);
            else if (strcmp(key, "allow_full_luci") == 0) cfg->allow_full_luci = (strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0);
        } else if (section == 1 && is_list) {
            if (strcmp(key, "relay") == 0 && cfg->relay_count < NORT_MAX_RELAYS) {
                snprintf(cfg->relays[cfg->relay_count++], sizeof(cfg->relays[0]), "%s", val);
            } else if (strcmp(key, "allowed_tunnel_host") == 0 && cfg->allowed_host_count < NORT_MAX_HOSTS) {
                snprintf(cfg->allowed_tunnel_hosts[cfg->allowed_host_count++], sizeof(cfg->allowed_tunnel_hosts[0]), "%s", val);
            }
        } else if (section == 2 && is_opt && has_peer) {
            if (strcmp(key, "npub") == 0) snprintf(cur_peer.npub, sizeof(cur_peer.npub), "%s", val);
            else if (strcmp(key, "name") == 0) snprintf(cur_peer.name, sizeof(cur_peer.name), "%s", val);
            else if (strcmp(key, "added_at") == 0) cur_peer.added_at = strtoll(val, NULL, 10);
        }
    }

    if (has_peer && cur_peer.npub[0] != '\0' && cfg->peer_count < NORT_MAX_PEERS) {
        uint8_t pub[32];
        if (nort_bech32_decode_npub(cur_peer.npub, pub) == 0) {
            nort_hex_encode(pub, 32, cur_peer.pub_hex);
            cfg->peers[cfg->peer_count++] = cur_peer;
        }
    }
    fclose(f);

    if (cfg->relay_count == 0) {
        snprintf(cfg->relays[0], sizeof(cfg->relays[0]), "wss://relay.gfmm.eu");
        cfg->relay_count = 1;
    }
    if (cfg->allowed_host_count == 0) {
        snprintf(cfg->allowed_tunnel_hosts[0], sizeof(cfg->allowed_tunnel_hosts[0]), "relay.gfmm.eu");
        cfg->allowed_host_count = 1;
    }
    return 0;
}

static void write_uci_clean(FILE *f, const char *s) {
    for (; *s; s++) {
        if (*s != '\'' && *s != '\n' && *s != '\r') fputc(*s, f);
    }
}

static int save_uci_unlocked(nort_config_t *cfg) {
    char path_copy[256];
    snprintf(path_copy, sizeof(path_copy), "%s", cfg->config_path);
    const char *dir = dirname(path_copy);
    if (mkdir_p(dir, 0755) != 0) return -1;

    char tmp_path[300];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", cfg->config_path);
    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    fprintf(f, "config agent 'main'\n");
    fprintf(f, "\toption enabled '%d'\n", cfg->enabled ? 1 : 0);
    fprintf(f, "\toption router_name '"); write_uci_clean(f, cfg->router_name); fprintf(f, "'\n");
    fprintf(f, "\toption lan_ip '"); write_uci_clean(f, cfg->lan_ip); fprintf(f, "'\n");
    fprintf(f, "\toption local_target '"); write_uci_clean(f, cfg->local_target); fprintf(f, "'\n");
    fprintf(f, "\toption allow_full_luci '%d'\n", cfg->allow_full_luci ? 1 : 0);
    for (size_t i = 0; i < cfg->relay_count; i++) {
        fprintf(f, "\tlist relay '"); write_uci_clean(f, cfg->relays[i]); fprintf(f, "'\n");
    }
    for (size_t i = 0; i < cfg->allowed_host_count; i++) {
        fprintf(f, "\tlist allowed_tunnel_host '"); write_uci_clean(f, cfg->allowed_tunnel_hosts[i]); fprintf(f, "'\n");
    }

    for (size_t i = 0; i < cfg->peer_count; i++) {
        fprintf(f, "\nconfig peer\n");
        fprintf(f, "\toption npub '"); write_uci_clean(f, cfg->peers[i].npub); fprintf(f, "'\n");
        fprintf(f, "\toption name '"); write_uci_clean(f, cfg->peers[i].name); fprintf(f, "'\n");
        fprintf(f, "\toption added_at '%lld'\n", (long long)cfg->peers[i].added_at);
    }

    fclose(f);
    return rename(tmp_path, cfg->config_path) == 0 ? 0 : -1;
}

int nort_config_save_uci(nort_config_t *cfg) {
    pthread_mutex_lock(&cfg->lock);
    int rc = save_uci_unlocked(cfg);
    pthread_mutex_unlock(&cfg->lock);
    return rc;
}

void nort_config_free(nort_config_t *cfg) {
    pthread_mutex_destroy(&cfg->lock);
}

bool nort_config_is_peer_authorized(nort_config_t *cfg, const char *pub_hex) {
    pthread_mutex_lock(&cfg->lock);
    bool found = false;
    for (size_t i = 0; i < cfg->peer_count; i++) {
        if (strcasecmp(cfg->peers[i].pub_hex, pub_hex) == 0) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&cfg->lock);
    return found;
}

int nort_config_add_or_update_peer(nort_config_t *cfg, const char *npub, const char *pub_hex, const char *name) {
    pthread_mutex_lock(&cfg->lock);
    bool updated = false;
    for (size_t i = 0; i < cfg->peer_count; i++) {
        if (strcasecmp(cfg->peers[i].pub_hex, pub_hex) == 0) {
            snprintf(cfg->peers[i].npub, sizeof(cfg->peers[i].npub), "%s", npub);
            snprintf(cfg->peers[i].name, sizeof(cfg->peers[i].name), "%s", name);
            updated = true;
            break;
        }
    }
    if (!updated) {
        if (cfg->peer_count >= NORT_MAX_PEERS) {
            pthread_mutex_unlock(&cfg->lock);
            return -1;
        }
        nort_peer_t *p = &cfg->peers[cfg->peer_count++];
        memset(p, 0, sizeof(*p));
        snprintf(p->npub, sizeof(p->npub), "%s", npub);
        for (size_t j = 0; j < 64 && pub_hex[j]; j++) {
            p->pub_hex[j] = (char)tolower((unsigned char)pub_hex[j]);
        }
        snprintf(p->name, sizeof(p->name), "%s", name);
        p->added_at = (int64_t)time(NULL);
    }
    int rc = save_uci_unlocked(cfg);
    pthread_mutex_unlock(&cfg->lock);
    return rc;
}

int nort_config_revoke_peer(nort_config_t *cfg, const char *npub_or_hex, bool *removed) {
    pthread_mutex_lock(&cfg->lock);
    *removed = false;
    size_t write_idx = 0;
    for (size_t i = 0; i < cfg->peer_count; i++) {
        if (strcasecmp(cfg->peers[i].npub, npub_or_hex) == 0 ||
            strcasecmp(cfg->peers[i].pub_hex, npub_or_hex) == 0) {
            *removed = true;
            continue;
        }
        cfg->peers[write_idx++] = cfg->peers[i];
    }
    cfg->peer_count = write_idx;
    int rc = *removed ? save_uci_unlocked(cfg) : 0;
    pthread_mutex_unlock(&cfg->lock);
    return rc;
}

bool nort_config_is_tunnel_host_allowed(nort_config_t *cfg, const char *host) {
    pthread_mutex_lock(&cfg->lock);
    bool allowed = false;
    for (size_t i = 0; i < cfg->allowed_host_count; i++) {
        if (strcasecmp(cfg->allowed_tunnel_hosts[i], host) == 0) {
            allowed = true;
            break;
        }
    }
    pthread_mutex_unlock(&cfg->lock);
    return allowed;
}
