#define _POSIX_C_SOURCE 200809L
#include "nort_config.h"
#include "nort_control.h"
#include "nort_crypto.h"
#include "nort_nostr.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv) {
    const char *config_path = "/etc/config/nopenwrtremote";
    const char *key_path = "/etc/nopenwrtremote/identity.key";
    const char *socket_path = "/var/run/nopenwrtremote.sock";

    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) config_path = argv[++i];
        else if (strcmp(argv[i], "--key") == 0) key_path = argv[++i];
        else if (strcmp(argv[i], "--socket") == 0) socket_path = argv[++i];
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (nort_crypto_init() != 0) {
        fprintf(stderr, "nort_crypto_init failed\n");
        return 1;
    }

    uint8_t priv_key[32];
    if (nort_config_load_or_create_key(key_path, priv_key) != 0) {
        fprintf(stderr, "failed loading or creating key at %s\n", key_path);
        nort_crypto_cleanup();
        return 1;
    }

    nort_config_t cfg;
    if (nort_config_load_uci(&cfg, config_path, key_path) != 0) {
        fprintf(stderr, "failed loading UCI config %s\n", config_path);
        nort_crypto_cleanup();
        return 1;
    }

    if (!cfg.enabled) {
        fprintf(stderr, "nopenwrtremote disabled in config\n");
        nort_config_free(&cfg);
        nort_crypto_cleanup();
        return 0;
    }

    nort_agent_t agent;
    if (nort_agent_init(&agent, &cfg, priv_key) != 0) {
        fprintf(stderr, "nort_agent_init failed\n");
        nort_config_free(&cfg);
        nort_crypto_cleanup();
        return 1;
    }
    memset(priv_key, 0, sizeof(priv_key));

    nort_control_srv_t *ctrl = NULL;
    if (nort_control_start(socket_path, &agent, &ctrl) != 0) {
        fprintf(stderr, "failed opening unix control socket %s\n", socket_path);
        nort_agent_stop(&agent);
        nort_config_free(&cfg);
        nort_crypto_cleanup();
        return 1;
    }

    nort_agent_start(&agent);
    fprintf(stderr, "nopenwrtremote-agent started (npub=%s)\n", agent.npub);

    while (!g_stop) {
        sleep(1);
    }

    nort_control_stop(ctrl);
    nort_agent_stop(&agent);
    nort_config_free(&cfg);
    nort_crypto_cleanup();
    return 0;
}
