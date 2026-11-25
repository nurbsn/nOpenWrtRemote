#ifndef NORT_TUNNEL_H
#define NORT_TUNNEL_H

#include <stdbool.h>
#include <stdint.h>
#include "nort_crypto.h"

typedef void (*nort_tunnel_done_cb)(void *user_data);

int nort_tunnel_start_session(
    const char *tunnel_url,
    nort_tunnel_crypto_t *tc,
    const char *local_target,
    bool allow_full_luci,
    volatile const bool *shutdown_flag,
    nort_tunnel_done_cb on_done,
    void *user_data
);

#endif
