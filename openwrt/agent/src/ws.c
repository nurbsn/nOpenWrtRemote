#define _POSIX_C_SOURCE 200809L
#include "nort_ws.h"
#include "nort_crypto.h"

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

struct nort_ws {
    int fd;
    bool use_tls;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    pthread_mutex_t write_lock;
};

static int parse_ws_url(const char *url, bool *use_tls, char *host, size_t host_cap, char *port, size_t port_cap, char *path, size_t path_cap) {
    const char *p = NULL;
    if (strncmp(url, "wss://", 6) == 0) {
        *use_tls = true;
        p = url + 6;
        snprintf(port, port_cap, "443");
    } else if (strncmp(url, "ws://", 5) == 0) {
        *use_tls = false;
        p = url + 5;
        snprintf(port, port_cap, "80");
    } else {
        return -1;
    }

    const char *slash = strchr(p, '/');
    size_t auth_len = slash ? (size_t)(slash - p) : strlen(p);
    if (auth_len == 0 || auth_len >= host_cap) return -1;

    char auth[256];
    if (auth_len >= sizeof(auth)) return -1;
    memcpy(auth, p, auth_len);
    auth[auth_len] = '\0';

    char *colon = strrchr(auth, ':');
    if (colon) {
        *colon = '\0';
        snprintf(port, port_cap, "%s", colon + 1);
    }
    snprintf(host, host_cap, "%s", auth);
    snprintf(path, path_cap, "%s", slash ? slash : "/");
    return 0;
}

static int tcp_connect_host(const char *host, const char *port, int timeout_ms) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;

        struct timeval tv = {
            .tv_sec = timeout_ms / 1000,
            .tv_usec = (timeout_ms % 1000) * 1000
        };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    ssize_t n = send(fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return (int)n;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    ssize_t n = recv(fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_TIMEOUT;
        if (errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (n == 0) return MBEDTLS_ERR_NET_CONN_RESET;
    return (int)n;
}

static int ws_raw_write(nort_ws_t *ws, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (ws->use_tls) {
            n = mbedtls_ssl_write(&ws->ssl, data + sent, len - sent);
            if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (n <= 0) return -1;
        } else {
            ssize_t sn = send(ws->fd, data + sent, len - sent, 0);
            if (sn < 0 && errno == EINTR) continue;
            if (sn <= 0) return -1;
            n = (int)sn;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int ws_raw_read_exact(nort_ws_t *ws, uint8_t *buf, size_t len, int timeout_ms) {
    size_t got = 0;
    while (got < len) {
        if (!ws->use_tls || mbedtls_ssl_get_bytes_avail(&ws->ssl) == 0) {
            struct pollfd pfd = { .fd = ws->fd, .events = POLLIN };
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr <= 0) return -1;
        }
        int n;
        if (ws->use_tls) {
            n = mbedtls_ssl_read(&ws->ssl, buf + got, len - got);
            if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (n <= 0) return -1;
        } else {
            ssize_t rn = recv(ws->fd, buf + got, len - got, 0);
            if (rn < 0 && errno == EINTR) continue;
            if (rn <= 0) return -1;
            n = (int)rn;
        }
        got += (size_t)n;
    }
    return 0;
}

int nort_ws_connect(const char *url, int timeout_ms, nort_ws_t **out_ws) {
    bool use_tls = false;
    char host[192], port[16], path[1024];
    if (parse_ws_url(url, &use_tls, host, sizeof(host), port, sizeof(port), path, sizeof(path)) != 0) {
        return -1;
    }

    int fd = tcp_connect_host(host, port, timeout_ms);
    if (fd < 0) return -1;

    nort_ws_t *ws = calloc(1, sizeof(*ws));
    if (!ws) {
        close(fd);
        return -1;
    }
    ws->fd = fd;
    ws->use_tls = use_tls;
    pthread_mutex_init(&ws->write_lock, NULL);

    if (use_tls) {
        mbedtls_ssl_init(&ws->ssl);
        mbedtls_ssl_config_init(&ws->conf);
        mbedtls_x509_crt_init(&ws->cacert);
        mbedtls_ctr_drbg_init(&ws->ctr_drbg);
        mbedtls_entropy_init(&ws->entropy);

        static const char pers[] = "nort_ws_tls";
        if (mbedtls_ctr_drbg_seed(&ws->ctr_drbg, mbedtls_entropy_func, &ws->entropy,
                                  (const unsigned char *)pers, sizeof(pers) - 1) != 0) {
            nort_ws_close(ws);
            return -1;
        }

        int ca_loaded = 0;
        if (mbedtls_x509_crt_parse_file(&ws->cacert, "/etc/ssl/certs/ca-certificates.crt") == 0) ca_loaded = 1;
        else if (mbedtls_x509_crt_parse_file(&ws->cacert, "/etc/ssl/cert.pem") == 0) ca_loaded = 1;
        else if (mbedtls_x509_crt_parse_path(&ws->cacert, "/etc/ssl/certs") >= 0) ca_loaded = 1;
        if (!ca_loaded) {
            nort_ws_close(ws);
            return -1;
        }

        if (mbedtls_ssl_config_defaults(&ws->conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            nort_ws_close(ws);
            return -1;
        }
        mbedtls_ssl_conf_authmode(&ws->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&ws->conf, &ws->cacert, NULL);
        mbedtls_ssl_conf_rng(&ws->conf, mbedtls_ctr_drbg_random, &ws->ctr_drbg);
        mbedtls_ssl_conf_read_timeout(&ws->conf, (uint32_t)timeout_ms);

        if (mbedtls_ssl_setup(&ws->ssl, &ws->conf) != 0 ||
            mbedtls_ssl_set_hostname(&ws->ssl, host) != 0) {
            nort_ws_close(ws);
            return -1;
        }
        mbedtls_ssl_set_bio(&ws->ssl, &ws->fd, bio_send, bio_recv, NULL);

        int hrc;
        while ((hrc = mbedtls_ssl_handshake(&ws->ssl)) != 0) {
            if (hrc != MBEDTLS_ERR_SSL_WANT_READ && hrc != MBEDTLS_ERR_SSL_WANT_WRITE) {
                nort_ws_close(ws);
                return -1;
            }
        }
    }

    uint8_t key_raw[16];
    if (nort_random_bytes(key_raw, sizeof(key_raw)) != 0) {
        nort_ws_close(ws);
        return -1;
    }
    unsigned char key_b64[32];
    size_t key_b64_len = 0;
    mbedtls_base64_encode(key_b64, sizeof(key_b64), &key_b64_len, key_raw, sizeof(key_raw));
    key_b64[key_b64_len] = '\0';

    char req[2048];
    int rlen = snprintf(
        req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        path, host, port, (char *)key_b64);

    if (rlen <= 0 || (size_t)rlen >= sizeof(req) || ws_raw_write(ws, (const uint8_t *)req, (size_t)rlen) != 0) {
        nort_ws_close(ws);
        return -1;
    }

    char resp[4096];
    size_t resp_len = 0;
    while (resp_len + 1 < sizeof(resp)) {
        uint8_t ch;
        if (ws_raw_read_exact(ws, &ch, 1, timeout_ms) != 0) {
            nort_ws_close(ws);
            return -1;
        }
        resp[resp_len++] = (char)ch;
        resp[resp_len] = '\0';
        if (resp_len >= 4 && memcmp(resp + resp_len - 4, "\r\n\r\n", 4) == 0) break;
    }

    if (!strstr(resp, " 101 ")) {
        nort_ws_close(ws);
        return -1;
    }

    *out_ws = ws;
    return 0;
}

static int ws_send_frame(nort_ws_t *ws, uint8_t opcode, const uint8_t *data, size_t len) {
    uint8_t header[14];
    size_t hlen = 0;
    header[0] = (uint8_t)(0x80u | (opcode & 0x0fu));

    if (len <= 125) {
        header[1] = (uint8_t)(0x80u | len);
        hlen = 2;
    } else if (len <= 65535) {
        header[1] = (uint8_t)(0x80u | 126u);
        header[2] = (uint8_t)((len >> 8) & 0xff);
        header[3] = (uint8_t)(len & 0xff);
        hlen = 4;
    } else {
        header[1] = (uint8_t)(0x80u | 127u);
        uint64_t l64 = (uint64_t)len;
        for (int i = 0; i < 8; i++) header[2 + i] = (uint8_t)((l64 >> (56 - i * 8)) & 0xff);
        hlen = 10;
    }

    uint8_t mask[4];
    if (nort_random_bytes(mask, sizeof(mask)) != 0) return -1;
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    uint8_t *masked = NULL;
    if (len > 0) {
        masked = malloc(len);
        if (!masked) return -1;
        for (size_t i = 0; i < len; i++) masked[i] = (uint8_t)(data[i] ^ mask[i & 3]);
    }

    pthread_mutex_lock(&ws->write_lock);
    int rc = ws_raw_write(ws, header, hlen);
    if (rc == 0 && len > 0) rc = ws_raw_write(ws, masked, len);
    pthread_mutex_unlock(&ws->write_lock);

    free(masked);
    return rc;
}

int nort_ws_send_text(nort_ws_t *ws, const char *text, size_t len) {
    return ws_send_frame(ws, NORT_WS_OP_TEXT, (const uint8_t *)text, len);
}

int nort_ws_send_binary(nort_ws_t *ws, const uint8_t *data, size_t len) {
    return ws_send_frame(ws, NORT_WS_OP_BINARY, data, len);
}

int nort_ws_recv(nort_ws_t *ws, uint8_t *out_opcode, uint8_t **out_payload, size_t *out_len, int timeout_ms) {
    uint8_t *acc = NULL;
    size_t acc_len = 0;
    uint8_t first_opcode = 0;

    for (;;) {
        uint8_t hdr[2];
        if (ws_raw_read_exact(ws, hdr, 2, timeout_ms) != 0) {
            free(acc);
            return -1;
        }

        bool fin = (hdr[0] & 0x80u) != 0;
        uint8_t opcode = hdr[0] & 0x0fu;
        bool masked = (hdr[1] & 0x80u) != 0;
        uint64_t plen = hdr[1] & 0x7fu;

        if (plen == 126) {
            uint8_t ext[2];
            if (ws_raw_read_exact(ws, ext, 2, timeout_ms) != 0) { free(acc); return -1; }
            plen = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (plen == 127) {
            uint8_t ext[8];
            if (ws_raw_read_exact(ws, ext, 8, timeout_ms) != 0) { free(acc); return -1; }
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | ext[i];
        }

        if (plen > 16u * 1024u * 1024u) {
            free(acc);
            return -1;
        }

        uint8_t mask[4] = {0};
        if (masked && ws_raw_read_exact(ws, mask, 4, timeout_ms) != 0) {
            free(acc);
            return -1;
        }

        uint8_t *chunk = NULL;
        if (plen > 0) {
            chunk = malloc((size_t)plen + 1);
            if (!chunk || ws_raw_read_exact(ws, chunk, (size_t)plen, timeout_ms) != 0) {
                free(chunk);
                free(acc);
                return -1;
            }
            if (masked) {
                for (size_t i = 0; i < (size_t)plen; i++) chunk[i] ^= mask[i & 3];
            }
        }

        if (opcode == 0x09) { /* Ping */
            (void)ws_send_frame(ws, 0x0a, chunk, (size_t)plen);
            free(chunk);
            continue;
        }
        if (opcode == 0x0a) { /* Pong */
            free(chunk);
            continue;
        }
        if (opcode == 0x08) { /* Close */
            free(chunk);
            free(acc);
            *out_opcode = NORT_WS_OP_CLOSE;
            *out_payload = NULL;
            *out_len = 0;
            return 0;
        }

        if (opcode != 0x00) first_opcode = opcode;

        if (plen > 0) {
            uint8_t *resized = realloc(acc, acc_len + (size_t)plen + 1);
            if (!resized) {
                free(chunk);
                free(acc);
                return -1;
            }
            acc = resized;
            memcpy(acc + acc_len, chunk, (size_t)plen);
            acc_len += (size_t)plen;
            free(chunk);
        }

        if (fin) {
            if (!acc) {
                acc = malloc(1);
                if (!acc) return -1;
            }
            acc[acc_len] = '\0';
            *out_opcode = first_opcode;
            *out_payload = acc;
            *out_len = acc_len;
            return 0;
        }
    }
}

void nort_ws_close(nort_ws_t *ws) {
    if (!ws) return;
    if (ws->use_tls) {
        mbedtls_ssl_close_notify(&ws->ssl);
        mbedtls_ssl_free(&ws->ssl);
        mbedtls_ssl_config_free(&ws->conf);
        mbedtls_x509_crt_free(&ws->cacert);
        mbedtls_ctr_drbg_free(&ws->ctr_drbg);
        mbedtls_entropy_free(&ws->entropy);
    }
    if (ws->fd >= 0) close(ws->fd);
    pthread_mutex_destroy(&ws->write_lock);
    free(ws);
}
