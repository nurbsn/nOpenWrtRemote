#define _POSIX_C_SOURCE 200809L
#include "nort_tunnel.h"
#include "nort_framing.h"
#include "nort_ws.h"

#include <ctype.h>
#include <errno.h>
#include <json-c/json.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char *find_str_ci(const char *haystack, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;
    for (const char *p = haystack; *p; p++) {
        if (strncasecmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
}

#define MAX_PENDING_STREAMS 64
#define MAX_HTTP_BODY_BYTES (16u * 1024u * 1024u)

typedef struct {
    bool active;
    uint32_t stream_id;
    char *meta_json;
    uint8_t *body;
    size_t body_len;
} pending_stream_t;

typedef struct {
    char *tunnel_url;
    nort_tunnel_crypto_t *tc;
    char *local_target;
    bool allow_full_luci;
    volatile const bool *shutdown_flag;
    nort_tunnel_done_cb on_done;
    void *user_data;
} tunnel_ctx_t;

static int parse_http_target(const char *url, char *host, size_t host_cap, char *port, size_t port_cap) {
    if (strncmp(url, "http://", 7) != 0) return -1;
    const char *p = url + 7;
    const char *slash = strchr(p, '/');
    size_t len = slash ? (size_t)(slash - p) : strlen(p);
    if (len == 0 || len >= host_cap) return -1;

    char auth[256];
    if (len >= sizeof(auth)) return -1;
    memcpy(auth, p, len);
    auth[len] = '\0';

    char *colon = strrchr(auth, ':');
    if (colon) {
        *colon = '\0';
        snprintf(port, port_cap, "%s", colon + 1);
    } else {
        snprintf(port, port_cap, "80");
    }
    snprintf(host, host_cap, "%s", auth);
    return 0;
}

static int tcp_connect_local(const char *host, const char *port) {
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
        struct timeval tv = { .tv_sec = 25, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int send_all_fd(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int read_all_http_response(int fd, uint8_t **out_raw, size_t *out_len) {
    size_t cap = 16384;
    size_t len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;

    for (;;) {
        if (len + 4096 > cap) {
            if (cap >= MAX_HTTP_BODY_BYTES) {
                free(buf);
                return -1;
            }
            cap *= 2;
            uint8_t *next = realloc(buf, cap);
            if (!next) { free(buf); return -1; }
            buf = next;
        }
        ssize_t n = recv(fd, buf + len, cap - len - 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    *out_raw = buf;
    *out_len = len;
    return 0;
}

static int decode_chunked_body(const uint8_t *in, size_t in_len, uint8_t **out_body, size_t *out_len) {
    size_t cap = in_len + 1;
    uint8_t *out = malloc(cap);
    if (!out) return -1;
    size_t out_pos = 0;
    size_t pos = 0;

    while (pos < in_len) {
        const uint8_t *nl = memchr(in + pos, '\n', in_len - pos);
        if (!nl) break;
        size_t line_len = (size_t)(nl - (in + pos));
        char hex_line[64];
        size_t copy_len = line_len < sizeof(hex_line) - 1 ? line_len : sizeof(hex_line) - 1;
        memcpy(hex_line, in + pos, copy_len);
        hex_line[copy_len] = '\0';
        char *semi = strchr(hex_line, ';');
        if (semi) *semi = '\0';
        size_t chunk_sz = (size_t)strtoul(hex_line, NULL, 16);
        pos = (size_t)(nl - in) + 1;
        if (chunk_sz == 0) break;
        if (pos + chunk_sz > in_len) chunk_sz = in_len - pos;
        memcpy(out + out_pos, in + pos, chunk_sz);
        out_pos += chunk_sz;
        pos += chunk_sz;
        if (pos + 2 <= in_len && in[pos] == '\r' && in[pos + 1] == '\n') pos += 2;
    }

    *out_body = out;
    *out_len = out_pos;
    return 0;
}

static int send_encrypted_frame(nort_ws_t *ws, nort_tunnel_crypto_t *tc, uint8_t type, uint32_t stream_id, const uint8_t *payload, size_t len) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (nort_frame_encode(type, stream_id, payload, len, &raw, &raw_len) != 0) return -1;

    uint8_t *env = NULL;
    size_t env_len = 0;
    int rc = nort_tunnel_crypto_seal(tc, raw, raw_len, &env, &env_len);
    free(raw);
    if (rc != 0) return -1;

    rc = nort_ws_send_binary(ws, env, env_len);
    free(env);
    return rc;
}

static void send_http_error(nort_ws_t *ws, nort_tunnel_crypto_t *tc, uint32_t stream_id, int status, const char *msg) {
    struct json_object *meta = json_object_new_object();
    struct json_object *headers = json_object_new_object();
    struct json_object *ct_arr = json_object_new_array();
    json_object_array_add(ct_arr, json_object_new_string("text/plain; charset=utf-8"));
    json_object_object_add(headers, "Content-Type", ct_arr);
    json_object_object_add(meta, "status", json_object_new_int(status));
    json_object_object_add(meta, "headers", headers);

    const char *meta_str = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RES_META, stream_id, (const uint8_t *)meta_str, strlen(meta_str));
    (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RES_BODY, stream_id, (const uint8_t *)msg, strlen(msg));
    (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RES_END, stream_id, NULL, 0);
    json_object_put(meta);
}

static void handle_ubus_req(nort_ws_t *ws, nort_tunnel_crypto_t *tc, const char *local_target, uint32_t stream_id, const uint8_t *body, size_t body_len) {
    char host[192], port[16];
    if (parse_http_target(local_target, host, sizeof(host), port, sizeof(port)) != 0) {
        (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RST, stream_id, (const uint8_t *)"bad local_target", 16);
        return;
    }

    int fd = tcp_connect_local(host, port);
    if (fd < 0) {
        (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RST, stream_id, (const uint8_t *)"ubus unreachable", 16);
        return;
    }

    char hdr[512];
    int hlen = snprintf(
        hdr, sizeof(hdr),
        "POST /ubus HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        host, port, body_len);

    if (send_all_fd(fd, (const uint8_t *)hdr, (size_t)hlen) != 0 ||
        (body_len > 0 && send_all_fd(fd, body, body_len) != 0)) {
        close(fd);
        (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RST, stream_id, (const uint8_t *)"ubus write failed", 17);
        return;
    }

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (read_all_http_response(fd, &raw, &raw_len) != 0) {
        close(fd);
        (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RST, stream_id, (const uint8_t *)"ubus read failed", 16);
        return;
    }
    close(fd);

    char *sep = strstr((char *)raw, "\r\n\r\n");
    if (!sep) {
        free(raw);
        (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RST, stream_id, (const uint8_t *)"bad ubus http", 13);
        return;
    }

    size_t hdr_len = (size_t)(sep - (char *)raw);
    const uint8_t *resp_body = (const uint8_t *)(sep + 4);
    size_t resp_body_len = raw_len - (hdr_len + 4);

    *sep = '\0';
    if (find_str_ci((char *)raw, "Transfer-Encoding: chunked")) {
        uint8_t *decoded = NULL;
        size_t decoded_len = 0;
        if (decode_chunked_body(resp_body, resp_body_len, &decoded, &decoded_len) == 0) {
            (void)send_encrypted_frame(ws, tc, NORT_FRAME_UBUS_RES, stream_id, decoded, decoded_len);
            free(decoded);
        }
    } else {
        (void)send_encrypted_frame(ws, tc, NORT_FRAME_UBUS_RES, stream_id, resp_body, resp_body_len);
    }
    free(raw);
}

static void handle_http_stream(
    nort_ws_t *ws,
    nort_tunnel_crypto_t *tc,
    const char *local_target,
    bool allow_full_luci,
    pending_stream_t *st
) {
    struct json_object *meta = json_tokener_parse(st->meta_json);
    if (!meta) {
        send_http_error(ws, tc, st->stream_id, 400, "Invalid HTTP request metadata");
        return;
    }

    struct json_object *jmethod = NULL, *jpath = NULL, *jheaders = NULL;
    const char *method = "GET";
    const char *path = "/";
    if (json_object_object_get_ex(meta, "method", &jmethod)) method = json_object_get_string(jmethod);
    if (json_object_object_get_ex(meta, "path", &jpath)) path = json_object_get_string(jpath);

    if (path[0] != '/') {
        send_http_error(ws, tc, st->stream_id, 400, "Path must start with /");
        json_object_put(meta);
        return;
    }
    if (!allow_full_luci && strncmp(path, "/ubus", 5) != 0) {
        send_http_error(ws, tc, st->stream_id, 403, "Full LuCI proxy disabled by router policy");
        json_object_put(meta);
        return;
    }

    char host[192], port[16];
    if (parse_http_target(local_target, host, sizeof(host), port, sizeof(port)) != 0) {
        send_http_error(ws, tc, st->stream_id, 502, "Invalid local_target");
        json_object_put(meta);
        return;
    }

    int fd = tcp_connect_local(host, port);
    if (fd < 0) {
        send_http_error(ws, tc, st->stream_id, 502, "Local LuCI unreachable");
        json_object_put(meta);
        return;
    }

    size_t req_cap = 4096 + strlen(path);
    char *req_hdr = malloc(req_cap);
    if (!req_hdr) {
        close(fd);
        json_object_put(meta);
        return;
    }

    int off = snprintf(req_hdr, req_cap, "%s %s HTTP/1.1\r\nHost: %s:%s\r\n", method, path, host, port);
    if (json_object_object_get_ex(meta, "headers", &jheaders) && json_object_is_type(jheaders, json_type_object)) {
        json_object_object_foreach(jheaders, key, val_arr) {
            if (strcasecmp(key, "Host") == 0 || strcasecmp(key, "Connection") == 0 ||
                strcasecmp(key, "Content-Length") == 0 || strcasecmp(key, "Accept-Encoding") == 0) {
                continue;
            }
            if (json_object_is_type(val_arr, json_type_array)) {
                size_t arr_len = json_object_array_length(val_arr);
                for (size_t i = 0; i < arr_len; i++) {
                    const char *v = json_object_get_string(json_object_array_get_idx(val_arr, i));
                    if (v && (size_t)off + strlen(key) + strlen(v) + 8 < req_cap) {
                        off += snprintf(req_hdr + off, req_cap - (size_t)off, "%s: %s\r\n", key, v);
                    }
                }
            }
        }
    }
    if (st->body_len > 0) {
        off += snprintf(req_hdr + off, req_cap - (size_t)off, "Content-Length: %zu\r\n", st->body_len);
    }
    off += snprintf(req_hdr + off, req_cap - (size_t)off, "Connection: close\r\n\r\n");

    int send_rc = send_all_fd(fd, (const uint8_t *)req_hdr, (size_t)off);
    free(req_hdr);
    json_object_put(meta);

    if (send_rc == 0 && st->body_len > 0) {
        send_rc = send_all_fd(fd, st->body, st->body_len);
    }
    if (send_rc != 0) {
        close(fd);
        send_http_error(ws, tc, st->stream_id, 502, "Failed forwarding request to local LuCI");
        return;
    }

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (read_all_http_response(fd, &raw, &raw_len) != 0) {
        close(fd);
        send_http_error(ws, tc, st->stream_id, 502, "Failed reading response from local LuCI");
        return;
    }
    close(fd);

    char *sep = strstr((char *)raw, "\r\n\r\n");
    if (!sep) {
        free(raw);
        send_http_error(ws, tc, st->stream_id, 502, "Invalid HTTP response from local LuCI");
        return;
    }

    size_t hdr_len = (size_t)(sep - (char *)raw);
    const uint8_t *resp_body = (const uint8_t *)(sep + 4);
    size_t resp_body_len = raw_len - (hdr_len + 4);
    *sep = '\0';

    bool is_chunked = find_str_ci((char *)raw, "Transfer-Encoding: chunked") != NULL;

    struct json_object *res_meta = json_object_new_object();
    struct json_object *res_headers = json_object_new_object();
    int status_code = 200;

    char *saveptr = NULL;
    char *line = strtok_r((char *)raw, "\r\n", &saveptr);
    if (line) {
        char *sp = strchr(line, ' ');
        if (sp) status_code = atoi(sp + 1);
    }
    while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *hname = line;
        char *hval = colon + 1;
        while (*hval == ' ' || *hval == '\t') hval++;
        if (strcasecmp(hname, "Transfer-Encoding") == 0 ||
            strcasecmp(hname, "Connection") == 0 ||
            strcasecmp(hname, "Content-Length") == 0) {
            continue;
        }
        struct json_object *arr = NULL;
        if (!json_object_object_get_ex(res_headers, hname, &arr)) {
            arr = json_object_new_array();
            json_object_object_add(res_headers, hname, arr);
        }
        json_object_array_add(arr, json_object_new_string(hval));
    }
    json_object_object_add(res_meta, "status", json_object_new_int(status_code));
    json_object_object_add(res_meta, "headers", res_headers);

    const char *res_meta_str = json_object_to_json_string_ext(res_meta, JSON_C_TO_STRING_PLAIN);
    (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RES_META, st->stream_id, (const uint8_t *)res_meta_str, strlen(res_meta_str));
    json_object_put(res_meta);

    const uint8_t *send_body = resp_body;
    size_t send_len = resp_body_len;
    uint8_t *decoded = NULL;
    if (is_chunked && decode_chunked_body(resp_body, resp_body_len, &decoded, &send_len) == 0) {
        send_body = decoded;
    }

    size_t pos = 0;
    while (pos < send_len) {
        size_t chunk = send_len - pos;
        if (chunk > 32768) chunk = 32768;
        if (send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RES_BODY, st->stream_id, send_body + pos, chunk) != 0) break;
        pos += chunk;
    }
    (void)send_encrypted_frame(ws, tc, NORT_FRAME_HTTP_RES_END, st->stream_id, NULL, 0);

    free(decoded);
    free(raw);
}

static pending_stream_t *find_stream(pending_stream_t *streams, uint32_t id, bool create) {
    pending_stream_t *empty = NULL;
    for (int i = 0; i < MAX_PENDING_STREAMS; i++) {
        if (streams[i].active && streams[i].stream_id == id) return &streams[i];
        if (!streams[i].active && !empty) empty = &streams[i];
    }
    if (create && empty) {
        memset(empty, 0, sizeof(*empty));
        empty->active = true;
        empty->stream_id = id;
        return empty;
    }
    return NULL;
}

static void free_stream(pending_stream_t *st) {
    if (!st) return;
    free(st->meta_json);
    free(st->body);
    memset(st, 0, sizeof(*st));
}

static void *tunnel_thread_fn(void *arg) {
    tunnel_ctx_t *ctx = (tunnel_ctx_t *)arg;
    nort_ws_t *ws = NULL;

    if (nort_ws_connect(ctx->tunnel_url, 15000, &ws) == 0) {
        pending_stream_t streams[MAX_PENDING_STREAMS];
        memset(streams, 0, sizeof(streams));

        while (!*(ctx->shutdown_flag)) {
            uint8_t opcode = 0;
            uint8_t *env = NULL;
            size_t env_len = 0;
            if (nort_ws_recv(ws, &opcode, &env, &env_len, 60000) != 0) break;
            if (opcode == NORT_WS_OP_CLOSE) {
                free(env);
                break;
            }
            if (opcode != NORT_WS_OP_BINARY) {
                free(env);
                continue;
            }

            uint8_t *plain = NULL;
            size_t plain_len = 0;
            if (nort_tunnel_crypto_open(ctx->tc, env, env_len, &plain, &plain_len) != 0) {
                free(env);
                break;
            }
            free(env);

            nort_frame_t f;
            if (nort_frame_decode(plain, plain_len, &f) != 0) {
                free(plain);
                continue;
            }
            free(plain);

            switch (f.type) {
                case NORT_FRAME_PING:
                    (void)send_encrypted_frame(ws, ctx->tc, NORT_FRAME_PONG, 0, f.payload, f.payload_len);
                    break;
                case NORT_FRAME_UBUS_REQ:
                    handle_ubus_req(ws, ctx->tc, ctx->local_target, f.stream_id, f.payload, f.payload_len);
                    break;
                case NORT_FRAME_HTTP_REQ_META: {
                    pending_stream_t *st = find_stream(streams, f.stream_id, true);
                    if (st) {
                        free(st->meta_json);
                        st->meta_json = malloc(f.payload_len + 1);
                        if (st->meta_json) {
                            memcpy(st->meta_json, f.payload, f.payload_len);
                            st->meta_json[f.payload_len] = '\0';
                        }
                    }
                    break;
                }
                case NORT_FRAME_HTTP_REQ_BODY: {
                    pending_stream_t *st = find_stream(streams, f.stream_id, false);
                    if (st && st->body_len + f.payload_len <= MAX_HTTP_BODY_BYTES) {
                        uint8_t *nb = realloc(st->body, st->body_len + f.payload_len);
                        if (nb) {
                            st->body = nb;
                            memcpy(st->body + st->body_len, f.payload, f.payload_len);
                            st->body_len += f.payload_len;
                        }
                    }
                    break;
                }
                case NORT_FRAME_HTTP_REQ_END: {
                    pending_stream_t *st = find_stream(streams, f.stream_id, false);
                    if (st) {
                        handle_http_stream(ws, ctx->tc, ctx->local_target, ctx->allow_full_luci, st);
                        free_stream(st);
                    }
                    break;
                }
                case NORT_FRAME_HTTP_RST:
                    free_stream(find_stream(streams, f.stream_id, false));
                    break;
                default:
                    break;
            }
            nort_frame_free(&f);
        }

        for (int i = 0; i < MAX_PENDING_STREAMS; i++) {
            if (streams[i].active) free_stream(&streams[i]);
        }
        nort_ws_close(ws);
    }

    if (ctx->on_done) ctx->on_done(ctx->user_data);
    nort_tunnel_crypto_free(ctx->tc);
    free(ctx->tc);
    free(ctx->tunnel_url);
    free(ctx->local_target);
    free(ctx);
    return NULL;
}

int nort_tunnel_start_session(
    const char *tunnel_url,
    nort_tunnel_crypto_t *tc,
    const char *local_target,
    bool allow_full_luci,
    volatile const bool *shutdown_flag,
    nort_tunnel_done_cb on_done,
    void *user_data
) {
    tunnel_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return -1;
    ctx->tunnel_url = strdup(tunnel_url);
    ctx->tc = tc;
    ctx->local_target = strdup(local_target);
    ctx->allow_full_luci = allow_full_luci;
    ctx->shutdown_flag = shutdown_flag;
    ctx->on_done = on_done;
    ctx->user_data = user_data;

    if (!ctx->tunnel_url || !ctx->local_target) {
        free(ctx->tunnel_url);
        free(ctx->local_target);
        free(ctx);
        return -1;
    }

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&tid, &attr, tunnel_thread_fn, ctx);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        free(ctx->tunnel_url);
        free(ctx->local_target);
        free(ctx);
        return -1;
    }
    return 0;
}
