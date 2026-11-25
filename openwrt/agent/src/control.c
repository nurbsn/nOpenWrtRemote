#define _POSIX_C_SOURCE 200809L
#include "nort_control.h"
#include "nort_config.h"

#include <errno.h>
#include <json-c/json.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

struct nort_control_srv {
    int fd;
    char socket_path[256];
    nort_agent_t *agent;
    volatile bool running;
    pthread_t thread;
};

static void send_http_json(int cfd, int status, const char *json) {
    const char *reason = status == 200 ? "OK" : (status == 400 ? "Bad Request" : "Internal Error");
    size_t blen = json ? strlen(json) : 0;
    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
                        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                        status, reason, blen);
    (void)send(cfd, hdr, (size_t)hlen, 0);
    if (blen > 0) (void)send(cfd, json, blen, 0);
}

static void handle_client(nort_control_srv_t *srv, int cfd) {
    char buf[4096];
    ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(cfd);
        return;
    }
    buf[n] = '\0';

    char method[16] = {0}, path[128] = {0};
    if (sscanf(buf, "%15s %127s", method, path) != 2) {
        send_http_json(cfd, 400, "{\"error\":\"bad request\"}");
        close(cfd);
        return;
    }

    if (strcmp(path, "/status") == 0) {
        char *j = nort_agent_status_json(srv->agent);
        send_http_json(cfd, 200, j ? j : "{}");
        free(j);
    } else if (strcmp(path, "/pairing/start") == 0 && strcmp(method, "POST") == 0) {
        char *j = NULL;
        if (nort_agent_start_pairing(srv->agent, &j) == 0 && j) {
            send_http_json(cfd, 200, j);
            free(j);
        } else {
            send_http_json(cfd, 500, "{\"error\":\"pairing failed\"}");
        }
    } else if (strcmp(path, "/peers") == 0) {
        char *j = nort_agent_peers_json(srv->agent);
        send_http_json(cfd, 200, j ? j : "{\"peers\":[]}");
        free(j);
    } else if (strcmp(path, "/peers/revoke") == 0 && strcmp(method, "POST") == 0) {
        const char *body = strstr(buf, "\r\n\r\n");
        body = body ? body + 4 : "";
        struct json_object *obj = json_tokener_parse(body);
        struct json_object *jnpub = NULL;
        const char *npub = (obj && json_object_object_get_ex(obj, "npub", &jnpub)) ? json_object_get_string(jnpub) : NULL;
        if (!npub || npub[0] == '\0') {
            if (obj) json_object_put(obj);
            send_http_json(cfd, 400, "{\"error\":\"npub required\"}");
            close(cfd);
            return;
        }
        bool removed = false;
        int rc = nort_config_revoke_peer(srv->agent->cfg, npub, &removed);
        if (obj) json_object_put(obj);
        if (rc == 0) {
            send_http_json(cfd, 200, removed ? "{\"revoked\":true}" : "{\"revoked\":false}");
        } else {
            send_http_json(cfd, 500, "{\"error\":\"revoke failed\"}");
        }
    } else {
        send_http_json(cfd, 400, "{\"error\":\"unknown endpoint\"}");
    }

    close(cfd);
}

static void *control_loop(void *arg) {
    nort_control_srv_t *srv = (nort_control_srv_t *)arg;
    while (srv->running) {
        struct pollfd pfd = { .fd = srv->fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 500);
        if (pr <= 0) continue;
        int cfd = accept(srv->fd, NULL, NULL);
        if (cfd >= 0) handle_client(srv, cfd);
    }
    return NULL;
}

int nort_control_start(const char *socket_path, nort_agent_t *agent, nort_control_srv_t **out_srv) {
    unlink(socket_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        return -1;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    chmod(socket_path, 0600);

    nort_control_srv_t *srv = calloc(1, sizeof(*srv));
    if (!srv) {
        close(fd);
        return -1;
    }
    srv->fd = fd;
    snprintf(srv->socket_path, sizeof(srv->socket_path), "%s", socket_path);
    srv->agent = agent;
    srv->running = true;

    if (pthread_create(&srv->thread, NULL, control_loop, srv) != 0) {
        close(fd);
        free(srv);
        return -1;
    }

    *out_srv = srv;
    return 0;
}

void nort_control_stop(nort_control_srv_t *srv) {
    if (!srv) return;
    srv->running = false;
    pthread_join(srv->thread, NULL);
    close(srv->fd);
    unlink(srv->socket_path);
    free(srv);
}
