#ifndef NORT_WS_H
#define NORT_WS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NORT_WS_OP_TEXT   0x01
#define NORT_WS_OP_BINARY 0x02
#define NORT_WS_OP_CLOSE  0x08

typedef struct nort_ws nort_ws_t;

int nort_ws_connect(const char *url, int timeout_ms, nort_ws_t **out_ws);
int nort_ws_send_text(nort_ws_t *ws, const char *text, size_t len);
int nort_ws_send_binary(nort_ws_t *ws, const uint8_t *data, size_t len);
int nort_ws_recv(nort_ws_t *ws, uint8_t *out_opcode, uint8_t **out_payload, size_t *out_len, int timeout_ms);
void nort_ws_close(nort_ws_t *ws);

#endif
