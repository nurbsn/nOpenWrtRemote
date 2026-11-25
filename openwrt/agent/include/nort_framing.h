#ifndef NORT_FRAMING_H
#define NORT_FRAMING_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    NORT_FRAME_HTTP_REQ_META = 0x01,
    NORT_FRAME_HTTP_REQ_BODY = 0x02,
    NORT_FRAME_HTTP_REQ_END  = 0x03,
    NORT_FRAME_HTTP_RES_META = 0x11,
    NORT_FRAME_HTTP_RES_BODY = 0x12,
    NORT_FRAME_HTTP_RES_END  = 0x13,
    NORT_FRAME_HTTP_RST      = 0x14,
    NORT_FRAME_UBUS_REQ      = 0x20,
    NORT_FRAME_UBUS_RES      = 0x21,
    NORT_FRAME_PING          = 0x30,
    NORT_FRAME_PONG          = 0x31
} nort_frame_type_t;

typedef struct {
    uint8_t type;
    uint32_t stream_id;
    uint8_t *payload;
    size_t payload_len;
} nort_frame_t;

int nort_frame_encode(uint8_t type, uint32_t stream_id, const uint8_t *payload, size_t payload_len, uint8_t **out_buf, size_t *out_len);
int nort_frame_decode(const uint8_t *raw, size_t raw_len, nort_frame_t *out_frame);
void nort_frame_free(nort_frame_t *frame);

#endif
