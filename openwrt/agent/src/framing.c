#include "nort_framing.h"
#include <stdlib.h>
#include <string.h>

int nort_frame_encode(
    uint8_t type,
    uint32_t stream_id,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t **out_buf,
    size_t *out_len
) {
    if (payload_len > 0xffffffffu) return -1;
    uint8_t *buf = malloc(9 + payload_len);
    if (!buf) return -1;

    buf[0] = type;
    buf[1] = (uint8_t)((stream_id >> 24) & 0xff);
    buf[2] = (uint8_t)((stream_id >> 16) & 0xff);
    buf[3] = (uint8_t)((stream_id >> 8) & 0xff);
    buf[4] = (uint8_t)(stream_id & 0xff);

    uint32_t plen = (uint32_t)payload_len;
    buf[5] = (uint8_t)((plen >> 24) & 0xff);
    buf[6] = (uint8_t)((plen >> 16) & 0xff);
    buf[7] = (uint8_t)((plen >> 8) & 0xff);
    buf[8] = (uint8_t)(plen & 0xff);

    if (payload_len > 0 && payload) {
        memcpy(buf + 9, payload, payload_len);
    }
    *out_buf = buf;
    *out_len = 9 + payload_len;
    return 0;
}

int nort_frame_decode(const uint8_t *raw, size_t raw_len, nort_frame_t *out_frame) {
    if (!raw || raw_len < 9 || !out_frame) return -1;
    uint32_t stream_id = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) |
                         ((uint32_t)raw[3] << 8) | (uint32_t)raw[4];
    uint32_t length = ((uint32_t)raw[5] << 24) | ((uint32_t)raw[6] << 16) |
                      ((uint32_t)raw[7] << 8) | (uint32_t)raw[8];

    if (raw_len != 9 + (size_t)length) return -1;

    uint8_t *payload = NULL;
    if (length > 0) {
        payload = malloc(length);
        if (!payload) return -1;
        memcpy(payload, raw + 9, length);
    }

    out_frame->type = raw[0];
    out_frame->stream_id = stream_id;
    out_frame->payload = payload;
    out_frame->payload_len = length;
    return 0;
}

void nort_frame_free(nort_frame_t *frame) {
    if (!frame) return;
    free(frame->payload);
    frame->payload = NULL;
    frame->payload_len = 0;
}
