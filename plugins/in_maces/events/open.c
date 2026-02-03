/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_open(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_open_t *open = &msg->event.open;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("fflag"),
        FLB_LOG_EVENT_UINT32_VALUE(open->fflag));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "file");
    encode_es_file_t(encoder, open->file);
    flb_log_event_encoder_body_commit_map(encoder);
}
