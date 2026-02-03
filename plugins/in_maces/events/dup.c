/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_dup(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_dup_t *dup = &msg->event.dup;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, dup->target);
    flb_log_event_encoder_body_commit_map(encoder);
}
