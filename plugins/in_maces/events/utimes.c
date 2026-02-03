/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_utimes(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_utimes_t *utimes = &msg->event.utimes;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "atime");
    encode_timespec(encoder, &utimes->atime);
    flb_log_event_encoder_append_body_cstring(encoder, "mtime");
    encode_timespec(encoder, &utimes->mtime);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, utimes->target);
    flb_log_event_encoder_body_commit_map(encoder);
}
