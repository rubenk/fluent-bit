/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_clone(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_clone_t *clone_ev = &msg->event.clone;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source");
    encode_es_file_t(encoder, clone_ev->source);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target_dir");
    encode_es_file_t(encoder, clone_ev->target_dir);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("target_name"),
        FLB_LOG_EVENT_STRING_VALUE(clone_ev->target_name.data, clone_ev->target_name.length));
    flb_log_event_encoder_body_commit_map(encoder);
}
