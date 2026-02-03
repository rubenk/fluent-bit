/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_link(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_link_t *link = &msg->event.link;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source");
    encode_es_file_t(encoder, link->source);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target_dir");
    encode_es_file_t(encoder, link->target_dir);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("target_filename"),
        FLB_LOG_EVENT_STRING_VALUE(link->target_filename.data, link->target_filename.length));
    flb_log_event_encoder_body_commit_map(encoder);
}
