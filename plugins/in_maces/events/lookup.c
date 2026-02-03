/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_lookup(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_lookup_t *lookup = &msg->event.lookup;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source_dir");
    encode_es_file_t(encoder, lookup->source_dir);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("relative_target"),
        FLB_LOG_EVENT_STRING_VALUE(lookup->relative_target.data, lookup->relative_target.length));
    flb_log_event_encoder_body_commit_map(encoder);
}
