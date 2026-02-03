/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_file_provider_materialize(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_file_provider_materialize_t *file_provider_materialize = &msg->event.file_provider_materialize;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (file_provider_materialize->instigator != NULL) {
        encode_es_process_t(encoder, file_provider_materialize->instigator);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source");
    encode_es_file_t(encoder, file_provider_materialize->source);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, file_provider_materialize->target);
    if (msg->version >= 8) {
        encode_audit_token_t(encoder, &file_provider_materialize->instigator_token);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
