/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_file_provider_update(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_file_provider_update_t *file_provider_update = &msg->event.file_provider_update;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source");
    encode_es_file_t(encoder, file_provider_update->source);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("target_path"),
        FLB_LOG_EVENT_STRING_VALUE(file_provider_update->target_path.data, file_provider_update->target_path.length));
    flb_log_event_encoder_body_commit_map(encoder);
}
