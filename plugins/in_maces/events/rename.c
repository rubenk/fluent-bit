/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_rename(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_rename_t *rename = &msg->event.rename;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source");
    encode_es_file_t(encoder, rename->source);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("destination_type"),
        FLB_LOG_EVENT_INT32_VALUE(rename->destination_type));
    if (rename->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "existing_file");
        encode_es_file_t(encoder, rename->destination.existing_file);
    } else if (rename->destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "new_path");
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("filename"),
            FLB_LOG_EVENT_STRING_VALUE(rename->destination.new_path.filename.data, rename->destination.new_path.filename.length));
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "dir");
        encode_es_file_t(encoder, rename->destination.new_path.dir);
        flb_log_event_encoder_body_commit_map(encoder);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
