/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_copyfile(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_copyfile_t *copyfile = &msg->event.copyfile;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source");
    encode_es_file_t(encoder, copyfile->source);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target_file");
    encode_es_file_t(encoder, copyfile->target_file);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target_dir");
    encode_es_file_t(encoder, copyfile->target_dir);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("target_name"),
        FLB_LOG_EVENT_STRING_VALUE(copyfile->target_name.data, copyfile->target_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("mode"),
        FLB_LOG_EVENT_INT32_VALUE(copyfile->mode));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("flags"),
        FLB_LOG_EVENT_INT32_VALUE(copyfile->flags));
    flb_log_event_encoder_body_commit_map(encoder);
}
