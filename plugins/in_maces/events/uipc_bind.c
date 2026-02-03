/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_uipc_bind(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_uipc_bind_t *uipc_bind = &msg->event.uipc_bind;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "dir");
    encode_es_file_t(encoder, uipc_bind->dir);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("filename"),
        FLB_LOG_EVENT_STRING_VALUE(uipc_bind->filename.data, uipc_bind->filename.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("mode"),
        FLB_LOG_EVENT_UINT32_VALUE(uipc_bind->mode));
    flb_log_event_encoder_body_commit_map(encoder);
}
