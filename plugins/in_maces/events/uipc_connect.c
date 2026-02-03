/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_uipc_connect(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_uipc_connect_t *uipc_connect = &msg->event.uipc_connect;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "file");
    encode_es_file_t(encoder, uipc_connect->file);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("domain"),
        FLB_LOG_EVENT_INT32_VALUE(uipc_connect->domain));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("type"),
        FLB_LOG_EVENT_INT32_VALUE(uipc_connect->type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("protocol"),
        FLB_LOG_EVENT_INT32_VALUE(uipc_connect->protocol));
    flb_log_event_encoder_body_commit_map(encoder);
}
