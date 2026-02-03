/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_xpc_connect(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_xpc_connect_t *xpc_connect = msg->event.xpc_connect;
    if (xpc_connect == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("service_name"),
        FLB_LOG_EVENT_STRING_VALUE(xpc_connect->service_name.data, xpc_connect->service_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("service_domain_type"),
        FLB_LOG_EVENT_INT32_VALUE(xpc_connect->service_domain_type));
    flb_log_event_encoder_body_commit_map(encoder);
}
