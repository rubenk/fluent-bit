/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_openssh_logout(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_openssh_logout_t *openssh_logout = msg->event.openssh_logout;
    if (openssh_logout == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
        FLB_LOG_EVENT_INT32_VALUE(openssh_logout->source_address_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
        FLB_LOG_EVENT_STRING_VALUE(openssh_logout->source_address.data, openssh_logout->source_address.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("username"),
        FLB_LOG_EVENT_STRING_VALUE(openssh_logout->username.data, openssh_logout->username.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("uid"),
        FLB_LOG_EVENT_UINT32_VALUE(openssh_logout->uid));
    flb_log_event_encoder_body_commit_map(encoder);
}
