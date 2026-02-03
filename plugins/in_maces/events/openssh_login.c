/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_openssh_login(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_openssh_login_t *openssh_login = msg->event.openssh_login;
    if (openssh_login == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("success"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(openssh_login->success));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("result_type"),
        FLB_LOG_EVENT_INT32_VALUE(openssh_login->result_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
        FLB_LOG_EVENT_INT32_VALUE(openssh_login->source_address_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
        FLB_LOG_EVENT_STRING_VALUE(openssh_login->source_address.data, openssh_login->source_address.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("username"),
        FLB_LOG_EVENT_STRING_VALUE(openssh_login->username.data, openssh_login->username.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("has_uid"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(openssh_login->has_uid));
    if (openssh_login->has_uid) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("uid"),
          FLB_LOG_EVENT_UINT32_VALUE(openssh_login->uid.uid));
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
