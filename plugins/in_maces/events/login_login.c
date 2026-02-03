/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_login_login(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_login_login_t *login_login = msg->event.login_login;
    if (login_login == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("success"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(login_login->success));
    if (login_login->failure_message.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("failure_message"),
          FLB_LOG_EVENT_STRING_VALUE(login_login->failure_message.data, login_login->failure_message.length));
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("username"),
        FLB_LOG_EVENT_STRING_VALUE(login_login->username.data, login_login->username.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("has_uid"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(login_login->has_uid));
    if (login_login->has_uid) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("uid"),
          FLB_LOG_EVENT_UINT32_VALUE(login_login->uid.uid));
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
