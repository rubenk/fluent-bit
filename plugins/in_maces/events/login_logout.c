/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_login_logout(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_login_logout_t *login_logout = msg->event.login_logout;
    if (login_logout == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("username"),
        FLB_LOG_EVENT_STRING_VALUE(login_logout->username.data, login_logout->username.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("uid"),
        FLB_LOG_EVENT_UINT32_VALUE(login_logout->uid));
    flb_log_event_encoder_body_commit_map(encoder);
}
