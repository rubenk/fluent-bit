/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_lw_session_logout(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_lw_session_logout_t *lw_session_logout = msg->event.lw_session_logout;
    if (lw_session_logout == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("username"),
        FLB_LOG_EVENT_STRING_VALUE(lw_session_logout->username.data, lw_session_logout->username.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
        FLB_LOG_EVENT_UINT32_VALUE(lw_session_logout->graphical_session_id));
    flb_log_event_encoder_body_commit_map(encoder);
}
