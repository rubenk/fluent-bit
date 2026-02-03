/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_od_enable_user(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_od_enable_user_t *od_enable_user = msg->event.od_enable_user;
    if (!od_enable_user) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    encode_od_instigator(encoder, od_enable_user->instigator);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
        FLB_LOG_EVENT_INT32_VALUE(od_enable_user->error_code));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("user_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_enable_user->user_name.data, od_enable_user->user_name.length));
    encode_od_tail(encoder, &od_enable_user->node_name,
                   &od_enable_user->db_path,
                   &od_enable_user->instigator_token, msg->version);
    flb_log_event_encoder_body_commit_map(encoder);
}
