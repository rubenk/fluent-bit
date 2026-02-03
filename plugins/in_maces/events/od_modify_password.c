/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_od_modify_password(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_od_modify_password_t *od_modify_password = msg->event.od_modify_password;
    if (!od_modify_password) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    encode_od_instigator(encoder, od_modify_password->instigator);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
        FLB_LOG_EVENT_INT32_VALUE(od_modify_password->error_code));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("account_type"),
        FLB_LOG_EVENT_INT32_VALUE(od_modify_password->account_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("account_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_modify_password->account_name.data, od_modify_password->account_name.length));
    encode_od_tail(encoder, &od_modify_password->node_name,
                   &od_modify_password->db_path,
                   &od_modify_password->instigator_token, msg->version);
    flb_log_event_encoder_body_commit_map(encoder);
}
