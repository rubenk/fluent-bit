/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_od_group_set(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_od_group_set_t *od_group_set = msg->event.od_group_set;
    if (!od_group_set) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    encode_od_instigator(encoder, od_group_set->instigator);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
        FLB_LOG_EVENT_INT32_VALUE(od_group_set->error_code));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("group_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_group_set->group_name.data, od_group_set->group_name.length));
    encode_od_members(encoder, od_group_set->members);
    encode_od_tail(encoder, &od_group_set->node_name,
                   &od_group_set->db_path,
                   &od_group_set->instigator_token, msg->version);
    flb_log_event_encoder_body_commit_map(encoder);
}
