/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_od_delete_group(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_od_delete_group_t *od_delete_group = msg->event.od_delete_group;
    if (!od_delete_group) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    encode_od_instigator(encoder, od_delete_group->instigator);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
        FLB_LOG_EVENT_INT32_VALUE(od_delete_group->error_code));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("group_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_delete_group->group_name.data, od_delete_group->group_name.length));
    encode_od_tail(encoder, &od_delete_group->node_name,
                   &od_delete_group->db_path,
                   &od_delete_group->instigator_token, msg->version);
    flb_log_event_encoder_body_commit_map(encoder);
}
