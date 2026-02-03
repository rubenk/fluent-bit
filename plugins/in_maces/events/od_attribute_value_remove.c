/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_od_attribute_value_remove(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_od_attribute_value_remove_t *od_attribute_value_remove = msg->event.od_attribute_value_remove;
    if (!od_attribute_value_remove) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    encode_od_instigator(encoder, od_attribute_value_remove->instigator);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
        FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_remove->error_code));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
        FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_remove->record_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->record_name.data, od_attribute_value_remove->record_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("attribute_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->attribute_name.data, od_attribute_value_remove->attribute_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("attribute_value"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->attribute_value.data, od_attribute_value_remove->attribute_value.length));
    encode_od_tail(encoder, &od_attribute_value_remove->node_name,
                   &od_attribute_value_remove->db_path,
                   &od_attribute_value_remove->instigator_token, msg->version);
    flb_log_event_encoder_body_commit_map(encoder);
}
