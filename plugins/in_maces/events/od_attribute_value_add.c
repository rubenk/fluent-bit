/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_od_attribute_value_add(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_od_attribute_value_add_t *od_attribute_value_add = msg->event.od_attribute_value_add;
    if (!od_attribute_value_add) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    encode_od_instigator(encoder, od_attribute_value_add->instigator);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
        FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_add->error_code));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
        FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_add->record_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->record_name.data, od_attribute_value_add->record_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("attribute_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->attribute_name.data, od_attribute_value_add->attribute_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("attribute_value"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->attribute_value.data, od_attribute_value_add->attribute_value.length));
    encode_od_tail(encoder, &od_attribute_value_add->node_name,
                   &od_attribute_value_add->db_path,
                   &od_attribute_value_add->instigator_token, msg->version);
    flb_log_event_encoder_body_commit_map(encoder);
}
