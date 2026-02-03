/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_od_attribute_set(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_od_attribute_set_t *od_attribute_set = msg->event.od_attribute_set;
    if (!od_attribute_set) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    encode_od_instigator(encoder, od_attribute_set->instigator);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
        FLB_LOG_EVENT_INT32_VALUE(od_attribute_set->error_code));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
        FLB_LOG_EVENT_INT32_VALUE(od_attribute_set->record_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_set->record_name.data, od_attribute_set->record_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("attribute_name"),
        FLB_LOG_EVENT_STRING_VALUE(od_attribute_set->attribute_name.data, od_attribute_set->attribute_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("attribute_value_count"),
        FLB_LOG_EVENT_UINT64_VALUE(od_attribute_set->attribute_value_count));
    flb_log_event_encoder_append_body_cstring(encoder, "attribute_values");
    flb_log_event_encoder_body_begin_array(encoder);
    for (size_t i = 0; i < od_attribute_set->attribute_value_count; i++) {
        flb_log_event_encoder_append_body_string(
            encoder,
            (char *)od_attribute_set->attribute_values[i].data,
            od_attribute_set->attribute_values[i].length);
    }
    flb_log_event_encoder_body_commit_array(encoder);
    encode_od_tail(encoder, &od_attribute_set->node_name,
                   &od_attribute_set->db_path,
                   &od_attribute_set->instigator_token, msg->version);
    flb_log_event_encoder_body_commit_map(encoder);
}
