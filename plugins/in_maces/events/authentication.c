/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_authentication(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_authentication_t *authentication = msg->event.authentication;
    if (!authentication) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("success"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(authentication->success));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("type"),
        FLB_LOG_EVENT_INT32_VALUE(authentication->type));
    switch(authentication->type) {
        case ES_AUTHENTICATION_TYPE_OD:
          encode_od_instigator(encoder, authentication->data.od->instigator);
          flb_log_event_encoder_append_body_values(
              encoder,
              FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
              FLB_LOG_EVENT_STRING_VALUE(authentication->data.od->record_type.data, authentication->data.od->record_type.length));
          flb_log_event_encoder_append_body_values(
              encoder,
              FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
              FLB_LOG_EVENT_STRING_VALUE(authentication->data.od->record_name.data, authentication->data.od->record_name.length));
          encode_od_tail(encoder, &authentication->data.od->node_name,
                         &authentication->data.od->db_path,
                         &authentication->data.od->instigator_token, msg->version);
          break;
        default:
          break;
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
