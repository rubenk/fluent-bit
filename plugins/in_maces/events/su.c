/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_su(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_su_t *su = msg->event.su;
    if (su == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("success"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(su->success));
    if(!su->success) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("failure_message"),
            FLB_LOG_EVENT_STRING_VALUE(su->failure_message.data, su->failure_message.length));
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("from_uid"),
        FLB_LOG_EVENT_UINT32_VALUE(su->from_uid));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("from_username"),
        FLB_LOG_EVENT_STRING_VALUE(su->from_username.data, su->from_username.length));
    if (su->has_to_uid) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("uid"),
          FLB_LOG_EVENT_UINT32_VALUE(su->to_uid.uid));
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("to_username"),
        FLB_LOG_EVENT_STRING_VALUE(su->to_username.data, su->to_username.length));
    if(su->success) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("shell"),
            FLB_LOG_EVENT_STRING_VALUE(su->shell.data, su->shell.length));
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "argv");
        flb_log_event_encoder_body_begin_array(encoder);
        for(size_t i = 0; i < su->argc; i++) {
            flb_log_event_encoder_append_body_string(
                encoder,
                (char *)su->argv[i].data,
                su->argv[i].length);
        }
        flb_log_event_encoder_body_commit_array(encoder);
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "env");
        flb_log_event_encoder_body_begin_array(encoder);
        for(size_t i = 0; i < su->env_count; i++) {
            flb_log_event_encoder_append_body_string(
                encoder,
                (char *)su->env[i].data,
                su->env[i].length);
        }
        flb_log_event_encoder_body_commit_array(encoder);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
