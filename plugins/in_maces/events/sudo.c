/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_sudo(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_sudo_t *sudo = msg->event.sudo;
    if (!sudo) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("success"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(sudo->success));
    if(!sudo->success) {
        const es_sudo_reject_info_t *reject_info = sudo->reject_info;
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "reject_info");
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("plugin_name"),
            FLB_LOG_EVENT_STRING_VALUE(reject_info->plugin_name.data, reject_info->plugin_name.length));
            flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("plugin_type"),
                FLB_LOG_EVENT_INT32_VALUE(reject_info->plugin_type));
            flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("failure_message"),
                FLB_LOG_EVENT_STRING_VALUE(reject_info->failure_message.data, reject_info->failure_message.length));
        flb_log_event_encoder_body_commit_map(encoder);
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("has_from_uid"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(sudo->has_from_uid));
    if (sudo->has_from_uid) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("from_uid"),
          FLB_LOG_EVENT_UINT32_VALUE(sudo->from_uid.uid));
    }
    if (sudo->from_username.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("from_username"),
          FLB_LOG_EVENT_STRING_VALUE(sudo->from_username.data, sudo->from_username.length));
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("has_to_uid"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(sudo->has_to_uid));
    if (sudo->has_to_uid) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("to_uid"),
          FLB_LOG_EVENT_UINT32_VALUE(sudo->to_uid.uid));
    }
    if (sudo->to_username.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("to_username"),
          FLB_LOG_EVENT_STRING_VALUE(sudo->to_username.data, sudo->to_username.length));
    }
    if(sudo->command.length > 0) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("command"),
            FLB_LOG_EVENT_STRING_VALUE(sudo->command.data, sudo->command.length));
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
