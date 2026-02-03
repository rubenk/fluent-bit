/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_screensharing_attach(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_screensharing_attach_t *screensharing_attach = msg->event.screensharing_attach;
    if (screensharing_attach == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("success"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(screensharing_attach->success));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
        FLB_LOG_EVENT_INT32_VALUE(screensharing_attach->source_address_type));
    if (screensharing_attach->source_address.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
          FLB_LOG_EVENT_STRING_VALUE(screensharing_attach->source_address.data, screensharing_attach->source_address.length));
    }
    if (screensharing_attach->viewer_appleid.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("viewer_appleid"),
          FLB_LOG_EVENT_STRING_VALUE(screensharing_attach->viewer_appleid.data, screensharing_attach->viewer_appleid.length));
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("authentication_type"),
        FLB_LOG_EVENT_STRING_VALUE(screensharing_attach->authentication_type.data, screensharing_attach->authentication_type.length));
    if (screensharing_attach->authentication_username.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("authentication_username"),
          FLB_LOG_EVENT_STRING_VALUE(screensharing_attach->authentication_username.data, screensharing_attach->authentication_username.length));
    }
    if (screensharing_attach->session_username.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("session_username"),
          FLB_LOG_EVENT_STRING_VALUE(screensharing_attach->session_username.data, screensharing_attach->session_username.length));
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("existing_session"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(screensharing_attach->existing_session));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
        FLB_LOG_EVENT_UINT32_VALUE(screensharing_attach->graphical_session_id));
    flb_log_event_encoder_body_commit_map(encoder);
}
