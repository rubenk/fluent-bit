/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_screensharing_detach(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_screensharing_detach_t *screensharing_detach = msg->event.screensharing_detach;
    if (screensharing_detach == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
        FLB_LOG_EVENT_INT32_VALUE(screensharing_detach->source_address_type));
    if (screensharing_detach->source_address.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
          FLB_LOG_EVENT_STRING_VALUE(screensharing_detach->source_address.data, screensharing_detach->source_address.length));
    }
    if (screensharing_detach->viewer_appleid.length > 0) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("viewer_appleid"),
          FLB_LOG_EVENT_STRING_VALUE(screensharing_detach->viewer_appleid.data, screensharing_detach->viewer_appleid.length));
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
        FLB_LOG_EVENT_UINT32_VALUE(screensharing_detach->graphical_session_id));
    flb_log_event_encoder_body_commit_map(encoder);
}
