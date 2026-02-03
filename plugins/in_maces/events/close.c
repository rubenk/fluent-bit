/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_close(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_close_t *close_ev = &msg->event.close;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("modified"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(close_ev->modified));
    if (msg->version >= 6) {
      flb_log_event_encoder_append_body_values(
          encoder,
          FLB_LOG_EVENT_CSTRING_VALUE("was_mapped_writable"),
          FLB_LOG_EVENT_BOOLEAN_VALUE(close_ev->was_mapped_writable));
    }
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, close_ev->target);
    flb_log_event_encoder_body_commit_map(encoder);
}
