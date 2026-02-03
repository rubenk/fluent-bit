/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_signal(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_signal_t *signal_ev = &msg->event.signal;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("sig"),
        FLB_LOG_EVENT_INT32_VALUE(signal_ev->sig));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_process_t(encoder, signal_ev->target);
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (signal_ev->instigator != NULL) {
        encode_es_process_t(encoder, signal_ev->instigator);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
