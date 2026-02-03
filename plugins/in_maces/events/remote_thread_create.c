/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_remote_thread_create(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_remote_thread_create_t *rtc = &msg->event.remote_thread_create;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "target");
    encode_es_process_t(encoder, rtc->target);
    flb_log_event_encoder_append_body_cstring(encoder, "thread_state");
    if (rtc->thread_state) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("flavor"),
            FLB_LOG_EVENT_INT32_VALUE(rtc->thread_state->flavor));
        flb_log_event_encoder_body_commit_map(encoder);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
