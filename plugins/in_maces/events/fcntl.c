/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_fcntl(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_fcntl_t *fcntl_ev = &msg->event.fcntl;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, fcntl_ev->target);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("cmd"),
        FLB_LOG_EVENT_INT32_VALUE(fcntl_ev->cmd));
    flb_log_event_encoder_body_commit_map(encoder);
}
