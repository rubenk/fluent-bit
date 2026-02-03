/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_setmode(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_setmode_t *setmode = &msg->event.setmode;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("mode"),
        FLB_LOG_EVENT_INT32_VALUE(setmode->mode));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, setmode->target);
    flb_log_event_encoder_body_commit_map(encoder);
}
