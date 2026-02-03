/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_setflags(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_setflags_t *setflags = &msg->event.setflags;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("flags"),
        FLB_LOG_EVENT_UINT32_VALUE(setflags->flags));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, setflags->target);
    flb_log_event_encoder_body_commit_map(encoder);
}
