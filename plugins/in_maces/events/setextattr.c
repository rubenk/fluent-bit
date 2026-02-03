/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_setextattr(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_setextattr_t *setextattr = &msg->event.setextattr;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, setextattr->target);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("extattr"),
        FLB_LOG_EVENT_STRING_VALUE(setextattr->extattr.data, setextattr->extattr.length));
    flb_log_event_encoder_body_commit_map(encoder);
}
