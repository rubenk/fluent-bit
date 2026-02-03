/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_iokit_open(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_iokit_open_t *iokit_open = &msg->event.iokit_open;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("user_client_type"),
        FLB_LOG_EVENT_UINT32_VALUE(iokit_open->user_client_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("user_client_class"),
        FLB_LOG_EVENT_STRING_VALUE(iokit_open->user_client_class.data, iokit_open->user_client_class.length));
    flb_log_event_encoder_body_commit_map(encoder);
}
