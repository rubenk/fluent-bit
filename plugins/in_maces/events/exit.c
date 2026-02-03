/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_exit(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_exit_t *exit_ev = &msg->event.exit;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("stat"),
        FLB_LOG_EVENT_UINT64_VALUE(exit_ev->stat));
    flb_log_event_encoder_body_commit_map(encoder);
}
