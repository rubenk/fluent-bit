/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"
#include <sys/types.h>

void encode_event_pty_close(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_pty_close_t *pty_close = &msg->event.pty_close;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("dev_major"),
        FLB_LOG_EVENT_INT32_VALUE(major(pty_close->dev)),
        FLB_LOG_EVENT_CSTRING_VALUE("dev_minor"),
        FLB_LOG_EVENT_INT32_VALUE(minor(pty_close->dev)));
    flb_log_event_encoder_body_commit_map(encoder);
}
