/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_fork(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_fork_t *fork_ev = &msg->event.fork;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "child");
    encode_es_process_t(encoder, fork_ev->child);
    flb_log_event_encoder_body_commit_map(encoder);
}
