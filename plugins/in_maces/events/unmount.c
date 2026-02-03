/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_unmount(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_unmount_t *unmount = &msg->event.unmount;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "statfs");
    encode_statfs(encoder, unmount->statfs);
    flb_log_event_encoder_body_commit_map(encoder);
}
