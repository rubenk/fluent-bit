/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_mount(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_mount_t *mount = &msg->event.mount;
    flb_log_event_encoder_body_begin_map(encoder);
    if (msg->version >= 8) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("disposition"),
            FLB_LOG_EVENT_INT32_VALUE(mount->disposition));
    }
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "statfs");
    encode_statfs(encoder, mount->statfs);
    flb_log_event_encoder_body_commit_map(encoder);
}
