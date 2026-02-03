/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_get_task_inspect(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_get_task_inspect_t *get_task_inspect = &msg->event.get_task_inspect;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_process_t(encoder, get_task_inspect->target);
    if (msg->version >= 5) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("type"),
            FLB_LOG_EVENT_INT32_VALUE(get_task_inspect->type));
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
