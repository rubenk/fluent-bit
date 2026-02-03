/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_exec(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_exec_t *exec = &msg->event.exec;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("dyld_exec_path"),
        FLB_LOG_EVENT_STRING_VALUE(exec->dyld_exec_path.data, exec->dyld_exec_path.length));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_process_t(encoder, exec->target);
    flb_log_event_encoder_body_commit_map(encoder);
}
