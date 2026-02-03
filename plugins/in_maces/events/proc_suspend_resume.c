/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_proc_suspend_resume(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_proc_suspend_resume_t *psr = &msg->event.proc_suspend_resume;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "target");
    if (psr->target) {
        encode_es_process_t(encoder, psr->target);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("type"),
        FLB_LOG_EVENT_INT32_VALUE(psr->type));
    flb_log_event_encoder_body_commit_map(encoder);
}
