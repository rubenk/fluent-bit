/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_mprotect(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_mprotect_t *mprotect_ev = &msg->event.mprotect;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("protection"),
        FLB_LOG_EVENT_INT32_VALUE(mprotect_ev->protection));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("address"),
        FLB_LOG_EVENT_UINT64_VALUE(mprotect_ev->address));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("size"),
        FLB_LOG_EVENT_UINT64_VALUE(mprotect_ev->size));
    flb_log_event_encoder_body_commit_map(encoder);
}
