/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_mmap(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_mmap_t *mmap_ev = &msg->event.mmap;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("max_protection"),
        FLB_LOG_EVENT_INT32_VALUE(mmap_ev->max_protection));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("protection"),
        FLB_LOG_EVENT_INT32_VALUE(mmap_ev->protection));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("flags"),
        FLB_LOG_EVENT_INT32_VALUE(mmap_ev->flags));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("file_pos"),
        FLB_LOG_EVENT_UINT64_VALUE(mmap_ev->file_pos));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "source");
    encode_es_file_t(encoder, mmap_ev->source);
    flb_log_event_encoder_body_commit_map(encoder);
}
