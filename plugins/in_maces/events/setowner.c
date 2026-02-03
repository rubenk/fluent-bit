/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_setowner(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_setowner_t *setowner = &msg->event.setowner;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("uid"),
        FLB_LOG_EVENT_UINT32_VALUE(setowner->uid));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("gid"),
        FLB_LOG_EVENT_UINT32_VALUE(setowner->gid));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "target");
    encode_es_file_t(encoder, setowner->target);
    flb_log_event_encoder_body_commit_map(encoder);
}
