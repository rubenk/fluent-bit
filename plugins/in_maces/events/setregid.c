/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_setregid(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_setregid_t *setregid = &msg->event.setregid;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("rgid"),
        FLB_LOG_EVENT_UINT32_VALUE(setregid->rgid));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("egid"),
        FLB_LOG_EVENT_UINT32_VALUE(setregid->egid));
    flb_log_event_encoder_body_commit_map(encoder);
}
