/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_settime(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    (void)msg;
    /* settime has no data fields (only reserved), emit empty map */
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_body_commit_map(encoder);
}
