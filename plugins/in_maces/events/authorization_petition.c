/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_authorization_petition(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_authorization_petition_t *ap = msg->event.authorization_petition;
    if (!ap) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (ap->instigator) {
        encode_es_process_t(encoder, ap->instigator);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "petitioner");
    if (ap->petitioner) {
        encode_es_process_t(encoder, ap->petitioner);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("flags"),
        FLB_LOG_EVENT_UINT32_VALUE(ap->flags));
    flb_log_event_encoder_append_body_cstring(encoder, "rights");
    flb_log_event_encoder_body_begin_array(encoder);
    for (size_t i = 0; i < ap->right_count; i++) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_STRING_VALUE(ap->rights[i].data, ap->rights[i].length));
    }
    flb_log_event_encoder_body_commit_array(encoder);
    if (msg->version >= 8) {
        flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
        encode_audit_token_t(encoder, &ap->instigator_token);
        flb_log_event_encoder_append_body_cstring(encoder, "petitioner_token");
        encode_audit_token_t(encoder, &ap->petitioner_token);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
