/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_tcc_modify(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_tcc_modify_t *tcc = msg->event.tcc_modify;
    if (!tcc) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("service"),
        FLB_LOG_EVENT_STRING_VALUE(tcc->service.data, tcc->service.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("identity"),
        FLB_LOG_EVENT_STRING_VALUE(tcc->identity.data, tcc->identity.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("identity_type"),
        FLB_LOG_EVENT_INT32_VALUE(tcc->identity_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("update_type"),
        FLB_LOG_EVENT_INT32_VALUE(tcc->update_type));
    flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
    encode_audit_token_t(encoder, &tcc->instigator_token);
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (tcc->instigator) {
        encode_es_process_t(encoder, tcc->instigator);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "responsible_token");
    if (tcc->responsible_token) {
        encode_audit_token_t(encoder, tcc->responsible_token);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "responsible");
    if (tcc->responsible) {
        encode_es_process_t(encoder, tcc->responsible);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("right"),
        FLB_LOG_EVENT_INT32_VALUE(tcc->right));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("reason"),
        FLB_LOG_EVENT_INT32_VALUE(tcc->reason));
    flb_log_event_encoder_body_commit_map(encoder);
}
