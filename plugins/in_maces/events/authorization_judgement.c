/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_authorization_judgement(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_authorization_judgement_t *aj = msg->event.authorization_judgement;
    if (!aj) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (aj->instigator) {
        encode_es_process_t(encoder, aj->instigator);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "petitioner");
    if (aj->petitioner) {
        encode_es_process_t(encoder, aj->petitioner);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("return_code"),
        FLB_LOG_EVENT_INT32_VALUE(aj->return_code));
    flb_log_event_encoder_append_body_cstring(encoder, "results");
    flb_log_event_encoder_body_begin_array(encoder);
    for (size_t i = 0; i < aj->result_count; i++) {
        es_authorization_result_t *result = &aj->results[i];
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("right_name"),
            FLB_LOG_EVENT_STRING_VALUE(result->right_name.data, result->right_name.length));
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("rule_class"),
            FLB_LOG_EVENT_INT32_VALUE(result->rule_class));
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("granted"),
            FLB_LOG_EVENT_BOOLEAN_VALUE(result->granted));
        flb_log_event_encoder_body_commit_map(encoder);
    }
    flb_log_event_encoder_body_commit_array(encoder);
    if (msg->version >= 8) {
        flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
        encode_audit_token_t(encoder, &aj->instigator_token);
        flb_log_event_encoder_append_body_cstring(encoder, "petitioner_token");
        encode_audit_token_t(encoder, &aj->petitioner_token);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
