/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_profile_remove(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_profile_remove_t *pr = msg->event.profile_remove;
    if (!pr) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    const es_profile_t *profile = pr->profile;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (pr->instigator) {
        encode_es_process_t(encoder, pr->instigator);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "profile");
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("uuid"),
        FLB_LOG_EVENT_STRING_VALUE(profile->uuid.data, profile->uuid.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("install_source"),
        FLB_LOG_EVENT_INT32_VALUE(profile->install_source));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("organization"),
        FLB_LOG_EVENT_STRING_VALUE(profile->organization.data, profile->organization.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("display_name"),
        FLB_LOG_EVENT_STRING_VALUE(profile->display_name.data, profile->display_name.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("scope"),
        FLB_LOG_EVENT_STRING_VALUE(profile->scope.data, profile->scope.length));
    flb_log_event_encoder_body_commit_map(encoder);
    if (msg->version >= 8) {
        flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
        encode_audit_token_t(encoder, &pr->instigator_token);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
