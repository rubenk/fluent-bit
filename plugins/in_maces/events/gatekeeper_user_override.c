/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"
#include <stdio.h>

void encode_event_gatekeeper_user_override(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_gatekeeper_user_override_t *gk = msg->event.gatekeeper_user_override;
    if (!gk) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("file_type"),
        FLB_LOG_EVENT_INT32_VALUE(gk->file_type));
    if (gk->file_type == ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("file_path"),
            FLB_LOG_EVENT_STRING_VALUE(gk->file.file_path.data, gk->file.file_path.length));
    } else {
        flb_log_event_encoder_append_body_cstring(encoder, "file");
        encode_es_file_t(encoder, gk->file.file);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "sha256");
    if (gk->sha256) {
        char sha256_hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(sha256_hex + (i * 2), 3, "%02x", (*gk->sha256)[i]);
        }
        sha256_hex[64] = '\0';
        flb_log_event_encoder_append_body_cstring(encoder, sha256_hex);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "signing_info");
    if (gk->signing_info) {
        const es_signed_file_info_t *si = gk->signing_info;
        flb_log_event_encoder_body_begin_map(encoder);
        char cdhash_hex[sizeof(es_cdhash_t) * 2 + 1];
        for (size_t i = 0; i < sizeof(es_cdhash_t); i++) {
            snprintf(cdhash_hex + (i * 2), 3, "%02x", si->cdhash[i]);
        }
        cdhash_hex[sizeof(es_cdhash_t) * 2] = '\0';
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("cdhash"),
            FLB_LOG_EVENT_CSTRING_VALUE(cdhash_hex));
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("signing_id"),
            FLB_LOG_EVENT_STRING_VALUE(si->signing_id.data, si->signing_id.length));
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("team_id"),
            FLB_LOG_EVENT_STRING_VALUE(si->team_id.data, si->team_id.length));
        flb_log_event_encoder_body_commit_map(encoder);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
