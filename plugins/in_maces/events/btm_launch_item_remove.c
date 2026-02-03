/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"

void encode_event_btm_launch_item_remove(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_btm_launch_item_remove_t *btm_launch_item_remove = msg->event.btm_launch_item_remove;
    if (btm_launch_item_remove == NULL) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_body_commit_map(encoder);
        return;
    }
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (btm_launch_item_remove->instigator != NULL) {
        encode_es_process_t(encoder, btm_launch_item_remove->instigator);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    flb_log_event_encoder_append_body_cstring(encoder, "app");
    if (btm_launch_item_remove->app != NULL) {
        encode_es_process_t(encoder, btm_launch_item_remove->app);
    } else {
        flb_log_event_encoder_append_body_null(encoder);
    }
    encode_btm_launch_item_t(encoder, btm_launch_item_remove->item);
    if (msg->version >= 8) {
        flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
        if (btm_launch_item_remove->instigator_token != NULL) {
            encode_audit_token_t(encoder, btm_launch_item_remove->instigator_token);
        } else {
            flb_log_event_encoder_append_body_null(encoder);
        }
        flb_log_event_encoder_append_body_cstring(encoder, "app_token");
        if (btm_launch_item_remove->app_token != NULL) {
            encode_audit_token_t(encoder, btm_launch_item_remove->app_token);
        } else {
            flb_log_event_encoder_append_body_null(encoder);
        }
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
