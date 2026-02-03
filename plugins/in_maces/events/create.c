/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"
#include <sys/acl.h>

void encode_event_create(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_create_t *create = &msg->event.create;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("destination_type"),
        FLB_LOG_EVENT_INT32_VALUE(create->destination_type));
    if (msg->version >= 2 && create->acl) {
        ssize_t acl_buf_size = acl_size(create->acl);
        if (acl_buf_size > 0) {
            char *buf = flb_malloc(acl_buf_size);
            if (buf && acl_copy_ext(buf, create->acl, acl_buf_size) != -1) {
                acl_t acl = acl_copy_int(buf);
                if (acl) {
                    char *acl_txt = acl_to_text(acl, NULL);
                    if (acl_txt) {
                        flb_log_event_encoder_append_body_values(
                            encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                            FLB_LOG_EVENT_CSTRING_VALUE(acl_txt));
                        acl_free(acl_txt);
                    } else {
                        flb_log_event_encoder_append_body_values(
                            encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                            FLB_LOG_EVENT_NULL_VALUE());
                    }
                    acl_free(acl);
                } else {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                        FLB_LOG_EVENT_NULL_VALUE());
                }
            } else {
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                    FLB_LOG_EVENT_NULL_VALUE());
            }
            if (buf) {
                flb_free(buf);
            }
        } else {
            flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                FLB_LOG_EVENT_NULL_VALUE());
        }
    } else {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("acl"),
            FLB_LOG_EVENT_NULL_VALUE());
    }
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "destination");
    if (create->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "existing_file");
        encode_es_file_t(encoder, create->destination.existing_file);
        flb_log_event_encoder_body_commit_map(encoder);
    } else if (create->destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("filename"),
            FLB_LOG_EVENT_STRING_VALUE(create->destination.new_path.filename.data, create->destination.new_path.filename.length));
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "dir");
        encode_es_file_t(encoder, create->destination.new_path.dir);
        flb_log_event_encoder_body_commit_map(encoder);
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
