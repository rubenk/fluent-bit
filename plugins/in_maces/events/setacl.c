/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../maces_encoders.h"
#include "../maces_event_handlers.h"
#include <sys/acl.h>

void encode_event_setacl(struct flb_log_event_encoder *encoder, const es_message_t *msg) {
    const es_event_setacl_t *setacl = &msg->event.setacl;
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_cstring(encoder, "target");
    encode_es_file_t(encoder, setacl->target);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("set_or_clear"),
        FLB_LOG_EVENT_INT32_VALUE(setacl->set_or_clear));
    if (setacl->set_or_clear == ES_SET) {
        ssize_t acl_buf_size = acl_size(setacl->acl.set);
        if (acl_buf_size > 0) {
            char *acl_buf = flb_malloc(acl_buf_size);
            if (acl_buf) {
                if (acl_copy_ext(acl_buf, setacl->acl.set, acl_buf_size) != -1) {
                    acl_t acl_copy = acl_copy_int(acl_buf);
                    if (acl_copy) {
                        char *acl_text = acl_to_text(acl_copy, NULL);
                        if (acl_text) {
                            flb_log_event_encoder_append_body_values(
                                encoder,
                                FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                                FLB_LOG_EVENT_CSTRING_VALUE(acl_text));
                            acl_free(acl_text);
                        }
                        acl_free(acl_copy);
                    }
                }
                flb_free(acl_buf);
            }
        }
    }
    flb_log_event_encoder_body_commit_map(encoder);
}
