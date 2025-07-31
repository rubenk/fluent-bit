/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <sys/types.h>
#include <sys/acl.h>

#include "events.h"

struct flb_maces_config {
    es_client_t *client;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *encoder;
};

static int encode_audit_token_t(struct flb_log_event_encoder *encoder, const audit_token_t *token) {
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("auid"),
                    FLB_LOG_EVENT_UINT64_VALUE(audit_token_to_auid(*token)));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("pidversion"),
                    FLB_LOG_EVENT_INT64_VALUE(audit_token_to_pidversion(*token)));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("euid"),
                    FLB_LOG_EVENT_UINT64_VALUE(audit_token_to_euid(*token)));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("rgid"),
                    FLB_LOG_EVENT_UINT64_VALUE(audit_token_to_rgid(*token)));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("egid"),
                    FLB_LOG_EVENT_UINT64_VALUE(audit_token_to_egid(*token)));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("ruid"),
                    FLB_LOG_EVENT_UINT64_VALUE(audit_token_to_ruid(*token)));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("asid"),
                    FLB_LOG_EVENT_UINT64_VALUE(audit_token_to_asid(*token)));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("pid"),
                    FLB_LOG_EVENT_UINT64_VALUE(audit_token_to_pid(*token)));
    flb_log_event_encoder_body_commit_map(encoder);

    return 0;
}

static int encode_es_file_t(struct flb_log_event_encoder *encoder, const es_file_t *file) {
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("path"),
                    FLB_LOG_EVENT_STRING_VALUE(file->path.data, file->path.length));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("path_truncated"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(file->path_truncated));
    flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "stat");
    flb_log_event_encoder_body_begin_map(encoder);
    struct stat stat = file->stat;
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_blocks"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_blocks));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_uid"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_uid));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_rdev"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_rdev));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_dev"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_dev));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_nlink"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_nlink));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_size"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_size));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_ino"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_ino));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_gid"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_gid));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_mode"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_mode));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_blksize"),
                    FLB_LOG_EVENT_UINT64_VALUE(stat.st_blksize));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_flags"),
                    FLB_LOG_EVENT_UINT32_VALUE(stat.st_flags));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("st_gen"),
                    FLB_LOG_EVENT_UINT32_VALUE(stat.st_gen));
    flb_log_event_encoder_body_commit_map(encoder);
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

static int encode_es_process_t(struct flb_log_event_encoder *encoder, const es_process_t *process) {
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("ppid"),
                    FLB_LOG_EVENT_UINT64_VALUE(process->ppid));
    flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "audit_token");
    encode_audit_token_t(encoder, &process->audit_token);
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("group_id"),
                    FLB_LOG_EVENT_UINT64_VALUE(process->group_id));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("original_ppid"),
                    FLB_LOG_EVENT_UINT64_VALUE(process->original_ppid));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("codesigning_flags"),
                    FLB_LOG_EVENT_UINT32_VALUE(process->codesigning_flags));
    if (process->executable) {
        flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "executable");
        encode_es_file_t(encoder, process->executable);
    }
    if (process->team_id.length > 0) {
        flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("team_id"),
                        FLB_LOG_EVENT_STRING_VALUE(process->team_id.data, process->team_id.length));
    } else {
        flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("team_id"),
                        FLB_LOG_EVENT_NULL_VALUE());
    }
    flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "parent_audit_token");
    encode_audit_token_t(encoder, &process->parent_audit_token);

    if (process->tty) {
        flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "tty");
        encode_es_file_t(encoder, process->tty);
    }
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("signing_id"),
                    FLB_LOG_EVENT_STRING_VALUE(process->signing_id.data, process->signing_id.length));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("is_es_client"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(process->is_es_client));
    flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "responsible_audit_token");
    encode_audit_token_t(encoder, &process->responsible_audit_token);

    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("is_platform_binary"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(process->is_platform_binary));
    flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("session_id"),
                    FLB_LOG_EVENT_UINT64_VALUE(process->session_id));
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

static int in_maces_init(struct flb_input_instance *ins, struct flb_config *config, void *data) {
    struct flb_maces_config *ctx = flb_calloc(1, sizeof(struct flb_maces_config));
    if (!ctx) {
      flb_errno();
      return -1;
    }

    ctx->encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->encoder == NULL) {
        flb_plg_error(ins, "could not initialize event encoder");
        flb_free(ctx);
        return -1;
    }

    ctx->ins = ins;

    flb_input_set_context(ins, ctx);

    // This block is called by Endpoint Security for each event
    es_handler_block_t handler = ^(es_client_t *c, const es_message_t *msg ) {
        flb_log_event_encoder_begin_record(ctx->encoder);
        es_events_t event = msg->event;
        flb_log_event_encoder_set_timestamp(ctx->encoder, &((struct flb_time) { .tm = msg->time}));
        flb_log_event_encoder_append_body_values(
                        ctx->encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("seq_num"),
                        FLB_LOG_EVENT_UINT64_VALUE(msg->seq_num));
        flb_log_event_encoder_append_body_values(
                        ctx->encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("version"),
                        FLB_LOG_EVENT_UINT32_VALUE(msg->version));
        flb_log_event_encoder_append_body_values(
                        ctx->encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("event_type"),
                        FLB_LOG_EVENT_UINT32_VALUE(msg->event_type));
        flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    "event");
        // event specific code
        flb_log_event_encoder_body_begin_map(ctx->encoder);
        flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    (char *)event_type_str(msg->event_type));
        switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_values(
                            ctx->encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("dyld_exec_path"),
                            FLB_LOG_EVENT_STRING_VALUE(event.exec.dyld_exec_path.data, event.exec.dyld_exec_path.length));
                flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    "target");
                encode_es_process_t(ctx->encoder, event.exec.target);
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_FORK:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_cstring(
                            ctx->encoder,
                            "child");
                encode_es_process_t(ctx->encoder, event.fork.child);
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_values(
                            ctx->encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("stat"),
                            FLB_LOG_EVENT_UINT64_VALUE(event.exit.stat));
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_OPEN:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_values(
                            ctx->encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("fflag"),
                   FLB_LOG_EVENT_UINT32_VALUE(event.open.fflag));
                flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    "file");
                encode_es_file_t(ctx->encoder, event.open.file);
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_CLOSE:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("modified"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(event.close.modified));
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("was_mapped_writable"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(event.close.was_mapped_writable));
                flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    "target");
                encode_es_file_t(ctx->encoder, event.close.target);
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_CREATE:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("destination_type"),
                    FLB_LOG_EVENT_INT32_VALUE(event.create.destination_type));
                if (msg->version >= 2 && event.create.acl) {
                    // as the comment in ESMessage.h says, the acl in the message
                    // is not a complete type. We need to convert it to an external representation first,
                    // and back again

                    // TODO: this needs error handling and proper sizing of the buffer
                    char buf[1024];
                    acl_copy_ext(buf, event.create.acl, 1024);
                    acl_t acl = acl_copy_int(buf);
                    char *acl_txt = acl_to_text(acl, NULL);
                    if (acl_txt == NULL) {
                        flb_errno();
                    } else {
                        flb_log_event_encoder_append_body_values(
                            ctx->encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                            FLB_LOG_EVENT_CSTRING_VALUE(acl_txt));
                        acl_free(acl);
                        acl_free(acl_txt);
                    }
                } else {
                    flb_log_event_encoder_append_body_values(
                        ctx->encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                        FLB_LOG_EVENT_NULL_VALUE());
                }
                flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    "destination");
                if (event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                    flb_log_event_encoder_body_begin_map(ctx->encoder);
                    flb_log_event_encoder_append_body_cstring(
                        ctx->encoder,
                        "existing_file");
                    encode_es_file_t(ctx->encoder, event.open.file);
                    flb_log_event_encoder_body_commit_map(ctx->encoder);
                } else if (event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
                    flb_log_event_encoder_body_begin_map(ctx->encoder);
                    flb_log_event_encoder_append_body_values(
                        ctx->encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("filename"),
                        FLB_LOG_EVENT_STRING_VALUE(event.create.destination.new_path.filename.data, event.create.destination.new_path.filename.length));
                    flb_log_event_encoder_append_body_cstring(
                        ctx->encoder,
                        "dir");
                    encode_es_file_t(ctx->encoder, event.create.destination.new_path.dir);
                    flb_log_event_encoder_body_commit_map(ctx->encoder);
                }
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_MMAP:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("max_protection"),
                    FLB_LOG_EVENT_INT32_VALUE(event.mmap.max_protection));
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protection"),
                    FLB_LOG_EVENT_INT32_VALUE(event.mmap.protection));
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("file_pos"),
                    FLB_LOG_EVENT_UINT64_VALUE(event.mmap.file_pos));
                flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    "source");
                encode_es_file_t(ctx->encoder, event.mmap.source);
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_MPROTECT:
                flb_log_event_encoder_body_begin_map(ctx->encoder);
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protection"),
                    FLB_LOG_EVENT_INT32_VALUE(event.mprotect.protection));
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("address"),
                    FLB_LOG_EVENT_UINT64_VALUE(event.mprotect.address));
                flb_log_event_encoder_append_body_values(
                    ctx->encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("size"),
                    FLB_LOG_EVENT_UINT64_VALUE(event.mprotect.size));
                flb_log_event_encoder_body_commit_map(ctx->encoder);
                break;
            default:
                flb_log_event_encoder_append_body_null(ctx->encoder);
                break;
        }

        flb_log_event_encoder_body_commit_map(ctx->encoder);

        flb_log_event_encoder_append_body_cstring(
            ctx->encoder,
            "process");
        encode_es_process_t(ctx->encoder, msg->process);
        flb_log_event_encoder_append_body_values(
                        ctx->encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("global_seq_num"),
                        FLB_LOG_EVENT_UINT64_VALUE(msg->global_seq_num));
        flb_log_event_encoder_append_body_cstring(
                    ctx->encoder,
                    "thread");
        flb_log_event_encoder_body_begin_map(ctx->encoder);
        flb_log_event_encoder_append_body_values(
                        ctx->encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("thread_id"),
                        FLB_LOG_EVENT_UINT64_VALUE(msg->thread->thread_id));
        flb_log_event_encoder_body_commit_map(ctx->encoder);
        flb_log_event_encoder_commit_record(ctx->encoder);
        flb_input_log_append(ins, NULL, 0,
                                 ctx->encoder->output_buffer,
                                 ctx->encoder->output_length);
    };

    es_new_client_result_t res = es_new_client(&ctx->client, handler);

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        switch(res) {
          case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            flb_plg_error(ins, "Application requires 'com.apple.developer.endpoint-security.client' entitlement");
            break;
          case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            flb_plg_error(ins, "Application lacks 'Transparency, Consent, and Control (TCC)' approval");
            break;
          case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            flb_plg_error(ins, "Application needs to run as root");
            break;
          default:
            flb_plg_error(ins, "Unknown error");
            break;
          // TODO: handle all documented errors in the enum
        }
        flb_free(ctx);
        return -1;
    }

    flb_plg_info(ins, "Endpoint Security Client initialized successfully");
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT};
    es_return_t subscribed = es_subscribe(ctx->client, events, sizeof events / sizeof *events);
    if(subscribed != ES_RETURN_SUCCESS) {
        flb_plg_error(ins, "Error subscribing to events");
        flb_free(ctx);
        return -1;
    } else {
        flb_plg_info(ins, "Subscribed to events");
    }

    return 0;
}

/* Plugin registration */
struct flb_input_plugin in_maces_plugin = {
    .name         = "maces",
    .description  = "MacOS Endpoint Security input plugin",
    .cb_init      = in_maces_init,
};
