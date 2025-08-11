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
        struct flb_log_event_encoder *encoder = ctx->encoder;
        es_events_t event = msg->event;

        // encode the generic part of each message
        flb_log_event_encoder_begin_record(encoder);
        flb_log_event_encoder_set_timestamp(encoder, &((struct flb_time) { .tm = msg->time}));
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("seq_num"),
            FLB_LOG_EVENT_UINT64_VALUE(msg->seq_num));
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("version"),
            FLB_LOG_EVENT_UINT32_VALUE(msg->version));
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("event_type"),
            FLB_LOG_EVENT_UINT32_VALUE(msg->event_type));
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "event");

        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_cstring(
            encoder,
            (char *)event_type_str(msg->event_type));

        // event specific code
        switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("dyld_exec_path"),
                    FLB_LOG_EVENT_STRING_VALUE(event.exec.dyld_exec_path.data, event.exec.dyld_exec_path.length));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, event.exec.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_FORK:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "child");
                encode_es_process_t(encoder, event.fork.child);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("stat"),
                    FLB_LOG_EVENT_UINT64_VALUE(event.exit.stat));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_OPEN:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("fflag"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.open.fflag));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file");
                encode_es_file_t(encoder, event.open.file);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_CLOSE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("modified"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(event.close.modified));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("was_mapped_writable"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(event.close.was_mapped_writable));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.close.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_CREATE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
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
                            encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("acl"),
                            FLB_LOG_EVENT_CSTRING_VALUE(acl_txt));
                        acl_free(acl);
                        acl_free(acl_txt);
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
                if (event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "existing_file");
                    encode_es_file_t(encoder, event.create.destination.existing_file);
                    flb_log_event_encoder_body_commit_map(encoder);
                } else if (event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("filename"),
                        FLB_LOG_EVENT_STRING_VALUE(event.create.destination.new_path.filename.data, event.create.destination.new_path.filename.length));
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "dir");
                    encode_es_file_t(encoder, event.create.destination.new_path.dir);
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_MMAP:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("max_protection"),
                    FLB_LOG_EVENT_INT32_VALUE(event.mmap.max_protection));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protection"),
                    FLB_LOG_EVENT_INT32_VALUE(event.mmap.protection));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("flags"),
                    FLB_LOG_EVENT_INT32_VALUE(event.mmap.flags));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("file_pos"),
                    FLB_LOG_EVENT_UINT64_VALUE(event.mmap.file_pos));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.mmap.source);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_MPROTECT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protection"),
                    FLB_LOG_EVENT_INT32_VALUE(event.mprotect.protection));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("address"),
                    FLB_LOG_EVENT_UINT64_VALUE(event.mprotect.address));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("size"),
                    FLB_LOG_EVENT_UINT64_VALUE(event.mprotect.size));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "dir");
                encode_es_file_t(encoder, event.uipc_bind.dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("filename"),
                    FLB_LOG_EVENT_STRING_VALUE(event.uipc_bind.filename.data, event.uipc_bind.filename.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("mode"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.uipc_bind.mode));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file");
                encode_es_file_t(encoder, event.uipc_connect.file);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("domain"),
                    FLB_LOG_EVENT_INT32_VALUE(event.uipc_connect.domain));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_INT32_VALUE(event.uipc_connect.type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protocol"),
                    FLB_LOG_EVENT_INT32_VALUE(event.uipc_connect.protocol));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_ACCESS:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("mode"),
                    FLB_LOG_EVENT_INT32_VALUE(event.access.mode));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.access.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_RENAME:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.rename.source);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("destination_type"),
                    FLB_LOG_EVENT_INT32_VALUE(event.rename.destination_type));
                if (event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "existing_file");
                    encode_es_file_t(encoder, event.rename.destination.existing_file);
                } else if (event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "new_path");
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("filename"),
                        FLB_LOG_EVENT_STRING_VALUE(event.rename.destination.new_path.filename.data, event.rename.destination.new_path.filename.length));
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "dir");
                    encode_es_file_t(encoder, event.rename.destination.new_path.dir);
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_UNLINK:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.unlink.target);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "parent_dir");
                encode_es_file_t(encoder, event.unlink.parent_dir);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_CHDIR:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.chdir.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_LINK:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.link.source);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_dir");
                encode_es_file_t(encoder, event.link.target_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("target_filename"),
                    FLB_LOG_EVENT_STRING_VALUE(event.link.target_filename.data, event.link.target_filename.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SIGNAL:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("sig"),
                    FLB_LOG_EVENT_INT32_VALUE(event.signal.sig));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, event.signal.target);
                if (event.signal.instigator) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator");
                  encode_es_process_t(encoder, event.signal.instigator);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.listextattr.target);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.setextattr.target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("extattr"),
                    FLB_LOG_EVENT_STRING_VALUE(event.setextattr.extattr.data, event.setextattr.extattr.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.getextattr.target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("extattr"),
                    FLB_LOG_EVENT_STRING_VALUE(event.getextattr.extattr.data, event.getextattr.extattr.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.deleteextattr.target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("extattr"),
                    FLB_LOG_EVENT_STRING_VALUE(event.deleteextattr.extattr.data, event.deleteextattr.extattr.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("flags"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setflags.flags));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.setflags.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file1");
                encode_es_file_t(encoder, event.exchangedata.file1);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file2");
                encode_es_file_t(encoder, event.exchangedata.file2);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_WRITE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.write.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.truncate.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_STAT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.stat.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_CHROOT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.chroot.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_client_type"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.iokit_open.user_client_type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_client_class"),
                    FLB_LOG_EVENT_STRING_VALUE(event.iokit_open.user_client_class.data, event.iokit_open.user_client_class.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_READLINK:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.readlink.source);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_LOOKUP:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source_dir");
                encode_es_file_t(encoder, event.lookup.source_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("relative_target"),
                    FLB_LOG_EVENT_STRING_VALUE(event.lookup.relative_target.data, event.lookup.relative_target.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_CLONE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.clone.source);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_dir");
                encode_es_file_t(encoder, event.clone.target_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("target_name"),
                    FLB_LOG_EVENT_STRING_VALUE(event.clone.target_name.data, event.clone.target_name.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_COPYFILE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.copyfile.source);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_file");
                encode_es_file_t(encoder, event.copyfile.target_file);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_dir");
                encode_es_file_t(encoder, event.copyfile.target_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("target_name"),
                    FLB_LOG_EVENT_STRING_VALUE(event.copyfile.target_name.data, event.copyfile.target_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("mode"),
                    FLB_LOG_EVENT_INT32_VALUE(event.copyfile.mode));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("flags"),
                    FLB_LOG_EVENT_INT32_VALUE(event.copyfile.flags));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_FCNTL:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.fcntl.target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("cmd"),
                    FLB_LOG_EVENT_INT32_VALUE(event.fcntl.cmd));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_READDIR:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.readdir.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.fsgetpath.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(event.kextload.identifier.data, event.kextload.identifier.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(event.kextunload.identifier.data, event.kextunload.identifier.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            default:
                flb_log_event_encoder_append_body_null(encoder);
                break;
        }

        flb_log_event_encoder_body_commit_map(encoder);

        flb_log_event_encoder_append_body_cstring(
            encoder,
            "process");
        encode_es_process_t(encoder, msg->process);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("global_seq_num"),
            FLB_LOG_EVENT_UINT64_VALUE(msg->global_seq_num));
        flb_log_event_encoder_append_body_cstring(
            encoder,
            "thread");
        flb_log_event_encoder_body_begin_map(encoder);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("thread_id"),
            FLB_LOG_EVENT_UINT64_VALUE(msg->thread->thread_id));
        flb_log_event_encoder_body_commit_map(encoder);
        flb_log_event_encoder_commit_record(encoder);
        flb_input_log_append(ins, NULL, 0,
            encoder->output_buffer,
            encoder->output_length);
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
    .name        = "maces",
    .description = "MacOS Endpoint Security input plugin",
    .cb_init     = in_maces_init,
};
