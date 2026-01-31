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
#include <uuid/uuid.h>
#include <pthread.h>
#include <Block.h>

#include "in_maces.h"
#include "maces_encoders.h"
#include "maces_events.h"
#include "events.h"

es_handler_block_t maces_create_event_handler(struct flb_maces_config *ctx) {
    struct flb_input_instance *ins = ctx->ins;

    es_handler_block_t handler = ^(es_client_t *c, const es_message_t *msg ) {
        int ret;
        pthread_mutex_lock(&ctx->encoder_mutex);
        struct flb_log_event_encoder *encoder = ctx->encoder;
        es_events_t event = msg->event;

        // encode the generic part of each message
        ret = flb_log_event_encoder_begin_record(encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(encoder, &((struct flb_time) { .tm = msg->time}));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("seq_num"),
                FLB_LOG_EVENT_UINT64_VALUE(msg->seq_num));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("version"),
                FLB_LOG_EVENT_UINT32_VALUE(msg->version));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("event_type"),
                FLB_LOG_EVENT_UINT32_VALUE(msg->event_type));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(
                encoder,
                "event");
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_body_begin_map(encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(
                encoder,
                (char *)event_type_str(msg->event_type));
        }

        // event specific code
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_EXEC: {
                es_event_exec_t *exec = &event.exec;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("dyld_exec_path"),
                    FLB_LOG_EVENT_STRING_VALUE(exec->dyld_exec_path.data, exec->dyld_exec_path.length));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, exec->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_FORK: {
                es_event_fork_t *fork = &event.fork;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "child");
                encode_es_process_t(encoder, fork->child);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_EXIT: {
                es_event_exit_t *exit = &event.exit;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("stat"),
                    FLB_LOG_EVENT_UINT64_VALUE(exit->stat));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OPEN: {
                es_event_open_t *open = &event.open;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("fflag"),
                    FLB_LOG_EVENT_UINT32_VALUE(open->fflag));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file");
                encode_es_file_t(encoder, open->file);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CLOSE: {
                es_event_close_t *close = &event.close;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("modified"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(close->modified));
                if (msg->version >= 6) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("was_mapped_writable"),
                      FLB_LOG_EVENT_BOOLEAN_VALUE(close->was_mapped_writable));
                }
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, close->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CREATE: {
                es_event_create_t *create = &event.create;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("destination_type"),
                    FLB_LOG_EVENT_INT32_VALUE(create->destination_type));
                if (msg->version >= 2 && create->acl) {
                    // as the comment in ESMessage.h says, the acl in the message
                    // is not a complete type. We need to convert it to an external representation first,
                    // and back again
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
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_TRACE: {
                es_event_trace_t *trace = &event.trace;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, trace->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_MMAP: {
                es_event_mmap_t *mmap = &event.mmap;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("max_protection"),
                    FLB_LOG_EVENT_INT32_VALUE(mmap->max_protection));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protection"),
                    FLB_LOG_EVENT_INT32_VALUE(mmap->protection));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("flags"),
                    FLB_LOG_EVENT_INT32_VALUE(mmap->flags));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("file_pos"),
                    FLB_LOG_EVENT_UINT64_VALUE(mmap->file_pos));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, mmap->source);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_MPROTECT: {
                es_event_mprotect_t *mprotect = &event.mprotect;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protection"),
                    FLB_LOG_EVENT_INT32_VALUE(mprotect->protection));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("address"),
                    FLB_LOG_EVENT_UINT64_VALUE(mprotect->address));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("size"),
                    FLB_LOG_EVENT_UINT64_VALUE(mprotect->size));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: {
                es_event_uipc_bind_t *uipc_bind = &event.uipc_bind;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "dir");
                encode_es_file_t(encoder, uipc_bind->dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("filename"),
                    FLB_LOG_EVENT_STRING_VALUE(uipc_bind->filename.data, uipc_bind->filename.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("mode"),
                    FLB_LOG_EVENT_UINT32_VALUE(uipc_bind->mode));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
                es_event_uipc_connect_t *uipc_connect = &event.uipc_connect;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file");
                encode_es_file_t(encoder, uipc_connect->file);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("domain"),
                    FLB_LOG_EVENT_INT32_VALUE(uipc_connect->domain));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_INT32_VALUE(uipc_connect->type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("protocol"),
                    FLB_LOG_EVENT_INT32_VALUE(uipc_connect->protocol));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_ACCESS: {
                es_event_access_t *access = &event.access;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("mode"),
                    FLB_LOG_EVENT_INT32_VALUE(access->mode));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, access->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_RENAME: {
                es_event_rename_t *rename = &event.rename;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, rename->source);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("destination_type"),
                    FLB_LOG_EVENT_INT32_VALUE(rename->destination_type));
                if (rename->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "existing_file");
                    encode_es_file_t(encoder, rename->destination.existing_file);
                } else if (rename->destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "new_path");
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("filename"),
                        FLB_LOG_EVENT_STRING_VALUE(rename->destination.new_path.filename.data, rename->destination.new_path.filename.length));
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "dir");
                    encode_es_file_t(encoder, rename->destination.new_path.dir);
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_UNLINK: {
                es_event_unlink_t *unlink = &event.unlink;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, unlink->target);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "parent_dir");
                encode_es_file_t(encoder, unlink->parent_dir);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CHDIR: {
                es_event_chdir_t *chdir = &event.chdir;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, chdir->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_LINK: {
                es_event_link_t *link = &event.link;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, link->source);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_dir");
                encode_es_file_t(encoder, link->target_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("target_filename"),
                    FLB_LOG_EVENT_STRING_VALUE(link->target_filename.data, link->target_filename.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_SIGNAL: {
                es_event_signal_t *signal = &event.signal;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("sig"),
                    FLB_LOG_EVENT_INT32_VALUE(signal->sig));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, signal->target);
                flb_log_event_encoder_append_body_cstring(encoder, "instigator");
                if (signal->instigator != NULL) {
                    encode_es_process_t(encoder, signal->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR: {
                es_event_listextattr_t *listextattr = &event.listextattr;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, listextattr->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: {
                es_event_setextattr_t *setextattr = &event.setextattr;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, setextattr->target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("extattr"),
                    FLB_LOG_EVENT_STRING_VALUE(setextattr->extattr.data, setextattr->extattr.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_GETEXTATTR: {
                es_event_getextattr_t *getextattr = &event.getextattr;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, getextattr->target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("extattr"),
                    FLB_LOG_EVENT_STRING_VALUE(getextattr->extattr.data, getextattr->extattr.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR: {
                es_event_deleteextattr_t *deleteextattr = &event.deleteextattr;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, deleteextattr->target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("extattr"),
                    FLB_LOG_EVENT_STRING_VALUE(deleteextattr->extattr.data, deleteextattr->extattr.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_SETFLAGS: {
                es_event_setflags_t *setflags = &event.setflags;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("flags"),
                    FLB_LOG_EVENT_UINT32_VALUE(setflags->flags));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, setflags->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: {
                es_event_exchangedata_t *exchangedata = &event.exchangedata;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file1");
                encode_es_file_t(encoder, exchangedata->file1);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "file2");
                encode_es_file_t(encoder, exchangedata->file2);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_WRITE: {
                es_event_write_t *write = &event.write;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, write->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_TRUNCATE: {
                es_event_truncate_t *truncate = &event.truncate;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, truncate->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_STAT: {
                es_event_stat_t *stat = &event.stat;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, stat->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CHROOT: {
                es_event_chroot_t *chroot = &event.chroot;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, chroot->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: {
                es_event_iokit_open_t *iokit_open = &event.iokit_open;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_client_type"),
                    FLB_LOG_EVENT_UINT32_VALUE(iokit_open->user_client_type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_client_class"),
                    FLB_LOG_EVENT_STRING_VALUE(iokit_open->user_client_class.data, iokit_open->user_client_class.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_READLINK: {
                es_event_readlink_t *readlink = &event.readlink;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, readlink->source);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_LOOKUP: {
                es_event_lookup_t *lookup = &event.lookup;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source_dir");
                encode_es_file_t(encoder, lookup->source_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("relative_target"),
                    FLB_LOG_EVENT_STRING_VALUE(lookup->relative_target.data, lookup->relative_target.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CLONE: {
                es_event_clone_t *clone = &event.clone;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, clone->source);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_dir");
                encode_es_file_t(encoder, clone->target_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("target_name"),
                    FLB_LOG_EVENT_STRING_VALUE(clone->target_name.data, clone->target_name.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_COPYFILE: {
                es_event_copyfile_t *copyfile = &event.copyfile;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, copyfile->source);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_file");
                encode_es_file_t(encoder, copyfile->target_file);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target_dir");
                encode_es_file_t(encoder, copyfile->target_dir);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("target_name"),
                    FLB_LOG_EVENT_STRING_VALUE(copyfile->target_name.data, copyfile->target_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("mode"),
                    FLB_LOG_EVENT_INT32_VALUE(copyfile->mode));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("flags"),
                    FLB_LOG_EVENT_INT32_VALUE(copyfile->flags));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_FCNTL: {
                es_event_fcntl_t *fcntl = &event.fcntl;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, fcntl->target);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("cmd"),
                    FLB_LOG_EVENT_INT32_VALUE(fcntl->cmd));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_READDIR: {
                es_event_readdir_t *readdir = &event.readdir;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, readdir->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_FSGETPATH: {
                es_event_fsgetpath_t *fsgetpath = &event.fsgetpath;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, fsgetpath->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: {
                es_event_kextload_t *kextload = &event.kextload;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(kextload->identifier.data, kextload->identifier.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD: {
                es_event_kextunload_t *kextunload = &event.kextunload;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(kextunload->identifier.data, kextunload->identifier.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_SETMODE: {
                es_event_setmode_t *setmode = &event.setmode;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("mode"),
                    FLB_LOG_EVENT_INT32_VALUE(setmode->mode));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, setmode->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_SETOWNER: {
                es_event_setowner_t *setowner = &event.setowner;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("uid"),
                    FLB_LOG_EVENT_UINT32_VALUE(setowner->uid));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("gid"),
                    FLB_LOG_EVENT_UINT32_VALUE(setowner->gid));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, setowner->target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_GET_TASK:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, event.get_task.target);
                if (msg->version >= 5) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("type"),
                      FLB_LOG_EVENT_INT32_VALUE(event.get_task.type));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, event.get_task_read.target);
                if (msg->version >= 5) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.get_task_read.type));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, event.get_task_inspect.target);
                if (msg->version >= 5) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.get_task_inspect.type));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_process_t(encoder, event.get_task_name.target);
                if (msg->version >= 5) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.get_task_name.type));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.file_provider_update.source);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("target_path"),
                    FLB_LOG_EVENT_STRING_VALUE(event.file_provider_update.target_path.data, event.file_provider_update.target_path.length));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(encoder, "instigator");
                if (event.file_provider_materialize.instigator) {
                    encode_es_process_t(encoder, event.file_provider_materialize.instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "source");
                encode_es_file_t(encoder, event.file_provider_materialize.source);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.file_provider_materialize.target);
                if (msg->version >= 8) {
                    encode_audit_token_t(encoder, &event.file_provider_materialize.instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_DUP:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.dup.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_MOUNT:
                flb_log_event_encoder_body_begin_map(encoder);
                if (msg->version >= 8) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("disposition"),
                        FLB_LOG_EVENT_INT32_VALUE(event.mount.disposition));
                }
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "statfs");
                encode_statfs(encoder, event.mount.statfs);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "statfs");
                encode_statfs(encoder, event.unmount.statfs);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_REMOUNT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "statfs");
                encode_statfs(encoder, event.remount.statfs);
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("remount_flags"),
                      FLB_LOG_EVENT_UINT64_VALUE(event.remount.remount_flags));
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("disposition"),
                      FLB_LOG_EVENT_INT32_VALUE(event.remount.disposition));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "attrlist");
                encode_attrlist(encoder, &event.getattrlist.attrlist);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.getattrlist.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "attrlist");
                encode_attrlist(encoder, &event.setattrlist.attrlist);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.setattrlist.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "attrlist");
                encode_attrlist(encoder, &event.searchfs.attrlist);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.searchfs.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_UTIMES:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(encoder, "atime");
                encode_timespec(encoder, &event.utimes.atime);
                flb_log_event_encoder_append_body_cstring(encoder, "mtime");
                encode_timespec(encoder, &event.utimes.mtime);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "target");
                encode_es_file_t(encoder, event.utimes.target);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
                if (event.lw_session_login) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.lw_session_login->username.data, event.lw_session_login->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.lw_session_login->graphical_session_id));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
                if (event.lw_session_logout) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.lw_session_logout->username.data, event.lw_session_logout->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.lw_session_logout->graphical_session_id));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
                if (event.lw_session_lock) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.lw_session_lock->username.data, event.lw_session_lock->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.lw_session_lock->graphical_session_id));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
                if (event.lw_session_unlock) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.lw_session_unlock->username.data, event.lw_session_unlock->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.lw_session_unlock->graphical_session_id));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
                if (event.screensharing_attach) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("success"),
                        FLB_LOG_EVENT_BOOLEAN_VALUE(event.screensharing_attach->success));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.screensharing_attach->source_address_type));
                    if (event.screensharing_attach->source_address.length > 0) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
                          FLB_LOG_EVENT_STRING_VALUE(event.screensharing_attach->source_address.data, event.screensharing_attach->source_address.length));
                    }
                    if (event.screensharing_attach->viewer_appleid.length > 0) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("viewer_appleid"),
                          FLB_LOG_EVENT_STRING_VALUE(event.screensharing_attach->viewer_appleid.data, event.screensharing_attach->viewer_appleid.length));
                    }
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("authentication_type"),
                        FLB_LOG_EVENT_STRING_VALUE(event.screensharing_attach->authentication_type.data, event.screensharing_attach->authentication_type.length));
                    if (event.screensharing_attach->authentication_username.length > 0) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("authentication_username"),
                          FLB_LOG_EVENT_STRING_VALUE(event.screensharing_attach->authentication_username.data, event.screensharing_attach->authentication_username.length));
                    }
                    if (event.screensharing_attach->session_username.length > 0) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("session_username"),
                          FLB_LOG_EVENT_STRING_VALUE(event.screensharing_attach->session_username.data, event.screensharing_attach->session_username.length));
                    }
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("existing_session"),
                        FLB_LOG_EVENT_BOOLEAN_VALUE(event.screensharing_attach->existing_session));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.screensharing_attach->graphical_session_id));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
                if (event.screensharing_detach) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.screensharing_detach->source_address_type));
                    if (event.screensharing_detach->source_address.length > 0) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
                          FLB_LOG_EVENT_STRING_VALUE(event.screensharing_detach->source_address.data, event.screensharing_detach->source_address.length));
                    }
                    if (event.screensharing_detach->viewer_appleid.length > 0) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("viewer_appleid"),
                          FLB_LOG_EVENT_STRING_VALUE(event.screensharing_detach->viewer_appleid.data, event.screensharing_detach->viewer_appleid.length));
                    }
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("graphical_session_id"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.screensharing_detach->graphical_session_id));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
                if (event.openssh_login) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("success"),
                        FLB_LOG_EVENT_BOOLEAN_VALUE(event.openssh_login->success));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("result_type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.openssh_login->result_type));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.openssh_login->source_address_type));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
                        FLB_LOG_EVENT_STRING_VALUE(event.openssh_login->source_address.data, event.openssh_login->source_address.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.openssh_login->username.data, event.openssh_login->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("has_uid"),
                        FLB_LOG_EVENT_BOOLEAN_VALUE(event.openssh_login->has_uid));
                    if (event.openssh_login->has_uid) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("uid"),
                          FLB_LOG_EVENT_UINT32_VALUE(event.openssh_login->uid.uid));
                    }
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
                if (event.openssh_logout) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("source_address_type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.openssh_logout->source_address_type));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("source_address"),
                        FLB_LOG_EVENT_STRING_VALUE(event.openssh_logout->source_address.data, event.openssh_logout->source_address.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.openssh_logout->username.data, event.openssh_logout->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("uid"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.openssh_logout->uid));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
                if (event.login_login) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("success"),
                        FLB_LOG_EVENT_BOOLEAN_VALUE(event.login_login->success));
                    if (event.login_login->failure_message.length > 0) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("failure_message"),
                          FLB_LOG_EVENT_STRING_VALUE(event.login_login->failure_message.data, event.login_login->failure_message.length));
                    }
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.login_login->username.data, event.login_login->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("has_uid"),
                        FLB_LOG_EVENT_BOOLEAN_VALUE(event.login_login->has_uid));
                    if (event.login_login->has_uid) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("uid"),
                          FLB_LOG_EVENT_UINT32_VALUE(event.login_login->uid.uid));
                    }
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
                if (event.login_logout) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.login_logout->username.data, event.login_logout->username.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("uid"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.login_logout->uid));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
                if (event.xpc_connect) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("service_name"),
                        FLB_LOG_EVENT_STRING_VALUE(event.xpc_connect->service_name.data, event.xpc_connect->service_name.length));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("service_domain_type"),
                        FLB_LOG_EVENT_INT32_VALUE(event.xpc_connect->service_domain_type));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("dev_major"),
                    FLB_LOG_EVENT_INT32_VALUE(major(event.pty_grant.dev)),
                    FLB_LOG_EVENT_CSTRING_VALUE("dev_minor"),
                    FLB_LOG_EVENT_INT32_VALUE(minor(event.pty_grant.dev)));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("dev_major"),
                    FLB_LOG_EVENT_INT32_VALUE(major(event.pty_close.dev)),
                    FLB_LOG_EVENT_CSTRING_VALUE("dev_minor"),
                    FLB_LOG_EVENT_INT32_VALUE(minor(event.pty_close.dev)));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
                if (event.btm_launch_item_add) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
                    if (event.btm_launch_item_add->instigator) {
                        encode_es_process_t(encoder, event.btm_launch_item_add->instigator);
                    } else {
                        flb_log_event_encoder_append_body_null(encoder);
                    }
                    flb_log_event_encoder_append_body_cstring(encoder, "app");
                    if (event.btm_launch_item_add->app) {
                        encode_es_process_t(encoder, event.btm_launch_item_add->app);
                    } else {
                        flb_log_event_encoder_append_body_null(encoder);
                    }
                    encode_btm_launch_item_t(encoder, event.btm_launch_item_add->item);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("executable_path"),
                        FLB_LOG_EVENT_STRING_VALUE(event.btm_launch_item_add->executable_path.data, event.btm_launch_item_add->executable_path.length));
                    if (msg->version >= 8) {
                        flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
                        if (event.btm_launch_item_add->instigator_token) {
                            encode_audit_token_t(encoder, event.btm_launch_item_add->instigator_token);
                        } else {
                            flb_log_event_encoder_append_body_null(encoder);
                        }
                        flb_log_event_encoder_append_body_cstring(encoder, "app_token");
                        if (event.btm_launch_item_add->app_token) {
                            encode_audit_token_t(encoder, event.btm_launch_item_add->app_token);
                        } else {
                            flb_log_event_encoder_append_body_null(encoder);
                        }
                    }
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
                if (event.btm_launch_item_remove) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
                    if (event.btm_launch_item_remove->instigator) {
                        encode_es_process_t(encoder, event.btm_launch_item_remove->instigator);
                    } else {
                        flb_log_event_encoder_append_body_null(encoder);
                    }
                    flb_log_event_encoder_append_body_cstring(encoder, "app");
                    if (event.btm_launch_item_remove->app) {
                        encode_es_process_t(encoder, event.btm_launch_item_remove->app);
                    } else {
                        flb_log_event_encoder_append_body_null(encoder);
                    }
                    encode_btm_launch_item_t(encoder, event.btm_launch_item_remove->item);
                    if (msg->version >= 8) {
                        flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
                        if (event.btm_launch_item_remove->instigator_token) {
                            encode_audit_token_t(encoder, event.btm_launch_item_remove->instigator_token);
                        } else {
                            flb_log_event_encoder_append_body_null(encoder);
                        }
                        flb_log_event_encoder_append_body_cstring(encoder, "app_token");
                        if (event.btm_launch_item_remove->app_token) {
                            encode_audit_token_t(encoder, event.btm_launch_item_remove->app_token);
                        } else {
                            flb_log_event_encoder_append_body_null(encoder);
                        }
                    }
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_SETUID:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("uid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setuid.uid));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETGID:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("gid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setgid.gid));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETEUID:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("euid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.seteuid.euid));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETEGID:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("egid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setegid.egid));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETREUID:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("ruid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setreuid.ruid));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("euid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setreuid.euid));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETREGID:
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("rgid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setregid.rgid));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("egid"),
                    FLB_LOG_EVENT_UINT32_VALUE(event.setregid.egid));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SU:
                if (event.su) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("success"),
                        FLB_LOG_EVENT_BOOLEAN_VALUE(event.su->success));
                    if(!event.su->success) {
                        flb_log_event_encoder_append_body_values(
                            encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("failure_message"),
                            FLB_LOG_EVENT_STRING_VALUE(event.su->failure_message.data, event.su->failure_message.length));
                    }
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("from_uid"),
                        FLB_LOG_EVENT_UINT32_VALUE(event.su->from_uid));
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("from_username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.su->from_username.data, event.su->from_username.length));
                    if (event.su->has_to_uid) {
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("uid"),
                          FLB_LOG_EVENT_UINT32_VALUE(event.su->to_uid.uid));
                    }
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("to_username"),
                        FLB_LOG_EVENT_STRING_VALUE(event.su->to_username.data, event.su->to_username.length));
                    if(event.su->success) {
                        flb_log_event_encoder_append_body_values(
                            encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("shell"),
                            FLB_LOG_EVENT_STRING_VALUE(event.su->shell.data, event.su->shell.length));
                        flb_log_event_encoder_append_body_cstring(
                            encoder,
                            "argv");
                        flb_log_event_encoder_body_begin_array(encoder);
                        for(size_t i = 0; i < event.su->argc; i++) {
                            flb_log_event_encoder_append_body_string(
                                encoder,
                                (char *)event.su->argv[i].data,
                                event.su->argv[i].length);
                        }
                        flb_log_event_encoder_body_commit_array(encoder);
                        flb_log_event_encoder_append_body_cstring(
                            encoder,
                            "env");
                        flb_log_event_encoder_body_begin_array(encoder);
                        for(size_t i = 0; i < event.su->env_count; i++) {
                            flb_log_event_encoder_append_body_string(
                                encoder,
                                (char *)event.su->env[i].data,
                                event.su->env[i].length);
                        }
                        flb_log_event_encoder_body_commit_array(encoder);
                    }
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                break;
            case ES_EVENT_TYPE_NOTIFY_SUDO: {
                es_event_sudo_t *sudo = event.sudo;
                if (!sudo) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("success"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(sudo->success));
                if(!sudo->success) {
                    es_sudo_reject_info_t *reject_info = sudo->reject_info;
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "reject_info");
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("plugin_name"),
                        FLB_LOG_EVENT_STRING_VALUE(reject_info->plugin_name.data, reject_info->plugin_name.length));
                        flb_log_event_encoder_append_body_values(
                            encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("plugin_type"),
                            FLB_LOG_EVENT_INT32_VALUE(reject_info->plugin_type));
                        flb_log_event_encoder_append_body_values(
                            encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("failure_message"),
                            FLB_LOG_EVENT_STRING_VALUE(reject_info->failure_message.data, reject_info->failure_message.length));
                    flb_log_event_encoder_body_commit_map(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("has_from_uid"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(sudo->has_from_uid));
                if (sudo->has_from_uid) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("from_uid"),
                      FLB_LOG_EVENT_UINT32_VALUE(sudo->from_uid.uid));
                }
                if (sudo->from_username.length > 0) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("from_username"),
                      FLB_LOG_EVENT_STRING_VALUE(sudo->from_username.data, sudo->from_username.length));
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("has_to_uid"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(sudo->has_to_uid));
                if (sudo->has_to_uid) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("to_uid"),
                      FLB_LOG_EVENT_UINT32_VALUE(sudo->to_uid.uid));
                }
                if (sudo->to_username.length > 0) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("to_username"),
                      FLB_LOG_EVENT_STRING_VALUE(sudo->to_username.data, sudo->to_username.length));
                }
                if(sudo->command.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("command"),
                        FLB_LOG_EVENT_STRING_VALUE(sudo->command.data, sudo->command.length));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER: {
                es_event_od_delete_user_t *od_delete_user = event.od_delete_user;
                if (!od_delete_user) break;
                flb_log_event_encoder_body_begin_map(encoder);
                if (od_delete_user->instigator) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator");
                  encode_es_process_t(encoder, od_delete_user->instigator);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_delete_user->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_delete_user->user_name.data, od_delete_user->user_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_delete_user->node_name.data, od_delete_user->node_name.length));
                if(od_delete_user->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_delete_user->db_path.data, od_delete_user->db_path.length));
                }
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator_token");
                encode_audit_token_t(encoder, &od_delete_user->instigator_token);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER: {
                es_event_od_create_user_t *od_create_user = event.od_create_user;
                if (!od_create_user) break;
                flb_log_event_encoder_body_begin_map(encoder);
                if (od_create_user->instigator) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator");
                  encode_es_process_t(encoder, od_create_user->instigator);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_create_user->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_create_user->user_name.data, od_create_user->user_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_create_user->node_name.data, od_create_user->node_name.length));
                if(od_create_user->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_create_user->db_path.data, od_create_user->db_path.length));
                }
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator_token");
                encode_audit_token_t(encoder, &od_create_user->instigator_token);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP: {
                es_event_od_create_group_t *od_create_group = event.od_create_group;
                if (!od_create_group) break;
                flb_log_event_encoder_body_begin_map(encoder);
                if (od_create_group->instigator) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator");
                  encode_es_process_t(encoder, od_create_group->instigator);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_create_group->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("group_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_create_group->group_name.data, od_create_group->group_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_create_group->node_name.data, od_create_group->node_name.length));
                if(od_create_group->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_create_group->db_path.data, od_create_group->db_path.length));
                }
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator_token");
                encode_audit_token_t(encoder, &od_create_group->instigator_token);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP: {
                es_event_od_delete_group_t *od_delete_group = event.od_delete_group;
                if (!od_delete_group) break;
                flb_log_event_encoder_body_begin_map(encoder);
                if (od_delete_group->instigator) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator");
                  encode_es_process_t(encoder, od_delete_group->instigator);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_delete_group->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("group_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_delete_group->group_name.data, od_delete_group->group_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_delete_group->node_name.data, od_delete_group->node_name.length));
                if(od_delete_group->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_delete_group->db_path.data, od_delete_group->db_path.length));
                }
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator_token");
                encode_audit_token_t(encoder, &od_delete_group->instigator_token);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD: {
                es_event_od_modify_password_t *od_modify_password = event.od_modify_password;
                if (!od_modify_password) break;
                flb_log_event_encoder_body_begin_map(encoder);
                if (od_modify_password->instigator) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator");
                  encode_es_process_t(encoder, od_modify_password->instigator);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_modify_password->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("account_type"),
                    FLB_LOG_EVENT_INT32_VALUE(od_modify_password->account_type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("account_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_modify_password->account_name.data, od_modify_password->account_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_modify_password->node_name.data, od_modify_password->node_name.length));
                if(od_modify_password->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_modify_password->db_path.data, od_modify_password->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_modify_password->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER: {
                es_event_od_disable_user_t *od_disable_user = event.od_disable_user;
                if (!od_disable_user) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_disable_user->instigator) {
                    encode_es_process_t(encoder, od_disable_user->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_disable_user->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_disable_user->user_name.data, od_disable_user->user_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_disable_user->node_name.data, od_disable_user->node_name.length));
                if(od_disable_user->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_disable_user->db_path.data, od_disable_user->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_disable_user->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER: {
                es_event_od_enable_user_t *od_enable_user = event.od_enable_user;
                if (!od_enable_user) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_enable_user->instigator) {
                    encode_es_process_t(encoder, od_enable_user->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_enable_user->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("user_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_enable_user->user_name.data, od_enable_user->user_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_enable_user->node_name.data, od_enable_user->node_name.length));
                if(od_enable_user->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_enable_user->db_path.data, od_enable_user->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_enable_user->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD: {
                es_event_od_attribute_value_add_t *od_attribute_value_add = event.od_attribute_value_add;
                if (!od_attribute_value_add) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_attribute_value_add->instigator) {
                    encode_es_process_t(encoder, od_attribute_value_add->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_add->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
                    FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_add->record_type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->record_name.data, od_attribute_value_add->record_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("attribute_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->attribute_name.data, od_attribute_value_add->attribute_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("attribute_value"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->attribute_value.data, od_attribute_value_add->attribute_value.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->node_name.data, od_attribute_value_add->node_name.length));
                if(od_attribute_value_add->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_add->db_path.data, od_attribute_value_add->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_attribute_value_add->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE: {
                es_event_od_attribute_value_remove_t *od_attribute_value_remove = event.od_attribute_value_remove;
                if (!od_attribute_value_remove) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_attribute_value_remove->instigator) {
                    encode_es_process_t(encoder, od_attribute_value_remove->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_remove->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
                    FLB_LOG_EVENT_INT32_VALUE(od_attribute_value_remove->record_type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->record_name.data, od_attribute_value_remove->record_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("attribute_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->attribute_name.data, od_attribute_value_remove->attribute_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("attribute_value"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->attribute_value.data, od_attribute_value_remove->attribute_value.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->node_name.data, od_attribute_value_remove->node_name.length));
                if(od_attribute_value_remove->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_attribute_value_remove->db_path.data, od_attribute_value_remove->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_attribute_value_remove->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET: {
                es_event_od_attribute_set_t *od_attribute_set = event.od_attribute_set;
                if (!od_attribute_set) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_attribute_set->instigator) {
                    encode_es_process_t(encoder, od_attribute_set->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_attribute_set->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
                    FLB_LOG_EVENT_INT32_VALUE(od_attribute_set->record_type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_set->record_name.data, od_attribute_set->record_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("attribute_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_set->attribute_name.data, od_attribute_set->attribute_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("attribute_value_count"),
                    FLB_LOG_EVENT_UINT64_VALUE(od_attribute_set->attribute_value_count));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "attribute_values");
                flb_log_event_encoder_body_begin_array(encoder);
                for(size_t i = 0; i < od_attribute_set->attribute_value_count; i++) {
                    flb_log_event_encoder_append_body_string(
                        encoder,
                        (char *)od_attribute_set->attribute_values[i].data, od_attribute_set->attribute_values[i].length);
                }
                flb_log_event_encoder_body_commit_array(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_attribute_set->node_name.data, od_attribute_set->node_name.length));
                if(od_attribute_set->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_attribute_set->db_path.data, od_attribute_set->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_attribute_set->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD: {
                es_event_od_group_add_t *od_group_add = event.od_group_add;
                if (!od_group_add) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_group_add->instigator) {
                    encode_es_process_t(encoder, od_group_add->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_group_add->error_code));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "member");
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("member_type"),
                    FLB_LOG_EVENT_INT32_VALUE(od_group_add->member->member_type));
                if (od_group_add->member->member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("member_value"),
                      FLB_LOG_EVENT_STRING_VALUE(od_group_add->member->member_value.name.data, od_group_add->member->member_value.name.length));
                } else {
                  uuid_string_t uuidstr;
                  uuid_unparse(od_group_add->member->member_value.uuid, uuidstr);
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("member_value"),
                      FLB_LOG_EVENT_CSTRING_VALUE(uuidstr));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("group_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_group_add->group_name.data, od_group_add->group_name.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_group_add->node_name.data, od_group_add->node_name.length));
                if(od_group_add->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_group_add->db_path.data, od_group_add->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_group_add->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE: {
                es_event_od_group_remove_t *od_group_remove = event.od_group_remove;
                if (!od_group_remove) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_group_remove->instigator) {
                    encode_es_process_t(encoder, od_group_remove->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_group_remove->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("group_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_group_remove->group_name.data, od_group_remove->group_name.length));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "member");
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("member_type"),
                    FLB_LOG_EVENT_INT32_VALUE(od_group_remove->member->member_type));
                if (od_group_remove->member->member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("member_value"),
                      FLB_LOG_EVENT_STRING_VALUE(od_group_remove->member->member_value.name.data, od_group_remove->member->member_value.name.length));
                } else {
                  uuid_string_t uuidstr;
                  uuid_unparse(od_group_remove->member->member_value.uuid, uuidstr);
                  flb_log_event_encoder_append_body_values(
                      encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("member_value"),
                      FLB_LOG_EVENT_CSTRING_VALUE(uuidstr));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_group_remove->node_name.data, od_group_remove->node_name.length));
                if(od_group_remove->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_group_remove->db_path.data, od_group_remove->db_path.length));
                }
                if (msg->version >= 8) {
                  flb_log_event_encoder_append_body_cstring(
                      encoder,
                      "instigator_token");
                  encode_audit_token_t(encoder, &od_group_remove->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET: {
                es_event_od_group_set_t *od_group_set = event.od_group_set;
                if (!od_group_set) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "instigator");
                if (od_group_set->instigator) {
                    encode_es_process_t(encoder, od_group_set->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("error_code"),
                    FLB_LOG_EVENT_INT32_VALUE(od_group_set->error_code));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("group_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_group_set->group_name.data, od_group_set->group_name.length));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "members");
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("member_type"),
                    FLB_LOG_EVENT_INT32_VALUE(od_group_set->members->member_type));
                flb_log_event_encoder_append_body_cstring(
                    encoder,
                    "member_values");
                flb_log_event_encoder_body_begin_array(encoder);
                if (od_group_set->members->member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
                    for (size_t i = 0; i < od_group_set->members->member_count; i++) {
                        flb_log_event_encoder_append_body_string(
                            encoder,
                            (char *)od_group_set->members->member_array.names[i].data,
                            od_group_set->members->member_array.names[i].length);
                    }
                } else {
                    for (size_t i = 0; i < od_group_set->members->member_count; i++) {
                        uuid_string_t uuidstr;
                        uuid_unparse(od_group_set->members->member_array.uuids[i], uuidstr);
                        flb_log_event_encoder_append_body_cstring(encoder, uuidstr);
                    }
                }
                flb_log_event_encoder_body_commit_array(encoder);
                flb_log_event_encoder_body_commit_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                    FLB_LOG_EVENT_STRING_VALUE(od_group_set->node_name.data, od_group_set->node_name.length));
                if (od_group_set->db_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                        FLB_LOG_EVENT_STRING_VALUE(od_group_set->db_path.data, od_group_set->db_path.length));
                }
                if (msg->version >= 8) {
                    flb_log_event_encoder_append_body_cstring(
                        encoder,
                        "instigator_token");
                    encode_audit_token_t(encoder, &od_group_set->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: {
                es_event_authentication_t *authentication = event.authentication;
                if (!authentication) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("success"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(authentication->success));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_INT32_VALUE(authentication->type));
                switch(authentication->type) {
                    case ES_AUTHENTICATION_TYPE_OD:
                      flb_log_event_encoder_append_body_cstring(encoder, "instigator");
                      if (authentication->data.od->instigator) {
                          encode_es_process_t(encoder, authentication->data.od->instigator);
                      } else {
                          flb_log_event_encoder_append_body_null(encoder);
                      }
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("record_type"),
                          FLB_LOG_EVENT_STRING_VALUE(authentication->data.od->record_type.data, authentication->data.od->record_type.length));
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("record_name"),
                          FLB_LOG_EVENT_STRING_VALUE(authentication->data.od->record_name.data, authentication->data.od->record_name.length));
                      flb_log_event_encoder_append_body_values(
                          encoder,
                          FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
                          FLB_LOG_EVENT_STRING_VALUE(authentication->data.od->node_name.data, authentication->data.od->node_name.length));
                      if(authentication->data.od->db_path.length > 0) {
                          flb_log_event_encoder_append_body_values(
                              encoder,
                              FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
                              FLB_LOG_EVENT_STRING_VALUE(authentication->data.od->db_path.data, authentication->data.od->db_path.length));
                      }
                      if (msg->version >= 8) {
                          flb_log_event_encoder_append_body_cstring(
                              encoder,
                              "instigator_token");
                          encode_audit_token_t(encoder, &authentication->data.od->instigator_token);
                      }
                      break;
                    default:
                      break;
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_SETTIME:
                /* settime has no data fields (only reserved), emit empty map */
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETACL: {
                es_event_setacl_t *setacl = &event.setacl;
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
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_PROC_CHECK: {
                es_event_proc_check_t *pc = &event.proc_check;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(encoder, "target");
                if (pc->target) {
                    encode_es_process_t(encoder, pc->target);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_INT32_VALUE(pc->type));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("flavor"),
                    FLB_LOG_EVENT_INT32_VALUE(pc->flavor));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME: {
                es_event_proc_suspend_resume_t *psr = &event.proc_suspend_resume;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(encoder, "target");
                if (psr->target) {
                    encode_es_process_t(encoder, psr->target);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_INT32_VALUE(psr->type));
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
                /* cs_invalidated has no data fields (only reserved), emit empty map */
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: {
                es_event_remote_thread_create_t *rtc = &event.remote_thread_create;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(encoder, "target");
                encode_es_process_t(encoder, rtc->target);
                flb_log_event_encoder_append_body_cstring(encoder, "thread_state");
                if (rtc->thread_state) {
                    flb_log_event_encoder_body_begin_map(encoder);
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("flavor"),
                        FLB_LOG_EVENT_INT32_VALUE(rtc->thread_state->flavor));
                    flb_log_event_encoder_body_commit_map(encoder);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED: {
                es_event_xp_malware_detected_t *xp = event.xp_malware_detected;
                if (!xp) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("signature_version"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->signature_version.data,
                                               xp->signature_version.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("malware_identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->malware_identifier.data,
                                               xp->malware_identifier.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("incident_identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->incident_identifier.data,
                                               xp->incident_identifier.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("detected_path"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->detected_path.data,
                                               xp->detected_path.length));
                if (msg->version >= 10) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("detected_executable"),
                        FLB_LOG_EVENT_STRING_VALUE(xp->detected_executable.data,
                                                   xp->detected_executable.length));
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED: {
                es_event_xp_malware_remediated_t *xp = event.xp_malware_remediated;
                if (!xp) break;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("signature_version"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->signature_version.data,
                                               xp->signature_version.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("malware_identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->malware_identifier.data,
                                               xp->malware_identifier.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("incident_identifier"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->incident_identifier.data,
                                               xp->incident_identifier.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("action_type"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->action_type.data,
                                               xp->action_type.length));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("success"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(xp->success));
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("result_description"),
                    FLB_LOG_EVENT_STRING_VALUE(xp->result_description.data,
                                               xp->result_description.length));
                if (xp->remediated_path.length > 0) {
                    flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("remediated_path"),
                        FLB_LOG_EVENT_STRING_VALUE(xp->remediated_path.data,
                                                   xp->remediated_path.length));
                }
                flb_log_event_encoder_append_body_cstring(encoder, "remediated_process_audit_token");
                if (xp->remediated_process_audit_token) {
                    encode_audit_token_t(encoder, xp->remediated_process_audit_token);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD: {
                es_event_profile_add_t *pa = event.profile_add;
                if (!pa) break;
                es_profile_t *profile = pa->profile;
                flb_log_event_encoder_body_begin_map(encoder);
                flb_log_event_encoder_append_body_cstring(encoder, "instigator");
                if (pa->instigator) {
                    encode_es_process_t(encoder, pa->instigator);
                } else {
                    flb_log_event_encoder_append_body_null(encoder);
                }
                flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("is_update"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(pa->is_update));
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
                    encode_audit_token_t(encoder, &pa->instigator_token);
                }
                flb_log_event_encoder_body_commit_map(encoder);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE: {
                es_event_profile_remove_t *pr = event.profile_remove;
                if (!pr) break;
                es_profile_t *profile = pr->profile;
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
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION: {
                es_event_authorization_petition_t *ap = event.authorization_petition;
                if (!ap) break;
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
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT: {
                es_event_authorization_judgement_t *aj = event.authorization_judgement;
                if (!aj) break;
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
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: {
                es_event_gatekeeper_user_override_t *gk = event.gatekeeper_user_override;
                if (!gk) break;
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
                    es_signed_file_info_t *si = gk->signing_info;
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
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY: {
                es_event_tcc_modify_t *tcc = event.tcc_modify;
                if (!tcc) break;
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
                break;
            }
            default:
                flb_log_event_encoder_append_body_null(encoder);
                break;
            }
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_body_commit_map(encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(
                encoder,
                "process");
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            encode_es_process_t(encoder, msg->process);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("global_seq_num"),
                FLB_LOG_EVENT_UINT64_VALUE(msg->global_seq_num));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(
                encoder,
                "thread");
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_body_begin_map(encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("thread_id"),
                FLB_LOG_EVENT_UINT64_VALUE(msg->thread->thread_id));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_body_commit_map(encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            flb_input_log_append(ins, NULL, 0,
                encoder->output_buffer,
                encoder->output_length);
        }
        else {
            flb_plg_error(ins, "Error encoding event (type=%u, seq=%llu): %d",
                          msg->event_type, msg->seq_num, ret);
        }

        flb_log_event_encoder_reset(encoder);
        pthread_mutex_unlock(&ctx->encoder_mutex);
    };

    return Block_copy(handler);
}
