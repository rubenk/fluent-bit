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
#include <pthread.h>
#include <Block.h>

#include "in_maces.h"
#include "maces_encoders.h"
#include "maces_events.h"
#include "maces_event_handlers.h"
#include "events.h"

es_handler_block_t maces_create_event_handler(struct flb_maces_config *ctx) {
    struct flb_input_instance *ins = ctx->ins;

    es_handler_block_t handler = ^(es_client_t *c, const es_message_t *msg ) {
        int ret;
        pthread_mutex_lock(&ctx->encoder_mutex);
        struct flb_log_event_encoder *encoder = ctx->encoder;

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

        // event specific code - dispatch to individual handlers
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                encode_event_exec(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_FORK:
                encode_event_fork(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                encode_event_exit(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OPEN:
                encode_event_open(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_CLOSE:
                encode_event_close(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_CREATE:
                encode_event_create(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_TRACE:
                encode_event_trace(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_MMAP:
                encode_event_mmap(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_MPROTECT:
                encode_event_mprotect(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
                encode_event_uipc_bind(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                encode_event_uipc_connect(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_ACCESS:
                encode_event_access(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_RENAME:
                encode_event_rename(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_UNLINK:
                encode_event_unlink(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_CHDIR:
                encode_event_chdir(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LINK:
                encode_event_link(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SIGNAL:
                encode_event_signal(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
                encode_event_listextattr(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
                encode_event_setextattr(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
                encode_event_getextattr(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
                encode_event_deleteextattr(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
                encode_event_setflags(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
                encode_event_exchangedata(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_WRITE:
                encode_event_write(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
                encode_event_truncate(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_STAT:
                encode_event_stat(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_CHROOT:
                encode_event_chroot(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
                encode_event_iokit_open(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_READLINK:
                encode_event_readlink(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LOOKUP:
                encode_event_lookup(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_CLONE:
                encode_event_clone(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_COPYFILE:
                encode_event_copyfile(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_FCNTL:
                encode_event_fcntl(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_READDIR:
                encode_event_readdir(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
                encode_event_fsgetpath(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
                encode_event_kextload(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
                encode_event_kextunload(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETMODE:
                encode_event_setmode(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETOWNER:
                encode_event_setowner(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_GET_TASK:
                encode_event_get_task(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
                encode_event_get_task_read(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
                encode_event_get_task_inspect(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
                encode_event_get_task_name(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
                encode_event_file_provider_update(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
                encode_event_file_provider_materialize(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_DUP:
                encode_event_dup(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_MOUNT:
                encode_event_mount(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
                encode_event_unmount(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_REMOUNT:
                encode_event_remount(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
                encode_event_getattrlist(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
                encode_event_setattrlist(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
                encode_event_searchfs(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_UTIMES:
                encode_event_utimes(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
                encode_event_lw_session_login(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
                encode_event_lw_session_logout(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
                encode_event_lw_session_lock(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
                encode_event_lw_session_unlock(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
                encode_event_screensharing_attach(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
                encode_event_screensharing_detach(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
                encode_event_openssh_login(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
                encode_event_openssh_logout(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
                encode_event_login_login(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
                encode_event_login_logout(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
                encode_event_xpc_connect(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
                encode_event_pty_grant(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
                encode_event_pty_close(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
                encode_event_btm_launch_item_add(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
                encode_event_btm_launch_item_remove(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETUID:
                encode_event_setuid(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETGID:
                encode_event_setgid(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETEUID:
                encode_event_seteuid(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETEGID:
                encode_event_setegid(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETREUID:
                encode_event_setreuid(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETREGID:
                encode_event_setregid(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SU:
                encode_event_su(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SUDO:
                encode_event_sudo(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER:
                encode_event_od_delete_user(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER:
                encode_event_od_create_user(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP:
                encode_event_od_create_group(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP:
                encode_event_od_delete_group(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
                encode_event_od_modify_password(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER:
                encode_event_od_disable_user(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER:
                encode_event_od_enable_user(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
                encode_event_od_attribute_value_add(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE:
                encode_event_od_attribute_value_remove(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET:
                encode_event_od_attribute_set(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
                encode_event_od_group_add(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
                encode_event_od_group_remove(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET:
                encode_event_od_group_set(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
                encode_event_authentication(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETTIME:
                encode_event_settime(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETACL:
                encode_event_setacl(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
                encode_event_proc_check(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
                encode_event_proc_suspend_resume(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
                encode_event_cs_invalidated(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
                encode_event_remote_thread_create(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
                encode_event_xp_malware_detected(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
                encode_event_xp_malware_remediated(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
                encode_event_profile_add(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE:
                encode_event_profile_remove(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
                encode_event_authorization_petition(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
                encode_event_authorization_judgement(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE:
                encode_event_gatekeeper_user_override(encoder, msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
                encode_event_tcc_modify(encoder, msg);
                break;
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
