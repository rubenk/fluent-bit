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

struct flb_maces_config {
    es_client_t *client;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *encoder;
};

const char *event_type_str(const es_event_type_t event_type) {
    static const char * const names[] = {
        // The following events are available beginning in macOS 10.15
        "AUTH_EXEC","AUTH_OPEN", "AUTH_KEXTLOAD", "AUTH_MMAP",
        "AUTH_MPROTECT", "AUTH_MOUNT", "AUTH_RENAME", "AUTH_SIGNAL",
        "AUTH_UNLINK", "NOTIFY_EXEC", "NOTIFY_OPEN", "NOTIFY_FORK",
        "NOTIFY_CLOSE", "NOTIFY_CREATE", "NOTIFY_EXCHANGEDATA", "NOTIFY_EXIT",
        "NOTIFY_GET_TASK", "NOTIFY_KEXTLOAD", "NOTIFY_KEXTUNLOAD",
        "NOTIFY_LINK", "NOTIFY_MMAP", "NOTIFY_MPROTECT", "NOTIFY_MOUNT",
        "NOTIFY_UNMOUNT", "NOTIFY_IOKIT_OPEN", "NOTIFY_RENAME",
        "NOTIFY_SETATTRLIST", "NOTIFY_SETEXTATTR", "NOTIFY_SETFLAGS",
        "NOTIFY_SETMODE", "NOTIFY_SETOWNER", "NOTIFY_SIGNAL", "NOTIFY_UNLINK",
        "NOTIFY_WRITE", "AUTH_FILE_PROVIDER_MATERIALIZE",
        "NOTIFY_FILE_PROVIDER_MATERIALIZE", "AUTH_FILE_PROVIDER_UPDATE",
        "NOTIFY_FILE_PROVIDER_UPDATE", "AUTH_READLINK", "NOTIFY_READLINK",
        "AUTH_TRUNCATE", "NOTIFY_TRUNCATE", "AUTH_LINK", "NOTIFY_LOOKUP",
        "AUTH_CREATE", "AUTH_SETATTRLIST", "AUTH_SETEXTATTR", "AUTH_SETFLAGS",
        "AUTH_SETMODE", "AUTH_SETOWNER",

        // The following events are available beginning in macOS 10.15.1
        "AUTH_CHDIR", "NOTIFY_CHDIR", "AUTH_GETATTRLIST",
        "NOTIFY_GETATTRLIST", "NOTIFY_STAT", "NOTIFY_ACCESS", "AUTH_CHROOT",
        "NOTIFY_CHROOT", "AUTH_UTIMES", "NOTIFY_UTIMES", "AUTH_CLONE",
        "NOTIFY_CLONE", "NOTIFY_FCNTL", "AUTH_GETEXTATTR",
        "NOTIFY_GETEXTATTR", "AUTH_LISTEXTATTR", "NOTIFY_LISTEXTATTR",
        "AUTH_READDIR", "NOTIFY_READDIR", "AUTH_DELETEEXTATTR",
        "NOTIFY_DELETEEXTATTR", "AUTH_FSGETPATH", "NOTIFY_FSGETPATH",
        "NOTIFY_DUP", "AUTH_SETTIME", "NOTIFY_SETTIME", "NOTIFY_UIPC_BIND",
        "AUTH_UIPC_BIND", "NOTIFY_UIPC_CONNECT", "AUTH_UIPC_CONNECT",
        "AUTH_EXCHANGEDATA", "AUTH_SETACL", "NOTIFY_SETACL",

        // The following events are available beginning in macOS 10.15.4
        "NOTIFY_PTY_GRANT", "NOTIFY_PTY_CLOSE", "AUTH_PROC_CHECK",
        "NOTIFY_PROC_CHECK", "AUTH_GET_TASK",

        // The following events are available beginning in macOS 11.0
        "AUTH_SEARCHFS", "NOTIFY_SEARCHFS", "AUTH_FCNTL", "AUTH_IOKIT_OPEN",
        "AUTH_PROC_SUSPEND_RESUME", "NOTIFY_PROC_SUSPEND_RESUME",
        "NOTIFY_CS_INVALIDATED", "NOTIFY_GET_TASK_NAME", "NOTIFY_TRACE",
        "NOTIFY_REMOTE_THREAD_CREATE", "AUTH_REMOUNT", "NOTIFY_REMOUNT",

        // The following events are available beginning in macOS 11.3
        "AUTH_GET_TASK_READ", "NOTIFY_GET_TASK_READ",
        "NOTIFY_GET_TASK_INSPECT",

        // The following events are available beginning in macOS 12.0
        "NOTIFY_SETUID", "NOTIFY_SETGID", "NOTIFY_SETEUID", "NOTIFY_SETEGID",
        "NOTIFY_SETREUID", "NOTIFY_SETREGID", "AUTH_COPYFILE",
        "NOTIFY_COPYFILE",

        // The following events are available beginning in macOS 13.0
        "NOTIFY_AUTHENTICATION",
        "NOTIFY_XP_MALWARE_DETECTED",
        "NOTIFY_XP_MALWARE_REMEDIATED",
        "NOTIFY_LW_SESSION_LOGIN",
        "NOTIFY_LW_SESSION_LOGOUT",
        "NOTIFY_LW_SESSION_LOCK",
        "NOTIFY_LW_SESSION_UNLOCK",
        "NOTIFY_SCREENSHARING_ATTACH",
        "NOTIFY_SCREENSHARING_DETACH",
        "NOTIFY_OPENSSH_LOGIN",
        "NOTIFY_OPENSSH_LOGOUT",
        "NOTIFY_LOGIN_LOGIN",
        "NOTIFY_LOGIN_LOGOUT",
        "NOTIFY_BTM_LAUNCH_ITEM_ADD",
        "NOTIFY_BTM_LAUNCH_ITEM_REMOVE",

        // The following events are available beginning in macOS 14.0
        "NOTIFY_PROFILE_ADD",
        "NOTIFY_PROFILE_REMOVE",
        "NOTIFY_SU",
        "NOTIFY_AUTHORIZATION_PETITION",
        "NOTIFY_AUTHORIZATION_JUDGEMENT",
        "NOTIFY_SUDO",
        "NOTIFY_OD_GROUP_ADD",
        "NOTIFY_OD_GROUP_REMOVE",
        "NOTIFY_OD_GROUP_SET",
        "NOTIFY_OD_MODIFY_PASSWORD",
        "NOTIFY_OD_DISABLE_USER",
        "NOTIFY_OD_ENABLE_USER",
        "NOTIFY_OD_ATTRIBUTE_VALUE_ADD",
        "NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE",
        "NOTIFY_OD_ATTRIBUTE_SET",
        "NOTIFY_OD_CREATE_USER",
        "NOTIFY_OD_CREATE_GROUP",
        "NOTIFY_OD_DELETE_USER",
        "NOTIFY_OD_DELETE_GROUP",
        "NOTIFY_XPC_CONNECT",

        // The following events are available beginning in macOS 15.0
        "NOTIFY_GATEKEEPER_USER_OVERRIDE",

        // The following events are available beginning in macOS 15.4
        "ES_EVENT_TYPE_NOTIFY_TCC_MODIFY"
    };

  return names[event_type];
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
        struct flb_time timestamp = {
            .tm = msg->time
        };
        flb_log_event_encoder_set_timestamp(ctx->encoder, &timestamp);
        flb_log_event_encoder_append_body_cstring(
                        ctx->encoder,
                        "event_type");
        flb_log_event_encoder_append_body_int32(
                        ctx->encoder,
                        msg->event_type);
        flb_log_event_encoder_append_body_cstring(
                        ctx->encoder,
                        "event");
        flb_log_event_encoder_append_body_cstring(
                        ctx->encoder,
                        (char *)event_type_str(msg->event_type));
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
