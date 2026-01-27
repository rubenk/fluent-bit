/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <stdio.h>
#include <strings.h>
#include "events.h"

const char *event_type_str(const es_event_type_t event_type) {
    static const char * const names[] = {
        // The following events are available beginning in macOS 10.15
        "AUTH_EXEC",
        "AUTH_OPEN",
        "AUTH_KEXTLOAD",
        "AUTH_MMAP",
        "AUTH_MPROTECT",
        "AUTH_MOUNT",
        "AUTH_RENAME",
        "AUTH_SIGNAL",
        "AUTH_UNLINK",
        "NOTIFY_EXEC",
        "NOTIFY_OPEN",
        "NOTIFY_FORK",
        "NOTIFY_CLOSE",
        "NOTIFY_CREATE",
        "NOTIFY_EXCHANGEDATA",
        "NOTIFY_EXIT",
        "NOTIFY_GET_TASK",
        "NOTIFY_KEXTLOAD",
        "NOTIFY_KEXTUNLOAD",
        "NOTIFY_LINK",
        "NOTIFY_MMAP",
        "NOTIFY_MPROTECT",
        "NOTIFY_MOUNT",
        "NOTIFY_UNMOUNT",
        "NOTIFY_IOKIT_OPEN",
        "NOTIFY_RENAME",
        "NOTIFY_SETATTRLIST",
        "NOTIFY_SETEXTATTR",
        "NOTIFY_SETFLAGS",
        "NOTIFY_SETMODE",
        "NOTIFY_SETOWNER",
        "NOTIFY_SIGNAL",
        "NOTIFY_UNLINK",
        "NOTIFY_WRITE",
        "AUTH_FILE_PROVIDER_MATERIALIZE",
        "NOTIFY_FILE_PROVIDER_MATERIALIZE",
        "AUTH_FILE_PROVIDER_UPDATE",
        "NOTIFY_FILE_PROVIDER_UPDATE",
        "AUTH_READLINK",
        "NOTIFY_READLINK",
        "AUTH_TRUNCATE",
        "NOTIFY_TRUNCATE",
        "AUTH_LINK",
        "NOTIFY_LOOKUP",
        "AUTH_CREATE",
        "AUTH_SETATTRLIST",
        "AUTH_SETEXTATTR",
        "AUTH_SETFLAGS",
        "AUTH_SETMODE",
        "AUTH_SETOWNER",

        // The following events are available beginning in macOS 10.15.1
        "AUTH_CHDIR",
        "NOTIFY_CHDIR",
        "AUTH_GETATTRLIST",
        "NOTIFY_GETATTRLIST",
        "NOTIFY_STAT",
        "NOTIFY_ACCESS",
        "AUTH_CHROOT",
        "NOTIFY_CHROOT",
        "AUTH_UTIMES",
        "NOTIFY_UTIMES",
        "AUTH_CLONE",
        "NOTIFY_CLONE",
        "NOTIFY_FCNTL",
        "AUTH_GETEXTATTR",
        "NOTIFY_GETEXTATTR",
        "AUTH_LISTEXTATTR",
        "NOTIFY_LISTEXTATTR",
        "AUTH_READDIR",
        "NOTIFY_READDIR",
        "AUTH_DELETEEXTATTR",
        "NOTIFY_DELETEEXTATTR",
        "AUTH_FSGETPATH",
        "NOTIFY_FSGETPATH",
        "NOTIFY_DUP",
        "AUTH_SETTIME",
        "NOTIFY_SETTIME",
        "NOTIFY_UIPC_BIND",
        "AUTH_UIPC_BIND",
        "NOTIFY_UIPC_CONNECT",
        "AUTH_UIPC_CONNECT",
        "AUTH_EXCHANGEDATA",
        "AUTH_SETACL",
        "NOTIFY_SETACL",

        // The following events are available beginning in macOS 10.15.4
        "NOTIFY_PTY_GRANT",
        "NOTIFY_PTY_CLOSE",
        "AUTH_PROC_CHECK",
        "NOTIFY_PROC_CHECK",
        "AUTH_GET_TASK",

        // The following events are available beginning in macOS 11.0
        "AUTH_SEARCHFS",
        "NOTIFY_SEARCHFS",
        "AUTH_FCNTL",
        "AUTH_IOKIT_OPEN",
        "AUTH_PROC_SUSPEND_RESUME",
        "NOTIFY_PROC_SUSPEND_RESUME",
        "NOTIFY_CS_INVALIDATED",
        "NOTIFY_GET_TASK_NAME",
        "NOTIFY_TRACE",
        "NOTIFY_REMOTE_THREAD_CREATE",
        "AUTH_REMOUNT",
        "NOTIFY_REMOUNT",

        // The following events are available beginning in macOS 11.3
        "AUTH_GET_TASK_READ",
        "NOTIFY_GET_TASK_READ",
        "NOTIFY_GET_TASK_INSPECT",

        // The following events are available beginning in macOS 12.0
        "NOTIFY_SETUID",
        "NOTIFY_SETGID",
        "NOTIFY_SETEUID",
        "NOTIFY_SETEGID",
        "NOTIFY_SETREUID",
        "NOTIFY_SETREGID",
        "AUTH_COPYFILE",
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
        "NOTIFY_TCC_MODIFY"
    };

  if (event_type >= sizeof(names) / sizeof(names[0])) {
      return "UNKNOWN";
  }
  return names[event_type];
}

/* Parse event type string name to enum value
 * Only NOTIFY_ events are subscribable (AUTH_ events are not supported for subscription)
 * Accepts lowercase names without prefix (e.g., "exec", "fork", "authentication")
 * Also accepts full names with NOTIFY_ prefix for backward compatibility
 * Returns 0 on success, -1 if name not recognized or not a NOTIFY_ event
 */
int event_type_from_str(const char *name, es_event_type_t *out) {
    /* Mapping of NOTIFY_ event names to their enum values
     * Only NOTIFY_ events are subscribable - AUTH_ events are excluded
     */
    struct {
        const char *short_name;  /* lowercase without NOTIFY_ prefix */
        const char *full_name;   /* with NOTIFY_ prefix */
        es_event_type_t type;
    } notify_events[] = {
        /* macOS 10.15 */
        {"exec", "NOTIFY_EXEC", ES_EVENT_TYPE_NOTIFY_EXEC},
        {"open", "NOTIFY_OPEN", ES_EVENT_TYPE_NOTIFY_OPEN},
        {"fork", "NOTIFY_FORK", ES_EVENT_TYPE_NOTIFY_FORK},
        {"close", "NOTIFY_CLOSE", ES_EVENT_TYPE_NOTIFY_CLOSE},
        {"create", "NOTIFY_CREATE", ES_EVENT_TYPE_NOTIFY_CREATE},
        {"exchangedata", "NOTIFY_EXCHANGEDATA", ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA},
        {"exit", "NOTIFY_EXIT", ES_EVENT_TYPE_NOTIFY_EXIT},
        {"get_task", "NOTIFY_GET_TASK", ES_EVENT_TYPE_NOTIFY_GET_TASK},
        {"kextload", "NOTIFY_KEXTLOAD", ES_EVENT_TYPE_NOTIFY_KEXTLOAD},
        {"kextunload", "NOTIFY_KEXTUNLOAD", ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD},
        {"link", "NOTIFY_LINK", ES_EVENT_TYPE_NOTIFY_LINK},
        {"mmap", "NOTIFY_MMAP", ES_EVENT_TYPE_NOTIFY_MMAP},
        {"mprotect", "NOTIFY_MPROTECT", ES_EVENT_TYPE_NOTIFY_MPROTECT},
        {"mount", "NOTIFY_MOUNT", ES_EVENT_TYPE_NOTIFY_MOUNT},
        {"unmount", "NOTIFY_UNMOUNT", ES_EVENT_TYPE_NOTIFY_UNMOUNT},
        {"iokit_open", "NOTIFY_IOKIT_OPEN", ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN},
        {"rename", "NOTIFY_RENAME", ES_EVENT_TYPE_NOTIFY_RENAME},
        {"setattrlist", "NOTIFY_SETATTRLIST", ES_EVENT_TYPE_NOTIFY_SETATTRLIST},
        {"setextattr", "NOTIFY_SETEXTATTR", ES_EVENT_TYPE_NOTIFY_SETEXTATTR},
        {"setflags", "NOTIFY_SETFLAGS", ES_EVENT_TYPE_NOTIFY_SETFLAGS},
        {"setmode", "NOTIFY_SETMODE", ES_EVENT_TYPE_NOTIFY_SETMODE},
        {"setowner", "NOTIFY_SETOWNER", ES_EVENT_TYPE_NOTIFY_SETOWNER},
        {"signal", "NOTIFY_SIGNAL", ES_EVENT_TYPE_NOTIFY_SIGNAL},
        {"unlink", "NOTIFY_UNLINK", ES_EVENT_TYPE_NOTIFY_UNLINK},
        {"write", "NOTIFY_WRITE", ES_EVENT_TYPE_NOTIFY_WRITE},
        {"file_provider_materialize", "NOTIFY_FILE_PROVIDER_MATERIALIZE", ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE},
        {"file_provider_update", "NOTIFY_FILE_PROVIDER_UPDATE", ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE},
        {"readlink", "NOTIFY_READLINK", ES_EVENT_TYPE_NOTIFY_READLINK},
        {"truncate", "NOTIFY_TRUNCATE", ES_EVENT_TYPE_NOTIFY_TRUNCATE},
        {"lookup", "NOTIFY_LOOKUP", ES_EVENT_TYPE_NOTIFY_LOOKUP},

        /* macOS 10.15.1 */
        {"chdir", "NOTIFY_CHDIR", ES_EVENT_TYPE_NOTIFY_CHDIR},
        {"getattrlist", "NOTIFY_GETATTRLIST", ES_EVENT_TYPE_NOTIFY_GETATTRLIST},
        {"stat", "NOTIFY_STAT", ES_EVENT_TYPE_NOTIFY_STAT},
        {"access", "NOTIFY_ACCESS", ES_EVENT_TYPE_NOTIFY_ACCESS},
        {"chroot", "NOTIFY_CHROOT", ES_EVENT_TYPE_NOTIFY_CHROOT},
        {"utimes", "NOTIFY_UTIMES", ES_EVENT_TYPE_NOTIFY_UTIMES},
        {"clone", "NOTIFY_CLONE", ES_EVENT_TYPE_NOTIFY_CLONE},
        {"fcntl", "NOTIFY_FCNTL", ES_EVENT_TYPE_NOTIFY_FCNTL},
        {"getextattr", "NOTIFY_GETEXTATTR", ES_EVENT_TYPE_NOTIFY_GETEXTATTR},
        {"listextattr", "NOTIFY_LISTEXTATTR", ES_EVENT_TYPE_NOTIFY_LISTEXTATTR},
        {"readdir", "NOTIFY_READDIR", ES_EVENT_TYPE_NOTIFY_READDIR},
        {"deleteextattr", "NOTIFY_DELETEEXTATTR", ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR},
        {"fsgetpath", "NOTIFY_FSGETPATH", ES_EVENT_TYPE_NOTIFY_FSGETPATH},
        {"dup", "NOTIFY_DUP", ES_EVENT_TYPE_NOTIFY_DUP},
        {"settime", "NOTIFY_SETTIME", ES_EVENT_TYPE_NOTIFY_SETTIME},
        {"uipc_bind", "NOTIFY_UIPC_BIND", ES_EVENT_TYPE_NOTIFY_UIPC_BIND},
        {"uipc_connect", "NOTIFY_UIPC_CONNECT", ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT},
        {"setacl", "NOTIFY_SETACL", ES_EVENT_TYPE_NOTIFY_SETACL},

        /* macOS 10.15.4 */
        {"pty_grant", "NOTIFY_PTY_GRANT", ES_EVENT_TYPE_NOTIFY_PTY_GRANT},
        {"pty_close", "NOTIFY_PTY_CLOSE", ES_EVENT_TYPE_NOTIFY_PTY_CLOSE},
        {"proc_check", "NOTIFY_PROC_CHECK", ES_EVENT_TYPE_NOTIFY_PROC_CHECK},

        /* macOS 11.0 */
        {"searchfs", "NOTIFY_SEARCHFS", ES_EVENT_TYPE_NOTIFY_SEARCHFS},
        {"proc_suspend_resume", "NOTIFY_PROC_SUSPEND_RESUME", ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME},
        {"cs_invalidated", "NOTIFY_CS_INVALIDATED", ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED},
        {"get_task_name", "NOTIFY_GET_TASK_NAME", ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME},
        {"trace", "NOTIFY_TRACE", ES_EVENT_TYPE_NOTIFY_TRACE},
        {"remote_thread_create", "NOTIFY_REMOTE_THREAD_CREATE", ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE},
        {"remount", "NOTIFY_REMOUNT", ES_EVENT_TYPE_NOTIFY_REMOUNT},

        /* macOS 11.3 */
        {"get_task_read", "NOTIFY_GET_TASK_READ", ES_EVENT_TYPE_NOTIFY_GET_TASK_READ},
        {"get_task_inspect", "NOTIFY_GET_TASK_INSPECT", ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT},

        /* macOS 12.0 */
        {"setuid", "NOTIFY_SETUID", ES_EVENT_TYPE_NOTIFY_SETUID},
        {"setgid", "NOTIFY_SETGID", ES_EVENT_TYPE_NOTIFY_SETGID},
        {"seteuid", "NOTIFY_SETEUID", ES_EVENT_TYPE_NOTIFY_SETEUID},
        {"setegid", "NOTIFY_SETEGID", ES_EVENT_TYPE_NOTIFY_SETEGID},
        {"setreuid", "NOTIFY_SETREUID", ES_EVENT_TYPE_NOTIFY_SETREUID},
        {"setregid", "NOTIFY_SETREGID", ES_EVENT_TYPE_NOTIFY_SETREGID},
        {"copyfile", "NOTIFY_COPYFILE", ES_EVENT_TYPE_NOTIFY_COPYFILE},

        /* macOS 13.0 */
        {"authentication", "NOTIFY_AUTHENTICATION", ES_EVENT_TYPE_NOTIFY_AUTHENTICATION},
        {"xp_malware_detected", "NOTIFY_XP_MALWARE_DETECTED", ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED},
        {"xp_malware_remediated", "NOTIFY_XP_MALWARE_REMEDIATED", ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED},
        {"lw_session_login", "NOTIFY_LW_SESSION_LOGIN", ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN},
        {"lw_session_logout", "NOTIFY_LW_SESSION_LOGOUT", ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT},
        {"lw_session_lock", "NOTIFY_LW_SESSION_LOCK", ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK},
        {"lw_session_unlock", "NOTIFY_LW_SESSION_UNLOCK", ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK},
        {"screensharing_attach", "NOTIFY_SCREENSHARING_ATTACH", ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH},
        {"screensharing_detach", "NOTIFY_SCREENSHARING_DETACH", ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH},
        {"openssh_login", "NOTIFY_OPENSSH_LOGIN", ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN},
        {"openssh_logout", "NOTIFY_OPENSSH_LOGOUT", ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT},
        {"login_login", "NOTIFY_LOGIN_LOGIN", ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN},
        {"login_logout", "NOTIFY_LOGIN_LOGOUT", ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT},
        {"btm_launch_item_add", "NOTIFY_BTM_LAUNCH_ITEM_ADD", ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD},
        {"btm_launch_item_remove", "NOTIFY_BTM_LAUNCH_ITEM_REMOVE", ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE},

        /* macOS 14.0 */
        {"profile_add", "NOTIFY_PROFILE_ADD", ES_EVENT_TYPE_NOTIFY_PROFILE_ADD},
        {"profile_remove", "NOTIFY_PROFILE_REMOVE", ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE},
        {"su", "NOTIFY_SU", ES_EVENT_TYPE_NOTIFY_SU},
        {"authorization_petition", "NOTIFY_AUTHORIZATION_PETITION", ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION},
        {"authorization_judgement", "NOTIFY_AUTHORIZATION_JUDGEMENT", ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT},
        {"sudo", "NOTIFY_SUDO", ES_EVENT_TYPE_NOTIFY_SUDO},
        {"od_group_add", "NOTIFY_OD_GROUP_ADD", ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD},
        {"od_group_remove", "NOTIFY_OD_GROUP_REMOVE", ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE},
        {"od_group_set", "NOTIFY_OD_GROUP_SET", ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET},
        {"od_modify_password", "NOTIFY_OD_MODIFY_PASSWORD", ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD},
        {"od_disable_user", "NOTIFY_OD_DISABLE_USER", ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER},
        {"od_enable_user", "NOTIFY_OD_ENABLE_USER", ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER},
        {"od_attribute_value_add", "NOTIFY_OD_ATTRIBUTE_VALUE_ADD", ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD},
        {"od_attribute_value_remove", "NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE", ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE},
        {"od_attribute_set", "NOTIFY_OD_ATTRIBUTE_SET", ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET},
        {"od_create_user", "NOTIFY_OD_CREATE_USER", ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER},
        {"od_create_group", "NOTIFY_OD_CREATE_GROUP", ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP},
        {"od_delete_user", "NOTIFY_OD_DELETE_USER", ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER},
        {"od_delete_group", "NOTIFY_OD_DELETE_GROUP", ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP},
        {"xpc_connect", "NOTIFY_XPC_CONNECT", ES_EVENT_TYPE_NOTIFY_XPC_CONNECT},

        /* macOS 15.0 */
        {"gatekeeper_user_override", "NOTIFY_GATEKEEPER_USER_OVERRIDE", ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE},

        /* macOS 15.4 */
        {"tcc_modify", "NOTIFY_TCC_MODIFY", ES_EVENT_TYPE_NOTIFY_TCC_MODIFY},

        {NULL, NULL, 0}
    };

    /* Try lowercase short name match (preferred) */
    for (int i = 0; notify_events[i].short_name != NULL; i++) {
        if (strcasecmp(name, notify_events[i].short_name) == 0) {
            *out = notify_events[i].type;
            return 0;
        }
    }

    /* Try full NOTIFY_ name match (backward compatibility) */
    for (int i = 0; notify_events[i].full_name != NULL; i++) {
        if (strcasecmp(name, notify_events[i].full_name) == 0) {
            *out = notify_events[i].type;
            return 0;
        }
    }

    return -1;  /* Not found or not a subscribable NOTIFY_ event */
}


