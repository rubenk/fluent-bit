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
 * Accepts names with or without NOTIFY_/AUTH_ prefix
 * Returns 0 on success, -1 if name not recognized
 */
int event_type_from_str(const char *name, es_event_type_t *out) {
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

    size_t count = sizeof(names) / sizeof(names[0]);

    /* Try exact match first */
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(name, names[i]) == 0) {
            *out = (es_event_type_t)i;
            return 0;
        }
    }

    /* Try with NOTIFY_ prefix */
    char with_notify[256];
    snprintf(with_notify, sizeof(with_notify), "NOTIFY_%s", name);
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(with_notify, names[i]) == 0) {
            *out = (es_event_type_t)i;
            return 0;
        }
    }

    /* Try with AUTH_ prefix */
    char with_auth[256];
    snprintf(with_auth, sizeof(with_auth), "AUTH_%s", name);
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(with_auth, names[i]) == 0) {
            *out = (es_event_type_t)i;
            return 0;
        }
    }

    return -1;  /* Not found */
}


