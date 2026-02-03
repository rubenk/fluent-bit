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

#ifndef FLB_IN_MACES_EVENT_HANDLERS_H
#define FLB_IN_MACES_EVENT_HANDLERS_H

#include <fluent-bit/flb_log_event_encoder.h>
#include <EndpointSecurity/EndpointSecurity.h>

void encode_event_exec(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_fork(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_exit(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_open(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_close(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_create(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_trace(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_mmap(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_mprotect(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_uipc_bind(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_uipc_connect(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_access(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_rename(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_unlink(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_chdir(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_link(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_signal(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_listextattr(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setextattr(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_getextattr(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_deleteextattr(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setflags(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_exchangedata(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_write(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_truncate(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_stat(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_chroot(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_iokit_open(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_readlink(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_lookup(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_clone(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_copyfile(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_fcntl(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_readdir(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_fsgetpath(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_kextload(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_kextunload(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setmode(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setowner(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_get_task(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_get_task_read(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_get_task_inspect(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_get_task_name(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_file_provider_update(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_file_provider_materialize(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_dup(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_mount(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_unmount(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_remount(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_getattrlist(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setattrlist(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_searchfs(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_utimes(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_lw_session_login(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_lw_session_logout(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_lw_session_lock(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_lw_session_unlock(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_screensharing_attach(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_screensharing_detach(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_openssh_login(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_openssh_logout(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_login_login(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_login_logout(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_xpc_connect(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_pty_grant(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_pty_close(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_btm_launch_item_add(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_btm_launch_item_remove(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setuid(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setgid(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_seteuid(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setegid(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setreuid(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setregid(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_su(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_sudo(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_delete_user(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_create_user(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_create_group(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_delete_group(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_modify_password(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_disable_user(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_enable_user(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_attribute_value_add(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_attribute_value_remove(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_attribute_set(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_group_add(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_group_remove(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_od_group_set(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_authentication(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_settime(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_setacl(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_proc_check(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_proc_suspend_resume(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_cs_invalidated(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_remote_thread_create(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_xp_malware_detected(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_xp_malware_remediated(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_profile_add(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_profile_remove(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_authorization_petition(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_authorization_judgement(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_gatekeeper_user_override(struct flb_log_event_encoder *encoder, const es_message_t *msg);
void encode_event_tcc_modify(struct flb_log_event_encoder *encoder, const es_message_t *msg);

#endif /* FLB_IN_MACES_EVENT_HANDLERS_H */
