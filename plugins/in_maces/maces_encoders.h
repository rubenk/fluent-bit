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

#ifndef FLB_IN_MACES_ENCODERS_H
#define FLB_IN_MACES_ENCODERS_H

#include "in_maces.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <sys/mount.h>
#include <time.h>

int encode_btm_launch_item_t(struct flb_log_event_encoder *encoder,
                              const es_btm_launch_item_t *item);

int encode_timespec(struct flb_log_event_encoder *encoder,
                    const struct timespec *ts);

int encode_attrlist(struct flb_log_event_encoder *encoder,
                    const struct attrlist *attrlist);

int encode_statfs(struct flb_log_event_encoder *encoder,
                  struct statfs *statfs);

int encode_audit_token_t(struct flb_log_event_encoder *encoder,
                         const audit_token_t *token);

int encode_es_file_t(struct flb_log_event_encoder *encoder,
                     const es_file_t *file);

int encode_es_process_t(struct flb_log_event_encoder *encoder,
                        const es_process_t *process);

int encode_uuid(struct flb_log_event_encoder *encoder,
                const char *field_name,
                const uuid_t uuid);

int encode_od_instigator(struct flb_log_event_encoder *encoder,
                         const es_process_t *instigator);

int encode_od_tail(struct flb_log_event_encoder *encoder,
                   const es_string_token_t *node_name,
                   const es_string_token_t *db_path,
                   const audit_token_t *instigator_token,
                   uint32_t msg_version);

int encode_od_member(struct flb_log_event_encoder *encoder,
                     const es_od_member_id_t *member);

int encode_od_members(struct flb_log_event_encoder *encoder,
                      const es_od_member_id_array_t *members);

#endif /* FLB_IN_MACES_ENCODERS_H */
