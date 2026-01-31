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

#include <fluent-bit/flb_log_event_encoder.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <uuid/uuid.h>

#include "in_maces.h"
#include "maces_encoders.h"

int encode_btm_launch_item_t(struct flb_log_event_encoder *encoder, const es_btm_launch_item_t *item) {
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "item");
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("item_type"),
        FLB_LOG_EVENT_INT32_VALUE(item->item_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("legacy"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(item->legacy));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("managed"),
        FLB_LOG_EVENT_BOOLEAN_VALUE(item->managed));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("uid"),
        FLB_LOG_EVENT_UINT32_VALUE(item->uid));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("item_url"),
        FLB_LOG_EVENT_STRING_VALUE(item->item_url.data, item->item_url.length));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("app_url"),
        FLB_LOG_EVENT_STRING_VALUE(item->app_url.data, item->app_url.length));
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

int encode_timespec(struct flb_log_event_encoder *encoder, const struct timespec *ts) {
    char buf[31];
    struct tm tm;
    gmtime_r(&ts->tv_sec, &tm);
    strftime(buf, 21, "%Y-%m-%dT%H:%M:%S.", &tm);
    snprintf(buf + 20, 11, "%09luZ", ts->tv_nsec);
    buf[30] = '\0';
    return flb_log_event_encoder_append_body_cstring(encoder, buf);
}
int encode_attrlist(struct flb_log_event_encoder *encoder, const struct attrlist *attrlist) {
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("bitmapcount"),
        FLB_LOG_EVENT_UINT32_VALUE(attrlist->bitmapcount));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("forkattr"),
        FLB_LOG_EVENT_UINT32_VALUE(attrlist->forkattr));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("fileattr"),
        FLB_LOG_EVENT_UINT32_VALUE(attrlist->fileattr));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("dirattr"),
        FLB_LOG_EVENT_UINT32_VALUE(attrlist->dirattr));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("volattr"),
        FLB_LOG_EVENT_UINT32_VALUE(attrlist->volattr));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("commonattr"),
        FLB_LOG_EVENT_UINT32_VALUE(attrlist->commonattr));
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

int encode_statfs(struct flb_log_event_encoder *encoder, struct statfs *statfs) {
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_bsize"),
        FLB_LOG_EVENT_UINT32_VALUE(statfs->f_bsize));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_iosize"),
        FLB_LOG_EVENT_INT32_VALUE(statfs->f_iosize));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_blocks"),
        FLB_LOG_EVENT_UINT64_VALUE(statfs->f_blocks));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_bfree"),
        FLB_LOG_EVENT_UINT64_VALUE(statfs->f_bfree));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_bavail"),
        FLB_LOG_EVENT_UINT64_VALUE(statfs->f_bavail));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_files"),
        FLB_LOG_EVENT_UINT64_VALUE(statfs->f_files));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_ffree"),
        FLB_LOG_EVENT_UINT64_VALUE(statfs->f_ffree));
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "f_fsid"),
    flb_log_event_encoder_body_begin_array(encoder);
    flb_log_event_encoder_append_body_int32(
        encoder,
        statfs->f_fsid.val[0]);
    flb_log_event_encoder_append_body_int32(
        encoder,
        statfs->f_fsid.val[1]);
    flb_log_event_encoder_body_commit_array(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_owner"),
        FLB_LOG_EVENT_UINT32_VALUE(statfs->f_owner));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_type"),
        FLB_LOG_EVENT_UINT32_VALUE(statfs->f_type));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_flags"),
        FLB_LOG_EVENT_UINT32_VALUE(statfs->f_flags));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_fssubtype"),
        FLB_LOG_EVENT_UINT32_VALUE(statfs->f_fssubtype));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_fstypename"),
        FLB_LOG_EVENT_CSTRING_VALUE(statfs->f_fstypename));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_mntonname"),
        FLB_LOG_EVENT_CSTRING_VALUE(statfs->f_mntonname));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_mntfromname"),
        FLB_LOG_EVENT_CSTRING_VALUE(statfs->f_mntfromname));
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("f_flags_ext"),
        FLB_LOG_EVENT_UINT32_VALUE(statfs->f_flags_ext));
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

int encode_audit_token_t(struct flb_log_event_encoder *encoder, const audit_token_t *token) {
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

int encode_es_file_t(struct flb_log_event_encoder *encoder, const es_file_t *file) {
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
    flb_log_event_encoder_append_body_cstring(encoder, "st_atimespec");
    encode_timespec(encoder, &stat.st_atimespec);
    flb_log_event_encoder_append_body_cstring(encoder, "st_mtimespec");
    encode_timespec(encoder, &stat.st_mtimespec);
    flb_log_event_encoder_append_body_cstring(encoder, "st_ctimespec");
    encode_timespec(encoder, &stat.st_ctimespec);
    flb_log_event_encoder_append_body_cstring(encoder, "st_birthtimespec");
    encode_timespec(encoder, &stat.st_birthtimespec);
    flb_log_event_encoder_body_commit_map(encoder);
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

int encode_od_instigator(struct flb_log_event_encoder *encoder,
                         const es_process_t *instigator) {
    flb_log_event_encoder_append_body_cstring(encoder, "instigator");
    if (instigator) {
        return encode_es_process_t(encoder, instigator);
    } else {
        return flb_log_event_encoder_append_body_null(encoder);
    }
}

int encode_od_tail(struct flb_log_event_encoder *encoder,
                   const es_string_token_t *node_name,
                   const es_string_token_t *db_path,
                   const audit_token_t *instigator_token,
                   uint32_t msg_version) {
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("node_name"),
        FLB_LOG_EVENT_STRING_VALUE(node_name->data, node_name->length));
    if (db_path->length > 0) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("db_path"),
            FLB_LOG_EVENT_STRING_VALUE(db_path->data, db_path->length));
    }
    if (msg_version >= 8) {
        flb_log_event_encoder_append_body_cstring(encoder, "instigator_token");
        encode_audit_token_t(encoder, instigator_token);
    }
    return 0;
}

int encode_od_member(struct flb_log_event_encoder *encoder,
                     const es_od_member_id_t *member) {
    flb_log_event_encoder_append_body_cstring(encoder, "member");
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("member_type"),
        FLB_LOG_EVENT_INT32_VALUE(member->member_type));
    if (member->member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("member_value"),
            FLB_LOG_EVENT_STRING_VALUE(member->member_value.name.data,
                                       member->member_value.name.length));
    } else {
        uuid_string_t uuidstr;
        uuid_unparse(member->member_value.uuid, uuidstr);
        flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("member_value"),
            FLB_LOG_EVENT_CSTRING_VALUE(uuidstr));
    }
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

int encode_od_members(struct flb_log_event_encoder *encoder,
                      const es_od_member_id_array_t *members) {
    flb_log_event_encoder_append_body_cstring(encoder, "members");
    flb_log_event_encoder_body_begin_map(encoder);
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("member_type"),
        FLB_LOG_EVENT_INT32_VALUE(members->member_type));
    flb_log_event_encoder_append_body_cstring(encoder, "member_values");
    flb_log_event_encoder_body_begin_array(encoder);
    if (members->member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
        for (size_t i = 0; i < members->member_count; i++) {
            flb_log_event_encoder_append_body_string(
                encoder,
                (char *)members->member_array.names[i].data,
                members->member_array.names[i].length);
        }
    } else {
        for (size_t i = 0; i < members->member_count; i++) {
            uuid_string_t uuidstr;
            uuid_unparse(members->member_array.uuids[i], uuidstr);
            flb_log_event_encoder_append_body_cstring(encoder, uuidstr);
        }
    }
    flb_log_event_encoder_body_commit_array(encoder);
    flb_log_event_encoder_body_commit_map(encoder);
    return 0;
}

int encode_es_process_t(struct flb_log_event_encoder *encoder, const es_process_t *process) {
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
    flb_log_event_encoder_append_body_cstring(
        encoder,
        "executable");
    encode_es_file_t(encoder, process->executable);

    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("team_id"),
        FLB_LOG_EVENT_STRING_VALUE(process->team_id.data, process->team_id.length));
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
    static const char hex_digits[] = "0123456789ABCDEF";
    char cdhash[sizeof(es_cdhash_t) * 2 + 1];
    for (size_t i = 0; i < sizeof(es_cdhash_t); i++) {
      cdhash[i * 2] = hex_digits[(process->cdhash[i] >> 4) & 0x0F];
      cdhash[i * 2 + 1] = hex_digits[process->cdhash[i] & 0x0F];
    }
    cdhash[sizeof(es_cdhash_t) * 2] = '\0';
    flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("cdhash"),
        FLB_LOG_EVENT_CSTRING_VALUE(cdhash));
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
