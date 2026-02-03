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
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_config_map.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <string.h>

#include "in_maces.h"
#include "maces_muting.h"
#include "events.h"

/*
 * Parse and apply a single mute rule.
 *
 * Rule format: "type:path" or "type:path:events"
 *
 * Types:
 *   - process:        Exact executable path match (ES_MUTE_PATH_TYPE_LITERAL)
 *   - process_prefix: Executable path prefix (ES_MUTE_PATH_TYPE_PREFIX)
 *   - target:         Exact target file path (ES_MUTE_PATH_TYPE_TARGET_LITERAL)
 *   - target_prefix:  Target path prefix (ES_MUTE_PATH_TYPE_TARGET_PREFIX)
 *
 * Events:
 *   - Optional comma-separated list of event types
 *   - If omitted, mutes ALL events for the path
 *
 * Examples:
 *   "process:/usr/sbin/cfprefsd"              -> mute all events from cfprefsd
 *   "process:/usr/libexec/amfid:open,close"   -> mute only open,close from amfid
 *   "target_prefix:/tmp/"                     -> mute all events targeting /tmp/
 *   "target_prefix:/tmp/:write,rename"        -> mute only write,rename for /tmp/
 */
static int apply_mute_rule(struct flb_maces_config *ctx, const char *rule)
{
    char *rule_copy = NULL;
    char *type_str = NULL;
    char *path = NULL;
    char *events_str = NULL;
    char *saveptr = NULL;
    es_mute_path_type_t path_type;
    es_return_t result;
    int ret = 0;

    rule_copy = flb_strdup(rule);
    if (!rule_copy) {
        flb_plg_error(ctx->ins, "Failed to allocate memory for mute rule");
        return -1;
    }

    /* Parse type (first component before ':') */
    type_str = strtok_r(rule_copy, ":", &saveptr);
    if (!type_str) {
        flb_plg_error(ctx->ins, "Invalid mute rule (missing type): %s", rule);
        flb_free(rule_copy);
        return -1;
    }

    /* Parse path (second component) */
    path = strtok_r(NULL, ":", &saveptr);
    if (!path || strlen(path) == 0) {
        flb_plg_error(ctx->ins, "Invalid mute rule (missing path): %s", rule);
        flb_free(rule_copy);
        return -1;
    }

    /* Parse optional events (everything after the second colon) */
    events_str = saveptr;
    if (events_str && strlen(events_str) == 0) {
        events_str = NULL;
    }

    /* Determine path type from type string */
    if (strcmp(type_str, "process") == 0) {
        path_type = ES_MUTE_PATH_TYPE_LITERAL;
    }
    else if (strcmp(type_str, "process_prefix") == 0) {
        path_type = ES_MUTE_PATH_TYPE_PREFIX;
    }
    else if (strcmp(type_str, "target") == 0) {
        path_type = ES_MUTE_PATH_TYPE_TARGET_LITERAL;
    }
    else if (strcmp(type_str, "target_prefix") == 0) {
        path_type = ES_MUTE_PATH_TYPE_TARGET_PREFIX;
    }
    else {
        flb_plg_error(ctx->ins, "Unknown mute type '%s' in rule: %s", type_str, rule);
        flb_free(rule_copy);
        return -1;
    }

    if (events_str == NULL) {
        /* Mute ALL events for this path */
        result = es_mute_path(ctx->client, path, path_type);
        if (result == ES_RETURN_SUCCESS) {
            flb_plg_info(ctx->ins, "Muted all events for %s:%s", type_str, path);
        }
        else {
            flb_plg_warn(ctx->ins, "Failed to mute %s:%s (error %d)",
                         type_str, path, result);
            ret = -1;
        }
    }
    else {
        /* Mute specific events for this path */
        struct mk_list event_list;
        struct mk_list *head;
        struct flb_slist_entry *entry;
        es_event_type_t *events = NULL;
        size_t events_count = 0;
        size_t events_capacity = 16;

        mk_list_init(&event_list);
        if (flb_slist_split_string(&event_list, events_str, ',', -1) <= 0) {
            flb_plg_error(ctx->ins, "Invalid events list in mute rule: %s", rule);
            flb_free(rule_copy);
            return -1;
        }

        events = flb_malloc(sizeof(es_event_type_t) * events_capacity);
        if (!events) {
            flb_plg_error(ctx->ins, "Failed to allocate memory for events array");
            flb_slist_destroy(&event_list);
            flb_free(rule_copy);
            return -1;
        }

        mk_list_foreach(head, &event_list) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            es_event_type_t event_type;

            if (event_type_from_str(entry->str, &event_type) == 0) {
                /* Expand array if needed */
                if (events_count >= events_capacity) {
                    events_capacity *= 2;
                    es_event_type_t *new_events = flb_realloc(events,
                        sizeof(es_event_type_t) * events_capacity);
                    if (!new_events) {
                        flb_plg_error(ctx->ins, "Failed to reallocate events array");
                        flb_free(events);
                        flb_slist_destroy(&event_list);
                        flb_free(rule_copy);
                        return -1;
                    }
                    events = new_events;
                }
                events[events_count++] = event_type;
            }
            else {
                flb_plg_warn(ctx->ins, "Unknown event type '%s' in mute rule, skipping",
                             entry->str);
            }
        }

        flb_slist_destroy(&event_list);

        if (events_count > 0) {
            result = es_mute_path_events(ctx->client, path, path_type,
                                          events, events_count);
            if (result == ES_RETURN_SUCCESS) {
                flb_plg_info(ctx->ins, "Muted %zu event(s) for %s:%s",
                             events_count, type_str, path);
            }
            else {
                flb_plg_warn(ctx->ins, "Failed to mute events for %s:%s (error %d)",
                             type_str, path, result);
                ret = -1;
            }
        }
        else {
            flb_plg_warn(ctx->ins, "No valid events in mute rule: %s", rule);
            ret = -1;
        }

        flb_free(events);
    }

    flb_free(rule_copy);
    return ret;
}

int maces_apply_muting(struct flb_maces_config *ctx)
{
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *entry;
    int errors = 0;
    int rules_applied = 0;

    if (!ctx->mute_rules) {
        return 0;  /* No muting configured */
    }

    /*
     * Iterate over the config map values. Each -p mute=... creates one
     * flb_config_map_val entry. For SLIST_1, the first entry in mv->val.list
     * contains the rule string.
     */
    flb_config_map_foreach(head, mv, ctx->mute_rules) {
        /* Get the first (and only) entry from the SLIST_1 split */
        entry = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);

        if (apply_mute_rule(ctx, entry->str) < 0) {
            errors++;
        }
        else {
            rules_applied++;
        }
    }

    if (rules_applied > 0 || errors > 0) {
        flb_plg_info(ctx->ins, "Applied %d mute rule(s), %d failed",
                     rules_applied, errors);
    }

    return (errors > 0) ? -1 : 0;
}

/*
 * Flags indicating which muting inversions are needed.
 */
#define INVERT_PATH         (1 << 0)  /* Process/executable path */
#define INVERT_TARGET_PATH  (1 << 1)  /* Target file path */

/*
 * Scan select rules to determine which inversions are needed.
 */
static int get_required_inversions(struct flb_maces_config *ctx)
{
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *entry;
    int inversions = 0;

    if (!ctx->select_rules) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->select_rules) {
        entry = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);

        if (strncmp(entry->str, "process", 7) == 0) {
            inversions |= INVERT_PATH;
        }
        else if (strncmp(entry->str, "target", 6) == 0) {
            inversions |= INVERT_TARGET_PATH;
        }
    }

    return inversions;
}

/*
 * Apply a single select rule (same as mute rule, but logs "Selected" instead).
 * After inversion, es_mute_path() selects instead of mutes.
 */
static int apply_select_rule(struct flb_maces_config *ctx, const char *rule)
{
    char *rule_copy = NULL;
    char *type_str = NULL;
    char *path = NULL;
    char *events_str = NULL;
    char *saveptr = NULL;
    es_mute_path_type_t path_type;
    es_return_t result;
    int ret = 0;

    rule_copy = flb_strdup(rule);
    if (!rule_copy) {
        flb_plg_error(ctx->ins, "Failed to allocate memory for select rule");
        return -1;
    }

    /* Parse type (first component before ':') */
    type_str = strtok_r(rule_copy, ":", &saveptr);
    if (!type_str) {
        flb_plg_error(ctx->ins, "Invalid select rule (missing type): %s", rule);
        flb_free(rule_copy);
        return -1;
    }

    /* Parse path (second component) */
    path = strtok_r(NULL, ":", &saveptr);
    if (!path || strlen(path) == 0) {
        flb_plg_error(ctx->ins, "Invalid select rule (missing path): %s", rule);
        flb_free(rule_copy);
        return -1;
    }

    /* Parse optional events (everything after the second colon) */
    events_str = saveptr;
    if (events_str && strlen(events_str) == 0) {
        events_str = NULL;
    }

    /* Determine path type from type string */
    if (strcmp(type_str, "process") == 0) {
        path_type = ES_MUTE_PATH_TYPE_LITERAL;
    }
    else if (strcmp(type_str, "process_prefix") == 0) {
        path_type = ES_MUTE_PATH_TYPE_PREFIX;
    }
    else if (strcmp(type_str, "target") == 0) {
        path_type = ES_MUTE_PATH_TYPE_TARGET_LITERAL;
    }
    else if (strcmp(type_str, "target_prefix") == 0) {
        path_type = ES_MUTE_PATH_TYPE_TARGET_PREFIX;
    }
    else {
        flb_plg_error(ctx->ins, "Unknown select type '%s' in rule: %s", type_str, rule);
        flb_free(rule_copy);
        return -1;
    }

    if (events_str == NULL) {
        /* Select ALL events for this path */
        result = es_mute_path(ctx->client, path, path_type);
        if (result == ES_RETURN_SUCCESS) {
            flb_plg_info(ctx->ins, "Selected all events for %s:%s", type_str, path);
        }
        else {
            flb_plg_warn(ctx->ins, "Failed to select %s:%s (error %d)",
                         type_str, path, result);
            ret = -1;
        }
    }
    else {
        /* Select specific events for this path */
        struct mk_list event_list;
        struct mk_list *head;
        struct flb_slist_entry *entry;
        es_event_type_t *events = NULL;
        size_t events_count = 0;
        size_t events_capacity = 16;

        mk_list_init(&event_list);
        if (flb_slist_split_string(&event_list, events_str, ',', -1) <= 0) {
            flb_plg_error(ctx->ins, "Invalid events list in select rule: %s", rule);
            flb_free(rule_copy);
            return -1;
        }

        events = flb_malloc(sizeof(es_event_type_t) * events_capacity);
        if (!events) {
            flb_plg_error(ctx->ins, "Failed to allocate memory for events array");
            flb_slist_destroy(&event_list);
            flb_free(rule_copy);
            return -1;
        }

        mk_list_foreach(head, &event_list) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            es_event_type_t event_type;

            if (event_type_from_str(entry->str, &event_type) == 0) {
                /* Expand array if needed */
                if (events_count >= events_capacity) {
                    events_capacity *= 2;
                    es_event_type_t *new_events = flb_realloc(events,
                        sizeof(es_event_type_t) * events_capacity);
                    if (!new_events) {
                        flb_plg_error(ctx->ins, "Failed to reallocate events array");
                        flb_free(events);
                        flb_slist_destroy(&event_list);
                        flb_free(rule_copy);
                        return -1;
                    }
                    events = new_events;
                }
                events[events_count++] = event_type;
            }
            else {
                flb_plg_warn(ctx->ins, "Unknown event type '%s' in select rule, skipping",
                             entry->str);
            }
        }

        flb_slist_destroy(&event_list);

        if (events_count > 0) {
            result = es_mute_path_events(ctx->client, path, path_type,
                                          events, events_count);
            if (result == ES_RETURN_SUCCESS) {
                flb_plg_info(ctx->ins, "Selected %zu event(s) for %s:%s",
                             events_count, type_str, path);
            }
            else {
                flb_plg_warn(ctx->ins, "Failed to select events for %s:%s (error %d)",
                             type_str, path, result);
                ret = -1;
            }
        }
        else {
            flb_plg_warn(ctx->ins, "No valid events in select rule: %s", rule);
            ret = -1;
        }

        flb_free(events);
    }

    flb_free(rule_copy);
    return ret;
}

int maces_apply_selection(struct flb_maces_config *ctx)
{
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *entry;
    int inversions;
    int errors = 0;
    int rules_applied = 0;
    es_return_t ret;

    if (!ctx->select_rules) {
        return 0;  /* No selection configured */
    }

    /* Determine which inversions are needed based on rule types */
    inversions = get_required_inversions(ctx);

    if (inversions == 0) {
        return 0;  /* No valid rules */
    }

    /*
     * Step 1: Clear default mute sets and invert muting.
     *
     * IMPORTANT: New ES clients have certain paths muted by default.
     * When we invert, these become SELECTED instead of muted.
     * We must clear them first with es_unmute_all_*.
     */
    if (inversions & INVERT_PATH) {
        /* Clear default muted paths first */
        ret = es_unmute_all_paths(ctx->client);
        if (ret != ES_RETURN_SUCCESS) {
            flb_plg_warn(ctx->ins, "Failed to clear default muted paths: %d", ret);
        }

        /* Invert path muting - now es_mute_path selects instead of mutes */
        ret = es_invert_muting(ctx->client, ES_MUTE_INVERSION_TYPE_PATH);
        if (ret == ES_RETURN_SUCCESS) {
            flb_plg_info(ctx->ins, "Inverted process path muting (selection mode)");
        }
        else {
            flb_plg_error(ctx->ins, "Failed to invert path muting: %d", ret);
            return -1;
        }
    }

    if (inversions & INVERT_TARGET_PATH) {
        /* Clear default muted target paths first */
        ret = es_unmute_all_target_paths(ctx->client);
        if (ret != ES_RETURN_SUCCESS) {
            flb_plg_warn(ctx->ins, "Failed to clear default muted target paths: %d", ret);
        }

        /* Invert target path muting */
        ret = es_invert_muting(ctx->client, ES_MUTE_INVERSION_TYPE_TARGET_PATH);
        if (ret == ES_RETURN_SUCCESS) {
            flb_plg_info(ctx->ins, "Inverted target path muting (selection mode)");
        }
        else {
            flb_plg_error(ctx->ins, "Failed to invert target path muting: %d", ret);
            return -1;
        }
    }

    /*
     * Step 2: Apply selection rules.
     * After inversion, es_mute_path() selects paths instead of muting them.
     */
    flb_config_map_foreach(head, mv, ctx->select_rules) {
        entry = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);

        if (apply_select_rule(ctx, entry->str) < 0) {
            errors++;
        }
        else {
            rules_applied++;
        }
    }

    if (rules_applied > 0 || errors > 0) {
        flb_plg_info(ctx->ins, "Applied %d select rule(s), %d failed",
                     rules_applied, errors);
    }

    return (errors > 0) ? -1 : 0;
}
