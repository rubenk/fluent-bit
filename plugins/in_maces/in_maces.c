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
#include <fluent-bit/flb_slist.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <pthread.h>

#include "in_maces.h"
#include "maces_encoders.h"
#include "maces_events.h"
#include "maces_muting.h"
#include "events.h"

/* Parse comma-separated event types configuration string
 * Returns 0 on success, -1 on error
 */
static int parse_events_config(struct flb_maces_config *ctx,
                                     struct flb_input_instance *ins) {
    struct mk_list event_list;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    es_event_type_t event_type;
    size_t count = 0;
    size_t capacity = 16;
    int ret;

    if (!ctx->events_str) {
        flb_plg_error(ins, "No events configured. Set 'events' to a comma-separated list of event types.");
        return -1;
    }

    /* Split comma-separated string into list */
    mk_list_init(&event_list);
    ret = flb_slist_split_string(&event_list, ctx->events_str, ',', -1);
    if (ret == -1 || ret == 0) {
        flb_plg_error(ins, "Failed to parse events configuration");
        return -1;
    }

    /* Allocate initial array */
    ctx->events = flb_malloc(sizeof(es_event_type_t) * capacity);
    if (!ctx->events) {
        flb_slist_destroy(&event_list);
        return -1;
    }

    /* Parse each event type name */
    mk_list_foreach(head, &event_list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* flb_slist automatically trims whitespace */
        if (event_type_from_str(entry->str, &event_type) == 0) {
            /* Expand array if needed */
            if (count >= capacity) {
                capacity *= 2;
                es_event_type_t *new_events = flb_realloc(ctx->events,
                                                           sizeof(es_event_type_t) * capacity);
                if (!new_events) {
                    flb_free(ctx->events);
                    ctx->events = NULL;
                    flb_slist_destroy(&event_list);
                    return -1;
                }
                ctx->events = new_events;
            }
            ctx->events[count++] = event_type;
            flb_plg_debug(ins, "Subscribed to event type: %s", entry->str);
        } else {
            flb_plg_warn(ins, "Unknown event type: %s (skipping)", entry->str);
        }
    }

    flb_slist_destroy(&event_list);

    if (count == 0) {
        flb_plg_error(ins, "No valid event types configured");
        flb_free(ctx->events);
        ctx->events = NULL;
        return -1;
    }

    ctx->events_count = count;
    flb_plg_info(ins, "Subscribed to %zu event types", count);

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

    if (pthread_mutex_init(&ctx->encoder_mutex, NULL) != 0) {
        flb_plg_error(ins, "could not initialize encoder mutex");
        flb_log_event_encoder_destroy(ctx->encoder);
        flb_free(ctx);
        return -1;
    }

    ctx->ins = ins;

    flb_input_set_context(ins, ctx);

    /* Load config map into context */
    int ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "Failed to load configuration");
        pthread_mutex_destroy(&ctx->encoder_mutex);
        flb_log_event_encoder_destroy(ctx->encoder);
        flb_free(ctx);
        return -1;
    }

    /* Parse event types configuration */
    if (parse_events_config(ctx, ins) != 0) {
        flb_plg_error(ins, "Failed to parse event types configuration");
        pthread_mutex_destroy(&ctx->encoder_mutex);
        flb_log_event_encoder_destroy(ctx->encoder);
        flb_free(ctx);
        return -1;
    }


    // Create event handler
    es_handler_block_t handler = maces_create_event_handler(ctx);

    es_new_client_result_t res = es_new_client(&ctx->client, handler);

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        switch(res) {
            case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
                flb_plg_error(ins, "Invalid argument provided to es_new_client");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
                flb_plg_error(ins, "Internal ES client error");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                flb_plg_error(ins, "Application requires 'com.apple.developer.endpoint-security.client' entitlement");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                flb_plg_error(ins, "Application lacks 'Transparency, Consent, and Control (TCC)' approval");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                flb_plg_error(ins, "Application needs to run as root");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
                flb_plg_error(ins, "Too many ES clients already exist on this system");
                break;
            default:
                flb_plg_error(ins, "Unknown ES client creation error (code %d)", res);
                break;
        }
        pthread_mutex_destroy(&ctx->encoder_mutex);
        flb_log_event_encoder_destroy(ctx->encoder);
        if (ctx->events) {
            flb_free(ctx->events);
        }
        flb_free(ctx);
        return -1;
    }

    flb_plg_info(ins, "Endpoint Security Client initialized successfully");

    /* Apply muting configuration before subscribing to events */
    if (maces_apply_muting(ctx) < 0) {
        flb_plg_warn(ins, "Some muting rules failed to apply");
        /* Continue anyway - partial muting is still useful */
    }

    es_return_t subscribed = es_subscribe(ctx->client, ctx->events, ctx->events_count);
    if(subscribed != ES_RETURN_SUCCESS) {
        flb_plg_error(ins, "Error subscribing to events");
        es_unsubscribe_all(ctx->client);
        es_delete_client(ctx->client);
        pthread_mutex_destroy(&ctx->encoder_mutex);
        flb_log_event_encoder_destroy(ctx->encoder);
        if (ctx->events) {
            flb_free(ctx->events);
        }
        flb_free(ctx);
        return -1;
    } else {
        flb_plg_info(ins, "Subscribed to events");
    }

    return 0;
}

static int in_maces_exit(void *data, struct flb_config *config)
{
    struct flb_maces_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->client) {
        es_unsubscribe_all(ctx->client);
        es_delete_client(ctx->client);
    }

    if (ctx->encoder) {
        flb_log_event_encoder_destroy(ctx->encoder);
    }

    pthread_mutex_destroy(&ctx->encoder_mutex);

    if (ctx->events) {
        flb_free(ctx->events);
    }

    flb_free(ctx);
    return 0;
}

/* Configuration map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "events", NULL,
     0, FLB_TRUE, offsetof(struct flb_maces_config, events_str),
     "Comma-separated list of events to subscribe (lowercase, without NOTIFY_ prefix). "
     "Examples: exec,fork,exit or authentication,sudo,su. "
     "Available types: exec, fork, exit, close, create, exchangedata, kextload, "
     "kextunload, link, mmap, mprotect, mount, unmount, iokit_open, rename, "
     "setattrlist, setextattr, setflags, setmode, setowner, signal, unlink, write, "
     "authentication, xp_malware_detected, xp_malware_remediated, lw_session_login, "
     "lw_session_logout, lw_session_lock, lw_session_unlock, screensharing_attach, "
     "screensharing_detach, openssh_login, openssh_logout, login_login, login_logout, "
     "btm_launch_item_add, btm_launch_item_remove, profile_add, profile_remove, su, "
     "authorization_petition, authorization_judgement, sudo, od_group_add, od_group_remove, "
     "od_group_set, od_modify_password, od_disable_user, od_enable_user, "
     "od_attribute_value_add, od_attribute_value_remove, od_attribute_set, od_create_user, "
     "od_create_group, od_delete_user, od_delete_group, xpc_connect. "
     "Note: Only NOTIFY_ events are subscribable; AUTH_ events are not supported."
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "mute", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_maces_config, mute_rules),
     "Mute rule in format 'type:path' or 'type:path:events'. "
     "Types: process (exact executable path), process_prefix (executable directory), "
     "target (exact target file), target_prefix (target directory). "
     "If events omitted, mutes ALL events for path. "
     "Examples: 'process:/usr/sbin/cfprefsd', 'target_prefix:/tmp/:write,rename'"
    },
    {0}
};

/* Plugin registration */
struct flb_input_plugin in_maces_plugin = {
    .name        = "maces",
    .description = "MacOS Endpoint Security input plugin",
    .cb_init     = in_maces_init,
    .cb_exit     = in_maces_exit,
    .config_map  = config_map,
};
