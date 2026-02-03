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

#ifndef FLB_IN_MACES_H
#define FLB_IN_MACES_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <pthread.h>

struct flb_maces_config {
    es_client_t *client;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *encoder;
    pthread_mutex_t encoder_mutex;

    /* Event configuration */
    char *events_str;             /* Comma-separated event type names from config */
    es_event_type_t *events;      /* Parsed array of event types to subscribe */
    size_t events_count;          /* Number of event types in the array */

    /* Muting configuration */
    struct mk_list *mute_rules;   /* List of mute rule strings */
};

#endif /* FLB_IN_MACES_H */
