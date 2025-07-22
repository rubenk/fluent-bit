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

#include <EndpointSecurity/EndpointSecurity.h>

static es_handler_block_t handler =  ^(es_client_t *c, const es_message_t *msg ) {
};

static int in_maces_init(struct flb_input_instance *in, struct flb_config *config, void *data) {
  es_client_t *client;
  es_new_client_result_t res = es_new_client(&client, handler);
  if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
    switch(res) {
      case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        flb_plg_error(in, "Application requires 'com.apple.developer.endpoint-security.client' entitlement");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        flb_plg_error(in, "Application lacks 'Transparency, Consent, and Control (TCC)' approval");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        flb_plg_error(in, "Application needs to run as root");
        break;
      default:
        flb_plg_error(in, "Unknown error");
        break;
    }
    return 1;
  }

  flb_plg_info(in, "Endpoint Security Client initialized successfully a");
  es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC};
  es_return_t subscribed = es_subscribe(client, events, sizeof events / sizeof *events);
  if(subscribed != ES_RETURN_SUCCESS) {
    flb_plg_error(in, "Error subscribing to events");
    return 1;
  } else {
    flb_plg_info(in, "Subscribed to events");
  }

  return 0;
}

/* Plugin registration */
struct flb_input_plugin in_maces_plugin = {
    .name         = "maces",
    .description  = "MacOS Endpoint Security input plugin",
    .cb_init      = in_maces_init,
};
