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

struct flb_maces_config {
    es_client_t *client;
    struct flb_input_instance *ins;
};

static es_handler_block_t handler =  ^(es_client_t *c, const es_message_t *msg ) {
  printf("%s\n", "Event received");
};

static int in_maces_init(struct flb_input_instance *ins, struct flb_config *config, void *data) {
  struct flb_maces_config *ctx = flb_calloc(1, sizeof(struct flb_maces_config));
  if (!ctx) {
      flb_errno();
      return -1;
  }

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

  ctx->ins = ins;
  flb_input_set_context(ins, ctx);

  flb_plg_info(ins, "Endpoint Security Client initialized successfully");
  es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC};
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
