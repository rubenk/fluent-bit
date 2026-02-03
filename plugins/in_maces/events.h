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

#include <EndpointSecurity/EndpointSecurity.h>

/* Convert event type enum to string name */
const char *event_type_str(const es_event_type_t event_type);

/* Parse event type string name to enum value
 * Only NOTIFY_ events are subscribable (AUTH_ events are not supported)
 * Accepts lowercase names without prefix (e.g., "exec", "fork", "authentication")
 * Also accepts full NOTIFY_ names for backward compatibility (e.g., "NOTIFY_EXEC")
 * Returns 0 on success, -1 if name not recognized or not a NOTIFY_ event
 */
int event_type_from_str(const char *name, es_event_type_t *out);


