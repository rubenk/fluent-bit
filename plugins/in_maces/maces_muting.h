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

#ifndef FLB_IN_MACES_MUTING_H
#define FLB_IN_MACES_MUTING_H

#include "in_maces.h"

/*
 * Apply all configured muting rules to the ES client.
 * Must be called after es_new_client() but before es_subscribe().
 *
 * Returns 0 on success, -1 if any rules failed to apply.
 */
int maces_apply_muting(struct flb_maces_config *ctx);

/*
 * Apply selection (inverted muting) rules to the ES client.
 * This enables "allowlist" mode - only events matching these rules are received.
 * Must be called after es_new_client() but before es_subscribe().
 * Must be called BEFORE maces_apply_muting() if both are used.
 *
 * Requires macOS Ventura (13.0) or later.
 *
 * Returns 0 on success, -1 if any rules failed to apply.
 */
int maces_apply_selection(struct flb_maces_config *ctx);

#endif /* FLB_IN_MACES_MUTING_H */
