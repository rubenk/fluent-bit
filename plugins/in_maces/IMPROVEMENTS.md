# macOS Endpoint Security Plugin - Improvements Tracker

This document tracks all improvements for the `in_maces` plugin, including completed work and remaining tasks.

**Quick Status:**
- ✅ **P0 (Critical):** 4/4 complete
- 🔄 **P1 (High Priority):** 4/5 complete (1 won't fix)
- ⏳ **P2 (Medium Priority):** 5/11 complete
- **Total commits:** 35

---

## Completed

### P0 (Critical)
- ✅ Fixed cdhash operator precedence bug
- ✅ Added thread safety for shared encoder
- ✅ Added null pointer checks for all event structures
- ✅ Completed ES client error handling

### P1 (High Priority)
- ✅ Added return value checks for all encoder operations
- ✅ Made events configurable (lowercase names, NOTIFY_-only, no default)
- ✅ Fixed cleanup on subscription failure
- ❌ Won't fix: Input validation (ES framework is trusted)

### P2 (Medium Priority)
- ✅ Fixed magic numbers (use sizeof(es_cdhash_t))
- ✅ Fixed inconsistent null check style (explicit null everywhere)
- ✅ Fixed TODOs in code (dev_t major/minor)
- ✅ Reduced OD events code duplication with helper functions

---

## P1 (High Priority) Issues

### 1. ~~No Return Value Checks for Encoder Operations~~ ✅ FIXED

**Status:** ✅ Complete (commit 354f32dd1)

**What was implemented:**
- Added `int ret` variable to track encoder operation results
- Added return value checks for all critical encoder operations:
  - `flb_log_event_encoder_begin_record()`
  - `flb_log_event_encoder_set_timestamp()`
  - All `flb_log_event_encoder_append_body_values()` calls
  - `flb_log_event_encoder_body_begin_map()` and `commit_map()`
  - `flb_log_event_encoder_commit_record()`
- Chain-checked with `if (ret == FLB_EVENT_ENCODER_SUCCESS)`
- Events only logged if all encoding succeeded
- Error messages include event type, sequence number, and error code:
  ```c
  flb_plg_error(ins, "Error encoding event (type=%u, seq=%llu): %d",
                msg->event_type, msg->seq_num, ret);
  ```
- Always reset encoder and unlock mutex regardless of success/failure

**Pattern used (matches other Fluent Bit plugins):**
```c
ret = flb_log_event_encoder_begin_record(encoder);

if (ret == FLB_EVENT_ENCODER_SUCCESS) {
    ret = flb_log_event_encoder_append_body_values(...);
}

if (ret == FLB_EVENT_ENCODER_SUCCESS) {
    flb_input_log_append(...);
}
else {
    flb_plg_error(...);
}

flb_log_event_encoder_reset(encoder);
```

---

### 2. ~~Only 3 Event Types Subscribed~~ ✅ FIXED

**Status:** ✅ Complete (commits 05aaaae40 and related)

**What was implemented:**
- Made event types configurable via plugin config
- Added `events` configuration option
- Users can specify comma-separated event names (e.g., "exec,fork,authentication")
- Lowercase names without NOTIFY_ prefix for user-friendly config
- Only NOTIFY_ events allowed (AUTH_ events excluded)
- Single source of truth in events.c
- Used Fluent Bit's flb_slist API for parsing
- No default - events must be explicitly configured

---

### 3. ~~No Configuration Options~~ ✅ FIXED

**Status:** ✅ Complete (part of P1.2 implementation)

**What was implemented:**
- Added `config_map` with events option
- Configurable event subscription via comma-separated list
- Dynamic event array allocation
- Proper cleanup in all error paths

---

### 4. ~~No Cleanup on Subscription Failure~~ ✅ FIXED

**Status:** ✅ Complete (commit 6e81db2be)

**What was implemented:**
- Added `es_unsubscribe_all(ctx->client)` before `es_delete_client(ctx->client)`
- Ensures proper cleanup of partial subscriptions on failure
- Prevents resource leaks when subscription fails

---

### 5. No Rate Limiting or Backpressure

**Location:** Handler block

**Issue:** If the system generates events faster than they can be processed, no rate limiting or backpressure is applied.

**Impact:**
- Memory exhaustion
- OOM killer may terminate fluent-bit
- System instability

**Fix:** Implement rate limiting:
- Event queue with maximum size
- Drop events when queue is full (with counter)
- Configurable rate limit (events per second)
- Expose metrics for dropped events

---

### 6. ~~No Input Validation from ES Framework~~ ❌ WON'T FIX

**Status:** ❌ Won't Fix - ES framework is trusted

**Rationale:**
- The Endpoint Security framework is a core macOS security component
- The system itself relies on ES - if ES is compromised, there are much bigger problems
- Adding validation would add unnecessary overhead for minimal security benefit
- ES framework data is considered trustworthy

---

## P2 (Medium Priority) Issues

### 7. ~~Massive Code Duplication in OD Events~~ ✅ FIXED

**Status:** ✅ Complete

**What was implemented:**
- Created `encode_od_instigator()` helper to encode instigator process or null
- Created `encode_od_tail()` helper to encode node_name, db_path (conditional), and instigator_token (version check)
- Created `encode_od_member()` helper for GROUP_ADD/GROUP_REMOVE member encoding
- Created `encode_od_members()` helper for GROUP_SET members array encoding
- Refactored all 13 OD events to use the helper functions
- Also refactored AUTHENTICATION event's OD branch

**Lines reduced:** 393 lines removed, 165 lines added (net reduction of 228 lines)

---

### 8. Duplicate UUID Encoding

**Location:** Lines 2159, 2223, 2290

**Issue:** UUID encoding is duplicated 3+ times:
```c
uuid_string_t uuidstr;
uuid_unparse(member_uuid, uuidstr);
flb_log_event_encoder_append_body_values(
    encoder,
    FLB_LOG_EVENT_CSTRING_VALUE("member_uuid"),
    FLB_LOG_EVENT_CSTRING_VALUE(uuidstr));
```

**Fix:** Create helper function:
```c
static int encode_uuid(
    struct flb_log_event_encoder *encoder,
    const char *field_name,
    const uuid_t uuid
);
```

---

### 9. 2000+ Line Handler Function

**Location:** in_maces_init function

**Issue:** The event handler block within `in_maces_init` is over 2000 lines long, making it:
- Hard to read and understand
- Difficult to maintain
- Impossible to test individual event types

**Fix:** Break into smaller functions per event category:
```c
static int encode_file_events(
    struct flb_log_event_encoder *encoder,
    const es_message_t *msg
);

static int encode_process_events(
    struct flb_log_event_encoder *encoder,
    const es_message_t *msg
);

static int encode_auth_events(
    struct flb_log_event_encoder *encoder,
    const es_message_t *msg
);

static int encode_od_events(
    struct flb_log_event_encoder *encoder,
    const es_message_t *msg
);
```

Then call appropriate function in handler:
```c
es_handler_block_t handler = ^(es_client_t *c, const es_message_t *msg) {
    pthread_mutex_lock(&ctx->encoder_mutex);

    encode_message_header(encoder, msg);

    switch (msg->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
        case ES_EVENT_TYPE_NOTIFY_FORK:
        // ... file events
            encode_file_events(encoder, msg);
            break;
        // ... etc
    }

    encode_message_footer(encoder, msg);
    pthread_mutex_unlock(&ctx->encoder_mutex);
};
```

---

### 10. ~~TODOs in Code~~ ✅ FIXED

**Status:** ✅ Complete (commit 88b211b67)

**What was implemented:**
- Decoded dev_t into dev_major and dev_minor using major() and minor() macros
- Applied to both PTY_GRANT and PTY_CLOSE events

---

### 11. ~~Magic Numbers~~ ✅ FIXED

**Status:** ✅ Complete (commit 1b79eb7f4)

**What was implemented:**
- Replaced magic number 20 with sizeof(es_cdhash_t)
- es_cdhash_t is defined in EndpointSecurity/ESTypes.h as uint8_t[20]
- Self-documenting and will adapt if Apple changes the size

---

### 12. ~~Inconsistent Null Check Style~~ ✅ FIXED

**Status:** ✅ Complete (commit 6e0f3d53f)

**What was implemented:**
- Standardized on explicit null for all optional fields
- Fields are always present with either a value or null
- Consistent JSON schema for downstream consumers
- Fixed: signal.instigator, file_provider_materialize.instigator,
  btm_launch_item_add (instigator, app, tokens),
  btm_launch_item_remove (instigator, app, tokens),
  authentication.data.od.instigator

---

### 13. No Pause/Resume Callbacks

**Location:** Plugin definition

**Issue:** The plugin doesn't implement standard Fluent Bit lifecycle callbacks:
- `cb_pre_run` - called before event collection starts
- `cb_pause` - called when plugin should pause
- `cb_resume` - called when plugin should resume

**Impact:** Cannot properly integrate with Fluent Bit's lifecycle management.

**Fix:** Implement callbacks if needed:
```c
static int in_maces_pause(void *data, struct flb_config *config) {
    struct flb_maces_config *ctx = data;
    if (ctx && ctx->client) {
        es_unsubscribe_all(ctx->client);
    }
    return 0;
}

static int in_maces_resume(void *data, struct flb_config *config) {
    struct flb_maces_config *ctx = data;
    if (ctx && ctx->client) {
        // Re-subscribe to events
    }
    return 0;
}
```

---

### 14. No Metrics/Statistics

**Location:** Plugin definition

**Issue:** No metrics are exposed for:
- Event counts by type
- Processing errors
- Encoding failures
- Dropped events
- Events per second

**Impact:**
- No visibility into plugin performance
- Cannot monitor or alert on issues
- Hard to debug problems in production

**Fix:** Add metrics using Fluent Bit's cmetrics API:
```c
struct flb_maces_config {
    // ... existing fields ...

    struct cmt_counter *events_total;
    struct cmt_counter *events_dropped;
    struct cmt_counter *encoding_errors;
    struct cmt_gauge *events_per_second;
};
```

---

### 15. Buffer Overflow Risk in Timestamp

**Location:** Lines 71-78

**Issue:** The `encode_timespec` function uses a fixed 31-byte buffer with fragile calculations:

```c
char buf[31];
struct tm tm;
gmtime_r(&ts->tv_sec, &tm);
strftime(buf, 21, "%Y-%m-%dT%H:%M:%S.", &tm);  // Uses first 21 bytes
snprintf(buf + 20, 11, "%09luZ", ts->tv_nsec); // Uses bytes 20-30
buf[30] = '\0';  // Redundant and confusing
```

**Impact:**
- Currently safe but fragile
- Easy to break if modified
- Hard to verify correctness

**Fix:** Make it clearer and safer:
```c
#define ISO8601_TIMESTAMP_SIZE 31

static int encode_timespec(struct flb_log_event_encoder *encoder,
                          const struct timespec *ts) {
    char buf[ISO8601_TIMESTAMP_SIZE];
    struct tm tm;
    size_t len;

    gmtime_r(&ts->tv_sec, &tm);
    len = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.", &tm);
    if (len == 0) {
        return -1;
    }

    snprintf(buf + len, sizeof(buf) - len, "%09luZ", ts->tv_nsec);

    return flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("mach_time"),
        FLB_LOG_EVENT_CSTRING_VALUE(buf));
}
```

---

### 16. ~~Unimplemented Event Types~~ ✅ FIXED

**Status:** ✅ Complete

**What was implemented:**
Added case handlers for all 14 previously unimplemented event types in `maces_events.c`:

| Event Type | macOS Version | Description |
|------------|---------------|-------------|
| `SETTIME` | 10.15.4 | System time modification (empty map - no data fields) |
| `SETACL` | 10.15.4 | File ACL modification (target, set_or_clear, acl text) |
| `PROC_CHECK` | 10.15.4 | Process check/inspection (target, type, flavor) |
| `PROC_SUSPEND_RESUME` | 11.0 | Process suspend/resume (target, type) |
| `CS_INVALIDATED` | 11.0 | Code signature invalidated (empty map - no data fields) |
| `REMOTE_THREAD_CREATE` | 11.0 | Remote thread injection (target, thread_state) |
| `XP_MALWARE_DETECTED` | 12.0 | XProtect malware detection (signature_version, malware_identifier, incident_identifier, detected_path, detected_executable) |
| `XP_MALWARE_REMEDIATED` | 12.0 | XProtect malware remediation (signature_version, malware_identifier, incident_identifier, action_type, success, result_description, remediated_path, remediated_process_audit_token) |
| `PROFILE_ADD` | 13.0 | Configuration profile added (instigator, is_update, profile details, instigator_token) |
| `PROFILE_REMOVE` | 13.0 | Configuration profile removed (instigator, profile details, instigator_token) |
| `AUTHORIZATION_PETITION` | 13.0 | Authorization request (instigator, petitioner, flags, rights array, tokens) |
| `AUTHORIZATION_JUDGEMENT` | 13.0 | Authorization decision (instigator, petitioner, return_code, results array with right_name/rule_class/granted, tokens) |
| `GATEKEEPER_USER_OVERRIDE` | 15.0 | Gatekeeper bypass by user (file_type, file/file_path, sha256, signing_info with cdhash/signing_id/team_id) |
| `TCC_MODIFY` | 15.4 | TCC database modification (service, identity, identity_type, update_type, instigator_token, instigator, responsible_token, responsible, right, reason) |

All 14 events now have proper case handlers with full field encoding.

---

### 17. FLB_MINIMAL Build Broken

**Location:** Fluent Bit cmake configuration

**Issue:** Building with `-DFLB_MINIMAL=On` fails due to missing generated headers:
- `mk_core/mk_core_info.h` not found
- `monkey/mk_info.h` not found

The monkey library headers are generated during cmake but the include paths aren't set up correctly when using the minimal build configuration.

**Impact:**
- Cannot do minimal/fast development builds with just maces + stdout
- Full builds take longer and produce larger binaries

**Fix:** This is a Fluent Bit core issue, not specific to maces. Options:
1. Report upstream to Fluent Bit
2. Work around by manually copying generated headers
3. Fix cmake target dependencies in lib/monkey

---

## Summary

### Work Completed

**Total Commits:** 19 (as of latest update)

**P0 Critical Issues:** 4/4 complete ✅
- Fixed cdhash operator precedence bug
- Added thread safety (pthread_mutex) for shared encoder
- Added null pointer checks for 25+ event structures
- Completed ES client error handling (all error codes)

**P1 High Priority Issues:** 1/6 complete
- Added comprehensive return value checking for all encoder operations

**Code Changes:**
- Lines added: 692+
- Lines removed: 380+
- Net increase: ~312 lines (mostly safety checks and error handling)
- Current file size: 2543 lines

### Priority Breakdown

| Priority | Total | Complete | Won't Fix | Remaining | Status |
|----------|-------|----------|-----------|-----------|--------|
| P0 (Critical) | 4 | 4 ✅ | 0 | 0 | Complete |
| P1 (High) | 6 | 4 ✅ | 1 ❌ | 1 | Nearly done |
| P2 (Medium) | 11 | 4 ✅ | 0 | 7 | In progress |

### Recommended Order

1. ~~**P1.1** - Add return value checks~~ ✅ **COMPLETE**
2. ~~**P1.2** - Expand event subscription~~ ✅ **COMPLETE**
3. ~~**P1.3** - Add configuration options~~ ✅ **COMPLETE**
4. ~~**P1.4** - Fix subscription cleanup~~ ✅ **COMPLETE**
5. **P1.5** - Add rate limiting (prevents resource exhaustion)
6. ~~**P1.6** - Add input validation~~ ❌ **WON'T FIX** (ES framework is trusted)
7. **P2.7** - Refactor OD events (reduces maintenance burden)
8. **P2.9** - Break up large function (improves maintainability)
9. Remaining P2 items as time permits

### Expected Final Impact

After all P1 and P2 improvements:
- Estimated file size: ~2200 lines (reduction from refactoring)
- Code quality: Significantly improved
- Functionality: Complete event coverage (90+ event types vs current 3)
- Maintainability: Much easier to maintain and extend
- Robustness: Full error handling, rate limiting, input validation

---

## Commit History

All commits made to improve the maces plugin:

### P0 Critical Fixes

1. **4c536c203** - Add bounds check to event_type_str
2. **5bb76ab5b** - Add explicit uuid/uuid.h include
3. **21114e2c9** - Fix missing commit_map for NOTIFY_LISTEXTATTR event
4. **47c5f8590** - Fix ACL buffer handling with dynamic allocation
5. **3a69b34a6** - Reset encoder after appending log event
6. **ff7654838** - Implement NOTIFY_OD_GROUP_SET event handler
7. **644de510c** - Add exit callback for proper cleanup
8. **e74f8ae17** - Fix variable name conflict with acl_size function
9. **ebfd0e92a** - Fix OD_GROUP_SET to use correct es_od_member_id_array_t structure
10. **f8911ebaf** - Fix event name format for NOTIFY_TCC_MODIFY
11. **85af134fb** - Fix memory leak when ES client creation fails
12. **5b17c9e15** - Fix memory leak when event subscription fails
13. **9292fd0db** - Fix all compilation warnings in maces plugin
14. **7e39143bb** - Fix operator precedence bug in cdhash encoding
15. **c460e8f39** - Add thread safety for shared encoder
16. **74f8540ca** - Add null pointer checks for all event structures
17. **8b342d8f5** - Complete ES client error handling

### P1 High Priority Fixes

18. **354f32dd1** - Add return value checking for all encoder operations
19. **[commit]** - Make event types configurable via plugin config
20. **[commit]** - Refactor to eliminate event name duplication
21. **[commit]** - Use lowercase event names and only allow NOTIFY_ events
22. **05aaaae40** - Use Fluent Bit's flb_slist API for string splitting
23. **6e81db2be** - Fix cleanup on subscription failure

### P2 Medium Priority Fixes

26. **1b79eb7f4** - Use sizeof(es_cdhash_t) instead of magic number 20
27. **6e0f3d53f** - Use explicit null for optional fields instead of omitting them
28. **88b211b67** - Decode dev_t into major and minor device numbers
29. **c6f18cd57** - Fix const char pointer warnings in su event encoding

### Configuration Fixes

30. **f03dd5254** - Change event_types default to none
31. **0b4781abe** - Rename event_types config option to events
32. **29019609c** - Fix events config: require explicit config, fix config map loading

### Documentation

33. **5be8f454c** - Add comprehensive improvements tracking document
34. **a541ac627** - Update IMPROVEMENTS.md to mark return value checking as complete

---

**Last Updated:** 2026-01-29
