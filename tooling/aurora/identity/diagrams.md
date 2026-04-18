# SummonerIdentity Diagrams

Structured rejection output convention used across workflows:
- Default reject behavior: method returns `None`
- With `return_status=True`: `{"ok": False, "code": "<reason>", "phase": "<method_phase>"}`
- Success with status: `{"ok": True, "code": "ok", "phase": "<method_phase>", "data": ...}`

Async note:
- `id(...)` is synchronous (typically called once at startup).
- Lifecycle methods shown in diagrams (`start/continue/advance_stream/seal/open`) are async in implementation.
- Custom hooks and `on_policy_event` handlers can be sync or async; async handlers are awaited.

Example:
```python
{"ok": False, "code": "session_verify_failed", "phase": "open_envelope"}
{"ok": True, "code": "ok", "phase": "open_envelope", "data": {"msg": "hi"}}
```

## 1) Message flow variants

Aurora uses two primary message-flow variants:
- `1a` encrypted per-peer flow (`to` is a peer identity),
- `1b` public discovery flow (`to=None`).

Use `1a` for normal peer conversations and `1b` for discovery or bootstrap.

### 1a) Request/response sequence (encrypted)

```text
Alice (role 0)                                              Bob (role 1)
    |                                                            |
    | start_session(peer=B)                                      |
    | seal_envelope(payload, to=B)                               |
    |----------------------------------------------------------->|
    |                                                            | open_envelope(env1)
    |                                                            |  - verify sender id
    |                                                            |  - verify envelope signature
    |                                                            |  - verify continuity
    |                                                            |  - decrypt payload
    |                                                            |
    |                                                            | continue_session(peer=A, peer_session=env1.session_proof)
    |                                                            | seal_envelope(reply, to=A)
    |<-----------------------------------------------------------|
    | open_envelope(env2)                                        |
    |  - verify sender id                                        |
    |  - verify envelope signature                               |
    |  - verify continuity                                       |
    |  - decrypt payload                                         |
    |  - if local_role=0 and sender_role=1 and response window valid:
    |      mark completed                                        |
```

Structured outputs commonly used in this flow:
- `start_session(..., return_status=True)`:
  - `active_session_exists`
  - `force_reset_failed`
  - `register_session_failed`
- `continue_session(..., return_status=True)`:
  - `invalid_peer_session`
  - `missing_or_expired_current_link`
  - `peer_session_mismatch`
  - `peer_sender_role_mismatch`
  - `register_session_failed`
- `seal_envelope(..., return_status=True)`:
  - `invalid_session`
  - `missing_or_expired_current_link`
  - `session_mismatch`
  - `register_session_failed`

Examples:
```python
{"ok": False, "code": "active_session_exists", "phase": "start_session"}
{"ok": False, "code": "peer_session_mismatch", "phase": "continue_session"}
{"ok": False, "code": "session_mismatch", "phase": "seal_envelope"}
```

### 1b) Public hello (`to=None`)

```text
Alice (role 0)                                              Bob (role 1)
    |                                                            |
    | start_session(None)                                        |
    | seal_envelope(payload, to=None)                            |
    |----------------------------------------------------------->|
    |                                                            | verify_discovery_envelope(env)
    |                                                            |  - validates sender identity + signature
    |                                                            |  - applies discovery-safe replay/session checks
    |                                                            |  - records peer learning and verification
    |                                                            |  - payload is plaintext JSON value
    |                                                            |
    | (discovery only; no per-peer continuity)                   |
    |                                                            |
    |<-----------------------------------------------------------|
    | Bob should reply by starting per-peer session:             |
    |     start_session(env["from"])                             |
```

Notes:
- `list_known_peers` / `find_peer` are discovery-cache queries by default.
- `list_verified_peers` is the safer selector for choosing conversation peers after
  successful `open_envelope(...)` / `verify_discovery_envelope(...)`.
- With custom peer store handler, keep fallback cache synchronized or provide your own query API.
- Successful `verify_discovery_envelope(...)` promotes the sender to a verified peer
  without committing generic session continuity.
- Service pattern: a central server can treat `to=None` as discovery ingress only,
  update a presence set (for example `online_agent_ids.add(env["from"])`), and
  reply on a per-peer encrypted path (`to=env["from"]`) with the latest presence view.

Structured outputs commonly seen in this flow:
- `invalid_session`, `discovery_requires_public_to_none`, `replay_detected`
- If encrypted payload is received with `to=None`: `encrypted_payload_without_to`

Examples:
```python
{"ok": False, "code": "invalid_session", "phase": "verify_discovery_envelope"}
{"ok": False, "code": "encrypted_payload_without_to", "phase": "verify_discovery_envelope"}
```

### 1c) Streamed turn sequence (`start -> chunk* -> end`)

```text
Alice (requester)                                           Bob (stream sender)
    |                                                            |
    | start_session(peer=B)                                      |
    | seal_envelope(request, to=B)                               |
    |----------------------------------------------------------->|
    |                                                            | open_envelope(request)
    |                                                            | continue_session(peer=A, stream=True, stream_ttl=30)
    |                                                            | seal_envelope(start frame, to=A)
    |<-----------------------------------------------------------|
    | open_envelope(start frame)                                 |
    |                                                            |
    |<-----------------------------------------------------------|
    | open_envelope(chunk frame)                                 |
    |                                                            | advance_stream_session(end_stream=False, stream_ttl=30)
    |                                                            | seal_envelope(chunk frame, to=A)
    |                                                            |
    |<-----------------------------------------------------------|
    | open_envelope(end frame)                                   |
    |                                                            | advance_stream_session(end_stream=True, ttl=120)
    |                                                            | seal_envelope(end frame, to=A)
```

Stream-specific outcomes often seen in status mode:
- continuity/state: `stream_not_active`, `stream_interrupted`, `stream_already_active`, `stream_active_continue_blocked`
- frame validity: `stream_phase_invalid`, `stream_seq_invalid`, `stream_ttl_expired`
- API/session validity: `invalid_stream_session`, `invalid_stream_mode`, `stream_ttl_invalid`, `stream_mode_unsupported`

The symmetric initiator-owned stream is also valid:
- replace Bob's `continue_session(..., stream=True, ...)` with Alice's
  `start_session(peer=B, stream=True, stream_ttl=30)`
- later `chunk` / `end` frames stay owned by the same sender role
- only the `phase="start"` frame is treated as start-form; `chunk` and `end`
  are continuation frames

## 2) Session boundary handling: sender vs receiver

These are two sides of the same boundary event (new thread start):
- Sender-side gate: "May I emit a start-form now?"
- Receiver-side gate: "Should I accept this incoming start-form?"

### 2a) Sender-side: `start_session` lifecycle policy

```text
start_session(peer)
|
+-- current_link(local_role=0) exists?
    |
    +-- No  -> CREATE new start-form
    +-- Yes
        |
        +-- stale/closed?
            |
            +-- Yes -> register_session(new=True, session_record=None)
            |             -> if fail: REJECT (register_session_failed)
            |             -> else: CREATE new start-form
            +-- No
                |
                +-- completed?
                    |
                    +-- Yes -> register_session(new=True, session_record=None)
                    |             -> if fail: REJECT (register_session_failed)
                    |             -> else: CREATE new start-form
                    +-- No
                        |
                        +-- force_reset?
                            |
                            +-- No  -> REJECT (active_session_exists)
                            +-- Yes -> reset_session hook/fallback
                                        -> if fail: REJECT (force_reset_failed)
                                        -> else: CREATE new start-form
```

Fallback reset semantics:
- archive summarizable completed current link
- drop incomplete current link
- clear active state
- staleness is stream-aware: a live stream stays active on its stream-progress
  window rather than only on the original requester-window `ttl`

Examples:
```python
{"ok": False, "code": "active_session_exists", "phase": "start_session"}
{"ok": False, "code": "force_reset_failed", "phase": "start_session"}
{"ok": False, "code": "register_session_failed", "phase": "start_session"}
```

### 2b) Receiver-side: start-form continuity check

Applies to both:
- per-peer envelopes (`to` is identity; peer slot keyed by sender identity)
- public envelopes (`to=None`; generic slot)

```text
Incoming session_proof
|
+-- start-form shape?  (not(x)_nonce is null AND x_nonce is present)
    |
    +-- No  -> route to ongoing-session checks
    +-- Yes
        |
        +-- current_link exists but is stale?
            |
            +-- Yes -> normalize to absent local state for start-form admission
            +-- No  -> keep current_link for replay/history checks
                |
                v
        +-- ts/ttl valid now?
            |
            +-- No  -> REJECT
            +-- Yes
                |
                +-- x_nonce replayed in current/seen/past?
                    |
                    +-- Yes -> REJECT
                    +-- No
                        |
                        +-- history_proof policy passes?
                            |
                            +-- No  -> REJECT
                            +-- Yes -> ACCEPT start-form
```

Rejection is surfaced from `open_envelope(..., return_status=True)` as `session_verify_failed`
for continuity failures, or earlier envelope-policy codes if pre-checks fail.

Note:
- This normalization rule applies only to fresh start-form admission.
- Ongoing-session checks still use the stored current link, and late/expired replies
  continue to fail closed instead of silently clearing local state.
- On an empty local slot:
  - proof-less bootstrap requires `history_proof is null` and `age == 0`
  - start forms that carry `history_proof` may still bootstrap if the proof
    decrypts correctly and `age == 0`

Examples:
```python
{"ok": False, "code": "session_verify_failed", "phase": "open_envelope"}
{"ok": False, "code": "to_identity_mismatch", "phase": "open_envelope"}
```

## 3) Ongoing continuity check

```text
Incoming non-start session_proof
|
+-- current link available and not expired?
    |
    +-- No  -> REJECT
    +-- Yes
        |
        +-- not(x)_nonce matches current?
            |
            +-- No  -> REJECT
            +-- Yes
                |
                +-- x_nonce fresh?
                    (not current, not in seen, not in past_chain)
                    |
                    +-- No  -> REJECT
                    +-- Yes -> ACCEPT update
```

Common rejections:
- `session_verify_failed` (continuity failure)
- `response_window_expired` (role-0 receives late reply outside allowed window)

Examples:
```python
{"ok": False, "code": "session_verify_failed", "phase": "open_envelope"}
{"ok": False, "code": "response_window_expired", "phase": "open_envelope"}
```

## 4) Failure handling (decrypt/signature and other checks)

```text
open_envelope(env)
|
+-- envelope shape/version valid?         no -> invalid_envelope / invalid_envelope_version
+-- identity + to checks valid?           no -> invalid_to_identity / to_identity_mismatch / invalid_envelope_fields
+-- timestamp policy valid?               no -> created_at_violation / clock_skew_violation / invalid_session_ts
+-- signature valid?                      no -> open_envelope_exception
+-- session continuity valid?             no -> session_verify_failed / response_window_expired
|                                             / stream_not_active / stream_interrupted
|                                             / stream_phase_invalid / stream_seq_invalid / stream_ttl_expired
+-- payload decrypt/parse valid?          no -> payload_decrypt_failed / encrypted_payload_without_to
+-- replay check pass?                    no -> replay_detected
+-- state commit succeeds?                no -> register_session_failed
+-- else ACCEPT payload
```

Failure handling rule:
- On invalid input/failure, return failure status (or `None`) and keep current chain state unchanged.
- `open_envelope(..., return_status=True)` returns statuses with `phase="open_envelope"`.

Representative codes from `open_envelope(..., return_status=True)`:
- Envelope/identity: `invalid_envelope`, `invalid_envelope_version`, `invalid_envelope_fields`,
  `invalid_to_identity`, `to_identity_mismatch`, `peer_key_check_failed`
- Timestamp policy: `created_at_violation`, `created_at_parse_error`, `invalid_session_ts`, `clock_skew_violation`
- Session/continuity: `session_verify_failed`, `response_window_expired`,
  `stream_not_active`, `stream_interrupted`, `stream_phase_invalid`, `stream_seq_invalid`, `stream_ttl_expired`
- Payload/decrypt: `encrypted_payload_without_to`, `payload_decrypt_failed`
- Replay/store: `replay_detected`, `register_session_failed`
- Catch-all: `open_envelope_exception`

Examples:
```python
{"ok": False, "code": "payload_decrypt_failed", "phase": "open_envelope"}
{"ok": False, "code": "replay_detected", "phase": "open_envelope"}
{"ok": False, "code": "open_envelope_exception", "phase": "open_envelope"}
```

## 5) Policy-event emission path (phase scoped)

```text
lifecycle API call
(start/continue/advance_stream/seal/open)
        |
        v
_ret(return_status, ok, code, data, phase, event_extra)
        |
        +--> _status(...) updates last_status
        |
        +--> _emit_result_policy_event(...)
               |
               +-- phase in ALLOWED_POLICY_PHASES ?
               |      no -> raise ValueError (developer wiring error)
               |
               +-- event_name = code
               +-- context = {
               |      schema_version, ts, phase, ok, code, has_data
               |   } + whitelisted event_extra
               |
               +-- dispatch handlers registered by on_policy_event(phase=...)
               |      (exceptions isolated/logged)
               |
               +-- no handler return value affects API result
        |
        v
return status dict (if return_status=True)
or data/None (default mode)
```

`open_envelope` telemetry highlights:
- failures add `validation_stage` (`structure|identity|signature|session|decrypt|replay|commit`)
- replay failures add `replay_store_mode` and `persist_replay`
- session outcomes may include `peer_fingerprint`, `session_form`, `sender_role`, `local_role`
- stream outcomes may include `stream_mode`, `stream_id`, `stream_phase`, `stream_seq`,
  `stream_policy`, `stream_reason`, `stream_ttl`, `stream_expired`,
  `stream_started_ts`, `stream_last_ts`, `stream_frame_count`
- `replaced_active_incomplete` is emitted on committed `ok` events only

## 6) Choosing a customization path

Customization is a scope decision. Use the built-in behavior when no custom
storage or trust rule is needed, then choose between class hooks, controls,
and local hooks based on how widely the rule should apply.

This section answers three questions:
- what can be attached to what,
- which hook wins when more than one scope is configured,
- and which customization mechanism best fits the rule you need to add.

### 6a) What can be attached to what?

This diagram shows the structural relationship between the agent, the active
identity, the optional controls object, and the hook scopes that can affect one
identity at runtime.

```text
SummonerAgent
    |
    +-- active identity ----------------------------------------+
                                                                |
                                                                v
                                                     SummonerIdentity
                                                                |
                                                                +-- attached controls object (0 or 1)
                                                                +-- local hook layer (0 or 1 per hook name)


SummonerIdentityControls
    |
    +-- zero to six configured hook callbacks


SummonerIdentity class
    |
    +-- process-wide class hooks
```

Key attachment facts:
- one identity has zero or one attached controls object at a time
- one controls object can define several hook callbacks
- one controls object may be reused across multiple identities when shared behavior is intentional
- a second `attach_controls(...)` call replaces the earlier attached controls object

### 6b) If more than one scope defines the same hook, which one wins?

Aurora resolves each hook name independently. The diagram below answers the
runtime question: "for this identity and this hook name, which implementation
will be used right now?"

```text
Need effective behavior for (identity, hook_name)
    |
    +-- local @identity.on_* hook present?
            |
            +-- Yes -> use local hook
            +-- No
                 |
                 +-- attached controls hook present?
                         |
                         +-- Yes -> use controls hook
                         +-- No
                              |
                              +-- class hook present?
                                      |
                                      +-- Yes -> use class hook
                                      +-- No -> use built-in fallback
```

Precedence summary:
- local hooks win for that one live identity object
- controls hooks apply next, but only for identities that attached that controls object
- class hooks provide the process-wide fallback
- built-in behavior is used only when no narrower scope defines that hook name

### 6c) Which customization mechanism should be used?

This decision tree starts from the practical question a developer usually asks:
"I need custom storage or trust behavior. Where should that behavior live?"

```text
Need custom storage or policy?
    |
    +-- No  -> use plain SummonerIdentity + built-in JSON stores
    |
    +-- Yes
         |
         +-- Should every SummonerIdentity in this process share it?
                 |
                 +-- Yes -> use class-level hooks (@SummonerIdentity.*)
                 +-- No
                      |
                      +-- Do you want a reusable named group of callbacks?
                              |
                              +-- Yes -> use SummonerIdentityControls + identity.attach_controls(...)
                              +-- No  -> use instance-local hooks (@identity.on_*)
```

Interpretation:
- choose plain `SummonerIdentity` when the built-in JSON stores and default verification are sufficient
- choose class hooks when every identity in the process should share the same rule
- choose `SummonerIdentityControls` when one identity needs a reusable attached control package
- choose local hooks when one live identity object needs a narrow direct override
