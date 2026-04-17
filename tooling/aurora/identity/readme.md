# SummonerIdentity Crypto Framework README

This page documents the public API exposed by the `tooling.aurora.identity` module: public constants, public functions, `SummonerIdentityControls`, and `SummonerIdentity` (methods and attributes). It also explains how the public operations compose into a typical messaging flow, where structured status outcomes fit, and how the phase-scoped policy event API can be used for operational telemetry.

Async note:
- `id(...)` is synchronous (typically called once at startup).
- Messaging/session lifecycle methods are async (`await identity.start_session(...)`, `await identity.seal_envelope(...)`, etc.).
- Hook surfaces and policy handlers may be synchronous or async.
- Snippet convention: blocks that include `await` start with `# inside an async function / handler` to keep examples concise.

Suggested order for initial use:

1. `Design intent`
2. `Wire formats`
3. `Session continuity rules`
4. `End-to-end examples`

The customization sections (`Storage hooks`, `SummonerIdentityControls`, instance hooks)
are easier to read after the basic flow already makes sense.

The documents around this README are meant to be used as a small reference
library. This file is the main API reference for `tooling.aurora.identity`. The
companion documents below cover the adjacent questions that are better handled
in dedicated notes.

### Companion documents inside `tooling/aurora/identity/`

| Document | Purpose |
| --- | --- |
| `cheatsheet.md` | Quick-start walkthroughs and side-by-side usage patterns |
| `streaming.md` | Streaming session rules, stream-specific states, and stream telemetry |
| `policy_event_api.md` | Phase-scoped policy-event telemetry model and event payload guidance |
| `identity_controls.md` | Identity-controls mental model, deployment patterns, and control-boundary examples |
| `diagrams.md` | Diagrams and visual mental models for identity, controls, and customization paths |
| `security_report.md` | Security interpretation, threat-oriented reasoning, and review-oriented discussion |

### Adjacent Aurora references outside `tooling/aurora/identity/`

| Document | Purpose |
| --- | --- |
| `tooling/aurora/identity_meta.md` | How `meta` affects fingerprints, public identity records, and continuity |
| `tooling/aurora/did_documentation.md` | Language-agnostic specification for the current Aurora agent identity record and local identity-file format |
| `tooling/aurora/versioning.md` | Version lifecycle across identity, host, agent, and merger surfaces |

## Contents

* [Design intent](#design-intent)
* [Wire formats](#wire-formats)
* [Session continuity rules](#session-continuity-rules)
* [History hash and history_proof](#history-hash-and-history_proof)
* [Storage hooks, controls, and fallback store](#storage-hooks-controls-and-fallback-store)
* [Hook precedence and safety](#hook-precedence-and-safety)
* [Structured outcomes (optional)](#structured-outcomes-optional)
* [Policy event API (phase-scoped telemetry)](#policy-event-api-phase-scoped-telemetry)
* [Hook surfaces](#hook-surfaces)
* [Fallback stores](#fallback-stores)
* [Public constants](#public-constants)
* [Public functions](#public-functions)

  * [`b64_encode`](#b64_encode)
  * [`b64_decode`](#b64_decode)
  * [`serialize_public_key`](#serialize_public_key)
  * [`sign_bytes`](#sign_bytes)
  * [`verify_bytes`](#verify_bytes)
  * [`sign_public_id`](#sign_public_id)
  * [`verify_public_id`](#verify_public_id)
  * [`id_fingerprint`](#id_fingerprint)
  * [`save_identity`](#save_identity)
  * [`load_identity`](#load_identity)
  * [`session_summary`](#session_summary)
  * [`hist_next`](#hist_next)
  * [`derive_sym_key`](#derive_sym_key)
  * [`derive_history_proof_key`](#derive_history_proof_key)
  * [`derive_payload_key`](#derive_payload_key)
* [Class: `SummonerIdentityControls`](#class-summoneridentitycontrols)

  * [`version`](#version)
  * [`configured_hooks`](#configured_hooks)
  * [`clear`](#clear)
  * [Controls hook decorators](#controls-hook-decorators)
* [Class: `SummonerIdentity`](#class-summoneridentity)

  * [Public attributes](#public-attributes)
  * [`store_versions`](#store_versions)
  * [`controls_version`](#controls_version)
  * [`__init__`](#__init__)
  * [`on_policy_event`](#on_policy_event)
  * [`attach_controls`](#attach_controls)
  * [`detach_controls`](#detach_controls)
  * [`require_controls`](#require_controls)
  * [`has_controls`](#has_controls)
  * [`clear_local_hooks`](#clear_local_hooks)
  * [Instance hook decorators](#instance-hook-decorators)
  * [`classify_session_record`](#classify_session_record)
  * [Default Delegates for Handlers](#default-delegates-for-handlers)
  * [`get_current_session`](#get_current_session)
  * [`verify_session_record`](#verify_session_record)
  * [`register_session_record`](#register_session_record)
  * [`force_reset_session`](#force_reset_session)
  * [`register_session`](#register_session)
  * [`reset_session`](#reset_session)
  * [`verify_session`](#verify_session)
  * [`get_session`](#get_session)
  * [`peer_key_store`](#peer_key_store)
  * [`replay_store`](#replay_store)
  * [`list_known_peers`](#list_known_peers)
  * [`list_verified_peers`](#list_verified_peers)
  * [`find_peer`](#find_peer)
  * [`id`](#id-method)
  * [`update_id_meta`](#update_id_meta)
  * [`start_session`](#start_session)
  * [`continue_session`](#continue_session)
  * [`advance_stream_session`](#advance_stream_session)
  * [`seal_envelope`](#seal_envelope)
  * [`open_envelope`](#open_envelope)
  * [`verify_discovery_envelope`](#verify_discovery_envelope)
* [End-to-end examples](#end-to-end-examples)

  * [Two-party encrypted conversation](#two-party-encrypted-conversation)
  * [Streamed response turn](#streamed-response-turn)
  * [Plaintext envelope (to=None)](#plaintext-envelope-to-none)
  * [Custom session storage hooks](#custom-session-storage-hooks)
* [Notes for implementers](#notes-for-implementers)

## Design intent

The protocol uses a **nonce-chain** to track continuity. The only orientation field is:

* `sender_role: 0|1`

There are **no explicit message types** (`init`, `response`), and the first signed message is treated as the handshake.

The scheme is intentionally minimal:

* **Signed envelopes** always authenticate `payload`, `session_proof`, and identities.
* **Optional encryption** happens when a receiver identity (`to`) is present.
* **Replay and continuity** are enforced by strict nonce-chain rules.
* **History** is a rolling hash of completed exchanges, used for continuity in new sessions.

## Wire formats

### Identity (public record)

```json
{
  "created_at": "<iso_utc>",
  "pub_enc_b64": "<x25519 raw b64>",
  "pub_sig_b64": "<ed25519 raw b64>",
  "meta": "<optional>",
  "sig": "<ed25519 signature over canonical core>",
  "v": "id.v1"
}
```

**Why:** The self-signature proves internal consistency. It does *not* prove real-world identity.
`meta` is optional metadata, not authoritative identity.

### Session proof (embedded in envelope)

```json
{
  "sender_role": 0,
  "0_nonce": "<hex>",
  "1_nonce": "<hex or null>",
  "ts": 1730000000,
  "ttl": 86400,
  "history_proof": "<object or null>",
  "age": 3,
  "mode": "single|stream",
  "stream": "null|{id,seq,phase}",
  "stream_ttl": "null|int"
}
```

**Convention:** If `sender_role = x`, then:

* `x_nonce` is the *fresh* nonce generated by the sender.
* `not(x)_nonce` is the last nonce observed from the peer.

**Important precision**

* There is no `session_proof` version field.
* For per-peer start messages, `history_proof` is an object:

```json
{
  "v": "histproof.v1",
  "nonce": "<b64>",
  "ciphertext": "<b64>"
}
```

* For public `to=None` starts and non-start updates, `history_proof` is `null`.
* `mode="single"` requires `stream=null` and `stream_ttl=null`.
* `mode="stream"` requires a valid `stream` object; non-end stream frames require positive `stream_ttl`.

### Session proof variants (compact appendix)

Per-peer start (`start_session(peer_public_id)`):

```json
{
  "sender_role": 0,
  "0_nonce": "<hex>",
  "1_nonce": null,
  "ts": 1730000000,
  "ttl": 86400,
  "history_proof": {
    "v": "histproof.v1",
    "nonce": "<b64>",
    "ciphertext": "<b64>"
  },
  "age": 3
}
```

Public start (`start_session(None)`):

```json
{
  "sender_role": 0,
  "0_nonce": "<hex>",
  "1_nonce": null,
  "ts": 1730000000,
  "ttl": 86400,
  "history_proof": null,
  "age": 0
}
```

Continue/reply (`continue_session(...)`):

```json
{
  "sender_role": 1,
  "0_nonce": "<hex>",
  "1_nonce": "<hex>",
  "ts": 1730000012,
  "ttl": 86400,
  "history_proof": null,
  "age": "<preserved continuity age>",
  "mode": "single",
  "stream": null,
  "stream_ttl": null
}
```

Stream start (`start_session(..., stream=True, stream_ttl=...)` or `continue_session(..., stream=True, stream_ttl=...)`):

Initiator-owned stream start (`start_session(..., stream=True, ...)`):

```json
{
  "sender_role": 0,
  "0_nonce": "<hex>",
  "1_nonce": null,
  "ts": 1730000012,
  "ttl": 120,
  "history_proof": {
    "v": "histproof.v1",
    "nonce": "<b64>",
    "ciphertext": "<b64>"
  },
  "age": 3,
  "mode": "stream",
  "stream": {"id": "<stream_id>", "seq": 0, "phase": "start"},
  "stream_ttl": 60
}
```

Responder-owned stream start (`continue_session(..., stream=True, ...)`):

```json
{
  "sender_role": 1,
  "0_nonce": "<hex>",
  "1_nonce": "<hex>",
  "ts": 1730000012,
  "ttl": 120,
  "history_proof": null,
  "age": "<preserved continuity age>",
  "mode": "stream",
  "stream": {"id": "<stream_id>", "seq": 0, "phase": "start"},
  "stream_ttl": 60
}
```

Age note:

* `continue_session(...)` and responder-owned stream starts normally preserve the
  active continuity age rather than resetting it to zero.
* `age = 0` is still expected on proof-less bootstrap cases where no prior local
  continuity exists.

Stream chunk/end (`advance_stream_session(...)`):

For stream-mode records, only `phase="start"` is treated as start-form. Later
`chunk` and `end` frames are continuation forms, even when an initiator-owned
stream keeps `1_nonce = null` across its frames.

```json
{
  "sender_role": 0,
  "0_nonce": "<hex>",
  "1_nonce": null,
  "ts": 1730000020,
  "ttl": 120,
  "history_proof": null,
  "age": 3,
  "mode": "stream",
  "stream": {"id": "<stream_id>", "seq": 1, "phase": "chunk|end"},
  "stream_ttl": "60 for chunk, null for end"
}
```

### Envelope

```json
{
  "v": "env.v1",
  "payload": "<JSON-serializable value or encrypted payload object>",
  "session_proof": "<session proof>",
  "from": "<sender public identity>",
  "to": "<receiver public identity or null>",
  "sig": "<ed25519 signature over canonical envelope core>"
}
```

If `to` is present, payload is encrypted and stored as:

```json
{
  "v": "payload.enc.v1",
  "nonce": "<b64>",
  "ciphertext": "<b64>"
}
```

## Session continuity rules

### Start-form rules

When there is no current session or the stored current link is stale (or the peer presents a valid start‑form reset):

* `not(x)_nonce` must be `null`
* `x_nonce` must be present
* `history_proof/age` must be consistent with local history or restart-convergence state
* If local history is empty and no current link is active:
  * proof-less bootstrap is accepted only when `history_proof is null` and `age == 0`
  * a well-formed `history_proof` may still bootstrap if it decrypts successfully and `age == 0`
* Fresh start-form admission treats a stale current link as absent local state.
  For stream-active links, staleness is evaluated from stream progress
  (`stream_last_ts + stream_ttl`) rather than only from the original requester-window `ttl`.

### Ongoing rules

When a session exists:

1. `not(x)_nonce` must match the stored current nonce of the peer.
2. `x_nonce` must be fresh:
   * not equal to current `x_nonce`
   * not present in past_chain
   * not present in current link `seen`

The `seen` list is a **minimal replay defense** for messages inside the same in‑progress conversation.

## Replay handling (step‑by‑step)

This protocol uses two replay defenses:

1. **Nonce‑chain + `seen` list** (session‑scoped)
2. **Replay cache** (message‑id based, optional persistence)

### A) Nonce‑chain replay defense (session‑scoped)

**Inbound start‑form**

1. `not(x)_nonce` must be `null` and `x_nonce` must be present.
2. Reject if the start‑form nonce is already in the current `seen` list.
3. Reject if the start‑form nonce appears in `past_chain`.
4. Reject if the start‑form's own `ts/ttl` window is already expired.
5. If `history_proof` exists, decrypt and validate it against local history.

**Inbound ongoing message**

1. Require an active `current_link` (not expired).
2. `not(x)_nonce` must match the stored peer nonce.
3. `x_nonce` must be fresh:
   - not equal to current `x_nonce`,
   - not present in `past_chain`,
   - not present in current `seen` list.
4. Reject if the stored link is expired by `ts/ttl` (with margin).

### B) Replay cache (message‑id based)

This replay cache check is always active:
- custom replay controls when `@SummonerIdentity.replay_store` is provided,
- otherwise fallback in-memory cache,
- optionally persisted to disk when `persist_replay=True`.

1. `open_envelope(...)` derives a stable `message_id` from:
   - sender public key fingerprint + envelope signature.
2. If the `message_id` already exists in the replay cache, the envelope is rejected.
3. Otherwise, it is recorded with expiry `now + ttl`.

**When it helps**

* Prevents replay across process restarts.
* Adds protection for public `to=None` flows.
* Works even if `seen` is cleared (e.g., after a crash).

**When it is not sufficient by itself**

* It does not enforce ordering or concurrency (that still depends on the nonce‑chain).

## History hash and history_proof

### History

Each completed exchange produces:

```
session_summary = H("summoner-link-v1" || 0_nonce || 1_nonce || ts || ttl)
hist_next = H(prev_hist || session_summary)
```

History is only updated when a **completed** link is finalized.

### `history_proof`

`history_proof` is an AEAD‑encrypted proof that binds a peer's claimed history hash to the new session:

Plaintext (example):

```json
{
  "0_nonce": "...",
  "1_nonce": null,
  "history_hash": "...",
  "age": 3
}
```

**Key derivation:** `derive_history_proof_key(sym_key, aad_bytes)`  
**AAD binds** identity direction, sender_role, ts, ttl, and version.

## Storage hooks, controls, and fallback store

If the normal `id(...) -> start_session(...) -> seal/open -> continue_session(...)`
workflow already matches application requirements, this section is only
necessary when custom storage or policy behavior is required. It can be read
later without affecting the rest of the API.

`SummonerIdentity` supports four ways to handle persistence and policy:

* built-in JSON fallback stores,
* class-level hooks,
* per-instance controls objects,
* instance-local hooks.

The most important structural rule is that one `SummonerIdentity` has zero or
one attached controls object at a time. A controls object can package several
hook callbacks, and the same controls object may be reused across multiple
identities when that is intentional.

The main selection guidance is:

* Start with the built-in JSON stores.
* Use `SummonerIdentityControls` when one `SummonerIdentity` object needs its own reusable set of storage or trust hooks.
* Use class-level hooks when every `SummonerIdentity` in the process should behave the same way.
* Use instance-local `@identity.on_*` hooks when one live object needs a narrow override and no reusable bundle is required.

### Which option should I pick?

| Situation | Recommended choice | Why |
| --- | --- | --- |
| You want a local SDK with no custom storage | Fallback stores | Lowest complexity; nothing extra to wire |
| Every identity in this Python process should share one policy | Class-level hooks | One place to define process-wide behavior |
| One specific identity instance needs custom storage or policy | `SummonerIdentityControls` | Per-instance customization without changing global behavior |
| One live identity object needs a one-off override | Instance-local hooks (`@identity.on_*`) | Smallest scope; stays attached to that one object |

### Mental model table

| Question | Most accurate answer |
| --- | --- |
| How many controls objects can one identity have attached at once? | Zero or one |
| How many hooks can one controls object define? | Zero to six hook callbacks |
| Can several identities share one controls object? | Yes, if shared behavior is intentional |
| What happens if `attach_controls(...)` is called twice on the same identity? | The second controls object replaces the first |
| What is the difference between controls and local hooks? | Controls are a separate reusable attached object; local hooks live directly on one identity instance |

### What `SummonerIdentityControls` does

`SummonerIdentityControls` is not a second identity engine and it does not do crypto by itself.

It is a small object that groups callbacks such as:

* `get_session`
* `register_session`
* `verify_session`
* `peer_key_store`
* `replay_store`

You attach that object to one `SummonerIdentity` instance with `identity.attach_controls(...)`.

This creates a middle ground that is:

* more structured and reusable than scattering `@identity.on_*` hooks directly on the instance,
* more isolated than class-level hooks, which affect every `SummonerIdentity` in the process.

### Operational purpose

In Aurora, a common deployment shape is:

* one `SummonerAgent` runtime,
* several prepared `SummonerIdentity` objects,
* and zero or more `SummonerIdentityControls` objects attached to those identities.

The agent binds one identity at a time with `attach_identity(...)`, but each
identity can already carry its own controls object before it is attached.

That means the most common reason for `SummonerIdentityControls` is:

* one agent or process holds several identity instances,
* but they should not share the same storage or policy.

For example:

* `alice` can keep using the built-in JSON files,
* `bob` can use a custom controls object that stores session state elsewhere,
* and neither one has to change the other.

More concrete Aurora-style example:

* one orchestrator agent keeps several prepared identities,
* one room identity wants custom replay/session checks and wants to persist
  continuity in a service or database,
* one observer identity can stay on the built-in JSON files,
* class-level hooks would affect all of them,
* instance-local hooks would work, but the controls object keeps the whole
  custom policy grouped with the right identity.

The first sketch shows the minimal explicit pattern: create the controls
object, attach it to the identity that needs it, then define the hook.

```python
from tooling.aurora import SummonerAgent, SummonerIdentity, SummonerIdentityControls

agent = SummonerAgent(name="room-orchestrator")

room_identity = SummonerIdentity()
observer_identity = SummonerIdentity()

room_identity.id("room.json")
observer_identity.id("observer.json")

identity_pool = {
    "room": room_identity,
    "observer": observer_identity,
}

room_controls = SummonerIdentityControls()
room_identity.attach_controls(room_controls)

@room_controls.on_peer_key_store
def peer_store(identity, peer_public_id, update=None):
    return identity.peer_key_store_default(peer_public_id, update=update)

agent.attach_identity(identity_pool["room"])
```

The next sketch adds two controls hooks to the same identity so the whole
custom policy remains grouped in one place.

```python
from tooling.aurora import SummonerAgent, SummonerIdentity, SummonerIdentityControls

agent = SummonerAgent(name="room-orchestrator")

room_identity = SummonerIdentity()
observer_identity = SummonerIdentity()

room_identity.id("room.json")
observer_identity.id("observer.json")

identity_pool = {
    "room": room_identity,
    "observer": observer_identity,
}

room_controls = SummonerIdentityControls()
room_identity.attach_controls(room_controls)

@room_controls.on_replay_store
def replay_store(identity, message_id, ttl, now=None, add=False):
    return identity.replay_store_default(message_id, ttl=ttl, now=now, add=add)

@room_controls.on_verify_session
def verify(identity, peer_public_id, local_role, session_record, use_margin=False):
    base = identity.verify_session_default(
        peer_public_id,
        local_role,
        session_record,
        use_margin=use_margin,
    )
    if not base.get("ok"):
        return base
    # Insert GM-only allowlist / room / tournament policy here.
    return base
```

In that sketch:

* `gm` gets the custom identity policy,
* `bot` keeps the normal built-in behavior,
* both identities still live in the same Python process.

The sections below describe status behavior, policy telemetry, and the storage interfaces.

## Hook precedence and safety

Hook resolution is deterministic:

1. instance-local hook (`@identity.on_*`)
2. attached controls (`identity.attach_controls(...)`)
3. class-level hook (`@SummonerIdentity.*`)
4. built-in fallback behavior

This precedence is implemented in `SummonerIdentity._resolve_hook_source(...)`.

Important consequences:

* Local hooks override controls hooks.
* Controls hooks override class hooks.
* `clear_local_hooks()` only clears the instance-local layer. It does not detach the controls.
* Controls callbacks receive the owning `SummonerIdentity` instance as their first argument.
* Class hooks and instance-local hooks keep the original decorator signature.

Compact resolution diagram:

```text
local @identity.on_* ?
    yes -> use local hook
    no  -> attached controls hook?
              yes -> use controls hook
              no  -> class hook?
                        yes -> use class hook
                        no  -> use built-in fallback
```

Safety rule:

* If `register_session` is customized, `verify_session` must also be customized in the same hook scope.
* “Same scope” means local-with-local, controls-with-controls, or class-with-class.
* Mixing `register_session` from controls scope with `verify_session` from class scope, for example, raises `ValueError`.

This fail-fast rule exists because persistence and verification must agree on lane keying, continuity shape, and expiry semantics.

## Structured outcomes (optional)

Core lifecycle methods support `return_status=True`:
* `start_session`
* `continue_session`
* `advance_stream_session`
* `seal_envelope`
* `open_envelope`
* `verify_discovery_envelope`

When enabled, they return a status object:
* `{"ok": True, "code": "ok", "phase": "<method_phase>", "data": ...}`
* `{"ok": False, "code": "<reason>", "phase": "<method_phase>"}` on failure

Default behavior is unchanged: success returns data, failure returns `None`.

`phase` values emitted by lifecycle methods are:
* `start_session`
* `continue_session`
* `advance_stream_session`
* `seal_envelope`
* `open_envelope`
* `verify_discovery_envelope`

### Rejection codes (reference)

Common `code` values by method when `return_status=True`:

* `start_session`:
  * `active_session_exists`
  * `force_reset_failed`
  * `register_session_failed`
  * `stream_mode_unsupported`
  * `stream_ttl_invalid`
* `continue_session`:
  * `invalid_peer_session`
  * `missing_or_expired_current_link`
  * `peer_session_mismatch`
  * `peer_sender_role_mismatch`
  * `register_session_failed`
  * `stream_mode_unsupported`
  * `stream_ttl_invalid`
  * `stream_active_continue_blocked`
* `advance_stream_session`:
  * `stream_mode_unsupported`
  * `invalid_stream_session`
  * `stream_ttl_invalid`
  * `stream_not_active`
  * `stream_interrupted`
  * `register_session_failed`
* `seal_envelope`:
  * `invalid_session`
  * `invalid_stream_mode`
  * `invalid_stream_fields`
  * `stream_mode_unsupported`
  * `stream_ttl_invalid`
  * `missing_or_expired_current_link`
  * `session_mismatch`
  * `register_session_failed`
* `open_envelope`:
  * envelope/identity: `invalid_envelope`, `invalid_envelope_version`, `invalid_envelope_fields`,
    `invalid_to_identity`, `to_identity_mismatch`, `peer_key_check_failed`
  * timestamp policy: `created_at_violation`, `created_at_parse_error`, `invalid_session_ts`, `clock_skew_violation`
  * continuity: `session_verify_failed`, `response_window_expired`
  * stream continuity: `invalid_stream_mode`, `invalid_stream_fields`, `stream_mode_unsupported`,
    `stream_phase_invalid`, `stream_seq_invalid`, `stream_state_conflict`, `stream_not_active`,
    `stream_already_active`, `stream_ttl_invalid`, `stream_ttl_expired`, `stream_interrupted`
  * payload/decrypt: `encrypted_payload_without_to`, `payload_decrypt_failed`
  * replay/store: `replay_detected`, `register_session_failed`
  * catch-all: `open_envelope_exception`
* `verify_discovery_envelope`:
  * envelope/identity: `invalid_envelope`, `invalid_envelope_version`, `invalid_envelope_fields`,
    `discovery_requires_public_to_none`, `peer_key_check_failed`
  * timestamp policy: `created_at_violation`, `created_at_parse_error`, `invalid_session_ts`, `clock_skew_violation`
  * session semantics: `invalid_session`, `stream_mode_unsupported`
  * signature/decrypt/replay: `encrypted_payload_without_to`, `replay_detected`
  * catch-all: `verify_discovery_envelope_exception`

Streaming note:
* With boolean-only custom verify hooks, detailed stream failures may collapse to `session_verify_failed`.

`continue_session` note:
* On role-0 recovery, `continue_session` may call `start_session(...)` internally and
  therefore return `start_session` codes/phases (for example `active_session_exists`).

Example:
```python
# inside an async function / handler
st = await identity.open_envelope(env, return_status=True)
if not st["ok"] and st["code"] == "session_verify_failed":
    # decide app-level recovery/retry policy
    ...
```

Important:
* Structured outcomes cover protocol decision failures.
* Programmer-misuse/precondition errors still raise `ValueError` (for example:
  calling methods before `id(...)`, or defining `register_session` without `verify_session`
  in the same hook scope).

### Decision matrix (recommended caller actions)

| Method | `code` | Typical meaning | Recommended caller action |
|---|---|---|---|
| `start_session` | `active_session_exists` | Active thread still open | Wait for reply, or call explicit `force_reset=True` if policy allows |
| `start_session` | `force_reset_failed` | Reset hook/store rejected reset | Surface to operator/app policy; do not proceed blindly |
| `start_session` | `register_session_failed` | Store/hook persistence failure | Retry after store recovery; keep message unsent |
| `continue_session` | `invalid_peer_session` | Malformed peer session proof | Drop message as invalid input |
| `continue_session` | `missing_or_expired_current_link` | Local continuity context missing/expired | If role-0 path: restart; if role-1 path: give up and wait for fresh start |
| `continue_session` | `peer_session_mismatch` | Peer proof does not match expected current link | Drop and await clean restart |
| `continue_session` | `peer_sender_role_mismatch` | Role orientation mismatch | Drop as protocol misuse/input error |
| `continue_session` | `stream_active_continue_blocked` | Non-stream continue attempted while stream turn is active | Continue same stream path or wait for stream end |
| `seal_envelope` | `invalid_session` | Caller passed malformed session dict | Fix caller logic; do not retry unchanged |
| `seal_envelope` | `invalid_stream_*` / `stream_ttl_invalid` | Outbound stream schema/timing fields invalid | Rebuild session proof via API (`start/continue/advance`) |
| `seal_envelope` | `missing_or_expired_current_link` | Session context expired before send | Recompute via `start_session` / `continue_session` |
| `seal_envelope` | `session_mismatch` | Provided session differs from stored current link | Rebuild from latest local state |
| `advance_stream_session` | `invalid_stream_session` | Input is not a valid active stream proof | Use last valid stream proof returned by API |
| `advance_stream_session` | `stream_not_active` / `stream_interrupted` | Stream is closed/mismatched | Start a new turn or new stream according to role |
| `open_envelope` | `invalid_envelope*` / `to_identity_mismatch` | Envelope malformed or misaddressed | Drop; optionally log sender diagnostics |
| `open_envelope` | `session_verify_failed` | Continuity/history check failed | Drop; keep state unchanged; wait for valid restart |
| `open_envelope` | `stream_ttl_expired` | Inbound non-end stream frame is late (`ts + stream_ttl` exceeded) | Drop frame; expect closure/restart path |
| `open_envelope` | `stream_interrupted` | Frame targets closed/interrupted stream state | Drop and wait for explicit new stream start |
| `open_envelope` | `response_window_expired` | Reply arrived too late for completion window | Drop late response; start fresh thread if needed |
| `open_envelope` | `payload_decrypt_failed` | Payload integrity/decrypt failure | Drop as tampered/corrupt |
| `open_envelope` | `replay_detected` | Duplicate envelope | Ignore duplicate |
| `open_envelope` | `register_session_failed` | Commit failed after validation | Retry only after storage recovers |
| `open_envelope` | `open_envelope_exception` | Unexpected exception path | Log with telemetry; treat as invalid input |

## Policy event API (phase-scoped telemetry)

`SummonerIdentity` supports phase-scoped telemetry handlers via:

* `on_policy_event(phase=...)`

This API is per-instance and emitted from the same return path used by structured outcomes (`_ret(...)`).
Lifecycle methods are async, and policy handlers may be synchronous or async.

### Registration and phase model

Allowed phases:

* `start_session`
* `continue_session`
* `advance_stream_session`
* `seal_envelope`
* `open_envelope`

Invalid phase registration raises `ValueError`.
Emission also validates phase internally; invalid emission phase is treated as a
developer wiring error and raises `ValueError`.

Handlers are called in registration order, and multiple handlers per phase are supported.
Handler exceptions are isolated: they are caught, logged, and do not change API return behavior.

### Handler signature

```python
@identity.on_policy_event(phase="open_envelope")
def on_open(event_name: str, context: dict) -> None:
    ...
```

Where:

* `event_name == code` (same string used in structured outcomes).
* `context` includes common fields and optional event-specific telemetry fields.

### Common context fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | `int` | Event schema version (`1`). |
| `ts` | `int` | Unix timestamp of event emission. |
| `phase` | `str` | Emission phase (`start_session`, `continue_session`, `advance_stream_session`, `seal_envelope`, `open_envelope`). |
| `ok` | `bool` | Success flag. |
| `code` | `str` | Same value as `event_name`. |
| `has_data` | `bool` | Whether the operation returned data. |

### Event-specific context fields (`open_envelope`)

| Field | Emitted on | Notes |
|---|---|---|
| `peer_fingerprint` | `ok`, `session_verify_failed`, `replay_detected`, `response_window_expired`, and stream-prefixed codes | Present when derivable from validated sender identity. |
| `session_form` | same as above | `start` or `continue`. |
| `sender_role` | same as above | `0` or `1` when derivable. |
| `local_role` | same as above | Counterpart role (`1 - sender_role`). |
| `replaced_active_incomplete` | `ok` only | True when committed start-form replaced unexpired incomplete active link. |
| `validation_stage` | failure events | One of `structure`, `identity`, `signature`, `session`, `decrypt`, `replay`, `commit`. |
| `replay_store_mode` | `replay_detected` | `memory`, `disk`, or `custom`. |
| `persist_replay` | `replay_detected` | Whether replay state persists to disk. |

### Stream telemetry context fields (`open_envelope`, stream-related outcomes)

| Field | Meaning |
|---|---|
| `stream_mode` | Parsed mode (`single` or `stream`) from session proof classification. |
| `stream_id` | Stream identity value from session proof. |
| `stream_phase` | Stream phase (`start`, `chunk`, `end`) from session proof. |
| `stream_seq` | Stream sequence index from session proof. |
| `stream_policy` | Current verifier policy label (`contiguous`). |
| `stream_ttl` | Stream TTL value when present. |
| `stream_expired` | Record-local stream-expiry indicator from classifier context. |
| `stream_reason` | Structured verify reason (or persisted interruption reason when available). |
| `stream_started_ts` | Optional stream start timestamp when known at emitter. |
| `stream_last_ts` | Optional timestamp of latest stream frame when known at emitter. |
| `stream_frame_count` | Optional derived count (`stream_seq + 1`) when known at emitter. |

Operational note:
* After timeout closure, later frames on the same closed stream may emit `stream_interrupted` with `stream_reason="timeout_closed"` (fallback path).

### Method to phase mapping

| Method | Emitted phase |
|---|---|
| `start_session(...)` | `start_session` |
| `continue_session(...)` | `continue_session` |
| `advance_stream_session(...)` | `advance_stream_session` |
| `seal_envelope(...)` | `seal_envelope` |
| `open_envelope(...)` | `open_envelope` |
| `verify_discovery_envelope(...)` | `verify_discovery_envelope` |

Note: `continue_session(...)` may internally restart via `start_session(...)` on the
`local_role == 0` recovery path. In that branch, emitted phase/status comes from
`start_session`.

### Example instrumentation

```python
from collections import Counter

metrics = Counter()

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    metrics[f"open:{event_name}"] += 1
    if ctx.get("validation_stage"):
        metrics[f"open_stage:{ctx['validation_stage']}"] += 1
    if event_name == "ok" and ctx.get("replaced_active_incomplete") is True:
        metrics["open:reset_like_accept"] += 1
```

## Hook surfaces

You can customize identity behavior in three public ways.

### 1. Class-level hooks

These affect all `SummonerIdentity` instances in the process:

* `@SummonerIdentity.register_session`
* `@SummonerIdentity.reset_session`
* `@SummonerIdentity.verify_session`
* `@SummonerIdentity.get_session`
* `@SummonerIdentity.peer_key_store`
* `@SummonerIdentity.replay_store`

Use this when the whole process shares one integration policy.

### 2. Attached controls objects

`SummonerIdentityControls` is a reusable controls object for one identity instance.

The following model is precise:

* `SummonerIdentity` is the engine.
* `SummonerIdentityControls` is a named group of storage / policy callbacks for one engine instance.
* `SummonerAgent` may prepare several identity objects, but it binds only one of them at a time.

Normal operation does not require this feature. When the built-in JSON stores
are sufficient, no controls object is necessary.

A controls object is appropriate when:

* one identity instance needs custom storage or policy,
* one agent or process keeps several prepared identities and only some need special rules,
* you want that customization to be easy to name, attach, detach, and test,
* and you do not want to affect every identity instance in the process.

Typical flow:

```python
controls = SummonerIdentityControls()

@controls.on_verify_session
def verify(identity, peer_public_id, local_role, session_record, use_margin=False):
    return identity.verify_session_default(
        peer_public_id,
        local_role,
        session_record,
        use_margin=use_margin,
    )

identity.attach_controls(controls)
```

Operational effect:

* per-instance behavior,
* reusable hook registration in one place,
* cleaner integration code than scattering many `@identity.on_*` decorators.

A controls object is usually unnecessary when:

* do not use it just because it exists,
* do not use it when fallback stores are already enough,
* do not use it when the whole process should share one global hook policy.

### 3. Instance-local hooks

These affect only one live instance:

* `@identity.on_register_session`
* `@identity.on_reset_session`
* `@identity.on_verify_session`
* `@identity.on_get_session`
* `@identity.on_peer_key_store`
* `@identity.on_replay_store`

Instance-local hooks are appropriate when the narrowest possible override is required.

**Critical rule:** If you define `register_session`, you must define `verify_session` in the same hook scope.  
Otherwise the class raises, because it cannot safely guess your verification logic.

If you use `force_reset` with custom storage, also define `reset_session` in that same model so active state can be force-closed consistently with your history model.

## Fallback stores

Stores JSON files next to the identity file by default (or under `store_dir`).

* `sessions.json`: session continuity state
* `peer_keys.json`: fingerprint-indexed peer cache + metadata
* `replay.json`: optional replay cache (only if `persist_replay=True`)

**Persistence controls**

* `persist_local=False` disables on-disk writes for all fallback stores.
* `load_local=False` skips reading fallback stores during `id(...)`.
* `persist_replay=True` enables disk persistence for `replay.json` (otherwise in-memory only).

All three files are written as wrapped versioned documents:

```json
{
  "__summoner_identity_store__": "<sessions|peer_keys|replay>",
  "v": "<store version string>",
  "data": { "...": "..." }
}
```

The store-version strings are:

* `sessions.store.v1`
* `peer_keys.store.v1`
* `replay.store.v1`

Use `SummonerIdentity.store_versions()` if you want to query them programmatically.

Store loading rules:

* the file must be a wrapped store document with `__summoner_identity_store__`, `v`, and `data`,
* unsupported versions are rejected fail-closed,
* malformed documents are rejected fail-closed.

### `sessions.json` inner `data` schema

```json
{
  "<peer_fingerprint>:<local_role>": {
    "peer_id": "<fingerprint>",
    "local_role": 0,
    "active": true,
    "past_chain": [{"0_nonce": "...", "1_nonce": "...", "delta_t": 9}],
    "current_link": {
      "0_nonce": "...",
      "1_nonce": "...",
      "ts": 123,
      "ttl": 456,
      "completed": false,
      "seen": ["..."],
      "stream_mode": "single|stream",
      "stream_id": "optional stream id",
      "stream_phase": "start|chunk|end|interrupted|null",
      "expected_next_seq": 2,
      "stream_active": true,
      "stream_last_ts": 123,
      "stream_ttl": 60,
      "missing_ranges": [],
      "stream_reason": "optional interruption reason"
    },
    "history": [{"hash": "...", "age": 2, "ts": 120}],
    "window": 20
  }
}
```

### `peer_keys.json` inner `data` schema

```json
{
  "<fingerprint>": {
    "public_id": "<full public identity record>",
    "pub_sig_b64": "<ed25519 raw b64>",
    "fingerprint": "<id_fingerprint(pub_sig_b64)>",
    "meta": "<optional metadata>",
    "first_seen": 1730000000,
    "last_seen": 1730000000
  }
}
```

### `replay.json` inner `data` schema

```json
{
  "items": {
    "<message_id>": {"exp": 1730000000}
  }
}
```

## Public constants

These constants are part of the wire format, fallback-store format, and/or domain separation.

```python
ID_VERSION: str
ENV_VERSION: str
PAYLOAD_ENC_VERSION: str
HISTORY_PROOF_VERSION: str
SESSIONS_STORE_VERSION: str
PEER_KEYS_STORE_VERSION: str
REPLAY_STORE_VERSION: str
IDENTITY_CONTROLS_VERSION: str
```

### Meaning

* `ID_VERSION` identifies the format of public identity records returned by `sign_public_id` and stored/loaded by `save_identity`/`load_identity`.
* `ENV_VERSION` identifies the envelope format produced by `seal_envelope` and consumed by `open_envelope`.
* `PAYLOAD_ENC_VERSION` identifies the payload encryption object format (when payload is encrypted).
* `HISTORY_PROOF_VERSION` identifies the history_proof encryption object format (when history_proof is present).
* `SESSIONS_STORE_VERSION`, `PEER_KEYS_STORE_VERSION`, and `REPLAY_STORE_VERSION` identify the wrapped fallback-store document versions.
* `IDENTITY_CONTROLS_VERSION` identifies the public controls API surface exposed by `SummonerIdentityControls`.

### When you use them

* Usually you do not set these directly. They exist so:

  * you can assert versions at API boundaries,
  * you can reject mismatched data early.

For application code, prefer the helper methods:

* `SummonerIdentity.store_versions()`
* `SummonerIdentity.controls_version()`

## Public functions

### `b64_encode`

**Typing**

```python
def b64_encode(data: bytes) -> str
```

**Description**
Encodes raw bytes using standard base64 and returns a UTF-8 string. Used throughout the module for portable storage and messaging.

**Inputs**

* `data`: raw bytes.

**Outputs**

* Base64-encoded string.

**Example**

```python
token = b64_encode(os.urandom(16))
```

**Suggested related internal checks**

* If you see decode errors later, verify you used `b64_encode` (standard base64) rather than urlsafe base64.

---

### `b64_decode`

**Typing**

```python
def b64_decode(data: str) -> bytes
```

**Description**
Decodes a standard base64 string into raw bytes.

**Inputs**

* `data`: base64 string.

**Outputs**

* decoded bytes.

**Example**

```python
raw = b64_decode(token)
```

---

### `serialize_public_key`

**Typing**

```python
def serialize_public_key(key: Any) -> str
```

**Description**
Serializes an X25519 or Ed25519 public key to raw bytes and base64-encodes the result.

**Inputs**

* `key`: an X25519 public key or Ed25519 public key object from `cryptography`.

**Outputs**

* Base64 string containing the 32-byte raw public key.

**Example**

```python
kx_priv = x25519.X25519PrivateKey.generate()
kx_pub_b64 = serialize_public_key(kx_priv.public_key())
```

**Suggested related internal checks**

* If you ever get “invalid key length” errors, check the private loader helpers (`_load_x25519_pub`, `_load_ed25519_pub`) and ensure the base64 text was not altered.

---

### `sign_bytes`

**Typing**

```python
def sign_bytes(priv_sign: ed25519.Ed25519PrivateKey, data: bytes) -> str
```

**Description**
Signs raw bytes using Ed25519 and returns a base64 signature.

**Inputs**

* `priv_sign`: Ed25519 private key.
* `data`: raw bytes to sign. For structured objects, you should sign canonical JSON bytes.

**Outputs**

* Base64-encoded 64-byte Ed25519 signature.

**Example**

```python
sig = sign_bytes(my_sign_priv, _canon_json_bytes(obj))
```

**Intended usage**

* Used internally to sign:

  * identity public cores (`sign_public_id`)
  * envelope cores (`SummonerIdentity.seal_envelope`)

---

### `verify_bytes`

**Typing**

```python
def verify_bytes(pub_sign_b64: str, data: bytes, sig_b64: str) -> None
```

**Description**
Verifies an Ed25519 signature. Raises on failure.

**Inputs**

* `pub_sign_b64`: base64 of the raw Ed25519 public key (32 bytes).
* `data`: the exact bytes that were signed.
* `sig_b64`: base64 Ed25519 signature (64 bytes).

**Outputs**

* `None` on success; raises `ValueError` or a verification exception on failure.

**Example**

```python
verify_bytes(peer_pub_sig_b64, _canon_json_bytes(obj), sig_b64)
```

---

### `sign_public_id`

**Typing**

```python
def sign_public_id(priv_sig: ed25519.Ed25519PrivateKey, pub: dict) -> dict
```

**Description**
Constructs a self-signed public identity record. The signature covers a canonical subset of fields (the “public core”), not arbitrary extras.

**Inputs**

* `priv_sig`: Ed25519 private key.
* `pub`: dict containing the public fields:

  * `created_at: str` (ISO UTC)
  * `pub_enc_b64: str` (X25519)
  * `pub_sig_b64: str` (Ed25519)
  * optional `meta: Any`

**Outputs**

* A dict containing the signed public identity record, including:

  * `v: ID_VERSION`
  * `sig: str`

**Example**

```python
pub = {
  "created_at": _iso_utc(_utc_now()),
  "pub_enc_b64": serialize_public_key(kx_priv.public_key()),
  "pub_sig_b64": serialize_public_key(sig_priv.public_key()),
  "meta": "alice",
}
public_id = sign_public_id(sig_priv, pub)
```

**Intention**

* This record can be shipped inside envelopes, stored in caches, and used to derive keys.
* `meta` is metadata only; the signing key is the identity anchor.

---

### `verify_public_id`

**Typing**

```python
def verify_public_id(pub: dict) -> None
```

**Description**
Verifies a self-signed public identity record. Raises on failure.

**Inputs**

* `pub`: the public identity dict produced by `sign_public_id` (or loaded from disk).

**Outputs**

* `None` on success; raises on failure.

**Example**

```python
verify_public_id(peer_public_id)
```

**Intention**

* Use before trusting:

  * `pub_enc_b64` for key agreement,
  * `pub_sig_b64` for signature verification.

---

### `id_fingerprint`

**Typing**

```python
def id_fingerprint(pub_sig_b64: str) -> str
```

**Description**
Returns a short stable identifier derived from the peer's Ed25519 public key. This is for **local indexing only**, not for cryptographic authentication, and also serves as the canonical identity key for peer caches/allowlists in this system.

**Inputs**

* `pub_sig_b64`: base64 Ed25519 public key.

**Outputs**

* A short url-safe-ish fingerprint string.

**Example**

```python
peer_key = id_fingerprint(peer_public_id["pub_sig_b64"])
```

**Intention**

* Used as the storage key prefix for fallback `sessions.json`.
* Used as the canonical identity key for peer caches and allowlists.

---

### `save_identity`

**Typing**

```python
def save_identity(
    path: str,
    *,
    priv_enc: x25519.X25519PrivateKey,
    priv_sig: ed25519.Ed25519PrivateKey,
    meta: Optional[Any] = None,
    password: Optional[bytes] = None,
    scrypt_n: int = 2**14,
    scrypt_r: int = 8,
    scrypt_p: int = 1,
) -> dict
```

**Description**
Writes an identity file containing:

* a self-signed public identity record,
* private key material:

  * plaintext base64 if `password is None`, or
  * encrypted under `password` using scrypt + AES-GCM.

The write is atomic (`_atomic_write_json`) with best-effort permissions.

**Inputs**

* `path`: target file path.
* `priv_enc`: X25519 private key (key agreement).
* `priv_sig`: Ed25519 private key (signatures).
* `meta`: optional metadata.
* `password`: optional bytes password (recommended for non-dev).
* `scrypt_*`: KDF parameters.

**Outputs**

* The signed public identity record dict.

**Example**

```python
priv_enc = x25519.X25519PrivateKey.generate()
priv_sig = ed25519.Ed25519PrivateKey.generate()

public_id = save_identity(
    "id.json",
    priv_enc=priv_enc,
    priv_sig=priv_sig,
    meta="Alice agent identity",
    password=b"correct horse battery staple",
)
```

---

### `load_identity`

**Typing**

```python
def load_identity(
    path: str,
    *,
    password: Optional[bytes] = None,
) -> Tuple[dict, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey]
```

**Description**
Loads an identity file produced by `save_identity`, validates the public record signature, and returns the public record plus private keys.

**Inputs**

* `path`: identity file.
* `password`: required if the private section is encrypted.

**Outputs**

* `(public_id, priv_enc, priv_sig)`

**Example**

```python
public_id, priv_enc, priv_sig = load_identity("id.json", password=b"...")
```

---

### `session_summary`

**Typing**

```python
def session_summary(lnk: dict) -> bytes
```

**Description**
Computes a domain-separated digest representing a **completed** link (a request/response pair in your session semantics). It binds at minimum:

* `0_nonce`, `1_nonce`
* `ts`, `ttl`

**Inputs**

* `lnk`: dict containing:

  * `0_nonce: str` hex
  * `1_nonce: str` hex
  * `ts: int`
  * `ttl: int`

**Outputs**

* `bytes` digest.

**Example**

```python
summary = session_summary({"0_nonce": n0, "1_nonce": n1, "ts": ts, "ttl": ttl})
```

**Intention**

* Used when finalizing history: a completed link contributes a single `summary` to the history hash chain.

---

### `hist_next`

**Typing**

```python
def hist_next(prev_hash_hex: Optional[str], summary: bytes) -> str
```

**Description**
Advances the history hash chain:

* If `prev_hash_hex is None`: `h1 = H(summary)`
* Else: `h_next = H(prev || summary)`

**Inputs**

* `prev_hash_hex`: previous hash in hex, or `None`.
* `summary`: bytes from `session_summary`.

**Outputs**

* next hash as hex string.

**Example**

```python
h1 = hist_next(None, summary1)
h2 = hist_next(h1, summary2)
```

---

### `derive_sym_key`

**Typing**

```python
def derive_sym_key(
    *,
    priv_enc: x25519.X25519PrivateKey,
    peer_pub_enc_b64: str,
    from_pub_sig_b64: str,
    to_pub_sig_b64: str,
    session: dict,
) -> bytes
```

**Description**
Derives a 32-byte symmetric key from:

* X25519 shared secret,
* HKDF salt bound to:

  * `from` and `to` identity fingerprints,
  * session proof fields: `sender_role`, nonces, ts, ttl,
  * the envelope version tag.

**Inputs**

* `priv_enc`: local X25519 private key.
* `peer_pub_enc_b64`: peer X25519 public key (base64 raw).
* `from_pub_sig_b64`, `to_pub_sig_b64`: signing public keys to bind direction.
* `session`: session proof dict containing the required fields.

**Outputs**

* 32-byte `sym_key`.

**Example**

```python
sym = derive_sym_key(
    priv_enc=my_priv_enc,
    peer_pub_enc_b64=peer_public_id["pub_enc_b64"],
    from_pub_sig_b64=my_public_id["pub_sig_b64"],
    to_pub_sig_b64=peer_public_id["pub_sig_b64"],
    session=session,
)
```

---

### `derive_history_proof_key`

**Typing**

```python
def derive_history_proof_key(sym_key: bytes, aad_bytes: bytes) -> bytes
```

**Description**
Derives a dedicated AEAD key for encrypting/decrypting `history_proof`. This is domain-separated from payload encryption and from the base session key.

**Inputs**

* `sym_key`: 32 bytes from `derive_sym_key`.
* `aad_bytes`: the AAD bytes used for history_proof.

**Outputs**

* 32-byte AEAD key.

**Example**

```python
kx = derive_history_proof_key(sym, aad_bytes)
```

---

### `derive_payload_key`

**Typing**

```python
def derive_payload_key(sym_key: bytes, aad_bytes: bytes) -> bytes
```

**Description**
Derives a dedicated AEAD key for payload encryption/decryption.

**Inputs**

* `sym_key`: 32 bytes from `derive_sym_key`.
* `aad_bytes`: payload AAD bytes.

**Outputs**

* 32-byte AEAD key.

**Example**

```python
kp = derive_payload_key(sym, aad_bytes)
```

## Class: `SummonerIdentityControls`

Reusable controls object for one `SummonerIdentity`.

Summary:

* The built-in JSON stores remain sufficient for many applications, in which case this class is unnecessary.
* This class is appropriate when one `SummonerIdentity` object needs custom storage or trust rules.
* Its purpose is to hold callbacks until they are attached with `identity.attach_controls(...)`.

Representative example:

* One agent may keep a room identity, a recovery identity, and an observer identity.
* Only the room identity may require custom replay and session handling.
* The controls object attaches that extra logic only to the relevant identity.

This class does not replace `SummonerIdentity`. It customizes storage and policy
behavior for one `SummonerIdentity` instance.

Controls callbacks receive the owning `SummonerIdentity` instance as their first argument, followed by the normal hook arguments.

**Example**

```python
controls = SummonerIdentityControls()

@controls.on_verify_session
def verify(identity, peer_public_id, local_role, session_record, use_margin=False):
    return identity.verify_session_default(
        peer_public_id,
        local_role,
        session_record,
        use_margin=use_margin,
    )
```

### `version`

```python
@staticmethod
def version() -> str
```

Returns the public controls API version string.

This method is primarily useful for tests, audits, or tooling that needs to
assert the controls API surface explicitly.

### `configured_hooks`

```python
def configured_hooks(self) -> tuple[str, ...]
```

Returns the controls hook names that are currently configured.

This method is primarily intended for debugging and introspection. It reports
which hooks are currently set on the controls object.

Typical values are drawn from:

* `register_session`
* `reset_session`
* `verify_session`
* `get_session`
* `peer_key_store`
* `replay_store`

### `clear`

```python
def clear(self) -> None
```

Clears all configured controls hooks on that controls object.

This does not detach the controls from a `SummonerIdentity`; it only clears that package's callbacks.

### Controls hook decorators

```python
controls.on_register_session(fn)
controls.on_reset_session(fn)
controls.on_verify_session(fn)
controls.on_get_session(fn)
controls.on_peer_key_store(fn)
controls.on_replay_store(fn)
```

These mirror the class-level hook names, but each callback receives the owning `SummonerIdentity` instance as its first argument.

Selection guidance:

* if you are only overriding one or two behaviors on one live object, `@identity.on_*` may be simpler;
* if you want a named, reusable group of callbacks for one identity object, `SummonerIdentityControls` is the clearer choice.

## Class: `SummonerIdentity`

### Public attributes

After `id(...)` is called, these attributes are meaningful:

* `ttl: int`
  Default TTL used when generating sessions.
* `margin: int`
  Safety margin used in expiry checks.
* `enforce_created_at: bool`
  If True, incoming session timestamps earlier than sender `created_at` are rejected.
* `max_clock_skew_seconds: Optional[int]`
  If set, reject sessions whose `ts` is too far in the future.
* `store_dir: Optional[str]`
  Optional override for where JSON stores are kept.
* `persist_local: bool`
  If True, fallback stores are written to disk.
* `load_local: bool`
  If True, fallback stores are loaded from disk in `id(...)`.
* `persist_replay: bool`
  If True, replay store is persisted to `replay.json`.
* `public_id: Optional[dict]`
  The loaded/created signed public identity record. `None` until `id(...)` is called.
* `controls: Optional[Any]`
  The currently attached controls object, if any.
* `last_status: dict`
  Last structured status emitted by lifecycle calls (`ok`, `code`, optional `phase`, optional `data`).

**Example**

```python
# inside an async function / handler
identity = SummonerIdentity(ttl=86400, margin=5)
identity.id("id.json", password=b"...")
print(identity.ttl, identity.margin)
print(identity.public_id.get("meta"))
```

---

### `store_versions`

**Typing**

```python
@staticmethod
def store_versions() -> dict[str, str]
```

**Description**

Returns the wrapped fallback-store version strings for:

* `sessions`
* `peer_keys`
* `replay`

**Example**

```python
store_versions = SummonerIdentity.store_versions()
assert store_versions["sessions"] == "sessions.store.v1"
```

---

### `controls_version`

**Typing**

```python
@staticmethod
def controls_version() -> str
```

**Description**

Returns the public controls API version used by `SummonerIdentityControls`.

**Example**

```python
assert SummonerIdentity.controls_version() == SummonerIdentityControls.version()
```

---

### `__init__`

**Typing**

```python
def __init__(
    self,
    ttl: int = 86400,
    margin: int = 0,
    *,
    enforce_created_at: bool = False,
    max_clock_skew_seconds: Optional[int] = None,
    store_dir: Optional[str] = None,
    persist_local: bool = True,
    load_local: bool = True,
    persist_replay: bool = False,
)
```

**Description**
Constructs the session manager. Does not load keys. Call `id(...)` to load/create an identity.

**Inputs**

* `ttl`: default TTL for sessions you create.
* `margin`: safety buffer applied during expiry checks.
* `enforce_created_at`: if True, reject session timestamps earlier than sender's created_at.
* `max_clock_skew_seconds`: if set, reject sessions whose `ts` is too far in the future.
* `store_dir`: override where `sessions.json`, `peer_keys.json`, and `replay.json` live.
* `persist_local`: if True, write fallback stores to disk.
* `load_local`: if True, load fallback stores from disk when `id(...)` is called.
* `persist_replay`: if True, persist replay store to disk (otherwise in-memory only).

**Outputs**

* None.

**Intended usage**

* Configure TTL policy at construction time.

---

### `on_policy_event`

**Typing**

```python
def on_policy_event(
    self,
    phase: str,
) -> Callable[[Callable[[str, dict], Any]], Callable[[str, dict], Any]]
```

**Description**
Registers a per-instance telemetry handler for a lifecycle phase.

This is decorator-style registration; handlers are called whenever a lifecycle method
emits a result through the shared return path.

**Inputs**

* `phase`: one of `start_session`, `continue_session`, `advance_stream_session`, `seal_envelope`, `open_envelope`, `verify_discovery_envelope`.

**Outputs**

* A decorator that registers a sync or async function `(event_name, context) -> Any`.

**Exceptions**

* Raises `ValueError` if `phase` is invalid.

**Example**

```python
@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    if event_name != "ok":
        print("reject", ctx.get("validation_stage"), event_name)
```

---

### `attach_controls`

**Typing**

```python
def attach_controls(self, controls: Optional[Any] = None) -> Any
```

**Description**

Attaches a per-instance controls object. If `controls is None`, a new
`SummonerIdentityControls()` is created and attached.

After attachment, that `SummonerIdentity` object uses these custom callbacks
until controls are detached or replaced.

One identity keeps one attached controls slot. If this method is called again,
the new controls object replaces the earlier one.

The same controls object may be reused across multiple identities. If it stores
mutable state internally, that state is shared across those identities.

The recommended controls type is `SummonerIdentityControls`, but any object
exposing callable hook attributes with the expected names is accepted.

For clarity, the examples in this documentation create the controls object
first and then pass it into `attach_controls(...)`. Omitting the argument is a
convenience form, but the explicit form makes ownership and reuse easier to
understand.

**Behavior**

* controls callbacks receive `self` as their first argument,
* controls hook names follow the same names as class hooks,
* once attached, controls hooks take precedence over class hooks but remain lower precedence than instance-local hooks.

**Selection guidance**

Use `attach_controls(...)` when you want per-instance customization that is more reusable than a few `@identity.on_*` decorators.

Skip it when:

* fallback stores are enough, or
* you really want process-wide behavior, in which case class hooks are simpler.

**Example**

This example shows the recommended teaching pattern: create the controls
object explicitly, attach it, then register the hook on that object.

```python
identity = SummonerIdentity()
identity.id("id.json")

controls = SummonerIdentityControls()
identity.attach_controls(controls)

@controls.on_peer_key_store
def peer_store(identity, peer_public_id, update=None):
    return identity.peer_key_store_default(peer_public_id, update=update)
```

**Agent-style example**

This example shows the same explicit pattern inside a `SummonerAgent`
deployment. Only the room identity receives the custom rule.

```python
from tooling.aurora import SummonerAgent, SummonerIdentity, SummonerIdentityControls

agent = SummonerAgent(name="room-orchestrator")

room_identity = SummonerIdentity()
observer_identity = SummonerIdentity()

room_identity.id("room.json")
observer_identity.id("observer.json")

identity_pool = {
    "room": room_identity,
    "observer": observer_identity,
}

room_controls = SummonerIdentityControls()
room_identity.attach_controls(room_controls)

@room_controls.on_verify_session
def verify(identity, peer_public_id, local_role, session_record, use_margin=False):
    base = identity.verify_session_default(
        peer_public_id,
        local_role,
        session_record,
        use_margin=use_margin,
    )
    if not base.get("ok"):
        return base
    # Only the room identity runs this extra rule.
    return base

agent.attach_identity(identity_pool["room"])
```

### `detach_controls`

**Typing**

```python
def detach_controls(self) -> Any | None
```

**Description**

Detaches and returns the current controls object, or `None` if no controls are attached.

This method removes the single attached controls object from the identity. It
does not affect class hooks or local `@identity.on_*` hooks.

### `require_controls`

**Typing**

```python
def require_controls(self) -> Any
```

**Description**

Returns the current controls object or raises `RuntimeError` if none are attached.

Use this when controls attachment is a programming invariant, not an optional feature.

### `has_controls`

**Typing**

```python
def has_controls(self) -> bool
```

**Description**

Returns `True` if a controls object is attached.

### `clear_local_hooks`

**Typing**

```python
def clear_local_hooks(self) -> None
```

**Description**

Clears all instance-local hooks registered with `@identity.on_*`.

This does not detach the controls and does not affect class-level hooks.

### Instance hook decorators

```python
identity.on_register_session(fn)
identity.on_reset_session(fn)
identity.on_verify_session(fn)
identity.on_get_session(fn)
identity.on_peer_key_store(fn)
identity.on_replay_store(fn)
```

These bind hooks only on one live `SummonerIdentity` instance.

They use the same callback signature as the class-level decorators.

---

### `classify_session_record`

**Typing**

```python
def classify_session_record(self, session_record: Any) -> dict
```

**Description**
Classifies the shape of an arbitrary session-like object without mutating state.

This helper is useful for diagnostics and policy handlers that need lightweight
classification (`start` form vs non-start form) before applying custom logic.

**Outputs**

Returns a dict with:

* `valid_shape: bool`
* `sender_role: 0 | 1 | None`
* `is_start_form: bool`
* `has_history_proof: bool`
* `mode: "single" | "stream" | None`
* `is_stream: bool`
* `stream_fields_valid: bool`
* `stream_id: str | None`
* `stream_seq: int | None`
* `stream_phase: "start" | "chunk" | "end" | None`
* `is_stream_start: bool`
* `is_stream_end: bool`
* `has_ttl: bool`
* `ttl_valid: bool`
* `has_stream_ttl: bool`
* `stream_ttl_valid: bool`
* `record_expired: bool`
* `record_expiry_basis: "ttl" | "stream_ttl" | None`

**Example**

```python
c = identity.classify_session_record(peer_session)
if c["valid_shape"] and c["is_start_form"]:
    ...
```

For stream mode, `is_start_form` is phase-aware:

* `stream_phase == "start"` -> `is_start_form == True`
* `stream_phase in ("chunk", "end")` -> `is_start_form == False`

---

### Default Delegates for Handlers

`SummonerIdentity` exposes public default delegates so custom handlers can extend baseline behavior without calling private `_..._fallback` methods directly.

The hook registration surfaces and the public runtime operations intentionally use different names to avoid ambiguity:

* Class-level decorators:
  * `@SummonerIdentity.get_session`
  * `@SummonerIdentity.verify_session`
  * `@SummonerIdentity.register_session`
  * `@SummonerIdentity.reset_session`
* Controls decorators:
  * `@controls.on_get_session`
  * `@controls.on_verify_session`
  * `@controls.on_register_session`
  * `@controls.on_reset_session`
* Instance-local decorators:
  * `@identity.on_get_session`
  * `@identity.on_verify_session`
  * `@identity.on_register_session`
  * `@identity.on_reset_session`
* Public hook-aware runtime methods:
  * `await identity.get_current_session(...)`
  * `await identity.verify_session_record(...)`
  * `await identity.register_session_record(...)`
  * `await identity.force_reset_session(...)`

Inside a custom hook, keep using the matching `*_default(...)` delegate.

Reason:

* The public runtime methods (`get_current_session(...)`, `verify_session_record(...)`,
  `register_session_record(...)`, `force_reset_session(...)`) are hook-aware.
* They route through the currently active hook source (local, controls, class, or fallback).
* Inside a custom hook, that hook source is already active, so calling the public runtime
  method would re-enter the same hook path instead of reaching baseline behavior.

In practice:

* outside hooks, use the public runtime methods
* inside hooks, use `*_default(...)` when you want baseline behavior

Available delegates:

* `get_session_default(peer_public_id, local_role) -> dict | None`
* `verify_session_default(peer_public_id, local_role, session_record, use_margin=False) -> dict`
* `register_session_default(peer_public_id, local_role, session_record, *, new=False, use_margin=False) -> bool`
* `reset_session_default(peer_public_id, local_role) -> bool`
* `peer_key_store_default(peer_public_id, update=None) -> dict | None`
* `replay_store_default(message_id, *, ttl, now=None, add=False) -> bool`

**Example**

```python
identity = SummonerIdentity()
risk = {}

@SummonerIdentity.verify_session
def my_verify(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = id_fingerprint(peer_public_id["pub_sig_b64"])
        if risk.get(fp, 0) > 5:
            return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if event_name == "session_verify_failed" and isinstance(fp, str):
        risk[fp] = risk.get(fp, 0) + 1
```

---

### `get_current_session`

**Typing**

```python
async def get_current_session(
    self,
    peer_public_id: dict | None,
    local_role: int,
) -> dict | None
```

**Description**
Public hook-aware runtime accessor for the current stored link of a peer/role lane.

Use this in application code when you want the configured session lookup behavior.
It routes through any installed `@SummonerIdentity.get_session` hook and otherwise
falls back to the built-in `sessions.json` lookup.

**Practical rule**

* Outside hooks, use `await identity.get_current_session(...)`.
* Inside a custom `@SummonerIdentity.get_session` hook, use `get_session_default(...)`
  if you want baseline behavior without recursing into the same hook.

---

### `verify_session_record`

**Typing**

```python
async def verify_session_record(
    self,
    peer_public_id: dict | None,
    local_role: int,
    session_record: dict,
    *,
    use_margin: bool = False,
) -> VerifyResult
```

**Description**
Public hook-aware runtime verifier for a session record.

Use this in application code when you want the configured verification behavior.
It routes through any installed `@SummonerIdentity.verify_session` hook and otherwise
falls back to the built-in verifier.

**Practical rule**

* Outside hooks, use `await identity.verify_session_record(...)`.
* Inside a custom `@SummonerIdentity.verify_session` hook, use
  `verify_session_default(...)` to extend baseline verification without recursion.

---

### `register_session_record`

**Typing**

```python
async def register_session_record(
    self,
    peer_public_id: dict | None,
    local_role: int,
    session_record: dict | None,
    *,
    new: bool = False,
    use_margin: bool = False,
) -> bool
```

**Description**
Public hook-aware runtime session registration method.

Use this in application code when you want the configured registration/persistence
behavior. It routes through any installed `@SummonerIdentity.register_session` hook
and otherwise falls back to the built-in `sessions.json` registration path.

**Practical rule**

* Outside hooks, use `await identity.register_session_record(...)`.
* Inside a custom `@SummonerIdentity.register_session` hook, use
  `register_session_default(...)` to extend fallback persistence semantics safely.

---

### `force_reset_session`

**Typing**

```python
async def force_reset_session(
    self,
    peer_public_id: dict | None,
    local_role: int,
) -> bool
```

**Description**
Public hook-aware runtime force-reset operation for a session lane.

Use this in application code when you want the configured reset behavior. It routes
through any installed `@SummonerIdentity.reset_session` hook and otherwise falls back
to the built-in reset logic.

**Practical rule**

* Outside hooks, use `await identity.force_reset_session(...)`.
* Inside a custom `@SummonerIdentity.reset_session` hook, use `reset_session_default(...)`
  if you want baseline behavior without recursing into the same hook.

---

### `register_session`

**Typing**

```python
@classmethod
def register_session(
    cls,
    fn: Callable[..., bool | Awaitable[bool]],
) -> Callable[..., bool | Awaitable[bool]]
```

**Description**
Registers a storage hook for persisting session state. If not provided, the class uses the fallback `sessions.json` store.

**Expected hook signature**

```python
def fn(peer_public_id, local_role, session_record, new=False, use_margin=False) -> bool | Awaitable[bool]
```

**Inputs**

* `peer_public_id`: peer identity dict (or `None` for generic/public).
* `local_role`: your local role (0/1) for this peer direction.
* `session_record`: the session proof dict or `None` (to end/discard).
* `new`: if True, indicates start/end semantics.
* `use_margin`: whether to apply margin when evaluating expiry.

**Outputs**

* `bool` success status (or awaitable resolving to `bool`).

**Example**

```python
@SummonerIdentity.register_session
async def my_register(peer_public_id, local_role, session_record, new=False, use_margin=False) -> bool:
    # Persist in sqlite, redis, etc.
    return True
```

Real integration note:

* this hook must be paired with `verify_session` in the same hook scope,
* otherwise `SummonerIdentity` raises `ValueError` before using the custom store path.

**Conventional pseudocode**

```python
async def register_session(peer_public_id, local_role, session_record, new=False, use_margin=False) -> bool:
    rec = load_slot(peer_public_id, local_role) or empty_record(peer_public_id, local_role)
    current = rec.current_link

    # 1) Clear expired current first.
    if current and is_expired(current, use_margin):
        finalize_history_if_completed(rec)
        rec.past_chain = []
        rec.current_link = None
        rec.active = False
        save_slot(rec)
        if not new:
            return False
        current = None

    # 2) New/start boundary behavior.
    if new:
        if session_record and session_record.get("_finalize_current_on_new"):
            mark_current_completed_if_summarizable(rec)
        finalize_history_if_completed(rec)
        rec.past_chain = []
        rec.current_link = None
        rec.active = False
        if session_record is None:
            save_slot(rec)
            return True
        if not is_start_form(session_record):
            return False
        rec.current_link = make_current_from_session(session_record, completed=False)
        rec.active = True
        save_slot(rec)
        return True

    # 3) Ongoing update behavior.
    if session_record is None:
        return False
    if current and current.completed:
        rec.past_chain.append(compact_completed_link(current, now=session_record.ts))
    rec.current_link = make_current_from_session(
        session_record,
        completed=bool(session_record.get("_completed", False)),
        seen=append_seen(current, session_record),
    )
    rec.active = True
    save_slot(rec)
    return True
```

**Best practices**

* If you provide `register_session`, also provide `verify_session` and `get_session` so the three agree on
  keying (`peer_public_id` fingerprint + `local_role`) and expiry policy.
* Mirror fallback semantics for `new=True` vs `new=False` (see `register_session_default(...)`) unless you
  explicitly want different reset/expiry behavior.
* Use `store_dir` as the base directory for your own persistence layout so all stores live together.
* If you disable persistence (`persist_local=False`), keep state in memory and accept that continuity resets on restart.

**Related default delegates**

* If you want to match the fallback semantics, use:

  * `register_session_default(...)`
  * `reset_session_default(...)`

---

### `reset_session`

**Typing**

```python
@classmethod
def reset_session(
    cls,
    fn: Callable[..., bool | Awaitable[bool]],
) -> Callable[..., bool | Awaitable[bool]]
```

**Description**
Registers a force-reset hook used by `start_session(..., force_reset=True)` when custom session storage is enabled.

**Expected hook signature**

```python
def fn(peer_public_id, local_role) -> bool | Awaitable[bool]
```

**Outputs**

* `bool` (or awaitable resolving to `bool`)

**Example**

```python
@SummonerIdentity.reset_session
async def my_reset(peer_public_id, local_role) -> bool:
    return True
```

**Conventional pseudocode**

```python
async def reset_session(peer_public_id, local_role) -> bool:
    rec = load_slot(peer_public_id, local_role)
    if not rec:
        return True

    current = rec.current_link

    # Archive only if link is summarizable (both nonces + timing).
    if current and has_summary_fields(current):
        current.completed = True
        rec.current_link = current
        finalize_history_if_completed(rec)

    # Drop active state regardless of whether summary was possible.
    rec.past_chain = []
    rec.current_link = None
    rec.active = False
    save_slot(rec)
    return True
```

**Best practices**

* Do not archive incomplete links.
* Never delete history entries; only clear active state.
* Return `False` on storage failure so caller surfaces `force_reset_failed`.

---

### `verify_session`

**Typing**

```python
@classmethod
def verify_session(
    cls,
    fn: Callable[..., Any | Awaitable[Any]],
) -> Callable[..., Any | Awaitable[Any]]
```

**Description**
Registers a verification hook for checking that incoming session proofs are consistent with local stored state.

**Expected hook signature**

```python
def fn(peer_public_id, local_role, session_record, use_margin=False) -> Any | Awaitable[Any]
```

**Outputs**

Hook return is normalized by `SummonerIdentity`:

* Boolean result form:
  * `True` -> `{"ok": True, "code": "ok"}`
  * `False` -> `{"ok": False, "code": "session_verify_failed"}`
* Structured style (recommended):
  * `{"ok": bool, "code": str, "reason": optional str}`
* Malformed structured output:
  * fails closed to `{"ok": False, "code": "session_verify_failed"}`

**Example**

```python
@SummonerIdentity.verify_session
async def my_verify(peer_public_id, local_role, session_record, use_margin=False):
    # Keep default protocol behavior, then add local policy.
    base = identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)
    if not base.get("ok", False):
        return base
    # optional policy gate:
    return {"ok": True, "code": "ok"}
```

**Conventional pseudocode**

```python
async def verify_session(peer_public_id, local_role, session_record, use_margin=False):
    rec = load_slot(peer_public_id, local_role)
    current = rec.current_link if rec else None
    cls = identity.classify_session_record(session_record)
    current_is_stale = bool(current) and is_stale_current_link(current, use_margin)
    current_for_start_form = None if current_is_stale and cls["is_start_form"] else current
    sender_role = session_record["sender_role"]
    x = sender_role
    nx = f"{x}_nonce"
    nnot = f"{1-x}_nonce"

    if cls["is_start_form"]:
        if not valid_ts_ttl(session_record, use_margin):
            return {"ok": False, "code": "session_verify_failed"}
        if nonce_replayed_in_current_or_past(rec, nx, session_record[nx], current=current_for_start_form):
            return {"ok": False, "code": "session_verify_failed"}
        if not valid_history_proof(peer_public_id, rec, session_record, current=current_for_start_form):
            return {"ok": False, "code": "session_verify_failed"}
        return {"ok": True, "code": "ok"}

    if not current or is_expired(current, use_margin):
        return {"ok": False, "code": "session_verify_failed"}
    if session_record[nnot] != current[nnot]:
        return {"ok": False, "code": "session_verify_failed"}
    if not nonce_is_fresh(rec, current, nx, session_record[nx]):
        return {"ok": False, "code": "session_verify_failed"}
    return {"ok": True, "code": "ok"}
```

**Best practices**

* Apply the same `margin`/expiry logic as the fallback verifier when `use_margin=True`.
* For fresh start-form admission, fallback verification normalizes a stale/expired
  persisted `current_link` to an absent local state.
* When the stored link is an active stream, staleness is evaluated from
  `stream_last_ts + stream_ttl`, not only from the requester-window `ttl`.
* If you enforce stricter policies (e.g., no reset while active), document them because they change behavior.
* If you use `max_clock_skew_seconds`, enforce it here too for custom verifiers.
* Start from `verify_session_default(...)` and add policy deltas, instead of re-implementing full fallback logic.
* Prefer structured return values for stream diagnostics (`stream_ttl_expired`, `stream_seq_invalid`, `stream_reason`, etc.).

**Related default delegate**

* `verify_session_default(...)`

---

### `get_session`

**Typing**

```python
@classmethod
def get_session(
    cls,
    fn: Callable[..., Optional[dict] | Awaitable[Optional[dict]]],
) -> Callable[..., Optional[dict] | Awaitable[Optional[dict]]]
```

**Description**
Registers a session lookup hook. Used by `continue_session` to retrieve local `current_link`.

**Expected hook signature**

```python
def fn(peer_public_id, local_role) -> dict | None | Awaitable[dict | None]
```

**Outputs**

* The stored link/session dict or `None`.

**Example**

```python
@SummonerIdentity.get_session
async def my_get(peer_public_id, local_role) -> Optional[dict]:
    return None
```

**Conventional pseudocode**

```python
async def get_session(peer_public_id, local_role) -> dict | None:
    rec = load_slot(peer_public_id, local_role)
    if not rec:
        return None
    return rec.current_link
```

**Best practices**

* Return the stored `current_link` exactly as your verifier expects. Mismatched shapes cause false rejects.
* If you persist sessions externally, prefer storing `ts`, `ttl`, `seen`, and `completed` fields intact.
* If you implement custom verification around restart/reload behavior, keep stale-state
  normalization in the verifier rather than mutating lookup results implicitly.

---

### `peer_key_store`

**Typing**

```python
@classmethod
def peer_key_store(
    cls,
    fn: Callable[..., Optional[dict] | Awaitable[Optional[dict]]],
) -> Callable[..., Optional[dict] | Awaitable[Optional[dict]]]
```

**Description**
Registers a peer key store hook used for fingerprint-indexed peer caching and identity registry persistence.

**Expected hook signature**

```python
def fn(peer_public_id, update=None) -> dict | None | Awaitable[dict | None]
```

**Semantics**

* `update=None`: return the stored record for this peer (or `None` if missing).
* `update=<dict>`: store and return the updated record.
* Consistency requirement: `id_fingerprint(update["pub_sig_b64"])` should match the
  fingerprint derived from `peer_public_id["pub_sig_b64"]`. If not, reject the write.

**Example**

```python
@SummonerIdentity.peer_key_store
async def my_peer_store(peer_public_id, update=None):
    # Return existing record or persist update.
    return None
```

**Conventional pseudocode**

```python
async def peer_key_store(peer_public_id, update=None) -> dict | None:
    fp = id_fingerprint(peer_public_id["pub_sig_b64"])
    rec = load_peer_record(fp)

    if update is None:
        return rec
    if id_fingerprint(update["pub_sig_b64"]) != fp:
        return None

    now = unix_now()
    if not rec:
        rec = {
            "public_id": update,
            "pub_sig_b64": update["pub_sig_b64"],
            "fingerprint": fp,
            "meta": update.get("meta"),
            "first_seen": now,
            "last_seen": now,
        }
    else:
        rec["public_id"] = update
        rec["pub_sig_b64"] = update["pub_sig_b64"]
        rec["fingerprint"] = fp
        rec["meta"] = update.get("meta")
        rec["last_seen"] = now
    save_peer_record(fp, rec)
    return rec
```

**Best practices**

* Key by `id_fingerprint(pub_sig_b64)`, not by metadata.
* Treat `meta` as advisory only; do not use it for trust decisions.
* If you provide a custom `@SummonerIdentity.peer_key_store`, remember that internal
  `self._peer_keys` fallback cache is not automatically synchronized through your handler.
  If you rely on `list_known_peers()` / `list_verified_peers()` / `find_peer()`,
  keep `self._peer_keys` updated yourself, or provide your own listing/search API
  in your application.

---

### `replay_store`

**Typing**

```python
@classmethod
def replay_store(
    cls,
    fn: Callable[..., bool | Awaitable[bool]],
) -> Callable[..., bool | Awaitable[bool]]
```

**Description**
Registers a replay cache hook. Used to reject duplicate envelopes across process lifetime.

**Expected hook signature**

```python
def fn(message_id, ttl, now, add) -> bool | Awaitable[bool]
```

**Semantics**

* `add=False`: return True if `message_id` is already present.
* `add=True`: store `message_id` and return True on success.

**Example**

```python
@SummonerIdentity.replay_store
async def my_replay_store(message_id, ttl, now, add) -> bool:
    return False
```

**Conventional pseudocode**

```python
async def replay_store(message_id, ttl, now, add) -> bool:
    items = load_replay_items()  # {message_id: {"exp": int}}
    cleanup_expired(items, now)

    if not add:
        rec = items.get(message_id)
        return bool(rec and now <= rec["exp"])

    exp = now + max(1, int(ttl))
    items[message_id] = {"exp": exp}
    save_replay_items(items)
    return True
```

**Best practices**

* If you enable `persist_replay`, keep replay records in a store that survives restarts.
* Always apply TTL expiration; otherwise the replay set grows unbounded.
* Use the provided `ttl` and `now` parameters so behavior matches the default cache.

---

### `list_known_peers`

**Typing**

```python
def list_known_peers(self) -> list[dict]
```

**Description**
Returns unique peer `public_id` records learned by the local peer cache.

**Outputs**

* `list[dict]` of public identities.

**Example**

```python
known = identity.list_known_peers()
for peer in known:
    print(peer.get("meta"), peer.get("pub_sig_b64"))
```

**Important behavior**

* This method reads the in-memory fallback peer cache (`self._peer_keys`).
* "Known" is intentionally broader than "verified".
  A peer may appear here after its self-signed identity was learned, even if
  later continuity checks failed or the peer was never promoted to a
  conversation-safe trust state.
* Use `list_verified_peers()` when the caller needs peers that are safe to treat
  as verified conversation candidates.
* With a custom `_peer_key_store_handler`, results may be incomplete unless your
  handler also keeps `self._peer_keys` synchronized.

---

### `list_verified_peers`

**Typing**

```python
def list_verified_peers(self) -> list[dict]
```

**Description**
Returns peer identities that are safe to treat as verified conversation peers.

Verification sources:

* explicit success markers written by `open_envelope(...)` or
  `verify_discovery_envelope(...)`
* continuity evidence already present in fallback session
  history or completed current-link state

**Outputs**

* `list[dict]` of verified public identities.

**Example**

```python
verified = identity.list_verified_peers()
for peer in verified:
    print(peer.get("meta"), peer.get("pub_sig_b64"))
```

**Important behavior**

* This method is stricter than `list_known_peers()`.
* It is the safer default for choosing peers to start or resume conversations with.
* With custom peer-key/session controls, the fallback view may be incomplete unless
  your application mirrors verification signals into fallback peer/session state.

---

### `find_peer`

**Typing**

```python
def find_peer(self, text: str) -> list[dict]
```

**Description**
Returns known peer identities where `text in str(public_id)`.
This is a convenience UX/discovery helper.

**Inputs**

* `text`: substring to match in stringified `public_id`.

**Outputs**

* `list[dict]` matches.

**Example**

```python
hits = identity.find_peer("alice")
```

**Important behavior**

* Search is string-based and fuzzy; do not use as a trust decision.
* Use it to browse discovery results, then pin by fingerprint or move to
  `list_verified_peers()` for conversation-safe selection.
* Same cache caveat as `list_known_peers`: with a custom `_peer_key_store_handler`,
  keep `self._peer_keys` synchronized if you want these helpers to be authoritative.

---

### `id` (method)

**Typing**

```python
def id(self, path: str = "id.json", meta: Optional[Any] = None, *, password: Optional[bytes] = None) -> dict
```

**Description**
Loads or creates the identity file and sets:

* `self.public_id`
* internal private keys for encryption/signing
* fallback store paths (`sessions.json`, `peer_keys.json`, `replay.json`)

If meta is provided and differs, it re-signs and rewrites the public record.

**Inputs**

* `path`: path to identity file (relative to caller's file directory).
* `meta`: optional metadata field.
* `password`: required if the identity file is encrypted.

**Outputs**

* The signed public identity record dict (also stored in `self.public_id`).

**Example**

```python
# inside an async function / handler
identity = SummonerIdentity()
my_public = identity.id("id.json", meta="agent alice", password=b"pw")
```

**Related private logic**

* Identity persistence is handled by:

  * `save_identity`
  * `load_identity`

---

### `update_id_meta`

**Typing**

```python
def update_id_meta(self, meta: Optional[Any], *, password: Optional[bytes] = None) -> dict
```

**Description**
Updates the identity metadata, re-signs the public identity, and persists it to disk.
This is the only method that commits meta changes to the identity file.

**Inputs**

* `meta`: new metadata (or `None` to clear).
* `password`: required if the identity file is encrypted.

**Outputs**

* The updated signed public identity record.

**Example**

```python
identity.update_id_meta({"role": "planner", "version": 2}, password=b"pw")
```

---

### `start_session`

**Typing**

```python
async def start_session(
    self,
    peer_public_id: Optional[dict] = None,
    ttl: Optional[int] = None,
    stream: bool = False,
    stream_ttl: Optional[int] = None,
    *,
    force_reset: bool = False,
    return_status: bool = False,
) -> Any
```

**Description**
Creates a start-form session proof with:

* `sender_role = 0`
* a fresh `0_nonce`
* `1_nonce = None`
* `ts`, `ttl`

If `peer_public_id` is provided, it includes `history_proof` as a continuity proof
bound to your stored history (or reset bootstrap state) for that peer.

If `peer_public_id` is `None`, this is a **public** session; the session proof is still required and is stored in the generic session slot.

Streaming mode:
* `stream=True` emits a stream-start proof with:
  * `mode="stream"`
  * `stream={"id": <generated>, "seq": 0, "phase": "start"}`
  * positive `stream_ttl`
* Stream mode is unsupported for `peer_public_id=None` and returns `stream_mode_unsupported`.

It persists the resulting session record through `register_session` (or fallback), with `new=True`.

Lifecycle policy for peer sessions:
* One active role-0 session is allowed per peer slot.
* If a live current link exists and is not completed, `start_session(...)` returns
  `None` unless `force_reset=True`.
* If active link is completed, `start_session(...)` finalizes it into history before starting the next one.
* `force_reset=True` restarts by force: completed/summarizable links are archived, incomplete links are dropped.
* Current-link liveness is stream-aware: active stream state remains live on its
  stream-progress window rather than only on the original requester-window `ttl`.

**Inputs**

* `peer_public_id`: peer identity record. If `None`, history_proof is omitted and generic slot is used.
* `ttl`: override TTL for this session record.
* `stream`: enable stream-start emission for this turn.
* `stream_ttl`: required positive int when `stream=True`.
* `force_reset`: explicit reset override for an active uncompleted session.

**Outputs**

* If `return_status=False` (default):
  * session record dict suitable for `seal_envelope`, or `None` on failure.
* If `return_status=True`:
  * `{"ok": True, "code": "ok", "phase": "start_session", "data": <session_dict>}`
  * `{"ok": False, "code": "<reason>", "phase": "start_session"}`

**Example**

```python
# inside an async function / handler
s0 = await identity.start_session(peer_public_id)
env = await identity.seal_envelope({"hello": 1}, s0, to=peer_public_id)
```

**Intended composition**

* Usually followed by `seal_envelope(...)`.

**Related private logic**

* history_proof binding uses internal AAD builders:

  * `_history_proof_aad_bytes`
* Symmetric key derivation for history_proof uses:

  * `_derive_sym_for_peer`
  * `derive_history_proof_key`

---

### `continue_session`

**Typing**

```python
async def continue_session(
    self,
    peer_public_id: Optional[dict],
    peer_session: dict,
    ttl: Optional[int] = None,
    use_margin: bool = True,
    *,
    stream: bool = False,
    stream_ttl: Optional[int] = None,
    return_status: bool = False,
) -> Any
```

**Description**
Given a peer's session proof (typically extracted from an envelope you just opened), computes the next session proof for your reply.

Algorithm:

* Derive `local_role = not(peer_session.sender_role)`.
* Lookup local `current_link` for `(peer, local_role)` via `get_session`.
* If missing or stale:
  * If `local_role == 0`, restart via `start_session(peer_public_id)`.
  * If `local_role == 1`, return `None` (give up; do not restart as role 0).
* Otherwise verify that `peer_session` matches the current_link (no advance).
* Create the next session:

  * `sender_role = local_role`
  * fresh nonce for your role
  * carry-forward of the other nonce
  * preserve `age` from current continuity when available, otherwise fall back to
    the peer's presented age
* Persist via `register_session(new=False)`.

Streaming mode:
* `stream=False` while local stream is active returns `stream_active_continue_blocked`.
* `stream=True` starts a responder-owned stream-turn (`phase="start"`, `seq=0`) and requires valid `stream_ttl`.
* Stream mode is unsupported for `peer_public_id=None`.

**Inputs**

* `peer_public_id`: verified peer identity dict or `None` for public flow.
* `peer_session`: peer session proof dict from last received envelope.
* `ttl`: optional TTL override.
* `use_margin`: apply safety margin when deciding expiry.
* `stream`: whether to begin stream mode on this continue path.
* `stream_ttl`: required positive int when `stream=True`.

**Outputs**

* If `return_status=False` (default):
  * next session proof dict, or `None` on failure.
* If `return_status=True`:
  * `{"ok": True, "code": "ok", "phase": "continue_session", "data": <session_dict>}`
  * `{"ok": False, "code": "<reason>", "phase": "continue_session"}`

Special case:
* If the role-0 recovery branch delegates to `start_session(...)`, return status/phase
  can be from `start_session` (for example `active_session_exists`).

**Example**

```python
# inside an async function / handler
payload = await identity.open_envelope(env_from_peer)
peer_session = env_from_peer["session_proof"]
next_s = await identity.continue_session(peer_public_id, peer_session)
reply = await identity.seal_envelope({"ack": True}, next_s, to=peer_public_id)
```

---

### `advance_stream_session`

**Typing**

```python
async def advance_stream_session(
    self,
    peer_public_id: Optional[dict],
    session: dict,
    *,
    end_stream: bool = False,
    ttl: Optional[int] = None,
    stream_ttl: Optional[int] = None,
    return_status: bool = False,
) -> Any
```

**Description**
Advances an active stream for the same sender role.

Behavior:
* Validates stream-mode session input (`invalid_stream_session` otherwise).
* Requires active matching stream state in storage.
* Increments stream sequence by exactly `+1`.
* Emits:
  * `phase="chunk"` when `end_stream=False` (requires valid positive `stream_ttl`)
  * `phase="end"` when `end_stream=True` (uses normal `ttl` handoff contract)

**Inputs**

* `peer_public_id`: required peer identity context for stream progression.
* `session`: last valid stream session proof from this sender turn.
* `end_stream`: whether to close stream and hand turn back.
* `ttl`: optional handoff TTL override for end frame.
* `stream_ttl`: required positive int for non-end chunk frames.

**Outputs**

* If `return_status=False` (default):
  * next stream session proof dict, or `None` on failure.
* If `return_status=True`:
  * `{"ok": True, "code": "ok", "phase": "advance_stream_session", "data": <session_dict>}`
  * `{"ok": False, "code": "<reason>", "phase": "advance_stream_session"}`

**Example**

```python
# inside an async function / handler
s2 = await identity.advance_stream_session(peer_public_id, s1, end_stream=False, stream_ttl=30)
env2 = await identity.seal_envelope({"delta": "part-2"}, s2, to=peer_public_id)

s3 = await identity.advance_stream_session(peer_public_id, s2, end_stream=True, ttl=120)
env3 = await identity.seal_envelope({"done": True}, s3, to=peer_public_id)
```

---

### `seal_envelope`

**Typing**

```python
async def seal_envelope(
    self,
    payload: Optional[Any],
    session: dict,
    to: Optional[dict] = None,
    *,
    id_meta: Optional[Any] = None,
    return_status: bool = False,
) -> Any
```

**Description**
Builds a signed envelope from `(payload, session_proof, from, to)`.
If `id_meta` is provided, the in-memory identity metadata is updated for this process
only (not persisted) before sealing.

* If `to` is provided:

  * derives `sym_key` (X25519 + HKDF) for the message direction,
  * derives a payload AEAD key,
  * encrypts `payload` using AES-GCM, binding to AAD that includes direction + session fields.
* If `to` is `None`:

  * leaves payload plaintext, but still signs the envelope and validates session_proof against the generic slot.

Before crypto/signing path continues, stream schema guards are enforced on `session`:
* `invalid_stream_mode`
* `invalid_stream_fields`
* `stream_ttl_invalid` for non-end stream frames
* `stream_mode_unsupported` for stream mode on unsupported boundary

Finally, signs the envelope core using your identity signing key.

**Inputs**

* `payload`: any JSON-serializable value (application data).
* `session`: session proof dict.
* `to`: optional peer identity dict. If provided, payload is encrypted.
* `id_meta`: optional identity metadata to use for this envelope only (not persisted).

**Outputs**

* If `return_status=False` (default):
  * envelope dict, or `None` on failure.
* If `return_status=True`:
  * `{"ok": True, "code": "ok", "phase": "seal_envelope", "data": <envelope_dict>}`
  * `{"ok": False, "code": "<reason>", "phase": "seal_envelope"}`

**Example (encrypted)**

```python
# inside an async function / handler
env = await identity.seal_envelope({"msg": "hi"}, session, to=peer_public_id)
```

**Example (plaintext)**

```python
# inside an async function / handler
env = await identity.seal_envelope({"broadcast": True}, session, to=None)
```

**Related private logic**

* Payload AAD builder:

  * `_payload_aad_bytes`
* Symmetric derivation:

  * `_derive_sym_for_peer`
  * `derive_payload_key`

---

### `open_envelope`

**Typing**

```python
async def open_envelope(self, envelope: dict, *, return_status: bool = False) -> Any
```

**Description**
Verifies and opens a received envelope.

Steps:

1. Validate structure and versions.
2. Verify `from` identity record (self-signature).
3. If `to` exists, verify it matches your own identity (by signing public key).
4. Enforce time checks (`created_at` policy and optional max clock skew).
5. Verify the envelope signature over the canonical envelope core.
6. Record peer identity in the fingerprint-indexed cache.
7. Verify session continuity using `verify_session(...)`.
8. If payload is encrypted:

   * derive `sym_key` for receiver direction,
   * derive payload AEAD key,
   * decrypt and parse payload value.
9. Check replay cache.
10. Commit session state (including completion marker when applicable), then record
    message id in replay cache and promote the sender to a verified peer.

Stream-specific semantics:
* Non-end stream frames are validated against `stream_ttl` (no receiver margin).
* For responder streams, requester-window TTL boundary is enforced at first stream boundary; subsequent chunks follow stream state + `stream_ttl`.
* After timeout/interruption, fallback state is closed/interrupted and later frames on same stream id are rejected (`stream_interrupted`).
* Common sequence on repeated delayed attempts: first late frame `stream_ttl_expired`, then `stream_interrupted` on subsequent attempts (with reason context when available).

Completion semantics:

* If this envelope is a role 1 message arriving to local role 0, and it is within `[ts, ts+ttl]` (with margin), it sets a storage-only `_completed` marker and persists it.

**Inputs**

* `envelope`: dict produced by another party's `seal_envelope`.

**Outputs**

* If `return_status=False` (default):
  * decrypted payload value (or plaintext payload value), or `None` on failure.
  * Note: because payload itself may be `None`, use `return_status=True` to disambiguate success vs failure.
* If `return_status=True`:
  * `{"ok": True, "code": "ok", "phase": "open_envelope", "data": <payload_value>}`
  * `{"ok": False, "code": "<reason>", "phase": "open_envelope"}`

**Example**

```python
# inside an async function / handler
st = await identity.open_envelope(env_from_peer, return_status=True)
if not st["ok"]:
    # reject / log
    ...
payload = st["data"]
```

**Related private logic**

* Signature verification:

  * `verify_bytes(...)`
* Symmetric derivation:

  * `_derive_sym_for_peer(..., receiver_side=True)`
* Failure path:

  * invalid envelopes fail closed and return `None` (or status with `ok=False`).
  * state commit occurs only after all checks pass.
  * policy telemetry for failures includes `validation_stage`.

---

### `verify_discovery_envelope`

**Typing**

```python
async def verify_discovery_envelope(
    self,
    envelope: dict,
    *,
    return_status: bool = False,
) -> Any
```

**Description**
Verify and learn a discovery/public envelope without committing generic session
continuity.

Use this helper for `to=None` discovery ingress when you want to:

* verify sender identity and envelope signature,
* require discovery-safe session semantics,
* update peer learning through the configured peer-key store,
* promote the sender to a verified peer after successful discovery validation,
* apply replay protection through the configured replay store,
* avoid turning broadcast discovery into a generic session-continuity workflow.

**Required discovery semantics**

`verify_discovery_envelope(...)` accepts only discovery/public envelopes with:

* `to is None`
* role-0 start-form
* non-stream mode
* plaintext payload (`payload` must not be an encrypted payload object)

**What it honors**

* custom `peer_key_store` hooks
* custom `replay_store` hooks
* policy-event emission for phase `verify_discovery_envelope`

**What it intentionally does not do**

* session verification hooks
* session registration hooks
* generic session continuity commit

**Return shape**

* Default: plaintext payload on success, else `None`
* If `return_status=True`: `{ok, code, phase, data?}`

**When to use it**

* Use `verify_discovery_envelope(...)` for peer discovery and public ingress.
* Use `open_envelope(...)` when you actually want session continuity verification and
  session-state commit on a peer/session lane.

## End-to-end examples

### Two-party encrypted conversation

```python
# inside an async function / handler
# Alice side
alice = SummonerIdentity(ttl=86400, margin=5)
alice_id = alice.id("alice_id.json", password=b"alice_pw")

# Bob side
bob = SummonerIdentity(ttl=86400, margin=5)
bob_id = bob.id("bob_id.json", password=b"bob_pw")

# Exchange alice_id and bob_id out-of-band (or via some directory)

# Alice starts a session and sends first encrypted message
s0 = await alice.start_session(bob_id)
env1 = await alice.seal_envelope({"msg": "hello bob"}, s0, to=bob_id)

# Bob receives and opens
payload1 = await bob.open_envelope(env1)
peer_session_1 = env1["session_proof"]      # peer's session proof for continuity
alice_peer = env1["from"]                   # verified sender identity from envelope
# Bob computes next session and replies
s1 = await bob.continue_session(alice_peer, peer_session_1)
env2 = await bob.seal_envelope({"msg": "hello alice"}, s1, to=alice_peer)

# Alice opens bob's reply
payload2 = await alice.open_envelope(env2)
```

Key points:

* `start_session()` always begins with role 0 and carries `history_proof` if available.
* `continue_session()` derives the next proof from the peer's proof.
* `seal_envelope()` encrypts when `to` is provided.
* `open_envelope()` validates signature, continuity, and decrypts.

---

### Streamed response turn

```python
# inside an async function / handler
# Requester (Alice) sends a normal request.
s0 = await alice.start_session(bob_id)
env0 = await alice.seal_envelope({"msg": "request"}, s0, to=bob_id)
assert await bob.open_envelope(env0) == {"msg": "request"}

# Responder (Bob) starts stream mode on continue path.
s1 = await bob.continue_session(alice_id, env0["session_proof"], stream=True, stream_ttl=30)
env1 = await bob.seal_envelope({"delta": "part-1"}, s1, to=alice_id)
assert await alice.open_envelope(env1) == {"delta": "part-1"}

# Same sender advances stream with chunk frame.
s2 = await bob.advance_stream_session(alice_id, s1, end_stream=False, stream_ttl=30)
env2 = await bob.seal_envelope({"delta": "part-2"}, s2, to=alice_id)
assert await alice.open_envelope(env2) == {"delta": "part-2"}

# End frame closes stream and hands turn back via ttl.
s3 = await bob.advance_stream_session(alice_id, s2, end_stream=True, ttl=120)
env3 = await bob.seal_envelope({"done": True}, s3, to=alice_id)
assert await alice.open_envelope(env3) == {"done": True}

# Alice continues with normal non-stream reply.
s4 = await alice.continue_session(bob_id, env3["session_proof"], stream=False)
env4 = await alice.seal_envelope({"ack": True}, s4, to=bob_id)
```

The symmetric initiator-owned stream path is also valid:

```python
s0 = await alice.start_session(bob_id, stream=True, stream_ttl=30)
env0 = await alice.seal_envelope({"delta": "part-1"}, s0, to=bob_id)
assert await bob.open_envelope(env0) == {"delta": "part-1"}

s1 = await alice.advance_stream_session(bob_id, s0, end_stream=False, stream_ttl=30)
env1 = await alice.seal_envelope({"delta": "part-2"}, s1, to=bob_id)
assert await bob.open_envelope(env1) == {"delta": "part-2"}

s2 = await alice.advance_stream_session(bob_id, s1, end_stream=True, ttl=120)
env2 = await alice.seal_envelope({"done": True}, s2, to=bob_id)
assert await bob.open_envelope(env2) == {"done": True}
```

Key points:

* Stream continuity uses `stream.id` + contiguous `stream.seq`.
* Non-end stream frames are governed by `stream_ttl` (no receiver margin).
* After end frame, normal `ttl` handoff contract applies for the next side.

---

### Plaintext envelope (to=None)

This is useful for discovery/broadcast where you want signed messages but not encryption.

```python
# inside an async function / handler
identity = SummonerIdentity()
my_id = identity.id("id.json")

s0 = await identity.start_session(peer_public_id=None)
env = await identity.seal_envelope({"announcement": "hello"}, s0, to=None)

# Receiver can still verify signature and read payload (no decryption).
# For discovery-only learning, prefer the discovery verifier:
st = await identity.verify_discovery_envelope(env, return_status=True)
assert st["ok"] is True
assert st["data"] == {"announcement": "hello"}
```

Important convention:

* `to=None` uses a generic session slot shared across senders.
* This is a discovery-only flow and does not establish per-peer continuity.
* `verify_discovery_envelope(...)` is the preferred receiver-side helper when you
  only want to validate discovery ingress, honor peer/replay hooks, and update
  peer learning without committing generic session continuity.
* `open_envelope(...)` remains available for generic-slot validation, but in
  multi-peer broadcast discovery it may surface generic-slot continuity pressure
  that is irrelevant to simple peer learning.
* If you want to reply to a discovery message, start a new per-peer session:
  `start_session(peer_public_id)` and then `seal_envelope(..., to=peer_public_id)`.
* For multi-tenant discovery services (for example, a Rust server), treat `to=None`
  as ingress-only: verify and record `from` into your presence set (for example
  `online_agent_ids.add(from)`), then respond per-client with `to=from`.
  Do not build long-lived continuity on `to=None`.
* Discovery helpers:
  * `list_known_peers()` and `find_peer(text)` can be used to browse learned peers.
  * `list_verified_peers()` is the safer selector for choosing conversation
    candidates after successful discovery/open verification.
  * The fallback peer cache is populated by both `open_envelope(...)` and
    `verify_discovery_envelope(...)`, and successful validation on those paths can
    promote a peer into the verified set.
  * They are authoritative with fallback peer store; with custom
    `_peer_key_store_handler`, keep fallback cache synced or provide your own query API.

Server-side discovery model:

```python
# inside an async function / handler
# Client -> server discovery
s0 = await client.start_session(None)
env_hello = await client.seal_envelope({"op": "discover"}, s0, to=None)

# Server verifies identity/signature, updates presence, then replies per peer.
client_id = env_hello["from"]
ids.add(client_id)
s_srv = await server.start_session(client_id)
env_reply = await server.seal_envelope({"agents_online": ids}, s_srv, to=client_id)
```

This works with current `SummonerIdentity` clients:
* inbound discovery (`to=None`) is signed but plaintext;
* outbound server reply (`to=client_id`) is encrypted and continuity-safe.

---

### Custom session storage hooks

If you want SQLite/Redis/etc, implement the hooks and keep the rest unchanged.

This example uses class-level hooks for brevity, but the same pairing can be expressed with:

* `SummonerIdentityControls` plus `identity.attach_controls(controls)`, or
* instance-local decorators on one live object via `@identity.on_*`

The important rule is unchanged: `register_session` and `verify_session` must be configured in the same hook scope.

```python
identity = SummonerIdentity()

@SummonerIdentity.get_session
def my_get_session(peer_public_id, local_role):
    # Example: keep default lookup behavior.
    return identity.get_session_default(peer_public_id, local_role)

@SummonerIdentity.verify_session
def my_verify_session(peer_public_id, local_role, session_record, use_margin=False):
    # Add policy on top of default verifier.
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@SummonerIdentity.register_session
def my_register_session(peer_public_id, local_role, session_record, new=False, use_margin=False):
    # Keep default persistence behavior (or wrap with your own DB write path).
    return identity.register_session_default(
        peer_public_id,
        local_role,
        session_record,
        new=new,
        use_margin=use_margin,
    )

@SummonerIdentity.reset_session
def my_reset_session(peer_public_id, local_role):
    # Keep default reset semantics.
    return identity.reset_session_default(peer_public_id, local_role)
```

## Notes for implementers

* If you see mismatched decryption or history_proof failures, the first place to inspect is AAD construction:

  * `_payload_aad_bytes(...)`
  * `_history_proof_aad_bytes(...)`
    Direction (`from/to`) must match between sender and receiver logic.
* If session verification rejects messages unexpectedly, compare your hook behavior to:

  * `verify_session_default(...)`
    Focus on:
  * start-form rule (`not(x)_nonce is None`)
  * `not(x)_nonce` equality check against stored `current_link`
  * x nonce freshness vs `past_chain` and `seen`
  * start-form normalization and stream-aware staleness via `_is_stale_current_link(...)`
* If debugging production reject spikes, register `on_policy_event(phase="open_envelope")` and inspect:

  * `event_name`/`code`,
  * `validation_stage` for failure depth,
  * reset-abuse signal `replaced_active_incomplete` on `ok` events.
* If your application needs forward secrecy, you typically introduce ephemeral X25519 for each message or rotate long-term identity keys on a schedule.

### Forward secrecy note

This protocol **does not provide forward secrecy** by default because it uses static X25519 identity keys.
The history hash/history_proof mechanism is about **continuity and decentralized identity**, not secrecy:
it lets a peer prove knowledge of a rolling history hash without revealing it.

If you need forward secrecy, add ephemeral X25519 keys per session (or per message) and mix them into
the HKDF derivation.
