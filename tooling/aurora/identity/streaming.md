# Summoner Identity Streaming API Reference (`identity.py`)

`SummonerIdentity` supports streaming by extending the session proof with
turn-owned stream metadata. This reference documents the current streaming API,
validation rules, persistence model, telemetry surface, and operational
behavior implemented in `tooling/aurora/identity/identity.py`.

Async note:
- `id(...)` is synchronous (typically called once at startup).
- Streaming/messaging lifecycle methods are async; snippets in this document assume an async context and use `await`.
- Custom hooks and `on_policy_event` handlers can be sync or async; async handlers are awaited.
- Snippet convention: blocks that include `await` start with `# inside an async function / handler` instead of repeating `asyncio.run(...)`.

## Contents

1) Scope and design intent
2) Streaming model (turn ownership and lifecycle)
3) Session proof schema for stream mode
4) Public API reference
5) Stream state machine and invariants
6) Verification and timeout semantics
7) Persistence model (fallback store)
8) Error/status codes (stream-related)
9) Policy event telemetry for streaming
10) Custom hook contract for streaming-safe integrations
11) Implementation notes
12) End-to-end examples
13) Operational checklist

## 1) Scope and design intent

Streaming extends the existing nonce-chain continuity protocol so one sender can emit multiple frames in the same turn.

Core goals:

1. Preserve existing single-message behavior by default.
2. Add explicit stream start/chunk/end semantics.
3. Enforce contiguous ordering and timeout safety.
4. Keep crypto/signature/replay guarantees unchanged.
5. Emit useful stream telemetry for policy and operations.

Non-goals:

1. No streaming over discovery/public `to=None` slots.
2. No out-of-order or gap-tolerant acceptance policy in fallback path.

## 2) Streaming model (turn ownership and lifecycle)

A stream is turn-owned continuity metadata attached to normal session proofs.

Lifecycle:

1. Start frame:
`mode="stream"` and `stream.phase="start"` with `stream.seq=0`.
2. Progress frames:
`stream.phase="chunk"` and strictly increasing contiguous `seq`.
3. End frame:
`stream.phase="end"` closes stream continuity and hands control back via normal `ttl`.

Design rule:

- Non-end stream frames are governed by `stream_ttl`.
- End stream frames are governed by normal session `ttl` (response contract).

## 3) Session proof schema for stream mode

Streaming uses the same session proof envelope, with additional fields:

```json
{
  "sender_role": 1,
  "0_nonce": "<hex>",
  "1_nonce": "<hex>",
  "ts": 1730000000,
  "ttl": 120,
  "history_proof": null,
  "age": 0,
  "mode": "stream",
  "stream": {
    "id": "a1b2c3d4e5f6a7b8",
    "seq": 0,
    "phase": "start"
  },
  "stream_ttl": 60
}
```

The example above shows a responder-owned stream start (`continue_session(..., stream=True, ...)`).
Initiator-owned stream starts created by `start_session(..., stream=True, ...)`
use `sender_role = 0` with `1_nonce = null`. Their later `chunk` and `end`
frames keep the same stream owner (`sender_role = 0`) and remain continuation
frames even though `1_nonce` stays `null`.

Age note:

- `age: 0` in the example is illustrative only.
- In ordinary reply/continue paths, the implementation preserves the active
  continuity age when available instead of resetting it to zero.

Normalization and validity rules:

The following table defines the strict schema contract for stream-related
fields in `session_proof`. It can be used to validate a constructed proof
before it reaches `seal_envelope(...)` or `open_envelope(...)`.

| Field | Type | Rule |
| --- | --- | --- |
| `mode` | `"single" \| "stream"` | Required for explicit stream semantics (if `mode`/`stream` are omitted, classification normalizes to single mode). |
| `stream` | `null \| {"id": str, "seq": int, "phase": "start"\|"chunk"\|"end"}` | Required when `mode="stream"`. |
| `stream_ttl` | `null \| int` | Required on stream `start`/`chunk`; generated as `null` on stream `end`; forbidden in single mode. |

Reject matrix:

The reject matrix clarifies combinations that are explicitly disallowed, even when the rest of the session proof looks well-formed.

| Condition | Result |
| --- | --- |
| `mode="single"` + non-null `stream` | Reject |
| `mode="single"` + non-null `stream_ttl` | Reject |
| `mode="stream"` + missing/malformed `stream` | Reject |
| stream `start`/`chunk` without valid positive `stream_ttl` | Reject |
| unsupported `mode` value | Reject |

Classification helper:

- `classify_session_record(session_record)` returns stream classification fields (`is_stream`, `stream_phase`, `stream_ttl_valid`, `record_expired`, etc.) and is the canonical parser used by method guards and fallback verify logic.

Classifier output groups:

`classify_session_record(...)` is record-local and intentionally store-agnostic.
The grouped fields below are useful as a quick map of what the classifier can and cannot decide on its own.

| Output group | Fields |
| --- | --- |
| Mode/shape | `mode`, `is_stream`, `stream_fields_valid`, `valid_shape` |
| Stream identity | `stream_id`, `stream_seq`, `stream_phase` |
| Stream form | `is_stream_start`, `is_stream_end`, `is_start_form` |
| TTL self-check | `has_ttl`, `ttl_valid`, `has_stream_ttl`, `stream_ttl_valid` |
| Expiry self-check | `record_expired`, `record_expiry_basis` |

For stream-mode records, `is_start_form` is phase-aware:

- `phase="start"` => start-form
- `phase="chunk"` or `phase="end"` => continuation form

This matters most for initiator-owned streams, where the opposite nonce can
remain `null` across `start`, `chunk`, and `end` frames.

## 4) Public API reference

The summary table below is a quick index of the streaming API surface.
Detailed method-level contracts follow immediately after it.

| Method | Signature delta | Semantics |
| --- | --- | --- |
| `start_session` | `stream: bool = False, stream_ttl: Optional[int] = None` | `stream=True` emits stream-start (`mode="stream"`, `phase="start"`, `seq=0`) with generated stream id. |
| `continue_session` | `stream: bool = False, stream_ttl: Optional[int] = None` | `stream=True` starts responder-owned stream turn (`phase="start"`, `seq=0`). |
| `advance_stream_session` | New method | Same-sender stream progression (`chunk` or `end`) with automatic contiguous sequence increment. |

## 4.1 `start_session(..., stream=False, stream_ttl=None, ...)`

Signature:

```python
start_session(
    peer_public_id: Optional[dict] = None,
    ttl: Optional[int] = None,
    stream: bool = False,
    stream_ttl: Optional[int] = None,
    *,
    force_reset: bool = False,
    return_status: bool = False,
) -> Any
```

Streaming behavior:

1. `stream=True` emits a stream-start proof:
   - `mode="stream"`
   - `stream={"id": <generated>, "seq": 0, "phase": "start"}`
   - `stream_ttl=<int>`
2. Active-session gating is stream-aware:
   a live current link can remain active on stream progress even when the
   original requester-window `ttl` would otherwise look old.
3. Rejects stream on `peer_public_id=None` with `stream_mode_unsupported`.
4. Rejects invalid/missing stream TTL with `stream_ttl_invalid`.

## 4.2 `continue_session(..., stream=False, stream_ttl=None, ...)`

Signature:

```python
continue_session(
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

Streaming behavior:

1. `stream=False` while a local stream is active is rejected with `stream_active_continue_blocked`.
2. `stream=True` starts a responder-owned stream (`phase="start"`, `seq=0`) on successful continue path.
3. `stream=True` requires valid positive `stream_ttl`.
4. `stream=True` with `peer_public_id=None` is rejected (`stream_mode_unsupported`).
5. If the current link is missing or stale, role 0 may restart through
   `start_session(...)`, while role 1 fails closed.
6. Non-stream continue preserves the active continuity `age` when available,
   falling back to the peer-presented age only when needed.

## 4.3 `advance_stream_session(...)`

Signature:

```python
advance_stream_session(
    peer_public_id: Optional[dict],
    session: dict,
    *,
    end_stream: bool = False,
    ttl: Optional[int] = None,
    stream_ttl: Optional[int] = None,
    return_status: bool = False,
) -> Any
```

Contract:

1. Requires stream-mode session input (`invalid_stream_session` otherwise).
2. Requires peer context (`peer_public_id` must not be `None`).
3. Requires active matching stream in store; otherwise:
   - `stream_not_active`, or
   - `stream_interrupted` on stream-id/state mismatch.
4. Increments `seq` by exactly `+1`.
5. `end_stream=False`:
   - emits `phase="chunk"`
   - requires valid positive `stream_ttl`
6. `end_stream=True`:
   - emits `phase="end"`
   - applies handoff `ttl` (normal turn response window)
   - stores `stream_ttl=None` in generated end frame.

## 4.4 `seal_envelope(...)` stream guards

Before signature/encryption, stream schema is validated:

1. Invalid `mode` -> `invalid_stream_mode`
2. Stream mode with malformed stream object -> `invalid_stream_fields`
3. Non-end stream without valid `stream_ttl` -> `stream_ttl_invalid`
4. Stream mode in unsupported boundary (`to=None`) -> `stream_mode_unsupported`

Crypto flow is unchanged after these guards pass.

## 4.5 `open_envelope(...)` stream-aware acceptance

Open path preserves validation order and adds stream-aware continuity semantics:

1. Verify session continuity using structured verify result (`ok/code/reason`).
2. Enforce first-responder boundary TTL only on stream start boundary, not every chunk.
3. For stream non-end frames:
   - enforce strict `stream_ttl` (no margin),
   - skip requester-window TTL rejection on commit persistence.
4. On stream timeout/interruption failure, fallback store marks stream interrupted/closed.

Return shape is unchanged:

- default: payload value or `None` (use `return_status=True` if `None` payloads are valid in your app)
- `return_status=True`: `{ok, code, phase, data?}`

## 5) Stream state machine and invariants

Fallback verification enforces contiguous stream policy.
Read this transition table as the protocol acceptance boundary for stream progression.
If a row is marked disallowed, fallback verify will reject with the mapped stable stream code.

| Current state | Next frame | Allowed | Failure code on reject |
| --- | --- | --- | --- |
| no active stream | `start(seq=0)` | Yes | - |
| no active stream | `chunk/end` | No | `stream_not_active` or `stream_interrupted` |
| active `start(seq=n)` | `chunk/end(seq=n+1)` | Yes | - |
| active `chunk(seq=n)` | `chunk/end(seq=n+1)` | Yes | - |
| active stream | repeated `start` | No | `stream_already_active` |
| active stream `id=A` | frame with `id=B` | No | `stream_state_conflict` |
| active stream | invalid phase progression | No | `stream_phase_invalid` |
| active stream | non-contiguous sequence | No | `stream_seq_invalid` |

A minimal progression example:

```python
# inside an async function / handler
# valid progression
s1 = await bob.continue_session(pub_a, env0["session_proof"], stream=True, stream_ttl=30)  # start seq=0
s2 = await bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30)           # chunk seq=1
s3 = await bob.advance_stream_session(pub_a, s2, end_stream=True, ttl=120)                  # end seq=2
```

## 6) Verification and timeout semantics

Timeout rules are intentionally split:
This split is important because stream progress safety (`stream_ttl`) and turn handoff (`ttl`) serve different protocol goals.
Treat this table as the normative timing contract for receiver behavior.

| Rule | Requirement |
| --- | --- |
| Frame timestamp refresh | `ts` is refreshed on every generated `start/chunk/end` frame. |
| Progress window | Non-end stream frames must satisfy `now <= ts + stream_ttl`. |
| Handoff window | End frames use normal `ttl` response contract. |
| Receiver margin | Receiver stream timeout verification does not apply `margin`. |
| Request-window boundary | First responder stream boundary is checked against requester `ttl`; later chunks are governed by stream state and `stream_ttl`. |

Important boundary behavior:

1. Original requester-window enforcement for responder stream is checked at first stream boundary (`is_stream_start`).
2. After that boundary passes, subsequent stream chunks are governed by stream state + `stream_ttl`, not repeatedly by original requester `ttl`.
3. During fresh stream-start admission after restart, fallback verification normalizes
   a stale persisted `current_link` to absent local state; for stream-active links,
   staleness is evaluated from `stream_last_ts + stream_ttl` rather than only from
   the original requester window.

Interruption closure behavior:

After a timeout/interruption verdict, fallback storage transitions into a closed-state model.
This table explains what behavior changes after closure and what recovery path is expected.

| Failure/recovery rule | Behavior |
| --- | --- |
| Timeout/interruption closure | Stream state is closed in fallback storage (`stream_active=False`, terminal phase). |
| Post-closure attempts | Later frames on closed stream id return `stream_interrupted` (with `stream_reason` when available). |
| Recovery path | Continue using normal lifecycle (`start_session` / new stream start per policy). |

## 7) Persistence model (fallback store)

Current-link stream fields persisted in fallback storage:
These fields are the minimum state needed for contiguous enforcement, timeout handling, and stream observability.
If you implement custom storage hooks, mirroring this shape is the safest path.

The fields below describe the inner `current_link` state stored inside
`sessions.json["data"][<lane>]`, not the outer wrapped store document. The
full file format is versioned and uses `__summoner_identity_store__`, `v`, and
`data`.

| Field | Purpose |
| --- | --- |
| `stream_mode` | Single vs stream tracking for current link. |
| `stream_id` | Active/closed stream identity. |
| `stream_phase` | Last accepted stream phase (`start/chunk/end/interrupted`). |
| `expected_next_seq` | Contiguous sequence validator state. |
| `stream_active` | Active vs closed marker. |
| `stream_last_ts` | Timestamp of last accepted stream frame. |
| `stream_ttl` | Last accepted progress timeout value. |
| `missing_ranges` | Reserved for optional gap-tolerant policies. |
| `stream_reason` | Optional closure/interruption reason metadata. |

Closure semantics:

1. End frames persist `stream_active=False` via normal record replacement.
2. Timeout/interruption marks `stream_phase="interrupted"` and `stream_active=False`.
3. `expected_next_seq` is cleared on interrupted closure.

## 8) Error/status codes (stream-related)

This code table is designed for quick triage and test assertions.
It maps each stream code to where it typically appears and what it means operationally.

| Code | Typical method/phase | Meaning |
| --- | --- | --- |
| `invalid_stream_mode` | `seal_envelope` / `open_envelope` | Unsupported `mode` value. |
| `invalid_stream_fields` | `seal_envelope` / `open_envelope` | Stream object/shape invalid for mode. |
| `invalid_stream_session` | `advance_stream_session` | Input session is not valid stream context. |
| `stream_mode_unsupported` | `start_session`, `continue_session`, `advance_stream_session`, `seal_envelope`, `open_envelope` | Stream requested/received on unsupported boundary (for example discovery/public slot). |
| `stream_ttl_invalid` | `start_session`, `continue_session`, `advance_stream_session`, `seal_envelope`, `open_envelope` | Missing/invalid non-end `stream_ttl`. |
| `stream_ttl_expired` | `open_envelope` | Inbound non-end stream frame exceeded `ts + stream_ttl`. |
| `stream_phase_invalid` | `open_envelope` | Invalid phase transition for current stream state. |
| `stream_seq_invalid` | `open_envelope` | Sequence not contiguous with expected-next state. |
| `stream_state_conflict` | `open_envelope` | Stream id/state conflict against persisted active stream. |
| `stream_not_active` | `open_envelope`, `advance_stream_session` | Non-start progression attempted without active stream. |
| `stream_already_active` | `open_envelope` | New stream start conflicts with already active stream. |
| `stream_active_continue_blocked` | `continue_session` | Non-stream continue attempted while local stream is active. |
| `stream_interrupted` | `open_envelope`, `advance_stream_session` | Frame targets closed/interrupted stream or stream-id mismatch on advance. |

Custom verify hooks (beginner-friendly):

If you implement your own `verify_session` hook, there are two output styles.
Use the structured style when you want precise stream errors.

1. Boolean result form:
   - Return `True` or `False`.
   - If you return `False`, detail is lost and status becomes `session_verify_failed`.
2. Structured style (recommended):
   - Return a dict like `{"ok": False, "code": "stream_ttl_expired", "reason": "frame arrived too late"}`.
   - `reason` is optional, but useful for policy events and debugging.
3. Malformed structured output:
   - If `ok` is missing or not a boolean, the system returns `session_verify_failed`.

## 9) Policy event telemetry for streaming

Streaming integrates with phase-scoped policy events.
The first table maps methods to emitted phases, so you can register the right handlers at the right lifecycle point.

| Method | Emitted phase |
| --- | --- |
| `start_session(...)` | `start_session` |
| `continue_session(...)` | `continue_session` |
| `advance_stream_session(...)` | `advance_stream_session` |
| `seal_envelope(...)` | `seal_envelope` |
| `open_envelope(...)` | `open_envelope` |

Stream event extras (when applicable):

These extras are intentionally compact and stable.
They are sufficient for stream observability, cooldown logic, and per-peer stream lifecycle analytics.

| Field | Meaning |
| --- | --- |
| `stream_mode` | Parsed mode (`single`/`stream`). |
| `stream_id` | Stream identity from session proof. |
| `stream_phase` | Stream phase from session proof. |
| `stream_seq` | Stream sequence from session proof. |
| `stream_policy` | Current verifier policy label (`contiguous`). |
| `stream_reason` | Structured verify reason or persisted interruption reason. |
| `stream_ttl` | Stream TTL value from proof when present. |
| `stream_expired` | Record-local expiry indicator from classifier context. |
| `stream_started_ts` | Optional start timestamp when known at emitter. |
| `stream_last_ts` | Optional most recent stream frame timestamp when known at emitter. |
| `stream_frame_count` | Optional derived frame count (`stream_seq + 1`). |

Where `stream_reason` comes from:

1. Structured verify result `reason`, when returned by verify path.
2. Closed-stream fallback state, when interruption reason was recorded.

### 9.1 Streaming event matrix

Use this matrix as a troubleshooting map from observed event code to likely trigger location.
It is also a practical checklist for stream test coverage across all phases.

| Method | Phase | Event name (`code`) | Trigger |
| --- | --- | --- | --- |
| `start_session(..., stream=True, ...)` | `start_session` | `stream_ttl_invalid` | Missing/invalid `stream_ttl` for stream start. |
| `start_session(peer_public_id=None, stream=True, ...)` | `start_session` | `stream_mode_unsupported` | Stream requested on unsupported boundary. |
| `continue_session(..., stream=False)` | `continue_session` | `stream_active_continue_blocked` | Active local stream exists and non-stream continue attempted. |
| `continue_session(..., stream=True, ...)` | `continue_session` | `stream_ttl_invalid` | Missing/invalid `stream_ttl` for responder stream start. |
| `continue_session(peer_public_id=None, stream=True, ...)` | `continue_session` | `stream_mode_unsupported` | Stream requested on unsupported boundary. |
| `seal_envelope(...)` | `seal_envelope` | `invalid_stream_mode` | Outbound session has unsupported `mode`. |
| `seal_envelope(...)` | `seal_envelope` | `invalid_stream_fields` | Outbound stream fields fail schema guard. |
| `seal_envelope(...)` | `seal_envelope` | `stream_ttl_invalid` | Outbound non-end stream frame has invalid `stream_ttl`. |
| `open_envelope(...)` | `open_envelope` | `stream_ttl_expired` | Inbound non-end stream frame violates `now <= ts + stream_ttl`. |
| `open_envelope(...)` | `open_envelope` | `stream_interrupted` | Inbound frame targets closed/interrupted stream state. |
| `open_envelope(...)` | `open_envelope` | `stream_seq_invalid` | Inbound stream sequence violates expected policy. |
| `open_envelope(...)` | `open_envelope` | `stream_phase_invalid` | Inbound phase transition invalid for current stream state. |
| `open_envelope(...)` | `open_envelope` | `stream_state_conflict` | Inbound stream id conflicts with active stream state. |
| `open_envelope(...)` | `open_envelope` | `stream_not_active` | Non-start frame received without active stream. |
| `open_envelope(...)` | `open_envelope` | `stream_already_active` | New start conflicts with already-active stream. |
| `advance_stream_session(...)` | `advance_stream_session` | `invalid_stream_session` | Input session is not valid stream-mode context. |
| `advance_stream_session(..., end_stream=False)` | `advance_stream_session` | `stream_not_active` | No active stream to advance. |
| `advance_stream_session(..., end_stream=False)` | `advance_stream_session` | `stream_ttl_invalid` | Missing/invalid `stream_ttl` on non-end frame. |
| `advance_stream_session(...)` | `advance_stream_session` | `stream_interrupted` | Advance attempted on mismatched/closed stream state. |

## 10) Custom hook contract for streaming-safe integrations

Custom storage or verification hooks must preserve the invariants in this
section. `SummonerIdentityControls` simply means that those custom callbacks
are attached to one `SummonerIdentity` instance instead of being made global.

If you use custom hooks (`verify_session`, `register_session`, `get_session`, etc.), whether through class decorators, `SummonerIdentityControls`, or instance-local `@identity.on_*` hooks, stream correctness depends on preserving these invariants:

1. Maintain per-peer+role stream fields equivalent to fallback model.
2. Enforce contiguous `seq` and stream-id continuity.
3. Enforce strict non-end `stream_ttl` checks (no margin).
4. Preserve closure semantics (`stream_active=False` on end/interruption).
5. Return structured verify results for precise stream codes and reasons.
6. Configure `register_session` and `verify_session` in the same hook scope.

Recommended minimal verify return:

```python
{"ok": False, "code": "stream_interrupted", "reason": "frame_on_closed_stream"}
```

## 11) Implementation notes

The current implementation includes several stream behaviors that are important operationally:

1. Timeout-closure reason propagation:
   - When fallback verify returns `stream_ttl_expired`, fallback closure marks interrupted state with `stream_reason="timeout_closed"`.
   - Later attempts on the same closed stream id can return `stream_interrupted` with this reason.
2. Optional stream timing/count telemetry is automatically emitted on open events:
   - `stream_started_ts`
   - `stream_last_ts`
   - `stream_frame_count`
3. Transition-level phase invalidation is explicit:
   - Active streams must progress `start/chunk -> chunk/end`, else `stream_phase_invalid`.

Operational meaning:

1. First late frame usually reports root cause: `stream_ttl_expired`.
2. Subsequent attempts report closed-state condition: `stream_interrupted` with reason context.

This preserves lifecycle signaling accuracy while retaining root-cause observability.

## 12) End-to-end examples

## 12.1 Request -> streamed response -> handoff

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity

alice = SummonerIdentity(ttl=120, margin=0)
bob = SummonerIdentity(ttl=120, margin=0)

alice.id("/tmp/alice_id.json")
bob.id("/tmp/bob_id.json")

pub_a = alice.public_id
pub_b = bob.public_id

# Alice request (single)
s0 = await alice.start_session(pub_b)
env0 = await alice.seal_envelope({"msg": "request"}, s0, to=pub_b)
assert await bob.open_envelope(env0) == {"msg": "request"}

# Bob begins streamed turn
s1 = await bob.continue_session(pub_a, env0["session_proof"], stream=True, stream_ttl=30)
env1 = await bob.seal_envelope({"delta": "part-1"}, s1, to=pub_a)
assert await alice.open_envelope(env1) == {"delta": "part-1"}

# Bob sends another chunk
s2 = await bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30)
env2 = await bob.seal_envelope({"delta": "part-2"}, s2, to=pub_a)
assert await alice.open_envelope(env2) == {"delta": "part-2"}

# Bob closes stream and hands turn back
s3 = await bob.advance_stream_session(pub_a, s2, end_stream=True, ttl=120)
env3 = await bob.seal_envelope({"done": True}, s3, to=pub_a)
assert await alice.open_envelope(env3) == {"done": True}

# Alice can now continue normally
s4 = await alice.continue_session(pub_b, env3["session_proof"], stream=False)
assert isinstance(s4, dict)
```

The symmetric initiator-owned stream path is also valid:

```python
# inside an async function / handler
s0 = await alice.start_session(pub_b, stream=True, stream_ttl=30)
env0 = await alice.seal_envelope({"delta": "part-1"}, s0, to=pub_b)
assert await bob.open_envelope(env0) == {"delta": "part-1"}

s1 = await alice.advance_stream_session(pub_b, s0, end_stream=False, stream_ttl=30)
env1 = await alice.seal_envelope({"delta": "part-2"}, s1, to=pub_b)
assert await bob.open_envelope(env1) == {"delta": "part-2"}

s2 = await alice.advance_stream_session(pub_b, s1, end_stream=True, ttl=120)
env2 = await alice.seal_envelope({"done": True}, s2, to=pub_b)
assert await bob.open_envelope(env2) == {"done": True}

s3 = await bob.continue_session(pub_a, env2["session_proof"], stream=False)
assert isinstance(s3, dict)
```

## 12.2 Policy telemetry on stream failures

```python
events = []

@alice.on_policy_event(phase="open_envelope")
def _on_open(name, ctx):
    if name.startswith("stream_"):
        events.append((name, ctx.get("stream_reason"), ctx.get("stream_id")))
```

Use this to:

1. detect timeout pressure (`stream_ttl_expired`),
2. detect repeated closed-stream retries (`stream_interrupted` + `timeout_closed`),
3. enforce cooldown/quarantine in custom verify policies.

## 12.3 Guard and failure snippets

### A) Active stream blocks non-stream continue

```python
# inside an async function / handler
st = await bob.continue_session(pub_a, env1["session_proof"], stream=False, return_status=True)
assert st["ok"] is False
assert st["code"] == "stream_active_continue_blocked"
```

### B) Stream unsupported for discovery/public slot

```python
# inside an async function / handler
st = await alice.start_session(None, stream=True, stream_ttl=60, return_status=True)
assert st["ok"] is False
assert st["code"] == "stream_mode_unsupported"
```

### C) Late chunk timeout then closed-stream interruption

```python
# inside an async function / handler
late = await bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=5)
env_late = await bob.seal_envelope({"delta": "late"}, late, to=pub_a)

# with receiver time beyond ts + stream_ttl
st1 = await alice.open_envelope(env_late, return_status=True)
assert st1["ok"] is False
assert st1["code"] == "stream_ttl_expired"

st2 = await alice.open_envelope(env_late, return_status=True)
assert st2["ok"] is False
assert st2["code"] == "stream_interrupted"
```

### D) Policy event exposes closed-stream reason

```python
seen = []

@alice.on_policy_event(phase="open_envelope")
def _open(name, ctx):
    if name == "stream_interrupted":
        seen.append(ctx.get("stream_reason"))

# after timeout-closure flow above:
assert "timeout_closed" in seen
```

## 13) Operational checklist

Before enabling stream mode in production, verify:

1. You always set explicit `stream_ttl` for stream starts/chunks.
2. Your sender pacing ensures next frame arrives before `ts + stream_ttl`.
3. Your custom hooks (if any) preserve contiguous seq + close semantics.
4. You collect `open_envelope` stream events for observability.
5. You treat `stream_ttl_expired` and `stream_interrupted` as distinct but related signals.

If you need strict custom behavior (for example alternate stream policies), implement it in custom verify/register hooks and keep structured verify codes/reasons stable.
