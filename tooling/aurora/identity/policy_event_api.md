# Policy Event API Guide and Reference (`identity.py`)

`SummonerIdentity` emits structured policy events at lifecycle boundaries.
This guide documents the event schema, registration API, and the operational
patterns that turn those events into enforcement and monitoring.

Async note:
- `id(...)` is synchronous (typically called once at startup).
- Messaging/session lifecycle methods are async and emit events from async return paths.
- Policy handlers can be synchronous or async; async handlers are awaited.

Suggested order for initial use:

1. Sections 1-3 to understand intent and mental model.
2. Sections 4-6 to learn the exact contract and event shape.
3. Sections 7-11 to operationalize telemetry into enforcement.
4. Sections 12-15 as production guardrails and quick-reference closure.

## 1) Why this API exists

`SummonerIdentity` already enforces protocol-level checks (identity validity, signatures, session continuity checks, replay checks, decrypt checks, storage commit).

This API provides a stable, structured way to observe outcomes and feed those outcomes back into policy decisions.

Without this API, most teams end up with one of two bad outcomes:

1. no visibility into failure shape (everything is just `None` / failure),
2. ad-hoc logging that is hard to aggregate, compare, and automate.

The policy event API solves this by emitting small, structured events at lifecycle boundaries.

It does not change core cryptographic semantics. It makes outcomes observable and operationally actionable.

## 2) Design vision and principles

The design choices below define what remains stable, what is intentionally
constrained, and where integrations can extend behavior safely.

The API follows a few explicit principles:

1. Deterministic emission points.
Each event comes from an existing lifecycle return path (`_ret(...)`) so behavior is consistent.

2. Stable base schema.
Every event has a minimal common context (`schema_version`, `phase`, `code`, etc.) so pipelines can decode safely.

3. Tight optional field discipline.
Only a whitelist of optional keys can pass into event context. This prevents context drift and accidental data leakage.

4. Isolation from handler failures.
Handler exceptions are caught and logged; they must not change protocol return outcomes.

5. Hook composition.
Telemetry should not be just dashboards. It should feed policy hooks (`verify_session`, etc.) via shared state.

6. O(1)-friendly signal extraction.
Fields and logic are chosen so common high-traffic decisions (counters, thresholds, quarantines) remain constant-time per event.

Taken together, these principles make the API predictable for production telemetry while still allowing custom policy behavior.

## 3) Mental model

Use this API as a 3-stage loop:

1. Observe:
`on_policy_event(phase=...)` receives `(event_name, context)`.

2. Classify:
increment counters, update a per-peer score, detect spikes by `validation_stage`, track reset pressure.

3. Enforce:
policy hooks (`verify_session`, `register_session`, etc.) read those in-memory decisions and allow/deny accordingly.

The key idea is that telemetry and enforcement are connected through your own policy state, not through implicit built-in behavior.

Trust-boundary reminder:

- `list_known_peers()` is a discovery cache.
- `list_verified_peers()` is the safer conversation boundary.
- Successful `open_envelope(...)` and `verify_discovery_envelope(...)` can promote
  peers into that verified set.

## 4) Registration API

Handlers register per `SummonerIdentity` instance, and event emission is centralized in the lifecycle return path. That keeps callback behavior predictable and makes downstream analytics easier to reason about.

## 4.1 `on_policy_event(phase=...)`

Decorator registration API (per `SummonerIdentity` instance):

```python
from tooling.aurora import SummonerIdentity

identity = SummonerIdentity()

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name: str, context: dict):
    ...
```

Allowed phases:

- `start_session`
- `continue_session`
- `advance_stream_session`
- `seal_envelope`
- `open_envelope`
- `verify_discovery_envelope`

Registration semantics:

1. Invalid phase raises `ValueError`.
2. Multiple handlers per phase are supported.
3. Handlers execute in registration order.
4. Handlers are instance-scoped (`identity_a` handlers do not affect `identity_b`).

## 4.2 Emission semantics

Events are emitted from `_ret(...)`, which is used by:

- `start_session(...)`
- `continue_session(...)`
- `advance_stream_session(...)`
- `seal_envelope(...)`
- `open_envelope(...)`
- `verify_discovery_envelope(...)`

Because lifecycle methods are async, these emissions happen on awaited method completion paths.

`event_name` is the same value as status `code`.

Examples:

- `ok`
- `active_session_exists`
- `session_verify_failed`
- `replay_detected`
- `invalid_envelope`

Important behavior:

- If internal code passes an invalid phase to `_emit_result_policy_event(...)`, it raises `ValueError`.
- This is deliberate fail-fast behavior for invalid internal wiring (for example, phase typos).

Handlers are easy to register, and event emission is centralized and consistent.

## 5) Event contract

The schema below is the stable contract between `SummonerIdentity` and the telemetry pipeline that consumes these events.

## 5.1 Base context (always present)

These keys are guaranteed on every emitted event, regardless of phase or outcome. Build your parser and storage schema around this set first, then treat optional fields as enrichment. If your pipeline can always decode this table, it stays robust even when optional context is absent.

| Key | Type | Meaning |
| --- | --- | --- |
| `schema_version` | `int` | Event schema version (`1`). |
| `ts` | `int` | Unix timestamp of emission. |
| `phase` | `str` | Lifecycle phase for this event. |
| `ok` | `bool` | Outcome success flag. |
| `code` | `str` | Outcome code (`event_name`). |
| `has_data` | `bool` | Whether the API returned non-`None` data. |

## 5.2 Optional context (whitelisted)

Optional fields are intentionally constrained so event payloads stay compact and predictable. The list below is the exact enrichment surface currently implemented. Designing against this fixed set helps prevent brittle downstream assumptions.

Optional context is merged only from this whitelist in implementation:

- `peer_fingerprint`
- `session_form`
- `sender_role`
- `local_role`
- `replaced_active_incomplete`
- `validation_stage`
- `replay_store_mode`
- `persist_replay`
- `stream_mode`
- `stream_id`
- `stream_phase`
- `stream_seq`
- `stream_policy`
- `stream_reason`
- `stream_ttl`
- `stream_expired`
- `stream_started_ts`
- `stream_last_ts`
- `stream_frame_count`

Any key outside this set is ignored.

## 5.3 Optional field semantics (deep explanation)

The following table shows when each optional field appears and how it is
typically used for indexing, alerting, and trust scoring.

| Field | When present | Why it matters |
| --- | --- | --- |
| `peer_fingerprint` | Open-path outcomes where peer identity is known (`ok`, `session_verify_failed`, `replay_detected`, `response_window_expired`) | Stable per-peer aggregation key. |
| `session_form` | Same event set as above | Distinguishes `start` pressure from normal `continue` traffic. For stream mode, only `stream_phase="start"` yields `session_form="start"`; `chunk` and `end` are continuation traffic. |
| `sender_role` / `local_role` | Same event set as above | Helps debug asymmetric role behavior and policy mismatches. |
| `replaced_active_incomplete` | Only `open_envelope` `ok`, only if boolean state exists | High-signal marker for accepted reset-like replacement pressure. |
| `validation_stage` | Non-`ok` `open_envelope` events | Enables fast triage: structure vs signature vs decrypt vs commit failures. |
| `replay_store_mode` | `replay_detected` | Tells you the replay control mode in effect (`memory`, `disk`, `custom`). |
| `persist_replay` | `replay_detected` | Shows whether replay state is durable across restart. |
| `stream_mode` | Stream-related session outcomes | Indicates parsed session mode (`single` / `stream`). |
| `stream_id` / `stream_phase` / `stream_seq` | Stream-related session outcomes | Correlates stream lifecycle and sequence progression. |
| `stream_policy` | Stream-related session outcomes | Indicates verifier policy label (`contiguous`). |
| `stream_reason` | Stream interruption/timeout outcomes when provided | Carries structured reason for diagnostics and policy logic. |
| `stream_ttl` / `stream_expired` | Stream-related session outcomes | Helps distinguish invalid TTL from actual timeout expiry. |
| `stream_started_ts` / `stream_last_ts` / `stream_frame_count` | Stream-related session outcomes when derivable | Useful for latency and stream-pressure analytics. |

Practical rule:

- Do not assume optional fields always exist.
- Always read with `ctx.get(...)` and type-check if needed.

## 5.4 Phase mapping

Phase mapping is the lifecycle anchor for every event. It lets you separate “where an issue happened” from “what code was returned,” which makes investigation and dashboards much clearer. Use this mapping as a primary dimension in your analytics model.

| Method | Emitted phase |
| --- | --- |
| `start_session(...)` | `start_session` |
| `continue_session(...)` | `continue_session` |
| `advance_stream_session(...)` | `advance_stream_session` |
| `seal_envelope(...)` | `seal_envelope` |
| `open_envelope(...)` | `open_envelope` |
| `verify_discovery_envelope(...)` | `verify_discovery_envelope` |

Note:

- `continue_session(...)` may internally return through a recovery path that emits `start_session` phase in that branch.
- `verify_discovery_envelope(...)` is discovery-only. It can emit identity/signature/replay
  outcomes and peer-learning telemetry, but it does not emit session-commit replacement
  semantics such as `replaced_active_incomplete`.
  A successful discovery verification can still promote a peer into the verified-peer set.

Summary: base keys are stable, optional keys are deliberate, and phase identifies lifecycle position. That combination is what allows you to keep parsers strict while still writing flexible, defensive handlers.

## 6) Open-envelope pipeline and stage taxonomy

`open_envelope` usually carries the most security signal, so this section maps validation stage to operational interpretation.

The implemented `validation_stage` progression is:

1. `structure`
2. `identity`
3. `session`
4. `signature`
5. `decrypt`
6. `replay`
7. `commit`

Interpretation guidance:

- `structure` spikes usually indicate cheap malformed flood.
- `signature` or `decrypt` spikes indicate more expensive garbage and often justify stronger pre-crypto throttling.
- `commit` spikes often indicate custom controls or state-store instability.

This stage taxonomy is what makes telemetry useful under pressure: it guides where to act first.

## 7) Failure isolation and operational safety

Because telemetry code changes often, this section defines safety boundaries between handler failures and protocol outcomes.

Policy handlers run in `try/except` inside `_emit_result_policy_event(...)`.

If a handler raises:

1. A warning is logged (`policy handler failed`),
2. The protocol method return value is unchanged,
3. Other handlers continue.

This protects the data plane from telemetry-plane bugs.

Operational implication:

- You can iterate on telemetry safely, but handler failures must still be monitored because silent telemetry degradation weakens policy posture.

## 8) Hook composition with public default delegates

Policy logic can be added without replacing baseline protocol logic.

If you are encountering `SummonerIdentityControls` for the first time, this is the
right moment to think about it: by this point you already know what events are
emitted and why custom hooks might want to read the same state.

The three hook scopes are:

- class hooks affect every `SummonerIdentity` in the process,
- controls hooks are a reusable group of callbacks attached to one `SummonerIdentity`,
- local hooks are narrow overrides placed directly on one live object.

When using custom hooks like `verify_session`, call public defaults instead of private internals.

The hook surfaces and the public runtime names are intentionally different:

- Class-level decorators:
  - `@SummonerIdentity.get_session`
  - `@SummonerIdentity.verify_session`
  - `@SummonerIdentity.register_session`
  - `@SummonerIdentity.reset_session`
- Controls decorators:
  - `@controls.on_get_session`
  - `@controls.on_verify_session`
  - `@controls.on_register_session`
  - `@controls.on_reset_session`
- Instance-local decorators:
  - `@identity.on_get_session`
  - `@identity.on_verify_session`
  - `@identity.on_register_session`
  - `@identity.on_reset_session`
- Public hook-aware runtime methods:
  - `await identity.get_current_session(...)`
  - `await identity.verify_session_record(...)`
  - `await identity.register_session_record(...)`
  - `await identity.force_reset_session(...)`

Inside custom handlers, keep delegating to `*_default(...)`.

Why this matters:

- The public runtime methods (`get_current_session(...)`, `verify_session_record(...)`,
  `register_session_record(...)`, `force_reset_session(...)`) are hook-aware.
- They route through the currently active hook source (local, controls, class, or fallback).
- Inside a custom handler, that hook source is already active, so calling the public
  runtime method would route back into the same handler path and recurse.

Safety rule:

- If `register_session` is customized, `verify_session` must also be customized in the same hook scope.
- “Same scope” means local-with-local, controls-with-controls, or class-with-class.

So the rule is:

- outside hooks: call the public runtime methods
- inside hooks: call the matching `*_default(...)` delegate when you want baseline behavior

Available default delegates:

- `get_session_default(peer_public_id, local_role)`
- `verify_session_default(peer_public_id, local_role, session_record, use_margin=False)`
- `register_session_default(peer_public_id, local_role, session_record, *, new=False, use_margin=False)`
- `reset_session_default(peer_public_id, local_role)`
- `peer_key_store_default(peer_public_id, update=None)`
- `replay_store_default(message_id, *, ttl, now=None, add=False)`

Pattern:

1. Evaluate your custom policy delta.
2. If not denied, delegate to the matching `*_default(...)` method.

Use this consistently for robust, additive customization.

Example (`verify_session` composition with a default delegate):

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
blocked = set()

@SummonerIdentity.verify_session
def verify_with_policy(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if fp in blocked:
            return False
    # Delegate to baseline SummonerIdentity continuity/freshness behavior.
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if event_name == "session_verify_failed" and isinstance(fp, str):
        blocked.add(fp)
```

The same composition pattern applies to other hooks (`register_session_default`, `reset_session_default`, `get_session_default`, `peer_key_store_default`, `replay_store_default`): enforce your delta first, then call the corresponding default when allowed.

The examples below use class-level decorators. The same pattern can also be expressed through `SummonerIdentityControls` or instance-local `@identity.on_*` hook registration.

## 9) Progressive integration guide

A gradual rollout keeps enforcement understandable and reduces deployment risk.
The three steps below move from observation to policy state to active
enforcement.

## 9.1 Step 1: Install basic observability

This first step should be operationally safe: observe only, enforce nothing. The snippet below builds phase and stage visibility with minimal code and no protocol behavior change. It is the right starting point for production rollouts.

Start with read-only metrics.

```python
from collections import Counter
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
counts = Counter()

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    counts[f"open:{event_name}"] += 1
    stage = ctx.get("validation_stage")
    if isinstance(stage, str):
        counts[f"open_stage:{stage}"] += 1
```

This gives immediate visibility with minimal risk.

## 9.2 Step 2: Add per-peer state

Once global visibility exists, the next improvement is peer-level attribution. This step introduces fingerprint-scoped counters so you can distinguish one noisy peer from broad system regressions. The resulting state is the foundation for later enforcement.

Use `peer_fingerprint` for peer-scoped counters.

```python
from collections import defaultdict
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
peer_counters = defaultdict(lambda: {"verify_fail": 0, "replay": 0})

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return
    if event_name == "session_verify_failed":
        peer_counters[fp]["verify_fail"] += 1
    elif event_name == "replay_detected":
        peer_counters[fp]["replay"] += 1
```

## 9.3 Step 3: Wire telemetry into enforcement

At this stage, telemetry becomes a security control. The implementation pattern
is deterministic: the handler updates risk state, the hook reads risk state,
and the hook returns an allow or deny decision. Keeping this loop deterministic
helps ensure that policy decisions remain explainable during incidents.

Feed state into a verify hook.

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
blocked = set()
risk = {}

@SummonerIdentity.verify_session
def verify_with_policy(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if fp in blocked:
            return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return
    if event_name == "session_verify_failed":
        risk[fp] = risk.get(fp, 0) + 1
        if risk[fp] >= 5:
            blocked.add(fp)
```

At this point you have the complete telemetry -> policy loop in place.
From here, the remaining work is calibration: thresholds, decay windows, and escalation logic tuned to your traffic.

## 10) Security recipes (real attack surfaces)

The following recipes adapt the generic model to common abuse paths.

## 10.1 Reset pressure detection (`replaced_active_incomplete`)

Reset pressure is subtle if you only count failures, because abusive starts can still be accepted. This recipe uses the committed-success signal to capture meaningful reset-like replacements. That makes thresholds more trustworthy and reduces noisy false positives.

Use committed-success reset-like replacements as a high-signal metric.

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
reset_pressure = {}
blocked = set()

@SummonerIdentity.verify_session
def verify(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if fp in blocked:
            return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if event_name == "ok" and ctx.get("replaced_active_incomplete") is True and isinstance(fp, str):
        reset_pressure[fp] = reset_pressure.get(fp, 0) + 1
        if reset_pressure[fp] >= 5:
            blocked.add(fp)
```

Reasoning:

- This signal is emitted only when replacement actually committed on success.
- That makes it cleaner than counting raw start-form attempts.

## 10.2 Replay posture and restart sensitivity

Replay counts are useful, but replay context is what makes them actionable. This recipe captures both event volume and replay durability posture so alerts can explain whether environment configuration contributes to the signal. It helps responders separate attacker pressure from operational weakness.

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity(persist_replay=False)
replay_hits = {}

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    if event_name != "replay_detected":
        return
    fp = ctx.get("peer_fingerprint")
    if isinstance(fp, str):
        replay_hits[fp] = replay_hits.get(fp, 0) + 1

    # Useful posture flags for alert annotation:
    mode = ctx.get("replay_store_mode")
    durable = ctx.get("persist_replay")
    # send (fp, mode, durable) to telemetry sink
```

Reasoning:

- `replay_detected` by itself is useful.
- `replay_store_mode` and `persist_replay` explain whether local posture may contribute.

## 10.3 DoS triage by failure stage

Not all failure spikes cost the same to process. This recipe classifies failures by validation stage so mitigation can be prioritized by computational cost and likely root cause. It is one of the fastest ways to convert telemetry into capacity protection.

```python
from collections import Counter
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
stage_counts = Counter()

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    if event_name == "ok":
        return
    stage_counts[ctx.get("validation_stage", "unspecified")] += 1
```

Operational mapping:

1. `structure` high: reject earlier at ingress.
2. `signature`/`decrypt` high: strengthen pre-crypto rate-limits.
3. `commit` high: inspect storage and custom hook reliability.

Use these recipes as templates, then tune thresholds to your own traffic profile.

## 11) Signal-to-action table

This table summarizes common signals into direct response playbooks.
Use it as an operator runbook seed, not as a fixed rulebook.
Each row should be treated as a hypothesis template: verify against your environment before enforcing aggressively. Over time, tune thresholds and actions with measured false-positive and false-negative outcomes.

| Signal pattern | Likely interpretation | Action |
| --- | --- | --- |
| `open_envelope:ok` + `replaced_active_incomplete=True` spike | Accepted reset pressure | Tighten reset policy and temporarily throttle/deny offending fingerprints. |
| `open_envelope:session_verify_failed` concentrated per fingerprint | Adversarial or buggy peer transitions | Quarantine peer; inspect `verify_session` policy and peer implementation. |
| `open_envelope:replay_detected` + `persist_replay=False` | Replay state may be restart-sensitive | Enable durable replay state if your reliability model requires it. |
| Failures concentrated at `validation_stage="structure"` | Malformed flood | Add cheap schema gates before expensive crypto work. |
| Failures concentrated at `validation_stage="commit"` | Commit/control-path instability | Inspect custom store handlers and storage health/latency. |

Treat this as a baseline matrix and calibrate thresholds against your own baseline behavior.
In practice, successful teams revisit this mapping regularly as traffic patterns and attack pressure evolve.

## 12) Common pitfalls

Most integration bugs come from assumptions around optional fields and hook behavior.
The list below is ordered by what tends to break real deployments first. If results look inconsistent, check these before debugging deeper cryptographic or transport layers.

1. Assuming optional fields always exist.
Use `ctx.get(...)` and type checks.

2. Mixing telemetry state between independent `SummonerIdentity` instances unintentionally.
Keep per-instance state explicit unless global aggregation is intentional.

3. Forgetting to delegate to defaults in custom hooks.
If you replace baseline logic accidentally, you can weaken protocol guarantees.

4. Treating telemetry as enforcement by itself.
Events do not block traffic unless hooks read policy state and enforce decisions.

5. Ignoring handler exceptions.
They are isolated from protocol return paths, so silent telemetry degradation is possible if not monitored.

If behavior looks wrong in production, inspect these five first.

## 13) API boundaries (what this API intentionally does not do)

These boundaries are deliberate and keep expectations realistic.
They are also important for architecture decisions: if you need behavior outside this boundary, implement it in your registry, control-plane, or deployment pipeline rather than in event parsing logic.

1. It does not emit raw payload content.
2. It does not alter cryptographic checks or session semantics.
3. It does not change boolean contracts of existing decorators.
4. It does not provide built-in distributed reputation storage (that is an integration concern).

This API is a telemetry and policy-composition surface, not a protocol redesign
layer.

## 14) Minimal production checklist

Use this checklist as a deployment gate.
Treat it as the minimum bar, not the final maturity target. Teams with higher risk profiles should add stricter thresholds, richer retention, and explicit incident automation on top of these items.

1. Register `open_envelope` handlers on all active traffic instances.
2. Persist or export event counters out-of-process.
3. Track per-fingerprint counters for `session_verify_failed`, `replay_detected`, and reset-like accepts.
4. Connect those counters to a verify/reset policy decision path.
5. Alert on `validation_stage` distribution shifts.
6. Audit handler error logs (`policy handler failed`).

If these six items are in place, you have the minimum viable production posture for this API.

## 15) Related documents

Use these documents for implementation details, broader security context, and quick operational lookup. Read order suggestion: implementation first (`identity.py`), then this guide, then the security report for threat framing, and finally the cheatsheet for daily operator reference.

- `tooling/aurora/identity/identity.py`
- `tooling/aurora/identity/readme.md`
- `tooling/aurora/identity/security_report.md`
- `tooling/aurora/identity/cheatsheet.md`

Reading this guide with the security report gives the best end-to-end picture of both signals and mitigations.

## Conclusion

The policy event API is most effective when treated as a closed loop system: structured outcomes feed telemetry, telemetry updates trust state, and trust state drives hook-based enforcement decisions. The API gives you a stable instrumentation surface without changing protocol semantics, which means you can harden operations continuously while keeping cryptographic behavior predictable.
