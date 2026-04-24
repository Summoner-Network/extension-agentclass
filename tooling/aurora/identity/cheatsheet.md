# SummonerIdentity Workflow Cheat Sheet

Payload-first reference for message workflows.

## 1) Minimal happy path (Alice <-> Bob)

Alice prepares her local identity:
```python
alice = SummonerIdentity()
alice_pub = alice.id("alice_id.json")
```

Alice obtains Bob's public identity dict (`bob_pub`) from her directory/discovery layer.
Typical sources are:
- a trusted directory record, or
- a verified peer returned by `list_verified_peers()`.

Selection guidance:
- use `list_verified_peers()` when you want a conversation-safe candidate list,
- use `list_known_peers()` / `find_peer()` when you are still browsing discovery results,
- and pin by fingerprint or directory record before treating a discovered peer as trusted.

Discovery-only lookup helpers are still available when Alice only has learned peers
cached and needs to browse them before making a trust decision.

Discovery lookup helpers (when Alice already has discovered peers cached):
```python
known = alice.list_known_peers()
verified = alice.list_verified_peers()
hits = alice.find_peer("bob")  # matches text in str(public_id), commonly via public_id["meta"]
bob_pub = verified[0] if verified else hits[0]
```

How discovery lookup works:
- `list_known_peers()` / `find_peer()` read `self._peer_keys` (local fallback peer cache).
- `list_verified_peers()` is stricter: it returns peers that were promoted through
  successful `open_envelope(...)` / `verify_discovery_envelope(...)` or through
  fallback continuity evidence already present locally.
- The fallback cache is loaded when you call `id(...)`, if `SummonerIdentity(load_local=True)` (default).
- If you use a custom `peer_key_store` hook (class-level, controls, or instance-local), keep
  `self._peer_keys` synchronized or expose your own peer listing/search API.

Alice starts and sends:
```python
# inside an async function / handler
s0 = await alice.start_session(bob_pub)
env1 = await alice.seal_envelope({"msg": "hi"}, s0, to=bob_pub)
```

What Bob receives (`env1` shape):
```python
{
  "v": "env.v1",
  "from": {"pub_sig_b64": "...", "pub_enc_b64": "...", ...},   # Alice public id
  "to": {"pub_sig_b64": "...", "pub_enc_b64": "...", ...},     # Bob public id
  "session_proof": {
    "sender_role": 0,
    "0_nonce": "<fresh nonce from Alice>",
    "1_nonce": None,
    "ts": <unix seconds>,
    "ttl": <seconds>,
    "history_proof": {
      "v": "histproof.v1",
      "nonce": "<b64>",
      "ciphertext": "<b64>"
    },
    "age": <int>
  },
  "payload": {"v": "payload.enc.v1", "nonce": "<b64 aead nonce>", "ciphertext": "<b64 ciphertext>"},
  "sig": "<signature over canonical envelope>"
}
```

Shape note:
- For readability, examples show the core fields.
- Actual `session_proof` records also carry stream fields in all modes:
  `mode`, `stream`, `stream_ttl` (for non-stream turns: `"single"`, `None`, `None`).

Bob opens and replies:
```python
# inside an async function / handler
payload1 = await bob.open_envelope(env1)  # {"msg": "hi"}
s1 = await bob.continue_session(env1["from"], env1["session_proof"])
env2 = await bob.seal_envelope({"msg": "ack"}, s1, to=env1["from"])
```

What Alice receives (`env2` shape difference):
```python
{
  ...
  "session_proof": {
    "sender_role": 1,
    "0_nonce": "<echo of Alice start nonce>",
    "1_nonce": "<fresh nonce from Bob>",
    "history_proof": None,
    ...
  },
  "payload": {"v": "payload.enc.v1", "nonce": "...", "ciphertext": "..."}
}
```

Non-start note:
- Reply/continue records emit `age: None` on the wire.
- The authoritative continuity age is kept in local `current_link` storage.

Alice final open:
```python
# inside an async function / handler
payload2 = await alice.open_envelope(env2)  # {"msg": "ack"}
```

## 2) Optional customization of storage and trust behavior

The minimal flow above remains the default. A plain `SummonerIdentity()` with
the built-in JSON stores is the correct starting point when no extra storage or
trust rules are required.

Customization becomes relevant only when a concrete storage or trust
requirement appears. The main question is scope: should the same rule apply to
every identity in the current process, should one identity carry a reusable
attached controls object, or should one live identity object receive a narrow
one-off override?

Aurora provides one mechanism for each of those scopes:

- class hooks on `SummonerIdentity`,
- `SummonerIdentityControls` for a reusable per-identity controls object,
- instance-local `@identity.on_*` hooks.

The comparison table and snippets below show the same session-lookup behavior
in each scope so the differences remain concrete.

For a longer deployment reference, including `SummonerAgent` attach / detach
scenarios and control-boundary examples, see:

* `tooling/aurora/identity/identity_controls.md`

Comparison table:

| Option | Initialization style | Runtime use | Portability |
| --- | --- | --- | --- |
| Class hooks | Register once on `SummonerIdentity` | Every identity in the process uses the same hook automatically | Not packaged as a separate object |
| `SummonerIdentityControls` | Build one controls object, then attach it to one or more identities | Only identities with that attached controls object use it | The same controls object can be attached to another identity |
| Instance-local `@identity.on_*` | Register directly on one live identity object | Only that identity uses the hook | Not portable as a separate package; re-register on each identity that needs it |

The next three snippets implement the same session-lookup idea in three
different scopes so the differences are concrete.

### Class hooks: one process-wide rule

This example defines one session lookup rule for the whole Python process. The
hook is registered on `SummonerIdentity` itself, so every identity in the
process uses the same lookup behavior unless a narrower scope overrides it. The
shared store is keyed only by peer and local role because the rule is not tied
to any one identity instance.

```python
from tooling.aurora import SummonerIdentity


class_session_store = {}


def session_key(peer_public_id, local_role):
    peer_key = "GENERIC" if peer_public_id is None else peer_public_id["pub_sig_b64"]
    return (peer_key, int(local_role))


@SummonerIdentity.get_session
def get_session(peer_public_id, local_role):
    return class_session_store.get(session_key(peer_public_id, local_role))


alice = SummonerIdentity()
bob = SummonerIdentity()
alice_pub = alice.id("alice.json")
bob_pub = bob.id("bob.json")

class_session_store[session_key(bob_pub, 0)] = {"source": "class", "peer": "bob"}

# inside an async function / handler
# Runtime use: every identity in this Python process resolves through the same
# class hook unless a narrower scope overrides it.
current = await alice.get_current_session(bob_pub, local_role=0)
```

### Controls: one reusable package that can be attached to more than one identity

This example creates one reusable `SummonerIdentityControls` object and
attaches it to two different identities. The controls hook receives the active
`identity` as its first argument, so one shared controls object can still apply
identity-specific behavior at runtime. This is the right pattern when the rule
should be packaged separately from the identity and reused later.

```python
from tooling.aurora import SummonerIdentity, SummonerIdentityControls


shared_controls_store = {}


def build_shared_controls():
    controls = SummonerIdentityControls()

    @controls.on_get_session
    def get_session(identity, peer_public_id, local_role):
        identity_key = identity.public_id["pub_sig_b64"]
        peer_key = "GENERIC" if peer_public_id is None else peer_public_id["pub_sig_b64"]
        return shared_controls_store.get((identity_key, peer_key, int(local_role)))

    return controls


shared_controls = build_shared_controls()

room_identity = SummonerIdentity()
recovery_identity = SummonerIdentity()
room_pub = room_identity.id("room.json")
recovery_pub = recovery_identity.id("recovery.json")

room_identity.attach_controls(shared_controls)
recovery_identity.attach_controls(shared_controls)

shared_controls_store[(room_pub["pub_sig_b64"], recovery_pub["pub_sig_b64"], 0)] = {
    "source": "controls",
    "identity": "room",
}
shared_controls_store[(recovery_pub["pub_sig_b64"], room_pub["pub_sig_b64"], 0)] = {
    "source": "controls",
    "identity": "recovery",
}

# inside an async function / handler
# Runtime use: only identities with the attached controls object use it.
current_room = await room_identity.get_current_session(recovery_pub, local_role=0)
current_recovery = await recovery_identity.get_current_session(room_pub, local_role=0)

# Portability: the same controls object was attached to two identities.
# If shared_controls stores mutable state internally, that state is shared too.
```

### Instance-local hooks: one live identity gets one direct override

This example attaches the hook directly to `room_identity`. The override stays
on that one live object, and `observer_identity` keeps the default behavior
because no matching local hook was registered on it. This is the narrowest
scope and fits one-off or temporary customization that does not need to travel
as a reusable package.

```python
from tooling.aurora import SummonerIdentity


local_session_store = {}


room_identity = SummonerIdentity()
observer_identity = SummonerIdentity()
room_pub = room_identity.id("room.json")
observer_pub = observer_identity.id("observer.json")


@room_identity.on_get_session
def get_session(peer_public_id, local_role):
    peer_key = "GENERIC" if peer_public_id is None else peer_public_id["pub_sig_b64"]
    return local_session_store.get((peer_key, int(local_role)))


local_session_store[(observer_pub["pub_sig_b64"], 0)] = {
    "source": "local",
    "identity": "room",
}

# inside an async function / handler
# Runtime use: only room_identity sees this local hook.
current_room = await room_identity.get_current_session(observer_pub, local_role=0)
current_observer = await observer_identity.get_current_session(room_pub, local_role=0)

# Portability: the hook does not travel as a separate object.
# If observer_identity should use the same override, it must register its own
# local hook or attach a shared controls object instead.
```

Compact mental model:

| Concern | Best mental model |
| --- | --- |
| Controls attachment | `identity -> optional controls object` |
| Effective behavior | `(identity, hook_name) -> active implementation` |
| Controls object | one reusable package containing zero to six hook callbacks |
| Local hooks | narrow override stored directly on one identity |
| Class hooks | process-wide fallback for all identities in the process |

Reuse note:
- if one controls object is reused across several identities, any mutable state
  stored on that controls object is shared across them.

Resolution order:

```text
local hook -> controls hook -> class hook -> built-in default
```

The smallest explicit pattern is: create a controls object, attach it to the
identity, then register hooks on that controls object.

```python
identity = SummonerIdentity()
identity.id("id.json")
controls = SummonerIdentityControls()
identity.attach_controls(controls)

@controls.on_peer_key_store
def peer_store(identity, peer_public_id, update=None):
    return identity.peer_key_store_default(peer_public_id, update=update)
```

Replacement behavior is easiest to see when two different controls objects are
attached in sequence. The second attachment replaces the first.

```python
controls_a = SummonerIdentityControls()
controls_b = SummonerIdentityControls()

identity.attach_controls(controls_a)
identity.attach_controls(controls_b)

# The identity now uses controls_b.
# controls_a is no longer attached.
```

The next sketch shows the same idea in a `SummonerAgent` workflow. The agent
binds one prepared identity, and only that identity carries the extra rule.

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
    # Add room-only allowlist / tournament policy here.
    return base

agent.attach_identity(identity_pool["room"])
```

## 3) Public "hello" (`to=None`)

Public discovery message:
```python
# inside an async function / handler
s0 = await alice.start_session(None)
env = await alice.seal_envelope({"msg": "hello"}, s0, to=None)
```

Public envelope format:
```python
{
  "v": "env.v1",
  "from": {"pub_sig_b64": "...", "pub_enc_b64": "...", ...},
  "to": None,
  "session_proof": {
    "sender_role": 0,
    "0_nonce": "<fresh>",
    "1_nonce": None,
    "ts": <unix seconds>,
    "ttl": <seconds>,
    "history_proof": None,
    "age": <int>
  },
  "payload": {"msg": "hello"},  # plaintext when to=None
  "sig": "<signature>"
}
```

Same shape note:
- Public-flow `session_proof` also includes `mode`, `stream`, `stream_ttl`.
- For public non-stream hello, this is typically `"single"`, `None`, `None`.

For a public hello, there are two receiver-side entry points:
- `verify_discovery_envelope(...)` for discovery/public ingress,
- `open_envelope(...)` for full continuity commit.

For discovery hello, prefer `verify_discovery_envelope(...)` because it verifies the
sender, honors peer/replay hooks, and promotes the peer to verified status without
creating generic-slot continuity pressure between unrelated broadcasters.

Receiver behavior:
```python
# inside an async function / handler
hello = await bob.verify_discovery_envelope(env)  # {"msg": "hello"}
```

Use `verify_discovery_envelope(...)` when discovery is only meant to:
- verify sender identity/signature,
- update peer learning,
- promote the sender to a verified peer,
- apply replay protection,
- and avoid generic-slot continuity conflicts between unrelated broadcasters.

This does not create per-peer encrypted continuity. A direct reply should use:
```python
# inside an async function / handler
s_peer = await bob.start_session(env["from"])
```

Server discovery pattern:
- Server accepts `to=None` only as a discovery ingress.
- Server verifies `from` identity signature and envelope signature, then records `from`
  as a learned and verified peer.
- Server does not continue the `to=None` generic flow; it responds per-client with `to=env["from"]`.

This model keeps discovery public and makes the server response encrypted/authenticated per client.

Pseudocode for the server-side response:
```python
# Discovery request arrives at server
on_message(env_hello):
  if env_hello.to is None:
    # 1) Validate envelope and sender identity
    assert verify_sender_identity(env_hello.from)
    assert verify_envelope_signature(env_hello)

    client_id = env_hello.from

    online_agent_ids.add(client_id)

    # 2) Start a fresh per-client encrypted session.
    #    Do not continue the shared discovery/generic slot.
    s_srv = start_session(peer = client_id)

    # 3) Build direct per-client reply (encrypted path)
    env_reply = seal_envelope(
      payload = { "agents_online": online_agent_ids },
      session = s_srv,
      from = server_identity,
      to = client_id
    )

    send(env_reply)
```

Interoperability note:
- Clients using current `SummonerIdentity` work with this model.
- `to=None` remains plaintext and discovery-oriented.
- Encrypted transport begins on the server reply (`to=<client_id>`).
- The important boundary is that discovery verification can learn and verify the
  client identity, but the direct reply still begins as a new per-peer session.

## 4) Active-thread reset flow (`force_reset=True`)

If Alice still has an active thread with Bob and wants to start fresh:
```python
# inside an async function / handler
s_new = await alice.start_session(bob_pub, force_reset=True)
env_new = await alice.seal_envelope({"msg": "new thread"}, s_new, to=bob_pub)
```

Bob receives a new start-form session proof (`sender_role=0`, `1_nonce=None`) with continuity fields:
```python
env_new["session_proof"] == {
  "sender_role": 0,
  "0_nonce": "<new fresh nonce>",
  "1_nonce": None,
  "history_proof": {
    "v": "histproof.v1",
    "nonce": "<b64>",
    "ciphertext": "<b64>"
  },
  "age": <history age used for reset/start>,
  ...
}
```

If continuity checks pass, Bob accepts and transitions to the new active thread. If checks fail, Bob returns failure (`None` or structured status with `return_status=True`) and keeps current state unchanged.

Restart note:
- On the fallback store, fresh start-form admission normalizes a stale persisted
  `current_link` to absent local state.
- If that stored link was stream-active, staleness is evaluated from
  `stream_last_ts + stream_ttl`, not only from the original requester-window TTL.
- Proof-less bootstrap on an empty local slot is accepted only when `history_proof`
  is absent and `age == 0`.

## 5) Policy event telemetry (phase-scoped)

Register handlers on the `SummonerIdentity` instance:
```python
metrics = {"open_fail": 0, "reset_like_accept": 0}

@bob.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    if event_name != "ok":
        metrics["open_fail"] += 1
        # available on failures:
        # ctx["validation_stage"] in {"structure","identity","signature","session","decrypt","replay","commit"}
    if event_name == "ok" and ctx.get("replaced_active_incomplete") is True:
        metrics["reset_like_accept"] += 1
```

Useful context fields in `open_envelope` handlers:
- Always present: `schema_version`, `ts`, `phase`, `ok`, `code`, `has_data`
- When derivable on session outcomes: `peer_fingerprint`, `session_form`, `sender_role`, `local_role`
- Reset-abuse signal on committed success only: `replaced_active_incomplete`
- Replay posture on `replay_detected`: `replay_store_mode`, `persist_replay`

Quick filter examples:
```python
@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    if event_name == "session_verify_failed":
        print("continuity reject", ctx.get("peer_fingerprint"), ctx.get("session_form"))
    elif event_name == "replay_detected":
        print("replay", ctx.get("replay_store_mode"), ctx.get("persist_replay"))
```

## 6) Streaming turn refresher (`start -> chunk* -> end`)

Minimal shape for a streamed response turn:
```python
# inside an async function / handler
# Alice -> Bob request (single message)
s0 = await alice.start_session(bob_pub)
env0 = await alice.seal_envelope({"msg": "request"}, s0, to=bob_pub)
assert await bob.open_envelope(env0) == {"msg": "request"}

# Bob starts a stream toward Alice
s1 = await bob.continue_session(alice_pub, env0["session_proof"], stream=True, stream_ttl=30)
env1 = await bob.seal_envelope({"delta": "part-1"}, s1, to=alice_pub)
assert await alice.open_envelope(env1) == {"delta": "part-1"}

# Zero or more chunks
s2 = await bob.advance_stream_session(alice_pub, s1, end_stream=False, stream_ttl=30)
env2 = await bob.seal_envelope({"delta": "part-2"}, s2, to=alice_pub)
assert await alice.open_envelope(env2) == {"delta": "part-2"}

# End frame closes the stream and returns to single-mode continuity
s3 = await bob.advance_stream_session(alice_pub, s2, end_stream=True, ttl=120)
env3 = await bob.seal_envelope({"done": True}, s3, to=alice_pub)
assert await alice.open_envelope(env3) == {"done": True}
```

The initiator can also own the stream directly:

```python
s0 = await alice.start_session(bob_pub, stream=True, stream_ttl=30)
env0 = await alice.seal_envelope({"delta": "part-1"}, s0, to=bob_pub)
assert await bob.open_envelope(env0) == {"delta": "part-1"}

s1 = await alice.advance_stream_session(bob_pub, s0, end_stream=False, stream_ttl=30)
env1 = await alice.seal_envelope({"delta": "part-2"}, s1, to=bob_pub)
assert await bob.open_envelope(env1) == {"delta": "part-2"}

s2 = await alice.advance_stream_session(bob_pub, s1, end_stream=True, ttl=120)
env2 = await alice.seal_envelope({"done": True}, s2, to=bob_pub)
assert await bob.open_envelope(env2) == {"done": True}
```

Stream proof fields to remember:
- `mode == "stream"` during stream frames.
- `stream = {"id": "...", "seq": <0..N>, "phase": "start"|"chunk"|"end"}`.
- `stream_ttl` applies to `start/chunk`; `end` uses normal `ttl`.
- Only `phase="start"` is start-form; `chunk` and `end` are continuation frames.

Common stream rejects (`return_status=True`):
- `stream_mode_unsupported`, `stream_ttl_invalid`
- `invalid_stream_session`, `invalid_stream_mode`
- `stream_not_active`, `stream_interrupted`
- `stream_phase_invalid`, `stream_seq_invalid`, `stream_ttl_expired`
- `stream_active_continue_blocked`

Policy telemetry quick filter for stream diagnostics:
```python
@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    if ctx.get("stream_mode") == "stream":
        print(
            event_name,
            ctx.get("stream_id"),
            ctx.get("stream_phase"),
            ctx.get("stream_seq"),
            ctx.get("stream_reason"),
        )
```
