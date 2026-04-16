# Summoner Identity Controls API Reference (`identity.py`)

`SummonerIdentityControls` denotes the per-identity control layer used by
Aurora to attach persistence, trust, continuity, and audit behavior to a
`SummonerIdentity` instance.

In this document, the term `controls` refers to that attached layer of
callable mechanisms. A controls object may define hooks such as session
retrieval, session verification, replay persistence, peer-key storage, reset
handling, and audit integration. 

<!-- It does not denote: 
- the whole application backend, 
- a relay or server component, 
- a separate identity engine, 
- or a complete IAM platform. -->

This reference is written for developers, but it is also suitable for security,
privacy, compliance, and enterprise architecture discussions.

## 1) Definition and boundaries

`SummonerIdentityControls` is appropriate when one `SummonerIdentity` object
needs its own reusable set of persistence or trust rules without changing the
behavior of every `SummonerIdentity` in the process.

The three Aurora layers below solve different architectural questions.

| Layer | Role | Representative operations | Primary question |
| --- | --- | --- | --- |
| `SummonerAgent` | Runtime workload | `attach_identity(...)`, `detach_identity()`, `require_identity()` | Which principal is this workload using right now? |
| `SummonerIdentity` | Cryptographic principal and continuity engine | `id(...)`, `start_session(...)`, `open_envelope(...)`, `continue_session(...)` | How does this principal establish, verify, and continue trust? |
| `SummonerIdentityControls` | Per-identity controls layer | `attach_controls(...)`, `detach_controls()`, `@controls.on_*` | Which persistence, trust, and audit rules apply to this principal? |

The boundary of the controls layer is precise.

| Controls can change | Controls do not change |
| --- | --- |
| Session retrieval and persistence | The identity keypair |
| Replay persistence | The public identity record |
| Peer verification policy | Message routing |
| Reset approval behavior | Who receives a message |
| Peer-key persistence | Relay mirroring or traffic visibility |
| Integration with external control systems | The cryptographic protocol itself |

If an identity is detached from an agent, the controls remain attached to the
identity because they belong to the identity object rather than the workload.

```python
from tooling.aurora import SummonerAgent, SummonerIdentity, SummonerIdentityControls


agent = SummonerAgent(name="room-orchestrator")
identity = SummonerIdentity()
controls = SummonerIdentityControls()

identity.id("room.json")
identity.attach_controls(controls)
agent.attach_identity(identity)

detached_identity = agent.detach_identity()

# detached_identity still carries its controls object.
assert detached_identity.require_controls() is controls
```

That separation is the key architectural point:

- `attach_identity(...)` binds a principal to a workload,
- `attach_controls(...)` binds persistence and trust behavior to that principal.

## 2) Mental model and mechanics

### 2.1) Attachment model

The current API is easiest to understand as two related structures:

1. an attachment structure:
   `SummonerIdentity -> optional SummonerIdentityControls`
2. a hook-resolution structure:
   `(identity, hook_name) -> effective behavior`

The attachment structure has the following cardinality.

| Relationship | Current API shape | Practical meaning |
| --- | --- | --- |
| `identity -> attached controls object` | `0 or 1` | An identity may have no controls or one attached controls object |
| `controls object -> identities using it` | `0 to many` | The same controls object may be reused across multiple identities |
| `controls object -> hook callbacks` | `0 to 6` | One controls object can package several behaviors together |
| `identity -> local hook per hook name` | `0 or 1` | One live identity can override one hook name locally |
| `SummonerIdentity class -> class hook per hook name` | `0 or 1` | Process-wide fallback is singular per hook name |

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
    +-- get_session?
    +-- verify_session?
    +-- register_session?
    +-- reset_session?
    +-- peer_key_store?
    +-- replay_store?


SummonerIdentity class
    |
    +-- process-wide class hooks
```

Three practical consequences follow from that model:

1. One identity has zero or one attached controls object at a time.
2. A second `attach_controls(other_controls)` call replaces the earlier
   attached controls object.
3. One controls object may be reused across multiple identities when shared
   behavior is intentional.

If one controls object is reused across several identities, any mutable state
stored on the controls object itself is shared across those identities. For
that reason, a shared controls object should usually be either stateless,
keyed by the incoming identity argument, or backed by an external authoritative
store.

### 2.2) Hook resolution and precedence

Aurora resolves each hook name independently. The runtime question is:
"for this identity and this hook name, which implementation is active now?"

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

| Scopes defined for the same hook name | Active implementation | Why |
| --- | --- | --- |
| Local + controls + class | Local hook | The live identity is the narrowest scope |
| Controls + class | Controls hook | The identity-specific controls are narrower than process scope |
| Class only | Class hook | It is the only custom scope present |
| None | Built-in default | No custom scope overrides the default |

This is why the most accurate model is not simply `identity -> control`.
The more precise model is:

- `identity -> optional controls object`
- `identity x hook_name -> effective behavior`

### 2.3) The four customization scopes

The four scopes are best understood as four different places where behavior can
live.

| Scope | How it is defined | Session lookup signature | Where it applies | Typical reason to choose it |
| --- | --- | --- | --- | --- |
| Plain `SummonerIdentity` | No hook definition | Not applicable | One identity using defaults | Built-in storage and verification are sufficient |
| Class hook | `@SummonerIdentity.get_session` | `fn(peer_public_id, local_role)` | Every `SummonerIdentity` in the current process | One infrastructure rule should apply everywhere |
| Controls hook | `@controls.on_get_session` | `fn(identity, peer_public_id, local_role)` | Every identity that attaches that controls object | One reusable identity profile needs its own control model |
| Instance-local hook | `@identity.on_get_session` | `fn(peer_public_id, local_role)` | One live identity object | One temporary or highly specific override is needed |

The `on_*` naming on controls and identity-local hooks is deliberate. It marks
those forms as callback registration rather than immediate runtime access.

The table below distinguishes the related `get_session` surfaces precisely.

| Form | Purpose | Who defines or calls it | Signature |
| --- | --- | --- | --- |
| `@SummonerIdentity.get_session` | Register the class-wide session lookup hook | The developer defines it once for the process | `fn(peer_public_id, local_role)` |
| `@controls.on_get_session` | Register the controls-based session lookup hook | The developer defines it on one `SummonerIdentityControls` object | `fn(identity, peer_public_id, local_role)` |
| `@identity.on_get_session` | Register the live-instance session lookup hook | The developer defines it on one live identity object | `fn(peer_public_id, local_role)` |
| `await identity.get_current_session(...)` | Perform runtime lookup of the current session | Application code or the framework calls it | `(peer_public_id, local_role) -> dict | None` |
| `identity.get_session_default(...)` | Execute the built-in fallback lookup logic | Hook authors call it inside a custom hook when default behavior is desired | `(peer_public_id, local_role) -> dict | None` |

### 2.4) Mixing scopes

The scopes can be mixed safely as long as they are used for different
responsibilities.

A common pattern is:

- class hooks for organization-wide infrastructure,
- controls for identity-profile policy,
- local hooks for a temporary live override.

The following snippet demonstrates precedence only. The marker dictionaries are
used so the active hook source remains obvious.

```python
from tooling.aurora import SummonerIdentity, SummonerIdentityControls


identity = SummonerIdentity(store_dir="./stores/probe")
identity.id("./stores/probe/id.json", meta={"role": "probe"})
controls = SummonerIdentityControls()


@SummonerIdentity.get_session
def class_get_session(peer_public_id, local_role):
    return {"source": "class"}


@controls.on_get_session
def controls_get_session(active_identity, peer_public_id, local_role):
    return {"source": "controls"}


identity.attach_controls(controls)


@identity.on_get_session
def local_get_session(peer_public_id, local_role):
    return {"source": "local"}


current = await identity.get_current_session(None, 0)
assert current == {"source": "local"}

identity.clear_local_hooks()
current = await identity.get_current_session(None, 0)
assert current == {"source": "controls"}
```

## 3) Selection guide

The correct selection criterion is not hook count. A single hook can justify
controls if that hook belongs to one identity profile and should travel with
that identity when it is attached, detached, stored in an identity pool, or
reused later.

Use `SummonerIdentityControls` when this statement is true:

> One specific identity object needs a reusable set of persistence or trust hooks, and those hooks must not leak to the other identities in the process.

| Requirement | Best mechanism | Reason |
| --- | --- | --- |
| No custom storage or policy | Plain `SummonerIdentity` | Lowest complexity |
| Same rule for every identity in the process | Class hooks | Process-wide behavior belongs at class scope |
| Reusable per-identity set of hooks | `SummonerIdentityControls` | Best fit for identity-specific behavior that should remain attachable and testable |
| Small override on one live identity | Local `@identity.on_*` hooks | Smallest scope and least setup |
| Different active principal on one workload | `agent.attach_identity(...)` / `detach_identity()` | This is identity binding, not controls binding |
| Traffic visibility, mirroring, or observer access | Not controls | Solve relay architecture or routing directly |

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
                      +-- Should the rule travel with one identity profile?
                              |
                              +-- Yes -> use SummonerIdentityControls + identity.attach_controls(...)
                              +-- No  -> use instance-local hooks (@identity.on_*)
```

The practical distinction between controls and local hooks is straightforward:

- controls are a separate reusable object that can be attached, detached,
  replaced, and reused deliberately;
- local hooks are direct overrides stored on one live identity object.

## 4) Deployment patterns

### 4.1) One agent keeps several identity profiles, but only one needs stricter policy

This is the primary Aurora use case for controls.

One orchestrator agent keeps several prepared identities:

- a room identity,
- a recovery identity,
- and perhaps an observer identity.

Only the room identity should:

- persist replay and session state to a shared store,
- reject peers not approved for the current room,
- and apply room-specific recovery or reset policy.

The other identities can keep the built-in JSON stores and default policy.

Controls are useful here because the rule set is attached to one identity
profile, involves more than one hook, and should remain grouped as one named
unit.

```python
from tooling.aurora import (
    SummonerAgent,
    SummonerIdentity,
    SummonerIdentityControls,
    id_fingerprint,
)


def build_room_controls(*, allowed_fingerprints):
    controls = SummonerIdentityControls()

    @controls.on_get_session
    def get_session(identity, peer_public_id, local_role):
        # Replace with a DB/cache lookup when shared continuity is required.
        return identity.get_session_default(peer_public_id, local_role)

    @controls.on_verify_session
    def verify(identity, peer_public_id, local_role, session_record, use_margin=False):
        base = identity.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )
        if not base.get("ok"):
            return base

        peer_fp = id_fingerprint(peer_public_id["pub_sig_b64"])
        if peer_fp not in allowed_fingerprints:
            return {"ok": False, "code": "peer_not_authorized_for_room"}

        return base

    @controls.on_register_session
    def register(identity, peer_public_id, local_role, session_record, new=False, use_margin=False):
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    @controls.on_replay_store
    def replay_store(identity, message_id, ttl, now=None, add=False):
        return identity.replay_store_default(message_id, ttl=ttl, now=now, add=add)

    return controls


def build_identity(path, *, meta, controls=None):
    identity = SummonerIdentity(store_dir=path, persist_replay=True)
    identity.id(f"{path}/id.json", meta=meta)
    if controls is not None:
        identity.attach_controls(controls)
    return identity


agent = SummonerAgent(name="room-orchestrator")

room_identity = build_identity(
    "./stores/room-7",
    meta={"role": "gm", "room": "room-7"},
    controls=build_room_controls(
        allowed_fingerprints={"fp-player-1", "fp-player-2"},
    ),
)

observer_identity = build_identity(
    "./stores/observer",
    meta={"role": "observer"},
)

identity_pool = {
    "room": room_identity,
    "observer": observer_identity,
}

agent.attach_identity(identity_pool["room"])
```

What this pattern demonstrates:

- the room identity remains the same principal throughout the match,
- only that principal carries the stricter persistence and verification model,
- the observer identity remains simpler and lower-risk,
- the separation is visible in code and therefore explainable in audit review.

### 4.2) One worker switches between prepared identities at controlled boundaries

In this pattern, one worker process handles one room or tenant at a time. Each
prepared identity already carries its own controls object.

The operational requirement is to:

- preload identities,
- attach one identity to the worker,
- detach it when the worker changes assignment,
- and reattach it later with the same behavior.

```python
from tooling.aurora import SummonerAgent, SummonerIdentity, SummonerIdentityControls


def make_room_controls(room_name):
    controls = SummonerIdentityControls()

    @controls.on_verify_session
    def verify(identity, peer_public_id, local_role, session_record, use_margin=False):
        base = identity.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )
        if not base.get("ok"):
            return base
        # Insert room-specific policy here.
        return base

    return controls


def build_room_identity(room_name):
    identity = SummonerIdentity(
        store_dir=f"./stores/{room_name}",
        persist_replay=True,
    )
    identity.id(
        f"./stores/{room_name}/id.json",
        meta={"role": "gm", "room": room_name},
    )
    controls = make_room_controls(room_name)
    identity.attach_controls(controls)
    return identity


room_identities = {
    "room-a": build_room_identity("room-a"),
    "room-b": build_room_identity("room-b"),
    "room-c": build_room_identity("room-c"),
}

worker = SummonerAgent(name="gm-worker")
worker.attach_identity(room_identities["room-a"])


def switch_room(agent, room_name):
    old_identity = agent.detach_identity()
    new_identity = room_identities[room_name]
    agent.attach_identity(new_identity)
    return old_identity, new_identity


old_identity, new_identity = switch_room(worker, "room-b")
```

The detached identity still keeps:

- its keys,
- its in-memory continuity state,
- its attached controls object,
- and its store configuration.

This is also the clearest Aurora pattern for controlled authority switching:
one workload implementation can operate under different approved principals at
different times, and each principal can carry its own persistence and trust
controls.

This pattern is appropriate at controlled boundaries such as startup, room
handoff, tenant handoff, maintenance, scheduled rotation, or administrative
failover. It is not a casual mid-request toggle.

### 4.3) One identity must use a shared continuity store across workers

Some principals must preserve continuity across process restart or across
several worker instances. In that case, the continuity concern belongs to one
identity and should not be forced onto every identity in the process.

Controls are a good fit because the persistence logic belongs naturally to the
hook surfaces:

- `get_session`
- `register_session`
- `reset_session`
- `replay_store`

```python
from tooling.aurora import SummonerIdentity, SummonerIdentityControls


def build_shared_store_controls(shared_store):
    controls = SummonerIdentityControls()

    @controls.on_get_session
    def get_session(identity, peer_public_id, local_role):
        # Replace with a real fetch from Redis / SQL / another shared store.
        return identity.get_session_default(peer_public_id, local_role)

    @controls.on_register_session
    def register(identity, peer_public_id, local_role, session_record, new=False, use_margin=False):
        # Replace with a real write into the authoritative store.
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    @controls.on_replay_store
    def replay_store(identity, message_id, ttl, now=None, add=False):
        # Replace with a shared replay cache/store.
        return identity.replay_store_default(message_id, ttl=ttl, now=now, add=add)

    return controls
```

The example delegates to defaults so it remains runnable as documentation. In a
production deployment, this is the location where the principal-specific shared
store would be connected.

## 5) Enterprise and compliance interpretation

`SummonerIdentityControls` is most valuable when a workload must keep
principal-specific persistence, trust, and audit behavior separate instead of
sharing one in-process rule.

| Concern | Interpretation in Aurora | Practical implication |
| --- | --- | --- |
| Principal binding | `SummonerAgent.attach_identity(...)` binds an explicit cryptographic principal to a workload | The active principal is explicit and reviewable |
| Principal-scoped controls | `SummonerIdentityControls` attaches principal-specific persistence and trust rules to that principal | Policy is bound to identity instead of process accident |
| Separation of duties | Different identities can carry different control models even if the runtime implementation is the same | Operator, approver, observer, room, tenant, or region roles can remain distinct |
| Auditability | Active identity and attached controls object are explicit in code | The active store and trust model can be explained during audit review |
| Privacy and compartmentalization | Data handling, continuity state, and peer trust logic can be segmented by principal | Trust and persistence domains do not have to collapse into one process-wide rule |

Typical enterprise applications include:

- tenant isolation,
- study or room isolation,
- data-domain separation,
- region-specific persistence,
- controlled authority switching,
- and identity-scoped audit integration.

<!-- ### 5.1) What controls do not solve

Controls do not solve every advanced deployment concern. In particular, they do
not provide:

- passive traffic visibility on a strict relay,
- message mirroring,
- observer access to unaddressed traffic,
- network or transport authorization,
- external IAM lifecycle by themselves,
- or HSM / KMS integration by themselves.

Those are separate concerns involving relay architecture, routing, transport
security, infrastructure IAM, key management, or audit platform design. A
controls object is where one identity can integrate with those systems. It is
not a replacement for them. -->

### 5.2) Final selection criterion

Use `SummonerIdentityControls` when the requirement is:

> This principal needs its own reusable control package.

Do not use `SummonerIdentityControls` when the real requirement is:

> I need a second identity,
> I need broader traffic visibility,
> or I need a transport or relay feature.

Those are different design questions.

## 6) Minimal API reminder

### 6.1) Identity binding on the agent

```python
identity = agent.attach_identity(store_dir="./store")
identity = agent.require_identity()
identity = agent.detach_identity()
```

### 6.2) Controls binding on the identity

This sequence shows the explicit controls lifecycle on one identity: create the
controls object, attach it, read it back if needed, and detach it when the
identity should stop using those rules.

```python
controls = SummonerIdentityControls()
identity.attach_controls(controls)
controls = identity.require_controls()
controls = identity.detach_controls()
```

Attachment notes:

- `attach_controls(...)` uses a single controls slot on the identity,
- a later `attach_controls(other_controls)` call replaces the earlier attached
  controls object,
- one controls object can still define multiple hook callbacks.

### 6.3) Hook registration on the controls

The hook is defined on the controls object itself, then the identity uses it
after attachment.

```python
controls = SummonerIdentityControls()

@controls.on_get_session
def get_session(identity, peer_public_id, local_role):
    return identity.get_session_default(peer_public_id, local_role)
```

That is the complete mechanical model:

- bind a principal to a workload,
- optionally bind controls to that principal,
- and keep each concern explicit.
