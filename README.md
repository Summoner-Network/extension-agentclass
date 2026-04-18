# Summoner Extension Workspace

This repository is an extension workspace built on top of `summoner-core`.

Its purpose is to host extension layers that add higher-level runtime,
identity, orchestration, or domain-specific behavior without moving those
concerns into the core Summoner package too early. Aurora is the current
extension in this repository. In the future, this repository may also contain
other extensions such as Brook, Petal, or additional experimental layers with
their own APIs, tests, and documentation.


## What This Repository Is For

`summoner-core` provides the base client, routing, send/receive decorators,
state synchronization, and merger/translation mechanisms.

This repository is for extension code that:

- builds on those core primitives,
- introduces higher-level behavior that is not yet part of core,
- may evolve at a different pace than core,
- and benefits from its own documentation and test surface.

The intent is to keep a clean separation between:

- **core orchestration contracts**, which belong in `summoner-core`, and
- **extension behavior**, which can mature here before any future promotion to
  core is considered.


## Current Extension: Aurora

Aurora is the current extension package in this repository. It extends the
Summoner runtime with two main capabilities:

1. **Agent-level orchestration utilities**
   Aurora introduces `SummonerAgent`, Aurora-aware merge/translation support,
   and keyed receive behavior for workloads that need stronger ordering and
   replay discipline than a plain route handler.

2. **Identity, continuity, and envelope handling**
   Aurora introduces `SummonerIdentity`, which provides signed public identity
   records, session continuity, encrypted envelopes, replay protection,
   discovery verification, and identity-scoped customization through
   `SummonerIdentityControls`.

In practical terms, Aurora is the layer that turns raw Summoner routing into a
more opinionated agent runtime with continuity-aware messaging and richer
identity semantics.


## Aurora Mental Model

Aurora can be understood as a layered extension on top of Summoner Core:

```text
Summoner Core
  |- routing
  |- send / receive orchestration
  |- state sync
  |- client merge / translation
  |
  v
Aurora
  |- SummonerAgent
  |- keyed_receive and Aurora DNA
  |- AgentMerger / AgentTranslation
  |- SummonerIdentity
  |- SummonerIdentityControls
```

The general separation is:

- `summoner-core` decides how the base orchestration engine behaves,
- Aurora adds stronger agent and identity patterns on top of that engine,
- application code decides the actual business workflow.


## Main Aurora Surfaces

The current Aurora public surface is centered around these objects:

| Surface | Purpose |
| --- | --- |
| `SummonerAgent` | Aurora-aware client class for higher-level agent workloads |
| `AgentMerger` / `AgentTranslation` | Aurora-aware replay and translation of Aurora DNA |
| `SummonerIdentity` | Signed identity records, session continuity, envelope sealing/opening, replay checks |
| `SummonerIdentityControls` | Identity-scoped storage and trust customization |
| `IdentityHostMixin` | Composition layer that binds a `SummonerIdentity` to an Aurora host |

Typical import path:

```python
from tooling.aurora import (
    SummonerAgent,
    SummonerIdentity,
    SummonerIdentityControls,
    id_fingerprint,
    verify_public_id,
)
```


## Repository Layout

The repository is organized so that each extension can keep its own code,
documentation, and tests.

| Path | Role |
| --- | --- |
| [`tooling/aurora`](tooling/aurora) | Aurora extension package |
| [`tooling/aurora/identity`](tooling/aurora/identity) | `SummonerIdentity` documentation and identity-layer exports currently hosted in Aurora |
| [`tests/test_aurora_agent`](tests/test_aurora_agent) | End-to-end Aurora agent example and supporting notes |
| [`tests/test_identity`](tests/test_identity) | Identity and controls test suite |
| [`core`](core) | Local `summoner-core` reference / integration workspace |
| [`tooling/your_package`](tooling/your_package) | Placeholder showing where additional extensions can live |

This layout is intentionally extension-friendly. Aurora is the current
extension, but the structure is not Aurora-specific.


## Where To Start

If you want to understand Aurora quickly, these are the best entry points:

| Goal | Start here |
| --- | --- |
| Understand the Aurora package surface | [`tooling/aurora/__init__.py`](tooling/aurora/__init__.py) |
| Understand the agent layer | [`tooling/aurora/agentclass.py`](tooling/aurora/agentclass.py) |
| Understand Aurora-aware replay / translation | [`tooling/aurora/agentmerger.py`](tooling/aurora/agentmerger.py) |
| Learn the identity workflow quickly | [`tooling/aurora/identity/cheatsheet.md`](tooling/aurora/identity/cheatsheet.md) |
| Read the full identity API reference | [`tooling/aurora/identity/readme.md`](tooling/aurora/identity/readme.md) |
| Understand identity-scoped controls | [`tooling/aurora/identity/identity_controls.md`](tooling/aurora/identity/identity_controls.md) |
| Understand how `meta` affects continuity | [`tooling/aurora/identity_meta.md`](tooling/aurora/identity_meta.md) |
| Understand version lifecycle in Aurora | [`tooling/aurora/versioning.md`](tooling/aurora/versioning.md) |
| See a concrete Aurora agent example | [`tests/test_aurora_agent/readme.md`](tests/test_aurora_agent/readme.md) |


## Future Extensions

Aurora should be read as the first extension in a broader extension workspace,
not as the only permanent content of this repository.

Future extensions may:

- add different orchestration models,
- add different identity or policy layers,
- target other deployment styles,
- or explore domain-specific agent runtimes.

If additional extensions are added later, the expected pattern is:

- one package per extension under `tooling/`,
- extension-specific documentation alongside that package,
- extension-specific tests under `tests/`,
- and a root README that continues to describe the repository as a family of
  Summoner extensions rather than a single package.
