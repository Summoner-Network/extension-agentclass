# Aurora Version Lifecycle

Aurora does not have one global version number that governs everything. It has
several independent version surfaces, and each one should change only when its
own contract changes.

That distinction matters because the version strings in Aurora do not all mean
the same thing:

- some version signed or encrypted wire formats,
- some version local on-disk store schemas,
- some version public Python integration surfaces,
- and one string is only a release marker for the Aurora layer itself.

This guide focuses on the string-valued version surfaces and the versioned
cryptographic labels in `identity.py`, `host.py`, `agentclass.py`, and
`agentmerger.py`. It does not attempt to catalog every internal integer field
named `schema_version`.

The safest rule is:

> Increase only the version that matches the contract you changed. Do not use a
> release bump as a substitute for a schema bump, and do not change a schema
> version when the public contract did not change.


## 1) Fast decision guide

Use the following questions to decide which version surface should move.

| Question | Version surface |
| --- | --- |
| Did the signed public identity record change shape or meaning? | `ID_VERSION` |
| Did the envelope object change shape or validation semantics? | `ENV_VERSION` |
| Did the encrypted payload object change shape, algorithm, or binding? | `PAYLOAD_ENC_VERSION` |
| Did the `history_proof` object change shape, algorithm, or continuity meaning? | `HISTORY_PROOF_VERSION` |
| Did the wrapped JSON file format of `sessions.json`, `peer_keys.json`, or `replay.json` change? | `SESSIONS_STORE_VERSION`, `PEER_KEYS_STORE_VERSION`, `REPLAY_STORE_VERSION` |
| Did the public controls contract change? | `IDENTITY_CONTROLS_VERSION` |
| Did the Aurora host integration contract change? | `IDENTITY_HOST_VERSION` |
| Did Aurora itself ship a new release without changing any schema? | `_AuroraMixin.release_version` |
| Did keyed-receive DNA become incompatible across Aurora exports/imports? | Add an explicit Aurora DNA schema version or a new type tag; current code has no dedicated Aurora DNA version string |


## 2) General rules before changing any version

Apply these rules every time a version string is considered for a change.

1. Identify the consumer of the value.
   A wire-format version is consumed by another Aurora identity. A store version
   is consumed by the local file loader. A host version is consumed by Python
   callers and tools that inspect `identity_versions()`.

2. Decide whether the change is additive or incompatible.
   If older code can still interpret the new value safely and correctly, a
   version bump is often not required. If older code would misread, silently
   accept, or mis-verify the new object, a version bump is required.

3. Update every coupled surface together.
   In `identity.py`, some version strings are tied to cryptographic domain
   labels such as `.../v1/...`. Those labels are part of the compatibility
   surface and must not drift independently.

4. Prefer fail-closed behavior over silent fallback.
   If a new version is introduced, loaders and validators should reject older or
   newer incompatible data explicitly rather than attempting a best-effort read.

5. Treat release markers and schema versions differently.
   `release_version` may move even when no serialized schema changes. A schema
   version must not be changed only because the package or feature set was
   released.


## 3) `identity.py`

`tooling/aurora/identity/identity.py` contains the largest version surface in
Aurora. Those values fall into four categories:

- signed and encrypted protocol objects,
- fallback-store document schemas,
- the public controls API,
- and versioned cryptographic domain labels.


### 3.1) Signed and encrypted protocol objects

| Constant | Current value | Governs | Increase when | Do not increase when |
| --- | --- | --- | --- | --- |
| `ID_VERSION` | `id.v1` | Public identity records and saved identity documents | The signed identity record changes shape, canonicalization, required fields, or signature meaning | Only internal helpers, comments, or runtime validation messages change |
| `ENV_VERSION` | `env.v1` | Envelope object structure and validation contract | The top-level envelope structure changes or an older `open_envelope()` would misinterpret a new envelope | Internal refactors preserve the exact accepted and emitted envelope contract |
| `PAYLOAD_ENC_VERSION` | `payload.enc.v1` | Encrypted payload object shape and payload encryption contract | The payload encryption object changes fields, algorithm, nonce rules, or AEAD binding | Only internal implementation changes while the payload object and cryptographic binding remain identical |
| `HISTORY_PROOF_VERSION` | `histproof.v1` | `history_proof` object shape and continuity proof contract | The proof object changes fields, algorithm, associated data, or continuity meaning | Only helper code changes while emitted and accepted `history_proof` objects stay identical |

#### Notes

- `ID_VERSION` is not only a public-id label. It is also written into saved
  identity documents that contain public and private material together. If the
  saved identity document meaning changes, that change must be treated as an
  `ID_VERSION` change.
- `ENV_VERSION`, `PAYLOAD_ENC_VERSION`, and `HISTORY_PROOF_VERSION` should be
  thought of as interoperability boundaries. If two Aurora runtimes do not agree
  on these values, they should not silently interoperate.


### 3.2) Fallback-store document schemas

| Constant | Current value | Governs | Increase when | Do not increase when |
| --- | --- | --- | --- | --- |
| `SESSIONS_STORE_VERSION` | `sessions.store.v1` | Wrapped `sessions.json` schema | The on-disk `sessions.json` document shape changes | Runtime session logic changes but `sessions.json` keeps the same wrapped schema |
| `PEER_KEYS_STORE_VERSION` | `peer_keys.store.v1` | Wrapped `peer_keys.json` schema | The on-disk `peer_keys.json` document shape changes | Peer-key lookup logic changes without changing the file schema |
| `REPLAY_STORE_VERSION` | `replay.store.v1` | Wrapped `replay.json` schema | The on-disk `replay.json` document shape changes | Replay rules change but the stored document shape stays identical |

#### Notes

- These versions govern the wrapped document schema, not the business meaning of
  every field in memory.
- If a future change only adds internal caching, eviction, or validation logic
  while the written JSON structure stays the same, the store version should not
  move.
- If any wrapped file changes shape, the loader should either migrate it
  explicitly or reject it clearly.


### 3.3) Public controls API

| Constant | Current value | Governs | Increase when | Do not increase when |
| --- | --- | --- | --- | --- |
| `IDENTITY_CONTROLS_VERSION` | `aurora.identity.controls.v1` | Public contract of `SummonerIdentityControls` and its hook model | Existing controls code could be misinterpreted because hook names, required signatures, precedence guarantees, or attach semantics changed incompatibly | Internal refactors or documentation changes preserve the same public controls contract |

#### Notes

- This is an API contract version, not a wire-format version.
- If a future change only adds a new optional helper without changing the
  meaning of the existing hook contract, a bump is usually not required.
- If Aurora introduces a new interpretation of existing controls hooks, the
  version should move because external callers and tooling may inspect it via
  `SummonerIdentity.controls_version()` or `IdentityHostMixin.identity_versions()`.


### 3.4) Versioned cryptographic domain labels

`identity.py` also contains version-bearing domain labels:

- `_HKDF_INFO_SYM = b"summoner/session/v1/sym"`
- `_HKDF_INFO_HISTORY_PROOF = b"summoner/session/v1/history_proof"`
- `_HKDF_INFO_PAYLOAD = b"summoner/session/v1/payload"`
- `_HIST_DOMAIN_RESET = b"summoner/hist/v1/reset"`
- `_LINK_DOMAIN = b"summoner/link/v1"`
- `_HISTORY_PROOF_AAD_DOMAIN = "summoner/history_proof/v1"`
- `_PAYLOAD_AAD_DOMAIN = "summoner/payload/v1"`
- `_ID_FILE_AAD = b"summoner/identity_file/v1"`

These are not cosmetic strings. They participate in domain separation for key
derivation, hashing, and AEAD associated data. They should be treated as part
of the compatibility surface.

| Domain label group | Increase when | Coupled versions that should usually move with it |
| --- | --- | --- |
| `_HKDF_INFO_PAYLOAD`, `_PAYLOAD_AAD_DOMAIN` | Payload encryption derivation or AEAD binding changes | `PAYLOAD_ENC_VERSION`, and often `ENV_VERSION` |
| `_HKDF_INFO_HISTORY_PROOF`, `_HISTORY_PROOF_AAD_DOMAIN` | History-proof derivation or AEAD binding changes | `HISTORY_PROOF_VERSION`, and often `ENV_VERSION` |
| `_HKDF_INFO_SYM` | Session symmetric-key derivation changes | Usually `ENV_VERSION`, and often `PAYLOAD_ENC_VERSION` plus `HISTORY_PROOF_VERSION` |
| `_HIST_DOMAIN_RESET`, `_LINK_DOMAIN` | Continuity hash semantics change | Usually `HISTORY_PROOF_VERSION`; document chain-reset consequences clearly |
| `_ID_FILE_AAD` | Saved identity-file protection changes | Usually `ID_VERSION` |

#### Rule

Do not change a versioned cryptographic domain label by itself and leave the
corresponding object version unchanged. A runtime that emits a new cryptographic
binding should also expose a new object version so mismatches fail clearly.


## 4) `host.py`

`tooling/aurora/identity/host.py` defines one host integration version.

| Constant | Current value | Governs | Increase when | Do not increase when |
| --- | --- | --- | --- | --- |
| `IDENTITY_HOST_VERSION` | `aurora.identity.host.v1` | Public Aurora host integration contract exposed by `IdentityHostMixin` | `attach_identity`, `detach_identity`, `require_identity`, `has_identity`, or the semantics of `identity_versions()` change incompatibly | Underlying identity wire/store versions move but the host contract stays the same |

#### Notes

- `identity_versions()` republishes identity-layer version strings, but that
  does not mean `IDENTITY_HOST_VERSION` must move every time one of those
  downstream versions changes.
- Increase `IDENTITY_HOST_VERSION` only when the host integration contract
  itself changes. Examples include a different attach contract, different
  required types, or a changed meaning of the returned version map.


## 5) `agentclass.py`

`tooling/aurora/agentclass.py` currently has one true version string and one
compatibility tag that should be managed deliberately.


### 5.1) `_AuroraMixin.release_version`

| Symbol | Current value | Governs | Increase when | Do not increase when |
| --- | --- | --- | --- | --- |
| `_AuroraMixin.release_version` | `beta.1.2.0` | Aurora release marker for the mixin and `SummonerAgent` layer | Aurora publishes a new release or milestone | A schema or protocol change happens but the Aurora release marker is intentionally unchanged |

This string is a release marker, not a serialized schema version. It should be
managed as release metadata.

Recommended convention:

- first segment: channel or stability stage, such as `beta`,
- next segment: major Aurora API generation,
- next segment: additive feature milestone,
- last segment: patch-level fixes and documentation corrections.

Using the current shape, the practical bump rules are:

- change `beta.1.2.0` to `beta.1.2.1` for bug fixes, test-only corrections,
  documentation improvements, or performance work that does not intentionally
  change the public Aurora contract;
- change `beta.1.2.0` to `beta.1.3.0` for additive Aurora features or new
  optional capabilities;
- change `beta.1.2.0` to `beta.2.0.0` when Aurora makes an intentional breaking
  public change at the agent layer;
- replace the `beta` prefix when Aurora exits the beta channel.

If the project later adopts a different release naming convention, this
documentation and the string format should be changed together.


### 5.2) `AURORA_KEYED_RECEIVE_TYPE`

`AURORA_KEYED_RECEIVE_TYPE = "aurora:keyed_receive"` is not a version string,
but it is the compatibility tag used in Aurora DNA exports and imports.

It should remain stable when:

- Aurora only adds optional DNA fields,
- merger/translation remains backward-compatible,
- and older keyed-receive DNA entries can still be interpreted correctly.

It should not be changed casually. If a future keyed-receive DNA change becomes
incompatible, Aurora should do one of the following explicitly:

1. add a dedicated DNA schema version field to the exported entry, or
2. introduce a new type tag such as `aurora:keyed_receive.v2`.

That decision belongs to `agentclass.py` because it is the file that emits the
Aurora DNA entries.


## 6) `agentmerger.py`

`tooling/aurora/agentmerger.py` does not currently define an independent version
string.

That is intentional today. The merger and translator consume:

- `AURORA_KEYED_RECEIVE_TYPE` from `agentclass.py`,
- the keyed-receive DNA field set emitted by `_build_aurora_dna_entry(...)`,
- and the general Aurora release line inherited from `_AuroraMixin`.

### What this means in practice

- If Aurora keyed-receive DNA remains backward-compatible, `agentmerger.py`
  does not need its own version constant.
- If `agentmerger.py` ever needs to support multiple incompatible Aurora DNA
  dialects, that is the point where Aurora should introduce an explicit DNA
  schema version or a versioned DNA type tag.
- A merger-specific version constant is only justified once the merger itself
  must branch on serialized Aurora data formats rather than simply replaying the
  current one.


## 7) Recommended change procedure

Use this checklist when any Aurora version string changes.

1. Update the owning constant in code.
2. Update every coupled constant or domain label that must move with it.
3. Update version-reporting helpers:
   - `SummonerIdentity.store_versions()`
   - `SummonerIdentity.controls_version()`
   - `IdentityHostMixin.identity_versions()`
4. Update documentation that names the old value or old lifecycle.
5. Update tests that assert the version or its behavior.
6. Add explicit validation, migration, or fail-closed handling for persisted or
   exchanged artifacts.
7. Record in the change description why the old version could no longer be
   interpreted safely.


## 8) Summary table

| File | Version surface | Current value | Primary trigger |
| --- | --- | --- | --- |
| `identity.py` | `ID_VERSION` | `id.v1` | Signed public identity record changes |
| `identity.py` | `ENV_VERSION` | `env.v1` | Envelope contract changes |
| `identity.py` | `PAYLOAD_ENC_VERSION` | `payload.enc.v1` | Encrypted payload object or binding changes |
| `identity.py` | `HISTORY_PROOF_VERSION` | `histproof.v1` | `history_proof` object or continuity proof changes |
| `identity.py` | `SESSIONS_STORE_VERSION` | `sessions.store.v1` | `sessions.json` wrapped schema changes |
| `identity.py` | `PEER_KEYS_STORE_VERSION` | `peer_keys.store.v1` | `peer_keys.json` wrapped schema changes |
| `identity.py` | `REPLAY_STORE_VERSION` | `replay.store.v1` | `replay.json` wrapped schema changes |
| `identity.py` | `IDENTITY_CONTROLS_VERSION` | `aurora.identity.controls.v1` | Controls API changes incompatibly |
| `identity.py` | versioned domain labels | `.../v1/...` | Cryptographic derivation or binding changes |
| `host.py` | `IDENTITY_HOST_VERSION` | `aurora.identity.host.v1` | Host integration contract changes |
| `agentclass.py` | `_AuroraMixin.release_version` | `beta.1.2.0` | Aurora release milestone changes |
| `agentclass.py` | `AURORA_KEYED_RECEIVE_TYPE` | `aurora:keyed_receive` | Introduce a new type only if Aurora DNA becomes incompatible |
| `agentmerger.py` | no dedicated version string today | — | Add one only if merger must interpret multiple incompatible Aurora DNA dialects |
