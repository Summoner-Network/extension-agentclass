# `meta` and Identity Continuity in Aurora

This note explains how the `meta` field in `SummonerIdentity` affects identity,
fingerprints, and continuity between agents.

The short answer is:

- `meta` is part of the signed public identity record.
- `meta` does **not** affect `id_fingerprint(...)`.
- adding or removing `meta` fields does **not** break session continuity as
  long as the same underlying keys remain in use.

That distinction is important for enterprise deployments. It allows Aurora
identities to carry additional directory or platform identifiers in `meta`
without forcing a relationship reset every time metadata evolves.


## 1) What `meta` is

A public Aurora identity record contains the following core fields:

- `created_at`
- `pub_enc_b64`
- `pub_sig_b64`
- optional `meta`
- `sig`
- `v`

`meta` is an optional signed metadata field. It is intended to carry
application-level identity information that should travel with the public
identity record.

Examples include:

- an enterprise directory identifier,
- a tenant identifier,
- a workload class or environment label,
- a compliance or policy profile reference,
- a human-readable agent label,
- or a platform-specific agent identifier such as a Microsoft Entra agent ID.


## 2) What `meta` changes and what it does not change

The most useful way to think about `meta` is:

> `meta` changes the signed claim set attached to an identity. It does not
> change the underlying cryptographic principal unless the keys change.

The table below summarizes the effect.

| Surface | Does `meta` affect it? | Why |
| --- | --- | --- |
| `verify_public_id(...)` | Yes | `meta` is included in the signed public core when present |
| `sig` on the public identity record | Yes | changing `meta` requires re-signing the public identity |
| `id_fingerprint(pub_sig_b64)` | No | the fingerprint is derived only from `pub_sig_b64` |
| fallback peer-cache key | No | peer records are keyed by the signing-key fingerprint |
| fallback session-store key | No | session keys are derived from the signing-key fingerprint |
| payload/history-proof AAD direction binding | No | those bindings use fingerprints, not `meta` |
| X25519 session key agreement | No | key agreement uses the encryption key plus signing-key direction data |
| continuity history for a peer | No | continuity is anchored to the same peer fingerprint and session chain |
| envelope signature | Indirectly yes | the `from` identity record changes, so the signed envelope content changes too |


## 3) Why `id_fingerprint(...)` does not change

Aurora computes the fingerprint from the signing public key only:

```python
def id_fingerprint(pub_sig_b64: str) -> str:
    raw = b64_decode(pub_sig_b64)
    return base64.urlsafe_b64encode(_sha256(raw)).decode("utf-8").rstrip("=")[:22]
```

This means:

- changing `meta` does not change the fingerprint,
- changing `sig` does not change the fingerprint,
- changing `created_at` does not change the fingerprint,
- only changing the signing public key changes the fingerprint.

In Aurora, the fingerprint is therefore a stable local identifier for the
cryptographic signer, not for the entire JSON shape of the public identity
record.


## 4) Why continuity is preserved when `meta` changes

Aurora continuity is anchored to the peer’s keys and fingerprinted direction,
not to the current contents of `meta`.

In the current implementation:

- peer caches are keyed by `id_fingerprint(pub_sig_b64)`,
- session-store keys are derived from `id_fingerprint(pub_sig_b64)`,
- payload AAD uses `from` and `to` fingerprints,
- `history_proof` AAD uses `from` and `to` fingerprints,
- and symmetric session derivation uses the encryption key plus signing-key
  direction data.

As a result, the following operation preserves continuity:

1. an agent keeps the same `pub_sig_b64` and `pub_enc_b64`,
2. the agent updates only `meta`,
3. the public identity record is re-signed,
4. peers receive the updated record,
5. and ongoing or future continuity checks still bind to the same cryptographic
   identity.


## 5) What peers will observe after a `meta` change

Although continuity is preserved, peers do observe a change in the public
identity record.

The peer-visible effects are:

1. the `from` identity object inside envelopes now contains the updated `meta`,
2. the `sig` on that public identity record changes because the signed content
   changed,
3. the peer cache entry keyed by fingerprint is refreshed with the new public
   identity record,
4. the fingerprint remains the same.

This means a peer that tracks the whole `public_id` object may notice that the
record changed, while a peer that tracks agents by fingerprint will still view
it as the same agent identity.


## 6) Practical scenarios


### Scenario A: add an enterprise directory identifier

Suppose an agent already has an Aurora identity and later adds this metadata:

```json
{
  "entra_agent_id": "8c9a7f8e-3a64-4c4b-a5d3-9c8b6d0e1234",
  "tenant_id": "contoso-eu-prod"
}
```

Effect:

- the public identity record is re-signed,
- `id_fingerprint(...)` stays the same,
- existing continuity history remains valid,
- peer caches can refresh the stored `meta` in place.

This is the normal enterprise enrichment pattern.


### Scenario B: remove a metadata field

Suppose an agent stops sending:

```json
{
  "display_name": "GM Room 17",
  "entra_agent_id": "8c9a7f8e-3a64-4c4b-a5d3-9c8b6d0e1234"
}
```

and later sends:

```json
{
  "entra_agent_id": "8c9a7f8e-3a64-4c4b-a5d3-9c8b6d0e1234"
}
```

Effect:

- the signed public record changes,
- the fingerprint does not change,
- continuity does not reset,
- peers see updated metadata for the same fingerprint.


### Scenario C: change only the metadata for one process run

Aurora also allows an in-memory metadata override during envelope creation:

```python
envelope = await identity.seal_envelope(
    payload,
    session,
    to=peer_public_id,
    id_meta={
        "entra_agent_id": "8c9a7f8e-3a64-4c4b-a5d3-9c8b6d0e1234",
        "deployment_slot": "blue",
    },
)
```

Effect:

- the in-memory `public_id` used by that process is updated and re-signed,
- the same signing and encryption keys remain in use,
- continuity remains intact,
- the metadata change is not committed to disk unless
  `update_id_meta(...)` or `id(..., meta=...)` is used to persist it.


### Scenario D: rotate the actual identity keys

This is the important contrast case.

If the agent changes:

- `pub_sig_b64`, or
- `pub_enc_b64`,

then the agent is no longer presenting the same cryptographic identity.

Effect:

- the fingerprint changes if `pub_sig_b64` changes,
- session derivation changes if `pub_enc_b64` changes,
- continuity relationships should be treated as a new identity boundary.

This is not a metadata update. It is an identity rotation.


## 7) Enterprise meaning of `meta`

For enterprise deployments, the right mental model is:

> `meta` is a signed claim set carried by the Aurora identity record.

That is useful because it allows a single Aurora identity to carry external
references such as:

- Entra agent identifiers,
- internal IAM subject identifiers,
- tenant or region labels,
- workload ownership markers,
- governance profile references.

This is especially useful when the enterprise wants:

- stable continuity anchored to the Aurora keys,
- but evolving business or directory identifiers attached to the same agent.


## 8) What `meta` does **not** prove by itself

`meta` is signed by the Aurora identity’s signing key. That proves:

- the holder of the current Aurora signing key is asserting this metadata.

It does **not** automatically prove:

- that an Entra ID is still valid in Microsoft,
- that a tenant label is authorized,
- that the agent is allowed to act under that external identifier,
- or that an external directory agrees with the claim.

If an enterprise wants `meta` to be authoritative, Aurora should be combined
with application or policy checks that validate the metadata against the
external source of truth.

In practice, the safe interpretation is:

- Aurora proves continuity of the cryptographic principal,
- `meta` carries signed claims about that principal,
- enterprise policy decides which of those claims are trusted for access control
  or routing decisions.


## 9) Recommended enterprise patterns

Use `meta` for stable, non-secret identity claims such as:

- enterprise agent ID,
- tenant ID,
- region,
- environment,
- policy profile name,
- human-readable label.

Avoid using `meta` for:

- private secrets,
- bearer tokens,
- short-lived access tokens,
- rapidly changing telemetry,
- or bulky data that would unnecessarily enlarge every envelope.

Keep the following rule in mind:

> If the value is part of the identity story, `meta` is a good candidate. If
> the value is part of a live session, secret, or transient runtime state, it
> should not live in `meta`.


## 10) Operational guidance

When an enterprise platform adds additional identifiers to Aurora identities,
the safest pattern is:

1. keep the Aurora signing and encryption keys stable for the life of the
   identity relationship,
2. put external directory identifiers in `meta`,
3. treat those fields as signed claims, not as automatic authority,
4. validate them externally when they matter for authorization,
5. rotate keys only when an actual identity boundary or key lifecycle event
   requires it.

This gives the platform two useful properties at the same time:

- continuity remains stable across metadata enrichment,
- and enterprise identity context can evolve without forcing every peer to
  rediscover the agent as a new principal.


## 11) Summary

`meta` is flexible by design.

Adding or removing metadata:

- changes the signed public identity record,
- does not change the Aurora fingerprint,
- does not reset continuity by itself,
- and allows enterprise identifiers to travel with the same cryptographic
  principal.

The continuity boundary in Aurora is the key material, not the metadata.
