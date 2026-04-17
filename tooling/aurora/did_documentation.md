# Aurora Agent Identity Specification

**Version:** `id.v1` profile  
**Audience:** clients, enterprise architects, security reviewers, developers,
and implementers  
**Scope:** This document defines the current Aurora agent identity model
implemented by `tooling.aurora.identity.identity.py`.

This document serves two purposes at the same time:

- it explains, in business and architectural terms, what an Aurora agent
  identity is and why it matters operationally;
- it specifies, in enough technical detail, how to generate, verify, persist,
  and interpret the current Aurora identity format in another programming
  language.


## 1) Abstract

Aurora defines an agent identity as a **self-signed public identity record**
backed by two long-term key pairs:

- an Ed25519 key pair for signatures,
- and an X25519 key pair for key agreement.

The public identity record is portable. It is the object exchanged between
agents, embedded in envelopes, cached by peers, and used as the continuity
anchor for ongoing relationships.

The design is intentionally compact:

- one creation timestamp,
- one signing public key,
- one encryption public key,
- optional signed metadata,
- one signature,
- one version tag.

This model gives Aurora three useful properties:

1. **stable identity continuity**
   An agent can restart, move hosts, or reload state and still present the same
   cryptographic identity if it keeps the same key material.

2. **extensible enterprise context**
   The `meta` field allows an Aurora identity to carry external identifiers such
   as tenant IDs, directory IDs, or platform-specific agent identifiers without
   redefining the cryptographic core of the identity.

3. **implementation portability**
   The identity format is simple enough to reproduce in another language, as
   long as the implementation follows the exact key serialization,
   canonicalization, and signature rules defined in this document.


## 2) Reader map

Different readers usually need different levels of detail. The document is
organized so each audience can stop at the right depth.

The progression is intentional. [Sections 3 through 6](#3-what-an-aurora-agent-id-is)
define the conceptual model: what the Aurora agent ID is, why the model
exists, what it means in enterprise settings, and how the major identity
surfaces relate to one another. [Sections 7 through 14](#7-cryptographic-profile)
then move into the implementation contract: algorithms, schemas,
canonicalization rules, persistence, and loading. [Sections 15 through
17](#15-metadata-and-enterprise-identifiers) return to operational
interpretation so that metadata, lifecycle, and compatibility claims are clear.

The links in the table below are meant to make that progression easy to follow
without scrolling through the whole document manually.

| Reader | Primary question | Most relevant sections |
| --- | --- | --- |
| Client or enterprise sponsor | What is Aurora’s identity model and why is it useful? | [1](#1-abstract), [3](#3-what-an-aurora-agent-id-is), [4](#4-why-this-model-exists), [5](#5-enterprise-and-operational-meaning), [15](#15-metadata-and-enterprise-identifiers), [16](#16-identity-change-semantics) |
| Enterprise architect | How does identity continuity interact with external enterprise identifiers? | [3](#3-what-an-aurora-agent-id-is), [4](#4-why-this-model-exists), [5](#5-enterprise-and-operational-meaning), [15](#15-metadata-and-enterprise-identifiers), [16](#16-identity-change-semantics) |
| Security reviewer | What is signed, what is stored locally, and what changes continuity? | [6](#6-identity-surfaces), [7](#7-cryptographic-profile), [8](#8-public-identity-record), [9](#9-canonical-json-for-signing), [13](#13-local-identity-file-format), [16](#16-identity-change-semantics) |
| Developer or integrator | How do I generate and verify an Aurora identity? | [8](#8-public-identity-record), [9](#9-canonical-json-for-signing), [10](#10-identity-generation-algorithm), [11](#11-public-identity-verification-algorithm), [12](#12-fingerprint-derivation), [13](#13-local-identity-file-format), [14](#14-local-identity-file-generation-and-loading), [17](#17-minimum-compliance-checklist) |
| Implementer in another language | What exact bytes and encodings must I reproduce? | [7](#7-cryptographic-profile), [8](#8-public-identity-record), [9](#9-canonical-json-for-signing), [10](#10-identity-generation-algorithm), [11](#11-public-identity-verification-algorithm), [12](#12-fingerprint-derivation), [13](#13-local-identity-file-format), [14](#14-local-identity-file-generation-and-loading), [17](#17-minimum-compliance-checklist) |


## 3) What an Aurora agent ID is

Aurora does not define agent identity as a separate application string such as
`my_id`.

That is the first idea a reader should anchor on before going further. Aurora
does not treat the agent ID as a label that floats separately from the
cryptographic material. It treats identity as a signed object that can travel
between runtimes, be embedded in envelopes, and be verified independently by a
peer.

In the current model, the **agent ID** is the signed public identity record
itself:

```json
{
  "created_at": "2026-04-16T17:45:03+00:00",
  "pub_enc_b64": "<base64 raw X25519 public key>",
  "pub_sig_b64": "<base64 raw Ed25519 public key>",
  "meta": "<optional JSON value>",
  "sig": "<base64 Ed25519 signature>",
  "v": "id.v1"
}
```

This object is the portable identity boundary for Aurora agents.

In other words, when one Aurora agent introduces itself to another, this is the
object it presents. The receiving side does not need an external registry to
understand the cryptographic shape of the identity. Everything needed to verify
the public claim set is already inside the record.

It tells other parties:

- when the identity was created,
- which public key is used for signatures,
- which public key is used for key agreement,
- which optional claims are attached to the identity,
- and that the holder of the Ed25519 private key has signed that claim set.

Aurora also defines a short fingerprint derived from `pub_sig_b64`, but that
fingerprint is only a local convenience index. It is not the full identity.

That distinction matters throughout this document. The public identity record
is the object that carries meaning between agents. The fingerprint is a local
shortcut derived from one field inside that record.


## 4) Why this model exists

Aurora’s identity model is designed for agent systems that need continuity,
security, and operational clarity without depending on an external registry.

This section explains the design intent before the document becomes more
technical. The goal is not only to describe what Aurora does, but also to make
clear why the current shape is useful for real deployments.

### 4.1) Stable continuity

When the same identity file is reused, the same public identity record can be
reconstructed and presented again. This allows peers to recognize the same
agent across restarts or migrations.

That property is central to Aurora’s session and continuity model. An agent is
not expected to renegotiate a brand-new persona every time its process restarts.
It can carry a stable cryptographic identity forward over time.

### 4.2) Clear cryptographic roles

Aurora separates:

- **authentication and signing**, handled by Ed25519,
- **key agreement**, handled by X25519.

This keeps the signing story and the confidentiality story distinct and easier
to reason about.

That separation also makes security review easier. A reviewer can ask one set
of questions about authenticity and another about key agreement without mixing
the two responsibilities together.

### 4.3) Metadata extensibility

The `meta` field is deliberately outside the bare minimum key material, but
inside the signed public core. That allows the identity to carry business or
directory context while keeping the cryptographic base small.

This is the feature that makes the identity model practical for enterprise use.
The record can remain compact while still carrying the identifiers that matter
to real organizations.

### 4.4) Local-first operability

Aurora does not require a registry, chain, or remote identity service to create
or validate the base identity record. An agent can generate, store, and reload
its identity locally.

That does not prevent an organization from adding a registry or directory above
Aurora. It means only that the base cryptographic identity format is valid on
its own and does not depend on those external systems to exist.


## 5) Enterprise and operational meaning

This identity model is useful in enterprise settings because it separates three
concerns cleanly:

The table below translates the technical model into operational language. Many
enterprise teams do not reason directly in terms of JSON objects and key
formats; they reason in terms of principals, claims, and operational handles.
Aurora can be mapped to those concepts without changing its underlying design.

| Concern | Aurora surface |
| --- | --- |
| Cryptographic principal | `pub_sig_b64` + `pub_enc_b64` |
| Signed identity claims | the public identity record, including `meta` |
| Local operational handle | the derived fingerprint |

That separation has practical benefits.

It allows different teams to talk about the same identity using the vocabulary
they already use. Security teams can reason about the principal. Platform teams
can reason about the operational handle. Business and compliance teams can
reason about the signed claim set.

### 5.1) Ownership and continuity

An enterprise can treat the public identity record as the portable ID card of
the agent. As long as the same keys are retained, the agent continues to be the
same Aurora principal even if metadata evolves.

That is the part that makes Aurora suitable for long-lived workloads. The
identity can accumulate richer metadata over time without being treated as a
different cryptographic subject.

### 5.2) External identity systems

An enterprise may want to attach identifiers such as:

- a Microsoft Entra agent ID,
- an internal IAM subject identifier,
- a tenant or region identifier,
- a governance profile,
- or a workload ownership label.

Those values belong in `meta`.

This is not a side channel or an afterthought. It is the intended extension
surface for external identity context.

Aurora signs them as part of the public identity record, which means the Aurora
principal is asserting them. It does **not** mean Aurora alone becomes the
source of truth for those external systems. External policy can still decide
which signed claims are trusted.

That distinction is often the most important one for enterprise architects.
Aurora can carry the signed claim, but the enterprise still decides whether that
claim is authoritative enough for routing, access control, audit, or policy.

### 5.3) Investor and client significance

For non-implementers, the strategic point is simple:

> Aurora gives agents a portable, cryptographically verifiable identity that can
> carry enterprise context without forcing a relationship reset every time that
> context evolves.

That makes it suitable for:

- stable enterprise agent deployments,
- multi-tenant platforms,
- regulated environments that need continuity and auditability,
- and platforms that need to map Aurora identities to external directory or IAM
  systems.


## 6) Identity surfaces

Aurora uses three related but distinct identity surfaces.

This distinction prevents confusion later in the document. Readers often use
the words “identity,” “fingerprint,” and “identity file” interchangeably, but
they solve different problems and they change under different conditions.

| Surface | Purpose | Stable across `meta` changes? | Stable across signing-key rotation? |
| --- | --- | --- | --- |
| Public identity record | The identity object exchanged between agents | No, because the signed object changes | No |
| Fingerprint | Local indexing key derived from the signing public key | Yes | No |
| Local identity file | Private persistence container for one identity | Usually yes until the operator rotates keys or metadata on disk | No |

The most important interpretation rule is:

> The public identity record is the portable agent identity. The fingerprint is
> a derived local index. The identity file is a private persistence container.

The rest of the specification depends on that distinction. The next sections
move from conceptual meaning to the exact rules that make those three surfaces
interoperate correctly.


## 7) Cryptographic profile

Aurora identity generation uses the following primitives:

This section defines the cryptographic contract of the identity layer. An
implementation in another language does not have freedom to swap these
primitives if it wants to remain compatible with the current Aurora profile.

| Purpose | Algorithm |
| --- | --- |
| Signing | Ed25519 |
| Key agreement | X25519 |
| Identity-file encryption | AES-256-GCM |
| Password-based key derivation | scrypt |
| Fingerprint hashing | SHA-256 |
| String encoding | UTF-8 |
| Binary-to-text encoding | Standard Base64 with padding |

### 7.1) Raw key format

Both public and private keys are serialized in **raw 32-byte form** before
Base64 encoding.

That detail is operationally important. Many libraries default to PEM, DER, or
other container formats. Aurora does not. Compatibility requires the raw 32-byte
form before Base64 encoding.

| Key type | Raw length | Encoding in Aurora |
| --- | --- | --- |
| X25519 public key | 32 bytes | standard Base64 |
| X25519 private key | 32 bytes | standard Base64 |
| Ed25519 public key | 32 bytes | standard Base64 |
| Ed25519 private key | 32 bytes | standard Base64 |
| Ed25519 signature | 64 bytes | standard Base64 |


## 8) Public identity record

The next three sections describe the public identity record from three
perspectives:

- what fields it contains,
- which subset is actually signed,
- and how another implementation must reproduce the canonical bytes.

### 8.1) Schema

The public identity record has this logical structure:

```json
{
  "created_at": "<ISO 8601 UTC string with explicit offset>",
  "pub_enc_b64": "<standard Base64 raw X25519 public key>",
  "pub_sig_b64": "<standard Base64 raw Ed25519 public key>",
  "meta": "<optional JSON value>",
  "sig": "<standard Base64 Ed25519 signature over canonical public core>",
  "v": "id.v1"
}
```

### 8.2) Field meanings

The table below should be read as a contract, not as informal documentation.
Fields that are marked required are required for successful verification in the
current Aurora implementation.

| Field | Required | Meaning |
| --- | --- | --- |
| `created_at` | Yes | UTC creation timestamp for this identity |
| `pub_enc_b64` | Yes | X25519 public key used in session derivation |
| `pub_sig_b64` | Yes | Ed25519 public key used for identity and envelope signatures |
| `meta` | No | Optional signed metadata claim set |
| `sig` | Yes | Ed25519 signature over the canonical public core |
| `v` | Yes | Public identity format version string; currently `id.v1` |

### 8.3) Signed public core

Aurora signs only the public core:

This is one of the most important implementation details in the whole document.
If another implementation signs the full final object instead of the public
core, its signatures will not verify against Aurora.

```json
{
  "created_at": "...",
  "pub_enc_b64": "...",
  "pub_sig_b64": "...",
  "meta": "..."   // included only when meta is not null
}
```

The fields `sig` and `v` are added after signing.

That pattern keeps the signature target small and unambiguous. It also avoids
the circular problem of signing a structure that already contains its own
signature.

### 8.4) `meta` inclusion rule

`meta` is included in the signed core **only if it is present and not null**.

That rule is simple, but it has real lifecycle consequences. A non-null `meta`
value changes the signed identity object. An omitted or null `meta` value does
not.

This means:

- if `meta` is omitted, it is not signed because it is absent,
- if `meta` is explicitly `null`, Aurora treats it as absent for signing,
- if `meta` has any non-null JSON value, that value is signed.

For interoperability, generators should prefer:

- omit `meta` entirely when it is not used,
- include `meta` only when it contains a real JSON value.


## 9) Canonical JSON for signing

Aurora signs the canonical JSON encoding of the public core.

This section is load-bearing. Most cross-language incompatibilities do not come
from the signature algorithm itself; they come from different JSON
canonicalization choices that produce different byte strings before signing.

The canonicalization rules are:

1. Serialize as JSON.
2. Sort object keys lexicographically.
3. Use compact separators: `","` between items and `":"` between key and value.
4. Use UTF-8 bytes for the final string.
5. Use standard JSON string escaping.
6. Use ASCII-escaped JSON output for non-ASCII characters.

The current Python reference behavior is equivalent to:

```python
json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
```

### 9.1) Interoperability guidance

For cross-language implementations, the safest approach is:

These recommendations are conservative on purpose. If a type or serializer
feature can introduce ambiguity across languages, it is better to avoid it than
to hope that two runtimes happen to encode it identically.

- object keys must be strings,
- keys must be sorted lexicographically before serialization,
- no extra whitespace may be emitted,
- integers, booleans, strings, arrays, objects, and `null` are safe JSON types,
- avoid floats, `NaN`, `Infinity`, implementation-specific map ordering, and
  non-string keys inside `meta`.

If another language cannot reproduce these exact rules, it should not claim to
emit Aurora-compatible signed identities.


## 10) Identity generation algorithm

This section is normative.

Everything up to this point has prepared the reader to understand what is being
generated. This section now describes the actual write-side process: how a
runtime creates an Aurora identity record from fresh key material.

### 10.1) What is being built

The goal of the generation algorithm is to produce one portable object: the
public identity record.

If a student is reading this for the first time, it helps to picture the
process like this:

1. start with two key pairs,
2. keep the private halves private,
3. collect the public halves plus a creation timestamp,
4. optionally attach metadata,
5. sign that public claim set,
6. and publish the signed result as the agent identity.

Another way to say the same thing is:

> Aurora turns a pair of long-term keys and a timestamp into a signed identity
> card for the agent.

The table below shows that story at a glance.

| Step | What you have at the start of the step | What you do | What comes out of the step |
| --- | --- | --- | --- |
| 1 | fresh X25519 and Ed25519 key pairs | generate `created_at` | a creation timestamp |
| 2 | key pairs + timestamp | extract public keys and encode them | portable public-key strings |
| 3 | public-key strings + timestamp + optional `meta` | build the unsigned public core | a JSON object that is ready to be signed |
| 4 | unsigned public core | canonicalize and sign with Ed25519 | a signature over the public core |
| 5 | unsigned public core + signature | add `sig` and `v` | the final public identity record |

### 10.2) Inputs

To generate an Aurora identity, an implementation needs only a small set of
inputs:

- a fresh X25519 key pair,
- a fresh Ed25519 key pair,
- an optional `meta` JSON value,
- and, if local persistence is also desired, an optional password for later
  identity-file encryption.

The important thing to notice is that the public identity record uses only the
**public** parts of the two key pairs. The private keys are used during signing
and later for runtime cryptographic operations, but they do not appear inside
the public identity record itself.

### 10.3) Step-by-step walkthrough

This subsection walks through the generation process slowly, in the same order a
new implementation should follow.

#### Step 1: create the identity timestamp

First, generate `created_at`.

This timestamp should be treated as the birth time of the identity. It becomes
part of the signed public core, so peers will later see and verify it as part
of the identity claim set.

Generate `created_at` as:

- current UTC time,
- with microseconds removed,
- formatted as ISO 8601,
- with an explicit UTC offset.

Example:

```text
2026-04-16T17:45:03+00:00
```

#### Step 2: expose only the public key material

Next, take the **public** halves of the two key pairs:

- X25519 public key from the key-agreement pair,
- Ed25519 public key from the signing pair.

Serialize each public key in raw 32-byte form, then encode it with standard
Base64.

At this point you have three public fields:

- `created_at`
- `pub_enc_b64`
- `pub_sig_b64`

The private keys remain private. They are not part of the public identity
record.

#### Step 3: build the unsigned public core

Now assemble the unsigned public core:

```json
{
  "created_at": "<created_at>",
  "pub_enc_b64": "<base64 raw X25519 public key>",
  "pub_sig_b64": "<base64 raw Ed25519 public key>",
  "meta": "<optional non-null JSON value>"
}
```

If `meta` is not used, omit it entirely. Do not include it as a decorative
placeholder.

This is the object that the agent is about to sign. It is not yet a complete
Aurora identity, because it does not yet prove that the holder of the Ed25519
private key stands behind the claim set.

#### Step 4: canonicalize and sign

Take the unsigned public core and canonicalize it exactly as defined in Section
9. That produces one deterministic UTF-8 byte string.

Then:

1. sign those bytes with the Ed25519 private key,
2. Base64-encode the resulting 64-byte signature using standard Base64.

No additional wrapping, hashing, or container format is applied before signing.
The Ed25519 signature is taken directly over the canonical UTF-8 bytes of the
public core.

This is the moment when the public claim set becomes a cryptographically bound
identity claim.

#### Step 5: assemble the final public identity record

Finally, copy the unsigned public core and add:

- `sig`
- `v`

The result is:

```json
{
  "created_at": "<created_at>",
  "pub_enc_b64": "<base64 raw X25519 public key>",
  "pub_sig_b64": "<base64 raw Ed25519 public key>",
  "meta": "<optional JSON value>",
  "sig": "<base64 Ed25519 signature>",
  "v": "id.v1"
}
```

This final object is the public identity record that other agents receive and
verify.

At this point the identity is portable. It can be:

- embedded in envelopes,
- stored in peer caches,
- persisted inside an identity file,
- or handed to another component as the public ID of the agent.

### 10.4) One concrete mental model

The following distinction helps many readers:

- the **unsigned public core** is the set of identity claims,
- the **signature** is the proof that the signing key stands behind those
  claims,
- the **final public identity record** is the claims plus that proof plus the
  version tag.

In compact form:

```text
unsigned claims
    +
signature over those claims
    +
format version
    =
Aurora public identity record
```

### 10.5) Reference pseudocode

```text
function generate_public_identity(x25519_keypair, ed25519_keypair, meta?):
    created_at = utc_now_without_microseconds_as_iso8601_with_offset()

    core = {
        "created_at": created_at,
        "pub_enc_b64": base64(raw_x25519_public_key(x25519_keypair.public)),
        "pub_sig_b64": base64(raw_ed25519_public_key(ed25519_keypair.public))
    }

    if meta is not null:
        core["meta"] = meta

    message = canonical_json_utf8(core)
    signature = ed25519_sign(ed25519_keypair.private, message)

    public_id = copy(core)
    public_id["sig"] = base64(signature)
    public_id["v"] = "id.v1"
    return public_id
```


## 11) Public identity verification algorithm

Generation is the sender-side problem. Verification is the receiver-side
problem. A compatible runtime must be able to reconstruct exactly the same
public core and signature target from the received object.

To verify a public identity record:

1. Ensure the value is a JSON object.
2. Ensure `v == "id.v1"`.
3. Ensure the required fields are present:
   - `created_at`
   - `pub_enc_b64`
   - `pub_sig_b64`
   - `sig`
4. Reconstruct the public core using only:
   - `created_at`
   - `pub_enc_b64`
   - `pub_sig_b64`
   - `meta` only if non-null
5. Canonicalize that core exactly as defined in [Section 9](#9-canonical-json-for-signing).
6. Decode `pub_sig_b64` as a raw 32-byte Ed25519 public key.
7. Decode `sig` as a 64-byte Ed25519 signature.
8. Verify the signature over the canonical UTF-8 bytes.

If any one of those steps fails, the public identity record must be rejected.
The current Aurora behavior is fail-closed rather than best-effort.

### 11.1) Reference pseudocode

```text
function verify_public_identity(public_id):
    require is_object(public_id)
    require public_id["v"] == "id.v1"
    require has(public_id, "created_at")
    require has(public_id, "pub_enc_b64")
    require has(public_id, "pub_sig_b64")
    require has(public_id, "sig")

    core = {
        "created_at": public_id["created_at"],
        "pub_enc_b64": public_id["pub_enc_b64"],
        "pub_sig_b64": public_id["pub_sig_b64"]
    }

    if get(public_id, "meta") is not null:
        core["meta"] = public_id["meta"]

    message = canonical_json_utf8(core)
    pub_sig = ed25519_public_from_raw(base64_decode(public_id["pub_sig_b64"]))
    signature = base64_decode(public_id["sig"])

    require length(signature) == 64
    ed25519_verify(pub_sig, message, signature)
```


## 12) Fingerprint derivation

Aurora also defines a short fingerprint used for local indexing.

This section is separate from the identity record itself because the fingerprint
serves a different purpose. It is a local handle derived from the signing key,
not a second identity format.

### 12.1) Algorithm

Input:

- `pub_sig_b64`

Algorithm:

1. Base64-decode `pub_sig_b64` to the raw 32-byte Ed25519 public key.
2. Compute `SHA-256(raw_pub_sig)`.
3. Base64-url encode the 32-byte hash digest.
4. Remove trailing `=` padding.
5. Take the first 22 characters.

Output:

- 22-character URL-safe string.

### 12.2) Reference pseudocode

```text
function identity_fingerprint(pub_sig_b64):
    raw = base64_decode(pub_sig_b64)
    digest = sha256(raw)
    text = base64url_encode(digest)
    text = remove_trailing_equals(text)
    return first_22_characters(text)
```

### 12.3) Meaning

The fingerprint is:

These properties explain why the fingerprint is useful for storage and lookup
while still being unsuitable as a substitute for the full signed identity
record.

- stable across `meta` changes,
- stable across `created_at` changes,
- unstable across signing-key rotation.

It is suitable for:

- local database keys,
- short peer identifiers,
- route-local indexing,
- UI lookup hints.

It is **not** a substitute for verifying the full public identity record.


## 13) Local identity-file format

Aurora stores private identity material in a local JSON file.

The public identity record is the portable object exchanged between agents. The
identity file is different: it is a local persistence artifact that contains
the public record plus the private key material needed to continue acting as
that identity.

The outer file version is also `id.v1`.

Two storage modes exist:

- plaintext private section,
- encrypted private section.

Both modes are part of the current implementation, but they should not be
treated as equivalent from an operational-security perspective.

### 13.1) Plaintext form

```json
{
  "v": "id.v1",
  "public": {
    "...": "public identity record"
  },
  "private": {
    "priv_enc_b64": "<base64 raw X25519 private key>",
    "priv_sig_b64": "<base64 raw Ed25519 private key>"
  }
}
```

This mode exists in the implementation but should be treated as a development
convenience only.

It is included here for completeness, interoperability, and migration clarity,
not as the recommended production profile.

### 13.2) Encrypted form

This is the preferred operational form. It keeps the public record readable
while protecting the private keys with password-derived encryption.

```json
{
  "v": "id.v1",
  "public": {
    "...": "public identity record"
  },
  "private_enc": {
    "kdf": "scrypt",
    "kdf_params": {
      "n": 16384,
      "r": 8,
      "p": 1
    },
    "salt": "<standard Base64 16-byte salt>",
    "nonce": "<standard Base64 12-byte AES-GCM nonce>",
    "aad": "c3VtbW9uZXIvaWRlbnRpdHlfZmlsZS92MQ==",
    "ciphertext": "<standard Base64 AES-GCM ciphertext>"
  }
}
```

The value of `aad` is the standard Base64 encoding of the UTF-8 bytes:

```text
summoner/identity_file/v1
```

### 13.3) Encrypted private payload

The inner payload is intentionally small. Aurora encrypts only the private key
material, not the public identity record, because peers still need the public
record to be portable and inspectable.

Before encryption, Aurora serializes this object canonically:

```json
{
  "priv_enc_b64": "<base64 raw X25519 private key>",
  "priv_sig_b64": "<base64 raw Ed25519 private key>"
}
```

The ciphertext is:

- AES-256-GCM,
- key derived from scrypt,
- 12-byte random nonce,
- associated data equal to the literal bytes `summoner/identity_file/v1`.

### 13.4) KDF parameters

Aurora’s current defaults are:

These parameters are not incidental implementation details. A runtime that
writes encrypted identity files needs to follow them or write explicit
parameter values into the file, exactly as Aurora does.

| Parameter | Value |
| --- | --- |
| `n` | `2^14` = `16384` |
| `r` | `8` |
| `p` | `1` |
| output length | `32` bytes |

Cross-language implementations that want byte-for-byte compatibility with the
current default file generation should use the same parameters unless the file
explicitly stores different values.


## 14) Local identity-file generation and loading

The previous section defined the shape of the file. This section defines the
processes that write and read it.

### 14.1) Save algorithm

The save path starts from a generated public identity record and then packages
the corresponding private material either directly or under encryption.

```text
function save_identity(path, x25519_keypair, ed25519_keypair, meta?, password?):
    public_id = generate_public_identity(x25519_keypair, ed25519_keypair, meta)

    private_payload = {
        "priv_enc_b64": base64(raw_x25519_private_key(x25519_keypair.private)),
        "priv_sig_b64": base64(raw_ed25519_private_key(ed25519_keypair.private))
    }

    if password is null:
        doc = {
            "v": "id.v1",
            "public": public_id,
            "private": private_payload
        }
        write_json_atomically(path, doc)
        return public_id

    salt = random_bytes(16)
    nonce = random_bytes(12)
    key = scrypt(password, salt, n=16384, r=8, p=1, length=32)
    aad = utf8("summoner/identity_file/v1")
    plaintext = canonical_json_utf8(private_payload)
    ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

    doc = {
        "v": "id.v1",
        "public": public_id,
        "private_enc": {
            "kdf": "scrypt",
            "kdf_params": {"n": 16384, "r": 8, "p": 1},
            "salt": base64(salt),
            "nonce": base64(nonce),
            "aad": base64(aad),
            "ciphertext": base64(ciphertext)
        }
    }

    write_json_atomically(path, doc)
    return public_id
```

### 14.2) Load algorithm

The load path does the reverse. It validates the public identity first, then
recovers the private material, and finally reconstructs the live key objects.

```text
function load_identity(path, password?):
    doc = parse_json(read_file(path))
    require doc["v"] == "id.v1"

    public_id = doc["public"]
    verify_public_identity(public_id)

    if has(doc, "private"):
        payload = doc["private"]
    else:
        enc = doc["private_enc"]
        require password is not null
        require enc["kdf"] == "scrypt"

        params = enc["kdf_params"]
        salt = base64_decode(enc["salt"])
        nonce = base64_decode(enc["nonce"])
        aad = base64_decode(enc["aad"])
        ciphertext = base64_decode(enc["ciphertext"])

        require aad == utf8("summoner/identity_file/v1")

        key = scrypt(
            password,
            salt,
            n=params["n"],
            r=params["r"],
            p=params["p"],
            length=32
        )

        plaintext = aes_gcm_decrypt(key, nonce, ciphertext, aad)
        payload = parse_json(utf8_decode(plaintext))

    priv_enc = x25519_private_from_raw(base64_decode(payload["priv_enc_b64"]))
    priv_sig = ed25519_private_from_raw(base64_decode(payload["priv_sig_b64"]))

    return (public_id, priv_enc, priv_sig)
```


## 15) Metadata and enterprise identifiers

`meta` is the intended extension surface for additional signed identity claims.

This section returns from pure format specification to enterprise semantics.
`meta` is where Aurora becomes practically useful for organizations that need to
map cryptographic principals to business, governance, or directory context.

Examples:

- Microsoft Entra agent ID,
- internal IAM subject ID,
- tenant ID,
- region,
- workload class,
- policy profile label.

### 15.1) What `meta` affects

If `meta` changes:

This list is the operational consequence of the signing rules defined earlier.
It tells the reader exactly what kind of identity change a metadata update is
and, just as importantly, what kind of identity change it is not.

- the public identity record changes,
- the identity signature changes,
- peers observe updated signed metadata,
- the fingerprint does **not** change.

### 15.2) Continuity meaning

Changing `meta` while keeping the same `pub_sig_b64` and `pub_enc_b64` does
**not** break continuity by itself.

Aurora continuity and local storage are keyed from the long-term key material,
not from the full JSON identity object.

This is why enterprise enrichment can happen without forcing every peer to
treat the agent as a new principal.

### 15.3) Authority meaning

`meta` is signed by the Aurora signing key, which means:

- the Aurora principal is asserting the metadata,

but it does **not** automatically mean:

- the external directory still accepts the value,
- the value is currently authorized,
- or the external platform considers that claim valid.

Enterprises that use `meta` for authorization-sensitive identifiers should
validate those claims against their own source of truth.

That division of responsibility is often the right architectural one: Aurora
proves continuity of the principal, while enterprise policy decides how much
authority to assign to the metadata attached to that principal.


## 16) Identity change semantics

The following table defines how the main identity changes should be interpreted.

This is the lifecycle section of the identity model. It helps operators and
reviewers distinguish between a metadata update, a normal continuity-preserving
evolution, and a true identity rotation.

| Change | Same fingerprint? | Same public identity record? | Same continuity boundary? |
| --- | --- | --- | --- |
| Update `meta` only | Yes | No | Yes |
| Update `created_at` only | Yes | No | No; this should not happen for a stable identity |
| Rotate Ed25519 signing key | No | No | No |
| Rotate X25519 encryption key only | Yes | No | No |
| Rotate both keys | No | No | No |

### Operational rule

For a stable agent identity:

These rules are simple, but they are worth stating explicitly because they
determine whether a deployment preserves trust continuity or accidentally
creates a new identity boundary.

- `created_at` should be written once at identity creation and then preserved,
- `meta` may evolve,
- the keys should change only when the deployment intends to create a new
  identity boundary or perform a controlled key lifecycle event.


## 17) Minimum compliance checklist

An implementation may claim compatibility with the current Aurora identity
format only if it does all of the following:

This checklist is intentionally strict. It is meant to answer a practical
question for implementers and reviewers: when is another implementation merely
similar to Aurora, and when is it actually compatible with Aurora?

- generates raw 32-byte X25519 and Ed25519 key material,
- serializes public keys as standard Base64 of raw bytes,
- signs only the canonical public core,
- uses `id.v1` exactly as the identity record version,
- omits `meta` from the signed core when it is absent or null,
- verifies the Ed25519 signature against the canonical public core,
- derives fingerprints from `pub_sig_b64` exactly as specified,
- loads and saves the outer identity file with `v == "id.v1"`,
- uses the same AES-GCM associated-data literal for encrypted identity files,
- and rejects unsupported versions rather than silently accepting them.


## Appendix A) Example public identity record

The example below is illustrative rather than executable. It is meant to help
non-implementers recognize the shape of the object and help implementers sanity
check their own serialized output.

```json
{
  "created_at": "2026-04-16T17:45:03+00:00",
  "pub_enc_b64": "7D2f+5m2l7v4ZQ5nQ7sUs+v5vU0YF8f0A8W5k4C2Q4k=",
  "pub_sig_b64": "Ykq0cB4B6tM0sR1g6Wg4fR7j2l4A6H8w2N9Y0m1x2zQ=",
  "meta": {
    "entra_agent_id": "8c9a7f8e-3a64-4c4b-a5d3-9c8b6d0e1234",
    "tenant_id": "contoso-eu-prod"
  },
  "sig": "<base64 Ed25519 signature over canonical public core>",
  "v": "id.v1"
}
```

This example is illustrative. The key values and signature are placeholders.


## Appendix B) Final interpretation

Aurora’s current identity model is intentionally compact:

This closing summary restates the model in its simplest form so that the reader
can leave the document with one clear mental picture rather than a scattered
memory of schemas and algorithms.

- one X25519 public key,
- one Ed25519 public key,
- one creation timestamp,
- optional signed metadata,
- one self-signature,
- one version tag.

That signed object is the portable agent identity.

If an application needs directory or enterprise identifiers, those belong in
`meta` as signed claims attached to the same cryptographic principal.
