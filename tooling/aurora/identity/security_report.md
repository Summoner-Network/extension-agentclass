# SummonerIdentity Security Report (Detailed + Examples)

This report is the security companion for the implemented aurora identity stack in:

- `tooling/aurora/identity/identity.py`
- `tooling/aurora/identity/readme.md`
- `tooling/aurora/identity/cheatsheet.md`
- `tooling/aurora/identity/diagrams.md`

It explains how the protocol works end‑to‑end, what is authenticated/encrypted, what attacks are prevented, what remains, and how to mitigate remaining risks. It also reflects the implemented policy-event API (`on_policy_event(...)`) used for security telemetry and operational response. **Every section includes concrete examples** using payload snippets and/or the SDK.

Async note:
- `id(...)` is synchronous (typically called once at startup).
- Messaging/session lifecycle methods are async; example snippets assume async context and use `await`.
- Custom hooks and `on_policy_event` handlers can be sync or async; async handlers are awaited.
- Snippet convention: blocks that include `await` start with `# inside an async function / handler` for readability.

Integration note:
- Most policy examples use class-level decorators for brevity.
- If you are reading this document for protocol/security understanding, you can ignore customization details on a first pass.
- Snippets that import `identity as identity_sdk` are intentionally using low-level helpers/constants for white-box security demonstrations.

## Contents

1. Threat Model and Scope
2. Protocol Walkthrough (Step‑by‑Step)
3. Cryptographic Construction (What binds to what)
4. Security Properties Achieved
5. Attacks Prevented (with reasoning)
6. Attacks Still Possible (Native Perspective, with concrete abuse paths)
7. Mitigations and Design Extensions
8. Threat Table (Quick Reference)
9. Registry and Reputation Guide (Telemetry-Driven)
10. Streaming Security Addendum

## 1) Threat Model and Scope

### In‑scope threats

1. Passive eavesdroppers observing traffic.
2. Active network attackers who can replay, reorder, or tamper with messages.
3. Malicious peers who try to forge messages or impersonate others.
4. Storage corruption or accidental key mismatch.

**Example (tamper in transit)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
import copy
import os
import tempfile

# 1) Create identities for Alice and Bob.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Alice starts a session and seals a message to Bob.
s0 = await alice.start_session(pub_b)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 3) Attacker flips a byte inside ciphertext.
tampered = copy.deepcopy(env)
ct = tampered["payload"]["ciphertext"]
tampered["payload"]["ciphertext"] = ("A" if ct[0] != "A" else "B") + ct[1:]

# 4) Bob rejects due to signature/AES-GCM integrity failure.
assert await bob.open_envelope(tampered) is None
```

### Out‑of‑scope threats

1. Full compromise of the local host where private keys reside.
2. Physical or side‑channel attacks on cryptographic primitives.
3. Full PKI or organizational identity verification (not provided by design).

**Example (out‑of‑scope)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Alice creates an identity file (contains private keys).
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")

# 2) Attacker steals alice.json and loads it as "Alice".
attacker = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
stolen_pub = attacker.id(os.path.join(tmp.name, "alice.json"))

# 3) Attacker can now produce valid signatures as Alice.
# This is out-of-scope because the private key is compromised.
assert stolen_pub["pub_sig_b64"] == pub_a["pub_sig_b64"]
```

### Assumptions

1. `cryptography` primitives are correct and safe.
2. RNG (`os.urandom`, `secrets.token_hex`) is secure.
3. Private keys are stored securely (encrypted or OS‑protected).
4. System clocks are not grossly wrong (clock skew bounds enforced if configured).

**Example (clock skew)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(max_clock_skew_seconds=30, store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Simulate Alice's clock being 5 minutes ahead when creating the session.
real_now = identity_sdk._now_unix
try:
    identity_sdk._now_unix = lambda: real_now() + 300
    s0 = await alice.start_session(pub_b)
    env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
finally:
    identity_sdk._now_unix = real_now

# 3) Bob rejects because the session timestamp is too far in the future.
assert await bob.open_envelope(env) is None
```

## 2) Protocol Walkthrough (Step‑by‑Step)

This walkthrough tracks **who does what**, **what is sent**, **what travels**,
and **what is received** across the full protocol flow.

For production readiness before using this flow end-to-end:

1. Encrypt identity files in production (`password` + scrypt).
2. Choose `ttl` and `margin` values that match real network latency.
3. Choose your reset handling policy for start-form replacements.
4. Decide whether forward secrecy is a requirement for your deployment.

**Example**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

# Example production-oriented envelope defaults.
identity = SummonerIdentity(ttl=300, margin=10, max_clock_skew_seconds=30)
```

### 2.1 Identity creation and storage

**Who:** Local party.

**What happens:**

1. Generate a static X25519 key pair (key agreement).
2. Generate a static Ed25519 key pair (signing).
3. Construct a public identity record with:
   - `created_at`
   - `pub_enc_b64` (X25519 public)
   - `pub_sig_b64` (Ed25519 public)
   - `meta` (optional)
4. Self‑sign the public record (`sig`).
5. Store identity JSON locally (plaintext for dev or encrypted with scrypt + AES‑GCM).

**Notes on `meta`:**
- `meta` is optional and signed (integrity‑protected).
- It is **not** authoritative identity; trust decisions should use the signing key.
- Persistent changes use `update_id_meta(...)`.
- `seal_envelope(..., id_meta=...)` only changes in‑memory identity for that process.

**What travels:**

- Only the signed **public identity record** is shared with peers or registries.

**Example (SDK)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create a local SummonerIdentity and identity file (encrypted).
tmp = tempfile.TemporaryDirectory()
identity = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
public_id = identity.id(os.path.join(tmp.name, "alice.json"), meta="alice", password=b"secret")

# 2) Share only the public record with peers/registries.
assert "priv_enc_b64" not in public_id
assert "priv_sig_b64" not in public_id
```

### 2.2 Session start (initiator, `sender_role = 0`)

**Who:** The party initiating a conversation.

**What happens:**

1. Call `start_session(peer_public_id)` (or `start_session(None)` for public `to=None`).
2. Create a **start‑form `session_proof`**:
   - `sender_role = 0`
   - `0_nonce` fresh
   - `1_nonce = null`
   - `ts` (unix seconds)
   - `ttl` (seconds)
   - `history_proof` (if peer is provided; carries finalized-tip continuity or reset/bootstrap state)
   - `age` (local history counter)
3. Store it under `(peer_id, local_role=0)` or a generic slot for public messages.

**Important convention for `to=None`:**
- The generic slot is shared across senders, so it is **discovery-only**.
- A `to=None` session does **not** establish per‑peer continuity.
- To reply to a discovery message, start a new per‑peer session with
  `start_session(peer_public_id)` and then send `to=peer_public_id`.
- Discovery helper note:
  - `list_known_peers()` / `find_peer(text)` read fallback peer cache and are best
    treated as discovery helpers.
  - `list_verified_peers()` is the safer selector for conversation candidates after
    successful `open_envelope(...)` / `verify_discovery_envelope(...)`.
  - With custom `_peer_key_store_handler`, keep `self._peer_keys` synchronized (or provide
    custom query endpoints) if you require authoritative discovery results.
- For a non-Python discovery server (for example Rust), apply the same security boundary:
  accept `to=None` as signed public ingress, update server presence state from `from`
  (for example `online_agent_ids.add(from)`), and respond with a per-peer encrypted
  envelope (`to=from`) carrying the current online set. This avoids multi-sender
  continuity collisions on any generic slot model.

**What travels:**

- The `session_proof` is embedded in the envelope.

**Example (SDK)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities for Alice and Bob.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Alice initiates a session toward Bob (sender_role=0, 0_nonce present).
s0 = await alice.start_session(pub_b)
assert s0["sender_role"] == 0
assert s0["0_nonce"] is not None and s0["1_nonce"] is None
```

### 2.3 Seal envelope (send)

**Who:** Sender.

**What happens:**

1. Validate that the provided `session_proof` matches the local `current_link`.
2. If `to` is present:
   - Derive `sym_key` using X25519 + HKDF.
   - Derive payload AEAD key bound to AAD (direction + session fields).
   - Encrypt payload with AES‑GCM.
3. Build envelope core:
   - `payload`, `session_proof`, `from`, `to`, `v`.
4. Sign envelope core with Ed25519.

**Meta behavior**
- If `id_meta` is provided to `seal_envelope`, the sender re‑signs its in‑memory public identity with that meta for this envelope only.
- This does **not** write to disk (use `update_id_meta` to persist).

**What travels:**

- Always: `from`, `session_proof`, `sig`.
- If `to` present: encrypted `payload`.
- If `to` absent: plaintext payload, still covered by the signature.

**Example (SDK)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities and a start session.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
s0 = await alice.start_session(pub_b)

# 2) Seal an encrypted envelope to Bob.
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
assert env["to"]["pub_sig_b64"] == pub_b["pub_sig_b64"]
assert "ciphertext" in env["payload"]
```

### 2.4 Open envelope (receive)

**Who:** Receiver.

**What happens:**

1. Validate structure and versions.
2. Verify sender identity record is self‑signed.
3. If `to` present, ensure it matches local identity.
4. Enforce time checks (created_at and max clock skew if configured).
5. Verify envelope signature over canonical envelope core.
6. Record peer identity in the fingerprint‑indexed cache.
7. Validate `session_proof` with nonce‑chain rules.
8. Decrypt payload if encrypted.
9. Replay cache check and store (optional).
10. Update local session state (current_link, history, completion flags) and
    promote the sender to a verified peer on successful trust-bearing open.

**What is received:**

- Verified payload value, or `None` on any failure.
- If your protocol allows `None` payloads, use `return_status=True` to disambiguate success from failure.

**Example (SDK)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Alice sends a message to Bob.
s0 = await alice.start_session(pub_b)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 3) Bob opens and verifies the envelope.
payload = await bob.open_envelope(env)
assert payload == {"msg": "hi"}
```

### 2.5 Continue session (responder)

**Who:** Receiver replying to a message.

**What happens:**

1. Call `continue_session(peer_public_id, peer_session_proof)`.
2. Validate peer proof equals local `current_link`.
3. Generate new nonce for own role.
4. Return new `session_proof` for reply.
5. Emit `age = null` on the non-start wire record while preserving the local
   continuity age in active session storage.

**Example (SDK)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Alice starts and sends.
s0 = await alice.start_session(pub_b)
env1 = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
assert await bob.open_envelope(env1) == {"msg": "hi"}

# 3) Bob continues the session and replies.
s1 = await bob.continue_session(pub_a, env1["session_proof"])
env2 = await bob.seal_envelope({"msg": "ack"}, s1, to=pub_a)
assert await alice.open_envelope(env2) == {"msg": "ack"}
```

### 2.6 End session

There is **no explicit close message**. Sessions end when:

1. `ttl` expires, or
2. A new valid start‑form is accepted and replaces the current session.

Sender-side lifecycle note:
- `start_session(peer)` now enforces one active role-0 session per peer.
- If a live uncompleted link exists, caller must wait for completion or use `force_reset=True`.
- Link liveness is stream-aware: an active stream remains live on its stream-progress
  window rather than only on the original requester-window `ttl`.

**Example (implicit end)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities with short TTL.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(ttl=1, store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(ttl=1, store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Alice starts session and sends a message.
s0 = await alice.start_session(pub_b, ttl=1)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 3) Simulate time passing so TTL expires before Bob opens.
real_now = identity_sdk._now_unix
try:
    identity_sdk._now_unix = lambda: real_now() + 2
    assert await bob.open_envelope(env) is None
finally:
    identity_sdk._now_unix = real_now

# 4) A fresh start_session establishes a new chain.
#    Because Alice still has an active uncompleted link, this requires explicit reset.
s1 = await alice.start_session(pub_b, force_reset=True)
assert s1["0_nonce"] != s0["0_nonce"]
```

## 3) Cryptographic Construction (What binds to what)

### 3.1 Identity signature

- Public identity record is self‑signed with Ed25519.
- Any change to `pub_enc_b64`, `pub_sig_b64`, `created_at`, or `meta` breaks the signature.
- This guarantees integrity of `meta`, but not its real‑world meaning.

**Example (tamper)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create a valid public identity.
tmp = tempfile.TemporaryDirectory()
identity = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
public_id = identity.id(os.path.join(tmp.name, "alice.json"), meta="alice")

# 2) Tamper with a signed field.
pub = dict(public_id)
pub["pub_enc_b64"] = "A" + pub["pub_enc_b64"][1:]

# 3) Verification fails.
try:
    identity_sdk.verify_public_id(pub)
    assert False, "tampered public id should fail verification"
except Exception:
    pass
```

### 3.2 Envelope signature

- The envelope signature covers canonical JSON of:
  - `payload`, `session_proof`, `from`, `to`, `v`.
- Any change to payload, session fields, or identity records invalidates the signature.

**Example (tamper)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import copy
import os
import tempfile

# 1) Create identities and a valid envelope.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
s0 = await alice.start_session(pub_b)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 2) Tamper with session_proof after signing.
tampered = copy.deepcopy(env)
tampered["session_proof"]["ttl"] += 1

# 3) Bob rejects because signature no longer matches.
assert await bob.open_envelope(tampered) is None
```

### 3.3 Payload encryption

- AES‑GCM key is derived from X25519 shared secret + HKDF.
- HKDF salt binds:
  - sender/receiver identities
  - session fields (`sender_role`, nonces, `ts`, `ttl`).
- AAD binds the direction and timing to prevent replay across directions or sessions.

**Example (directional AAD)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Alice sends encrypted payload to Bob.
s0 = await alice.start_session(pub_b)
env_a_to_b = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 3) Bob (malicious) reuses Alice's ciphertext in a B->A envelope.
s1 = await bob.continue_session(pub_a, env_a_to_b["session_proof"])
core = {
    "v": identity_sdk.ENV_VERSION,
    "payload": env_a_to_b["payload"],  # ciphertext from A->B
    "session_proof": s1,
    "from": pub_b,
    "to": pub_a,
}
sig = identity_sdk.sign_bytes(bob._priv_sig, identity_sdk._canon_json_bytes(core))  # internal access for demo
env_b_to_a = dict(core)
env_b_to_a["sig"] = sig

# 4) Alice rejects because AAD binds direction (B->A != A->B).
assert await alice.open_envelope(env_b_to_a) is None
```

### 3.4 History proof

- `history_proof` is AEAD‑encrypted with a key derived from `sym_key` + AAD.
- AAD binds identity direction + session timing fields.
- Proof plaintext binds a rolling `history_hash` to the new session.

**Example (continuity failure)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import copy
import os
import tempfile

# 1) Create identities.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Complete one full exchange to create history on Alice's side.
s0 = await alice.start_session(pub_b)
env1 = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
assert await bob.open_envelope(env1) == {"msg": "hi"}
s1 = await bob.continue_session(pub_a, env1["session_proof"])
env2 = await bob.seal_envelope({"msg": "ack"}, s1, to=pub_a)
assert await alice.open_envelope(env2) == {"msg": "ack"}

# 3) Alice starts a new session with history_proof.
s2 = await alice.start_session(pub_b)
assert s2["history_proof"] is not None

# 4) Attacker tampers with history_proof ciphertext.
bad = copy.deepcopy(s2)
bad["history_proof"]["ciphertext"] = "A" + bad["history_proof"]["ciphertext"][1:]

# 5) Bob rejects because history_proof decryption fails.
env3 = await alice.seal_envelope({"msg": "new"}, bad, to=pub_b)
assert await bob.open_envelope(env3) is None
```

## 4) Security Properties Achieved

### 4.1 Message integrity and authenticity

- Only the signing key holder can produce a valid envelope signature.
- This includes any `meta` carried inside the sender's public identity record.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import copy
import os
import tempfile

# 1) Create identities and a valid envelope.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
s0 = await alice.start_session(pub_b)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 2) Attacker modifies the payload after signing.
tampered = copy.deepcopy(env)
tampered["payload"]["ciphertext"] = "A" + tampered["payload"]["ciphertext"][1:]

# 3) Bob rejects because the signature/AES-GCM integrity fails.
assert await bob.open_envelope(tampered) is None
```

### 4.2 Optional confidentiality

- Payload is confidential if `to` is present and keys remain private.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) to=pub_b -> encrypted payload.
s0 = await alice.start_session(pub_b)
env_enc = await alice.seal_envelope({"msg": "secret"}, s0, to=pub_b)
assert "ciphertext" in env_enc["payload"]

# 3) to=None -> plaintext payload (still signed).
s1 = await alice.start_session(None)
env_plain = await alice.seal_envelope({"msg": "public"}, s1, to=None)
assert env_plain["payload"] == {"msg": "public"}
```

Note:
- `to=None` uses the generic session slot and is intended for discovery/broadcast only.
- It does not establish per‑peer continuity; reply with a new per‑peer session.

### 4.3 Replay resistance (session scoped)

- Nonce‑chain rules enforce continuity and freshness.
- `seen` list blocks replay within the current conversation.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities and send a message.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
s0 = await alice.start_session(pub_b)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 2) First open succeeds.
assert await bob.open_envelope(env) == {"msg": "hi"}

# 3) Replay of the same envelope is rejected.
assert await bob.open_envelope(env) is None
```

### 4.4 Continuity across sessions

- `history_proof` binds prior history to the start of a new session.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create identities.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Complete one exchange to seed history.
s0 = await alice.start_session(pub_b)
env1 = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
assert await bob.open_envelope(env1) == {"msg": "hi"}
s1 = await bob.continue_session(pub_a, env1["session_proof"])
env2 = await bob.seal_envelope({"msg": "ack"}, s1, to=pub_a)
assert await alice.open_envelope(env2) == {"msg": "ack"}

# 3) New session includes history_proof.
s2 = await alice.start_session(pub_b)
assert isinstance(s2.get("history_proof"), dict)
```

### 4.5 Peer identity cache (fingerprint‑keyed)

- `peer_keys.json` is keyed by the signing‑key fingerprint.
- `meta` is metadata only.

Use case split:
- The first snippet is an in-memory logic demo (`persist_local=False`, `load_local=False`).
  It isolates fingerprint behavior without introducing disk I/O.
- The second snippet is a persistence lifecycle demo (`persist_local=True`, `load_local=True`).
  It shows how `open_envelope()` updates peer cache/verification state and how a new
  process reloads it via `id(...)`.

**Example A: in-memory fingerprint behavior**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Bob receives identities and caches them by fingerprint.
tmp = tempfile.TemporaryDirectory()
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Alice (legit) sends first message; Bob caches her fingerprint.
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
s0 = await alice.start_session(pub_b)
env1 = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
assert await bob.open_envelope(env1) == {"msg": "hi"}

# 3) Attacker creates a different key but reuses the same meta label "alice".
tmp2 = tempfile.TemporaryDirectory()
attacker = SummonerIdentity(store_dir=tmp2.name, persist_local=False, load_local=False)
fake_pub_a = attacker.id(os.path.join(tmp2.name, "alice.json"), meta="alice")
s1 = await attacker.start_session(pub_b)
env2 = await attacker.seal_envelope({"msg": "evil"}, s1, to=pub_b)

# 4) Bob still verifies signatures, but sees a new fingerprint (new identity).
assert await bob.open_envelope(env2) == {"msg": "evil"}
assert identity_sdk.id_fingerprint(fake_pub_a["pub_sig_b64"]) != identity_sdk.id_fingerprint(pub_a["pub_sig_b64"])
```

**Example B: persisted cache lifecycle with attacker (load on `id`, update on `open_envelope`)**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

tmp = tempfile.TemporaryDirectory()

# 1) Process A: create Bob/Alice with local persistence enabled.
bob = SummonerIdentity(store_dir=tmp.name, persist_local=True, load_local=True)
alice = SummonerIdentity(store_dir=tmp.name, persist_local=True, load_local=True)
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")

# 2) Alice sends one message to Bob (cache update via open_envelope).
s0 = await alice.start_session(pub_b)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
assert await bob.open_envelope(env) == {"msg": "hi"}

# 3) Attacker uses different keys but same meta label and sends to Bob.
#    (Persistence is not needed on attacker side for this demo.)
tmp2 = tempfile.TemporaryDirectory()
attacker = SummonerIdentity(store_dir=tmp2.name, persist_local=False, load_local=False)
fake_pub_a = attacker.id(os.path.join(tmp2.name, "alice.json"), meta="alice")
s1 = await attacker.start_session(pub_b)
env_bad = await attacker.seal_envelope({"msg": "evil"}, s1, to=pub_b)
assert await bob.open_envelope(env_bad) == {"msg": "evil"}

# 4) Process B: new Bob instance reloads persisted fallback stores when id(...) is called.
bob_reloaded = SummonerIdentity(store_dir=tmp.name, persist_local=True, load_local=True)
bob_reloaded.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 5) Bob reloads and searches for "alice": two matches remain visible.
hits = bob_reloaded.find_peer("alice")
assert len(hits) >= 2
assert any(p.get("pub_sig_b64") == pub_a["pub_sig_b64"] for p in hits)
assert any(p.get("pub_sig_b64") == fake_pub_a["pub_sig_b64"] for p in hits)
assert identity_sdk.id_fingerprint(fake_pub_a["pub_sig_b64"]) != identity_sdk.id_fingerprint(pub_a["pub_sig_b64"])
```

Best-practice resolution in real UX:
- Treat `find_peer("alice")` as discovery only, not as trust.
- Resolve ambiguity by pinning fingerprint (`id_fingerprint(pub_sig_b64)`) or using a trusted directory.
- Once trust-bearing verification succeeds, prefer `list_verified_peers()` when
  selecting peers for conversation workflows.
- After Bob selects one identity, session continuity and encryption bind replies to that selected keypair.
- If attacker and real Alice each have their own session with Bob, Bob's replies stay scoped to each session; data intended for real Alice is not decryptable by attacker.

## 5) Attacks Prevented (with reasoning)

1. **Payload tampering**
   - Signature covers payload and session proof.

   **Example**
   ```python
# inside an async function / handler
   from tooling.aurora import SummonerIdentity
   from tooling.aurora.identity import identity as identity_sdk
   import copy
   import os
   import tempfile

   # 1) Create identities and a valid envelope.
   tmp = tempfile.TemporaryDirectory()
   alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
   pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
   s0 = await alice.start_session(pub_b)
   env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

   # 2) Attacker swaps ciphertext or payload.
   tampered = copy.deepcopy(env)
   tampered["payload"]["ciphertext"] = "A" + tampered["payload"]["ciphertext"][1:]

   # 3) Bob rejects.
   assert await bob.open_envelope(tampered) is None
   ```

2. **Message forgery**
   - Requires Ed25519 private key.

   **Example**
   ```python
   from tooling.aurora import SummonerIdentity
   from tooling.aurora.identity import identity as identity_sdk
   import os
   import tempfile

   # 1) Create identities for Alice (victim) and Mallory (attacker).
   tmp = tempfile.TemporaryDirectory()
   alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   mallory = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
   pub_m = mallory.id(os.path.join(tmp.name, "mallory.json"), meta="mallory")

   # 2) Mallory crafts an envelope that claims to be from Alice but signs with Mallory's key.
   s0 = await mallory.start_session(pub_a)
   core = {
       "v": identity_sdk.ENV_VERSION,
       "payload": {"msg": "forged"},
       "session_proof": s0,
       "from": pub_a,   # claim Alice
       "to": None,
   }
   sig = identity_sdk.sign_bytes(mallory._priv_sig, identity_sdk._canon_json_bytes(core))  # wrong key
   forged = dict(core)
   forged["sig"] = sig

   # 3) Alice (or any verifier) rejects because signature doesn't match Alice's pub_sig_b64.
   assert await alice.open_envelope(forged) is None
   ```

3. **Identity record tampering**
   - Identity record is self‑signed.

   **Example**
   ```python
   from tooling.aurora import SummonerIdentity
   from tooling.aurora.identity import identity as identity_sdk
   import os
   import tempfile

   # 1) Create a valid identity.
   tmp = tempfile.TemporaryDirectory()
   identity = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   public_id = identity.id(os.path.join(tmp.name, "alice.json"), meta="alice")

   # 2) Remove a required field or alter it.
   bad = dict(public_id)
   del bad["pub_sig_b64"]

   # 3) Verification fails.
   try:
       identity_sdk.verify_public_id(bad)
       assert False, "invalid identity should fail"
   except Exception:
       pass
   ```

4. **Replay inside an active session**
   - Nonce freshness + `seen` list.

   **Example**
   ```python
   from tooling.aurora import SummonerIdentity
   from tooling.aurora.identity import identity as identity_sdk
   import os
   import tempfile

   # 1) Create identities and a valid envelope.
   tmp = tempfile.TemporaryDirectory()
   alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
   pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
   s0 = await alice.start_session(pub_b)
   env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

   # 2) First open succeeds; replay fails.
   assert await bob.open_envelope(env) == {"msg": "hi"}
   assert await bob.open_envelope(env) is None
   ```

5. **Cross‑session encrypted blob reuse**
   - AAD binds identity direction and session timing.

   **Example**
   ```python
   from tooling.aurora import SummonerIdentity
   from tooling.aurora.identity import identity as identity_sdk
   import os
   import tempfile

   # 1) Create identities.
   tmp = tempfile.TemporaryDirectory()
   alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
   pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
   pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

   # 2) Alice sends a ciphertext in session A.
   s0 = await alice.start_session(pub_b)
   env_a = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

   # 3) Alice starts a new session B and (maliciously) reuses old ciphertext.
   s1 = await alice.start_session(pub_b, force_reset=True)
   core = {
       "v": identity_sdk.ENV_VERSION,
       "payload": env_a["payload"],  # ciphertext from session A
       "session_proof": s1,
       "from": pub_a,
       "to": pub_b,
   }
   sig = identity_sdk.sign_bytes(alice._priv_sig, identity_sdk._canon_json_bytes(core))  # internal access for demo
   env_reuse = dict(core)
   env_reuse["sig"] = sig

   # 4) Bob rejects because AAD binds to session A, not session B.
   assert await bob.open_envelope(env_reuse) is None
   ```

## 6) Attacks Still Possible (Native Perspective, with concrete abuse paths)

The remaining attack surface in this section is limited to native protocol
exposure. Section 7 contains the corresponding mitigation playbooks, with one
dedicated subsection per attack class (`6.1` through `6.6`).

### 6.1 Real‑world identity impersonation

**Abuse path:**

- Attacker creates their own identity and claims to be “Alice.”
- Self‑signature is valid but not tied to a real‑world identity.

**Example**
```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Attacker creates a fresh identity but uses meta "Alice".
tmp = tempfile.TemporaryDirectory()
attacker = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
fake_pub = attacker.id(os.path.join(tmp.name, "alice.json"), meta="Alice (fake)")

# 2) The public record is self-signed and verifies.
identity_sdk.verify_public_id(fake_pub)

# 3) But there is no real-world binding; it only proves internal consistency.
```

### 6.2 Lack of forward secrecy

**Abuse path:**

- Attacker records traffic now and steals static X25519 key later.
- Past ciphertexts become decryptable.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Alice sends an encrypted message to Bob.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
s0 = await alice.start_session(pub_b)
env = await alice.seal_envelope({"msg": "secret"}, s0, to=pub_b)

# 2) Later, attacker steals Bob's identity file and can decrypt old ciphertexts.
attacker = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
attacker.id(os.path.join(tmp.name, "bob.json"))  # stolen private keys
assert await attacker.open_envelope(env) == {"msg": "secret"}
```

### 6.3 Reset abuse

**Abuse path:**

- Attacker spams valid start‑form messages.
- Receiver accepts reset, discarding ongoing continuity.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Attacker repeatedly starts new sessions toward Bob.
tmp = tempfile.TemporaryDirectory()
attacker = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_attacker = attacker.id(os.path.join(tmp.name, "attacker.json"), meta="attacker")
pub_bob = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Bob will accept each valid start-form. Attacker uses force_reset to keep
#    opening fresh local starts without waiting for completion.
for _ in range(3):
    s0 = await attacker.start_session(pub_bob, force_reset=True)
    env = await attacker.seal_envelope({"msg": "reset"}, s0, to=pub_bob)
    assert await bob.open_envelope(env) == {"msg": "reset"}
```

### 6.4 Concurrency / out‑of‑order messages (availability risk, not crypto break)

**Abuse path:**

- Two messages sent in parallel can violate strict nonce-chain sequencing.
- Receiver rejects one or both messages to preserve continuity invariants.
- This is not a signature/encryption bypass; it is a liveness/UX issue that an
  attacker can amplify (for example by intentional reordering or flooding).

**Remark:** This remains in "still possible" because, while fail-closed continuity checks preserve integrity/authenticity, parallel and reordered delivery can still create availability loss without explicit application-level ordering controls.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Alice sends one message to Bob.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
s0 = await alice.start_session(pub_b)
env1 = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)
assert await bob.open_envelope(env1) == {"msg": "hi"}

# 2) Bob replies twice using the same session proof (concurrent replies).
s1 = await bob.continue_session(pub_a, env1["session_proof"])
env2 = await bob.seal_envelope({"msg": "ack-1"}, s1, to=pub_a)
env3 = await bob.seal_envelope({"msg": "ack-2"}, s1, to=pub_a)

# 3) Alice accepts the first, but the second is rejected.
#    Security property: fail-closed continuity is preserved.
#    Operational tradeoff: one concurrent reply is dropped.
assert await alice.open_envelope(env2) == {"msg": "ack-1"}
assert await alice.open_envelope(env3) is None
```

### 6.5 Replay across long time windows (configuration-dependent residual risk)

**Abuse path:**

- Replay protections exist (`seen` + message-id replay cache), but acceptance windows
  can still be long if TTL is large and replay state is not persisted across restarts.
- If a process restarts with `persist_replay=False`, replayed envelopes may
  be accepted again while still inside TTL/clock-skew bounds.

**Remark:** This remains in "still possible" because, although nonce-chain and replay-cache protections are present, replay acceptance risk can still persist when runtime policy is permissive (for example long TTL windows or non-durable replay state).

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Alice sends a message with long TTL.
tmp = tempfile.TemporaryDirectory()
alice = SummonerIdentity(ttl=86400, store_dir=tmp.name, persist_local=False, load_local=False)
bob = SummonerIdentity(ttl=86400, store_dir=tmp.name, persist_local=False, load_local=False)
pub_a = alice.id(os.path.join(tmp.name, "alice.json"), meta="alice")
pub_b = bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")
s0 = await alice.start_session(pub_b, ttl=86400)
env = await alice.seal_envelope({"msg": "hi"}, s0, to=pub_b)

# 2) Bob accepts once, then process restarts and loses replay cache.
assert await bob.open_envelope(env) == {"msg": "hi"}
bob = SummonerIdentity(ttl=86400, store_dir=tmp.name, persist_local=False, load_local=False)
bob.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 3) Replay within TTL may be accepted because in-memory replay state was lost.
assert await bob.open_envelope(env) == {"msg": "hi"}
```

### 6.6 DoS via invalid envelopes

**Abuse path:**

- Attacker sends many malformed envelopes.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

# 1) Create a receiver.
tmp = tempfile.TemporaryDirectory()
receiver = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
receiver.id(os.path.join(tmp.name, "bob.json"), meta="bob")

# 2) Malformed envelopes still trigger parsing/verification work.
bad_env = {"v": identity_sdk.ENV_VERSION, "from": {}, "to": {}, "session_proof": {}, "payload": {}, "sig": "x"}
for _ in range(1000):
    await receiver.open_envelope(bad_env)
```

## 7) Mitigations and Design Extensions

Section 7 is organized as attack-specific mitigation playbooks (`7.1` to `7.6`). The protocol is intentionally fail-closed but not all risks are natively eliminated, so mitigations combine:

1. native policy controls (verification rules, TTL/skew settings, replay persistence),
2. transport/operational controls (rate limits, admission, isolation, incident response),
3. telemetry-driven enforcement (per-peer counters, dynamic throttles, quarantine decisions).

Design constraints that matter for mitigation planning:

1. **No forward secrecy by default (static X25519)**: optimize continuity/identity stability, not retroactive secrecy.
2. **No real-world identity binding by default**: self-signatures prove key ownership, not external identity.
3. **Strict nonce-chain ordering**: preserves integrity but can reduce liveness under concurrency/reordering.
4. **Protocol-layer DoS cost remains**: signature/decrypt/verification work is still non-trivial.

Telemetry baseline used across all subsections:

- Register per-instance handlers with `on_policy_event(phase=...)`.
- `event_name == code`; common context includes `schema_version`, `ts`, `phase`, `ok`, `code`, `has_data`.
- `open_envelope` provides high-value optional fields:
  - `peer_fingerprint`, `session_form`, `sender_role`, `local_role`,
  - `replaced_active_incomplete` (committed `ok` only),
  - `validation_stage` on failures,
  - `replay_store_mode` and `persist_replay` on `replay_detected`.

Detailed telemetry field reference and signal-to-action tables are provided in Section 9 ("Registry and Reputation Guide"), so Section 7 stays focused on threat-specific mitigation strategy.

Implementation note: examples below use public default delegates such as `identity.verify_session_default(...)`, `identity.register_session_default(...)`, `identity.get_session_default(...)`, `identity.reset_session_default(...)`, `identity.peer_key_store_default(...)`, and `identity.replay_store_default(...)` so custom handlers can extend baseline behavior without relying on private method names.

### 7.1 Mitigations for 6.1 Real‑world identity impersonation

Goal: prevent trust decisions based on self-asserted labels (`meta`) and enforce key ownership trust.

Controls (strongest first):

1. Hard pin peer fingerprints to expected identities (allowlist mode).
2. Require registry-backed trust state before enabling privileged actions.
3. Use TOFU only for low-risk workflows and require explicit operator confirmation on first-seen keys.
4. Treat key rotation as identity change unless externally attested.
5. Separate "can message me" from "can execute high-impact action" permissions.

Telemetry and response:

- Alert on first-seen `peer_fingerprint` attempting privileged operation.
- Alert on abrupt fingerprint churn for the same business identity label.
- Quarantine unknown fingerprints pending attestation.

**Example**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
allowlist = {"trusted_fp_1", "trusted_fp_2"}
failed_unknown = {}
blocked = set()

@SummonerIdentity.verify_session
def verify_allowlisted_peer(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if fp in blocked or fp not in allowlist:
            return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def detect_unknown_peer(event_name, ctx):
    if event_name != "session_verify_failed":
        return
    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return
    failed_unknown[fp] = failed_unknown.get(fp, 0) + 1
    if failed_unknown[fp] >= 3:
        blocked.add(fp)  # telemetry -> verify_session enforcement path
```

### 7.2 Mitigations for 6.2 Lack of forward secrecy

Goal: reduce blast radius of long-term key compromise.

Controls:

1. Add ephemeral X25519 key agreement per session (or per message) and mix into HKDF.
2. Rotate long-term identity keys on a fixed schedule and on incident triggers.
3. Shorten session TTL to reduce useful lifetime of captured traffic keys.
4. Encrypt identity files at rest and enforce secret management controls (KMS/HSM where possible).
5. Use process isolation and least privilege for components holding private keys.

Telemetry and response:

- Alert on abnormal decryption behavior or key-load events outside expected hosts.
- On compromise: immediate fingerprint revocation + key rollover + channel re-establishment.

**Example**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity(ttl=300, max_clock_skew_seconds=30)
suspicion = {}
quarantined = set()

@SummonerIdentity.verify_session
def verify_ttl_cap(peer_public_id, local_role, session_record, use_margin=False):
    if int(session_record.get("ttl", 0)) > 300:
        return False
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if fp in quarantined:
            return False  # telemetry-driven quarantine
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def detect_key_compromise_signals(event_name, ctx):
    if event_name not in ("payload_decrypt_failed", "peer_key_check_failed"):
        return
    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return
    suspicion[fp] = suspicion.get(fp, 0) + 1
    if suspicion[fp] >= 3:
        quarantined.add(fp)

# Future hardening (v2): add ephemeral X25519 to session_proof and HKDF mix.
```

### 7.3 Mitigations for 6.3 Reset abuse

Goal: prevent adversaries from repeatedly forcing new start-form continuity windows.

Controls:

1. Enforce strict start-form replacement policy in `verify_session`:
   - reject replacement while active incomplete link is live,
   - allow replacement only after expiry or explicit authorization.
2. Require signed reset authorization tokens for non-expiry resets.
3. Apply per-peer reset rate limits and temporary lockouts.
4. Gate high-impact operations behind continuity age or minimum successful exchange depth.
5. Keep replay state durable (`persist_replay=True`) where restart replay pressure is relevant.

Telemetry and response:

- Track accepted replacements via `event_name="ok"` + `replaced_active_incomplete=True`.
- Track failed reset attempts via `session_verify_failed` with `session_form="start"`.
- Trigger dynamic controls (throttles/deny) on per-fingerprint reset pressure.

**Example**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
reset_pressure = {}
blocked = set()

@SummonerIdentity.verify_session
def strict_verify(peer_public_id, local_role, session_record, use_margin=False):
    fp = None
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
    if isinstance(fp, str) and fp in blocked:
        return False

    current = identity.get_session_default(peer_public_id, local_role)
    if current and not identity._is_stale_current_link(current, use_margin=use_margin):
        cls = identity.classify_session_record(session_record)
        if cls.get("is_start_form"):
            return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def monitor_resets(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return
    if event_name == "ok" and ctx.get("replaced_active_incomplete") is True:
        reset_pressure[fp] = reset_pressure.get(fp, 0) + 1
    if reset_pressure.get(fp, 0) > 5:
        blocked.add(fp)  # telemetry -> verify_session deny path
```

### 7.4 Mitigations for 6.4 Concurrency / out-of-order availability risk

Goal: preserve liveness under parallel and reordered traffic without weakening integrity checks.

Controls:

1. Allocate separate sessions/channels for independent concurrent flows.
2. Introduce sender-side sequencing queues per `(peer_fingerprint, flow_id)`.
3. Use idempotency keys at application layer for retry-safe operations.
4. Classify drops as expected sequencing failures vs malicious churn.
5. Avoid "auto-relaxing" continuity checks; preserve fail-closed integrity.

Telemetry and response:

- Track `session_verify_failed` by peer and operation type.
- Track concurrent-send fanout and reorder rate at transport layer.

**Example**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
violations = {}
serialized_only = set()

@SummonerIdentity.verify_session
def strict_chain(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if fp in serialized_only:
            # If peer is unstable, only accept start-form until pressure clears.
            cls = identity.classify_session_record(session_record)
            if not cls.get("is_start_form"):
                return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def detect_reorder_pressure(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return
    if event_name == "session_verify_failed":
        violations[fp] = violations.get(fp, 0) + 1
        if violations[fp] >= 5:
            serialized_only.add(fp)  # telemetry -> stricter verify policy
    elif event_name == "ok":
        violations[fp] = max(0, violations.get(fp, 0) - 1)
```

### 7.5 Mitigations for 6.5 Replay across long windows

Goal: minimize replay acceptance windows across restarts and long-lived sessions.

Controls:

1. Use short TTL in production and enforce strict clock skew bounds.
2. Enable `persist_replay=True` on long-lived receivers.
3. Protect replay store integrity/availability (durable storage with controlled writes).
4. Keep system clocks synchronized (NTP discipline, skew alerting).
5. Segment high-risk workloads into stricter TTL profiles.

Telemetry and response:

- Track `replay_detected` with `replay_store_mode` and `persist_replay`.
- Differentiate post-restart replay bursts from sustained adversarial replay traffic.

**Example**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity(ttl=300, max_clock_skew_seconds=30, persist_replay=True)
replay_alerts = []
replay_cache = {}
replay_pressure = {}
blocked = set()

@SummonerIdentity.replay_store
def replay_controls(message_id, ttl, now, add):
    # Delegate to default semantics first, then mirror into external cache.
    seen = identity.replay_store_default(message_id, ttl=ttl, now=now, add=add)
    if add:
        replay_cache[message_id] = {"exp": int(now) + int(ttl)}
    return seen

@SummonerIdentity.verify_session
def verify_replay_pressure(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if replay_pressure.get(fp, 0) >= 10 or fp in blocked:
            return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def monitor_replay(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if event_name == "replay_detected" and isinstance(fp, str):
        replay_pressure[fp] = replay_pressure.get(fp, 0) + 1
        replay_alerts.append((fp, ctx.get("replay_store_mode"), ctx.get("persist_replay")))
        if replay_pressure[fp] >= 20:
            blocked.add(fp)
```

### 7.6 Mitigations for 6.6 DoS via invalid envelopes

Goal: shift rejection cost left and bound expensive cryptographic work under hostile traffic.

Controls:

1. Transport-level rate limits, admission control, and connection quotas.
2. Cheap edge validation (required fields/types) before full cryptographic path.
3. Per-fingerprint / per-source throttling and temporary bans.
4. Circuit breakers for high reject-rate conditions.
5. Capacity isolation for high-priority tenants/queues.

Telemetry and response:

- Use `validation_stage` distribution to identify cost hotspots:
  - `structure` spikes: malformed flood, tighten edge schema gates,
  - `signature`/`decrypt` spikes: crypto-garbage pressure, increase pre-crypto throttles,
  - `commit` spikes: inspect state store or custom controls health.

**Example**

```python
from collections import Counter

from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

def fast_reject(env: dict) -> bool:
    # Fail fast before expensive crypto.
    required = ("v", "from", "session_proof", "payload", "sig")
    return isinstance(env, dict) and all(k in env for k in required)

identity = SummonerIdentity()
stage_counts = Counter()
peer_penalty = {}
blocked = set()

@SummonerIdentity.verify_session
def keep_strict_verify(peer_public_id, local_role, session_record, use_margin=False):
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
        if fp in blocked:
            return False
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

@identity.on_policy_event(phase="open_envelope")
def classify_dos_shape(event_name, ctx):
    if event_name != "ok":
        stage = ctx.get("validation_stage", "unspecified")
        stage_counts[stage] += 1
        fp = ctx.get("peer_fingerprint")
        if isinstance(fp, str):
            peer_penalty[fp] = peer_penalty.get(fp, 0) + 1
            if peer_penalty[fp] >= 20:
                blocked.add(fp)  # telemetry -> verify_session deny path
```

## 8) Threat Table (Quick Reference)

| Threat | Native Security | With Telemetry | How / Why | Residual Risk | Primary telemetry signal |
| --- | --- | --- | --- | --- | --- |
| Payload tampering | Yes | Yes | Ed25519 signature over envelope core | None if keys safe | `open_envelope` failures at `validation_stage=signature` or decrypt-related failures |
| Message forgery | Yes | Yes | Only holder of signing key can sign | Key theft breaks | `open_envelope:peer_key_check_failed` or signature-stage failures |
| Identity record tampering | Yes | Yes | Identity record is self‑signed | Registry compromise can still distribute bad IDs | `open_envelope:invalid_to_identity`, `open_envelope:to_identity_mismatch` |
| Passive eavesdropping (to present) | Yes | Yes (detection assist only) | AES‑GCM with X25519 + HKDF | No forward secrecy | No direct event proves confidentiality; monitor key compromise process externally |
| Replay within active session | Mostly | High (with replay alerts and enforcement) | Nonce chain + replay cache | Concurrency not supported | `open_envelope:replay_detected` (+ `replay_store_mode`, `persist_replay`) |
| Start‑form replay / reset pressure | Partially | High (with strict policy + telemetry enforcement) | Start-form policy + session verification | Reset abuse still possible unless stricter policy is enforced | `open_envelope:ok` with `replaced_active_incomplete=True` |
| Real‑world identity impersonation | No | Partial detection only | Self‑signing is not PKI | Use registry/TOFU/PKI | New `peer_fingerprint` arrivals inconsistent with expected trust mapping |
| Key compromise | No | Partial detection/response | Static keys expose past traffic | Use rotations or ephemeral keys | Sudden behavior changes by known `peer_fingerprint`; registry revocation telemetry |
| DoS (invalid envelopes) | No | Partial mitigation via detection and rate controls | Crypto verification still costs | Add rate limiting | `open_envelope` failure distribution by `validation_stage` |

## 9) Registry and Reputation Guide (Telemetry-Driven)

The registry model below combines identity directory design and runtime
operations. The registry can act as both a key directory and a telemetry-aware
trust decision engine that updates trust state over time.

### 9.1 Registry objectives and trust boundary

A production registry should:

1. Resolve names or principals to verified public identities.
2. Track trust decisions and key lifecycle (new key, rotated key, revoked key).
3. Ingest telemetry-derived reputation signals per peer fingerprint.
4. Provide auditable state for incident response.

Key boundary:

- `meta` remains advisory metadata only.
- Identity authority is the signing key (`pub_sig_b64`) plus your external trust process (PKI, org workflow, or manual verification).
- In local SDK terms, `list_known_peers()` is discovery state, while
  `list_verified_peers()` is the stricter conversation-safe boundary.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

tmp = tempfile.TemporaryDirectory()
identity = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
public_id = identity.id(os.path.join(tmp.name, "alice.json"), meta="alice")
identity_sdk.verify_public_id(public_id)
fingerprint = identity_sdk.id_fingerprint(public_id["pub_sig_b64"])

registry = {
    fingerprint: {
        "public_id": public_id,
        "trust": "tofu",
        "revoked": False,
    }
}
```

### 9.2 Recommended registry data model

Use fingerprint as the primary key and keep operational counters separate from identity payload:

| Field | Source | Purpose |
| --- | --- | --- |
| `fingerprint` | `id_fingerprint(pub_sig_b64)` | Stable primary key for trust and telemetry joins. |
| `public_id` | identity ingestion | Canonical signed identity record. |
| `first_seen`, `last_seen` | registry ingest + telemetry updates | Timeline and anomaly detection. |
| `trust_state` | operator / policy engine | `tofu`, `pinned`, `quarantined`, `revoked`. |
| `reputation_score` | telemetry aggregation | Fast, numeric enforcement input. |
| `counters.*` | policy event stream | Event-class volume (`replay_detected`, `session_verify_failed`, etc.). |
| `last_reset_like_accept_ts` | `open_envelope:ok` + `replaced_active_incomplete=True` | Reset-abuse traceability anchor. |
| `notes` | ops workflow | Human audit context (ticket, owner, incident id). |

### 9.3 Telemetry ingestion and reputation loop

Operational loop:

1. Register `on_policy_event` handlers on every traffic-serving `SummonerIdentity`.
2. Aggregate by `peer_fingerprint` and by `event_name`.
3. Convert repeated signals into registry actions (`quarantined`, temporary deny, escalated review).
4. Route enforcement decisions into verify/reset policy handlers.

Telemetry event context reference:

| Field | Meaning | Typical use |
| --- | --- | --- |
| `schema_version` | Event schema version (`1`) | Decoder validation in pipelines. |
| `ts` | Event timestamp (unix seconds) | Windowed alerting and incident timelines. |
| `phase` | Emitting API phase | Split dashboards by lifecycle step. |
| `ok` | Outcome success flag | Fast success/failure rates. |
| `code` | Outcome code (same as `event_name`) | Error taxonomy and SLO buckets. |
| `has_data` | Whether payload data was returned | Validate expected data-plane behavior. |
| `peer_fingerprint` | Stable peer key id (when derivable) | Per-peer counters/throttles/allow-block actions. |
| `session_form` | `start` or `continue` (when derivable) | Reset pressure vs normal continuation analysis. |
| `sender_role`, `local_role` | Directional protocol roles (when derivable) | Diagnose asymmetric traffic anomalies. |
| `replaced_active_incomplete` | True only on committed `ok` replacements | High-signal reset-abuse acceptance metric. |
| `validation_stage` | Failure stage in open pipeline | Distinguish malformed flood vs crypto garbage vs state-control issues. |
| `replay_store_mode` | `memory` / `disk` / `custom` on replay events | Explain replay posture and restart behavior. |
| `persist_replay` | Replay durability flag on replay events | Detect misconfiguration for long-lived receivers. |

### 9.4 Building Trust Metrics from Event Taxonomy

The telemetry context table above defines the raw signals; this subsection shows how to convert those signals into registry state that is both actionable and auditable. The objective is to make each reputation update deterministic, easy to reason about, and inexpensive to compute under sustained traffic. Instead of operating from ad-hoc alerts, the registry becomes a derived state machine fed directly by policy events.

Concrete event-to-registry transformation design:

1. Normalize each event to a canonical tuple:
   - `(ts, phase, code, peer_fingerprint, validation_stage, session_form, replaced_active_incomplete, persist_replay, replay_store_mode)`.
2. Ignore events without `peer_fingerprint` for peer-scoped reputation, but still keep global counters by `code` and `validation_stage`.
3. Upsert peer entry by fingerprint and update timeline fields:
   - set `first_seen` if missing,
   - always set `last_seen = ts`.
4. Update counters in O(1):
   - `counters.code[code] += 1`
   - `counters.stage[validation_stage] += 1` when stage is present.
5. Derive high-signal fields:
   - if `code == "ok"` and `replaced_active_incomplete=True`, set `last_reset_like_accept_ts = ts`.
   - if `code == "replay_detected"`, increment replay pressure and annotate posture from `persist_replay`/`replay_store_mode`.
6. Recompute `reputation_score` from weighted event classes (deterministic function).
7. Map score and hard conditions to `trust_state`:
   - `revoked` (manual/operator or key compromise),
   - `quarantined` (score <= threshold or severe condition),
   - `pinned` / `tofu` (healthy states).
8. Attach operator notes only from workflow systems (`notes` is not telemetry-derived).

How each 9.2 field is built from telemetry:

| 9.2 field | Build rule from event stream |
| --- | --- |
| `fingerprint` | `ctx["peer_fingerprint"]` (primary key). |
| `public_id` | Registry ingest path (not from runtime event stream). |
| `first_seen` | First event timestamp observed for fingerprint. |
| `last_seen` | Latest event timestamp observed for fingerprint. |
| `trust_state` | State machine output from score + hard rules + operator overrides. |
| `reputation_score` | Weighted aggregation over recent event classes. |
| `counters.*` | O(1) increments keyed by `code` and optional `validation_stage`. |
| `last_reset_like_accept_ts` | Last `open_envelope:ok` where `replaced_active_incomplete=True`. |
| `notes` | External incident workflow metadata (ticket, owner, reason). |

The snippet below implements the transform directly. It first maintains global and per-peer O(1) counters from `event_name` and `validation_stage`, then updates registry timeline fields (`first_seen`, `last_seen`) keyed by `peer_fingerprint`. Next it derives compact trust features (verify failures, replay pressure, reset-like accepts), computes a deterministic reputation score, and maps that score to `trust_state` with operator overrides. This gives a concrete baseline pipeline where policy events are immediately converted into auditable reputation state.

```python
from collections import Counter, defaultdict
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
metrics = Counter()
by_peer = defaultdict(Counter)
registry_state = {}

@identity.on_policy_event(phase="open_envelope")
def on_open(event_name, ctx):
    ts = int(ctx.get("ts", 0))
    metrics[f"open:{event_name}"] += 1
    stage = ctx.get("validation_stage")
    if isinstance(stage, str):
        metrics[f"open_stage:{stage}"] += 1

    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return

    by_peer[fp][event_name] += 1
    entry = registry_state.setdefault(
        fp,
        {
            "first_seen": ts,
            "last_seen": ts,
            "trust_state": "tofu",
            "reputation_score": 0,
            "counters": {"code": Counter(), "stage": Counter()},
            "last_reset_like_accept_ts": None,
            "features": Counter(),
            "notes": {},
        },
    )
    entry["last_seen"] = ts
    entry["counters"]["code"][event_name] += 1
    if isinstance(stage, str):
        entry["counters"]["stage"][stage] += 1

    if event_name == "session_verify_failed":
        entry["features"]["verify_fail_24h"] += 1
    if event_name == "replay_detected":
        entry["features"]["replay_24h"] += 1
        if ctx.get("persist_replay") is False:
            entry["features"]["replay_non_durable_24h"] += 1
    if event_name == "ok" and ctx.get("replaced_active_incomplete") is True:
        entry["features"]["reset_like_accept_24h"] += 1
        entry["last_reset_like_accept_ts"] = ts

    # Example deterministic weighted score function.
    entry["reputation_score"] = (
        -2 * entry["features"]["reset_like_accept_24h"]
        -1 * entry["features"]["verify_fail_24h"]
        -1 * entry["features"]["replay_24h"]
        -1 * entry["features"]["replay_non_durable_24h"]
    )

    if entry["reputation_score"] <= -20:
        entry["trust_state"] = "quarantined"
    elif entry.get("operator_pinned") is True:
        entry["trust_state"] = "pinned"
    else:
        entry["trust_state"] = "tofu"
```

### 9.5 Incident response path

If a peer or local identity is compromised:

1. Mark fingerprint as `revoked` or `quarantined` in the registry.
2. Push revocation/disallow updates to enforcement handlers.
3. Rotate to a new identity and redistribute through trusted channel.
4. Keep old fingerprint history for forensics; do not recycle its trust state.

**Example**

```python
# inside an async function / handler
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk
import os
import tempfile

tmp = tempfile.TemporaryDirectory()
identity = SummonerIdentity(store_dir=tmp.name, persist_local=False, load_local=False)
public_id = identity.id(os.path.join(tmp.name, "alice.json"), meta="alice")
fp = identity_sdk.id_fingerprint(public_id["pub_sig_b64"])

registry = {fp: {"trust_state": "revoked", "revoked": True}}
```

### 9.6 What registry + telemetry still does not solve

- It does not prove real-world identity by itself.
- It does not retroactively provide forward secrecy if static keys were compromised.
- It improves detection and response speed, but policy and governance remain required for final trust decisions.

## 10) Streaming Security Addendum

Streaming adds stateful continuity concerns on top of the base protocol. This
addendum maps those concerns to the behavior implemented in `identity.py`.

The streaming implementation is stateful and fail-closed: sequence, phase, stream-id continuity, and non-end `stream_ttl` are verified before acceptance. It also exposes stream telemetry (`stream_id`, `stream_phase`, `stream_seq`, `stream_ttl`, `stream_reason`, and timing extras) so operators can enforce local policy beyond protocol minimums.

For stream mode, start-form classification is phase-aware:
- `phase="start"` is the only stream start-form
- `phase="chunk"` and `phase="end"` are continuation frames

This matters especially for initiator-owned streams started with
`start_session(..., stream=True, ...)`, because their opposite nonce can remain
`null` across the stream without making later frames reset-like.

### 10.1 Quick map: abuse path -> native behavior -> policy control

Use this table as an operations index. The "native behavior" column is what protocol/fallback logic already does. The "policy control" column is what you should add in handlers and transport controls.

| Stream abuse class | Native behavior (implemented) | Policy control (recommended) |
| --- | --- | --- |
| Turn keepalive without `end` | Valid chunks are accepted while continuity + `stream_ttl` pass. | Enforce max frames and max wall-clock duration per `(peer_fingerprint, stream_id)`. |
| Gap-state pressure | Default policy is contiguous sequence (`stream_seq_invalid` on jumps). | Keep contiguous default; if custom gap tolerance is enabled, cap gap counters/spans. |
| Expensive-but-valid stream DoS | Verify/decrypt/commit still executes for valid frames. | Per-peer/per-stream rate limits and completion-ratio throttles at transport/policy layer. |
| Timeout/restart thrash | Timeouts close stream state; repeated attempts become `stream_interrupted`. | Timeout counters + cooldown windows for unstable peers. |
| Post-timeout delayed old frames | Closed streams are rejected (`stream_interrupted`), with reason propagation available. | Maintain closed-stream cache and deny by stream id in custom verify when needed. |
| Observability downgrade (bool verify) | `False` collapses to `session_verify_failed`. | Prefer structured verify outputs with explicit stream `code` and `reason`. |

### 10.2 Turn-hijack via valid chunk keepalive

Abuse path:

1. Peer opens a stream-turn and keeps sending valid `chunk` frames before timeout.
2. Protocol continuity remains valid, so frames can keep passing.
3. Turn handoff is delayed if no `end` frame is sent.

Mitigation:

1. Hard-cap frames per stream id.
2. Hard-cap stream wall-clock duration.
3. Quarantine peers with repeated stream-overrun patterns.

**Example (policy-event counters + blocklist signal)**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
stream_state = {}  # (fp, sid) -> {'first_ts': int, 'last_ts': int, 'frames': int, 'timeouts': int}
blocked = set()

@identity.on_policy_event(phase="open_envelope")
def monitor_stream_abuse(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    sid = ctx.get("stream_id")
    ev_ts = ctx.get("ts")
    if not (isinstance(fp, str) and isinstance(sid, str) and isinstance(ev_ts, int)):
        return

    key = (fp, sid)
    st = stream_state.setdefault(key, {"first_ts": ev_ts, "last_ts": ev_ts, "frames": 0, "timeouts": 0})

    if event_name == "ok" and ctx.get("stream_phase") in ("start", "chunk"):
        st["frames"] += 1
        st["last_ts"] = ev_ts
        if st["frames"] > 200 or (st["last_ts"] - st["first_ts"]) > 180:
            blocked.add(fp)

    if event_name in ("stream_ttl_expired", "stream_interrupted"):
        st["timeouts"] += 1
        if st["timeouts"] >= 3:
            blocked.add(fp)
```

### 10.3 Gap-state pressure and custom sequence policy

Current implementation defaults to contiguous stream sequence checks (`stream_seq_invalid` on out-of-order/jump). This is the safest memory posture because fallback storage does not need unbounded gap tracking.

If you introduce a custom gap-tolerant policy in hooks, keep all accounting O(1) and bounded. Do not accumulate unbounded missing-range state.

**Example (bounded gap accounting for custom policy extensions)**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
gap_state = {}  # (fp, sid) -> {'last_seq': int, 'gap_count': int, 'gap_span': int}
blocked = set()

@identity.on_policy_event(phase="open_envelope")
def monitor_gap_pressure(event_name, ctx):
    if event_name != "ok":
        return
    fp = ctx.get("peer_fingerprint")
    sid = ctx.get("stream_id")
    seq = ctx.get("stream_seq")
    phase = ctx.get("stream_phase")
    if not (isinstance(fp, str) and isinstance(sid, str) and isinstance(seq, int) and phase in ("start", "chunk", "end")):
        return

    key = (fp, sid)
    st = gap_state.setdefault(key, {"last_seq": -1, "gap_count": 0, "gap_span": 0})
    if st["last_seq"] >= 0 and seq > st["last_seq"] + 1:
        missing = seq - st["last_seq"] - 1
        st["gap_count"] += 1
        st["gap_span"] += missing
    st["last_seq"] = max(st["last_seq"], seq)

    if st["gap_count"] > 16 or st["gap_span"] > 1024:
        blocked.add(fp)
```

### 10.4 Valid-stream DoS (expensive-but-valid frames)

Malformed-envelope filters are not enough here because attacker traffic can remain cryptographically valid. That means verify/decrypt/commit paths still execute and can consume CPU.

Primary controls are external to protocol correctness:

1. Per-peer rate limits.
2. Per-stream token bucket quotas.
3. Completion-ratio monitoring (many chunks, few ends).

**Example (chunk/end/fail ratio monitor)**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
stats = {}
blocked = set()

@identity.on_policy_event(phase="open_envelope")
def monitor_stream_ratio(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    if not isinstance(fp, str):
        return
    rec = stats.setdefault(fp, {"chunks": 0, "ends": 0, "fail": 0})
    if event_name == "ok" and ctx.get("stream_phase") == "chunk":
        rec["chunks"] += 1
    elif event_name == "ok" and ctx.get("stream_phase") == "end":
        rec["ends"] += 1
    elif event_name in ("stream_ttl_expired", "stream_interrupted"):
        rec["fail"] += 1
    if rec["chunks"] > 500 and rec["ends"] == 0:
        blocked.add(fp)
```

### 10.5 Timeout/restart thrash and post-timeout delayed frames

Two related patterns matter operationally:

1. Thrash: repeated timeout closures and immediate restart pressure.
2. Delayed old-frame arrivals after timeout closure.

Implemented behavior already helps:

1. Late non-end frame returns `stream_ttl_expired` on timeout boundary.
2. Stream is then closed/interrupted in fallback state.
3. Further frames on that closed stream id return `stream_interrupted` (with `stream_reason` when available, e.g. `timeout_closed`).
4. Fresh start-form admission after restart normalizes stale persisted
   `current_link` state to absent local state.
5. For stream-active links, staleness is derived from `stream_last_ts + stream_ttl`
   rather than from the original requester-window TTL alone.

Important distinction:
- This normalization applies only to fresh start-form admission.
- Ongoing frames and late replies still fail closed against the stored state and
  preserve timeout/interruption diagnostics (`stream_ttl_expired`,
  `stream_interrupted`, `response_window_expired`, etc.).

**Example A (timeout thrash cooldown)**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
timeout_pressure = {}  # fp -> {'count': int, 'last_ts': int, 'cooldown_until': int}
blocked = set()

@identity.on_policy_event(phase="open_envelope")
def monitor_timeout_thrash(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    ev_ts = ctx.get("ts")
    if not (isinstance(fp, str) and isinstance(ev_ts, int)):
        return

    st = timeout_pressure.setdefault(fp, {"count": 0, "last_ts": 0, "cooldown_until": 0})
    if event_name in ("stream_ttl_expired", "stream_interrupted"):
        st["count"] += 1
        st["last_ts"] = ev_ts
        if st["count"] >= 5:
            st["cooldown_until"] = ev_ts + 300
            blocked.add(fp)
    elif event_name == "ok":
        st["count"] = max(0, st["count"] - 1)
```

**Example B (closed-stream cache + custom verify deny)**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
closed_streams = {}  # (fp, sid) -> closed_ts

@identity.on_policy_event(phase="open_envelope")
def mark_closed_streams(event_name, ctx):
    fp = ctx.get("peer_fingerprint")
    sid = ctx.get("stream_id")
    ev_ts = ctx.get("ts")
    if not (isinstance(fp, str) and isinstance(sid, str) and isinstance(ev_ts, int)):
        return
    if event_name in ("stream_ttl_expired", "stream_interrupted"):
        closed_streams[(fp, sid)] = ev_ts

@SummonerIdentity.verify_session
def reject_closed_stream(peer_public_id, local_role, session_record, use_margin=False):
    fp = None
    if isinstance(peer_public_id, dict):
        fp = identity_sdk.id_fingerprint(peer_public_id["pub_sig_b64"])
    s = session_record.get("stream") if isinstance(session_record, dict) else None
    if isinstance(fp, str) and isinstance(s, dict):
        sid = s.get("id")
        if isinstance(sid, str) and (fp, sid) in closed_streams:
            return {"ok": False, "code": "stream_interrupted", "reason": "frame_on_closed_stream"}
    return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)
```

### 10.6 Observability downgrade with boolean-only verify hooks

If a custom verify hook returns only booleans, failure detail can collapse into generic `session_verify_failed`. That weakens incident triage because operations teams lose stream-specific reason codes.

Recommended policy:

1. Support boolean-return paths when you need the compact form.
2. Prefer structured verify output: `{"ok": bool, "code": str, "reason": optional str}`.
3. Alert on low-quality failure telemetry (high generic failure ratio without detailed stream codes).

**Example (reason-quality monitor)**

```python
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import identity as identity_sdk

identity = SummonerIdentity()
generic_fail = 0
detailed_fail = 0
blocked = set()

@identity.on_policy_event(phase="open_envelope")
def monitor_reason_quality(event_name, ctx):
    global generic_fail, detailed_fail
    fp = ctx.get("peer_fingerprint")
    if event_name == "session_verify_failed":
        generic_fail += 1
        if isinstance(fp, str) and generic_fail >= 20 and detailed_fail == 0:
            blocked.add(fp)
    if event_name in ("stream_ttl_expired", "stream_interrupted", "stream_seq_invalid"):
        detailed_fail += 1
```
