# =============================================================================
# SummonerIdentity Crypto Framework
# =============================================================================
"""
This module defines a compact crypto framework for agent-to-agent messaging based on:

- Self-signed public identities (X25519 for key agreement, Ed25519 for signatures).
- A session proof carried in each message, using a nonce-chain invariant with `sender_role: 0/1`.
- A deterministic per-session symmetric key (`sym_key`) derived from X25519 + HKDF, bound to:
  - both identities (via fingerprints of signing public keys), and
  - session fields (`sender_role`, nonces, timestamp, ttl).
- Authenticated encryption (AES-GCM) for:
  - the application payload (when a receiver identity is provided),
  - a continuity proof (`history_proof`) that binds a rolling history hash (`history_hash`) to the current session.

The design is intentionally simple at the API boundary:
- `SummonerIdentity.id(...)` loads or creates an identity.
- `SummonerIdentity.start_session(...)` produces the initial session proof (always `sender_role = 0`).
- `SummonerIdentity.continue_session(...)` produces the next session proof for replies.
- `SummonerIdentity.seal_envelope(...)` creates a signed envelope (and encrypts payload if `to` is set).
- `SummonerIdentity.open_envelope(...)` verifies and opens an envelope.

Public surface
- The SDK exposes `SummonerIdentity` and `SummonerIdentityControls` directly.
- `tooling.aurora` re-exports both names for ergonomic imports.

What is authenticated and what is encrypted
- The entire envelope core is Ed25519-signed by the sender. This authenticates:
  - payload (ciphertext or plaintext),
  - session proof fields (nonces, ts, ttl, history_proof),
  - sender and receiver public identity records.
- The payload is AES-GCM encrypted when `to` is present.
- The `history_proof` field is AES-GCM encrypted when `peer_public_id` is present at session start.

About identity binding and MitM
- Public identities are self-signed. This proves the record is internally consistent and not corrupted.
- This does not, by itself, prove the identity belongs to a specific real-world entity.
  If you need stronger binding, pin identities out-of-band (TOFU or explicit allowlists).

Security notes (practical)
- This framework uses static X25519 keys by default. It provides confidentiality and integrity, and
  it provides per-session key separation via HKDF binding to session fields.
  It does not provide forward secrecy unless you rotate identity keys or introduce ephemeral X25519.
- The nonce-chain checks aim to provide replay resistance and continuity inside a session.

Storage model
- Session continuity is tracked per peer and per local role. The fallback store writes a `sessions.json`
  next to the identity file, keyed by `(peer_fingerprint, local_role)`.
- Fallback JSON stores use versioned wrapped documents on disk.
- A rolling history list stores hashes `h1..hn`. Each finalized completed exchange can append a new hash.
  The `history_proof` mechanism allows a peer to prove continuity with that list without exposing key material.

Dependencies
- `cryptography` (X25519, Ed25519, HKDF, Scrypt, AESGCM).
"""

from __future__ import annotations

import base64
import datetime as _dt
import inspect
import json
import logging
import os
import secrets
import tempfile
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Protocol, runtime_checkable, Tuple, TypedDict, Union

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# =============================================================================
# Versions / domains
# =============================================================================
#
# Versions:
# - ID_VERSION: identity record format version.
# - ENV_VERSION: envelope format version.
# - PAYLOAD_ENC_VERSION: payload encryption object version.
# - HISTORY_PROOF_VERSION: history_proof encryption object version.
# - SESSIONS_STORE_VERSION / PEER_KEYS_STORE_VERSION / REPLAY_STORE_VERSION:
#   local fallback store document versions.
# - IDENTITY_CONTROLS_VERSION: instance controls API version for SummonerIdentity.
#
# Domains / info labels:
# - HKDF info labels provide domain separation between:
#   - the session symmetric key, the history_proof AEAD key, and the payload AEAD key.
# - The history and summary domains provide domain separation for hashing.

ID_VERSION = "id.v1"
ENV_VERSION = "env.v1"
PAYLOAD_ENC_VERSION = "payload.enc.v1"
HISTORY_PROOF_VERSION = "histproof.v1"
SESSIONS_STORE_VERSION = "sessions.store.v1"
PEER_KEYS_STORE_VERSION = "peer_keys.store.v1"
REPLAY_STORE_VERSION = "replay.store.v1"
IDENTITY_CONTROLS_VERSION = "aurora.identity.controls.v1"

_HKDF_INFO_SYM = b"summoner/session/v1/sym"
_HKDF_INFO_HISTORY_PROOF = b"summoner/session/v1/history_proof"
_HKDF_INFO_PAYLOAD = b"summoner/session/v1/payload"

_HIST_DOMAIN_RESET = b"summoner/hist/v1/reset"
_LINK_DOMAIN = b"summoner/link/v1"
_HISTORY_PROOF_AAD_DOMAIN = "summoner/history_proof/v1"
_PAYLOAD_AAD_DOMAIN = "summoner/payload/v1"

_ID_FILE_AAD = b"summoner/identity_file/v1"
_STORE_DOC_KIND_FIELD = "__summoner_identity_store__"
_STORE_DOC_VERSION_FIELD = "v"
_STORE_DOC_DATA_FIELD = "data"
_SUMMONER_IDENTITY_HOOK_NAMES = (
    "register_session",
    "reset_session",
    "verify_session",
    "get_session",
    "peer_key_store",
    "replay_store",
)

_LOGGER = logging.getLogger(__name__)
_HOOK_UNSET = object()

ALLOWED_POLICY_PHASES = frozenset({
    "start_session",
    "continue_session",
    "advance_stream_session",
    "seal_envelope",
    "open_envelope",
    "verify_discovery_envelope",
})

_POLICY_EVENT_EXTRA_FIELDS = frozenset({
    "peer_fingerprint",
    "session_form",
    "sender_role",
    "local_role",
    "replaced_active_incomplete",
    "validation_stage",
    "replay_store_mode",
    "persist_replay",
    "stream_mode",
    "stream_id",
    "stream_phase",
    "stream_seq",
    "stream_policy",
    "stream_reason",
    "stream_ttl",
    "stream_expired",
    "stream_started_ts",
    "stream_last_ts",
    "stream_frame_count",
})


# =============================================================================
# Interfaces
# =============================================================================
#
# SessionStore is provided as a minimal protocol for external storage, if desired.
# This module also supports decorator-based hooks on SummonerIdentity (register/verify/get).
#
# Note: SummonerIdentity supports both sync and async hooks. Async hooks are awaited.

@runtime_checkable
class SessionStore(Protocol):
    """Minimal interface for a key-value session store."""
    def get(self, key: str) -> Optional[dict]: ...
    def set(self, key: str, value: dict) -> None: ...


class PolicyEventContext(TypedDict, total=False):
    schema_version: int
    ts: int
    phase: str
    ok: bool
    code: str
    has_data: bool
    peer_fingerprint: str
    session_form: str
    sender_role: int
    local_role: int
    replaced_active_incomplete: bool
    validation_stage: str
    replay_store_mode: str
    persist_replay: bool
    stream_mode: str
    stream_id: str
    stream_phase: str
    stream_seq: int
    stream_policy: str
    stream_reason: str
    stream_ttl: int
    stream_expired: bool
    stream_started_ts: int
    stream_last_ts: int
    stream_frame_count: int


class VerifyResult(TypedDict, total=False):
    ok: bool
    code: str
    reason: str


@dataclass
class SummonerIdentityControls:
    """
    Reusable per-identity controls object for SummonerIdentity.

    This object groups storage and trust callbacks for one identity instance.
    When the built-in JSON stores are sufficient, no controls object is
    required. It becomes relevant when one SummonerIdentity must use custom
    persistence or verification behavior without changing the other identities
    in the same runtime.

    In a common Aurora deployment, a single SummonerAgent prepares several
    SummonerIdentity objects ahead of time, attaches controls only to the
    identities that require additional rules, and then binds one identity to the
    agent at runtime. The controls remain attached to the identity object, so
    stricter replay or verification behavior stays with the relevant principal
    while other identities continue to use the default JSON stores.

    The identity remains the same principal: the keypair, public identity
    record, and continuity model do not change. The controls change only how
    that principal persists or validates state. This is useful for workload
    separation, tenant-specific storage rules, stricter verification policy,
    shared continuity stores, or audit-domain separation.

    Cardinality model
    - One SummonerIdentity can have zero or one attached controls object at a time.
    - One SummonerIdentityControls object can define zero to six hook callbacks.
    - One SummonerIdentityControls object may be reused across multiple identities.
      If it holds mutable state internally, that state is shared across those
      identities.

    Each configured callback receives the owning SummonerIdentity instance as
    its first argument, followed by the same arguments as the corresponding
    class-hook path. Callbacks may be synchronous or async.

    Example:
        controls = SummonerIdentityControls()
        @controls.on_verify_session
        def verify(identity, peer_public_id, local_role, session_record, use_margin=False):
            return identity.verify_session_default(
                peer_public_id,
                local_role,
                session_record,
                use_margin=use_margin,
            )
    """

    register_session: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
    reset_session: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
    verify_session: Optional[Callable[..., Union[Any, Awaitable[Any]]]] = None
    get_session: Optional[Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]] = None
    peer_key_store: Optional[Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]] = None
    replay_store: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None

    _HOOK_NAMES = _SUMMONER_IDENTITY_HOOK_NAMES

    @staticmethod
    def version() -> str:
        return IDENTITY_CONTROLS_VERSION

    def configured_hooks(self) -> Tuple[str, ...]:
        out = []
        for hook_name in self._HOOK_NAMES:
            if getattr(self, hook_name, None) is not None:
                out.append(hook_name)
        return tuple(out)

    def _bind(self, hook_name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        if hook_name not in self._HOOK_NAMES:
            raise ValueError(f"unknown SummonerIdentityControls hook {hook_name!r}")
        if not callable(fn):
            raise TypeError(f"{hook_name} controls hook must be callable")
        setattr(self, hook_name, fn)
        return fn

    def clear(self) -> None:
        for hook_name in self._HOOK_NAMES:
            setattr(self, hook_name, None)

    def on_register_session(
        self,
        fn: Callable[..., Union[bool, Awaitable[bool]]],
    ) -> Callable[..., Union[bool, Awaitable[bool]]]:
        return self._bind("register_session", fn)

    def on_reset_session(
        self,
        fn: Callable[..., Union[bool, Awaitable[bool]]],
    ) -> Callable[..., Union[bool, Awaitable[bool]]]:
        return self._bind("reset_session", fn)

    def on_verify_session(
        self,
        fn: Callable[..., Union[Any, Awaitable[Any]]],
    ) -> Callable[..., Union[Any, Awaitable[Any]]]:
        return self._bind("verify_session", fn)

    def on_get_session(
        self,
        fn: Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]],
    ) -> Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]:
        """
        Register a session-lookup hook on this controls object.

        Expected signature:
            fn(identity, peer_public_id, local_role) -> (dict | None) | Awaitable[dict | None]

        The attached SummonerIdentity instance is passed as the first argument so
        one controls object can be reused across more than one identity profile
        when appropriate.

        Runtime code does not call `on_get_session(...)` to perform a lookup.
        Runtime code calls `get_current_session(...)`, `start_session(...)`,
        `continue_session(...)`, or `open_envelope(...)` on the identity, and
        those paths invoke the active controls hook automatically.
        """
        return self._bind("get_session", fn)

    def on_peer_key_store(
        self,
        fn: Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]],
    ) -> Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]:
        return self._bind("peer_key_store", fn)

    def on_replay_store(
        self,
        fn: Callable[..., Union[bool, Awaitable[bool]]],
    ) -> Callable[..., Union[bool, Awaitable[bool]]]:
        return self._bind("replay_store", fn)


async def _maybe_await(x: Any) -> Any:
    """
    Normalize a hook result so call sites can accept sync or async handlers.

    If `x` is awaitable, it is awaited and its resolved value is returned.
    Otherwise, `x` is returned as-is.
    """
    return await x if inspect.isawaitable(x) else x


# =============================================================================
# Encoding / canonical JSON / time
# =============================================================================

def b64_encode(data: bytes) -> str:
    """Standard base64 encoding to UTF-8 string."""
    return base64.b64encode(data).decode("utf-8")


def b64_decode(data: str) -> bytes:
    """Standard base64 decoding from UTF-8 string."""
    return base64.b64decode(data.encode("utf-8"))


def _canon_json_bytes(obj: Any) -> bytes:
    """
    Canonical JSON serialization used for signing and for derived salts.

    - sort_keys=True and compact separators ensure deterministic output across runs.
    - Callers must ensure `obj` contains only JSON-serializable data.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _utc_now() -> _dt.datetime:
    """
    Current UTC time with microseconds removed.

    Removing microseconds improves reproducibility and reduces accidental mismatches
    in serialized timestamps.
    """
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def _iso_utc(ts: _dt.datetime) -> str:
    """
    Convert a datetime to an ISO 8601 string in UTC with an explicit offset.

    The function coerces naive datetimes to UTC, then normalizes to UTC.
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return ts.astimezone(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _now_unix() -> int:
    """Current time as Unix epoch seconds (UTC)."""
    return int(_utc_now().timestamp())


def _log_warning(msg: str, **fields: Any) -> None:
    """Best-effort structured warning logger for policy callback failures."""
    if fields:
        _LOGGER.warning("%s | %s", msg, fields)
        return
    _LOGGER.warning("%s", msg)


def _sha256(data: bytes) -> bytes:
    """Compute SHA-256 digest."""
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


# =============================================================================
# Public key serialization
# =============================================================================

def serialize_public_key(key: Any) -> str:
    """
    Serialize a public key (X25519 or Ed25519) in raw format, base64-encoded.
    """
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64_encode(raw)


def _load_x25519_pub(pub_b64: str) -> x25519.X25519PublicKey:
    """Load a base64-encoded raw X25519 public key."""
    raw = b64_decode(pub_b64)
    if len(raw) != 32:
        raise ValueError("invalid X25519 public key length")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def _load_ed25519_pub(pub_b64: str) -> ed25519.Ed25519PublicKey:
    """Load a base64-encoded raw Ed25519 public key."""
    raw = b64_decode(pub_b64)
    if len(raw) != 32:
        raise ValueError("invalid Ed25519 public key length")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


# =============================================================================
# Signatures
# =============================================================================

def sign_bytes(priv_sign: ed25519.Ed25519PrivateKey, data: bytes) -> str:
    """
    Ed25519 signature of `data`, returned as base64 string.

    The caller is responsible for canonicalizing structured data before signing.
    """
    return b64_encode(priv_sign.sign(data))


def verify_bytes(pub_sign_b64: str, data: bytes, sig_b64: str) -> None:
    """
    Verify an Ed25519 signature (base64) over `data` using a base64 public key.

    Raises if verification fails or if the signature/public key has invalid length.
    """
    pub = _load_ed25519_pub(pub_sign_b64)
    sig = b64_decode(sig_b64)
    if len(sig) != 64:
        raise ValueError("invalid Ed25519 signature length")
    pub.verify(sig, data)


# =============================================================================
# Identity (public record is self-signed)
# =============================================================================
#
# Public identity fields are signed using the Ed25519 private key.
# The record is intended to be shipped inside envelopes and used to derive keys.
#
# Private identity material is stored either:
# - in plaintext JSON (no password), or
# - encrypted under a password via scrypt + AES-GCM.
#
# If you use plaintext storage, treat it as a development convenience only.

def _id_public_core(pub: dict) -> dict:
    """
    Extract the canonical, signed subset of a public identity record.

    Only these fields are signed and verified. This avoids accidentally binding
    unknown or mutable fields into the identity signature.
    """
    core = {
        "created_at": pub["created_at"],
        "pub_enc_b64": pub["pub_enc_b64"],
        "pub_sig_b64": pub["pub_sig_b64"],
    }
    if pub.get("meta") is not None:
        core["meta"] = pub["meta"]
    return core


def sign_public_id(priv_sig: ed25519.Ed25519PrivateKey, pub: dict) -> dict:
    """
    Produce a self-signed public identity record.

    Input `pub` should contain the public fields. The returned dict adds:
    - "sig": Ed25519 signature over canonical JSON of the public core fields
    - "v": ID_VERSION
    """
    core = _id_public_core(pub)
    sig = sign_bytes(priv_sig, _canon_json_bytes(core))
    out = dict(core)
    out["sig"] = sig
    out["v"] = ID_VERSION
    return out


def verify_public_id(pub: dict) -> None:
    """
    Verify a self-signed public identity record.

    Checks:
    - schema type is dict
    - version matches ID_VERSION
    - required fields are present
    - Ed25519 signature verifies over the canonical public core fields
    """
    if not isinstance(pub, dict):
        raise ValueError("public id must be a dict")
    if pub.get("v") != ID_VERSION:
        raise ValueError("unsupported id version")
    for k in ("created_at", "pub_enc_b64", "pub_sig_b64", "sig"):
        if k not in pub:
            raise ValueError(f"public id missing field: {k}")
    core = _id_public_core(pub)
    verify_bytes(pub["pub_sig_b64"], _canon_json_bytes(core), pub["sig"])


def id_fingerprint(pub_sig_b64: str) -> str:
    """
    Short, stable identifier derived from the signing public key.

    This is used only for local indexing and storage keys. It is not a substitute
    for the full public key, and it is not a cryptographic proof of identity.
    """
    raw = b64_decode(pub_sig_b64)
    return base64.urlsafe_b64encode(_sha256(raw)).decode("utf-8").rstrip("=")[:22]


def _atomic_write_json(path: str, doc: dict, *, mode: int = 0o600) -> None:
    """
    Write JSON atomically:
    - write to a temporary file in the same directory,
    - fsync,
    - replace the target path,
    - best-effort chmod.

    This reduces the risk of partial files during crashes.
    """
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, mode)
        except Exception:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except Exception:
            pass
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def _wrap_store_doc(store_name: str, version: str, data: dict[str, Any]) -> dict[str, Any]:
    """Wrap fallback store data in a versioned store document."""
    return {
        _STORE_DOC_KIND_FIELD: store_name,
        _STORE_DOC_VERSION_FIELD: version,
        _STORE_DOC_DATA_FIELD: data,
    }


def _unwrap_store_doc(obj: Any, *, store_name: str, version: str) -> dict[str, Any]:
    """
    Load fallback store data from a versioned wrapped store document.
    """
    if not isinstance(obj, dict):
        raise ValueError(f"invalid {store_name} store document")
    doc_store_name = obj.get(_STORE_DOC_KIND_FIELD)
    if doc_store_name is None:
        raise ValueError(f"invalid {store_name} store document")
    if doc_store_name != store_name:
        raise ValueError(f"unexpected store kind for {store_name}: {doc_store_name!r}")
    if obj.get(_STORE_DOC_VERSION_FIELD) != version:
        raise ValueError(f"unsupported {store_name} store version")
    data = obj.get(_STORE_DOC_DATA_FIELD)
    if not isinstance(data, dict):
        raise ValueError(f"invalid {store_name} store data")
    return data


def _kdf_scrypt(password: bytes, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    """
    Derive a 32-byte key from a password using scrypt.

    Parameters are exposed for integration-level policy. The defaults are moderate.
    Strong password policy is an application-level responsibility.
    """
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password)


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
) -> dict:
    """
    Save an identity file containing:
    - a self-signed public record,
    - private keys either in plaintext (no password) or encrypted (password).

    Returns the signed public identity record (the object intended to be shared).

    If `password is None`, the private keys are stored in plaintext base64.
    Treat that mode as development convenience only.
    """
    created_at = _iso_utc(_utc_now())
    pub = {
        "created_at": created_at,
        "pub_enc_b64": serialize_public_key(priv_enc.public_key()),
        "pub_sig_b64": serialize_public_key(priv_sig.public_key()),
    }
    if meta is not None:
        pub["meta"] = meta

    pub_signed = sign_public_id(priv_sig, pub)

    priv_enc_raw = priv_enc.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_sig_raw = priv_sig.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    private_obj = {
        "priv_enc_b64": b64_encode(priv_enc_raw),
        "priv_sig_b64": b64_encode(priv_sig_raw),
    }
    private_bytes = _canon_json_bytes(private_obj)

    if password is None:
        doc = {"v": ID_VERSION, "public": pub_signed, "private": private_obj}
        _atomic_write_json(path, doc, mode=0o600)
        return pub_signed

    salt = os.urandom(16)
    key = _kdf_scrypt(password, salt, n=scrypt_n, r=scrypt_r, p=scrypt_p)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, private_bytes, associated_data=_ID_FILE_AAD)

    doc = {
        "v": ID_VERSION,
        "public": pub_signed,
        "private_enc": {
            "kdf": "scrypt",
            "kdf_params": {"n": scrypt_n, "r": scrypt_r, "p": scrypt_p},
            "salt": b64_encode(salt),
            "nonce": b64_encode(nonce),
            "aad": b64_encode(_ID_FILE_AAD),
            "ciphertext": b64_encode(ct),
        },
    }
    _atomic_write_json(path, doc, mode=0o600)
    return pub_signed


def load_identity(
    path: str,
    *,
    password: Optional[bytes] = None,
) -> Tuple[dict, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey]:
    """
    Load an identity file and return:
    - public identity record (signed),
    - X25519 private key (encryption / key agreement),
    - Ed25519 private key (signatures).

    If the private section is encrypted, `password` must be provided.
    """
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    if doc.get("v") != ID_VERSION:
        raise ValueError("unsupported identity file format")

    public = doc.get("public")
    verify_public_id(public)

    if "private" in doc:
        private_obj = doc["private"]
    else:
        enc = doc.get("private_enc")
        if not isinstance(enc, dict):
            raise ValueError("missing private section")
        if not password:
            raise ValueError("password required")
        if enc.get("aad") != b64_encode(_ID_FILE_AAD):
            raise ValueError("identity AAD mismatch")
        params = enc.get("kdf_params") or {}
        n = int(params.get("n", 2**14))
        r = int(params.get("r", 8))
        p = int(params.get("p", 1))
        salt = b64_decode(enc["salt"])
        nonce = b64_decode(enc["nonce"])
        ct = b64_decode(enc["ciphertext"])
        key = _kdf_scrypt(password, salt, n=n, r=r, p=p)
        private_bytes = AESGCM(key).decrypt(nonce, ct, associated_data=_ID_FILE_AAD)
        private_obj = json.loads(private_bytes.decode("utf-8"))

    priv_enc = x25519.X25519PrivateKey.from_private_bytes(b64_decode(private_obj["priv_enc_b64"]))
    priv_sig = ed25519.Ed25519PrivateKey.from_private_bytes(b64_decode(private_obj["priv_sig_b64"]))
    return public, priv_enc, priv_sig


# =============================================================================
# History hashing (stores h1..hn)
# =============================================================================
#
# The history is a list of hashes (h1..hn). The update rule is:
# - h1 = H(summary_1)
# - h_{k+1} = H(h_k || summary_{k+1})
#
# Where each summary is a domain-separated digest of the completed link.
#
# The history list is not a secret. It is a compact commitment to a sequence of completed
# exchanges. The history_proof mechanism allows a peer to prove continuity with a given
# history value without sending the entire history (and without including sym_key in plaintext).

def session_summary(lnk: dict) -> bytes:
    """
    Compute a domain-separated digest representing a completed link.

    Expected input fields:
    - "0_nonce": hex string
    - "1_nonce": hex string
    - "ts": int (unix seconds)
    - "ttl": int (seconds)

    This function intentionally binds summary to session timing fields as well.
    """
    # Completed link must have both nonces and timing.
    n0 = lnk.get("0_nonce")
    n1 = lnk.get("1_nonce")
    ts = lnk.get("ts")
    ttl = lnk.get("ttl")
    if not (isinstance(n0, str) and isinstance(n1, str) and isinstance(ts, int) and isinstance(ttl, int)):
        raise ValueError("invalid link for session_summary")
    msg = _LINK_DOMAIN + bytes.fromhex(n0) + bytes.fromhex(n1) + ts.to_bytes(8, "big") + ttl.to_bytes(8, "big")
    return _sha256(msg)


def hist_next(prev_hash_hex: Optional[str], summary: bytes) -> str:
    """
    Advance the history hash chain by one step.

    - If prev_hash_hex is None: returns h1 = H(summary)
    - Else: returns H(prev || summary)

    The caller decides where and when to store the resulting hash.
    """
    if prev_hash_hex is None:
        return _sha256(summary).hex()
    return _sha256(bytes.fromhex(prev_hash_hex) + summary).hex()


# =============================================================================
# Key derivation: sym_key from X25519 + HKDF, bound to session fields
# =============================================================================
#
# The per-session sym_key is derived from:
# - X25519 shared secret (static keys),
# - HKDF-SHA256 with a salt derived from identities and session proof fields.
#
# This ensures:
# - keys differ across peers (bound to from/to),
# - keys differ across sessions (bound to nonces and timing),
# - domain separation across distinct uses (sym vs history_proof vs payload).

def derive_sym_key(
    *,
    priv_enc: x25519.X25519PrivateKey,
    peer_pub_enc_b64: str,
    from_pub_sig_b64: str,
    to_pub_sig_b64: str,
    session: dict,
) -> bytes:
    """
    Derive a 32-byte symmetric session key.

    Inputs:
    - priv_enc: local X25519 private key
    - peer_pub_enc_b64: peer X25519 public key (base64 raw)
    - from_pub_sig_b64, to_pub_sig_b64: signing public keys (base64 raw) used to bind salt
    - session: the session proof dict (must include sender_role, nonces, ts, ttl)

    The salt is computed from a canonical JSON object including:
    - fingerprints of from/to signing keys,
    - sender_role, nonces, ts, ttl,
    - ENV_VERSION domain tag.

    Both sides must compute the same (from,to) ordering for a given message direction.
    """
    peer_pub = _load_x25519_pub(peer_pub_enc_b64)
    shared = priv_enc.exchange(peer_pub)

    # Bind salt to identities + session proof fields.
    salt_obj = {
        "from": id_fingerprint(from_pub_sig_b64),
        "to": id_fingerprint(to_pub_sig_b64),
        "sender_role": int(session["sender_role"]),
        "0_nonce": session.get("0_nonce"),
        "1_nonce": session.get("1_nonce"),
        "ts": int(session["ts"]),
        "ttl": int(session["ttl"]),
        "v": ENV_VERSION,
    }
    salt = _sha256(_canon_json_bytes(salt_obj))

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO_SYM,
    )
    return hkdf.derive(shared)


def derive_history_proof_key(sym_key: bytes, aad_bytes: bytes) -> bytes:
    """
    Derive a dedicated AEAD key for encrypting/decrypting history_proof.

    - Domain separation via HKDF info label.
    - Salt binds to the exact AAD bytes so that history_proof keys vary when AAD varies.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_sha256(aad_bytes),
        info=_HKDF_INFO_HISTORY_PROOF,
    )
    return hkdf.derive(sym_key)


def derive_payload_key(sym_key: bytes, aad_bytes: bytes) -> bytes:
    """
    Derive a dedicated AEAD key for encrypting/decrypting payloads.

    - Domain separation via HKDF info label.
    - Salt binds to the exact AAD bytes so that payload keys vary when AAD varies.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_sha256(aad_bytes),
        info=_HKDF_INFO_PAYLOAD,
    )
    return hkdf.derive(sym_key)


# =============================================================================
# SummonerIdentity class
# =============================================================================

class SummonerIdentity:
    """
    A stateful helper for producing and consuming signed envelopes with session continuity.

    Public workflow
    - Load or create an identity:
        identity = SummonerIdentity(...)
        my_public = identity.id("id.json", password=...)
    - Exchange public identities out-of-band (or via a discovery layer).
    - Start a session to a peer:
        s0 = await identity.start_session(peer_public)
    - Send a message:
        env = await identity.seal_envelope({"msg": "hi"}, s0, to=peer_public)
    - Receive a message:
        payload = await identity.open_envelope(env_from_peer)
    - Reply:
        next_session = await identity.continue_session(peer_public, peer_session)
        env2 = await identity.seal_envelope({"msg": "ack"}, next_session, to=peer_public)

    Storage hooks
    This class supports optional hooks to integrate external persistence or custom policies:
      - controls objects via:
        - `controls = SummonerIdentityControls(...)`
        - `controls = SummonerIdentityControls(); @controls.on_verify_session ...`
        - `identity.attach_controls(controls)`
        - use this when one `SummonerIdentity` instance needs its own reusable set of hooks
        - common Aurora pattern: prepare several identities ahead of time, attach
          controls only to the identities that need them, then bind one identity
          to the agent at runtime
      - class-level defaults via:
        - @SummonerIdentity.register_session(fn)
        - @SummonerIdentity.reset_session(fn)
        - @SummonerIdentity.verify_session(fn)
        - @SummonerIdentity.get_session(fn)
        - @SummonerIdentity.peer_key_store(fn)
        - @SummonerIdentity.replay_store(fn)
        - use this when the whole process should share one hook policy
      - instance-local hooks via:
        - @identity.on_register_session
        - @identity.on_reset_session
        - @identity.on_verify_session
        - @identity.on_get_session
        - @identity.on_peer_key_store
        - @identity.on_replay_store
        - use this for narrow one-off changes on one live object
    If more than one scope defines the same hook name, resolution order is:
      1) instance-local `@identity.on_*`
      2) attached `SummonerIdentityControls`
      3) class-level `@SummonerIdentity.*`
      4) built-in default behavior
    The `on_*` prefix indicates callback registration on one live object.
    It distinguishes hook configuration from runtime methods such as
    `get_current_session(...)`, `verify_session_record(...)`, and
    `register_session_record(...)`.
    Hook functions may be synchronous or async; async hooks are awaited.

    If hooks are not provided, fallback JSON stores are used:
      - sessions.json (session continuity)
      - peer_keys.json (fingerprint-indexed peer cache + metadata)
      - replay.json (optional, only if persist_replay=True)
    These stores are written and read as versioned documents.

    Important invariants
    - `sender_role` is carried in each session proof.
    - When `sender_role = x`, the sender must provide:
      - a fresh `x_nonce`, and
      - the last observed `not(x)_nonce`.
    - A session "start form" has `not(x)_nonce = null` and `x_nonce` present.
      In this framework, start_session always uses `sender_role = 0`, so start form is:
        - 0_nonce present, 1_nonce null.
    - Public messages (`to=None`) still require a session_proof and are stored
      under a generic session slot (peer_public_id=None). This is a discovery-only
      convention: the generic slot is not bound to a specific sender, so a `to=None`
      session cannot be safely continued into a per-peer thread without custom
      storage/verification policy. The recommended flow is:
        1) receive broadcast (`to=None`) for discovery/identity,
        2) start a new per-peer session with `start_session(peer_public_id)`.
    """

    _register_session_handler: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
    _reset_session_handler: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
    _verify_session_handler: Optional[Callable[..., Union[Any, Awaitable[Any]]]] = None
    _get_session_handler: Optional[Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]] = None
    _peer_key_store_handler: Optional[Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]] = None
    _replay_store_handler: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
    _HOOK_NAMES = _SUMMONER_IDENTITY_HOOK_NAMES

    @staticmethod
    def store_versions() -> dict[str, str]:
        return {
            "sessions": SESSIONS_STORE_VERSION,
            "peer_keys": PEER_KEYS_STORE_VERSION,
            "replay": REPLAY_STORE_VERSION,
        }

    @staticmethod
    def controls_version() -> str:
        return IDENTITY_CONTROLS_VERSION

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
    ):
        """
        Parameters
        - ttl: default session TTL in seconds, applied when creating sessions.
        - margin: safety buffer in seconds used for expiry checks.
          This margin is applied when validating whether a session is still valid.
        - enforce_created_at: if True, reject session timestamps earlier than sender's created_at.
        - max_clock_skew_seconds: if set, reject sessions with ts too far in the future.
        - store_dir: optional override for where JSON stores are kept (sessions/peer_keys/replay).
          If relative, it is resolved relative to the caller's file directory.
        - persist_local: if True, write fallback stores to disk when they change.
        - load_local: if True, load fallback stores from disk when the identity is loaded.
        - persist_replay: if True, persist replay store to disk (replay.json).
          Otherwise replay is kept in memory only for the current process.
        """
        self.ttl = int(ttl)
        self.margin = int(margin)
        self.enforce_created_at = bool(enforce_created_at)
        self.max_clock_skew_seconds = None if max_clock_skew_seconds is None else int(max_clock_skew_seconds)
        self.store_dir = store_dir
        self.persist_local = bool(persist_local)
        self.load_local = bool(load_local)
        self.persist_replay = bool(persist_replay)

        self.public_id: Optional[dict] = None
        self._priv_enc: Optional[x25519.X25519PrivateKey] = None
        self._priv_sig: Optional[ed25519.Ed25519PrivateKey] = None

        self._sessions_path: Optional[str] = None
        self._sessions: dict[str, dict] = {}
        self._peer_keys_path: Optional[str] = None
        self._peer_keys: dict[str, dict] = {}
        self._replay_path: Optional[str] = None
        self._replay: dict[str, dict] = {}
        self._id_path: Optional[str] = None
        self._id_password: Optional[bytes] = None
        self._id_meta: Optional[Any] = None
        self._id_requires_password: bool = False
        self._policy_event_handlers: dict[str, list[Callable[[str, PolicyEventContext], Any]]] = {}
        self.controls: Optional[Any] = None
        self._register_session_handler_local: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
        self._reset_session_handler_local: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
        self._verify_session_handler_local: Optional[Callable[..., Union[Any, Awaitable[Any]]]] = None
        self._get_session_handler_local: Optional[Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]] = None
        self._peer_key_store_handler_local: Optional[Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]] = None
        self._replay_store_handler_local: Optional[Callable[..., Union[bool, Awaitable[bool]]]] = None
        self.last_status: dict[str, Any] = {"ok": True, "code": "init"}

    def _status(self, ok: bool, code: str, data: Optional[Any] = None, phase: Optional[str] = None) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": bool(ok), "code": str(code)}
        if phase is not None:
            out["phase"] = str(phase)
        if data is not None:
            out["data"] = data
        self.last_status = out
        return out

    async def _ret(
        self,
        return_status: bool,
        ok: bool,
        code: str,
        data: Optional[Any] = None,
        phase: Optional[str] = None,
        event_extra: Optional[dict[str, Any]] = None,
    ) -> Any:
        out = self._status(ok=ok, code=code, data=data, phase=phase)
        await self._emit_result_policy_event(
            ok=ok,
            code=code,
            data=data,
            phase=phase,
            event_extra=event_extra,
        )
        if return_status:
            return out
        return data if ok else None

    async def _emit_result_policy_event(
        self,
        ok: bool,
        code: str,
        data: Any,
        phase: Optional[str],
        event_extra: Optional[dict[str, Any]] = None,
    ) -> None:
        p = str(phase) if isinstance(phase, str) else ""
        if p not in ALLOWED_POLICY_PHASES:
            raise ValueError(f"invalid policy event phase: {phase!r}")
        handlers = self._policy_event_handlers.get(p, [])
        if not handlers:
            return

        event_name = str(code)
        context: PolicyEventContext = {
            "schema_version": 1,
            "ts": _now_unix(),
            "phase": p,
            "ok": bool(ok),
            "code": str(code),
            "has_data": data is not None,
        }
        if isinstance(event_extra, dict):
            for k in _POLICY_EVENT_EXTRA_FIELDS:
                if k in event_extra:
                    context[k] = event_extra[k]

        for handler in handlers:
            try:
                await _maybe_await(handler(event_name, context))
            except Exception as exc:
                _log_warning("policy handler failed", phase=p, code=event_name, exc=exc)

    def on_policy_event(
        self,
        phase: str,
    ) -> Callable[
        [Callable[[str, PolicyEventContext], Union[Any, Awaitable[Any]]]],
        Callable[[str, PolicyEventContext], Union[Any, Awaitable[Any]]],
    ]:
        """
        Register a policy-event callback for a specific phase.

        Expected signature:
            fn(event_name, context) -> Any | Awaitable[Any]

        Policy handlers may be synchronous or async. Handler exceptions are caught
        and logged as warnings so they do not break envelope processing.
        """
        def _register(
            fn: Callable[[str, PolicyEventContext], Union[Any, Awaitable[Any]]]
        ) -> Callable[[str, PolicyEventContext], Union[Any, Awaitable[Any]]]:
            p = str(phase) if isinstance(phase, str) else ""
            if p not in ALLOWED_POLICY_PHASES:
                raise ValueError(f"invalid policy phase: {phase!r}")
            self._policy_event_handlers.setdefault(p, []).append(fn)
            return fn

        return _register

    def _validate_controls(self, controls: Any) -> None:
        for hook_name in self._HOOK_NAMES:
            fn = getattr(controls, hook_name, None)
            if fn is not None and not callable(fn):
                raise TypeError(f"{hook_name} controls hook must be callable")

    def attach_controls(self, controls: Optional[Any] = None) -> Any:
        """
        Attach per-identity controls to this SummonerIdentity.

        Use this method when this identity instance requires custom hook
        behavior. If the built-in JSON stores are sufficient, this feature can
        be omitted. Class hooks remain the better choice when every
        SummonerIdentity in the process should share the same behavior.

        In a common Aurora deployment, one agent prepares several
        SummonerIdentity objects ahead of time, each identity may carry its own
        controls object, and the agent binds whichever identity is active with
        `agent.attach_identity(...)`. `attach_controls(...)` allows one identity
        to carry stricter logic without affecting the others.

        This API stores one attached controls object in a single slot. If a
        controls object is already attached and `attach_controls(...)` is called
        again, the new controls object replaces the previous one.

        The recommended controls type is SummonerIdentityControls, but any object
        exposing callable hook attributes named like the SummonerIdentity hooks is
        accepted. Controls callbacks receive this SummonerIdentity instance as
        their first argument.
        """
        if controls is None:
            controls = SummonerIdentityControls()
        self._validate_controls(controls)
        self.controls = controls
        return controls

    def detach_controls(self) -> Optional[Any]:
        controls = self.controls
        self.controls = None
        return controls

    def require_controls(self) -> Any:
        if self.controls is None:
            raise RuntimeError(
                "No SummonerIdentity controls are attached. Call attach_controls(...) first."
            )
        return self.controls

    def has_controls(self) -> bool:
        return self.controls is not None

    def _bind_instance_hook(self, hook_name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        if hook_name not in self._HOOK_NAMES:
            raise ValueError(f"unknown SummonerIdentity hook {hook_name!r}")
        if not callable(fn):
            raise TypeError(f"{hook_name} hook must be callable")
        setattr(self, f"_{hook_name}_handler_local", fn)
        return fn

    def _resolve_hook_source(self, hook_name: str) -> Optional[str]:
        if hook_name not in self._HOOK_NAMES:
            raise ValueError(f"unknown SummonerIdentity hook {hook_name!r}")
        local = getattr(self, f"_{hook_name}_handler_local", None)
        if local is not None:
            return "local"
        controls = self.controls
        if controls is not None:
            controls_hook = getattr(controls, hook_name, None)
            if controls_hook is not None:
                if not callable(controls_hook):
                    raise TypeError(f"{hook_name} controls hook must be callable")
                return "controls"
        class_hook = getattr(self.__class__, f"_{hook_name}_handler", None)
        if class_hook is not None:
            return "class"
        return None

    async def _call_hook(self, hook_name: str, *args, **kwargs) -> Any:
        source = self._resolve_hook_source(hook_name)
        if source is None:
            return _HOOK_UNSET
        if source == "local":
            fn = getattr(self, f"_{hook_name}_handler_local")
            return await _maybe_await(fn(*args, **kwargs))
        if source == "controls":
            controls = self.controls
            if controls is None:
                raise RuntimeError("controls hook resolution requires attached controls")
            fn = getattr(controls, hook_name)
            return await _maybe_await(fn(self, *args, **kwargs))
        fn = getattr(self.__class__, f"_{hook_name}_handler")
        return await _maybe_await(fn(*args, **kwargs))

    def clear_local_hooks(self) -> None:
        for hook_name in self._HOOK_NAMES:
            setattr(self, f"_{hook_name}_handler_local", None)

    def on_register_session(
        self,
        fn: Callable[..., Union[bool, Awaitable[bool]]],
    ) -> Callable[..., Union[bool, Awaitable[bool]]]:
        return self._bind_instance_hook("register_session", fn)

    def on_reset_session(
        self,
        fn: Callable[..., Union[bool, Awaitable[bool]]],
    ) -> Callable[..., Union[bool, Awaitable[bool]]]:
        return self._bind_instance_hook("reset_session", fn)

    def on_verify_session(
        self,
        fn: Callable[..., Union[Any, Awaitable[Any]]],
    ) -> Callable[..., Union[Any, Awaitable[Any]]]:
        return self._bind_instance_hook("verify_session", fn)

    def on_get_session(
        self,
        fn: Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]],
    ) -> Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]:
        """
        Register a session-lookup hook on this live identity object.

        Expected signature:
            fn(peer_public_id, local_role) -> (dict | None) | Awaitable[dict | None]

        This method registers behavior. Runtime code does not call
        `on_get_session(...)` to perform a lookup. Runtime code calls
        `get_current_session(...)`, `start_session(...)`, `continue_session(...)`,
        or `open_envelope(...)`, and those paths invoke the active session-lookup
        hook automatically.

        If the custom hook wants the built-in lookup logic, call
        `get_session_default(peer_public_id, local_role)` from inside the hook.
        """
        return self._bind_instance_hook("get_session", fn)

    def on_peer_key_store(
        self,
        fn: Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]],
    ) -> Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]:
        return self._bind_instance_hook("peer_key_store", fn)

    def on_replay_store(
        self,
        fn: Callable[..., Union[bool, Awaitable[bool]]],
    ) -> Callable[..., Union[bool, Awaitable[bool]]]:
        return self._bind_instance_hook("replay_store", fn)

    def _require_custom_verify_for_register(self) -> None:
        register_source = self._resolve_hook_source("register_session")
        if register_source is None:
            return
        verify_source = self._resolve_hook_source("verify_session")
        if verify_source != register_source:
            raise ValueError(
                "custom register_session requires custom verify_session in the same hook scope"
            )

    # -------------------------
    # decorators
    # -------------------------

    @classmethod
    def register_session(cls, fn: Callable[..., Union[bool, Awaitable[bool]]]) -> Callable[..., Union[bool, Awaitable[bool]]]:
        """
        Register a custom persistence hook.

        Expected signature:
            fn(peer_public_id, local_role, session_record, new=False, use_margin=False) -> bool | Awaitable[bool]

        The hook should persist and update state for (peer, local_role).
        """
        cls._register_session_handler = fn
        return fn

    @classmethod
    def reset_session(cls, fn: Callable[..., Union[bool, Awaitable[bool]]]) -> Callable[..., Union[bool, Awaitable[bool]]]:
        """
        Register a custom reset hook for force-reset semantics.

        Expected signature:
            fn(peer_public_id, local_role) -> bool | Awaitable[bool]

        Used by force_reset semantics in start_session(). A typical implementation
        archives summarizable completed state and clears current active state.
        Incomplete links should generally be dropped, not archived.
        """
        cls._reset_session_handler = fn
        return fn

    @classmethod
    def verify_session(cls, fn: Callable[..., Union[Any, Awaitable[Any]]]) -> Callable[..., Union[Any, Awaitable[Any]]]:
        """
        Register a custom verification hook.

        Expected signature:
            fn(peer_public_id, local_role, session_record, use_margin=False)
                -> (bool | {"ok": bool, "code": str, "reason"?: str}) | Awaitable[...]

        The hook should enforce continuity and freshness rules for incoming session proofs.
        """
        cls._verify_session_handler = fn
        return fn

    @classmethod
    def get_session(
        cls,
        fn: Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]],
    ) -> Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]:
        """
        Register a custom session lookup hook.

        Expected signature:
            fn(peer_public_id, local_role) -> (dict | None) | Awaitable[dict | None]

        This decorator registers the process-wide session-lookup hook. Runtime
        code normally does not call this hook directly. Instead, runtime paths
        such as `get_current_session(...)`, `start_session(...)`,
        `continue_session(...)`, and `open_envelope(...)` resolve and invoke the
        active hook automatically.

        Typically returns the stored `current_link` for the peer and local role.
        """
        cls._get_session_handler = fn
        return fn

    @classmethod
    def peer_key_store(
        cls,
        fn: Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]],
    ) -> Callable[..., Union[Optional[dict], Awaitable[Optional[dict]]]]:
        """
        Register a custom peer key store hook.

        Expected signature:
            fn(peer_public_id, update=None) -> (dict | None) | Awaitable[dict | None]

        If update is None: return the stored record for this peer (or None).
        If update is a dict: store and return the new record.
        """
        cls._peer_key_store_handler = fn
        return fn

    @classmethod
    def replay_store(cls, fn: Callable[..., Union[bool, Awaitable[bool]]]) -> Callable[..., Union[bool, Awaitable[bool]]]:
        """
        Register a custom replay store hook.

        Expected signature:
            fn(message_id, ttl, now, add) -> bool | Awaitable[bool]

        - If add is False: return True if message_id is already present.
        - If add is True: store message_id and return True on success.
        """
        cls._replay_store_handler = fn
        return fn

    # -------------------------
    # identity
    # -------------------------

    def id(self, path: str = "id.json", meta: Optional[Any] = None, *, password: Optional[bytes] = None) -> dict:
        """
        Load or create an identity at `path`.

        Behavior
        - If the file exists: load it (decrypting private keys if needed).
        - If it does not exist: generate new X25519 + Ed25519 keys and write the file.
        - If `meta` is provided and differs from stored, update the public record and re-sign.

        Path resolution
        - If `path` is relative, it is interpreted relative to the caller file directory.

        Returns
        - The signed public identity record, suitable for sharing.
        """
        caller_dir = os.path.dirname(os.path.abspath(inspect.stack()[1].filename))
        if not os.path.isabs(path):
            path = os.path.join(caller_dir, path)

        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            self._id_requires_password = bool(isinstance(doc, dict) and "private_enc" in doc)
            pub, priv_enc, priv_sig = load_identity(path, password=password)
            if meta is not None and pub.get("meta") != meta:
                core = dict(_id_public_core(pub))
                core["created_at"] = pub["created_at"]
                core["pub_enc_b64"] = pub["pub_enc_b64"]
                core["pub_sig_b64"] = pub["pub_sig_b64"]
                core["meta"] = meta
                pub = sign_public_id(priv_sig, core)
                save_identity(
                    path,
                    priv_enc=priv_enc,
                    priv_sig=priv_sig,
                    meta=pub.get("meta"),
                    password=password,
                )
        else:
            priv_enc = x25519.X25519PrivateKey.generate()
            priv_sig = ed25519.Ed25519PrivateKey.generate()
            self._id_requires_password = password is not None
            pub = save_identity(
                path,
                priv_enc=priv_enc,
                priv_sig=priv_sig,
                meta=meta,
                password=password,
            )

        self.public_id = pub
        self._priv_enc = priv_enc
        self._priv_sig = priv_sig
        self._id_meta = pub.get("meta")
        self._id_path = path
        self._id_password = password

        base_dir = self.store_dir
        if base_dir is None:
            base_dir = os.path.dirname(path)
        else:
            if not os.path.isabs(base_dir):
                base_dir = os.path.join(caller_dir, base_dir)

        self._sessions_path = os.path.join(base_dir, "sessions.json")
        self._peer_keys_path = os.path.join(base_dir, "peer_keys.json")
        self._replay_path = os.path.join(base_dir, "replay.json")

        if self.load_local:
            self._load_sessions_fallback()
            self._load_peer_keys_fallback()
            if self.persist_replay:
                self._load_replay_fallback()
        else:
            self._sessions = {}
            self._peer_keys = {}
            self._replay = {}
        return pub

    def update_id_meta(self, meta: Optional[Any], *, password: Optional[bytes] = None) -> dict:
        """
        Update identity metadata, re-sign, and persist to disk.

        This is the only method that commits meta changes to the identity file.
        """
        if self.public_id is None or self._priv_enc is None or self._priv_sig is None:
            raise ValueError("call .id(...) first")
        if not self._id_path:
            raise ValueError("identity path is not set")

        if self._id_requires_password and password is None:
            raise ValueError("password required to update encrypted identity")
        use_password = password if password is not None else self._id_password

        core = {
            "created_at": self.public_id.get("created_at"),
            "pub_enc_b64": self.public_id.get("pub_enc_b64"),
            "pub_sig_b64": self.public_id.get("pub_sig_b64"),
        }
        if meta is not None:
            core["meta"] = meta

        pub = sign_public_id(self._priv_sig, core)
        save_identity(
            self._id_path,
            priv_enc=self._priv_enc,
            priv_sig=self._priv_sig,
            meta=pub.get("meta"),
            password=use_password,
        )

        self.public_id = pub
        self._id_meta = pub.get("meta")
        self._id_password = use_password
        return pub

    def list_known_peers(self) -> list[dict]:
        """
        Return known peer public identities from the local peer-key cache.

        Notes:
        - This method reads the in-memory fallback cache populated by
          `open_envelope()` and `verify_discovery_envelope()`.
        - "Known" is intentionally broader than "verified". A peer may appear
          here after its self-signed identity has been learned, even if session
          continuity was later rejected. Use `list_verified_peers()` when the
          caller needs a conversation-safe trust boundary.
        - With custom peer_key_store controls, this list may be incomplete unless your
          application keeps the fallback cache in sync or provides its own listing API.
        """
        out: list[dict] = []
        seen: set[str] = set()
        if not isinstance(self._peer_keys, dict):
            return out
        for rec in self._peer_keys.values():
            if not isinstance(rec, dict):
                continue
            pub = rec.get("public_id")
            if not isinstance(pub, dict):
                continue
            pub_sig = pub.get("pub_sig_b64")
            if not isinstance(pub_sig, str):
                continue
            if pub_sig in seen:
                continue
            seen.add(pub_sig)
            out.append(pub)
        return out

    def _peer_has_verified_continuity_fallback(self, pub_sig_b64: str) -> bool:
        """
        Return whether fallback session storage contains completed continuity for a peer.

        This is used as trust evidence for stores that predate explicit peer
        verification flags in `peer_keys.json`.
        """
        if not isinstance(pub_sig_b64, str):
            return False
        fp = id_fingerprint(pub_sig_b64)
        for local_role in (0, 1):
            rec = self._sessions.get(f"{fp}:{local_role}")
            if not isinstance(rec, dict):
                continue
            history = rec.get("history")
            if isinstance(history, list) and history:
                return True
            current = rec.get("current_link")
            if isinstance(current, dict) and bool(current.get("completed", False)):
                return True
        return False

    def _peer_is_verified_fallback(self, rec: dict) -> bool:
        """
        Return whether one fallback peer-key record is trusted for conversation use.

        Trust is explicit when `verified=True`, and it is also supported when the
        session store contains completed continuity for the same fingerprint.
        """
        if not isinstance(rec, dict):
            return False
        if bool(rec.get("verified", False)):
            return True
        pub_sig = rec.get("pub_sig_b64")
        if not isinstance(pub_sig, str):
            return False
        return self._peer_has_verified_continuity_fallback(pub_sig)

    def list_verified_peers(self) -> list[dict]:
        """
        Return peer identities that are safe to treat as verified conversation peers.

        Verification sources:
        - explicit success markers written by `open_envelope()` or
          `verify_discovery_envelope()`
        - completed continuity evidence already present in fallback session
          history/current-link state

        Notes:
        - This is stricter than `list_known_peers()`.
        - With custom peer-key/session controls, the fallback view may be
          incomplete unless your application mirrors these trust signals.
        """
        out: list[dict] = []
        seen: set[str] = set()
        if not isinstance(self._peer_keys, dict):
            return out
        for rec in self._peer_keys.values():
            if not self._peer_is_verified_fallback(rec):
                continue
            pub = rec.get("public_id")
            if not isinstance(pub, dict):
                continue
            pub_sig = pub.get("pub_sig_b64")
            if not isinstance(pub_sig, str):
                continue
            if pub_sig in seen:
                continue
            seen.add(pub_sig)
            out.append(pub)
        return out

    def find_peer(self, text: str) -> list[dict]:
        """
        Return known peer public identities where `text` appears in `str(public_id)`.

        This is a convenience search for UX-level lookup, not a trust primitive.
        """
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return [pub for pub in self.list_known_peers() if text in str(pub)]

    # -------------------------
    # fallback session storage
    # -------------------------

    def _load_sessions_fallback(self) -> None:
        """
        Load the fallback `sessions.json` store into memory.

        The file is treated as untrusted input and must contain a wrapped,
        versioned store document.
        """
        if not self.load_local:
            self._sessions = {}
            return
        if not self._sessions_path or not os.path.exists(self._sessions_path):
            self._sessions = {}
            return
        with open(self._sessions_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        self._sessions = _unwrap_store_doc(
            obj,
            store_name="sessions",
            version=SESSIONS_STORE_VERSION,
        )

    def _save_sessions_fallback(self) -> None:
        """
        Persist the in-memory fallback sessions dict.

        Uses atomic write with best-effort chmod(600) and writes a versioned
        store document.
        """
        if not self.persist_local:
            return
        if self._sessions_path:
            _atomic_write_json(
                self._sessions_path,
                _wrap_store_doc("sessions", SESSIONS_STORE_VERSION, self._sessions),
                mode=0o600,
            )

    def _load_peer_keys_fallback(self) -> None:
        """
        Load the fallback `peer_keys.json` store into memory.

        The file is treated as untrusted input and must contain a wrapped,
        versioned store document.
        """
        if not self.load_local:
            self._peer_keys = {}
            return
        if not self._peer_keys_path or not os.path.exists(self._peer_keys_path):
            self._peer_keys = {}
            return
        with open(self._peer_keys_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        self._peer_keys = _unwrap_store_doc(
            obj,
            store_name="peer_keys",
            version=PEER_KEYS_STORE_VERSION,
        )

    def _save_peer_keys_fallback(self) -> None:
        """
        Persist the in-memory fallback peer key store.

        Uses atomic write with best-effort chmod(600) and writes a versioned
        store document.
        """
        if not self.persist_local:
            return
        if self._peer_keys_path:
            _atomic_write_json(
                self._peer_keys_path,
                _wrap_store_doc("peer_keys", PEER_KEYS_STORE_VERSION, self._peer_keys),
                mode=0o600,
            )

    def _load_replay_fallback(self) -> None:
        """
        Load the fallback `replay.json` store into memory.

        The file is treated as untrusted input and must contain a wrapped,
        versioned store document.
        """
        if not self.load_local or not self.persist_replay:
            self._replay = {}
            return
        if not self._replay_path or not os.path.exists(self._replay_path):
            self._replay = {}
            return
        with open(self._replay_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        self._replay = _unwrap_store_doc(
            obj,
            store_name="replay",
            version=REPLAY_STORE_VERSION,
        )

    def _save_replay_fallback(self) -> None:
        """
        Persist the in-memory fallback replay store.

        Uses atomic write with best-effort chmod(600) and writes a versioned
        store document.
        """
        if not self.persist_local or not self.persist_replay:
            return
        if self._replay_path:
            _atomic_write_json(
                self._replay_path,
                _wrap_store_doc("replay", REPLAY_STORE_VERSION, self._replay),
                mode=0o600,
            )

    def _sess_key(self, peer_pub_sig_b64: str, local_role: int) -> str:
        """
        Construct the fallback store key for (peer, local_role).

        - peer is represented by fingerprint of the peer signing public key.
        - local_role is 0 or 1.
        """
        return f"{id_fingerprint(peer_pub_sig_b64)}:{int(local_role)}"

    def _is_expired(self, link: dict, *, use_margin: bool) -> bool:
        """
        Check whether a stored link is expired.

        Expiry condition:
            now > ts + ttl - margin

        margin is applied only if use_margin=True.
        """
        ts = link.get("ts")
        ttl = link.get("ttl")
        if not (isinstance(ts, int) and isinstance(ttl, int)):
            return True
        margin = self.margin if use_margin else 0
        return _now_unix() > (ts + ttl - margin)

    async def _peer_key_store(self, peer_public_id: dict, update: Optional[dict]) -> Optional[dict]:
        """
        Retrieve or update the peer key store.

        If a custom hook is provided, it is used.
        Otherwise, a fallback store is used keyed by signing-key fingerprint.
        """
        raw = await self._call_hook("peer_key_store", peer_public_id, update=update)
        if raw is not _HOOK_UNSET:
            return raw
        return self._peer_key_store_fallback(peer_public_id, update)

    def _peer_key_store_fallback(self, peer_public_id: dict, update: Optional[dict]) -> Optional[dict]:
        """
        Fallback peer key store keyed by signing-key fingerprint.

        Records contain:
        - public_id
        - pub_sig_b64
        - fingerprint
        - meta (metadata)
        - first_seen
        - last_seen
        - verified
        - verified_at
        - verified_via
        """
        if not isinstance(peer_public_id, dict):
            return None
        pub_sig = peer_public_id.get("pub_sig_b64")
        if not isinstance(pub_sig, str):
            return None
        fp = id_fingerprint(pub_sig)

        rec = self._peer_keys.get(fp)
        if update is None:
            return rec

        # Use update payload as the stored record source while keeping keying anchored
        # to peer_public_id. This mirrors the public hook contract.
        if not isinstance(update, dict):
            return None
        up_sig = update.get("pub_sig_b64")
        if not isinstance(up_sig, str):
            return None
        if id_fingerprint(up_sig) != fp:
            return None

        now = _now_unix()
        if not isinstance(rec, dict):
            rec = {
                "public_id": update,
                "pub_sig_b64": up_sig,
                "fingerprint": fp,
                "meta": update.get("meta"),
                "first_seen": now,
                "last_seen": now,
                "verified": False,
                "verified_at": None,
                "verified_via": None,
            }
        else:
            rec["public_id"] = update
            rec["pub_sig_b64"] = up_sig
            rec["fingerprint"] = fp
            rec["meta"] = update.get("meta")
            rec["last_seen"] = now
            rec.setdefault("verified", False)
            rec.setdefault("verified_at", None)
            rec.setdefault("verified_via", None)

        self._peer_keys[fp] = rec
        self._save_peer_keys_fallback()
        return rec

    async def _peer_key_check(self, peer_public_id: dict) -> bool:
        """
        Record peer identity by signing-key fingerprint.

        Policy:
        - If no record exists: store and accept.
        - If record exists: refresh last_seen and accept.

        This is an identity-cache operation, not a continuity trust decision.
        Verified conversation use is tracked separately.
        """
        if not isinstance(peer_public_id, dict):
            return False

        rec = await self._peer_key_store(peer_public_id, update=None)
        if not isinstance(rec, dict):
            await self._peer_key_store(peer_public_id, update=peer_public_id)
            return True

        await self._peer_key_store(peer_public_id, update=peer_public_id)
        return True

    def _mark_peer_verified_fallback(self, peer_public_id: dict, *, via: str) -> bool:
        """
        Mark one fallback peer-key record as verified for conversation use.

        This marker is written only after discovery verification or full envelope
        verification succeeds.
        """
        if not isinstance(peer_public_id, dict):
            return False
        pub_sig = peer_public_id.get("pub_sig_b64")
        if not isinstance(pub_sig, str):
            return False
        fp = id_fingerprint(pub_sig)
        rec = self._peer_key_store_fallback(peer_public_id, update=peer_public_id)
        if not isinstance(rec, dict):
            return False
        rec["verified"] = True
        rec["verified_at"] = _now_unix()
        rec["verified_via"] = via if isinstance(via, str) and via else None
        self._peer_keys[fp] = rec
        self._save_peer_keys_fallback()
        return True

    async def _mark_peer_verified(self, peer_public_id: dict, *, via: str) -> bool:
        """
        Mark one peer identity as verified after a successful trust-bearing check.

        Fallback storage persists this explicitly. Custom peer-key controls do not
        currently have a separate verification hook, so we best-effort refresh the
        peer record and rely on application-specific trust storage when needed.
        """
        if self._resolve_hook_source("peer_key_store") is not None:
            rec = await self._peer_key_store(peer_public_id, update=peer_public_id)
            return isinstance(rec, dict)
        return self._mark_peer_verified_fallback(peer_public_id, via=via)

    async def _replay_seen(self, message_id: str, ttl: int) -> bool:
        """
        Check whether a message_id has already been observed.

        If a custom hook is provided, it is used. Otherwise a fallback store is used.
        """
        now = _now_unix()
        raw = await self._call_hook("replay_store", message_id, ttl=ttl, now=now, add=False)
        if raw is not _HOOK_UNSET:
            return bool(raw)
        return self._replay_seen_fallback(message_id, ttl, now)

    async def _replay_add(self, message_id: str, ttl: int) -> bool:
        """
        Store a message_id in the replay cache.

        If a custom hook is provided, it is used. Otherwise a fallback store is used.
        """
        now = _now_unix()
        raw = await self._call_hook("replay_store", message_id, ttl=ttl, now=now, add=True)
        if raw is not _HOOK_UNSET:
            return bool(raw)
        return self._replay_add_fallback(message_id, ttl, now)

    def _replay_seen_fallback(self, message_id: str, ttl: int, now: int) -> bool:
        items = self._replay.get("items")
        if not isinstance(items, dict):
            items = {}
        self._replay_cleanup(items, now)
        rec = items.get(message_id)
        if not isinstance(rec, dict):
            return False
        exp = rec.get("exp")
        return isinstance(exp, int) and now <= exp

    def _replay_add_fallback(self, message_id: str, ttl: int, now: int) -> bool:
        items = self._replay.get("items")
        if not isinstance(items, dict):
            items = {}
        self._replay_cleanup(items, now)
        exp = now + max(1, int(ttl))
        items[message_id] = {"exp": exp}
        self._replay["items"] = items
        self._save_replay_fallback()
        return True

    def _replay_cleanup(self, items: dict, now: int) -> None:
        drop = [k for k, v in items.items() if isinstance(v, dict) and isinstance(v.get("exp"), int) and v.get("exp") < now]
        for k in drop:
            items.pop(k, None)

    def _message_id(self, sender_pub_sig_b64: str, sig: str) -> str:
        """
        Derive a stable message id for replay detection.

        Uses sender public key and the envelope signature.
        """
        raw = f"{sender_pub_sig_b64}:{sig}".encode("utf-8")
        return _sha256(raw).hex()

    # -------------------------
    # hooks dispatch
    # -------------------------

    async def _get_session(self, peer_public_id: Optional[dict], local_role: int) -> Optional[dict]:
        """
        Return the current stored link for (peer_public_id, local_role).

        If a custom hook is provided, it is used.
        Otherwise, fallback store returns rec["current_link"] if present.
        """
        raw = await self._call_hook("get_session", peer_public_id, local_role)
        if raw is not _HOOK_UNSET:
            return raw
        return self._get_session_fallback(peer_public_id, local_role)

    def _is_stale_current_link(self, current: dict, *, use_margin: bool) -> bool:
        """
        Check whether a stored current_link should be treated as expired.

        Normal links expire on their requester-window (`ts` + `ttl`).
        Active streams instead expire on their most recent stream frame window
        (`stream_last_ts` + `stream_ttl`) so that in-progress streams are not
        cleared merely because the original requester window has elapsed.
        """
        if not isinstance(current, dict):
            return True
        if bool(current.get("stream_active", False)):
            last_ts = current.get("stream_last_ts")
            stream_ttl = current.get("stream_ttl")
            if isinstance(last_ts, int) and isinstance(stream_ttl, int) and stream_ttl > 0:
                margin = self.margin if use_margin else 0
                return _now_unix() > (last_ts + stream_ttl - margin)
        return self._is_expired(current, use_margin=use_margin)

    def _load_fallback_session_record(self, peer_public_id: Optional[dict], local_role: int) -> tuple[str, Optional[dict], Optional[dict]]:
        """
        Return fallback store key, record, and current_link without mutation.
        """
        if peer_public_id is None:
            key = f"GENERIC:{int(local_role)}"
        else:
            key = self._sess_key(peer_public_id["pub_sig_b64"], local_role)
        rec = self._sessions.get(key)
        if not isinstance(rec, dict):
            return key, None, None
        current = rec.get("current_link")
        return key, rec, current if isinstance(current, dict) else None

    def _get_session_fallback(self, peer_public_id: Optional[dict], local_role: int) -> Optional[dict]:
        _, _, current = self._load_fallback_session_record(peer_public_id, local_role)
        return current

    async def _verify_session(self, peer_public_id: Optional[dict], local_role: int, session_record: dict, use_margin: bool) -> VerifyResult:
        """
        Verify session continuity for a received session_record.

        If a custom hook is provided, it is used.
        Otherwise, fallback verification enforces:
        - correct start form when no current_link exists,
        - nonce-chain continuity when current_link exists,
        - freshness (no nonce reuse within the stored chain),
        - TTL constraints.
        """
        raw = await self._call_hook(
            "verify_session",
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )
        if raw is not _HOOK_UNSET:
            return self._normalize_verify_result(raw)
        self._require_custom_verify_for_register()
        return self._normalize_verify_result(
            self._verify_session_fallback(peer_public_id, local_role, session_record, use_margin)
        )

    def _normalize_verify_result(self, raw: Any) -> VerifyResult:
        """
        Normalize verify hook output to a structured result.

        Supported outputs:
        - bool
        - dict with {"ok": bool, "code": str, "reason"?: str}
        """
        if isinstance(raw, bool):
            if raw:
                return {"ok": True, "code": "ok"}
            return {"ok": False, "code": "session_verify_failed"}
        if isinstance(raw, dict):
            ok_raw = raw.get("ok")
            if not isinstance(ok_raw, bool):
                return {"ok": False, "code": "session_verify_failed"}
            ok = ok_raw
            code = raw.get("code")
            if not isinstance(code, str) or not code:
                code = "ok" if ok else "session_verify_failed"
            out: VerifyResult = {"ok": ok, "code": code}
            reason = raw.get("reason")
            if isinstance(reason, str) and reason:
                out["reason"] = reason
            return out
        return {"ok": False, "code": "session_verify_failed"}

    def _mark_stream_interrupted_fallback(
        self,
        peer_public_id: Optional[dict],
        local_role: int,
        stream_id: Optional[str],
        reason: Optional[str] = None,
    ) -> None:
        """
        Best-effort fallback state closure for interrupted/expired streams.

        This only applies to fallback storage paths (no custom register/get handlers).
        """
        if (
            self._resolve_hook_source("register_session") is not None
            or self._resolve_hook_source("get_session") is not None
        ):
            return
        if not isinstance(stream_id, str) or not stream_id:
            return
        if peer_public_id is None:
            key = f"GENERIC:{int(local_role)}"
        else:
            key = self._sess_key(peer_public_id["pub_sig_b64"], local_role)
        rec = self._sessions.get(key)
        if not isinstance(rec, dict):
            return
        cur = rec.get("current_link")
        if not isinstance(cur, dict):
            return
        if cur.get("stream_id") != stream_id:
            return
        if cur.get("stream_active") is False and cur.get("stream_phase") == "interrupted":
            return
        nxt = dict(cur)
        nxt["stream_active"] = False
        nxt["stream_phase"] = "interrupted"
        nxt["expected_next_seq"] = None
        if isinstance(reason, str) and reason:
            nxt["stream_reason"] = reason
        rec["current_link"] = nxt
        self._sessions[key] = rec
        self._save_sessions_fallback()

    async def _register_session(self, peer_public_id: Optional[dict], local_role: int, session_record: Optional[dict], new: bool, use_margin: bool) -> bool:
        """
        Persist a session_record for (peer_public_id, local_role).

        If a custom hook is provided, it is used.
        Otherwise, fallback store updates:
        - current_link,
        - past_chain,
        - history (only when completed links are finalized).
        """
        raw = await self._call_hook(
            "register_session",
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )
        if raw is not _HOOK_UNSET:
            return bool(raw)
        return self._register_session_fallback(peer_public_id, local_role, session_record, new, use_margin)

    async def _force_reset_session(self, peer_public_id: Optional[dict], local_role: int) -> bool:
        """
        Force-reset a slot and start a fresh thread boundary.

        Fallback behavior:
        - If current_link is summarizable (both nonces + timing), finalize it into history.
        - If current_link is incomplete (not summarizable), drop it without archiving.
        - Clear active chain state (current_link/past_chain/active).

        This ensures force reset never errors on incomplete links while still preserving
        completed continuity when available.
        """
        raw = await self._call_hook("reset_session", peer_public_id, local_role)
        if raw is not _HOOK_UNSET:
            return bool(raw)
        if self._resolve_hook_source("register_session") is not None:
            # With custom stores, explicit reset semantics must be supplied by reset_session.
            return False
        return self._reset_session_fallback(peer_public_id, local_role)

    def _reset_session_fallback(self, peer_public_id: Optional[dict], local_role: int) -> bool:
        """
        Internal fallback reset implementation used when no custom reset hook exists.
        """

        if peer_public_id is None:
            peer_key = f"GENERIC:{int(local_role)}"
            peer_id = None
        else:
            verify_public_id(peer_public_id)
            peer_key = self._sess_key(peer_public_id["pub_sig_b64"], local_role)
            peer_id = id_fingerprint(peer_public_id["pub_sig_b64"])

        rec = self._sessions.get(peer_key)
        if not isinstance(rec, dict):
            rec = {
                "peer_id": peer_id,
                "local_role": int(local_role),
                "active": False,
                "past_chain": [],
                "current_link": None,
                "history": [],
                "window": 20,
            }

        current = rec.get("current_link")
        if isinstance(current, dict):
            n0 = current.get("0_nonce")
            n1 = current.get("1_nonce")
            ts = current.get("ts")
            ttl = current.get("ttl")
            # Only finalize if the link is complete enough for session_summary.
            if isinstance(n0, str) and isinstance(n1, str) and isinstance(ts, int) and isinstance(ttl, int):
                cur = dict(current)
                cur["completed"] = True
                rec["current_link"] = cur
                self._finalize_history_if_completed(rec)
        rec["past_chain"] = []
        rec["current_link"] = None
        rec["active"] = False
        self._sessions[peer_key] = rec
        self._save_sessions_fallback()
        return True

    # -------------------------
    # public hook-aware session operations
    # -------------------------

    async def get_current_session(self, peer_public_id: Optional[dict], local_role: int) -> Optional[dict]:
        """
        Return the current stored link for (peer_public_id, local_role).

        This is the public hook-aware runtime accessor. It resolves the active
        session-lookup path in the normal precedence order:
        instance-local `@identity.on_get_session`, attached
        `SummonerIdentityControls`, class-level `@SummonerIdentity.get_session`,
        then the built-in fallback logic.
        """
        return await self._get_session(peer_public_id, local_role)

    async def verify_session_record(
        self,
        peer_public_id: Optional[dict],
        local_role: int,
        session_record: dict,
        *,
        use_margin: bool = False,
    ) -> VerifyResult:
        """
        Verify a session record through the configured verification path.

        This is the public hook-aware runtime entrypoint corresponding to the
        `@SummonerIdentity.verify_session` decorator.
        """
        return await self._verify_session(peer_public_id, local_role, session_record, use_margin)

    async def register_session_record(
        self,
        peer_public_id: Optional[dict],
        local_role: int,
        session_record: Optional[dict],
        *,
        new: bool = False,
        use_margin: bool = False,
    ) -> bool:
        """
        Persist a session record through the configured registration path.

        This is the public hook-aware runtime entrypoint corresponding to the
        `@SummonerIdentity.register_session` decorator.
        """
        return await self._register_session(peer_public_id, local_role, session_record, new, use_margin)

    async def force_reset_session(self, peer_public_id: Optional[dict], local_role: int) -> bool:
        """
        Force-reset a session slot through the configured reset path.

        This is the public hook-aware runtime entrypoint corresponding to the
        `@SummonerIdentity.reset_session` decorator.
        """
        return await self._force_reset_session(peer_public_id, local_role)

    # -------------------------
    # public default delegates for custom handlers
    # -------------------------

    def get_session_default(self, peer_public_id: Optional[dict], local_role: int) -> Optional[dict]:
        """
        Public default implementation for get_session handlers.

        This helper is intended for hook authors who want to keep the built-in
        lookup behavior and add logic around it.
        """
        return self._get_session_fallback(peer_public_id, local_role)

    def verify_session_default(
        self,
        peer_public_id: Optional[dict],
        local_role: int,
        session_record: dict,
        use_margin: bool = False,
    ) -> VerifyResult:
        """
        Public default implementation for verify_session handlers.
        """
        return self._normalize_verify_result(
            self._verify_session_fallback(peer_public_id, local_role, session_record, use_margin)
        )

    def register_session_default(
        self,
        peer_public_id: Optional[dict],
        local_role: int,
        session_record: Optional[dict],
        *,
        new: bool = False,
        use_margin: bool = False,
    ) -> bool:
        """
        Public default implementation for register_session handlers.
        """
        return self._register_session_fallback(peer_public_id, local_role, session_record, new, use_margin)

    def reset_session_default(self, peer_public_id: Optional[dict], local_role: int) -> bool:
        """
        Public default implementation for reset_session handlers.
        """
        return self._reset_session_fallback(peer_public_id, local_role)

    def peer_key_store_default(self, peer_public_id: dict, update: Optional[dict] = None) -> Optional[dict]:
        """
        Public default implementation for peer_key_store handlers.
        """
        return self._peer_key_store_fallback(peer_public_id, update)

    def replay_store_default(
        self,
        message_id: str,
        *,
        ttl: int,
        now: Optional[int] = None,
        add: bool = False,
    ) -> bool:
        """
        Public default implementation for replay_store handlers.
        """
        ts_now = _now_unix() if now is None else int(now)
        if add:
            return self._replay_add_fallback(message_id, ttl, ts_now)
        return self._replay_seen_fallback(message_id, ttl, ts_now)

    # -------------------------
    # session helpers
    # -------------------------

    def classify_session_record(self, session_record: Any) -> dict[str, Any]:
        """
        Classify an inbound session proof for policy decisions.

        Returns:
        - valid_shape: bool
        - sender_role: 0|1|None
        - is_start_form: bool
        - has_history_proof: bool
        - mode: "single" | "stream" | None
        - is_stream: bool
        - stream_fields_valid: bool
        - stream_id: str | None
        - stream_seq: int | None
        - stream_phase: "start"|"chunk"|"end"|None
        - is_stream_start: bool
        - is_stream_end: bool
        - has_ttl: bool
        - ttl_valid: bool
        - has_stream_ttl: bool
        - stream_ttl_valid: bool
        - record_expired: bool
        - record_expiry_basis: "ttl"|"stream_ttl"|None
        """
        out: dict[str, Any] = {
            "valid_shape": False,
            "sender_role": None,
            "is_start_form": False,
            "has_history_proof": False,
            "mode": None,
            "is_stream": False,
            "stream_fields_valid": False,
            "stream_id": None,
            "stream_seq": None,
            "stream_phase": None,
            "is_stream_start": False,
            "is_stream_end": False,
            "has_ttl": False,
            "ttl_valid": False,
            "has_stream_ttl": False,
            "stream_ttl_valid": False,
            "record_expired": False,
            "record_expiry_basis": None,
        }
        if not isinstance(session_record, dict):
            return out

        sender_role = session_record.get("sender_role")
        if not isinstance(sender_role, int) or sender_role not in (0, 1):
            return out

        n0 = session_record.get("0_nonce")
        n1 = session_record.get("1_nonce")
        ts = session_record.get("ts")
        ttl = session_record.get("ttl")
        out["has_ttl"] = ttl is not None
        out["ttl_valid"] = isinstance(ttl, int) and ttl > 0
        if not (isinstance(ts, int) and out["ttl_valid"]):
            return out
        if not ((isinstance(n0, str) or n0 is None) and (isinstance(n1, str) or n1 is None)):
            return out

        mode = session_record.get("mode")
        stream = session_record.get("stream")
        stream_ttl = session_record.get("stream_ttl")

        if mode is None and stream is None:
            mode = "single"
        if mode not in ("single", "stream"):
            return out

        out["mode"] = mode
        out["is_stream"] = mode == "stream"
        out["has_stream_ttl"] = stream_ttl is not None
        out["stream_ttl_valid"] = isinstance(stream_ttl, int) and stream_ttl > 0

        nx = f"{sender_role}_nonce"
        nnot = f"{1-sender_role}_nonce"
        out["valid_shape"] = True
        out["sender_role"] = sender_role
        base_start_form = session_record.get(nnot) is None and isinstance(session_record.get(nx), str)
        out["has_history_proof"] = isinstance(session_record.get("history_proof"), dict)

        if mode == "single":
            out["is_start_form"] = base_start_form
            out["stream_fields_valid"] = stream is None and stream_ttl is None
            out["record_expired"] = _now_unix() > (int(ts) + int(ttl))
            out["record_expiry_basis"] = "ttl" if out["record_expired"] else None
            return out

        if not isinstance(stream, dict):
            return out
        sid = stream.get("id")
        seq = stream.get("seq")
        phase = stream.get("phase")
        if not (isinstance(sid, str) and sid and isinstance(seq, int) and seq >= 0 and phase in ("start", "chunk", "end")):
            return out

        out["stream_fields_valid"] = True
        out["stream_id"] = sid
        out["stream_seq"] = seq
        out["stream_phase"] = phase
        out["is_stream_start"] = phase == "start"
        out["is_stream_end"] = phase == "end"
        out["is_start_form"] = base_start_form and phase == "start"
        if phase in ("start", "chunk"):
            out["record_expired"] = not out["stream_ttl_valid"] or (_now_unix() > (int(ts) + int(stream_ttl)))
            out["record_expiry_basis"] = "stream_ttl" if out["record_expired"] else None
        else:
            out["record_expired"] = _now_unix() > (int(ts) + int(ttl))
            out["record_expiry_basis"] = "ttl" if out["record_expired"] else None
        return out

    def _replay_store_mode(self) -> str:
        if self._resolve_hook_source("replay_store") is not None:
            return "custom"
        if self.persist_replay:
            return "disk"
        return "memory"

    async def start_session(
        self,
        peer_public_id: Optional[dict] = None,
        ttl: Optional[int] = None,
        stream: bool = False,
        stream_ttl: Optional[int] = None,
        *,
        force_reset: bool = False,
        return_status: bool = False,
    ) -> Any:
        """
        Create a start-form session proof (always sender_role = 0) and persist it.

        Fields:
        - sender_role: 0
        - 0_nonce: fresh hex nonce (sender-owned)
        - 1_nonce: null
        - ts: unix seconds
        - ttl: seconds (parameter or default)
        - history_proof: encrypted continuity proof (optional)
        - age: integer index into peer history (meaning depends on policy)

        history_proof behavior:
        - If peer_public_id is provided, and we have stored history for that peer,
          history_proof is populated to allow continuity validation by the peer.
        - history_proof plaintext includes history_hash (not sym_key), plus nonces and age.
        - history_proof is AEAD-encrypted under a key derived from sym_key, and AAD binds
          to the message direction and session timing fields.

        Session lifecycle policy:
        - Only one active role-0 session is allowed per peer slot.
        - If an unexpired and not-completed active session exists, start_session returns None
          unless force_reset=True.
        - If the active session is completed, a new start finalizes it into history first.
        - force_reset=True archives completed/summarizable current links and drops incomplete
          links, then starts a new session.

        Return behavior:
        - Default: returns `session_record` on success, else `None`.
        - If `return_status=True`: returns `{ok, code, phase, data?}`.
        """
        self._require_custom_verify_for_register()
        if self.public_id is None:
            raise ValueError("call .id(...) first")
        if peer_public_id is not None:
            verify_public_id(peer_public_id)
        if stream and peer_public_id is None:
            return await self._ret(return_status, False, "stream_mode_unsupported", phase="start_session")
        if stream and (not isinstance(stream_ttl, int) or stream_ttl <= 0):
            return await self._ret(return_status, False, "stream_ttl_invalid", phase="start_session")

        # Enforce single-active-session policy for local role 0.
        current = await self._get_session(peer_public_id, local_role=0)
        if isinstance(current, dict):
            # Clear stale state first so restart is deterministic. Active streams
            # stay live on their stream_ttl window rather than the original start ttl.
            if self._is_stale_current_link(current, use_margin=False):
                ok_clear = await self._register_session(
                    peer_public_id,
                    local_role=0,
                    session_record=None,
                    new=True,
                    use_margin=False,
                )
                if not ok_clear:
                    return await self._ret(return_status, False, "register_session_failed", phase="start_session")
            elif bool(current.get("completed", False)):
                ok_clear = await self._register_session(
                    peer_public_id,
                    local_role=0,
                    session_record=None,
                    new=True,
                    use_margin=False,
                )
                if not ok_clear:
                    return await self._ret(return_status, False, "register_session_failed", phase="start_session")
            elif force_reset:
                ok_drop = await self._force_reset_session(peer_public_id, local_role=0)
                if not ok_drop:
                    return await self._ret(return_status, False, "force_reset_failed", phase="start_session")
            else:
                return await self._ret(return_status, False, "active_session_exists", phase="start_session")

        ttl_i = int(ttl if ttl is not None else self.ttl)
        ts = _now_unix()

        session = {
            "sender_role": 0,
            "0_nonce": secrets.token_hex(16),
            "1_nonce": None,
            "ts": ts,
            "ttl": ttl_i,
            "history_proof": None,
            "age": 0,
            "mode": "single",
            "stream": None,
            "stream_ttl": None,
        }
        if stream:
            session["mode"] = "stream"
            session["stream"] = {
                "id": secrets.token_hex(8),
                "seq": 0,
                "phase": "start",
            }
            session["stream_ttl"] = int(stream_ttl)

        if peer_public_id is not None:
            peer_sig = peer_public_id["pub_sig_b64"]
            key = self._sess_key(peer_sig, local_role=0)
            rec = self._sessions.get(key) if isinstance(self._sessions.get(key), dict) else None
            history = (rec.get("history") if rec else None) or []

            if history:
                history_hash = str(history[-1]["hash"])
                session["age"] = int(history[-1]["age"])
            else:
                # Reset hash is used when no history exists locally.
                history_hash = _sha256(_HIST_DOMAIN_RESET).hex()
                session["age"] = 0

            # History proof key is derived from sym_key and AAD. History proof plaintext excludes sym_key.
            sym = self._derive_sym_for_peer(peer_public_id, session, receiver_side=False)
            aad_bytes = self._history_proof_aad_bytes(peer_public_id, session, receiver_side=False)
            kx = derive_history_proof_key(sym, aad_bytes)

            plaintext = {
                "0_nonce": session["0_nonce"],
                "history_hash": history_hash,
                "1_nonce": session["1_nonce"],
                "age": session["age"],
            }
            nonce = os.urandom(12)
            ct = AESGCM(kx).encrypt(nonce, _canon_json_bytes(plaintext), associated_data=aad_bytes)

            session["history_proof"] = {
                "v": HISTORY_PROOF_VERSION,
                "nonce": b64_encode(nonce),
                "ciphertext": b64_encode(ct),
            }

        ok = await self._register_session(peer_public_id, local_role=0, session_record=session, new=True, use_margin=False)
        if not ok:
            return await self._ret(return_status, False, "register_session_failed", phase="start_session")
        return await self._ret(return_status, True, "ok", data=session, phase="start_session")

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
    ) -> Any:
        """
        Given a peer's session proof, construct the next session proof for replying.

        Steps:
        - Derive local_role = not(peer_session.sender_role).
        - Check local stored current_link for (peer, local_role).
          - If missing or expired:
            - If local_role == 0, restart with start_session(peer_public_id).
            - If local_role == 1, return None (do not restart as role 0).
        - Validate that the peer_session matches the current link (no advance).
        - Produce next_session:
          - sender_role = local_role
          - carry forward peer nonces as needed
          - generate a fresh nonce for the local role
          - update ts and ttl
          - history_proof is not populated here (it is used as a start-session continuity proof)
        - Persist the next session proof via register_session.

        The returned session proof is intended to be used by seal_envelope().

        Notes:
        - If peer_public_id is None, this is a public (to=None) flow and uses the
          generic session slot for the given local_role. Because that slot is shared,
          it should be treated as a one-point discovery session, not as a per-peer
          chain you can continue later.

        Return behavior:
        - Default: returns `next_session` on success, else `None`.
        - If `return_status=True`: returns `{ok, code, phase, data?}`.
        """
        self._require_custom_verify_for_register()
        if self.public_id is None:
            raise ValueError("call .id(...) first")
        if peer_public_id is not None:
            verify_public_id(peer_public_id)
        if stream and peer_public_id is None:
            return await self._ret(return_status, False, "stream_mode_unsupported", phase="continue_session")
        if stream and (not isinstance(stream_ttl, int) or stream_ttl <= 0):
            return await self._ret(return_status, False, "stream_ttl_invalid", phase="continue_session")
        if not isinstance(peer_session, dict):
            return await self._ret(return_status, False, "invalid_peer_session", phase="continue_session")
        sender_role = peer_session.get("sender_role")
        if not isinstance(sender_role, int) or sender_role not in (0, 1):
            return await self._ret(return_status, False, "invalid_peer_session", phase="continue_session")

        x = sender_role
        local_role = 1 - x

        current = await self._get_session(peer_public_id, local_role=local_role)
        if not stream and isinstance(current, dict) and bool(current.get("stream_active", False)):
            return await self._ret(return_status, False, "stream_active_continue_blocked", phase="continue_session")
        # Enforce TTL contract using margin: if there isn't enough time to respond,
        # role 1 must give up (no restart), role 0 may start a new session.
        if current is None or self._is_stale_current_link(current, use_margin=use_margin):
            if local_role == 0:
                # Restart as role 0 without force-clearing local state here.
                # start_session() enforces lifecycle policy and handles expiry/state transitions.
                return await self.start_session(peer_public_id, ttl=ttl, return_status=return_status)
            # End local state; do not respond as role 1.
            ok_clear = await self._register_session(peer_public_id, local_role=local_role, session_record=None, new=True, use_margin=use_margin)
            if not ok_clear:
                return await self._ret(return_status, False, "register_session_failed", phase="continue_session")
            return await self._ret(return_status, False, "missing_or_expired_current_link", phase="continue_session")

        # The peer proof should match our last accepted link for this role pair.
        # Enforce equality on core continuity fields before deriving the reply step.
        for k in ("0_nonce", "1_nonce", "ts", "ttl"):
            if peer_session.get(k) != current.get(k):
                return await self._ret(return_status, False, "peer_session_mismatch", phase="continue_session")
        # Sender role must be the peer's role, so our local_role is not(sender_role).
        if sender_role != (1 - local_role):
            return await self._ret(return_status, False, "peer_sender_role_mismatch", phase="continue_session")

        ttl_i = int(ttl if ttl is not None else self.ttl)
        ts = _now_unix()

        next_session = {
            "sender_role": local_role,
            "0_nonce": peer_session.get("0_nonce"),
            "1_nonce": peer_session.get("1_nonce"),
            "ts": ts,
            "ttl": ttl_i,
            "history_proof": None,
            "age": 0,
            "mode": "single",
            "stream": None,
            "stream_ttl": None,
        }

        age = current.get("age") if isinstance(current, dict) else None
        if not isinstance(age, int) or age < 0:
            age = peer_session.get("age")
        if isinstance(age, int) and age >= 0:
            next_session["age"] = age

        if local_role == 0:
            next_session["0_nonce"] = secrets.token_hex(16)
            next_session["1_nonce"] = peer_session.get("1_nonce")
        else:
            next_session["1_nonce"] = secrets.token_hex(16)
            next_session["0_nonce"] = peer_session.get("0_nonce")

        if stream:
            next_session["mode"] = "stream"
            next_session["stream"] = {
                "id": secrets.token_hex(8),
                "seq": 0,
                "phase": "start",
            }
            next_session["stream_ttl"] = int(stream_ttl)

        ok = await self._register_session(peer_public_id, local_role=local_role, session_record=next_session, new=False, use_margin=use_margin)
        if not ok:
            return await self._ret(return_status, False, "register_session_failed", phase="continue_session")
        return await self._ret(return_status, True, "ok", data=next_session, phase="continue_session")

    async def advance_stream_session(
        self,
        peer_public_id: Optional[dict],
        session: dict,
        *,
        end_stream: bool = False,
        ttl: Optional[int] = None,
        stream_ttl: Optional[int] = None,
        return_status: bool = False,
    ) -> Any:
        """
        Advance an active stream for the same sender role.
        """
        if self.public_id is None:
            raise ValueError("call .id(...) first")
        if peer_public_id is not None:
            verify_public_id(peer_public_id)
        if peer_public_id is None:
            return await self._ret(return_status, False, "stream_mode_unsupported", phase="advance_stream_session")
        cls = self.classify_session_record(session)
        if not cls.get("valid_shape") or not cls.get("is_stream") or not cls.get("stream_fields_valid"):
            return await self._ret(return_status, False, "invalid_stream_session", phase="advance_stream_session")
        if not end_stream and (not isinstance(stream_ttl, int) or stream_ttl <= 0):
            return await self._ret(return_status, False, "stream_ttl_invalid", phase="advance_stream_session")

        sender_role = int(session.get("sender_role"))
        current = await self._get_session(peer_public_id, local_role=sender_role)
        if not isinstance(current, dict) or not bool(current.get("stream_active", False)):
            return await self._ret(return_status, False, "stream_not_active", phase="advance_stream_session")
        cur_id = current.get("stream_id")
        in_id = cls.get("stream_id")
        if not (isinstance(cur_id, str) and isinstance(in_id, str) and cur_id == in_id):
            return await self._ret(return_status, False, "stream_interrupted", phase="advance_stream_session")

        seq = int(cls.get("stream_seq", 0)) + 1
        phase = "end" if end_stream else "chunk"
        ttl_i = int(ttl if ttl is not None else self.ttl) if end_stream else int(session.get("ttl", self.ttl))
        ts = _now_unix()

        nx = f"{sender_role}_nonce"
        nnot = f"{1-sender_role}_nonce"
        next_session = {
            "sender_role": sender_role,
            "0_nonce": session.get("0_nonce"),
            "1_nonce": session.get("1_nonce"),
            "ts": ts,
            "ttl": ttl_i,
            "history_proof": None,
            "age": int(session.get("age", 0)),
            "mode": "stream",
            "stream": {"id": in_id, "seq": seq, "phase": phase},
            "stream_ttl": None if end_stream else int(stream_ttl),
        }
        next_session[nnot] = session.get(nnot)
        next_session[nx] = secrets.token_hex(16)

        ok = await self._register_session(peer_public_id, local_role=sender_role, session_record=next_session, new=False, use_margin=False)
        if not ok:
            return await self._ret(return_status, False, "register_session_failed", phase="advance_stream_session")
        return await self._ret(return_status, True, "ok", data=next_session, phase="advance_stream_session")

    # -------------------------
    # envelope IO
    # -------------------------

    async def seal_envelope(
        self,
        payload: Optional[Any],
        session: dict,
        to: Optional[dict] = None,
        *,
        id_meta: Optional[Any] = None,
        return_status: bool = False,
    ) -> Any:
        """
        Build a signed envelope.

        If `to` is provided:
        - payload is encrypted under an AEAD key derived from sym_key.
        - the symmetric key sym_key is derived deterministically from:
          X25519(shared(self_priv_enc, to_pub_enc)) and HKDF salt bound to (from,to,session fields).
        - payload AAD is derived from session fields and direction (from=self, to=peer).

        If `to` is None:
        - payload is transmitted in plaintext, but still covered by the envelope signature.
        - session_proof is still required; it is validated against the generic session slot.
        - This is intended for discovery/broadcast, not for per-peer continuity. Reply to a
          discovery message should start a new per-peer session.

        The envelope signature covers the canonical JSON encoding of:
            {"v", "payload", "session_proof", "from", "to"}

        Return behavior:
        - Default: returns `envelope` on success, else `None`.
        - If `return_status=True`: returns `{ok, code, phase, data?}`.
        """
        self._require_custom_verify_for_register()
        if self.public_id is None or self._priv_sig is None:
            raise ValueError("call .id(...) first")
        try:
            _canon_json_bytes(payload)
        except Exception as exc:
            raise ValueError("payload must be JSON-serializable") from exc
        if not isinstance(session, dict):
            return await self._ret(return_status, False, "invalid_session", phase="seal_envelope")
        raw_mode = session.get("mode")
        if raw_mode is not None and raw_mode not in ("single", "stream"):
            return await self._ret(return_status, False, "invalid_stream_mode", phase="seal_envelope")
        sender_role = session.get("sender_role")
        if not isinstance(sender_role, int) or sender_role not in (0, 1):
            return await self._ret(return_status, False, "invalid_session", phase="seal_envelope")
        session_cls = self.classify_session_record(session)
        if not bool(session_cls.get("valid_shape", False)):
            return await self._ret(return_status, False, "invalid_session", phase="seal_envelope")
        if session_cls.get("mode") not in ("single", "stream"):
            return await self._ret(return_status, False, "invalid_stream_mode", phase="seal_envelope")
        if session_cls.get("mode") == "stream":
            if to is None:
                return await self._ret(return_status, False, "stream_mode_unsupported", phase="seal_envelope")
            if not bool(session_cls.get("stream_fields_valid", False)):
                return await self._ret(return_status, False, "invalid_stream_fields", phase="seal_envelope")
            if not bool(session_cls.get("is_stream_end", False)) and not bool(session_cls.get("stream_ttl_valid", False)):
                return await self._ret(return_status, False, "stream_ttl_invalid", phase="seal_envelope")
        elif session.get("stream_ttl") is not None:
            return await self._ret(return_status, False, "invalid_stream_fields", phase="seal_envelope")

        # Outbound: ensure the provided session_proof matches our stored current_link.
        if to is not None:
            verify_public_id(to)
        local_role = sender_role
        current = await self._get_session(to, local_role=local_role)
        # Enforce TTL contract using margin before sending.
        if current is None or self._is_expired(current, use_margin=True):
            return await self._ret(return_status, False, "missing_or_expired_current_link", phase="seal_envelope")
        for k in ("0_nonce", "1_nonce", "ts", "ttl"):
            if session.get(k) != current.get(k):
                return await self._ret(return_status, False, "session_mismatch", phase="seal_envelope")

        out_payload: Any = payload
        if to is not None:
            sym = self._derive_sym_for_peer(to, session, receiver_side=False)
            aad_bytes = self._payload_aad_bytes(to, session, receiver_side=False)
            kp = derive_payload_key(sym, aad_bytes)
            nonce = os.urandom(12)
            ct = AESGCM(kp).encrypt(nonce, _canon_json_bytes(payload), associated_data=aad_bytes)
            out_payload = {"v": PAYLOAD_ENC_VERSION, "nonce": b64_encode(nonce), "ciphertext": b64_encode(ct)}

        if id_meta is not None:
            # Update in-memory identity metadata for this process only.
            base = {
                "created_at": self.public_id.get("created_at"),
                "pub_enc_b64": self.public_id.get("pub_enc_b64"),
                "pub_sig_b64": self.public_id.get("pub_sig_b64"),
                "meta": id_meta,
            }
            self.public_id = sign_public_id(self._priv_sig, base)
            self._id_meta = id_meta

        core = {
            "v": ENV_VERSION,
            "payload": out_payload,
            "session_proof": session,
            "from": self.public_id,
            "to": to,
        }
        sig = sign_bytes(self._priv_sig, _canon_json_bytes(core))
        out = dict(core)
        out["sig"] = sig

        ok = await self._register_session(to, local_role=int(session["sender_role"]), session_record=session, new=False, use_margin=True)
        if not ok:
            return await self._ret(return_status, False, "register_session_failed", phase="seal_envelope")
        return await self._ret(return_status, True, "ok", data=out, phase="seal_envelope")

    async def open_envelope(self, envelope: dict, *, return_status: bool = False) -> Any:
        """
        Verify and open an envelope.

        Steps:
        - Validate envelope structure and version.
        - Verify sender public identity record (self-signed).
        - If `to` is present, verify it matches our identity (by signing public key).
        - Verify envelope signature using sender's signing public key.
        - Verify session continuity using nonce-chain rules.
        - If payload is encrypted, derive sym_key and decrypt using the payload AEAD key.

        Completion point (storage-only):
        - When local_role == 0 and sender_role == 1, the exchange is treated as completed if:
          - current time is within the sender-provided [ts, ts+ttl] window (with margin).
        - A completion marker is stored as `_completed = True` in session_record passed to storage.

        Returns:
        - Default: opened payload if all checks pass, else `None`.
        - If `return_status=True`: `{ok, code, phase, data?}`.

        Notes:
        - If `to` is None, session validation and storage use the generic session slot.
          This is a discovery-only convention and does not establish per-peer continuity.
        """
        self._require_custom_verify_for_register()
        if self.public_id is None or self._priv_enc is None:
            raise ValueError("call .id(...) first")
        if not isinstance(envelope, dict):
            return await self._ret(
                return_status,
                False,
                "invalid_envelope",
                phase="open_envelope",
                event_extra={"validation_stage": "structure"},
            )
        if envelope.get("v") != ENV_VERSION:
            return await self._ret(
                return_status,
                False,
                "invalid_envelope_version",
                phase="open_envelope",
                event_extra={"validation_stage": "structure"},
            )

        validation_stage = "structure"
        try:
            sender = envelope.get("from")
            to = envelope.get("to")
            session = envelope.get("session_proof")
            sig = envelope.get("sig")
            payload_obj = envelope.get("payload")
            sender_role: Optional[int] = None
            local_role: Optional[int] = None
            is_start_form = False
            session_cls: dict[str, Any] = {}
            verify_reason: Optional[str] = None
            peer_fingerprint: Optional[str] = None
            replaced_active_incomplete: Optional[bool] = None
            session_peer: Optional[dict] = None
            current_link: Optional[dict] = None

            def _open_event_extra(code: str, stage: str) -> dict[str, Any]:
                extra: dict[str, Any] = {}
                if code != "ok":
                    extra["validation_stage"] = stage
                if code in ("ok", "session_verify_failed", "replay_detected", "response_window_expired") or str(code).startswith("stream_"):
                    if peer_fingerprint is not None:
                        extra["peer_fingerprint"] = peer_fingerprint
                    if sender_role in (0, 1):
                        extra["sender_role"] = sender_role
                    if local_role in (0, 1):
                        extra["local_role"] = local_role
                    extra["session_form"] = "start" if is_start_form else "continue"
                    # Emit only on committed success so "replaced" means it actually took effect.
                    if code == "ok" and isinstance(replaced_active_incomplete, bool):
                        extra["replaced_active_incomplete"] = replaced_active_incomplete
                    if session_cls:
                        if isinstance(session_cls.get("mode"), str):
                            extra["stream_mode"] = session_cls.get("mode")
                        if isinstance(session_cls.get("stream_id"), str):
                            extra["stream_id"] = session_cls.get("stream_id")
                        if isinstance(session_cls.get("stream_phase"), str):
                            extra["stream_phase"] = session_cls.get("stream_phase")
                        if isinstance(session_cls.get("stream_seq"), int):
                            extra["stream_seq"] = session_cls.get("stream_seq")
                        if isinstance(session_cls.get("stream_ttl_valid"), bool):
                            extra["stream_expired"] = bool(session_cls.get("record_expired", False))
                        sttl = session.get("stream_ttl") if isinstance(session, dict) else None
                        if isinstance(sttl, int):
                            extra["stream_ttl"] = sttl
                        sts = session.get("ts") if isinstance(session, dict) else None
                        if isinstance(sts, int):
                            extra["stream_last_ts"] = sts
                            if bool(session_cls.get("is_stream_start", False)):
                                extra["stream_started_ts"] = sts
                        sseq = session_cls.get("stream_seq")
                        if isinstance(sseq, int) and sseq >= 0:
                            extra["stream_frame_count"] = sseq + 1
                    if isinstance(verify_reason, str) and verify_reason:
                        extra["stream_reason"] = verify_reason
                    if bool(session_cls.get("is_stream", False)):
                        extra["stream_policy"] = "contiguous"
                if code == "replay_detected":
                    extra["replay_store_mode"] = self._replay_store_mode()
                    extra["persist_replay"] = bool(self.persist_replay)
                return extra

            async def _ret_open(
                ok: bool,
                code: str,
                *,
                data: Optional[Any] = None,
                stage: Optional[str] = None,
            ) -> Any:
                stg = stage if isinstance(stage, str) else validation_stage
                return await self._ret(
                    return_status,
                    ok,
                    code,
                    data=data,
                    phase="open_envelope",
                    event_extra=_open_event_extra(code, stg),
                )

            if not (isinstance(sender, dict) and isinstance(session, dict) and isinstance(sig, str)):
                return await _ret_open(False, "invalid_envelope_fields", stage="structure")

            validation_stage = "identity"
            verify_public_id(sender)
            peer_fingerprint = id_fingerprint(sender["pub_sig_b64"])

            if to is not None:
                if not isinstance(to, dict):
                    return await _ret_open(False, "invalid_to_identity", stage="identity")
                verify_public_id(to)
                if to.get("pub_sig_b64") != self.public_id.get("pub_sig_b64"):
                    return await _ret_open(False, "to_identity_mismatch", stage="identity")

            if self.enforce_created_at:
                created_at = sender.get("created_at")
                if isinstance(created_at, str):
                    try:
                        ts_created = _dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        if ts_created.tzinfo is None:
                            ts_created = ts_created.replace(tzinfo=_dt.timezone.utc)
                        if int(session.get("ts", 0)) < int(ts_created.timestamp()):
                            return await _ret_open(False, "created_at_violation", stage="identity")
                    except Exception:
                        return await _ret_open(False, "created_at_parse_error", stage="identity")

            validation_stage = "session"
            if self.max_clock_skew_seconds is not None:
                ts = session.get("ts")
                if not isinstance(ts, int):
                    return await _ret_open(False, "invalid_session_ts", stage="session")
                now = _now_unix()
                if ts > now + int(self.max_clock_skew_seconds):
                    return await _ret_open(False, "clock_skew_violation", stage="session")

            validation_stage = "signature"
            core = {
                "v": ENV_VERSION,
                "payload": payload_obj,
                "session_proof": session,
                "from": sender,
                "to": to,
            }
            verify_bytes(sender["pub_sig_b64"], _canon_json_bytes(core), sig)

            validation_stage = "identity"
            if not await self._peer_key_check(sender):
                return await _ret_open(False, "peer_key_check_failed", stage="identity")

            validation_stage = "session"
            sender_role = int(session.get("sender_role"))
            local_role = 1 - sender_role
            session_cls = self.classify_session_record(session)

            session_peer = None if to is None else sender
            current_link = await self._get_session(session_peer, local_role=local_role)
            is_start_form = bool(session_cls.get("is_start_form", False))
            replaced_active_incomplete = bool(
                is_start_form
                and isinstance(current_link, dict)
                and current_link.get("completed") is not True
                and not self._is_expired(current_link, use_margin=True)
            )

            vr = await self._verify_session(session_peer, local_role=local_role, session_record=session, use_margin=True)
            if not bool(vr.get("ok", False)):
                reason = vr.get("reason")
                verify_reason = reason if isinstance(reason, str) and reason else None
                code = str(vr.get("code", "session_verify_failed"))
                if code in ("stream_ttl_expired", "stream_interrupted"):
                    self._mark_stream_interrupted_fallback(
                        session_peer,
                        int(local_role),
                        session_cls.get("stream_id") if isinstance(session_cls, dict) else None,
                        reason=("timeout_closed" if code == "stream_ttl_expired" else None),
                    )
                return await _ret_open(False, code, stage="session")

            # Contract check for responses: if we are role 0 receiving role 1,
            # ensure our original request window is still valid (with margin).
            current_link = await self._get_session(session_peer, local_role=local_role)
            if local_role == 0 and sender_role == 1:
                # Only enforce original requester TTL at the first responder boundary
                # for stream mode; subsequent stream frames are governed by stream_ttl.
                enforce_boundary = True
                if bool(session_cls.get("is_stream", False)):
                    enforce_boundary = bool(session_cls.get("is_stream_start", False))
                if enforce_boundary:
                    if current_link is None or self._is_expired(current_link, use_margin=True):
                        return await _ret_open(False, "response_window_expired", stage="session")

            validation_stage = "decrypt"
            if isinstance(payload_obj, dict) and payload_obj.get("v") == PAYLOAD_ENC_VERSION:
                if to is None:
                    return await _ret_open(False, "encrypted_payload_without_to", stage="decrypt")
                sym = self._derive_sym_for_peer(sender, session, receiver_side=True)
                aad_bytes = self._payload_aad_bytes(sender, session, receiver_side=True)
                kp = derive_payload_key(sym, aad_bytes)
                nonce = b64_decode(payload_obj["nonce"])
                ct = b64_decode(payload_obj["ciphertext"])
                try:
                    pt = AESGCM(kp).decrypt(nonce, ct, associated_data=aad_bytes)
                except Exception:
                    return await _ret_open(False, "payload_decrypt_failed", stage="decrypt")
                payload = json.loads(pt.decode("utf-8"))
            else:
                payload = payload_obj

            msg_id = self._message_id(sender["pub_sig_b64"], sig)
            ttl_i = int(session.get("ttl", self.ttl))
            validation_stage = "replay"
            if await self._replay_seen(msg_id, ttl_i):
                return await _ret_open(False, "replay_detected", stage="replay")

            # Commit session state only after all validation/decrypt/replay checks pass.
            session_local = session
            session_new = is_start_form

            validation_stage = "commit"
            if local_role == 0 and sender_role == 1:
                if bool(session_cls.get("is_stream", False)) and not bool(session_cls.get("is_stream_end", False)):
                    # Stream is still in-progress; do not finalize completion yet.
                    pass
                else:
                # Use the original request window (current_link) for completion.
                    ts = current_link.get("ts") if isinstance(current_link, dict) else session.get("ts")
                    ttl = current_link.get("ttl") if isinstance(current_link, dict) else session.get("ttl")
                    if isinstance(ts, int) and isinstance(ttl, int):
                        now = _now_unix()
                        if now <= ts + ttl - self.margin:
                            session_local = dict(session)
                            session_local["_completed"] = True
                            session_new = False
                        else:
                            return await _ret_open(False, "response_window_expired", stage="commit")

            ok_commit = await self._register_session(
                session_peer,
                local_role=local_role,
                session_record=session_local,
                new=session_new,
                # Non-end stream frames are governed by stream_ttl and should not be rejected
                # by requester-window ttl during commit persistence.
                use_margin=not (
                    bool(session_cls.get("is_stream", False))
                    and not bool(session_cls.get("is_stream_end", False))
                ),
            )
            if not ok_commit:
                return await _ret_open(False, "register_session_failed", stage="commit")

            await self._replay_add(msg_id, ttl_i)
            await self._mark_peer_verified(sender, via="session")

            return await _ret_open(True, "ok", data=payload, stage="commit")
        except Exception:
            # Fail closed: treat as invalid envelope.
            return await self._ret(
                return_status,
                False,
                "open_envelope_exception",
                phase="open_envelope",
                event_extra={"validation_stage": validation_stage},
            )

    async def verify_discovery_envelope(self, envelope: dict, *, return_status: bool = False) -> Any:
        """
        Verify and learn a discovery/public envelope without session continuity commit.

        Step by step:
        - Validate the envelope structure and sender public identity.
        - Require public discovery semantics: `to=None`, role-0 start-form, non-stream.
        - Verify the envelope signature with the sender signing key.
        - Update peer identity knowledge through the configured peer-key store.
        - Apply replay protection through the configured replay store.

        Returns:
        - Default: plaintext payload if verification succeeds, else `None`.
        - If `return_status=True`: `{ok, code, phase, data?}`.

        Notes:
        - This helper is for discovery/public ingress only. It does not call
          session verification or session registration hooks.
        - Custom `peer_key_store` and `replay_store` hooks are still honored.
        """
        if self.public_id is None or self._priv_enc is None:
            raise ValueError("call .id(...) first")
        if not isinstance(envelope, dict):
            return await self._ret(
                return_status,
                False,
                "invalid_envelope",
                phase="verify_discovery_envelope",
                event_extra={"validation_stage": "structure"},
            )
        if envelope.get("v") != ENV_VERSION:
            return await self._ret(
                return_status,
                False,
                "invalid_envelope_version",
                phase="verify_discovery_envelope",
                event_extra={"validation_stage": "structure"},
            )

        validation_stage = "structure"
        try:
            sender = envelope.get("from")
            to = envelope.get("to")
            session = envelope.get("session_proof")
            sig = envelope.get("sig")
            payload_obj = envelope.get("payload")
            peer_fingerprint: Optional[str] = None
            sender_role: Optional[int] = None
            local_role: Optional[int] = None
            session_cls: dict[str, Any] = {}

            def _discovery_event_extra(code: str, stage: str) -> dict[str, Any]:
                extra: dict[str, Any] = {}
                if code != "ok":
                    extra["validation_stage"] = stage
                if peer_fingerprint is not None:
                    extra["peer_fingerprint"] = peer_fingerprint
                if sender_role in (0, 1):
                    extra["sender_role"] = sender_role
                if local_role in (0, 1):
                    extra["local_role"] = local_role
                if session_cls:
                    extra["session_form"] = "start" if bool(session_cls.get("is_start_form", False)) else "continue"
                    if isinstance(session_cls.get("mode"), str):
                        extra["stream_mode"] = session_cls.get("mode")
                    if isinstance(session_cls.get("stream_id"), str):
                        extra["stream_id"] = session_cls.get("stream_id")
                    if isinstance(session_cls.get("stream_phase"), str):
                        extra["stream_phase"] = session_cls.get("stream_phase")
                    if isinstance(session_cls.get("stream_seq"), int):
                        extra["stream_seq"] = session_cls.get("stream_seq")
                if code == "replay_detected":
                    extra["replay_store_mode"] = self._replay_store_mode()
                    extra["persist_replay"] = bool(self.persist_replay)
                return extra

            async def _ret_discovery(
                ok: bool,
                code: str,
                *,
                data: Optional[Any] = None,
                stage: Optional[str] = None,
            ) -> Any:
                stg = stage if isinstance(stage, str) else validation_stage
                return await self._ret(
                    return_status,
                    ok,
                    code,
                    data=data,
                    phase="verify_discovery_envelope",
                    event_extra=_discovery_event_extra(code, stg),
                )

            if not (isinstance(sender, dict) and isinstance(session, dict) and isinstance(sig, str)):
                return await _ret_discovery(False, "invalid_envelope_fields", stage="structure")

            validation_stage = "identity"
            verify_public_id(sender)
            peer_fingerprint = id_fingerprint(sender["pub_sig_b64"])
            if to is not None:
                return await _ret_discovery(False, "discovery_requires_public_to_none", stage="identity")

            if self.enforce_created_at:
                created_at = sender.get("created_at")
                if isinstance(created_at, str):
                    try:
                        ts_created = _dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        if ts_created.tzinfo is None:
                            ts_created = ts_created.replace(tzinfo=_dt.timezone.utc)
                        if int(session.get("ts", 0)) < int(ts_created.timestamp()):
                            return await _ret_discovery(False, "created_at_violation", stage="identity")
                    except Exception:
                        return await _ret_discovery(False, "created_at_parse_error", stage="identity")

            validation_stage = "session"
            if self.max_clock_skew_seconds is not None:
                ts = session.get("ts")
                if not isinstance(ts, int):
                    return await _ret_discovery(False, "invalid_session_ts", stage="session")
                now = _now_unix()
                if ts > now + int(self.max_clock_skew_seconds):
                    return await _ret_discovery(False, "clock_skew_violation", stage="session")

            session_cls = self.classify_session_record(session)
            if not (isinstance(session_cls, dict) and bool(session_cls.get("valid_shape"))):
                return await _ret_discovery(False, "invalid_session", stage="session")
            try:
                sender_role = int(session.get("sender_role"))
            except Exception:
                return await _ret_discovery(False, "invalid_session", stage="session")
            local_role = 1 - sender_role
            if sender_role != 0 or not bool(session_cls.get("is_start_form")):
                return await _ret_discovery(False, "invalid_session", stage="session")
            if bool(session_cls.get("is_stream")):
                return await _ret_discovery(False, "stream_mode_unsupported", stage="session")

            validation_stage = "signature"
            core = {
                "v": ENV_VERSION,
                "payload": payload_obj,
                "session_proof": session,
                "from": sender,
                "to": to,
            }
            verify_bytes(sender["pub_sig_b64"], _canon_json_bytes(core), sig)

            validation_stage = "identity"
            if not await self._peer_key_check(sender):
                return await _ret_discovery(False, "peer_key_check_failed", stage="identity")

            validation_stage = "decrypt"
            if isinstance(payload_obj, dict) and payload_obj.get("v") == PAYLOAD_ENC_VERSION:
                return await _ret_discovery(False, "encrypted_payload_without_to", stage="decrypt")
            payload = payload_obj

            validation_stage = "replay"
            msg_id = self._message_id(sender["pub_sig_b64"], sig)
            ttl_i = int(session.get("ttl", self.ttl))
            if await self._replay_seen(msg_id, ttl_i):
                return await _ret_discovery(False, "replay_detected", stage="replay")
            await self._replay_add(msg_id, ttl_i)
            await self._mark_peer_verified(sender, via="discovery")

            return await _ret_discovery(True, "ok", data=payload, stage="replay")
        except Exception:
            return await self._ret(
                return_status,
                False,
                "verify_discovery_envelope_exception",
                phase="verify_discovery_envelope",
                event_extra={"validation_stage": validation_stage},
            )

    # -------------------------
    # internal helpers
    # -------------------------

    def _derive_sym_for_peer(self, peer_public_id: dict, session: dict, receiver_side: bool = False) -> bytes:
        """
        Derive sym_key for a given message direction.

        receiver_side:
        - False: we are producing a message from self -> peer
        - True:  we are consuming a message from peer -> self

        This flag ensures both parties bind the HKDF salt to the same (from,to) ordering.
        """
        if self.public_id is None or self._priv_enc is None:
            raise ValueError("call .id(...) first")
        peer_pub_enc = peer_public_id["pub_enc_b64"]

        if receiver_side:
            from_sig = peer_public_id["pub_sig_b64"]
            to_sig = self.public_id["pub_sig_b64"]
        else:
            from_sig = self.public_id["pub_sig_b64"]
            to_sig = peer_public_id["pub_sig_b64"]

        return derive_sym_key(
            priv_enc=self._priv_enc,
            peer_pub_enc_b64=peer_pub_enc,
            from_pub_sig_b64=from_sig,
            to_pub_sig_b64=to_sig,
            session=session,
        )

    def _history_proof_aad_bytes(self, peer_public_id: dict, session: dict, receiver_side: bool) -> bytes:
        """
        Construct AAD for history_proof encryption/decryption.

        history_proof is intended to be validated by the receiver of the start-session proof.
        Therefore, AAD must be bound to the message direction (sender -> receiver), not
        to the local perspective.

        receiver_side:
        - False: we are creating history_proof for self -> peer (start_session side)
        - True:  we are verifying history_proof for peer -> self (receiver side)

        The AAD binds:
        - direction (from,to fingerprints),
        - sender_role,
        - ts and ttl,
        - a domain tag and history_proof version.

        Binding history_proof to these fields prevents it from being reused as a bearer token across:
        - different identities (from/to),
        - different sessions (ts/ttl/nonces indirectly via sym_key and proof),
        - different protocol contexts (domain tag).
        """
        if self.public_id is None:
            raise ValueError("call .id(...) first")

        if receiver_side:
            from_fp = id_fingerprint(peer_public_id["pub_sig_b64"])
            to_fp = id_fingerprint(self.public_id["pub_sig_b64"])
        else:
            from_fp = id_fingerprint(self.public_id["pub_sig_b64"])
            to_fp = id_fingerprint(peer_public_id["pub_sig_b64"])

        aad_obj = {
            "domain": _HISTORY_PROOF_AAD_DOMAIN,
            "from": from_fp,
            "to": to_fp,
            "sender_role": int(session["sender_role"]),
            "ts": int(session["ts"]),
            "ttl": int(session["ttl"]),
            "v": HISTORY_PROOF_VERSION,
        }
        return _canon_json_bytes(aad_obj)

    def _payload_aad_bytes(self, peer_public_id: dict, session: dict, receiver_side: bool) -> bytes:
        """
        Construct AAD for payload encryption/decryption.

        This AAD is direction-sensitive and must match between sender and receiver:
        - sender uses (from=self, to=peer)
        - receiver uses (from=peer, to=self)

        The AAD binds:
        - direction (from/to fingerprints),
        - sender_role,
        - ts and ttl,
        - a domain tag and payload encryption version.

        If any of these fields are modified, decryption fails (integrity).
        """
        if self.public_id is None:
            raise ValueError("call .id(...) first")

        if receiver_side:
            from_fp = id_fingerprint(peer_public_id["pub_sig_b64"])
            to_fp = id_fingerprint(self.public_id["pub_sig_b64"])
        else:
            from_fp = id_fingerprint(self.public_id["pub_sig_b64"])
            to_fp = id_fingerprint(peer_public_id["pub_sig_b64"])

        aad_obj = {
            "domain": _PAYLOAD_AAD_DOMAIN,
            "from": from_fp,
            "to": to_fp,
            "sender_role": int(session["sender_role"]),
            "ts": int(session["ts"]),
            "ttl": int(session["ttl"]),
            "v": PAYLOAD_ENC_VERSION,
        }
        return _canon_json_bytes(aad_obj)

    # -------------------------
    # fallback verify/register logic
    # -------------------------

    def _verify_session_fallback(self, peer_public_id: Optional[dict], local_role: int, session_record: dict, use_margin: bool) -> Any:
        """
        Default continuity verifier.

        Two cases:
        1) Start-form (including reset):
           - Require not(x)_nonce is None and x_nonce is present, where x=sender_role.
           - If history_proof is present, decrypt it and validate it against local history.
           - If history_proof is absent, accept only if we have no history recorded for this peer.
           - If a current_link exists, reject start-form replays of the same nonce.
        2) Ongoing session:
           - Require not(x)_nonce matches stored value.
           - Require x_nonce is fresh (not equal to current and not present in past_chain/seen).
           - Require TTL not exceeded.

        The verifier is intentionally strict. If you want more permissive reset semantics,
        implement a custom verify hook.
        """
        _, rec, current = self._load_fallback_session_record(peer_public_id, local_role)
        current_is_stale = isinstance(current, dict) and self._is_stale_current_link(current, use_margin=use_margin)

        cls = self.classify_session_record(session_record)
        is_start_form = bool(cls.get("is_start_form", False))
        current_for_start_form = None if current_is_stale and is_start_form else current
        # Fresh start-form admission intentionally ignores a stale current_link so
        # that expired state does not block restart. We still retain access to the
        # raw stored link for two narrower cases:
        #   1. reject start-form nonce reuse against the existing current_link, and
        #   2. allow one-step restart convergence when the sender proves
        #      "tip + current_link", even if that current_link is stale locally.
        current_for_restart_convergence = current if is_start_form else current_for_start_form
        if not bool(cls.get("valid_shape")):
            return {"ok": False, "code": "invalid_stream_fields"}
        if cls.get("mode") not in ("single", "stream"):
            return {"ok": False, "code": "invalid_stream_mode"}
        is_stream = bool(cls.get("is_stream"))
        if is_stream and peer_public_id is None:
            return {"ok": False, "code": "stream_mode_unsupported"}
        if is_stream and not bool(cls.get("stream_fields_valid")):
            stream_obj = session_record.get("stream")
            if isinstance(stream_obj, dict):
                phase = stream_obj.get("phase")
                seq = stream_obj.get("seq")
                if phase not in ("start", "chunk", "end"):
                    return {"ok": False, "code": "stream_phase_invalid"}
                if not isinstance(seq, int) or seq < 0:
                    return {"ok": False, "code": "stream_seq_invalid"}
            return {"ok": False, "code": "invalid_stream_fields"}
        if is_stream and not bool(cls.get("is_stream_end")) and not bool(cls.get("stream_ttl_valid")):
            return {"ok": False, "code": "stream_ttl_invalid"}

        sender_role = int(session_record.get("sender_role"))
        x = sender_role
        nx = f"{x}_nonce"
        nnot = f"{1-x}_nonce"

        if is_stream:
            phase = cls.get("stream_phase")
            sid = cls.get("stream_id")
            seq = cls.get("stream_seq")
            cur_sid = current.get("stream_id") if isinstance(current, dict) else None
            cur_active = bool(current.get("stream_active", False)) if isinstance(current, dict) else False
            if phase == "start":
                if current_is_stale:
                    cur_sid = None
                    cur_active = False
                if cur_active:
                    return {"ok": False, "code": "stream_already_active"}
                if seq != 0:
                    return {"ok": False, "code": "stream_seq_invalid"}
            else:
                if not cur_active:
                    if (
                        isinstance(current, dict)
                        and isinstance(cur_sid, str)
                        and cur_sid == sid
                        and current.get("stream_phase") in ("interrupted", "end")
                    ):
                        reason = current.get("stream_reason") if isinstance(current, dict) else None
                        if isinstance(reason, str) and reason:
                            return {"ok": False, "code": "stream_interrupted", "reason": reason}
                        return {"ok": False, "code": "stream_interrupted"}
                    return {"ok": False, "code": "stream_not_active"}
                if not (isinstance(cur_sid, str) and cur_sid == sid):
                    return {"ok": False, "code": "stream_state_conflict"}
                prev_phase = current.get("stream_phase")
                # Active streams may only progress chunk/end after start or chunk.
                if prev_phase in ("start", "chunk") and phase not in ("chunk", "end"):
                    return {"ok": False, "code": "stream_phase_invalid"}
                if prev_phase not in ("start", "chunk"):
                    return {"ok": False, "code": "stream_phase_invalid"}
                expected = current.get("expected_next_seq")
                if isinstance(expected, int) and seq != expected:
                    return {"ok": False, "code": "stream_seq_invalid"}
            # Receiver-side strict stream_ttl check for non-end frames.
            if phase in ("start", "chunk"):
                ts = session_record.get("ts")
                sttl = session_record.get("stream_ttl")
                if not (isinstance(ts, int) and isinstance(sttl, int) and sttl > 0):
                    return {"ok": False, "code": "stream_ttl_invalid"}
                if _now_unix() > (ts + sttl):
                    return {"ok": False, "code": "stream_ttl_expired"}

        # Start-form: allow restart if proof is valid, even if a current_link exists.
        if is_start_form:
            # Reject start-forms that are already expired by their own ts/ttl.
            ts = session_record.get("ts")
            ttl = session_record.get("ttl")
            if not (isinstance(ts, int) and isinstance(ttl, int)):
                return False
            if (not is_stream) and _now_unix() > (ts + ttl - (self.margin if use_margin else 0)):
                return False
            # Reject exact replays of the same start-form nonce, even if current_link expired.
            if isinstance(current_for_restart_convergence, dict):
                x_nonce = session_record.get(nx)
                if x_nonce == current_for_restart_convergence.get(nx):
                    return False
                seen = current_for_restart_convergence.get("seen")
                if isinstance(seen, list) and x_nonce in seen:
                    return False
                past = rec.get("past_chain") if isinstance(rec, dict) else None
                if isinstance(past, list):
                    for it in past:
                        if isinstance(it, dict) and it.get(nx) == x_nonce:
                            return False

            age = session_record.get("age")
            history_proof = session_record.get("history_proof")
            if not isinstance(age, int) or age < 0:
                return False

            if history_proof is None:
                if isinstance(current_for_start_form, dict):
                    return False
                if isinstance(rec, dict) and rec.get("history"):
                    return False
                return True

            if not isinstance(history_proof, dict) or history_proof.get("v") != HISTORY_PROOF_VERSION:
                return False
            if peer_public_id is None or self.public_id is None or self._priv_enc is None:
                return False

            # Derive sym_key and decrypt history proof with direction peer -> self.
            sym = self._derive_sym_for_peer(peer_public_id, session_record, receiver_side=True)
            aad_bytes = self._history_proof_aad_bytes(peer_public_id, session_record, receiver_side=True)
            kx = derive_history_proof_key(sym, aad_bytes)

            try:
                nonce = b64_decode(history_proof["nonce"])
                ct = b64_decode(history_proof["ciphertext"])
                pt = AESGCM(kx).decrypt(nonce, ct, associated_data=aad_bytes)
                obj = json.loads(pt.decode("utf-8"))
            except Exception:
                return False

            if not isinstance(obj, dict):
                return False
            history_hash = obj.get("history_hash")
            if not isinstance(history_hash, str):
                return False

            history = (rec.get("history") if isinstance(rec, dict) else None) or []
            # Case A: proof references current finalized history tip.
            if history:
                last = history[-1]
                if int(last.get("age", -1)) == age and str(last.get("hash")) == history_hash:
                    return True

            # Case B: proof references current_link that is not yet archived locally.
            # This lets role 1 converge when role 0 starts a new session and carries
            # a proof for "tip + current_link".
            if isinstance(current_for_restart_convergence, dict):
                prev = None if not history else str(history[-1]["hash"])
                n0 = current_for_restart_convergence.get("0_nonce")
                n1 = current_for_restart_convergence.get("1_nonce")
                ts = current_for_restart_convergence.get("ts")
                ttl = current_for_restart_convergence.get("ttl")
                if isinstance(n0, str) and isinstance(n1, str) and isinstance(ts, int) and isinstance(ttl, int):
                    cand_hash = hist_next(prev, session_summary(current_for_restart_convergence))
                    cand_age = (int(history[-1]["age"]) if history else 0) + 1
                    if cand_age == age and cand_hash == history_hash:
                        session_record["_finalize_current_on_new"] = True
                        return True
                elif not history:
                    # Incomplete local current with no finalized history: allow reset-to-tip only.
                    reset_hash = _sha256(_HIST_DOMAIN_RESET).hex()
                    if age == 0 and history_hash == reset_hash:
                        return True

            # Bootstrap only if we have neither history nor current_link.
            if not history and not isinstance(current_for_start_form, dict):
                return age == 0
            return False

        # Not start-form: require a live current_link.
        if not isinstance(current, dict):
            return False
        if not (is_stream and cls.get("stream_phase") in ("start", "chunk")) and self._is_expired(current, use_margin=use_margin):
            return False

        # Ongoing session checks
        if session_record.get(nnot) != current.get(nnot):
            return False

        x_nonce = session_record.get(nx)
        if not isinstance(x_nonce, str):
            return False
        if x_nonce == current.get(nx):
            return False

        past = rec.get("past_chain") if isinstance(rec, dict) else None
        if isinstance(past, list):
            for it in past:
                if isinstance(it, dict) and it.get(nx) == x_nonce:
                    return False

        # Extra replay defense: reject if this nonce already appears in current_link.seen list.
        seen = current.get("seen") if isinstance(current, dict) else None
        if isinstance(seen, list) and x_nonce in seen:
            return False

        if not (is_stream and cls.get("stream_phase") in ("start", "chunk")) and self._is_expired(current, use_margin=use_margin):
            return False

        return True

    def _register_session_fallback(self, peer_public_id: Optional[dict], local_role: int, session_record: Optional[dict], new: bool, use_margin: bool) -> bool:
        """
        Default persistence logic.

        Storage record schema (fallback):
        {
          "peer_id": <fingerprint or None>,
          "local_role": 0/1,
          "active": bool,
          "past_chain": [ {"0_nonce":..., "1_nonce":..., "delta_t":...}, ... ],
          "current_link": {"0_nonce":..., "1_nonce":..., "ts":..., "ttl":..., "completed": bool, "seen": [...]} or None,
          "history": [ {"hash":..., "age":..., "ts":...}, ... ],
          "window": <int>,
        }

        Policy highlights:
        - Expiry ends a conversation. History is finalized only if current_link.completed is true.
        - new=True ends the current conversation, finalizes history if completed, then optionally starts a new one.
        - new=False updates current_link; completed links are archived into past_chain before replacement.
        """
        if peer_public_id is None:
            peer_key = f"GENERIC:{int(local_role)}"
            peer_id = None
        else:
            verify_public_id(peer_public_id)
            peer_key = self._sess_key(peer_public_id["pub_sig_b64"], local_role)
            peer_id = id_fingerprint(peer_public_id["pub_sig_b64"])

        force_finalize_current = bool(
            isinstance(session_record, dict)
            and session_record.get("_finalize_current_on_new", False)
        )

        rec = self._sessions.get(peer_key)
        if not isinstance(rec, dict):
            rec = {
                "peer_id": peer_id,
                "local_role": int(local_role),
                "active": False,
                "past_chain": [],
                "current_link": None,
                "history": [],
                "window": 20,
            }

        current = rec.get("current_link")
        incoming_stream_non_end = bool(
            isinstance(session_record, dict)
            and session_record.get("mode") == "stream"
            and isinstance(session_record.get("stream"), dict)
            and (session_record.get("stream") or {}).get("phase") in ("start", "chunk")
        )

        if isinstance(current, dict) and self._is_expired(current, use_margin=use_margin):
            if (not new) and incoming_stream_non_end:
                # For in-progress stream frames, allow continuity persistence to proceed
                # even if requester-window ttl has expired.
                pass
            else:
                if new and force_finalize_current and current.get("completed") is not True:
                    current = dict(current)
                    current["completed"] = True
                    rec["current_link"] = current
                self._finalize_history_if_completed(rec)
                rec["past_chain"] = []
                rec["current_link"] = None
                rec["active"] = False
                self._sessions[peer_key] = rec
                self._save_sessions_fallback()
                if not new:
                    return False
                # For new=True, continue with fresh-session registration after clearing expired state.
                current = None

        if new:
            if force_finalize_current and isinstance(current, dict) and current.get("completed") is not True:
                cur = dict(current)
                cur["completed"] = True
                rec["current_link"] = cur
            self._finalize_history_if_completed(rec)
            rec["past_chain"] = []
            rec["current_link"] = None
            rec["active"] = False

            if session_record is None:
                self._sessions[peer_key] = rec
                self._save_sessions_fallback()
                return True

            sender_role = int(session_record.get("sender_role", local_role))
            x = sender_role
            nx = f"{x}_nonce"
            nnot = f"{1-x}_nonce"
            if session_record.get(nnot) is not None or not isinstance(session_record.get(nx), str):
                return False

            rec["current_link"] = {
                "0_nonce": session_record.get("0_nonce"),
                "1_nonce": session_record.get("1_nonce"),
                "ts": int(session_record.get("ts", _now_unix())),
                "ttl": int(session_record.get("ttl", self.ttl)),
                "completed": False,
                "seen": [session_record.get(nx)],
                "stream_mode": str(session_record.get("mode", "single")),
                "stream_id": ((session_record.get("stream") or {}).get("id") if isinstance(session_record.get("stream"), dict) else None),
                "stream_phase": ((session_record.get("stream") or {}).get("phase") if isinstance(session_record.get("stream"), dict) else None),
                "expected_next_seq": (
                    int((session_record.get("stream") or {}).get("seq", -1)) + 1
                    if isinstance(session_record.get("stream"), dict) else None
                ),
                "stream_active": bool(
                    isinstance(session_record.get("stream"), dict)
                    and (session_record.get("stream") or {}).get("phase") != "end"
                ),
                "stream_last_ts": int(session_record.get("ts", _now_unix())),
                "stream_ttl": session_record.get("stream_ttl"),
                "missing_ranges": [],
            }
            rec["active"] = True
            self._sessions[peer_key] = rec
            self._save_sessions_fallback()
            return True

        if session_record is None:
            return False

        if isinstance(current, dict) and current.get("completed") is True:
            delta_t = max(0, int(session_record.get("ts", _now_unix())) - int(current.get("ts", 0)))
            rec.setdefault("past_chain", [])
            rec["past_chain"].append({"0_nonce": current.get("0_nonce"), "1_nonce": current.get("1_nonce"), "delta_t": delta_t})

        completed = bool(session_record.get("_completed", False))
        seen = current.get("seen") if isinstance(current, dict) else None
        if not isinstance(seen, list):
            seen = []
        nx = f"{int(session_record.get('sender_role'))}_nonce"
        if session_record.get(nx) is not None:
            seen = list(seen) + [session_record.get(nx)]

        rec["current_link"] = {
            "0_nonce": session_record.get("0_nonce"),
            "1_nonce": session_record.get("1_nonce"),
            "ts": int(session_record.get("ts", _now_unix())),
            "ttl": int(session_record.get("ttl", self.ttl)),
            "completed": completed,
            "seen": seen,
            "stream_mode": str(session_record.get("mode", "single")),
            "stream_id": ((session_record.get("stream") or {}).get("id") if isinstance(session_record.get("stream"), dict) else None),
            "stream_phase": ((session_record.get("stream") or {}).get("phase") if isinstance(session_record.get("stream"), dict) else None),
            "expected_next_seq": (
                int((session_record.get("stream") or {}).get("seq", -1)) + 1
                if isinstance(session_record.get("stream"), dict) else None
            ),
            "stream_active": bool(
                isinstance(session_record.get("stream"), dict)
                and (session_record.get("stream") or {}).get("phase") not in ("end", "interrupted")
            ),
            "stream_last_ts": int(session_record.get("ts", _now_unix())),
            "stream_ttl": session_record.get("stream_ttl"),
            "missing_ranges": (current.get("missing_ranges") if isinstance(current.get("missing_ranges"), list) else []),
        }
        rec["active"] = True

        self._sessions[peer_key] = rec
        self._save_sessions_fallback()
        return True

    def _finalize_history_if_completed(self, rec: dict) -> None:
        """
        Append a new history hash if the current_link is marked completed.

        - summary is computed from the completed link.
        - new hash is computed via hist_next(prev, summary).
        - age advances from the last stored finalized age, not from the current
          in-memory list length. This matters when history has been windowed or
          otherwise starts above age 1.
        - window is applied if set to a positive integer.
        """
        cur = rec.get("current_link")
        if not (isinstance(cur, dict) and cur.get("completed") is True):
            return

        summary = session_summary(cur)
        history = rec.get("history") or []
        prev = None if not history else str(history[-1]["hash"])
        new_hash = hist_next(prev, summary)

        if history:
            try:
                new_age = int(history[-1]["age"]) + 1
            except Exception:
                new_age = len(history) + 1
        else:
            new_age = 1
        history.append({"hash": new_hash, "age": new_age, "ts": int(cur.get("ts", 0))})

        window = rec.get("window")
        if isinstance(window, int) and window > 0 and len(history) > window:
            history = history[-window:]

        rec["history"] = history
        # Caller is responsible for clearing current_link/past_chain when ending the conversation.
