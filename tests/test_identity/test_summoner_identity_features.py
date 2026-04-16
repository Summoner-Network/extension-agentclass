"""Feature and hardening tests for SummonerIdentity behavior toggles and hooks."""
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity

def _flip_first_char(s: str) -> str:
    """Return a deterministically modified string that always differs from input."""
    if not isinstance(s, str) or not s:
        return 'B'
    c0 = s[0]
    return ('B' if c0 == 'A' else 'A') + s[1:]

def _make_pair(tmp_path, *, enforce_created_at: bool=False):
    """Create test pair with optional created_at enforcement enabled."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0, enforce_created_at=enforce_created_at)
    identity_b = SummonerIdentity(ttl=60, margin=0, enforce_created_at=enforce_created_at)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b)

@pytest.fixture(autouse=True)
def _reset_class_hooks():
    """Ensure class-level hooks are reset between tests to avoid cross-test leakage."""
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None
    yield
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None

def test_signature_tamper_rejected(tmp_path):
    """Envelope signature tampering should cause receiver rejection."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}
    tampered = dict(env)
    tampered['sig'] = _flip_first_char(tampered['sig'])
    assert asyncio.run(identity_b.open_envelope(tampered)) is None

def test_payload_aad_binding_rejects_session_proof_tamper(tmp_path):
    """Tampering session fields without re-signing must fail signature/AAD validation."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    tampered = dict(env)
    tampered['session_proof'] = dict(env['session_proof'])
    tampered['session_proof']['ttl'] = tampered['session_proof']['ttl'] + 1
    assert asyncio.run(identity_b.open_envelope(tampered)) is None

def test_enforce_created_at_blocks_earlier_ts(tmp_path):
    """When enabled, receiver rejects session timestamps earlier than sender created_at."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path, enforce_created_at=True)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    s0['ts'] = 0
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) is None

def test_custom_register_without_verify_raises(tmp_path):
    """Custom register hook without verify hook must raise for safety."""
    identity_a, _, _, pub_b = _make_pair(tmp_path)

    @SummonerIdentity.register_session
    def _custom_register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        return True
    with pytest.raises(ValueError):
        asyncio.run(identity_a.start_session(pub_b))

def test_history_proof_mismatch_rejected(tmp_path):
    """Receiver rejects start-form when history_proof decrypt/match fails."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    s1 = asyncio.run(identity_b.continue_session(pub_a, env1['session_proof']))
    env2 = asyncio.run(identity_b.seal_envelope({'msg': 'ack'}, s1, to=pub_a))
    assert asyncio.run(identity_a.open_envelope(env2)) == {'msg': 'ack'}
    s2 = asyncio.run(identity_a.start_session(pub_b))
    assert isinstance(s2.get('history_proof'), dict)
    bad = dict(s2)
    bad['history_proof'] = dict(s2['history_proof'])
    bad['history_proof']['ciphertext'] = _flip_first_char(bad['history_proof']['ciphertext'])
    env3 = asyncio.run(identity_a.seal_envelope({'msg': 'new'}, bad, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env3)) is None

def test_history_proof_bootstrap_when_local_history_empty(tmp_path):
    """Bootstrap continuity is allowed when receiver has no local history/current link."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    assert isinstance(s0.get('history_proof'), dict)
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}

def test_public_discovery_does_not_establish_per_peer_continuity(tmp_path):
    """Public discovery session must not be continued as a per-peer chain directly."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(None))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hello'}, s0, to=None))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hello'}
    assert asyncio.run(identity_b.continue_session(pub_a, env1['session_proof'])) is None
    s1 = asyncio.run(identity_b.start_session(pub_a))
    env2 = asyncio.run(identity_b.seal_envelope({'msg': 'ack'}, s1, to=pub_a))
    assert asyncio.run(identity_a.open_envelope(env2)) == {'msg': 'ack'}


def test_payload_none_roundtrip_public(tmp_path):
    """Public/plain payload may be None and should roundtrip unchanged."""
    identity_a, identity_b, _, _ = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(None))
    env = asyncio.run(identity_a.seal_envelope(None, s0, to=None))
    assert asyncio.run(identity_b.open_envelope(env)) is None


def test_payload_list_roundtrip_encrypted(tmp_path):
    """Encrypted payload may be a JSON list and should roundtrip unchanged."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    payload = ["hello", 1, {"ok": True}, None]
    env = asyncio.run(identity_a.seal_envelope(payload, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == payload


def test_payload_must_be_json_serializable(tmp_path):
    """Non-JSON payload should fail fast in seal_envelope."""
    identity_a, _, _, _ = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(None))
    with pytest.raises(ValueError):
        asyncio.run(identity_a.seal_envelope(object(), s0, to=None))


def test_payload_none_disambiguates_with_return_status(tmp_path):
    """When payload is None, return_status=True disambiguates success from failure."""
    identity_a, identity_b, _, _ = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(None))
    env = asyncio.run(identity_a.seal_envelope(None, s0, to=None))
    st = asyncio.run(identity_b.open_envelope(env, return_status=True))
    assert isinstance(st, dict)
    assert st.get("ok") is True
    assert st.get("code") == "ok"
    assert st.get("data") is None
