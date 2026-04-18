"""Pressure-style robustness tests for replay and malformed-input bursts."""
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, id_fingerprint

@pytest.fixture(autouse=True)
def _reset_class_hooks():
    """Reset hooks around each pressure test."""
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None
    yield
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None

def _make_pair(tmp_path):
    """Create isolated pair for pressure scenarios."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0)
    identity_b = SummonerIdentity(ttl=60, margin=0)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b)

def test_replay_pressure_does_not_corrupt_state(tmp_path):
    """Repeated replay attempts should not mutate stored current link state."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}
    key = f"{id_fingerprint(pub_a['pub_sig_b64'])}:1"
    before = identity_b._sessions.get(key)['current_link'].copy()
    for _ in range(25):
        assert asyncio.run(identity_b.open_envelope(env)) is None
    after = identity_b._sessions.get(key)['current_link'].copy()
    assert before == after

def test_many_invalid_envelopes_do_not_crash(tmp_path):
    """A burst of malformed envelopes should fail safely and not crash receiver."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    variants = []
    variants.append({**env, 'sig': 'A'})
    variants.append({**env, 'payload': {'v': 'payload.enc.v1'}})
    variants.append({**env, 'session_proof': {'sender_role': 'x'}})
    variants.append({**env, 'from': None})
    for v in variants:
        assert asyncio.run(identity_b.open_envelope(v)) is None
