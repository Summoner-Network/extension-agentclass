"""Misuse and malformed-input tests for SummonerIdentity."""
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity

@pytest.fixture(autouse=True)
def _reset_class_hooks():
    """Reset global hooks to keep misuse tests isolated."""
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None
    yield
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None

def _make_pair(tmp_path):
    """Create isolated Alice/Bob pair for misuse tests."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0)
    identity_b = SummonerIdentity(ttl=60, margin=0)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b)

def _make_triple(tmp_path):
    """Create isolated Alice/Bob/Charlie set for cross-peer misuse scenarios."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    c_dir = tmp_path / 'c'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    c_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0)
    identity_b = SummonerIdentity(ttl=60, margin=0)
    identity_c = SummonerIdentity(ttl=60, margin=0)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    pub_c = identity_c.id(str(c_dir / 'id.json'))
    return (identity_a, identity_b, identity_c, pub_a, pub_b, pub_c)

def test_signature_identity_mismatch_rejected(tmp_path):
    """Replacing `from` identity without matching signature must be rejected."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    identity_x = SummonerIdentity()
    pub_x = identity_x.id(str(tmp_path / 'x' / 'id.json'))
    tampered = dict(env)
    tampered['from'] = pub_x
    assert asyncio.run(identity_b.open_envelope(tampered)) is None

def test_history_proof_replay_across_peers_rejected(tmp_path):
    """Envelope replay to a different peer identity should fail integrity checks."""
    identity_a, identity_b, identity_c, pub_a, pub_b, pub_c = _make_triple(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env_ab = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env_ab)) == {'msg': 'hi'}
    env_ac = dict(env_ab)
    env_ac['to'] = pub_c
    assert asyncio.run(identity_c.open_envelope(env_ac)) is None

def test_cross_direction_swap_rejected(tmp_path):
    """Swapping from/to identities should invalidate signature and be rejected."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    swapped = dict(env)
    swapped['from'] = pub_b
    swapped['to'] = pub_a
    assert asyncio.run(identity_b.open_envelope(swapped)) is None

@pytest.mark.parametrize('mutator', [lambda e: {**e, 'sig': 123}, lambda e: {k: v for k, v in e.items() if k != 'sig'}, lambda e: {**e, 'session_proof': 'nope'}, lambda e: {**e, 'from': 'nope'}, lambda e: {**e, 'payload': 'nope'}])
def test_malformed_envelope_soft_fail(tmp_path, mutator):
    """Malformed envelopes must fail closed with `None`, without raising."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    bad = mutator(env)
    assert asyncio.run(identity_b.open_envelope(bad)) is None
