"""Core happy-path and replay behavior tests for SummonerIdentity."""
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, id_fingerprint

def _make_pair(tmp_path):
    """Create isolated Alice/Bob identities and SummonerIdentity objects."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0)
    identity_b = SummonerIdentity(ttl=60, margin=0)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b)

def test_encrypted_roundtrip_and_completion(tmp_path):
    """Roundtrip encrypted exchange should succeed and mark role-0 link as completed."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    s1 = asyncio.run(identity_b.continue_session(pub_a, env1['session_proof']))
    env2 = asyncio.run(identity_b.seal_envelope({'msg': 'ack'}, s1, to=pub_a))
    assert asyncio.run(identity_a.open_envelope(env2)) == {'msg': 'ack'}
    key = f"{id_fingerprint(pub_b['pub_sig_b64'])}:0"
    rec = identity_a._sessions.get(key)
    assert rec is not None
    assert rec['current_link']['completed'] is True

def test_history_proof_continuity_proof_roundtrip(tmp_path):
    """After one completed exchange, next start should carry history_proof and be accepted."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    s1 = asyncio.run(identity_b.continue_session(pub_a, env1['session_proof']))
    env2 = asyncio.run(identity_b.seal_envelope({'msg': 'ack'}, s1, to=pub_a))
    assert asyncio.run(identity_a.open_envelope(env2)) == {'msg': 'ack'}
    s2 = asyncio.run(identity_a.start_session(pub_b))
    assert isinstance(s2.get('history_proof'), dict)
    env3 = asyncio.run(identity_a.seal_envelope({'msg': 'new'}, s2, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env3)) == {'msg': 'new'}

def test_replay_same_message_rejected(tmp_path):
    """Exact envelope replay should be rejected by continuity/replay defenses."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    assert asyncio.run(identity_b.open_envelope(env1)) is None
