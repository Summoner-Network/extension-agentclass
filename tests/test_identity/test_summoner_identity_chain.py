"""Session-chain invariants and contract behavior tests for SummonerIdentity."""
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, id_fingerprint

def _make_pair(tmp_path):
    """Create isolated pair used for chain/continuity tests."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0)
    identity_b = SummonerIdentity(ttl=60, margin=0)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b)

def test_open_envelope_requires_advancement(tmp_path):
    """Receiver should reject reuse of the same session proof (no nonce advancement)."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    env1_replay = asyncio.run(identity_a.seal_envelope({'msg': 'hi-again'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1_replay)) is None

def test_continue_session_requires_match_not_advance(tmp_path):
    """`continue_session` expects exact current peer proof, not an already-advanced one."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    s0_advanced = dict(env1['session_proof'])
    s0_advanced['0_nonce'] = 'f' * 32
    assert asyncio.run(identity_b.continue_session(pub_a, s0_advanced)) is None
    s1 = asyncio.run(identity_b.continue_session(pub_a, env1['session_proof']))
    assert s1 is not None

def test_start_form_reset_accepted_and_replay_rejected(tmp_path):
    """Valid reset start-form is accepted once; replay of that same start-form is rejected."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    s1 = asyncio.run(identity_b.continue_session(pub_a, env1['session_proof']))
    env2 = asyncio.run(identity_b.seal_envelope({'msg': 'ack'}, s1, to=pub_a))
    assert asyncio.run(identity_a.open_envelope(env2)) == {'msg': 'ack'}
    s2 = asyncio.run(identity_a.start_session(pub_b))
    env3 = asyncio.run(identity_a.seal_envelope({'msg': 'new'}, s2, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env3)) == {'msg': 'new'}
    env3_replay = asyncio.run(identity_a.seal_envelope({'msg': 'new-again'}, s2, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env3_replay)) is None

def test_public_hello_requires_session_proof(tmp_path):
    """Public `to=None` messages still require and validate a session proof."""
    identity_a, identity_b, _, _ = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(None))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hello'}, s0, to=None))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hello'}

def test_ttl_expiry_forces_reset(tmp_path):
    """After receiver-side expiry, stale message is rejected and a fresh reset start is accepted."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    key = f"{id_fingerprint(pub_a['pub_sig_b64'])}:1"
    rec = identity_b._sessions.get(key)
    assert rec is not None
    rec['current_link']['ts'] = 0
    rec['current_link']['ttl'] = 1
    identity_b._sessions[key] = rec
    assert asyncio.run(identity_b.open_envelope(env1)) is None
    s2 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    env2 = asyncio.run(identity_a.seal_envelope({'msg': 'reset'}, s2, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env2)) == {'msg': 'reset'}

def test_continue_session_role1_expired_gives_up(tmp_path):
    """Role-1 continuation should fail closed when local role-1 link is expired/missing."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    key = f"{id_fingerprint(pub_a['pub_sig_b64'])}:1"
    rec = identity_b._sessions.get(key)
    assert rec is not None
    rec['current_link']['ts'] = 0
    rec['current_link']['ttl'] = 1
    identity_b._sessions[key] = rec
    assert asyncio.run(identity_b.continue_session(pub_a, env1['session_proof'])) is None

def test_continue_session_role0_expired_restarts(tmp_path):
    """Role-0 continuation may restart as new role-0 start when prior role-0 link expired."""
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
    rec['current_link']['ts'] = 0
    rec['current_link']['ttl'] = 1
    identity_a._sessions[key] = rec
    s2 = asyncio.run(identity_a.continue_session(pub_b, env2['session_proof']))
    assert s2 is not None
    assert s2['sender_role'] == 0
    assert s2['1_nonce'] is None

def test_open_envelope_rejects_late_response_by_contract(tmp_path):
    """Late role-1 response outside original role-0 request window should be rejected."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    s1 = asyncio.run(identity_b.continue_session(pub_a, env1['session_proof']))
    env2 = asyncio.run(identity_b.seal_envelope({'msg': 'ack'}, s1, to=pub_a))
    key = f"{id_fingerprint(pub_b['pub_sig_b64'])}:0"
    rec = identity_a._sessions.get(key)
    assert rec is not None
    rec['current_link']['ts'] = 0
    rec['current_link']['ttl'] = 1
    identity_a._sessions[key] = rec
    assert asyncio.run(identity_a.open_envelope(env2)) is None
