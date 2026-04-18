"""Custom-handler matrix tests for stream behavior."""
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
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._reset_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None
    SummonerIdentity._peer_key_store_handler = None
    SummonerIdentity._replay_store_handler = None
    yield
    SummonerIdentity._register_session_handler = None
    SummonerIdentity._reset_session_handler = None
    SummonerIdentity._verify_session_handler = None
    SummonerIdentity._get_session_handler = None
    SummonerIdentity._peer_key_store_handler = None
    SummonerIdentity._replay_store_handler = None

def _pair(tmp_path):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    a = SummonerIdentity(ttl=120, margin=0)
    b = SummonerIdentity(ttl=120, margin=0)
    pub_a = a.id(str(a_dir / 'id.json'))
    pub_b = b.id(str(b_dir / 'id.json'))
    return (a, b, pub_a, pub_b)

def test_custom_register_get_verify_default_delegation_supports_stream(tmp_path):
    """
    Custom register/get/verify hooks that delegate to defaults should preserve stream behavior.
    """
    alice, _, _, _ = _pair(tmp_path)
    peer = alice.public_id

    @SummonerIdentity.register_session
    def _reg(peer_public_id, local_role, session_record, new=False, use_margin=False):
        return alice.register_session_default(peer_public_id, local_role, session_record, new=new, use_margin=use_margin)

    @SummonerIdentity.get_session
    def _get(peer_public_id, local_role):
        return alice.get_session_default(peer_public_id, local_role)

    @SummonerIdentity.verify_session
    def _ver(peer_public_id, local_role, session_record, use_margin=False):
        return alice.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)
    s0 = asyncio.run(alice.start_session(peer))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=peer))
    assert asyncio.run(alice.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(alice.continue_session(peer, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(alice.seal_envelope({'delta': 'p1'}, s1, to=peer))
    out = asyncio.run(alice.open_envelope(env1, return_status=True))
    assert out['ok'] is True

def test_custom_verify_malformed_result_fails_closed(tmp_path):
    alice, bob, pub_a, pub_b = _pair(tmp_path)

    @SummonerIdentity.verify_session
    def _bad_verify(peer_public_id, local_role, session_record, use_margin=False):
        return {'code': 'nope'}
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    st = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'session_verify_failed'

def test_custom_replay_store_detects_stream_replay(tmp_path):
    alice, bob, pub_a, pub_b = _pair(tmp_path)
    items = {}

    @SummonerIdentity.replay_store
    def _replay(message_id, ttl, now, add=False):
        if add:
            items[message_id] = now + max(1, int(ttl))
            return True
        exp = items.get(message_id)
        return isinstance(exp, int) and now <= exp

    @SummonerIdentity.verify_session
    def _always_true(peer_public_id, local_role, session_record, use_margin=False):
        return True
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    st = asyncio.run(alice.open_envelope(env1, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'replay_detected'

def test_custom_register_without_verify_still_raises_for_stream_paths(tmp_path):
    alice, _, _, pub_b = _pair(tmp_path)

    @SummonerIdentity.register_session
    def _reg_only(peer_public_id, local_role, session_record, new=False, use_margin=False):
        return True
    with pytest.raises(ValueError):
        asyncio.run(alice.start_session(pub_b))
