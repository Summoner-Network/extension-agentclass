"""Branch-focused stream path tests for SummonerIdentity."""
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

def _pair(tmp_path, *, ttl=120, margin=0):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=ttl, margin=margin)
    bob = SummonerIdentity(ttl=ttl, margin=margin)
    pub_a = alice.id(str(a_dir / 'id.json'))
    pub_b = bob.id(str(b_dir / 'id.json'))
    return (alice, bob, pub_a, pub_b)

def _setup_stream_turn(tmp_path):
    alice, bob, pub_a, pub_b = _pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    return (alice, bob, pub_a, pub_b, s1)

def test_branch_advance_stream_register_session_failed(tmp_path):
    alice, bob, pub_a, _, s1 = _setup_stream_turn(tmp_path)

    @SummonerIdentity.register_session
    def _reg_fail(peer_public_id, local_role, session_record, new=False, use_margin=False):
        return False

    @SummonerIdentity.verify_session
    def _ver_ok(peer_public_id, local_role, session_record, use_margin=False):
        return True
    st = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'register_session_failed'

def test_branch_open_stream_commit_register_session_failed(tmp_path):
    alice, _, _, _ = _pair(tmp_path)
    peer = alice.public_id
    s0 = asyncio.run(alice.start_session(peer))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=peer))
    assert asyncio.run(alice.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(alice.continue_session(peer, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(alice.seal_envelope({'delta': 'p1'}, s1, to=peer))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}

    @SummonerIdentity.verify_session
    def _ver_ok(peer_public_id, local_role, session_record, use_margin=False):
        return True

    @SummonerIdentity.register_session
    def _reg_fail_on_commit(peer_public_id, local_role, session_record, new=False, use_margin=False):
        if isinstance(session_record, dict):
            s = session_record.get('stream')
            if isinstance(s, dict) and int(local_role) == 0:
                return False
        return alice.register_session_default(peer_public_id, local_role, session_record, new=new, use_margin=use_margin)
    s2 = asyncio.run(alice.advance_stream_session(peer, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(alice.seal_envelope({'delta': 'p2'}, s2, to=peer))
    assert isinstance(env2, dict)
    st = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'register_session_failed'

def test_branch_seal_stream_missing_or_expired_current_link_and_session_mismatch(tmp_path):
    alice, bob, pub_a, pub_b = _pair(tmp_path, ttl=1, margin=0)
    s_missing = {'sender_role': 1, '0_nonce': 'aa' * 16, '1_nonce': 'bb' * 16, 'ts': 1, 'ttl': 60, 'history_proof': None, 'age': 0, 'mode': 'stream', 'stream': {'id': 'x', 'seq': 0, 'phase': 'start'}, 'stream_ttl': 30}
    st_missing = asyncio.run(bob.seal_envelope({'delta': 'x'}, s_missing, to=pub_a, return_status=True))
    assert st_missing['ok'] is False
    assert st_missing['code'] == 'missing_or_expired_current_link'
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    bad = dict(s1)
    bad['ttl'] = int(bad['ttl']) + 1
    st_mismatch = asyncio.run(bob.seal_envelope({'delta': 'bad'}, bad, to=pub_a, return_status=True))
    assert st_mismatch['ok'] is False
    assert st_mismatch['code'] == 'session_mismatch'

def test_branch_normalize_verify_result_invalid_type_maps_to_session_verify_failed(tmp_path):
    alice, bob, pub_a, pub_b = _pair(tmp_path)

    @SummonerIdentity.verify_session
    def _bad_verify(peer_public_id, local_role, session_record, use_margin=False):
        return ['not', 'valid']
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    st = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'session_verify_failed'

def test_branch_stream_optional_telemetry_fields_are_whitelisted(tmp_path):
    alice, _, _, _ = _pair(tmp_path)
    got = {}

    @alice.on_policy_event(phase='open_envelope')
    def _on_open(name, ctx):
        if name == 'stream_interrupted':
            got.update(ctx)
    asyncio.run(alice._ret(True, False, 'stream_interrupted', phase='open_envelope', event_extra={'stream_started_ts': 100, 'stream_last_ts': 111, 'stream_frame_count': 3}))
    assert got.get('stream_started_ts') == 100
    assert got.get('stream_last_ts') == 111
    assert got.get('stream_frame_count') == 3
