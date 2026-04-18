"""Persistence and restart behavior tests for streaming SummonerIdentity flows."""
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

def _mk_store_pair(tmp_path, *, persist_replay=False):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(store_dir=str(a_dir), persist_local=True, load_local=True, persist_replay=persist_replay, ttl=120, margin=0)
    bob = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True, persist_replay=persist_replay, ttl=120, margin=0)
    pub_a = alice.id(str(a_dir / 'id.json'))
    pub_b = bob.id(str(b_dir / 'id.json'))
    return (alice, bob, pub_a, pub_b, a_dir, b_dir)

def test_stream_state_persists_and_can_advance_after_restart(tmp_path):
    alice, bob, pub_a, pub_b, _, b_dir = _mk_store_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    bob2 = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True, ttl=120, margin=0)
    bob2.id(str(b_dir / 'id.json'))
    key = f"{id_fingerprint(pub_a['pub_sig_b64'])}:1"
    rec = bob2._sessions.get(key)
    assert isinstance(rec, dict)
    current = rec.get('current_link')
    assert isinstance(current, dict)
    assert current.get('stream_active') is True
    assert isinstance(current.get('expected_next_seq'), int)
    s2 = asyncio.run(bob2.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob2.seal_envelope({'delta': 'p2'}, s2, to=pub_a))
    assert asyncio.run(alice.open_envelope(env2)) == {'delta': 'p2'}

def test_stream_end_closure_persists_and_blocks_further_advance_after_restart(tmp_path):
    alice, bob, pub_a, pub_b, _, b_dir = _mk_store_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    s_mid = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env_mid = asyncio.run(bob.seal_envelope({'delta': 'p2'}, s_mid, to=pub_a))
    assert asyncio.run(alice.open_envelope(env_mid)) == {'delta': 'p2'}
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s_mid, end_stream=True, ttl=120))
    env2 = asyncio.run(bob.seal_envelope({'done': True}, s2, to=pub_a))
    st_end = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st_end['ok'] is True
    bob2 = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True, ttl=120, margin=0)
    bob2.id(str(b_dir / 'id.json'))
    st = asyncio.run(bob2.advance_stream_session(pub_a, s2, end_stream=False, stream_ttl=30, return_status=True))
    assert st['ok'] is False
    assert st['code'] in ('stream_not_active', 'stream_interrupted')

def test_stream_replay_rejected_after_receiver_restart_with_persisted_replay(tmp_path):
    alice, bob, pub_a, pub_b, a_dir, b_dir = _mk_store_pair(tmp_path, persist_replay=True)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    bob2 = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True, persist_replay=True, ttl=120, margin=0)
    bob2.id(str(b_dir / 'id.json'))
    st = asyncio.run(bob2.open_envelope(env0, return_status=True))
    assert st['ok'] is False
    assert st['code'] in ('replay_detected', 'session_verify_failed')

def test_stream_persistence_files_written(tmp_path):
    alice, bob, pub_a, pub_b, a_dir, b_dir = _mk_store_pair(tmp_path, persist_replay=True)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    assert (a_dir / 'sessions.json').exists()
    assert (a_dir / 'peer_keys.json').exists()
    assert (a_dir / 'replay.json').exists()
    assert (b_dir / 'sessions.json').exists()

def test_generic_discovery_open_succeeds_after_receiver_restart_with_expired_current_link(tmp_path):
    alice, bob, _, _, _, b_dir = _mk_store_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(None))
    env0 = asyncio.run(alice.seal_envelope(None, s0, to=None))
    assert asyncio.run(bob.open_envelope(env0)) is None
    rec = bob._sessions.get('GENERIC:1')
    assert isinstance(rec, dict)
    assert isinstance(rec.get('current_link'), dict)
    rec['current_link']['ts'] = 0
    rec['current_link']['ttl'] = 1
    bob._sessions['GENERIC:1'] = rec
    bob._save_sessions_fallback()
    bob2 = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True, ttl=120, margin=0)
    bob2.id(str(b_dir / 'id.json'))
    s1 = asyncio.run(alice.start_session(None, force_reset=True))
    env1 = asyncio.run(alice.seal_envelope(None, s1, to=None))
    st = asyncio.run(bob2.open_envelope(env1, return_status=True))
    assert st['ok'] is True
    assert st['code'] == 'ok'

def test_initiator_stream_restart_succeeds_after_both_sides_reload_expired_state(tmp_path):
    alice, bob, pub_a, pub_b, a_dir, b_dir = _mk_store_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b, stream=True, stream_ttl=30))
    env0 = asyncio.run(alice.seal_envelope({'delta': 'part-1'}, s0, to=pub_b))
    st0 = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st0['ok'] is True

    a_key = f"{id_fingerprint(pub_b['pub_sig_b64'])}:0"
    a_rec = alice._sessions.get(a_key)
    assert isinstance(a_rec, dict)
    assert isinstance(a_rec.get('current_link'), dict)
    a_rec['current_link']['ts'] = 0
    a_rec['current_link']['ttl'] = 1
    a_rec['current_link']['stream_last_ts'] = 0
    a_rec['current_link']['stream_ttl'] = 1
    alice._sessions[a_key] = a_rec
    alice._save_sessions_fallback()

    b_key = f"{id_fingerprint(pub_a['pub_sig_b64'])}:1"
    b_rec = bob._sessions.get(b_key)
    assert isinstance(b_rec, dict)
    assert isinstance(b_rec.get('current_link'), dict)
    b_rec['current_link']['ts'] = 0
    b_rec['current_link']['ttl'] = 1
    b_rec['current_link']['stream_last_ts'] = 0
    b_rec['current_link']['stream_ttl'] = 1
    bob._sessions[b_key] = b_rec
    bob._save_sessions_fallback()

    alice2 = SummonerIdentity(store_dir=str(a_dir), persist_local=True, load_local=True, ttl=120, margin=0)
    bob2 = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True, ttl=120, margin=0)
    alice2.id(str(a_dir / 'id.json'))
    bob2.id(str(b_dir / 'id.json'))

    s1 = asyncio.run(alice2.start_session(pub_b, stream=True, stream_ttl=30, return_status=True))
    assert s1['ok'] is True
    env1 = asyncio.run(alice2.seal_envelope({'delta': 'fresh-start'}, s1['data'], to=pub_b))
    st1 = asyncio.run(bob2.open_envelope(env1, return_status=True))
    assert st1['ok'] is True

def test_role1_restart_converges_stale_current_link_from_new_start(tmp_path):
    """Receiver-side stale current_link should still converge when sender proves tip+current."""
    alice, bob, pub_a, pub_b, a_dir, b_dir = _mk_store_pair(tmp_path)

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}

    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof']))
    env1 = asyncio.run(bob.seal_envelope({'msg': 'reply'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'msg': 'reply'}

    a_key = f"{id_fingerprint(pub_b['pub_sig_b64'])}:0"
    b_key = f"{id_fingerprint(pub_a['pub_sig_b64'])}:1"

    a_rec = alice._sessions.get(a_key)
    b_rec = bob._sessions.get(b_key)
    assert isinstance(a_rec, dict) and isinstance(a_rec.get('current_link'), dict)
    assert isinstance(b_rec, dict) and isinstance(b_rec.get('current_link'), dict)
    assert a_rec['current_link'].get('completed') is True
    assert b_rec['current_link'].get('completed') is False

    a_rec['current_link']['ts'] = 0
    a_rec['current_link']['ttl'] = 1
    alice._sessions[a_key] = a_rec
    alice._save_sessions_fallback()

    b_rec['current_link']['ts'] = 0
    b_rec['current_link']['ttl'] = 1
    bob._sessions[b_key] = b_rec
    bob._save_sessions_fallback()

    alice2 = SummonerIdentity(store_dir=str(a_dir), persist_local=True, load_local=True, ttl=120, margin=0)
    bob2 = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True, ttl=120, margin=0)
    alice2.id(str(a_dir / 'id.json'))
    bob2.id(str(b_dir / 'id.json'))

    s2 = asyncio.run(alice2.start_session(pub_b, return_status=True))
    assert s2['ok'] is True
    env2 = asyncio.run(alice2.seal_envelope({'msg': 'restart'}, s2['data'], to=pub_b))
    st2 = asyncio.run(bob2.open_envelope(env2, return_status=True))
    assert st2['ok'] is True
    assert st2['code'] == 'ok'

    b_after = bob2._sessions.get(b_key) or {}
    history = b_after.get('history') or []
    assert len(history) == 1
    assert history[-1].get('age') == 1
    current_after = b_after.get('current_link') or {}
    assert current_after.get('0_nonce') == s2['data'].get('0_nonce')
    assert current_after.get('completed') is False
