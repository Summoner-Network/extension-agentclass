"""Focused stream event-matrix tests for edge-case coverage."""
import copy
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity
from tooling.aurora.identity import sign_bytes
from tooling.aurora.identity.identity import _canon_json_bytes

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

def _make_pair(tmp_path, *, ttl=120, margin=0):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=ttl, margin=margin)
    bob = SummonerIdentity(ttl=ttl, margin=margin)
    pub_a = alice.id(str(a_dir / 'id.json'))
    pub_b = bob.id(str(b_dir / 'id.json'))
    return (alice, bob, pub_a, pub_b)

def _resign(sender: SummonerIdentity, env: dict, session_override: dict) -> dict:
    out = copy.deepcopy(env)
    out['session_proof'] = session_override
    core = {'v': out['v'], 'payload': out['payload'], 'session_proof': out['session_proof'], 'from': out['from'], 'to': out['to']}
    out['sig'] = sign_bytes(sender._priv_sig, _canon_json_bytes(core))
    return out

def _setup_stream(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=120, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    return (alice, bob, pub_a, pub_b, s1)

def test_v4_case_b_local_role1_continue_after_timeout_fails(tmp_path, monkeypatch):
    """
    v4 14.10 Case B style: local_role=1 after timeout should fail continue path.
    """
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=1, margin=0)
    s0 = asyncio.run(bob.start_session(pub_a, stream=True, stream_ttl=5))
    env0 = asyncio.run(bob.seal_envelope({'delta': 'start'}, s0, to=pub_a))
    assert asyncio.run(alice.open_envelope(env0)) == {'delta': 'start'}
    ts0 = int(s0['ts'])
    monkeypatch.setattr("tooling.aurora.identity.identity._now_unix", lambda: ts0 + 6)
    st_timeout = asyncio.run(alice.open_envelope(env0, return_status=True))
    assert st_timeout['ok'] is False
    assert st_timeout['code'] in ('stream_ttl_expired', 'replay_detected', 'stream_already_active')
    st = asyncio.run(alice.continue_session(pub_b, env0['session_proof'], stream=False, return_status=True))
    assert st['ok'] is False
    assert st['code'] in ('missing_or_expired_current_link', 'stream_interrupted', 'peer_session_mismatch', 'stream_active_continue_blocked')

def test_v4_event_matrix_continue_stream_none_peer_unsupported(tmp_path):
    alice, _, _, _ = _make_pair(tmp_path)
    peer_session = {'sender_role': 0, '0_nonce': 'aa' * 16, '1_nonce': None, 'ts': 1, 'ttl': 60, 'history_proof': None, 'age': 0}
    st = asyncio.run(alice.continue_session(None, peer_session, stream=True, stream_ttl=30, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_mode_unsupported'

def test_v4_event_matrix_advance_none_peer_unsupported(tmp_path):
    alice, _, _, _ = _make_pair(tmp_path)
    session = {'sender_role': 0, '0_nonce': 'aa' * 16, '1_nonce': None, 'ts': 1, 'ttl': 60, 'history_proof': None, 'age': 0, 'mode': 'stream', 'stream': {'id': 'x', 'seq': 0, 'phase': 'start'}, 'stream_ttl': 30}
    st = asyncio.run(alice.advance_stream_session(None, session, end_stream=False, stream_ttl=30, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_mode_unsupported'

def test_v4_event_matrix_seal_invalid_stream_mode_explicit(tmp_path):
    alice, _, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    bad = dict(s0)
    bad['mode'] = 'weird'
    bad['stream'] = None
    bad['stream_ttl'] = None
    st = asyncio.run(alice.seal_envelope({'msg': 'x'}, bad, to=pub_b, return_status=True))
    assert st['ok'] is False
    assert st['code'] in ('invalid_stream_mode', 'invalid_session')

def test_v4_fallback_path_stream_interrupted_after_closed_stream(tmp_path):
    """
    Exercise fallback path producing stream_interrupted (no custom verify hook).
    """
    alice, bob, pub_a, _, s1 = _setup_stream(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=True, ttl=120))
    env2 = asyncio.run(bob.seal_envelope({'done': True}, s2, to=pub_a))
    assert asyncio.run(alice.open_envelope(env2)) == {'done': True}
    bad = dict(copy.deepcopy(s2))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['phase'] = 'chunk'
    bad['stream']['seq'] = bad['stream']['seq'] + 1
    bad['stream_ttl'] = 30
    bad['ts'] = bad['ts'] + 1
    env_bad = _resign(bob, env2, bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] in ('stream_not_active', 'stream_interrupted')

def test_v4_optional_stream_telemetry_fields_can_be_carried_via_event_extra(tmp_path):
    """
    Optional extras from v4 are whitelisted; ensure they flow when provided.
    """
    alice, _, _, _ = _make_pair(tmp_path)
    got = {}

    @alice.on_policy_event(phase='open_envelope')
    def _on_open(name, ctx):
        got.update(ctx)
    asyncio.run(alice._ret(True, False, 'stream_interrupted', phase='open_envelope', event_extra={'stream_started_ts': 100, 'stream_last_ts': 110, 'stream_frame_count': 7}))
    assert got.get('stream_started_ts') == 100
    assert got.get('stream_last_ts') == 110
    assert got.get('stream_frame_count') == 7
