"""Streaming-focused tests for SummonerIdentity."""
import asyncio
import copy
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
    """Reset class-level hooks around each test."""
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

def _make_pair(tmp_path, *, ttl=60, margin=0):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=ttl, margin=margin)
    bob = SummonerIdentity(ttl=ttl, margin=margin)
    pub_a = alice.id(str(a_dir / 'id.json'))
    pub_b = bob.id(str(b_dir / 'id.json'))
    return (alice, bob, pub_a, pub_b)

def _resign_env(sender: SummonerIdentity, env: dict, *, session_override=None, to_override=None) -> dict:
    out = copy.deepcopy(env)
    if session_override is not None:
        out['session_proof'] = session_override
    if to_override is not None:
        out['to'] = to_override
    core = {'v': out['v'], 'payload': out['payload'], 'session_proof': out['session_proof'], 'from': out['from'], 'to': out['to']}
    out['sig'] = sign_bytes(sender._priv_sig, _canon_json_bytes(core))
    return out

def _setup_stream_turn(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=120, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'part-1'}, s1, to=pub_a))
    st1 = asyncio.run(alice.open_envelope(env1, return_status=True))
    assert st1['ok'] is True
    return (alice, bob, pub_a, pub_b, env0, s1, env1)

def test_streamed_response_turn_end_to_end_and_handoff(tmp_path):
    alice, bob, pub_a, pub_b, env0, s1, env1 = _setup_stream_turn(tmp_path)
    c1 = alice.classify_session_record(env1['session_proof'])
    assert c1['is_stream'] is True
    assert c1['stream_phase'] == 'start'
    assert c1['stream_seq'] == 0
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=pub_a))
    st2 = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st2['ok'] is True
    s3 = asyncio.run(bob.advance_stream_session(pub_a, s2, end_stream=True, ttl=120))
    env3 = asyncio.run(bob.seal_envelope({'done': True}, s3, to=pub_a))
    st3 = asyncio.run(alice.open_envelope(env3, return_status=True))
    assert st3['ok'] is True
    s4 = asyncio.run(alice.continue_session(pub_b, env3['session_proof'], stream=False))
    env4 = asyncio.run(alice.seal_envelope({'ack': 'ok'}, s4, to=pub_b))
    assert asyncio.run(bob.open_envelope(env4)) == {'ack': 'ok'}
    c3 = alice.classify_session_record(env3['session_proof'])
    assert c3['stream_phase'] == 'end'
    assert c3['is_stream_end'] is True

def test_initiator_streamed_turn_end_to_end_and_handoff(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=120, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b, stream=True, stream_ttl=30))
    c0 = alice.classify_session_record(s0)
    assert c0['is_stream'] is True
    assert c0['stream_phase'] == 'start'
    assert c0['stream_seq'] == 0
    assert c0['is_start_form'] is True
    env0 = asyncio.run(alice.seal_envelope({'delta': 'part-1'}, s0, to=pub_b))
    st0 = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st0['ok'] is True
    s1 = asyncio.run(alice.advance_stream_session(pub_b, s0, end_stream=False, stream_ttl=30))
    c1 = alice.classify_session_record(s1)
    assert c1['stream_phase'] == 'chunk'
    assert c1['stream_seq'] == 1
    assert c1['is_start_form'] is False
    env1 = asyncio.run(alice.seal_envelope({'delta': 'part-2'}, s1, to=pub_b))
    st1 = asyncio.run(bob.open_envelope(env1, return_status=True))
    assert st1['ok'] is True
    s2 = asyncio.run(alice.advance_stream_session(pub_b, s1, end_stream=True, ttl=120))
    c2 = alice.classify_session_record(s2)
    assert c2['stream_phase'] == 'end'
    assert c2['stream_seq'] == 2
    assert c2['is_start_form'] is False
    env2 = asyncio.run(alice.seal_envelope({'done': True}, s2, to=pub_b))
    st2 = asyncio.run(bob.open_envelope(env2, return_status=True))
    assert st2['ok'] is True
    s3 = asyncio.run(bob.continue_session(pub_a, env2['session_proof'], stream=False))
    env3 = asyncio.run(bob.seal_envelope({'ack': 'ok'}, s3, to=pub_a))
    assert asyncio.run(alice.open_envelope(env3)) == {'ack': 'ok'}

def test_classify_initiator_stream_marks_only_start_as_start_form(tmp_path):
    alice, _, _, pub_b = _make_pair(tmp_path, ttl=120, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b, stream=True, stream_ttl=30))
    c0 = alice.classify_session_record(s0)
    assert c0['stream_phase'] == 'start'
    assert c0['is_start_form'] is True
    s1 = asyncio.run(alice.advance_stream_session(pub_b, s0, end_stream=False, stream_ttl=30))
    c1 = alice.classify_session_record(s1)
    assert c1['stream_phase'] == 'chunk'
    assert c1['is_start_form'] is False
    s2 = asyncio.run(alice.advance_stream_session(pub_b, s1, end_stream=True, ttl=60))
    c2 = alice.classify_session_record(s2)
    assert c2['stream_phase'] == 'end'
    assert c2['is_start_form'] is False

def test_start_stream_discovery_boundary_rejected(tmp_path):
    alice, _, _, _ = _make_pair(tmp_path)
    st = asyncio.run(alice.start_session(None, stream=True, stream_ttl=10, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_mode_unsupported'

def test_continue_stream_requires_positive_stream_ttl(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'x'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'x'}
    st = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=0, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_ttl_invalid'

def test_continue_non_stream_blocked_while_stream_active(tmp_path):
    alice, bob, pub_a, _, env0, _, env1 = _setup_stream_turn(tmp_path)
    st = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=False, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_active_continue_blocked'

def test_advance_stream_requires_stream_context(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'x'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'x'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=False))
    st = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'invalid_stream_session'

def test_advance_stream_requires_ttl_for_chunk(tmp_path):
    _, bob, pub_a, _, _, s1, _ = _setup_stream_turn(tmp_path)
    st = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=None, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_ttl_invalid'

def test_advance_after_end_rejected(tmp_path):
    alice, bob, pub_a, _, _, s1, _ = _setup_stream_turn(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=True, ttl=60))
    env2 = asyncio.run(bob.seal_envelope({'done': True}, s2, to=pub_a))
    assert asyncio.run(alice.open_envelope(env2)) == {'done': True}
    st = asyncio.run(bob.advance_stream_session(pub_a, s2, end_stream=False, stream_ttl=30, return_status=True))
    assert st['ok'] is False
    assert st['code'] in ('stream_not_active', 'stream_interrupted')

def test_seal_stream_without_ttl_rejected(tmp_path):
    _, bob, pub_a, _, _, s1, _ = _setup_stream_turn(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    bad = dict(s2)
    bad.pop('stream_ttl', None)
    st = asyncio.run(bob.seal_envelope({'delta': 'x'}, bad, to=pub_a, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_ttl_invalid'

def test_seal_single_mode_with_stream_ttl_rejected(tmp_path):
    alice, _, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    bad = dict(s0)
    bad['stream_ttl'] = 30
    st = asyncio.run(alice.seal_envelope({'msg': 'x'}, bad, to=pub_b, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'invalid_stream_fields'

def test_open_out_of_order_chunk_stream_seq_invalid(tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    bad = dict(copy.deepcopy(env2['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['seq'] = bad['stream']['seq'] + 2
    env_bad = _resign_env(bob, env2, session_override=bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_seq_invalid'

def test_open_stream_state_conflict_on_stream_id_mismatch(tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    bad = dict(copy.deepcopy(env2['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['id'] = 'deadbeef'
    env_bad = _resign_env(bob, env2, session_override=bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_state_conflict'

def test_open_stream_phase_invalid(tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    bad = dict(copy.deepcopy(env2['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['phase'] = 'bogus'
    env_bad = _resign_env(bob, env2, session_override=bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_phase_invalid'

def test_open_stream_not_active_for_first_chunk(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=120, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'part-1'}, s1, to=pub_a))
    bad = dict(copy.deepcopy(env1['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['phase'] = 'chunk'
    bad['stream']['seq'] = 1
    env_bad = _resign_env(bob, env1, session_override=bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_not_active'

def test_open_stream_already_active_on_repeated_start(tmp_path):
    alice, bob, _, _, _, _, env1 = _setup_stream_turn(tmp_path)
    bad = dict(copy.deepcopy(env1['session_proof']))
    bad['ts'] = bad['ts'] + 1
    env_bad = _resign_env(bob, env1, session_override=bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_already_active'

def test_open_stream_ttl_expired_no_margin(monkeypatch, tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=5))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    ts = int(s2['ts'])
    monkeypatch.setattr("tooling.aurora.identity.identity._now_unix", lambda: ts + 6)
    st = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_ttl_expired'

def test_stream_chunk_acceptance_after_original_request_window(monkeypatch, tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=1, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b, ttl=1))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'part-1'}, s1, to=pub_a))
    st1 = asyncio.run(alice.open_envelope(env1, return_status=True))
    assert st1['ok'] is True
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=pub_a))
    future = max(int(s0['ts']) + 5, int(s2['ts']) + 1)
    monkeypatch.setattr("tooling.aurora.identity.identity._now_unix", lambda: future)
    st2 = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st2['ok'] is True
    assert st2['code'] == 'ok'

def test_stream_mode_unsupported_for_discovery_open(tmp_path):
    alice, bob, _, _ = _make_pair(tmp_path)
    s0 = asyncio.run(bob.start_session(None))
    env0 = asyncio.run(bob.seal_envelope({'msg': 'hello'}, s0, to=None))
    bad = dict(copy.deepcopy(env0['session_proof']))
    bad['mode'] = 'stream'
    bad['stream'] = {'id': 'abc123', 'seq': 0, 'phase': 'start'}
    bad['stream_ttl'] = 10
    env_bad = _resign_env(bob, env0, session_override=bad, to_override=None)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_mode_unsupported'

def test_bool_verify_hook_collapses_stream_failure_to_session_verify_failed(tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)

    @SummonerIdentity.verify_session
    def _bool_verify(peer_public_id, local_role, session_record, use_margin=False):
        return False
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    st = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'session_verify_failed'

def test_structured_verify_hook_code_passthrough(tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)

    @SummonerIdentity.verify_session
    def _structured(peer_public_id, local_role, session_record, use_margin=False):
        return {'ok': False, 'code': 'stream_state_conflict', 'reason': 'forced_conflict'}
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    st = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_state_conflict'

def test_open_stream_failure_policy_event_has_stream_extras(tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)
    got = {}

    @alice.on_policy_event(phase='open_envelope')
    def _on_open(name, ctx):
        if name.startswith('stream_'):
            got.clear()
            got.update(ctx)
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    bad = dict(copy.deepcopy(env2['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['seq'] = bad['stream']['seq'] + 2
    env_bad = _resign_env(bob, env2, session_override=bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert got.get('stream_mode') == 'stream'
    assert isinstance(got.get('stream_id'), str)
    assert got.get('stream_phase') == 'chunk'
    assert isinstance(got.get('stream_seq'), int)
    assert got.get('stream_policy') == 'contiguous'

def test_open_stream_failure_event_carries_verify_reason(tmp_path):
    alice, bob, _, _, _, s1, _ = _setup_stream_turn(tmp_path)
    got = {}

    @SummonerIdentity.verify_session
    def _structured(peer_public_id, local_role, session_record, use_margin=False):
        return {'ok': False, 'code': 'stream_state_conflict', 'reason': 'unit_test_reason'}

    @alice.on_policy_event(phase='open_envelope')
    def _on_open(name, ctx):
        if name == 'stream_state_conflict':
            got.clear()
            got.update(ctx)
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'part-2'}, s2, to=alice.public_id))
    st = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_state_conflict'
    assert got.get('stream_reason') == 'unit_test_reason'

def test_advance_stream_session_policy_phase_emits(tmp_path):
    _, bob, pub_a, _, _, s1, _ = _setup_stream_turn(tmp_path)
    seen = []

    @bob.on_policy_event(phase='advance_stream_session')
    def _on_advance(name, ctx):
        seen.append((name, ctx.get('phase')))
    st = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30, return_status=True))
    assert st['ok'] is True
    assert seen and seen[-1] == ('ok', 'advance_stream_session')

def test_classify_stream_record_reports_required_fields(tmp_path):
    _, bob, pub_a, _, _, s1, _ = _setup_stream_turn(tmp_path)
    c1 = bob.classify_session_record(s1)
    assert c1['valid_shape'] is True
    assert c1['mode'] == 'stream'
    assert c1['is_stream'] is True
    assert c1['stream_fields_valid'] is True
    assert c1['stream_phase'] == 'start'
    assert c1['stream_ttl_valid'] is True
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    c2 = bob.classify_session_record(s2)
    assert c2['stream_phase'] == 'chunk'
    assert c2['record_expiry_basis'] in (None, 'stream_ttl')
    s3 = asyncio.run(bob.advance_stream_session(pub_a, s2, end_stream=True, ttl=60))
    c3 = bob.classify_session_record(s3)
    assert c3['stream_phase'] == 'end'
    assert c3['record_expiry_basis'] in (None, 'ttl')
