"""Integration and telemetry contract tests for streaming workflows."""
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

def _make_pair(tmp_path):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=120, margin=0)
    bob = SummonerIdentity(ttl=120, margin=0)
    pub_a = alice.id(str(a_dir / 'id.json'), meta='alice')
    pub_b = bob.id(str(b_dir / 'id.json'), meta='bob')
    return (alice, bob, pub_a, pub_b)

def _resign(sender: SummonerIdentity, env: dict, session_override: dict) -> dict:
    out = copy.deepcopy(env)
    out['session_proof'] = session_override
    core = {'v': out['v'], 'payload': out['payload'], 'session_proof': out['session_proof'], 'from': out['from'], 'to': out['to']}
    out['sig'] = sign_bytes(sender._priv_sig, _canon_json_bytes(core))
    return out

def test_collab_style_streamed_delta_workflow_mapping(tmp_path):
    """
    v4 section 13 mapping:
    request -> streamed deltas -> final response -> opposite-side follow-up.
    """
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b, stream=False))
    env0 = asyncio.run(alice.seal_envelope({'type': 'collab_request', 'request_id': 'r1'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'type': 'collab_request', 'request_id': 'r1'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'type': 'collab_delta', 'request_id': 'r1', 'text': 'A'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'type': 'collab_delta', 'request_id': 'r1', 'text': 'A'}
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'type': 'collab_delta', 'request_id': 'r1', 'text': 'B'}, s2, to=pub_a))
    assert asyncio.run(alice.open_envelope(env2)) == {'type': 'collab_delta', 'request_id': 'r1', 'text': 'B'}
    s3 = asyncio.run(bob.advance_stream_session(pub_a, s2, end_stream=True, ttl=120))
    env3 = asyncio.run(bob.seal_envelope({'type': 'collab_response', 'request_id': 'r1', 'done': True}, s3, to=pub_a))
    assert asyncio.run(alice.open_envelope(env3)) == {'type': 'collab_response', 'request_id': 'r1', 'done': True}
    s4 = asyncio.run(alice.continue_session(pub_b, env3['session_proof'], stream=False))
    env4 = asyncio.run(alice.seal_envelope({'type': 'ack', 'request_id': 'r1'}, s4, to=pub_b))
    assert asyncio.run(bob.open_envelope(env4)) == {'type': 'ack', 'request_id': 'r1'}

def test_policy_event_sequence_for_stream_open_success_path(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    seen = []

    @alice.on_policy_event(phase='open_envelope')
    def _on_open(name, ctx):
        if name == 'ok' and ctx.get('stream_mode') == 'stream':
            seen.append((ctx.get('stream_phase'), ctx.get('stream_seq')))
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'req'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'req'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': '1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': '1'}
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': '2'}, s2, to=pub_a))
    assert asyncio.run(alice.open_envelope(env2)) == {'delta': '2'}
    s3 = asyncio.run(bob.advance_stream_session(pub_a, s2, end_stream=True, ttl=120))
    env3 = asyncio.run(bob.seal_envelope({'done': True}, s3, to=pub_a))
    assert asyncio.run(alice.open_envelope(env3)) == {'done': True}
    assert seen[0] == ('start', 0)
    assert seen[1] == ('chunk', 1)
    assert seen[2] == ('end', 2)

def test_policy_event_contract_for_stream_failures(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    got = []

    @alice.on_policy_event(phase='open_envelope')
    def _on_open(name, ctx):
        if name.startswith('stream_'):
            got.append((name, dict(ctx)))
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'req'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'req'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': '1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': '1'}
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': '2'}, s2, to=pub_a))
    bad = dict(copy.deepcopy(env2['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['seq'] = bad['stream']['seq'] + 5
    env_bad = _resign(bob, env2, bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_seq_invalid'
    assert got
    name, ctx = got[-1]
    assert name == 'stream_seq_invalid'
    assert ctx.get('phase') == 'open_envelope'
    assert ctx.get('stream_mode') == 'stream'
    assert isinstance(ctx.get('stream_id'), str)
    assert ctx.get('stream_phase') == 'chunk'
    assert isinstance(ctx.get('stream_seq'), int)
    assert 'validation_stage' in ctx

def test_stream_start_phase_exists_and_does_not_break_non_stream_events(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    start_events = []
    cont_events = []
    adv_events = []

    @alice.on_policy_event(phase='start_session')
    def _on_start(name, ctx):
        start_events.append(name)

    @bob.on_policy_event(phase='continue_session')
    def _on_continue(name, ctx):
        cont_events.append(name)

    @bob.on_policy_event(phase='advance_stream_session')
    def _on_advance(name, ctx):
        adv_events.append(name)
    s0 = asyncio.run(alice.start_session(pub_b, stream=False))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'req'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'req'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    assert isinstance(s2, dict)
    assert start_events and start_events[-1] == 'ok'
    assert cont_events and cont_events[-1] == 'ok'
    assert adv_events and adv_events[-1] == 'ok'

def test_open_stream_events_auto_include_optional_stream_timing_fields(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    seen = []

    @alice.on_policy_event(phase='open_envelope')
    def _on_open(name, ctx):
        if name == 'ok' and ctx.get('stream_mode') == 'stream':
            seen.append(dict(ctx))
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'req'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'req'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': '1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': '1'}
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': '2'}, s2, to=pub_a))
    assert asyncio.run(alice.open_envelope(env2)) == {'delta': '2'}
    assert len(seen) >= 2
    assert isinstance(seen[0].get('stream_started_ts'), int)
    assert isinstance(seen[0].get('stream_last_ts'), int)
    assert seen[0].get('stream_frame_count') == 1
    assert isinstance(seen[1].get('stream_last_ts'), int)
    assert seen[1].get('stream_frame_count') == 2
