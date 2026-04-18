"""Boundary and fail-closed robustness tests for streaming."""
import asyncio
import copy
import os
import random
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

def _make_pair(tmp_path, *, ttl=120, margin=0, max_clock_skew_seconds=None):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=ttl, margin=margin, max_clock_skew_seconds=max_clock_skew_seconds)
    bob = SummonerIdentity(ttl=ttl, margin=margin, max_clock_skew_seconds=max_clock_skew_seconds)
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
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=5))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    return (alice, bob, pub_a, s1)

def test_stream_ttl_exact_boundary_accepts(monkeypatch, tmp_path):
    alice, bob, pub_a, s1 = _setup_stream(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=5))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'edge'}, s2, to=pub_a))
    ts = int(s2['ts'])
    monkeypatch.setattr("tooling.aurora.identity.identity._now_unix", lambda: ts + 5)
    st = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st['ok'] is True
    assert st['code'] == 'ok'

def test_stream_ttl_one_past_boundary_rejects(monkeypatch, tmp_path):
    alice, bob, pub_a, s1 = _setup_stream(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=5))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'late'}, s2, to=pub_a))
    ts = int(s2['ts'])
    monkeypatch.setattr("tooling.aurora.identity.identity._now_unix", lambda: ts + 6)
    st = asyncio.run(alice.open_envelope(env2, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_ttl_expired'

def test_stream_seq_negative_rejected(tmp_path):
    alice, bob, pub_a, s1 = _setup_stream(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=5))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'p2'}, s2, to=pub_a))
    bad = dict(copy.deepcopy(env2['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['seq'] = -1
    env_bad = _resign(bob, env2, bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] in ('stream_seq_invalid', 'invalid_stream_fields')

def test_stream_future_clock_skew_checked_before_stream_logic(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=120, margin=0, max_clock_skew_seconds=1)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=5))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'future'}, s1, to=pub_a))
    bad = dict(copy.deepcopy(env1['session_proof']))
    bad['ts'] = int(bad['ts']) + 120
    env1 = _resign(bob, env1, bad)
    st = asyncio.run(alice.open_envelope(env1, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'clock_skew_violation'

def test_single_mode_session_without_stream_fields_is_accepted(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path, ttl=120, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'single'}, s0, to=pub_b))
    proof_without_stream_fields = dict(copy.deepcopy(env0['session_proof']))
    proof_without_stream_fields.pop('mode', None)
    proof_without_stream_fields.pop('stream', None)
    proof_without_stream_fields.pop('stream_ttl', None)
    env_single_mode = _resign(alice, env0, proof_without_stream_fields)
    st = asyncio.run(bob.open_envelope(env_single_mode, return_status=True))
    assert st['ok'] is True
    assert st['code'] == 'ok'

def test_stream_mutation_fuzz_fail_closed_no_exceptions(tmp_path):
    """
    Deterministic mutation sweep: receiver must fail-closed or accept cleanly, never crash.
    """
    rng = random.Random(1337)
    alice, bob, pub_a, s1 = _setup_stream(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=5))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'seed'}, s2, to=pub_a))
    fields = [('mode', ['single', 'stream', 'bad', None]), ('stream_ttl', [None, -1, 0, 1, 5, 999999]), ('sender_role', [0, 1, 2, 'x']), ('ts', [0, int(s2['ts']), int(s2['ts']) + 1]), ('ttl', [0, 1, 120]), ('stream.phase', ['start', 'chunk', 'end', 'bogus']), ('stream.seq', [-1, 0, 1, 2, 99])]
    for _ in range(40):
        mut = dict(copy.deepcopy(env2['session_proof']))
        key, vals = rng.choice(fields)
        val = rng.choice(vals)
        if key == 'stream.phase':
            if not isinstance(mut.get('stream'), dict):
                mut['stream'] = {'id': 'x', 'seq': 0, 'phase': 'chunk'}
            mut['stream']['phase'] = val
        elif key == 'stream.seq':
            if not isinstance(mut.get('stream'), dict):
                mut['stream'] = {'id': 'x', 'seq': 0, 'phase': 'chunk'}
            mut['stream']['seq'] = val
        else:
            mut[key] = val
        env_mut = _resign(bob, env2, mut)
        st = asyncio.run(alice.open_envelope(env_mut, return_status=True))
        assert isinstance(st, dict)
        assert 'ok' in st and isinstance(st['ok'], bool)
        assert 'code' in st and isinstance(st['code'], str)
