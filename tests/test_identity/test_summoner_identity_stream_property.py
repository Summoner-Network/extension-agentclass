"""Deterministic property-style streaming tests (no optional dependencies)."""
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

def _pair(tmp_path):
    salt = random.randint(0, 10000000)
    a_dir = tmp_path / f'a_{salt}'
    b_dir = tmp_path / f'b_{salt}'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    a = SummonerIdentity(ttl=120, margin=0, persist_local=False, load_local=False)
    b = SummonerIdentity(ttl=120, margin=0, persist_local=False, load_local=False)
    pub_a = a.id(str(a_dir / 'id.json'))
    pub_b = b.id(str(b_dir / 'id.json'))
    return (a, b, pub_a, pub_b)

def _resign(sender: SummonerIdentity, env: dict, session_override: dict) -> dict:
    out = copy.deepcopy(env)
    out['session_proof'] = session_override
    core = {'v': out['v'], 'payload': out['payload'], 'session_proof': out['session_proof'], 'from': out['from'], 'to': out['to']}
    out['sig'] = sign_bytes(sender._priv_sig, _canon_json_bytes(core))
    return out

def _run_stream_seq_monotonic_and_phase_progression(tmp_path, chunk_count, end_ttl):
    """
    For any chunk_count, seq is contiguous and phases progress start->chunk*->end.
    """
    alice, bob, pub_a, pub_b = _pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    cur = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    assert cur['stream']['phase'] == 'start'
    assert cur['stream']['seq'] == 0
    env_start = asyncio.run(bob.seal_envelope({'delta': 'start'}, cur, to=pub_a))
    assert asyncio.run(alice.open_envelope(env_start)) == {'delta': 'start'}
    expected_seq = 0
    for i in range(chunk_count):
        cur = asyncio.run(bob.advance_stream_session(pub_a, cur, end_stream=False, stream_ttl=30))
        expected_seq += 1
        assert cur['stream']['phase'] == 'chunk'
        assert cur['stream']['seq'] == expected_seq
        env = asyncio.run(bob.seal_envelope({'delta': str(i)}, cur, to=pub_a))
        assert asyncio.run(alice.open_envelope(env)) == {'delta': str(i)}
    cur = asyncio.run(bob.advance_stream_session(pub_a, cur, end_stream=True, ttl=end_ttl))
    expected_seq += 1
    assert cur['stream']['phase'] == 'end'
    assert cur['stream']['seq'] == expected_seq
    env_end = asyncio.run(bob.seal_envelope({'done': True}, cur, to=pub_a))
    assert asyncio.run(alice.open_envelope(env_end)) == {'done': True}

def _run_mutated_stream_session_fail_closed(tmp_path, bad_mode, bad_phase, bad_seq, bad_ttl):
    """
    Mutated stream session proofs should either fail with status or (rarely) remain valid,
    but must always return a structured status and never raise.
    """
    alice, bob, pub_a, pub_b = _pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'start'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'start'}
    s2 = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'x'}, s2, to=pub_a))
    mut = dict(copy.deepcopy(env2['session_proof']))
    if isinstance(mut.get('stream'), dict):
        mut['stream'] = dict(mut['stream'])
    else:
        mut['stream'] = {'id': 'x', 'seq': 1, 'phase': 'chunk'}
    mut['mode'] = bad_mode
    mut['stream']['phase'] = bad_phase
    mut['stream']['seq'] = bad_seq
    mut['stream_ttl'] = bad_ttl
    env_mut = _resign(bob, env2, mut)
    st_out = asyncio.run(alice.open_envelope(env_mut, return_status=True))
    assert isinstance(st_out, dict)
    assert isinstance(st_out.get('ok'), bool)
    assert isinstance(st_out.get('code'), str)

@pytest.mark.parametrize('chunk_count,end_ttl', [(0, 1), (1, 60), (2, 120), (6, 300)])
def test_property_stream_seq_monotonic_and_phase_progression(tmp_path, chunk_count, end_ttl):
    _run_stream_seq_monotonic_and_phase_progression(tmp_path, chunk_count, end_ttl)

def test_property_mutated_stream_session_fail_closed(tmp_path):
    rng = random.Random(4242)
    mode_space = [None, 0, 1, 'single', 'stream', 'bad', '']
    phase_space = [None, 0, 'start', 'chunk', 'end', 'bogus', '']
    seq_space = [-10, -1, 0, 1, 2, 20, 'x', '']
    ttl_space = [None, -5, -1, 0, 1, 5, 'x', '']
    for _ in range(40):
        _run_mutated_stream_session_fail_closed(tmp_path, bad_mode=rng.choice(mode_space), bad_phase=rng.choice(phase_space), bad_seq=rng.choice(seq_space), bad_ttl=rng.choice(ttl_space))
