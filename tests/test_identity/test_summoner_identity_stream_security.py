"""Security-oriented stream tests mapped to streaming plan v4 Section 18."""
import asyncio
import copy
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, id_fingerprint
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

def _resign_env(sender: SummonerIdentity, env: dict, *, session_override=None) -> dict:
    out = copy.deepcopy(env)
    if session_override is not None:
        out['session_proof'] = session_override
    core = {'v': out['v'], 'payload': out['payload'], 'session_proof': out['session_proof'], 'from': out['from'], 'to': out['to']}
    out['sig'] = sign_bytes(sender._priv_sig, _canon_json_bytes(core))
    return out

def _start_stream_turn(tmp_path):
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({'msg': 'request'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {'msg': 'request'}
    s1 = asyncio.run(bob.continue_session(pub_a, env0['session_proof'], stream=True, stream_ttl=30))
    env1 = asyncio.run(bob.seal_envelope({'delta': 'p1'}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {'delta': 'p1'}
    return (alice, bob, pub_a, pub_b, s1, env1)

def test_security_turn_hijack_detector_blocks_on_chunk_caps(tmp_path):
    """Section 18.1: policy-event cap detector can quarantine endless chunk streams."""
    alice, bob, pub_a, _, s1, _ = _start_stream_turn(tmp_path)
    blocked = set()
    per_stream = {}

    @alice.on_policy_event(phase='open_envelope')
    def _monitor(event_name, ctx):
        if event_name != 'ok':
            return
        if ctx.get('stream_phase') not in ('start', 'chunk'):
            return
        fp = ctx.get('peer_fingerprint')
        sid = ctx.get('stream_id')
        if not (isinstance(fp, str) and isinstance(sid, str)):
            return
        k = (fp, sid)
        per_stream[k] = per_stream.get(k, 0) + 1
        if per_stream[k] > 3:
            blocked.add(fp)
    cur = s1
    for i in range(4):
        cur = asyncio.run(bob.advance_stream_session(pub_a, cur, end_stream=False, stream_ttl=30))
        env = asyncio.run(bob.seal_envelope({'delta': f'chunk-{i}'}, cur, to=pub_a))
        assert asyncio.run(alice.open_envelope(env)) == {'delta': f'chunk-{i}'}
    assert blocked
    assert isinstance(next(iter(blocked)), str)

def test_security_contiguous_policy_rejects_gap_attack_and_avoids_gap_state_growth(tmp_path):
    """Section 18.2: default contiguous policy rejects large seq jumps."""
    alice, bob, _, _, s1, _ = _start_stream_turn(tmp_path)
    s2 = asyncio.run(bob.advance_stream_session(alice.public_id, s1, end_stream=False, stream_ttl=30))
    env2 = asyncio.run(bob.seal_envelope({'delta': 'p2'}, s2, to=alice.public_id))
    bad = dict(copy.deepcopy(env2['session_proof']))
    bad['stream'] = dict(bad['stream'])
    bad['stream']['seq'] = bad['stream']['seq'] + 128
    env_bad = _resign_env(bob, env2, session_override=bad)
    st = asyncio.run(alice.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_seq_invalid'
    key = f"{id_fingerprint(bob.public_id['pub_sig_b64'])}:0"
    rec = alice._sessions.get(key) or {}
    current = rec.get('current_link') or {}
    assert current.get('missing_ranges', []) == []

def test_security_valid_stream_dos_ratio_detector_trips(tmp_path):
    """Section 18.3: policy detector can flag high chunk/no-end patterns."""
    alice, bob, pub_a, _, s1, _ = _start_stream_turn(tmp_path)
    stats = {'chunks': 0, 'ends': 0}
    blocked = set()

    @alice.on_policy_event(phase='open_envelope')
    def _monitor(event_name, ctx):
        fp = ctx.get('peer_fingerprint')
        if not isinstance(fp, str):
            return
        if event_name == 'ok' and ctx.get('stream_phase') == 'chunk':
            stats['chunks'] += 1
        if event_name == 'ok' and ctx.get('stream_phase') == 'end':
            stats['ends'] += 1
        if stats['chunks'] >= 5 and stats['ends'] == 0:
            blocked.add(fp)
    cur = s1
    for i in range(5):
        cur = asyncio.run(bob.advance_stream_session(pub_a, cur, end_stream=False, stream_ttl=30))
        env = asyncio.run(bob.seal_envelope({'delta': f'chunk-{i}'}, cur, to=pub_a))
        assert asyncio.run(alice.open_envelope(env)) == {'delta': f'chunk-{i}'}
    assert blocked

def test_security_timeout_restart_thrash_detector_sets_cooldown(monkeypatch, tmp_path):
    """Section 18.4: repeated timeout failures can trigger local cooldown policy."""
    alice, bob, pub_a, _, s1, _ = _start_stream_turn(tmp_path)
    pressure = {}
    interrupted_reasons = []

    @alice.on_policy_event(phase='open_envelope')
    def _monitor(event_name, ctx):
        fp = ctx.get('peer_fingerprint')
        ev_ts = ctx.get('ts')
        if not (isinstance(fp, str) and isinstance(ev_ts, int)):
            return
        st = pressure.setdefault(fp, {'count': 0, 'cooldown_until': 0})
        if event_name in ('stream_ttl_expired', 'stream_interrupted'):
            st['count'] += 1
            if st['count'] >= 3:
                st['cooldown_until'] = ev_ts + 60
        if event_name == 'stream_interrupted':
            interrupted_reasons.append(ctx.get('stream_reason'))
    cur = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=5))
    env = asyncio.run(bob.seal_envelope({'delta': 'late'}, cur, to=pub_a))
    ts = int(cur['ts'])
    monkeypatch.setattr("tooling.aurora.identity.identity._now_unix", lambda: ts + 6)
    seen_codes = []
    for _ in range(3):
        st = asyncio.run(alice.open_envelope(env, return_status=True))
        assert st['ok'] is False
        seen_codes.append(st['code'])
    assert seen_codes[0] == 'stream_ttl_expired'
    assert all((c in ('stream_ttl_expired', 'stream_interrupted') for c in seen_codes))
    assert 'stream_interrupted' in seen_codes[1:]
    assert interrupted_reasons and all((r == 'timeout_closed' for r in interrupted_reasons))
    assert pressure
    assert next(iter(pressure.values()))['cooldown_until'] > 0

def test_security_post_timeout_closed_stream_cache_with_custom_verify(monkeypatch, tmp_path):
    """Section 18.5: local closed-stream cache can force stream_interrupted on delayed frames."""
    alice, bob, pub_a, _, s1, _ = _start_stream_turn(tmp_path)
    closed_streams = {}

    @alice.on_policy_event(phase='open_envelope')
    def _mark_closed(event_name, ctx):
        if event_name not in ('stream_ttl_expired', 'stream_interrupted'):
            return
        fp = ctx.get('peer_fingerprint')
        sid = ctx.get('stream_id')
        ts = ctx.get('ts')
        if isinstance(fp, str) and isinstance(sid, str) and isinstance(ts, int):
            closed_streams[fp, sid] = ts
    cur = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=5))
    env = asyncio.run(bob.seal_envelope({'delta': 'late'}, cur, to=pub_a))
    ts = int(cur['ts'])
    monkeypatch.setattr("tooling.aurora.identity.identity._now_unix", lambda: ts + 6)
    st_timeout = asyncio.run(alice.open_envelope(env, return_status=True))
    assert st_timeout['ok'] is False
    assert st_timeout['code'] == 'stream_ttl_expired'

    @SummonerIdentity.verify_session
    def _reject_closed(peer_public_id, local_role, session_record, use_margin=False):
        fp = None
        if isinstance(peer_public_id, dict):
            fp = id_fingerprint(peer_public_id['pub_sig_b64'])
        s = session_record.get('stream') if isinstance(session_record, dict) else None
        sid = s.get('id') if isinstance(s, dict) else None
        if isinstance(fp, str) and isinstance(sid, str) and ((fp, sid) in closed_streams):
            return {'ok': False, 'code': 'stream_interrupted', 'reason': 'frame_on_closed_stream'}
        return alice.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)
    st_closed = asyncio.run(alice.open_envelope(env, return_status=True))
    assert st_closed['ok'] is False
    assert st_closed['code'] == 'stream_interrupted'

def test_security_observability_downgrade_monitor_with_bool_verify_hook(tmp_path):
    """Section 18.6: monitor detects low-quality generic verify failures."""
    alice, bob, pub_a, _, s1, _ = _start_stream_turn(tmp_path)
    counts = {'generic': 0, 'detailed': 0}
    blocked = set()

    @alice.on_policy_event(phase='open_envelope')
    def _monitor(event_name, ctx):
        fp = ctx.get('peer_fingerprint')
        if event_name == 'session_verify_failed':
            counts['generic'] += 1
            if isinstance(fp, str) and counts['generic'] >= 3 and (counts['detailed'] == 0):
                blocked.add(fp)
        if event_name in ('stream_ttl_expired', 'stream_interrupted', 'stream_seq_invalid'):
            counts['detailed'] += 1

    @SummonerIdentity.verify_session
    def _bool_verify(peer_public_id, local_role, session_record, use_margin=False):
        return False
    cur = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env = asyncio.run(bob.seal_envelope({'delta': 'x'}, cur, to=pub_a))
    for _ in range(3):
        st = asyncio.run(alice.open_envelope(env, return_status=True))
        assert st['ok'] is False
        assert st['code'] == 'session_verify_failed'
    assert blocked
    assert counts['detailed'] == 0

def test_security_reason_quality_improves_with_structured_verify(tmp_path):
    """Section 18.6: structured verify returns detailed stream failures for observability."""
    alice, bob, pub_a, _, s1, _ = _start_stream_turn(tmp_path)
    counts = {'generic': 0, 'detailed': 0}

    @alice.on_policy_event(phase='open_envelope')
    def _monitor(event_name, ctx):
        if event_name == 'session_verify_failed':
            counts['generic'] += 1
        if event_name in ('stream_ttl_expired', 'stream_interrupted', 'stream_seq_invalid'):
            counts['detailed'] += 1

    @SummonerIdentity.verify_session
    def _structured(peer_public_id, local_role, session_record, use_margin=False):
        return {'ok': False, 'code': 'stream_seq_invalid', 'reason': 'synthetic_detailed_failure'}
    cur = asyncio.run(bob.advance_stream_session(pub_a, s1, end_stream=False, stream_ttl=30))
    env = asyncio.run(bob.seal_envelope({'delta': 'x'}, cur, to=pub_a))
    st = asyncio.run(alice.open_envelope(env, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'stream_seq_invalid'
    assert counts['generic'] == 0
    assert counts['detailed'] >= 1
