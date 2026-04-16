"""Lifecycle-focused tests for SummonerIdentity.

Covers active-session gating, reset semantics, history convergence, failure
non-destructiveness, and structured status outputs.
"""
import asyncio
import copy
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, id_fingerprint
from tooling.aurora.identity import ENV_VERSION, sign_bytes
from tooling.aurora.identity.identity import _canon_json_bytes

def _flip_first_char(s: str) -> str:
    """Return a deterministically modified string that always differs from input."""
    if not isinstance(s, str) or not s:
        return 'B'
    return ('B' if s[0] == 'A' else 'A') + s[1:]

def _make_pair(tmp_path, *, ttl=120, margin=0):
    """Create isolated Alice/Bob envelopes with configurable ttl/margin."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=ttl, margin=margin)
    identity_b = SummonerIdentity(ttl=ttl, margin=margin)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b)

def _complete_exchange(identity_a, identity_b, pub_a, pub_b, msg='hi', ack='ack'):
    """Run a full A->B->A exchange and assert successful delivery."""
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': msg}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': msg}
    peer_a = env1['from']
    s1 = asyncio.run(identity_b.continue_session(peer_a, env1['session_proof']))
    env2 = asyncio.run(identity_b.seal_envelope({'msg': ack}, s1, to=peer_a))
    assert asyncio.run(identity_a.open_envelope(env2)) == {'msg': ack}
    return (s0, env1, s1, env2)

def _role0_rec(identity_local, peer_public_id):
    """Return fallback session record for local role 0 and a peer."""
    key = f"{id_fingerprint(peer_public_id['pub_sig_b64'])}:0"
    return identity_local._sessions.get(key) or {}

def _role1_rec(identity_local, peer_public_id):
    """Return fallback session record for local role 1 and a peer."""
    key = f"{id_fingerprint(peer_public_id['pub_sig_b64'])}:1"
    return identity_local._sessions.get(key) or {}

@pytest.fixture(autouse=True)
def _reset_class_hooks():
    """Reset global class-level hooks before/after each lifecycle test."""
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

def test_start_session_blocked_while_uncompleted_active_link_exists(tmp_path):
    """Second start should be blocked while first thread is still active and uncompleted."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    assert s0 is not None
    assert asyncio.run(identity_a.start_session(pub_b)) is None
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'hi'}
    assert asyncio.run(identity_a.start_session(pub_b)) is None

def test_start_after_completion_finalizes_history_and_builds_history_proof(tmp_path):
    """After completion, a new start should finalize history and carry history_proof."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    _complete_exchange(identity_a, identity_b, pub_a, pub_b)
    s2 = asyncio.run(identity_a.start_session(pub_b))
    assert s2 is not None
    assert isinstance(s2.get('history_proof'), dict)
    assert s2.get('age') == 1
    rec = _role0_rec(identity_a, pub_b)
    assert len(rec.get('history', [])) == 1
    assert rec.get('current_link', {}).get('completed') is False

def test_force_reset_discards_incomplete_current_without_advancing_history(tmp_path):
    """Force reset should drop incomplete active link and keep finalized history age unchanged."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    _complete_exchange(identity_a, identity_b, pub_a, pub_b)
    s2 = asyncio.run(identity_a.start_session(pub_b))
    assert s2 is not None
    rec_before = _role0_rec(identity_a, pub_b)
    assert len(rec_before.get('history', [])) == 1
    s3 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    assert s3 is not None
    assert s3.get('age') == 1
    rec_after = _role0_rec(identity_a, pub_b)
    assert len(rec_after.get('history', [])) == 1

def test_force_reset_on_completed_link_still_finalizes_before_restart(tmp_path):
    """Force reset must not lose a completed link; it should finalize before restart."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    _complete_exchange(identity_a, identity_b, pub_a, pub_b)
    rec0 = _role0_rec(identity_a, pub_b)
    assert rec0.get('current_link', {}).get('completed') is True
    assert rec0.get('history', []) == []
    s1 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    assert s1 is not None
    assert s1.get('age') == 1
    rec1 = _role0_rec(identity_a, pub_b)
    assert len(rec1.get('history', [])) == 1

def test_finalize_history_uses_last_recorded_age_after_window_trim(tmp_path):
    """Completed-link finalization must advance from the last stored age, not history length."""
    identity, _, _, _ = _make_pair(tmp_path)
    rec = {
        'peer_id': 'peer',
        'local_role': 0,
        'active': True,
        'past_chain': [],
        'history': [
            {'hash': '11' * 32, 'age': 20, 'ts': 1},
            {'hash': '22' * 32, 'age': 21, 'ts': 2},
        ],
        'window': 2,
        'current_link': {
            '0_nonce': 'aa' * 16,
            '1_nonce': 'bb' * 16,
            'ts': 3,
            'ttl': 45,
            'completed': True,
            'seen': [],
        },
    }
    identity._finalize_history_if_completed(rec)
    history = rec['history']
    assert [item['age'] for item in history] == [21, 22]
    assert history[-1]['ts'] == 3

def test_force_reset_fails_closed_for_custom_store_without_reset_hook(tmp_path):
    """With custom register/get hooks, force_reset should fail unless reset hook is provided."""
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    state = {}

    @SummonerIdentity.get_session
    def _get(peer_public_id, local_role):
        key = ('GENERIC' if peer_public_id is None else peer_public_id['pub_sig_b64'], int(local_role))
        rec = state.get(key)
        return rec.get('current_link') if isinstance(rec, dict) else None

    @SummonerIdentity.register_session
    def _register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        key = ('GENERIC' if peer_public_id is None else peer_public_id['pub_sig_b64'], int(local_role))
        rec = state.get(key, {'current_link': None})
        if new:
            rec['current_link'] = None
            if isinstance(session_record, dict):
                rec['current_link'] = {'0_nonce': session_record.get('0_nonce'), '1_nonce': session_record.get('1_nonce'), 'ts': int(session_record.get('ts', 0)), 'ttl': int(session_record.get('ttl', 0)), 'completed': False, 'seen': []}
                state[key] = rec
                return True
        return True

    @SummonerIdentity.verify_session
    def _verify(peer_public_id, local_role, session_record, use_margin=False):
        return identity_a.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )

    s0 = asyncio.run(identity_a.start_session(pub_b))
    assert s0 is not None
    assert asyncio.run(identity_a.start_session(pub_b, force_reset=True)) is None

def test_force_reset_works_with_custom_reset_hook(tmp_path):
    """With reset hook installed, force_reset should succeed and call reset path once."""
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    state = {}
    reset_calls = {'count': 0}

    @SummonerIdentity.get_session
    def _get(peer_public_id, local_role):
        key = ('GENERIC' if peer_public_id is None else peer_public_id['pub_sig_b64'], int(local_role))
        rec = state.get(key)
        return rec.get('current_link') if isinstance(rec, dict) else None

    @SummonerIdentity.register_session
    def _register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        key = ('GENERIC' if peer_public_id is None else peer_public_id['pub_sig_b64'], int(local_role))
        rec = state.get(key, {'current_link': None})
        if new:
            rec['current_link'] = None
            if isinstance(session_record, dict):
                rec['current_link'] = {'0_nonce': session_record.get('0_nonce'), '1_nonce': session_record.get('1_nonce'), 'ts': int(session_record.get('ts', 0)), 'ttl': int(session_record.get('ttl', 0)), 'completed': False, 'seen': []}
                state[key] = rec
                return True
        return True

    @SummonerIdentity.verify_session
    def _verify(peer_public_id, local_role, session_record, use_margin=False):
        return identity_a.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )

    @SummonerIdentity.reset_session
    def _reset(peer_public_id, local_role):
        reset_calls['count'] += 1
        key = ('GENERIC' if peer_public_id is None else peer_public_id['pub_sig_b64'], int(local_role))
        rec = state.get(key, {'current_link': None})
        rec['current_link'] = None
        state[key] = rec
        return True
    s0 = asyncio.run(identity_a.start_session(pub_b))
    assert s0 is not None
    s1 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    assert s1 is not None
    assert reset_calls['count'] == 1

def test_bob_restarts_chain_when_alice_force_resets_active_thread(tmp_path):
    """Role-1 side should replace current chain when receiving valid post-force-reset start."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'one'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'one'}
    rec_before = _role1_rec(identity_b, pub_a)
    old_link = dict(rec_before.get('current_link') or {})
    assert old_link.get('0_nonce') == s0.get('0_nonce')
    assert old_link.get('1_nonce') is None
    s_reset = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    assert s_reset is not None
    env2 = asyncio.run(identity_a.seal_envelope({'msg': 'two'}, s_reset, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env2)) == {'msg': 'two'}
    rec_after = _role1_rec(identity_b, pub_a)
    new_link = rec_after.get('current_link') or {}
    assert new_link.get('0_nonce') == s_reset.get('0_nonce')
    assert new_link.get('0_nonce') != old_link.get('0_nonce')
    assert new_link.get('1_nonce') is None
    hist = rec_after.get('history') or []
    assert len(hist) == 0

def test_invalid_envelope_does_not_clear_bob_current_chain(tmp_path):
    """Invalid incoming envelope must not mutate Bob's current chain state."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'one'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'one'}
    rec_before = _role1_rec(identity_b, pub_a)
    old_link = dict(rec_before.get('current_link') or {})
    bad = copy.deepcopy(env1)
    bad['payload']['ciphertext'] = _flip_first_char(bad['payload']['ciphertext'])
    core = {'v': ENV_VERSION, 'payload': bad['payload'], 'session_proof': bad['session_proof'], 'from': bad['from'], 'to': bad['to']}
    bad['sig'] = sign_bytes(identity_a._priv_sig, _canon_json_bytes(core))
    assert asyncio.run(identity_b.open_envelope(bad)) is None
    rec_after = _role1_rec(identity_b, pub_a)
    assert rec_after.get('current_link') == old_link

def test_late_response_rejection_does_not_clear_alice_chain(tmp_path):
    """Rejecting late reply must preserve Alice local current-link state."""
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
    link_before = dict(rec['current_link'])
    assert asyncio.run(identity_a.open_envelope(env2)) is None
    rec_after = identity_a._sessions.get(key) or {}
    assert rec_after.get('current_link') == link_before

def test_stale_start_form_nonce_reuse_still_rejected(tmp_path):
    """An expired current_link must not allow reuse of the same start-form nonce."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'one'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'one'}

    key = f"{id_fingerprint(pub_a['pub_sig_b64'])}:1"
    rec = identity_b._sessions.get(key)
    assert rec is not None
    rec['current_link']['ts'] = 0
    rec['current_link']['ttl'] = 1
    identity_b._sessions[key] = rec

    env2 = asyncio.run(identity_a.seal_envelope({'msg': 'two'}, s0, to=pub_b))
    st = asyncio.run(identity_b.open_envelope(env2, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'session_verify_failed'

def test_four_session_lifecycle_two_build_then_reset_then_continue(tmp_path):
    """End-to-end four-session scenario: build history, reset, continue, verify convergence."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    _complete_exchange(identity_a, identity_b, pub_a, pub_b, msg='s1', ack='s1-ack')
    s2 = asyncio.run(identity_a.start_session(pub_b))
    assert s2 is not None and s2.get('age') == 1
    env2 = asyncio.run(identity_a.seal_envelope({'msg': 's2'}, s2, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env2)) == {'msg': 's2'}
    s2r = asyncio.run(identity_b.continue_session(env2['from'], env2['session_proof']))
    env2r = asyncio.run(identity_b.seal_envelope({'msg': 's2-ack'}, s2r, to=env2['from']))
    assert asyncio.run(identity_a.open_envelope(env2r)) == {'msg': 's2-ack'}
    s3 = asyncio.run(identity_a.start_session(pub_b))
    assert s3 is not None and s3.get('age') == 2
    env3 = asyncio.run(identity_a.seal_envelope({'msg': 's3'}, s3, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env3)) == {'msg': 's3'}
    s4 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    assert s4 is not None and s4.get('age') == 2
    env4 = asyncio.run(identity_a.seal_envelope({'msg': 's4'}, s4, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env4)) == {'msg': 's4'}
    bob_rec = _role1_rec(identity_b, pub_a)
    bob_hist = bob_rec.get('history') or []
    assert len(bob_hist) == 2
    s4r = asyncio.run(identity_b.continue_session(env4['from'], env4['session_proof']))
    env4r = asyncio.run(identity_b.seal_envelope({'msg': 's4-ack'}, s4r, to=env4['from']))
    assert asyncio.run(identity_a.open_envelope(env4r)) == {'msg': 's4-ack'}
    alice_rec = _role0_rec(identity_a, pub_b)
    alice_hist = alice_rec.get('history') or []
    assert len(alice_hist) == 2
    assert [h['hash'] for h in alice_hist] == [h['hash'] for h in bob_hist]

def test_bob_rejects_wrong_history_then_accepts_next_valid_start(tmp_path):
    """Bob should reject wrong history proof but recover on next valid start-form."""
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    _complete_exchange(identity_a, identity_b, pub_a, pub_b, msg='base', ack='base-ack')
    s2 = asyncio.run(identity_a.start_session(pub_b))
    env2 = asyncio.run(identity_a.seal_envelope({'msg': 's2'}, s2, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env2)) == {'msg': 's2'}
    s3 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    assert s3 is not None
    env3_good = asyncio.run(identity_a.seal_envelope({'msg': 'recover'}, s3, to=pub_b))
    bad = copy.deepcopy(env3_good)
    bad['session_proof']['history_proof']['ciphertext'] = _flip_first_char(bad['session_proof']['history_proof']['ciphertext'])
    core = {'v': ENV_VERSION, 'payload': bad['payload'], 'session_proof': bad['session_proof'], 'from': bad['from'], 'to': bad['to']}
    bad['sig'] = sign_bytes(identity_a._priv_sig, _canon_json_bytes(core))
    rec_before = copy.deepcopy(_role1_rec(identity_b, pub_a))
    assert asyncio.run(identity_b.open_envelope(bad)) is None
    rec_after_bad = _role1_rec(identity_b, pub_a)
    assert rec_after_bad == rec_before
    assert asyncio.run(identity_b.open_envelope(env3_good)) == {'msg': 'recover'}
    rec_after_good = _role1_rec(identity_b, pub_a)
    assert rec_after_good.get('current_link', {}).get('0_nonce') == s3.get('0_nonce')

def test_structured_status_outputs_for_decision_logic(tmp_path):
    """`return_status=True` should return machine-friendly outcome codes for orchestration."""
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    assert isinstance(s0, dict)
    st = asyncio.run(identity_a.start_session(pub_b, return_status=True))
    assert st['ok'] is False and st['code'] == 'active_session_exists'
    env_ok = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b, return_status=True))
    assert env_ok['ok'] is True and isinstance(env_ok['data'], dict)
    bad = copy.deepcopy(env_ok['data'])
    bad['sig'] = 'AA=='
    st_open = asyncio.run(identity_b.open_envelope(bad, return_status=True))
    assert st_open['ok'] is False and st_open['code'] == 'open_envelope_exception'
