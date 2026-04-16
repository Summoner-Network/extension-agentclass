"""Policy event API tests for SummonerIdentity."""
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

def _make_pair(tmp_path):
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0)
    identity_b = SummonerIdentity(ttl=60, margin=0)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b)

def test_on_policy_event_registers_handler_per_phase(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    events = []

    @identity_a.on_policy_event(phase='start_session')
    def _on_start(event_name, ctx):
        events.append((event_name, ctx['phase']))
    asyncio.run(identity_a.start_session(pub_b))
    assert events and events[0][1] == 'start_session'

def test_multiple_handlers_same_phase_all_fire_in_registration_order(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    order = []

    @identity_a.on_policy_event(phase='start_session')
    def _h1(event_name, ctx):
        order.append('h1')

    @identity_a.on_policy_event(phase='start_session')
    def _h2(event_name, ctx):
        order.append('h2')
    asyncio.run(identity_a.start_session(pub_b))
    assert order == ['h1', 'h2']

def test_register_invalid_phase_raises_value_error_by_default(tmp_path):
    identity_a, _, _, _ = _make_pair(tmp_path)
    with pytest.raises(ValueError):

        @identity_a.on_policy_event(phase='bad_phase')
        def _bad(event_name, ctx):
            return None

def test_start_session_events_have_phase_start_session(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    phases = []

    @identity_a.on_policy_event(phase='start_session')
    def _h(event_name, ctx):
        phases.append(ctx['phase'])
    asyncio.run(identity_a.start_session(pub_b))
    assert phases == ['start_session']

def test_continue_session_events_have_phase_continue_session(tmp_path):
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    phases = []
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}

    @identity_b.on_policy_event(phase='continue_session')
    def _h(event_name, ctx):
        phases.append(ctx['phase'])
    asyncio.run(identity_b.continue_session(pub_a, env['session_proof']))
    assert phases == ['continue_session']

def test_seal_envelope_events_have_phase_seal_envelope(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    phases = []

    @identity_a.on_policy_event(phase='seal_envelope')
    def _h(event_name, ctx):
        phases.append(ctx['phase'])
    s0 = asyncio.run(identity_a.start_session(pub_b))
    asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert phases == ['seal_envelope']

def test_open_envelope_events_have_phase_open_envelope(tmp_path):
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    phases = []

    @identity_b.on_policy_event(phase='open_envelope')
    def _h(event_name, ctx):
        phases.append(ctx['phase'])
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    asyncio.run(identity_b.open_envelope(env))
    assert phases == ['open_envelope']

def test_policy_event_emitted_from_ret_in_data_mode(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    events = []

    @identity_a.on_policy_event(phase='start_session')
    def _h(event_name, ctx):
        events.append(event_name)
    out = asyncio.run(identity_a.start_session(pub_b, return_status=False))
    assert isinstance(out, dict)
    assert events == ['ok']

def test_policy_event_emitted_from_ret_in_status_mode(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    events = []

    @identity_a.on_policy_event(phase='start_session')
    def _h(event_name, ctx):
        events.append(event_name)
    out = asyncio.run(identity_a.start_session(pub_b, return_status=True))
    assert isinstance(out, dict) and out['ok'] is True
    assert events == ['ok']

def test_policy_event_name_matches_code(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    names = []

    @identity_a.on_policy_event(phase='start_session')
    def _h(event_name, ctx):
        names.append(event_name)
    asyncio.run(identity_a.start_session(pub_b))
    asyncio.run(identity_a.start_session(pub_b))
    assert names[-1] == 'active_session_exists'

def test_policy_event_context_required_keys_includes_schema_version(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)
    got = {}

    @identity_a.on_policy_event(phase='start_session')
    def _h(event_name, ctx):
        got.update(ctx)
    asyncio.run(identity_a.start_session(pub_b))
    for k in ('schema_version', 'ts', 'phase', 'ok', 'code', 'has_data'):
        assert k in got
    assert got['schema_version'] == 1

def test_event_extra_whitelist_fields_are_merged_into_context(tmp_path):
    identity_a, _, _, _ = _make_pair(tmp_path)
    got = {}

    @identity_a.on_policy_event(phase='start_session')
    def _h(event_name, ctx):
        got.update(ctx)
    asyncio.run(identity_a._ret(True, True, 'ok', data={'x': 1}, phase='start_session', event_extra={'peer_fingerprint': 'abc', 'validation_stage': 'session', 'not_allowed': 1}))
    assert got.get('peer_fingerprint') == 'abc'
    assert got.get('validation_stage') == 'session'
    assert 'not_allowed' not in got

def test_policy_handler_exception_does_not_change_api_return(tmp_path):
    identity_a, _, _, pub_b = _make_pair(tmp_path)

    @identity_a.on_policy_event(phase='start_session')
    def _h(event_name, ctx):
        raise RuntimeError('boom')
    out = asyncio.run(identity_a.start_session(pub_b))
    assert isinstance(out, dict) and out.get('sender_role') == 0

def test_invalid_emission_phase_raises_value_error(tmp_path):
    identity_a, _, _, _ = _make_pair(tmp_path)
    with pytest.raises(ValueError):
        asyncio.run(identity_a._ret(False, True, 'ok', phase='bad_phase'))

def test_phase_handlers_are_isolated(tmp_path):
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    seen_start = []
    seen_open = []

    @identity_a.on_policy_event(phase='start_session')
    def _on_start(event_name, ctx):
        seen_start.append(event_name)

    @identity_b.on_policy_event(phase='open_envelope')
    def _on_open(event_name, ctx):
        seen_open.append(event_name)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    assert seen_start == ['ok']
    assert seen_open == []
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    asyncio.run(identity_b.open_envelope(env))
    assert seen_open == ['ok']

def test_classify_session_record_start_and_non_start_forms(tmp_path):
    identity_a, identity_b, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    c0 = identity_a.classify_session_record(s0)
    assert c0['valid_shape'] is True
    assert c0['is_start_form'] is True
    assert c0['sender_role'] == 0
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    asyncio.run(identity_b.open_envelope(env))
    s1 = asyncio.run(identity_b.continue_session(pub_a, env['session_proof']))
    c1 = identity_b.classify_session_record(s1)
    assert c1['valid_shape'] is True
    assert c1['is_start_form'] is False

def test_open_envelope_ok_event_includes_session_form_and_roles_when_derivable(tmp_path):
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    got = {}

    @identity_b.on_policy_event(phase='open_envelope')
    def _h(event_name, ctx):
        if event_name == 'ok':
            got.update(ctx)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    asyncio.run(identity_b.open_envelope(env))
    assert got.get('session_form') == 'start'
    assert got.get('sender_role') == 0
    assert got.get('local_role') == 1
    assert isinstance(got.get('peer_fingerprint'), str)

def test_open_envelope_start_form_replacement_sets_replaced_active_incomplete(tmp_path):
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    flags = []

    @identity_b.on_policy_event(phase='open_envelope')
    def _h(event_name, ctx):
        if event_name == 'ok':
            flags.append(ctx.get('replaced_active_incomplete'))
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env1 = asyncio.run(identity_a.seal_envelope({'msg': 'm1'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env1)) == {'msg': 'm1'}
    s1 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    env2 = asyncio.run(identity_a.seal_envelope({'msg': 'm2'}, s1, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env2)) == {'msg': 'm2'}
    assert flags[0] is False
    assert flags[1] is True

def test_open_envelope_failure_includes_validation_stage(tmp_path):
    identity_a, identity_b, _, _ = _make_pair(tmp_path)
    got = {}

    @identity_b.on_policy_event(phase='open_envelope')
    def _h(event_name, ctx):
        got.clear()
        got.update({'event_name': event_name, **ctx})
    asyncio.run(identity_b.open_envelope('not_a_dict'))
    assert got['event_name'] == 'invalid_envelope'
    assert got['validation_stage'] == 'structure'

def test_replay_context_includes_store_mode_and_persistence_flag(tmp_path):
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    replay_ctx = {}

    @SummonerIdentity.verify_session
    def _verify_session(peer_public_id, local_role, session_record, use_margin=False):
        return True

    @identity_b.on_policy_event(phase='open_envelope')
    def _h(event_name, ctx):
        if event_name == 'replay_detected':
            replay_ctx.update(ctx)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}
    assert asyncio.run(identity_b.open_envelope(env)) is None
    assert replay_ctx['replay_store_mode'] in {'memory', 'disk', 'custom'}
    assert replay_ctx['persist_replay'] is False

def test_replay_fields_only_present_on_replay_detected_event(tmp_path):
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    seen = {}

    @SummonerIdentity.verify_session
    def _verify_session(peer_public_id, local_role, session_record, use_margin=False):
        return True

    @identity_b.on_policy_event(phase='open_envelope')
    def _h(event_name, ctx):
        seen.setdefault(event_name, []).append(dict(ctx))
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    asyncio.run(identity_b.open_envelope(env))
    asyncio.run(identity_b.open_envelope(env))
    assert 'ok' in seen and 'replay_detected' in seen
    assert 'replay_store_mode' not in seen['ok'][-1]
    assert 'persist_replay' not in seen['ok'][-1]
    assert 'replay_store_mode' in seen['replay_detected'][-1]
    assert 'persist_replay' in seen['replay_detected'][-1]

def test_validation_stage_only_present_on_open_envelope_failure_events(tmp_path):
    identity_a, identity_b, _, pub_b = _make_pair(tmp_path)
    seen = {}

    @identity_b.on_policy_event(phase='open_envelope')
    def _h(event_name, ctx):
        seen.setdefault(event_name, []).append(dict(ctx))
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    asyncio.run(identity_b.open_envelope(env))
    asyncio.run(identity_b.open_envelope('not_a_dict'))
    assert 'ok' in seen and 'invalid_envelope' in seen
    assert 'validation_stage' not in seen['ok'][-1]
    assert seen['invalid_envelope'][-1]['validation_stage'] == 'structure'
