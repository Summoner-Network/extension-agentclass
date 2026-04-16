"""Decorator hook sync/async tests for SummonerIdentity."""
import asyncio
import os
import sys

import pytest

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
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


def _wrap_mode(mode, fn):
    if mode == "sync":
        return fn

    async def _wrapped(*args, **kwargs):
        return fn(*args, **kwargs)

    return _wrapped


def _make_pair(tmp_path, *, ttl=60):
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=ttl, margin=0)
    bob = SummonerIdentity(ttl=ttl, margin=0)
    pub_a = alice.id(str(a_dir / "id.json"))
    pub_b = bob.id(str(b_dir / "id.json"))
    return alice, bob, pub_a, pub_b


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_on_policy_event_handler_supports_sync_and_async(tmp_path, mode):
    alice, _, _, pub_b = _make_pair(tmp_path)
    seen = []

    def _handler(event_name, ctx):
        seen.append((event_name, ctx.get("phase")))

    alice.on_policy_event(phase="start_session")(_wrap_mode(mode, _handler))

    asyncio.run(alice.start_session(pub_b))
    assert seen
    assert seen[0][1] == "start_session"


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_on_policy_event_handler_supports_verify_discovery_envelope_phase(tmp_path, mode):
    alice, bob, _, _ = _make_pair(tmp_path)
    seen = []

    def _handler(event_name, ctx):
        seen.append((event_name, ctx.get("phase"), ctx.get("peer_fingerprint")))

    bob.on_policy_event(phase="verify_discovery_envelope")(_wrap_mode(mode, _handler))

    s0 = asyncio.run(alice.start_session(None, ttl=15))
    env0 = asyncio.run(alice.seal_envelope({"msg": "hello"}, s0, to=None))
    st = asyncio.run(bob.verify_discovery_envelope(env0, return_status=True))

    assert st["ok"] is True
    assert seen
    assert seen[0][1] == "verify_discovery_envelope"
    assert isinstance(seen[0][2], str)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_register_get_verify_hooks_support_sync_and_async(tmp_path, mode):
    identity = SummonerIdentity(ttl=60, margin=0)
    pub = identity.id(str(tmp_path / "self-id.json"))
    calls = {"get": 0, "verify": 0, "register": 0}

    def _get(peer_public_id, local_role):
        calls["get"] += 1
        return identity.get_session_default(peer_public_id, local_role)

    def _verify(peer_public_id, local_role, session_record, use_margin=False):
        calls["verify"] += 1
        return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

    def _register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        calls["register"] += 1
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    SummonerIdentity.get_session(_wrap_mode(mode, _get))
    SummonerIdentity.verify_session(_wrap_mode(mode, _verify))
    SummonerIdentity.register_session(_wrap_mode(mode, _register))

    s0 = asyncio.run(identity.start_session(pub))
    env0 = asyncio.run(identity.seal_envelope({"msg": "hello"}, s0, to=pub))
    out = asyncio.run(identity.open_envelope(env0))

    assert out == {"msg": "hello"}
    assert calls["get"] > 0
    assert calls["verify"] > 0
    assert calls["register"] > 0


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_instance_scoped_session_hooks_support_sync_and_async_without_leaking(tmp_path, mode):
    identity = SummonerIdentity(ttl=60, margin=0)
    other = SummonerIdentity(ttl=60, margin=0)
    pub = identity.id(str(tmp_path / "self-id.json"))
    pub_other = other.id(str(tmp_path / "other-id.json"))
    calls = {"get": 0, "verify": 0, "register": 0}

    def _get(peer_public_id, local_role):
        calls["get"] += 1
        return identity.get_session_default(peer_public_id, local_role)

    def _verify(peer_public_id, local_role, session_record, use_margin=False):
        calls["verify"] += 1
        return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

    def _register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        calls["register"] += 1
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    identity.on_get_session(_wrap_mode(mode, _get))
    identity.on_verify_session(_wrap_mode(mode, _verify))
    identity.on_register_session(_wrap_mode(mode, _register))

    s0 = asyncio.run(identity.start_session(pub))
    env0 = asyncio.run(identity.seal_envelope({"msg": "hello"}, s0, to=pub))
    out0 = asyncio.run(identity.open_envelope(env0))

    assert out0 == {"msg": "hello"}
    assert calls["get"] > 0
    assert calls["verify"] > 0
    assert calls["register"] > 0

    after_local = dict(calls)

    s1 = asyncio.run(other.start_session(pub_other))
    env1 = asyncio.run(other.seal_envelope({"msg": "plain"}, s1, to=pub_other))
    out1 = asyncio.run(other.open_envelope(env1))

    assert out1 == {"msg": "plain"}
    assert calls == after_local


def test_public_runtime_session_methods_are_available_on_instance(tmp_path):
    identity = SummonerIdentity(ttl=60, margin=0)
    pub = identity.id(str(tmp_path / "self-id.json"))

    s0 = asyncio.run(identity.start_session(pub))
    assert isinstance(s0, dict)

    vr = asyncio.run(identity.verify_session_record(pub, 1, s0, use_margin=False))
    assert vr["ok"] is True

    ok = asyncio.run(identity.register_session_record(pub, 1, s0, new=True, use_margin=False))
    assert ok is True

    current = asyncio.run(identity.get_current_session(pub, 1))
    assert isinstance(current, dict)
    assert current.get("0_nonce") == s0.get("0_nonce")

    ok_reset = asyncio.run(identity.force_reset_session(pub, 1))
    assert ok_reset is True
    assert asyncio.run(identity.get_current_session(pub, 1)) is None


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_reset_hook_supports_sync_and_async(tmp_path, mode):
    identity = SummonerIdentity(ttl=60, margin=0)
    pub = identity.id(str(tmp_path / "self-id.json"))
    reset_calls = {"n": 0}

    def _get(peer_public_id, local_role):
        return identity.get_session_default(peer_public_id, local_role)

    def _verify(peer_public_id, local_role, session_record, use_margin=False):
        return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

    def _register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    def _reset(peer_public_id, local_role):
        reset_calls["n"] += 1
        return identity.reset_session_default(peer_public_id, local_role)

    SummonerIdentity.get_session(_wrap_mode(mode, _get))
    SummonerIdentity.verify_session(_wrap_mode(mode, _verify))
    SummonerIdentity.register_session(_wrap_mode(mode, _register))
    SummonerIdentity.reset_session(_wrap_mode(mode, _reset))

    assert asyncio.run(identity.start_session(pub)) is not None
    assert asyncio.run(identity.start_session(pub, force_reset=True)) is not None
    assert reset_calls["n"] == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_instance_reset_hook_supports_sync_and_async(tmp_path, mode):
    identity = SummonerIdentity(ttl=60, margin=0)
    pub = identity.id(str(tmp_path / "self-id.json"))
    reset_calls = {"n": 0}

    def _verify(peer_public_id, local_role, session_record, use_margin=False):
        return identity.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )

    def _register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    def _reset(peer_public_id, local_role):
        reset_calls["n"] += 1
        return identity.reset_session_default(peer_public_id, local_role)

    identity.on_verify_session(_wrap_mode(mode, _verify))
    identity.on_register_session(_wrap_mode(mode, _register))
    identity.on_reset_session(_wrap_mode(mode, _reset))

    assert asyncio.run(identity.start_session(pub)) is not None
    assert asyncio.run(identity.start_session(pub, force_reset=True)) is not None
    assert reset_calls["n"] == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_instance_peer_key_store_hook_overrides_class_hook_and_clear_restores_class(tmp_path, mode):
    alice, bob, _, pub_b = _make_pair(tmp_path / "pair-one")
    carol_dir = tmp_path / "carol"
    carol_dir.mkdir(parents=True, exist_ok=True)
    carol = SummonerIdentity(ttl=60, margin=0)
    carol.id(str(carol_dir / "id.json"))
    class_state = {}
    local_state = {}
    calls = {"class": 0, "local": 0}

    def _class_peer_store(peer_public_id, update=None):
        fp = peer_public_id["pub_sig_b64"]
        calls["class"] += 1
        if update is None:
            return class_state.get(fp)
        class_state[fp] = dict(update)
        return class_state[fp]

    def _local_peer_store(peer_public_id, update=None):
        fp = peer_public_id["pub_sig_b64"]
        calls["local"] += 1
        if update is None:
            return local_state.get(fp)
        local_state[fp] = dict(update)
        return local_state[fp]

    SummonerIdentity.peer_key_store(_wrap_mode(mode, _class_peer_store))
    bob.on_peer_key_store(_wrap_mode(mode, _local_peer_store))

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "local"}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {"msg": "local"}
    assert calls["local"] > 0
    assert calls["class"] == 0

    bob.clear_local_hooks()

    s1 = asyncio.run(carol.start_session(pub_b))
    env1 = asyncio.run(carol.seal_envelope({"msg": "class"}, s1, to=pub_b))
    assert asyncio.run(bob.open_envelope(env1)) == {"msg": "class"}
    assert calls["class"] > 0
    assert carol.public_id["pub_sig_b64"] in class_state


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_instance_replay_store_hook_supports_sync_and_async(tmp_path, mode):
    alice, bob, _, pub_b = _make_pair(tmp_path)
    replay = {}
    calls = {"seen": 0, "add": 0}

    def _replay_store(message_id, ttl, now, add=False):
        if add:
            calls["add"] += 1
            replay[message_id] = now + max(1, int(ttl))
            return True
        calls["seen"] += 1
        exp = replay.get(message_id)
        return isinstance(exp, int) and now <= exp

    bob.on_replay_store(_wrap_mode(mode, _replay_store))
    bob.on_verify_session(_wrap_mode(mode, lambda *args, **kwargs: True))

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "once"}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {"msg": "once"}

    st = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st["ok"] is False
    assert st["code"] == "replay_detected"
    assert calls["seen"] >= 2
    assert calls["add"] >= 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_peer_key_store_hook_supports_sync_and_async(tmp_path, mode):
    alice, bob, _, pub_b = _make_pair(tmp_path)
    peer_state = {}
    calls = {"read": 0, "write": 0}

    def _peer_store(peer_public_id, update=None):
        fp = peer_public_id["pub_sig_b64"]
        if update is None:
            calls["read"] += 1
            return peer_state.get(fp)
        calls["write"] += 1
        peer_state[fp] = dict(update)
        return peer_state[fp]

    SummonerIdentity.peer_key_store(_wrap_mode(mode, _peer_store))

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "peer-cache"}, s0, to=pub_b))
    out = asyncio.run(bob.open_envelope(env0))

    assert out == {"msg": "peer-cache"}
    assert calls["read"] >= 1
    assert calls["write"] >= 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_verify_discovery_envelope_uses_peer_key_store_hook(tmp_path, mode):
    alice, bob, _, _ = _make_pair(tmp_path)
    peer_state = {}
    calls = {"read": 0, "write": 0}

    def _peer_store(peer_public_id, update=None):
        fp = peer_public_id["pub_sig_b64"]
        if update is None:
            calls["read"] += 1
            return peer_state.get(fp)
        calls["write"] += 1
        peer_state[fp] = dict(update)
        return peer_state[fp]

    SummonerIdentity.peer_key_store(_wrap_mode(mode, _peer_store))

    s0 = asyncio.run(alice.start_session(None, ttl=15))
    env0 = asyncio.run(alice.seal_envelope({"msg": "peer-cache"}, s0, to=None))
    out = asyncio.run(bob.verify_discovery_envelope(env0))

    assert out == {"msg": "peer-cache"}
    assert calls["read"] >= 1
    assert calls["write"] >= 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_replay_store_hook_supports_sync_and_async(tmp_path, mode):
    alice, bob, _, pub_b = _make_pair(tmp_path)
    replay = {}
    calls = {"seen": 0, "add": 0}

    def _replay_store(message_id, ttl, now, add=False):
        if add:
            calls["add"] += 1
            replay[message_id] = now + max(1, int(ttl))
            return True
        calls["seen"] += 1
        exp = replay.get(message_id)
        return isinstance(exp, int) and now <= exp

    SummonerIdentity.replay_store(_wrap_mode(mode, _replay_store))
    SummonerIdentity.verify_session(_wrap_mode(mode, lambda *args, **kwargs: True))

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "once"}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {"msg": "once"}

    st = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st["ok"] is False
    assert st["code"] == "replay_detected"
    assert calls["seen"] >= 2
    assert calls["add"] >= 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_verify_discovery_envelope_uses_replay_store_hook(tmp_path, mode):
    alice, bob, _, _ = _make_pair(tmp_path)
    replay = {}
    calls = {"seen": 0, "add": 0}

    def _replay_store(message_id, ttl, now, add=False):
        if add:
            calls["add"] += 1
            replay[message_id] = now + max(1, int(ttl))
            return True
        calls["seen"] += 1
        exp = replay.get(message_id)
        return isinstance(exp, int) and now <= exp

    SummonerIdentity.replay_store(_wrap_mode(mode, _replay_store))

    s0 = asyncio.run(alice.start_session(None, ttl=15))
    env0 = asyncio.run(alice.seal_envelope({"msg": "once"}, s0, to=None))
    assert asyncio.run(bob.verify_discovery_envelope(env0)) == {"msg": "once"}

    st = asyncio.run(bob.verify_discovery_envelope(env0, return_status=True))
    assert st["ok"] is False
    assert st["code"] == "replay_detected"
    assert calls["seen"] >= 2
    assert calls["add"] >= 1
