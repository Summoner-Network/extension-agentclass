"""SummonerIdentityControls behavior tests."""
import asyncio
import os
import sys

import pytest


target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.aurora import SummonerIdentity, SummonerIdentityControls


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


def _make_single(tmp_path, name, *, ttl=60):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    identity = SummonerIdentity(ttl=ttl, margin=0)
    pub = identity.id(str(d / "id.json"))
    return identity, pub


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_controls_object_supports_sync_and_async_without_leaking(tmp_path, mode):
    identity, pub = _make_single(tmp_path, "self")
    other, pub_other = _make_single(tmp_path, "other")
    calls = {"get": 0, "verify": 0, "register": 0}

    controls = SummonerIdentityControls()

    def _get(envelope, peer_public_id, local_role):
        assert envelope is identity
        calls["get"] += 1
        return envelope.get_session_default(peer_public_id, local_role)

    def _verify(envelope, peer_public_id, local_role, session_record, use_margin=False):
        assert envelope is identity
        calls["verify"] += 1
        return envelope.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )

    def _register(envelope, peer_public_id, local_role, session_record, new=False, use_margin=False):
        assert envelope is identity
        calls["register"] += 1
        return envelope.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    controls.on_get_session(_wrap_mode(mode, _get))
    controls.on_verify_session(_wrap_mode(mode, _verify))
    controls.on_register_session(_wrap_mode(mode, _register))
    assert controls.configured_hooks() == ("register_session", "verify_session", "get_session")

    attached = identity.attach_controls(controls)
    assert attached is controls
    assert identity.require_controls() is controls
    assert identity.has_controls() is True

    s0 = asyncio.run(identity.start_session(pub))
    env0 = asyncio.run(identity.seal_envelope({"msg": "hello"}, s0, to=pub))
    out0 = asyncio.run(identity.open_envelope(env0))

    assert out0 == {"msg": "hello"}
    assert calls["get"] > 0
    assert calls["verify"] > 0
    assert calls["register"] > 0

    after_controls = dict(calls)

    s1 = asyncio.run(other.start_session(pub_other))
    env1 = asyncio.run(other.seal_envelope({"msg": "plain"}, s1, to=pub_other))
    out1 = asyncio.run(other.open_envelope(env1))

    assert out1 == {"msg": "plain"}
    assert calls == after_controls

    assert identity.detach_controls() is controls
    assert identity.has_controls() is False
    with pytest.raises(RuntimeError):
        identity.require_controls()


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_controls_reset_hook_supports_sync_and_async(tmp_path, mode):
    identity, pub = _make_single(tmp_path, "self")
    reset_calls = {"n": 0}

    controls = SummonerIdentityControls()

    def _verify(envelope, peer_public_id, local_role, session_record, use_margin=False):
        assert envelope is identity
        return envelope.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )

    def _register(envelope, peer_public_id, local_role, session_record, new=False, use_margin=False):
        assert envelope is identity
        return envelope.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    def _reset(envelope, peer_public_id, local_role):
        assert envelope is identity
        reset_calls["n"] += 1
        return envelope.reset_session_default(peer_public_id, local_role)

    controls.on_verify_session(_wrap_mode(mode, _verify))
    controls.on_register_session(_wrap_mode(mode, _register))
    controls.on_reset_session(_wrap_mode(mode, _reset))
    identity.attach_controls(controls)

    assert asyncio.run(identity.start_session(pub)) is not None
    assert asyncio.run(identity.start_session(pub, force_reset=True)) is not None
    assert reset_calls["n"] == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_controls_replay_store_hook_supports_sync_and_async(tmp_path, mode):
    alice, bob, _, pub_b = _make_pair(tmp_path)
    replay = {}
    calls = {"seen": 0, "add": 0}

    controls = SummonerIdentityControls()

    def _replay_store(envelope, message_id, ttl, now, add=False):
        assert envelope is bob
        if add:
            calls["add"] += 1
            replay[message_id] = now + max(1, int(ttl))
            return True
        calls["seen"] += 1
        exp = replay.get(message_id)
        return isinstance(exp, int) and now <= exp

    controls.on_replay_store(_wrap_mode(mode, _replay_store))
    controls.on_verify_session(_wrap_mode(mode, lambda envelope, *args, **kwargs: True))
    bob.attach_controls(controls)

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "once"}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {"msg": "once"}

    st = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st["ok"] is False
    assert st["code"] == "replay_detected"
    assert calls["seen"] >= 2
    assert calls["add"] >= 1


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_one_controls_object_can_be_reused_across_multiple_identities(tmp_path, mode):
    alice, pub_a = _make_single(tmp_path, "alice")
    bob, pub_b = _make_single(tmp_path, "bob")
    carol, pub_c = _make_single(tmp_path, "carol")

    controls = SummonerIdentityControls()
    seen = []

    def _get(envelope, peer_public_id, local_role):
        seen.append(envelope.public_id["pub_sig_b64"])
        return {
            "owner": envelope.public_id["pub_sig_b64"],
            "peer": None if peer_public_id is None else peer_public_id["pub_sig_b64"],
            "local_role": int(local_role),
        }

    controls.on_get_session(_wrap_mode(mode, _get))

    bob.attach_controls(controls)
    carol.attach_controls(controls)

    current_b = asyncio.run(bob.get_current_session(pub_a, 1))
    current_c = asyncio.run(carol.get_current_session(pub_a, 1))

    assert bob.require_controls() is controls
    assert carol.require_controls() is controls
    assert current_b["owner"] == pub_b["pub_sig_b64"]
    assert current_c["owner"] == pub_c["pub_sig_b64"]
    assert current_b["peer"] == pub_a["pub_sig_b64"]
    assert current_c["peer"] == pub_a["pub_sig_b64"]
    assert seen == [pub_b["pub_sig_b64"], pub_c["pub_sig_b64"]]


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_attach_controls_replaces_previous_controls_object(tmp_path, mode):
    alice, bob, _, pub_b = _make_pair(tmp_path)
    calls = {"a": 0, "b": 0}

    controls_a = SummonerIdentityControls()
    controls_b = SummonerIdentityControls()

    def _peer_store_a(envelope, peer_public_id, update=None):
        assert envelope is bob
        calls["a"] += 1
        return envelope.peer_key_store_default(peer_public_id, update=update)

    def _peer_store_b(envelope, peer_public_id, update=None):
        assert envelope is bob
        calls["b"] += 1
        return envelope.peer_key_store_default(peer_public_id, update=update)

    controls_a.on_peer_key_store(_wrap_mode(mode, _peer_store_a))
    controls_b.on_peer_key_store(_wrap_mode(mode, _peer_store_b))

    assert bob.attach_controls(controls_a) is controls_a
    assert bob.attach_controls(controls_b) is controls_b
    assert bob.require_controls() is controls_b

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "replacement"}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {"msg": "replacement"}

    assert calls["a"] == 0
    assert calls["b"] > 0


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_local_hooks_override_controls_and_controls_override_class_hooks(tmp_path, mode):
    alice, bob, _, pub_b = _make_pair(tmp_path / "pair-one")
    carol, _, _, _ = _make_pair(tmp_path / "pair-two")
    dave, _, _, _ = _make_pair(tmp_path / "pair-three")

    class_state = {}
    controls_state = {}
    local_state = {}
    calls = {"class": 0, "controls": 0, "local": 0}

    def _class_peer_store(peer_public_id, update=None):
        fp = peer_public_id["pub_sig_b64"]
        calls["class"] += 1
        if update is None:
            return class_state.get(fp)
        class_state[fp] = dict(update)
        return class_state[fp]

    def _controls_peer_store(envelope, peer_public_id, update=None):
        assert envelope is bob
        fp = peer_public_id["pub_sig_b64"]
        calls["controls"] += 1
        if update is None:
            return controls_state.get(fp)
        controls_state[fp] = dict(update)
        return controls_state[fp]

    def _local_peer_store(peer_public_id, update=None):
        fp = peer_public_id["pub_sig_b64"]
        calls["local"] += 1
        if update is None:
            return local_state.get(fp)
        local_state[fp] = dict(update)
        return local_state[fp]

    SummonerIdentity.peer_key_store(_wrap_mode(mode, _class_peer_store))

    controls = SummonerIdentityControls()
    controls.on_peer_key_store(_wrap_mode(mode, _controls_peer_store))
    bob.attach_controls(controls)
    bob.on_peer_key_store(_wrap_mode(mode, _local_peer_store))

    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "local"}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {"msg": "local"}
    assert calls["local"] > 0
    assert calls["controls"] == 0
    assert calls["class"] == 0

    bob.clear_local_hooks()

    s1 = asyncio.run(carol.start_session(pub_b))
    env1 = asyncio.run(carol.seal_envelope({"msg": "controls"}, s1, to=pub_b))
    assert asyncio.run(bob.open_envelope(env1)) == {"msg": "controls"}
    assert calls["controls"] > 0
    assert calls["class"] == 0

    assert bob.detach_controls() is controls

    s2 = asyncio.run(dave.start_session(pub_b))
    env2 = asyncio.run(dave.seal_envelope({"msg": "class"}, s2, to=pub_b))
    assert asyncio.run(bob.open_envelope(env2)) == {"msg": "class"}
    assert calls["class"] > 0


def test_controls_register_requires_verify_in_same_hook_scope(tmp_path):
    identity, pub = _make_single(tmp_path, "self")
    controls = SummonerIdentityControls()

    @SummonerIdentity.verify_session
    def _class_verify(peer_public_id, local_role, session_record, use_margin=False):
        return identity.verify_session_default(peer_public_id, local_role, session_record, use_margin=use_margin)

    @controls.on_register_session
    def _controls_register(identity, peer_public_id, local_role, session_record, new=False, use_margin=False):
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    identity.attach_controls(controls)

    with pytest.raises(ValueError, match="same hook scope"):
        asyncio.run(identity.start_session(pub))


def test_local_register_requires_verify_in_same_hook_scope(tmp_path):
    identity, pub = _make_single(tmp_path, "self")
    controls = SummonerIdentityControls()

    @controls.on_verify_session
    def _controls_verify(identity, peer_public_id, local_role, session_record, use_margin=False):
        return identity.verify_session_default(
            peer_public_id,
            local_role,
            session_record,
            use_margin=use_margin,
        )

    identity.attach_controls(controls)

    @identity.on_register_session
    def _local_register(peer_public_id, local_role, session_record, new=False, use_margin=False):
        return identity.register_session_default(
            peer_public_id,
            local_role,
            session_record,
            new=new,
            use_margin=use_margin,
        )

    with pytest.raises(ValueError, match="same hook scope"):
        asyncio.run(identity.start_session(pub))
