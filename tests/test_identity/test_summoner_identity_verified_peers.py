"""Verified-peer and continuity-hardening tests for SummonerIdentity."""
import asyncio
import copy
import os
import sys
import pytest

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.aurora import SummonerIdentity, id_fingerprint
from tooling.aurora.identity import sign_bytes
from tooling.aurora.identity.identity import _canon_json_bytes, _now_unix


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
    """Create isolated SummonerIdentity peers for one test."""
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=ttl, margin=margin)
    bob = SummonerIdentity(ttl=ttl, margin=margin)
    pub_a = alice.id(str(a_dir / "id.json"))
    pub_b = bob.id(str(b_dir / "id.json"))
    return alice, bob, pub_a, pub_b


def _resign_env(sender: SummonerIdentity, env: dict, *, session_override=None, to_override=None) -> dict:
    """Return a fresh signed copy of an envelope after controlled mutation."""
    out = copy.deepcopy(env)
    if session_override is not None:
        out["session_proof"] = session_override
    if to_override is not None:
        out["to"] = to_override
    core = {
        "v": out["v"],
        "payload": out["payload"],
        "session_proof": out["session_proof"],
        "from": out["from"],
        "to": out["to"],
    }
    out["sig"] = sign_bytes(sender._priv_sig, _canon_json_bytes(core))
    return out


def _contains_peer(peers: list[dict], pub: dict) -> bool:
    """Return whether one peer list contains a given public identity."""
    target = pub.get("pub_sig_b64") if isinstance(pub, dict) else None
    if not isinstance(target, str):
        return False
    for peer in peers:
        if isinstance(peer, dict) and peer.get("pub_sig_b64") == target:
            return True
    return False


def _complete_exchange(alice, bob, pub_a, pub_b):
    """Run one completed Alice -> Bob -> Alice exchange."""
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "hello"}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env0)) == {"msg": "hello"}
    s1 = asyncio.run(bob.continue_session(pub_a, env0["session_proof"]))
    env1 = asyncio.run(bob.seal_envelope({"msg": "ack"}, s1, to=pub_a))
    assert asyncio.run(alice.open_envelope(env1)) == {"msg": "ack"}
    return env0, env1


def test_bootstrap_age_nonzero_is_rejected_but_identity_only_stays_known(tmp_path):
    """Failed bootstrap continuity should not promote a peer from known to verified."""
    alice, bob, _, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "hello"}, s0, to=pub_b))
    bad_session = dict(env0["session_proof"])
    bad_session["age"] = 5
    env_bad = _resign_env(alice, env0, session_override=bad_session)

    st = asyncio.run(bob.open_envelope(env_bad, return_status=True))
    assert st["ok"] is False
    assert st["code"] == "session_verify_failed"
    assert _contains_peer(bob.list_known_peers(), env_bad["from"])
    assert not _contains_peer(bob.list_verified_peers(), env_bad["from"])


def test_verify_discovery_envelope_marks_peer_verified(tmp_path):
    """Verified discovery should explicitly promote a peer to verified."""
    alice, bob, pub_a, _ = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(None, ttl=15))
    env0 = asyncio.run(alice.seal_envelope(None, s0, to=None))

    st = asyncio.run(bob.verify_discovery_envelope(env0, return_status=True))
    assert st["ok"] is True
    assert _contains_peer(bob.list_verified_peers(), pub_a)


def test_successful_open_envelope_marks_peer_verified(tmp_path):
    """A successfully opened exchange envelope should mark the sender as verified."""
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    s0 = asyncio.run(alice.start_session(pub_b))
    env0 = asyncio.run(alice.seal_envelope({"msg": "hello"}, s0, to=pub_b))

    st = asyncio.run(bob.open_envelope(env0, return_status=True))
    assert st["ok"] is True
    assert _contains_peer(bob.list_verified_peers(), pub_a)


def test_list_verified_peers_uses_completed_continuity_evidence(tmp_path):
    """Completed continuity should count as verified when peer records lack an explicit flag."""
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    _complete_exchange(alice, bob, pub_a, pub_b)

    fp = id_fingerprint(pub_b["pub_sig_b64"])
    rec = alice._peer_keys[fp]
    rec.pop("verified", None)
    rec.pop("verified_at", None)
    rec.pop("verified_via", None)

    assert _contains_peer(alice.list_verified_peers(), pub_b)


def test_continue_session_preserves_age_after_history_backed_restart(tmp_path):
    """Replies on a restarted thread should carry the established continuity age forward."""
    alice, bob, pub_a, pub_b = _make_pair(tmp_path)
    _complete_exchange(alice, bob, pub_a, pub_b)

    s2 = asyncio.run(alice.start_session(pub_b))
    assert s2["age"] == 1
    env2 = asyncio.run(alice.seal_envelope({"msg": "again"}, s2, to=pub_b))
    assert asyncio.run(bob.open_envelope(env2)) == {"msg": "again"}

    s3 = asyncio.run(bob.continue_session(pub_a, env2["session_proof"]))
    assert isinstance(s3, dict)
    assert s3["age"] == 1


def test_start_session_respects_live_stream_current_link_not_original_ttl(tmp_path):
    """Role-0 restart should stay blocked while a stream current_link is still live."""
    alice, _, _, pub_b = _make_pair(tmp_path, ttl=120, margin=0)
    s0 = asyncio.run(alice.start_session(pub_b, stream=True, stream_ttl=30))
    assert isinstance(s0, dict)

    key = f"{id_fingerprint(pub_b['pub_sig_b64'])}:0"
    rec = alice._sessions[key]
    current = dict(rec.get("current_link") or {})
    assert isinstance(current, dict)
    current["ts"] = 0
    current["ttl"] = 1
    current["stream_active"] = True
    current["stream_last_ts"] = _now_unix()
    current["stream_ttl"] = 30
    rec["current_link"] = current
    alice._sessions[key] = rec

    st = asyncio.run(alice.start_session(pub_b, return_status=True))
    assert st["ok"] is False
    assert st["code"] == "active_session_exists"
