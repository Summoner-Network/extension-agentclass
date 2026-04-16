"""Storage/persistence behavior tests for SummonerIdentity fallback stores."""
import asyncio
import json
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, id_fingerprint
from tooling.aurora.identity import (
    PEER_KEYS_STORE_VERSION,
    REPLAY_STORE_VERSION,
    SESSIONS_STORE_VERSION,
)

def _make_pair(tmp_path, **kwargs):
    """Create isolated pair plus identity directories with configurable envelope options."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(**kwargs)
    identity_b = SummonerIdentity(**kwargs)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    return (identity_a, identity_b, pub_a, pub_b, a_dir, b_dir)

@pytest.fixture(autouse=True)
def _reset_class_hooks():
    """Reset all class-level storage/session hooks around each storage test."""
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

def test_clock_skew_future_ts_rejected(tmp_path):
    """Receiver should reject sessions too far in the future when skew limit is configured."""
    identity_a, identity_b, _, pub_b, _, _ = _make_pair(tmp_path, ttl=60, margin=0, max_clock_skew_seconds=1)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    s0['ts'] = s0['ts'] + 120
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) is None

def test_peer_key_store_is_fingerprint_keyed(tmp_path):
    """Peer cache should index separate identities by fingerprint, not filename/path."""
    identity_a, identity_b, _, pub_b, a_dir, b_dir = _make_pair(tmp_path, ttl=60, margin=0)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}
    alt_dir = tmp_path / 'alt'
    alt_dir.mkdir(parents=True, exist_ok=True)
    identity_alt = SummonerIdentity(ttl=60, margin=0)
    alt_pub = identity_alt.id(str(alt_dir / 'id.json'))
    s1 = asyncio.run(identity_alt.start_session(identity_b.public_id))
    env2 = asyncio.run(identity_alt.seal_envelope({'msg': 'new'}, s1, to=identity_b.public_id))
    assert asyncio.run(identity_b.open_envelope(env2)) == {'msg': 'new'}
    peer_keys = identity_b._peer_keys
    fp_a = id_fingerprint(identity_a.public_id['pub_sig_b64'])
    fp_alt = id_fingerprint(alt_pub['pub_sig_b64'])
    assert fp_a in peer_keys
    assert fp_alt in peer_keys

def test_replay_cache_blocks_reopen_across_restart(tmp_path):
    """Persisted replay cache should reject a replayed message after restart."""
    identity_a, identity_b, _, pub_b, a_dir, b_dir = _make_pair(tmp_path, ttl=60, margin=0, persist_replay=True)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}
    identity_b2 = SummonerIdentity(ttl=60, margin=0, persist_replay=True)
    identity_b2.id(str(b_dir / 'id.json'))
    assert asyncio.run(identity_b2.open_envelope(env)) is None

def test_persistence_files_written(tmp_path):
    """Fallback persistence should materialize expected JSON files after successful traffic."""
    identity_a, identity_b, _, pub_b, a_dir, b_dir = _make_pair(tmp_path, ttl=60, margin=0, persist_replay=True)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}
    assert (a_dir / 'sessions.json').exists()
    assert (b_dir / 'sessions.json').exists()
    assert (b_dir / 'peer_keys.json').exists()
    assert (b_dir / 'replay.json').exists()

def test_persistence_files_use_versioned_store_docs(tmp_path):
    """Fallback persistence should write wrapped store docs with explicit versions."""
    identity_a, identity_b, _, pub_b, a_dir, b_dir = _make_pair(tmp_path, ttl=60, margin=0, persist_replay=True)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}

    with open(a_dir / 'sessions.json', 'r', encoding='utf-8') as f:
        a_sessions = json.load(f)
    with open(b_dir / 'peer_keys.json', 'r', encoding='utf-8') as f:
        b_peer_keys = json.load(f)
    with open(b_dir / 'replay.json', 'r', encoding='utf-8') as f:
        b_replay = json.load(f)

    assert a_sessions['__summoner_identity_store__'] == 'sessions'
    assert a_sessions['v'] == SESSIONS_STORE_VERSION
    assert isinstance(a_sessions['data'], dict)

    assert b_peer_keys['__summoner_identity_store__'] == 'peer_keys'
    assert b_peer_keys['v'] == PEER_KEYS_STORE_VERSION
    assert isinstance(b_peer_keys['data'], dict)

    assert b_replay['__summoner_identity_store__'] == 'replay'
    assert b_replay['v'] == REPLAY_STORE_VERSION
    assert isinstance(b_replay['data'], dict)

def test_list_known_peers_returns_cached_public_ids(tmp_path):
    """Known peer listing should return unique public_id records observed by receiver."""
    identity_a, identity_b, _, pub_b, _, _ = _make_pair(tmp_path, ttl=60, margin=0)
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'first'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'first'}
    alt_dir = tmp_path / 'alt-list'
    alt_dir.mkdir(parents=True, exist_ok=True)
    identity_alt = SummonerIdentity(ttl=60, margin=0)
    alt_pub = identity_alt.id(str(alt_dir / 'id.json'))
    s1 = asyncio.run(identity_alt.start_session(identity_b.public_id))
    env2 = asyncio.run(identity_alt.seal_envelope({'msg': 'second'}, s1, to=identity_b.public_id))
    assert asyncio.run(identity_b.open_envelope(env2)) == {'msg': 'second'}
    known = identity_b.list_known_peers()
    sigs = {p.get('pub_sig_b64') for p in known if isinstance(p, dict)}
    assert identity_a.public_id['pub_sig_b64'] in sigs
    assert alt_pub['pub_sig_b64'] in sigs

def test_verify_discovery_envelope_accepts_consecutive_public_hellos(tmp_path):
    """Discovery-only verification should learn consecutive public hellos from distinct peers."""
    recv_dir = tmp_path / 'recv'
    recv_dir.mkdir(parents=True, exist_ok=True)
    receiver = SummonerIdentity(ttl=60, margin=0, persist_replay=True)
    receiver.id(str(recv_dir / 'id.json'))

    alice_dir = tmp_path / 'alice'
    alice_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(ttl=60, margin=0, persist_replay=True)
    alice.id(str(alice_dir / 'id.json'))

    carol_dir = tmp_path / 'carol'
    carol_dir.mkdir(parents=True, exist_ok=True)
    carol = SummonerIdentity(ttl=60, margin=0, persist_replay=True)
    carol.id(str(carol_dir / 'id.json'))

    s0 = asyncio.run(alice.start_session(None, ttl=15))
    env0 = asyncio.run(alice.seal_envelope(None, s0, to=None))
    st0 = asyncio.run(receiver.verify_discovery_envelope(env0, return_status=True))
    assert st0["ok"] is True
    assert st0.get("data") is None

    s1 = asyncio.run(carol.start_session(None, ttl=15))
    env1 = asyncio.run(carol.seal_envelope(None, s1, to=None))
    st1 = asyncio.run(receiver.verify_discovery_envelope(env1, return_status=True))
    assert st1["ok"] is True
    assert st1.get("data") is None

    known = receiver.list_known_peers()
    sigs = {p.get("pub_sig_b64") for p in known if isinstance(p, dict)}
    assert alice.public_id["pub_sig_b64"] in sigs
    assert carol.public_id["pub_sig_b64"] in sigs

def test_find_peer_matches_text_in_stringified_public_id(tmp_path):
    """find_peer should return IDs whose stringified public_id contains search text."""
    identity_a, identity_b, _, pub_b, _, _ = _make_pair(tmp_path, ttl=60, margin=0)
    identity_a.update_id_meta({'label': 'alice-search-marker'})
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hello'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hello'}
    matches = identity_b.find_peer('alice-search-marker')
    assert any((m.get('pub_sig_b64') == identity_a.public_id['pub_sig_b64'] for m in matches))
    frag = identity_a.public_id['pub_sig_b64'][:10]
    matches_sig = identity_b.find_peer(frag)
    assert any((m.get('pub_sig_b64') == identity_a.public_id['pub_sig_b64'] for m in matches_sig))
