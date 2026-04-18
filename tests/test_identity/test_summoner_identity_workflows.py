"""Workflow tests for SummonerIdentity end-to-end scenarios."""
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, id_fingerprint
from tooling.aurora.identity import ENV_VERSION, PAYLOAD_ENC_VERSION, sign_bytes
from tooling.aurora.identity.identity import _canon_json_bytes

@pytest.fixture(autouse=True)
def _reset_class_hooks():
    """Reset class-level hooks around each workflow test."""
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

def test_workflow_peer_search_after_reload_shows_legit_and_impersonator(tmp_path):
    """Bob reloads persisted peer cache and still sees two 'alice' identities by fingerprint."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    atk_dir = tmp_path / 'attacker'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    atk_dir.mkdir(parents=True, exist_ok=True)
    bob = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True)
    alice = SummonerIdentity(store_dir=str(a_dir), persist_local=True, load_local=True)
    pub_b = bob.id(str(b_dir / 'id.json'), meta='bob')
    pub_a = alice.id(str(a_dir / 'id.json'), meta='alice')
    s0 = asyncio.run(alice.start_session(pub_b))
    env_good = asyncio.run(alice.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env_good)) == {'msg': 'hi'}
    attacker = SummonerIdentity(store_dir=str(atk_dir), persist_local=False, load_local=False)
    fake_pub_a = attacker.id(str(atk_dir / 'id.json'), meta='alice')
    s1 = asyncio.run(attacker.start_session(pub_b))
    env_bad = asyncio.run(attacker.seal_envelope({'msg': 'evil'}, s1, to=pub_b))
    assert asyncio.run(bob.open_envelope(env_bad)) == {'msg': 'evil'}
    bob_reloaded = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True)
    bob_reloaded.id(str(b_dir / 'id.json'), meta='bob')
    hits = bob_reloaded.find_peer('alice')
    assert len(hits) >= 2
    assert any((p.get('pub_sig_b64') == pub_a['pub_sig_b64'] for p in hits))
    assert any((p.get('pub_sig_b64') == fake_pub_a['pub_sig_b64'] for p in hits))
    assert id_fingerprint(pub_a['pub_sig_b64']) != id_fingerprint(fake_pub_a['pub_sig_b64'])

def test_workflow_cross_session_ciphertext_reuse_rejected(tmp_path):
    """Re-signing old ciphertext under a new session proof must fail on receiver open."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(store_dir=str(a_dir), persist_local=False, load_local=False)
    bob = SummonerIdentity(store_dir=str(b_dir), persist_local=False, load_local=False)
    pub_a = alice.id(str(a_dir / 'id.json'), meta='alice')
    pub_b = bob.id(str(b_dir / 'id.json'), meta='bob')
    s0 = asyncio.run(alice.start_session(pub_b))
    env_a = asyncio.run(alice.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    s1 = asyncio.run(alice.start_session(pub_b, force_reset=True))
    core = {'v': ENV_VERSION, 'payload': env_a['payload'], 'session_proof': s1, 'from': pub_a, 'to': pub_b}
    sig = sign_bytes(alice._priv_sig, _canon_json_bytes(core))
    env_reuse = dict(core)
    env_reuse['sig'] = sig
    assert asyncio.run(bob.open_envelope(env_reuse)) is None

def test_workflow_optional_confidentiality_encrypted_vs_public(tmp_path):
    """Encrypted when `to` is set; plaintext payload when `to=None`."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(store_dir=str(a_dir), persist_local=False, load_local=False)
    bob = SummonerIdentity(store_dir=str(b_dir), persist_local=False, load_local=False)
    pub_b = bob.id(str(b_dir / 'id.json'), meta='bob')
    alice.id(str(a_dir / 'id.json'), meta='alice')
    s_enc = asyncio.run(alice.start_session(pub_b))
    env_enc = asyncio.run(alice.seal_envelope({'msg': 'secret'}, s_enc, to=pub_b))
    assert isinstance(env_enc.get('payload'), dict)
    assert 'ciphertext' in env_enc['payload']
    s_pub = asyncio.run(alice.start_session(None))
    env_pub = asyncio.run(alice.seal_envelope({'msg': 'public'}, s_pub, to=None))
    assert env_pub['payload'] == {'msg': 'public'}

def test_workflow_discovery_then_direct_encrypted_reply(tmp_path):
    """Public discovery should transition to a new per-peer encrypted reply flow."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(store_dir=str(a_dir), persist_local=False, load_local=False)
    bob = SummonerIdentity(store_dir=str(b_dir), persist_local=False, load_local=False)
    pub_a = alice.id(str(a_dir / 'id.json'), meta='alice')
    bob.id(str(b_dir / 'id.json'), meta='bob')
    s0 = asyncio.run(alice.start_session(None))
    env_hello = asyncio.run(alice.seal_envelope({'msg': 'hello'}, s0, to=None))
    assert asyncio.run(bob.open_envelope(env_hello)) == {'msg': 'hello'}
    s1 = asyncio.run(bob.start_session(env_hello['from']))
    env_reply = asyncio.run(bob.seal_envelope({'msg': 'ack'}, s1, to=env_hello['from']))
    assert asyncio.run(alice.open_envelope(env_reply)) == {'msg': 'ack'}
    assert env_reply['to']['pub_sig_b64'] == pub_a['pub_sig_b64']

def test_workflow_rejects_encrypted_payload_when_to_none(tmp_path):
    """Receiver should reject payload.enc.v1 envelopes that set `to=None`."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(store_dir=str(a_dir), persist_local=False, load_local=False)
    bob = SummonerIdentity(store_dir=str(b_dir), persist_local=False, load_local=False)
    pub_a = alice.id(str(a_dir / 'id.json'), meta='alice')
    bob.id(str(b_dir / 'id.json'), meta='bob')
    s0 = asyncio.run(alice.start_session(None))
    core = {'v': ENV_VERSION, 'payload': {'v': PAYLOAD_ENC_VERSION, 'nonce': 'AA==', 'ciphertext': 'AA=='}, 'session_proof': s0, 'from': pub_a, 'to': None}
    sig = sign_bytes(alice._priv_sig, _canon_json_bytes(core))
    env_bad = dict(core)
    env_bad['sig'] = sig
    st = asyncio.run(bob.open_envelope(env_bad, return_status=True))
    assert st['ok'] is False
    assert st['code'] == 'encrypted_payload_without_to'

def test_workflow_restart_with_and_without_load_local(tmp_path):
    """Persisted peer cache is visible after restart only when load_local=True."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    alice = SummonerIdentity(store_dir=str(a_dir), persist_local=True, load_local=True)
    bob = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True)
    pub_b = bob.id(str(b_dir / 'id.json'), meta='bob')
    pub_a = alice.id(str(a_dir / 'id.json'), meta='alice')
    s0 = asyncio.run(alice.start_session(pub_b))
    env = asyncio.run(alice.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(bob.open_envelope(env)) == {'msg': 'hi'}
    bob_no_load = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=False)
    bob_no_load.id(str(b_dir / 'id.json'), meta='bob')
    assert bob_no_load.find_peer('alice') == []
    bob_loaded = SummonerIdentity(store_dir=str(b_dir), persist_local=True, load_local=True)
    bob_loaded.id(str(b_dir / 'id.json'), meta='bob')
    hits = bob_loaded.find_peer('alice')
    assert any((p.get('pub_sig_b64') == pub_a['pub_sig_b64'] for p in hits))
