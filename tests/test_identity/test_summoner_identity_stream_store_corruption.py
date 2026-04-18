"""Store-validation and malformed-state tests for streaming-related fallback stores."""
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

def _write(path, text):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)

def _store_doc(store_name, version, data):
    return {
        '__summoner_identity_store__': store_name,
        'v': version,
        'data': data,
    }


@pytest.mark.parametrize(
    ('filename', 'store_name', 'version', 'payload', 'persist_replay'),
    [
        ('sessions.json', 'sessions', SESSIONS_STORE_VERSION, ['bad', 'shape'], False),
        ('peer_keys.json', 'peer_keys', PEER_KEYS_STORE_VERSION, ['oops'], False),
        ('replay.json', 'replay', REPLAY_STORE_VERSION, 'oops', True),
    ],
)
def test_non_dict_store_docs_raise_on_load_fail_closed(
    tmp_path,
    filename,
    store_name,
    version,
    payload,
    persist_replay,
):
    d = tmp_path / 'node'
    d.mkdir(parents=True, exist_ok=True)
    _write(d / filename, json.dumps(payload))
    identity = SummonerIdentity(
        store_dir=str(d),
        persist_local=True,
        load_local=True,
        persist_replay=persist_replay,
        ttl=120,
        margin=0,
    )
    with pytest.raises(ValueError, match=fr'invalid {store_name} store document'):
        identity.id(str(d / 'id.json'))


@pytest.mark.parametrize(
    ('filename', 'store_name', 'version', 'payload', 'persist_replay'),
    [
        ('sessions.json', 'sessions', SESSIONS_STORE_VERSION, {'x:1': {}}, False),
        ('peer_keys.json', 'peer_keys', PEER_KEYS_STORE_VERSION, {'fingerprint': {}}, False),
        ('replay.json', 'replay', REPLAY_STORE_VERSION, {'items': {}}, True),
    ],
)
def test_unwrapped_store_docs_raise_on_load_fail_closed(
    tmp_path,
    filename,
    store_name,
    version,
    payload,
    persist_replay,
):
    d = tmp_path / 'node'
    d.mkdir(parents=True, exist_ok=True)
    _write(d / filename, json.dumps(payload))
    identity = SummonerIdentity(
        store_dir=str(d),
        persist_local=True,
        load_local=True,
        persist_replay=persist_replay,
        ttl=120,
        margin=0,
    )
    with pytest.raises(ValueError, match=fr'invalid {store_name} store document'):
        identity.id(str(d / 'id.json'))

def test_invalid_json_sessions_file_raises_on_load_fail_closed(tmp_path):
    d = tmp_path / 'node'
    d.mkdir(parents=True, exist_ok=True)
    _write(d / 'sessions.json', '{invalid-json')
    identity = SummonerIdentity(store_dir=str(d), persist_local=True, load_local=True, ttl=120, margin=0)
    with pytest.raises(json.JSONDecodeError):
        identity.id(str(d / 'id.json'))

@pytest.mark.parametrize(
    ('filename', 'store_name', 'version', 'persist_replay'),
    [
        ('sessions.json', 'sessions', SESSIONS_STORE_VERSION, False),
        ('peer_keys.json', 'peer_keys', PEER_KEYS_STORE_VERSION, False),
        ('replay.json', 'replay', REPLAY_STORE_VERSION, True),
    ],
)
def test_unsupported_wrapped_store_version_raises_on_load_fail_closed(
    tmp_path,
    filename,
    store_name,
    version,
    persist_replay,
):
    d = tmp_path / 'node'
    d.mkdir(parents=True, exist_ok=True)
    bad = _store_doc(store_name, f'{version}.future', {})
    _write(d / filename, json.dumps(bad))
    identity = SummonerIdentity(
        store_dir=str(d),
        persist_local=True,
        load_local=True,
        persist_replay=persist_replay,
        ttl=120,
        margin=0,
    )
    with pytest.raises(ValueError):
        identity.id(str(d / 'id.json'))

def test_store_doc_current_link_missing_stream_fields_does_not_break_continue(tmp_path):
    d = tmp_path / 'node'
    d.mkdir(parents=True, exist_ok=True)
    identity = SummonerIdentity(store_dir=str(d), persist_local=True, load_local=True, ttl=120, margin=0)
    pub = identity.id(str(d / 'id.json'))
    fp = id_fingerprint(pub['pub_sig_b64'])
    key = f'{fp}:1'
    stored_sessions = {
        key: {
            'peer_id': fp,
            'local_role': 1,
            'active': True,
            'past_chain': [],
            'history': [],
            'window': 20,
            'current_link': {'0_nonce': 'aa' * 16, '1_nonce': 'bb' * 16, 'ts': 1, 'ttl': 1, 'completed': False, 'seen': []},
        }
    }
    _write(
        d / 'sessions.json',
        json.dumps(_store_doc('sessions', SESSIONS_STORE_VERSION, stored_sessions)),
    )
    identity2 = SummonerIdentity(store_dir=str(d), persist_local=True, load_local=True, ttl=120, margin=0)
    identity2.id(str(d / 'id.json'))
    st = asyncio.run(identity2.continue_session(pub, {'sender_role': 0}, return_status=True))
    assert st['ok'] is False
    assert isinstance(st['code'], str)
