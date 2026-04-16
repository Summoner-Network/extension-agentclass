"""identity metadata tests.

These tests document metadata semantics for identity persistence and envelope-level
ephemeral overrides in the SummonerIdentity implementation.
"""
import asyncio
import os
import sys
import pytest
target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..'))
if target_path not in sys.path:
    sys.path.insert(0, target_path)
from tooling.aurora import SummonerIdentity, verify_public_id

def _make_env(tmp_path):
    """Create two isolated SummonerIdentity instances and directories."""
    a_dir = tmp_path / 'a'
    b_dir = tmp_path / 'b'
    a_dir.mkdir(parents=True, exist_ok=True)
    b_dir.mkdir(parents=True, exist_ok=True)
    identity_a = SummonerIdentity(ttl=60, margin=0)
    identity_b = SummonerIdentity(ttl=60, margin=0)
    return (identity_a, identity_b, a_dir, b_dir)

def test_update_id_meta_persists_and_resigns(tmp_path):
    """`update_id_meta` should persist to disk and keep public identity signature valid."""
    identity_a, _, a_dir, _ = _make_env(tmp_path)
    pub = identity_a.id(str(a_dir / 'id.json'))
    assert 'meta' not in pub
    updated = identity_a.update_id_meta({'role': 'planner'})
    assert updated.get('meta') == {'role': 'planner'}
    identity_a2 = SummonerIdentity()
    pub2 = identity_a2.id(str(a_dir / 'id.json'))
    assert pub2.get('meta') == {'role': 'planner'}
    verify_public_id(pub2)

def test_seal_envelope_id_meta_is_ephemeral(tmp_path):
    """`id_meta` in `seal_envelope` is in-memory/ephemeral and must not rewrite identity file."""
    identity_a, identity_b, a_dir, b_dir = _make_env(tmp_path)
    pub_a = identity_a.id(str(a_dir / 'id.json'), meta='v1')
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b, id_meta='v2'))
    assert env['from'].get('meta') == 'v2'
    identity_a2 = SummonerIdentity()
    pub2 = identity_a2.id(str(a_dir / 'id.json'))
    assert pub2.get('meta') == 'v1'
    s1 = asyncio.run(identity_a.start_session(pub_b, force_reset=True))
    env2 = asyncio.run(identity_a.seal_envelope({'msg': 'hi2'}, s1, to=pub_b))
    assert env2['from'].get('meta') == 'v2'

def test_seal_envelope_uses_latest_meta_when_none(tmp_path):
    """Without per-envelope override, sender metadata should come from latest in-memory identity."""
    identity_a, identity_b, a_dir, b_dir = _make_env(tmp_path)
    identity_a.id(str(a_dir / 'id.json'), meta='v1')
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    identity_a.update_id_meta('v3')
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert env['from'].get('meta') == 'v3'

def test_update_id_meta_requires_password_for_encrypted_identity(tmp_path):
    """Encrypted identity files require password to mutate metadata."""
    identity_a, _, a_dir, _ = _make_env(tmp_path)
    identity_a.id(str(a_dir / 'id.json'), meta='v1', password=b'pw')
    with pytest.raises(ValueError):
        identity_a.update_id_meta('v2')
    updated = identity_a.update_id_meta('v2', password=b'pw')
    assert updated.get('meta') == 'v2'

def test_meta_absent_is_valid(tmp_path):
    """Metadata is optional; envelopes remain valid when `meta` is absent."""
    identity_a, identity_b, a_dir, b_dir = _make_env(tmp_path)
    pub_a = identity_a.id(str(a_dir / 'id.json'))
    pub_b = identity_b.id(str(b_dir / 'id.json'))
    assert 'meta' not in pub_a
    s0 = asyncio.run(identity_a.start_session(pub_b))
    env = asyncio.run(identity_a.seal_envelope({'msg': 'hi'}, s0, to=pub_b))
    assert asyncio.run(identity_b.open_envelope(env)) == {'msg': 'hi'}
