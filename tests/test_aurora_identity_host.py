import os
import sys

import pytest

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.aurora import (
    AgentMerger,
    AgentTranslation,
    SummonerIdentity,
    SummonerIdentityControls,
    IDENTITY_HOST_VERSION,
    SummonerAgent,
)
from tooling.aurora.identity import (
    ENV_VERSION,
    HISTORY_PROOF_VERSION,
    ID_VERSION,
    IDENTITY_CONTROLS_VERSION,
    PAYLOAD_ENC_VERSION,
    PEER_KEYS_STORE_VERSION,
    REPLAY_STORE_VERSION,
    SESSIONS_STORE_VERSION,
)


def _close_clients(*clients):
    for client in clients:
        if client is not None:
            client.loop.close()


def test_summoner_agent_identity_host_attach_require_and_detach():
    agent = SummonerAgent(name="aurora-identity-host")

    try:
        assert agent.identity is None
        assert agent.has_identity() is False

        with pytest.raises(RuntimeError):
            agent.require_identity()

        identity = agent.attach_identity(ttl=42, persist_replay=True)

        assert isinstance(identity, SummonerIdentity)
        assert agent.identity is identity
        assert agent.require_identity() is identity
        assert agent.has_identity() is True
        assert identity.ttl == 42
        assert identity.persist_replay is True

        versions = agent.identity_versions()
        assert versions == {
            "integration": IDENTITY_HOST_VERSION,
            "controls": IDENTITY_CONTROLS_VERSION,
            "id_record": ID_VERSION,
            "envelope": ENV_VERSION,
            "payload_encryption": PAYLOAD_ENC_VERSION,
            "history_proof": HISTORY_PROOF_VERSION,
            "sessions_store": SESSIONS_STORE_VERSION,
            "peer_keys_store": PEER_KEYS_STORE_VERSION,
            "replay_store": REPLAY_STORE_VERSION,
        }

        assert SummonerIdentity.store_versions() == {
            "sessions": SESSIONS_STORE_VERSION,
            "peer_keys": PEER_KEYS_STORE_VERSION,
            "replay": REPLAY_STORE_VERSION,
        }
        assert SummonerIdentity.controls_version() == IDENTITY_CONTROLS_VERSION
        assert SummonerIdentityControls.version() == IDENTITY_CONTROLS_VERSION

        assert agent.detach_identity() is identity
        assert agent.identity is None
        assert agent.has_identity() is False
    finally:
        _close_clients(agent)


def test_identity_host_accepts_existing_summoner_identity_and_rejects_mixed_inputs():
    agent = SummonerAgent(name="aurora-identity-existing")

    try:
        provided = SummonerIdentity(ttl=7)
        attached = agent.attach_identity(provided)

        assert attached is provided
        assert agent.identity is provided

        with pytest.raises(ValueError):
            agent.attach_identity(provided, ttl=9)
    finally:
        _close_clients(agent)


def test_identity_host_rejects_non_identity_objects():
    agent = SummonerAgent(name="aurora-identity-bad-type")

    try:
        with pytest.raises(TypeError, match="SummonerIdentity"):
            agent.attach_identity(identity=object())
    finally:
        _close_clients(agent)


def test_identity_host_can_attach_controls_to_identity():
    agent = SummonerAgent(name="aurora-identity-controls")

    try:
        controls = SummonerIdentityControls()
        attached = agent.attach_identity(ttl=11, controls=controls)

        assert agent.identity is attached
        assert attached.require_controls() is controls
        assert attached.has_controls() is True
        assert attached.detach_controls() is controls
        assert attached.has_controls() is False
    finally:
        _close_clients(agent)


@pytest.mark.parametrize(
    ("client_type", "factory"),
    [
        ("merger", lambda: AgentMerger([], name="aurora-identity-merger")),
        ("translation", lambda: AgentTranslation([], name="aurora-identity-translation")),
    ],
)
def test_identity_host_is_available_on_merger_and_translation(client_type, factory):
    client = factory()

    try:
        assert client_type in {"merger", "translation"}
        assert client.identity is None

        identity = client.attach_identity(ttl=21)

        assert isinstance(identity, SummonerIdentity)
        assert client.require_identity() is identity
        assert identity.ttl == 21
    finally:
        _close_clients(client)
