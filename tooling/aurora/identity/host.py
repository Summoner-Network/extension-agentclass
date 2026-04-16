from __future__ import annotations

from typing import Any, Optional

from .identity import (
    SummonerIdentity,
    ENV_VERSION,
    HISTORY_PROOF_VERSION,
    ID_VERSION,
    IDENTITY_CONTROLS_VERSION,
    PAYLOAD_ENC_VERSION,
    PEER_KEYS_STORE_VERSION,
    REPLAY_STORE_VERSION,
    SESSIONS_STORE_VERSION,
)


IDENTITY_HOST_VERSION = "aurora.identity.host.v1"


class IdentityHostMixin:
    """
    Cooperative Aurora mixin that hosts a SummonerIdentity instance by composition.

    The mixin intentionally avoids flattening the SummonerIdentity API onto the
    agent class. Callers access the crypto/session engine via `agent.identity`
    after attaching one with `attach_identity(...)`.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identity: Optional[SummonerIdentity] = None

    @staticmethod
    def identity_versions() -> dict[str, str]:
        return {
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

    def attach_identity(
        self,
        identity: Optional[SummonerIdentity] = None,
        controls: Optional[object] = None,
        **summoner_identity_kwargs: Any,
    ) -> SummonerIdentity:
        """
        Attach a SummonerIdentity to this Aurora host.

        Use this to bind the cryptographic principal that the workload should
        use. A common Aurora pattern is to prepare several SummonerIdentity
        objects ahead of time and bind one of them to the agent when that
        principal becomes active. If `controls` is provided, those controls are
        attached to the identity before the host stores it on `self.identity`.
        """
        if identity is not None and summoner_identity_kwargs:
            raise ValueError(
                "Provide either an existing SummonerIdentity or constructor kwargs, not both."
            )

        if identity is None:
            identity = SummonerIdentity(**summoner_identity_kwargs)
        elif not isinstance(identity, SummonerIdentity):
            raise TypeError("identity must be a SummonerIdentity instance")
        if controls is not None:
            identity.attach_controls(controls)

        self.identity = identity
        return identity

    def detach_identity(self) -> Optional[SummonerIdentity]:
        identity = self.identity
        self.identity = None
        return identity

    def require_identity(self) -> SummonerIdentity:
        if self.identity is None:
            raise RuntimeError(
                "No SummonerIdentity is attached. Call attach_identity(...) first."
            )
        return self.identity

    def has_identity(self) -> bool:
        return self.identity is not None
