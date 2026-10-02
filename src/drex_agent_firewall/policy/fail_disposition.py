"""Fail-open vs fail-closed resolution on provider error or timeout."""

from __future__ import annotations

from drex_agent_firewall.schemas.config import FailDisposition
from drex_agent_firewall.schemas.decision import ActionClass, FinalDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope


class FailDispositionResolver:
    """Resolves disposition when Drex evaluation fails or times out."""

    def __init__(self, disposition: FailDisposition):
        self.disposition = disposition

    def resolve(self, envelope: ActionEnvelope, error: Exception) -> FinalDecision:
        # Heuristic determination of ActionClass if not yet evaluated
        if envelope.read_only:
            ac = ActionClass.READ
        elif envelope.destructive:
            ac = ActionClass.DELETE
        elif envelope.external_write:
            ac = ActionClass.EXTERNAL_PUBLISH
        elif envelope.filesystem_write:
            ac = ActionClass.WRITE
        elif envelope.process_execution:
            ac = ActionClass.EXECUTE
        elif envelope.network_access:
            ac = ActionClass.NETWORK
        elif envelope.credential_access:
            ac = ActionClass.AUTH
        else:
            ac = ActionClass.UNKNOWN

        return self.disposition.for_action_class(ac)
