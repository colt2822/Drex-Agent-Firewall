"""Base interface for Drex Decision Providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from drex_agent_firewall.schemas.decision import DrexEvaluationResult
from drex_agent_firewall.schemas.envelope import ActionEnvelope


class BaseDecisionProvider(ABC):
    """Abstract base class for all decision providers (Live Drex, Replay, etc.)."""

    @abstractmethod
    def evaluate(self, envelope: ActionEnvelope) -> DrexEvaluationResult:
        """Evaluate an ActionEnvelope synchronously and return structured probabilities."""
        pass

    @abstractmethod
    async def evaluate_async(self, envelope: ActionEnvelope) -> DrexEvaluationResult:
        """Evaluate an ActionEnvelope asynchronously."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifying name of the provider ('drex' or 'REPLAY')."""
        pass
