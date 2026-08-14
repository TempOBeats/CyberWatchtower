from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class IntentSelection:
    intent: str
    confidence: str


class ModelGateway(Protocol):
    name: str

    def select_intent(self, request: str) -> IntentSelection:
        """Select a bounded intent; gateways do not execute capabilities."""
