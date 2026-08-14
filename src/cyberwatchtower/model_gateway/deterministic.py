from enum import Enum

from cyberwatchtower.advisor.questions import QuestionIntent, classify_question

from .base import IntentSelection


class GatewayIntent(str, Enum):
    SECURITY_BRIEFING = "SECURITY_BRIEFING"
    WHY_DANGEROUS = QuestionIntent.WHY_DANGEROUS.value
    WHAT_CHANGED = QuestionIntent.WHAT_CHANGED.value
    FIX_FIRST = QuestionIntent.FIX_FIRST.value
    UNSUPPORTED = "UNSUPPORTED"


class DeterministicGateway:
    name = "deterministic"

    def select_intent(self, request: str) -> IntentSelection:
        normalized = " ".join(request.casefold().split())
        if "briefing" in normalized or "security posture" in normalized:
            return IntentSelection(GatewayIntent.SECURITY_BRIEFING.value, "HIGH")
        question_intent = classify_question(request)
        if question_intent != QuestionIntent.UNKNOWN:
            return IntentSelection(question_intent.value, "HIGH")
        return IntentSelection(GatewayIntent.UNSUPPORTED.value, "LOW")
