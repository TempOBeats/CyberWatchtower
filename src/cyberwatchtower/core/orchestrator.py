from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import Enum

from cyberwatchtower.advisor.questions import answer_question
from cyberwatchtower.briefing.builder import SecurityBriefing, build_security_briefing
from cyberwatchtower.capabilities.registry import (
    CapabilityContext,
    CapabilityPlan,
    CapabilityRegistry,
    CapabilityRequest,
    PermissionClass,
    build_read_only_registry,
)
from cyberwatchtower.conversation.session import ConversationSession, resolve_finding_reference
from cyberwatchtower.core.evidence import (
    Claim,
    EpistemicRole,
    EvidenceRef,
    EvidenceSource,
    GroundedResponse,
    ResponseSection,
)
from cyberwatchtower.core.grounding import require_grounded
from cyberwatchtower.intelligence import analyze_history
from cyberwatchtower.model_gateway.base import ModelGateway
from cyberwatchtower.model_gateway.deterministic import DeterministicGateway, GatewayIntent
from cyberwatchtower.memory.context import build_memory_context, persisted_finding_candidates
from cyberwatchtower.memory.service import SecurityMemory
from cyberwatchtower.memory.investigation_models import ReferenceState, ReferenceType


class OrchestratorState(str, Enum):
    RECEIVED = "RECEIVED"
    INTENT_CLASSIFIED = "INTENT_CLASSIFIED"
    PLAN_PROPOSED = "PLAN_PROPOSED"
    POLICY_CHECKED = "POLICY_CHECKED"
    EXECUTED = "EXECUTED"
    GROUNDED = "GROUNDED"
    COMPLETED = "COMPLETED"
    CLARIFICATION_REQUIRED = "CLARIFICATION_REQUIRED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class OrchestratorResult:
    state: OrchestratorState
    states: tuple[OrchestratorState, ...]
    plan: CapabilityPlan
    response: GroundedResponse
    briefing: SecurityBriefing | None = None


class IntelligenceOrchestrator:
    def __init__(
        self,
        gateway: ModelGateway | None = None,
        registry: CapabilityRegistry | None = None,
        memory: SecurityMemory | None = None,
    ) -> None:
        self.gateway = gateway or DeterministicGateway()
        self.memory = memory
        self.registry = registry or build_read_only_registry(memory)

    def _plan(self, intent: str, finding_id: str | None) -> CapabilityPlan:
        requests = [
            CapabilityRequest("load_reports", {}),
            CapabilityRequest("compare_scans", {}),
        ]
        if intent == GatewayIntent.WHY_DANGEROUS.value and finding_id:
            requests.append(CapabilityRequest("explain_finding", {"finding_id": finding_id}))
        return CapabilityPlan(tuple(requests))

    def _check_policy(self, plan: CapabilityPlan) -> None:
        for request in plan.requests:
            definition = self.registry.definition(request.capability_id)
            if definition.permission != PermissionClass.READ_ONLY:
                raise PermissionError(
                    "The orchestrator cannot manufacture approval for "
                    f"{request.capability_id}."
                )

    @staticmethod
    def _isolate_latest_system(reports: Sequence[dict]) -> list[dict]:
        if not reports:
            return []
        latest_system = reports[-1].get("system", {})
        system_id = latest_system.get("system_id")
        hostname = latest_system.get("hostname")
        if system_id:
            return [
                report for report in reports
                if report.get("system", {}).get("system_id") == system_id
                or (
                    report.get("system", {}).get("system_id") is None
                    and hostname
                    and report.get("system", {}).get("hostname") == hostname
                )
            ]
        if hostname:
            return [
                report for report in reports
                if report.get("system", {}).get("hostname") == hostname
            ]
        return [reports[-1]]

    def handle(
        self,
        request: str,
        *,
        session: ConversationSession | None = None,
        reports: Sequence[dict] = (),
        report_directory: str = "reports",
        explicit_finding_id: str | None = None,
    ) -> OrchestratorResult:
        session = session or ConversationSession()
        states = [OrchestratorState.RECEIVED]
        try:
            selection = self.gateway.select_intent(request)
        except Exception:
            selection = DeterministicGateway().select_intent(request)
        intent = selection.intent
        states.append(OrchestratorState.INTENT_CLASSIFIED)

        loaded_reports = self._isolate_latest_system(list(reports))
        preliminary = None
        if loaded_reports:
            preliminary = build_security_briefing(
                loaded_reports[-1],
                None,
                analyze_history(loaded_reports),
            )
        finding_id = (
            resolve_finding_reference(
                request,
                preliminary.advisor_context,
                session,
                explicit_finding_id,
            )
            if preliminary else (explicit_finding_id or session.focused_finding_id)
        )
        plan = self._plan(intent, finding_id)
        states.append(OrchestratorState.PLAN_PROPOSED)
        self._check_policy(plan)
        states.append(OrchestratorState.POLICY_CHECKED)

        initial_system_id = (
            loaded_reports[-1].get("system", {}).get("system_id")
            if loaded_reports else None
        )
        capability_context = CapabilityContext(
            report_directory, tuple(loaded_reports), self.memory, initial_system_id
        )
        if not loaded_reports:
            loaded_reports = list(self.registry.execute(plan.requests[0], capability_context))
            loaded_reports = self._isolate_latest_system(loaded_reports)
            system_id = loaded_reports[-1].get("system", {}).get("system_id") if loaded_reports else None
            capability_context = CapabilityContext(
                report_directory, tuple(loaded_reports), self.memory, system_id
            )
        if not loaded_reports:
            response = self._notice(intent, "No saved CyberWatchtower reports are available.")
            return OrchestratorResult(
                OrchestratorState.COMPLETED,
                tuple((*states, OrchestratorState.EXECUTED, OrchestratorState.GROUNDED, OrchestratorState.COMPLETED)),
                plan,
                response,
            )

        comparison = self.registry.execute(
            CapabilityRequest("compare_scans", {}), capability_context
        ) if len(loaded_reports) >= 2 else None
        if intent == GatewayIntent.WHY_DANGEROUS.value and finding_id:
            self.registry.execute(
                CapabilityRequest("explain_finding", {"finding_id": finding_id}),
                capability_context,
            )
        system_id = loaded_reports[-1].get("system", {}).get("system_id")
        memory_context = None
        base_briefing = build_security_briefing(
            loaded_reports[-1], comparison, analyze_history(loaded_reports)
        )
        if self.memory is not None and system_id:
            finding_ids = tuple(item.finding_id for item in base_briefing.advisor_context.findings)
            memory_context = build_memory_context(
                self.memory, system_id=system_id, finding_ids=finding_ids,
                findings=base_briefing.advisor_context.findings,
                action_ids=tuple(item.action_id for item in base_briefing.advisory.actions),
            )
        briefing = base_briefing if memory_context is None else build_security_briefing(
            loaded_reports[-1], comparison, analyze_history(loaded_reports), memory_context
        )
        states.append(OrchestratorState.EXECUTED)
        persisted_candidates = ()
        if self.memory is not None and system_id:
            persisted_candidates = persisted_finding_candidates(
                self.memory, system_id=system_id, session_id=session.session_id,
                known_finding_ids={item.finding_id for item in briefing.advisor_context.findings},
            )
        finding_id = resolve_finding_reference(
            request, briefing.advisor_context, session, explicit_finding_id,
            persisted_candidates,
        )

        if intent == GatewayIntent.SECURITY_BRIEFING.value:
            response = briefing.response
        elif intent in {
            GatewayIntent.WHY_DANGEROUS.value,
            GatewayIntent.WHAT_CHANGED.value,
            GatewayIntent.FIX_FIRST.value,
        }:
            if intent == GatewayIntent.WHY_DANGEROUS.value and finding_id is None:
                response = self._notice(
                    intent,
                    "Select a current finding before asking for an explanation.",
                )
                return OrchestratorResult(
                    OrchestratorState.CLARIFICATION_REQUIRED,
                    tuple((*states, OrchestratorState.CLARIFICATION_REQUIRED)),
                    plan,
                    response,
                    briefing,
                )
            answer = answer_question(
                request,
                briefing.advisor_context,
                briefing.advisory,
                finding_id,
            )
            response = self._question_response(answer.intent.value, answer.answer, answer.finding_ids, answer.action_ids)
        else:
            response = self._notice(
                intent,
                "Supported requests are: security briefing, why this is dangerous, what changed, and what to fix first.",
            )

        if memory_context and memory_context.limitation and response.notice is None:
            response = replace(response, notice=memory_context.limitation)
        response = require_grounded(response)
        states.extend((OrchestratorState.GROUNDED, OrchestratorState.COMPLETED))
        session.last_intent = intent
        focused_finding = response.finding_ids[0] if response.finding_ids else None
        focused_action = response.action_ids[0] if response.action_ids else None
        if focused_finding:
            session.focus(focused_finding, focused_action)
            if self.memory is not None and system_id:
                try:
                    now = datetime.now(timezone.utc)
                    self.memory.remember_reference(
                        system_id=system_id, session_id=session.session_id,
                        reference_type=ReferenceType.FINDING,
                        target_id=focused_finding,
                        reference_state=ReferenceState.FOCUSED,
                        created_at=now, expires_at=now + timedelta(hours=24),
                    )
                except Exception:
                    pass
        return OrchestratorResult(
            OrchestratorState.COMPLETED,
            tuple(states),
            plan,
            response,
            briefing,
        )

    @staticmethod
    def _question_response(intent, text, finding_ids, action_ids):
        source_id = finding_ids[0] if finding_ids else (action_ids[0] if action_ids else intent)
        source = EvidenceSource.DETERMINISTIC_FINDING if finding_ids else EvidenceSource.DETERMINISTIC_ADVISOR
        evidence = EvidenceRef(
            "answer:evidence", source, source_id,
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic Advisor answer",
        )
        return GroundedResponse(
            intent,
            (ResponseSection("answer", "Answer", (
                Claim("answer", text, EpistemicRole.DETERMINISTIC_DERIVATION, (evidence.evidence_id,)),
            )),),
            (evidence,),
            tuple(finding_ids),
            tuple(action_ids),
        )

    @staticmethod
    def _notice(intent: str, text: str) -> GroundedResponse:
        evidence = EvidenceRef(
            "system:capability", EvidenceSource.DETERMINISTIC_ADVISOR,
            "supported_capabilities", EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic capability state",
        )
        return require_grounded(GroundedResponse(
            intent,
            (ResponseSection("notice", "CyberWatchtower", (
                Claim("notice", text, EpistemicRole.DETERMINISTIC_DERIVATION, (evidence.evidence_id,)),
            )),),
            (evidence,),
        ))
