from dataclasses import dataclass, field
from uuid import uuid4

from cyberwatchtower.advisor.models import AdvisorContext


@dataclass
class ConversationSession:
    """Ephemeral conversational references; intentionally has no persistence API."""

    session_id: str = field(default_factory=lambda: f"session:{uuid4().hex}")
    focused_finding_id: str | None = None
    focused_action_id: str | None = None
    last_intent: str | None = None
    referenced_finding_ids: list[str] = field(default_factory=list)

    def focus(self, finding_id: str | None, action_id: str | None = None) -> None:
        self.focused_finding_id = finding_id
        self.focused_action_id = action_id
        if finding_id and finding_id not in self.referenced_finding_ids:
            self.referenced_finding_ids.append(finding_id)


def resolve_finding_reference(
    request: str,
    context: AdvisorContext,
    session: ConversationSession,
    explicit_finding_id: str | None = None,
    persisted_candidates: tuple[str, ...] = (),
) -> str | None:
    known = {finding.finding_id: finding for finding in context.findings}
    if explicit_finding_id is not None:
        return explicit_finding_id if explicit_finding_id in known else None
    for finding_id in known:
        if finding_id in request:
            return finding_id
    normalized = request.casefold()
    title_matches = [
        finding.finding_id
        for finding in known.values()
        if finding.title.casefold() in normalized
    ]
    if len(title_matches) == 1:
        return title_matches[0]
    if any(token in normalized.split() for token in ("it", "this", "that")):
        if session.focused_finding_id in known:
            return session.focused_finding_id
        valid_persisted = tuple(
            candidate for candidate in persisted_candidates if candidate in known
        )
        if len(valid_persisted) == 1:
            return valid_persisted[0]
    return None
