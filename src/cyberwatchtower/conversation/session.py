from dataclasses import dataclass, field

from cyberwatchtower.advisor.models import AdvisorContext


@dataclass
class ConversationSession:
    """Ephemeral conversational references; intentionally has no persistence API."""

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
) -> str | None:
    known = {finding.finding_id: finding for finding in context.findings}
    if explicit_finding_id in known:
        return explicit_finding_id
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
        return session.focused_finding_id
    return None
