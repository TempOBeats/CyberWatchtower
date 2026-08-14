from cyberwatchtower.core.evidence import GroundedResponse


def render_grounded_response(response: GroundedResponse) -> str:
    title = (
        "CYBERWATCHTOWER SECURITY BRIEFING"
        if response.intent == "SECURITY_BRIEFING"
        else "CYBERWATCHTOWER INTELLIGENCE"
    )
    lines = [title, "=" * len(title)]
    for section in response.sections:
        lines.extend(("", section.title.upper()))
        if not section.claims:
            lines.append("No applicable items.")
            continue
        numbered = section.section_id in {"priorities", "next"}
        for index, claim in enumerate(section.claims, start=1):
            prefix = f"{index}. " if numbered else ""
            lines.append(f"{prefix}{claim.text}")
    if response.notice:
        lines.extend(("", f"Notice: {response.notice}"))
    return "\n".join(lines)
