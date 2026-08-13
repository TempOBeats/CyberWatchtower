IDENTITY_EVIDENCE_FIELDS = {
    "address",
    "application",
    "port",
    "process",
    "protocol",
}


def finding_identity(finding: dict) -> str:
    """Return a stable identity for current and legacy report findings."""

    stored_identity = finding.get("finding_id")

    if isinstance(stored_identity, str) and stored_identity.strip():
        return stored_identity.strip()

    title = str(finding.get("title", "Unknown finding")).strip().casefold()
    components = [f"type={title}"]

    technique_id = finding.get("technique_id")
    if technique_id:
        components.append(f"technique_id={str(technique_id).strip().casefold()}")

    evidence_values = {}

    for item in finding.get("evidence", []):
        if not isinstance(item, str) or ":" not in item:
            continue

        label, value = item.split(":", 1)
        label = label.strip().casefold()

        if label in IDENTITY_EVIDENCE_FIELDS:
            evidence_values[label] = value.strip().casefold()

    for label in sorted(evidence_values):
        components.append(f"{label}={evidence_values[label]}")

    return "|".join(components)
