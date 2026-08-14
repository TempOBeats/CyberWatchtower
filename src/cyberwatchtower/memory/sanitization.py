import unicodedata


SAFE_EVIDENCE_LABELS = frozenset({
    "address",
    "application",
    "exposure",
    "forward policy",
    "input policy",
    "output policy",
    "port",
    "process",
    "protocol",
    "service",
    "service/application",
})

SENSITIVE_MARKERS = frozenset({
    "api-key",
    "api_key",
    "apikey",
    "authorization:",
    "bearer ",
    "command line",
    "credential",
    "cookie:",
    "environment=",
    "password",
    "raw argv",
    "stderr",
    "token=",
    "token:",
})

MAX_EVIDENCE_LENGTH = 512


def contains_sensitive_marker(value: str) -> bool:
    return any(marker in value.casefold() for marker in SENSITIVE_MARKERS)


def sanitize_evidence(items: list[str]) -> tuple[tuple[str, ...], int]:
    """Keep only bounded, labeled, non-sensitive deterministic evidence."""

    safe_items = []
    omitted = 0
    for item in items:
        normalized = unicodedata.normalize("NFC", item).strip()
        if (
            not normalized
            or len(normalized) > MAX_EVIDENCE_LENGTH
            or ":" not in normalized
            or any(unicodedata.category(char) == "Cc" for char in normalized)
        ):
            omitted += 1
            continue
        label, value = normalized.split(":", 1)
        clean_label = label.strip()
        clean_value = value.strip()
        searchable = normalized.casefold()
        if (
            clean_label.casefold() not in SAFE_EVIDENCE_LABELS
            or not clean_value
            or contains_sensitive_marker(searchable)
        ):
            omitted += 1
            continue
        safe_items.append(f"{clean_label}: {clean_value}")
    return tuple(safe_items), omitted
