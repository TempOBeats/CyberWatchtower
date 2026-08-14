import hashlib
import platform
import socket
import uuid
from pathlib import Path


SYSTEM_ID_NAMESPACE = b"cyberwatchtower:system-id:v1\0"
MACHINE_ID_PATHS = (
    Path("/etc/machine-id"),
    Path("/var/lib/dbus/machine-id"),
)


def derive_system_id(raw_identifier: str) -> str:
    """Derive a stable opaque ID without retaining the raw machine identifier."""

    normalized = raw_identifier.strip()
    if not normalized:
        raise ValueError("A non-empty machine identifier is required.")

    digest = hashlib.sha256(
        SYSTEM_ID_NAMESPACE + normalized.encode("utf-8", errors="strict")
    ).hexdigest()
    return f"cwt-{digest}"


def get_local_system_id(paths: tuple[Path, ...] = MACHINE_ID_PATHS) -> str:
    """Return an opaque local system ID; raw source identifiers never leave here."""

    for path in paths:
        try:
            raw_identifier = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue

        if raw_identifier:
            return derive_system_id(raw_identifier)

    fallback_parts = (
        platform.system(),
        platform.machine(),
        socket.gethostname(),
        str(uuid.getnode()),
    )
    return derive_system_id("\0".join(fallback_parts))
