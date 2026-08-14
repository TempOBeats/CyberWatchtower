import json
from datetime import datetime, timezone
from pathlib import Path

from .finding_identity import finding_identity
from .report_contracts import (
    LegacyIdentityResolution,
    canonical_report_digest,
    coverage_complete_for_source,
    legacy_resolution_authorizes,
)


def _report_timestamp(report: dict, report_path: Path) -> float:
    generated_at = report.get("generated_at")

    if isinstance(generated_at, str):
        try:
            timestamp = datetime.fromisoformat(generated_at)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            return timestamp.timestamp()
        except ValueError:
            pass

    try:
        return report_path.stat().st_mtime
    except OSError:
        return 0.0


def load_reports(
    report_directory="reports",
    hostname: str | None = None,
    system_id: str | None = None,
    legacy_resolutions: dict[str, LegacyIdentityResolution] | None = None,
) -> list[dict]:
    """Load saved CyberWatchtower JSON reports in chronological order."""

    report_dir = Path(report_directory)

    if not report_dir.exists():
        return []

    reports_with_timestamps = []

    for report_path in sorted(report_dir.glob("*.json")):
        try:
            with report_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            report_system = data.get("system", {})
            report_system_id = report_system.get("system_id")

            if system_id is not None:
                if report_system_id is not None:
                    if report_system_id != system_id:
                        continue
                else:
                    resolution = (legacy_resolutions or {}).get(
                        canonical_report_digest(data)
                    )
                    if not legacy_resolution_authorizes(
                        resolution,
                        system_id=system_id,
                        hostname=report_system.get("hostname"),
                    ):
                        continue
            elif hostname is not None and report_system.get("hostname") != hostname:
                continue

            data["_report_path"] = str(report_path)
            reports_with_timestamps.append(
                (_report_timestamp(data, report_path), str(report_path), data)
            )

        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue

    reports_with_timestamps.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in reports_with_timestamps]

def compare_reports(previous: dict, current: dict) -> dict:
    """Compare two CyberWatchtower reports."""

    previous_score = previous.get("security_score", {})
    current_score = current.get("security_score", {})

    old_score = previous_score.get("score", 0)
    new_score = current_score.get("score", 0)

    change = new_score - old_score

    if change > 0:
        trend = "IMPROVED"
    elif change < 0:
        trend = "DECLINED"
    else:
        trend = "UNCHANGED"

    previous_findings = {
        finding_identity(finding): finding
        for finding in previous.get("findings", [])
    }

    current_findings = {
        finding_identity(finding): finding
        for finding in current.get("findings", [])
    }

    new_identities = set(current_findings) - set(previous_findings)
    resolved_identities = set(previous_findings) - set(current_findings)

    confirmed_resolved_identities = {
        identity
        for identity in resolved_identities
        if coverage_complete_for_source(
            previous_findings[identity].get("source"), current.get("coverage")
        )
    }
    uncertain_identities = resolved_identities - confirmed_resolved_identities

    new_findings = [
        current_findings[identity]
        for identity in sorted(new_identities)
    ]

    resolved_findings = [
        previous_findings[identity]
        for identity in sorted(confirmed_resolved_identities)
    ]

    uncertain_findings = [
        previous_findings[identity]
        for identity in sorted(uncertain_identities)
    ]

    return {
        "previous_score": old_score,
        "current_score": new_score,
        "change": change,
        "trend": trend,
        "previous_risk": previous_score.get("risk_level", "UNKNOWN"),
        "current_risk": current_score.get("risk_level", "UNKNOWN"),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "uncertain_findings": uncertain_findings,
    }
