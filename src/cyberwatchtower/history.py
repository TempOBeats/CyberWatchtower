import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from .finding_identity import finding_identity
from .report_contracts import (
    LegacyIdentityResolution,
    canonical_report_digest,
    coverage_complete_for_source,
    legacy_resolution_authorizes,
    report_schema_version,
)
from .scoring_report import scoring_version_from_score


_FindingT = TypeVar("_FindingT")


class _DuplicateFindingIdentity(ValueError):
    """Signal ambiguous semantic input without selecting an arbitrary winner."""


@dataclass(frozen=True, slots=True)
class _ReportComparisonSemantics:
    previous_score: int
    current_score: int
    previous_scoring_version: str
    current_scoring_version: str
    previous_risk: str
    current_risk: str
    score_change: int | None
    score_trend: str
    added_findings: tuple[object, ...]
    resolved_findings: tuple[object, ...]
    uncertain_findings: tuple[object, ...]


def _finding_index(
    findings: Iterable[_FindingT],
    *,
    identity_of: Callable[[_FindingT], str],
    reject_duplicate_identities: bool,
) -> dict[str, _FindingT]:
    indexed: dict[str, _FindingT] = {}
    for finding in findings:
        identity = identity_of(finding)
        if reject_duplicate_identities and identity in indexed:
            raise _DuplicateFindingIdentity(identity)
        indexed[identity] = finding
    return indexed


def _compare_report_semantics(
    *,
    previous_score: int,
    current_score: int,
    previous_scoring_version: str,
    current_scoring_version: str,
    previous_risk: str,
    current_risk: str,
    previous_findings: Iterable[_FindingT],
    current_findings: Iterable[_FindingT],
    current_coverage: Mapping | None,
    current_assessment_domains: object | None,
    identity_of: Callable[[_FindingT], str],
    source_of: Callable[[_FindingT], object],
    reject_duplicate_identities: bool,
) -> _ReportComparisonSemantics:
    """Compare already supplied observations without loading or filtering reports."""

    if previous_scoring_version != current_scoring_version:
        score_change = None
        score_trend = "INCOMPARABLE"
    else:
        score_change = current_score - previous_score
        score_trend = (
            "IMPROVED"
            if score_change > 0
            else "DECLINED"
            if score_change < 0
            else "UNCHANGED"
        )

    previous_index = _finding_index(
        previous_findings,
        identity_of=identity_of,
        reject_duplicate_identities=reject_duplicate_identities,
    )
    current_index = _finding_index(
        current_findings,
        identity_of=identity_of,
        reject_duplicate_identities=reject_duplicate_identities,
    )
    added_identities = set(current_index) - set(previous_index)
    disappeared_identities = set(previous_index) - set(current_index)
    resolved_identities = {
        identity
        for identity in disappeared_identities
        if coverage_complete_for_source(
            source_of(previous_index[identity]),
            current_coverage,
            current_assessment_domains,
        )
    }
    uncertain_identities = disappeared_identities - resolved_identities

    return _ReportComparisonSemantics(
        previous_score=previous_score,
        current_score=current_score,
        previous_scoring_version=previous_scoring_version,
        current_scoring_version=current_scoring_version,
        previous_risk=previous_risk,
        current_risk=current_risk,
        score_change=score_change,
        score_trend=score_trend,
        added_findings=tuple(
            current_index[identity] for identity in sorted(added_identities)
        ),
        resolved_findings=tuple(
            previous_index[identity] for identity in sorted(resolved_identities)
        ),
        uncertain_findings=tuple(
            previous_index[identity] for identity in sorted(uncertain_identities)
        ),
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
    previous_scoring_version = scoring_version_from_score(previous_score).value
    current_scoring_version = scoring_version_from_score(current_score).value

    semantics = _compare_report_semantics(
        previous_score=old_score,
        current_score=new_score,
        previous_scoring_version=previous_scoring_version,
        current_scoring_version=current_scoring_version,
        previous_risk=previous_score.get("risk_level", "UNKNOWN"),
        current_risk=current_score.get("risk_level", "UNKNOWN"),
        previous_findings=previous.get("findings", []),
        current_findings=current.get("findings", []),
        current_coverage=current.get("coverage"),
        current_assessment_domains=current.get("assessment_domains"),
        identity_of=finding_identity,
        source_of=lambda finding: finding.get("source"),
        reject_duplicate_identities=False,
    )

    return {
        "previous_report_schema_version": report_schema_version(previous),
        "current_report_schema_version": report_schema_version(current),
        "previous_score": old_score,
        "current_score": new_score,
        "previous_scoring_version": previous_scoring_version,
        "current_scoring_version": current_scoring_version,
        "scoring_methodology_changed": semantics.score_trend == "INCOMPARABLE",
        "change": semantics.score_change,
        "trend": (
            "SCORING_VERSION_CHANGED"
            if semantics.score_trend == "INCOMPARABLE"
            else semantics.score_trend
        ),
        "previous_risk": semantics.previous_risk,
        "current_risk": semantics.current_risk,
        "new_findings": list(semantics.added_findings),
        "resolved_findings": list(semantics.resolved_findings),
        "uncertain_findings": list(semantics.uncertain_findings),
    }
