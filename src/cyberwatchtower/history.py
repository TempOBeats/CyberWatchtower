import json
from pathlib import Path


def load_reports(report_directory="reports") -> list[dict]:
    """Load saved CyberWatchtower JSON reports in chronological order."""

    report_dir = Path(report_directory)

    if not report_dir.exists():
        return []

    reports = []

    for report_path in sorted(report_dir.glob("*.json")):
        try:
            with report_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            data["_report_path"] = str(report_path)
            reports.append(data)

        except (OSError, json.JSONDecodeError):
            continue

    return reports

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
        finding.get("title", "Unknown finding"): finding
        for finding in previous.get("findings", [])
    }

    current_findings = {
        finding.get("title", "Unknown finding"): finding
        for finding in current.get("findings", [])
    }

    new_titles = set(current_findings) - set(previous_findings)
    resolved_titles = set(previous_findings) - set(current_findings)

    new_findings = [
        current_findings[title]
        for title in sorted(new_titles)
    ]

    resolved_findings = [
        previous_findings[title]
        for title in sorted(resolved_titles)
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
    }
