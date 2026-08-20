from collections import defaultdict

from .finding_identity import finding_identity
from .presentation import report_listener_group_id
from .scoring_report import scoring_version_from_score


def _score_summary(scores):
    if not scores:
        return {
            "scan_count": 0,
            "average_score": None,
            "best_score": None,
            "worst_score": None,
            "overall_change": None,
            "overall_trend": "UNKNOWN",
        }
    first_score = scores[0]
    latest_score = scores[-1]
    overall_change = latest_score - first_score
    if overall_change > 0:
        overall_trend = "IMPROVED"
    elif overall_change < 0:
        overall_trend = "DECLINED"
    else:
        overall_trend = "UNCHANGED"
    return {
        "scan_count": len(scores),
        "average_score": round(sum(scores) / len(scores), 1),
        "best_score": max(scores),
        "worst_score": min(scores),
        "overall_change": overall_change,
        "overall_trend": overall_trend,
    }


def analyze_history(reports):
    """
    Analyze CyberWatchtower scan history and produce
    long-term security intelligence.
    """

    if not reports:
        return {
            "total_scans": 0,
            "average_score": 0,
            "best_score": 0,
            "worst_score": 0,
            "overall_change": 0,
            "overall_trend": "UNKNOWN",
            "scoring_version": None,
            "mixed_scoring_versions": False,
            "score_series_by_version": {},
            "findings": [],
        }

    scores_by_version = defaultdict(list)
    finding_history = defaultdict(
        lambda: {
            "title": "",
            "severity": "",
            "first_seen": None,
            "last_seen": None,
            "occurrences": 0,
        }
    )

    for report in reports:
        score_data = report.get("security_score", {})
        score = score_data.get("score")

        if isinstance(score, (int, float)):
            scoring_version = scoring_version_from_score(score_data).value
            scores_by_version[scoring_version].append(score)

        timestamp = report.get("generated_at", "UNKNOWN")

        for finding in report.get("findings", []):
            title = finding.get("title", "Unknown finding")
            identity = finding_identity(finding)

            record = finding_history[identity]

            record["title"] = title
            record["finding_id"] = identity
            record["severity"] = finding.get("severity", "UNKNOWN")
            record["presentation_group_id"] = report_listener_group_id(finding)

            if record["first_seen"] is None:
                record["first_seen"] = timestamp

            record["last_seen"] = timestamp
            record["occurrences"] += 1

    score_series = {
        version: _score_summary(scores)
        for version, scores in sorted(scores_by_version.items())
    }
    if len(score_series) == 1:
        scoring_version, summary = next(iter(score_series.items()))
        average_score = summary["average_score"]
        best_score = summary["best_score"]
        worst_score = summary["worst_score"]
        overall_change = summary["overall_change"]
        overall_trend = summary["overall_trend"]
        mixed_scoring_versions = False
    elif len(score_series) > 1:
        scoring_version = None
        average_score = None
        best_score = None
        worst_score = None
        overall_change = None
        overall_trend = "SCORING_VERSION_CHANGED"
        mixed_scoring_versions = True
    else:
        scoring_version = None
        average_score = 0
        best_score = 0
        worst_score = 0
        overall_change = 0
        overall_trend = "UNKNOWN"
        mixed_scoring_versions = False

    findings = sorted(
        finding_history.values(),
        key=lambda item: item["occurrences"],
        reverse=True,
    )

    return {
        "total_scans": len(reports),
        "average_score": average_score,
        "best_score": best_score,
        "worst_score": worst_score,
        "overall_change": overall_change,
        "overall_trend": overall_trend,
        "scoring_version": scoring_version,
        "mixed_scoring_versions": mixed_scoring_versions,
        "score_series_by_version": score_series,
        "findings": findings,
    }
