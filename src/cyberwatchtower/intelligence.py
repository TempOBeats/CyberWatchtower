from collections import defaultdict

from .finding_identity import finding_identity


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
            "findings": [],
        }

    scores = []
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
            scores.append(score)

        timestamp = report.get("generated_at", "UNKNOWN")

        for finding in report.get("findings", []):
            title = finding.get("title", "Unknown finding")
            identity = finding_identity(finding)

            record = finding_history[identity]

            record["title"] = title
            record["finding_id"] = identity
            record["severity"] = finding.get("severity", "UNKNOWN")

            if record["first_seen"] is None:
                record["first_seen"] = timestamp

            record["last_seen"] = timestamp
            record["occurrences"] += 1

    if scores:
        first_score = scores[0]
        latest_score = scores[-1]
        overall_change = latest_score - first_score

        if overall_change > 0:
            overall_trend = "IMPROVED"
        elif overall_change < 0:
            overall_trend = "DECLINED"
        else:
            overall_trend = "UNCHANGED"

        average_score = round(sum(scores) / len(scores), 1)
        best_score = max(scores)
        worst_score = min(scores)

    else:
        average_score = 0
        best_score = 0
        worst_score = 0
        overall_change = 0
        overall_trend = "UNKNOWN"

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
        "findings": findings,
    }
