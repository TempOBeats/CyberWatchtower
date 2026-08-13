SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}


def calculate_security_score(findings: list) -> dict:
    """Calculate an overall CyberWatchtower security score."""

    score = 100

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.severity.name

        if severity in counts:
            counts[severity] += 1
            score -= SEVERITY_WEIGHTS[severity]

    score = max(0, score)

    if score >= 90:
        risk_level = "LOW"
    elif score >= 75:
        risk_level = "MODERATE"
    elif score >= 50:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "score": score,
        "risk_level": risk_level,
        "counts": counts,
    }
