import json
from datetime import datetime
from pathlib import Path


def finding_to_dict(finding):
    return {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "recommendation": finding.recommendation,
        "evidence": finding.evidence,
        "confidence": finding.confidence,
    }


def save_json_report(results, report_directory="reports"):
    report_dir = Path(report_directory)
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    hostname = results["system"].get("hostname", "unknown")
    safe_hostname = "".join(
        char if char.isalnum() or char in "-_" else "_"
        for char in hostname
    )

    report_path = report_dir / (
        f"cyberwatchtower_{safe_hostname}_{timestamp}.json"
    )

    report = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "system": results["system"],
        "security_score": results["score"],
        "findings": [
            finding_to_dict(finding)
            for finding in results["findings"]
        ],
    }

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report_path
