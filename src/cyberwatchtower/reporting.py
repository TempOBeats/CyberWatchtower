import json
from datetime import datetime
from pathlib import Path

from .finding_identity import finding_identity
from .report_contracts import (
    CURRENT_REPORT_SCHEMA_VERSION,
    assessment_assurance_summary,
    normalize_assessment_domains,
    normalize_coverage,
)


def finding_to_dict(finding):
    data = {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "recommendation": finding.recommendation,
        "evidence": finding.evidence,
        "confidence": finding.confidence,
        "technique_id": finding.technique_id,
        "source": finding.source,
        "kind": finding.kind.value,
        "assessment_state": finding.assessment_state.value,
    }

    data["finding_id"] = finding.finding_id or finding_identity(data)

    return data


def save_json_report(results, report_directory="reports"):
    report_dir = Path(report_directory)
    report_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now().astimezone()
    timestamp = now.strftime("%Y%m%d_%H%M%S_%f")

    hostname = results["system"].get("hostname", "unknown")
    safe_hostname = "".join(
        char if char.isalnum() or char in "-_" else "_"
        for char in hostname
    )

    base_report_path = report_dir / (
        f"cyberwatchtower_{safe_hostname}_{timestamp}.json"
    )

    assessment_domains = normalize_assessment_domains(
        results.get("assessment_domains")
    )
    coverage = normalize_coverage(results.get("coverage"), assessment_domains)
    report = {
        "schema_version": CURRENT_REPORT_SCHEMA_VERSION,
        "generated_at": now.isoformat(),
        "system": results["system"],
        "assessment_domains": [domain.value for domain in assessment_domains],
        "coverage": coverage,
        "assessment_assurance": assessment_assurance_summary(
            coverage, assessment_domains
        ),
        "security_score": results["score"],
        "findings": [
            finding_to_dict(finding)
            for finding in results["findings"]
        ],
    }

    report_path = base_report_path
    collision_number = 0

    while True:
        try:
            with report_path.open("x", encoding="utf-8") as file:
                json.dump(report, file, indent=2)
            break
        except FileExistsError:
            collision_number += 1
            report_path = base_report_path.with_stem(
                f"{base_report_path.stem}_{collision_number}"
            )

    return report_path
