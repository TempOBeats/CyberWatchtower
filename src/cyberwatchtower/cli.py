from .scanner import run_scan
from .reporting import save_json_report
from .history import load_reports, compare_reports

def main():
    print()
    print("================================")
    print("        CYBERWATCHTOWER")
    print("================================")
    print()
    print("Initializing security assessment...")
    print()

    results = run_scan()

    print("SYSTEM INFORMATION")
    print("------------------")

    for key, value in results["system"].items():
        print(f"{key}: {value}")

    print()
    print("SECURITY FINDINGS")
    print("-----------------")

    if not results["findings"]:
        print("No findings detected by the checks currently enabled.")

    else:
        for finding in results["findings"]:
            print()
            print(f"[{finding.severity.value}] {finding.title}")
            print(f"Description: {finding.description}")
            print(f"Confidence: {finding.confidence}%")
            print(f"Recommendation: {finding.recommendation}")

            if finding.evidence:
                print("Evidence:")

                for item in finding.evidence:
                    print(f" - {item}")

    score = results["score"]

    print()
    print("SECURITY SCORE")
    print("==============")
    print(f"Score: {score['score']}/100")
    print(f"Risk Level: {score['risk_level']}")

    print("FINDINGS:")
    print(f" - Critical: {score['counts']['CRITICAL']}")
    print(f" - High: {score['counts']['HIGH']}")
    print(f" - Medium: {score['counts']['MEDIUM']}")
    print(f" - Low: {score['counts']['LOW']}")
    print(f" - Info: {score['counts']['INFO']}")

    report_path = save_json_report(results)

    reports = load_reports()

    comparison = None

    if len(reports) >= 2:
        comparison = compare_reports(reports[-2], reports[-1])

    print()
    print("REPORT")
    print("======")
    print(f"Saved to: {report_path}")

    if comparison:
        print()
        print("SECURITY TREND")
        print("==============")
        print(f"Previous Score: {comparison['previous_score']}/100")
        print(f"Current Score: {comparison['current_score']}/100")
        print(f"Change: {comparison['change']:+d}")
        print(f"Trend: {comparison['trend']}")

        if comparison["new_findings"]:
            print()
            print("NEW FINDINGS")
            print("------------")

            for finding in comparison["new_findings"]:
                print(
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                )

        if comparison["resolved_findings"]:
            print()
            print("RESOLVED FINDINGS")
            print("-----------------")

            for finding in comparison["resolved_findings"]:
                print(
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                )

    print()
    print("CyberWatchtower scan complete.")


if __name__ == "__main__":
    main()
