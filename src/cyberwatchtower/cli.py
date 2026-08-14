import argparse
import sys

from .scanner import run_scan
from .reporting import save_json_report
from .history import load_reports, compare_reports
from cyberwatchtower.intelligence import analyze_history


def _display_advisor(current_report, comparison, intelligence):
    """Display advisory output without affecting the deterministic scan path."""

    try:
        from .advisor.context import build_advisor_context
        from .advisor.rendering import render_advisory
        from .advisor.service import generate_advisory

        context = build_advisor_context(
            current_report,
            comparison,
            intelligence,
        )
        advisory = generate_advisory(context)
        print()
        print(render_advisory(advisory, context))
    except Exception:
        print()
        print("AI ADVISOR")
        print("==========")
        print(
            "Advisor unavailable; the deterministic scan and report remain complete."
        )


def _intelligence_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberwatchtower")
    subparsers = parser.add_subparsers(dest="command", required=True)
    briefing = subparsers.add_parser("briefing", help="Brief saved scan data")
    briefing.add_argument("--reports", default="reports")
    ask = subparsers.add_parser("ask", help="Ask a supported grounded question")
    ask.add_argument("question")
    ask.add_argument("--finding-id")
    ask.add_argument("--reports", default="reports")
    return parser


def _run_intelligence_command(arguments: list[str]) -> None:
    from .briefing.rendering import render_grounded_response
    from .conversation.session import ConversationSession
    from .core.orchestrator import IntelligenceOrchestrator

    parsed = _intelligence_parser().parse_args(arguments)
    request = (
        "Give me my security briefing"
        if parsed.command == "briefing"
        else parsed.question
    )
    try:
        result = IntelligenceOrchestrator().handle(
            request,
            session=ConversationSession(),
            report_directory=parsed.reports,
            explicit_finding_id=getattr(parsed, "finding_id", None),
        )
        print(render_grounded_response(result.response))
    except Exception:
        print("CYBERWATCHTOWER INTELLIGENCE")
        print("============================")
        print(
            "Intelligence Core unavailable; saved reports and the deterministic "
            "scanner remain unchanged."
        )


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"briefing", "ask"}:
        _run_intelligence_command(arguments)
        return

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

    reports = load_reports(
        hostname=results["system"].get("hostname"),
        system_id=results["system"].get("system_id"),
    )

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
                print(f"[{finding['severity']}] {finding['title']}")
                if finding.get("evidence"):
                    for item in finding["evidence"]:
                        print(f" - {item}")

        if comparison["resolved_findings"]:
            print()
            print("RESOLVED FINDINGS")
            print("-----------------")

            for finding in comparison["resolved_findings"]:
                print(f"[{finding['severity']}] {finding['title']}")

    intelligence = analyze_history(reports)

    print()
    print("SECURITY INTELLIGENCE")
    print("=====================")
    print(f"Historical Scans: {intelligence['total_scans']}")
    print(f"Average Score: {intelligence['average_score']}/100")
    print(f"Best Score: {intelligence['best_score']}/100")
    print(f"Worst Score: {intelligence['worst_score']}/100")
    print(f"Long-Term Change: {intelligence['overall_change']:+}")
    print(f"Long-Term Trend: {intelligence['overall_trend']}")

    recurring = [
        finding
        for finding in intelligence["findings"]
        if finding["occurrences"] > 1
    ]

    if recurring:
        print()
        print("RECURRING FINDINGS")
        print("==================")

        for finding in recurring:
            print(
                f"[{finding['severity']}] {finding['title']} "
                f"({finding['occurrences']} occurrences)"
            )

    _display_advisor(reports[-1], comparison, intelligence)

    print()
    print("CyberWatchtower scan complete.")


if __name__ == "__main__":
    main()
