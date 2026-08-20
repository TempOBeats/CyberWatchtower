import argparse
import os
import sys
from pathlib import Path

from .scanner import run_scan
from .reporting import save_json_report
from .history import load_reports, compare_reports
from cyberwatchtower.intelligence import analyze_history


MEMORY_ENVIRONMENT_VARIABLE = "CYBERWATCHTOWER_MEMORY_DB"


def _memory_path(explicit: str | None = None) -> Path | None:
    value = explicit or os.environ.get(MEMORY_ENVIRONMENT_VARIABLE)
    return Path(value) if value else None


def _open_optional_memory(explicit: str | None = None):
    path = _memory_path(explicit)
    if path is None:
        return None, None
    try:
        from .memory.service import SQLiteSecurityMemory
        return SQLiteSecurityMemory.open(path), None
    except Exception:
        return None, "Persistent memory is unavailable; deterministic operation continues."


def _ingest_saved_report(report_path: Path, explicit: str | None = None) -> str | None:
    """Best-effort post-save ingestion; never raises into the scan path."""

    memory, notice = _open_optional_memory(explicit)
    if memory is None:
        return notice
    try:
        from .memory.ingestion_models import IngestionStatus, ReportIngestionRequest
        result = memory.ingest_report(ReportIngestionRequest(report_path))
        if result.status not in {IngestionStatus.INGESTED, IngestionStatus.DUPLICATE}:
            return "Persistent memory could not ingest this report; the saved JSON report remains complete."
        return None
    except Exception:
        return "Persistent memory could not ingest this report; the saved JSON report remains complete."
    finally:
        try:
            memory.close()
        except Exception:
            pass


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
    briefing.add_argument("--memory-db")
    ask = subparsers.add_parser("ask", help="Ask a supported grounded question")
    ask.add_argument("question")
    ask.add_argument("--finding-id")
    ask.add_argument("--reports", default="reports")
    ask.add_argument("--memory-db")
    ask.add_argument("--session-id")
    memory = subparsers.add_parser("memory", help="Read-only memory diagnostics")
    memory_commands = memory.add_subparsers(dest="memory_command", required=True)
    status = memory_commands.add_parser("status", help="Show sanitized memory status")
    status.add_argument("--system-id", required=True)
    status.add_argument("--memory-db")
    check = memory_commands.add_parser("check", help="Run read-only integrity checks")
    check.add_argument("--memory-db")
    return parser


def _print_top_level_help() -> None:
    parser = argparse.ArgumentParser(
        prog="cyberwatchtower",
        description=(
            "Run a deterministic local security assessment, or use a saved-data "
            "intelligence command."
        ),
    )
    parser.add_argument(
        "--memory-db",
        metavar="PATH",
        help="optionally ingest a completed scan into Persistent Security Memory",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("briefing", "ask", "memory"),
        help="read-only command over already saved CyberWatchtower data",
    )
    parser.print_help()


def _run_memory_command(parsed) -> None:
    path = _memory_path(parsed.memory_db)
    print("CYBERWATCHTOWER MEMORY")
    print("=====================")
    if path is None:
        print("Memory is disabled; deterministic scanning and JSON reports remain available.")
        return
    if parsed.memory_command == "check":
        from .memory.integrity import diagnose_memory_path
        from .memory.service import SQLiteSecurityMemory
        try:
            memory = SQLiteSecurityMemory.open_readonly(path)
            try:
                report = memory.integrity_report()
            finally:
                memory.close()
        except Exception:
            report = diagnose_memory_path(path)
        print(f"Health: {report.health}")
        print(f"Schema version: {report.schema_version if report.schema_version is not None else 'unavailable'}")
        for item in report.diagnostics:
            print(f"[{item.severity.value}] {item.code}: {item.summary} ({item.count})")
        return
    try:
        from .memory.service import SQLiteSecurityMemory
        memory = SQLiteSecurityMemory.open_readonly(path)
        try:
            status = memory.operational_status(system_id=parsed.system_id)
        finally:
            memory.close()
        print(f"Health: {status.health}")
        print(f"Schema version: {status.schema_version}")
        print(f"Latest report: {status.latest_report_at or 'none'}")
        for label, count in status.safe_counts:
            print(f"{label.replace('_', ' ').title()}: {count}")
        print(f"Active exceptions: {status.active_exception_count}")
        print(f"Pending exceptions: {status.pending_exception_count}")
        print(f"Expired exceptions: {status.expired_exception_count}")
        print(f"Retention eligible: {status.retention_eligible_count}")
    except Exception:
        print("Memory status is unavailable; preserve the database and run memory check.")


def _run_intelligence_command(arguments: list[str]) -> None:
    from .briefing.rendering import render_grounded_response
    from .conversation.session import ConversationSession
    from .core.orchestrator import IntelligenceOrchestrator

    parsed = _intelligence_parser().parse_args(arguments)
    if parsed.command == "memory":
        _run_memory_command(parsed)
        return
    request = (
        "Give me my security briefing"
        if parsed.command == "briefing"
        else parsed.question
    )
    memory, memory_notice = _open_optional_memory(parsed.memory_db)
    try:
        session = ConversationSession()
        if getattr(parsed, "session_id", None):
            session.session_id = parsed.session_id
        result = IntelligenceOrchestrator(memory=memory).handle(
            request,
            session=session,
            report_directory=parsed.reports,
            explicit_finding_id=getattr(parsed, "finding_id", None),
        )
        rendered = render_grounded_response(result.response)
        print(rendered)
        if memory_notice and "Persistent memory" not in rendered:
            print(f"\nNotice: {memory_notice}")
    except Exception:
        print("CYBERWATCHTOWER INTELLIGENCE")
        print("============================")
        print(
            "Intelligence Core unavailable; saved reports and the deterministic "
            "scanner remain unchanged."
        )
    finally:
        if memory is not None:
            try:
                memory.close()
            except Exception:
                pass


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["-h"], ["--help"]):
        _print_top_level_help()
        return
    if arguments and arguments[0] in {"briefing", "ask", "memory"}:
        _run_intelligence_command(arguments)
        return

    print()
    print("================================")
    print("        CYBERWATCHTOWER")
    print("================================")
    print()
    print("Initializing security assessment...")
    print()

    memory_argument = None
    if "--memory-db" in arguments:
        index = arguments.index("--memory-db")
        if index + 1 >= len(arguments):
            raise SystemExit("--memory-db requires a path")
        memory_argument = arguments[index + 1]
        del arguments[index:index + 2]

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
        from .presentation import group_findings
        for group in group_findings(results["findings"]):
            finding = group.findings[0]
            print()
            print(f"[{finding.severity.value}] {finding.title}")
            if len(group.findings) > 1:
                print(
                    f"Related listener findings: {len(group.findings)} "
                    "(all atomic findings remain in the saved report)"
                )
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
    assurance = results.get("assessment_assurance", {})
    print(f"Assessment Assurance: {assurance.get('level', 'INCOMPLETE')}")
    for limitation in assurance.get("limitations", ()):
        print(f"Coverage Limitation: {limitation}")

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

    memory_notice = _ingest_saved_report(report_path, memory_argument)
    if memory_notice:
        print(f"Memory notice: {memory_notice}")

    if comparison:
        print()
        print("SECURITY TREND")
        print("==============")
        print(f"Previous Score: {comparison['previous_score']}/100")
        print(f"Current Score: {comparison['current_score']}/100")
        print(
            f"Change: {comparison['change']:+d}"
            if comparison["change"] is not None
            else "Change: N/A"
        )
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

        if comparison.get("uncertain_findings"):
            print()
            print("DISAPPEARANCE UNCERTAIN")
            print("-----------------------")
            for finding in comparison["uncertain_findings"]:
                print(f"[{finding['severity']}] {finding['title']}")
            print("Coverage was insufficient to confirm resolution.")

    intelligence = analyze_history(reports)

    print()
    print("SECURITY INTELLIGENCE")
    print("=====================")
    print(f"Historical Scans: {intelligence['total_scans']}")
    print(
        f"Average Score: {intelligence['average_score']}/100"
        if intelligence["average_score"] is not None
        else "Average Score: N/A"
    )
    print(
        f"Best Score: {intelligence['best_score']}/100"
        if intelligence["best_score"] is not None
        else "Best Score: N/A"
    )
    print(
        f"Worst Score: {intelligence['worst_score']}/100"
        if intelligence["worst_score"] is not None
        else "Worst Score: N/A"
    )
    print(
        f"Long-Term Change: {intelligence['overall_change']:+}"
        if intelligence["overall_change"] is not None
        else "Long-Term Change: N/A"
    )
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

        grouped_recurring = {}
        for finding in recurring:
            key = finding.get("presentation_group_id") or finding["finding_id"]
            grouped_recurring.setdefault(key, []).append(finding)
        for group in grouped_recurring.values():
            finding = group[0]
            related = (
                f", {len(group)} related listeners" if len(group) > 1 else ""
            )
            print(
                f"[{finding['severity']}] {finding['title']} "
                f"({max(item['occurrences'] for item in group)} occurrences"
                f"{related})"
            )

    _display_advisor(reports[-1], comparison, intelligence)

    print()
    print("CyberWatchtower scan complete.")


if __name__ == "__main__":
    main()
