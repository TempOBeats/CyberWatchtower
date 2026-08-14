import shutil
import subprocess
import re
from dataclasses import dataclass
from enum import Enum
from .service_intelligence import lookup_service
from .process_intelligence import inspect_process_application

def _run_command(command: list[str]) -> dict:
    """Run a local system command safely and capture its output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr_present": bool(result.stderr.strip()),
            "returncode": result.returncode,
            "failure_code": (
                None if result.returncode == 0 and not result.stderr.strip()
                else "SOCKET_COMMAND_FAILED"
            ),
        }

    except (subprocess.SubprocessError, OSError) as exc:
        return {
            "success": False,
            "stdout": "",
            "stderr_present": False,
            "returncode": -1,
            "failure_code": (
                "SOCKET_COMMAND_TIMEOUT"
                if isinstance(exc, subprocess.TimeoutExpired)
                else "SOCKET_COMMAND_UNAVAILABLE"
            ),
        }


class SocketCompletenessCode(str, Enum):
    COMPLETE = "COMPLETE"
    COMMAND_UNAVAILABLE = "SOCKET_COMMAND_UNAVAILABLE"
    COMMAND_FAILED = "SOCKET_COMMAND_FAILED"
    COMMAND_TIMEOUT = "SOCKET_COMMAND_TIMEOUT"
    OUTPUT_MALFORMED = "SOCKET_OUTPUT_MALFORMED"


@dataclass(frozen=True)
class SocketParseResult:
    services: tuple[dict, ...]
    complete: bool
    code: SocketCompletenessCode
    message: str


_EXPECTED_HEADER_FIELDS = (
    "netid", "state", "recv-q", "send-q", "local", "address:port",
    "peer", "address:port",
)


def parse_listening_services_checked(raw_output: str) -> SocketParseResult:
    """Parse `ss` output and fail coverage closed on any structural doubt."""

    if not isinstance(raw_output, str):
        return SocketParseResult((), False, SocketCompletenessCode.OUTPUT_MALFORMED,
                                 "Socket output was not textual.")
    lines = raw_output.splitlines()
    if not lines:
        return SocketParseResult((), False, SocketCompletenessCode.OUTPUT_MALFORMED,
                                 "Socket output did not contain the expected header.")
    header = tuple(lines[0].casefold().split())
    if header[:len(_EXPECTED_HEADER_FIELDS)] != _EXPECTED_HEADER_FIELDS:
        return SocketParseResult((), False, SocketCompletenessCode.OUTPUT_MALFORMED,
                                 "Socket output did not match the expected structure.")

    services = []
    for line in lines[1:]:
        if not line.strip():
            continue
        parsed = _parse_service_row(line)
        if parsed is None:
            return SocketParseResult(
                tuple(services), False, SocketCompletenessCode.OUTPUT_MALFORMED,
                "Socket output contained an unexpected or incomplete service row.",
            )
        services.append(parsed)
    return SocketParseResult(tuple(services), True, SocketCompletenessCode.COMPLETE,
                             "Socket output was parsed completely.")


def inspect_listening_services() -> dict:
    """Inspect TCP/UDP sockets listening on the local machine."""

    ss_path = shutil.which("ss")

    if not ss_path:
        return {
            "available": False,
            "accessible": False,
            "message": "The ss utility could not be found.",
            "failure_code": SocketCompletenessCode.COMMAND_UNAVAILABLE.value,
            "services": [],
        }

    result = _run_command([ss_path, "-lntup"])

    if not result["success"] or result.get("stderr_present"):
        return {
            "available": True,
            "accessible": False,
            "message": (
                "CyberWatchtower could not completely inspect listening services."
            ),
            "failure_code": result.get("failure_code") or (
                SocketCompletenessCode.COMMAND_FAILED.value
            ),
            "services": [],
        }

    return {
        "available": True,
        "accessible": True,
        "message": "Listening network services successfully inspected.",
        "raw_output": result["stdout"],
    }

def parse_listening_services(raw_output: str) -> list[dict]:
    """Convert ss output into structured listening-service records."""

    return list(parse_listening_services_checked(raw_output).services)


def _parse_service_row(line: str) -> dict | None:
    parts = line.split()
    if len(parts) < 6:
        return None
    protocol = parts[0].casefold()
    state = parts[1]
    local_address = parts[4]
    if protocol not in {"tcp", "udp"} or ":" not in local_address:
        return None
    address, port = local_address.rsplit(":", 1)
    if not address or not port.isdigit() or not 0 <= int(port) <= 65535:
        return None

    process_name = "unknown"
    pid = None
    process_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
    if process_match:
        process_name = process_match.group(1)
        pid = int(process_match.group(2))

    if address in ("0.0.0.0", "*", "[::]", "::"):
        exposure = "all_interfaces"
    elif address.startswith("127.") or address in ("::1", "[::1]"):
        exposure = "loopback"
    else:
        exposure = "interface"
    return {
        "protocol": protocol,
        "state": state,
        "address": address,
        "port": port,
        "exposure": exposure,
        "process": process_name,
        "pid": pid,
    }


def enrich_process_intelligence(
    services: list[dict], proc_root="/proc"
) -> list[dict]:
    """Add safe interpreter application metadata to service records."""

    enriched_services = []

    for service in services:
        enriched_service = dict(service)
        process_data = inspect_process_application(
            service.get("pid"),
            service.get("process", "unknown"),
            proc_root,
        )

        if process_data["application"]:
            enriched_service["application"] = process_data["application"]
            enriched_service["application_name"] = process_data["application_name"]
            enriched_service["known_application"] = process_data[
                "known_application"
            ]

        enriched_services.append(enriched_service)

    return enriched_services

def assess_network_exposure(services: list[dict]) -> list[dict]:
    """Assess listening services for potentially risky exposure."""

    findings = []

    for service in services:
        exposure = service.get("exposure")
        port = service.get("port", "unknown")
        protocol = service.get("protocol", "unknown")
        address = service.get("address", "unknown")
        process_name = service.get("process", "unknown")
        pid = service.get("pid")
        application = service.get("application")
        application_name = service.get("application_name")
        risk = classify_service_risk(service)

        if exposure == "all_interfaces":
            findings.append(
                {
                    "severity": risk["severity"],
                    "title": (
                        f"{risk['service_name']} service listening on all interfaces"
                        if risk["known_service"]
                        else "Unknown service listening on all interfaces"
                    ),
                    "description": (
                        f"A {protocol.upper()} service on port {port} "
                        f"is bound to all network interfaces. {risk['reason']}"
                    ),
                    "evidence": [
                        f"Service: {risk['service_name']}",
                        f"Protocol: {protocol}",
                        f"Address: {address}",
                        f"Port: {port}",
                        f"Process: {process_name}",
                        f"PID: {pid if pid is not None else 'unknown'}",
                        *(
                            [
                                f"Application: {application}",
                                f"Service/Application: {application_name}",
                            ]
                            if application
                            else []
                        ),
                        "Exposure: all interfaces",
                    ],
                    "recommendation": risk["recommendation"],
                }
            )

    return findings

def classify_service_risk(service: dict) -> dict:
    """Classify the potential risk of a listening network service."""

    process = service.get("process", "unknown").lower()
    port = str(service.get("port", "unknown"))
    exposure = service.get("exposure", "local")
    intelligence = lookup_service(port)
    application_name = service.get("application_name")
    known_application = service.get("known_application", False)

    risk = {
        "severity": intelligence["default_severity"],
        "reason": intelligence["description"],
        "service_name": intelligence["name"],
        "known_service": intelligence["known"],
        "recommendation": intelligence["recommendation"],
    }

    if not intelligence["known"] and known_application and application_name:
        risk.update(
            {
                "service_name": application_name,
                "known_service": True,
                "reason": (
                    f"Process metadata identifies this service as {application_name}."
                ),
                "recommendation": (
                    f"Verify that {application_name} is expected and restrict its "
                    "network exposure when remote access is unnecessary."
                ),
            }
        )

    if exposure == "all_interfaces" and risk["severity"] == "INFO":
        risk["severity"] = "MEDIUM"
        risk["reason"] = (
            f"{risk['service_name']} is listening on all network interfaces. "
            f"{risk['reason']}"
        )

    if (
        process in {"python", "python3", "node", "ruby", "perl"}
        and exposure == "all_interfaces"
        and not risk["known_service"]
    ):
        risk["severity"] = "MEDIUM"
        risk["reason"] = (
            f"General-purpose runtime '{process}' is listening on all "
            "network interfaces using an unrecognized port."
        )

    return risk
