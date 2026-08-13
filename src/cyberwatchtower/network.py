import shutil
import subprocess
import re
from .service_intelligence import lookup_service

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
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }

    except (subprocess.SubprocessError, OSError) as exc:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
        }


def inspect_listening_services() -> dict:
    """Inspect TCP/UDP sockets listening on the local machine."""

    ss_path = shutil.which("ss")

    if not ss_path:
        return {
            "available": False,
            "message": "The ss utility could not be found.",
            "services": [],
        }

    result = _run_command([ss_path, "-lntup"])

    if not result["success"] or result["stderr"]:
        return {
            "available": True,
            "accessible": False,
            "message": (
                "CyberWatchtower could not completely inspect listening services."
            ),
            "error": result["stderr"],
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

    services = []

    lines = raw_output.splitlines()

    # Skip the header
    for line in lines[1:]:
        parts = line.split()

        if len(parts) < 5:
            continue

        protocol = parts[0]
        state = parts[1]
        local_address = parts[4]

        process_name = "unknown"
        pid = None

        process_match = re.search(
            r'users:\(\("([^"]+)",pid=(\d+)',
            line,
        )

        if process_match:
            process_name = process_match.group(1)
            pid = int(process_match.group(2))



        if ":" in local_address:
            address, port = local_address.rsplit(":", 1)
        else:
            address = local_address
            port = "unknown"

        exposure = "local"

        if address in ("0.0.0.0", "*", "[::]", "::"):
            exposure = "all_interfaces"
        elif address.startswith("127.") or address in ("::1", "[::1]"):
            exposure = "loopback"
        else:
            exposure = "interface"

        services.append(
            {
                "protocol": protocol,
                "state": state,
                "address": address,
                "port": port,
                "exposure": exposure,
                "process": process_name,
                "pid": pid,
            }
        )
    return services

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

    risk = {
        "severity": intelligence["default_severity"],
        "reason": intelligence["description"],
        "service_name": intelligence["name"],
        "known_service": intelligence["known"],
        "recommendation": intelligence["recommendation"],
    }

    if exposure == "all_interfaces" and risk["severity"] == "INFO":
        risk["severity"] = "MEDIUM"
        risk["reason"] = (
            f"{intelligence['name']} is listening on all network interfaces. "
            f"{intelligence['description']}"
        )

    if (
        process in {"python", "python3", "node", "ruby", "perl"}
        and exposure == "all_interfaces"
        and not intelligence["known"]
    ):
        risk["severity"] = "MEDIUM"
        risk["reason"] = (
            f"General-purpose runtime '{process}' is listening on all "
            "network interfaces using an unrecognized port."
        )

    return risk
