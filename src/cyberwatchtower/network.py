import shutil
import subprocess


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

    if not result["success"]:
        return {
            "available": True,
            "accessible": False,
            "message": "CyberWatchtower could not inspect listening services.",
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

        if exposure == "all_interfaces":
            findings.append(
                {
                    "severity": "MEDIUM",
                    "title": "Service listening on all interfaces",
                    "description": (
                        f"A {protocol.upper()} service on port {port} "
                        "is bound to all network interfaces."
                    ),
                    "evidence": [
                        f"Protocol: {protocol}",
                        f"Address: {address}",
                        f"Port: {port}",
                        "Exposure: all interfaces",
                    ],
                    "recommendation": (
                        "Verify that this service needs to be reachable "
                        "from other systems. Restrict its bind address or "
                        "firewall access if remote access is unnecessary."
                    ),
                }
            )

    return findings
