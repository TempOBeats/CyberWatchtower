import shutil
import subprocess


def run_command(command: list[str]) -> dict:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def check_firewall() -> dict:
    tools = {
        "ufw": shutil.which("ufw"),
        "firewalld": shutil.which("firewall-cmd"),
        "nftables": shutil.which("nft"),
        "iptables": shutil.which("iptables"),
    }

    detected = [
        name
        for name, path in tools.items()
        if path is not None
    ]

    return {
        "detected_tools": detected,
        "tool_paths": tools,
    }

def inspect_iptables() -> dict:
    if not shutil.which("iptables"):
        return {
            "available": False,
            "message": "iptables is not installed.",
        }

    result = run_command(
        ["iptables", "-L", "-n"]
    )

    output = result["stdout"]

    if result["returncode"] != 0:
        return {
            "available": True,
            "accessible": False,
            "message": "iptables exists, but CyberWatchtower could not read the rules.",
            "error": result["stderr"],
        }

    policies = {}

    for line in output.splitlines():
        if line.startswith("Chain ") and "(policy " in line:
            parts = line.split()

            chain_name = parts[1]
            policy = parts[3].replace(")", "")

            policies[chain_name] = policy

    return {
        "available": True,
        "accessible": True,
        "policies": policies,
        "raw_output": output,
    }

def assess_iptables(data: dict) -> dict:
    if not data.get("available"):
        return {
            "status": "unavailable",
            "severity": "INFO",
            "confidence": 100,
            "message": "iptables is not available on this system.",
        }

    if not data.get("accessible"):
        return {
            "status": "permission_required",
            "severity": "INFO",
            "confidence": 100,
            "message": "iptables exists, but elevated privileges are required to inspect its rules.",
        }

    policies = data.get("policies", {})

    input_policy = policies.get("INPUT")
    forward_policy = policies.get("FORWARD")
    output_policy = policies.get("OUTPUT")

    if input_policy not in {"ACCEPT", "DROP"}:
        return {
            "status": "inconclusive",
            "severity": "INFO",
            "confidence": 50,
            "message": (
                "CyberWatchtower could not determine a recognized default "
                "INPUT policy from the iptables output."
            ),
            "evidence": [
                f"INPUT policy: {input_policy or 'unknown'}",
                f"FORWARD policy: {forward_policy or 'unknown'}",
                f"OUTPUT policy: {output_policy or 'unknown'}",
            ],
            "recommendation": (
                "Review the iptables configuration directly and verify the "
                "default INPUT policy."
            ),
        }

    if input_policy == "ACCEPT":
        return {
            "status": "permissive",
            "severity": "MEDIUM",
            "confidence": 90,
            "message": (
                "The default INPUT policy is ACCEPT. "
                "Inbound traffic is permitted by default unless another rule blocks it."
            ),
            "evidence": [
                f"INPUT policy: {input_policy}",
                f"FORWARD policy: {forward_policy}",
                f"OUTPUT policy: {output_policy}",
            ],
            "recommendation": (
                "Review the firewall rules and determine whether a more restrictive "
                "default inbound policy is appropriate for this system."
            ),
        }

    return {
        "status": "configured",
        "severity": "INFO",
        "confidence": 80,
        "message": "iptables appears to have a non-ACCEPT default inbound policy.",
        "evidence": [
            f"INPUT policy: {input_policy}",
            f"FORWARD policy: {forward_policy}",
            f"OUTPUT policy: {output_policy}",
        ],
    }
