import shutil
import subprocess


def run_command(command: list[str]) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return result.stdout.strip()


def check_firewall() -> dict:
    if shutil.which("ufw"):
        output = run_command(["ufw", "status"])

        if "Status: active" in output:
            return {
                "status": "active",
                "tool": "ufw",
                "message": "UFW firewall is active.",
            }

        return {
            "status": "inactive",
            "tool": "ufw",
            "message": "UFW is installed but does not appear active.",
        }

    if shutil.which("firewall-cmd"):
        output = run_command(["firewall-cmd", "--state"])

        if output == "running":
            return {
                "status": "active",
                "tool": "firewalld",
                "message": "Firewalld is active.",
            }

        return {
            "status": "inactive",
            "tool": "firewalld",
            "message": "Firewalld is installed but does not appear active.",
        }

    if shutil.which("nft"):
        return {
            "status": "available",
            "tool": "nftables",
            "message": "nftables is installed. Rules require further inspection.",
        }

    if shutil.which("iptables"):
        return {
            "status": "available",
            "tool": "iptables",
            "message": "iptables is installed. Rules require further inspection.",
        }

    return {
        "status": "unknown",
        "tool": None,
        "message": "No supported Linux firewall technology was detected.",
    }
