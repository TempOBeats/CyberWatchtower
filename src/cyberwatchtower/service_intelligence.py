SERVICE_DATABASE = {
    "22": {
        "name": "SSH",
        "category": "remote_access",
        "default_severity": "MEDIUM",
        "description": "Secure Shell remote administration service.",
        "recommendation": (
            "Verify remote SSH access is required. "
            "Restrict access to trusted networks or hosts when possible."
        ),
    },
    "23": {
        "name": "Telnet",
        "category": "remote_access",
        "default_severity": "HIGH",
        "description": "Telnet provides unencrypted remote access.",
        "recommendation": (
            "Disable Telnet when possible and use an encrypted "
            "remote-access protocol such as SSH."
        ),
    },
    "80": {
        "name": "HTTP",
        "category": "web",
        "default_severity": "INFO",
        "description": "Standard unencrypted web service.",
        "recommendation": (
            "Verify the web service is expected. "
            "Use HTTPS when sensitive information is transmitted."
        ),
    },
    "443": {
        "name": "HTTPS",
        "category": "web",
        "default_severity": "INFO",
        "description": "Encrypted HTTPS web service.",
        "recommendation": (
            "Verify the service is expected and maintain current "
            "TLS configuration and certificates."
        ),
    },
    "3389": {
        "name": "RDP",
        "category": "remote_access",
        "default_severity": "HIGH",
        "description": "Remote Desktop Protocol provides remote system access.",
        "recommendation": (
            "Restrict RDP exposure to trusted networks, VPN users, "
            "or approved management systems."
        ),
    },
    "3306": {
        "name": "MySQL",
        "category": "database",
        "default_severity": "HIGH",
        "description": "MySQL database service.",
        "recommendation": (
            "Avoid exposing database services directly to untrusted networks. "
            "Restrict access to approved application hosts."
        ),
    },
    "5432": {
        "name": "PostgreSQL",
        "category": "database",
        "default_severity": "HIGH",
        "description": "PostgreSQL database service.",
        "recommendation": (
            "Restrict database access to trusted systems and "
            "avoid unnecessary public network exposure."
        ),
    },
}

ALTERNATE_PORT_DATABASE = {
    "8000": {
        "name": "HTTP Development Server",
        "category": "web",
        "default_severity": "MEDIUM",
        "description": (
            "Port 8000 is commonly used by development web servers."
        ),
        "recommendation": (
            "Verify the development server is intentional and avoid exposing "
            "it to untrusted networks unless required."
        ),
    },
    "8080": {
        "name": "Alternate HTTP",
        "category": "web",
        "default_severity": "MEDIUM",
        "description": (
            "Port 8080 is commonly used for alternate HTTP or development web services."
        ),
        "recommendation": (
            "Verify the web service is expected and restrict network exposure "
            "if remote access is unnecessary."
        ),
    },
    "8443": {
        "name": "Alternate HTTPS",
        "category": "web",
        "default_severity": "MEDIUM",
        "description": (
            "Port 8443 is commonly used for alternate HTTPS services."
        ),
        "recommendation": (
            "Verify the service is expected and maintain secure TLS configuration."
        ),
    },
}


def lookup_service(port: str) -> dict:
    """Return service intelligence for a port."""

    port = str(port)

    service = SERVICE_DATABASE.get(port)

    if not service:
        service = ALTERNATE_PORT_DATABASE.get(port)

    if service:
        return {
            "known": True,
            "port": port,
            **service,
        }

    return {
        "known": False,
        "port": port,
        "name": "Unknown",
        "category": "unknown",
        "default_severity": "INFO",
        "description": "No built-in service intelligence is available for this port.",
        "recommendation": (
            "Identify the service using this port and verify that "
            "its network exposure is expected."
        ),
    }
