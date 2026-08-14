import platform
import socket
import getpass

from .system_identity import get_local_system_id

def collect_system_information() -> dict:
    return {
        "system_id": get_local_system_id(),
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "architecture":platform.machine(),
        "processor": platform.processor(),
    }
