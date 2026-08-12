import platform
import socket
import getpass

def collect_system_information() -> dict:
    return {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "architecture":platform.machine(),
        "processor": platform.processor(),
    }
