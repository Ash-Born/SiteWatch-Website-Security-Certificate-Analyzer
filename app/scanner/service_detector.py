import socket
from typing import Optional

class ServiceDetector:
    COMMON_PORTS = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-alt",
        8443: "HTTPS-alt"
    }

    def __init__(self, timeout=1.0):
        self.timeout = timeout

    def detect(self, target: str, port: int, banner: Optional[str] = None) -> str:
        """Detect service name based on banner and port."""
        if banner:
            return self.detect_from_banner(banner, port)
        
        # Fallback to common ports list first
        service_name = self.COMMON_PORTS.get(port)
        if service_name:
            return service_name

        # If not in common ports and no banner, we try once to grab a banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))
            if port in [80, 8080, 8443]:
                sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode("utf-8"))
            grabbed_banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if grabbed_banner:
                return self.detect_from_banner(grabbed_banner, port)
        except:
            pass
        finally:
            sock.close()

        return "unknown"

    def detect_from_banner(self, banner: str, port: int) -> str:
        """Helper to analyze banner content for service names."""
        banner_upper = banner.upper()
        if "SSH-" in banner_upper:
            return "SSH"
        elif "HTTP/" in banner_upper or "SERVER:" in banner_upper:
            return "HTTP"
        elif "220 " in banner_upper and ("FTP" in banner_upper or "FILEZILLA" in banner_upper):
            return "FTP"
        elif "AMQP" in banner_upper:
            return "AMQP"
        
        # Fallback to port mapping if banner is unrecognized
        return self.COMMON_PORTS.get(port, "unknown")