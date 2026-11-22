import socket
from typing import List, Dict, Optional

class BannerGrabber:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
    
    def grab_banner(self, target: str, port: int) -> Optional[str]:
        """Attempt to grab a banner from the target port."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Send standard HTTP request if port is a common web port to trigger a response
            if port in [80, 8080]:
                sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode("utf-8"))
                
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else None
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def grab_banners(self, target: str, ports: List[int]) -> Dict[int, Optional[str]]:
        """Grab banners from a list of ports on the target host."""
        results = {}
        for port in ports:
            results[port] = self.grab_banner(target, port)
        return results