"""Compatibility wrapper for the concurrent, explicit-state TCP scanner."""
from app.scanner.port_scanner import PortScanner


class ThreadedPortScanner:
    def __init__(self, timeout: float = 10.0, threads: int = 10):
        self.timeout = max(10.0, float(timeout))
        self.num_threads = max(1, min(int(threads), 128))

    def scan(self, target: str, ports: list[int], grab_banners: bool = False) -> list[dict]:
        return PortScanner(timeout=self.timeout, workers=self.num_threads).scan(target, ports, grab_banners)
