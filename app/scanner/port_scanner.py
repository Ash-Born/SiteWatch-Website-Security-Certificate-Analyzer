"""Concurrent TCP connect scanner with explicit closed/filtered/error states."""
from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.scanner.service_detector import ServiceDetector
from app.scanner.version_detector import VersionDetector


class PortScanner:
    def __init__(self, timeout: float = 10.0, workers: int = 64):
        self.timeout = max(10.0, float(timeout))
        self.workers = max(1, min(int(workers), 128))
        self.service_detector = ServiceDetector(timeout=self.timeout)
        self.version_detector = VersionDetector()

    def scan(self, target: str, ports: list[int], grab_banners: bool = False) -> list[dict]:
        """Probe ports concurrently; never turn a timeout or network error into a false closed result."""
        checked_ports = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
        print(f"Scanning {target} for {len(checked_ports)} TCP ports (timeout {self.timeout:g}s)…")
        started = time.monotonic()
        results: dict[int, dict] = {}
        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(checked_ports)))) as pool:
            futures = {pool.submit(self.scan_port_and_detect, target, port, grab_banners): port for port in checked_ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    results[port] = future.result()
                except Exception as exc:  # Defensive: preserve an explicit result if an unexpected worker error occurs.
                    results[port] = {"port": port, "status": "error", "service": "unknown",
                                     "error": f"{type(exc).__name__}: {str(exc)[:180]}"}
        print(f"Scan complete in {time.monotonic() - started:.2f}s")
        return [results[port] for port in checked_ports]

    def scan_port_and_detect(self, target: str, port: int, grab_banner: bool = False) -> dict:
        result = {"port": port, "status": "closed", "service": "unknown"}
        if grab_banner:
            result.update({"banner": None, "software": "unknown", "version": "unknown"})
        try:
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                result["status"] = "open"
                banner = None
                if grab_banner:
                    try:
                        sock.settimeout(self.timeout)
                        if port in (80, 8080):
                            sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore"))
                        banner = sock.recv(2048).decode("utf-8", errors="replace").strip() or None
                    except (socket.timeout, OSError):
                        banner = None
                result["service"] = (
                    self.service_detector.detect_from_banner(banner, port)
                    if banner else self.service_detector.COMMON_PORTS.get(port, "unknown")
                )
                if banner:
                    result["banner"] = banner[:1000]
                    version = self.version_detector.detect(banner)
                    result["software"] = version.get("software", "unknown")
                    result["version"] = version.get("version", "unknown")
        except socket.timeout as exc:
            result.update({"status": "filtered", "error": f"Connection timed out after {self.timeout:g}s"})
        except ConnectionRefusedError:
            result["status"] = "closed"
        except OSError as exc:
            result["status"] = "closed" if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET) else "error"
            result["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
        return result
