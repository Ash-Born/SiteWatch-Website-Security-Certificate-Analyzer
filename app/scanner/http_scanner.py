"""
HTTP Security Scanner module for Vulnerability Scanner.
Handles HTTP/HTTPS service checks, header security, server banner analysis,
robots.txt inspection, directory listing detection, and HTTPS redirection verification.
"""

from typing import Dict, Any, List, Optional
import re
import urllib3
import requests

# Disable insecure HTTPS request warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPScanner:
    """
    Dedicated HTTP Security Assessment Scanner.
    Executes checks only against detected web services.
    """

    REQUIRED_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy"
    ]

    WEB_SERVICES = {
        "HTTP", "HTTPS", "HTTP-ALT", "HTTPS-ALT",
        "APACHE", "NGINX", "IIS", "TOMCAT",
        "LIGHTTPD", "EXPRESS", "CADDY", "WERKZEUG"
    }

    WEB_PORTS = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 9443}

    COMMON_DIR_PATHS = [
        "/",
        "/images/",
        "/uploads/",
        "/assets/",
        "/static/",
        "/backup/",
        "/css/",
        "/js/",
        "/files/",
        "/doc/"
    ]

    SENSITIVE_ROBOTS_PATTERNS = [
        r'/admin', r'/backup', r'/private', r'/config', r'/secret',
        r'/db', r'/api/v1/internal', r'/login', r'/wp-admin', r'/sql',
        r'/cgi-bin', r'/\.env', r'/\.git', r'/user', r'/test'
    ]

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def should_scan_service(self, service: str, software: str = "", port: int = 0) -> bool:
        """
        Task 2 – Detect HTTP Services
        Only execute HTTP checks when detected service or software is web-related.
        Avoid probing non-web services.
        """
        svc_upper = (service or "").upper().strip()
        soft_upper = (software or "").upper().strip()

        if svc_upper in self.WEB_SERVICES or soft_upper in self.WEB_SERVICES:
            return True

        if any(ws in svc_upper for ws in ["HTTP", "HTTPS", "WEB"]) or any(ws in soft_upper for ws in ["APACHE", "NGINX", "IIS", "TOMCAT"]):
            return True

        if port in self.WEB_PORTS:
            return True

        return False

    def check_security_headers(self, headers: Dict[str, str]) -> tuple[Dict[str, bool], List[Dict[str, Any]]]:
        """
        Task 3 – Check Security Headers
        Inspect response headers for required security headers.
        """
        # Convert header keys to lowercase for case-insensitive lookup
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        header_status = {}
        findings = []

        header_recommendations = {
            "Content-Security-Policy": ("Medium", "Add a Content-Security-Policy (CSP) header to restrict resource origins and mitigate XSS attacks."),
            "Strict-Transport-Security": ("Medium", "Add Strict-Transport-Security (HSTS) header to enforce encrypted HTTPS connections."),
            "X-Content-Type-Options": ("Low", "Add X-Content-Type-Options: nosniff header to prevent browsers from MIME-sniffing response content."),
            "X-Frame-Options": ("Medium", "Add X-Frame-Options (e.g. DENY or SAMEORIGIN) to reduce clickjacking risk."),
            "Referrer-Policy": ("Low", "Add Referrer-Policy (e.g. strict-origin-when-cross-origin) to control referrer information leakage.")
        }

        for header_name in self.REQUIRED_HEADERS:
            is_present = header_name.lower() in headers_lower
            header_status[header_name] = is_present

            if not is_present:
                sev, rec = header_recommendations.get(header_name, ("Medium", f"Configure {header_name} security header."))
                findings.append({
                    "id": f"HTTP-HDR-MISSING-{header_name.upper().replace('-', '_')}",
                    "type": "Missing Header",
                    "title": f"Missing Security Header: {header_name}",
                    "severity": sev,
                    "header": header_name,
                    "description": f"The response header '{header_name}' was not returned by the web server.",
                    "recommendation": rec,
                    "evidence": f"Header '{header_name}' was missing in HTTP response headers."
                })

        return header_status, findings

    def analyze_server_header(self, headers: Dict[str, str], software: str = "", version: str = "") -> tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Task 4 – Analyze Server Header
        Store Server header as evidence, compare with version detection,
        and flag if precise version appears exposed.
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        server_val = headers_lower.get("server")

        findings = []
        if not server_val:
            return None, findings

        # Check if version numbers are present in Server header (e.g., Apache/2.4.49, nginx/1.18.0)
        has_version_number = bool(re.search(r'\d+\.\d+', server_val))

        if has_version_number:
            findings.append({
                "id": "HTTP-SRV-VER-EXPOSED",
                "type": "Configuration Issue",
                "title": "Server Header Information Disclosure",
                "severity": "Low",
                "description": f"The web server exposes detailed software version details in its Server header: '{server_val}'.",
                "recommendation": "Configure the web server to suppress or minimize software version numbers in HTTP response headers (e.g., ServerTokens Prod in Apache, server_tokens off in nginx).",
                "evidence": f"Server: {server_val}"
            })

        return server_val, findings

    def check_robots_txt(self, base_url: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Task 5 – Check robots.txt
        Request GET /robots.txt. Record Exists/Missing/Accessible and report sensitive paths as informational findings.
        """
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        robots_info = {
            "status": "Missing",
            "exists": False,
            "accessible": False,
            "sensitive_paths": []
        }
        findings = []

        try:
            resp = requests.get(robots_url, timeout=self.timeout, verify=False, allow_redirects=True)
            if resp.status_code == 200 and "Disallow" in resp.text or "User-agent" in resp.text or "Allow" in resp.text:
                robots_info["exists"] = True
                robots_info["accessible"] = True
                robots_info["status"] = "Found"

                lines = resp.text.splitlines()
                disallowed_paths = []
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            path = parts[1].strip()
                            if path:
                                disallowed_paths.append(path)

                sensitive_discovered = []
                for path in disallowed_paths:
                    for pattern in self.SENSITIVE_ROBOTS_PATTERNS:
                        if re.search(pattern, path, re.IGNORECASE):
                            sensitive_discovered.append(path)
                            break

                robots_info["sensitive_paths"] = sensitive_discovered

                if sensitive_discovered:
                    findings.append({
                        "id": "HTTP-ROBOTS-SENSITIVE-PATHS",
                        "type": "Configuration Issue",
                        "title": "Sensitive Paths Discovered in robots.txt",
                        "severity": "Low",
                        "description": f"The robots.txt file exposes {len(sensitive_discovered)} sensitive administrative/private path(s).",
                        "recommendation": "Ensure sensitive administrative or private paths listed in robots.txt are properly restricted with authentication and access controls.",
                        "evidence": f"Exposed paths in robots.txt: {', '.join(sensitive_discovered[:5])}"
                    })

            elif resp.status_code == 200:
                robots_info["exists"] = True
                robots_info["accessible"] = True
                robots_info["status"] = "Accessible"
            else:
                robots_info["status"] = "Missing"

        except Exception:
            robots_info["status"] = "Missing"

        return robots_info, findings

    def check_directory_listing(self, base_url: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Task 6 – Detect Directory Listing
        Check whether directory indexing appears enabled on common paths.
        """
        dir_info = {
            "status": "Disabled",
            "exposed_paths": []
        }
        findings = []

        indexing_patterns = [
            r'<title>\s*Index of\s+',
            r'Directory Listing for',
            r'\[PARENTDIR\]',
            r'<a href="\?C=N;O=D">',
            r'Index of /'
        ]

        for path in self.COMMON_DIR_PATHS:
            target_url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = requests.get(target_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    body = resp.text
                    is_indexed = any(re.search(pat, body, re.IGNORECASE) for pat in indexing_patterns)
                    if is_indexed:
                        dir_info["exposed_paths"].append(path)
            except Exception:
                continue

        if dir_info["exposed_paths"]:
            dir_info["status"] = "Enabled"
            findings.append({
                "id": "HTTP-DIR-LISTING-ENABLED",
                "type": "Directory Listing",
                "title": f"Directory Listing Enabled on {', '.join(dir_info['exposed_paths'][:3])}",
                "severity": "Medium",
                "description": f"Directory browsing is enabled on path(s): {', '.join(dir_info['exposed_paths'])}. This allows unauthenticated users to view directory contents.",
                "recommendation": "Disable directory indexing/browsing in web server configuration (e.g., 'Options -Indexes' in Apache or 'autoindex off;' in nginx).",
                "evidence": f"Accessible directory listing confirmed at: {', '.join(dir_info['exposed_paths'])}"
            })

        return dir_info, findings

    def check_https_redirection(self, target: str, http_port: int = 80) -> List[Dict[str, Any]]:
        """
        Task 7 – HTTPS Redirection
        Verify whether HTTP redirects to HTTPS. If not, generate a finding.
        """
        findings = []
        http_url = f"http://{target}:{http_port}/"

        try:
            resp = requests.get(http_url, timeout=self.timeout, verify=False, allow_redirects=False)
            is_redirect = resp.status_code in (301, 302, 307, 308)
            location = resp.headers.get("Location", "")

            redirects_to_https = is_redirect and location.lower().startswith("https://")

            if not redirects_to_https:
                findings.append({
                    "id": "HTTP-NO-HTTPS-REDIRECT",
                    "type": "TLS Issue",
                    "title": "HTTP to HTTPS Redirection Disabled",
                    "severity": "Medium",
                    "description": "The web server serves cleartext HTTP traffic and does not automatically redirect requests to encrypted HTTPS.",
                    "recommendation": "Configure the web server to automatically redirect all unauthenticated HTTP requests to HTTPS.",
                    "evidence": f"HTTP request to {http_url} returned HTTP {resp.status_code} without redirecting to https://"
                })
        except Exception as e:
            # If HTTP port connection fails or resets, assume redirect check could not confirm unencrypted serving
            pass

        return findings

    def scan_web_service(
        self,
        target: str,
        port: int,
        service_name: str,
        software: str = "",
        version: str = "",
        all_open_ports: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Executes full HTTP scan suite on a single detected web service.
        """
        scheme = "https" if port in (443, 8443) or "HTTPS" in service_name.upper() else "http"
        base_url = f"{scheme}://{target}:{port}"

        headers = {}
        server_header = None
        all_findings = []

        # 1. Fetch root page response headers & body
        try:
            resp = requests.get(base_url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = dict(resp.headers)
        except Exception as e:
            pass

        # 2. Check Security Headers (Task 3)
        header_status, hdr_findings = self.check_security_headers(headers)
        all_findings.extend(hdr_findings)

        # 3. Analyze Server Header (Task 4)
        server_header, srv_findings = self.analyze_server_header(headers, software, version)
        all_findings.extend(srv_findings)

        # 4. Check robots.txt (Task 5)
        robots_info, robots_findings = self.check_robots_txt(base_url)
        all_findings.extend(robots_findings)

        # 5. Detect Directory Listing (Task 6)
        dir_info, dir_findings = self.check_directory_listing(base_url)
        all_findings.extend(dir_findings)

        # 6. HTTPS Redirection check (Task 7)
        https_redirect_checked = False
        if scheme == "http" and all_open_ports and (443 in all_open_ports or 8443 in all_open_ports):
            https_redirect_checked = True
            redirect_findings = self.check_https_redirection(target, http_port=port)
            all_findings.extend(redirect_findings)

        # Display server string preference
        display_server = server_header or (f"{software}/{version}".strip("/") if software and software != "unknown" else "Unknown Web Server")

        assessment = {
            "target": target,
            "port": port,
            "scheme": scheme,
            "server": display_server,
            "server_header": server_header,
            "headers": header_status,
            "robots_txt": robots_info,
            "directory_listing": dir_info,
            "https_redirection_checked": https_redirect_checked,
            "findings": all_findings
        }

        return assessment
