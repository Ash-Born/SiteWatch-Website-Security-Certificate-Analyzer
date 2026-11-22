"""
Service layer for Vulnerability Scanner.
Provides business logic decoupled from API endpoints (FastAPI).
"""

from typing import List, Dict, Any, Optional
import socket
from fastapi import HTTPException

from app.scanner.port_scanner import PortScanner
from app.scanner.threaded_port_scanner import ThreadedPortScanner
from app.scanner.cve_lookup import CVELookup
from app.scanner.risk_scorer import RiskScorer
from app.scanner.http_scanner import HTTPScanner
from app.scanner.ssl_scanner import SSLScanner
from app.scanner.report_generator import HTMLReportGenerator

from app.scanner.pdf_report_generator import PDFReportGenerator
import time
import app.database as database

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]

SCAN_PROFILES = {
    "Quick": {"ports": DEFAULT_PORTS, "grab_banners": False, "cve_lookup": False},
    "Full TCP": {"ports": list(range(1, 1025)), "grab_banners": False, "cve_lookup": False},
    "Service Detection": {"ports": DEFAULT_PORTS, "grab_banners": True, "cve_lookup": False},
    "Vulnerability": {"ports": DEFAULT_PORTS, "grab_banners": True, "cve_lookup": True},
}


def resolve_target(target: str) -> str:
    """Validate target hostname or IP address by attempting DNS resolution."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to resolve host or invalid IP address: {target}"
        )


class ScannerService:
    """Service class encapsulating scan execution, CVE enrichment, HTTP assessment, risk evaluation, and storage."""

    @staticmethod
    def run_scan(
        asset_id: int,
        scan_profile: str = "Quick",
        threads: int = 10,
        timeout: float = 10.0,
        use_threaded: bool = True,
        grab_banners: bool = False,
        user_id: Optional[int] = None,
        save_to_db: bool = True
    ) -> Dict[str, Any]:
        """Executes a port scan, enriches results with CVE and HTTP data, calculates risk summary, and optionally persists results."""
        start_time = time.time()
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="Authentication required to scan assets")
        
        asset = database.get_asset_by_id(asset_id, user_id=user_id)
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found or access denied")
        
        scan_target = asset["ip_address"]
        ip_address = resolve_target(scan_target)

        profile_config = SCAN_PROFILES.get(scan_profile, SCAN_PROFILES["Quick"])
        ports_to_scan = profile_config["ports"]
        do_grab_banners = profile_config["grab_banners"] or grab_banners
        do_cve_lookup = profile_config["cve_lookup"]

        if use_threaded:
            scanner = ThreadedPortScanner(timeout=timeout, threads=threads)
        else:
            scanner = PortScanner(timeout=timeout)

        status = "Pending"
        try:
            status = "Running"
            results = scanner.scan(ip_address, ports_to_scan, grab_banners=do_grab_banners)
            status = "Completed"
        except Exception as e:
            status = "Failed"
            raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

        all_vulnerabilities = []
        all_merged_findings = []

        if do_cve_lookup:
            cve_lookup = CVELookup()
            for item in results:
                software = item.get("software")
                version = item.get("version")
                if item.get("status") == "open" and software and software != "unknown" and version and version != "unknown":
                    matched_cves = cve_lookup.lookup(software, version)
                    matched_cves.sort(key=lambda c: c.get("cvss_score", 0.0), reverse=True)
                    item["vulnerabilities"] = matched_cves
                    all_vulnerabilities.extend(matched_cves)
                    
                    for cve in matched_cves:
                        all_merged_findings.append({
                            "id": cve.get("cve_id"),
                            "type": "CVE",
                            "title": f"{cve.get('cve_id')} - {cve.get('software')}",
                            "severity": cve.get("severity", "MEDIUM"),
                            "cvss_score": cve.get("cvss_score", 0.0),
                            "port": item.get("port"),
                            "service": item.get("service"),
                            "description": cve.get("description"),
                            "recommendation": cve.get("remediation"),
                            "evidence": f"Software {item.get('software')} {item.get('version')} matched {cve.get('cve_id')}"
                        })
                else:
                    item["vulnerabilities"] = []
        else:
            for item in results:
                item["vulnerabilities"] = []

        # Run HTTP Security Scanner on open web services (Task 1 & Task 2)
        http_scanner = HTTPScanner(timeout=max(timeout, 10.0))
        ssl_scanner = SSLScanner(timeout=max(timeout, 10.0))
        open_ports = [r["port"] for r in results if r.get("status") == "open"]
        
        aggregated_http_assessment = None
        aggregated_ssl_assessment = None
        http_findings_list = []
        ssl_findings_list = []

        for item in results:
            item_findings = []
            # Copy CVE findings into item["findings"]
            for cve in item.get("vulnerabilities", []):
                item_findings.append({
                    "id": cve.get("cve_id"),
                    "type": "CVE",
                    "title": f"{cve.get('cve_id')} - {cve.get('software')}",
                    "severity": cve.get("severity", "MEDIUM"),
                    "cvss_score": cve.get("cvss_score", 0.0),
                    "port": item.get("port"),
                    "service": item.get("service"),
                    "description": cve.get("description"),
                    "recommendation": cve.get("remediation"),
                    "evidence": f"Software {item.get('software')} {item.get('version')} matched {cve.get('cve_id')}"
                })

            port_num = item.get("port", 0)
            svc_name = (item.get("service") or "").upper()

            # Execute HTTP assessment
            if item.get("status") == "open" and http_scanner.should_scan_service(item.get("service", ""), item.get("software", ""), port_num):
                http_eval = http_scanner.scan_web_service(
                    target=ip_address,
                    port=item["port"],
                    service_name=item.get("service", "HTTP"),
                    software=item.get("software", ""),
                    version=item.get("version", ""),
                    all_open_ports=open_ports
                )
                item["http_assessment"] = http_eval
                service_http_findings = http_eval.get("findings", [])
                item_findings.extend(service_http_findings)
                http_findings_list.extend(service_http_findings)
                all_merged_findings.extend(service_http_findings)

                if not aggregated_http_assessment:
                    aggregated_http_assessment = http_eval

            # Execute SSL/TLS assessment on SSL/TLS enabled ports
            if item.get("status") == "open" and (port_num in (443, 8443, 993, 995, 465, 636) or "SSL" in svc_name or "HTTPS" in svc_name):
                ssl_eval = ssl_scanner.scan_ssl_tls(target=ip_address, port=port_num)
                if ssl_eval.get("ssl_enabled"):
                    item["ssl_assessment"] = ssl_eval
                    service_ssl_findings = ssl_eval.get("findings", [])
                    item_findings.extend(service_ssl_findings)
                    ssl_findings_list.extend(service_ssl_findings)
                    all_merged_findings.extend(service_ssl_findings)

                    if not aggregated_ssl_assessment:
                        aggregated_ssl_assessment = ssl_eval

            item["findings"] = item_findings

        if not aggregated_http_assessment:
            aggregated_http_assessment = {
                "target": ip_address,
                "server": "N/A (No Web Service Detected)",
                "headers": {
                    "Content-Security-Policy": False,
                    "Strict-Transport-Security": False,
                    "X-Content-Type-Options": False,
                    "X-Frame-Options": False,
                    "Referrer-Policy": False
                },
                "robots_txt": {"status": "Missing", "sensitive_paths": []},
                "directory_listing": {"status": "Disabled", "exposed_paths": []},
                "https_redirection_checked": False,
                "findings": []
            }

        aggregated_http_assessment["findings"] = http_findings_list

        if not aggregated_ssl_assessment:
            aggregated_ssl_assessment = {
                "target": ip_address,
                "port": 443,
                "ssl_enabled": False,
                "tls_version": "N/A",
                "supported_tls_versions": [],
                "certificate": {
                    "subject": "N/A",
                    "issuer": "N/A",
                    "not_before": "N/A",
                    "not_after": "N/A",
                    "days_until_expiration": 0,
                    "is_self_signed": False,
                    "is_expired": False,
                    "is_valid": False,
                    "validity_status": "No Certificate Found"
                },
                "cipher": {"name": "N/A", "version": "N/A", "secret_bits": 0},
                "findings": []
            }

        aggregated_ssl_assessment["findings"] = ssl_findings_list

        risk_stats = RiskScorer.calculate_host_risk(all_vulnerabilities)
        
        end_time = time.time()
        duration = round(end_time - start_time, 2)

        scan_data = {
            "target": scan_target,
            "asset_id": asset_id,
            "scan_profile": scan_profile,
            "status": status,
            "duration": duration,
            "ports_scanned": len(ports_to_scan),
            "use_threaded": use_threaded,
            "results": results,
            "risk_summary": risk_stats,
            "http_assessment": aggregated_http_assessment,
            "ssl_assessment": aggregated_ssl_assessment,
            "findings": all_merged_findings
        }


        if save_to_db and user_id is not None:
            try:
                saved_id = database.save_scan(scan_data, user_id=user_id, asset_id=asset_id)
                scan_data["id"] = saved_id
            except Exception as e:
                print(f"Error saving scan to database: {e}")

        return scan_data

    @staticmethod
    def list_user_scans(user_id: int) -> List[Dict[str, Any]]:
        """Retrieve scan history for a user."""
        return database.get_all_scans(user_id=user_id)

    @staticmethod
    def get_user_scan(scan_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific scan record for a user."""
        return database.get_scan(scan_id, user_id=user_id)

    @staticmethod
    def generate_html_report(scan_data: Dict[str, Any]) -> str:
        """Generate HTML report string from scan data."""
        return HTMLReportGenerator.generate_report(scan_data)

    @staticmethod
    def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
        """Generate PDF report bytes from scan data."""
        return PDFReportGenerator.generate_report(scan_data)


class AssetService:
    """Service class encapsulating Asset management business logic."""

    @staticmethod
    def create_asset(user_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        # Validate target IP or hostname resolution
        resolve_target(data["ip_address"])
        try:
            return database.create_asset(
                user_id=user_id,
                hostname=data["hostname"].strip(),
                ip_address=data["ip_address"].strip(),
                operating_system=data.get("operating_system"),
                criticality=data.get("criticality", "Medium"),
                owner_team=data.get("owner"),
                description=data.get("description")
            )
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

    @staticmethod
    def list_assets(user_id: int) -> List[Dict[str, Any]]:
        return database.get_all_assets(user_id)

    @staticmethod
    def get_asset(asset_id: int, user_id: int) -> Dict[str, Any]:
        asset = database.get_asset_by_id(asset_id, user_id)
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found or access denied")
        return asset

    @staticmethod
    def update_asset(asset_id: int, user_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        if data.get("ip_address"):
            resolve_target(data["ip_address"])
        try:
            updated = database.update_asset(
                asset_id=asset_id,
                user_id=user_id,
                hostname=data.get("hostname").strip() if data.get("hostname") else None,
                ip_address=data.get("ip_address").strip() if data.get("ip_address") else None,
                operating_system=data.get("operating_system"),
                criticality=data.get("criticality"),
                owner_team=data.get("owner"),
                description=data.get("description")
            )
            if not updated:
                raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found or access denied")
            return updated
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

    @staticmethod
    def delete_asset(asset_id: int, user_id: int) -> bool:
        success = database.delete_asset(asset_id, user_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found or access denied")
        return True


class CveService:
    """Service class for CVE database queries."""

    @staticmethod
    def lookup(software: str, version: str) -> List[Dict[str, Any]]:
        lookup_engine = CVELookup()
        return lookup_engine.lookup(software, version)

    @staticmethod
    def search(query: str) -> List[Dict[str, Any]]:
        lookup_engine = CVELookup()
        return lookup_engine.search_nvd(query)
