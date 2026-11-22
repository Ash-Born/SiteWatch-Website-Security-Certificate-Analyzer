import json
import os
import re
import urllib.parse
import requests
from typing import List, Dict, Any

class CVELookup:
    
    def __init__(self, db_path: str = None):
        # The db_path is kept for backwards compatibility in existing tests,
        # but we no longer use a local database.
        self.db_path = db_path
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _parse_nvd_response(self, data: dict) -> List[Dict[str, Any]]:
        results = []
        vulnerabilities = data.get("vulnerabilities", [])
        
        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")
            
            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break
            
            # Extract CVSS score and severity
            cvss_score = 0.0
            severity = "NONE"
            metrics = cve_data.get("metrics", {})
            
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "NONE")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "NONE")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "NONE")
                
            # If severity is still NONE but score is > 0, we can estimate
            if severity == "NONE" and cvss_score > 0:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                    
            # We don't have perfect remediation info from NVD usually, so we'll leave it generic
            remediation = None
            
            # For software, we'll try to guess from description or leave as general
            software_guess = "Unknown"
            
            # We append the CVE
            results.append({
                "cve_id": cve_id,
                "software": software_guess,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "remediation": remediation,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
            
        return results

    def lookup(self, software: str, version: str) -> List[Dict[str, Any]]:
        """Correlate only an exact NVD CPE name; banners are not identity proof."""
        if not software or not software.startswith("cpe:2.3:"):
            return []
        return self._fetch_cpe(software)

    def _fetch_cpe(self, cpe_name: str) -> List[Dict[str, Any]]:
        try:
            headers = {"User-Agent": "Website-Security-Analyzer/1.0"}
            api_key = os.getenv("NVD_API_KEY")
            if api_key:
                headers["apiKey"] = api_key
            response = requests.get(self.base_url, params={"cpeName": cpe_name, "resultsPerPage": 50},
                                    headers=headers, timeout=(3.05, 8))
            response.raise_for_status()
            results = self._parse_nvd_response(response.json())
            for result in results:
                result["software"] = cpe_name
            return results
        except requests.RequestException:
            return []

    def search_nvd(self, query: str) -> List[Dict[str, Any]]:
        """Search the NVD database matching query term."""
        if not query:
            return []
            
        return self._fetch_from_nvd(query)
        
    def _fetch_from_nvd(self, query: str) -> List[Dict[str, Any]]:
        encoded_query = urllib.parse.quote(query)
        # Limit to 10 results to respect API capacity and keep processing fast
        url = f"{self.base_url}?keywordSearch={encoded_query}&resultsPerPage=10"
        try:
            headers = {"User-Agent": "Vulnerability-Scanner/1.0"}
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                results = self._parse_nvd_response(data)
                
                # Update software field to match query if it was mostly unknown
                for r in results:
                    if r["software"] == "Unknown":
                        r["software"] = "Keyword match; product applicability unconfirmed"
                        
                return results
            else:
                print(f"Failed to fetch from NVD API: Status {response.status_code}")
                return []
        except Exception as e:
            print(f"Error querying NVD API: {e}")
            return []


        
