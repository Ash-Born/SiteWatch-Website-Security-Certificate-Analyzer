import math
from typing import List, Dict, Any

class RiskScorer:
    @staticmethod
    def cvss_roundup(value: float) -> float:
        """
        Official CVSS v3.1 specification Roundup function.
        It rounds a floating point number up to the next one decimal place.
        For example:
            cvss_roundup(8.41) -> 8.5
            cvss_roundup(8.00) -> 8.0
            cvss_roundup(8.45) -> 8.5
        """
        # Ensure we work with 2 decimal precision to avoid floating point representation issues
        # Multiply by 100 and cast/round to int
        val_int = int(round(value * 100, 5))
        if val_int % 10 == 0:
            return val_int / 100.0
        return (val_int // 10 + 1) / 10.0

    @staticmethod
    def get_severity(cvss_score: float) -> str:
        """Categorize a CVSS v3 score into the standard NVD severity rating scale."""
        if cvss_score is None:
            return "NONE"
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score >= 0.1:
            return "LOW"
        return "NONE"

    @staticmethod
    def calculate_host_risk(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate the overall CVSS risk score, a weighted cumulative risk score,
        and severity metrics for a host based on all its detected vulnerabilities.
        
        The weighted score is calculated using the formula:
          weighted_score = max_cvss + (sum of other CVSS scores * 0.1)
        capped at 10.0, and rounded up to the nearest one decimal place per the CVSS spec.
        """
        if not vulnerabilities:
            return {
                "max_cvss_score": 0.0,
                "weighted_risk_score": 0.0,
                "host_severity": "NONE",
                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "NONE": 0
                }
            }

        # Extract scores, default to 0.0 if not present
        scores = [v.get("cvss_score", 0.0) for v in vulnerabilities]
        max_cvss = max(scores)

        # Count severities
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "NONE": 0
        }
        for v in vulnerabilities:
            sev = v.get("severity", "").upper()
            if sev not in counts:
                # If severity field is missing, infer from CVSS score
                sev = RiskScorer.get_severity(v.get("cvss_score"))
            counts[sev] += 1

        # Calculate weighted score (max_cvss + 10% of other vulnerabilities' CVSS scores)
        other_scores = sorted(scores)
        if len(other_scores) > 1:
            other_scores.pop()  # Remove one instance of the maximum score
            weighted = max_cvss + sum(other_scores) * 0.1
        else:
            weighted = max_cvss

        # Bound to 0.0 - 10.0 range and round up per CVSS spec
        max_cvss_bounded = max(0.0, min(10.0, max_cvss))
        weighted_bounded = max(0.0, min(10.0, weighted))
        
        max_cvss_final = RiskScorer.cvss_roundup(max_cvss_bounded)
        weighted_final = RiskScorer.cvss_roundup(weighted_bounded)

        return {
            "max_cvss_score": max_cvss_final,
            "weighted_risk_score": weighted_final,
            "host_severity": RiskScorer.get_severity(weighted_final),
            "severity_counts": counts
        }
