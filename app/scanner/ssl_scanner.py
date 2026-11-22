"""
SSL/TLS Security Scanner module for Vulnerability Scanner.
Inspects TLS protocol version, certificate subject, issuer, expiration,
self-signed status, certificate validity, cipher information, and generates
security findings with evidence and severity.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class SSLScanner:
    """
    Dedicated SSL/TLS Certificate & Cipher Assessment Scanner.
    Inspects host SSL/TLS endpoints for certificates, ciphers, and security risks.
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    @staticmethod
    def _parse_dn_tuple(dn_tuple: Optional[Tuple]) -> Dict[str, str]:
        """Convert certificate Subject/Issuer tuple format to a clean key-value dictionary."""
        if not dn_tuple:
            return {}
        
        mapping = {
            "commonName": "common_name",
            "organizationName": "organization",
            "organizationalUnitName": "organizational_unit",
            "countryName": "country",
            "stateOrProvinceName": "state",
            "localityName": "locality"
        }
        
        result = {}
        for rdn in dn_tuple:
            for entry in rdn:
                if isinstance(entry, tuple) and len(entry) == 2:
                    key, val = entry
                    mapped_key = mapping.get(key, key)
                    result[mapped_key] = val
        return result


    @staticmethod
    def _format_dn_string(dn_dict: Dict[str, str]) -> str:
        """Format Distinguished Name dictionary into readable string representation."""
        if not dn_dict:
            return "Unknown"
        
        parts = []
        if "common_name" in dn_dict:
            parts.append(f"CN={dn_dict['common_name']}")
        if "organization" in dn_dict:
            parts.append(f"O={dn_dict['organization']}")
        if "organizational_unit" in dn_dict:
            parts.append(f"OU={dn_dict['organizational_unit']}")
        if "country" in dn_dict:
            parts.append(f"C={dn_dict['country']}")

        for k, v in dn_dict.items():
            if k not in ("common_name", "organization", "organizational_unit", "country"):
                parts.append(f"{k}={v}")

        return ", ".join(parts) if parts else "Unknown"

    @staticmethod
    def _parse_cert_date(date_str: Optional[str]) -> Optional[datetime]:
        """Parse certificate ASN.1 date string (e.g. 'May 15 12:00:00 2025 GMT') into UTC datetime."""
        if not date_str:
            return None
        try:
            # ASN.1 time format from ssl module is typically '%b %d %H:%M:%S %Y %Z'
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                # Handle single-digit day padding if formatted differently
                dt = datetime.strptime(" ".join(date_str.split()), "%b %d %H:%M:%S %Y GMT")
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                return None

    def check_supported_tls_versions(self, target: str, port: int) -> List[str]:
        """Probe which TLS protocol versions (TLS 1.0, 1.1, 1.2, 1.3) the server accepts."""
        supported = []
        
        if not hasattr(ssl, "TLSVersion"):
            return supported

        version_map = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]

        for ver_name, ver_enum in version_map:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver_enum
                ctx.maximum_version = ver_enum
                with socket.create_connection((target, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target) as sslsock:
                        if sslsock.version():
                            supported.append(ver_name)
            except Exception:
                pass

        return supported

    def scan_ssl_tls(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Executes full SSL/TLS assessment on target and port.
        Returns certificate details, protocol version, cipher details, validity, self-signed status,
        and security findings with severity and evidence.
        """
        assessment = {
            "target": target,
            "port": port,
            "ssl_enabled": False,
            "tls_version": "N/A",
            "supported_tls_versions": [],
            "certificate": {
                "subject": "N/A",
                "subject_dict": {},
                "issuer": "N/A",
                "issuer_dict": {},
                "subject_alt_names": [],
                "not_before": "N/A",
                "not_after": "N/A",
                "days_until_expiration": 0,
                "is_self_signed": False,
                "is_expired": False,
                "is_valid": False,
                "validity_status": "No Certificate Found"
            },
            "cipher": {
                "name": "N/A",
                "version": "N/A",
                "secret_bits": 0
            },
            "findings": []
        }

        cert = None
        tls_version = None
        cipher_info = None
        verification_error = None

        # Attempt 1: Standard context with hostname check & certificate verification
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as sslsock:
                    cert = sslsock.getpeercert()
                    tls_version = sslsock.version()
                    cipher_info = sslsock.cipher()
        except ssl.SSLCertVerificationError as ve:
            verification_error = str(ve)
        except Exception:
            pass

        # Attempt 2: Fallback unverified context to extract certificate details if verification failed
        if not cert:
            try:
                context = ssl._create_unverified_context()
                with socket.create_connection((target, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as sslsock:
                        cert = sslsock.getpeercert()
                        tls_version = sslsock.version()
                        cipher_info = sslsock.cipher()
            except Exception as e:
                # SSL/TLS not supported on this port
                return assessment

        if not cert and not tls_version and not cipher_info:
            return assessment

        assessment["ssl_enabled"] = True
        assessment["tls_version"] = tls_version or "Unknown"

        if cipher_info:
            assessment["cipher"] = {
                "name": cipher_info[0] if len(cipher_info) > 0 else "Unknown",
                "version": cipher_info[1] if len(cipher_info) > 1 else "Unknown",
                "secret_bits": cipher_info[2] if len(cipher_info) > 2 else 0
            }

        # Subject & Issuer parsing
        subject_tuple = cert.get("subject", ()) if cert else ()
        issuer_tuple = cert.get("issuer", ()) if cert else ()

        subject_dict = self._parse_dn_tuple(subject_tuple)
        issuer_dict = self._parse_dn_tuple(issuer_tuple)

        subject_str = self._format_dn_string(subject_dict)
        issuer_str = self._format_dn_string(issuer_dict)

        # Subject Alternative Names (SANs)
        san_list = []
        if cert and "subjectAltName" in cert:
            for san_type, san_val in cert["subjectAltName"]:
                san_list.append(f"{san_type}:{san_val}")

        # Expiration & Dates
        not_before_raw = cert.get("notBefore") if cert else None
        not_after_raw = cert.get("notAfter") if cert else None

        dt_not_before = self._parse_cert_date(not_before_raw)
        dt_not_after = self._parse_cert_date(not_after_raw)
        now_utc = datetime.now(timezone.utc)

        days_until_expiration = 0
        is_expired = False
        is_not_yet_valid = False
        expiring_soon = False

        if dt_not_after:
            delta = dt_not_after - now_utc
            days_until_expiration = delta.days
            if days_until_expiration < 0:
                is_expired = True
            elif days_until_expiration <= 30:
                expiring_soon = True

        if dt_not_before and now_utc < dt_not_before:
            is_not_yet_valid = True

        # Self-Signed Status Determination
        is_self_signed = False
        if subject_dict and issuer_dict:
            if subject_dict == issuer_dict:
                is_self_signed = True
            elif subject_dict.get("common_name") and subject_dict.get("common_name") == issuer_dict.get("common_name"):
                is_self_signed = True

        if verification_error and ("self signed certificate" in verification_error.lower() or "self-signed" in verification_error.lower()):
            is_self_signed = True

        # Validity Status
        is_valid = True
        validity_reasons = []

        if is_expired:
            is_valid = False
            validity_reasons.append(f"Expired on {not_after_raw}")
        if is_not_yet_valid:
            is_valid = False
            validity_reasons.append(f"Not valid until {not_before_raw}")
        if is_self_signed:
            is_valid = False
            validity_reasons.append("Self-Signed Certificate")
        if verification_error:
            is_valid = False
            if "hostname" in verification_error.lower() or "match" in verification_error.lower():
                validity_reasons.append("Hostname Mismatch")
            elif not validity_reasons:
                validity_reasons.append("Untrusted Certificate Authority")

        validity_status = "Valid" if is_valid else "; ".join(validity_reasons) if validity_reasons else "Invalid"

        assessment["certificate"] = {
            "subject": subject_str,
            "subject_dict": subject_dict,
            "issuer": issuer_str,
            "issuer_dict": issuer_dict,
            "subject_alt_names": san_list,
            "not_before": not_before_raw or "N/A",
            "not_after": not_after_raw or "N/A",
            "days_until_expiration": days_until_expiration,
            "is_self_signed": is_self_signed,
            "is_expired": is_expired,
            "is_valid": is_valid,
            "validity_status": validity_status
        }

        # Check supported protocol versions
        supported_tls = self.check_supported_tls_versions(target, port)
        if not supported_tls and tls_version:
            supported_tls = [tls_version]
        assessment["supported_tls_versions"] = supported_tls

        # ---------------------------------------------------------
        # GENERATE SECURITY FINDINGS WITH EVIDENCE AND SEVERITY
        # ---------------------------------------------------------
        findings = []

        # 1. Expired Certificate Finding
        if is_expired:
            findings.append({
                "id": "SSL-CERT-EXPIRED",
                "type": "TLS/SSL Vulnerability",
                "title": "SSL/TLS Certificate Has Expired",
                "severity": "High",
                "description": f"The SSL/TLS certificate for host '{target}' expired on {not_after_raw}.",
                "recommendation": "Renew the SSL/TLS certificate immediately with a trusted Certificate Authority.",
                "evidence": f"Certificate notAfter date is {not_after_raw} ({abs(days_until_expiration)} days past current date)."
            })

        # 2. Certificate Expiring Soon Finding
        elif expiring_soon:
            findings.append({
                "id": "SSL-CERT-EXPIRING-SOON",
                "type": "TLS/SSL Warning",
                "title": "SSL/TLS Certificate Expiring Soon",
                "severity": "Medium",
                "description": f"The SSL/TLS certificate for '{target}' will expire in {days_until_expiration} days on {not_after_raw}.",
                "recommendation": "Plan certificate renewal before the expiration date to avoid service disruption.",
                "evidence": f"Certificate expires in {days_until_expiration} days (notAfter: {not_after_raw})."
            })

        # 3. Not Yet Valid Certificate Finding
        if is_not_yet_valid:
            findings.append({
                "id": "SSL-CERT-NOT-YET-VALID",
                "type": "TLS/SSL Issue",
                "title": "SSL/TLS Certificate Not Yet Valid",
                "severity": "Medium",
                "description": f"The SSL/TLS certificate activation date is set in the future ({not_before_raw}).",
                "recommendation": "Verify system time or issue a certificate with valid start date.",
                "evidence": f"Certificate notBefore date: {not_before_raw}"
            })

        # 4. Self-Signed Certificate Finding
        if is_self_signed:
            findings.append({
                "id": "SSL-CERT-SELF-SIGNED",
                "type": "TLS/SSL Issue",
                "title": "Self-Signed SSL/TLS Certificate In Use",
                "severity": "Medium",
                "description": f"The SSL/TLS certificate presented by '{target}' is self-signed and not issued by a public/trusted CA.",
                "recommendation": "Replace self-signed certificates in production with certificates signed by a trusted Certificate Authority (e.g. Let's Encrypt).",
                "evidence": f"Certificate Subject ({subject_str}) matches Issuer ({issuer_str})."
            })

        # 5. Hostname Mismatch / Untrusted CA Verification Error
        if verification_error and not is_self_signed and not is_expired:
            findings.append({
                "id": "SSL-CERT-VERIFICATION-FAILED",
                "type": "TLS/SSL Vulnerability",
                "title": "SSL/TLS Certificate Verification Failed",
                "severity": "Medium",
                "description": f"Certificate validation for target '{target}' failed: {verification_error}",
                "recommendation": "Ensure the server certificate matches the domain hostname and has a complete valid trust chain.",
                "evidence": f"Verification error: {verification_error}"
            })

        # 6. Deprecated TLS Version Supported Finding
        deprecated_versions = [v for v in supported_tls if v in ("TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2")]
        if deprecated_versions:
            findings.append({
                "id": "SSL-DEPRECATED-TLS-VERSION",
                "type": "TLS Protocol Risk",
                "title": f"Deprecated TLS Protocol(s) Supported ({', '.join(deprecated_versions)})",
                "severity": "High",
                "description": f"The server accepts connection requests using legacy TLS versions ({', '.join(deprecated_versions)}). Legacy TLS versions contain known cryptographic vulnerabilities (e.g. POODLE, BEAST).",
                "recommendation": "Disable support for TLS 1.0 and TLS 1.1 in the web server configuration. Enforce TLS 1.2 or TLS 1.3.",
                "evidence": f"Server accepted handshake using deprecated version(s): {', '.join(deprecated_versions)}"
            })

        # 7. Weak Cipher Suite Finding
        cipher_name = assessment["cipher"]["name"]
        secret_bits = assessment["cipher"]["secret_bits"]
        if secret_bits > 0 and secret_bits < 128:
            findings.append({
                "id": "SSL-WEAK-CIPHER-KEY-SIZE",
                "type": "TLS Cipher Risk",
                "title": f"Weak Key Length in Cipher Suite ({secret_bits}-bit)",
                "severity": "High",
                "description": f"The negotiated cipher suite '{cipher_name}' uses weak key lengths ({secret_bits}-bit), making it susceptible to brute-force decryption.",
                "recommendation": "Reconfigure server cipher suites to enforce at least 128-bit or 256-bit encryption algorithms.",
                "evidence": f"Cipher: {cipher_name}, Secret Bits: {secret_bits}"
            })
        
        weak_cipher_keywords = ["RC4", "3DES", "DES", "NULL", "ANON", "MD5", "EXPORT"]
        if any(kw in cipher_name.upper() for kw in weak_cipher_keywords):
            findings.append({
                "id": "SSL-WEAK-CIPHER-SUITE",
                "type": "TLS Cipher Risk",
                "title": f"Weak or Insecure Cipher Suite Negotiated ({cipher_name})",
                "severity": "Medium",
                "description": f"The server negotiated a weak cryptographic cipher suite '{cipher_name}'.",
                "recommendation": "Disable weak ciphers (RC4, 3DES, DES, NULL, ANON, MD5, EXPORT) in web server configuration.",
                "evidence": f"Negotiated cipher suite: {cipher_name}"
            })

        assessment["findings"] = findings
        return assessment
