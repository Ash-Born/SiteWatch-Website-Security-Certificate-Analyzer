"""Evidence-based, passive TLS/DNS/HTTP posture checks for authorized domains."""
from __future__ import annotations

import ipaddress
import http.client
import json
import re
import socket
import ssl
from functools import lru_cache
from html.parser import HTMLParser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID, NameOID
from OpenSSL import SSL, crypto
from app.scanner.cve_lookup import CVELookup

SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
CONNECT_TIMEOUT = 10.0
_MITIGATION_FILE = Path(__file__).with_name("data") / "mitigations.json"
MITIGATIONS = json.loads(_MITIGATION_FILE.read_text(encoding="utf-8"))


class _ActiveContentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.http_resources = []

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        candidate = attr.get("src") or attr.get("href")
        active = tag in {"script", "iframe", "frame", "video", "audio", "source", "object", "embed"}
        if tag == "link" and "stylesheet" in attr.get("rel", "").lower():
            active = True
        if active and candidate and candidate.strip().lower().startswith("http://"):
            self.http_resources.append(candidate[:300])


class _ComplianceSignalParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.payment_actions = []
        self.payment_fields = []
        self.trust_candidates = set()
        self.text_parts = []
        self.attribute_text = []
        self.links = []
        self.current_link_index = None
        self.script_sources = []
        self.html_lang = None
        self.aria_count = 0
        self.has_address = False

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "html":
            self.html_lang = attr.get("lang")
        if any(key.lower().startswith("aria-") for key in attr):
            self.aria_count += 1
        if tag == "address":
            self.has_address = True
        if tag == "a" and attr.get("href"):
            self.links.append((str(attr.get("href"))[:400], " ".join(str(attr.get(key, "")) for key in ("title", "aria-label") if attr.get(key))[:300]))
            self.current_link_index = len(self.links) - 1
        if tag == "script" and attr.get("src"):
            self.script_sources.append(str(attr["src"])[:400])
        action = attr.get("action", "")
        if tag == "form" and action:
            self.payment_actions.append(action[:300])
        field = " ".join(str(attr.get(key, "")) for key in ("name", "id", "autocomplete", "placeholder"))
        if tag == "input" and re.search(r"payment|card|cvv|cvc|paypal|stripe", field, re.I):
            self.payment_fields.append(field[:150])
        for value in attr.values():
            self._find_trust_candidate(str(value))
        self.attribute_text.extend(str(attr[key]) for key in ("alt", "title", "aria-label", "class", "id") if attr.get(key))

    def handle_endtag(self, tag):
        if tag == "a":
            self.current_link_index = None

    def handle_data(self, data):
        if data.strip():
            self.text_parts.append(data.strip()[:2000])
            if self.current_link_index is not None:
                href, label = self.links[self.current_link_index]
                self.links[self.current_link_index] = (href, (label + " " + data.strip())[:300].strip())
        self._find_trust_candidate(data)

    def _find_trust_candidate(self, value):
        for vendor in ("norton", "mcafee", "trustwave", "cloudflare", "digicert"):
            if vendor in value.lower():
                self.trust_candidates.add(vendor)


def _signal(signal_id: str, name: str, category: str, status: str, evidence: str) -> dict:
    return {"id": signal_id, "name": name, "category": category,
            "status": status, "evidence": evidence[:500],
            "interpretation": "Observed public signal only; this does not verify certification or regulatory compliance."}


def _fetch_site_path(host: str, ip: str, path: str, scheme: str = "https") -> tuple[int, dict, bytes]:
    """Fetch a small same-host resource through the already validated public IP."""
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Only same-origin absolute paths are allowed")
    port = 443 if scheme == "https" else 80
    if scheme == "https":
        class PinnedHTTPSConnection(http.client.HTTPSConnection):
            def connect(self):
                raw = socket.create_connection((ip, self.port), self.timeout)
                self.sock = self._context.wrap_socket(raw, server_hostname=host)
        connection = PinnedHTTPSConnection(host, port, timeout=CONNECT_TIMEOUT, context=ssl.create_default_context())
    else:
        class PinnedHTTPConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.create_connection((ip, self.port), self.timeout)
        connection = PinnedHTTPConnection(host, port, timeout=CONNECT_TIMEOUT)
    try:
        connection.request("GET", path, headers={"User-Agent": "WebsiteSecurityAnalyzer/1.0", "Connection": "close"})
        response = connection.getresponse()
        payload = response.read(16_384)
        return response.status, {key.lower(): value for key, value in response.getheaders()}, payload
    finally:
        connection.close()


def _finding(check_id: str, title: str, severity: str, evidence: str, confidence: str = "high") -> dict:
    return {
        "id": check_id,
        "check_id": check_id,
        "type": check_id.split(".", 1)[0].upper(),
        "title": title,
        "severity": severity,
        "cvss_score": 0.0,
        "confidence": confidence,
        "evidence": evidence,
        "description": title,
        "recommendation": MITIGATIONS.get(check_id, {}).get("plan", "Review the evidence and correct the affected configuration."),
        "references": MITIGATIONS.get(check_id, {}).get("references", []),
    }


@lru_cache(maxsize=128)
def _lookup_exact_cpe(cpe_name: str) -> tuple[dict, ...]:
    """Cache exact CPE lookups to reduce load on NVD across repeated assessments."""
    try:
        return tuple(CVELookup().lookup(cpe_name, ""))
    except Exception:
        # CVE intelligence is supplementary; an NVD outage must not fail a live scan.
        return ()


def _server_software_from_banner(server_header: str) -> list[dict]:
    """Recognize only well-known, explicit server/version banners and build exact CPEs."""
    patterns = (
        ("Apache HTTP Server", "apache", "http_server", re.compile(r"\bApache(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I)),
        ("nginx", "nginx", "nginx", re.compile(r"\bnginx/(\d+\.\d+(?:\.\d+)?)", re.I)),
    )
    observed, seen = [], set()
    for product, vendor, cpe_product, pattern in patterns:
        for match in pattern.finditer(server_header or ""):
            version = match.group(1)
            cpe_name = f"cpe:2.3:a:{vendor}:{cpe_product}:{version}:*:*:*:*:*:*:*"
            if cpe_name in seen:
                continue
            seen.add(cpe_name)
            cves = sorted(_lookup_exact_cpe(cpe_name), key=lambda item: item.get("cvss_score", 0), reverse=True)
            observed.append({
                "product": product,
                "version": version,
                "server_header": server_header[:300],
                "cpe": cpe_name,
                "match_type": "exact_version_cpe",
                "lookup_status": "completed" if cves else "no_matches_or_unavailable",
                "cves": cves,
                "applicability_note": "NVD CPE version match based on a publicly disclosed banner; vendor backports, build options, and deployment context can change applicability.",
            })
    return observed


def _resolve_public(host: str) -> list[str]:
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        if not literal_ip.is_global:
            raise ValueError("Private, loopback, link-local, and reserved IP targets cannot be scanned")
        return [str(literal_ip)]
    try:
        records = socket.getaddrinfo(host.rstrip(".") + ".", None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Target hostname did not resolve") from exc
    ips = sorted({record[4][0] for record in records})
    if not ips:
        raise ValueError("Target hostname did not resolve")
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError("Targets resolving to private, loopback, link-local, or reserved addresses are not allowed")
    return ips


def _http_url(target: str) -> tuple[str, str]:
    raw = target.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError("Control characters are not allowed in a target")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ValueError("Provide a valid public hostname or HTTP(S) URL")
    if parts.port not in (None, 80, 443):
        raise ValueError("Only standard web ports 80 and 443 are supported")
    host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if "." not in host or len(host) > 253:
        raise ValueError("A fully qualified domain name is required")
    return host, f"https://{host}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")


def validate_public_website_target(target: str) -> str:
    """Validate schedule input using the same URL and public-DNS rules as live scans."""
    host, normalized_url = _http_url(target)
    _resolve_public(host)
    return normalized_url


def _get_peer_chain(ip: str, host: str) -> list[x509.Certificate]:
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
    raw = socket.create_connection((ip, 443), timeout=CONNECT_TIMEOUT)
    connection = SSL.Connection(context, raw)
    connection.set_tlsext_host_name(host.encode("ascii"))
    connection.set_connect_state()
    try:
        connection.do_handshake()
        certificates = connection.get_peer_cert_chain() or []
        return [x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)) for cert in certificates]
    finally:
        connection.close()


def _validate_chain_with_system_roots(chain: list[x509.Certificate]) -> tuple[bool, str | None, list[x509.Certificate]]:
    """Retry using OS roots; fetch a missing issuer certificate from its AIA URL if needed."""
    if not chain:
        return False, "The server did not provide a certificate chain", chain
    verified_chain = list(chain)
    # Some servers omit an intermediate. Try its public CA Issuers AIA endpoint,
    # validating the fetched certificate signature before adding it to the path.
    for _ in range(2):
        current = verified_chain[-1]
        if current.issuer == current.subject or any(current.issuer == item.subject for item in verified_chain[:-1]):
            break
        try:
            aia = current.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            issuer_urls = [item.access_location.value for item in aia
                           if item.access_method == AuthorityInformationAccessOID.CA_ISSUERS
                           and isinstance(item.access_location, x509.UniformResourceIdentifier)]
        except x509.ExtensionNotFound:
            break
        added = False
        for issuer_url in issuer_urls[:2]:
            try:
                payload = _fetch_public_url(issuer_url, "GET", max_bytes=1_000_000)
                try:
                    candidates = [x509.load_der_x509_certificate(payload)]
                except ValueError:
                    try:
                        candidates = [x509.load_pem_x509_certificate(payload)]
                    except ValueError:
                        try:
                            candidates = x509.load_der_pkcs7_certificates(payload)
                        except ValueError:
                            candidates = x509.load_pem_pkcs7_certificates(payload)
                for candidate in candidates:
                    if candidate.subject == current.issuer:
                        candidate.verify_directly_issued_by(current)
                        verified_chain.append(candidate)
                        added = True
                        break
                if added:
                    break
            except Exception:
                continue
        if not added:
            break
    try:
        store = crypto.X509Store()
        store.set_default_paths()
        leaf = crypto.X509.from_cryptography(verified_chain[0])
        untrusted = [crypto.X509.from_cryptography(cert) for cert in verified_chain[1:]]
        crypto.X509StoreContext(store, leaf, untrusted).verify_certificate()
        return True, None, verified_chain
    except Exception as exc:
        return False, str(exc)[:300], verified_chain


def _fetch_public_url(url: str, method: str, body: bytes = b"", headers: dict | None = None, max_bytes: int = 4_000_000) -> bytes:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ValueError("Unsupported certificate status URL")
    hostname = parts.hostname.encode("idna").decode("ascii")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in {80, 443}:
        raise ValueError("Certificate status endpoint uses a nonstandard port")
    addresses = {item[4][0] for item in socket.getaddrinfo(hostname.rstrip(".") + ".", port, type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Certificate status endpoint must resolve to public addresses")
    pinned = sorted(addresses)[0]
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    request_headers = {"Host": hostname, "User-Agent": "WebsiteSecurityAnalyzer/1.0", "Connection": "close", **(headers or {})}
    if parts.scheme == "https":
        class PinnedHTTPS(http.client.HTTPSConnection):
            def connect(self):
                raw = socket.create_connection((pinned, self.port), self.timeout)
                self.sock = self._context.wrap_socket(raw, server_hostname=hostname)
        connection = PinnedHTTPS(hostname, port, timeout=CONNECT_TIMEOUT, context=ssl.create_default_context())
    else:
        class PinnedHTTP(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.create_connection((pinned, self.port), self.timeout)
        connection = PinnedHTTP(hostname, port, timeout=CONNECT_TIMEOUT)
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"Certificate status endpoint returned HTTP {response.status}")
        payload = response.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("Certificate status response exceeded the size limit")
        return payload
    finally:
        connection.close()


def _verify_signed_data(public_key, signature: bytes, data: bytes, hash_algorithm) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(signature, data, hash_algorithm)
    elif isinstance(public_key, (ed25519.Ed25519PublicKey,)):
        public_key.verify(signature, data)
    else:
        raise ValueError("Unsupported certificate status signature key")


def _check_ocsp(cert: x509.Certificate, issuer: x509.Certificate, url: str) -> dict:
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
    response_data = _fetch_public_url(url, "POST", request.public_bytes(serialization.Encoding.DER), {
        "Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"
    }, max_bytes=1_000_000)
    response = ocsp.load_der_ocsp_response(response_data)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError("OCSP responder returned an unsuccessful response")
    if (response.serial_number != cert.serial_number or response.issuer_name_hash != request.issuer_name_hash
            or response.issuer_key_hash != request.issuer_key_hash):
        raise ValueError("OCSP response did not identify the requested certificate and issuer")
    now = datetime.now(timezone.utc)
    if not response.this_update_utc or response.this_update_utc > now or not response.next_update_utc or response.next_update_utc < now:
        raise ValueError("OCSP response is outside its valid time window")
    signer = None
    if response.responder_name == issuer.subject:
        signer = issuer
    else:
        for delegated in response.certificates:
            if delegated.subject == response.responder_name:
                delegated.verify_directly_issued_by(issuer)
                eku = delegated.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                    raise ValueError("OCSP responder certificate lacks the OCSP signing usage")
                if delegated.not_valid_before_utc > now or delegated.not_valid_after_utc < now:
                    raise ValueError("OCSP responder certificate is outside its validity window")
                signer = delegated
                break
    if signer is None:
        raise ValueError("OCSP responder identity could not be verified")
    _verify_signed_data(signer.public_key(), response.signature, response.tbs_response_bytes, response.signature_hash_algorithm)
    return {"status": response.certificate_status.name.lower(), "source": "OCSP", "this_update": response.this_update_utc.isoformat(), "next_update": response.next_update_utc.isoformat()}


def _check_crl(cert: x509.Certificate, issuer: x509.Certificate, url: str) -> dict:
    payload = _fetch_public_url(url, "GET")
    try:
        crl = x509.load_der_x509_crl(payload)
    except ValueError:
        crl = x509.load_pem_x509_crl(payload)
    now = datetime.now(timezone.utc)
    if crl.issuer != issuer.subject or not crl.next_update_utc or crl.next_update_utc < now or crl.last_update_utc > now:
        raise ValueError("CRL issuer or validity window did not match")
    try:
        key_usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        if not key_usage.crl_sign:
            raise ValueError("Issuer certificate does not permit CRL signing")
    except x509.ExtensionNotFound:
        pass
    _verify_signed_data(issuer.public_key(), crl.signature, crl.tbs_certlist_bytes, crl.signature_hash_algorithm)
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
        raise ValueError("Delta CRLs are not treated as a complete revocation list")
    except x509.ExtensionNotFound:
        pass
    try:
        issuing_point = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
        if issuing_point.indirect_crl or issuing_point.only_some_reasons or issuing_point.only_contains_ca_certs or issuing_point.only_contains_attribute_certs:
            raise ValueError("Partitioned or indirect CRLs are not treated as complete")
    except x509.ExtensionNotFound:
        pass
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return {"status": "revoked" if revoked else "good", "source": "CRL", "this_update": crl.last_update_utc.isoformat(), "next_update": crl.next_update_utc.isoformat()}


def _check_revocation(cert: x509.Certificate, chain: list[x509.Certificate]) -> dict:
    if len(chain) < 2:
        return {"status": "unknown", "reason": "Issuing certificate was not supplied by the server"}
    issuer = chain[1]
    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:
        return {"status": "unknown", "reason": "Leaf certificate issuer could not be matched to the supplied chain"}
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        urls = [item.access_location.value for item in aia if item.access_method == AuthorityInformationAccessOID.OCSP and isinstance(item.access_location, x509.UniformResourceIdentifier)]
        for url in urls[:2]:
            try:
                result = _check_ocsp(cert, issuer, url)
                if result["status"] in {"good", "revoked"}:
                    return result
            except Exception:
                continue
    except x509.ExtensionNotFound:
        pass
    try:
        distribution_points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls = [name.value for point in distribution_points for name in (point.full_name or []) if isinstance(name, x509.UniformResourceIdentifier)]
        for url in urls[:2]:
            try:
                result = _check_crl(cert, issuer, url)
                return result
            except Exception:
                continue
    except x509.ExtensionNotFound:
        pass
    return {"status": "unknown", "reason": "No verifiable OCSP response or complete signed CRL was available"}


def analyze_website(target: str) -> dict:
    host, requested_url = _http_url(target)
    resolved_ips = _resolve_public(host)
    findings: list[dict] = []
    checks: dict = {"dns": {}, "tls": {}, "http": {}}
    zone = host  # <-- ডিফল্ট ভ্যালু যোগ করা হলো

    # DNS checks use live authoritative/public resolver answers. Missing answers are kept as unknown.
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = CONNECT_TIMEOUT
    try:
        cname_answer = resolver.resolve(host + ".", "CNAME", lifetime=CONNECT_TIMEOUT, raise_on_no_answer=False)
        caa_name = cname_answer.canonical_name.to_text().rstrip(".") or host
        checks["dns"]["caa_lookup_name"] = caa_name
        zone = resolver.resolve(caa_name + ".", "SOA", lifetime=CONNECT_TIMEOUT).rrset.name.to_text().rstrip(".")
        labels, zone_labels = caa_name.split("."), zone.split(".")
        start = len(labels) - len(zone_labels)
        caa_answers, checked_names = [], []
        for offset in range(0, start + 1):
            candidate = ".".join(labels[offset:])
            checked_names.append(candidate)
            try:
                caa_answers = list(resolver.resolve(candidate + ".", "CAA", lifetime=CONNECT_TIMEOUT))
                if caa_answers:
                    checks["dns"]["caa_found_at"] = candidate
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
        checks["dns"]["caa"] = [r.to_text() for r in caa_answers]
        checks["dns"]["caa_names_checked"] = checked_names
        if not caa_answers:
            findings.append(_finding("dns.no_caa", "No applicable CAA record observed", "LOW", f"Live DNS queries found no CAA record from {host} through zone apex {zone}"))
    except Exception as exc:
        checks["dns"]["caa_status"] = f"unknown: {type(exc).__name__}"
    try:
        dnskey = resolver.resolve(zone + ".", "DNSKEY", lifetime=CONNECT_TIMEOUT, raise_on_no_answer=False)
        checks["dns"]["dnssec_dnskey_observed"] = bool(dnskey.rrset)
        checks["dns"]["dnssec_ad_bit"] = bool(getattr(dnskey.response, "flags", 0) & 0x0020)
    except Exception as exc:
        checks["dns"]["dnssec_status"] = f"unknown: {type(exc).__name__}"
    checks["dns"]["addresses"] = resolved_ips
    for key, name in (("spf", host), ("dmarc", f"_dmarc.{host}")):
        try:
            answer = resolver.resolve(name + ".", "TXT", lifetime=CONNECT_TIMEOUT)
            values = [r.to_text().strip('"') for r in answer]
            checks["dns"][key] = [v for v in values if key != "spf" or v.lower().startswith("v=spf1")]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            checks["dns"][key] = []
        except Exception as exc:
            checks["dns"][f"{key}_status"] = f"unknown: {type(exc).__name__}"
    checks["dns"]["resolver_answers"] = {}
    for resolver_ip in ("8.8.8.8", "1.1.1.1"):
        try:
            public_resolver = dns.resolver.Resolver(configure=False)
            public_resolver.nameservers = [resolver_ip]
            answer = public_resolver.resolve(host + ".", "A", lifetime=CONNECT_TIMEOUT)
            checks["dns"]["resolver_answers"][resolver_ip] = sorted({r.address for r in answer})
        except Exception as exc:
            checks["dns"]["resolver_answers"][resolver_ip] = f"unknown: {type(exc).__name__}"
    observed_answers = [v for v in checks["dns"]["resolver_answers"].values() if isinstance(v, list)]
    if len(observed_answers) == 2 and all(v == observed_answers[0] for v in observed_answers):
        checks["dns"]["resolver_consistency"] = "same"
    elif len(observed_answers) == 2:
        checks["dns"]["resolver_consistency"] = "different; CDN geography and DNS rotation can explain differences"
    elif observed_answers:
        checks["dns"]["resolver_consistency"] = "partial; only one public resolver replied"
    else:
        checks["dns"]["resolver_consistency"] = "unknown; public resolver queries failed"

    supported = []
    cert_bytes = None
    for version, label in ((ssl.TLSVersion.TLSv1, "TLSv1"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
                           (ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (ssl.TLSVersion.TLSv1_3, "TLSv1.3")):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                try:
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
            with socket.create_connection((resolved_ips[0], 443), timeout=CONNECT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as conn:
                    supported.append(conn.version() or label)
                    cert_bytes = cert_bytes or conn.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError, ValueError):
            continue
    checks["tls"]["supported_protocols"] = sorted(set(supported))
    peer_chain = []
    try:
        peer_chain = _get_peer_chain(resolved_ips[0], host)
        checks["tls"]["certificate_chain"] = [{
            "subject": item.subject.rfc4514_string(), "issuer": item.issuer.rfc4514_string(),
            "sha256_fingerprint": item.fingerprint(hashes.SHA256()).hex()
        } for item in peer_chain]
        if peer_chain:
            cert_bytes = cert_bytes or peer_chain[0].public_bytes(serialization.Encoding.DER)
    except (OSError, SSL.Error, ValueError) as exc:
        checks["tls"]["chain_capture_status"] = f"unknown: {type(exc).__name__}"
    checks["tls"]["chain_validated"] = False
    checks["tls"]["revocation"] = {"status": "unknown", "reason": "Certificate revocation status was not established"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((resolved_ips[0], 443), timeout=CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                checks["tls"]["chain_validated"] = True
                checks["tls"]["negotiated_protocol"] = conn.version()
                cert_bytes = conn.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        checks["tls"]["verification_error"] = str(exc)[:300]
    except (OSError, ssl.SSLError) as exc:
        checks["tls"]["status"] = f"unknown: {type(exc).__name__}"
    if not checks["tls"]["chain_validated"] and peer_chain:
        fallback_valid, fallback_error, fallback_chain = _validate_chain_with_system_roots(peer_chain)
        checks["tls"]["system_root_fallback"] = {
            "attempted": True, "validated": fallback_valid,
            "error": fallback_error,
        }
        if fallback_valid:
            checks["tls"]["chain_validated"] = True
            peer_chain = fallback_chain
            checks["tls"]["system_root_fallback"]["chain_subjects_used"] = [cert.subject.rfc4514_string() for cert in fallback_chain]
            checks["tls"].pop("verification_error", None)
        elif fallback_error and not checks["tls"].get("verification_error"):
            checks["tls"]["verification_error"] = fallback_error
    if cert_bytes:
        cert = x509.load_der_x509_certificate(cert_bytes)
        if cert is not None:
            if checks["tls"]["chain_validated"] and peer_chain and peer_chain[0].fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256()):
                try:
                    revocation = _check_revocation(cert, peer_chain)
                except Exception:
                    revocation = {"status": "unknown", "reason": "OCSP/CRL response could not be validated"}
            else:
                revocation = {"status": "unknown", "reason": "Trusted issuer chain and matching peer certificate were not confirmed"}
            checks["tls"]["revocation"] = revocation
            if revocation.get("status") == "revoked":
                findings.append(_finding("tls.certificate_revoked", "TLS certificate is confirmed revoked", "CRITICAL", f"Validated {revocation.get('source')} response; serial {cert.serial_number}"))
            now = datetime.now(timezone.utc)
            not_after = cert.not_valid_after_utc
            days_left = (not_after - now).days
            checks["tls"].update({"issuer": cert.issuer.rfc4514_string(), "not_after": not_after.isoformat(), "days_until_expiry": days_left})
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                names = san.get_values_for_type(x509.DNSName)
                checks["tls"]["sans"] = names
                try:
                    target_ip = ipaddress.ip_address(host)
                except ValueError:
                    target_ip = None
                if target_ip:
                    ip_sans = san.get_values_for_type(x509.IPAddress)
                    checks["tls"]["ip_sans"] = [str(value) for value in ip_sans]
                    matches = target_ip in ip_sans
                else:
                    matches = False
                    for name in names:
                        if name.startswith("*."):
                            if host.endswith(name[1:]):
                                matches = True
                                break
                        elif name == host:
                            matches = True
                            break
                if not matches:
                    reported_sans = checks["tls"].get("sans", []) + checks["tls"].get("ip_sans", [])
                    findings.append(_finding("tls.hostname_mismatch", "Certificate hostname does not match target", "HIGH", f"Target {host}; certificate SANs: {', '.join(reported_sans[:8])}"))
            except x509.ExtensionNotFound:
                findings.append(_finding("tls.hostname_mismatch", "Certificate has no subject alternative names", "HIGH", "No SAN extension found"))
            if days_left < 0:
                findings.append(_finding("tls.certificate_expired", "TLS certificate is expired", "CRITICAL", f"Certificate expired at {not_after.isoformat()}"))
            elif days_left <= 30:
                findings.append(_finding("tls.certificate_expiring", "TLS certificate expires within 30 days", "MEDIUM", f"Certificate expires in {days_left} days"))
            verification_error = checks["tls"].get("verification_error", "")
            expiry_error = "expired" in verification_error.lower() or "not yet valid" in verification_error.lower()
            self_issued = cert.issuer == cert.subject
            if not checks["tls"]["chain_validated"] and verification_error and not expiry_error and not self_issued:
                findings.append(_finding("tls.certificate_untrusted", "TLS certificate chain validation failed", "HIGH", verification_error))
            if cert.issuer == cert.subject and not checks["tls"]["chain_validated"]:
                findings.append(_finding("tls.self_signed", "TLS certificate may be self-signed", "HIGH", "Leaf certificate issuer equals its subject and the default trust store rejected it", "medium"))
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
                findings.append(_finding("tls.weak_rsa_key", "RSA public key is smaller than 2048 bits", "HIGH", f"RSA key size: {pub.key_size} bits"))
            if cert.signature_hash_algorithm and cert.signature_hash_algorithm.name.lower() == "sha1":
                findings.append(_finding("tls.sha1_signature", "Certificate uses SHA-1 signature", "HIGH", "Certificate signature hash: SHA-1"))
            try:
                policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
                policy_oids = [str(policy.policy_identifier.dotted_string) for policy in policies]
            except x509.ExtensionNotFound:
                policy_oids = []
            known_ev_oids = {"2.23.140.1.1", "1.3.6.1.4.1.4146.1.1", "1.3.6.1.4.1.34697.2.1", "1.3.6.1.4.1.34697.2.2", "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.6334.1.100.1", "2.16.756.1.89.1.2.1.1", "1.3.6.1.4.1.23223.1.1.1", "2.16.840.1.114412.2.1", "1.3.6.1.4.1.7879.13.24.1", "1.3.6.1.4.1.4788.2.202.1"}
            checks["tls"]["certificate_policy_oids"] = policy_oids
            checks["tls"]["certificate_type_signal"] = "EV policy OID observed; validation process not verified" if known_ev_oids.intersection(policy_oids) else ("Organization field present; DV/OV/EV cannot be confirmed" if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else "No organization field; DV/OV/EV cannot be confirmed")
    if any(p in {"TLSv1", "TLSv1.1"} for p in supported):
        findings.append(_finding("tls.legacy_protocol", "Legacy TLS protocol is enabled", "HIGH", ", ".join(supported)))
    weak_ciphers = []
    for cipher_name in ("RC4-SHA", "DES-CBC3-SHA", "NULL-SHA", "EXP-RC4-MD5"):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(f"{cipher_name}:@SECLEVEL=0")
            with socket.create_connection((resolved_ips[0], 443), timeout=CONNECT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as conn:
                    negotiated = conn.cipher()
                    if negotiated:
                        weak_ciphers.append(negotiated[0])
        except (OSError, ssl.SSLError, ValueError):
            continue
    if weak_ciphers:
        findings.append(_finding("tls.weak_cipher", "Weak TLS cipher suite was negotiated", "HIGH", ", ".join(sorted(set(weak_ciphers)))))

    response = None
    signal_parser = None
    response_headers = {}
    html_page_observed = False
    try:
        parts = urlsplit(requested_url)
        request_path = parts.path or "/"
        if parts.query:
            request_path += "?" + parts.query
        if parts.scheme == "https":
            class PinnedHTTPSConnection(http.client.HTTPSConnection):
                def connect(self):
                    raw = socket.create_connection((resolved_ips[0], self.port), self.timeout)
                    self.sock = self._context.wrap_socket(raw, server_hostname=host)
            conn = PinnedHTTPSConnection(host, 443, timeout=CONNECT_TIMEOUT, context=ssl.create_default_context())
        else:
            class PinnedHTTPConnection(http.client.HTTPConnection):
                def connect(self):
                    self.sock = socket.create_connection((resolved_ips[0], self.port), self.timeout)
            conn = PinnedHTTPConnection(host, 80, timeout=CONNECT_TIMEOUT)
        conn.request("GET", request_path, headers={"User-Agent": "WebsiteSecurityAnalyzer/1.0", "DNT": "1", "Connection": "close"})
        response = conn.getresponse()
        body_sample = response.read(512_000)
        class ResponseView:
            status_code = response.status
            headers = response.headers
            url = requested_url
            body = body_sample
        response = ResponseView()
        conn.close()
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        checks["http"]["status"] = f"unknown: {type(exc).__name__}"
    if response is not None:
        headers = {k.lower(): v for k, v in response.headers.items()}
        response_headers = headers
        safe_header_names = {"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "content-type", "server", "location"}
        safe_headers = {k: v for k, v in response.headers.items() if k.lower() in safe_header_names}
        checks["http"].update({"status_code": response.status_code, "url": str(response.url), "headers": safe_headers})
        if 200 <= response.status_code < 300 and requested_url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(_finding("http.no_hsts", "HSTS header is absent", "MEDIUM", "HTTPS response did not include Strict-Transport-Security"))
        is_html = "text/html" in headers.get("content-type", "").lower() or b"<html" in response.body[:4096].lower()
        html_page_observed = 200 <= response.status_code < 300 and is_html
        if 200 <= response.status_code < 300 and is_html and "content-security-policy" not in headers:
            findings.append(_finding("http.no_csp", "Content Security Policy header is absent", "MEDIUM", "Response did not include Content-Security-Policy"))
        if 200 <= response.status_code < 300 and is_html and "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            findings.append(_finding("http.no_frame_protection", "Clickjacking frame protection is absent", "MEDIUM", "No X-Frame-Options or CSP frame-ancestors directive"))
        if 200 <= response.status_code < 300 and headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(_finding("http.no_nosniff", "MIME sniffing protection is absent", "LOW", "X-Content-Type-Options is not nosniff"))
        if 200 <= response.status_code < 300 and "referrer-policy" not in headers:
            findings.append(_finding("http.no_referrer_policy", "Referrer-Policy header is absent", "LOW", "Successful HTTP response did not include Referrer-Policy"))
        if 200 <= response.status_code < 300 and "permissions-policy" not in headers:
            findings.append(_finding("http.no_permissions_policy", "Permissions-Policy header is absent", "LOW", "Successful HTTP response did not include Permissions-Policy", "medium"))
        cookies = response.headers.get_all("Set-Cookie") or []
        weak = []
        missing_samesite = []
        cookie_observations = []
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            attrs = [part.strip() for part in cookie.split(";")[1:]]
            attr_names = {part.split("=", 1)[0].lower() for part in attrs}
            cookie_observations.append({"name": name, "secure": "secure" in attr_names,
                                        "httponly": "httponly" in attr_names,
                                        "samesite": next((part.split("=", 1)[1] for part in attrs if part.lower().startswith("samesite=")), None)})
            session_like = bool(re.search(r"session|sessid|sid|auth|token", name, re.I)) and not bool(re.search(r"csrf|xsrf", name, re.I))
            if session_like and ("secure" not in attr_names or "httponly" not in attr_names):
                weak.append(name)
            if session_like and not re.search(r"(?:^|;)\s*samesite\s*=", cookie, re.I):
                missing_samesite.append(name)
        checks["http"]["cookies"] = cookie_observations
        if weak:
            findings.append(_finding("http.cookie_insecure", "A session-like cookie lacks Secure or HttpOnly", "MEDIUM", "; ".join(weak[:5])))
        if missing_samesite:
            findings.append(_finding("http.cookie_samesite", "A session-like cookie has no SameSite attribute", "LOW", "; ".join(missing_samesite[:5]), "medium"))
        if 200 <= response.status_code < 300 and is_html and requested_url.startswith("https://"):
            parser = _ActiveContentParser()
            try:
                parser.feed(response.body.decode("utf-8", errors="replace"))
            except Exception:
                pass
            if parser.http_resources:
                findings.append(_finding("http.mixed_content", "Active page content uses insecure HTTP URLs", "MEDIUM", "; ".join(parser.http_resources[:5]), "medium"))
        if 200 <= response.status_code < 300 and is_html:
            signal_parser = _ComplianceSignalParser()
            try:
                signal_parser.feed(response.body.decode("utf-8", errors="replace"))
            except Exception:
                pass
    server_banner = response_headers.get("server", "")
    vulnerable_software = _server_software_from_banner(server_banner) if server_banner else []
    for software in vulnerable_software:
        for cve in software["cves"]:
            if cve.get("severity") == "CRITICAL" or float(cve.get("cvss_score") or 0) >= 9.0:
                cve_id = cve.get("cve_id", "CVE")
                findings.append({
                    **_finding(
                        f"cve.{cve_id.lower()}",
                        f"{cve_id} may affect {software['product']} {software['version']}",
                        "CRITICAL",
                        f"Server header disclosed {server_banner}; NVD returned a matching CPE version ({software['cpe']}).",
                        "medium",
                    ),
                    "cvss_score": cve.get("cvss_score", 0),
                    "description": cve.get("description", "NVD lists this CVE for the matching CPE version."),
                    "recommendation": "Confirm the installed build and vendor advisory, then upgrade to a fixed supported release or apply the vendor security update. Verify the fix with a follow-up assessment.",
                    "references": [cve.get("nvd_url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                })
    if requested_url.startswith("https://"):
        http_url = "http://" + requested_url[len("https://"):]
        try:
            class PinnedRedirectConnection(http.client.HTTPConnection):
                def connect(self):
                    self.sock = socket.create_connection((resolved_ips[0], 80), self.timeout)
            redirect_conn = PinnedRedirectConnection(host, 80, timeout=CONNECT_TIMEOUT)
            http_parts = urlsplit(http_url)
            http_path = http_parts.path or "/"
            if http_parts.query:
                http_path += "?" + http_parts.query
            redirect_conn.request("GET", http_path, headers={"User-Agent": "WebsiteSecurityAnalyzer/1.0", "Connection": "close"})
            redirect = redirect_conn.getresponse()
            checks["http"]["http_status"] = redirect.status
            loc = redirect.getheader("Location", "")
            loc_parts = urlsplit(loc)
            safe_location = loc_parts._replace(query="[redacted]" if loc_parts.query else "").geturl()
            checks["http"]["http_location"] = safe_location
            redirect_conn.close()
            if redirect.status not in (301, 302, 303, 307, 308) or not loc.lower().startswith("https://"):
                findings.append(_finding("http.no_https_redirect", "HTTP endpoint does not redirect to HTTPS", "MEDIUM", f"HTTP status {redirect.status}; Location: {safe_location or '(absent)'}"))
        except (OSError, http.client.HTTPException):
            checks["http"]["http_status"] = "unknown"

    # Publicly observable indicators only; none of these establish certification or compliance.
    signals = []
    text = " ".join(signal_parser.text_parts).lower() if signal_parser else ""
    attribute_text = " ".join(signal_parser.attribute_text).lower() if signal_parser else ""
    searchable_page = f"{text} {attribute_text}"
    links = signal_parser.links if signal_parser else []
    privacy_links = [(href, label) for href, label in links if re.search(r"privacy|data-protection", href + " " + label, re.I)]
    terms_links = [(href, label) for href, label in links if re.search(r"terms|conditions|legal", href + " " + label, re.I)]
    cmp_matches = [src for src in (signal_parser.script_sources if signal_parser else []) if re.search(r"onetrust|cookiebot|usercentrics|consentmanager|didomi", src, re.I)]
    page_status = lambda detected: ("detected" if detected else "missing") if html_page_observed else "unknown"

    payment_evidence = (signal_parser.payment_fields + signal_parser.payment_actions)[:3] if signal_parser else []
    payment_terms = [word for word in ("credit card", "cvv", "stripe", "paypal", "payment") if word in searchable_page]
    payment_detail = "; ".join(payment_evidence or payment_terms) or ("No payment form or payment keyword observed in sampled content" if html_page_observed else "HTML page unavailable")
    signals.append(_signal("pci_payment_indicators", "PCI DSS payment indicators", "E-Commerce Security", page_status(bool(payment_evidence or payment_terms)), payment_detail))

    consent_terms = [word for word in ("cookie consent", "cookie", "gdpr", "privacy policy", "cookie preferences", "manage cookies") if word in searchable_page]
    consent_evidence = cmp_matches[:2] or [f"{href} ({label or 'privacy link'})" for href, label in privacy_links[:2]] or consent_terms
    signals.append(_signal("privacy_consent", "GDPR / cookie-consent indicators", "Data Privacy", page_status(bool(consent_evidence)), "; ".join(consent_evidence) or ("No visible CMP, consent text, or privacy link observed" if html_page_observed else "HTML page unavailable")))

    iso_soc = [term for term in ("iso 27001", "iso/iec 27001", "soc 2", "soc2", "aicpa") if term in searchable_page]
    signals.append(_signal("iso_soc_claims", "ISO 27001 / SOC 2 references", "Trust Signals", page_status(bool(iso_soc)), ", ".join(iso_soc) or ("No ISO 27001 or SOC 2 references observed" if html_page_observed else "HTML page unavailable")))
    vendors = sorted(signal_parser.trust_candidates) if signal_parser else []
    signals.append(_signal("trust_seals", "Trust seal vendor references", "Trust Signals", page_status(bool(vendors)), ", ".join(vendors) or ("No known trust seal vendor references observed" if html_page_observed else "HTML page unavailable")))
    health_terms = [term for term in ("hipaa", "health insurance", "medical") if term in searchable_page]
    signals.append(_signal("health_privacy_claims", "Health privacy references", "Trust Signals", page_status(bool(health_terms)), ", ".join(health_terms) or ("No HIPAA or health-related references observed" if html_page_observed else "HTML page unavailable")))

    known_ev_oids = {"2.23.140.1.1", "1.3.6.1.4.1.4146.1.1", "1.3.6.1.4.1.34697.2.1", "1.3.6.1.4.1.34697.2.2", "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.6334.1.100.1", "2.16.756.1.89.1.2.1.1", "1.3.6.1.4.1.23223.1.1.1", "2.16.840.1.114412.2.1", "1.3.6.1.4.1.7879.13.24.1", "1.3.6.1.4.1.4788.2.202.1"}
    policy_oids = checks["tls"].get("certificate_policy_oids", [])
    ev_observed = bool(known_ev_oids.intersection(policy_oids))
    signals.append(_signal("ev_certificate_oid", "EV certificate policy OID", "Transport Security", "detected" if ev_observed else "missing" if cert_bytes else "unknown", f"Observed policy OIDs: {', '.join(policy_oids)}" if ev_observed else "No recognized EV policy OID observed" if cert_bytes else "Certificate policy could not be inspected"))

    hsts = response_headers.get("strict-transport-security", "")
    age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)
    hsts_ready = bool(age and int(age.group(1)) >= 31_536_000 and re.search(r"(?:^|;)\s*preload(?:;|$)", hsts, re.I))
    signals.append(_signal("hsts_preload", "HSTS preload signal", "Transport Security", ("detected" if hsts_ready else "missing") if response is not None else "unknown", hsts or ("HSTS missing or lacks one-year max-age and preload" if response is not None else "HTTP response headers unavailable")))

    spf_values, dmarc_values = checks["dns"].get("spf"), checks["dns"].get("dmarc")
    mail_known = isinstance(spf_values, list) and isinstance(dmarc_values, list)
    mail_present = bool(spf_values) and bool(dmarc_values)
    mail_evidence = f"SPF: {'; '.join(spf_values) if spf_values else 'not observed'} · DMARC: {'; '.join(dmarc_values) if dmarc_values else 'not observed'}" if mail_known else "DNS record lookup inconclusive"
    signals.append(_signal("spf_dmarc", "SPF and DMARC DNS records", "DNS & Email", ("detected" if mail_present else "missing") if mail_known else "unknown", mail_evidence))

    accessible = bool(signal_parser and signal_parser.html_lang and signal_parser.aria_count)
    accessibility_detail = f"html lang={signal_parser.html_lang or 'missing'}; aria attributes={signal_parser.aria_count}" if signal_parser and html_page_observed else "HTML page unavailable"
    signals.append(_signal("accessibility_markup", "Accessibility markup indicators", "Accessibility", page_status(accessible), accessibility_detail))
    policy_links = privacy_links + terms_links
    policy_detail = "; ".join(f"{href} ({label or 'policy link'})" for href, label in policy_links[:4]) or ("No terms or privacy links observed" if html_page_observed else "HTML page unavailable")
    signals.append(_signal("terms_privacy_links", "Terms and privacy links", "Site Transparency", page_status(bool(policy_links)), policy_detail))

    phone = re.search(r"(?:\+?\d[\d ().-]{7,}\d)", text)
    contact_found = bool(signal_parser and signal_parser.has_address) or "contact us" in searchable_page or bool(phone)
    contact_detail = "<address> element observed" if signal_parser and signal_parser.has_address else "Contact Us text observed" if "contact us" in searchable_page else f"Phone-like text observed: {phone.group(0)}" if phone else ("No address, Contact Us text, or phone-like value observed" if html_page_observed else "HTML page unavailable")
    signals.append(_signal("contact_information", "Contact information indicator", "Site Transparency", page_status(contact_found), contact_detail))

    resource_scheme = "https" if requested_url.startswith("https://") else "http"
    for path, signal_id, name, category in (("/.well-known/security.txt", "security_txt", "security.txt", "Security Operations"), ("/ads.txt", "ads_txt", "ads.txt", "Advertising")):
        try:
            resource_status, _, resource_body = _fetch_site_path(host, resolved_ips[0], path, resource_scheme)
            exists = resource_status == 200 and bool(resource_body.strip())
            state = "detected" if exists else "missing" if resource_status in (404, 410) else "unknown"
            evidence = f"https://{host}{path} returned HTTP {resource_status}" + (f" · {resource_body[:100].decode('utf-8', errors='replace').strip()}" if exists else "")
        except Exception as exc:
            state, evidence = "unknown", f"Same-origin resource could not be fetched ({type(exc).__name__})"
        signals.append(_signal(signal_id, name, category, state, evidence))

    tk_header = response_headers.get("tk")
    signals.append(_signal("dnt_tracking_header", "DNT / tracking-status response", "Data Privacy", "detected" if tk_header else "unknown", f"Tk: {tk_header}" if tk_header else "No Tk response header; DNT policy cannot be inferred"))
    protocols = checks["tls"].get("supported_protocols", [])
    tls_state = "detected" if "TLSv1.3" in protocols and not any(item in {"TLSv1", "TLSv1.1"} for item in protocols) else "missing" if protocols else "unknown"
    signals.append(_signal("modern_tls_profile", "Modern TLS profile indicator", "Transport Security", tls_state, f"TLS probe results: {', '.join(protocols)}" if protocols else "TLS protocol support could not be confirmed"))
    checks["compliance_signals"] = signals

    has_http_response = isinstance(checks["http"].get("status_code"), int) or isinstance(checks["http"].get("http_status"), int)
    if not cert_bytes and not supported and not has_http_response:
        raise ValueError("The hostname resolved, but no TLS certificate or HTTP response was received. The target may be unreachable or may not serve web traffic on ports 80/443.")

    unique: dict[str, dict] = {}
    for finding in findings:
        unique.setdefault(finding["check_id"], finding)
    findings = list(unique.values())
    score_breakdown = [{"check_id": f["check_id"], "severity": f["severity"],
                        "confidence": f["confidence"],
                        "deduction": SEVERITY_WEIGHTS[f["severity"]] if f["confidence"] == "high" else 0}
                       for f in findings]
    deductions = min(100, sum(item["deduction"] for item in score_breakdown))
    layer_coverage = {
        "dns": "observed" if bool(checks["dns"].get("addresses")) else "unknown",
        "tls": "observed" if bool(cert_bytes or supported) else "unknown",
        "http": "observed" if isinstance(checks["http"].get("status_code"), int) or isinstance(checks["http"].get("http_status"), int) else "unknown",
    }
    # Score the measured posture when DNS and the TLS endpoint were observed.
    # Missing controls (CAA, HSTS, etc.) are findings and deductions, not missing coverage.
    score_available = layer_coverage["dns"] == "observed" and layer_coverage["tls"] == "observed"
    score = max(0, 100 - deductions) if score_available else None
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F") if score is not None else "INCOMPLETE"
    return {"target": host, "checks": checks, "compliance_signals": signals,
            "vulnerable_software": vulnerable_software, "findings": findings,
            "score": score, "grade": grade, "score_breakdown": score_breakdown,
            "layer_coverage": layer_coverage,
            "scoring_method": {"formula": "100 minus severity deductions, floor 0",
                               "weights": SEVERITY_WEIGHTS, "confidence_rule": "only high-confidence observations affect score",
                               "deductions": deductions, "complete": score_available,
                               "score_eligibility": "DNS resolution and TLS certificate/protocol observation"},
            "data_source": "Live DNS queries and direct TLS/HTTP observations",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "scan_status": "completed"}
