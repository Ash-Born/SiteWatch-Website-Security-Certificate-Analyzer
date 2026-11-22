from typing import Dict, Any
from datetime import datetime
from html import escape

class HTMLReportGenerator:
    """Generates a comprehensive HTML report including HTTP Security Assessment."""

    @staticmethod
    def generate_report(scan_data: Dict[str, Any]) -> str:
        details = scan_data.get("details") or {}
        if details:
            findings_html = "".join(
                "<article><h3>{} <small>{}</small></h3><p><b>Evidence</b>: {}</p><p><b>Mitigation</b>: {}</p></article>".format(
                    escape(str(f.get("title", "Finding"))), escape(str(f.get("severity", "INFO"))),
                    escape(str(f.get("evidence", ""))), escape(str(f.get("recommendation", ""))))
                for f in details.get("findings", [])
            ) or "<p>No scored findings were observed. Incomplete checks are reported as unknown.</p>"
            technical_json = escape(__import__("json").dumps(details.get("checks", {}), indent=2, ensure_ascii=False))
            raw_score = details.get("score")
            score_display = f"{escape(str(raw_score))}/100" if isinstance(raw_score, (int, float)) else "Not scored (incomplete checks)"
            return """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Website assessment: {target}</title>
<style>body{{font:15px system-ui,sans-serif;background:#f3f6f4;color:#17221b;margin:0;padding:32px}}main{{max-width:900px;margin:auto;background:white;padding:32px;border:1px solid #d9e3dc;border-radius:12px}}h1{{font-size:26px}}.score{{font-size:34px;color:#197144}}article{{border-top:1px solid #dce5df;padding:14px 0}}small{{color:#9a4c3e}}code,pre{{font-family:ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}}pre{{background:#f2f6f3;padding:15px;border-radius:7px}}p{{line-height:1.55}}</style></head><body><main>
<h1>Website security assessment</h1><p><b>Target:</b> {target}</p><p>Observed: {observed}</p><p>Source: {source}</p><div class="score">{score} · Grade {grade}</div><h2>Findings and mitigation plans</h2>{findings}<h2>Technical observations</h2><pre>{checks}</pre></main></body></html>""".format(
                target=escape(str(details.get("target", scan_data.get("target", "")))),
                observed=escape(str(details.get("observed_at", ""))), source=escape(str(details.get("data_source", ""))),
                score=score_display, grade=escape(str(details.get("grade", "—"))), findings=findings_html, checks=technical_json)
        target = scan_data.get("target", "Unknown")
        ports_scanned = scan_data.get("ports_scanned", 0)
        risk_summary = scan_data.get("risk_summary", {})
        results = scan_data.get("results", [])
        http_eval = scan_data.get("http_assessment") or {}
        ssl_eval = scan_data.get("ssl_assessment") or {}
        findings = scan_data.get("findings") or []
        
        max_cvss = risk_summary.get("max_cvss_score", 0.0)
        weighted_risk = risk_summary.get("weighted_risk_score", 0.0)
        host_severity = risk_summary.get("host_severity", "UNKNOWN")

        server_name = http_eval.get("server", "Unknown / Not Detected")
        headers = http_eval.get("headers") or {}
        robots_info = http_eval.get("robots_txt") or {"status": "Missing"}
        robots_status = robots_info.get("status", "Missing")
        dir_info = http_eval.get("directory_listing") or {"status": "Disabled"}
        dir_status = dir_info.get("status", "Disabled")

        # SSL/TLS info
        ssl_enabled = ssl_eval.get("ssl_enabled", False)
        tls_ver = ssl_eval.get("tls_version", "N/A")
        cert_info = ssl_eval.get("certificate") or {}
        cert_subject = cert_info.get("subject", "N/A")
        cert_issuer = cert_info.get("issuer", "N/A")
        cert_expires = cert_info.get("not_after", "N/A")
        days_left = cert_info.get("days_until_expiration", 0)
        is_self_signed = cert_info.get("is_self_signed", False)
        validity_status = cert_info.get("validity_status", "N/A")
        cipher_info = ssl_eval.get("cipher") or {}
        cipher_name = cipher_info.get("name", "N/A")
        cipher_bits = cipher_info.get("secret_bits", 0)

        # Format header checks
        hsts_mark = "✓ HSTS" if headers.get("Strict-Transport-Security") else "✗ HSTS"
        csp_mark = "✓ CSP" if headers.get("Content-Security-Policy") else "✗ CSP"
        xfo_mark = "✓ X-Frame-Options" if headers.get("X-Frame-Options") else "✗ X-Frame-Options"
        xcto_mark = "✓ X-Content-Type-Options" if headers.get("X-Content-Type-Options") else "✗ X-Content-Type-Options"
        rp_mark = "✓ Referrer-Policy" if headers.get("Referrer-Policy") else "✗ Referrer-Policy"

        # Start HTML template
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        h1 {{ color: #0f172a; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; margin-top: 0; }}
        h2 {{ color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #e2e8f0; padding: 10px; text-align: left; font-size: 14px; }}
        th {{ background-color: #f1f5f9; color: #334155; }}
        .vuln-list {{ margin: 0; padding-left: 20px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge-pass {{ background-color: #dcfce7; color: #15803d; }}
        .badge-fail {{ background-color: #fee2e2; color: #b91c1c; }}
        .badge-info {{ background-color: #e0f2fe; color: #0369a1; }}
        .http-card {{ background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 15px; margin-bottom: 20px; }}
        .http-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 10px; }}
        .header-item {{ font-size: 14px; padding: 4px 0; }}
        .pass {{ color: #16a34a; font-weight: bold; }}
        .fail {{ color: #dc2626; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <h2>Summary</h2>
        <ul>
            <li><strong>Ports Scanned:</strong> {ports_scanned}</li>
            <li><strong>Max CVSS Score:</strong> {max_cvss}</li>
            <li><strong>Weighted Risk Score:</strong> {weighted_risk:.1f}</li>
            <li><strong>Host Risk Severity:</strong> {host_severity}</li>
            <li><strong>Total Findings:</strong> {len(findings)}</li>
        </ul>

        <h2>HTTP Security Assessment</h2>
        <div class="http-card">
            <div class="http-grid">
                <div>
                    <strong>Server:</strong><br>
                    <span>{server_name}</span>
                </div>
                <div>
                    <strong>robots.txt:</strong><br>
                    <span class="badge { 'badge-pass' if robots_status in ('Found', 'Accessible') else 'badge-info' }">{robots_status}</span>
                </div>
                <div>
                    <strong>Directory Listing:</strong><br>
                    <span class="badge { 'badge-pass' if dir_status == 'Disabled' else 'badge-fail' }">{dir_status}</span>
                </div>
            </div>

            <div style="margin-top: 15px;">
                <strong>Headers:</strong>
                <div style="display: flex; gap: 15px; flex-wrap: wrap; margin-top: 8px;">
                    <span class="header-item { 'pass' if headers.get('Strict-Transport-Security') else 'fail' }">{hsts_mark}</span>
                    <span class="header-item { 'pass' if headers.get('Content-Security-Policy') else 'fail' }">{csp_mark}</span>
                    <span class="header-item { 'pass' if headers.get('X-Frame-Options') else 'fail' }">{xfo_mark}</span>
                    <span class="header-item { 'pass' if headers.get('X-Content-Type-Options') else 'fail' }">{xcto_mark}</span>
                    <span class="header-item { 'pass' if headers.get('Referrer-Policy') else 'fail' }">{rp_mark}</span>
                </div>
            </div>
        </div>

        <h2>SSL/TLS Certificate & Cipher Assessment</h2>
        <div class="http-card">
            <div class="http-grid">
                <div>
                    <strong>TLS Protocol Version:</strong><br>
                    <span>{tls_ver}</span>
                </div>
                <div>
                    <strong>Certificate Validity:</strong><br>
                    <span class="badge { 'badge-pass' if cert_info.get('is_valid') else 'badge-fail' }">{validity_status}</span>
                </div>
                <div>
                    <strong>Self-Signed Status:</strong><br>
                    <span class="badge { 'badge-fail' if is_self_signed else 'badge-pass' }">{ 'Yes (Self-Signed)' if is_self_signed else 'No (CA Signed)' }</span>
                </div>
            </div>
            <div style="margin-top: 12px; font-size: 13px; color: #334155;">
                <p style="margin: 4px 0;"><strong>Certificate Subject:</strong> {cert_subject}</p>
                <p style="margin: 4px 0;"><strong>Certificate Issuer:</strong> {cert_issuer}</p>
                <p style="margin: 4px 0;"><strong>Certificate Expiration:</strong> {cert_expires} ({days_left} days remaining)</p>
                <p style="margin: 4px 0;"><strong>Cipher Suite:</strong> {cipher_name} ({cipher_bits}-bit encryption)</p>
            </div>
        </div>


        <h2>Scan Results & Services</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Service</th>
                    <th>Software & Version</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for result in results:
            port = result.get("port", "N/A")
            status = result.get("status", "N/A")
            service = result.get("service", "N/A")
            software = result.get("software")
            version = result.get("version")
            
            soft_ver = f"{software} {version}" if software and version and software != "unknown" else "Unknown"
            
            html += f"""
                <tr>
                    <td><strong>{port}</strong></td>
                    <td>{status.upper()}</td>
                    <td>{service}</td>
                    <td>{soft_ver}</td>
                </tr>
            """
            
            port_findings = result.get("findings") or []
            if port_findings:
                html += f"""
                <tr>
                    <td colspan="4">
                        <strong>Discovered Security Findings:</strong>
                        <ul class="vuln-list">
                """
                for f in port_findings:
                    f_type = f.get("type", "Finding")
                    f_title = f.get("title", f_type)
                    severity = f.get("severity", "UNKNOWN")
                    rec = f.get("recommendation", "")
                    
                    html += f"""
                            <li style="margin-bottom: 6px;">
                                <strong>[{f_type}] {f_title}</strong> - Severity: <span class="badge { 'badge-fail' if severity.upper() in ('HIGH', 'CRITICAL', 'MEDIUM') else 'badge-info' }">{severity}</span><br>
                                <span style="font-size: 13px; color: #475569;">Recommendation: {rec}</span>
                            </li>
                    """
                html += """
                        </ul>
                    </td>
                </tr>
                """

        if not results:
            html += """
                <tr>
                    <td colspan="4">No results found or target unreachable.</td>
                </tr>
            """

        html += """
            </tbody>
        </table>
        <hr>
        <p style="font-size: 12px; color: #64748b; text-align: center;">Generated by Vulnerability Scanner</p>
    </div>
</body>
</html>
"""
        return html
