import io
from html import escape
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Canvas that performs a two-pass render to draw 'Page X of Y' page numbers and headers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count):
        # Cover page (page 1) has special sidebar accent but no header/footer
        if self._pageNumber == 1:
            self.saveState()
            # Draw decorative side accent on cover page
            self.setFillColor(colors.HexColor("#0f172a")) # Dark slate blue
            self.rect(0, 0, 18, 792, fill=True, stroke=False)
            self.setFillColor(colors.HexColor("#3b82f6")) # Vivid blue accent
            self.rect(18, 0, 6, 792, fill=True, stroke=False)
            self.restoreState()
            return
            
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b")) # slate text
        
        # Header (Top margin is 54, so y=756)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 756, 576, 756)
        self.drawString(36, 762, "Network Vulnerability Scan Report")
        
        # Footer (Bottom margin is 54, so y=45)
        self.line(36, 45, 576, 45)
        self.drawString(36, 32, "CONFIDENTIAL - Internal Security Review Only")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 32, page_text)
        self.restoreState()


class PDFReportGenerator:
    """Generates a professional, print-ready PDF report for scan findings."""

    @staticmethod
    def get_severity_colors(severity: str):
        sev = severity.upper()
        if sev == "CRITICAL":
            return colors.HexColor("#ef4444"), colors.white
        elif sev == "HIGH":
            return colors.HexColor("#f97316"), colors.white
        elif sev == "MEDIUM":
            return colors.HexColor("#eab308"), colors.HexColor("#0f172a")
        elif sev == "LOW":
            return colors.HexColor("#3b82f6"), colors.white
        else:
            return colors.HexColor("#10b981"), colors.white

    @staticmethod
    def draw_line(color, thickness=1, space_after=10):
        t = Table([['']], colWidths=[540], rowHeights=[thickness])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), color),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ]))
        return KeepTogether([t, Spacer(1, space_after)])

    @classmethod
    def _generate_website_report(cls, scan_data: Dict[str, Any], report: Dict[str, Any]) -> bytes:
        """Render the exact live website-analyzer payload instead of legacy port-scan defaults."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=42, rightMargin=42, topMargin=48, bottomMargin=48)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("WebsiteTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=colors.HexColor("#12345a"), alignment=0, spaceAfter=8)
        heading_style = ParagraphStyle("WebsiteHeading", parent=styles["Heading2"], fontSize=13, leading=17, textColor=colors.HexColor("#174b7a"), spaceBefore=14, spaceAfter=7, keepWithNext=True)
        body_style = ParagraphStyle("WebsiteBody", parent=styles["BodyText"], fontSize=9, leading=13, textColor=colors.HexColor("#334155"), spaceAfter=5, wordWrap="CJK")
        small_style = ParagraphStyle("WebsiteSmall", parent=body_style, fontSize=8, leading=11)
        label_style = ParagraphStyle("WebsiteLabel", parent=body_style, fontName="Helvetica-Bold", fontSize=8.5)

        def safe(value: Any, empty: str = "Not observed") -> str:
            if value is None or value == "":
                return empty
            return escape(str(value)).replace("\n", "<br/>")

        def data_table(rows: list[list[Any]], widths: list[int] | None = None) -> Table:
            converted = [[Paragraph(safe(cell), small_style) for cell in row] for row in rows]
            table = Table(converted, colWidths=widths or [165, 363], repeatRows=0, hAlign="LEFT")
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), .45, colors.HexColor("#dbe4ee")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            return table

        checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
        dns = checks.get("dns") if isinstance(checks.get("dns"), dict) else {}
        tls = checks.get("tls") if isinstance(checks.get("tls"), dict) else {}
        http = checks.get("http") if isinstance(checks.get("http"), dict) else {}
        headers = http.get("headers") if isinstance(http.get("headers"), dict) else {}
        header_lookup = {str(key).lower(): value for key, value in headers.items()}
        findings = report.get("findings") if isinstance(report.get("findings"), list) else []
        observed_http = isinstance(http.get("status_code"), int)
        observed_tls = bool(tls.get("issuer") or tls.get("supported_protocols") or tls.get("certificate_chain"))
        reachable = observed_http or observed_tls
        target = report.get("target") or scan_data.get("target") or "Unknown target"
        observed_at = report.get("observed_at") or scan_data.get("timestamp") or "Unknown"
        score = report.get("score", scan_data.get("score"))
        grade = report.get("grade", scan_data.get("grade"))
        score_text = f"{score}/100" if isinstance(score, (int, float)) else "Not scored"
        grade_text = str(grade or "Not available")

        story = [
            Paragraph("SiteWatch Website Security Assessment", title_style),
            Paragraph(f"Target: <b>{safe(target)}</b>", body_style),
            Paragraph(f"Scan date: {safe(observed_at)}", body_style),
            Paragraph("Live TLS, DNS, and HTTP observations captured by the website analyzer.", body_style),
            Spacer(1, 9),
            data_table([
                ["Overall posture score", score_text], ["Grade", grade_text],
                ["Connectivity", "Online: TLS or HTTP endpoint responded" if reachable else "Target is unreachable or blocked by firewall"],
                ["Findings observed", str(len(findings))],
            ]),
        ]

        if not reachable:
            story.extend([Spacer(1, 12), Paragraph("Target is unreachable or blocked by firewall", ParagraphStyle("Unreachable", parent=heading_style, textColor=colors.HexColor("#b42318"))),
                          Paragraph("The scan did not receive a usable TLS certificate/protocol observation or HTTP response. No security score should be interpreted as a passing result.", body_style)])

        story.extend([Paragraph("TLS certificate", heading_style), data_table([
            ["Issuer", tls.get("issuer") or "Not observed"],
            ["Negotiated protocol", tls.get("negotiated_protocol") or "Not observed"],
            ["Supported protocols", ", ".join(tls.get("supported_protocols") or []) or "Not observed"],
            ["Certificate expiry", tls.get("not_after") or "Not observed"],
            ["Days to expiry", str(tls.get("days_until_expiry")) if tls.get("days_until_expiry") is not None else "Not observed"],
            ["Chain validation", "Validated" if tls.get("chain_validated") is True else "Not validated" if tls.get("chain_validated") is False else "Unknown"],
            ["Revocation", (tls.get("revocation") or {}).get("status", "unknown")],
        ])])

        story.extend([Paragraph("DNS observations", heading_style), data_table([
            ["Resolved addresses", ", ".join(dns.get("addresses") or []) or "Not observed"],
            ["CAA", "; ".join(dns.get("caa") or []) or ("No CAA record observed" if isinstance(dns.get("caa"), list) else "Unknown")],
            ["SPF", "; ".join(dns.get("spf") or []) or ("No SPF record observed" if isinstance(dns.get("spf"), list) else "Unknown")],
            ["DMARC", "; ".join(dns.get("dmarc") or []) or ("No DMARC record observed" if isinstance(dns.get("dmarc"), list) else "Unknown")],
        ])])

        story.append(Paragraph("HTTP response and security headers", heading_style))
        story.append(data_table([
            ["HTTP status", str(http.get("status_code")) if observed_http else "No HTTP response observed"],
            ["Response URL", http.get("url") or "Not observed"],
            ["Server", header_lookup.get("server") or "Not disclosed"],
        ]))
        header_rows = []
        for name in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"):
            value = header_lookup.get(name.lower())
            state = f"Present: {value}" if value else "Missing from observed response" if observed_http else "Unknown: no HTTP response"
            header_rows.append([name, state])
        story.append(data_table(header_rows))

        story.append(Paragraph("Findings and remediation", heading_style))
        if findings:
            for finding in findings:
                severity = str(finding.get("severity") or "INFO").upper()
                color, _ = cls.get_severity_colors(severity)
                title = safe(finding.get("title") or finding.get("check_id") or "Finding")
                detail = safe(finding.get("description") or "")
                evidence = safe(finding.get("evidence") or "No evidence attached")
                mitigation = safe(finding.get("recommendation") or "Review the affected configuration.")
                severity_color = "#" + color.hexval()[-6:]
                card = Table([[Paragraph(f"<b>{title}</b>  ·  <font color='{severity_color}'><b>{safe(severity)}</b></font>", body_style)],
                              [Paragraph(f"<b>Description:</b> {detail}<br/><b>Evidence:</b> {evidence}<br/><b>Mitigation:</b> {mitigation}", small_style)]], colWidths=[528])
                card.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), .6, colors.HexColor("#d8e1eb")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
                story.extend([card, Spacer(1, 7)])
        else:
            story.append(Paragraph("No scored findings were returned. This posture score does not certify that the target is vulnerability-free.", body_style))

        story.append(Spacer(1, 10))
        story.append(Paragraph("Data source: " + safe(report.get("data_source") or "Saved live analyzer report"), small_style))
        story.append(Paragraph("Generated from the saved analyzer JSON payload. Missing values are shown as not observed, not as proof that a control is absent.", small_style))
        doc.build(story)
        pdf = buffer.getvalue()
        buffer.close()
        return pdf

    @classmethod
    def generate_report(cls, scan_data: Dict[str, Any]) -> bytes:
        details = scan_data.get("details") if isinstance(scan_data, dict) else None
        if not isinstance(details, dict) and isinstance(scan_data, dict) and isinstance(scan_data.get("checks"), dict):
            details = scan_data
        if isinstance(details, dict) and isinstance(details.get("checks"), dict):
            return cls._generate_website_report(scan_data, details)
        buffer = io.BytesIO()
        
        # Setup document template with margins
        # Page size: Letter (612 x 792 points)
        # Margin: Left/Right 36pt (0.5 in), Top/Bottom 54pt (0.75 in)
        # Printable area width = 540 pt
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=54,
            bottomMargin=54
        )
        
        styles = getSampleStyleSheet()
        
        # Custom styles setup
        cover_title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=26,
            leading=32,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=12
        )
        
        cover_subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=13,
            leading=18,
            textColor=colors.HexColor('#475569'),
            spaceAfter=40
        )
        
        cover_meta_label = ParagraphStyle(
            'CoverMetaLabel',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#64748b')
        )
        
        cover_meta_val = ParagraphStyle(
            'CoverMetaVal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#1e293b')
        )
        
        h1_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=colors.HexColor('#1e3a8a'),
            spaceBefore=14,
            spaceAfter=10,
            keepWithNext=True
        )
        
        h2_style = ParagraphStyle(
            'SubSectionHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=15,
            textColor=colors.HexColor('#0f172a'),
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True
        )
        
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor('#334155'),
            spaceAfter=8
        )
        
        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=11,
            textColor=colors.white
        )
        
        table_body_style = ParagraphStyle(
            'TableBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#334155')
        )
        
        table_body_bold_style = ParagraphStyle(
            'TableBodyBold',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#1e293b')
        )

        story = []
        
        # ----------------------------------------------------
        # 1. COVER PAGE
        # ----------------------------------------------------
        story.append(Spacer(1, 40))
        
        # App logo title
        logo_title = Paragraph("SECURITY SCANNER", ParagraphStyle(
            'CoverLogo',
            fontName='Helvetica-Bold',
            fontSize=34,
            leading=40,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=4
        ))
        story.append(logo_title)
        
        sub_logo = Paragraph("VULNERABILITY ASSESSMENT REPORT", ParagraphStyle(
            'CoverSubLogo',
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569'),
            spaceAfter=20
        ))
        story.append(sub_logo)
        
        # Divider line
        story.append(cls.draw_line(colors.HexColor("#3b82f6"), thickness=2.5, space_after=35))
        
        # Report Info
        target = scan_data.get("target", "Unknown Target")
        story.append(Paragraph(f"Security Audit Report for {target}", cover_title_style))
        story.append(Paragraph("Automated Network Service Mapping & Vulnerability Correlation Findings", cover_subtitle_style))
        
        # Metadata Card table
        now_str = datetime.now().strftime("%B %d, %Y - %H:%M:%S")
        risk_summary = scan_data.get("risk_summary", {})
        host_severity = risk_summary.get("host_severity", "UNKNOWN")
        weighted_score = risk_summary.get("weighted_risk_score", 0.0)
        max_cvss = risk_summary.get("max_cvss_score", 0.0)
        ports_scanned = scan_data.get("ports_scanned", 0)
        
        meta_data = [
            [Paragraph("Target Host IP/DNS:", cover_meta_label), Paragraph(target, cover_meta_val)],
            [Paragraph("Assessment Timestamp:", cover_meta_label), Paragraph(now_str, cover_meta_val)],
            [Paragraph("Ports Scanned:", cover_meta_label), Paragraph(str(ports_scanned), cover_meta_val)],
            [Paragraph("Host Risk Severity:", cover_meta_label), Paragraph(f"<b>{host_severity}</b>", cover_meta_val)],
            [Paragraph("Weighted Risk Index:", cover_meta_label), Paragraph(f"<b>{weighted_score:.1f} / 10.0</b>", cover_meta_val)],
            [Paragraph("Highest Discovered CVSS:", cover_meta_label), Paragraph(f"<b>{max_cvss:.1f}</b>", cover_meta_val)]
        ]
        
        meta_table = Table(meta_data, colWidths=[160, 380])
        meta_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        story.append(meta_table)
        
        story.append(Spacer(1, 80))
        
        # Confidentiality footer note
        story.append(Paragraph(
            "<b>Notice:</b> This file contains security scanner findings and potential system "
            "vulnerabilities. Restricted Distribution Only. Store in accordance with organization policy.",
            ParagraphStyle(
                'NoticeStyle',
                fontName='Helvetica-Oblique',
                fontSize=8.5,
                leading=12,
                textColor=colors.HexColor('#64748b')
            )
        ))
        
        story.append(PageBreak())
        
        # ----------------------------------------------------
        # 2. EXECUTIVE SUMMARY PAGE
        # ----------------------------------------------------
        story.append(Paragraph("Executive Summary", h1_style))
        story.append(cls.draw_line(colors.HexColor("#cbd5e1"), thickness=1, space_after=15))
        
        intro_text = (
            f"An automated vulnerability assessment and port discovery scan was performed against "
            f"target host <b>{target}</b> on {now_str}. The scan checked <b>{ports_scanned}</b> ports and "
            f"cross-referenced the discovered services with the local National Vulnerability Database (NVD) "
            f"vulnerability feed."
        )
        story.append(Paragraph(intro_text, body_style))
        story.append(Spacer(1, 10))
        
        # Risk assessment card
        bg_color, text_color = cls.get_severity_colors(host_severity)
        
        risk_card_data = [
            [
                Paragraph(f"<b>Host Security Rating:</b> {host_severity} ({weighted_score:.1f}/10)", ParagraphStyle('HSA', fontName='Helvetica-Bold', fontSize=10, textColor=text_color)),
            ],
            [
                Paragraph(
                    f"A total of <b>{ports_scanned}</b> ports were scanned. Based on the services identified and "
                    f"cross-referenced CVE vulnerability information, the system has calculated a cumulative risk rating "
                    f"of {weighted_score:.1f}/10. Please review the detailed vulnerability findings below for remediation options.",
                    ParagraphStyle('HSAB', fontName='Helvetica', fontSize=9, leading=13, textColor=text_color)
                )
            ]
        ]
        
        risk_card_table = Table(risk_card_data, colWidths=[540])
        risk_card_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg_color),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('RIGHTPADDING', (0,0), (-1,-1), 12),
            ('BOX', (0,0), (-1,-1), 1, bg_color.darker() if hasattr(bg_color, 'darker') else bg_color),
        ]))
        story.append(risk_card_table)
        story.append(Spacer(1, 15))
        
        # Severity breakdown table
        story.append(Paragraph("Vulnerability Severity Breakdown", h2_style))
        sev_counts = risk_summary.get("severity_counts", {})
        
        sev_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
        sev_table_data = [[
            Paragraph("<b>Severity</b>", ParagraphStyle('S1', fontName='Helvetica-Bold', fontSize=9, textColor=colors.HexColor('#0f172a'))),
            Paragraph("<b>Count</b>", ParagraphStyle('S2', fontName='Helvetica-Bold', fontSize=9, alignment=1, textColor=colors.HexColor('#0f172a'))),
            Paragraph("<b>Percentage</b>", ParagraphStyle('S3', fontName='Helvetica-Bold', fontSize=9, alignment=1, textColor=colors.HexColor('#0f172a'))),
            Paragraph("<b>Status</b>", ParagraphStyle('S4', fontName='Helvetica-Bold', fontSize=9, textColor=colors.HexColor('#0f172a'))),
        ]]
        
        total_vulns = sum(sev_counts.get(level, 0) for level in sev_levels)
        if total_vulns == 0:
            total_vulns = 1 # Avoid division by zero
            
        for level in sev_levels:
            count = sev_counts.get(level, 0)
            pct = (count / total_vulns) * 100 if total_vulns > 0 else 0
            
            c_bg, c_fg = cls.get_severity_colors(level)
            
            status_text = "Requires Immediate Action" if level in ["CRITICAL", "HIGH"] and count > 0 else "Monitor & Patch" if count > 0 else "Secure"
            
            sev_table_data.append([
                Paragraph(level, ParagraphStyle('SL', fontName='Helvetica-Bold', fontSize=8.5, textColor=c_bg)),
                Paragraph(str(count), ParagraphStyle('SC', fontName='Helvetica', fontSize=8.5, alignment=1)),
                Paragraph(f"{pct:.1f}%", ParagraphStyle('SP', fontName='Helvetica', fontSize=8.5, alignment=1)),
                Paragraph(status_text, ParagraphStyle('SS', fontName='Helvetica', fontSize=8.5, textColor=colors.HexColor("#475569") if count > 0 else colors.HexColor("#10b981"))),
            ])
            
        sev_table = Table(sev_table_data, colWidths=[120, 80, 100, 240])
        sev_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LINEBELOW', (0,0), (-1,0), 1.5, colors.HexColor("#cbd5e1")),
            ('LINEBELOW', (0,1), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 20))
        
        # ----------------------------------------------------
        # 2.5 HTTP SECURITY ASSESSMENT (Task 10)
        # ----------------------------------------------------
        story.append(Paragraph("HTTP Security Assessment", h1_style))
        story.append(cls.draw_line(colors.HexColor("#cbd5e1"), thickness=1, space_after=15))
        
        http_eval = scan_data.get("http_assessment") or {}
        server_str = http_eval.get("server", "Unknown / Not Detected")
        robots_info = http_eval.get("robots_txt") or {"status": "Missing"}
        robots_status = robots_info.get("status", "Missing")
        dir_info = http_eval.get("directory_listing") or {"status": "Disabled"}
        dir_status = dir_info.get("status", "Disabled")
        headers = http_eval.get("headers") or {}

        # Security Headers status strings
        hsts_str = "<b>✓ HSTS</b>" if headers.get("Strict-Transport-Security") else "<font color='#ef4444'><b>✗ HSTS</b></font>"
        csp_str = "<b>✓ CSP</b>" if headers.get("Content-Security-Policy") else "<font color='#ef4444'><b>✗ CSP</b></font>"
        xfo_str = "<b>✓ X-Frame-Options</b>" if headers.get("X-Frame-Options") else "<font color='#ef4444'><b>✗ X-Frame-Options</b></font>"
        xcto_str = "<b>✓ X-Content-Type-Options</b>" if headers.get("X-Content-Type-Options") else "<font color='#ef4444'><b>✗ X-Content-Type-Options</b></font>"
        rp_str = "<b>✓ Referrer-Policy</b>" if headers.get("Referrer-Policy") else "<font color='#ef4444'><b>✗ Referrer-Policy</b></font>"

        headers_display = f"{hsts_str} &nbsp;&nbsp;&nbsp;&nbsp; {csp_str} &nbsp;&nbsp;&nbsp;&nbsp; {xfo_str} &nbsp;&nbsp;&nbsp;&nbsp; {xcto_str} &nbsp;&nbsp;&nbsp;&nbsp; {rp_str}"

        http_table_data = [
            [Paragraph("<b>Server:</b>", table_body_bold_style), Paragraph(server_str, table_body_style)],
            [Paragraph("<b>robots.txt:</b>", table_body_bold_style), Paragraph(robots_status, table_body_style)],
            [Paragraph("<b>Directory Listing:</b>", table_body_bold_style), Paragraph(dir_status, table_body_style)],
            [Paragraph("<b>Headers:</b>", table_body_bold_style), Paragraph(headers_display, table_body_style)]
        ]

        http_table = Table(http_table_data, colWidths=[120, 420])
        http_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        story.append(http_table)
        story.append(Spacer(1, 15))

        # ----------------------------------------------------
        # 2.6 SSL/TLS ASSESSMENT
        # ----------------------------------------------------
        story.append(Paragraph("SSL/TLS & Certificate Assessment", h1_style))
        story.append(cls.draw_line(colors.HexColor("#cbd5e1"), thickness=1, space_after=15))

        ssl_eval = scan_data.get("ssl_assessment") or {}
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

        ssl_table_data = [
            [Paragraph("<b>TLS Protocol Version:</b>", table_body_bold_style), Paragraph(str(tls_ver), table_body_style)],
            [Paragraph("<b>Certificate Validity:</b>", table_body_bold_style), Paragraph(str(validity_status), table_body_style)],
            [Paragraph("<b>Self-Signed Status:</b>", table_body_bold_style), Paragraph("Yes (Self-Signed)" if is_self_signed else "No (CA Signed)", table_body_style)],
            [Paragraph("<b>Certificate Subject:</b>", table_body_bold_style), Paragraph(str(cert_subject), table_body_style)],
            [Paragraph("<b>Certificate Issuer:</b>", table_body_bold_style), Paragraph(str(cert_issuer), table_body_style)],
            [Paragraph("<b>Certificate Expiration:</b>", table_body_bold_style), Paragraph(f"{cert_expires} ({days_left} days remaining)", table_body_style)],
            [Paragraph("<b>Cipher Suite:</b>", table_body_bold_style), Paragraph(f"{cipher_name} ({cipher_bits}-bit encryption)", table_body_style)]
        ]

        ssl_table = Table(ssl_table_data, colWidths=[140, 400])
        ssl_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        story.append(ssl_table)
        story.append(Spacer(1, 20))
        
        # ----------------------------------------------------
        # 3. DISCOVERED PORTS AND SERVICES
        # ----------------------------------------------------
        story.append(Paragraph("Discovered Services & Open Ports", h1_style))
        story.append(cls.draw_line(colors.HexColor("#cbd5e1"), thickness=1, space_after=15))

        
        results = scan_data.get("results", [])
        
        ports_table_data = [[
            Paragraph("Port", table_header_style),
            Paragraph("Status", table_header_style),
            Paragraph("Service", table_header_style),
            Paragraph("Software / Version / Banner", table_header_style),
            Paragraph("Vulnerabilities", table_header_style)
        ]]
        
        for res in results:
            port = str(res.get("port", "N/A"))
            status = str(res.get("status", "N/A")).upper()
            service = str(res.get("service", "N/A"))
            
            software = res.get("software")
            version = res.get("version")
            banner = res.get("banner")
            
            desc_parts = []
            if software and software != "unknown":
                desc_parts.append(f"<b>{software}</b> {version if version else ''}")
            if banner:
                desc_parts.append(f"Banner: {banner}")
            if not desc_parts:
                desc_parts.append("No responsive signature detected.")
            
            soft_desc = Paragraph("; ".join(desc_parts), table_body_style)
            
            vulns = res.get("vulnerabilities", [])
            vuln_count = len(vulns)
            if vuln_count > 0:
                max_v_cvss = max(v.get("cvss_score", 0.0) for v in vulns)
                vuln_desc = Paragraph(f"<b>{vuln_count} CVEs</b> (Max CVSS: {max_v_cvss:.1f})", ParagraphStyle('VC', parent=table_body_style, textColor=colors.HexColor("#ef4444")))
            else:
                vuln_desc = Paragraph("None", table_body_style)
                
            ports_table_data.append([
                Paragraph(port, table_body_bold_style),
                Paragraph(status, table_body_style),
                Paragraph(service, table_body_bold_style),
                soft_desc,
                vuln_desc
            ])
            
        if not results:
            ports_table_data.append([
                Paragraph("N/A", table_body_style),
                Paragraph("N/A", table_body_style),
                Paragraph("N/A", table_body_style),
                Paragraph("No open ports or services found during target inspection.", table_body_style),
                Paragraph("None", table_body_style)
            ])
            
        ports_table = Table(ports_table_data, colWidths=[50, 60, 80, 230, 120])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e3a8a")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(ports_table)
        story.append(Spacer(1, 20))
        
        # ----------------------------------------------------
        # 4. DETAILED VULNERABILITY ASSESSMENT
        # ----------------------------------------------------
        all_vulns = []
        for res in results:
            port = res.get("port")
            service = res.get("service")
            for v in res.get("vulnerabilities", []):
                v_copy = dict(v)
                v_copy["port"] = port
                v_copy["service"] = service
                all_vulns.append(v_copy)
                
        all_vulns.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)
        
        if all_vulns:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Vulnerability Assessment", h1_style))
            story.append(cls.draw_line(colors.HexColor("#cbd5e1"), thickness=1, space_after=15))
            
            for v in all_vulns:
                cve_id = v.get("cve_id", "N/A")
                severity = v.get("severity", "UNKNOWN")
                cvss = v.get("cvss_score", 0.0)
                port = v.get("port", "N/A")
                service = v.get("service", "N/A")
                desc = v.get("description", "No description available.")
                remediation = v.get("remediation", "No remediation recommendation provided.")
                
                c_bg, c_fg = cls.get_severity_colors(severity)
                
                vuln_card_data = [
                    [
                        Paragraph(f"<b>{cve_id}</b>", ParagraphStyle('VId', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white)),
                        Paragraph(f"<b>Severity: {severity} ({cvss:.1f})</b>", ParagraphStyle('VSec', fontName='Helvetica-Bold', fontSize=9, alignment=2, textColor=colors.white))
                    ],
                    [
                        Paragraph(f"<b>Port / Service:</b> TCP {port} ({service})", ParagraphStyle('VPort', fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor("#334155"))),
                        ""
                    ],
                    [
                        Paragraph(f"<b>Description:</b><br/>{desc}", ParagraphStyle('VDesc', fontName='Helvetica', fontSize=8.5, leading=12, textColor=colors.HexColor("#1e293b"))),
                        ""
                    ],
                    [
                        Paragraph(f"<b>Suggested Remediation:</b><br/>{remediation}", ParagraphStyle('VRem', fontName='Helvetica', fontSize=8.5, leading=12, textColor=colors.HexColor("#1e293b"))),
                        ""
                    ]
                ]
                
                vuln_table = Table(vuln_card_data, colWidths=[270, 270])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), c_bg),
                    ('SPAN', (0,1), (1,1)),
                    ('SPAN', (0,2), (1,2)),
                    ('SPAN', (0,3), (1,3)),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0), (-1,-1), 5),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                    ('LEFTPADDING', (0,0), (-1,-1), 8),
                    ('RIGHTPADDING', (0,0), (-1,-1), 8),
                    ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f8fafc")),
                    ('BOX', (0,0), (-1,-1), 0.75, colors.HexColor("#cbd5e1")),
                    ('LINEBELOW', (0,0), (-1,0), 0.75, c_bg.darker() if hasattr(c_bg, 'darker') else c_bg),
                    ('LINEBELOW', (0,1), (-1,1), 0.5, colors.HexColor("#e2e8f0")),
                    ('LINEBELOW', (0,2), (-1,2), 0.5, colors.HexColor("#e2e8f0")),
                ]))
                
                story.append(KeepTogether([vuln_table, Spacer(1, 12)]))
                
        # Build document
        doc.build(story, canvasmaker=NumberedCanvas)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes
