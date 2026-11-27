# 🛡️ SiteWatch: Website Security & Certificate Analyzer

**SiteWatch** is a full-stack, automated cybersecurity tool designed to perform live, in-depth security audits of public websites. It evaluates a target's TLS/SSL certificates, DNS security, HTTP response headers, and compliance signals, providing a comprehensive security score (0-100) and actionable mitigation plans.

This project was developed as the final project for the **Network Security** course.

**Institution:** University of Frontier Technology, Bangladesh (UFTB)  
**Department:** Cyber Security Engineering  
**Instructor:** Md Masud Rana (Lecturer)  
**Team Members:** 
- Tahmid Ezaz (2304013)
- MD. Firoz Hasan (2304039)
- Saydi Hasan Parash (2304026)

---

## 🚀 Key Features

- **Live Web Assessment:** Scans targets from the outside in, detecting TLS misconfigurations (expired certs, weak ciphers, old protocols), DNS issues (missing CAA, SPF/DMARC, DNSSEC signals), and missing HTTP security headers (HSTS, CSP, X-Frame-Options).
- **Intelligent Scoring Engine:** Calculates a risk score (Grade A to F) based on severity deductions (Critical=25, High=15, Medium=8, Low=3). Evaluates layer coverage and flags reports as `INCOMPLETE` if core layers (DNS/TLS/HTTP) fail.
- **Attack Surface Graph:** An interactive, node-based visual graph showing the real-time risk level of each layer (DNS, TLS, HTTP, Compliance) with color-coded nodes.
- **Automated Reporting:** Generates downloadable PDF, JSON, and HTML reports containing detailed evidence and step-by-step mitigation plans.
- **Scheduled Scans & Alerts:** Includes a background scheduler (APScheduler) for automated periodic scans. Real-time alerts are pushed to Discord/Slack via Webhooks if critical vulnerabilities are found.
- **Enterprise Auth & Admin Panel:** JWT-based authentication, role-based access control (Admin/User), password hashing, and a dedicated Admin Dashboard for user management, activity logs, and global threat mapping.
- **Live Scanning Animation:** A real-time, hacker-style radar animation with a live terminal log to visualize the scanning process.

---

## 🏗️ System Architecture

SiteWatch is built on a decoupled, modern architecture:

1. **Frontend (React.js):** Handles the UI, interactive data visualizations (Force-Graph, Recharts), and user input. Communicates with the backend via REST APIs. Features a particle/network canvas background.
2. **Backend (FastAPI):** The core orchestration layer. Receives the domain, resolves DNS, connects via raw sockets to extract TLS certificates, and parses HTTP responses.
3. **Scanner Engine:** Python-based modules using `ssl`, `socket`, `cryptography`, and `dnspython` to deeply analyze network traffic and map findings to severity scores.
4. **Database (MySQL 8.4):** Stores user credentials, scan history (JSON blobs), scheduled jobs, and admin activity logs.

---

## 💻 Technology Stack

- **Frontend:** React.js (Vite), Tailwind CSS 4, Framer Motion, React-Force-Graph, Recharts, Sonner (Notifications).
- **Backend:** Python, FastAPI, SQLAlchemy, Alembic.
- **Database:** MySQL 8.4 (Dockerized, port 3307).
- **Security Libraries:** `ssl`, `socket`, `cryptography`, `pyOpenSSL`, `dnspython`.
- **Deployment & Infrastructure:** Docker, Cloudflare Tunnels.

---

## 🔒 Security Engineering Highlights (Deep Dive)

- **SSRF Mitigation (Server-Side Request Forgery):** The scanner resolves the target domain and verifies that the IP address is public (blocking `127.0.0.1`, `192.168.x.x`, and reserved ranges) before initiating connections. Network connections are pinned to the resolved public IP to prevent DNS rebinding attacks.
- **Deep TLS Inspection:** Bypasses basic checks by directly parsing X.509 certificates, validating the certificate chain against system trust stores, and querying OCSP with signed CRL fallback for revocation status.
- **Zero False-Positives:** NVD keyword results are not automatically promoted to confirmed vulnerabilities. Unknown checks are not scored. Only high-confidence observations change the score.
- **Secure Auth & API:** Implements JWT for session management, `bcrypt` for secure password hashing, rate limiting, strict CORS origin validation, and custom headers (`X-Scan-Key`) to authorize scanning actions.
- **Admin Protection:** Backend verifies administrator role from the database for every admin operation. Admins can review accounts, suspend users, or reactivate them.

---

## 🗄️ Database & API Design

The MySQL database stores users, roles, assets, scan history, and activity logs. User scan history is isolated by authenticated accounts.

**Key API Endpoints:**
- `POST /api/v1/analyze`: Initiates a live scan (requires JWT + X-Scan-Key).
- `GET /api/v1/scans/{scan_id}`: Retrieves a specific scan report with evidence and mitigation.
- `GET /api/v1/scans/{scan_id}/report`: Downloads the HTML report.
- `GET /api/v1/users/me`: Retrieves user profile (name, email, avatar URL).
- `POST /api/v1/users/me/avatar`: Uploads and re-encodes profile images as WebP (max 5MB).
- `GET /api/v1/admin/overview`: Fetches global system stats for the Admin dashboard.
- `POST /api/v1/admin/users/{user_id}/suspend`: Suspends a user account.

*(Note: Avatars are stored in a Docker volume `avatar_data`)*

---

## 🛡️ Scoring Methodology

A letter grade is returned only when DNS, TLS, and HTTP layers are all successfully observed. Otherwise, the report says `INCOMPLETE` and has no score. This is a posture score, not CVSS, and not a compliance certification. 

The score is calculated as: **`max(0, 100 - deductions)`**
- **A:** 90+
- **B:** 75+
- **C:** 60+
- **D:** 40+
- **F:** Below 40

---

## ⚙️ How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Ash-Born/SiteWatch-Website-Security-Certificate-Analyzer.git
   cd SiteWatch-Website-Security-Certificate-Analyzer
