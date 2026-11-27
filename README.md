<<<<<<< HEAD
# Website Security & Certificate Analyzer

FastAPI, MySQL and React application for live website posture checks across TLS, DNS and HTTP. It saves the actual observations and produces one mitigation plan per finding. It does not seed demo targets, sample findings or fake scan history.

## Run locally with Docker

The project has a local `.env` file with the bootstrap admin credentials and scan key configured for this workspace. Keep it private; it is git-ignored. For a fresh installation, copy `.env.example` to `.env`, replace every placeholder with private secrets, and set `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD`, `SCAN_ACCESS_KEY`, `JWT_SECRET`, `MYSQL_ROOT_PASSWORD` and `MYSQL_PASSWORD`.

```bash
docker compose up --build -d
```

- Dashboard: `http://localhost:3001`
- FastAPI documentation: `http://localhost:8001/docs`
- MySQL is bound to localhost port `3307`; it is not exposed on every network interface.

Compose runs the Alembic migrations before starting FastAPI. MySQL data persists in the `mysql_data` volume. `docker compose down` keeps it; `docker compose down -v` deletes it.

## Accounts and scan access

- Registration creates a normal user. Passwords must be at least 12 characters and are bcrypt-hashed.
- The `ADMIN` identity is reserved and created from the bootstrap values in `.env`. A role cannot be selected during registration.
- The backend verifies administrator role from the database for every admin operation. Admins can review accounts and recorded activity, suspend users, or reactivate them.
- A signed-in user must also provide the configured `SCAN_ACCESS_KEY` in the dashboard before a scan can run. The API requires the same value in the `X-Scan-Key` header. The frontend keeps it in the current browser session.

## Live assessment

`POST /api/v1/analyze` accepts a public hostname or HTTP(S) URL. It performs bounded live DNS queries, TLS handshakes, certificate parsing and a single HTTP request. The hostname is resolved first; private, loopback, link-local and reserved IPs are rejected, and network connections are pinned to a resolved public address. Redirects are not followed. The HTTP URL is assessed over HTTPS, and the HTTP endpoint is checked separately for an HTTPS redirect.

The report includes observed DNS answers, multi-resolver DNS comparisons, DNSSEC signals, SPF/DMARC records, negotiated TLS versions and cipher probes, the presented certificate chain, certificate validity and name checks, OCSP with signed CRL fallback, HTTP security headers, session-like cookie flags, and detectable active mixed content. Revocation is reported as unknown unless a fresh OCSP response or complete CRL can be validated against the presented issuer. DNS resolver and network failures are recorded as unknown rather than vulnerabilities. DNSKEY absence alone is not treated as proof DNSSEC is disabled. CAA lookup follows the hostname through its enclosing DNS zone to account for inherited CAA records.

EV policy OIDs, payment form markers and trust-seal vendor strings are returned as unverified signals. The analyzer does not treat those markers as proof of organization validation, payment compliance or an authentic seal. Compliance standards are not inferred from a public page scan.

## Scoring and false-positive controls

Each distinct, directly observed check is counted once. Severity deductions follow the project weights: Critical 25, High 15, Medium 8, Low 3, Info 0; the score is `max(0, 100 - deductions)`. Grades use A (90+), B (75+), C (60+), D (40+), F (below 40). A letter grade is returned only when DNS, TLS and HTTP were all observed; otherwise the report says `INCOMPLETE` and has no score. Only high-confidence observations change the score; medium-confidence observations remain visible with zero deduction. Unknown checks are not scored. This is a posture score, not CVSS and not a compliance certification.

NVD keyword results are not automatically promoted to confirmed vulnerabilities from a service banner. Automatic CVE correlation only accepts an exact CPE name; a keyword search remains reference information and is not a finding. Live NVD search uses the NIST NVD API. Per-check mitigation plans and authoritative references are maintained in `app/scanner/data/mitigations.json`.

## Persistence and API

MySQL stores users, account roles/status, assets, scan history and admin activity logs. User scan history is isolated by authenticated account. Admin endpoints are role-protected:

- `GET /api/v1/admin/overview`
- `POST /api/v1/admin/users/{user_id}/suspend`
- `POST /api/v1/admin/users/{user_id}/activate`

Website assessment data is saved under scan history and can be retrieved from `GET /api/v1/scans/{scan_id}`. The JSON includes evidence, score breakdown, grade, timestamps, live check observations and finding-specific mitigation. HTML reports are available from `GET /api/v1/scans/{scan_id}/report`.

## Main components

- `app/scanner/website_analyzer.py` — bounded public-target TLS, DNS and HTTP checks
- `app/scanner/data/mitigations.json` — mitigation plans and source references
- `app/api/routes.py` — authentication, analysis and admin API
- `app/models.py`, `alembic/` — MySQL schema and migrations
- `frontend/src/App.jsx` — login/registration, scan dashboard, reports, history and admin dashboard
- `docker-compose.yml` — MySQL, FastAPI and React/Nginx deployment

## Command center dashboard and profile

The React application uses the SiteWatch brand, an animated canvas network background, glass panels, transition effects, Lucide icons, and Recharts. Dashboard counters, recent scan rows, severity distribution, and the seven-day chart are derived from the signed-in user's saved scan history. The latest result uses the newest report and shows its score, grade, findings count, and report link. Empty accounts show empty states instead of seeded/sample values. The scan modal follows the supplied radar reference and displays estimated progress and phases while the synchronous request is pending; 100% and the completion toast appear only after the API responds. It does not claim to receive backend progress events.

The page/component structure in `frontend/src/App.jsx` is:

```text
App
├── NetworkBackdrop
├── AuthScreen
├── Dashboard
│   ├── Stat
│   ├── ScanTable
│   └── Report
├── ProfilePage
│   └── AvatarImage
├── AdminDashboard
└── ScanAnimation
```

Profile endpoints require the signed-in user's JWT:

- `GET /api/v1/users/me` — read username, role, name, email, and avatar URL
- `PUT /api/v1/users/me` — update name/email
- `POST /api/v1/users/me/avatar` — upload JPEG, PNG, or WebP (maximum 5 MB and 20 megapixels); image is re-encoded as WebP
- `GET /api/v1/users/me/avatar` — retrieve the current user's private avatar
- `PUT /api/v1/users/me/password` — change password after verifying the current password
- `GET /api/v1/health` — unauthenticated API status check for the dashboard's online indicator

Avatar files are kept in the `avatar_data` Docker volume. `alembic/versions/0005_user_profile.py` adds profile fields; startup applies migrations through the existing Alembic command. The scan summary endpoint now returns score, grade, and severity counts to power charts from persisted reports.

The frontend uses Tailwind CSS 4 through the Vite plugin, `recharts` for data visualizations, `framer-motion` for transitions and the scan overlay, and `sonner` for scan completion/error notifications. The particle/network effect is a small canvas component, so it does not need a particle library. To install them manually from `frontend/`:

```bash
npm install tailwindcss @tailwindcss/vite recharts framer-motion sonner
```

Redis and Celery are not included yet: current checks are bounded and run synchronously. Add a job queue only when scheduled or bulk scans require background workers.
=======
# 🛡️ SiteWatch: Website Security & Certificate Analyzer

**SiteWatch** is a full-stack, automated cybersecurity tool designed to perform live, in-depth security audits of public websites. It evaluates a target's TLS/SSL certificates, DNS security, HTTP response headers, and compliance signals, providing a comprehensive security score (0-100) and actionable mitigation plans.

This project was developed as the final project for the **Network Security** course.

**Institution:** University of Frontier Technology, Bangladesh (UFTB)  
**Department:** Cyber Security Engineering  
**Instructor:** Md Masud Rana (Lecturer)  
**Team Members:** 
- Tahmid Ezaz (2304013)
- MD. Firoz Hasan (2304039)
- Saydi Hasan Porosh (2304026)

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
   git clone https://github.com/Ash-Born/ZENITH-Website-Security-Certificate-Analyzer.git
   cd ZENITH-Website-Security-Certificate-Analyzer
>>>>>>> 2df651180f6fcc61e5689eeb2b68877fc6ab2b19
