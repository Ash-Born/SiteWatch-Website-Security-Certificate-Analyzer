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
