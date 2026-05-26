# TraceZ — Privacy-First Safe Browsing Shield

> A production-grade Chrome Manifest V3 Security Extension integrated with a hardened FastAPI analysis backend.

TraceZ protects users in real-time from phishing domains, malicious payloads, homoglyph domain-spoofing attacks, and command & control (C2) servers.

---

## 🏗️ Architecture

The workspace is organized into clean, modular components:

```
tracez/
├── app/               → Monolithic App Backend & Templates (For easy root-level launch)
│   ├── main.py        → FastAPI entrypoint & monolithic routers
│   ├── database.py    → SQLite configurations & schemas (ARGON2, TRZ threats)
│   ├── static/        → Public UI assets (dashboard styles, client app.js, icons)
│   └── templates/     → Monolithic single-page dashboard HTML
├── backend/           → Hardened Backend (Contains duplicate of app/ to prevent namespace reload issues)
│   ├── app/           → Core API routes, custom rate-limiters, security middlewares
│   ├── tests/         → Automated test suites (backend & extension endpoints)
│   └── run.py         → FastAPI isolated Uvicorn launcher
├── extension/         → Google Chrome Extension source (Manifest V3)
│   ├── background/    → Service worker handling network logs and telemetry syncing
│   ├── content/       → Content scripts injecting isolated Shadow DOM warning overlays
│   ├── popup/         → Extension toolbar quick stats and shield triggers
│   └── lib/           → Offline heuristics, homoglyph matchers, and scoring algorithms
├── scripts/           → Packaging scripts (manifest checkers and ZIP compiler)
└── shared/            → Offline databases (safe allowlists, default blocklists)
```

---

## 🔒 Security Hardening Implementations

TraceZ is built using DevSecOps best practices to prevent vulnerabilities:

1. **SSRF Mitigation**: The active redirect analysis engine checks every hop resolving hostname DNS, blocking internal, multicast, loopback, and private IP ranges (e.g., RFC 1918) before establishing a connection.
2. **Path-Specific Rate Limiting**: sliding-window rate limiters prevent brute-force attacks:
   - Authentication routes (`/api/auth`): 5 requests / min
   - Scan requests (`/api/scan`): 30 requests / min
   - Admin features (`/api/admin`): 20 requests / min
   - Other requests: 100 requests / min
3. **MIME Sniffing & Framing Protection**: Global middleware sets headers preventing MIME-type confusion (`X-Content-Type-Options: nosniff`) and framing attacks (`X-Frame-Options: DENY`).
4. **Argon2 Password Hashing**: Upgraded standard hashing implementations to industrial-standard Argon2 secure encryption.
5. **Conditional Content Security Policy**: Permissive CSP applied to user-facing static pages (allowing Leaflet CDN map tiles and local scripts) while maintaining a strict `default-src 'none'; sandbox` policy for raw JSON API endpoints.

---

## 🚀 Setup & Execution Guide

### 1. Prerequisites
Ensure you have Python 3.12+ installed. Set the active IDE workspace to:
```
C:\Users\Administrator\.gemini\antigravity\scratch\tracez
```

### 2. Run the Security Server
From the root workspace folder, install dependencies and launch the server:
```powershell
pip install -r requirements.txt
python run.py
```
* The server will boot on `http://127.0.0.1:8000/`.
* On startup, the launcher automatically creates a local SQLite database (`tracez.db`) and seeds default threats and accounts.

### 🛡️ Default System Credentials
* **Admin Account**: `admin@1` / `divesh@9192`
* **User Account**: `user@tracez.app` / `User@123_`

### 3. Load the Extension in Chrome
1. In your browser, navigate to `chrome://extensions/`.
2. Toggle **Developer mode** in the top-right corner to **ON**.
3. Click **Load unpacked** in the top-left corner.
4. Select the `C:\Users\Administrator\.gemini\antigravity\scratch\tracez\dist` folder (or the `extension/` folder).
5. Open the dashboard at [http://127.0.0.1:8000/](http://127.0.0.1:8000/), navigate to the **Extension** tab, and you will see the status update to **Extension Active & Shielding**.

---

## 🔬 Automated Testing

We have built full test suites. To execute them and verify that all endpoints, auth cookies, database models, and rate limits are fully functional:

```powershell
# Run backend routes and security assertions
python backend/tests/test_backend.py

# Run extension logs and blocklist sync checks
python backend/tests/test_extension_api.py
```

---

## 🛠️ Pushing to GitHub Repo

Since the environment does not store your personal GitHub auth token, you can push the codebase directly from your local terminal. Execute the following commands:

```bash
# Add the remote repository URL
git remote set-url origin https://github.com/diveshchoyal/tracez.git

# Push changes securely to the main branch
git push -u origin main --force
```
