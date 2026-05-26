# TraceZ — Safe Browsing Shield

> Privacy-First Browser Security Extension. Lightweight phishing detection and safe browsing protection.

## Architecture

```
tracez/
├── extension/     → Chrome Extension (Manifest V3)
├── backend/       → FastAPI Backend API
└── shared/        → Shared blocklists & resources
```

## Quick Start

### 1. Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate       # Windows
pip install -r requirements.txt
cp .env.example .env        # Edit with your API keys
python run.py
```

Backend runs at `http://localhost:8000`

### 2. Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. TraceZ icon appears in toolbar

## Features (MVP)

- ✅ Real-time phishing detection
- ✅ Homoglyph/IDN attack detection
- ✅ Domain reputation scoring
- ✅ Suspicious redirect detection
- ✅ Fake login form detection
- ✅ Warning overlays for risky pages
- ✅ Full block pages for dangerous sites
- ✅ Local blocklist (works offline)
- ✅ Threat intelligence API enrichment
- ✅ Admin dashboard

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Extension | Chrome Manifest V3, Vanilla JS |
| Backend | Python 3.12, FastAPI, SQLAlchemy |
| Database | SQLite (upgradeable to PostgreSQL) |
| Auth | Argon2 + JWT |
| Detection | Heuristic scoring + API reputation |

## Security

- All inputs sanitized
- SSRF protection on URL scanning
- JWT session tokens (not plain cookies)
- Rate limiting on all endpoints
- Security headers middleware
- CSP enforced on extension pages

## License

Proprietary — TraceZ Security Platform
