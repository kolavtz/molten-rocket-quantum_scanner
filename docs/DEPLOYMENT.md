# QuantumShield Deployment Guide

## Quick Start (Local)

```bash
# 1. Clone the project
git clone <repo-url>
cd quantum-safe-scanner

# 2. Create virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the dashboard
python web/app.py
# → Open http://127.0.0.1:5000
```

---

## Docker Deployment

### Build & Run
```bash
docker build -t quantumshield .
docker run -p 5000:5000 quantumshield
```

### Docker Compose
```yaml
version: "3.9"
services:
  scanner:
    build: .
    ports:
      - "5000:5000"
    environment:
      - QSS_DEBUG=false
      - QSS_SECRET_KEY=your-production-secret
    volumes:
      - scan_data:/app/scan_results
    restart: unless-stopped

volumes:
  scan_data:
```

```bash
docker compose up -d
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QSS_SECRET_KEY` | `dev-secret-change-in-production` | Flask secret key |
| `QSS_DEBUG` | `true` | Debug mode on/off |

---

## Production Checklist

1. **Set a strong `QSS_SECRET_KEY`** — never use the default in production
2. **Disable debug mode** — set `QSS_DEBUG=false`
3. **Use gunicorn** (Linux) or **waitress** (Windows) in place of Flask dev server:
   ```bash
   # Linux
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 web.app:app

   # Windows
   pip install waitress
   waitress-serve --port=5000 web.app:app
   ```
4. **Reverse proxy** — put Nginx or Caddy in front for TLS termination
5. **Persist results** — mount `scan_results/` to a durable volume or switch to a database
6. **Rate limiting** — add Flask-Limiter to prevent scan abuse via the API

---

## Network Requirements

The scanner needs **outbound TCP access** to the targets being scanned:
- Port 443 (HTTPS) — primary
- Ports 8443, 636, 993, 995, 465 — additional TLS services
- DNS resolution for hostnames

The web dashboard listens on **port 5000** (configurable).
