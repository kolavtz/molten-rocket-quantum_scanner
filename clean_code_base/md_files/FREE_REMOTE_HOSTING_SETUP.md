# Free Remote Hosting + Remote MySQL Setup

This guide helps you:
1. connect QuantumShield to your remote MySQL host,
2. push your SQL schema/migrations to that remote DB,
3. deploy the Flask app on a free hosting platform.

---

## 1) Configure environment variables

Create/update your local `.env` (do **not** commit it):

- `REMOTE_MYSQL_HOST`
- `REMOTE_MYSQL_PORT`
- `REMOTE_MYSQL_USER`
- `REMOTE_MYSQL_PASSWORD`
- `REMOTE_MYSQL_DATABASE`

Also set the runtime DB values the app itself uses:

- `MYSQL_HOST=${REMOTE_MYSQL_HOST}`
- `MYSQL_PORT=${REMOTE_MYSQL_PORT}`
- `MYSQL_USER=${REMOTE_MYSQL_USER}`
- `MYSQL_PASSWORD=${REMOTE_MYSQL_PASSWORD}`
- `MYSQL_DATABASE=${REMOTE_MYSQL_DATABASE}`

---

## 2) Verify remote DB connectivity

Run:

- `python scripts/remote_db_check.py`

Expected output includes:

- `[OK] Connected to MySQL server version ...`
- `[OK] Active database: ...`

---

## 3) Push SQL to remote database

Apply canonical schema:

- `python scripts/push_sql_to_remote.py --file schema_v2_inventory_api_first.sql`

Apply migrations (optional but recommended):

- `python scripts/push_sql_to_remote.py --file migrations/001_add_findings_and_metrics_tables.sql`

You can also run multiple files in one call:

- `python scripts/push_sql_to_remote.py --file schema_v2_inventory_api_first.sql --file migrations/001_add_findings_and_metrics_tables.sql`

---

## 4) Free web hosting (Render example)

QuantumShield already has a `Procfile`:

- `web: gunicorn --bind 0.0.0.0:$PORT web.app:app`

### Render setup

1. Push code to GitHub (without `.env`).
2. Create a new **Web Service** on Render from your repo.
3. Runtime: Python.
4. Build command:
   - `pip install -r requirements.txt`
5. Start command:
   - `gunicorn --bind 0.0.0.0:$PORT web.app:app`
6. Add environment variables in Render dashboard:
   - `MYSQL_HOST`
   - `MYSQL_PORT`
   - `MYSQL_USER`
   - `MYSQL_PASSWORD`
   - `MYSQL_DATABASE`
   - `QSS_SECRET_KEY`
   - `QSS_DEBUG=false`
   - any required SMTP/admin env values

After deploy, the app will connect directly to your remote SQL host.

---

## 5) Security checklist (important)

- Never commit real credentials to git.
- Rotate any credentials that were previously shared in chat or committed.
- Keep `.env` in `.gitignore` (already recommended).
- Use a new strong `QSS_SECRET_KEY` in production.
- Set `QSS_DEBUG=false` in production.

---

## 6) Optional: quick health checks after deploy

- Open the app URL and verify login/dashboard loads.
- Trigger one scan from UI and confirm rows persist in remote DB.
- Verify key tables exist (`assets`, `scans`, `certificates`, `cbom_entries`).

---

If you want, next step I can also add a one-command script that runs:
`remote_db_check -> push schema -> push migration` in sequence.
