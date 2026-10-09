# Shared database contract

The whole team works against **one shared Postgres database**. Every service reads and
writes its own tables in that database. Nothing is stored in SQLite files, JSON files on
disk, or Python dictionaries in memory.

Read this file fully before you touch any database code.

## 1. Connection

| Variable | Used by | Format |
|---|---|---|
| `DATABASE_URL` | every Python service except `dlp-gateway` | `postgresql://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require` |
| `POSTGRES_URL` | `dlp-gateway` only (SQLAlchemy + asyncpg) | `postgresql+asyncpg://USER:PASSWORD@HOST:5432/DBNAME?ssl=require` |

- Both point at the **same** database. Yash shares the real values privately.
- Put them in a file named `.env` in the repo root (copy `.env.example`). `.env` is gitignored.
- `docker-compose.yml` already passes `DATABASE_URL` into every service. You do not need to edit it.
- **Never** write the real URL in code, a commit, an issue, a PR, a screenshot or an AI chat.
  In code, the only allowed way to get it is `os.getenv("DATABASE_URL")`.

## 2. Rules for a shared database

Four people and about ten services use this database at the same time. Breaking it breaks everyone.

1. **Only the owner creates or changes a table.** See the ownership table in section 4.
2. **Create tables with `CREATE TABLE IF NOT EXISTS`**, run once at service startup.
3. **Add columns with `ALTER TABLE <t> ADD COLUMN IF NOT EXISTS <col> <type>`.**
4. **Never run `DROP TABLE`, `TRUNCATE`, or `DELETE` without a `WHERE`.** Not even "just to reset".
5. **Never rename or remove a column** that already exists. Add a new one instead.
6. **Table names are prefixed with the module** (`credential_`, `attachment_`, `url_`, `smtp_`, ...).
7. **Seed data with `INSERT ... ON CONFLICT DO NOTHING`** so running it twice is harmless.
8. **A database error must never break a scan.** Wrap every write in `try/except`, log the
   error, and still return the scan result to the caller.
9. **No silent SQLite fallback.** If `DATABASE_URL` is missing or the connection fails, log a
   clear error. Do not quietly write to a local file, because then your data is invisible to
   everyone else and the dashboard shows nothing.
10. Timestamps are `TIMESTAMP WITH TIME ZONE DEFAULT NOW()`. Structured data is `JSONB`.

## 3. The `db.py` template (copy this, do not invent your own)

Every Python service that talks to the database has one file named `db.py` that starts with
exactly this code. Add your own table SQL and functions below it.

`psycopg2-binary` must be listed in the service's `requirements.txt`.

```python
"""Shared-Postgres access for this service. Contract: docs/DATABASE.md"""
import os
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor, Json  # Json(...) wraps dict/list for JSONB columns

DATABASE_URL = os.getenv("DATABASE_URL")


@contextmanager
def get_cursor():
    """Open a connection, yield a dict cursor, commit on success, roll back on error."""
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set. See docs/SETUP.md")
    conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> bool:
    """Create this service's tables. Call once at startup. Safe to call many times."""
    try:
        with get_cursor() as cur:
            cur.execute(SCHEMA_SQL)  # define SCHEMA_SQL below with CREATE TABLE IF NOT EXISTS ...
        print("[DB] tables ready")
        return True
    except Exception as e:
        print(f"[DB] init_db failed: {e}")
        return False
```

How to use it:

```python
# write
def save_scan(result: dict):
    try:
        with get_cursor() as cur:
            cur.execute(
                "INSERT INTO my_table (title, findings) VALUES (%s, %s) RETURNING id, created_at",
                (result["title"], Json(result["findings"])),
            )
            return cur.fetchone()          # a dict: {"id": 1, "created_at": datetime}
    except Exception as e:
        print(f"[DB] save_scan failed: {e}")
        return None                        # the scan still succeeds

# read
def get_history(limit: int = 50) -> list:
    try:
        with get_cursor() as cur:
            cur.execute("SELECT * FROM my_table ORDER BY created_at DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        print(f"[DB] get_history failed: {e}")
        return []
```

Things that go wrong most often:

- Placeholders are `%s`, never `?` (that is SQLite) and never an f-string with user input.
- `datetime` values are not JSON serialisable. Convert with `.isoformat()` before returning from an API.
- `Decimal` values from `AVG(...)` are not JSON serialisable. Wrap with `float(...)`.
- Pass a Python `dict`/`list` to a `JSONB` column as `Json(value)`.

## 4. Table ownership

| Table | Owner module | Owner | Status |
|---|---|---|---|
| `credential_scans` | `Credential_Scanner-main` | Manash | new |
| `credential_patterns` | `Credential_Scanner-main` | Manash | new |
| `attachment_scan_history` | `attachment_scanner` | Manash | exists, gets new columns |
| `attachment_bad_hashes` | `attachment_scanner` | Manash | new |
| `url_scans`, `url_feedback`, `url_retraining` | `website_spoofing_model-main` | Mitanshu | move from SQLite |
| `smtp_decisions` | `smtp-fraud-gateway` | Mitanshu | exists |
| `smtp_domain_lists`, `smtp_settings` | `smtp-fraud-gateway` | Mitanshu | new |
| `sandbox_scans` | `sandbox` | Yash | new |
| `prompt_guard_events` | `fraudshield-prompt-guard` | Yash | new |
| `voice_predictions`, `voice_feedback`, `voice_retraining` | `fraudshield-voice` | Yash | exists |
| `retrain_state`, `retrain_runs` | `retrain-scheduler` | Yash | new |
| `email_inbox`, `email_attachments`, `email_feedback`, `email_retraining` | `email_monitoring` | Yash | exists |
| `dlp_events`, `user_risk_profiles`, `dlp_policies`, `alerts` | `dlp-gateway` | Yash | exists |
| `app_users` | `dlp-gateway` | Yash | new |

The exact `CREATE TABLE` statement for every **new** table is in the issue that creates it.
Use that statement exactly. If you need a column that is not there, add it with
`ADD COLUMN IF NOT EXISTS` and update this file in the same PR.

## 5. Checking the database by hand

```bash
# list all tables
psql "$DATABASE_URL" -c '\dt'

# look at the newest rows of a table
psql "$DATABASE_URL" -c 'SELECT * FROM credential_scans ORDER BY created_at DESC LIMIT 5;'
```

If you do not have `psql`, run it through Docker:

```bash
docker run --rm -it --env-file .env postgres:16-alpine sh -c 'psql "$DATABASE_URL" -c "\dt"'
```
