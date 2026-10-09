# API contract between the services and the dashboard

The frontend dashboards used to show numbers typed into the source code. They now read live
numbers from the database through each service.

To make that possible without the frontend and backend owners waiting on each other, **every
backend service exposes the same two endpoints with the same response shape**. Backend owners
build exactly this. The frontend owner codes against exactly this.

## 1. `GET /summary`

Returns everything the dashboard needs about one module, computed from that module's tables.

```json
{
  "module": "attachment-scanner",
  "total_scans": 128,
  "threats_detected": 37,
  "by_risk": { "critical": 4, "high": 11, "medium": 22, "low": 0, "clean": 91 },
  "avg_processing_ms": 412.5,
  "daily": [
    { "date": "2026-10-03", "scans": 9,  "threats": 2 },
    { "date": "2026-10-04", "scans": 14, "threats": 3 }
  ],
  "recent": [
    {
      "id": 57,
      "created_at": "2026-10-09T10:42:11+00:00",
      "title": "invoice_final.pdf",
      "risk": "high",
      "score": 78,
      "summary": "PDF contains an embedded JavaScript action"
    }
  ]
}
```

Field rules:

| Field | Type | Rule |
|---|---|---|
| `module` | string | The fixed module id from the table in section 3 |
| `total_scans` | int | Count of all rows |
| `threats_detected` | int | Count of rows whose normalised risk is not `clean` and not `low` |
| `by_risk` | object | Always all five keys, lower case, `0` when empty |
| `avg_processing_ms` | number | Average processing time, `0` when there are no rows |
| `daily` | array | Last 7 calendar days that have data, oldest first, `date` as `YYYY-MM-DD` |
| `recent` | array | Newest 10 rows, newest first |
| `recent[].risk` | string | One of `critical`, `high`, `medium`, `low`, `clean` |
| `recent[].score` | number | 0 to 100 |
| `recent[].title` | string | What was scanned: file name, URL, email subject, model name |

If the database is unreachable, return HTTP 200 with the same shape and zeros/empty arrays,
plus `"db": "unavailable"`. The dashboard must keep rendering.

## 2. `GET /history?limit=50`

```json
{ "history": [ { "id": 57, "created_at": "2026-10-09T10:42:11+00:00", "...": "module specific columns" } ], "count": 1 }
```

- Newest first. `limit` defaults to 50 and is capped at 200.
- Every row has at least `id` and `created_at` (ISO 8601 string).
- Services that already have `/history` or `/decisions` keep their current shape. Do not break existing pages.

## 3. Module ids, URL prefixes and risk mapping

The frontend calls `<prefix>/summary`. Nginx (and the Vite dev proxy) strips the prefix and
forwards to the service.

| Module id | Frontend prefix | Service (compose name : port) | Owner | Own labels → normalised risk |
|---|---|---|---|---|
| `credential-scanner` | `/api/cred-scan` | `credential-scanner:8002` | Manash | `Critical/High/Medium/Low/Clean` → lower case |
| `attachment-scanner` | `/api/attachment-scan` | `attachment-scanner:8007` | Manash | `Critical/High/Medium/Low/Clean` → lower case |
| `website-spoofing` | `/api/website-spoofing` | `website-spoofing:5000` | Mitanshu | `DANGEROUS`→`critical`, `SUSPICIOUS`→`medium`, `SAFE`→`clean` |
| `smtp-gateway` | `/api/smtp-gateway` | `smtp-fraud-gateway:8010` | Mitanshu | decision `REJECT`→`critical`, `QUARANTINE`→`high`, `TAG`→`medium`, `ACCEPT`→`clean` |
| `sandbox` | `/api/sandbox` | `sandbox-harness:8000` | Yash | risk level of the scan → `critical/high/medium/low` |
| `prompt-guard` | `/api/prompt-guard` | `prompt-guard:8005` | Yash | `INJECTION`/`CRITICAL`→`critical`, `SUSPICIOUS`→`medium`, `CLEAN`→`clean` |
| `voice-scanner` | `/api/voice-scan` | `voice-scanner:8000` | Yash | tier `CRITICAL/HIGH/MEDIUM/LOW` → lower case |
| `email-monitor` | `/api/email` | `email-monitor:8009` | Yash | risk_tier `CRITICAL/HIGH/MEDIUM/LOW` → lower case, `UNKNOWN`→`clean` |
| `dlp-gateway` | `/api/dlp` | `dlp-gateway:8001` | Yash | risk_tier → lower case |

## 4. SQL pattern for `/summary`

Adapt the table name, the timestamp column, the risk expression and the processing-time
column. Everything else stays the same. `RISK` below stands for an SQL expression that
produces one of the five lower-case values (for a table that already stores
`Critical/High/...` it is simply `LOWER(risk_label)`).

```sql
-- totals + by_risk
SELECT
  COUNT(*)                                            AS total_scans,
  COUNT(*) FILTER (WHERE RISK IN ('critical','high','medium')) AS threats_detected,
  COUNT(*) FILTER (WHERE RISK = 'critical')           AS critical,
  COUNT(*) FILTER (WHERE RISK = 'high')               AS high,
  COUNT(*) FILTER (WHERE RISK = 'medium')             AS medium,
  COUNT(*) FILTER (WHERE RISK = 'low')                AS low,
  COUNT(*) FILTER (WHERE RISK = 'clean')              AS clean,
  COALESCE(AVG(processing_ms), 0)                     AS avg_processing_ms
FROM my_table;

-- daily (last 7 days with data, oldest first)
SELECT TO_CHAR(DATE(created_at), 'YYYY-MM-DD')        AS date,
       COUNT(*)                                       AS scans,
       COUNT(*) FILTER (WHERE RISK IN ('critical','high','medium')) AS threats
FROM my_table
WHERE created_at >= NOW() - INTERVAL '7 days'
GROUP BY DATE(created_at)
ORDER BY DATE(created_at);

-- recent
SELECT id, created_at, <title column> AS title, RISK AS risk,
       <score column> AS score, <summary column> AS summary
FROM my_table
ORDER BY created_at DESC
LIMIT 10;
```

Before returning: convert `created_at` with `.isoformat()` and wrap `avg_processing_ms` with `float(...)`.

## 5. Testing an endpoint

```bash
# directly against the service
curl -s http://localhost:8007/summary | python3 -m json.tool

# through nginx, the way the frontend calls it
curl -s http://localhost/api/attachment-scan/summary | python3 -m json.tool
```

A response is correct when it has every key from section 1, `by_risk` has all five keys,
and the numbers change after you run a new scan.
