# Attachment Scanner

The API analyzes uploaded files through four phases:

1. **File Type Detection:** compare declared and detected formats and report mismatches.
2. **Deep Content Analysis:** run relevant analyzers on PDF, Office, executable, archive, HTML and image content.
3. **Hash Reputation Check:** check file hashes against the available malware reputation data.
4. **Risk Verdict:** combine findings into a severity score, summary and recommended action. The API also stores analysis history when the database is available.

Run the service from this directory with `python api.py` (port 8007).

## Endpoints

### `POST /analyze`

Upload a file for analysis.

```bash
curl -X POST http://localhost:8007/analyze -F 'file=@./Test Files/test_phishing.html'
```

### `GET /history`

Return recent analysis history. The optional `limit` parameter is capped at 100.

```bash
curl 'http://localhost:8007/history?limit=10'
```

### `GET /stats`

Return aggregate analysis statistics.

```bash
curl http://localhost:8007/stats
```
