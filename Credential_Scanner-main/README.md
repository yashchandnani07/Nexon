# Credential_Scanner

## API endpoints

Start the API with `uvicorn main:app --host 0.0.0.0 --port 8002` from this directory.

### `GET /health`

Returns API and LLM availability.

```bash
curl http://localhost:8002/health
```

### `POST /scan/text`

Scan text submitted as multipart form data.

```bash
curl -X POST http://localhost:8002/scan/text -F 'text=password=example-value-123'
```

### `POST /scan/file`

Scan an uploaded document (up to 25 MB).

```bash
curl -X POST http://localhost:8002/scan/file -F 'file=@./sample.txt'
```

### `POST /admin/reload-patterns`

Reload `patterns.json` without restarting the API.

```bash
curl -X POST http://localhost:8002/admin/reload-patterns
```

### `POST /analyze/email`

Scan an email subject, sender and body submitted as JSON.

```bash
curl -X POST http://localhost:8002/analyze/email -H 'Content-Type: application/json' -d '{"subject":"Account notice","sender":"sender@example.test","text":"Please review this message."}'
```

### `GET /`

Serves the browser scanning interface.

```bash
curl http://localhost:8002/
```
