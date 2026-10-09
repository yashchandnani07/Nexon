# 🛡️ SMTP Fraud Gateway

Pre-delivery email fraud inspection and security gateway for banking environments.

The SMTP Fraud Gateway intercepts incoming and outgoing email messages before they reach the recipient's mailbox, performing automated, real-time threat detection and AI scoring.

---

## 🚀 Overview

The gateway operates simultaneously as:
1. **An SMTP Proxy / Server (Port `2525`)**: Intercepts SMTP traffic, runs extraction pipelines, scores threats, and decides whether to forward or quarantine the email.
2. **A REST Management & Inspection API (Port `8010`)**: Exposes operational endpoints for manual email scoring, quarantine reviews, analyst triage, and performance statistics.

### Threat Detection Pipeline
- **Ensemble Scorer**: Combines heuristic rules and XGBoost machine learning to compute a normalized fraud score ($0.0 - 1.0$).
- **Decisions**:
  - `REJECT`: High-risk malicious email (score $\ge 0.70$) — blocked from delivery.
  - `QUARANTINE`: Suspicious email (score $\ge 0.40$) — held for security analyst review.
  - `TAG`: Low-to-moderate risk email (score $\ge 0.20$) — flagged with security warning headers.
  - `ALLOW`: Clean email (score $< 0.20$) — forwarded directly downstream.
- **Multilingual Phishing & Deception Detection**: Detects spoofed sender headers, homograph attacks, and credential-harvesting indicators across multiple languages.
- **Explainability**: Outputs SHAP attribution and top contributing risk factors for auditability.

---

## 🔌 Ports & Interfaces

| Service | Port | Description |
|---|---|---|
| **SMTP Server** | `2525` | Inbound/Outbound SMTP proxy receiving raw RFC 5322 emails (`GATEWAY_SMTP_PORT`) |
| **REST API** | `8010` | FastAPI HTTP service for threat analysis, quarantine release/reject, and stats |

---

## 📡 REST API Reference (`src/main.py`)

Base URL: `http://localhost:8010`

### 1. `GET /health`
Liveness check returning service and SMTP status.
```bash
curl -s http://localhost:8010/health
```
Response:
```json
{"status":"ok","service":"smtp-fraud-gateway","smtp_port":2525}
```

### 2. `GET /decisions`
Retrieves paginated audit log of email decisions made by the gateway.
```bash
curl -s "http://localhost:8010/decisions?limit=50&offset=0"
```

### 3. `GET /decisions/{decision_id}`
Retrieves details, features, and SHAP contributors for a specific decision ID.
```bash
curl -s http://localhost:8010/decisions/1
```

### 4. `GET /stats`
Retrieves gateway statistics including total processed count, decision breakdown, and risk tier distribution.
```bash
curl -s http://localhost:8010/stats
```

### 5. `POST /quarantine/{decision_id}/release`
Releases a quarantined email and forwards it to downstream recipients.
```bash
curl -s -X POST http://localhost:8010/quarantine/1/release
```

### 6. `POST /quarantine/{decision_id}/reject`
Confirms rejection of a quarantined email, permanently discarding it.
```bash
curl -s -X POST http://localhost:8010/quarantine/1/reject
```

### 7. `POST /analyze`
Analyzes structured email contents without requiring raw RFC 5322 format.
```bash
curl -s -X POST http://localhost:8010/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "alerts@security-update.com",
    "recipients": ["employee@bank.com"],
    "subject": "Urgent Password Reset Required",
    "body": "Please click http://paypa1-secure-login.xyz to verify your account."
  }'
```

### 8. `POST /analyze-explain`
Performs full analysis with detailed linguistic explanations and LLaMA-based contextual analysis.
```bash
curl -s -X POST http://localhost:8010/analyze-explain \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "hr@partner-co.com",
    "subject": "Updated Benefits",
    "body": "Review the attached document."
  }'
```

### 9. `POST /validate`
Performs lightweight sender, homograph, and domain reputation validation.
```bash
curl -s -X POST http://localhost:8010/validate \
  -H "Content-Type: application/json" \
  -d '{"sender":"exec@bаrсlays.com","subject":"Payment notice"}'
```

### 10. `POST /score-raw`
Scores a raw MIME/RFC 5322 email string.
```bash
curl -s -X POST http://localhost:8010/score-raw \
  -H "Content-Type: application/json" \
  -d '{"raw_email":"From: test@example.com\nTo: user@example.com\nSubject: Test\n\nHello"}'
```

### 11. `POST /inbound-webhook`
Webhook endpoint for upstream MTAs / mail gateways delivering serialized email payloads.
```bash
curl -s -X POST http://localhost:8010/inbound-webhook \
  -H "Content-Type: application/json" \
  -d '{"sender":"external@vendor.com","body":"Invoice enclosed"}'
```

### 12. `GET /demo`
Serves an interactive web interface for testing email payloads against the gateway.
```bash
curl -s http://localhost:8010/demo
```

### 13. `POST /test-email`
Sends a synthetic test email into the local gateway on port 2525 to verify end-to-end processing.
```bash
curl -s -X POST http://localhost:8010/test-email \
  -H "Content-Type: application/json" \
  -d '{"scenario":"credential_harvesting"}'
```

### 14. `GET /test-templates`
Lists pre-configured test email attack scenarios (CEO fraud, homograph attacks, credential phishing, etc.).
```bash
curl -s http://localhost:8010/test-templates
```

---

## ⚙️ Configuration & Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql://...` | Connection string to shared PostgreSQL database for audit decisions |
| `GATEWAY_SMTP_PORT` | `2525` | Port on which the SMTP interceptor listens |
| `REJECT_THRESHOLD` | `0.70` | Fraud score threshold triggering immediate email rejection |
| `QUARANTINE_THRESHOLD` | `0.40` | Fraud score threshold triggering quarantine isolation |
| `TAG_THRESHOLD` | `0.20` | Fraud score threshold adding security warning headers |
| `FORWARD_SMTP_HOST` | `mailhog` | Downstream SMTP server host for allowed emails |
| `FORWARD_SMTP_PORT` | `1025` | Downstream SMTP server port |
| `FORWARD_SMTP_USER` | `""` | Optional SMTP authentication username |
| `FORWARD_SMTP_PASS` | `""` | Optional SMTP authentication password |
| `FORWARD_TO_EMAIL` | `""` | Optional override destination mailbox |
| `EMAIL_MONITOR_URL` | `http://email-monitor:8009` | Email monitoring microservice URL |
| `ATTACHMENT_SCANNER_URL` | `http://attachment-scanner:8007` | Attachment scanner microservice URL |
| `OLLAMA_URL` | `http://sandbox-ollama:11434` | Ollama LLM endpoint for explainability |
| `LLAMA_MODEL` | `llama3` | Ollama model name |
| `LLAMA_TIMEOUT` | `45` | LLM inference timeout in seconds |
