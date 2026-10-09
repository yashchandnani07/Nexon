<div align="center">

# 🛡️ AegisAI — FraudShield Platform

**AI-Powered Enterprise Fraud Detection & Data Security**

*Built for Barclays Hack-O-Hire 2.0*

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Latest-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=white)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-Latest-EE4C2C?logo=pytorch&logoColor=white)](https://pytorch.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 📖 Overview

**AegisAI** is a comprehensive, enterprise-grade security platform that protects banking organisations from the full spectrum of modern AI-era threats. Built as a **microservices architecture** with 10+ containerised services, it combines cutting-edge machine learning with rule-based systems to defend against:

- 📧 **Phishing emails** (multilingual, AI-generated)
- 🎙️ **Deepfake voice calls** (vishing attacks)
- 💉 **Prompt injection attacks** on LLM systems
- 🔒 **Data leakage** to external AI tools
- 🔑 **Credential exposure** in documents and emails
- 📎 **Malicious attachments** (malware, macros, exploits)
- 🌐 **Spoofed / phishing websites**
- 📨 **Fraudulent SMTP email delivery**

---

## 📌 Project Status & Origin

**Baseline.** This repository starts from the existing AegisAI FraudShield platform, which was
originally built for Barclays Hack-O-Hire 2.0
([original repository](https://github.com/OnkarNanaware/Barclay-s-Hackathon)). The module
folders are imported from that baseline in commits named `chore(<module>): import baseline ...`.

**Built in this repository.** Everything after the baseline imports, tracked in
[Issues](https://github.com/yashchandnani07/Nexon/issues):

- One shared PostgreSQL database for every service, replacing per-service SQLite files,
  JSON files on disk and in-memory state ([docs/DATABASE.md](docs/DATABASE.md))
- A common `/summary` and `/history` API on every service ([docs/API_CONTRACT.md](docs/API_CONTRACT.md))
- Dashboards that read live data from those APIs instead of values typed into the source
- Detection rules, domain lists, thresholds and users stored in the database instead of in code
- Secrets moved out of source files into `.env`

### Team

| Owner | GitHub | Area |
|---|---|---|
| Aditya | [@adityarandive10](https://github.com/adityarandive10) | Frontend |
| Manash | [@manash008](https://github.com/manash008) | Credential Scanner, Attachment Scanner |
| Mitanshu | [@mitanshu007](https://github.com/mitanshu007) | Website Spoofing, SMTP Fraud Gateway |
| Yash | [@yashchandnani07](https://github.com/yashchandnani07) | Sandbox Harness, DLP Gateway, Email Monitor, Prompt Guard, Voice Scanner, Scheduler, infrastructure |

### Documentation

| Document | What it covers |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Install, `.env`, running one service or the whole stack |
| [docs/DATABASE.md](docs/DATABASE.md) | Shared database rules, the `db.py` template, table ownership |
| [docs/API_CONTRACT.md](docs/API_CONTRACT.md) | The `/summary` and `/history` endpoints every service exposes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Folder ownership, branching, commit messages, what never to commit |

---

## 🏗️ Architecture

```
                         Internet / Employee Devices
                                    │
                           ┌────────▼────────┐
                           │  NGINX  (:80)   │  ← Reverse Proxy + React SPA
                           └────────┬────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │               Aegis Service Mesh (aegisai-net)         │
        │                                                        │
  ┌─────▼──────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
  │Email Monitor│  │DLP Gateway│  │Prompt Guard│  │Voice Scanner│  │
  │  :8009     │  │  :8001   │  │  :8005   │  │   :8006    │  │
  └────────────┘  └──────────┘  └──────────┘  └────────────┘  │
                                                                 │
  ┌─────────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
  │  Credential  │  │Attachment│  │ Website  │  │SMTP Fraud │  │
  │  Scanner    │  │ Scanner  │  │ Spoofing │  │ Gateway   │  │
  │  :8002      │  │  :8007   │  │  :8008   │  │:2525/:8010│  │
  └─────────────┘  └──────────┘  └──────────┘  └───────────┘  │
                                                                 │
        ┌────────────────── Shared Infrastructure ─────────────┐ │
        │  PostgreSQL(:5432)  Redis(:6379)  MailHog(:1025)     │ │
        │  Ollama LLM Runtime(:11434)  Sandbox Harness(:8000)  │ │
        └──────────────────────────────────────────────────────┘ │
        └────────────────────────────────────────────────────────┘
```

---

## 🧩 Modules

| # | Service | Port | Description |
|---|---------|------|-------------|
| 1 | **Email Monitor** | `8009` | Live Gmail IMAP monitoring with 8-stage threat analysis pipeline |
| 2 | **DLP Gateway** | `8001` | 11-layer Data Loss Prevention — blocks sensitive data from reaching external AI |
| 3 | **Prompt Guard** | `8005` | 5-layer prompt injection detection with ProtectAI DeBERTa v2 |
| 4 | **Voice Scanner** | `8006` | Deepfake voice detection using custom CNN-BiLSTM + Random Forest ensemble |
| 5 | **Credential Scanner** | `8002` | Hybrid credential detection: Regex + Entropy + NER + LLM |
| 6 | **Attachment Scanner** | `8007` | 4-phase malware analysis with YARA (1900+ rules), PDF/Office/PE/ZIP |
| 7 | **Website Spoofing** | `8008` | PhishGuard v3 — XGBoost + 6-module URL/SSL/WHOIS/Cookie analysis |
| 8 | **SMTP Fraud Gateway** | `2525/8010` | SMTP proxy intercepting outgoing emails before delivery |
| 9 | **Sandbox Harness** | `8000` | Isolated LLM testing harness for prompt injection research |
| 10 | **Frontend** | `80` | React 18 + Vite dashboard for analysts |

---

## 🤖 ML Models & AI

| Model | Architecture | Task |
|-------|-------------|------|
| `protectai/deberta-v3-base-prompt-injection-v2` | DeBERTa-v3-base | Prompt injection binary classifier |
| `url_phishing_xgboost_v3.pkl` | XGBoost (27 URL features) | URL phishing detection |
| `best_eer_v2.pt` | Custom CNN-BiLSTM | Deepfake voice detection |
| `rf_model.pkl` | Random Forest (MFCC features) | Voice deepfake ensemble (15%) |
| `gliner_medium` | GLiNER | Zero-shot PII NER |
| RoBERTa / DeBERTa-v3 / DistilBERT | Transformers (HuggingFace) | Email phishing classification cascade |
| `mistral:7b-instruct-q4_K_M` | Mistral 7B (Ollama, quantized) | DLP semantic scan — Layer 11 |
| `qwen3:8b` | Qwen 3 (Ollama) | Email content analysis & summarization |
| `tinyllama` | TinyLlama (Ollama) | Sandbox + voice explanation fallback |
| `llama3` / `llama3.2` | LLaMA 3 (Ollama) | Prompt guard chatbot backend |
| YARA Rules (1900+) | Community rules | Malware/exploit pattern matching |

---

## 🚀 Getting Started

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Latest | Container runtime |
| [Docker Compose](https://docs.docker.com/compose/) | v2+ | Service orchestration |
| [Git](https://git-scm.com/) | Latest | Version control |

> **Minimum Hardware**: 16 GB RAM recommended (Ollama LLMs require memory). 8 GB may work with smaller models only.

---

### 1. Clone the Repository

```bash
git clone https://github.com/yashchandnani07/Nexon.git
cd Nexon
```

---

### 2. Configure Environment Variables

Create the root `.env` (shared database URL, IMAP credentials, JWT secret) and the DLP
Gateway settings file:

```bash
cp .env.example .env
cp dlp-gateway/.env.example dlp-gateway/.env
```

Fill in `.env` as described in [docs/SETUP.md](docs/SETUP.md). No credential is stored in
`docker-compose.yml`; it reads everything from `.env`. If `DATABASE_URL` is left unset, the
services fall back to the local `postgres` container.

---

### 3. Build & Start All Services

```bash
docker compose up --build
```

This will:
1. Build all 10 service Docker images
2. Start PostgreSQL and Redis (infrastructure)
3. Start Ollama and auto-pull `tinyllama`
4. Build the React frontend and serve via Nginx
5. Start all detection microservices

> **First build takes 10–20 minutes** due to ML model downloads (HuggingFace transformers, PyTorch, etc.)

---

### 4. Access the Platform

| Service | URL | Description |
|---------|-----|-------------|
| **Main Dashboard** | http://localhost | React frontend (Email Monitor) |
| **DLP Gateway API** | http://localhost/api/dlp/docs | Swagger UI |
| **Prompt Guard API** | http://localhost/api/prompt-guard/docs | Swagger UI |
| **Voice Scanner API** | http://localhost/api/voice-scan/docs | Swagger UI |
| **Credential Scanner** | http://localhost/api/cred-scan/ | Web UI + API |
| **Attachment Scanner API** | http://localhost/api/attachment-scan/docs | Swagger UI |
| **Website Spoofing** | http://localhost/api/website-spoofing/ | PhishGuard dashboard |
| **SMTP Gateway API** | http://localhost/api/smtp-gateway/docs | Swagger UI |
| **Email Monitor API** | http://localhost/api/email/docs | Swagger UI |
| **MailHog (email testing)** | http://localhost:8025 | Fake SMTP UI |
| **Sandbox Harness** | http://localhost/api/sandbox/docs | LLM test harness |

---

### 5. Stop All Services

```bash
docker compose down
```

To also remove volumes (local Postgres data and downloaded Ollama models):

```bash
docker compose down -v
```

---

## 🧭 Module Deep-Dives

### 📧 Module 1 — Email Monitor

Monitors a real Gmail inbox via **IMAP SSL** and runs every incoming email through an **8-stage threat analysis pipeline**:

```
Incoming Email (IMAP every 10s)
       │
       ├─ 1. Phishing Score      ── RoBERTa → DeBERTa-v3 → DistilBERT cascade
       ├─ 2. AI Text Detection   ── Heuristics + model
       ├─ 3. Credential Scan     ── Regex + NER + Shannon entropy
       ├─ 4. URL Scan            ── PhishGuard XGBoost + 6 modules (per URL)
       ├─ 5. Rule Heuristics     ── Fast rule-based fraud check
       ├─ 6. LLM Analysis        ── qwen3:8b entity extraction via Ollama
       ├─ 7. Voice Deepfake      ── CNN-BiLSTM + RF for audio attachments
       └─ 8. Multilingual Fraud  ── Rule Engine + XGBoost + LLM ensemble
               │
               ▼
       Weighted Risk Score (0–100)
       LOW < 30 | MEDIUM 30–49 | HIGH 50–69 | CRITICAL ≥ 70
```

**Risk aggregation weights:**
```
Phishing (25%) + URL scan (20%) + LLM (15%) + Multilingual (15%)
+ Credentials (15%) + Voice (10%)
```

---

### 🔒 Module 2 — DLP Gateway

Intercepts employee prompts sent to external AI tools (ChatGPT, Gemini, etc.) and scans for sensitive data using an **11-layer asynchronous engine**:

| Layer | Type | Detects |
|-------|------|---------|
| L1 | Regex | API keys, passwords, tokens, private keys |
| L2 | Regex + Luhn | Credit cards, IFSC, account numbers |
| L3 | Regex + GLiNER NER | PII — names, DOB, Aadhaar, PAN, SSN |
| L4 | Regex | Confidential document markers |
| L5 | Regex | Employee/HR data (salaries, ratings) |
| L6 | Regex | Business strategy / IP |
| L7 | Shannon Entropy | High-entropy secrets (JWT, API keys) |
| L8 | RapidFuzz | Fuzzy/typo-obfuscated keywords |
| L9 | Unicode + Base64 | Invisible chars, base64-encoded secrets |
| L10 | Regex | Data exfiltration intent |
| **L11** | **Mistral 7B (LLM)** | **Semantic/implicit leakage, jailbreaks** |

**Decision:** `PASS` (< 30) / `WARN` (30–54) / `BLOCK` (≥ 55)

---

### 💉 Module 3 — Prompt Guard

5-layer middleware that protects LLM chatbots from **prompt injection attacks**:

| Layer | Method | Description |
|-------|--------|-------------|
| 1 | Regex | Known injection phrases ("ignore instructions", "DAN mode") |
| 2 | YARA Rules | Complex multi-pattern injection signatures |
| 3 | Transformer | HuggingFace text classifier |
| 4 | Canary Token | Secret token injected into system prompt; detects fishing |
| **5** | **ProtectAI DeBERTa v2** | **Binary classifier — INJECTION / BENIGN** |

Also supports **multi-turn attack detection** — catches gradual manipulation across conversation history.

**Block threshold:** DeBERTa confidence ≥ 82%

---

### 🎙️ Module 4 — Voice Scanner (Deepfake Detection)

Custom **CNN-BiLSTM** model trained on the **ASVspoof 2019 LA** dataset:

```
Audio Input (WAV/MP3/FLAC/OGG/M4A)
      │
   Librosa (16kHz, mono)
      │
   MFCC Extraction (40 coefficients, N_FFT=1024, Hop=512)
      │
      ├─ CNN Block: Conv1D(40→64→128) + BN + ReLU + MaxPool
      ├─ BiLSTM:    hidden=64, 2 layers, bidirectional
      ├─ Mean Pool  (temporal aggregation)
      └─ Classifier Head: Linear(128→64→1) + Sigmoid
      │
   Deep Score (85% weight)
      │
   Random Forest on MFCC aggregates (15% weight)
      │
   Score Calibration
      │
   Risk (0–100): LOW / MEDIUM / HIGH / CRITICAL
      │
   SHAP Top-5 indicators + LLM explanation (Ollama)
```

**Real-time WebSocket** (`/ws/realtime`) accepts PCM Float32 at 16kHz and returns verdicts every 3 seconds.

**Risk Tiers:**
- 🔴 **CRITICAL (≥86):** BLOCK — trigger incident response
- 🟠 **HIGH (61–85):** BLOCK — escalate to security team
- 🟡 **MEDIUM (31–60):** FLAG — human reviewer within 1 hour
- 🟢 **LOW (0–30):** ALLOW — log and monitor

---

### 🔑 Module 5 — Credential Scanner

Hybrid credential detector scanning emails, documents, and text for exposed secrets:

```
Input: Plain text, .eml, .pdf, .docx, .png, .jpg
       │
   Layer 2: TruffleHog-style Regex  (AWS keys, GitHub tokens, passwords, sort codes)
   Layer 3: Shannon Entropy         (high-randomness secrets)
   Layer 4: NLTK NER                (names, organisations, emails, phones)
   Layer 5: LLM (Ollama llama3)     (semantic understanding — optional)
       │
   Context Analysis → context_multiplier
   Risk Scoring → Clean / Low / Medium / High / Critical
```

Accepts file upload or raw text via web UI or REST API.

---

### 📎 Module 6 — Attachment Scanner

Deep static analysis of email attachments through **4 structured phases**:

1. **File Type Detection** — Magic bytes vs declared extension (mismatch = Critical)
2. **Deep Content Analysis** — Type-specific analyzers run in parallel:
   - PDF: pikepdf + PyMuPDF + pdfminer (object tree, streams, URLs)
   - Office: VBA macros, DDE injection, remote templates, XLM
   - PE (`.exe`/`.dll`): Import table, section entropy, packer detection
   - ZIP/Archive: Payload extraction, path traversal detection
   - **YARA Engine:** 1900+ community rules (ransomware, shellcode, LOLBins)
3. **Hash Reputation** — MD5/SHA1/SHA256 against malware database
4. **Risk Verdict** — Scored with tier multipliers; Critical findings carry 2× bonus weight

---

### 🌐 Module 7 — Website Spoofing (PhishGuard v3)

ML-powered URL and website analysis combining **XGBoost + 6 live security checks**:

| Check | What it Does |
|-------|-------------|
| **XGBoost ML** | 27 structural URL features → PHISHING / SAFE (PhiUSIIL dataset) |
| **SSL Validator** | Live port-443 handshake, cert expiry, trusted issuer, SNI mismatch |
| **WHOIS/DNS** | Domain age (<30 days), DNS resolution, dead domain penalty (+30%) |
| **Cookie Inspector** | Missing `HttpOnly`/`Secure` flags, exposed JWT session tokens |
| **URL Encoding** | Double-encoding (`%2520`), obfuscation detection |
| **HTML Scraper** | Hidden login forms, external `<form action>`, iFrames |

**Also includes:** Chrome Extension (Manifest V3) for real-time browser-side scanning with live cookie analysis.

---

### 📨 Module 8 — SMTP Fraud Gateway

Acts as a **transparent SMTP proxy** for outgoing emails:

```
Mail Client → :2525 SMTP Handler
                    │
           Multilingual Fraud Engine
           ┌────────────────────────┐
           │  Language Detection    │
           │  Rule Engine           │
           │  XGBoost classifier    │
           │  Ollama LLM            │
           │  Homograph detection   │
           │  Suspicious domain DB  │
           │  AI content detector   │
           └────────────────────────┘
                    │
         PASS → smtp.gmail.com:587 → Delivered
         REJECT → Bounce + security notice
         QUARANTINE → Held for review
```

REST API at `:8010` is also called by the Email Monitor for multilingual fraud scoring on incoming emails.

---

### 🧪 Module 9 — Sandbox Harness

Isolated environment for security research and testing:

- **Ollama LLM runtime** with `tinyllama` auto-loaded
- Upload DLP test payloads and see how the LLM responds
- Generate benchmark reports (`dlp_test_suite.py`)
- Test prompt injection payloads safely without production impact
- Results and reports persisted in `sandbox/results/` and `sandbox/reports/`

---

## 📁 Project Structure

```
hack-o-hire-2.0-master/
│
├── docker-compose.yml              # Orchestrates all 13 containers
├── nginx/
│   └── nginx.conf                  # Reverse proxy routing rules
│
├── Frontend/                       # React 18 + Vite dashboard
│   ├── src/
│   ├── package.json
│   └── vite.config.js
│
├── email_monitoring/               # Module 1 — Email Monitor
│   ├── email_api.py                # FastAPI server (port 8009)
│   ├── imap_worker.py              # Background IMAP poller
│   ├── email_db.py                 # PostgreSQL ORM
│   └── src/                        # Phishing scorer, pipeline, Ollama, etc.
│
├── dlp-gateway/                    # Module 2 — DLP Gateway
│   ├── detection/
│   │   ├── engine.py               # 11-layer async engine
│   │   └── patterns.py             # Regex pattern library
│   ├── gateway/                    # FastAPI router
│   ├── models/                     # GLiNER model weights
│   └── browser-extension/          # Chrome extension for DLP
│
├── fraudshield-prompt-guard/       # Module 3 — Prompt Guard
│   └── src/
│       ├── api.py                  # FastAPI server (port 8005)
│       ├── local_guard.py          # ProtectAI DeBERTa v2 wrapper
│       ├── regex_scanner.py
│       ├── yara_scanner.py
│       ├── transformer_detector.py
│       └── canary.py
│
├── fraudshield-voice/              # Module 4 — Voice Scanner
│   └── src/
│       ├── api.py                  # FastAPI + WebSocket (port 8006)
│       ├── model.py                # CNN-BiLSTM architecture
│       ├── features.py             # MFCC extraction
│       ├── evaluate.py             # Inference pipeline
│       ├── train.py                # Training script
│       └── config.py               # Hyperparameters
│
├── Credential_Scanner-main/        # Module 5 — Credential Scanner
│   ├── main.py                     # FastAPI server (port 8002)
│   ├── patterns.py
│   ├── entropy.py
│   ├── ner_detector.py
│   └── llm_analyzer.py
│
├── attachment_scanner/             # Module 6 — Attachment Scanner
│   ├── attachment_main.py          # 4-phase orchestrator
│   ├── pdf_analyzer.py
│   ├── office_analyzer.py
│   ├── pe_analyzer.py
│   ├── zip_analyzer.py
│   ├── pattern_engine.py           # YARA engine
│   └── yara_rules/                 # 1900+ community rules
│
├── website_spoofing_model-main/    # Module 7 — PhishGuard
│   ├── flask_api.py                # Flask server (port 8008/5000)
│   ├── app/
│   │   ├── predictor.py            # XGBoost wrapper
│   │   ├── ssl_checker.py
│   │   ├── whois_checker.py
│   │   ├── cookie_detector.py
│   │   └── html_analyzer.py
│   ├── models/
│   │   └── url_phishing_xgboost_v3.pkl
│   ├── dashboard/
│   │   └── index.html
│   └── extension/                  # Chrome Extension (Manifest V3)
│
├── smtp-fraud-gateway/             # Module 8 — SMTP Fraud Gateway
│   └── src/
│       ├── main.py                 # SMTP + FastAPI (ports 2525 / 8010)
│       ├── multilingual_analyzer.py
│       ├── lang_detector.py
│       └── llm_classifier.py
│
├── sandbox/                        # Module 9 — Sandbox Harness
│   ├── harness/
│   ├── payloads/
│   ├── results/
│   └── docker/
│
├── prompt-injection/               # Fine-tuned prompt injection model
│   └── best_model/                 # Local model weights directory
│
├── seed_dlp.ps1                    # PowerShell script to seed DLP policies
├── start-dev.ps1                   # Dev startup script (Windows)
├── smtp_demo.py                    # SMTP demo script
└── test_gateway.py                 # Gateway test suite
```

---

## 🛠️ Tech Stack

### Backend
| Technology | Version | Used For |
|-----------|---------|---------|
| **Python** | 3.10+ | All backend services |
| **FastAPI** | Latest | REST APIs for 8 services |
| **Flask** | Latest | PhishGuard website spoofing |
| **Uvicorn** | Latest | ASGI server |
| **Pydantic** | v2 | Request/response validation |

### Machine Learning
| Technology | Used For |
|-----------|---------|
| **PyTorch** | Custom CNN-BiLSTM voice model |
| **HuggingFace Transformers** | DeBERTa v2, RoBERTa, DistilBERT, DeBERTa-v3 |
| **XGBoost** | URL phishing + voice ensemble |
| **scikit-learn** | Random Forest, calibration |
| **GLiNER** | Zero-shot NER for PII |
| **NLTK** | NER in credential scanner |
| **Librosa** | Audio loading, MFCC, mel spectrograms |
| **SHAP** | Model explainability |
| **RapidFuzz** | Fuzzy keyword matching |

### LLM / Generative AI
| Technology | Models | Used For |
|-----------|--------|---------|
| **Ollama** | `qwen3:8b` | Email analysis & summarization |
| **Ollama** | `mistral:7b-instruct-q4_K_M` | DLP semantic scan (Layer 11) |
| **Ollama** | `tinyllama` | Sandbox + voice explanation |
| **Ollama** | `llama3` / `llama3.2` | Prompt guard chatbot backend |

### Security & Scanning
| Technology | Used For |
|-----------|---------|
| **YARA** | 1900+ malware pattern rules (attachment scanner) |
| **pikepdf** | PDF object tree analysis |
| **PyMuPDF (fitz)** | PDF text + URL extraction |
| **pdfminer.six** | PDF stream text |
| **python-magic** | Magic byte MIME detection |
| **python-docx** | Office document analysis |
| **python-whois** | Domain registration lookup |

### Infrastructure
| Technology | Used For |
|-----------|---------|
| **Docker** | All services containerised |
| **Docker Compose** | 13-container orchestration |
| **Nginx** | Reverse proxy + static SPA |
| **PostgreSQL 16** | Shared relational database |
| **Redis 7** | DLP gateway caching |
| **MailHog** | Development email testing |

### Frontend
| Technology | Used For |
|-----------|---------|
| **React 18** | UI framework |
| **Vite** | Build tool |
| **TailwindCSS** | Styling |
| **PostCSS** | CSS processing |

---

## 📡 API Reference

All APIs are accessible through Nginx at `http://localhost`. Each service also exposes interactive Swagger UI at its `/docs` path.

### Email Monitor (`/api/email/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/emails` | List emails with filters (risk, search, unread) |
| `GET` | `/emails/{id}` | Get single email details |
| `POST` | `/emails/{id}/analyze` | Trigger full 8-stage analysis |
| `POST` | `/emails/{id}/flag` | Toggle flagged state |
| `GET` | `/emails/{id}/attachments/{att_id}/download` | Download attachment |
| `POST` | `/emails/{id}/attachments/{att_id}/analyze` | Analyze attachment |
| `POST` | `/emails/{id}/feedback` | Submit analyst correction |
| `GET` | `/stats` | Email statistics dashboard |
| `POST` | `/admin/retrain` | Trigger model retraining |

### DLP Gateway (`/api/dlp/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Scan text for sensitive data (11 layers) |
| `GET` | `/ws/live` | WebSocket — live DLP alerts |
| `GET` | `/policies` | List active DLP policies |
| `GET` | `/audit` | Audit log of all scans |

### Prompt Guard (`/api/prompt-guard/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/guard/check` | Check prompt for injection (5 layers) |
| `POST` | `/guard/sanitize` | Sanitize a suspicious prompt |
| `POST` | `/guard/check-output` | Check LLM output for canary leak |
| `GET` | `/guard/canary/{session_id}` | Generate canary token |
| `POST` | `/chat/v2` | Full middleware demo — guard + Ollama LLM |
| `GET` | `/stats` | Guard statistics |

### Voice Scanner (`/api/voice-scan/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze/voice` | Analyze audio file for deepfake |
| `WS` | `/ws/realtime` | Real-time PCM stream analysis |
| `GET` | `/history` | Recent scan history |
| `POST` | `/feedback/{id}` | Submit REAL/FAKE correction |
| `POST` | `/admin/retrain` | Trigger retraining |

### Credential Scanner (`/api/cred-scan/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan/text` | Scan plain text |
| `POST` | `/scan/file` | Scan uploaded file (.pdf, .docx, .eml, etc.) |
| `POST` | `/analyze/email` | Scan email content |

### Attachment Scanner (`/api/attachment-scan/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Full 4-phase attachment analysis |

### Website Spoofing (`/api/website-spoofing/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Analyze URL (XGBoost + 6 modules) |

### SMTP Gateway (`/api/smtp-gateway/`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Analyze email for multilingual fraud |
| `GET` | `/history` | Recent SMTP scan history |

---

## ⚙️ Configuration

### Environment Variables

#### DLP Gateway (`dlp-gateway/.env`)
```env
POSTGRES_URL=postgresql+asyncpg://dlp:dlp@postgres:5432/dlp
REDIS_URL=redis://redis:6379
SMTP_HOST=mailhog
SMTP_PORT=1025
OLLAMA_URL=http://sandbox-ollama:11434
HF_HUB_OFFLINE=1                    # Use cached HuggingFace models only
TRANSFORMERS_OFFLINE=1
```

#### Prompt Guard
```env
LOCAL_GUARD_MODEL_PATH=/app/prompt-injection/best_model   # fine-tuned local model
OLLAMA_HOST=http://sandbox-ollama:11434
PROMPT_GUARD_MODEL=protectai/deberta-v3-base-prompt-injection-v2
```

#### Email Monitor (in `docker-compose.yml`)
```env
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USE_SSL=true
IMAP_USER=your-email@gmail.com
IMAP_PASSWORD=your-16-char-app-password
POLL_INTERVAL=10                     # seconds between inbox checks
OLLAMA_HOST=http://sandbox-ollama:11434
SMTP_GATEWAY_URL=http://smtp-fraud-gateway:8010
```

#### SMTP Fraud Gateway
```env
FORWARD_SMTP_HOST=smtp.gmail.com
FORWARD_SMTP_PORT=587
FORWARD_SMTP_USER=your-email@gmail.com
FORWARD_SMTP_PASS=your-smtp-password
GATEWAY_SMTP_PORT=2525
```

---

## 🧑‍💻 Development

### Running Individual Services

To run a single service for development (outside Docker):

```bash
# Example: Run Email Monitor
cd email_monitoring
pip install -r requirements.txt
python email_api.py

# Example: Run Prompt Guard
cd fraudshield-prompt-guard
pip install -r requirements.txt
python src/api.py

# Example: Run Voice Scanner
cd fraudshield-voice
pip install -r requirements.txt
python src/api.py
```

### Running the Frontend

```bash
cd Frontend
npm install
npm run dev        # dev server with hot reload
npm run build      # production build
```

### Seeding DLP Policies (Windows)

```powershell
.\seed_dlp.ps1
```

### Testing the SMTP Gateway

```bash
python smtp_demo.py
python test_gateway.py
```

### Training the Voice Model

```bash
cd fraudshield-voice
python src/train.py       # requires ASVspoof 2019 LA dataset
```

---

## 🔑 Key Design Decisions

### 1. Offline-First LLMs
All LLMs run **locally via Ollama** — zero data leaves the organisation. Critical for GDPR/DPDP compliance in banking.

### 2. Fail-Open Safety
ML models that fail to load return a **benign verdict** rather than blocking all traffic. Prevents denial-of-service from model failures.

### 3. Multi-Layer Defence-in-Depth
Every threat has **multiple independent detection layers**. An attacker must evade all layers simultaneously to succeed.

### 4. Score Fusion (Ensemble)
Multiple models vote and their scores are **weighted and fused** — no single point of failure or bias.

### 5. Human-in-the-Loop Retraining
Analysts submit corrections → corrections queue → admin triggers retraining. Models improve from real-world feedback without manual dataset curation.

### 6. Canary Tokens
Unique secret strings are embedded in LLM system prompts. If user input attempts to extract the system prompt, the canary appears in output and is immediately flagged.

### 7. Async Parallel Scanning
DLP Engine runs fast detection layers in parallel using `asyncio.gather()` — keeps latency low even with 11 layers.

---

## 📊 Performance Characteristics

| Module | Approx. Latency | Notes |
|--------|----------------|-------|
| Email Monitor (full pipeline) | 5–15 seconds | Depends on URL count & audio attachments |
| DLP Gateway (L1–L10) | 50–200ms | Fully async, parallel layers |
| DLP Gateway (L11 Mistral) | 5–60 seconds | LLM scan — sync, fail-open on timeout |
| Prompt Guard (DeBERTa) | 100–300ms | CPU: ~300ms, GPU: <100ms |
| Voice Scanner (file) | 1–5 seconds | Depends on audio length |
| Credential Scanner | 200ms–5s | Depends on file size |
| Attachment Scanner | 500ms–10s | YARA + deep analysis |
| PhishGuard URL Scan | 1–10 seconds | WHOIS/DNS lookups are slowest |

---

## 🤝 Contributors

The baseline platform was built for **Barclays Hack-O-Hire 2.0** by its original team
([original repository](https://github.com/OnkarNanaware/Barclay-s-Hackathon)). The work in
this repository is by the team listed under [Project Status & Origin](#-project-status--origin).

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with 🛡️ for the security of tomorrow's banking ecosystem**

</div>
