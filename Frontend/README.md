# 🛡️ AegisAI — Security Operations & Analyst Dashboard

Interactive web dashboard for the AegisAI Fraud Detection & Security Intelligence Platform. Built with React 18, Vite, Tailwind CSS, Framer Motion, and Recharts.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd Frontend
npm install
```

### 2. Run Locally in Development Mode
```bash
npm run dev
```
Starts the Vite development server on `http://localhost:5173`. Proxies `/api/...` requests to backend services running locally or via Docker.

### 3. Build for Production
```bash
npm run build
```
Compiles and bundles the application from source into the `dist/` directory.

### 4. Preview Production Build
```bash
npm run preview
```

---

## 📄 Application Pages (`src/pages/`)

### Analyst & Security Operations Pages
| Page Component | Route / View | Description |
|---|---|---|
| `Dashboard.jsx` | `/` (Dashboard) | Real-time threat feed, cross-service incident metrics, risk tier distribution |
| `EmailPhishing.jsx` | `/email-phishing` | Live email inspection, multilingual NLP phishing scores, header anomalies |
| `EmailDetail.jsx` | `/email-detail` | Detailed audit inspector for individual emails with raw headers & body view |
| `Mailbox.jsx` | `/mailbox` | Inbox monitor view displaying synchronized IMAP mailbox items |
| `CredentialScanner.jsx` | `/credential-scanner` | Secret & token scanner with entropy analysis, NER, and regex detection |
| `AttachmentAnalyzer.jsx` | `/attachment-analyzer` | Drag-and-drop file inspection with YARA rules, PE/Office analysis |
| `WebsiteSpoofing.jsx` | `/website-spoofing` | URL phishing classifier, SSL certificate validator, cookie inspector |
| `DeepfakeVoice.jsx` | `/voice-scanner` | Audio spectrogram and deepfake voice detection with CNN-BiLSTM scores |
| `PromptInjection.jsx` | `/prompt-guard` | LLM prompt injection and jailbreak detection analyzer |
| `PromptGuardChatbot.jsx` | `/prompt-guard-chatbot` | Interactive protected chat interface with real-time prompt guardrail testing |
| `AgentSandbox.jsx` | `/sandbox` | Isolated LLM execution sandbox harness for adversarial prompt testing |
| `FeedbackRetraining.jsx` | `/feedback-retraining` | Analyst feedback queue and human-in-the-loop validation |
| `MyAnalytics.jsx` | `/analytics` | Analyst activity and personal triage performance analytics |
| `Login.jsx` | `/login` | Analyst & admin authentication portal |

### Admin & Policy Pages (`src/pages/admin/`)
| Page Component | Route / View | Description |
|---|---|---|
| `AdminOverview.jsx` | `/admin` | System-wide health status and infrastructure telemetry |
| `AdminPortal.jsx` | `/admin-portal` | User and role management interface |
| `AdminAnalytics.jsx` | `/admin-analytics` | Comprehensive organizational fraud analytics and trend visualizations |
| `DLPGuardian.jsx` | `/admin/dlp` | Data Loss Prevention rules, policies, and outbound AI leakage monitor |
| `ModelAnalytics.jsx` | `/admin/model-analytics` | Model performance, drift tracking, and confusion matrices |
| `ModelPolicies.jsx` | `/admin/policies` | Threshold policy definitions and automated action rules |
| `ModelRetraining.jsx` | `/admin/retraining` | Model retraining pipeline orchestrator and dataset versioning |
| `PromptMonitor.jsx` | `/admin/prompt-monitor` | Production LLM guardrail monitor |
| `SandboxMonitor.jsx` | `/admin/sandbox-monitor` | Sandbox VM status and payload experiment audit log |

---

## 🔌 API Proxy Configuration (`vite.config.js`)

In development, Vite proxies the following path prefixes to local backend microservices:

| Prefix | Target Service | Local URL | Rewrite Behavior |
|---|---|---|---|
| `/api/dlp` | DLP Gateway | `http://localhost:8001` | Strips `/api/dlp` |
| `/api/sandbox` | Sandbox Harness | `http://localhost:8000` | Strips `/api/sandbox` |
| `/api/prompt-guard` | Prompt Guard | `http://127.0.0.1:8005` | Strips `/api/prompt-guard` |
| `/api/voice-scan/ws` | Voice Scanner (WebSocket) | `ws://localhost:8006` | Strips `/api/voice-scan` (WS enabled) |
| `/api/voice-scan` | Voice Scanner (HTTP) | `http://localhost:8006` | Strips `/api/voice-scan` |
| `/api/website-spoofing` | Website Spoofing API | `http://localhost:8008` | Strips `/api/website-spoofing` |
| `/api/attachment-scan` | Attachment Scanner | `http://localhost:8007` | Strips `/api/attachment-scan` |
| `/api/cred-scan` | Credential Scanner | `http://localhost:8002` | Strips `/api/cred-scan` |
| `/api/email` | Email Monitor | `http://localhost:8009` | Strips `/api/email` |
| `/api/smtp-gateway` | SMTP Fraud Gateway | `http://localhost:8010` | Strips `/api/smtp-gateway` |
| `/api/retrain-scheduler` | Retrain Scheduler | `http://localhost:9000` | Strips `/api/retrain-scheduler` |
| `/ws/live` | Live WebSocket Hub | `ws://localhost:8001` | Passthrough (WS enabled) |
