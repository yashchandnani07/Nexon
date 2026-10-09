# Setup

## 1. What you need installed

- Git
- Docker Desktop (or Docker Engine) with Docker Compose v2. Check with `docker compose version`.
- Node.js 20 (frontend owner only)
- Python 3.10 or 3.11 (only if you want to run one service without Docker)

## 2. Get the repository

```bash
git clone https://github.com/yashchandnani07/Nexon.git
```

```bash
cd Nexon
```

This `Nexon` folder is your **repo folder**. Your older copy of the project, the one already
on your machine, is your **local project folder**. The import issues tell you which folders
to copy from the local project folder into the repo folder.

## 3. Create your `.env`

```bash
cp .env.example .env
```

Open `.env` and paste the `DATABASE_URL` and `POSTGRES_URL` values Yash sent you privately.
Both describe the same shared database, in two formats. See [DATABASE.md](DATABASE.md).

`.env` is gitignored. Check it with:

```bash
git status --short
```

`.env` must not appear in that list. If it does, stop and ask in the team chat.

The DLP gateway also reads its own settings file:

```bash
cp dlp-gateway/.env.example dlp-gateway/.env
```

## 4. Run one service

You rarely need the whole stack. Build and run only the service you are working on:

```bash
docker compose up --build credential-scanner
```

Replace `credential-scanner` with your service name:

| Folder | Compose service name | URL on your machine |
|---|---|---|
| `Credential_Scanner-main/` | `credential-scanner` | http://localhost:8002 |
| `attachment_scanner/` | `attachment-scanner` | http://localhost:8007 |
| `website_spoofing_model-main/` | `website-spoofing` | http://localhost:8008 |
| `smtp-fraud-gateway/` | `smtp-fraud-gateway` | http://localhost:8010 (SMTP on 2525) |
| `sandbox/` | `sandbox-harness` | http://localhost:8000 |
| `fraudshield-prompt-guard/` | `prompt-guard` | http://localhost:8005 |
| `fraudshield-voice/` | `voice-scanner` | http://localhost:8006 |
| `email_monitoring/` | `email-monitor` | http://localhost:8009 |
| `dlp-gateway/` | `dlp-gateway` | http://localhost:8001 |
| `retrain-scheduler/` | `retrain-scheduler` | http://localhost:9000 |
| `Frontend/` + `nginx/` | `frontend-builder`, `nginx` | http://localhost |

Every FastAPI service has interactive docs at `/docs`, for example http://localhost:8002/docs.

## 5. Run everything

```bash
docker compose up --build
```

The first build downloads several gigabytes of Python packages and models. Start it early.

Stop everything:

```bash
docker compose down
```

Do **not** add `-v`. With the shared database it is harmless, but it deletes downloaded
Ollama models and you will wait for them again.

## 6. Run the frontend with hot reload

```bash
cd Frontend
```

```bash
npm install
```

```bash
npm run dev
```

Open http://localhost:5173. The Vite dev server proxies `/api/...` to the backend services
on your machine, so the services you need must be running through Docker.

## 7. Model files

Model weights are not stored in git (they are too large). Each service either downloads its
model during `docker build` or trains a small one at build time. If a service logs
"model not found", copy that service's `models/` folder from your local project folder into
the same place in the repo folder. `models/` is gitignored, so it will not be committed.

## 8. If something fails

| Symptom | Fix |
|---|---|
| `DATABASE_URL is not set` | You have no `.env` in the repo root, or it has no `DATABASE_URL=` line |
| `connection refused` / `could not translate host name` | The URL in `.env` is wrong, or your network blocks port 5432 |
| `SSL connection is required` | Add `?sslmode=require` to the end of `DATABASE_URL` |
| `too many connections` | Someone left a loop running. Stop your containers with `docker compose down` |
| `port is already allocated` | Another copy of the stack is running. `docker compose down`, then retry |
| Frontend shows zeros everywhere | The service is down, or its `/summary` endpoint is not merged yet |
