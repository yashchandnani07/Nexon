# How we work in this repo

Read this once before your first commit. It is short.

## 1. Who owns what

| Owner | GitHub | Folders (only this person edits them) |
|---|---|---|
| Aditya | @adityarandive10 | `Frontend/` |
| Manash | @manash008 | `Credential_Scanner-main/`, `attachment_scanner/` |
| Mitanshu | @mitanshu007 | `website_spoofing_model-main/`, `smtp-fraud-gateway/` |
| Yash | @yashchandnani07 | `sandbox/`, `dlp-gateway/`, `email_monitoring/`, `fraudshield-prompt-guard/`, `prompt-injection/`, `fraudshield-voice/`, `retrain-scheduler/`, `outlook-plugin/`, `nginx/`, `docker-compose.yml`, `docs/`, root files |

**Stay inside your folders.** If you need a change in someone else's folder, comment on
their issue or open a new issue and assign it to them. This is what keeps four people from
overwriting each other.

## 2. Two kinds of issues, two ways to push

### A. "Import baseline" issues → push directly to `main`

These issues bring an existing module folder into the repo. Nobody else touches your
folders, so there is nothing to review and no conflict to resolve.

```bash
git checkout main
```

```bash
git pull --rebase origin main
```

Copy the folder(s) named in the issue from your local project folder into the repo folder, then:

```bash
git add <folder>
```

```bash
git status --short
```

Read the list. Stop if you see `.env`, `*.db`, `node_modules`, `*.log`, or any personal file.

```bash
git commit -m "chore(<module>): import baseline <module> module"
```

```bash
git pull --rebase origin main
```

```bash
git push origin main
```

### B. Every other issue → branch, small pushes, pull request

```bash
git checkout main
```

```bash
git pull --rebase origin main
```

```bash
git checkout -b feat/<issue-number>-<short-name>
```

Example: `git checkout -b feat/7-credential-scan-history`

Work in small steps. **Commit and push after each step that works**, not once at the end:

```bash
git add <files you changed>
```

```bash
git commit -m "feat(credential-scanner): add db.py with credential_scans table"
```

```bash
git push -u origin feat/<issue-number>-<short-name>
```

When the checklist in the issue is complete, open a pull request into `main`. Put
`Closes #<issue-number>` in the description. Merge it yourself once your service builds and
the "How to test" steps in the issue pass. Use **Squash and merge** only if your branch has
messy commits; otherwise use a normal merge.

## 3. `main` must always build

Before every push to `main` and before merging any PR, build your service:

```bash
docker compose build <service-name>
```

Service names are listed in [docs/SETUP.md](docs/SETUP.md). If the build fails, fix it before pushing.

## 4. Commit messages

Format: `<type>(<module>): <what changed>`

| Type | Use for |
|---|---|
| `feat` | new behaviour (an endpoint, a table, a page reading live data) |
| `fix` | a bug fix |
| `refactor` | moving code without changing behaviour |
| `docs` | README or `docs/` only |
| `chore` | imports, dependencies, config, cleanup |
| `test` | tests only |

Modules: `frontend`, `credential-scanner`, `attachment-scanner`, `website-spoofing`,
`smtp-gateway`, `sandbox`, `prompt-guard`, `voice`, `email-monitor`, `dlp`, `scheduler`, `infra`.

Good: `feat(smtp-gateway): load trusted domains from smtp_domain_lists table`
Bad: `update`, `changes`, `final`, `fix bug`

Write what the commit really does. One logical change per commit.

## 5. Never commit these

- `.env` files or anything with a real password, token, API key or database URL
- `*.db`, `*.sqlite` files
- `node_modules/`, `Frontend/dist/`, `__pycache__/`, `venv/`
- `*.log`, `logs.txt`, `plogs.txt`
- `email_monitoring/extracted_attachments/` (real people's files)
- model weights (`models/`, `*.pt`, `*.bin`, `*.joblib`, `*.gguf`)

`.gitignore` already blocks all of these. Do not use `git add -f` to get around it.

If you commit a secret by accident, **tell the team immediately**. The secret must be
changed; deleting the commit is not enough on a public repo.

## 6. Branding

Do not add the names of banks, events or other organisations to titles, comments, sample
data, commit messages or docs. Use neutral names (`example-bank.com`, `AegisAI`). Detection
keyword lists that exist to catch impersonation of well-known brands are functional and stay.

## 7. Documentation is part of the task

Every issue ends with a "Docs" checkbox. A PR that adds an endpoint or a table without
updating the module `README.md` (and `docs/DATABASE.md` when a table changes) is not finished.

## 8. Working with an AI assistant

Each issue has a section named **Prompt for your AI assistant**. Paste it, together with the
files it names, into your assistant. Before you accept what it gives you:

- It must use the `db.py` template from [docs/DATABASE.md](docs/DATABASE.md), not its own.
- It must use `%s` placeholders, never `?`.
- It must not add SQLite, a new ORM, or a new framework.
- It must not rename existing endpoints or change their response shape.
- It must not put the database URL in the code.

Run the "How to test" steps yourself. Do not push code you have not run.

## 9. When you are stuck for more than 15 minutes

Comment on your issue with: what you ran, the full error text, and what you already tried.
Then tag the owner you need.
