#!/usr/bin/env bash
# Repository checks run by CI and runnable locally: scripts/ci_checks.sh [files|content|branding|compose|all]
# Only reads tracked files. Never prints a matched secret value, only file and line.
set -u
cd "$(git rev-parse --show-toplevel)"
fail=0

check_files() {
  echo "== forbidden files"
  bad=$(git ls-files | grep -E '\.env($|\.local$)|\.(db|sqlite|sqlite3|pem|key|pfx|log)$|(^|/)(logs|plogs)\.txt$|__pycache__|(^|/)node_modules/|(^|/)Frontend/dist/|extracted_attachments/|(^|/)smtp-fraud-gateway-2/' || true)
  if [ -n "$bad" ]; then echo "::error::These files must not be tracked:"; echo "$bad"; fail=1; else echo "ok"; fi
}

check_branding() {
  echo "== third-party / event branding"
  hits=$(git grep -nIiE 'barclay|brclay|hack-o-hire' -- . ':!scripts/ci_checks.sh' ':!.github/workflows/ci.yml' | cut -d: -f1,2 || true)
  if [ -n "$hits" ]; then echo "::error::Branding found (use neutral names like example-bank.com):"; echo "$hits"; fail=1; else echo "ok"; fi
}

check_content() {
  echo "== secrets in file contents"
  local out=""
  # provider tokens and private keys (the AWS docs example key is allowed)
  p1=$(git grep -nIE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[bp]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9]{32,}|-----BEGIN [A-Z ]*PRIVATE KEY-----' -- . ':!*.md' ':!.env.example' | grep -v 'AKIAIOSFODNN7EXAMPLE' | cut -d: -f1,2 || true)
  [ -n "$p1" ] && out="$out"$'\n'"[token or private key]"$'\n'"$p1"
  # database URLs with credentials, except local defaults, placeholders and variable references
  p2=$(git grep -nIE 'postgres(ql)?(\+[a-z0-9]+)?://[^:/@[:space:]"'"'"']+:[^@[:space:]"'"'"']+@' -- . ':!*.md' ':!.env.example' | grep -vE '@(localhost|127\.0\.0\.1|postgres)(:|/)|USER:PASSWORD@|\$\{|%s|\{[a-z_]+\}|user:pass|username:password' | cut -d: -f1,2 || true)
  [ -n "$p2" ] && out="$out"$'\n'"[database URL with credentials]"$'\n'"$p2"
  # hardcoded password / secret assignments to a non-empty string literal
  p3=$(git grep -nIiE '(password|passwd|secret|api_key|apikey|token)[a-z_]*["'"'"']? *[:=] *["'"'"'][^"'"'"'$ {}<]{8,}["'"'"']' -- '*.py' '*.js' '*.jsx' '*.yml' '*.yaml' '*.ts' ':!*test*' ':!*Test*' ':!*demo*' ':!*sample*' ':!*smoke*' ':!*.min.js' ':!Frontend/src/pages/Login.jsx' | grep -viE 'example|changeme|your[-_]|placeholder|<[a-z_]+>|os\.(getenv|environ)|process\.env|\$\{' | cut -d: -f1,2 || true)
  [ -n "$p3" ] && out="$out"$'\n'"[hardcoded credential]"$'\n'"$p3"
  if [ -n "$out" ]; then echo "::error::Possible secrets (values not shown):$out"; fail=1; else echo "ok"; fi
}

check_compose() {
  echo "== docker compose config"
  if [ -f docker-compose.yml ]; then
    [ -f .env ] || cp .env.example .env
    [ -f dlp-gateway/.env ] || { [ -f dlp-gateway/.env.example ] && cp dlp-gateway/.env.example dlp-gateway/.env; }
    if docker compose config -q; then echo "ok"; else echo "::error::docker-compose.yml is invalid"; fail=1; fi
  else
    echo "docker-compose.yml not on this branch yet, skipped"
  fi
}

case "${1:-all}" in
  files) check_files ;;
  branding) check_branding ;;
  content) check_content ;;
  compose) check_compose ;;
  all) check_files; check_branding; check_content; check_compose ;;
  *) echo "usage: $0 [files|content|branding|compose|all]"; exit 2 ;;
esac
exit $fail
