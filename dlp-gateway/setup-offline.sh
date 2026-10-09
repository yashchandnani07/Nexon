#!/bin/bash
# setup-offline.sh
# Run ONCE with internet. After this, everything works air-gapped forever.

set -e

echo "======================================"
echo " Guardrail-DLP Offline Setup"
echo " Run this ONCE with internet access."
echo "======================================"

# 1. Pull all Docker base images
echo ""
echo "[1/5] Pulling Docker base images..."
docker pull python:3.11-slim
docker pull node:20-alpine
docker pull postgres:16-alpine
docker pull redis:7-alpine
docker pull nginx:alpine
docker pull ollama/ollama:latest
docker pull mailhog/mailhog:latest

# 2. Pull Ollama LLM model (mistral 7B quantized — ~4GB, best for finance security tasks)
echo ""
echo "[2/5] Pulling Ollama model (this takes 5-10 min on first run)..."
docker compose up -d ollama
echo "Waiting for Ollama to start..."
sleep 15
docker exec guardrail-dlp-ollama-1 ollama pull mistral:7b-instruct-q4_K_M
echo "Model downloaded. Stopping temporary Ollama container..."
docker compose stop ollama

# 3. Pre-download GLiNER model into ./models folder (baked into Docker image)
echo ""
echo "[3/5] Downloading GLiNER NER model..."
mkdir -p ./models
pip install gliner transformers torch --quiet
python - <<'EOF'
import os, shutil
from gliner import GLiNER
from transformers import AutoTokenizer

MODEL_NAME = "urchade/gliner_medium-v2.1"
SAVE_DIR = "./models/gliner_medium"
TOKENIZER_SAVE_DIR = "./models/deberta-tokenizer"

print(f"Downloading GLiNER model: {MODEL_NAME}")
model = GLiNER.from_pretrained(MODEL_NAME)
model.save_pretrained(SAVE_DIR)
print(f"GLiNER saved to {SAVE_DIR}")

print("Downloading tokenizer: microsoft/mdeberta-v3-base")
tok = AutoTokenizer.from_pretrained("microsoft/mdeberta-v3-base")
tok.save_pretrained(TOKENIZER_SAVE_DIR)
print(f"Tokenizer saved to {TOKENIZER_SAVE_DIR}")
EOF

# 4. Pre-install node_modules for the React dashboard
echo ""
echo "[4/5] Installing React dashboard dependencies..."
cd dashboard && npm install && cd ..

# 5. Build all Docker images (caches everything)
echo ""
echo "[5/5] Building all Docker images (caches layers)..."
docker compose build

echo ""
echo "======================================"
echo " ✅ Offline setup complete!"
echo " You can now disconnect from internet."
echo " Run: docker compose up"
echo "======================================"
