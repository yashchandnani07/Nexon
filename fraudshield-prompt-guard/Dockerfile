FROM python:3.10-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --default-timeout=2000 --no-cache-dir -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu

# Pre-download ProtectAI DeBERTa Prompt Guard v2 at build time
# so the container starts instantly without network access at runtime.
ARG PROMPT_GUARD_MODEL=protectai/deberta-v3-base-prompt-injection-v2
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
    AutoTokenizer.from_pretrained('${PROMPT_GUARD_MODEL}'); \
    AutoModelForSequenceClassification.from_pretrained('${PROMPT_GUARD_MODEL}')"

# Copy application source
COPY . .

# Adjust Python path to load from src
ENV PYTHONPATH=/app/src
ENV PROMPT_GUARD_MODEL=${PROMPT_GUARD_MODEL}

# Expose port
EXPOSE 8005

# Run the FastAPI server
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8005"]
