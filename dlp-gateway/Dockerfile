FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install all dependencies (torch/gliner excluded — GLiNER is optional, NER gracefully disabled)
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV HF_HUB_OFFLINE=1
ENV TRANSFORMERS_OFFLINE=1
ENV HF_DATASETS_OFFLINE=1
# GLiNER model path — if absent, engine falls back to regex-only (10 layers still active)
ENV GLINER_MODEL_PATH=/app/models/gliner_medium

EXPOSE 8001
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8001"]
