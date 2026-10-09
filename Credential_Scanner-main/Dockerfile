FROM python:3.10-slim

# Install system dependencies for OCR and image processing
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    poppler-utils \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install torch (CPU-only wheel – much smaller image than the default GPU wheel)
RUN pip install --no-cache-dir torch --extra-index-url https://download.pytorch.org/whl/cpu

# Copy requirements and install remaining deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Pre-download the BERT PII-detection model at build time so the first
# request is fast (model weights are baked into the image layer).
RUN python - <<'EOF'
from transformers import AutoTokenizer, AutoModelForTokenClassification
model_name = "SoelMgd/bert-pii-detection"
AutoTokenizer.from_pretrained(model_name)
AutoModelForTokenClassification.from_pretrained(model_name)
print("BERT PII model cached successfully.")
EOF

# Expose port
EXPOSE 8002

# Run the FastAPI server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]

