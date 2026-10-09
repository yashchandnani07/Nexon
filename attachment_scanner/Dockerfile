FROM python:3.10-slim

WORKDIR /app

# Install system dependencies:
#   libmagic1  — python-magic file type detection
#   libzbar0   — pyzbar QR code decoding (image analyzer)
#   zlib1g     — zlib compression support
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libzbar0 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8007

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8007"]
