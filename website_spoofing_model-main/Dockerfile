FROM python:3.10-slim

WORKDIR /app

# Install system dependencies if required for ML (libgomp for lightgbm/xgboost usually)
RUN apt-get update && apt-get install -y \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV PORT=5000

CMD ["python", "flask_api.py"]
