FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Train XGBoost model on synthetic data at build time
RUN cd src && python train_bootstrap.py

# Runtime: set workdir to src so local imports resolve
WORKDIR /app/src

EXPOSE 8010 2525

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
