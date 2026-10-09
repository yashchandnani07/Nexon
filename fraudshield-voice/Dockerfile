FROM python:3.10-slim

# Install necessary OS packages for audio processing
RUN apt-get update && apt-get install -y \
    ffmpeg \
    libsndfile1 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --default-timeout=2000 --no-cache-dir -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu

# Copy application source
COPY . .

# Adjust Python path to load from src
ENV PYTHONPATH=/app/src

# Expose internal API port
EXPOSE 8000

# Run the FastAPI server
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
