FROM python:3.11-slim

WORKDIR /app

# System deps for fitz (PyMuPDF), lxml, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 libgomp1 gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir \
        fastapi uvicorn[standard] psycopg2-binary \
        requests python-multipart \
        PyMuPDF python-docx \
        scikit-learn joblib numpy tldextract python-whois \
        beautifulsoup4 xgboost

# Copy all source files
COPY . .

EXPOSE 8009

CMD ["python", "-m", "uvicorn", "email_api:app", "--host", "0.0.0.0", "--port", "8009", "--workers", "1"]
