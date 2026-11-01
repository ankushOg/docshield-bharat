# DocShield Dockerfile for Render Free Web Service Deployment
# Installs Tesseract OCR system binaries + OpenCV headless dependencies alongside Python packages.

FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system-level Tesseract OCR engine and OpenCV runtime libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project source files
COPY . .

# Create local fallback upload directory with non-root user permissions
RUN useradd -m appuser && mkdir -p /app/uploads && chown -R appuser:appuser /app
USER appuser

# Render dynamically injects the PORT environment variable (default 10000)
EXPOSE 10000

CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 2 --timeout 120"]
