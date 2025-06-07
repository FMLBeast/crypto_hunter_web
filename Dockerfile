# Dockerfile

# 1. Base image
FROM python:3.11.5-slim

# 2. Env vars (no inline comments)
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=run.py
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0
ENV CELERY_BROKER_URL=redis://redis:6379/0
ENV CELERY_RESULT_BACKEND=redis://redis:6379/0
ENV PATH="/root/.local/bin:${PATH}"

# 3. Working directory
WORKDIR /app

# 4. System deps (including Ruby for zsteg)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential libssl-dev gcc \
      ruby-full steghide binwalk exiftool foremost && \
    rm -rf /var/lib/apt/lists/*

# Install zsteg gem
RUN gem install zsteg

# 5. Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. App code
COPY . .

# 7. Expose port & add healthcheck
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl -f http://localhost:5000/health || exit 1

# 8. Default to Gunicorn (override in compose for worker)
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:5000"]
