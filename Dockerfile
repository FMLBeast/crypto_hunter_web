# Dockerfile

FROM python:3.11.5-slim    # lock to a patch release

ENV PYTHONUNBUFFERED=1 \
    FLASK_APP=run.py \
    FLASK_ENV=production \
    CELERY_BROKER_URL=redis://redis:6379/0 \
    CELERY_RESULT_BACKEND=redis://redis:6379/0 \
    PATH="/root/.local/bin:${PATH}"   # ensure user‐installed binaries are found

WORKDIR /app

# system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev gcc \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y --no-install-recommends zsteg steghide binwalk exiftool foremost && \
    rm -rf /var/lib/apt/lists/*

# python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# app code
COPY . .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl -f http://localhost:5000/health || exit 1

# default to web; override in compose for worker
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:5000"]
