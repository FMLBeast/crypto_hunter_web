FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libmagic1 libmagic-dev libpq-dev build-essential \
    curl wget git file binutils util-linux xxd netcat-openbsd ca-certificates \
    && rm -rf /var/lib/apt/lists/* && apt-get clean

RUN groupadd -r appuser --gid 1000 && \
    useradd -r -g appuser --uid 1000 --home-dir /app --shell /bin/bash appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && pip cache purge

FROM base AS development
RUN pip install --no-cache-dir flask-shell-ipython ipython ipdb watchdog pytest pytest-flask black flake8
RUN mkdir -p /app/logs /app/uploads /app/instance /app/temp && \
    chown -R appuser:appuser /app && chmod -R 755 /app
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=8000", "--reload"]

FROM base AS production
COPY --chown=appuser:appuser . .
RUN mkdir -p /app/logs /app/uploads /app/instance /app/temp /app/static && \
    chown -R appuser:appuser /app && chmod -R 755 /app && \
    chmod -R 777 /app/logs /app/uploads /app/temp
USER appuser
ENV PYTHONPATH="/app" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 FLASK_ENV=production
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
EXPOSE 8000
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "gevent", "--timeout", "120", "--access-logfile", "/app/logs/access.log", "--error-logfile", "/app/logs/error.log"]
