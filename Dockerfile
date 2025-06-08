# Multi-stage Dockerfile - Production optimized with development support
FROM python:3.11-slim as base

# Install system dependencies once for all stages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libmagic1 \
    libmagic-dev \
    libpq-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Development stage
FROM base as development

# Install development tools
RUN pip install --no-cache-dir \
    flask-shell-ipython \
    ipython \
    ipdb \
    watchdog \
    pytest \
    pytest-flask \
    black \
    flake8

# Create development directories
RUN mkdir -p /app/logs /app/uploads /app/instance && \
    chown -R appuser:appuser /app
USER appuser

# Development server with hot reload
EXPOSE 8000
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=8000", "--reload", "--debugger"]

# Production stage
FROM base as production

# Copy application code
COPY --chown=appuser:appuser . .

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads /app/instance && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production server
EXPOSE 8000
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "gevent", "--worker-connections", "1000", "--max-requests", "10000", "--max-requests-jitter", "1000", "--preload", "--access-logfile", "-", "--error-logfile", "-"]

# Testing stage (for CI/CD)
FROM development as testing
COPY . .
RUN python -m pytest tests/ -v --cov=crypto_hunter_web --cov-report=term-missing
