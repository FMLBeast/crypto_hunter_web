# Multi-stage build for Crypto Hunter application

# Base stage with common dependencies
FROM python:3.11-slim AS base

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    binwalk \
    foremost \
    steghide \
    libimage-exiftool-perl \
    ruby \
    ruby-dev \
    && gem install zsteg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Development stage
FROM base AS development

# Copy the entire project
COPY . .

# Production stage
FROM base AS production

# Copy the application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/uploads /app/logs /app/instance /app/production /app/extracted_files

# Set permissions
RUN chmod -R 755 /app

# Expose port for web service
EXPOSE 8000

# Set default command to run the web application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120", "wsgi:app"]