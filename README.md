# 🔍 Crypto Hunter - Advanced Cryptocurrency Analysis Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/framework-Flask-red.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/security-production--ready-green.svg)](https://github.com/crypto-hunter/security)

**Crypto Hunter** is a cutting-edge platform for analyzing files, detecting cryptocurrency artifacts, and performing comprehensive cryptographic analysis. Built for security researchers, forensics investigators, and cryptocurrency enthusiasts.

## ✨ Features

### 🔐 Advanced Crypto Detection
- **Multi-Currency Support**: Bitcoin, Ethereum, Litecoin, Monero, Zcash, and 15+ more
- **Pattern Recognition**: Private keys, wallet addresses, mnemonic phrases, certificates
- **Smart Analysis**: AI-powered crypto content detection with confidence scoring
- **Blockchain Integration**: Real-time wallet balance and transaction lookups

### 📁 Comprehensive File Analysis
- **Universal Support**: 50+ file formats including executables, archives, documents
- **Deep Inspection**: Hex dumps, string extraction, metadata analysis
- **Binary Analysis**: PE/ELF/Mach-O executables, packed files, obfuscation detection
- **Archive Processing**: Automatic extraction and recursive analysis

### 🤖 AI-Powered Intelligence
- **LLM Integration**: GPT-4 and Claude for intelligent analysis
- **Context Understanding**: Natural language insights about findings
- **Risk Assessment**: Automated threat and anomaly detection
- **Smart Categorization**: Automatic tagging and classification

### 🌐 Production-Ready Architecture
- **Scalable Design**: Microservices with Redis and PostgreSQL
- **Background Processing**: Celery for heavy analysis tasks
- **API-First**: RESTful API with comprehensive documentation
- **Security-Hardened**: Rate limiting, authentication, audit logging

### 📊 Advanced Visualization
- **Interactive Graphs**: File relationships and analysis workflows
- **Real-time Dashboards**: Statistics, metrics, and system health
- **Export Capabilities**: JSON, CSV, PDF reports
- **Custom Dashboards**: Configurable views for different use cases

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+**
- **PostgreSQL 13+** (or SQLite for development)
- **Redis 6+**
- **Docker & Docker Compose** (recommended)

### 1. Clone Repository

```bash
git clone https://github.com/crypto-hunter/crypto-hunter-web.git
cd crypto-hunter-web
```

### 2. Environment Setup

Create `.env` file:

```bash
# Core Configuration
SECRET_KEY=your-super-secret-key-here
FLASK_ENV=development

# Database
DATABASE_URL=postgresql://crypto_hunter:password@localhost:5432/crypto_hunter

# Redis
REDIS_URL=redis://localhost:6379/0

# AI Services (Optional)
OPENAI_API_KEY=sk-your-openai-key
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key

# Features
ENABLE_REGISTRATION=true
ENABLE_AI_ANALYSIS=true
```

### 3. Development Setup

#### Option A: Local Development (Fast)

```bash
# Install dependencies
pip install -r requirements.txt

# Setup Redis (Docker)
python dev.py local

# Initialize database
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

# Create admin user
flask user create --username admin --email admin@example.com --admin

# Run development server
python run_local.py
```

#### Option B: Docker Development

```bash
# Start all services
docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d

# Initialize database
docker-compose exec web flask db upgrade

# Create admin user
docker-compose exec web flask user create --username admin --email admin@example.com --admin
```

### 4. Access Application

- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api/docs
- **Flower (Task Monitor)**: http://localhost:5556
- **Grafana (Metrics)**: http://localhost:3000

## 📖 Usage Guide

### File Upload & Analysis

1. **Upload Files**
   ```bash
   # Web interface
   Navigate to /files/upload

   # API
   curl -X POST http://localhost:8000/api/files/upload \
     -H "X-API-Key: your-api-key" \
     -F "file=@sample.txt" \
     -F "auto_analyze=true"
   ```

2. **Start Analysis**
   ```bash
   # Comprehensive analysis
   curl -X POST http://localhost:8000/api/crypto/analyze/FILE_HASH \
     -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"deep_scan": true, "include_blockchain": true}'
   ```

3. **View Results**
   ```bash
   # Get analysis results
   curl -X GET http://localhost:8000/api/files/FILE_HASH/results \
     -H "X-API-Key: your-api-key"
   ```

### Crypto Pattern Detection

```python
from crypto_hunter_web.utils.crypto_patterns import CryptoPatterns

analyzer = CryptoPatterns()

# Analyze text content
results = analyzer.analyze_content("""
Here's my Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
And my Ethereum wallet: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
""")

print(f"Crypto content detected: {results['has_crypto_content']}")
print(f"Confidence score: {results['confidence_score']}")
print(f"Patterns found: {len(results['patterns_found'])}")
```

### API Usage Examples

#### Authentication
```bash
# Create API key
curl -X POST http://localhost:8000/auth/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{"name": "My API Key", "permissions": ["api:read", "api:write"]}'

# Use API key
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/crypto/statistics
```

#### Search Crypto Patterns
```bash
curl -X POST http://localhost:8000/api/crypto/patterns/search \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "pattern_types": ["wallet_address", "private_key"],
    "confidence_min": 0.8,
    "limit": 100
  }'
```

#### Wallet Address Analysis
```bash
curl -X POST http://localhost:8000/api/crypto/wallets/identify \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "addresses": [
      "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    ]
  }'
```

## 🏗️ Architecture

### System Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Frontend  │    │   Flask API     │    │   Background    │
│   (React/HTML)  │◄──►│   Application   │◄──►│   Workers       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │      Redis      │    │   File Storage  │
│   Database      │    │   Cache/Queue   │    │   (Local/S3)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Core Components

- **Flask Application**: Main web application with security features
- **Celery Workers**: Background processing for file analysis
- **PostgreSQL**: Primary database for persistent storage
- **Redis**: Caching, session storage, and task queue
- **Nginx**: Reverse proxy and static file serving (production)

### Analysis Pipeline

```
File Upload → Validation → Storage → Queue Analysis → 
Pattern Detection → AI Analysis → Results Storage → 
Notification → Report Generation
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | *Required* |
| `DATABASE_URL` | PostgreSQL connection string | `sqlite:///crypto_hunter.db` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `OPENAI_API_KEY` | OpenAI API key for AI analysis | Optional |
| `ANTHROPIC_API_KEY` | Anthropic API key | Optional |
| `MAX_CONTENT_LENGTH` | Maximum file upload size | `1073741824` (1GB) |
| `ENABLE_REGISTRATION` | Allow user registration | `true` |
| `ENABLE_AI_ANALYSIS` | Enable AI-powered analysis | `true` |
| `LOG_LEVEL` | Logging level | `INFO` |

### Feature Flags

```python
# config.py
ENABLE_REGISTRATION = True      # User registration
ENABLE_API = True              # REST API
ENABLE_BACKGROUND_TASKS = True # Async processing
ENABLE_AI_ANALYSIS = True     # AI features
ENABLE_CRYPTO_ANALYSIS = True # Crypto detection
ENABLE_FILE_UPLOAD = True     # File uploads
```

## 🔒 Security

### Security Features

- **Authentication**: Multi-factor authentication support
- **Authorization**: Role-based access control (RBAC)
- **Rate Limiting**: Configurable rate limits per user/IP
- **Input Validation**: Comprehensive input sanitization
- **CSRF Protection**: Cross-site request forgery protection
- **Audit Logging**: Complete audit trail of user actions
- **API Security**: API key management with permissions

### Security Best Practices

1. **Change Default Credentials**
   ```bash
   # Generate secure secret key
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

2. **Use HTTPS in Production**
   ```nginx
   # nginx.conf
   server {
       listen 443 ssl;
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
   }
   ```

3. **Configure Rate Limiting**
   ```python
   # Adjust in config.py
   RATELIMIT_DEFAULT = "1000 per hour, 10000 per day"
   ```

4. **Enable Security Headers**
   ```python
   # Already configured in app factory
   Content-Security-Policy: default-src 'self'
   X-Frame-Options: DENY
   X-Content-Type-Options: nosniff
   ```

## 🐳 Docker Deployment

### Production Deployment

```bash
# Production with monitoring
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# With monitoring stack
docker-compose --profile monitoring up -d

# With logging stack
docker-compose --profile logging up -d
```

### Docker Services

- **web**: Main Flask application
- **worker**: Celery background workers
- **beat**: Celery scheduler
- **flower**: Task monitoring
- **db**: PostgreSQL database
- **redis**: Cache and message broker
- **nginx**: Reverse proxy
- **prometheus**: Metrics collection
- **grafana**: Metrics visualization

### Scaling

```bash
# Scale workers
docker-compose up -d --scale worker=4

# Scale web instances
docker-compose up -d --scale web=3
```

## 📊 Monitoring

### Health Checks

```bash
# Application health
curl http://localhost:8000/health

# Readiness check
curl http://localhost:8000/ready

# Metrics endpoint
curl http://localhost:8000/metrics
```

### Grafana Dashboards

- **System Overview**: CPU, memory, disk usage
- **Application Metrics**: Request rates, response times
- **Analysis Pipeline**: File processing statistics
- **Security Events**: Failed logins, rate limits

### Log Analysis

```bash
# View application logs
docker-compose logs -f web

# View worker logs
docker-compose logs -f worker

# View all logs
docker-compose logs -f
```

## 🧪 Testing

### Run Tests

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=crypto_hunter_web --cov-report=html

# Run specific test categories
pytest tests/test_auth.py
pytest tests/test_crypto_api.py
pytest tests/test_file_analysis.py
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **API Tests**: REST API endpoint testing
- **Security Tests**: Authentication and authorization
- **Performance Tests**: Load and stress testing

### Continuous Integration

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v3
        with:
          python-version: 3.11
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest --cov=crypto_hunter_web
```

## 📚 API Documentation

### Authentication

```bash
# Get API key
POST /auth/api-keys/create
{
  "name": "My API Key",
  "permissions": ["api:read", "api:write"]
}

# Use API key
GET /api/endpoint
Headers: X-API-Key: your-api-key-here
```

### File Operations

```bash
# Upload file
POST /api/files/upload
Content-Type: multipart/form-data

# Get file info
GET /api/files/{file_hash}

# Start analysis
POST /api/files/{file_hash}/analyze
{
  "analysis_types": ["crypto", "strings", "metadata"],
  "deep_scan": true
}
```

### Crypto Analysis

```bash
# Search patterns
POST /api/crypto/patterns/search
{
  "pattern_types": ["wallet_address"],
  "confidence_min": 0.8
}

# Identify wallets
POST /api/crypto/wallets/identify
{
  "addresses": ["1A1zP1eP..."]
}

# Get statistics
GET /api/crypto/statistics?days=30
```

## 🛠️ Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/crypto-hunter/crypto-hunter-web.git
cd crypto-hunter-web

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Run development server
python run_local.py
```

### Code Style

```bash
# Format code
black crypto_hunter_web/
isort crypto_hunter_web/

# Lint code
flake8 crypto_hunter_web/
mypy crypto_hunter_web/

# Security checks
bandit -r crypto_hunter_web/
```

### Adding New Features

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/new-crypto-detection
   ```

2. **Add Tests First** (TDD)
   ```python
   # tests/test_new_feature.py
   def test_new_crypto_pattern():
       assert new_pattern_detector.detect("test") == expected_result
   ```

3. **Implement Feature**
   ```python
   # crypto_hunter_web/services/new_detector.py
   class NewPatternDetector:
       def detect(self, content):
           # Implementation
           return result
   ```

4. **Update Documentation**
   ```markdown
   # Add to README.md and API docs
   ```

5. **Submit Pull Request**

### Database Migrations

```bash
# Create migration
flask db migrate -m "Add new table"

# Apply migration
flask db upgrade

# Rollback migration
flask db downgrade
```

### Database Schema Validation

The application automatically checks if the database schema matches the SQLAlchemy models during startup. If a mismatch is detected, it can automatically re-initialize the database.

```bash
# Enable automatic database re-initialization in .env
AUTO_REINIT_DB=true
```

> **Warning**: When `AUTO_REINIT_DB` is set to `true`, the application will drop and recreate all tables if a schema mismatch is detected. This will delete all data in the database. Use with caution in production environments.

You can also manually check and fix schema mismatches using the provided script:

```bash
# Check schema without making changes
python database/check_db_schema.py

# Check and automatically fix schema mismatches
AUTO_REINIT_DB=true python database/check_db_schema.py
```

## 📁 Project Organization

The project has been reorganized to make it cleaner and more maintainable. Files have been grouped into the following directories:

- **extraction**: Contains extraction-related files
- **database**: Contains database-related files
- **docker**: Contains Docker-related files
- **docs**: Contains documentation files
- **scripts**: Contains scripts for various tasks

For more details, see [REORGANIZATION.md](REORGANIZATION.md).

## 🚀 Production Deployment

### Prerequisites

- **Server**: Linux server with Docker support
- **Domain**: Configured domain with SSL certificate
- **Resources**: 4GB+ RAM, 50GB+ storage
- **Monitoring**: Configured alerting system

### Deployment Steps

1. **Server Setup**
   ```bash
   # Install Docker and Docker Compose
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh

   # Configure firewall
   ufw allow 80,443/tcp
   ```

2. **SSL Configuration**
   ```bash
   # Get SSL certificate (Let's Encrypt)
   certbot certonly --standalone -d your-domain.com
   ```

3. **Environment Configuration**
   ```bash
   # Production environment file
   cp .env.example .env.prod
   # Edit with production values
   ```

4. **Deploy Application**
   ```bash
   # Deploy with production config
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

   # Initialize database
   docker-compose exec web flask db upgrade

   # Create admin user
   docker-compose exec web flask user create --admin
   ```

5. **Setup Monitoring**
   ```bash
   # Enable monitoring stack
   docker-compose --profile monitoring up -d
   ```

### Production Checklist

- [ ] SSL certificate configured
- [ ] Database backups automated
- [ ] Log rotation configured
- [ ] Monitoring alerts setup
- [ ] Security headers enabled
- [ ] Rate limiting configured
- [ ] Admin user created
- [ ] Health checks passing

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Make changes and add tests**
4. **Ensure tests pass**: `pytest`
5. **Commit changes**: `git commit -m 'Add amazing feature'`
6. **Push to branch**: `git push origin feature/amazing-feature`
7. **Open Pull Request**

### Development Guidelines

- Follow PEP 8 style guide
- Write comprehensive tests
- Update documentation
- Use semantic commit messages
- Ensure backward compatibility

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Flask Community** for the excellent web framework
- **Celery Team** for robust background processing
- **Crypto Community** for pattern databases and insights
- **Security Researchers** for vulnerability reports and improvements

## 📞 Support

- **Documentation**: [https://docs.cryptohunter.local](https://docs.cryptohunter.local)
- **Issues**: [GitHub Issues](https://github.com/crypto-hunter/crypto-hunter-web/issues)
- **Discussions**: [GitHub Discussions](https://github.com/crypto-hunter/crypto-hunter-web/discussions)
- **Email**: support@cryptohunter.local

## 🗺️ Roadmap

### v2.1 (Q2 2024)
- [ ] Machine learning model training
- [ ] Advanced blockchain analysis
- [ ] Mobile application support
- [ ] Enhanced reporting features

### v2.2 (Q3 2024)
- [ ] Cloud storage integration
- [ ] Advanced visualization
- [ ] Real-time collaboration
- [ ] Plugin system

### v3.0 (Q4 2024)
- [ ] Distributed analysis
- [ ] Advanced AI models
- [ ] Enterprise features
- [ ] SaaS offering

---

**Made with ❤️ by the Crypto Hunter Team**

*Securing the digital world, one file at a time.*
