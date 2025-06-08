# Makefile for Crypto Hunter - Best-in-class build automation
# Usage: make <target>

.PHONY: help setup install clean test lint format build run stop status
.DEFAULT_GOAL := help

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
NC := \033[0m # No Color

# Configuration
PYTHON := python3
PIP := pip3
DOCKER := docker
DOCKER_COMPOSE := docker-compose
PROJECT_NAME := crypto-hunter
IMAGE_TAG := $(PROJECT_NAME):latest
VENV := venv

# Help target
help: ## Show this help message
	@echo "$(CYAN)🔍 Crypto Hunter - Build Automation$(NC)"
	@echo "$(CYAN)=====================================$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Quick Start:$(NC)"
	@echo "  $(CYAN)make setup$(NC)    - Complete development setup"
	@echo "  $(CYAN)make run$(NC)      - Start development server"
	@echo "  $(CYAN)make test$(NC)     - Run test suite"

# Development Setup
setup: ## Complete development environment setup
	@echo "$(BLUE)🚀 Setting up Crypto Hunter development environment...$(NC)"
	@$(MAKE) install-system-deps
	@$(MAKE) create-venv
	@$(MAKE) install-python-deps
	@$(MAKE) install-forensics-tools
	@$(MAKE) setup-services
	@$(MAKE) init-database
	@$(MAKE) create-admin-user
	@echo "$(GREEN)✅ Setup complete! Run 'make run' to start developing$(NC)"

create-venv: ## Create Python virtual environment
	@echo "$(BLUE)📦 Creating Python virtual environment...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		$(PYTHON) -m venv $(VENV); \
		echo "$(GREEN)✅ Virtual environment created$(NC)"; \
	else \
		echo "$(YELLOW)⚠️ Virtual environment already exists$(NC)"; \
	fi

install-python-deps: ## Install Python dependencies
	@echo "$(BLUE)📦 Installing Python dependencies...$(NC)"
	@. $(VENV)/bin/activate && $(PIP) install --upgrade pip setuptools wheel
	@. $(VENV)/bin/activate && $(PIP) install -r requirements.txt
	@if [ -f "requirements-dev.txt" ]; then \
		. $(VENV)/bin/activate && $(PIP) install -r requirements-dev.txt; \
	fi
	@echo "$(GREEN)✅ Python dependencies installed$(NC)"

install-system-deps: ## Install system dependencies
	@echo "$(BLUE)📦 Installing system dependencies...$(NC)"
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update; \
		sudo apt-get install -y python3-dev python3-pip python3-venv \
			postgresql-client redis-tools git curl wget; \
		echo "$(GREEN)✅ System dependencies installed$(NC)"; \
	elif command -v brew >/dev/null 2>&1; then \
		brew install python3 postgresql redis git; \
		echo "$(GREEN)✅ System dependencies installed$(NC)"; \
	else \
		echo "$(YELLOW)⚠️ Please install dependencies manually$(NC)"; \
	fi

install-forensics-tools: ## Install forensics analysis tools
	@echo "$(BLUE)🔧 Installing forensics tools...$(NC)"
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get install -y binutils bsdmainutils file exiftool \
			steghide foremost sox ffmpeg wireshark-common tcpdump \
			hashcat john radare2 build-essential; \
		. $(VENV)/bin/activate && $(PIP) install binwalk; \
		if command -v gem >/dev/null 2>&1; then \
			gem install zsteg; \
		fi; \
		echo "$(GREEN)✅ Forensics tools installed$(NC)"; \
	else \
		echo "$(YELLOW)⚠️ Manual forensics tools installation required$(NC)"; \
		echo "Run: python dev.py tools"; \
	fi

# Services Management
setup-services: ## Setup development services (Redis, PostgreSQL)
	@echo "$(BLUE)🔧 Setting up development services...$(NC)"
	@$(MAKE) start-redis
	@$(MAKE) start-postgres
	@sleep 5  # Wait for services to start
	@echo "$(GREEN)✅ Development services ready$(NC)"

start-redis: ## Start Redis container
	@echo "$(BLUE)🔴 Starting Redis...$(NC)"
	@if [ "$$($(DOCKER) ps -q -f name=crypto-hunter-redis)" ]; then \
		echo "$(YELLOW)⚠️ Redis already running$(NC)"; \
	elif [ "$$($(DOCKER) ps -aq -f name=crypto-hunter-redis)" ]; then \
		$(DOCKER) start crypto-hunter-redis; \
		echo "$(GREEN)✅ Redis started$(NC)"; \
	else \
		$(DOCKER) run -d --name crypto-hunter-redis \
			-p 6379:6379 --restart unless-stopped \
			redis:7-alpine redis-server --appendonly yes; \
		echo "$(GREEN)✅ Redis container created and started$(NC)"; \
	fi

start-postgres: ## Start PostgreSQL container
	@echo "$(BLUE)🐘 Starting PostgreSQL...$(NC)"
	@if [ "$$($(DOCKER) ps -q -f name=crypto-hunter-postgres)" ]; then \
		echo "$(YELLOW)⚠️ PostgreSQL already running$(NC)"; \
	elif [ "$$($(DOCKER) ps -aq -f name=crypto-hunter-postgres)" ]; then \
		$(DOCKER) start crypto-hunter-postgres; \
		echo "$(GREEN)✅ PostgreSQL started$(NC)"; \
	else \
		$(DOCKER) run -d --name crypto-hunter-postgres \
			-p 5432:5432 --restart unless-stopped \
			-e POSTGRES_DB=crypto_hunter_dev \
			-e POSTGRES_USER=crypto_hunter \
			-e POSTGRES_PASSWORD=dev_password \
			postgres:15-alpine; \
		echo "$(GREEN)✅ PostgreSQL container created and started$(NC)"; \
	fi

stop-services: ## Stop development services
	@echo "$(YELLOW)🛑 Stopping development services...$(NC)"
	@$(DOCKER) stop crypto-hunter-redis crypto-hunter-postgres 2>/dev/null || true
	@echo "$(GREEN)✅ Services stopped$(NC)"

# Database Management
init-database: ## Initialize database
	@echo "$(BLUE)🗄️ Initializing database...$(NC)"
	@. $(VENV)/bin/activate && flask db init 2>/dev/null || echo "Database already initialized"
	@. $(VENV)/bin/activate && flask db migrate -m "Initial migration" 2>/dev/null || echo "No new migrations"
	@. $(VENV)/bin/activate && flask db upgrade
	@echo "$(GREEN)✅ Database initialized$(NC)"

create-admin-user: ## Create admin user
	@echo "$(BLUE)👤 Creating admin user...$(NC)"
	@. $(VENV)/bin/activate && flask user create \
		--username admin --email admin@crypto-hunter.local \
		--password admin123 --admin 2>/dev/null || echo "Admin user may already exist"
	@echo "$(GREEN)✅ Admin user: admin / admin123$(NC)"

migrate: ## Create and apply database migrations
	@echo "$(BLUE)🗄️ Creating database migration...$(NC)"
	@. $(VENV)/bin/activate && flask db migrate
	@. $(VENV)/bin/activate && flask db upgrade
	@echo "$(GREEN)✅ Database migrated$(NC)"

reset-db: ## Reset database (destructive)
	@echo "$(RED)⚠️ This will delete all data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo ""; \
		. $(VENV)/bin/activate && flask system reset --yes; \
		$(MAKE) create-admin-user; \
		echo "$(GREEN)✅ Database reset complete$(NC)"; \
	else \
		echo ""; \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

# Development
run: ## Start development server
	@echo "$(BLUE)🌶️ Starting development server...$(NC)"
	@. $(VENV)/bin/activate && python run_local.py

run-prod: ## Start production server
	@echo "$(BLUE)🚀 Starting production server...$(NC)"
	@. $(VENV)/bin/activate && gunicorn wsgi:app \
		--bind 0.0.0.0:8000 \
		--workers 4 \
		--worker-class gevent \
		--access-logfile - \
		--error-logfile -

run-celery: ## Start Celery worker
	@echo "$(BLUE)👷 Starting Celery worker...$(NC)"
	@. $(VENV)/bin/activate && celery -A crypto_hunter_web.services.background_service \
		worker --loglevel=info --concurrency=2

run-beat: ## Start Celery beat scheduler
	@echo "$(BLUE)⏰ Starting Celery beat...$(NC)"
	@. $(VENV)/bin/activate && celery -A crypto_hunter_web.services.background_service \
		beat --loglevel=info

run-flower: ## Start Flower monitoring
	@echo "$(BLUE)🌸 Starting Flower monitoring...$(NC)"
	@. $(VENV)/bin/activate && celery -A crypto_hunter_web.services.background_service \
		flower --port=5555

# Testing
test: ## Run test suite
	@echo "$(BLUE)🧪 Running test suite...$(NC)"
	@. $(VENV)/bin/activate && python -m pytest tests/ -v
	@echo "$(GREEN)✅ Tests completed$(NC)"

test-coverage: ## Run tests with coverage
	@echo "$(BLUE)🧪 Running tests with coverage...$(NC)"
	@. $(VENV)/bin/activate && python -m pytest tests/ -v \
		--cov=crypto_hunter_web --cov-report=html --cov-report=term
	@echo "$(GREEN)✅ Coverage report generated in htmlcov/$(NC)"

test-integration: ## Run integration tests
	@echo "$(BLUE)🧪 Running integration tests...$(NC)"
	@. $(VENV)/bin/activate && python -m pytest tests/integration/ -v -s
	@echo "$(GREEN)✅ Integration tests completed$(NC)"

test-forensics: ## Test forensics tools
	@echo "$(BLUE)🧪 Testing forensics tools...$(NC)"
	@. $(VENV)/bin/activate && flask forensics test
	@echo "$(GREEN)✅ Forensics tools tested$(NC)"

# Code Quality
lint: ## Lint code with flake8
	@echo "$(BLUE)🔍 Linting code...$(NC)"
	@. $(VENV)/bin/activate && flake8 crypto_hunter_web/ --max-line-length=100 \
		--exclude=migrations/ --ignore=E203,W503
	@echo "$(GREEN)✅ Code linting completed$(NC)"

format: ## Format code with black and isort
	@echo "$(BLUE)🎨 Formatting code...$(NC)"
	@. $(VENV)/bin/activate && black crypto_hunter_web/ --line-length=100
	@. $(VENV)/bin/activate && isort crypto_hunter_web/
	@echo "$(GREEN)✅ Code formatted$(NC)"

security-scan: ## Security scan with bandit
	@echo "$(BLUE)🔒 Running security scan...$(NC)"
	@. $(VENV)/bin/activate && bandit -r crypto_hunter_web/ \
		-x crypto_hunter_web/migrations/ -f json -o security-report.json 2>/dev/null || true
	@. $(VENV)/bin/activate && bandit -r crypto_hunter_web/ \
		-x crypto_hunter_web/migrations/ --severity-level medium
	@echo "$(GREEN)✅ Security scan completed$(NC)"

check: lint format test ## Run all code quality checks

# Docker Operations
build: ## Build Docker image
	@echo "$(BLUE)🐳 Building Docker image...$(NC)"
	@$(DOCKER) build -t $(IMAGE_TAG) .
	@echo "$(GREEN)✅ Docker image built: $(IMAGE_TAG)$(NC)"

build-dev: ## Build development Docker image
	@echo "$(BLUE)🐳 Building development Docker image...$(NC)"
	@$(DOCKER) build --target development -t $(PROJECT_NAME):dev .
	@echo "$(GREEN)✅ Development image built: $(PROJECT_NAME):dev$(NC)"

docker-run: ## Run Docker container
	@echo "$(BLUE)🐳 Running Docker container...$(NC)"
	@$(DOCKER) run -d --name $(PROJECT_NAME) \
		-p 8000:8000 \
		-e DATABASE_URL=postgresql://crypto_hunter:dev_password@host.docker.internal:5432/crypto_hunter_dev \
		-e REDIS_URL=redis://host.docker.internal:6379/0 \
		$(IMAGE_TAG)
	@echo "$(GREEN)✅ Container started: http://localhost:8000$(NC)"

docker-stop: ## Stop Docker container
	@echo "$(YELLOW)🛑 Stopping Docker container...$(NC)"
	@$(DOCKER) stop $(PROJECT_NAME) 2>/dev/null || true
	@$(DOCKER) rm $(PROJECT_NAME) 2>/dev/null || true
	@echo "$(GREEN)✅ Container stopped$(NC)"

docker-compose-up: ## Start with docker-compose
	@echo "$(BLUE)🐳 Starting with docker-compose...$(NC)"
	@$(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)✅ Stack started with docker-compose$(NC)"

docker-compose-down: ## Stop docker-compose stack
	@echo "$(YELLOW)🛑 Stopping docker-compose stack...$(NC)"
	@$(DOCKER_COMPOSE) down
	@echo "$(GREEN)✅ Stack stopped$(NC)"

# System Management
status: ## Show system status
	@echo "$(BLUE)📊 System Status$(NC)"
	@echo "$(CYAN)=================$(NC)"
	@. $(VENV)/bin/activate && flask system health

check-tools: ## Check forensics tools availability
	@echo "$(BLUE)🔧 Checking forensics tools...$(NC)"
	@. $(VENV)/bin/activate && flask forensics check

logs: ## Show application logs
	@echo "$(BLUE)📋 Application logs (last 50 lines):$(NC)"
	@tail -n 50 logs/development.log 2>/dev/null || echo "No logs found"

clean: ## Clean up temporary files
	@echo "$(BLUE)🧹 Cleaning up...$(NC)"
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache/
	@rm -rf htmlcov/
	@rm -rf dist/
	@rm -rf build/
	@rm -f security-report.json
	@echo "$(GREEN)✅ Cleanup completed$(NC)"

clean-all: clean ## Clean everything including venv and containers
	@echo "$(YELLOW)🗑️ Deep cleaning...$(NC)"
	@rm -rf $(VENV)/
	@$(DOCKER) stop crypto-hunter-redis crypto-hunter-postgres 2>/dev/null || true
	@$(DOCKER) rm crypto-hunter-redis crypto-hunter-postgres 2>/dev/null || true
	@$(DOCKER) rmi $(IMAGE_TAG) 2>/dev/null || true
	@echo "$(GREEN)✅ Deep cleanup completed$(NC)"

# Deployment
deploy-staging: ## Deploy to staging
	@echo "$(BLUE)🚀 Deploying to staging...$(NC)"
	@$(MAKE) build
	@$(MAKE) test
	@echo "$(GREEN)✅ Ready for staging deployment$(NC)"

deploy-prod: ## Deploy to production
	@echo "$(BLUE)🚀 Deploying to production...$(NC)"
	@$(MAKE) build
	@$(MAKE) test
	@$(MAKE) security-scan
	@echo "$(RED)⚠️ Manual production deployment required$(NC)"
	@echo "Review security scan and deploy manually"

# Backup and Restore
backup: ## Backup database
	@echo "$(BLUE)💾 Creating database backup...$(NC)"
	@. $(VENV)/bin/activate && flask system backup --output backup-$$(date +%Y%m%d-%H%M%S).sql
	@echo "$(GREEN)✅ Database backup created$(NC)"

# Monitoring
monitor: ## Start monitoring dashboard
	@echo "$(BLUE)📊 Starting monitoring...$(NC)"
	@echo "$(CYAN)Available endpoints:$(NC)"
	@echo "  🌐 Application: http://localhost:8000"
	@echo "  ❤️ Health: http://localhost:8000/health"
	@echo "  🌸 Flower: http://localhost:5555 (if running)"
	@echo "  🔧 Admin: Create with 'make create-admin-user'"

# Development helpers
shell: ## Open Flask shell
	@echo "$(BLUE)🐚 Opening Flask shell...$(NC)"
	@. $(VENV)/bin/activate && flask shell

routes: ## Show all application routes
	@echo "$(BLUE)🛣️ Application routes:$(NC)"
	@. $(VENV)/bin/activate && flask routes

# Quick development targets
dev: setup run ## Quick development setup and run

quick-test: ## Quick test run (no coverage)
	@. $(VENV)/bin/activate && python -m pytest tests/ -x -q

quick-check: ## Quick code quality check
	@. $(VENV)/bin/activate && black --check crypto_hunter_web/ --line-length=100
	@. $(VENV)/bin/activate && flake8 crypto_hunter_web/ --max-line-length=100 --exclude=migrations/

# Installation verification
verify: ## Verify installation
	@echo "$(BLUE)🔍 Verifying installation...$(NC)"
	@$(MAKE) check-tools
	@$(MAKE) status
	@$(MAKE) quick-test
	@echo "$(GREEN)✅ Installation verified$(NC)"

# Environment info
info: ## Show environment information
	@echo "$(CYAN)🔍 Crypto Hunter Environment Information$(NC)"
	@echo "$(CYAN)=======================================$(NC)"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Pip: $$($(PIP) --version)"
	@echo "Docker: $$($(DOCKER) --version 2>/dev/null || echo 'Not available')"
	@echo "Git: $$(git --version 2>/dev/null || echo 'Not available')"
	@echo "Virtual Environment: $$([ -d '$(VENV)' ] && echo 'Present' || echo 'Missing')"
	@echo "Redis: $$($(DOCKER) ps --filter name=crypto-hunter-redis --format 'table {{.Status}}' | grep -v STATUS || echo 'Not running')"
	@echo "PostgreSQL: $$($(DOCKER) ps --filter name=crypto-hunter-postgres --format 'table {{.Status}}' | grep -v STATUS || echo 'Not running')"