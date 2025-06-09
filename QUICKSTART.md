# Crypto Hunter - Quick Start Guide

🔍 **Get Crypto Hunter running in 3 simple steps**

## Option 1: Automated Installation (Recommended)

```bash
# Run the installation script
python install.py

# Start the application
python run_local.py
```

## Option 2: Manual Installation

```bash
# Install core dependencies
pip install Flask Flask-SQLAlchemy Flask-Login python-dotenv Werkzeug

# Create directories and .env file
python -c "
from pathlib import Path
for d in ['logs', 'uploads', 'instance', 'temp']: Path(d).mkdir(exist_ok=True)
with open('.env', 'w') as f: f.write('SECRET_KEY=dev-key\nFLASK_ENV=development\nDATABASE_URL=sqlite:///instance/app.db\n')
"

# Run the application
python run.py
```

## Option 3: Minimal Requirements

If you're having dependency issues, use the minimal requirements:

```bash
pip install -r requirements-minimal.txt
python run.py
```

## Troubleshooting

### Celery Version Error
If you see `ERROR: Could not find a version that satisfies the requirement celery==5.3.2`:

1. Use the minimal requirements: `pip install -r requirements-minimal.txt`
2. Or install specific version: `pip install celery>=5.3.0,<6.0.0`
3. Or skip celery entirely for basic functionality

### Missing Dependencies
The app is designed to work even with missing optional dependencies:

- **Redis**: Background tasks will be disabled
- **PostgreSQL**: SQLite will be used instead
- **Celery**: Background processing will be disabled
- **AI libraries**: AI features will be disabled

### Database Issues
The app defaults to SQLite which requires no setup:
```bash
# Database will be created automatically at:
instance/crypto_hunter_dev.db
```

## Access Your Application

Once running, visit: **http://localhost:8000**

## File Structure
```
crypto_hunter_web/
├── run.py                 # Main entry point
├── run_local.py          # Development setup
├── install.py            # Installation script
├── requirements.txt      # Full dependencies
├── requirements-minimal.txt  # Core dependencies
├── .env                  # Configuration (auto-created)
└── crypto_hunter_web/    # Application code
```

## What's Working

✅ **Dashboard** - Main interface with file stats  
✅ **File Upload** - Basic file handling  
✅ **Database** - SQLite storage  
✅ **Authentication** - User management  
✅ **Error Handling** - Graceful fallbacks  

## Getting Help

1. Check logs in `logs/crypto_hunter.log`
2. Verify `.env` configuration
3. Try running with minimal dependencies
4. Check Python version (3.8+ required)

**Quick test**: `python -c "import flask; print('Flask works!')"`