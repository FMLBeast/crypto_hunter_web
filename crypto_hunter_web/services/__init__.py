"""
crypto_hunter_web.services package
"""

# Celery config
from .celery_config import celery_app

# Auth
from .auth_service import AuthService

# Crypto-intelligence (fallback if class is named differently)
try:
    from .crypto_intelligence import CryptoIntelligenceService
except ImportError:
    try:
        from .crypto_intelligence import CryptoIntelligence as CryptoIntelligenceService
    except ImportError:
        raise ImportError(
            "crypto_intelligence.py must define CryptoIntelligenceService or CryptoIntelligence"
        )

# Background tasks
from .background_crypto import (
    continuous_crypto_monitor,
    system_health_check,
    cleanup_old_tasks,
    manage_priority_queue,
)

# LLM orchestrator
from .llm_crypto_orchestrator import LLMCryptoOrchestrator

# Import services
from .import_service import ImportService
from .enhanced_import_service import EnhancedImportService

# Search
from .search_service import SearchService

# File analysis
from .file_analyzer import FileAnalyzer

# Extraction engine
from .extraction_engine import ExtractionEngine

# Graph builder (try function first, then class)
try:
    from .graph_builder import build_derivation_graph
except ImportError:
    try:
        from .graph_builder import GraphBuilder as build_derivation_graph
    except ImportError:
        raise ImportError(
            "graph_builder.py must define build_derivation_graph() or GraphBuilder"
        )

# Relationship manager
from .relationship_manager import RelationshipManager

__all__ = [
    "celery_app",
    "AuthService",
    "CryptoIntelligenceService",
    "continuous_crypto_monitor",
    "system_health_check",
    "cleanup_old_tasks",
    "manage_priority_queue",
    "auto_analyze_new_files",
    "LLMCryptoOrchestrator",
    "ImportService",
    "EnhancedImportService",
    "SearchService",
    "FileAnalyzer",
    "ExtractionEngine",
    "build_derivation_graph",
    "RelationshipManager",
]
