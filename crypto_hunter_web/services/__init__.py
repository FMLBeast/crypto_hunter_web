# crypto_hunter_web/services/__init__.py - CLEAN SERVICE IMPORTS

"""
crypto_hunter_web.services package
Handles all service layer functionality with proper error handling
"""

import logging

logger = logging.getLogger(__name__)

# Core services - these must exist
try:
    from .auth_service import AuthService
except ImportError as e:
    logger.error(f"Failed to import AuthService: {e}")
    raise

try:
    from .search_service import SearchService
except ImportError as e:
    logger.error(f"Failed to import SearchService: {e}")
    raise

try:
    from .file_analyzer import FileAnalyzer
except ImportError as e:
    logger.error(f"Failed to import FileAnalyzer: {e}")
    raise

# Celery app - import from unified location
try:
    from crypto_hunter_web.services.celery_app import celery_app
except ImportError as e:
    logger.error(f"Failed to import celery_app: {e}")
    celery_app = None

# Optional services - graceful degradation
ImportService = None
try:
    from .import_service import ImportService
except ImportError as e:
    logger.warning(f"ImportService not available: {e}")

EnhancedImportService = None
try:
    from .enhanced_import_service import EnhancedImportService
except ImportError as e:
    logger.warning(f"EnhancedImportService not available: {e}")

CryptoIntelligenceService = None
try:
    from .crypto_intelligence import CryptoIntelligenceService
except ImportError:
    try:
        from .crypto_intelligence import CryptoIntelligence as CryptoIntelligenceService
    except ImportError as e:
        logger.warning(f"CryptoIntelligenceService not available: {e}")

LLMCryptoOrchestrator = None
try:
    from .llm_crypto_orchestrator import LLMCryptoOrchestrator
except ImportError as e:
    logger.warning(f"LLMCryptoOrchestrator not available: {e}")

ExtractionEngine = None
try:
    from .extraction_engine import ExtractionEngine
except ImportError as e:
    logger.warning(f"ExtractionEngine not available: {e}")

RelationshipManager = None
try:
    from .relationship_manager import RelationshipManager
except ImportError as e:
    logger.warning(f"RelationshipManager not available: {e}")

# Graph builder - try function first, then class
build_derivation_graph = None
try:
    from .graph_builder import build_derivation_graph
except ImportError:
    try:
        from .graph_builder import GraphBuilder as build_derivation_graph
    except ImportError as e:
        logger.warning(f"Graph builder not available: {e}")

# Background task functions - optional
continuous_crypto_monitor = None
system_health_check = None
cleanup_old_tasks = None
manage_priority_queue = None

try:
    from .background_crypto import (
        continuous_crypto_monitor,
        system_health_check,
        cleanup_old_tasks,
        manage_priority_queue,
    )
except ImportError as e:
    logger.warning(f"Background crypto tasks not available: {e}")

# Build __all__ dynamically based on what imported successfully
__all__ = [
    "AuthService",
    "SearchService", 
    "FileAnalyzer",
]

# Add optional services that loaded successfully
optional_exports = {
    "celery_app": celery_app,
    "ImportService": ImportService,
    "EnhancedImportService": EnhancedImportService,
    "CryptoIntelligenceService": CryptoIntelligenceService,
    "LLMCryptoOrchestrator": LLMCryptoOrchestrator,
    "ExtractionEngine": ExtractionEngine,
    "RelationshipManager": RelationshipManager,
    "build_derivation_graph": build_derivation_graph,
    "continuous_crypto_monitor": continuous_crypto_monitor,
    "system_health_check": system_health_check,
    "cleanup_old_tasks": cleanup_old_tasks,
    "manage_priority_queue": manage_priority_queue,
}

for name, obj in optional_exports.items():
    if obj is not None:
        __all__.append(name)

# Log successful imports
logger.info(f"Services loaded: {', '.join(__all__)}")

# Provide helper function to check service availability
def is_service_available(service_name: str) -> bool:
    """Check if a service is available"""
    return service_name in __all__ and globals().get(service_name) is not None

def get_available_services() -> list:
    """Get list of available services"""
    return __all__.copy()