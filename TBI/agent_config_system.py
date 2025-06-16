"""
crypto_hunter_web/config/agent_config.py
Configuration management system for Crypto Hunter agents
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path
import yaml
from enum import Enum

logger = logging.getLogger(__name__)


class AgentConfigLevel(Enum):
    """Configuration precedence levels"""
    DEFAULT = 1
    ENVIRONMENT = 2
    FILE = 3
    DATABASE = 4
    RUNTIME = 5


@dataclass
class AgentResourceConfig:
    """Resource allocation configuration for agents"""
    max_memory_mb: int = 1024
    max_cpu_percent: int = 50
    max_execution_time: int = 600
    max_concurrent_tasks: int = 3
    temp_storage_mb: int = 500


@dataclass
class AgentSecurityConfig:
    """Security configuration for agent operations"""
    allow_network_access: bool = False
    allow_file_system_write: bool = True
    allowed_directories: List[str] = field(default_factory=lambda: ['/tmp', './temp'])
    blocked_commands: List[str] = field(default_factory=lambda: ['rm', 'del', 'format'])
    sandbox_mode: bool = True
    encryption_required: bool = False


@dataclass
class AgentBehaviorConfig:
    """Behavioral configuration for agent operations"""
    auto_retry_failed_tasks: bool = True
    max_retries: int = 3
    retry_delay_seconds: int = 5
    log_level: str = "INFO"
    enable_detailed_logging: bool = True
    enable_profiling: bool = False
    cache_results: bool = True
    cache_ttl_seconds: int = 3600


@dataclass
class WorkflowConfig:
    """Configuration for workflow execution"""
    max_parallel_workflows: int = 5
    workflow_timeout_seconds: int = 1800
    step_timeout_seconds: int = 300
    auto_cleanup_failed: bool = True
    enable_step_caching: bool = True
    failure_threshold_percent: int = 20


@dataclass
class IntegrationConfig:
    """Configuration for external integrations"""
    llm_provider: str = "openai"
    llm_api_key: Optional[str] = None
    llm_model: str = "gpt-3.5-turbo"
    llm_max_tokens: int = 2000
    enable_ai_suggestions: bool = True
    
    database_pool_size: int = 10
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    
    external_tools_path: str = "/usr/local/bin"
    enable_external_tools: bool = True


@dataclass
class MonitoringConfig:
    """Configuration for monitoring and alerting"""
    enable_metrics: bool = True
    metrics_retention_days: int = 30
    enable_alerts: bool = True
    alert_thresholds: Dict[str, Any] = field(default_factory=lambda: {
        'failure_rate_percent': 15,
        'queue_size': 100,
        'memory_usage_percent': 80,
        'execution_time_seconds': 900
    })
    webhook_url: Optional[str] = None


@dataclass
class AgentSpecificConfig:
    """Configuration specific to individual agent types"""
    
    # File Analysis Agent
    file_analysis: Dict[str, Any] = field(default_factory=lambda: {
        'max_file_size_mb': 100,
        'supported_formats': ['*'],
        'enable_deep_scan': True,
        'entropy_threshold': 7.0,
        'metadata_extraction': True
    })
    
    # Steganography Agent
    steganography: Dict[str, Any] = field(default_factory=lambda: {
        'tools_enabled': ['zsteg', 'steghide', 'binwalk', 'exiftool'],
        'max_extraction_depth': 5,
        'enable_frequency_analysis': True,
        'password_lists': ['common_passwords.txt'],
        'bit_plane_analysis': True
    })
    
    # Cryptography Agent
    cryptography: Dict[str, Any] = field(default_factory=lambda: {
        'cipher_types': ['caesar', 'substitution', 'vigenere', 'base64', 'hex'],
        'max_key_length': 50,
        'enable_frequency_analysis': True,
        'dictionary_files': ['english_words.txt'],
        'brute_force_timeout': 300
    })
    
    # Intelligence Agent
    intelligence: Dict[str, Any] = field(default_factory=lambda: {
        'correlation_threshold': 0.3,
        'max_hypotheses': 10,
        'enable_ml_inference': False,
        'confidence_threshold': 0.6,
        'cross_validation_required': True
    })
    
    # Relationship Agent
    relationship: Dict[str, Any] = field(default_factory=lambda: {
        'similarity_algorithm': 'cosine',
        'min_similarity_score': 0.3,
        'max_relationships_per_file': 20,
        'enable_content_analysis': True,
        'graph_analysis_depth': 3
    })
    
    # Validation Agent
    validation: Dict[str, Any] = field(default_factory=lambda: {
        'strict_validation': False,
        'auto_validate_high_confidence': True,
        'require_multiple_confirmations': False,
        'validation_timeout': 60,
        'enable_cross_validation': True
    })
    
    # Presentation Agent
    presentation: Dict[str, Any] = field(default_factory=lambda: {
        'output_formats': ['html', 'json', 'pdf'],
        'include_charts': True,
        'max_report_size_mb': 50,
        'template_directory': './templates',
        'enable_interactive_elements': True
    })


@dataclass
class CompleteAgentConfig:
    """Complete configuration for the agent system"""
    resources: AgentResourceConfig = field(default_factory=AgentResourceConfig)
    security: AgentSecurityConfig = field(default_factory=AgentSecurityConfig)
    behavior: AgentBehaviorConfig = field(default_factory=AgentBehaviorConfig)
    workflows: WorkflowConfig = field(default_factory=WorkflowConfig)
    integrations: IntegrationConfig = field(default_factory=IntegrationConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    agents: AgentSpecificConfig = field(default_factory=AgentSpecificConfig)
    
    # Metadata
    config_version: str = "1.0"
    last_updated: Optional[str] = None
    environment: str = "development"


class AgentConfigManager:
    """Manages agent configuration from multiple sources"""
    
    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.config_file = self.config_dir / "agent_config.yaml"
        self.environment_config_file = self.config_dir / f"agent_config_{os.environ.get('ENVIRONMENT', 'development')}.yaml"
        
        self._config: Optional[CompleteAgentConfig] = None
        self._config_sources: Dict[AgentConfigLevel, Dict[str, Any]] = {}
        
        logger.info(f"AgentConfigManager initialized with config_dir: {self.config_dir}")
    
    def load_config(self, force_reload: bool = False) -> CompleteAgentConfig:
        """Load configuration from all sources with proper precedence"""
        if self._config is not None and not force_reload:
            return self._config
        
        logger.info("Loading agent configuration from all sources...")
        
        # 1. Load default configuration
        self._config_sources[AgentConfigLevel.DEFAULT] = asdict(CompleteAgentConfig())
        
        # 2. Load environment variables
        self._load_environment_config()
        
        # 3. Load configuration files
        self._load_file_config()
        
        # 4. Load database configuration (if available)
        self._load_database_config()
        
        # 5. Merge all configurations with proper precedence
        merged_config = self._merge_configurations()
        
        # 6. Validate configuration
        self._config = self._validate_and_create_config(merged_config)
        
        logger.info("✅ Agent configuration loaded successfully")
        self._log_config_summary()
        
        return self._config
    
    def _load_environment_config(self):
        """Load configuration from environment variables"""
        env_config = {}
        
        # Map environment variables to config structure
        env_mappings = {
            'AGENT_MAX_MEMORY_MB': ('resources', 'max_memory_mb', int),
            'AGENT_MAX_CPU_PERCENT': ('resources', 'max_cpu_percent', int),
            'AGENT_MAX_EXECUTION_TIME': ('resources', 'max_execution_time', int),
            'AGENT_SANDBOX_MODE': ('security', 'sandbox_mode', bool),
            'AGENT_LOG_LEVEL': ('behavior', 'log_level', str),
            'AGENT_AUTO_RETRY': ('behavior', 'auto_retry_failed_tasks', bool),
            'AGENT_MAX_RETRIES': ('behavior', 'max_retries', int),
            'WORKFLOW_TIMEOUT': ('workflows', 'workflow_timeout_seconds', int),
            'LLM_PROVIDER': ('integrations', 'llm_provider', str),
            'LLM_API_KEY': ('integrations', 'llm_api_key', str),
            'LLM_MODEL': ('integrations', 'llm_model', str),
            'REDIS_HOST': ('integrations', 'redis_host', str),
            'REDIS_PORT': ('integrations', 'redis_port', int),
            'ENABLE_METRICS': ('monitoring', 'enable_metrics', bool),
            'WEBHOOK_URL': ('monitoring', 'webhook_url', str)
        }
        
        for env_var, (section, key, type_func) in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    if type_func == bool:
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    else:
                        value = type_func(value)
                    
                    if section not in env_config:
                        env_config[section] = {}
                    env_config[section][key] = value
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid environment variable {env_var}={value}: {e}")
        
        self._config_sources[AgentConfigLevel.ENVIRONMENT] = env_config
        logger.info(f"Loaded {len(env_config)} environment configuration sections")
    
    def _load_file_config(self):
        """Load configuration from YAML files"""
        file_config = {}
        
        # Load main config file
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    main_config = yaml.safe_load(f) or {}
                file_config.update(main_config)
                logger.info(f"Loaded main config file: {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to load main config file: {e}")
        
        # Load environment-specific config file
        if self.environment_config_file.exists():
            try:
                with open(self.environment_config_file, 'r') as f:
                    env_config = yaml.safe_load(f) or {}
                file_config = self._deep_merge_dict(file_config, env_config)
                logger.info(f"Loaded environment config file: {self.environment_config_file}")
            except Exception as e:
                logger.error(f"Failed to load environment config file: {e}")
        
        self._config_sources[AgentConfigLevel.FILE] = file_config
    
    def _load_database_config(self):
        """Load configuration from database (if available)"""
        db_config = {}
        
        try:
            # This would integrate with your database to load saved configurations
            # For now, this is a placeholder
            from crypto_hunter_web.extensions import db
            
            # Example query - adjust based on your schema
            # config_rows = db.session.execute(
            #     "SELECT config_key, config_value FROM agent_configurations WHERE active = true"
            # ).fetchall()
            
            # For demonstration, we'll just log that database config loading is available
            logger.debug("Database configuration loading available but not implemented")
            
        except Exception as e:
            logger.debug(f"Database configuration not available: {e}")
        
        self._config_sources[AgentConfigLevel.DATABASE] = db_config
    
    def _merge_configurations(self) -> Dict[str, Any]:
        """Merge configurations with proper precedence"""
        merged = {}
        
        # Merge in order of precedence (lowest to highest)
        for level in [AgentConfigLevel.DEFAULT, AgentConfigLevel.ENVIRONMENT, 
                     AgentConfigLevel.FILE, AgentConfigLevel.DATABASE]:
            if level in self._config_sources:
                merged = self._deep_merge_dict(merged, self._config_sources[level])
        
        return merged
    
    def _deep_merge_dict(self, base: Dict, update: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = base.copy()
        
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_dict(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _validate_and_create_config(self, config_dict: Dict[str, Any]) -> CompleteAgentConfig:
        """Validate and create configuration object"""
        try:
            # Create configuration sections
            resources = AgentResourceConfig(**config_dict.get('resources', {}))
            security = AgentSecurityConfig(**config_dict.get('security', {}))
            behavior = AgentBehaviorConfig(**config_dict.get('behavior', {}))
            workflows = WorkflowConfig(**config_dict.get('workflows', {}))
            integrations = IntegrationConfig(**config_dict.get('integrations', {}))
            monitoring = MonitoringConfig(**config_dict.get('monitoring', {}))
            agents = AgentSpecificConfig(**config_dict.get('agents', {}))
            
            # Create complete configuration
            complete_config = CompleteAgentConfig(
                resources=resources,
                security=security,
                behavior=behavior,
                workflows=workflows,
                integrations=integrations,
                monitoring=monitoring,
                agents=agents,
                config_version=config_dict.get('config_version', '1.0'),
                environment=config_dict.get('environment', os.environ.get('ENVIRONMENT', 'development'))
            )
            
            # Validate configuration
            self._validate_config(complete_config)
            
            return complete_config
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise ValueError(f"Invalid agent configuration: {e}")
    
    def _validate_config(self, config: CompleteAgentConfig):
        """Validate configuration for consistency and safety"""
        # Resource validation
        if config.resources.max_memory_mb < 100:
            raise ValueError("max_memory_mb must be at least 100MB")
        
        if config.resources.max_cpu_percent < 1 or config.resources.max_cpu_percent > 100:
            raise ValueError("max_cpu_percent must be between 1 and 100")
        
        # Security validation
        if config.security.sandbox_mode and not config.security.allowed_directories:
            raise ValueError("sandbox_mode requires allowed_directories to be specified")
        
        # Workflow validation
        if config.workflows.max_parallel_workflows < 1:
            raise ValueError("max_parallel_workflows must be at least 1")
        
        # Integration validation
        if config.integrations.llm_provider and not config.integrations.llm_api_key:
            logger.warning("LLM provider specified but no API key provided")
        
        logger.info("✅ Configuration validation passed")
    
    def _log_config_summary(self):
        """Log a summary of the loaded configuration"""
        if not self._config:
            return
        
        logger.info("📊 Agent Configuration Summary:")
        logger.info(f"  Environment: {self._config.environment}")
        logger.info(f"  Max Memory: {self._config.resources.max_memory_mb}MB")
        logger.info(f"  Max CPU: {self._config.resources.max_cpu_percent}%")
        logger.info(f"  Sandbox Mode: {self._config.security.sandbox_mode}")
        logger.info(f"  Log Level: {self._config.behavior.log_level}")
        logger.info(f"  Max Workflows: {self._config.workflows.max_parallel_workflows}")
        logger.info(f"  LLM Provider: {self._config.integrations.llm_provider}")
        logger.info(f"  Metrics Enabled: {self._config.monitoring.enable_metrics}")
    
    def save_config(self, config: CompleteAgentConfig, save_to_file: bool = True):
        """Save configuration to file"""
        if save_to_file:
            try:
                config_dict = asdict(config)
                with open(self.config_file, 'w') as f:
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                logger.info(f"Configuration saved to {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to save configuration: {e}")
                raise
    
    def get_agent_config(self, agent_type: str) -> Dict[str, Any]:
        """Get configuration for specific agent type"""
        if not self._config:
            self.load_config()
        
        agent_configs = asdict(self._config.agents)
        return agent_configs.get(agent_type, {})
    
    def update_runtime_config(self, section: str, key: str, value: Any):
        """Update configuration at runtime"""
        if not self._config:
            self.load_config()
        
        # Store runtime changes
        if AgentConfigLevel.RUNTIME not in self._config_sources:
            self._config_sources[AgentConfigLevel.RUNTIME] = {}
        
        if section not in self._config_sources[AgentConfigLevel.RUNTIME]:
            self._config_sources[AgentConfigLevel.RUNTIME][section] = {}
        
        self._config_sources[AgentConfigLevel.RUNTIME][section][key] = value
        
        # Reload configuration with new runtime values
        self.load_config(force_reload=True)
        
        logger.info(f"Runtime configuration updated: {section}.{key} = {value}")
    
    def get_effective_config_source(self, section: str, key: str) -> AgentConfigLevel:
        """Get the source of a specific configuration value"""
        for level in reversed(list(AgentConfigLevel)):
            if (level in self._config_sources and 
                section in self._config_sources[level] and 
                key in self._config_sources[level][section]):
                return level
        
        return AgentConfigLevel.DEFAULT


# Global configuration manager instance
config_manager = AgentConfigManager()


def get_agent_config() -> CompleteAgentConfig:
    """Get the current agent configuration"""
    return config_manager.load_config()


def get_agent_specific_config(agent_type: str) -> Dict[str, Any]:
    """Get configuration for a specific agent type"""
    return config_manager.get_agent_config(agent_type)


def update_config(section: str, key: str, value: Any):
    """Update configuration at runtime"""
    config_manager.update_runtime_config(section, key, value)


# Configuration templates for different environments
ENVIRONMENT_TEMPLATES = {
    'development': {
        'resources': {
            'max_memory_mb': 512,
            'max_execution_time': 300,
            'max_concurrent_tasks': 2
        },
        'security': {
            'sandbox_mode': False,
            'allow_network_access': True
        },
        'behavior': {
            'log_level': 'DEBUG',
            'enable_detailed_logging': True,
            'enable_profiling': True
        },
        'monitoring': {
            'enable_metrics': True,
            'enable_alerts': False
        }
    },
    'testing': {
        'resources': {
            'max_memory_mb': 256,
            'max_execution_time': 60,
            'max_concurrent_tasks': 1
        },
        'security': {
            'sandbox_mode': True,
            'allow_network_access': False
        },
        'behavior': {
            'log_level': 'WARNING',
            'auto_retry_failed_tasks': False,
            'cache_results': False
        }
    },
    'production': {
        'resources': {
            'max_memory_mb': 2048,
            'max_execution_time': 900,
            'max_concurrent_tasks': 5
        },
        'security': {
            'sandbox_mode': True,
            'allow_network_access': False,
            'encryption_required': True
        },
        'behavior': {
            'log_level': 'INFO',
            'enable_detailed_logging': False,
            'enable_profiling': False
        },
        'workflows': {
            'max_parallel_workflows': 10
        },
        'monitoring': {
            'enable_metrics': True,
            'enable_alerts': True,
            'metrics_retention_days': 90
        }
    }
}


def create_environment_config(environment: str, output_file: Optional[str] = None) -> str:
    """Create configuration file for specific environment"""
    if environment not in ENVIRONMENT_TEMPLATES:
        raise ValueError(f"Unknown environment: {environment}. Available: {list(ENVIRONMENT_TEMPLATES.keys())}")
    
    template = ENVIRONMENT_TEMPLATES[environment]
    
    if output_file is None:
        output_file = f"agent_config_{environment}.yaml"
    
    with open(output_file, 'w') as f:
        yaml.dump(template, f, default_flow_style=False, indent=2)
    
    logger.info(f"Environment configuration created: {output_file}")
    return output_file


# CLI utility for configuration management
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python agent_config.py [load|create-env|validate] [args...]")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "load":
        config = get_agent_config()
        print("✅ Configuration loaded successfully")
        print(f"Environment: {config.environment}")
        print(f"Version: {config.config_version}")
        
    elif command == "create-env":
        if len(sys.argv) < 3:
            print("Usage: python agent_config.py create-env <environment>")
            sys.exit(1)
        
        env = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        
        try:
            file_path = create_environment_config(env, output_file)
            print(f"✅ Environment configuration created: {file_path}")
        except ValueError as e:
            print(f"❌ {e}")
            sys.exit(1)
    
    elif command == "validate":
        try:
            config = get_agent_config()
            print("✅ Configuration is valid")
        except Exception as e:
            print(f"❌ Configuration validation failed: {e}")
            sys.exit(1)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)