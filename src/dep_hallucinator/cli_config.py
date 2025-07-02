"""
Comprehensive configuration management for Dep-Hallucinator.

Provides configurable settings for all system components including timeouts,
limits, security settings, ML parameters, and heuristic weights.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

console = Console()


@dataclass
class ScanConfig:
    """Core scanning configuration."""

    rate_limit: float = 10.0
    max_concurrent: int = 20
    timeout_seconds: int = 30
    retry_attempts: int = 3
    fail_on_high: bool = False
    quiet: bool = False
    verbose: bool = False
    output_format: str = "console"
    output_file: Optional[str] = None


@dataclass
class SecurityConfig:
    """Security and validation configuration."""

    max_file_size_mb: int = 10
    max_credential_length: int = 500
    max_input_length: int = 1000
    max_description_length: int = 5000
    max_author_length: int = 200
    max_lines_per_file: int = 100000  # Maximum lines to process per dependency file
    allowed_file_extensions: List[str] = field(
        default_factory=lambda: [
            ".txt",
            ".json",
            ".lock",
            ".xml",
            ".gradle",
            ".kts",
            ".mod",
            ".sum",
            ".toml",
        ]
    )
    min_credential_length: int = 8

    @property
    def max_file_size_bytes(self) -> int:
        """Convert MB to bytes for internal use."""
        return self.max_file_size_mb * 1024 * 1024


@dataclass
class MLConfig:
    """Machine Learning model configuration."""

    max_feature_value: float = 10.0
    min_feature_value: float = -10.0
    max_iterations: int = 100
    ai_probability_threshold: float = 0.7
    high_confidence_threshold: float = 0.85
    ensemble_ml_weight: float = 0.35
    ensemble_heuristic_weight: float = 0.65
    confidence_levels: Dict[str, float] = field(
        default_factory=lambda: {"HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3}
    )


@dataclass
class HeuristicConfig:
    """Heuristic analysis configuration."""

    suspicious_threshold: float = 0.7
    highly_suspicious_threshold: float = 0.85
    risk_thresholds: Dict[str, float] = field(
        default_factory=lambda: {"HIGH": 0.85, "MEDIUM": 0.60, "LOW": 0.30}
    )
    weights: Dict[str, float] = field(
        default_factory=lambda: {
            "package_age": 0.22,
            "download_count": 0.18,
            "metadata_completeness": 0.18,
            "naming_pattern": 0.14,
            "typosquatting": 0.09,
            "version_analysis": 0.09,
            "ml_pattern_analysis": 0.10,
        }
    )
    package_age_scoring: Dict[str, float] = field(
        default_factory=lambda: {
                    "very_new": 0.95,
        "new": 0.85,
        "recent": 0.70,
        "moderate": 0.45,
        "established": 0.25,
        "mature": 0.10,
        }
    )
    download_thresholds: Dict[str, int] = field(
        default_factory=lambda: {
            "very_low": 10,
            "low": 100,
            "moderate": 1000,
            "high": 10000,
            "very_high": 100000,
        }
    )


@dataclass
class NetworkConfig:
    """Network and registry configuration."""

    user_agent: str = "dep-hallucinator/1.0.0 (Security Scanner)"
    registry_urls: Dict[str, str] = field(
        default_factory=lambda: {
            "pypi": "https://pypi.org/pypi",
            "npm": "https://registry.npmjs.org",
        }
    )
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    pool_timeout: float = 5.0
    max_keepalive_connections: int = 100
    max_connections: int = 100


@dataclass
class LoggingConfig:
    """Logging and error handling configuration."""

    log_level: str = "WARNING"
    enable_file_logging: bool = False
    log_file_path: Optional[str] = None
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_log_file_size_mb: int = 50
    log_backup_count: int = 3
    enable_sensitive_data_masking: bool = True


@dataclass
class PerformanceConfig:
    """Performance optimization configuration."""

    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    max_cache_size: int = 1000
    gc_threshold: int = 700
    memory_limit_mb: Optional[int] = None
    enable_compression: bool = True


@dataclass
class ProductionConfig:
    """Production-specific configuration optimizations."""
    
    # Resource limits for production
    max_memory_mb: int = 512
    max_cpu_usage_percent: int = 80
    
    # Performance optimizations
    enable_uvloop: bool = True
    enable_orjson: bool = True
    enable_lz4_compression: bool = True
    
    # Connection pooling
    http_pool_connections: int = 10
    http_pool_maxsize: int = 20
    http_retries: int = 3
    
    # Async optimizations
    max_async_workers: int = 20
    async_timeout: float = 30.0
    
    # Cache optimizations
    cache_compression_level: int = 1
    cache_memory_limit_mb: int = 128
    
    # Monitoring and health checks
    enable_metrics: bool = True
    metrics_interval_seconds: int = 60
    enable_health_checks: bool = True
    health_check_interval_seconds: int = 30
    
    # Graceful shutdown
    shutdown_timeout_seconds: int = 30
    
    @classmethod
    def for_environment(cls, env: str = "production") -> "ProductionConfig":
        """Create production config optimized for specific environments."""
        if env == "production":
            return cls(
                max_memory_mb=512,
                max_cpu_usage_percent=80,
                http_pool_connections=10,
                max_async_workers=15,
                cache_memory_limit_mb=128,
            )
        elif env == "high-performance":
            return cls(
                max_memory_mb=1024,
                max_cpu_usage_percent=90,
                http_pool_connections=20,
                max_async_workers=30,
                cache_memory_limit_mb=256,
            )
        elif env == "resource-constrained":
            return cls(
                max_memory_mb=256,
                max_cpu_usage_percent=70,
                http_pool_connections=5,
                max_async_workers=10,
                cache_memory_limit_mb=64,
            )
        else:
            return cls()


@dataclass
class ComprehensiveConfig:
    """Main configuration containing all subsections."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    heuristics: HeuristicConfig = field(default_factory=HeuristicConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    production: ProductionConfig = field(default_factory=ProductionConfig)

    # Backwards compatibility
    @property
    def registry_urls(self) -> Dict[str, str]:
        """Backwards compatibility property."""
        return self.network.registry_urls

    @property
    def user_agent(self) -> str:
        """Backwards compatibility property."""
        return self.network.user_agent
    
    @classmethod
    def for_production(cls) -> "ComprehensiveConfig":
        """Create production-optimized configuration."""
        config = cls()
        
        # Production-optimized scan settings
        config.scan.rate_limit = 15.0  # Higher throughput
        config.scan.max_concurrent = 25
        config.scan.timeout_seconds = 20
        config.scan.retry_attempts = 2
        
        # Production security settings
        config.security.max_file_size_mb = 5
        config.security.max_lines_per_file = 50000
        
        # Performance optimizations
        config.performance.enable_caching = True
        config.performance.cache_ttl_seconds = 1800
        config.performance.max_cache_size = 2000
        config.performance.gc_threshold = 500
        config.performance.enable_compression = True
        
        # Network optimizations
        config.network.connect_timeout = 5.0
        config.network.read_timeout = 15.0
        config.network.max_keepalive_connections = 50
        config.network.max_connections = 100
        
        # Logging for production
        config.logging.log_level = "INFO"
        config.logging.enable_file_logging = True
        config.logging.enable_sensitive_data_masking = True
        
        # Production-specific settings
        config.production = ProductionConfig.for_environment("production")
        
        return config


# Global configuration instance
_global_config: Optional[ComprehensiveConfig] = None


def validate_config_values(config: ComprehensiveConfig) -> List[str]:
    """
    Validate configuration values and return any errors.

    Args:
        config: Configuration to validate

    Returns:
        List[str]: List of validation errors (empty if valid)
    """
    errors = []

    # Validate scan config
    if config.scan.rate_limit <= 0:
        errors.append("scan.rate_limit must be positive")
    if config.scan.max_concurrent <= 0:
        errors.append("scan.max_concurrent must be positive")
    if config.scan.timeout_seconds <= 0:
        errors.append("scan.timeout_seconds must be positive")
    if config.scan.retry_attempts < 0:
        errors.append("scan.retry_attempts must be non-negative")

    # Validate security config
    if config.security.max_file_size_mb <= 0:
        errors.append("security.max_file_size_mb must be positive")
    if config.security.max_credential_length <= 0:
        errors.append("security.max_credential_length must be positive")
    if config.security.min_credential_length <= 0:
        errors.append("security.min_credential_length must be positive")
    if config.security.min_credential_length > config.security.max_credential_length:
        errors.append("security.min_credential_length must be <= max_credential_length")

    # Validate ML config
    if config.ml.min_feature_value >= config.ml.max_feature_value:
        errors.append("ml.min_feature_value must be < max_feature_value")
    if not (0.0 <= config.ml.ai_probability_threshold <= 1.0):
        errors.append("ml.ai_probability_threshold must be between 0.0 and 1.0")
    if not (0.0 <= config.ml.high_confidence_threshold <= 1.0):
        errors.append("ml.high_confidence_threshold must be between 0.0 and 1.0")
    if (
        abs(config.ml.ensemble_ml_weight + config.ml.ensemble_heuristic_weight - 1.0)
        > 0.01
    ):
        errors.append(
            "ml.ensemble_ml_weight + ensemble_heuristic_weight must sum to 1.0"
        )

    # Validate heuristics config
    heuristic_weight_sum = sum(config.heuristics.weights.values())
    if abs(heuristic_weight_sum - 1.0) > 0.01:
        errors.append(
            f"heuristics.weights must sum to 1.0 (currently: {heuristic_weight_sum:.3f})"
        )

    # Validate network config
    if config.network.connect_timeout <= 0:
        errors.append("network.connect_timeout must be positive")
    if config.network.read_timeout <= 0:
        errors.append("network.read_timeout must be positive")

    return errors


def load_config_file(config_path: Path) -> Optional[Dict[str, Any]]:
    """Load config from file."""
    if not config_path.exists():
        return None

    try:
        with open(config_path, encoding="utf-8") as f:
            if config_path.suffix.lower() in [".yaml", ".yml"]:
                if HAS_YAML:
                    return yaml.safe_load(f)
                else:
                    console.print(
                        "⚠️  PyYAML not installed, skipping YAML config", style="yellow"
                    )
                    return None
            elif config_path.suffix.lower() == ".json":
                return json.load(f)
    except Exception as e:
        console.print(
            f"⚠️  Error loading config from {config_path}: {e}", style="yellow"
        )

    return None


def find_config_file() -> Optional[Path]:
    """Find config file in standard locations."""
    locations = [
        Path.cwd() / ".dep-hallucinator.json",
        Path.cwd() / ".dep-hallucinator.yaml",
        Path.cwd() / ".dep-hallucinator.yml",
        Path.home() / ".config" / "dep-hallucinator" / "config.json",
        Path.home() / ".config" / "dep-hallucinator" / "config.yaml",
        Path.home() / ".dep-hallucinator.json",
    ]

    for location in locations:
        if location.exists():
            return location

    return None


def load_environment_overrides(config: ComprehensiveConfig) -> None:
    """Load environment variable overrides with production optimizations."""
    
    # Helper function for safe environment variable parsing
    def get_env_bool(key: str, default: bool = False) -> bool:
        value = os.environ.get(key, "").lower()
        return value in ["true", "1", "yes", "on"] if value else default
    
    def get_env_int(key: str, default: Optional[int] = None) -> Optional[int]:
        try:
            return int(os.environ[key]) if key in os.environ else default
        except ValueError:
            console.print(f"⚠️  Invalid integer value for {key}, using default", style="yellow")
            return default
    
    def get_env_float(key: str, default: Optional[float] = None) -> Optional[float]:
        try:
            return float(os.environ[key]) if key in os.environ else default
        except ValueError:
            console.print(f"⚠️  Invalid float value for {key}, using default", style="yellow")
            return default

    # Production mode detection
    production_mode = get_env_bool("DEP_HALLUCINATOR_PRODUCTION", False)
    environment = os.environ.get("DEP_HALLUCINATOR_ENV", "development").lower()
    
    # If production mode is enabled, apply production config first
    if production_mode or environment == "production":
        prod_config = ComprehensiveConfig.for_production()
        config.scan = prod_config.scan
        config.security = prod_config.security
        config.performance = prod_config.performance
        config.network = prod_config.network
        config.logging = prod_config.logging
        config.production = prod_config.production

    # Scan configuration overrides
    if rate_limit := get_env_float("DEP_HALLUCINATOR_RATE_LIMIT"):
        config.scan.rate_limit = rate_limit
    if max_concurrent := get_env_int("DEP_HALLUCINATOR_MAX_CONCURRENT"):
        config.scan.max_concurrent = max_concurrent
    if timeout := get_env_int("DEP_HALLUCINATOR_TIMEOUT"):
        config.scan.timeout_seconds = timeout
    if retry_attempts := get_env_int("DEP_HALLUCINATOR_RETRY_ATTEMPTS"):
        config.scan.retry_attempts = retry_attempts
    
    config.scan.fail_on_high = get_env_bool("DEP_HALLUCINATOR_FAIL_ON_HIGH", config.scan.fail_on_high)

    # Security configuration overrides
    if max_file_size := get_env_int("DEP_HALLUCINATOR_MAX_FILE_SIZE_MB"):
        config.security.max_file_size_mb = max_file_size
    if max_cred_length := get_env_int("DEP_HALLUCINATOR_MAX_CREDENTIAL_LENGTH"):
        config.security.max_credential_length = max_cred_length

    # Network configuration overrides
    if user_agent := os.environ.get("DEP_HALLUCINATOR_USER_AGENT"):
        config.network.user_agent = user_agent
    if connect_timeout := get_env_float("DEP_HALLUCINATOR_CONNECT_TIMEOUT"):
        config.network.connect_timeout = connect_timeout
    if read_timeout := get_env_float("DEP_HALLUCINATOR_READ_TIMEOUT"):
        config.network.read_timeout = read_timeout

    # ML configuration overrides
    if ai_threshold := get_env_float("DEP_HALLUCINATOR_AI_THRESHOLD"):
        config.ml.ai_probability_threshold = ai_threshold
    if ml_weight := get_env_float("DEP_HALLUCINATOR_ML_WEIGHT"):
        if 0.0 <= ml_weight <= 1.0:
            config.ml.ensemble_ml_weight = ml_weight
            config.ml.ensemble_heuristic_weight = 1.0 - ml_weight

    # Logging configuration overrides
    if log_level := os.environ.get("DEP_HALLUCINATOR_LOG_LEVEL"):
        config.logging.log_level = log_level.upper()
    if log_file := os.environ.get("DEP_HALLUCINATOR_LOG_FILE"):
        config.logging.log_file_path = log_file
        config.logging.enable_file_logging = True
    
    # Production-specific environment variables
    if max_memory := get_env_int("DEP_HALLUCINATOR_MAX_MEMORY_MB"):
        config.production.max_memory_mb = max_memory
    if max_cpu := get_env_int("DEP_HALLUCINATOR_MAX_CPU_PERCENT"):
        config.production.max_cpu_usage_percent = max_cpu
    if pool_connections := get_env_int("DEP_HALLUCINATOR_HTTP_POOL_CONNECTIONS"):
        config.production.http_pool_connections = pool_connections
    if async_workers := get_env_int("DEP_HALLUCINATOR_MAX_ASYNC_WORKERS"):
        config.production.max_async_workers = async_workers
    
    # Performance tuning overrides
    config.production.enable_uvloop = get_env_bool("DEP_HALLUCINATOR_ENABLE_UVLOOP", config.production.enable_uvloop)
    config.production.enable_orjson = get_env_bool("DEP_HALLUCINATOR_ENABLE_ORJSON", config.production.enable_orjson)
    config.production.enable_lz4_compression = get_env_bool("DEP_HALLUCINATOR_ENABLE_LZ4", config.production.enable_lz4_compression)
    
    # Cache configuration overrides
    if cache_memory := get_env_int("DEP_HALLUCINATOR_CACHE_MEMORY_MB"):
        config.production.cache_memory_limit_mb = cache_memory
    if cache_ttl := get_env_int("DEP_HALLUCINATOR_CACHE_TTL_SECONDS"):
        config.performance.cache_ttl_seconds = cache_ttl
    
    # Monitoring and health checks
    config.production.enable_metrics = get_env_bool("DEP_HALLUCINATOR_ENABLE_METRICS", config.production.enable_metrics)
    config.production.enable_health_checks = get_env_bool("DEP_HALLUCINATOR_ENABLE_HEALTH_CHECKS", config.production.enable_health_checks)


def apply_config_section(
    config: Any, section_data: Dict[str, Any], section_name: str
) -> None:
    """Apply configuration from dictionary to config section."""
    for key, value in section_data.items():
        if hasattr(config, key):
            if isinstance(getattr(config, key), dict) and isinstance(value, dict):
                # Handle nested dictionaries (like weights, thresholds)
                getattr(config, key).update(value)
            else:
                setattr(config, key, value)
        else:
            console.print(
                f"⚠️  Unknown config key in {section_name}: {key}", style="yellow"
            )


def load_config() -> ComprehensiveConfig:
    """Load comprehensive configuration from file and environment."""
    global _global_config

    if _global_config is not None:
        return _global_config

    config = ComprehensiveConfig()

    # Load from config file
    config_file = find_config_file()
    if config_file:
        file_config = load_config_file(config_file)
        if file_config:
            if "scan" in file_config:
                apply_config_section(config.scan, file_config["scan"], "scan")

            if "security" in file_config:
                apply_config_section(
                    config.security, file_config["security"], "security"
                )

            if "ml" in file_config:
                apply_config_section(config.ml, file_config["ml"], "ml")

            if "heuristics" in file_config:
                apply_config_section(
                    config.heuristics, file_config["heuristics"], "heuristics"
                )

            if "network" in file_config:
                apply_config_section(config.network, file_config["network"], "network")

            if "logging" in file_config:
                apply_config_section(config.logging, file_config["logging"], "logging")

            if "performance" in file_config:
                apply_config_section(
                    config.performance, file_config["performance"], "performance"
                )

            # Backwards compatibility
            if "registry_urls" in file_config:
                config.network.registry_urls.update(file_config["registry_urls"])

            if "user_agent" in file_config:
                config.network.user_agent = str(file_config["user_agent"])

    load_environment_overrides(config)

    # Validate configuration
    validation_errors = validate_config_values(config)
    if validation_errors:
        console.print("⚠️  Configuration validation errors:", style="red")
        for error in validation_errors:
            console.print(f"  • {error}", style="red")
        console.print("Using default values for invalid settings.", style="yellow")

    _global_config = config
    return config


def get_config() -> ComprehensiveConfig:
    """Get the global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = load_config()
    return _global_config


def reset_config() -> None:
    """Reset the global configuration (useful for testing)."""
    global _global_config
    _global_config = None


def create_sample_config() -> str:
    """Generate comprehensive sample configuration."""
    sample_config = {
        "scan": {
            "rate_limit": 10.0,
            "max_concurrent": 20,
            "timeout_seconds": 30,
            "retry_attempts": 3,
            "fail_on_high": False,
        },
        "security": {
            "max_file_size_mb": 10,
            "max_credential_length": 500,
            "max_input_length": 1000,
            "max_description_length": 5000,
            "max_author_length": 200,
            "allowed_file_extensions": [".txt", ".json"],
            "min_credential_length": 8,
        },
        "ml": {
            "max_feature_value": 10.0,
            "min_feature_value": -10.0,
            "max_iterations": 100,
            "ai_probability_threshold": 0.7,
            "high_confidence_threshold": 0.85,
            "ensemble_ml_weight": 0.35,
            "ensemble_heuristic_weight": 0.65,
            "confidence_levels": {"HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3},
        },
        "heuristics": {
            "suspicious_threshold": 0.7,
            "highly_suspicious_threshold": 0.85,
            "risk_thresholds": {"HIGH": 0.85, "MEDIUM": 0.60, "LOW": 0.30},
            "weights": {
                "package_age": 0.22,
                "download_count": 0.18,
                "metadata_completeness": 0.18,
                "naming_pattern": 0.14,
                "typosquatting": 0.09,
                "version_analysis": 0.09,
                "ml_pattern_analysis": 0.10,
            },
            "package_age_scoring": {
                "very_new": 0.95,
                "new": 0.85,
                "recent": 0.70,
                "moderate": 0.45,
                "established": 0.25,
                "mature": 0.10,
            },
            "download_thresholds": {
                "very_low": 10,
                "low": 100,
                "moderate": 1000,
                "high": 10000,
                "very_high": 100000,
            },
        },
        "network": {
            "user_agent": "dep-hallucinator/1.0.0 (Security Scanner)",
            "registry_urls": {
                "pypi": "https://pypi.org/pypi",
                "npm": "https://registry.npmjs.org",
            },
            "connect_timeout": 10.0,
            "read_timeout": 30.0,
            "pool_timeout": 5.0,
            "max_keepalive_connections": 100,
            "max_connections": 100,
        },
        "logging": {
            "log_level": "WARNING",
            "enable_file_logging": False,
            "log_file_path": None,
            "log_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "max_log_file_size_mb": 50,
            "log_backup_count": 3,
            "enable_sensitive_data_masking": True,
        },
        "performance": {
            "enable_caching": True,
            "cache_ttl_seconds": 3600,
            "max_cache_size": 1000,
            "gc_threshold": 700,
            "memory_limit_mb": None,
            "enable_compression": True,
        },
    }

    return json.dumps(sample_config, indent=2)


# Backwards compatibility aliases
CLIConfig = ComprehensiveConfig
