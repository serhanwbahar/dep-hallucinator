"""
Structured logging configuration for dep-hallucinator.

Provides consistent, machine-readable logging for security analysis,
SIEM integration, and operational monitoring.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "component": getattr(record, "component", "dep_hallucinator"),
            "message": record.getMessage(),
        }

        # Add extra fields from record
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "getMessage",
                "exc_info",
                "exc_text",
                "stack_info",
            ]:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


class SecurityLogger:
    """Structured logger for security events."""

    def __init__(self, name: str = "dep_hallucinator"):
        self.logger = logging.getLogger(name)
        self._setup_logger()
        self.scan_context: Dict[str, Any] = {}

    def _setup_logger(self) -> None:
        """Setup logger with structured formatting."""
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(StructuredFormatter())
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def set_scan_context(
        self,
        scan_id: Optional[str] = None,
        file_path: Optional[str] = None,
        total_dependencies: Optional[int] = None,
    ) -> None:
        """Set scan context for logging."""
        self.scan_context = {}
        if scan_id:
            self.scan_context["scan_id"] = scan_id
        if file_path:
            self.scan_context["file_path"] = file_path
        if total_dependencies is not None:
            self.scan_context["total_dependencies"] = total_dependencies

    def clear_scan_context(self) -> None:
        """Clear scan context."""
        self.scan_context.clear()

    def _log(self, level: str, event_type: str, **kwargs) -> None:
        """Internal logging method."""
        log_data = {"event_type": event_type, **self.scan_context, **kwargs}

        # Create log record with extra data
        getattr(self.logger, level.lower())("", extra=log_data)

    def info(self, event_type: str, **kwargs) -> None:
        """Log info level event."""
        self._log("info", event_type, **kwargs)

    def warning(self, event_type: str, **kwargs) -> None:
        """Log warning level event."""
        self._log("warning", event_type, **kwargs)

    def error(self, event_type: str, **kwargs) -> None:
        """Log error level event."""
        self._log("error", event_type, **kwargs)

    def debug(self, event_type: str, **kwargs) -> None:
        """Log debug level event."""
        self._log("debug", event_type, **kwargs)


# Global logger instances
_security_logger = SecurityLogger("security")
_scanner_logger = SecurityLogger("scanner")
_forensic_logger = SecurityLogger("forensic")
_registry_logger = SecurityLogger("registry")
_ml_logger = SecurityLogger("ml_engine")


def get_security_logger() -> SecurityLogger:
    """Get security events logger."""
    return _security_logger


def get_scanner_logger() -> SecurityLogger:
    """Get scanner operations logger."""
    return _scanner_logger


def get_forensic_logger() -> SecurityLogger:
    """Get forensic operations logger."""
    return _forensic_logger


def get_registry_logger() -> SecurityLogger:
    """Get registry operations logger."""
    return _registry_logger


def get_ml_logger() -> SecurityLogger:
    """Get ML operations logger."""
    return _ml_logger


def log_security_event(
    event_type: str,
    severity: str = "info",
    package_name: Optional[str] = None,
    risk_level: Optional[str] = None,
    **kwargs,
) -> None:
    """
    Log a security-specific event.

    Args:
        event_type: Type of security event
        severity: Log severity level
        package_name: Package name if applicable
        risk_level: Risk level if applicable
        **kwargs: Additional context
    """
    logger = get_security_logger()

    log_data = kwargs.copy()
    if package_name:
        log_data["package_name"] = package_name
    if risk_level:
        log_data["risk_level"] = risk_level

    # Route to appropriate log level
    getattr(logger, severity.lower(), logger.info)(event_type, **log_data)


def log_scan_start(scan_id: str, file_path: str, total_dependencies: int) -> None:
    """Log scan start event."""
    logger = get_scanner_logger()
    logger.set_scan_context(scan_id, file_path, total_dependencies)
    logger.info(
        "scan_started",
        scan_id=scan_id,
        file_path=file_path,
        total_dependencies=total_dependencies,
    )


def log_scan_complete(
    scan_id: str,
    duration_ms: int,
    findings_count: int,
    critical_count: int = 0,
    high_count: int = 0,
) -> None:
    """Log scan completion event."""
    logger = get_scanner_logger()
    logger.info(
        "scan_completed",
        scan_id=scan_id,
        scan_duration_ms=duration_ms,
        total_findings=findings_count,
        critical_findings=critical_count,
        high_findings=high_count,
    )
    logger.clear_scan_context()


def log_package_analysis(
    package_name: str,
    registry: str,
    risk_level: str,
    suspicion_score: Optional[float] = None,
    ml_probability: Optional[float] = None,
) -> None:
    """Log package analysis result."""
    logger = get_scanner_logger()

    log_data = {
        "package_name": package_name,
        "registry": registry,
        "risk_level": risk_level,
    }

    if suspicion_score is not None:
        log_data["suspicion_score"] = float(suspicion_score)
    if ml_probability is not None:
        log_data["ml_probability"] = float(ml_probability)

    if risk_level.upper() in ["CRITICAL", "HIGH"]:
        logger.warning("high_risk_package_detected", **log_data)
    else:
        logger.info("package_analyzed", **log_data)


def log_registry_check(
    package_name: str,
    registry: str,
    exists: bool,
    response_time_ms: Optional[float] = None,
) -> None:
    """Log registry check result."""
    logger = get_registry_logger()

    log_data = {
        "package_name": package_name,
        "registry": registry,
        "package_exists": exists,
    }

    if response_time_ms is not None:
        log_data["response_time_ms"] = response_time_ms

    if not exists:
        logger.warning("package_not_found_in_registry", **log_data)
    else:
        logger.debug("registry_check_completed", **log_data)


def log_forensic_operation(operation: str, **kwargs) -> None:
    """Log forensic operation."""
    logger = get_forensic_logger()
    logger.info("forensic_operation", operation=operation, **kwargs)


def log_ml_operation(operation: str, **kwargs) -> None:
    """Log ML operation."""
    logger = get_ml_logger()
    logger.info("ml_operation", operation=operation, **kwargs)


def set_scan_context(
    scan_id: Optional[str] = None,
    file_path: Optional[str] = None,
    total_dependencies: Optional[int] = None,
) -> None:
    """Set global scan context for all loggers."""
    for logger in [
        _security_logger,
        _scanner_logger,
        _forensic_logger,
        _registry_logger,
        _ml_logger,
    ]:
        logger.set_scan_context(scan_id, file_path, total_dependencies)


def clear_scan_context() -> None:
    """Clear global scan context."""
    for logger in [
        _security_logger,
        _scanner_logger,
        _forensic_logger,
        _registry_logger,
        _ml_logger,
    ]:
        logger.clear_scan_context()


def configure_logging(log_level: str = "INFO", enable_json: bool = True) -> None:
    """Configure logging for the application."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Configure our loggers
    for logger in [
        _security_logger,
        _scanner_logger,
        _forensic_logger,
        _registry_logger,
        _ml_logger,
    ]:
        logger.logger.setLevel(level)


# Initialize with default configuration
configure_logging()
