"""
Comprehensive error handling system for Dep-Hallucinator.

Provides structured logging, error callbacks, and consistent error management
across all modules to ensure proper library behavior.
"""

import logging
import sys
import traceback
import warnings
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class ErrorLevel(Enum):
    """Error severity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ErrorCategory(Enum):
    """Error categories for better classification."""

    PARSING = "PARSING"
    NETWORK = "NETWORK"
    VALIDATION = "VALIDATION"
    SECURITY = "SECURITY"
    ML_MODEL = "ML_MODEL"
    CREDENTIAL = "CREDENTIAL"
    CONFIGURATION = "CONFIGURATION"
    FILESYSTEM = "FILESYSTEM"


@dataclass
class ErrorContext:
    """Structured error context information."""

    level: ErrorLevel
    category: ErrorCategory
    message: str
    module: str
    function: str
    details: Dict[str, Any] = field(default_factory=dict)
    exception: Optional[Exception] = None
    traceback_info: Optional[str] = None
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert error context to dictionary for logging."""
        return {
            "level": self.level.value,
            "category": self.category.value,
            "message": self.message,
            "module": self.module,
            "function": self.function,
            "details": self.details,
            "exception_type": type(self.exception).__name__ if self.exception else None,
            "exception_message": str(self.exception) if self.exception else None,
            "traceback": self.traceback_info,
            "suggestions": self.suggestions,
        }


class SecureLogger:
    """Secure logger that sanitizes sensitive information."""

    def __init__(self, name: str, level: int = logging.WARNING):
        """
        Initialize secure logger.

        Args:
            name: Logger name
            level: Logging level
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Create formatter that sanitizes sensitive info
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        # Add console handler if none exists
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _sanitize_message(self, message: str) -> str:
        """
        Sanitize message to remove sensitive information.

        Args:
            message: Original message

        Returns:
            str: Sanitized message
        """
        import re

        # Patterns for common sensitive information
        sensitive_patterns = [
            (r'token["\s]*[:=]["\s]*([a-zA-Z0-9_\-+=/.]{8,})', 'token="[REDACTED]"'),
            (r'key["\s]*[:=]["\s]*([a-zA-Z0-9_\-+=/.]{8,})', 'key="[REDACTED]"'),
            (r'password["\s]*[:=]["\s]*([^\s"\']+)', 'password="[REDACTED]"'),
            (r"(https?://[^@\s]+:)[^@\s]+@", r"\1[REDACTED]@"),  # URLs with credentials
            (r"Authorization:\s*\w+\s+([^\s]+)", "Authorization: [REDACTED]"),
            (r"X-API-Key:\s*([^\s]+)", "X-API-Key: [REDACTED]"),
        ]

        sanitized = message
        for pattern, replacement in sensitive_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def log_error_context(self, context: ErrorContext):
        """
        Log error context with appropriate level.

        Args:
            context: Error context to log
        """
        sanitized_message = self._sanitize_message(context.message)
        sanitized_details = self._sanitize_dict(context.details)

        log_data = {
            "category": context.category.value,
            "module": context.module,
            "function": context.function,
            "details": sanitized_details,
        }

        if context.exception:
            log_data["exception"] = type(context.exception).__name__

        if context.suggestions:
            log_data["suggestions"] = context.suggestions

        # Format log message
        log_message = f"{sanitized_message} | {log_data}"

        # Log with appropriate level
        if context.level == ErrorLevel.DEBUG:
            self.logger.debug(log_message)
        elif context.level == ErrorLevel.INFO:
            self.logger.info(log_message)
        elif context.level == ErrorLevel.WARNING:
            self.logger.warning(log_message)
        elif context.level == ErrorLevel.ERROR:
            self.logger.error(log_message)
        elif context.level == ErrorLevel.CRITICAL:
            self.logger.critical(log_message)

    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize dictionary values to remove sensitive info."""
        if not isinstance(data, dict):
            return data

        sanitized = {}
        sensitive_keys = {"token", "key", "password", "secret", "credential", "auth"}

        for key, value in data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, str):
                sanitized[key] = self._sanitize_message(value)
            else:
                sanitized[key] = value

        return sanitized


# Error callback type
ErrorCallback = Callable[[ErrorContext], None]


class ErrorHandler:
    """
    Centralized error handler for consistent error management.

    Provides logging, callbacks, and structured error handling
    for library components.
    """

    def __init__(
        self,
        logger_name: str = "dep_hallucinator",
        log_level: int = logging.WARNING,
        enable_callbacks: bool = True,
    ):
        """
        Initialize error handler.

        Args:
            logger_name: Name for the logger
            log_level: Logging level
            enable_callbacks: Whether to enable error callbacks
        """
        self.logger = SecureLogger(logger_name, log_level)
        self.enable_callbacks = enable_callbacks
        self.error_callbacks: Dict[ErrorCategory, List[ErrorCallback]] = {}
        self.global_callbacks: List[ErrorCallback] = []
        self.error_stats: Dict[str, int] = {}

    def register_callback(
        self, callback: ErrorCallback, category: Optional[ErrorCategory] = None
    ):
        """
        Register error callback.

        Args:
            callback: Function to call on errors
            category: Error category to filter, None for all errors
        """
        if not self.enable_callbacks:
            return

        if category is None:
            self.global_callbacks.append(callback)
        else:
            if category not in self.error_callbacks:
                self.error_callbacks[category] = []
            self.error_callbacks[category].append(callback)

    def handle_error(
        self,
        level: ErrorLevel,
        category: ErrorCategory,
        message: str,
        module: str,
        function: str,
        exception: Optional[Exception] = None,
        details: Optional[Dict[str, Any]] = None,
        suggestions: Optional[List[str]] = None,
    ) -> ErrorContext:
        """
        Handle an error with structured logging and callbacks.

        Args:
            level: Error severity level
            category: Error category
            message: Error message
            module: Module where error occurred
            function: Function where error occurred
            exception: Optional exception object
            details: Additional error details
            suggestions: Suggested fixes

        Returns:
            ErrorContext: The created error context
        """
        # Create error context
        context = ErrorContext(
            level=level,
            category=category,
            message=message,
            module=module,
            function=function,
            details=details or {},
            exception=exception,
            traceback_info=traceback.format_exc() if exception else None,
            suggestions=suggestions or [],
        )

        # Update error statistics
        stat_key = f"{category.value}_{level.value}"
        self.error_stats[stat_key] = self.error_stats.get(stat_key, 0) + 1

        # Log the error
        self.logger.log_error_context(context)

        # Call callbacks
        if self.enable_callbacks:
            # Call category-specific callbacks
            if category in self.error_callbacks:
                for callback in self.error_callbacks[category]:
                    try:
                        callback(context)
                    except Exception as cb_error:
                        # Don't let callback errors break the main flow
                        self.logger.logger.error(f"Error in callback: {cb_error}")

            # Call global callbacks
            for callback in self.global_callbacks:
                try:
                    callback(context)
                except Exception as cb_error:
                    self.logger.logger.error(f"Error in global callback: {cb_error}")

        return context

    def warning(
        self,
        category: ErrorCategory,
        message: str,
        module: str,
        function: str,
        **kwargs,
    ) -> ErrorContext:
        """Handle warning level error."""
        return self.handle_error(
            ErrorLevel.WARNING, category, message, module, function, **kwargs
        )

    def error(
        self,
        category: ErrorCategory,
        message: str,
        module: str,
        function: str,
        **kwargs,
    ) -> ErrorContext:
        """Handle error level error."""
        return self.handle_error(
            ErrorLevel.ERROR, category, message, module, function, **kwargs
        )

    def critical(
        self,
        category: ErrorCategory,
        message: str,
        module: str,
        function: str,
        **kwargs,
    ) -> ErrorContext:
        """Handle critical level error."""
        return self.handle_error(
            ErrorLevel.CRITICAL, category, message, module, function, **kwargs
        )

    def get_error_stats(self) -> Dict[str, int]:
        """Get error statistics."""
        return self.error_stats.copy()

    def reset_stats(self):
        """Reset error statistics."""
        self.error_stats.clear()


# Global error handler instance
_global_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """
    Get the global error handler instance.

    Returns:
        ErrorHandler: Global error handler
    """
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ErrorHandler()
    return _global_error_handler


def setup_error_handling(
    log_level: int = logging.WARNING,
    enable_callbacks: bool = True,
    logger_name: str = "dep_hallucinator",
) -> ErrorHandler:
    """
    Setup global error handling configuration.

    Args:
        log_level: Logging level
        enable_callbacks: Whether to enable callbacks
        logger_name: Logger name

    Returns:
        ErrorHandler: Configured error handler
    """
    global _global_error_handler
    _global_error_handler = ErrorHandler(logger_name, log_level, enable_callbacks)
    return _global_error_handler


def log_parsing_error(
    message: str,
    module: str,
    function: str,
    line_number: Optional[int] = None,
    file_path: Optional[str] = None,
    exception: Optional[Exception] = None,
):
    """
    Convenience function for logging parsing errors.

    Args:
        message: Error message
        module: Module name
        function: Function name
        line_number: Line number where error occurred
        file_path: File being parsed
        exception: Optional exception
    """
    details = {}
    if line_number is not None:
        details["line_number"] = line_number
    if file_path is not None:
        # Sanitize file path to prevent information disclosure
        details["file_path"] = Path(file_path).name  # Only filename, not full path

    suggestions = [
        "Check file format and encoding",
        "Verify file is not corrupted",
        "Review parsing documentation",
    ]

    get_error_handler().warning(
        ErrorCategory.PARSING,
        message,
        module,
        function,
        details=details,
        exception=exception,
        suggestions=suggestions,
    )


def log_network_error(
    message: str,
    module: str,
    function: str,
    url: Optional[str] = None,
    status_code: Optional[int] = None,
    exception: Optional[Exception] = None,
):
    """
    Convenience function for logging network errors.

    Args:
        message: Error message
        module: Module name
        function: Function name
        url: URL that failed (will be sanitized)
        status_code: HTTP status code
        exception: Optional exception
    """
    details = {}
    if url is not None:
        # Sanitize URL to remove credentials
        from urllib.parse import urlparse

        parsed = urlparse(url)
        sanitized_url = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            sanitized_url += f":{parsed.port}"
        sanitized_url += parsed.path
        details["url"] = sanitized_url

    if status_code is not None:
        details["status_code"] = status_code

    suggestions = [
        "Check network connectivity",
        "Verify registry URL is correct",
        "Check if authentication is required",
        "Review rate limiting settings",
    ]

    get_error_handler().error(
        ErrorCategory.NETWORK,
        message,
        module,
        function,
        details=details,
        exception=exception,
        suggestions=suggestions,
    )


def log_credential_error(
    message: str,
    module: str,
    function: str,
    credential_type: Optional[str] = None,
    exception: Optional[Exception] = None,
):
    """
    Convenience function for logging credential errors.

    Args:
        message: Error message
        module: Module name
        function: Function name
        credential_type: Type of credential (API key, token, etc.)
        exception: Optional exception
    """
    details = {}
    if credential_type is not None:
        details["credential_type"] = credential_type

    suggestions = [
        "Verify credential is valid and not expired",
        "Check credential permissions and scope",
        "Ensure credential is properly formatted",
        "Review credential storage security",
    ]

    get_error_handler().warning(
        ErrorCategory.CREDENTIAL,
        message,
        module,
        function,
        details=details,
        exception=exception,
        suggestions=suggestions,
    )


def deprecation_warning(
    message: str, module: str, function: str, version: Optional[str] = None
):
    """
    Issue a deprecation warning.

    Args:
        message: Deprecation message
        module: Module name
        function: Function name
        version: Version when feature will be removed
    """
    full_message = message
    if version:
        full_message += f" (will be removed in version {version})"

    warnings.warn(full_message, DeprecationWarning, stacklevel=3)

    get_error_handler().warning(
        ErrorCategory.CONFIGURATION,
        full_message,
        module,
        function,
        suggestions=["Update code to use recommended alternatives"],
    )
