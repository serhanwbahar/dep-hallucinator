"""
Registry clients for querying package repositories.

Implements secure, rate-limited clients for PyPI and npm registries with
comprehensive API key security and private registry support.
"""

import asyncio
import json
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx
from httpx import HTTPStatusError, RequestError

from .cache_manager import get_cache_manager
from .cli_config import get_config
from .error_handling import ErrorCategory, get_error_handler, log_credential_error

# Security constants for credential protection
CREDENTIAL_PATTERN = re.compile(r"^[a-zA-Z0-9_\-+=/.]+$")  # Valid credential characters
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "x-api-key",
    "token",
    "api-key",
    "private-token",
}


def _validate_credential(credential: str, credential_type: str = "API key") -> str:
    """
    Validate and sanitize credential inputs.

    Args:
        credential: The credential to validate
        credential_type: Type of credential for error messages

    Returns:
        str: Validated credential

    Raises:
        ValueError: If credential is invalid or unsafe
    """
    if not credential or not isinstance(credential, str):
        raise ValueError(f"Invalid {credential_type}: must be a non-empty string")

    credential = credential.strip()

    # Get configuration for validation limits
    config = get_config()
    max_credential_length = config.security.max_credential_length
    min_credential_length = config.security.min_credential_length

    # Length validation
    if len(credential) > max_credential_length:
        raise ValueError(
            f"{credential_type} too long: {len(credential)} chars (max: {max_credential_length})"
        )

    # Pattern validation - only allow safe characters
    if not CREDENTIAL_PATTERN.match(credential):
        raise ValueError(f"Invalid {credential_type}: contains unsafe characters")

    # Basic validation to reject obviously invalid credentials
    if len(credential) < min_credential_length:
        raise ValueError(
            f"{credential_type} too short (minimum {min_credential_length} characters)"
        )

    return credential


def _sanitize_url_for_logging(url: str) -> str:
    """
    Sanitize URL for safe logging by removing credentials.

    Args:
        url: URL that may contain credentials

    Returns:
        str: Sanitized URL safe for logging
    """
    try:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            # Remove credentials from URL
            sanitized_netloc = parsed.hostname or "unknown-host"
            if parsed.port:
                sanitized_netloc += f":{parsed.port}"
            sanitized_url = f"{parsed.scheme}://{sanitized_netloc}{parsed.path}"
            if parsed.query:
                sanitized_url += f"?{parsed.query}"
            return sanitized_url
        return url
    except Exception:
        return "[REDACTED_URL]"


def _load_credentials_from_env() -> Dict[str, str]:
    """
    Load credentials from environment variables securely.

    Returns:
        Dict[str, str]: Mapping of registry names to credentials
    """
    credentials = {}

    # Standard environment variable patterns
    env_patterns = [
        "PYPI_API_TOKEN",
        "NPM_AUTH_TOKEN",
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "REGISTRY_TOKEN",
        "DEP_HALLUCINATOR_PYPI_TOKEN",
        "DEP_HALLUCINATOR_NPM_TOKEN",
    ]

    for env_var in env_patterns:
        value = os.getenv(env_var)
        if value:
            try:
                validated_credential = _validate_credential(
                    value, f"environment variable {env_var}"
                )
                # Map to registry type
                if "pypi" in env_var.lower():
                    credentials["pypi"] = validated_credential
                elif "npm" in env_var.lower():
                    credentials["npm"] = validated_credential
                else:
                    # Generic registry token
                    credentials["default"] = validated_credential
            except ValueError as e:
                log_credential_error(
                    "Invalid credential format in environment variable",
                    "registry_clients",
                    "_load_credentials_from_env",
                    credential_type="environment_variable",
                    exception=e,
                )

    return credentials


def _load_credentials_from_config() -> Dict[str, Dict[str, str]]:
    """
    Load credentials from secure configuration files.

    Returns:
        Dict[str, Dict[str, str]]: Registry configurations with credentials
    """
    credentials = {}

    # Look for credential files in secure locations
    credential_files = [
        Path.home() / ".config" / "dep-hallucinator" / "credentials.json",
        Path.home() / ".dep-hallucinator-credentials.json",
        Path.cwd() / ".dep-hallucinator-credentials.json",  # Only if properly secured
    ]

    for cred_file in credential_files:
        if cred_file.exists():
            try:
                # Check file permissions (Unix-like systems)
                if hasattr(os, "stat"):
                    stat_info = cred_file.stat()
                    # Check if file is readable by others (security risk)
                    if stat_info.st_mode & 0o077:
                        get_error_handler().warning(
                            ErrorCategory.SECURITY,
                            "Credential file has overly permissive permissions",
                            "registry_clients",
                            "_load_credentials_from_config",
                            details={"file_path": str(cred_file)},
                        )
                        continue

                with open(cred_file, encoding="utf-8") as f:
                    data = json.load(f)

                if isinstance(data, dict) and "registries" in data:
                    for registry_name, config in data["registries"].items():
                        if isinstance(config, dict):
                            # Validate registry configuration
                            validated_config = {}

                            if "api_key" in config:
                                validated_config["api_key"] = _validate_credential(
                                    config["api_key"], f"API key for {registry_name}"
                                )

                            if "token" in config:
                                validated_config["token"] = _validate_credential(
                                    config["token"], f"token for {registry_name}"
                                )

                            if "base_url" in config:
                                validated_config["base_url"] = str(
                                    config["base_url"]
                                ).strip()

                            if "auth_type" in config:
                                auth_type = str(config["auth_type"]).lower()
                                if auth_type in ["bearer", "api_key", "basic"]:
                                    validated_config["auth_type"] = auth_type

                            if validated_config:
                                credentials[registry_name] = validated_config

            except (json.JSONDecodeError, ValueError, PermissionError) as e:
                log_credential_error(
                    "Could not load credentials from file",
                    "registry_clients",
                    "_load_credentials_from_config",
                    credential_type="configuration_file",
                    exception=e,
                )

    return credentials


@dataclass(frozen=True)
class RegistryConfig:
    """Configuration for a registry including credentials."""

    base_url: str
    api_key: Optional[str] = None
    token: Optional[str] = None
    auth_type: str = "bearer"  # bearer, api_key, basic
    custom_headers: Optional[Dict[str, str]] = None

    def __post_init__(self):
        """Validate registry configuration."""
        # Validate base URL
        if not self.base_url or not isinstance(self.base_url, str):
            raise ValueError("base_url must be a non-empty string")

        # Validate auth type
        valid_auth_types = {"bearer", "api_key", "basic"}
        if self.auth_type not in valid_auth_types:
            raise ValueError(f"auth_type must be one of: {valid_auth_types}")

        # Validate credentials if provided
        if self.api_key:
            object.__setattr__(
                self, "api_key", _validate_credential(self.api_key, "API key")
            )

        if self.token:
            object.__setattr__(self, "token", _validate_credential(self.token, "token"))

    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for this registry.

        Returns:
            Dict[str, str]: HTTP headers for authentication
        """
        headers = {}

        if self.token:
            if self.auth_type == "bearer":
                headers["Authorization"] = f"Bearer {self.token}"
            elif self.auth_type == "api_key":
                headers["X-API-Key"] = self.token
            elif self.auth_type == "basic":
                # For basic auth, token should be base64 encoded username:password
                headers["Authorization"] = f"Basic {self.token}"

        elif self.api_key:
            headers["X-API-Key"] = self.api_key

        # Add custom headers
        if self.custom_headers:
            for name, value in self.custom_headers.items():
                # Validate header names and values
                if isinstance(name, str) and isinstance(value, str):
                    # Avoid overwriting auth headers
                    if name.lower() not in SENSITIVE_HEADER_NAMES:
                        headers[name] = value

        return headers

    def get_sanitized_config(self) -> Dict[str, Any]:
        """
        Get sanitized configuration for logging/debugging.

        Returns:
            Dict[str, Any]: Configuration with credentials redacted
        """
        return {
            "base_url": _sanitize_url_for_logging(self.base_url),
            "auth_type": self.auth_type,
            "has_api_key": bool(self.api_key),
            "has_token": bool(self.token),
            "has_custom_headers": bool(self.custom_headers),
        }


@dataclass(frozen=True)
class PackageInfo:
    """Information about a package from a registry."""

    name: str
    exists: bool
    version: Optional[str] = None
    created_at: Optional[str] = None
    download_count: Optional[int] = None
    author: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    last_modified: Optional[str] = None


@dataclass(frozen=True)
class RegistryCheckResult:
    """Result of checking a package in a registry."""

    package_name: str
    registry_type: str
    package_info: Optional[PackageInfo] = None
    error: Optional[str] = None
    check_duration_ms: Optional[int] = None


class RateLimiter:
    """Simple rate limiter to prevent overwhelming registries."""

    def __init__(self, requests_per_second: float = 10.0):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0

    async def acquire(self) -> None:
        """Wait if necessary to respect rate limits."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.min_interval:
            wait_time = self.min_interval - time_since_last
            await asyncio.sleep(wait_time)

        self.last_request_time = time.time()


class SecureCredentialManager:
    """Manages credentials securely with protection against exposure."""

    def __init__(self):
        self._env_credentials = _load_credentials_from_env()
        self._config_credentials = _load_credentials_from_config()
        self._registry_configs: Dict[str, RegistryConfig] = {}
        self._setup_default_registries()

    def _setup_default_registries(self) -> None:
        """Setup default registry configurations."""
        # Default PyPI configuration
        pypi_config = {"base_url": "https://pypi.org/pypi", "auth_type": "bearer"}

        # Add credentials if available
        if "pypi" in self._env_credentials:
            pypi_config["token"] = self._env_credentials["pypi"]
        elif "pypi" in self._config_credentials and isinstance(
            self._config_credentials["pypi"], dict
        ):
            # Only update with valid RegistryConfig fields
            for key, value in self._config_credentials["pypi"].items():
                if key in {"api_key", "token", "auth_type", "base_url"}:
                    pypi_config[key] = value
                elif key == "custom_headers" and isinstance(value, dict):
                    pypi_config[key] = value

        self._registry_configs["pypi"] = RegistryConfig(**pypi_config)

        # Default npm configuration
        npm_config = {"base_url": "https://registry.npmjs.org", "auth_type": "bearer"}

        # Add credentials if available
        if "npm" in self._env_credentials:
            npm_config["token"] = self._env_credentials["npm"]
        elif "npm" in self._config_credentials and isinstance(
            self._config_credentials["npm"], dict
        ):
            # Only update with valid RegistryConfig fields
            for key, value in self._config_credentials["npm"].items():
                if key in {"api_key", "token", "auth_type", "base_url"}:
                    npm_config[key] = value
                elif key == "custom_headers" and isinstance(value, dict):
                    npm_config[key] = value

        self._registry_configs["npm"] = RegistryConfig(**npm_config)

    def add_registry(self, name: str, config: RegistryConfig) -> None:
        """
        Add a custom registry configuration.

        Args:
            name: Registry name
            config: Registry configuration
        """
        if not name or not isinstance(name, str):
            raise ValueError("Registry name must be a non-empty string")

        self._registry_configs[name] = config

    def get_registry_config(self, registry_type: str) -> RegistryConfig:
        """
        Get configuration for a registry type.

        Args:
            registry_type: Type of registry (pypi, npm, etc.)

        Returns:
            RegistryConfig: Configuration for the registry

        Raises:
            ValueError: If registry type is not configured
        """
        if registry_type not in self._registry_configs:
            raise ValueError(f"Registry '{registry_type}' not configured")

        return self._registry_configs[registry_type]

    def list_registries(self) -> List[str]:
        """
        List available registry configurations.

        Returns:
            List[str]: List of configured registry names
        """
        return list(self._registry_configs.keys())

    def get_sanitized_configs(self) -> Dict[str, Dict[str, Any]]:
        """
        Get sanitized configurations for debugging.

        Returns:
            Dict[str, Dict[str, Any]]: Sanitized configurations
        """
        return {
            name: config.get_sanitized_config()
            for name, config in self._registry_configs.items()
        }


class BaseRegistryClient(ABC):
    """
    Base class for registry clients with secure credential support.

    Uses proper async context manager pattern for httpx.AsyncClient resource management.
    The HTTP client is initialized on context entry and properly cleaned up on exit.
    """

    def __init__(
        self,
        rate_limit_rps: float = 10.0,
        timeout: float = 30.0,
        registry_config: Optional[RegistryConfig] = None,
        credential_manager: Optional[SecureCredentialManager] = None,
    ):
        self.rate_limiter = RateLimiter(rate_limit_rps)
        self.timeout = timeout
        self.registry_config = registry_config
        self.credential_manager = credential_manager or SecureCredentialManager()
        self.client: Optional[httpx.AsyncClient] = None

        # Build secure headers
        self._headers = {
            "User-Agent": "dep-hallucinator/1.0.0 (Security Scanner)",
            "Accept": "application/json",
        }

        # Add authentication headers if registry config is provided
        if self.registry_config:
            auth_headers = self.registry_config.get_auth_headers()
            self._headers.update(auth_headers)

    async def __aenter__(self):
        """Initialize the HTTP client when entering the context."""
        self.client = httpx.AsyncClient(timeout=self.timeout, headers=self._headers)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up the HTTP client when exiting the context."""
        if self.client:
            await self.client.aclose()
            self.client = None

    @abstractmethod
    async def check_package_exists(self, package_name: str) -> RegistryCheckResult:
        """Check if a package exists in the registry."""
        pass

    @abstractmethod
    def get_registry_type(self) -> str:
        """Get the registry type identifier."""
        pass


class PyPIClient(BaseRegistryClient):
    """Client for querying the Python Package Index (PyPI) with secure API key support."""

    def __init__(
        self,
        rate_limit_rps: float = 10.0,
        timeout: float = 30.0,
        credential_manager: Optional[SecureCredentialManager] = None,
    ):
        self.credential_manager = credential_manager or SecureCredentialManager()

        try:
            # Get PyPI configuration with credentials
            registry_config = self.credential_manager.get_registry_config("pypi")
            self.base_url = registry_config.base_url
        except ValueError:
            # Fallback to default PyPI if no configuration
            self.base_url = "https://pypi.org/pypi"
            registry_config = None

        super().__init__(
            rate_limit_rps, timeout, registry_config, self.credential_manager
        )

    def get_registry_type(self) -> str:
        return "pypi"

    async def check_package_exists(self, package_name: str) -> RegistryCheckResult:
        """
        Check if a Python package exists on PyPI.

        Args:
            package_name: The name of the package to check

        Returns:
            RegistryCheckResult with package information or error details
        """
        start_time = time.time()

        # Sanitize package name
        if not package_name or not isinstance(package_name, str):
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Invalid package name",
            )

        # Clean package name for URL safety
        clean_name = quote(package_name.strip())
        if not clean_name:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Empty package name after sanitization",
            )

        # Check cache first
        cache_manager = get_cache_manager()
        cached_result = cache_manager.get(package_name, self.get_registry_type())
        if cached_result is not None:
            # Update duration to reflect cache hit (very fast)
            cached_result = RegistryCheckResult(
                package_name=cached_result.package_name,
                registry_type=cached_result.registry_type,
                package_info=cached_result.package_info,
                error=cached_result.error,
                check_duration_ms=int((time.time() - start_time) * 1000),
            )
            return cached_result

        url = f"{self.base_url}/{clean_name}/json"

        try:
            await self.rate_limiter.acquire()

            if self.client is None:
                return RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    error="HTTP client not initialized - use within async context manager",
                )

            response = await self.client.get(url)
            duration_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 404:
                # Package does not exist - this is the critical finding
                result = RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    package_info=PackageInfo(name=package_name, exists=False),
                    check_duration_ms=duration_ms,
                )
                # Cache 404 results (critical findings) for medium duration
                cache_manager.put(
                    package_name, self.get_registry_type(), result, ttl_seconds=1800
                )  # 30 minutes
                return result

            response.raise_for_status()
            data = response.json()

            # Extract package information
            info_data = data.get("info", {})

            # Get creation date from releases
            releases = data.get("releases", {})
            created_at = None
            if releases:
                # Find the earliest release
                earliest_version = min(releases.keys()) if releases else None
                if earliest_version and releases[earliest_version]:
                    upload_time = releases[earliest_version][0].get("upload_time")
                    if upload_time:
                        created_at = upload_time

            # Try to get download stats from recent releases
            download_count = self._estimate_download_count(data)

            package_info = PackageInfo(
                name=package_name,
                exists=True,
                version=info_data.get("version"),
                created_at=created_at,
                download_count=download_count,
                author=info_data.get("author"),
                description=info_data.get("summary"),
                homepage=info_data.get("home_page"),
                repository=info_data.get("project_urls", {}).get("Repository")
                or info_data.get("project_url"),
                license=info_data.get("license"),
                last_modified=None,
            )

            result = RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                package_info=package_info,
                check_duration_ms=duration_ms,
            )

            # Cache the successful result
            cache_manager.put(package_name, self.get_registry_type(), result)
            return result

        except HTTPStatusError as e:
            result = RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"HTTP {e.response.status_code}: {e.response.text[:100]}",
            )
            # Cache HTTP errors (like 404) for shorter duration
            cache_manager.put(
                package_name, self.get_registry_type(), result, ttl_seconds=300
            )  # 5 minutes
            return result
        except RequestError as e:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"Network error: {str(e)}",
            )
        except Exception as e:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"Unexpected error: {str(e)}",
            )

    def _estimate_download_count(self, package_data: Dict) -> Optional[int]:
        """Estimate download count from package data (PyPI doesn't provide exact counts)."""
        # PyPI doesn't provide download counts in basic API
        # We can use release count and age as a rough indicator
        releases = package_data.get("releases", {})
        if not releases:
            return 0

        # More releases generally indicates more usage
        release_count = len(releases)

        # Rough heuristic: packages with many releases likely have some downloads but this is biased
        # I don't have a solution for this yet, need to find a better way to estimate or fetch download count
        if release_count >= 10:
            return 1000  # Estimate moderate usage
        elif release_count >= 5:
            return 100  # Estimate low usage
        elif release_count >= 2:
            return 10  # Estimate very low usage
        else:
            return 1  # Single release, minimal usage


class NPMClient(BaseRegistryClient):
    """Client for querying the npm registry with secure API key support."""

    def __init__(
        self,
        rate_limit_rps: float = 10.0,
        timeout: float = 30.0,
        credential_manager: Optional[SecureCredentialManager] = None,
    ):
        self.credential_manager = credential_manager or SecureCredentialManager()

        try:
            # Get npm configuration with credentials
            registry_config = self.credential_manager.get_registry_config("npm")
            self.base_url = registry_config.base_url
        except ValueError:
            # Fallback to default npm if no configuration
            self.base_url = "https://registry.npmjs.org"
            registry_config = None

        super().__init__(
            rate_limit_rps, timeout, registry_config, self.credential_manager
        )

    def get_registry_type(self) -> str:
        return "npm"

    async def check_package_exists(self, package_name: str) -> RegistryCheckResult:
        """
        Check if an npm package exists on the registry.

        Args:
            package_name: The name of the package to check

        Returns:
            RegistryCheckResult with package information or error details
        """
        start_time = time.time()

        # Sanitize package name
        if not package_name or not isinstance(package_name, str):
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Invalid package name",
            )

        # Clean package name for URL safety
        clean_name = quote(package_name.strip())
        if not clean_name:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Empty package name after sanitization",
            )

        # Check cache first
        cache_manager = get_cache_manager()
        cached_result = cache_manager.get(package_name, self.get_registry_type())
        if cached_result is not None:
            # Update duration to reflect cache hit (very fast)
            cached_result = RegistryCheckResult(
                package_name=cached_result.package_name,
                registry_type=cached_result.registry_type,
                package_info=cached_result.package_info,
                error=cached_result.error,
                check_duration_ms=int((time.time() - start_time) * 1000),
            )
            return cached_result

        url = f"{self.base_url}/{clean_name}"

        try:
            await self.rate_limiter.acquire()

            if self.client is None:
                return RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    error="HTTP client not initialized - use within async context manager",
                )

            response = await self.client.get(url)
            duration_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 404:
                # Package does not exist - this is the critical finding
                result = RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    package_info=PackageInfo(name=package_name, exists=False),
                    check_duration_ms=duration_ms,
                )
                # Cache 404 results (critical findings) for medium duration
                cache_manager.put(
                    package_name, self.get_registry_type(), result, ttl_seconds=1800
                )  # 30 minutes
                return result

            response.raise_for_status()
            data = response.json()

            # Extract package information
            latest_version = data.get("dist-tags", {}).get("latest")
            version_data = (
                data.get("versions", {}).get(latest_version, {})
                if latest_version
                else {}
            )
            time_data = data.get("time", {})

            # Get creation date
            created_at = time_data.get("created") or time_data.get(latest_version)

            # Get author information
            author = None
            if "author" in version_data:
                author_data = version_data["author"]
                if isinstance(author_data, dict):
                    author = author_data.get("name")
                elif isinstance(author_data, str):
                    author = author_data

            package_info = PackageInfo(
                name=package_name,
                exists=True,
                version=latest_version,
                created_at=created_at,
                download_count=None,  # npm doesn't provide this in basic API
                author=author,
                description=version_data.get("description"),
                homepage=version_data.get("homepage"),
                repository=self._extract_repository_url(version_data.get("repository")),
                license=self._extract_license(version_data.get("license")),
                last_modified=time_data.get("modified"),
            )

            result = RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                package_info=package_info,
                check_duration_ms=duration_ms,
            )

            # Cache the successful result
            cache_manager.put(package_name, self.get_registry_type(), result)
            return result

        except HTTPStatusError as e:
            result = RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"HTTP {e.response.status_code}: {e.response.text[:100]}",
            )
            # Cache HTTP errors (like 404) for shorter duration
            cache_manager.put(
                package_name, self.get_registry_type(), result, ttl_seconds=300
            )  # 5 minutes
            return result
        except RequestError as e:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"Network error: {str(e)}",
            )
        except Exception as e:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"Unexpected error: {str(e)}",
            )

    def _extract_repository_url(self, repository_data: Any) -> Optional[str]:
        """Extract repository URL from npm repository field."""
        if not repository_data:
            return None

        if isinstance(repository_data, str):
            return repository_data
        elif isinstance(repository_data, dict):
            return repository_data.get("url")

        return None

    def _extract_license(self, license_data: Any) -> Optional[str]:
        """Extract license string from npm license field."""
        if not license_data:
            return None

        if isinstance(license_data, str):
            return license_data
        elif isinstance(license_data, dict):
            return license_data.get("type")
        elif isinstance(license_data, list) and license_data:
            # Multiple licenses, take the first one
            first_license = license_data[0]
            if isinstance(first_license, dict):
                return first_license.get("type")
            return str(first_license)

        return None


class MavenCentralClient(BaseRegistryClient):
    """Client for Maven Central repository."""

    def __init__(self, rate_limit_rps: float = 10.0, timeout: float = 30.0):
        self.base_url = "https://search.maven.org/solrsearch/select"
        super().__init__(rate_limit_rps, timeout, None, None)

    def get_registry_type(self) -> str:
        return "maven"

    async def check_package_exists(self, package_name: str) -> RegistryCheckResult:
        """Check if a Maven package exists in Maven Central."""
        start_time = time.time()

        if not package_name or not isinstance(package_name, str):
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Invalid package name",
            )

        # Maven packages are in format "groupId:artifactId"
        if ":" not in package_name:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Invalid Maven package format (expected groupId:artifactId)",
            )

        group_id, artifact_id = package_name.split(":", 1)

        # Check cache first
        cache_manager = get_cache_manager()
        cached_result = cache_manager.get(package_name, self.get_registry_type())
        if cached_result is not None:
            cached_result = RegistryCheckResult(
                package_name=cached_result.package_name,
                registry_type=cached_result.registry_type,
                package_info=cached_result.package_info,
                error=cached_result.error,
                check_duration_ms=int((time.time() - start_time) * 1000),
            )
            return cached_result

        # Query Maven Central
        params = {"q": f"g:{group_id} AND a:{artifact_id}", "rows": 1, "wt": "json"}

        try:
            await self.rate_limiter.acquire()

            if self.client is None:
                return RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    error="HTTP client not initialized",
                )

            response = await self.client.get(self.base_url, params=params)
            duration_ms = int((time.time() - start_time) * 1000)

            response.raise_for_status()
            data = response.json()

            docs = data.get("response", {}).get("docs", [])

            if not docs:
                # Package does not exist
                result = RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    package_info=PackageInfo(name=package_name, exists=False),
                    check_duration_ms=duration_ms,
                )
                cache_manager.put(
                    package_name, self.get_registry_type(), result, ttl_seconds=1800
                )
                return result

            # Package exists
            doc = docs[0]
            package_info = PackageInfo(
                name=package_name,
                exists=True,
                version=doc.get("latestVersion"),
                created_at=None,  # Not available in Maven Central API
                download_count=None,
                author=None,
                description=None,
                homepage=None,
                repository=None,
                license=None,
                last_modified=None,
            )

            result = RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                package_info=package_info,
                check_duration_ms=duration_ms,
            )

            cache_manager.put(package_name, self.get_registry_type(), result)
            return result

        except Exception as e:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"Maven Central check failed: {str(e)}",
            )


class CratesIOClient(BaseRegistryClient):
    """Client for crates.io (Rust package registry)."""

    def __init__(self, rate_limit_rps: float = 10.0, timeout: float = 30.0):
        self.base_url = "https://crates.io/api/v1/crates"
        super().__init__(rate_limit_rps, timeout, None, None)

    def get_registry_type(self) -> str:
        return "crates"

    async def check_package_exists(self, package_name: str) -> RegistryCheckResult:
        """Check if a Rust crate exists on crates.io."""
        start_time = time.time()

        if not package_name or not isinstance(package_name, str):
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Invalid package name",
            )

        clean_name = package_name.strip()

        # Check cache first
        cache_manager = get_cache_manager()
        cached_result = cache_manager.get(package_name, self.get_registry_type())
        if cached_result is not None:
            cached_result = RegistryCheckResult(
                package_name=cached_result.package_name,
                registry_type=cached_result.registry_type,
                package_info=cached_result.package_info,
                error=cached_result.error,
                check_duration_ms=int((time.time() - start_time) * 1000),
            )
            return cached_result

        url = f"{self.base_url}/{clean_name}"

        try:
            await self.rate_limiter.acquire()

            if self.client is None:
                return RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    error="HTTP client not initialized",
                )

            response = await self.client.get(url)
            duration_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 404:
                # Package does not exist
                result = RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    package_info=PackageInfo(name=package_name, exists=False),
                    check_duration_ms=duration_ms,
                )
                cache_manager.put(
                    package_name, self.get_registry_type(), result, ttl_seconds=1800
                )
                return result

            response.raise_for_status()
            data = response.json()

            crate_data = data.get("crate", {})
            package_info = PackageInfo(
                name=package_name,
                exists=True,
                version=crate_data.get("newest_version"),
                created_at=crate_data.get("created_at"),
                download_count=crate_data.get("downloads"),
                author=None,  # Would need separate API call
                description=crate_data.get("description"),
                homepage=crate_data.get("homepage"),
                repository=crate_data.get("repository"),
                license=None,  # Would need separate API call
                last_modified=crate_data.get("updated_at"),
            )

            result = RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                package_info=package_info,
                check_duration_ms=duration_ms,
            )

            cache_manager.put(package_name, self.get_registry_type(), result)
            return result

        except Exception as e:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"Crates.io check failed: {str(e)}",
            )


class GoModuleClient(BaseRegistryClient):
    """Client for Go module proxy."""

    def __init__(self, rate_limit_rps: float = 10.0, timeout: float = 30.0):
        self.base_url = "https://proxy.golang.org"
        super().__init__(rate_limit_rps, timeout, None, None)

    def get_registry_type(self) -> str:
        return "go"

    async def check_package_exists(self, package_name: str) -> RegistryCheckResult:
        """Check if a Go module exists on the module proxy."""
        start_time = time.time()

        if not package_name or not isinstance(package_name, str):
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error="Invalid package name",
            )

        clean_name = package_name.strip()

        # Check cache first
        cache_manager = get_cache_manager()
        cached_result = cache_manager.get(package_name, self.get_registry_type())
        if cached_result is not None:
            cached_result = RegistryCheckResult(
                package_name=cached_result.package_name,
                registry_type=cached_result.registry_type,
                package_info=cached_result.package_info,
                error=cached_result.error,
                check_duration_ms=int((time.time() - start_time) * 1000),
            )
            return cached_result

        # Try to get the latest version info from Go proxy
        url = f"{self.base_url}/{clean_name}/@latest"

        try:
            await self.rate_limiter.acquire()

            if self.client is None:
                return RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    error="HTTP client not initialized",
                )

            response = await self.client.get(url)
            duration_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 404 or response.status_code == 410:
                # Package does not exist or is not available
                result = RegistryCheckResult(
                    package_name=package_name,
                    registry_type=self.get_registry_type(),
                    package_info=PackageInfo(name=package_name, exists=False),
                    check_duration_ms=duration_ms,
                )
                cache_manager.put(
                    package_name, self.get_registry_type(), result, ttl_seconds=1800
                )
                return result

            response.raise_for_status()
            data = response.json()

            package_info = PackageInfo(
                name=package_name,
                exists=True,
                version=data.get("Version"),
                created_at=data.get("Time"),
                download_count=None,  # Not available in Go proxy
                author=None,
                description=None,
                homepage=None,
                repository=None,
                license=None,
                last_modified=data.get("Time"),
            )

            result = RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                package_info=package_info,
                check_duration_ms=duration_ms,
            )

            cache_manager.put(package_name, self.get_registry_type(), result)
            return result

        except Exception as e:
            return RegistryCheckResult(
                package_name=package_name,
                registry_type=self.get_registry_type(),
                error=f"Go module check failed: {str(e)}",
            )


def get_registry_client(
    registry_type: str, rate_limit_rps: float = 10.0
) -> BaseRegistryClient:
    """
    Factory function to get the appropriate registry client.

    Args:
        registry_type: Type of registry ('pypi', 'npm', 'maven', 'crates', 'go')
        rate_limit_rps: Requests per second limit

    Returns:
        Configured registry client

    Raises:
        ValueError: If registry_type is not supported
    """
    if registry_type == "pypi":
        return PyPIClient(rate_limit_rps)
    elif registry_type == "npm":
        return NPMClient(rate_limit_rps)
    elif registry_type == "maven":
        return MavenCentralClient(rate_limit_rps)
    elif registry_type == "crates":
        return CratesIOClient(rate_limit_rps)
    elif registry_type == "go":
        return GoModuleClient(rate_limit_rps)
    else:
        raise ValueError(f"Unsupported registry type: {registry_type}")
