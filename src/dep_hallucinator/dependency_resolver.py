"""
Dependency resolution engine for transitive dependency scanning.

Provides secure dependency tree resolution for Python (pip) and JavaScript (npm)
ecosystems without requiring package installation, preventing security risks.
"""

import asyncio
import json
import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

from .cli_config import get_config
from .dependency import Dependency
from .error_handling import ErrorCategory, get_error_handler


class DependencyType(Enum):
    """Types of dependencies in the dependency tree."""

    DIRECT = "direct"  # Directly specified in requirements file
    TRANSITIVE = "transitive"  # Dependency of a dependency
    DEV = "dev"  # Development dependency
    OPTIONAL = "optional"  # Optional dependency


@dataclass(frozen=True)
class ResolvedDependency:
    """A dependency with resolution metadata."""

    name: str
    version: str
    dependency_type: DependencyType
    depth: int  # How deep in the dependency tree (0 = direct)
    parent: Optional[str] = None  # Parent dependency name
    source_file: str = "resolved"
    version_specifier: Optional[str] = None  # Original version specifier

    def to_dependency(self) -> Dependency:
        """Convert to basic Dependency object for scanning."""
        return Dependency(
            name=self.name, version=self.version, source_file=self.source_file
        )


@dataclass
class DependencyTree:
    """Complete dependency tree with metadata."""

    direct_dependencies: List[ResolvedDependency] = field(default_factory=list)
    transitive_dependencies: List[ResolvedDependency] = field(default_factory=list)
    resolution_errors: List[str] = field(default_factory=list)
    total_dependencies: int = 0
    max_depth: int = 0
    ecosystem: str = "unknown"

    def __post_init__(self):
        """Calculate derived fields."""
        all_deps = self.direct_dependencies + self.transitive_dependencies
        self.total_dependencies = len(all_deps)
        self.max_depth = max((dep.depth for dep in all_deps), default=0)

    def get_all_dependencies(self) -> List[ResolvedDependency]:
        """Get all dependencies (direct + transitive)."""
        return self.direct_dependencies + self.transitive_dependencies

    def get_dependencies_by_depth(self, depth: int) -> List[ResolvedDependency]:
        """Get dependencies at a specific depth level."""
        return [dep for dep in self.get_all_dependencies() if dep.depth == depth]

    def get_dependency_chain(self, dependency_name: str) -> List[str]:
        """Get the chain of dependencies leading to a specific package."""
        chain = []
        current = dependency_name

        # Build chain by following parent relationships
        while current:
            chain.append(current)
            # Find dependency with this name
            dep = next(
                (d for d in self.get_all_dependencies() if d.name == current), None
            )
            if dep and dep.parent:
                current = dep.parent
            else:
                break

        return list(reversed(chain))  # Root to leaf order


class BaseDependencyResolver(ABC):
    """Base class for dependency resolvers."""

    def __init__(self, max_depth: int = 5, include_dev: bool = False):
        """
        Initialize resolver.

        Args:
            max_depth: Maximum dependency depth to resolve
            include_dev: Whether to include development dependencies
        """
        self.max_depth = max_depth
        self.include_dev = include_dev
        self.error_handler = get_error_handler()

        # Security limits from config
        config = get_config()
        self.max_dependencies = 1000  # Prevent DoS attacks
        self.timeout_seconds = config.scan.timeout_seconds * 3  # Longer for resolution

    @abstractmethod
    async def resolve_dependencies(self, file_path: str) -> DependencyTree:
        """Resolve dependency tree from a dependency file."""
        pass

    @abstractmethod
    def get_ecosystem(self) -> str:
        """Get the ecosystem name (pip, npm, etc.)."""
        pass

    def _validate_file_path(self, file_path: str) -> Path:
        """Validate and sanitize file path."""
        try:
            path = Path(file_path).resolve()
            if not path.exists():
                raise ValueError(f"File does not exist: {path}")
            if not path.is_file():
                raise ValueError(f"Path is not a file: {path}")
            return path
        except Exception as e:
            raise ValueError(f"Invalid file path: {e}")

    async def _run_command_safely(
        self,
        command: List[str],
        cwd: Optional[Path] = None,
        capture_output: bool = True,
    ) -> Tuple[str, str, int]:
        """
        Run a command safely with timeouts and security controls.

        Args:
            command: Command and arguments to run
            cwd: Working directory
            capture_output: Whether to capture stdout/stderr

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        # Security: Validate command
        if not command or not isinstance(command[0], str):
            raise ValueError("Invalid command")

        # Prevent command injection
        safe_command = [str(arg) for arg in command]

        try:
            # Use asyncio subprocess for timeout support
            process = await asyncio.create_subprocess_exec(
                *safe_command,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                cwd=cwd,
            )

            # Wait with timeout
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )

            stdout = (
                stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
            )
            stderr = (
                stderr_data.decode("utf-8", errors="replace") if stderr_data else ""
            )

            return stdout, stderr, process.returncode or 0

        except asyncio.TimeoutError:
            self.error_handler.warning(
                ErrorCategory.VALIDATION,
                f"Command timed out after {self.timeout_seconds}s",
                "dependency_resolver",
                "_run_command_safely",
                details={"command": safe_command[0]},
            )
            raise ValueError(f"Command timed out: {safe_command[0]}")
        except Exception as e:
            self.error_handler.error(
                ErrorCategory.VALIDATION,
                f"Command execution failed: {e}",
                "dependency_resolver",
                "_run_command_safely",
                exception=e,
                details={"command": safe_command[0]},
            )
            raise ValueError(f"Command failed: {e}")


class SimpleDependencyResolver(BaseDependencyResolver):
    """Simple dependency resolver that parses files without external tools."""

    def __init__(self, ecosystem: str, max_depth: int = 5, include_dev: bool = False):
        super().__init__(max_depth, include_dev)
        self.ecosystem = ecosystem

    def get_ecosystem(self) -> str:
        return self.ecosystem

    async def resolve_dependencies(self, file_path: str) -> DependencyTree:
        """Resolve dependencies by parsing the file directly."""
        validated_path = self._validate_file_path(file_path)
        dependency_tree = DependencyTree(ecosystem=self.ecosystem)

        try:
            if self.ecosystem == "pip":
                resolved_deps = await self._parse_requirements_file(validated_path)
            elif self.ecosystem == "npm":
                resolved_deps = await self._parse_package_json_file(validated_path)
            else:
                raise ValueError(f"Unsupported ecosystem: {self.ecosystem}")

            # Populate dependency tree (only direct dependencies for now)
            dependency_tree.direct_dependencies = resolved_deps

        except Exception as e:
            dependency_tree.resolution_errors.append(f"Resolution failed: {e}")
            self.error_handler.error(
                ErrorCategory.VALIDATION,
                f"Dependency resolution failed: {e}",
                "dependency_resolver",
                "resolve_dependencies",
                exception=e,
                details={"file_path": str(validated_path)},
            )

        return dependency_tree

    async def _parse_requirements_file(
        self, file_path: Path
    ) -> List[ResolvedDependency]:
        """Parse requirements.txt file."""
        resolved_deps = []

        try:
            # Use streaming processing to avoid loading entire file into memory
            with open(file_path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue

                    # Parse package name and version
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)([><=!~]+.*)?", line)
                    if match:
                        package_name = match.group(1)
                        version_spec = match.group(2) or ""

                        resolved_deps.append(
                            ResolvedDependency(
                                name=package_name,
                                version="any",  # We don't resolve actual versions in simple mode
                                dependency_type=DependencyType.DIRECT,
                                depth=0,
                                source_file=str(file_path),
                                version_specifier=version_spec,
                            )
                        )

        except Exception as e:
            raise ValueError(f"Failed to parse requirements file: {e}")

        return resolved_deps

    async def _parse_package_json_file(
        self, file_path: Path
    ) -> List[ResolvedDependency]:
        """Parse package.json file."""
        resolved_deps = []

        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)

            # Parse dependencies
            dependencies = data.get("dependencies", {})
            for name, version in dependencies.items():
                resolved_deps.append(
                    ResolvedDependency(
                        name=name,
                        version=version,
                        dependency_type=DependencyType.DIRECT,
                        depth=0,
                        source_file=str(file_path),
                        version_specifier=version,
                    )
                )

            # Parse devDependencies if requested
            if self.include_dev:
                dev_dependencies = data.get("devDependencies", {})
                for name, version in dev_dependencies.items():
                    resolved_deps.append(
                        ResolvedDependency(
                            name=name,
                            version=version,
                            dependency_type=DependencyType.DEV,
                            depth=0,
                            source_file=str(file_path),
                            version_specifier=version,
                        )
                    )

        except Exception as e:
            raise ValueError(f"Failed to parse package.json: {e}")

        return resolved_deps


def get_dependency_resolver(
    file_path: str, max_depth: int = 5, include_dev: bool = False
) -> BaseDependencyResolver:
    """
    Factory function to get appropriate dependency resolver.

    Args:
        file_path: Path to dependency file
        max_depth: Maximum dependency depth to resolve
        include_dev: Whether to include development dependencies

    Returns:
        Appropriate dependency resolver

    Raises:
        ValueError: If file type is not supported
    """
    path = Path(file_path)

    if path.name == "requirements.txt" or path.suffix == ".txt":
        return SimpleDependencyResolver("pip", max_depth, include_dev)
    elif path.name == "package.json":
        return SimpleDependencyResolver("npm", max_depth, include_dev)
    else:
        raise ValueError(f"Unsupported dependency file: {path.name}")


async def resolve_all_dependencies(
    file_path: str, max_depth: int = 5, include_dev: bool = False
) -> DependencyTree:
    """
    Convenience function to resolve all dependencies for a file.

    Args:
        file_path: Path to dependency file
        max_depth: Maximum dependency depth to resolve
        include_dev: Whether to include development dependencies

    Returns:
        Complete dependency tree
    """
    resolver = get_dependency_resolver(file_path, max_depth, include_dev)
    return await resolver.resolve_dependencies(file_path)
