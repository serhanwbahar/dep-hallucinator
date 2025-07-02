import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Dict, List, Optional

import toml

from .cli_config import get_config
from .error_handling import (
    ErrorCallback,
    ErrorCategory,
    deprecation_warning,
    get_error_handler,
    log_parsing_error,
)


def _validate_file_path(file_path: str) -> Path:
    """
    Validate file path to prevent path traversal and other security issues.

    Args:
        file_path: The file path to validate

    Returns:
        Path: Validated and resolved path object

    Raises:
        ValueError: If path is invalid or unsafe
    """
    if not file_path or not isinstance(file_path, str):
        raise ValueError("File path must be a non-empty string")

    try:
        # Convert to Path object and resolve
        path = Path(file_path).resolve()
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid file path: {e}")

    # Check if file exists
    if not path.exists():
        raise ValueError(f"File does not exist: {path}")

    # Check if it's actually a file
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    # Check file extension
    config = get_config()
    allowed_extensions = set(config.security.allowed_file_extensions)
    if path.suffix.lower() not in allowed_extensions:
        raise ValueError(f"File type not allowed: {path.suffix}")

    # Check file size
    try:
        file_size = path.stat().st_size
        max_file_size = config.security.max_file_size_bytes
        if file_size > max_file_size:
            raise ValueError(
                f"File too large: {file_size} bytes (max: {max_file_size})"
            )
    except OSError as e:
        raise ValueError(f"Cannot access file: {e}")

    # Prevent access to sensitive system files
    # Convert to string for string operations
    path_str = str(path).lower()
    sensitive_paths = [
        "/etc/",
        "/proc/",
        "/sys/",
        "/dev/",
        "c:\\windows\\",
        "c:\\program files\\",
    ]
    if any(sensitive in path_str for sensitive in sensitive_paths):
        raise ValueError("Access to system files is not allowed")

    return path


def _safe_read_file(file_path: str) -> str:
    """
    Safely read a file with validation and error handling.

    DEPRECATED: Use _safe_read_file_streaming for large files to avoid memory issues.

    Args:
        file_path: The file path to read

    Returns:
        str: File contents

    Raises:
        ValueError: If file cannot be read safely
    """
    # Check file size and warn if it's large
    validated_path = _validate_file_path(file_path)
    try:
        file_size = validated_path.stat().st_size
        if file_size > 1024 * 1024:  # 1MB threshold
            deprecation_warning(
                f"Loading large file ({file_size} bytes) into memory. Consider using streaming parsing.",
                "parsers",
                "_safe_read_file",
                version="2.0.0",
            )
    except OSError:
        pass

    try:
        with open(validated_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
            return content
    except UnicodeDecodeError:
        raise ValueError("File contains invalid UTF-8 characters")
    except PermissionError:
        raise ValueError("Permission denied reading file")
    except OSError as e:
        raise ValueError(f"Error reading file: {e}")


def _safe_read_file_streaming(file_path: str, chunk_size: int = 8192) -> str:
    """
    Safely read a file using streaming with memory-efficient chunked processing.

    Args:
        file_path: The file path to read
        chunk_size: Size of chunks to read at a time (default: 8KB)

    Returns:
        str: File contents

    Raises:
        ValueError: If file cannot be read safely
    """
    validated_path = _validate_file_path(file_path)

    # Get config for memory limits
    config = get_config()
    max_content_size = config.security.max_file_size_bytes

    try:
        content_parts = []
        total_size = 0

        with open(validated_path, encoding="utf-8", errors="replace") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                # Check memory limits
                chunk_size_bytes = len(chunk.encode("utf-8"))
                total_size += chunk_size_bytes

                if total_size > max_content_size:
                    raise ValueError(
                        f"File too large: {total_size} bytes (max: {max_content_size})"
                    )

                content_parts.append(chunk)

        return "".join(content_parts)

    except UnicodeDecodeError:
        raise ValueError("File contains invalid UTF-8 characters")
    except PermissionError:
        raise ValueError("Permission denied reading file")
    except OSError as e:
        raise ValueError(f"Error reading file: {e}")


def _process_file_line_by_line(
    file_path: str,
    line_processor: Callable[[str, int], Optional[Dict[str, str]]],
    max_lines: Optional[int] = None,
) -> List[Dict[str, str]]:
    """
    Process a file line by line without loading entire content into memory.

    Args:
        file_path: The file path to process
        line_processor: Function to process each line (line, line_number) -> Optional[Dict]
        max_lines: Maximum number of lines to process (None = no limit)

    Returns:
        List[Dict[str, str]]: List of processed results

    Raises:
        ValueError: If file cannot be processed safely
    """
    validated_path = _validate_file_path(file_path)

    # Get config limits
    config = get_config()
    default_max_lines = getattr(
        config.security, "max_lines_per_file", 100000
    )  # Default 100K lines
    if max_lines is None:
        max_lines = default_max_lines

    results = []

    try:
        with open(validated_path, encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                # Check line limits
                if max_lines is not None and line_num > max_lines:
                    get_error_handler().warning(
                        ErrorCategory.PARSING,
                        f"File has too many lines, stopping at {max_lines}",
                        "parsers",
                        "_process_file_line_by_line",
                        details={
                            "file_path": Path(file_path).name,
                            "lines_processed": line_num - 1,
                        },
                    )
                    break

                # Process the line
                try:
                    result = line_processor(line, line_num)
                    if result:
                        result["source"] = str(validated_path)
                        results.append(result)
                except Exception as e:
                    # Log parsing error but continue processing
                    log_parsing_error(
                        f"Could not process line: {line.strip()[:100]}...",
                        module="parsers",
                        function="_process_file_line_by_line",
                        line_number=line_num,
                        file_path=file_path,
                        exception=e,
                    )
                    continue

        return results

    except UnicodeDecodeError:
        raise ValueError("File contains invalid UTF-8 characters")
    except PermissionError:
        raise ValueError("Permission denied reading file")
    except OSError as e:
        raise ValueError(f"Error reading file: {e}")


def parse_requirements_txt(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a requirements.txt file and returns a list of dependencies.

    Handles various pip requirement formats including:
    - Simple names: package-name
    - Version specifiers: package==1.0.0, package>=1.0.0
    - Git URLs: git+https://github.com/user/repo.git
    - Editable installs: -e path/to/package
    - Comment lines and blank lines (ignored)

    Args:
        file_path: Path to the requirements.txt file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read or is invalid
    """
    # Register error callback if provided
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    # Validate file path first
    validated_path = _validate_file_path(file_path)

    # Ensure it's a requirements file
    if not (
        validated_path.name == "requirements.txt" or validated_path.suffix == ".txt"
    ):
        raise ValueError("File must be requirements.txt or have .txt extension")

    def process_requirement_line(line: str, line_num: int) -> Optional[Dict[str, str]]:
        """Process a single requirement line."""
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            return None

        # Skip pip options (lines starting with -)
        if line.startswith("-"):
            return None

        # Extract package name and version
        return _parse_requirement_line(line)

    try:
        # Use streaming line-by-line processing
        dependencies = _process_file_line_by_line(
            str(validated_path), process_requirement_line
        )
    except ValueError:
        # Re-raise validation errors
        raise
    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing requirements file: {e}",
            "parsers",
            "parse_requirements_txt",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing requirements file: {e}")

    return dependencies


def _parse_requirement_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single requirement line and extract package name and version."""
    # Remove inline comments
    line = line.split("#")[0].strip()

    # Handle git URLs - extract package name from URL
    if line.startswith("git+") or ".git" in line:
        # Try to extract package name from git URL
        # Example: git+https://github.com/user/package-name.git
        git_match = re.search(r"/([^/]+?)(?:\.git)?(?:#|$)", line)
        if git_match:
            package_name = git_match.group(1)
            return {"name": package_name, "version": "git"}
        else:
            return {"name": "unknown-git-package", "version": "git"}

    # Handle editable installs
    if line.startswith("-e "):
        line = line[3:].strip()
        # For editable installs, the package name might not be clear
        # I'll use the path/URL as the name for now
        return {"name": f"editable-{line}", "version": "editable"}

    # Standard package requirements
    # Split on version operators: ==, >=, <=, ~=, !=, >, <
    version_pattern = r"([a-zA-Z0-9\-_.]+)\s*([><=!~]+.*)?"
    match = re.match(version_pattern, line)

    if match:
        package_name = match.group(1).strip()
        version_spec = match.group(2).strip() if match.group(2) else "any"

        # Clean up package name (remove any remaining special chars)
        package_name = re.sub(r"[^\w\-.]", "", package_name)

        return {"name": package_name, "version": version_spec}

    # Fallback: treat the whole line as a package name
    clean_name = re.sub(r"[^\w\-.]", "", line)
    if clean_name:
        return {"name": clean_name, "version": "any"}

    return None


def parse_package_json(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a package.json file and returns a list of dependencies.

    Extracts dependencies from:
    - dependencies
    - devDependencies
    - peerDependencies
    - optionalDependencies

    Args:
        file_path: Path to the package.json file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read or contains invalid JSON
    """
    # Register error callback if provided
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    # Validate file path first
    validated_path = _validate_file_path(file_path)

    # Ensure it's a package.json-like file
    if not (
        validated_path.name.endswith(".json")
        and "package" in validated_path.name.lower()
    ):
        raise ValueError(
            "File must be a package.json file (containing 'package' and ending with '.json')"
        )

    dependencies = []

    try:
        # Use streaming read for large package.json files
        content = _safe_read_file_streaming(str(validated_path))
        data = json.loads(content)
    except json.JSONDecodeError as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Invalid JSON format in package.json: {e}",
            "parsers",
            "parse_package_json",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Invalid JSON format: {e}")
    except ValueError:
        # Re-raise validation errors
        raise
    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing package.json file: {e}",
            "parsers",
            "parse_package_json",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing package.json file: {e}")

    if not isinstance(data, dict):
        error_handler.error(
            ErrorCategory.PARSING,
            "package.json must contain a JSON object",
            "parsers",
            "parse_package_json",
            details={
                "file_path": Path(file_path).name,
                "data_type": type(data).__name__,
            },
        )
        raise ValueError("package.json must contain a JSON object")

    # Define dependency sections to check
    dependency_sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ]

    for section in dependency_sections:
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            for package, version in section_deps.items():
                # Validate package name
                if not isinstance(package, str) or not package.strip():
                    error_handler.warning(
                        ErrorCategory.PARSING,
                        f"Invalid package name in {section}: {str(package)[:50]}",
                        "parsers",
                        "parse_package_json",
                        details={
                            "section": section,
                            "file_path": Path(file_path).name,
                            "package": str(package)[:50],  # Limit length for security
                            "package_type": type(package).__name__,
                        },
                    )
                    continue

                dependencies.append(
                    {
                        "name": package.strip(),
                        "version": str(version).strip() if version else "unknown",
                        "source": str(validated_path),
                    }
                )

    return dependencies


def get_supported_file_types() -> List[str]:
    """Return a list of supported dependency file types."""
    return [
        "requirements.txt",
        "package.json",
        "poetry.lock",
        "Pipfile.lock",
        "yarn.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
    ]


def parse_poetry_lock(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a poetry.lock file and returns a list of dependencies.

    Poetry lock files use TOML format and contain detailed dependency information.

    Args:
        file_path: Path to the poetry.lock file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read or contains invalid TOML
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if validated_path.name != "poetry.lock":
        raise ValueError("File must be named poetry.lock")

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        data = toml.loads(content)
    except toml.TomlDecodeError as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Invalid TOML format in poetry.lock: {e}",
            "parsers",
            "parse_poetry_lock",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Invalid TOML format: {e}")
    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing poetry.lock file: {e}",
            "parsers",
            "parse_poetry_lock",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing poetry.lock file: {e}")

    # Poetry lock files have packages under 'package' section
    packages = data.get("package", [])

    for package in packages:
        if isinstance(package, dict):
            name = package.get("name", "").strip()
            version = package.get("version", "").strip()

            if name:
                dependencies.append(
                    {
                        "name": name,
                        "version": version or "unknown",
                        "source": str(validated_path),
                    }
                )

    return dependencies


def parse_pipfile_lock(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a Pipfile.lock file and returns a list of dependencies.

    Pipfile.lock files use JSON format and contain locked dependency versions.

    Args:
        file_path: Path to the Pipfile.lock file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read or contains invalid JSON
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if validated_path.name != "Pipfile.lock":
        raise ValueError("File must be named Pipfile.lock")

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        data = json.loads(content)
    except json.JSONDecodeError as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Invalid JSON format in Pipfile.lock: {e}",
            "parsers",
            "parse_pipfile_lock",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Invalid JSON format: {e}")
    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing Pipfile.lock file: {e}",
            "parsers",
            "parse_pipfile_lock",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing Pipfile.lock file: {e}")

    # Check both default and develop dependencies
    for section in ["default", "develop"]:
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            for package_name, package_info in section_deps.items():
                version = "unknown"
                if isinstance(package_info, dict):
                    version = package_info.get("version", "unknown")
                elif isinstance(package_info, str):
                    version = package_info

                dependencies.append(
                    {
                        "name": package_name,
                        "version": version,
                        "source": str(validated_path),
                    }
                )

    return dependencies


def parse_yarn_lock(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a yarn.lock file and returns a list of dependencies.

    Yarn lock files use a custom format that's similar to YAML but not quite.

    Args:
        file_path: Path to the yarn.lock file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if validated_path.name != "yarn.lock":
        raise ValueError("File must be named yarn.lock")

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        lines = content.splitlines()

        current_package = None
        current_version = None

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Package declaration line (ends with :)
            if line.endswith(":") and not line.startswith(" "):
                # Extract package name from something like "package-name@^1.0.0:"
                package_spec = line[:-1]  # Remove trailing :

                # Handle multiple package specs separated by commas
                package_specs = [spec.strip() for spec in package_spec.split(",")]

                for spec in package_specs:
                    # Extract package name (before @ symbol)
                    if "@" in spec:
                        parts = spec.split("@")
                        package_name = parts[0].strip().strip("\"'")
                        if package_name and package_name not in [
                            dep["name"] for dep in dependencies
                        ]:
                            current_package = package_name
                            break

            # Version line
            elif line.startswith("version ") and current_package:
                version_match = re.search(r'version\s+"([^"]+)"', line)
                if version_match:
                    current_version = version_match.group(1)

                    dependencies.append(
                        {
                            "name": current_package,
                            "version": current_version,
                            "source": str(validated_path),
                        }
                    )

                    current_package = None
                    current_version = None

    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing yarn.lock file: {e}",
            "parsers",
            "parse_yarn_lock",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing yarn.lock file: {e}")

    return dependencies


def parse_pom_xml(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a Maven pom.xml file and returns a list of dependencies.

    Args:
        file_path: Path to the pom.xml file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read or contains invalid XML
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if not validated_path.name.endswith("pom.xml"):
        raise ValueError("File must be a pom.xml file (ending with 'pom.xml')")

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        root = ET.fromstring(content)

        # Maven XML uses namespaces, so we need to handle that
        namespace = {"maven": "http://maven.apache.org/POM/4.0.0"}

        # Try with namespace first, fallback to no namespace
        dep_elements = root.findall(".//maven:dependency", namespace)
        if not dep_elements:
            # Try with full namespace in tag name
            dep_elements = root.findall(
                ".//{http://maven.apache.org/POM/4.0.0}dependency"
            )
        if not dep_elements:
            dep_elements = root.findall(".//dependency")

        for dep in dep_elements:
            group_id = None
            artifact_id = None
            version = None

            # Iterate through children directly to handle namespaces properly
            for child in dep:
                tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if tag_name == "groupId":
                    group_id = child.text
                elif tag_name == "artifactId":
                    artifact_id = child.text
                elif tag_name == "version":
                    version = child.text

            if artifact_id:
                # Combine groupId and artifactId for full package name
                package_name = f"{group_id}:{artifact_id}" if group_id else artifact_id

                dependencies.append(
                    {
                        "name": package_name,
                        "version": version or "unknown",
                        "source": str(validated_path),
                    }
                )

    except ET.ParseError as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Invalid XML format in pom.xml: {e}",
            "parsers",
            "parse_pom_xml",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Invalid XML format: {e}")
    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing pom.xml file: {e}",
            "parsers",
            "parse_pom_xml",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing pom.xml file: {e}")

    return dependencies


def parse_gradle_build(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a Gradle build.gradle or build.gradle.kts file and returns a list of dependencies.

    Note: This is a basic parser that looks for dependency declarations.
    Gradle files can be very complex with programmatic dependency resolution.

    Args:
        file_path: Path to the build.gradle or build.gradle.kts file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if not (
        (
            validated_path.name.endswith(".gradle")
            or validated_path.name.endswith(".gradle.kts")
        )
        and "build" in validated_path.name.lower()
    ):
        raise ValueError(
            "File must be a Gradle build file (containing 'build' and ending with '.gradle' or '.gradle.kts')"
        )

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        lines = content.splitlines()

        in_dependencies_block = False

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("//") or line.startswith("/*"):
                continue

            # Check for dependencies block
            if "dependencies" in line and "{" in line:
                in_dependencies_block = True
                continue

            if in_dependencies_block:
                # End of dependencies block
                if line == "}":
                    in_dependencies_block = False
                    continue

                # Look for dependency declarations
                # Patterns: implementation 'group:artifact:version'
                #          compile "group:artifact:version"
                #          testImplementation group: 'com.example', name: 'artifact', version: '1.0'

                dep_patterns = [
                    r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s+['\"]([^'\"]+)['\"]",
                    r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s*\(\s*['\"]([^'\"]+)['\"]",
                ]

                for pattern in dep_patterns:
                    match = re.search(pattern, line)
                    if match:
                        dependency_string = match.group(1)

                        # Parse group:artifact:version format
                        parts = dependency_string.split(":")
                        if len(parts) >= 2:
                            group = parts[0]
                            artifact = parts[1]
                            version = parts[2] if len(parts) > 2 else "unknown"

                            package_name = f"{group}:{artifact}"

                            dependencies.append(
                                {
                                    "name": package_name,
                                    "version": version,
                                    "source": str(validated_path),
                                }
                            )
                        break

    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing Gradle build file: {e}",
            "parsers",
            "parse_gradle_build",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing Gradle build file: {e}")

    return dependencies


def parse_go_mod(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a go.mod file and returns a list of dependencies.

    Args:
        file_path: Path to the go.mod file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if not validated_path.name.endswith("go.mod"):
        raise ValueError("File must be a go.mod file (ending with 'go.mod')")

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        lines = content.splitlines()

        in_require_block = False

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("//"):
                continue

            # Check for require block
            if line.startswith("require"):
                if "(" in line:
                    in_require_block = True
                    continue
                else:
                    # Single line require
                    require_match = re.match(r"require\s+([^\s]+)\s+([^\s]+)", line)
                    if require_match:
                        module = require_match.group(1)
                        version = require_match.group(2)

                        dependencies.append(
                            {
                                "name": module,
                                "version": version,
                                "source": str(validated_path),
                            }
                        )
                    continue

            if in_require_block:
                # End of require block
                if line == ")":
                    in_require_block = False
                    continue

                # Parse module version line
                parts = line.split()
                if len(parts) >= 2:
                    module = parts[0]
                    version = parts[1]

                    dependencies.append(
                        {
                            "name": module,
                            "version": version,
                            "source": str(validated_path),
                        }
                    )

    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing go.mod file: {e}",
            "parsers",
            "parse_go_mod",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing go.mod file: {e}")

    return dependencies


def parse_cargo_toml(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a Cargo.toml file and returns a list of dependencies.

    Cargo.toml files use TOML format and contain Rust dependencies in sections:
    - [dependencies] - Runtime dependencies
    - [dev-dependencies] - Development dependencies
    - [build-dependencies] - Build-time dependencies

    Args:
        file_path: Path to the Cargo.toml file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read or contains invalid TOML
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if not validated_path.name.endswith("Cargo.toml"):
        raise ValueError("File must be a Cargo.toml file (ending with 'Cargo.toml')")

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        data = toml.loads(content)
    except toml.TomlDecodeError as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Invalid TOML format in Cargo.toml: {e}",
            "parsers",
            "parse_cargo_toml",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Invalid TOML format: {e}")
    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing Cargo.toml file: {e}",
            "parsers",
            "parse_cargo_toml",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing Cargo.toml file: {e}")

    # Define dependency sections to check
    dependency_sections = ["dependencies", "dev-dependencies", "build-dependencies"]

    for section in dependency_sections:
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            for package_name, package_info in section_deps.items():
                version = "unknown"

                # Handle different version specification formats
                if isinstance(package_info, str):
                    # Simple version string: package = "1.0.0"
                    version = package_info
                elif isinstance(package_info, dict):
                    # Complex specification: package = { version = "1.0.0", features = [...] }
                    version = package_info.get("version", "unknown")

                    # Handle git dependencies
                    if "git" in package_info:
                        git_url = package_info["git"]
                        version = f"git+{git_url}"

                    # Handle path dependencies (local crates)
                    elif "path" in package_info:
                        path = package_info["path"]
                        version = f"path:{path}"

                dependencies.append(
                    {
                        "name": package_name,
                        "version": version,
                        "source": str(validated_path),
                    }
                )

    return dependencies


def parse_cargo_lock(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parses a Cargo.lock file and returns a list of dependencies.

    Cargo.lock files use TOML format and contain the exact resolved dependency tree.

    Args:
        file_path: Path to the Cargo.lock file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file cannot be read or contains invalid TOML
    """
    error_handler = get_error_handler()
    if error_callback:
        error_handler.register_callback(error_callback, ErrorCategory.PARSING)

    validated_path = _validate_file_path(file_path)

    if validated_path.name != "Cargo.lock":
        raise ValueError("File must be named Cargo.lock")

    dependencies = []

    try:
        content = _safe_read_file(str(validated_path))
        data = toml.loads(content)
    except toml.TomlDecodeError as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Invalid TOML format in Cargo.lock: {e}",
            "parsers",
            "parse_cargo_lock",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Invalid TOML format: {e}")
    except Exception as e:
        error_handler.error(
            ErrorCategory.PARSING,
            f"Error processing Cargo.lock file: {e}",
            "parsers",
            "parse_cargo_lock",
            exception=e,
            details={"file_path": Path(file_path).name},
        )
        raise ValueError(f"Error processing Cargo.lock file: {e}")

    # Cargo.lock has packages under 'package' section (similar to Poetry)
    packages = data.get("package", [])

    for package in packages:
        if isinstance(package, dict):
            name = package.get("name", "").strip()
            version = package.get("version", "").strip()

            # Skip the main package (the project itself)
            # We can identify it by checking if it has a source field
            source = package.get("source")
            if source is None:
                # This is likely the main package, skip it
                continue

            if name:
                dependencies.append(
                    {
                        "name": name,
                        "version": version or "unknown",
                        "source": str(validated_path),
                    }
                )

    return dependencies


def detect_file_type(file_path: str) -> str:
    """
    Detect the dependency file type based on filename.

    Args:
        file_path: Path to the file

    Returns:
        str: File type identifier

    Raises:
        ValueError: If file type is not supported
    """
    path = Path(file_path)
    filename = path.name.lower()

    # Map filenames to types
    file_type_map = {
        "requirements.txt": "requirements",
        "package.json": "package_json",
        "poetry.lock": "poetry_lock",
        "pipfile.lock": "pipfile_lock",
        "yarn.lock": "yarn_lock",
        "pom.xml": "pom_xml",
        "build.gradle": "gradle_build",
        "build.gradle.kts": "gradle_build",
        "go.mod": "go_mod",
        "cargo.toml": "cargo_toml",
        "cargo.lock": "cargo_lock",
    }

    if filename in file_type_map:
        return file_type_map[filename]

    # Check for patterns
    if filename.endswith(".txt"):
        # For .txt files, default to requirements format if it contains requirements
        # OR if it's any .txt file (for testing flexibility)
        return "requirements"
    if filename.endswith(".json") and "package" in filename:
        return "package_json"
    if filename.endswith("pom.xml"):
        return "pom_xml"
    if filename.endswith("go.mod"):
        return "go_mod"
    if filename.endswith("cargo.toml"):
        return "cargo_toml"
    if filename.endswith("cargo.lock"):
        return "cargo_lock"
    if filename.endswith(".gradle") or filename.endswith(".gradle.kts"):
        return "gradle_build"

    raise ValueError(f"Unsupported file type: {filename}")


def parse_dependency_file(
    file_path: str, error_callback: Optional[ErrorCallback] = None
) -> List[Dict[str, str]]:
    """
    Parse any supported dependency file type.

    Args:
        file_path: Path to the dependency file
        error_callback: Optional callback for handling parsing errors

    Returns:
        List[Dict[str, str]]: List of dependency dictionaries

    Raises:
        ValueError: If file type is not supported or parsing fails
    """
    file_type = detect_file_type(file_path)

    parser_map = {
        "requirements": parse_requirements_txt,
        "package_json": parse_package_json,
        "poetry_lock": parse_poetry_lock,
        "pipfile_lock": parse_pipfile_lock,
        "yarn_lock": parse_yarn_lock,
        "pom_xml": parse_pom_xml,
        "gradle_build": parse_gradle_build,
        "go_mod": parse_go_mod,
        "cargo_toml": parse_cargo_toml,
        "cargo_lock": parse_cargo_lock,
    }

    parser = parser_map.get(file_type)
    if not parser:
        raise ValueError(f"No parser available for file type: {file_type}")

    return parser(file_path, error_callback)
