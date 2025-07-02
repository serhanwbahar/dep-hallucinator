"""
Core scanning engine for dependency security checks.

Implements the main scanning logic to detect AI-generated dependency confusion vulnerabilities.
"""

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .cli_config import get_config
from .dependency import Dependency
from .dependency_resolver import (
    resolve_all_dependencies,
)
from .heuristics import HallucinationScore, get_heuristic_engine
from .package_lists import get_package_list_manager
from .registry_clients import (
    BaseRegistryClient,
    RegistryCheckResult,
    get_registry_client,
)
from .signature_verification import SignatureStatus, get_signature_verifier
from .structured_logging import (
    get_scanner_logger,
)


class RiskLevel(Enum):
    """Risk levels for dependency findings."""

    CRITICAL = "CRITICAL"  # Package does not exist - exploitable
    HIGH = "HIGH"  # Package exists but highly suspicious
    MEDIUM = "MEDIUM"  # Package exists with some suspicious traits
    LOW = "LOW"  # Package appears legitimate
    ERROR = "ERROR"  # Could not check the package


@dataclass(frozen=True)
class SecurityFinding:
    """A security finding for a dependency."""

    dependency: Dependency
    risk_level: RiskLevel
    registry_result: Optional[RegistryCheckResult] = None
    heuristic_score: Optional[HallucinationScore] = None
    signature_verified: Optional[bool] = None
    signature_details: Optional[Dict] = None
    reasons: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None

    def __post_init__(self):
        if self.reasons is None:
            object.__setattr__(self, "reasons", [])
        if self.recommendations is None:
            object.__setattr__(self, "recommendations", [])


@dataclass(frozen=True)
class ScanResult:
    """Complete scan results for a dependency file."""

    total_dependencies: int
    findings: List[SecurityFinding]
    scan_duration_ms: int
    errors: Optional[List[str]] = None

    def __post_init__(self):
        if self.errors is None:
            object.__setattr__(self, "errors", [])

    @property
    def critical_findings(self) -> List[SecurityFinding]:
        """Get all critical findings."""
        return [f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]

    @property
    def high_risk_findings(self) -> List[SecurityFinding]:
        """Get all high-risk findings."""
        return [f for f in self.findings if f.risk_level == RiskLevel.HIGH]

    @property
    def has_critical_vulnerabilities(self) -> bool:
        """Check if there are any critical vulnerabilities."""
        return len(self.critical_findings) > 0


class DependencyScanner:
    """
    Main scanner for detecting AI-generated dependency confusion vulnerabilities.

    Follows the RORO pattern: receives dependency objects, returns scan results.
    """

    def __init__(
        self,
        rate_limit_rps: float = 10.0,
        max_concurrent: int = 20,
        resolve_transitive: bool = False,
        max_depth: int = 3,
        verify_signatures: bool = False,
    ):
        """
        Initialize the scanner.

        Args:
            rate_limit_rps: API requests per second limit per registry
            max_concurrent: Maximum concurrent registry checks
            resolve_transitive: Whether to resolve and scan transitive dependencies
            max_depth: Maximum depth for transitive dependency resolution
            verify_signatures: Whether to verify package signatures (2025 standards)
        """
        self.rate_limit_rps = rate_limit_rps
        self.max_concurrent = max_concurrent
        self.resolve_transitive = resolve_transitive
        self.max_depth = max_depth
        self.verify_signatures = verify_signatures
        self._semaphore = None  # Lazy-load to avoid event loop issues
        self.heuristic_engine = get_heuristic_engine()
        self.package_list_manager = get_package_list_manager()
        self.signature_verifier = (
            get_signature_verifier() if verify_signatures else None
        )

    @property
    def semaphore(self):
        """Lazy-load semaphore to avoid event loop issues."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
        return self._semaphore

    async def scan_dependencies(self, dependencies: List[Dependency]) -> ScanResult:
        """
        Scan a list of dependencies for security vulnerabilities.

        Args:
            dependencies: List of dependencies to scan

        Returns:
            ScanResult with findings and metadata
        """
        logger = get_scanner_logger()

        if not dependencies:
            logger.info("scan_empty", total_dependencies=0)
            return ScanResult(total_dependencies=0, findings=[], scan_duration_ms=0)

        start_time = asyncio.get_event_loop().time()
        logger.info("scan_started", total_dependencies=len(dependencies))

        # Group dependencies by registry type
        dependency_groups = self._group_dependencies_by_registry(dependencies)

        # Scan each group concurrently
        all_findings = []
        scan_errors = []

        scan_tasks = []
        for registry_type, deps in dependency_groups.items():
            if deps:  # Only create tasks for non-empty groups
                task = self._scan_registry_group(registry_type, deps)
                scan_tasks.append(task)

        if scan_tasks:
            group_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            for result in group_results:
                if isinstance(result, BaseException):
                    scan_errors.append(f"Registry scan error: {str(result)}")
                else:
                    findings, errors = result
                    all_findings.extend(findings)
                    scan_errors.extend(errors)

        end_time = asyncio.get_event_loop().time()
        duration_ms = int((end_time - start_time) * 1000)

        # Log scan completion with security metrics
        critical_count = len(
            [f for f in all_findings if f.risk_level == RiskLevel.CRITICAL]
        )
        high_count = len([f for f in all_findings if f.risk_level == RiskLevel.HIGH])

        logger.info(
            "scan_completed",
            total_dependencies=len(dependencies),
            total_findings=len(all_findings),
            critical_findings=critical_count,
            high_findings=high_count,
            scan_duration_ms=duration_ms,
            error_count=len(scan_errors),
        )

        return ScanResult(
            total_dependencies=len(dependencies),
            findings=all_findings,
            scan_duration_ms=duration_ms,
            errors=scan_errors,
        )

    async def scan_dependency_file(self, file_path: str) -> ScanResult:
        """
        Scan a dependency file, optionally resolving transitive dependencies.

        Args:
            file_path: Path to dependency file (requirements.txt, package.json)

        Returns:
            ScanResult with findings and metadata
        """
        start_time = asyncio.get_event_loop().time()

        try:
            if self.resolve_transitive:
                # Resolve transitive dependencies
                dependency_tree = await resolve_all_dependencies(
                    file_path, max_depth=self.max_depth, include_dev=False
                )

                # Convert resolved dependencies to Dependency objects
                dependencies = []
                for resolved_dep in dependency_tree.get_all_dependencies():
                    dependencies.append(resolved_dep.to_dependency())

                # Add resolution errors to scan errors
                scan_errors = dependency_tree.resolution_errors

                # Scan all dependencies (direct + transitive)
                scan_result = await self.scan_dependencies(dependencies)

                # Add resolution errors to existing scan errors
                if scan_errors:
                    if scan_result.errors:
                        scan_result.errors.extend(scan_errors)
                    else:
                        # Need to update the errors field - create new ScanResult
                        scan_result = ScanResult(
                            total_dependencies=scan_result.total_dependencies,
                            findings=scan_result.findings,
                            scan_duration_ms=scan_result.scan_duration_ms,
                            errors=scan_errors,
                        )

                # Update metadata to include transitive info
                updated_findings = []
                for finding in scan_result.findings:
                    # Add transitive dependency information to findings if available
                    dep_name = finding.dependency.name
                    resolved_dep = next(
                        (
                            d
                            for d in dependency_tree.get_all_dependencies()
                            if d.name == dep_name
                        ),
                        None,
                    )
                    if resolved_dep and resolved_dep.depth > 0:
                        # This is a transitive dependency
                        chain = dependency_tree.get_dependency_chain(dep_name)
                        if len(chain) > 1:
                            chain_str = " → ".join(chain)
                            # Create new reasons list with transitive info
                            updated_reasons = (
                                list(finding.reasons) if finding.reasons else []
                            )
                            updated_reasons.append(
                                f"Transitive dependency chain: {chain_str}"
                            )

                            # Create new SecurityFinding with updated reasons
                            updated_finding = SecurityFinding(
                                dependency=finding.dependency,
                                risk_level=finding.risk_level,
                                registry_result=finding.registry_result,
                                heuristic_score=finding.heuristic_score,
                                reasons=updated_reasons,
                                recommendations=finding.recommendations,
                            )
                            updated_findings.append(updated_finding)
                        else:
                            updated_findings.append(finding)
                    else:
                        updated_findings.append(finding)

                # Create new ScanResult with updated findings
                scan_result = ScanResult(
                    total_dependencies=scan_result.total_dependencies,
                    findings=updated_findings,
                    scan_duration_ms=scan_result.scan_duration_ms,
                    errors=scan_result.errors,
                )

                return scan_result

            else:
                # Traditional scanning - only direct dependencies
                from .main import parse_dependency_file

                dependencies = parse_dependency_file(file_path)
                return await self.scan_dependencies(dependencies)

        except Exception as e:
            end_time = asyncio.get_event_loop().time()
            duration_ms = int((end_time - start_time) * 1000)

            return ScanResult(
                total_dependencies=0,
                findings=[],
                scan_duration_ms=duration_ms,
                errors=[f"File scanning failed: {str(e)}"],
            )

    def _group_dependencies_by_registry(
        self, dependencies: List[Dependency]
    ) -> Dict[str, List[Dependency]]:
        """Group dependencies by their target registry based on source file type."""
        # Include ALL supported registry types to prevent silent dropping
        groups = {"pypi": [], "npm": [], "maven": [], "crates": [], "go": []}

        for dep in dependencies:
            registry_type = self._determine_registry_type(dep.source_file)
            if registry_type in groups:
                groups[registry_type].append(dep)
            else:
                # Log unexpected registry types for debugging
                logger = get_scanner_logger()
                logger.warning(
                    f"Unknown registry type '{registry_type}' for dependency '{dep.name}' from '{dep.source_file}'"
                )
                # Default to pypi for backward compatibility
                groups["pypi"].append(dep)

        return groups

    def _determine_registry_type(self, source_file: str) -> str:
        """Determine the registry type based on the source file."""
        file_lower = source_file.lower()

        # Python ecosystem files
        if any(
            x in file_lower for x in ["requirements.txt", "poetry.lock", "pipfile.lock"]
        ) or file_lower.endswith(".txt"):
            return "pypi"

        # JavaScript/Node.js ecosystem files
        elif any(
            x in file_lower for x in ["package.json", "yarn.lock"]
        ) or file_lower.endswith(".json"):
            return "npm"

        # Java ecosystem files (Maven/Gradle) - now uses Maven Central
        elif any(x in file_lower for x in ["pom.xml", "build.gradle"]):
            return "maven"

        # Go ecosystem files - now uses Go module proxy
        elif any(x in file_lower for x in ["go.mod", "go.sum"]):
            return "go"

        # Rust ecosystem files (Cargo) - now uses crates.io
        elif any(x in file_lower for x in ["cargo.toml", "cargo.lock"]):
            return "crates"

        else:
            # Default to PyPI for unknown file types
            return "pypi"

    async def _scan_registry_group(
        self, registry_type: str, dependencies: List[Dependency]
    ) -> Tuple[List[SecurityFinding], List[str]]:
        """Scan a group of dependencies for a specific registry."""
        findings = []
        errors = []

        try:
            async with get_registry_client(
                registry_type, self.rate_limit_rps
            ) as client:
                # Create tasks for concurrent scanning
                tasks = []
                for dep in dependencies:
                    task = self._scan_single_dependency(client, dep)
                    tasks.append(task)

                # Process with semaphore to limit concurrency
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for i, result in enumerate(results):
                    dep = dependencies[i]
                    if isinstance(result, Exception):
                        errors.append(f"Error scanning {dep.name}: {str(result)}")
                        # Create error finding
                        finding = SecurityFinding(
                            dependency=dep,
                            risk_level=RiskLevel.ERROR,
                            reasons=[f"Scan error: {str(result)}"],
                            recommendations=[
                                "Manually verify this package before installation"
                            ],
                        )
                        findings.append(finding)
                    else:
                        findings.append(result)

        except Exception as e:
            errors.append(f"Registry client error for {registry_type}: {str(e)}")

        return findings, errors

    async def _scan_single_dependency(
        self, client: BaseRegistryClient, dependency: Dependency
    ) -> SecurityFinding:
        """Scan a single dependency using the provided client."""
        async with self.semaphore:
            # Check allowlist/denylist first
            registry_type = client.get_registry_type()

            # Check denylist - automatic HIGH/CRITICAL risk
            is_denylisted, denylist_entry = self.package_list_manager.is_denylisted(
                dependency.name, registry_type
            )
            if is_denylisted:
                return SecurityFinding(
                    dependency=dependency,
                    risk_level=RiskLevel.CRITICAL,
                    reasons=[
                        f"Package is on the denylist: {denylist_entry.reason if denylist_entry else 'Known malicious package'}",
                        "Package flagged as potentially dangerous",
                        "May be AI-generated or malicious",
                    ],
                    recommendations=[
                        "⚠️  DO NOT INSTALL this package",
                        "Package is explicitly marked as dangerous",
                        "Find an alternative package for your needs",
                        "Review why this package was needed",
                    ],
                )

            # Check allowlist - bypass detailed analysis for trusted packages
            is_allowlisted, allowlist_entry = self.package_list_manager.is_allowlisted(
                dependency.name, registry_type
            )
            if is_allowlisted:
                return SecurityFinding(
                    dependency=dependency,
                    risk_level=RiskLevel.LOW,
                    reasons=[
                        f"Package is on the allowlist: {allowlist_entry.reason if allowlist_entry else 'Trusted package'}",
                        "Package pre-approved as safe",
                    ],
                    recommendations=[
                        "✅ Package is trusted and safe to use",
                        "No additional verification needed",
                    ],
                )

            # Proceed with normal registry check for unlisted packages
            registry_result = await client.check_package_exists(dependency.name)

            if registry_result.error:
                return SecurityFinding(
                    dependency=dependency,
                    risk_level=RiskLevel.ERROR,
                    registry_result=registry_result,
                    reasons=[f"Registry check failed: {registry_result.error}"],
                    recommendations=[
                        "Manually verify this package before installation"
                    ],
                )

            if (
                not registry_result.package_info
                or not registry_result.package_info.exists
            ):
                # CRITICAL: Package does not exist - prime target for dependency confusion
                return SecurityFinding(
                    dependency=dependency,
                    risk_level=RiskLevel.CRITICAL,
                    registry_result=registry_result,
                    reasons=[
                        "Package does not exist in the registry",
                        "Vulnerable to dependency confusion attacks",
                        "Malicious actors can register this name",
                    ],
                    recommendations=[
                        "⚠️  DO NOT INSTALL this package",
                        "Verify the package name is correct",
                        "Check if this was generated by an AI assistant",
                        "Consider using an alternative, existing package",
                    ],
                )

            # Package exists - perform heuristic analysis
            registry_type = client.get_registry_type()
            heuristic_score = await self.heuristic_engine.analyze_package(
                registry_result.package_info, registry_type
            )

            # Perform signature verification if enabled
            signature_verified = None
            signature_details = None
            if self.verify_signatures and self.signature_verifier:
                try:
                    async with self.signature_verifier:
                        verification_result = (
                            await self.signature_verifier.verify_package_signature(
                                dependency.name, dependency.version, registry_type
                            )
                        )
                        signature_verified = (
                            verification_result.status == SignatureStatus.VERIFIED
                        )
                        signature_details = {
                            "status": verification_result.status.value,
                            "method": (
                                verification_result.method.value
                                if verification_result.method
                                else None
                            ),
                            "verified_at": verification_result.verified_at,
                            "signature_data": verification_result.signature_data,
                        }

                        # Adjust risk level based on signature verification
                        if verification_result.status == SignatureStatus.VERIFIED:
                            # Verified signatures reduce risk
                            pass  # Keep current risk level
                        elif verification_result.status == SignatureStatus.UNSIGNED:
                            # No signatures available - slight increase in suspicion
                            pass  # Don't change risk level for now
                        else:
                            # Verification failed - add to reasons but don't modify immutable heuristic_score
                            pass

                except Exception as e:
                    # Don't fail the scan for signature verification errors
                    signature_details = {"error": str(e)}

            # Determine risk level based on heuristic score
            if heuristic_score.is_highly_suspicious:
                risk_level = RiskLevel.HIGH
                reasons = [
                    "Package exists but exhibits highly suspicious characteristics"
                ]
                recommendations = [
                    "⚠️  Exercise extreme caution before installing",
                    "Manually verify package legitimacy",
                    "Consider if this package name was AI-generated",
                    "Look for alternative, well-established packages",
                ]
            elif heuristic_score.is_suspicious:
                risk_level = RiskLevel.MEDIUM
                reasons = ["Package exists but shows suspicious characteristics"]
                recommendations = [
                    "Review package carefully before installation",
                    "Check package author and repository",
                    "Verify package purpose matches your needs",
                    "Consider using more established alternatives",
                ]
            else:
                risk_level = RiskLevel.LOW
                reasons = ["Package appears legitimate"]
                recommendations = ["Package seems safe to use"]

            # Add heuristic-specific reasons
            for heuristic_result in heuristic_score.heuristic_results:
                if heuristic_result.score > 0.5:  # Only include significant findings
                    reasons.extend(heuristic_result.reasons)

            return SecurityFinding(
                dependency=dependency,
                risk_level=risk_level,
                registry_result=registry_result,
                heuristic_score=heuristic_score,
                signature_verified=signature_verified,
                signature_details=signature_details,
                reasons=reasons,
                recommendations=recommendations,
            )


def get_dependency_scanner(
    rate_limit_rps: Optional[float] = None,
    max_concurrent: Optional[int] = None,
    resolve_transitive: bool = False,
    max_depth: int = 3,
    verify_signatures: bool = False,
) -> DependencyScanner:
    """
    Factory function to create a dependency scanner.

    Args:
        rate_limit_rps: API requests per second limit per registry (defaults to config value)
        max_concurrent: Maximum concurrent registry checks (defaults to config value)
        resolve_transitive: Whether to resolve and scan transitive dependencies
        max_depth: Maximum depth for transitive dependency resolution
        verify_signatures: Whether to verify package signatures using 2025 standards

    Returns:
        Configured DependencyScanner instance
    """
    # Use config defaults if not specified
    if rate_limit_rps is None or max_concurrent is None:
        config = get_config()
        rate_limit_rps = rate_limit_rps or config.scan.rate_limit
        max_concurrent = max_concurrent or config.scan.max_concurrent

    return DependencyScanner(
        rate_limit_rps, max_concurrent, resolve_transitive, max_depth, verify_signatures
    )
