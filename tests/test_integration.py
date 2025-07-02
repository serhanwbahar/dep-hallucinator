"""
Integration tests for dep-hallucinator.
Tests complete end-to-end workflows and real scenarios.
"""

import json
import pytest
from unittest.mock import patch, AsyncMock
from pathlib import Path

from src.dep_hallucinator.main import parse_dependency_file
from src.dep_hallucinator.scanner import get_dependency_scanner
from src.dep_hallucinator.registry_clients import PackageInfo, RegistryCheckResult


class TestEndToEndScanning:
    """Test complete scanning workflows."""

    @pytest.mark.asyncio
    async def test_complete_requirements_scan(self, sample_requirements_txt, mock_registry_client):
        """Test complete workflow: parse -> scan -> report."""
        # Step 1: Parse the file
        dependencies = parse_dependency_file(str(sample_requirements_txt))
        assert len(dependencies) == 4
        
        # Step 2: Scan dependencies
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            result = await scanner.scan_dependency_file(str(sample_requirements_txt))
        
        # Step 3: Verify results
        assert result.total_dependencies == 4
        assert result.has_critical_vulnerabilities  # suspicious-ai-package should be flagged
        assert len(result.critical_findings) == 1

    @pytest.mark.asyncio
    async def test_complete_package_json_scan(self, sample_package_json, mock_registry_client):
        """Test complete workflow for package.json."""
        # Parse and scan package.json
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            result = await scanner.scan_dependency_file(str(sample_package_json))
        
        assert result.total_dependencies >= 3
        assert result.has_critical_vulnerabilities  # ai-fake-helper should be flagged

    @pytest.mark.asyncio
    async def test_mixed_file_types(self, temp_dir, mock_registry_client):
        """Test scanning different file types in one workflow."""
        # Create multiple file types
        req_file = temp_dir / "requirements.txt"
        req_file.write_text("requests==2.28.1\nsuspicious-package==1.0.0")
        
        pkg_file = temp_dir / "package.json"
        pkg_content = {
            "dependencies": {
                "express": "^4.18.0",
                "ai-helper": "1.0.0"
            }
        }
        pkg_file.write_text(json.dumps(pkg_content))
        
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            # Scan both files
            req_result = await scanner.scan_dependency_file(str(req_file))
            pkg_result = await scanner.scan_dependency_file(str(pkg_file))
        
        # Both should find suspicious packages
        assert req_result.has_critical_vulnerabilities
        assert pkg_result.has_critical_vulnerabilities


class TestRealWorldScenarios:
    """Test realistic dependency scenarios."""

    @pytest.mark.asyncio
    async def test_large_dependency_file(self, temp_dir, mock_registry_client):
        """Test scanning a large dependency file."""
        # Create a file with many dependencies
        deps = []
        for i in range(50):
            if i % 10 == 0:  # Every 10th package is suspicious
                deps.append(f"suspicious-package-{i}==1.0.0")
            else:
                deps.append(f"legitimate-package-{i}==1.0.0")
        
        large_file = temp_dir / "large_requirements.txt"
        large_file.write_text("\n".join(deps))
        
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            result = await scanner.scan_dependency_file(str(large_file))
        
        assert result.total_dependencies == 50
        assert len(result.critical_findings) == 5  # Every 10th package

    @pytest.mark.asyncio
    async def test_all_legitimate_packages(self, temp_dir, mock_registry_client):
        """Test scanning when all packages are legitimate."""
        # Create file with only legitimate packages
        legit_file = temp_dir / "legitimate.txt"
        legit_file.write_text("requests==2.28.1\nflask==2.0.0\nnumpy==1.21.0")
        
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            result = await scanner.scan_dependency_file(str(legit_file))
        
        assert result.total_dependencies == 3
        assert not result.has_critical_vulnerabilities
        assert len(result.critical_findings) == 0

    @pytest.mark.asyncio
    async def test_all_suspicious_packages(self, temp_dir, mock_registry_client):
        """Test scanning when all packages are suspicious."""
        # Create file with only suspicious packages
        suspicious_file = temp_dir / "suspicious.txt"
        suspicious_file.write_text("""
ai-super-helper==1.0.0
fake-data-processor==2.0.0
suspicious-ai-lib==1.5.0
""".strip())
        
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            result = await scanner.scan_dependency_file(str(suspicious_file))
        
        assert result.total_dependencies == 3
        assert result.has_critical_vulnerabilities
        assert len(result.critical_findings) == 3  # All should be flagged


class TestErrorRecovery:
    """Test error handling and recovery scenarios."""

    @pytest.mark.asyncio
    async def test_network_timeout_recovery(self, sample_requirements_txt):
        """Test recovery from network timeouts."""
        # Create a client that times out sometimes
        failing_client = AsyncMock()
        call_count = 0
        
        def timeout_sometimes(package_name):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # First two calls timeout
                raise TimeoutError("Network timeout")
            # Subsequent calls succeed
            return RegistryCheckResult(
                package_name=package_name,
                registry_type="pypi",
                package_info=PackageInfo(name=package_name, exists=True),
                check_duration_ms=500
            )
        
        failing_client.check_package_exists.side_effect = timeout_sometimes
        
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=failing_client):
            result = await scanner.scan_dependency_file(str(sample_requirements_txt))
        
        # Should complete despite some timeouts
        assert result.total_dependencies == 4
        # May have some errors recorded
        assert result.errors is not None

    @pytest.mark.asyncio
    async def test_partial_registry_failure(self, sample_requirements_txt):
        """Test handling when some registry checks fail."""
        from src.dep_hallucinator.registry_clients import RegistryCheckResult, PackageInfo
        
        # Create a client that fails for specific packages
        partial_fail_client = AsyncMock()
        
        async def fail_for_some(package_name):
            if "suspicious" in package_name:
                raise Exception("Registry API error")
            return RegistryCheckResult(
                package_name=package_name,
                registry_type="pypi",
                package_info=PackageInfo(name=package_name, exists=True),
                check_duration_ms=200,
                error=None
            )
        
        partial_fail_client.check_package_exists.side_effect = fail_for_some
        partial_fail_client.get_registry_type.return_value = "pypi"
        
        # Mock the async context manager
        async def mock_aenter(self):
            return partial_fail_client
        
        async def mock_aexit(self, *args):
            pass
        
        partial_fail_client.__aenter__ = mock_aenter
        partial_fail_client.__aexit__ = mock_aexit
        
        scanner = get_dependency_scanner()
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=partial_fail_client):
            result = await scanner.scan_dependency_file(str(sample_requirements_txt))
        
        # Should complete and handle failed packages gracefully
        assert result.total_dependencies == 4
        # Should have findings for all packages (some with errors)
        assert len(result.findings) > 0
        # Check that the suspicious package that caused the exception has ERROR risk level
        suspicious_finding = next((f for f in result.findings if "suspicious" in f.dependency.name), None)
        assert suspicious_finding is not None
        assert suspicious_finding.risk_level.value == "ERROR"


class TestConfigurationIntegration:
    """Test integration with different configurations."""

    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, sample_requirements_txt, mock_registry_client):
        """Test that rate limiting is properly applied."""
        scanner = get_dependency_scanner(rate_limit_rps=1.0, max_concurrent=1)
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            result = await scanner.scan_dependency_file(str(sample_requirements_txt))
        
        assert result.total_dependencies == 4
        # Scan should take longer due to rate limiting, but still complete

    @pytest.mark.asyncio
    async def test_high_concurrency_scanning(self, temp_dir, mock_registry_client):
        """Test scanning with high concurrency settings."""
        # Create a larger file
        deps = [f"package-{i}==1.0.0" for i in range(20)]
        large_file = temp_dir / "many_deps.txt"
        large_file.write_text("\n".join(deps))
        
        scanner = get_dependency_scanner(rate_limit_rps=100.0, max_concurrent=50)
        
        with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
            result = await scanner.scan_dependency_file(str(large_file))
        
        assert result.total_dependencies == 20
        # Should complete quickly with high concurrency


class TestDataIntegrity:
    """Test data integrity and consistency."""

    @pytest.mark.asyncio
    async def test_scan_result_consistency(self, sample_requirements_txt, mock_registry_client):
        """Test that scan results are consistent across multiple runs."""
        scanner = get_dependency_scanner()
        
        results = []
        for _ in range(3):
            with patch("src.dep_hallucinator.scanner.get_registry_client", return_value=mock_registry_client):
                result = await scanner.scan_dependency_file(str(sample_requirements_txt))
                results.append(result)
        
        # All results should be consistent
        for result in results:
            assert result.total_dependencies == 4
            assert result.has_critical_vulnerabilities == results[0].has_critical_vulnerabilities
            assert len(result.critical_findings) == len(results[0].critical_findings)

    def test_dependency_parsing_consistency(self, sample_requirements_txt):
        """Test that parsing produces consistent results."""
        # Parse the same file multiple times
        results = []
        for _ in range(3):
            deps = parse_dependency_file(str(sample_requirements_txt))
            results.append(deps)
        
        # All results should be identical
        for result in results:
            assert len(result) == len(results[0])
            for i, dep in enumerate(result):
                # Handle both dict and Dependency object types
                dep_name = dep["name"] if isinstance(dep, dict) else dep.name
                dep_version = dep["version"] if isinstance(dep, dict) else dep.version
                ref_name = results[0][i]["name"] if isinstance(results[0][i], dict) else results[0][i].name
                ref_version = results[0][i]["version"] if isinstance(results[0][i], dict) else results[0][i].version
                assert dep_name == ref_name
                assert dep_version == ref_version


class TestFileFormatSupport:
    """Test support for different file formats."""

    def test_poetry_lock_support(self, temp_dir):
        """Test basic poetry.lock file support."""
        poetry_content = """
[[package]]
name = "requests"
version = "2.28.1"
description = "Python HTTP for Humans."

[[package]]
name = "suspicious-ai-lib"
version = "1.0.0"
description = "AI generated package"
"""
        poetry_file = temp_dir / "poetry.lock"
        poetry_file.write_text(poetry_content)
        
        dependencies = parse_dependency_file(str(poetry_file))
        assert len(dependencies) == 2
        # Handle both dict and Dependency object types
        dep0_name = dependencies[0]["name"] if isinstance(dependencies[0], dict) else dependencies[0].name
        dep1_name = dependencies[1]["name"] if isinstance(dependencies[1], dict) else dependencies[1].name
        assert dep0_name == "requests"
        assert dep1_name == "suspicious-ai-lib"

    def test_cargo_toml_support(self, temp_dir):
        """Test basic Cargo.toml file support."""
        cargo_content = """
[dependencies]
serde = "1.0"
tokio = "1.0"
suspicious-rust-crate = "0.1.0"
"""
        cargo_file = temp_dir / "Cargo.toml"
        cargo_file.write_text(cargo_content)
        
        dependencies = parse_dependency_file(str(cargo_file))
        assert len(dependencies) >= 2  # Should parse at least some dependencies 