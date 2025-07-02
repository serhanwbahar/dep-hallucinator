"""
CLI interface tests for dep-hallucinator.
Tests the command-line interface and main entry points.
"""

import json
import pytest
from click.testing import CliRunner
from unittest.mock import patch, AsyncMock

from src.dep_hallucinator.main import cli
from src.dep_hallucinator.registry_clients import PackageInfo, RegistryCheckResult
from src.dep_hallucinator.scanner import ScanResult, SecurityFinding


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_cli_help(self):
        """Test CLI help message."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        
        assert result.exit_code == 0
        assert "dep-hallucinator" in result.output.lower()

    def test_cli_version(self):
        """Test CLI version display."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_info_command(self):
        """Test the info command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["info"])
        
        assert result.exit_code == 0
        assert "dep-hallucinator" in result.output.lower()


class TestScanCommand:
    """Test the scan command functionality."""

    def setup_method(self):
        """Set up mock for each test."""
        self.mock_scan_result = ScanResult(
            total_dependencies=2,
            findings=[],
            scan_duration_ms=500,
            errors=[]
        )

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_scan_requirements_file(self, mock_scan, sample_requirements_txt):
        """Test scanning a requirements.txt file."""
        mock_scan.return_value = None  # async_scan_dependencies doesn't return anything
        
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(sample_requirements_txt)])
        
        assert result.exit_code == 0
        mock_scan.assert_called_once()

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_scan_package_json_file(self, mock_scan, sample_package_json):
        """Test scanning a package.json file."""
        mock_scan.return_value = None
        
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(sample_package_json)])
        
        assert result.exit_code == 0
        mock_scan.assert_called_once()

    def test_scan_nonexistent_file(self):
        """Test scanning a non-existent file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "nonexistent.txt"])
        
        assert result.exit_code != 0
        assert "does not exist" in result.output.lower()

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_scan_with_options(self, mock_scan, sample_requirements_txt):
        """Test scan command with various options."""
        mock_scan.return_value = None
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(sample_requirements_txt),
            "--rate-limit", "5.0",
            "--max-concurrent", "10",
            "--quiet"
        ])
        
        assert result.exit_code == 0
        mock_scan.assert_called_once()

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_scan_with_json_output(self, mock_scan, sample_requirements_txt, temp_dir):
        """Test scan command with JSON output."""
        mock_scan.return_value = None
        
        output_file = temp_dir / "results.json"
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(sample_requirements_txt),
            "--output-format", "json",
            "--output-file", str(output_file)
        ])
        
        assert result.exit_code == 0
        mock_scan.assert_called_once()


class TestBatchCommand:
    """Test the batch scanning functionality."""

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_batch_scan_multiple_files(self, mock_scan, sample_requirements_txt, sample_package_json):
        """Test batch scanning multiple files."""
        mock_scan.return_value = None
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "batch", 
            str(sample_requirements_txt),
            str(sample_package_json)
        ])
        
        assert result.exit_code == 0
        # Should be called twice (once for each file)
        assert mock_scan.call_count == 2

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_batch_scan_with_options(self, mock_scan, sample_requirements_txt, sample_package_json):
        """Test batch scan with rate limiting options."""
        mock_scan.return_value = None
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "batch",
            str(sample_requirements_txt),
            str(sample_package_json),
            "--rate-limit", "3.0",
            "--quiet"
        ])
        
        assert result.exit_code == 0
        assert mock_scan.call_count == 2


class TestConfigCommands:
    """Test configuration management commands."""

    def test_config_init(self, temp_dir):
        """Test creating a configuration file."""
        config_file = temp_dir / "test-config.json"
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "config", "init",
            "--path", str(config_file)
        ])
        
        assert result.exit_code == 0
        assert config_file.exists()
        
        # Verify it's valid JSON
        config_data = json.loads(config_file.read_text())
        assert "scan" in config_data

    def test_config_show(self):
        """Test showing current configuration."""
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "show"])
        
        assert result.exit_code == 0
        # Should show some configuration information
        assert len(result.output) > 0

    def test_config_validate_valid_file(self, temp_dir):
        """Test validating a valid configuration file."""
        config_file = temp_dir / "valid-config.json"
        config_data = {
            "scan": {
                "rate_limit": 10.0,
                "max_concurrent": 20
            }
        }
        config_file.write_text(json.dumps(config_data))
        
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", str(config_file)])
        
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_config_validate_invalid_file(self, temp_dir):
        """Test validating an invalid configuration file."""
        config_file = temp_dir / "invalid-config.json"
        config_file.write_text("invalid json content")
        
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", str(config_file)])
        
        # Check that either exit code is non-zero OR output indicates error
        assert result.exit_code != 0 or "error" in result.output.lower() or "invalid" in result.output.lower()


class TestErrorHandling:
    """Test CLI error handling."""

    def test_invalid_command(self):
        """Test handling of invalid commands."""
        runner = CliRunner()
        result = runner.invoke(cli, ["invalid-command"])
        
        assert result.exit_code != 0

    def test_missing_file_argument(self):
        """Test scan command without file argument."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        
        assert result.exit_code != 0
        assert "missing" in result.output.lower() or "required" in result.output.lower()

    def test_invalid_rate_limit(self, sample_requirements_txt):
        """Test scan with invalid rate limit."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(sample_requirements_txt),
            "--rate-limit", "invalid"
        ])
        
        assert result.exit_code != 0

    def test_invalid_max_concurrent(self, sample_requirements_txt):
        """Test scan with invalid max concurrent value."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(sample_requirements_txt),
            "--max-concurrent", "invalid"
        ])
        
        assert result.exit_code != 0


class TestOutputFormats:
    """Test different output formats."""

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_console_output_format(self, mock_scan, sample_requirements_txt):
        """Test console output format (default)."""
        mock_scan.return_value = None
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(sample_requirements_txt),
            "--output-format", "console"
        ])
        
        assert result.exit_code == 0

    @patch("src.dep_hallucinator.main.async_scan_dependencies")
    def test_json_output_format(self, mock_scan, sample_requirements_txt):
        """Test JSON output format."""
        mock_scan.return_value = None
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(sample_requirements_txt),
            "--output-format", "json"
        ])
        
        assert result.exit_code == 0

    def test_invalid_output_format(self, sample_requirements_txt):
        """Test invalid output format."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(sample_requirements_txt),
            "--output-format", "invalid"
        ])
        
        assert result.exit_code != 0 