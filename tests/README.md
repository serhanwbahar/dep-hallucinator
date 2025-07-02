# Test Suite for dep-hallucinator

This directory contains a simplified, comprehensive test suite for the dep-hallucinator project.

## Overview

The test suite uses a streamlined 3-file structure that covers all functionality while being easy to maintain:

- **`test_core.py`**: Core functionality, parsers, scanners, and registry clients
- **`test_cli.py`**: Command-line interface and user interaction tests  
- **`test_integration.py`**: End-to-end workflows and component integration

## Test Structure

```
tests/
├── conftest.py          # Shared fixtures and configuration
├── pytest.ini          # Pytest configuration
├── README.md           # This file
├── test_core.py        # Core functionality tests
├── test_cli.py         # CLI tests
└── test_integration.py # Integration tests
```

## Running Tests

### Quick Start

```bash
# Install test dependencies
pip install -e ".[dev,test]"

# Run all tests
make test

# Run with coverage
make coverage
```

### Detailed Test Commands

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run specific test files
pytest tests/test_core.py -v
pytest tests/test_cli.py -v
pytest tests/test_integration.py -v

# Run tests with coverage report
pytest tests/ --cov=src/dep_hallucinator --cov-report=html --cov-report=term

# Run tests matching specific patterns
pytest tests/ -k "test_scan" -v
pytest tests/ -k "suspicious" -v
```

## Test Categories

### Core Tests (`test_core.py`)

Tests for the fundamental components and business logic:

#### **Parser Tests**
- File format detection and validation
- Dependency extraction from various file types
- Error handling for malformed files
- Edge cases and boundary conditions

#### **Scanner Tests**  
- Package scanning workflows
- Registry client integration
- Risk level determination
- Heuristic analysis
- ML pattern recognition
- Performance and concurrency

#### **Registry Client Tests**
- API interactions and responses
- Rate limiting and timeout handling
- Authentication and credentials
- Error handling and retries
- Cache behavior

#### **Security Tests**
- Input validation and sanitization
- Credential protection
- Network security
- Error message safety

### CLI Tests (`test_cli.py`)

Tests for command-line interface functionality:

#### **Command Tests**
- `scan` command with various options
- `batch` command for multiple files
- `config` commands (init, show, validate)
- `cache` management commands
- Error handling and help text

#### **Output Tests**
- Console output formatting
- JSON output structure
- Quiet and verbose modes
- Exit codes and error reporting

#### **Configuration Tests**
- Config file loading and validation
- Environment variable handling
- Command-line option precedence
- Default value handling

### Integration Tests (`test_integration.py`)

Tests for complete workflows and component interactions:

#### **End-to-End Scanning**
- Complete scan workflows from file to report
- Multi-file batch processing
- Real registry interactions (mocked)
- Performance under load

#### **Error Recovery**
- Network failure handling
- Partial registry failures
- File access errors
- Graceful degradation

#### **Advanced Features**
- Transitive dependency resolution
- SBOM generation
- Signature verification
- Forensic analysis

## Test Fixtures and Mocking

### Shared Fixtures (`conftest.py`)

The test suite uses comprehensive fixtures for consistent testing:

#### **File Fixtures**
- Sample dependency files for all supported formats
- Malformed files for error testing
- Large files for performance testing

#### **Mock Registry Clients**
- Simulated PyPI, npm, Maven, Crates.io, Go responses
- Configurable error scenarios
- Rate limiting simulation
- Async behavior mocking

#### **Configuration Fixtures**
- Test configurations for various scenarios
- Temporary directories and files
- Environment variable mocking

### Mocking Strategy

- **Registry APIs**: Mock all external HTTP calls
- **File System**: Use temporary files and directories  
- **Async Operations**: Proper async mocking with AsyncMock
- **ML Models**: Mock ML predictions for consistent testing
- **Time**: Frozen time for predictable testing

## Test Coverage

### Current Coverage
- **Overall**: 95%+ test coverage
- **Core Components**: 100% coverage
- **CLI**: 90%+ coverage
- **Integration**: 85%+ coverage

### Coverage Requirements
- **New Code**: 100% coverage required
- **Critical Paths**: 100% coverage required
- **Error Handling**: All error paths tested

### Running Coverage
```bash
# Generate HTML coverage report
make coverage

# View coverage in browser
open htmlcov/index.html
```

## Test Data

### Mock Packages
Tests use realistic but fictional package data:
- `requests==2.28.1` - Legitimate package
- `suspicious-ai-package==1.0.0` - Non-existent suspicious package
- `fake-tensorflow==1.0.0` - Typosquatting example

### Test Files
Sample dependency files are generated dynamically in tests:
- `requirements.txt` with mixed legitimate/suspicious packages
- `package.json` with various dependency types
- `pom.xml` with Java dependencies
- Malformed files for error testing

## Performance Testing

### Benchmarks
```bash
# Run performance-sensitive tests
pytest tests/ -k "performance" -v

# Profile memory usage
pytest tests/ --profile

# Test with large inputs
pytest tests/test_integration.py::TestScaling -v
```

### Performance Targets
- **Small files** (< 50 deps): < 5 seconds
- **Medium files** (< 500 deps): < 30 seconds
- **Large files** (< 5000 deps): < 5 minutes
- **Memory usage**: < 512MB for typical scans

## Adding New Tests

### Guidelines
1. **Follow the 3-file structure**: Add tests to the appropriate file
2. **Use descriptive names**: `test_scan_suspicious_packages_returns_critical`
3. **Test both success and failure**: Happy path and error conditions
4. **Use fixtures**: Leverage existing fixtures from `conftest.py`
5. **Mock external dependencies**: Don't make real network calls
6. **Add docstrings**: Explain what the test validates

### Example Test
```python
@pytest.mark.asyncio
async def test_scan_suspicious_package_detection(mock_registry_client):
    """Test that suspicious packages are correctly identified as CRITICAL."""
    scanner = get_dependency_scanner()
    
    with patch("src.dep_hallucinator.scanner.get_registry_client", 
               return_value=mock_registry_client):
        # Test with a suspicious package
        dependencies = [Dependency("suspicious-ai-lib", "1.0.0", "requirements.txt")]
        result = await scanner.scan_dependencies(dependencies)
        
        # Verify critical finding
        assert result.has_critical_vulnerabilities
        assert len(result.critical_findings) == 1
        assert "suspicious-ai-lib" in result.critical_findings[0].dependency.name
```

## Continuous Integration

The test suite is designed for CI/CD environments:

- **Fast execution**: Optimized for quick feedback
- **Reliable mocking**: No external dependencies
- **Clear reporting**: JUnit XML and coverage reports
- **Parallel execution**: Safe for parallel test runs

### CI Commands
```bash
# CI test run with coverage
pytest tests/ -v --cov=src/dep_hallucinator --cov-report=xml --junit-xml=test-results.xml

# Quick smoke test
pytest tests/ -x --tb=short
``` 