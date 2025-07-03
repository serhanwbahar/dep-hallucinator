# Release Notes - v1.0.0

## Features

### CLI Commands
- `scan` - Scan single dependency file
- `batch` - Scan multiple files
- `config` - Manage configuration
- `completion` - Shell completion scripts
- `info` - Display tool information

### Configuration
- Config file support (`.dep-hallucinator.json`)
- Environment variables for all settings
- User-level and project-level configuration

### Output
- Console and JSON output formats
- Verbose and quiet modes
- File export for results

## Usage

```bash
# Basic scan
dep-hallucinator scan requirements.txt

# Batch scan
dep-hallucinator batch requirements.txt package.json

# JSON output
dep-hallucinator scan requirements.txt --output-format json

# Configure
dep-hallucinator config init
dep-hallucinator config show
```

## Configuration

### File Configuration
```json
{
  "scan": {
    "rate_limit": 10.0,
    "max_concurrent": 20,
    "timeout_seconds": 30
  }
}
```

### Environment Variables
```bash
export DEP_HALLUCINATOR_RATE_LIMIT=10.0
export DEP_HALLUCINATOR_MAX_CONCURRENT=20
export DEP_HALLUCINATOR_TIMEOUT=30
```

## CI/CD Integration

```yaml
- name: Security Scan
  run: |
    pip install dep-hallucinator
    dep-hallucinator scan requirements.txt --quiet
```

## Exit Codes
- `0`: No critical vulnerabilities
- `1`: Critical vulnerabilities found
- `130`: Interrupted

## Installation

```bash
pip install dep-hallucinator
```

## Breaking Changes

- New CLI structure with subcommands
- Configuration file format updated
- Environment variable naming standardized

## Technical Changes

- Enhanced type hints
- Better error handling
- Async performance improvements
- Modular code structure
- Rich terminal output
- Click CLI framework

## Dependencies

- Rich: Terminal formatting
- Click: CLI framework
- HTTPX: HTTP client

---

**Changelog**: https://github.com/serhanwbahar/dep-hallucinator/compare/v0.0.1...v1.0.0 