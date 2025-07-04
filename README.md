# Dep-Hallucinator

Security scanner that detects AI-generated dependency confusion vulnerabilities in software projects.

## Problem

AI code assistants sometimes suggest packages that don't exist. Attackers can register these hallucinated package names with malicious code. When developers install the suggested dependency, they execute the attacker's payload.

## Solution

Dep-Hallucinator detects these non-existent packages and suspicious packages that may be malicious registrations.

## Features

* **Registry scanning**: Checks PyPI, npm, Maven Central, Crates.io, and Go Modules
* **ML detection**: Identifies AI-generated naming patterns
* **Heuristic analysis**: Analyzes package age, downloads, and metadata
* **Risk classification**: CRITICAL/HIGH/MEDIUM/LOW risk levels with explanations
* **Multi-language support**: Python, JavaScript, Java, Rust, Go
* **SBOM generation**: Creates Software Bill of Materials
* **CI/CD integration**: Exit codes and JSON output

## Supported Ecosystems

| Language | Registry | File Types |
|----------|----------|------------|
| Python | PyPI | `requirements.txt`, `poetry.lock`, `Pipfile.lock` |
| JavaScript | npm | `package.json`, `yarn.lock` |
| Java | Maven Central | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Rust | Crates.io | `Cargo.toml`, `Cargo.lock` |
| Go | Go Modules | `go.mod`, `go.sum` |

## Installation

```bash
pip install dep-hallucinator
```

## Usage

```bash
# Basic scan
dep-hallucinator scan requirements.txt

# With options
dep-hallucinator scan requirements.txt --rate-limit 5.0 --max-concurrent 10

# JSON output
dep-hallucinator scan requirements.txt --output-format json

# Generate SBOM
dep-hallucinator scan requirements.txt --generate-sbom

# Batch scan
dep-hallucinator batch requirements.txt package.json pom.xml
```

## Example Output

```
🔍 Scanning 8 dependencies...

📊 Scan Summary           
🚨 CRITICAL │   2   │ VULNERABLE
🔶 HIGH     │   1   │ SUSPICIOUS  
✅ LOW      │   5   │     OK     

🚨 CRITICAL VULNERABILITIES

📦 ai-powered-data-processor (==1.0.0)
   Suspicion Score: 100% (CRITICAL) | ML: 95%
   Reasons:
   • Package does not exist in the registry
   • Vulnerable to dependency confusion attacks
   • ML models indicate high probability of AI generation
   Recommendations:
   → Do not install this package
   → Check if this was generated by an AI assistant
```

## Configuration

Create `.dep-hallucinator.json`:

```json
{
  "scan": {
    "rate_limit": 10.0,
    "max_concurrent": 20,
    "timeout_seconds": 30
  },
  "security": {
    "max_file_size_mb": 10
  }
}
```

## Development

```bash
git clone https://github.com/serhanwbahar/dep-hallucinator.git
cd dep-hallucinator
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,test]"
make test
```

## Exit Codes

- `0`: No critical vulnerabilities
- `1`: Critical vulnerabilities found
- `130`: Scan interrupted

## Documentation

* [Complete Documentation](./documentation.md) - Comprehensive usage guide
* [Security Policy](./security.md) - Vulnerability reporting
* [Contributing](./contributing.md) - Development guidelines
* [Deployment](./deployment.md) - Production deployment

## License

MIT License. See LICENSE file.
