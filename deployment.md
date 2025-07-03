# Deployment Guide

Deploy dep-hallucinator in production environments.

## Installation

### From PyPI
```bash
pip install dep-hallucinator
```

### Development Installation
```bash
git clone https://github.com/serhanwbahar/dep-hallucinator.git
cd dep-hallucinator
pip install -e ".[dev,test]"
```

## Configuration

### Environment Variables
See `env.example` for all available options:

```bash
# Rate limiting
DEP_HALLUCINATOR_RATE_LIMIT=10.0
DEP_HALLUCINATOR_MAX_CONCURRENT=20

# Logging
DEP_HALLUCINATOR_LOG_LEVEL=INFO
DEP_HALLUCINATOR_ENABLE_FILE_LOGGING=true

# Performance
DEP_HALLUCINATOR_ENABLE_CACHE=true
DEP_HALLUCINATOR_CACHE_TTL=3600
```

## Docker Deployment

Use the included Dockerfile:

```bash
# Build
docker build -t dep-hallucinator .

# Run scan
docker run -v ./deps:/deps dep-hallucinator scan /deps/requirements.txt

# Use docker-compose
docker-compose up dep-hallucinator
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    pip install dep-hallucinator
    dep-hallucinator scan requirements.txt --quiet
```

### Jenkins
```groovy
stage('Security Scan') {
    steps {
        sh 'dep-hallucinator scan requirements.txt --quiet'
    }
}
```

## Health Monitoring

```bash
# Basic health check
dep-hallucinator --version

# Test functionality
dep-hallucinator scan requirements.txt --quiet
```

## Troubleshooting

### Common Issues

**High memory usage**: Reduce cache size and concurrency
```bash
export DEP_HALLUCINATOR_MAX_CACHE_SIZE=1000
export DEP_HALLUCINATOR_MAX_CONCURRENT=10
```

**Rate limit exceeded**: Reduce request rate
```bash
export DEP_HALLUCINATOR_RATE_LIMIT=5.0
```

**Network timeouts**: Increase timeout
```bash
export DEP_HALLUCINATOR_TIMEOUT=60
```

### Debug Mode
```bash
export DEP_HALLUCINATOR_LOG_LEVEL=DEBUG
```

## Related Documentation

- [Production Deployment](production_deployment.md) - Detailed production setup
- [Contributing](contributing.md) - Development guidelines  
- [Security](security.md) - Security policies 