# Production Deployment Guide

This guide covers deploying dep-hallucinator in production environments with security best practices.

## 🚀 Quick Production Setup

### 1. Install from PyPI (Recommended)
```bash
pip install dep-hallucinator
```

### 2. Development Installation
```bash
git clone https://github.com/serhanwbahar/dep-hallucinator.git
cd dep-hallucinator
pip install -e .
```

## 🔧 Production Configuration

### Environment Variables
Copy `env.example` to `.env` and configure:

```bash
cp env.example .env
# Edit .env with your settings
```

### Key Production Settings
```bash
# Rate limiting for production load
DEP_HALLUCINATOR_RATE_LIMIT=15.0
DEP_HALLUCINATOR_MAX_CONCURRENT=30

# Security settings
DEP_HALLUCINATOR_LOG_LEVEL=WARNING
DEP_HALLUCINATOR_ENABLE_FILE_LOGGING=true
DEP_HALLUCINATOR_LOG_FILE=/var/log/dep-hallucinator.log

# Performance optimization
DEP_HALLUCINATOR_ENABLE_CACHE=true
DEP_HALLUCINATOR_CACHE_TTL=7200
```

## 🐳 Docker Deployment

### Create Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY src/ ./src/

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD dep-hallucinator --version

ENTRYPOINT ["dep-hallucinator"]
CMD ["--help"]
```

### Build and Run
```bash
docker build -t dep-hallucinator:1.0.0 .
docker run -v /path/to/deps:/deps dep-hallucinator:1.0.0 scan /deps/requirements.txt
```

## ☸️ Kubernetes Deployment

### Deployment YAML
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dep-hallucinator
spec:
  replicas: 3
  selector:
    matchLabels:
      app: dep-hallucinator
  template:
    metadata:
      labels:
        app: dep-hallucinator
    spec:
      containers:
      - name: dep-hallucinator
        image: dep-hallucinator:1.0.0
        env:
        - name: DEP_HALLUCINATOR_RATE_LIMIT
          value: "20.0"
        - name: DEP_HALLUCINATOR_LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command:
            - dep-hallucinator
            - --version
          initialDelaySeconds: 30
          periodSeconds: 60
```

## 🔐 Security Configuration

### API Key Management
```bash
# Set registry credentials securely
export PYPI_API_TOKEN="pypi-AgEIcHlwaS5vcmcCJDUwZjA..."
export NPM_AUTH_TOKEN="npm_1234567890abcdef..."

# Or use Kubernetes secrets
kubectl create secret generic registry-credentials \
  --from-literal=pypi-token="$PYPI_API_TOKEN" \
  --from-literal=npm-token="$NPM_AUTH_TOKEN"
```

### File Permissions
```bash
# Secure credential files
chmod 600 ~/.dep-hallucinator-credentials.json
chown root:root ~/.dep-hallucinator-credentials.json

# Log file permissions
mkdir -p /var/log
touch /var/log/dep-hallucinator.log
chmod 640 /var/log/dep-hallucinator.log
chown appuser:appgroup /var/log/dep-hallucinator.log
```

## 🏥 Health Monitoring

### Health Check Script
```bash
#!/bin/bash
# health-check.sh

set -e

echo "🏥 Running health checks..."

# Check if binary exists and runs
dep-hallucinator --version

# Test basic functionality
echo "requests==2.28.1" > /tmp/health_deps.txt
dep-hallucinator scan /tmp/health_deps.txt --quiet
rm -f /tmp/health_deps.txt

echo "✅ Health check passed"
```

### Monitoring Metrics
Monitor these key metrics:

- **Scan Success Rate**: Percentage of successful scans
- **Response Time**: Average scan completion time
- **Error Rate**: Rate of scan failures
- **Cache Hit Rate**: Efficiency of caching
- **Memory Usage**: Memory consumption patterns
- **API Rate Limits**: Registry API usage

## 🚨 CI/CD Integration

### GitHub Actions
The included `.github/workflows/ci.yml` provides:
- Multi-version Python testing
- Security scanning
- Functional testing
- Automated PyPI publishing

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Test') {
            steps {
                sh 'make test'
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'make security-scan'
            }
        }
        
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'make publish'
            }
        }
    }
}
```

## 📊 Performance Tuning

### Production Optimization
```bash
# High-throughput scanning
export DEP_HALLUCINATOR_RATE_LIMIT=50.0
export DEP_HALLUCINATOR_MAX_CONCURRENT=100
export DEP_HALLUCINATOR_TIMEOUT=60

# Memory optimization
export DEP_HALLUCINATOR_MAX_CACHE_SIZE=5000
export DEP_HALLUCINATOR_ENABLE_COMPRESSION=true
```

### Batch Processing
```bash
# Scan multiple files efficiently
dep-hallucinator batch \
  requirements.txt package.json pom.xml \
  --rate-limit 30.0 \
  --max-concurrent 50 \
  --output-format json \
  --output-dir ./scan-results/
```

## 🔄 Backup and Recovery

### Configuration Backup
```bash
# Backup configuration
tar -czf dep-hallucinator-config-$(date +%Y%m%d).tar.gz \
  ~/.dep-hallucinator-credentials.json \
  .dep-hallucinator.json \
  .env

# Restore configuration
tar -xzf dep-hallucinator-config-20240315.tar.gz
```

### Database/Cache Recovery
```bash
# Clear and rebuild cache if corrupted
dep-hallucinator cache clear --confirm
dep-hallucinator cache cleanup
```

## 🚦 Production Checklist

### Pre-Deployment
- [ ] Security scan passed (`make security-scan`)
- [ ] All tests passing (`make test`)
- [ ] Configuration validated
- [ ] Credentials secured
- [ ] Monitoring configured
- [ ] Backup strategy defined

### Post-Deployment
- [ ] Health check passing
- [ ] Performance metrics normal
- [ ] Error rates acceptable
- [ ] Security monitoring active
- [ ] Log aggregation working

## 🆘 Troubleshooting

### Common Issues

**Issue**: High memory usage
```bash
# Solution: Reduce cache size and concurrency
export DEP_HALLUCINATOR_MAX_CACHE_SIZE=1000
export DEP_HALLUCINATOR_MAX_CONCURRENT=20
```

**Issue**: Rate limit exceeded
```bash
# Solution: Reduce request rate
export DEP_HALLUCINATOR_RATE_LIMIT=5.0
```

**Issue**: Network timeouts
```bash
# Solution: Increase timeout and add retries
export DEP_HALLUCINATOR_TIMEOUT=60
export DEP_HALLUCINATOR_RETRY_ATTEMPTS=5
```

### Debug Mode
```bash
# Enable debug logging (not for production)
export DEP_HALLUCINATOR_LOG_LEVEL=DEBUG
export DEP_HALLUCINATOR_VERBOSE=true
```

## 📞 Support

For production support:
- 📧 **Email**: serhan@swb.sh
- 🐛 **Issues**: https://github.com/serhanwbahar/dep-hallucinator/issues
- 📖 **Documentation**: See README.md and SECURITY.md

---

**Note**: Always test configuration changes in a staging environment before deploying to production. 