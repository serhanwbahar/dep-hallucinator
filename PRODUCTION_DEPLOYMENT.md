# Production Deployment

Deploy dep-hallucinator in production environments.

## Quick Start

### Standard Production

```bash
docker compose up dep-hallucinator
# or
pip install "dep-hallucinator[production,rich]"
export DEP_HALLUCINATOR_PRODUCTION=true
```

### High Performance

```bash
docker compose --profile hpc up dep-hallucinator-hpc
# or
pip install "dep-hallucinator[all]"
export DEP_HALLUCINATOR_ENV=high-performance
```

### Resource Constrained

```bash
docker compose --profile lite up dep-hallucinator-lite
# or
pip install dep-hallucinator
export DEP_HALLUCINATOR_ENV=resource-constrained
```

## Configuration

### Environment Variables

```bash
# Production mode
export DEP_HALLUCINATOR_PRODUCTION=true
export DEP_HALLUCINATOR_ENV=production

# Performance
export DEP_HALLUCINATOR_RATE_LIMIT=15.0
export DEP_HALLUCINATOR_MAX_CONCURRENT=25
export DEP_HALLUCINATOR_TIMEOUT=20

# Memory limits
export DEP_HALLUCINATOR_MAX_MEMORY_MB=512
export DEP_HALLUCINATOR_MAX_ASYNC_WORKERS=15

# Optimizations
export DEP_HALLUCINATOR_ENABLE_UVLOOP=true
export DEP_HALLUCINATOR_ENABLE_ORJSON=true
export DEP_HALLUCINATOR_ENABLE_LZ4=true

# Logging
export DEP_HALLUCINATOR_LOG_LEVEL=INFO
export DEP_HALLUCINATOR_ENABLE_FILE_LOGGING=true
```

### Configuration File

`.dep-hallucinator.json`:

```json
{
  "scan": {
    "rate_limit": 15.0,
    "max_concurrent": 25,
    "timeout_seconds": 20,
    "retry_attempts": 2
  },
  "security": {
    "max_file_size_mb": 5,
    "max_lines_per_file": 50000
  },
  "performance": {
    "enable_caching": true,
    "cache_ttl_seconds": 1800,
    "max_cache_size": 2000
  },
  "production": {
    "max_memory_mb": 512,
    "enable_uvloop": true,
    "enable_orjson": true,
    "enable_lz4_compression": true
  }
}
```

## Docker Deployment

### Build Images

```bash
# Production
docker build --target production -t dep-hallucinator:prod .

# High performance
docker build --target production --build-arg BUILD_ENV=full -t dep-hallucinator:hpc .
```

### Run Containers

```bash
# Production
docker run -it --rm \
  --memory=512m \
  -v ./data:/app/data \
  dep-hallucinator:prod scan requirements.txt

# With compose
docker compose up dep-hallucinator
```

## Environment Profiles

### Production (512MB RAM)
- Rate limit: 15 req/s
- Max concurrent: 25
- Memory optimized
- File logging enabled

### High Performance (1GB RAM)
- Rate limit: 25 req/s
- Max concurrent: 40
- All optimizations enabled
- Maximum throughput

### Resource Constrained (256MB RAM)
- Rate limit: 10 req/s
- Max concurrent: 10
- Minimal features
- CI/CD optimized

## Monitoring

### Health Checks

```bash
# Built-in health check
dep-hallucinator --version

# Container health check
curl http://localhost:8080/health
```

### Performance Stats

```bash
dep-hallucinator --performance-stats
```

### Metrics

Enable metrics collection:

```bash
export DEP_HALLUCINATOR_ENABLE_METRICS=true
```

## Security

### Container Security

- Non-root user (depscanner)
- Minimal base image
- Read-only file system
- Resource limits

### Network Security

- HTTPS only
- Request timeouts
- Rate limiting
- Input validation

### Credential Security

- Environment variables only
- No hardcoded secrets
- Automatic log sanitization
- Secure file permissions

## Scaling

### Horizontal Scaling

```bash
# Scale with compose
docker compose up --scale dep-hallucinator=3

# Kubernetes deployment
kubectl apply -f k8s/deployment.yaml
kubectl scale deployment dep-hallucinator --replicas=5
```

### Load Balancing

Use nginx or similar for load balancing multiple instances.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    pip install dep-hallucinator
    dep-hallucinator scan requirements.txt --quiet --fail-on-high
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install dep-hallucinator
    - dep-hallucinator scan requirements.txt --output-format json
```

### Jenkins

```groovy
stage('Security Scan') {
    steps {
        sh 'dep-hallucinator scan requirements.txt --quiet'
    }
}
```

## Troubleshooting

### Common Issues

1. **Memory errors**: Reduce `max_concurrent` or increase memory limit
2. **Rate limiting**: Adjust `rate_limit` setting
3. **Timeouts**: Increase `timeout_seconds`
4. **Cache issues**: Clear cache with `dep-hallucinator cache clear`

### Performance Tuning

1. Enable uvloop on Unix systems
2. Use orjson for faster JSON processing
3. Enable LZ4 cache compression
4. Adjust garbage collection threshold

### Debugging

```bash
# Debug mode
export DEP_HALLUCINATOR_LOG_LEVEL=DEBUG

# Verbose output
dep-hallucinator scan requirements.txt --verbose

# Check configuration
dep-hallucinator config show
``` 