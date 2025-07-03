# Structured Logging

## Overview

Dep-hallucinator provides structured JSON logging for integration with SIEM systems and security monitoring tools.

## Features

- Security-focused event logging
- JSON format output
- Component-specific loggers
- Automatic context propagation
- Risk level categorization

## JSON Log Format

```json
{
  "timestamp": "2024-12-19T10:30:45.123456+00:00",
  "level": "WARNING",
  "component": "scanner",
  "event_type": "high_risk_package_detected",
  "scan_context": {
    "scan_id": "scan_1734601845",
    "file_path": "requirements.txt",
    "total_dependencies": 25
  },
  "package_name": "fake-tensorflow",
  "registry": "pypi",
  "risk_level": "CRITICAL",
  "suspicion_score": 0.95,
  "ml_probability": 0.92
}
```

## Components

### Loggers
- **Security Logger**: Threat detection events
- **Scanner Logger**: Package analysis operations  
- **Forensic Logger**: Audit trails
- **Registry Logger**: API interactions
- **ML Logger**: Machine learning predictions

### Event Types

**Security Events:**
- `security_scan_initiated`
- `high_risk_package_detected`
- `dependency_confusion_attack_detected`
- `ai_hallucination_detected`
- `signature_verification_failed`

**Scanner Events:**
- `scan_started` / `scan_completed`
- `package_analyzed`
- `registry_check_completed`

## Usage

### Basic Logging
```python
from dep_hallucinator.structured_logging import get_scanner_logger

logger = get_scanner_logger()
logger.info("dependency_file_parsed", 
            file_path="requirements.txt",
            total_packages=15)
```

### Security Events
```python
from dep_hallucinator.structured_logging import log_security_event

log_security_event(
    "dependency_confusion_attack_detected",
    severity="warning",
    package_name="fake-tensorflow", 
    risk_level="CRITICAL",
    attack_vector="typosquatting"
)
```

### Scan Context
```python
from dep_hallucinator.structured_logging import (
    set_scan_context, log_scan_start, log_scan_complete
)

# Set context for all logs
set_scan_context(
    scan_id="scan_123456",
    file_path="requirements.txt", 
    total_dependencies=25
)

log_scan_start("scan_123456", "requirements.txt", 25)
log_scan_complete("scan_123456", 3500, 25, critical_count=1)
```

## SIEM Integration

### Splunk
```conf
[json_logs]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = timestamp
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
```

### ELK Stack
```yaml
filter {
  if [fields][service] == "dep-hallucinator" {
    json {
      source => "message"
    }
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
}
```

## Key Metrics

Monitor these metrics:
- Critical/High risk package detections
- Scan frequency and coverage
- Registry response times
- ML model confidence trends

## Configuration

### Environment Variables
```bash
export DEP_HALLUCINATOR_LOG_LEVEL=INFO
export DEP_HALLUCINATOR_ENABLE_FILE_LOGGING=true
export DEP_HALLUCINATOR_LOG_FILE=/var/log/dep-hallucinator.log
```

### Log Levels
- `DEBUG`: Detailed diagnostic information
- `INFO`: General operational messages
- `WARNING`: Important security findings
- `ERROR`: Scan failures and system errors
- `CRITICAL`: Immediate action required

## Benefits

- Real-time threat detection
- Audit-ready compliance logs
- Performance monitoring
- Historical trend analysis
- Incident response data 