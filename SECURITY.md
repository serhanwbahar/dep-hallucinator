# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting Vulnerabilities

**Do not file public issues for security vulnerabilities.**

Email: **serhan@swb.sh**

Include:
- Description of the vulnerability
- Impact assessment
- Steps to reproduce
- Affected versions
- Suggested fix (if any)

## Response Timeline

- **24 hours**: Acknowledgment
- **7 days**: Initial assessment
- **30 days**: Fix and release

## Security Features

### Credential Protection
- API key sanitization in logs
- Environment variable validation
- Secure file permission checks

### Input Validation
- File size and content limits
- URL and package name validation
- Regex pattern safety

### Network Security
- HTTPS enforcement
- Request timeouts and retries
- Rate limiting protection

### Error Handling
- No sensitive data in error messages
- Graceful failure handling
- Secure exception logging

## Responsible Disclosure

We will:
1. Confirm and assess the vulnerability
2. Develop a fix
3. Test thoroughly
4. Release fix with advisory
5. Credit the reporter (if desired)

## Updates

This policy may be updated. Check this repository for the latest version.

---

**Note**: This project is designed to improve security by detecting AI-generated dependency confusion vulnerabilities. If you believe you've found a case where dep-hallucinator fails to detect a legitimate security threat, please also report this using the same process. 