# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 28.x    | :white_check_mark: |
| 27.x    | :white_check_mark: |
| < 27.0  | :x:                |

## Reporting a Vulnerability

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report them via:
- Email: security@cyberdudebivash.com
- Subject: [SECURITY] Brief description

### What to Include
- Type of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline
- Acknowledgment: 24 hours
- Initial assessment: 72 hours
- Fix timeline: Based on severity

## Security Practices

This platform follows:
- OWASP Top 10 guidelines
- Secure coding standards
- Regular dependency audits
- No credentials in repository
- Environment-based configuration

## Credentials

**NEVER** commit real credentials. Use:
1. Environment variables
2. Secrets managers (AWS Secrets, HashiCorp Vault)
3. `.env` files (gitignored)

---
© 2026 CyberDudeBivash Pvt. Ltd.
