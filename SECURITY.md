# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Do not open public issues for security vulnerabilities. Report security concerns via email to:

**security@unifiedprojects.co.uk**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

You should receive an acknowledgment within 48 hours. We'll keep you updated on the progress and coordinate disclosure timelines.

## Security Considerations

UTun uses post-quantum cryptography to protect against future quantum computer attacks. However, keep these best practices in mind:

- Keep private keys secure with proper file permissions (0600)
- Rotate keys according to your security policy
- Keep dependencies updated
- Monitor logs for anomalies
- Use network isolation (firewalls, Docker networks) to restrict tunnel port access
