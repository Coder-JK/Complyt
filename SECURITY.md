# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in Complyt, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email jeetakansagara123@gmail.com with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix within 5 business days.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (current) | Yes |

## Security practices

- No secrets are committed to the repository
- All GitHub Actions are pinned to exact commit SHAs
- Dependencies are monitored via OSV scanning
- SQLite database files are local-only and gitignored
- All external API calls use HTTPS with timeout and retry policies
- No user-supplied input is passed to shell commands without validation
