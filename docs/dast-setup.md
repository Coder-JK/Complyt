# DAST Setup

How to configure Dynamic Application Security Testing in Complyt.

## What It Checks

Complyt's built-in DAST scanner runs 15 passive HTTP security checks against your target URL:

**Security Headers** (6 checks):
- HTTP-01: Strict-Transport-Security (HSTS)
- HTTP-02: X-Content-Type-Options
- HTTP-03: X-Frame-Options
- HTTP-04: Content-Security-Policy
- HTTP-05: Referrer-Policy
- HTTP-06: Permissions-Policy

**Information Disclosure** (2 checks):
- HTTP-07: Server version disclosure
- HTTP-08: X-Powered-By header

**TLS/Certificate** (2 checks):
- HTTP-09: Weak TLS protocol (TLSv1, TLSv1.1, SSLv3)
- HTTP-10: Certificate expiry (<30 days or expired)

**Cookie Security** (3 checks):
- HTTP-11: Cookie missing Secure flag
- HTTP-12: Cookie missing HttpOnly flag
- HTTP-13: Cookie missing SameSite attribute

**Application Security** (2 checks):
- HTTP-14: Overly permissive CORS (wildcard `*` or origin reflection)
- HTTP-15: Sensitive paths exposed (`/.env`, `/.git/config`, `/.aws/credentials`, `/wp-admin`, `/server-status`, `/phpinfo.php`, `/actuator`, `/.well-known/security.txt`)

See [Scanner Reference](scanner-reference.md) for the full check table.

## Step-by-Step Configuration

1. **Open Complyt** and go to **Settings**.

2. **Scroll to Security Testing**.

3. **Enter the target URL** — the HTTP(S) endpoint you want to scan (e.g., `https://app.example.com`).

4. **Click Test** to verify the URL is reachable. Complyt makes a single GET request to confirm connectivity.

5. **Click Save**. The URL is stored in the workspace settings.

6. **Run an evidence pack**. The DAST check will now run as part of the pipeline and produce `dast.json`.

## Safety

All checks are **passive and read-only**:

- Only standard HTTP methods are used (GET, HEAD).
- No attack payloads, fuzzing, or injection attempts.
- No authentication is attempted.
- The User-Agent header identifies itself as `ComplytDAST/1.0`.
- Request timeout is 10 seconds per request.
- Safe for production environments.

The scanner does **not**:
- Submit forms
- Attempt login
- Modify any data
- Send more than ~10 requests total (main page + 8 sensitive path checks + CORS check)

## Enhanced Mode

Install Nuclei via `pnpm setup:tools` for thousands of additional checks from the Nuclei template library:

```bash
pnpm setup:tools
```

When Nuclei is available, Complyt runs it alongside the built-in checks and merges the results into the DAST output.

## Troubleshooting

### "Connection failed" error

The target URL is unreachable from your machine. Check that:
- The URL is correct and includes the protocol (`http://` or `https://`)
- The server is running and accessible from your network
- No firewall is blocking the connection

### TLS checks show "Skipped"

TLS/certificate checks only run for `https://` URLs. If you're testing an `http://` endpoint, these checks are skipped and noted in the output.

### Partial results

Some checks may show `error` status if the target server disconnects or times out mid-scan. This is noted in the output but doesn't affect other checks.
