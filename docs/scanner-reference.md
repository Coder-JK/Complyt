# Scanner Reference

Complete reference for all 8 built-in vulnerability scanning layers.

## Overview

| # | Layer | Built-in Rules | Output File | Enhanced Tool |
|---|---|---|---|---|
| 1 | SCA (dependencies) | OSV.dev + KEV + EPSS | `sbom.json`, `osv.json`, `osv_enriched.json` | Syft |
| 2 | SAST (code bugs) | 14 patterns | `sast.json` | Semgrep |
| 3 | Secret detection | 30 patterns | `secrets.json` | Gitleaks |
| 4 | License compliance | 36+ SPDX IDs | `license-audit.json` | — |
| 5 | Dockerfile security | 18 rules | `dockerfile-lint.json` | Hadolint |
| 6 | Container images | EOL + OSV | `container-scan.json` | Trivy |
| 7 | Cloud security (AWS) | 25 checks | `cspm-aws.json` | — |
| 8 | HTTP security (DAST) | 15 checks | `dast.json` | Nuclei |

---

## 1. SCA — Software Composition Analysis

**Scanner**: `complyt-sbom` + OSV.dev + CISA KEV + FIRST EPSS

**What it checks**: Parses `package.json` and lockfile into a CycloneDX 1.5 SBOM, queries each component against the OSV.dev vulnerability database, then enriches results with CISA KEV (known exploited) and EPSS (exploitation probability) scores.

**Output files**:
- `sbom.json` — CycloneDX 1.5 Software Bill of Materials
- `osv.json` — Raw vulnerability scan results
- `osv_enriched.json` — Vulnerabilities with KEV flags and EPSS scores

**Enhanced tool**: Syft (set `SYFT_PATH` for richer SBOM analysis)

---

## 2. SAST — Static Application Security Testing

**Scanner**: `complyt-sast`

**What it checks**: Scans `.js`, `.ts`, `.jsx`, `.tsx` files for security-relevant code patterns. Skips `node_modules`, `.git`, `.next`, `dist`, `build`, `.d.ts`, test files.

**Output file**: `sast.json`

**Enhanced tool**: Semgrep (install via `pnpm setup:tools`)

### All 14 Rules

| Rule ID | Severity | Title | Description |
|---|---|---|---|
| SAST-001 | critical | eval() with expression | eval() called with non-literal argument enables code injection |
| SAST-002 | critical | child_process.exec with variable | Command execution with string interpolation enables command injection |
| SAST-003 | high | Non-literal filesystem path | Filesystem operation with variable path enables path traversal |
| SAST-004 | high | Dynamic require() | Dynamic require() with variable enables arbitrary module loading |
| SAST-005 | high | SQL injection via template literal | SQL query built with template literal interpolation enables SQL injection |
| SAST-006 | high | XSS via innerHTML/dangerouslySetInnerHTML | Setting innerHTML with dynamic content enables XSS |
| SAST-007 | medium | Dynamic RegExp construction | RegExp with variable pattern enables ReDoS attacks |
| SAST-008 | medium | Deprecated Buffer constructor | new Buffer() is deprecated and unsafe |
| SAST-009 | medium | Weak hash algorithm | MD5 and SHA1 are cryptographically broken |
| SAST-010 | medium | Weak random number generator | pseudoRandomBytes() and Math.random() are not cryptographically secure |
| SAST-011 | medium | Timing attack in comparison | Direct string comparison on secrets is vulnerable to timing attacks |
| SAST-012 | low | Logging sensitive data | Sensitive values may be logged to console |
| SAST-013 | high | Open redirect | Redirect using user-controlled input enables open redirect attacks |
| SAST-014 | info | Unicode bidi control character | Bidirectional control characters can be used in trojan source attacks |

---

## 3. Secret Detection

**Scanner**: `complyt-secrets`

**What it checks**: Scans all text files (skips binary, >1MB, `node_modules`, `.git`) for hardcoded credentials using regex pattern matching with Shannon entropy validation for generic patterns.

**Output file**: `secrets.json` (all detected values are redacted)

**Enhanced tool**: Gitleaks (install via `pnpm setup:tools`)

### All 30 Rules

| Rule ID | Severity | Description |
|---|---|---|
| aws-access-key-id | critical | AWS Access Key ID (AKIA/ASIA/ABIA/ACCA prefix) |
| aws-secret-key | critical | AWS Secret Access Key |
| aws-mws-key | critical | Amazon MWS Auth Token |
| github-pat | critical | GitHub Personal Access Token (ghp_ prefix) |
| github-oauth | critical | GitHub OAuth Access Token (gho_ prefix) |
| github-app-token | critical | GitHub App Token (ghu_/ghs_ prefix) |
| stripe-secret | critical | Stripe Secret Key (sk_test_/sk_live_) |
| stripe-restricted | high | Stripe Restricted API Key (rk_test_/rk_live_) |
| openai-api-key | critical | OpenAI API Key |
| google-api-key | high | Google API Key (AIza prefix) |
| slack-bot-token | critical | Slack Bot Token (xoxb- prefix) |
| slack-user-token | critical | Slack User/App Token (xoxp-/xoxe- prefix) |
| slack-webhook | high | Slack Webhook URL |
| private-key | critical | Private Key (RSA/EC/DSA/OPENSSH) |
| npm-access-token | critical | NPM Access Token (npm_ prefix) |
| sendgrid-api-key | critical | SendGrid API Key (SG. prefix) |
| twilio-api-key | high | Twilio API Key (SK prefix) |
| database-url | critical | Database Connection String (mongodb/postgres/mysql/redis/amqp) |
| jwt-token | medium | JSON Web Token (eyJ prefix) |
| azure-client-secret | critical | Azure Client Secret |
| heroku-api-key | high | Heroku API Key |
| mailgun-api-key | high | Mailgun API Key (key- prefix) |
| digitalocean-token | critical | DigitalOcean Personal Access Token (dop_v1_ prefix) |
| cloudflare-api-key | critical | Cloudflare API Key |
| firebase-key | high | Firebase API Key (AIzaSy prefix) |
| supabase-key | high | Supabase Service Key (sbp_ prefix) |
| anthropic-api-key | critical | Anthropic API Key (sk-ant-api03- prefix) |
| vercel-token | high | Vercel Access Token (vercel_ prefix) |
| generic-password | medium | Generic password assignment (entropy-validated) |
| generic-api-key | medium | Generic API key assignment (entropy-validated) |

---

## 4. License Compliance

**Scanner**: `complyt-license`

**What it checks**: Reads the `license` field from each dependency's `package.json` in `node_modules/`, resolves SPDX expressions (OR picks least restrictive, AND picks most restrictive), and classifies each into a risk tier.

**Output file**: `license-audit.json`

### Risk Tiers

| Risk | Action | Examples |
|---|---|---|
| Permissive | allow | MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, Unlicense, CC0-1.0, 0BSD, Zlib |
| Weak copyleft | warn | LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0, CDDL-1.0 |
| Strong copyleft | block | GPL-2.0, GPL-3.0, EUPL-1.2, CC-BY-SA-4.0, OSL-3.0 |
| Network copyleft | block | AGPL-3.0, SSPL-1.0 |
| Proprietary | review | BUSL-1.1, Elastic-2.0, UNLICENSED |
| Unknown | review | Unrecognized SPDX identifiers |

---

## 5. Dockerfile Security

**Scanner**: `complyt-dockerfile`

**What it checks**: Finds Dockerfiles in the project root, `docker/`, `.docker/`, and `deploy/` directories. Parses each Dockerfile and checks against 18 lint rules covering security, best practices, and deprecated instructions.

**Output file**: `dockerfile-lint.json`

### All 18 Rules

| Rule ID | Severity | Title |
|---|---|---|
| DL3000 | error | Use absolute WORKDIR |
| DL3002 | warning | Last USER should not be root |
| DL3004 | error | Do not use sudo |
| DL3005 | warning | Do not use apt-get upgrade |
| DL3006 | warning | Always tag image version |
| DL3007 | warning | Do not use :latest tag |
| DL3008 | warning | Pin versions in apt-get install |
| DL3009 | info | Delete apt lists after install |
| DL3015 | info | Use --no-install-recommends |
| DL3020 | error | Use COPY instead of ADD |
| DL3045 | warning | COPY to relative dest without WORKDIR |
| DL3055 | warning | Missing HEALTHCHECK |
| DL4000 | error | MAINTAINER is deprecated |
| DL4003 | warning | Multiple CMD instructions |
| DL4006 | warning | Set pipefail before pipe in RUN |
| DL-SEC1 | error | Secrets in ENV/ARG |
| DL-SEC2 | error | Invalid EXPOSE port |
| DL-SEC3 | warning | Missing .dockerignore |

---

## 6. Container Image Scanning

**Scanner**: `complyt-container`

**What it checks**: Finds Dockerfiles, extracts `FROM` directives, checks base images against an EOL database (15 known EOL images), and optionally scans OS packages for vulnerabilities via Docker + OSV.dev or Trivy.

**Output file**: `container-scan.json`

**Enhanced tool**: Trivy (install via `pnpm setup:tools`)

### Capabilities by Tooling

| Capability | No tools | Docker available | Trivy available |
|---|---|---|---|
| Dockerfile FROM parsing | Yes | Yes | Yes |
| Base image EOL detection | Yes | Yes | Yes |
| OS package enumeration | No | Yes (dpkg/apk) | Yes |
| OS package vuln scan | No | Yes (via OSV.dev) | Yes (Trivy DB) |

### EOL Images Detected

node:14, node:16, node:18, python:3.6, python:3.7, python:3.8, ubuntu:18.04, ubuntu:20.04, debian:stretch, debian:buster, alpine:3.14, alpine:3.15, alpine:3.16, centos:7, centos:8

---

## 7. Cloud Security (AWS CSPM)

**Scanner**: `cspm-aws`

**Requires**: AWS credentials configured in Settings → Cloud Security.

**What it checks**: Runs 25 read-only checks against your AWS account using the AWS SDK. Covers S3, IAM, CloudTrail, EC2/VPC, RDS, KMS, and CloudWatch Logs.

**Output file**: `cspm-aws.json`

See [CSPM Setup Guide](cspm-setup.md) for configuration instructions.

### All 25 Checks

| Check ID | Severity | Title |
|---|---|---|
| S3-01 | critical | S3 buckets should block public access |
| S3-02 | high | S3 buckets should have server-side encryption enabled |
| S3-03 | medium | S3 buckets should have versioning enabled |
| S3-04 | medium | S3 buckets should have access logging enabled |
| S3-05 | critical | S3 account-level public access block should be enabled |
| IAM-01 | critical | Root account should have MFA enabled |
| IAM-02 | high | All IAM users should have MFA enabled |
| IAM-03 | high | IAM access keys should be rotated within 90 days |
| IAM-04 | medium | IAM user credentials should be used within 90 days |
| IAM-05 | critical | IAM policies should not allow full wildcard access |
| IAM-06 | high | IAM password policy should enforce strong requirements |
| CT-01 | critical | CloudTrail should be enabled |
| CT-02 | critical | All CloudTrail trails should be actively logging |
| CT-03 | high | CloudTrail log file validation should be enabled |
| EC2-01 | critical | Security groups should not allow unrestricted SSH access |
| EC2-02 | critical | Security groups should not allow unrestricted RDP access |
| EC2-03 | high | Default security groups should restrict all inbound traffic |
| EC2-04 | high | EBS volumes should be encrypted |
| EC2-05 | high | EC2 instances should require IMDSv2 |
| RDS-01 | high | RDS instances should have storage encryption enabled |
| RDS-02 | critical | RDS instances should not be publicly accessible |
| RDS-03 | high | RDS instances should have automated backups enabled |
| KMS-01 | medium | KMS customer-managed keys should have rotation enabled |
| KMS-02 | high | KMS keys should not be scheduled for deletion |
| LOG-01 | medium | CloudWatch log groups should have a retention policy |

---

## 8. HTTP Security Audit (DAST)

**Scanner**: `complyt-dast`

**Requires**: DAST target URL configured in Settings → Security Testing.

**What it checks**: Makes passive HTTP requests to the target URL and inspects response headers, TLS configuration, cookies, CORS policy, and sensitive path exposure. All checks are read-only — no attack payloads, safe for production.

**Output file**: `dast.json`

**Enhanced tool**: Nuclei (install via `pnpm setup:tools` for thousands of additional checks)

See [DAST Setup Guide](dast-setup.md) for configuration instructions.

### All 15 Checks

| Check ID | Severity | Title |
|---|---|---|
| HTTP-01 | high | Missing HSTS (Strict-Transport-Security) |
| HTTP-02 | medium | Missing X-Content-Type-Options |
| HTTP-03 | medium | Missing X-Frame-Options |
| HTTP-04 | medium | Missing Content-Security-Policy |
| HTTP-05 | low | Missing Referrer-Policy |
| HTTP-06 | low | Missing Permissions-Policy |
| HTTP-07 | high | Server version disclosure |
| HTTP-08 | medium | X-Powered-By disclosure |
| HTTP-09 | high | Weak TLS protocol (TLSv1, TLSv1.1, SSLv3) |
| HTTP-10 | high | Certificate expiry (<30 days or expired) |
| HTTP-11 | high | Cookie missing Secure flag |
| HTTP-12 | medium | Cookie missing HttpOnly flag |
| HTTP-13 | medium | Cookie missing SameSite attribute |
| HTTP-14 | high | Overly permissive CORS (wildcard or origin reflection) |
| HTTP-15 | high | Sensitive paths exposed (/.env, /.git/config, /.aws/credentials, etc.) |
