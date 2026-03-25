# Evidence Pack Reference

## Overview

The evidence pack is Complyt's core output. It produces up to 13 audit-ready artifacts covering 8 vulnerability scanning layers, a control matrix, integrity manifest, and human-readable README.

## Pipeline Steps

### 1. SBOM Generation

**What**: Generates a CycloneDX 1.5 Software Bill of Materials listing all software components and their versions.

**How**: Parses `package.json` and lockfile (pnpm-lock.yaml, package-lock.json, or yarn.lock) to extract dependency names and resolved versions. If `SYFT_PATH` environment variable points to a valid Syft binary, Syft is used instead for richer analysis.

**Output**: `sbom.json` (CycloneDX 1.5 JSON format)

### 2. SCA — Vulnerability Scanning + Enrichment

**What**: Queries the OSV.dev vulnerability database for known vulnerabilities, then enriches with CISA KEV and EPSS data.

**How**: For each SBOM component, sends a `POST` to `https://api.osv.dev/v1/query` with the package name, ecosystem (npm), and version. CVE IDs are cross-referenced against the CISA KEV catalog (cached 24h) and batch-queried against FIRST EPSS API.

**Output**:
- `osv.json` — Raw vulnerability scan results with IDs, summaries, severity scores, and aliases
- `osv_enriched.json` — Vulnerabilities enriched with KEV match flags (dateAdded, dueDate, requiredAction, knownRansomwareCampaignUse) and EPSS scores (probability 0-1, percentile, date)

### 3. Secret Detection

**What**: Scans all text files in the project for hardcoded credentials and secrets.

**How**: Walks the directory tree (skipping `node_modules`, `.git`, `.next`, `dist`, `build`, binary files, files >1MB). Matches each line against 30 regex patterns covering AWS keys, GitHub tokens, Stripe keys, database URLs, private keys, and more. Generic patterns (password, API key assignments) use Shannon entropy validation to reduce false positives.

**Output**: `secrets.json` — All detected values are **redacted** (first 4 + last 4 characters shown). Includes file path, line number, rule ID, and severity.

### 4. SAST — Static Analysis

**What**: Scans JavaScript/TypeScript source files for security-relevant code patterns.

**How**: Walks `.js`, `.ts`, `.jsx`, `.tsx` files (skipping test files, `.d.ts`, standard skip directories). Matches each line against 14 regex rules covering code injection (eval), command injection, SQL injection, XSS, path traversal, weak crypto, timing attacks, and trojan source attacks.

**Output**: `sast.json` — Findings with rule ID, file, line number, matched code snippet (truncated to 100 chars), severity, and description.

### 5. License Compliance

**What**: Audits the license of every dependency for compliance risk.

**How**: Reads the `license` field from each dependency's `package.json` in `node_modules/`. Resolves SPDX expressions (OR picks least restrictive, AND picks most restrictive). Classifies each license into risk tiers: permissive (allow), weak copyleft (warn), strong copyleft (block), network copyleft (block), proprietary (review), unknown (review).

**Output**: `license-audit.json` — Per-package license, risk classification, recommended action, and explanation.

### 6. Dockerfile Security

**What**: Lints Dockerfiles for security issues and best practice violations.

**How**: Finds Dockerfiles in the project root and `docker/`, `.docker/`, `deploy/` directories. Parses each Dockerfile and checks against 18 rules covering: running as root, using sudo, unversioned base images, `:latest` tag, unpinned apt packages, missing HEALTHCHECK, deprecated MAINTAINER, secrets in ENV/ARG, missing .dockerignore, and more.

**Output**: `dockerfile-lint.json` — Findings with rule ID, severity, file, line number, and detail.

### 7. Container Image Scanning

**What**: Checks container base images for end-of-life status and OS-level vulnerabilities.

**How**: Extracts `FROM` directives from Dockerfiles. Checks each image:tag against a database of 15 known EOL images. If Docker is available, runs the container to enumerate OS packages (dpkg/apk), then queries each package against OSV.dev. If Trivy is installed, uses Trivy instead for comprehensive scanning.

**Output**: `container-scan.json` — Per-image results with EOL status, OS package count, and vulnerabilities.

### 8. Cloud Security (AWS CSPM)

**What**: Assesses the security posture of an AWS account.

**How**: Uses the AWS SDK v3 with user-provided credentials (encrypted at rest with AES-256-GCM). Runs 25 read-only checks across S3, IAM, CloudTrail, EC2, RDS, KMS, and CloudWatch Logs. Each check returns pass/fail/error with affected resource details.

**Requires**: AWS credentials configured in Settings. Produces a `not_configured` status artifact if credentials are missing.

**Output**: `cspm-aws.json` — Check results with pass/fail status, affected resource ARNs, and summary statistics.

### 9. HTTP Security Audit (DAST)

**What**: Tests a web application's HTTP security posture.

**How**: Makes passive HTTP requests to the target URL. Checks 6 security headers (HSTS, CSP, X-Frame-Options, etc.), 2 information disclosure headers, TLS protocol + certificate expiry, 3 cookie security attributes, CORS configuration, and 8 sensitive path exposures.

**Requires**: Target URL configured in Settings. Produces a `not_configured` status artifact if URL is missing.

**Output**: `dast.json` — Check results with pass/fail status, TLS info, and details for each check.

## Audit Pack Contents

When exported as a ZIP, the audit pack contains up to 13 files:

| File | Format | Description |
|---|---|---|
| `sbom.json` | CycloneDX 1.5 JSON | Software Bill of Materials |
| `osv.json` | JSON | Raw vulnerability scan results |
| `osv_enriched.json` | JSON | Vulnerabilities + KEV + EPSS |
| `sast.json` | JSON | Static analysis findings |
| `secrets.json` | JSON | Secret detection results (redacted) |
| `license-audit.json` | JSON | License compliance audit |
| `dockerfile-lint.json` | JSON | Dockerfile security lint |
| `container-scan.json` | JSON | Container image scan |
| `cspm-aws.json` | JSON | AWS cloud security posture |
| `dast.json` | JSON | HTTP security audit |
| `control-matrix.csv` | CSV | Control status matrix |
| `evidence-manifest.json` | JSON | Artifact metadata with SHA-256 hashes |
| `README.md` | Markdown | Human-readable explanation |

## Data Sources

| Source | URL | License | Update Frequency |
|---|---|---|---|
| OSV.dev | https://api.osv.dev/v1/query | Apache-2.0 | Continuous |
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CC0 | Weekdays (US Eastern) |
| FIRST EPSS | https://api.first.org/data/v1/epss | Free | Daily |

## Offline Mode

If network access is unavailable:
- SBOM generation works fully offline (local file parsing)
- Secret detection works fully offline
- SAST works fully offline
- License compliance works fully offline
- Dockerfile lint works fully offline
- Container scanning: EOL checks work offline; OS vuln scans require Docker + network
- CSPM: requires network access to AWS APIs
- DAST: requires network access to target URL
- KEV data uses the last cached copy (if available)
- OSV and EPSS queries are skipped
- The run is marked with `offline: true` in metadata
