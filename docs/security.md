# Security

## Data Handling

### Local-first architecture

Complyt runs entirely on your local machine. No data is sent to any hosted service by default.

- **Database**: SQLite file stored locally at `apps/web/data/complyt.db`
- **Evidence artifacts**: Stored on local filesystem under `apps/web/data/artifacts/`
- **Exports**: Generated ZIP files stored under `apps/web/data/exports/`
- **Credentials**: Encrypted in the database, never transmitted externally

### External API calls

The evidence pipeline makes outbound HTTPS calls to:

| Service | URL | Data sent | Data received |
|---|---|---|---|
| OSV.dev | `api.osv.dev/v1/query` | Package name, ecosystem, version | Known vulnerabilities for that package |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | None (GET request) | Full KEV catalog |
| FIRST EPSS | `api.first.org/data/v1/epss` | CVE IDs | Exploitation probability scores |
| AWS APIs | Various `*.amazonaws.com` endpoints | Read-only API calls with user-provided credentials | Resource configuration data |
| DAST target | User-configured URL | GET/HEAD requests with `ComplytDAST/1.0` User-Agent | HTTP response headers and status codes |

**Privacy note**: OSV queries send package names and versions. No source code, credentials, or proprietary data is transmitted. AWS API calls use the user's own credentials and only perform read operations.

All external calls can be disabled by setting `OFFLINE_MODE=true` in `.env`.

### No secrets in repository

- `.env` is gitignored; `.env.example` documents available settings
- `*.db` files are gitignored
- `data/` directory is gitignored
- No API keys are required for basic operation

## AWS Credential Storage

AWS credentials for CSPM scanning are stored using defense-in-depth:

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key derivation**: `scrypt` with a salt composed of `hostname:username:pepper`
- **IV**: 12 random bytes per encryption operation
- **Authentication tag**: 16 bytes (GCM provides both confidentiality and integrity)

### Security properties

- The encryption key is **derived from the machine identity** (hostname + OS username). Moving the database to another machine renders the credentials unreadable.
- Credentials are encrypted **before** being written to SQLite. The database never contains plaintext credentials.
- Credentials are **never transmitted** to any external service. They are decrypted in-memory only at scan time and passed directly to the AWS SDK.
- The `pepper` value is hardcoded but provides an additional layer — an attacker needs both the database file and knowledge of the derivation scheme.

### Limitations

- The key derivation is deterministic per machine/user. If an attacker has access to both the database and the same machine with the same user account, they can derive the key.
- This is appropriate for a local-first single-user tool. It protects against casual database file exposure but not against a compromised machine.

## DAST Target URL Safety

The built-in DAST scanner is designed to be safe for production environments:

### What it does

- Sends **GET and HEAD requests only** — no POST, PUT, DELETE, or PATCH
- Checks **response headers** for security best practices (HSTS, CSP, etc.)
- Inspects **TLS configuration** (protocol version, certificate expiry)
- Probes **8 sensitive paths** via HEAD requests (/.env, /.git/config, etc.)
- Checks **CORS policy** with a test Origin header

### What it does NOT do

- No form submission or authentication attempts
- No fuzzing, injection, or attack payload delivery
- No parameter tampering or path traversal attempts
- No active exploitation of any kind
- No more than ~10 total HTTP requests per scan

### User-Agent identification

All requests include `User-Agent: ComplytDAST/1.0` so the target can identify and allowlist the scanner.

## CSPM Read-Only Operations

The AWS CSPM scanner uses exclusively read-only AWS API operations:

| Service | Operations Used |
|---|---|
| S3 | `ListBuckets`, `GetPublicAccessBlock`, `GetBucketEncryption`, `GetBucketVersioning`, `GetBucketLogging` |
| S3 Control | `GetPublicAccessBlock` (account level) |
| IAM | `GetAccountSummary`, `ListUsers`, `ListMFADevices`, `ListAccessKeys`, `ListPolicies`, `GetPolicyVersion`, `GetAccountPasswordPolicy` |
| CloudTrail | `DescribeTrails`, `GetTrailStatus` |
| EC2 | `DescribeSecurityGroups`, `DescribeVolumes`, `DescribeInstances` |
| RDS | `DescribeDBInstances` |
| STS | `GetCallerIdentity` |
| KMS | `ListKeys`, `DescribeKey`, `GetKeyRotationStatus` |
| CloudWatch Logs | `DescribeLogGroups` |

No `Create*`, `Put*`, `Update*`, `Delete*`, or `Modify*` operations are used. The [minimal IAM policy](cspm-setup.md) documents exactly which permissions are required.

Each API call has a 15-second timeout. Checks run with a concurrency limit of 5 to avoid API throttling.

## Threat Model

### In scope

| Threat | Mitigation |
|---|---|
| Dependency supply-chain attack | SBOM generation, OSV scanning, KEV monitoring |
| Hardcoded secrets in code | 30-pattern secret scanner with entropy validation |
| Code security bugs | 14-rule SAST scanner |
| License compliance risk | License audit with SPDX classification |
| Insecure Docker configurations | 18-rule Dockerfile linter |
| Vulnerable container base images | EOL detection + OS package vulnerability scanning |
| Cloud misconfigurations | 25 AWS CSPM checks |
| Web application security gaps | 15 HTTP security checks |
| Stale vulnerability data | Automated pipeline with configurable schedule |
| Evidence tampering | SHA-256 hashes in evidence manifests |
| Secret leakage in repo | `.gitignore` patterns, `.env.example` pattern, no defaults |
| Credential exposure | AES-256-GCM encryption with machine-derived key |

### Out of scope (v0)

- Authentication and authorization (single-user local app)
- Encryption at rest for evidence artifacts (relies on OS-level disk encryption)
- Multi-tenant data isolation
- Network-level security (assumes trusted local network)

## Supply-Chain Hardening

### GitHub Actions

All GitHub Actions in CI workflows are pinned to exact commit SHAs:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

This prevents tag-based supply-chain attacks where a compromised action tag could point to malicious code.

### Dependency monitoring

The `vuln-evidence-pack.yml` workflow runs weekly to:
1. Generate an SBOM of the project
2. Download the latest CISA KEV catalog
3. Upload evidence artifacts for review

### Artifact integrity

Every evidence artifact includes:
- SHA-256 content hash
- ISO 8601 collection timestamp
- Generator metadata (tool name and version)

The `evidence-manifest.json` in each export ZIP provides a complete integrity record.
