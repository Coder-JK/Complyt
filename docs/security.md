# Security

## Data Handling

### Local-first architecture

Complyt runs entirely on your local machine. No data is sent to any hosted service by default.

- **Database**: SQLite file stored locally at `apps/web/data/complyt.db`
- **Evidence artifacts**: Stored on local filesystem under `apps/web/data/artifacts/`
- **Exports**: Generated ZIP files stored under `apps/web/data/exports/`

### External API calls

The evidence pipeline makes outbound HTTPS calls to:

| Service | URL | Data sent | Data received |
|---|---|---|---|
| OSV.dev | `api.osv.dev/v1/query` | Package name, ecosystem, version | Known vulnerabilities for that package |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | None (GET request) | Full KEV catalog |
| FIRST EPSS | `api.first.org/data/v1/epss` | CVE IDs | Exploitation probability scores |

**Privacy note**: OSV queries send package names and versions. No source code, credentials, or proprietary data is transmitted.

All external calls can be disabled by setting `OFFLINE_MODE=true` in `.env`.

### No secrets in repository

- `.env` is gitignored; `.env.example` documents available settings
- `*.db` files are gitignored
- `data/` directory is gitignored
- No API keys are required for basic operation

## Threat Model

### In scope

| Threat | Mitigation |
|---|---|
| Dependency supply-chain attack | SBOM generation, OSV scanning, KEV monitoring |
| Stale vulnerability data | Automated pipeline with configurable schedule |
| Evidence tampering | SHA-256 hashes in evidence manifests |
| Secret leakage in repo | `.gitignore` patterns, `.env.example` pattern, no defaults |

### Out of scope (v0)

- Authentication and authorization (single-user local app)
- Encryption at rest (relies on OS-level disk encryption)
- Multi-tenant data isolation
- Network-level security (assumes trusted local network)

## Supply-Chain Hardening

### GitHub Actions

All GitHub Actions in CI workflows are pinned to exact commit SHAs:

```yaml
# Example from .github/workflows/ci.yml
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
