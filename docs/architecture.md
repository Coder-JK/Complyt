# Architecture

## Overview

Complyt is a compliance automation toolkit built as a monorepo with a single Next.js application. It runs entirely locally with no external infrastructure requirements. The evidence pipeline includes 8 built-in vulnerability scanning layers with an extensible scanner registry.

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Framework | Next.js 15 (App Router) | Single deployable with SSR, API routes, and React 19 |
| Language | TypeScript (strict mode) | Type safety across UI and API |
| Database | SQLite via Drizzle ORM | Zero-config local persistence, no server required |
| UI | Tailwind CSS + shadcn/ui | Consistent, accessible component primitives |
| Validation | Zod | Runtime type checking for API inputs |
| Testing | Vitest + Playwright | Fast unit tests + browser-based e2e |
| Monorepo | pnpm workspaces + Turborepo | Fast installs and cached task execution |
| AWS SDK | @aws-sdk/client-* (v3) | CSPM checks against AWS accounts |
| Crypto | Node.js crypto (AES-256-GCM) | Local credential encryption |

## Data Model

Six core tables in SQLite:

- **workspaces**: Scoping boundary for controls, runs, and exports
- **controls**: Compliance controls with status tracking (not_started, in_progress, met, not_met)
- **evidence_runs**: Records of evidence collection pipeline executions
- **evidence_artifacts**: Individual output files produced by runs (SBOM, OSV, SAST, secrets, etc.)
- **exports**: Generated audit pack ZIP archives
- **cloud_credentials**: Encrypted AWS credentials per workspace (AES-256-GCM)

All IDs are UUIDs. Timestamps are ISO 8601 strings.

## Scanner Registry

Scanners are registered via a central registry (`registry.ts`) that defines a common interface:

```
ScannerDef {
  id: string
  name: string
  layer: "sca" | "sast" | "secrets" | "license" | "dockerfile" | "container" | "cspm" | "dast"
  builtin: boolean
  requiresConfig?: "aws_credentials" | "dast_target_url"
  check: () => boolean       // availability check
  run: (ctx) => ScanResult   // execution
}
```

The `/api/evidence/capabilities` endpoint exposes scanner availability to the UI.

## Scanner Modules

All built-in scanners live in `apps/web/src/lib/evidence/scanners/`:

| Module | Layer | Rules | Output |
|---|---|---|---|
| `sast-builtin.ts` | SAST | 14 regex patterns | `sast.json` |
| `secrets-builtin.ts` | Secret detection | 30 regex patterns + entropy | `secrets.json` |
| `license.ts` | License compliance | 36+ SPDX identifiers | `license-audit.json` |
| `dockerfile.ts` | Dockerfile security | 18 lint rules | `dockerfile-lint.json` |
| `container.ts` | Container scanning | EOL DB + OSV queries | `container-scan.json` |
| `cspm-aws.ts` | Cloud security | 25 AWS API checks | `cspm-aws.json` |
| `dast-builtin.ts` | HTTP security | 15 passive checks | `dast.json` |

SCA (SBOM + OSV + KEV + EPSS) uses the modules in the parent `evidence/` directory: `sbom.ts`, `osv.ts`, `kev.ts`, `epss.ts`, `enrich.ts`.

Enhanced scanners (Semgrep, Gitleaks, Trivy) are optional and detected at runtime via `sast.ts` and `secrets.ts`.

## Credential Storage

AWS credentials for CSPM are stored encrypted:

1. User enters credentials in Settings UI
2. API route encrypts with `AES-256-GCM` using a key derived from the machine's hostname + OS username via `scrypt`
3. Encrypted blob is stored in the `cloud_credentials` table
4. At scan time, the pipeline decrypts credentials in-memory and passes them to the AWS SDK
5. Credentials never leave the machine

## Evidence Pipeline

The pipeline (`pipeline.ts`) runs in-process within the Next.js API route. It executes 9 steps sequentially:

1. **SBOM Generation** — Parses `package.json` and lockfile into CycloneDX 1.5 JSON
2. **SCA / OSV Scanning** — Queries OSV.dev per package, enriches with CISA KEV + EPSS
3. **Secret Detection** — Scans all text files for 30 credential patterns
4. **SAST** — Scans JS/TS files for 14 security-relevant code patterns
5. **License Compliance** — Classifies each dependency license against SPDX database
6. **Dockerfile Security** — Lints Dockerfiles against 18 rules
7. **Container Scanning** — Checks base images for EOL status + OS package vulnerabilities
8. **AWS CSPM** — Runs 25 read-only AWS checks (requires configured credentials)
9. **DAST** — Runs 15 passive HTTP security checks (requires configured target URL)

Steps 8-9 gracefully handle missing configuration by producing a `not_configured` status artifact.

Enhanced scanners (Semgrep, Gitleaks) run after the built-in pipeline when detected.

Each step saves its output as a JSON artifact with SHA-256 hash to the local filesystem and records metadata in the database.

All network calls use a resilient HTTP client with 10s timeouts, 3x exponential backoff retries, and disk caching for offline mode.

## DAST Flow

1. User configures target URL in Settings
2. Pipeline calls `runBuiltinDastScan(url)`
3. Scanner makes a single GET request to retrieve headers
4. Checks 6 security headers, 2 disclosure headers, TLS protocol + cert expiry
5. Parses Set-Cookie headers for Secure/HttpOnly/SameSite flags
6. Makes a CORS probe with `Origin: https://evil.example.com`
7. Makes HEAD requests to 8 sensitive paths (/.env, /.git/config, etc.)
8. Total: ~10 HTTP requests, all passive, no attack payloads

## File System Layout

```
apps/web/data/
  complyt.db              # SQLite database
  cache/
    kev.json              # Cached CISA KEV catalog
  artifacts/
    {run-id}/
      sbom.json           # CycloneDX SBOM
      osv.json            # OSV scan results
      osv_enriched.json   # Enriched with KEV + EPSS
      sast.json           # SAST findings
      secrets.json        # Secret detection (redacted)
      license-audit.json  # License compliance
      dockerfile-lint.json # Dockerfile lint
      container-scan.json # Container scan
      cspm-aws.json       # AWS CSPM results
      dast.json           # DAST results
  exports/
    audit-pack-*.zip      # Generated audit pack archives
```

All data files are gitignored. The database and all artifacts live in the local filesystem.

## API Routes

| Method | Path | Description |
|---|---|---|
| GET | `/api/workspaces` | List all workspaces |
| POST | `/api/workspaces` | Create workspace (seeds 25 starter controls) |
| GET | `/api/workspaces/[id]` | Get workspace details |
| PATCH | `/api/workspaces/[id]` | Update workspace |
| GET | `/api/workspaces/[id]/credentials` | Get credential status (not the secret) |
| POST | `/api/workspaces/[id]/credentials` | Store encrypted AWS credentials |
| DELETE | `/api/workspaces/[id]/credentials` | Remove stored credentials |
| GET | `/api/controls?workspaceId=` | List controls for workspace |
| PATCH | `/api/controls` | Update control status |
| POST | `/api/evidence/run` | Start evidence pipeline run |
| GET | `/api/evidence/runs?workspaceId=` | List evidence runs |
| GET | `/api/evidence/runs/[id]` | Get run details with artifacts |
| GET | `/api/evidence/capabilities` | List available scanners and their status |
| GET | `/api/exports?workspaceId=` | List exports |
| POST | `/api/exports` | Generate audit pack ZIP |
| GET | `/api/exports/[id]/download` | Download export ZIP |

## Assumptions

1. SBOM generation from `package.json`/lockfile is sufficient for MVP; Syft is optional.
2. OSV API is queried over HTTPS; no offline vulnerability database is bundled.
3. KEV data is CC0 licensed and freely redistributable.
4. EPSS API is free and unauthenticated.
5. No authentication in v0 (local-first single-user).
6. The starter control matrix includes 25 generic controls (no copyrighted standard text).
7. AWS CSPM uses read-only API calls only — never creates/modifies/deletes resources.
8. DAST checks are passive — no attack payloads, safe for production.
