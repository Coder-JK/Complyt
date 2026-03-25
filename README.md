# Complyt

Open-source compliance automation toolkit. Generate audit-ready evidence packs with 8 built-in vulnerability scanning layers and maintain continuous control monitoring — no external tools required.

## What it does

- **Tracks controls as data** with 25 starter controls across 8 categories in a local SQLite database with a web UI
- **Runs 8 vulnerability scanning layers** — all built-in after `pnpm install`:
  - **SCA** (dependency vulnerabilities via OSV.dev + CISA KEV + EPSS)
  - **SAST** (14 code bug patterns)
  - **Secret detection** (30 credential patterns with entropy analysis)
  - **License compliance** (36+ SPDX identifiers classified by risk)
  - **Dockerfile security** (18 lint rules)
  - **Container image scanning** (EOL detection + OS package vulnerabilities)
  - **Cloud security** (25 AWS CSPM checks across S3, IAM, CloudTrail, EC2, RDS, KMS)
  - **HTTP security audit** (15 DAST checks — headers, TLS, cookies, CORS, sensitive paths)
- **Optional enhanced scanners** (Semgrep, Gitleaks, Trivy, Nuclei) for deeper analysis via `pnpm setup:tools`
- **Exports auditor-ready evidence packs** as ZIP archives with SHA-256 integrity hashes

## Quickstart

```bash
# Prerequisites: Node.js >= 20, pnpm >= 9
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000). Create a workspace, run an evidence pack, and export.

## Commands

| Command | Description |
|---|---|
| `pnpm dev` | Start development server |
| `pnpm build` | Production build |
| `pnpm lint` | Run ESLint |
| `pnpm typecheck` | Run TypeScript type checking |
| `pnpm test` | Run unit tests (Vitest) |
| `pnpm test:e2e` | Run end-to-end tests (Playwright) |
| `pnpm db:push` | Push database schema changes |
| `pnpm db:studio` | Open Drizzle Studio (DB browser) |
| `pnpm setup:tools` | Install optional enhanced scanners |

## Scan Coverage

All 8 layers work out of the box after `pnpm install`. No external tools required.

| Layer | Built-in | Rules | Enhanced Tool | Output File |
|---|---|---|---|---|
| SCA (dependencies) | Yes | OSV.dev + KEV + EPSS | Syft | `sbom.json`, `osv.json`, `osv_enriched.json` |
| SAST (code bugs) | Yes | 14 patterns | Semgrep | `sast.json` |
| Secret detection | Yes | 30 patterns | Gitleaks | `secrets.json` |
| License compliance | Yes | 36+ SPDX IDs | — | `license-audit.json` |
| Dockerfile security | Yes | 18 rules | Hadolint | `dockerfile-lint.json` |
| Container images | Yes | EOL + OSV | Trivy | `container-scan.json` |
| Cloud security (AWS) | Yes | 25 checks | — | `cspm-aws.json` |
| HTTP security (DAST) | Yes | 15 checks | Nuclei | `dast.json` |

## Evidence Pack Contents

An exported audit pack ZIP can contain up to 13 files:

| File | Description |
|---|---|
| `sbom.json` | CycloneDX 1.5 Software Bill of Materials |
| `osv.json` | OSV vulnerability scan results |
| `osv_enriched.json` | Vulnerabilities enriched with CISA KEV + EPSS data |
| `sast.json` | Static analysis findings (code bugs) |
| `secrets.json` | Detected credential/secret leaks (redacted) |
| `license-audit.json` | License compliance audit with risk classifications |
| `dockerfile-lint.json` | Dockerfile security lint results |
| `container-scan.json` | Container image vulnerability scan |
| `cspm-aws.json` | AWS cloud security posture assessment |
| `dast.json` | HTTP security audit results |
| `control-matrix.csv` | Control status matrix |
| `evidence-manifest.json` | Artifact metadata with SHA-256 hashes and timestamps |
| `README.md` | Human-readable explanation of each artifact |

## Architecture

- **Monorepo**: pnpm workspaces + Turborepo
- **Web app**: Next.js 15 (App Router, React 19)
- **Database**: SQLite via Drizzle ORM
- **UI**: Tailwind CSS + shadcn/ui
- **Validation**: Zod
- **Testing**: Vitest (unit) + Playwright (e2e)

See [docs/architecture.md](docs/architecture.md) for details.

## External Data Sources

All network calls are optional and resilient (timeouts, retries, caching, offline mode).

| Source | URL | License |
|---|---|---|
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CC0 |
| OSV.dev API | https://api.osv.dev/v1/query | Apache-2.0 |
| FIRST EPSS API | https://api.first.org/data/v1/epss | Free |

## Documentation

See the [docs/](docs/) directory:

- **[User Guide](docs/user-guide.md)** — what Complyt does, who it's for, and a walkthrough
- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Security](docs/security.md)
- [Evidence Packs](docs/evidence-packs/vuln-pack.md)
- [Scanner Reference](docs/scanner-reference.md)
- [CSPM Setup](docs/cspm-setup.md)
- [DAST Setup](docs/dast-setup.md)
- [Contributing](docs/contributing.md)
- [Releasing](docs/releasing.md)

## License

[Apache-2.0](LICENSE)
