# Complyt

Open-source compliance automation toolkit. Generate audit-ready evidence packs and maintain continuous control monitoring using your existing stack.

## What it does

- **Tracks controls as data** in a local SQLite database with a web UI
- **Runs repeatable evidence collectors** that produce SBOM, vulnerability scans, and enriched reports
- **Exports auditor-ready evidence packs** as ZIP archives with full provenance (hashes, timestamps, manifests)
- **Enriches vulnerability data** with CISA KEV (known exploited) and EPSS (exploitation probability) scores

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

## Evidence Pack contents

An exported audit pack ZIP contains:

| File | Description |
|---|---|
| `sbom.json` | CycloneDX Software Bill of Materials |
| `osv.json` | OSV vulnerability scan results |
| `osv_enriched.json` | Vulnerabilities enriched with CISA KEV + EPSS data |
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

## External data sources

All network calls are optional and resilient (timeouts, retries, caching, offline mode).

| Source | URL | License |
|---|---|---|
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CC0 |
| OSV.dev API | https://api.osv.dev/v1/query | Apache-2.0 |
| FIRST EPSS API | https://api.first.org/data/v1/epss | Free |

## Documentation

See the [docs/](docs/) directory:

- **[User Guide](docs/user-guide.md)** -- what Complyt does, who it's for, and a walkthrough with screenshots
- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Security](docs/security.md)
- [Evidence Packs: Vulnerability](docs/evidence-packs/vuln-pack.md)
- [Contributing](docs/contributing.md)
- [Releasing](docs/releasing.md)

## License

[Apache-2.0](LICENSE)
