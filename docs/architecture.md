# Architecture

## Overview

Complyt is a compliance automation toolkit built as a monorepo with a single Next.js application. It runs entirely locally with no external infrastructure requirements.

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

## Data Model

Five core tables in SQLite:

- **workspaces**: Scoping boundary for controls, runs, and exports
- **controls**: Compliance controls with status tracking (not_started, in_progress, met, not_met)
- **evidence_runs**: Records of evidence collection pipeline executions
- **evidence_artifacts**: Individual output files produced by runs (SBOM, OSV scan, enriched report)
- **exports**: Generated audit pack ZIP archives

All IDs are UUIDs. Timestamps are ISO 8601 strings.

## Evidence Pipeline

The pipeline runs in-process within the Next.js API route:

1. **SBOM Generation**: Parses `package.json` and lockfile into CycloneDX 1.5 JSON. Optionally uses Syft CLI if `SYFT_PATH` is configured.
2. **OSV Scanning**: Extracts components from SBOM and queries `POST https://api.osv.dev/v1/query` per package (concurrency limit: 5).
3. **KEV Enrichment**: Downloads CISA KEV JSON catalog (cached 24h) and matches CVE IDs from OSV results.
4. **EPSS Enrichment**: Batch-queries `https://api.first.org/data/v1/epss` for exploitation probability scores.
5. **Enrichment**: Combines OSV results with KEV match flags and EPSS scores into `osv_enriched.json`.

All network calls use a resilient HTTP client with 10s timeouts, 3x exponential backoff retries, and disk caching for offline mode.

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
  exports/
    audit-pack-*.zip      # Generated audit pack archives
```

All data files are gitignored. The database and all artifacts live in the local filesystem.

## API Routes

| Method | Path | Description |
|---|---|---|
| GET | `/api/workspaces` | List all workspaces |
| POST | `/api/workspaces` | Create workspace (seeds 12 starter controls) |
| GET | `/api/workspaces/[id]` | Get workspace details |
| PATCH | `/api/workspaces/[id]` | Update workspace |
| GET | `/api/controls?workspaceId=` | List controls for workspace |
| PATCH | `/api/controls` | Update control status |
| POST | `/api/evidence/run` | Start evidence pipeline run |
| GET | `/api/evidence/runs?workspaceId=` | List evidence runs |
| GET | `/api/evidence/runs/[id]` | Get run details with artifacts |
| GET | `/api/exports?workspaceId=` | List exports |
| POST | `/api/exports` | Generate audit pack ZIP |
| GET | `/api/exports/[id]/download` | Download export ZIP |

## Assumptions

1. SBOM generation from `package.json`/lockfile is sufficient for MVP; Syft is optional.
2. OSV API is queried over HTTPS; no offline vulnerability database is bundled.
3. KEV data is CC0 licensed and freely redistributable.
4. EPSS API is free and unauthenticated.
5. No authentication in v0 (local-first single-user).
6. The starter control matrix includes 12 generic controls (no copyrighted standard text).
