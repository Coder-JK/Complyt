# Contributing

See also [CONTRIBUTING.md](../CONTRIBUTING.md) in the repository root for the quick version.

## Development Environment

### Prerequisites

- Node.js >= 20
- pnpm >= 9
- Git

### Setup

```bash
git clone https://github.com/Coder-JK/Complyt.git
cd complyt
pnpm install
cp .env.example .env
pnpm dev
```

### Project Structure

```
apps/web/           Next.js application
  src/
    app/            App Router pages and API routes
    components/     React components (ui/ for shadcn, layout/ for shell)
    lib/
      db/           Database schema, client, validation
      evidence/     SBOM, OSV, KEV, EPSS, enrichment, pipeline
      export/       ZIP generation, manifest, CSV
  e2e/              Playwright tests
schemas/            JSON Schema files
docs/               Documentation
.github/workflows/  CI/CD
```

### Running Checks

```bash
pnpm lint         # ESLint
pnpm typecheck    # TypeScript strict
pnpm test         # Vitest unit tests
pnpm test:e2e     # Playwright e2e tests
```

All four must pass before submitting a PR.

## Code Conventions

- **TypeScript strict mode** everywhere
- **Zod** for all runtime data validation
- **Named exports** preferred over default exports (except Next.js pages)
- **Imports at top of file** -- no inline imports
- **Exhaustive switch handling** for TypeScript unions and enums
- **No inline comments** unless explaining non-obvious intent

## Adding a New Evidence Collector

1. Create a new module in `apps/web/src/lib/evidence/`
2. Implement the collection logic with the resilient HTTP client from `http.ts`
3. Add the artifact type to the schema enum in `apps/web/src/lib/db/schema.ts`
4. Integrate into the pipeline in `pipeline.ts`
5. Add unit tests
6. Update documentation

## Pull Request Guidelines

1. Create a feature branch from `main`
2. Use conventional commit messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`
3. Include tests for new functionality
4. Ensure all checks pass
5. Describe what and why in the PR description
