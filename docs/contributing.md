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
      db/           Database schema, client, validation, seed-controls
      evidence/     Pipeline, SBOM, OSV, KEV, EPSS, enrichment, crypto
        scanners/   Built-in scanner modules (SAST, secrets, license, etc.)
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
- **Imports at top of file** — no inline imports
- **Exhaustive switch handling** for TypeScript unions and enums
- **No inline comments** unless explaining non-obvious intent

## How to Add a New Scanner

Complyt uses a modular scanner architecture. Each scanner is a standalone module that follows a consistent pattern.

### 1. Create a scanner module

Create a new file in `apps/web/src/lib/evidence/scanners/`:

```typescript
// apps/web/src/lib/evidence/scanners/my-scanner.ts

export interface MyScanResult {
  scan_timestamp: string;
  scanner: "complyt-my-scanner";
  results: MyFinding[];
  summary: {
    total_findings: number;
    by_severity: Record<string, number>;
  };
}

export function runMyScan(targetDir: string): MyScanResult {
  const timestamp = new Date().toISOString();

  // 1. Walk files or call APIs
  // 2. Apply rules/checks
  // 3. Collect findings

  return {
    scan_timestamp: timestamp,
    scanner: "complyt-my-scanner",
    results: findings,
    summary: {
      total_findings: findings.length,
      by_severity: bySeverity,
    },
  };
}
```

Key requirements:
- Export a `run*` function that accepts `targetDir` (string) and returns a typed result
- Include `scan_timestamp` and `scanner` identifier in the output
- Include a `summary` with counts
- Handle errors gracefully (return empty results, don't throw)
- Use `path.resolve()` for directory safety

### 2. Add the artifact type

Add your new type to the `ArtifactType` union in `apps/web/src/lib/evidence/pipeline.ts`:

```typescript
type ArtifactType =
  | "sbom"
  | "osv_scan"
  // ... existing types ...
  | "my_scanner";  // add this
```

### 3. Integrate into the pipeline

Add a new step block in `pipeline.ts`:

```typescript
{
  const t0 = Date.now();
  try {
    const result = runMyScan(scanDir);
    artifactCount += await saveArtifact(
      db, runId, workspaceId,
      "my_scanner", "my-scanner.json",
      result, artifactsDir
    );
    steps.my_scanner = {
      status: "completed",
      duration_ms: Date.now() - t0,
      summary: { total_findings: result.summary.total_findings },
    };
  } catch (err) {
    steps.my_scanner = {
      status: "failed",
      reason: err instanceof Error ? err.message : String(err),
      duration_ms: Date.now() - t0,
    };
  }
}
```

### 4. Register in the scanner registry (optional)

If you want the scanner to appear in the capabilities API:

```typescript
// In registry.ts or a registration file
import { registerScanner } from "./registry";

registerScanner({
  id: "my-scanner",
  name: "My Scanner",
  layer: "sast",  // pick the appropriate layer
  builtin: true,
  check: () => true,
  run: async (ctx) => { /* ... */ },
});
```

### 5. Update the export

Add the new artifact to the ZIP export in `apps/web/src/lib/export/zip.ts` so it's included in audit packs.

### 6. Add tests

Add unit tests in the appropriate test directory. Test both the scanner logic and the pipeline integration.

### 7. Update documentation

- Add the scanner to the table in `docs/scanner-reference.md`
- Update the evidence pack contents table in `docs/evidence-packs/vuln-pack.md`
- Update the pipeline steps in `docs/architecture.md`

## Pull Request Guidelines

1. Create a feature branch from `main`
2. Use conventional commit messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`
3. Include tests for new functionality
4. Ensure all checks pass
5. Describe what and why in the PR description
