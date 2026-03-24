# Complyt Documentation

This directory contains the full documentation for Complyt.

## Contents

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Setup, commands, and troubleshooting |
| [Architecture](architecture.md) | System design, data flows, and tech choices |
| [Security](security.md) | Threat model, data handling, supply-chain hardening |
| [Vulnerability Evidence Pack](evidence-packs/vuln-pack.md) | SBOM + OSV + KEV + EPSS pipeline |
| [Contributing](contributing.md) | Development setup and PR guidelines |
| [Releasing](releasing.md) | Release process and SBOM generation |
| [OpenAPI Specification](openapi.yaml) | Machine-readable API documentation |

## Machine-Readable Schemas

Located in `/schemas/`:

| Schema | Description |
|---|---|
| `evidence-artifact.schema.json` | Evidence artifact metadata |
| `evidence-run.schema.json` | Evidence collection run record |
| `exports-manifest.schema.json` | Export archive manifest |
