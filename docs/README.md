# Complyt Documentation

This directory contains the full documentation for Complyt.

## Contents

| Document | Description |
|---|---|
| [User Guide](user-guide.md) | What Complyt does, who it's for, walkthrough |
| [Getting Started](getting-started.md) | Setup, commands, configuration, and troubleshooting |
| [Architecture](architecture.md) | System design, scanner registry, data flows, and tech choices |
| [Security](security.md) | Threat model, data handling, credential storage, supply-chain hardening |
| [Evidence Pack Reference](evidence-packs/vuln-pack.md) | All 8 scanning layers and 13 artifact types |
| [Scanner Reference](scanner-reference.md) | Complete reference for all 8 scanner layers with rule IDs |
| [CSPM Setup](cspm-setup.md) | AWS cloud security configuration and IAM policy |
| [DAST Setup](dast-setup.md) | HTTP security testing configuration and safety notes |
| [Contributing](contributing.md) | Development setup, PR guidelines, and how to add scanners |
| [Releasing](releasing.md) | Release process and SBOM generation |
| [OpenAPI Specification](openapi.yaml) | Machine-readable API documentation |

## Machine-Readable Schemas

Located in `/schemas/`:

| Schema | Description |
|---|---|
| `evidence-artifact.schema.json` | Evidence artifact metadata |
| `evidence-run.schema.json` | Evidence collection run record |
| `exports-manifest.schema.json` | Export archive manifest |
