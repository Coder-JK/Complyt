# Releasing

## Version Scheme

Complyt follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes to API or data model
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes

## Release Process

### 1. Prepare the release

```bash
# Ensure main is clean
git checkout main
git pull origin main

# Run all checks
pnpm lint
pnpm typecheck
pnpm test
```

### 2. Update version

Update `version` in:
- `package.json` (root)
- `apps/web/package.json`

### 3. Generate SBOM for the release

```bash
# If Syft is installed
syft dir:. -o cyclonedx-json > sbom.json
```

### 4. Create the release

```bash
git add -A
git commit -m "chore: release v0.x.y"
git tag v0.x.y
git push origin main --tags
```

### 5. GitHub Release

Create a GitHub release from the tag with:
- Changelog summary
- Link to SBOM artifact
- Link to documentation

## Release Cadence

- **Monthly**: Tagged releases with changelog
- **Weekly**: Patch releases when needed for security fixes

## SBOM for Releases

Every tagged release should include a CycloneDX SBOM as a release artifact. This demonstrates supply-chain transparency and is generated either:

1. Locally using Syft: `syft dir:. -o cyclonedx-json`
2. In CI via the `vuln-evidence-pack.yml` workflow
