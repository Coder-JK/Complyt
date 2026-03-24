# Contributing to Complyt

Thank you for considering contributing to Complyt.

## Development setup

1. **Prerequisites**: Node.js >= 20, pnpm >= 9
2. Clone the repo and install dependencies:
   ```bash
   git clone https://github.com/Coder-JK/Complyt.git
   cd complyt
   pnpm install
   ```
3. Copy environment config:
   ```bash
   cp .env.example .env
   ```
4. Start the development server:
   ```bash
   pnpm dev
   ```

## Before submitting a PR

Run the full check suite:

```bash
pnpm lint
pnpm typecheck
pnpm test
```

## Code style

- TypeScript strict mode everywhere
- Use Zod for all runtime data validation
- Prefer named exports over default exports
- Keep imports at the top of files (no inline imports)
- Use exhaustive switch handling for unions and enums

## Commit messages

Use conventional commits:

```
feat: add EPSS enrichment module
fix: handle empty SBOM gracefully
docs: update architecture diagram
test: add KEV matcher unit tests
```

## Pull request process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Ensure all checks pass (`pnpm lint && pnpm typecheck && pnpm test`)
4. Open a PR with a clear description of what and why
5. Address review feedback

## Security vulnerabilities

If you discover a security vulnerability, do NOT open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
