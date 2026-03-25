# Getting Started

## Prerequisites

- **Node.js** >= 20
- **pnpm** >= 9 (`npm install -g pnpm`)

## Installation

```bash
git clone https://github.com/Coder-JK/Complyt.git
cd Complyt
pnpm install
```

## Configuration

Copy the environment template:

```bash
cp .env.example .env
```

Edit `.env` if needed. All settings have sensible defaults for local use.

## Running

```bash
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## First Steps

1. Navigate to **Settings** and create a workspace
2. Go to **Controls** to see the 25 starter controls across 8 categories
3. Go to **Evidence Runs** and click **Run Evidence Pack**
4. Once the run completes, go to **Exports** and click **Generate Audit Pack**
5. Download the ZIP and inspect the contents

All 8 scanning layers work immediately — no additional configuration needed for steps 1-7 of the pipeline (SBOM, SCA, Secrets, SAST, Licenses, Dockerfile, Container).

## Configuring AWS Credentials (CSPM)

To enable cloud security posture checks:

1. Create an IAM user with the [minimal read-only policy](cspm-setup.md)
2. Go to **Settings → Cloud Security**
3. Enter your AWS Access Key ID, Secret Access Key, and Region
4. Click **Test & Save**

Credentials are encrypted with AES-256-GCM and stored locally. See [CSPM Setup](cspm-setup.md) for the full guide.

## Configuring DAST Target URL

To enable HTTP security checks:

1. Go to **Settings → Security Testing**
2. Enter your application's URL (e.g., `https://app.example.com`)
3. Click **Test** to verify connectivity, then **Save**

All checks are passive — safe for production. See [DAST Setup](dast-setup.md) for details.

## Enhanced Scanners (Optional)

Install optional external tools for deeper analysis:

```bash
pnpm setup:tools
```

This installs:

| Tool | Layer | What it adds |
|---|---|---|
| Semgrep | SAST | Thousands of community rules beyond the 14 built-in patterns |
| Gitleaks | Secrets | Git history scanning and additional patterns |
| Trivy | Container | Comprehensive OS package vulnerability database |
| Nuclei | DAST | Thousands of HTTP security check templates |

Enhanced scanners run **in addition to** built-in scanners — they don't replace them.

## Available Commands

| Command | Description |
|---|---|
| `pnpm dev` | Start development server with Turbopack |
| `pnpm build` | Create production build |
| `pnpm lint` | Run ESLint |
| `pnpm typecheck` | TypeScript type checking |
| `pnpm test` | Run unit tests (Vitest) |
| `pnpm test:e2e` | Run end-to-end tests (Playwright) |
| `pnpm db:push` | Push database schema changes |
| `pnpm db:studio` | Open Drizzle Studio (database browser) |
| `pnpm setup:tools` | Install optional enhanced scanners |

## Troubleshooting

### `better-sqlite3` build fails

Ensure you have the build tools for native Node.js modules:

- **Windows**: `npm install -g windows-build-tools`
- **macOS**: `xcode-select --install`
- **Linux**: `sudo apt-get install build-essential python3`

### Port 3000 already in use

Next.js will automatically try the next available port. Check the terminal output for the actual URL.

### Evidence run shows "offline" mode

The SCA pipeline requires internet access to query OSV.dev, CISA KEV, and EPSS APIs. If you're offline, the pipeline will use cached data if available and mark the run as offline. The 6 local scanners (SAST, Secrets, Licenses, Dockerfile, Container EOL, SBOM) still run fully offline.

### CSPM shows "not_configured"

You haven't added AWS credentials yet. Go to Settings → Cloud Security to configure them.

### DAST shows "not_configured"

You haven't set a target URL yet. Go to Settings → Security Testing to configure it.

### Database issues

Delete `apps/web/data/complyt.db` and restart the dev server. The database is automatically recreated.
