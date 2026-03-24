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
2. Go to **Controls** to see the 12 starter controls
3. Go to **Evidence Runs** and click **Run Evidence Pack**
4. Once the run completes, go to **Exports** and click **Generate Audit Pack**
5. Download the ZIP and inspect the contents

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

## Troubleshooting

### `better-sqlite3` build fails

Ensure you have the build tools for native Node.js modules:

- **Windows**: `npm install -g windows-build-tools`
- **macOS**: `xcode-select --install`
- **Linux**: `sudo apt-get install build-essential python3`

### Port 3000 already in use

Next.js will automatically try the next available port. Check the terminal output for the actual URL.

### Evidence run shows "offline" mode

The evidence pipeline requires internet access to query OSV.dev, CISA KEV, and EPSS APIs. If you're offline, the pipeline will use cached data if available and mark the run as offline.

### Database issues

Delete `apps/web/data/complyt.db` and restart the dev server. The database is automatically recreated.
