# Complyt User Guide

## What is Complyt?

Complyt is an open-source compliance automation toolkit that answers the question your auditor will definitely ask:

**"Show me your vulnerability management evidence."**

Complyt covers all 8 vulnerability layers auditors expect — built-in, no external tools required.

Instead of scrambling to collect screenshots, PDFs, and spreadsheets before an audit, Complyt generates a complete, auditor-ready **evidence pack** automatically by scanning your software, infrastructure, and cloud environment across 8 security layers and enriching the results with authoritative threat intelligence.

---

## Who is this for?

**Engineering leads and security/compliance owners at startups and SMBs** who are:

- Preparing for **SOC 2 Type I/II** or **ISO 27001** certification
- Blocked on an **enterprise deal** because the buyer wants proof of security posture
- Tired of **manually collecting evidence** via screenshots and spreadsheets
- Running a small team and can't afford $30K+/year for Vanta, Drata, or Secureframe

## What problem does it solve?

Auditors want proof that you:

1. **Know what software you're running** (Software Bill of Materials)
2. **Scan for vulnerabilities regularly** (vulnerability scanning evidence)
3. **Check your code for security bugs** (SAST evidence)
4. **Don't leak secrets** (secret detection evidence)
5. **Manage open-source license risk** (license compliance)
6. **Secure your containers** (Dockerfile + image scanning)
7. **Harden your cloud infrastructure** (cloud security posture)
8. **Test your web application** (DAST evidence)
9. **Prioritize based on real-world risk** (KEV + EPSS enrichment)
10. **Track remediation** (control status tracking)

### What auditors want — and what Complyt delivers

| Auditor Question | Complyt Layer | Built-in | Output |
|---|---|---|---|
| "Do you have an SBOM?" | SCA | Yes | `sbom.json` |
| "Do you scan dependencies for vulnerabilities?" | SCA + KEV + EPSS | Yes | `osv.json`, `osv_enriched.json` |
| "Do you run static analysis on your code?" | SAST | Yes | `sast.json` |
| "Do you scan for hardcoded secrets?" | Secret detection | Yes | `secrets.json` |
| "Do you audit open-source licenses?" | License compliance | Yes | `license-audit.json` |
| "Are your Dockerfiles secure?" | Dockerfile security | Yes | `dockerfile-lint.json` |
| "Do you scan container images?" | Container scanning | Yes | `container-scan.json` |
| "Do you assess your cloud security?" | AWS CSPM | Yes | `cspm-aws.json` |
| "Do you test your web app for vulnerabilities?" | DAST | Yes | `dast.json` |

Complyt produces all of this in a single click, packaged as a ZIP file your auditor can consume directly.

---

## The Walkthrough

### Step 1: Create a Workspace

Go to **Settings** and create a workspace. A workspace scopes everything — controls, scans, and exports — to one project or product.

Enter your project name (e.g., "My SaaS Product"), point it at your project directory, and click **Create Workspace**. Complyt automatically seeds 25 starter compliance controls covering 8 categories: vulnerability management, supply chain security, asset management, data integrity, code security, container security, cloud security, and application security.

---

### Step 2: Configure AWS Credentials (Optional)

If you want cloud security posture checks, go to **Settings → Cloud Security**:

1. Enter your AWS Access Key ID, Secret Access Key, and Region
2. Click **Test & Save** to verify connectivity
3. Complyt encrypts credentials with AES-256-GCM before storing locally

See [CSPM Setup](cspm-setup.md) for the required IAM policy.

---

### Step 3: Configure DAST Target URL (Optional)

If you want HTTP security checks, go to **Settings → Security Testing**:

1. Enter your application's URL (e.g., `https://app.example.com`)
2. Click **Test** to verify the URL is reachable
3. Click **Save**

All DAST checks are passive and safe for production. See [DAST Setup](dast-setup.md) for details.

---

### Step 4: Review Your Controls

Navigate to **Controls** to see the 25 pre-seeded controls organized by category.

Each control has:
- **Control ID** (e.g., VM-01, SCM-02, CS-01) for reference
- **Title and description** explaining what the control requires
- **Frequency** (daily, weekly, monthly, quarterly)
- **Status badge** you can click to cycle through: Not Started, In Progress, Met, Not Met

---

### Step 5: Run an Evidence Pack

Go to **Evidence Runs** and click **Run Evidence Pack**.

Complyt executes a 9-step pipeline:

| Step | What it does | Output | Requires |
|------|-------------|--------|----------|
| 1. SBOM | Parses `package.json` into CycloneDX 1.5 SBOM | `sbom.json` | — |
| 2. SCA | Queries OSV.dev + enriches with KEV + EPSS | `osv.json`, `osv_enriched.json` | Network |
| 3. Secrets | Scans for 30 credential patterns | `secrets.json` | — |
| 4. SAST | Scans for 14 code bug patterns | `sast.json` | — |
| 5. Licenses | Audits dependency licenses against 36+ SPDX IDs | `license-audit.json` | — |
| 6. Dockerfile | Lints Dockerfiles against 18 rules | `dockerfile-lint.json` | — |
| 7. Containers | Checks base images for EOL + OS vulns | `container-scan.json` | — |
| 8. CSPM | Runs 25 AWS security checks | `cspm-aws.json` | AWS creds |
| 9. DAST | Runs 15 HTTP security checks | `dast.json` | Target URL |

Steps 1-7 run automatically with no configuration. Steps 8-9 run when configured.

---

### Step 6: Export an Audit Pack

Go to **Exports** and click **Generate Audit Pack**.

Complyt produces a ZIP file containing up to 13 files:

| File | What it is |
|------|-----------|
| `sbom.json` | CycloneDX 1.5 Software Bill of Materials |
| `osv.json` | Raw vulnerability scan results from OSV.dev |
| `osv_enriched.json` | Vulnerabilities enriched with KEV flags and EPSS scores |
| `sast.json` | Static analysis findings |
| `secrets.json` | Detected credential leaks (redacted) |
| `license-audit.json` | License risk audit |
| `dockerfile-lint.json` | Dockerfile security lint |
| `container-scan.json` | Container image scan |
| `cspm-aws.json` | AWS cloud security posture |
| `dast.json` | HTTP security audit |
| `control-matrix.csv` | Your control status matrix (importable into any spreadsheet) |
| `evidence-manifest.json` | Machine-readable manifest with SHA-256 hashes for every artifact |
| `README.md` | Human-readable explanation of each file and its provenance |

Every artifact includes cryptographic integrity hashes and timestamps. Click **Download** to get the ZIP. Hand it to your auditor.

---

### Step 7: Monitor from the Dashboard

The **Dashboard** gives you a real-time overview of your compliance posture: controls met vs total, evidence runs completed, exports generated, open findings, and control coverage breakdown.

---

## Why should someone use Complyt instead of doing it manually?

| Manual approach | Complyt |
|----------------|---------|
| Screenshot your `npm audit` output every week | Automated SBOM + OSV scan with structured JSON |
| Google each CVE to see if it's critical | Automatic KEV + EPSS enrichment with real-world exploitation data |
| Run separate tools for SAST, secrets, licenses, Docker, cloud | 8 layers in one pipeline, one click |
| Copy-paste into a spreadsheet for your auditor | One-click ZIP export with integrity hashes |
| Spend 2-4 hours per audit cycle collecting evidence | Run completes in seconds |
| Evidence has no provenance trail | Every artifact has SHA-256 hash, timestamp, and generator metadata |
| Costs $0 but wastes your time | Costs $0 and saves your time |

## Why should someone use Complyt instead of Vanta/Drata/Secureframe?

| Paid platforms ($15K-$50K/year) | Complyt (free, open source) |
|--------------------------------|----------------------------|
| Hosted SaaS — your data on their servers | Runs locally — your data never leaves your machine |
| Vendor lock-in on exports and integrations | Open formats (CycloneDX, JSON, CSV) |
| Opaque pricing, demo-gated | Apache-2.0, fork it, extend it |
| Full GRC platform (you're paying for features you don't need yet) | Focused on the 8 layers auditors ask for |
| Requires onboarding call and setup | `pnpm install && pnpm dev` — running in 60 seconds |

Complyt is not a replacement for Vanta — it's what you use **before** you can afford Vanta, or **instead of** Vanta if all you need is vulnerability management evidence.

---

## How it works under the hood

```
Your project                   Complyt                           External APIs
┌─────────────┐      ┌───────────────────────────────┐   ┌──────────────────────┐
│ package.json │─────>│ 1. SBOM (CycloneDX 1.5)      │   │ OSV.dev API          │
│ lockfile     │      │ 2. SCA (OSV + KEV + EPSS)     │<──│ CISA KEV             │
│ source code  │─────>│ 3. Secrets (30 patterns)      │   │ FIRST EPSS API       │
│ Dockerfiles  │─────>│ 4. SAST (14 patterns)         │   │ AWS APIs (read-only) │
│              │      │ 5. Licenses (36+ SPDX IDs)    │   └──────────────────────┘
│              │      │ 6. Dockerfile (18 rules)       │
│              │      │ 7. Containers (EOL + OSV)      │
│              │      │ 8. CSPM (25 AWS checks)        │
│              │      │ 9. DAST (15 HTTP checks) ──────│──> Target URL
│              │      │         │                      │
│              │      │         v                      │
│              │      │  ┌──────────────┐              │
│              │      │  │ Audit Pack   │              │
│              │      │  │ ZIP Export   │              │
│              │      │  └──────────────┘              │
│              │      └───────────────────────────────┘
└─────────────┘               │
                              v
                     ┌────────────────────┐
                     │ audit-pack.zip     │
                     │  13 artifacts      │
                     │  SHA-256 hashes    │
                     │  evidence manifest │
                     └────────────────────┘
```

All network calls are:
- **Optional**: SBOM, SAST, secrets, licenses, Dockerfile, container scans work fully offline
- **Cached**: KEV catalog cached for 24 hours
- **Resilient**: 10s timeouts, 3x retries with exponential backoff
- **Transparent**: offline runs are marked as such in the evidence

---

## Data sources and their authority

| Source | Maintained by | Why it matters |
|--------|--------------|----------------|
| [OSV.dev](https://osv.dev) | Google / OpenSSF | Largest open vulnerability database, aggregates from 20+ sources |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | US CISA | Definitive list of vulnerabilities being actively exploited |
| [FIRST EPSS](https://www.first.org/epss/) | Forum of Incident Response and Security Teams | Statistical model predicting exploitation probability |
| [CycloneDX](https://cyclonedx.org/) | OWASP | International standard for SBOMs, widely accepted by auditors |

---

## Quick Start

```bash
git clone https://github.com/Coder-JK/Complyt.git
cd Complyt
pnpm install
pnpm dev
```

Open http://localhost:3000, create a workspace, run an evidence pack, export it. Done.
