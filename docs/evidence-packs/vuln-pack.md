# Vulnerability Management Evidence Pack

## Overview

The vulnerability evidence pack is Complyt's core evidence collection pipeline. It produces audit-ready artifacts that demonstrate your organization's vulnerability management practices.

## Pipeline Steps

### 1. SBOM Generation

**What**: Generates a CycloneDX 1.5 Software Bill of Materials listing all software components and their versions.

**How**: Parses `package.json` and lockfile (pnpm-lock.yaml, package-lock.json, or yarn.lock) to extract dependency names and resolved versions. If `SYFT_PATH` environment variable points to a valid Syft binary, Syft is used instead for richer analysis.

**Output**: `sbom.json` (CycloneDX 1.5 JSON format)

### 2. OSV Vulnerability Scanning

**What**: Queries the OSV.dev vulnerability database for known vulnerabilities in each component from the SBOM.

**How**: For each component, sends a `POST` request to `https://api.osv.dev/v1/query` with the package name, ecosystem (npm), and version. Requests are parallelized with a concurrency limit of 5.

**Output**: `osv.json` containing all vulnerability matches with IDs, summaries, severity scores, and aliases.

### 3. CISA KEV Enrichment

**What**: Cross-references vulnerability CVE IDs against the CISA Known Exploited Vulnerabilities catalog.

**How**: Downloads the KEV JSON feed from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (cached locally for 24 hours). For each vulnerability with a CVE alias, checks for a KEV match.

**KEV match fields added**:
- `cve`: The matching CVE ID
- `dateAdded`: When the vulnerability was added to KEV
- `dueDate`: CISA-mandated remediation deadline
- `requiredAction`: Recommended remediation action
- `knownRansomwareCampaignUse`: Whether the vulnerability is used in ransomware campaigns

**Why KEV matters**: CISA explicitly recommends using the KEV catalog as input to vulnerability remediation prioritization. KEV-listed vulnerabilities represent confirmed exploitation in the wild.

### 4. EPSS Enrichment

**What**: Scores each vulnerability by its exploitation probability using the FIRST Exploit Prediction Scoring System.

**How**: Batch-queries `https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...` in groups of 30 CVEs.

**EPSS fields added**:
- `score`: Probability of exploitation in the next 30 days (0.0 to 1.0)
- `percentile`: Relative ranking among all scored CVEs
- `date`: Date of the EPSS score

### 5. Enriched Output

**Output**: `osv_enriched.json` containing all OSV results with KEV and EPSS fields attached to each vulnerability.

**Summary statistics included**:
- Total packages scanned
- Vulnerable packages found
- Total vulnerabilities
- KEV matches (confirmed exploited)
- EPSS-scored vulnerabilities
- Maximum EPSS score

## Audit Pack Contents

When exported as a ZIP, the audit pack contains:

| File | Format | Description |
|---|---|---|
| `sbom.json` | CycloneDX 1.5 JSON | Software Bill of Materials |
| `osv.json` | JSON | Raw vulnerability scan results |
| `osv_enriched.json` | JSON | Vulnerabilities + KEV + EPSS |
| `control-matrix.csv` | CSV | Control status matrix |
| `evidence-manifest.json` | JSON | Artifact metadata with SHA-256 hashes |
| `README.md` | Markdown | Human-readable explanation |

## Data Sources

| Source | URL | License | Update Frequency |
|---|---|---|---|
| OSV.dev | https://api.osv.dev/v1/query | Apache-2.0 | Continuous |
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CC0 | Weekdays (US Eastern) |
| FIRST EPSS | https://api.first.org/data/v1/epss | Free | Daily |

## Offline Mode

If network access is unavailable:
- SBOM generation works fully offline (local file parsing)
- KEV data uses the last cached copy (if available)
- OSV and EPSS queries are skipped
- The run is marked with `offline: true` in metadata
