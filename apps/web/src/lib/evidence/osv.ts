import { resilientFetch, OfflineError } from "./http";

const OSV_API = "https://api.osv.dev/v1/query";
const CONCURRENCY_LIMIT = 5;

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem: string; name: string };
    ranges?: Array<{ type: string; events: Array<Record<string, string>> }>;
  }>;
  references?: Array<{ type: string; url: string }>;
}

interface OsvQueryResult {
  vulns?: OsvVulnerability[];
}

export interface OsvPackageResult {
  package: { name: string; version: string; ecosystem: string; purl: string };
  vulnerabilities: OsvVulnerability[];
}

export interface OsvScanResult {
  scan_timestamp: string;
  scanner: string;
  results: OsvPackageResult[];
  summary: {
    total_packages: number;
    vulnerable_packages: number;
    total_vulnerabilities: number;
  };
}

interface SbomComponent {
  name: string;
  version: string;
  purl: string;
}

export async function scanWithOsv(
  components: SbomComponent[]
): Promise<OsvScanResult> {
  const results: OsvPackageResult[] = [];
  const batches = chunk(components, CONCURRENCY_LIMIT);

  for (const batch of batches) {
    const batchResults = await Promise.allSettled(
      batch.map((comp) => queryOsv(comp))
    );

    for (let i = 0; i < batchResults.length; i++) {
      const result = batchResults[i];
      const comp = batch[i];
      if (result.status === "fulfilled" && result.value.vulns?.length) {
        results.push({
          package: {
            name: comp.name,
            version: comp.version,
            ecosystem: ecosystemFromPurl(comp.purl),
            purl: comp.purl,
          },
          vulnerabilities: result.value.vulns,
        });
      }
    }
  }

  const totalVulns = results.reduce(
    (sum, r) => sum + r.vulnerabilities.length,
    0
  );

  return {
    scan_timestamp: new Date().toISOString(),
    scanner: "complyt-osv",
    results,
    summary: {
      total_packages: components.length,
      vulnerable_packages: results.length,
      total_vulnerabilities: totalVulns,
    },
  };
}

function ecosystemFromPurl(purl: string): string {
  const match = purl.match(/^pkg:([^/]+)\//);
  if (!match) return "npm";
  const ecosystemMap: Record<string, string> = {
    npm: "npm", pypi: "PyPI", golang: "Go", maven: "Maven",
    nuget: "NuGet", gem: "RubyGems", cargo: "crates.io",
  };
  return ecosystemMap[match[1]] ?? match[1];
}

async function queryOsv(component: SbomComponent): Promise<OsvQueryResult> {
  try {
    const response = await resilientFetch(OSV_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: {
          name: component.name,
          ecosystem: ecosystemFromPurl(component.purl),
        },
        version: component.version,
      }),
      maxRetries: 1,
      timeoutMs: 8000,
    });

    return await response.json();
  } catch (error) {
    if (error instanceof OfflineError) {
      throw error;
    }
    return { vulns: [] };
  }
}

function chunk<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
