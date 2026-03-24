import type { OsvScanResult } from "./osv";
import type { KevEntry } from "./kev";
import type { EpssEntry } from "./epss";

export interface EnrichedVulnerability {
  id: string;
  summary?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  kev?: {
    cve: string;
    dateAdded: string;
    dueDate: string;
    requiredAction: string;
    knownRansomwareCampaignUse: string;
  };
  epss?: {
    cve: string;
    score: number;
    percentile: number;
    date: string;
  };
}

export interface EnrichedPackageResult {
  package: {
    name: string;
    version: string;
    ecosystem: string;
    purl: string;
  };
  vulnerabilities: EnrichedVulnerability[];
}

export interface EnrichedScanResult {
  scan_timestamp: string;
  enrichment_timestamp: string;
  scanner: string;
  results: EnrichedPackageResult[];
  summary: {
    total_packages: number;
    vulnerable_packages: number;
    total_vulnerabilities: number;
    kev_matches: number;
    epss_scored: number;
    max_epss_score: number;
  };
}

export function enrichOsvResults(
  osvScan: OsvScanResult,
  kevMap: Map<string, KevEntry>,
  epssMap: Map<string, EpssEntry>
): EnrichedScanResult {
  let kevMatches = 0;
  let epssScored = 0;
  let maxEpss = 0;

  const results: EnrichedPackageResult[] = osvScan.results.map((pkgResult) => {
    const enrichedVulns: EnrichedVulnerability[] =
      pkgResult.vulnerabilities.map((vuln) => {
        const enriched: EnrichedVulnerability = {
          id: vuln.id,
          summary: vuln.summary,
          aliases: vuln.aliases,
          severity: vuln.severity,
        };

        const allIds = [vuln.id, ...(vuln.aliases ?? [])];
        const cveIds = allIds.filter((id) => id.startsWith("CVE-"));

        for (const cve of cveIds) {
          const kevEntry = kevMap.get(cve);
          if (kevEntry) {
            enriched.kev = {
              cve,
              dateAdded: kevEntry.dateAdded,
              dueDate: kevEntry.dueDate,
              requiredAction: kevEntry.requiredAction,
              knownRansomwareCampaignUse: kevEntry.knownRansomwareCampaignUse,
            };
            kevMatches++;
            break;
          }
        }

        for (const cve of cveIds) {
          const epssEntry = epssMap.get(cve);
          if (epssEntry) {
            enriched.epss = {
              cve,
              score: epssEntry.epss,
              percentile: epssEntry.percentile,
              date: epssEntry.date,
            };
            epssScored++;
            if (epssEntry.epss > maxEpss) maxEpss = epssEntry.epss;
            break;
          }
        }

        return enriched;
      });

    return {
      package: pkgResult.package,
      vulnerabilities: enrichedVulns,
    };
  });

  return {
    scan_timestamp: osvScan.scan_timestamp,
    enrichment_timestamp: new Date().toISOString(),
    scanner: "complyt-enriched",
    results,
    summary: {
      total_packages: osvScan.summary.total_packages,
      vulnerable_packages: osvScan.summary.vulnerable_packages,
      total_vulnerabilities: osvScan.summary.total_vulnerabilities,
      kev_matches: kevMatches,
      epss_scored: epssScored,
      max_epss_score: maxEpss,
    },
  };
}
