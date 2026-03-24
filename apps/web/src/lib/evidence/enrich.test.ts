import { describe, it, expect } from "vitest";
import { enrichOsvResults } from "./enrich";
import type { OsvScanResult } from "./osv";
import type { KevEntry } from "./kev";
import type { EpssEntry } from "./epss";

function makeOsvScan(overrides?: Partial<OsvScanResult>): OsvScanResult {
  return {
    scan_timestamp: "2026-03-24T00:00:00Z",
    scanner: "complyt-osv",
    results: [
      {
        package: {
          name: "lodash",
          version: "4.17.20",
          ecosystem: "npm",
          purl: "pkg:npm/lodash@4.17.20",
        },
        vulnerabilities: [
          {
            id: "GHSA-test-1234",
            summary: "Prototype pollution in lodash",
            aliases: ["CVE-2021-23337"],
            severity: [{ type: "CVSS_V3", score: "7.2" }],
          },
          {
            id: "GHSA-test-5678",
            summary: "ReDoS in lodash",
            aliases: ["CVE-2020-28500"],
          },
        ],
      },
    ],
    summary: {
      total_packages: 10,
      vulnerable_packages: 1,
      total_vulnerabilities: 2,
    },
    ...overrides,
  };
}

describe("enrichOsvResults", () => {
  it("matches KEV entries by CVE alias", () => {
    const kevMap = new Map<string, KevEntry>([
      [
        "CVE-2021-23337",
        {
          cveID: "CVE-2021-23337",
          vendorProject: "Lodash",
          product: "Lodash",
          vulnerabilityName: "Prototype Pollution",
          dateAdded: "2023-01-01",
          shortDescription: "Prototype pollution",
          requiredAction: "Apply updates per vendor instructions",
          dueDate: "2023-02-01",
          knownRansomwareCampaignUse: "Unknown",
          notes: "",
        },
      ],
    ]);

    const epssMap = new Map<string, EpssEntry>();
    const result = enrichOsvResults(makeOsvScan(), kevMap, epssMap);

    expect(result.summary.kev_matches).toBe(1);
    const enrichedVuln = result.results[0].vulnerabilities[0];
    expect(enrichedVuln.kev).toBeDefined();
    expect(enrichedVuln.kev?.cve).toBe("CVE-2021-23337");
    expect(enrichedVuln.kev?.dueDate).toBe("2023-02-01");
  });

  it("attaches EPSS scores by CVE alias", () => {
    const kevMap = new Map<string, KevEntry>();
    const epssMap = new Map<string, EpssEntry>([
      [
        "CVE-2020-28500",
        {
          cve: "CVE-2020-28500",
          epss: 0.042,
          percentile: 0.85,
          date: "2026-03-24",
        },
      ],
    ]);

    const result = enrichOsvResults(makeOsvScan(), kevMap, epssMap);

    expect(result.summary.epss_scored).toBe(1);
    expect(result.summary.max_epss_score).toBe(0.042);
    const enrichedVuln = result.results[0].vulnerabilities[1];
    expect(enrichedVuln.epss).toBeDefined();
    expect(enrichedVuln.epss?.score).toBe(0.042);
    expect(enrichedVuln.epss?.percentile).toBe(0.85);
  });

  it("handles scan with no vulnerabilities", () => {
    const emptyOsv: OsvScanResult = {
      scan_timestamp: "2026-03-24T00:00:00Z",
      scanner: "complyt-osv",
      results: [],
      summary: {
        total_packages: 5,
        vulnerable_packages: 0,
        total_vulnerabilities: 0,
      },
    };

    const result = enrichOsvResults(emptyOsv, new Map(), new Map());

    expect(result.summary.kev_matches).toBe(0);
    expect(result.summary.epss_scored).toBe(0);
    expect(result.results).toHaveLength(0);
  });

  it("handles vulnerabilities with no CVE aliases", () => {
    const osvScan: OsvScanResult = {
      scan_timestamp: "2026-03-24T00:00:00Z",
      scanner: "complyt-osv",
      results: [
        {
          package: {
            name: "test-pkg",
            version: "1.0.0",
            ecosystem: "npm",
            purl: "pkg:npm/test-pkg@1.0.0",
          },
          vulnerabilities: [
            {
              id: "GHSA-xxxx-yyyy",
              summary: "Some vuln",
              aliases: [],
            },
          ],
        },
      ],
      summary: {
        total_packages: 1,
        vulnerable_packages: 1,
        total_vulnerabilities: 1,
      },
    };

    const kevMap = new Map<string, KevEntry>([
      [
        "CVE-9999-9999",
        {
          cveID: "CVE-9999-9999",
          vendorProject: "Other",
          product: "Other",
          vulnerabilityName: "Other",
          dateAdded: "2023-01-01",
          shortDescription: "Other",
          requiredAction: "Update",
          dueDate: "2023-02-01",
          knownRansomwareCampaignUse: "Unknown",
          notes: "",
        },
      ],
    ]);

    const result = enrichOsvResults(osvScan, kevMap, new Map());
    expect(result.summary.kev_matches).toBe(0);
  });
});
