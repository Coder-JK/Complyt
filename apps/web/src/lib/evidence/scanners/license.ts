import fs from "fs";
import path from "path";

export enum LicenseRisk {
  PERMISSIVE = "permissive",
  WEAK_COPYLEFT = "weak_copyleft",
  STRONG_COPYLEFT = "strong_copyleft",
  NETWORK_COPYLEFT = "network_copyleft",
  PROPRIETARY = "proprietary",
  UNKNOWN = "unknown",
}

const RISK_SEVERITY: Record<LicenseRisk, number> = {
  [LicenseRisk.PERMISSIVE]: 0,
  [LicenseRisk.WEAK_COPYLEFT]: 1,
  [LicenseRisk.STRONG_COPYLEFT]: 2,
  [LicenseRisk.NETWORK_COPYLEFT]: 3,
  [LicenseRisk.PROPRIETARY]: 4,
  [LicenseRisk.UNKNOWN]: 5,
};

const LICENSE_DB: Record<string, { risk: LicenseRisk; action: "allow" | "warn" | "block" | "review" }> = {
  "MIT": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "ISC": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "BSD-2-Clause": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "BSD-3-Clause": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "Apache-2.0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "Unlicense": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "CC0-1.0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "0BSD": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "MIT-0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "Zlib": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "BlueOak-1.0.0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "Artistic-2.0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "Python-2.0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "BSL-1.0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "CC-BY-4.0": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "WTFPL": { risk: LicenseRisk.PERMISSIVE, action: "allow" },
  "LGPL-2.0-only": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "LGPL-2.1-only": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "LGPL-2.1-or-later": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "LGPL-3.0-only": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "LGPL-3.0-or-later": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "MPL-2.0": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "EPL-1.0": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "EPL-2.0": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "CDDL-1.0": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "CDDL-1.1": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "CPL-1.0": { risk: LicenseRisk.WEAK_COPYLEFT, action: "warn" },
  "GPL-2.0-only": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "GPL-2.0-or-later": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "GPL-3.0-only": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "GPL-3.0-or-later": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "EUPL-1.1": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "EUPL-1.2": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "CC-BY-SA-4.0": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "OSL-3.0": { risk: LicenseRisk.STRONG_COPYLEFT, action: "block" },
  "AGPL-3.0-only": { risk: LicenseRisk.NETWORK_COPYLEFT, action: "block" },
  "AGPL-3.0-or-later": { risk: LicenseRisk.NETWORK_COPYLEFT, action: "block" },
  "SSPL-1.0": { risk: LicenseRisk.NETWORK_COPYLEFT, action: "block" },
  "BUSL-1.1": { risk: LicenseRisk.PROPRIETARY, action: "review" },
  "Elastic-2.0": { risk: LicenseRisk.PROPRIETARY, action: "review" },
};

export interface LicenseResult {
  package: string;
  version: string;
  license: string;
  risk: LicenseRisk;
  action: "allow" | "warn" | "block" | "review";
  reason: string;
}

export interface LicenseScanResult {
  scan_timestamp: string;
  scanner: "complyt-license";
  total_packages: number;
  results: LicenseResult[];
  summary: {
    permissive: number;
    weak_copyleft: number;
    strong_copyleft: number;
    network_copyleft: number;
    proprietary: number;
    unknown: number;
    blocked: number;
  };
}

export function parseSpdxExpression(expr: string): string {
  const trimmed = expr.trim();
  if (!trimmed) return "";

  if (/\bOR\b/i.test(trimmed)) {
    const parts = trimmed.split(/\s+OR\s+/i).map((p) => p.trim().replace(/^\(|\)$/g, ""));
    let bestPart = parts[0];
    let bestSeverity = riskSeverityOf(bestPart);
    for (let i = 1; i < parts.length; i++) {
      const s = riskSeverityOf(parts[i]);
      if (s < bestSeverity) {
        bestSeverity = s;
        bestPart = parts[i];
      }
    }
    return bestPart;
  }

  if (/\bAND\b/i.test(trimmed)) {
    const parts = trimmed.split(/\s+AND\s+/i).map((p) => p.trim().replace(/^\(|\)$/g, ""));
    let worstPart = parts[0];
    let worstSeverity = riskSeverityOf(worstPart);
    for (let i = 1; i < parts.length; i++) {
      const s = riskSeverityOf(parts[i]);
      if (s > worstSeverity) {
        worstSeverity = s;
        worstPart = parts[i];
      }
    }
    return worstPart;
  }

  return trimmed.replace(/^\(|\)$/g, "");
}

function riskSeverityOf(identifier: string): number {
  const clean = identifier.trim().replace(/^\(|\)$/g, "");
  const entry = LICENSE_DB[clean];
  if (!entry) return RISK_SEVERITY[LicenseRisk.UNKNOWN];
  return RISK_SEVERITY[entry.risk];
}

export function classifyLicense(license: string): { risk: LicenseRisk; action: "allow" | "warn" | "block" | "review" } {
  if (!license || license.trim() === "") {
    return { risk: LicenseRisk.UNKNOWN, action: "review" };
  }

  if (license.trim().toUpperCase() === "UNLICENSED") {
    return { risk: LicenseRisk.PROPRIETARY, action: "review" };
  }

  const resolved = parseSpdxExpression(license);
  const entry = LICENSE_DB[resolved];
  if (entry) {
    return { risk: entry.risk, action: entry.action };
  }

  return { risk: LicenseRisk.UNKNOWN, action: "review" };
}

function readPackageLicense(packageName: string, targetDir: string): string {
  try {
    const pkgJsonPath = path.join(targetDir, "node_modules", packageName, "package.json");
    const content = fs.readFileSync(pkgJsonPath, "utf-8");
    const pkg = JSON.parse(content);

    if (typeof pkg.license === "string") return pkg.license;
    if (typeof pkg.license === "object" && pkg.license?.type) return pkg.license.type;
    if (Array.isArray(pkg.licenses) && pkg.licenses.length > 0) {
      return pkg.licenses.map((l: { type?: string }) => l.type ?? "").filter(Boolean).join(" OR ");
    }

    return "";
  } catch {
    return "";
  }
}

function buildReason(license: string, risk: LicenseRisk, action: string, rawLicense: string): string {
  if (!rawLicense || rawLicense.trim() === "") {
    return "No license field found in package.json";
  }
  if (rawLicense.trim().toUpperCase() === "UNLICENSED") {
    return "Package is marked UNLICENSED (proprietary, not open source)";
  }

  const resolved = parseSpdxExpression(rawLicense);
  const wasExpression = resolved !== rawLicense.trim();

  switch (risk) {
    case LicenseRisk.PERMISSIVE:
      return wasExpression
        ? `SPDX expression "${rawLicense}" resolved to ${resolved} (permissive)`
        : `${license} is a permissive license`;
    case LicenseRisk.WEAK_COPYLEFT:
      return wasExpression
        ? `SPDX expression "${rawLicense}" resolved to ${resolved} (weak copyleft — review linking requirements)`
        : `${license} is weak copyleft — review linking requirements`;
    case LicenseRisk.STRONG_COPYLEFT:
      return wasExpression
        ? `SPDX expression "${rawLicense}" resolved to ${resolved} (strong copyleft — derivative work must use same license)`
        : `${license} is strong copyleft — derivative work must use same license`;
    case LicenseRisk.NETWORK_COPYLEFT:
      return wasExpression
        ? `SPDX expression "${rawLicense}" resolved to ${resolved} (network copyleft — applies to SaaS/network use)`
        : `${license} is network copyleft — applies to SaaS/network use`;
    case LicenseRisk.PROPRIETARY:
      return `${license} is a proprietary/source-available license — manual review required`;
    case LicenseRisk.UNKNOWN:
      return `License "${rawLicense}" is not in the known SPDX database — manual review required`;
    default: {
      const _exhaustive: never = risk;
      return `Unhandled risk level: ${_exhaustive}`;
    }
  }
}

export function runLicenseScan(
  sbom: { components: Array<{ name: string; version: string }> },
  targetDir: string,
): LicenseScanResult {
  const timestamp = new Date().toISOString();
  const results: LicenseResult[] = [];

  const summary = {
    permissive: 0,
    weak_copyleft: 0,
    strong_copyleft: 0,
    network_copyleft: 0,
    proprietary: 0,
    unknown: 0,
    blocked: 0,
  };

  for (const component of sbom.components) {
    const rawLicense = readPackageLicense(component.name, targetDir);
    const { risk, action } = classifyLicense(rawLicense);
    const displayLicense = rawLicense || "unknown";
    const reason = buildReason(displayLicense, risk, action, rawLicense);

    results.push({
      package: component.name,
      version: component.version,
      license: displayLicense,
      risk,
      action,
      reason,
    });

    summary[risk] += 1;
    if (action === "block") {
      summary.blocked += 1;
    }
  }

  return {
    scan_timestamp: timestamp,
    scanner: "complyt-license",
    total_packages: sbom.components.length,
    results,
    summary,
  };
}
