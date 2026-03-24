import fs from "fs";
import path from "path";
import { execSync } from "child_process";

export interface SecretFinding {
  description: string;
  file: string;
  startLine: number;
  endLine: number;
  match: string;
  secret: string;
  ruleID: string;
  entropy: number;
  author: string;
  date: string;
  commit: string;
  fingerprint: string;
}

export interface SecretScanResult {
  scan_timestamp: string;
  scanner: string;
  scanner_version: string | null;
  target_directory: string;
  results: SecretFinding[];
  summary: {
    total_findings: number;
    by_rule: Record<string, number>;
  };
  errors: string[];
}

export function isGitleaksAvailable(): boolean {
  try {
    execSync("gitleaks version", { timeout: 5000, stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

export function runGitleaksScan(targetDir: string): SecretScanResult {
  const timestamp = new Date().toISOString();

  if (!isGitleaksAvailable()) {
    return {
      scan_timestamp: timestamp,
      scanner: "gitleaks",
      scanner_version: null,
      target_directory: targetDir,
      results: [],
      summary: { total_findings: 0, by_rule: {} },
      errors: ["gitleaks not installed -- skipping secret scan. Install: https://github.com/gitleaks/gitleaks#installing"],
    };
  }

  const safeDir = path.resolve(targetDir);
  if (!fs.existsSync(safeDir)) {
    return {
      scan_timestamp: timestamp,
      scanner: "gitleaks",
      scanner_version: null,
      target_directory: targetDir,
      results: [],
      summary: { total_findings: 0, by_rule: {} },
      errors: [`Target directory does not exist: ${safeDir}`],
    };
  }

  let version: string | null = null;
  try {
    version = execSync("gitleaks version", {
      timeout: 5000,
      encoding: "utf-8",
    }).trim();
  } catch {
    // version detection failed
  }

  try {
    const reportPath = path.join(safeDir, ".gitleaks-report.json");

    try {
      execSync(
        `gitleaks detect --source "${safeDir}" --report-format json --report-path "${reportPath}" --no-git`,
        {
          timeout: 120000,
          maxBuffer: 50 * 1024 * 1024,
          encoding: "utf-8",
        }
      );
    } catch {
      // gitleaks exits with code 1 when findings are detected -- that's expected
    }

    let results: SecretFinding[] = [];
    if (fs.existsSync(reportPath)) {
      const raw = fs.readFileSync(reportPath, "utf-8");
      const parsed = JSON.parse(raw);
      results = Array.isArray(parsed) ? parsed.map((r: Record<string, unknown>) => ({
        description: (r.Description ?? r.description ?? "") as string,
        file: (r.File ?? r.file ?? "") as string,
        startLine: (r.StartLine ?? r.startLine ?? 0) as number,
        endLine: (r.EndLine ?? r.endLine ?? 0) as number,
        match: redactSecret((r.Match ?? r.match ?? "") as string),
        secret: "[REDACTED]",
        ruleID: (r.RuleID ?? r.ruleID ?? "") as string,
        entropy: (r.Entropy ?? r.entropy ?? 0) as number,
        author: (r.Author ?? r.author ?? "") as string,
        date: (r.Date ?? r.date ?? "") as string,
        commit: (r.Commit ?? r.commit ?? "") as string,
        fingerprint: (r.Fingerprint ?? r.fingerprint ?? "") as string,
      })) : [];

      fs.unlinkSync(reportPath);
    }

    const byRule: Record<string, number> = {};
    for (const finding of results) {
      byRule[finding.ruleID] = (byRule[finding.ruleID] || 0) + 1;
    }

    return {
      scan_timestamp: timestamp,
      scanner: "gitleaks",
      scanner_version: version,
      target_directory: safeDir,
      results,
      summary: {
        total_findings: results.length,
        by_rule: byRule,
      },
      errors: [],
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      scan_timestamp: timestamp,
      scanner: "gitleaks",
      scanner_version: version,
      target_directory: safeDir,
      results: [],
      summary: { total_findings: 0, by_rule: {} },
      errors: [`Gitleaks scan failed: ${msg.slice(0, 500)}`],
    };
  }
}

function redactSecret(match: string): string {
  if (match.length <= 8) return "[REDACTED]";
  return match.slice(0, 4) + "..." + match.slice(-4);
}
