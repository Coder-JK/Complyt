import fs from "fs";
import path from "path";
import { execSync, execFileSync } from "child_process";

export interface SastFinding {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  message: string;
  severity: string;
  metadata?: Record<string, unknown>;
}

export interface SastScanResult {
  scan_timestamp: string;
  scanner: string;
  scanner_version: string | null;
  target_directory: string;
  results: SastFinding[];
  summary: {
    total_findings: number;
    by_severity: Record<string, number>;
  };
  errors: string[];
}

export function isSemgrepAvailable(): boolean {
  try {
    execSync("semgrep --version", { timeout: 5000, stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

export function runSemgrepScan(targetDir: string): SastScanResult {
  const timestamp = new Date().toISOString();

  if (!isSemgrepAvailable()) {
    return {
      scan_timestamp: timestamp,
      scanner: "semgrep",
      scanner_version: null,
      target_directory: targetDir,
      results: [],
      summary: { total_findings: 0, by_severity: {} },
      errors: ["semgrep not installed -- skipping SAST scan. Install: https://semgrep.dev/docs/getting-started/cli-oss"],
    };
  }

  const safeDir = path.resolve(targetDir);
  if (!fs.existsSync(safeDir)) {
    return {
      scan_timestamp: timestamp,
      scanner: "semgrep",
      scanner_version: null,
      target_directory: targetDir,
      results: [],
      summary: { total_findings: 0, by_severity: {} },
      errors: [`Target directory does not exist: ${safeDir}`],
    };
  }

  let version: string | null = null;
  try {
    version = execSync("semgrep --version", {
      timeout: 5000,
      encoding: "utf-8",
    }).trim();
  } catch {
    // version detection failed
  }

  try {
    const output = execFileSync("semgrep", ["scan", "--config", "auto", "--json", "--quiet", safeDir], {
      timeout: 120000,
      maxBuffer: 50 * 1024 * 1024,
      encoding: "utf-8",
      cwd: safeDir,
    });

    const parsed = JSON.parse(output);
    const results: SastFinding[] = (parsed.results || []).map(
      (r: Record<string, unknown>) => ({
        check_id: r.check_id,
        path: r.path,
        start: r.start,
        end: r.end,
        message: (r.extra as Record<string, unknown>)?.message ?? "",
        severity: (r.extra as Record<string, unknown>)?.severity ?? "unknown",
        metadata: (r.extra as Record<string, unknown>)?.metadata as Record<string, unknown>,
      })
    );

    const bySeverity: Record<string, number> = {};
    for (const finding of results) {
      bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    }

    return {
      scan_timestamp: timestamp,
      scanner: "semgrep",
      scanner_version: version,
      target_directory: safeDir,
      results,
      summary: {
        total_findings: results.length,
        by_severity: bySeverity,
      },
      errors: [],
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      scan_timestamp: timestamp,
      scanner: "semgrep",
      scanner_version: version,
      target_directory: safeDir,
      results: [],
      summary: { total_findings: 0, by_severity: {} },
      errors: [`Semgrep scan failed: ${msg.slice(0, 500)}`],
    };
  }
}
