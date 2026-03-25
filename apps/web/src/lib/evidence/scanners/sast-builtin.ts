import fs from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SastFindingBuiltin {
  rule_id: string;
  title: string;
  file: string;
  line: number;
  match: string;
  severity: string;
  description: string;
}

export interface SastScanResult {
  scan_timestamp: string;
  scanner: "complyt-sast";
  target_directory: string;
  files_scanned: number;
  results: SastFindingBuiltin[];
  summary: {
    total_findings: number;
    by_severity: Record<string, number>;
  };
}

interface SastRule {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  regex: RegExp;
  description: string;
  multiline?: boolean;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const SAST_RULES: SastRule[] = [
  {
    id: "SAST-001",
    severity: "critical",
    title: "eval() with expression",
    regex: /\beval\s*\([^)]*[a-zA-Z_$][a-zA-Z0-9_$]*[^)]*\)/,
    description:
      "eval() called with non-literal argument enables code injection",
  },
  {
    id: "SAST-002",
    severity: "critical",
    title: "child_process.exec with variable",
    regex: /(?:exec|execSync)\s*\([^)]*(?:\$\{|`|\+\s*[a-zA-Z])/,
    description:
      "Command execution with string interpolation/concatenation enables command injection",
  },
  {
    id: "SAST-003",
    severity: "high",
    title: "Non-literal filesystem path",
    regex: /\bfs\.\w+(?:Sync)?\s*\(\s*(?!['"`\/])(?:[a-zA-Z_$]|\.\.\/)/,
    description:
      "Filesystem operation with variable path enables path traversal",
  },
  {
    id: "SAST-004",
    severity: "high",
    title: "Dynamic require()",
    regex: /\brequire\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\)/,
    description:
      "Dynamic require() with variable enables arbitrary module loading",
  },
  {
    id: "SAST-005",
    severity: "high",
    title: "SQL injection via template literal",
    regex: /(?:query|execute|raw)\s*\(\s*`[^`]*\$\{/,
    description:
      "SQL query built with template literal interpolation enables SQL injection",
  },
  {
    id: "SAST-006",
    severity: "high",
    title: "XSS via innerHTML/dangerouslySetInnerHTML",
    regex:
      /(?:\.innerHTML\s*=|dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:)\s*(?!['"]\s*['"<])/,
    description:
      "Setting innerHTML or dangerouslySetInnerHTML with dynamic content enables XSS",
  },
  {
    id: "SAST-007",
    severity: "medium",
    title: "Dynamic RegExp construction",
    regex: /new\s+RegExp\s*\(\s*[a-zA-Z_$]/,
    description: "RegExp with variable pattern enables ReDoS attacks",
  },
  {
    id: "SAST-008",
    severity: "medium",
    title: "Deprecated Buffer constructor",
    regex: /new\s+Buffer\s*\(/,
    description:
      "new Buffer() is deprecated and unsafe, use Buffer.from() or Buffer.alloc()",
  },
  {
    id: "SAST-009",
    severity: "medium",
    title: "Weak hash algorithm",
    regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]/,
    description:
      "MD5 and SHA1 are cryptographically broken, use SHA-256 or stronger",
  },
  {
    id: "SAST-010",
    severity: "medium",
    title: "Weak random number generator",
    regex: /(?:pseudoRandomBytes|Math\.random)\s*\(/,
    description:
      "pseudoRandomBytes() and Math.random() are not cryptographically secure",
  },
  {
    id: "SAST-011",
    severity: "medium",
    title: "Timing attack in comparison",
    regex:
      /(?:password|secret|token|key)\s*===?\s*(?:req\.|params\.|body\.|query\.)/,
    description:
      "Direct string comparison on secrets is vulnerable to timing attacks, use crypto.timingSafeEqual()",
  },
  {
    id: "SAST-012",
    severity: "low",
    title: "Logging sensitive data",
    regex:
      /console\.(?:log|info|debug|warn)\s*\([^)]*(?:password|secret|token|apiKey|api_key|credential)/,
    description: "Sensitive values may be logged to console",
  },
  {
    id: "SAST-013",
    severity: "high",
    title: "Open redirect",
    regex:
      /res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\.[a-zA-Z]|[a-zA-Z_$]+\s*\))/,
    description:
      "Redirect using user-controlled input enables open redirect attacks",
  },
  {
    id: "SAST-014",
    severity: "info",
    title: "Unicode bidi control character",
    regex: /[\u202A-\u202E\u2066-\u2069\u200F\u200E]/,
    description:
      "Unicode bidirectional control characters can be used in trojan source attacks",
  },
];

// ---------------------------------------------------------------------------
// Directory walking
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build"]);
const SCANNABLE_EXTS = new Set([".js", ".ts", ".jsx", ".tsx"]);

function shouldSkipFile(name: string): boolean {
  if (name.endsWith(".d.ts")) return true;
  const lower = name.toLowerCase();
  if (lower.includes(".test.") || lower.includes(".spec.")) return true;
  return false;
}

function collectFiles(dir: string): string[] {
  const files: string[] = [];

  function walk(current: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        try {
          const realPath = fs.realpathSync(fullPath);
          if (realPath !== fullPath && realPath.startsWith(dir)) continue;
        } catch {
          continue;
        }
        walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = path.extname(entry.name).toLowerCase();
      if (!SCANNABLE_EXTS.has(ext)) continue;
      if (shouldSkipFile(entry.name)) continue;

      files.push(fullPath);
    }
  }

  walk(dir);
  return files;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

function truncateMatch(raw: string): string {
  return raw.length > 100 ? raw.slice(0, 100) + "…" : raw;
}

function scanFile(
  filePath: string,
  relativeBase: string
): SastFindingBuiltin[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const relativePath = path.relative(relativeBase, filePath);
  const lines = content.split("\n");
  const findings: SastFindingBuiltin[] = [];

  for (let i = 0; i < lines.length; i++) {
    const windowLines = lines.slice(i, i + 3);
    const singleLine = lines[i];
    const windowText = windowLines.join("\n");

    for (const rule of SAST_RULES) {
      const target = rule.multiline ? windowText : singleLine;
      const m = rule.regex.exec(target);
      if (!m) continue;

      findings.push({
        rule_id: rule.id,
        title: rule.title,
        file: relativePath,
        line: i + 1,
        match: truncateMatch(m[0]),
        severity: rule.severity,
        description: rule.description,
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function runBuiltinSastScan(targetDir: string): SastScanResult {
  const timestamp = new Date().toISOString();
  const safeDir = path.resolve(targetDir);

  if (!fs.existsSync(safeDir)) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-sast",
      target_directory: safeDir,
      files_scanned: 0,
      results: [],
      summary: { total_findings: 0, by_severity: {} },
    };
  }

  const files = collectFiles(safeDir);
  const allFindings: SastFindingBuiltin[] = [];

  for (const filePath of files) {
    const findings = scanFile(filePath, safeDir);
    allFindings.push(...findings);
  }

  const bySeverity: Record<string, number> = {};
  for (const f of allFindings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  return {
    scan_timestamp: timestamp,
    scanner: "complyt-sast",
    target_directory: safeDir,
    files_scanned: files.length,
    results: allFindings,
    summary: {
      total_findings: allFindings.length,
      by_severity: bySeverity,
    },
  };
}
