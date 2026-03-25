import fs from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SecretFindingBuiltin {
  rule_id: string;
  file: string;
  line: number;
  match: string;
  severity: string;
  description: string;
}

export interface SecretScanResult {
  scan_timestamp: string;
  scanner: "complyt-secrets";
  target_directory: string;
  files_scanned: number;
  files_skipped: number;
  results: SecretFindingBuiltin[];
  summary: {
    total: number;
    by_severity: Record<string, number>;
  };
}

interface SecretRule {
  id: string;
  severity: "critical" | "high" | "medium";
  description: string;
  keywords: string[];
  regex: RegExp;
  entropyCheck?: boolean;
}

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const ENTROPY_THRESHOLD = 3.5;

const SECRET_RULES: SecretRule[] = [
  {
    id: "aws-access-key-id",
    severity: "critical",
    description: "AWS Access Key ID",
    keywords: ["AKIA", "ASIA", "ABIA", "ACCA"],
    regex: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/,
  },
  {
    id: "aws-secret-key",
    severity: "critical",
    description: "AWS Secret Access Key",
    keywords: ["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"],
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[\s'"=:]+([A-Za-z0-9/+=]{40})/,
  },
  {
    id: "aws-mws-key",
    severity: "critical",
    description: "Amazon MWS Auth Token",
    keywords: ["amzn.mws"],
    regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,
  },
  {
    id: "github-pat",
    severity: "critical",
    description: "GitHub Personal Access Token",
    keywords: ["ghp_"],
    regex: /ghp_[0-9a-zA-Z]{36}/,
  },
  {
    id: "github-oauth",
    severity: "critical",
    description: "GitHub OAuth Access Token",
    keywords: ["gho_"],
    regex: /gho_[0-9a-zA-Z]{36}/,
  },
  {
    id: "github-app-token",
    severity: "critical",
    description: "GitHub App Token",
    keywords: ["ghu_", "ghs_"],
    regex: /(?:ghu|ghs)_[0-9a-zA-Z]{36}/,
  },
  {
    id: "stripe-secret",
    severity: "critical",
    description: "Stripe Secret Key",
    keywords: ["sk_test_", "sk_live_"],
    regex: /\bsk_(?:test|live)_[a-zA-Z0-9]{10,99}\b/,
  },
  {
    id: "stripe-restricted",
    severity: "high",
    description: "Stripe Restricted API Key",
    keywords: ["rk_test_", "rk_live_"],
    regex: /\brk_(?:test|live)_[a-zA-Z0-9]{10,99}\b/,
  },
  {
    id: "openai-api-key",
    severity: "critical",
    description: "OpenAI API Key",
    keywords: ["sk-", "T3BlbkFJ"],
    regex: /\bsk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}\b/,
  },
  {
    id: "google-api-key",
    severity: "high",
    description: "Google API Key",
    keywords: ["AIza"],
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/,
  },
  {
    id: "slack-bot-token",
    severity: "critical",
    description: "Slack Bot Token",
    keywords: ["xoxb-"],
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/,
  },
  {
    id: "slack-user-token",
    severity: "critical",
    description: "Slack User/App Token",
    keywords: ["xoxp-", "xoxe-"],
    regex: /xox[pe]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/,
  },
  {
    id: "slack-webhook",
    severity: "high",
    description: "Slack Webhook URL",
    keywords: ["hooks.slack.com"],
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24}/,
  },
  {
    id: "private-key",
    severity: "critical",
    description: "Private Key (RSA/EC/DSA/OPENSSH)",
    keywords: ["BEGIN", "PRIVATE KEY"],
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    id: "npm-access-token",
    severity: "critical",
    description: "NPM Access Token",
    keywords: ["npm_"],
    regex: /\bnpm_[a-z0-9]{36}\b/,
  },
  {
    id: "sendgrid-api-key",
    severity: "critical",
    description: "SendGrid API Key",
    keywords: ["SG."],
    regex: /\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b/,
  },
  {
    id: "twilio-api-key",
    severity: "high",
    description: "Twilio API Key",
    keywords: ["SK"],
    regex: /\bSK[0-9a-fA-F]{32}\b/,
  },
  {
    id: "database-url",
    severity: "critical",
    description: "Database Connection String",
    keywords: ["mongodb", "postgres", "postgresql", "mysql", "redis", "amqp"],
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)s?:\/\/[^\s'"]{10,}/,
  },
  {
    id: "jwt-token",
    severity: "medium",
    description: "JSON Web Token",
    keywords: ["eyJ"],
    regex: /\beyJ[a-zA-Z0-9]{17,}\.eyJ[a-zA-Z0-9\/\\_\-]{17,}\.[a-zA-Z0-9\/\\_\-]{10,}\b/,
  },
  {
    id: "azure-client-secret",
    severity: "critical",
    description: "Azure Client Secret",
    keywords: ["Q~"],
    regex: /[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34}/,
  },
  {
    id: "heroku-api-key",
    severity: "high",
    description: "Heroku API Key",
    keywords: ["heroku"],
    regex: /[hH][eE][rR][oO][kK][uU][\s'"=:]+[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/,
  },
  {
    id: "mailgun-api-key",
    severity: "high",
    description: "Mailgun API Key",
    keywords: ["key-"],
    regex: /key-[0-9a-zA-Z]{32}/,
  },
  {
    id: "digitalocean-token",
    severity: "critical",
    description: "DigitalOcean Personal Access Token",
    keywords: ["dop_v1_"],
    regex: /\bdop_v1_[a-f0-9]{64}\b/,
  },
  {
    id: "cloudflare-api-key",
    severity: "critical",
    description: "Cloudflare API Key",
    keywords: ["v1.0-"],
    regex: /\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b/,
  },
  {
    id: "firebase-key",
    severity: "high",
    description: "Firebase API Key",
    keywords: ["AIzaSy"],
    regex: /\bAIzaSy[0-9A-Za-z\-_]{33}\b/,
  },
  {
    id: "supabase-key",
    severity: "high",
    description: "Supabase Service Key",
    keywords: ["sbp_"],
    regex: /\bsbp_[a-f0-9]{40}\b/,
  },
  {
    id: "anthropic-api-key",
    severity: "critical",
    description: "Anthropic API Key",
    keywords: ["sk-ant-api03-"],
    regex: /\bsk-ant-api03-[a-zA-Z0-9_\-]{90,}\b/,
  },
  {
    id: "vercel-token",
    severity: "high",
    description: "Vercel Access Token",
    keywords: ["vercel_"],
    regex: /\bvercel_[a-zA-Z0-9]{24}\b/,
  },
  {
    id: "generic-password",
    severity: "medium",
    description: "Generic password assignment",
    keywords: ["password", "passwd", "pwd"],
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]/,
    entropyCheck: true,
  },
  {
    id: "generic-api-key",
    severity: "medium",
    description: "Generic API key assignment",
    keywords: ["api_key", "apikey", "api-key", "access_token", "auth_token"],
    regex: /(?:api_key|apikey|api-key|access_token|auth_token)\s*[=:]\s*['"]([^'"]{8,})['"]/,
    entropyCheck: true,
  },
];

// ---------------------------------------------------------------------------
// Directory walking
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build"]);
const MAX_FILE_SIZE = 1024 * 1024; // 1 MB

function isBinaryBuffer(buf: Buffer): boolean {
  for (let i = 0; i < Math.min(buf.length, 512); i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function collectFiles(dir: string): { scanned: string[]; skipped: number } {
  const scanned: string[] = [];
  let skipped = 0;

  function walk(current: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      skipped++;
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          skipped++;
          continue;
        }
        let realPath: string;
        try {
          realPath = fs.realpathSync(fullPath);
        } catch {
          skipped++;
          continue;
        }
        if (realPath !== fullPath && realPath.startsWith(dir)) {
          skipped++;
          continue;
        }
        walk(fullPath);
        continue;
      }

      if (!entry.isFile()) {
        skipped++;
        continue;
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(fullPath);
      } catch {
        skipped++;
        continue;
      }

      if (stat.size > MAX_FILE_SIZE || stat.size === 0) {
        skipped++;
        continue;
      }

      let headBuf: Buffer;
      try {
        const fd = fs.openSync(fullPath, "r");
        headBuf = Buffer.alloc(Math.min(512, stat.size));
        fs.readSync(fd, headBuf, 0, headBuf.length, 0);
        fs.closeSync(fd);
      } catch {
        skipped++;
        continue;
      }

      if (isBinaryBuffer(headBuf)) {
        skipped++;
        continue;
      }

      scanned.push(fullPath);
    }
  }

  walk(dir);
  return { scanned, skipped };
}

// ---------------------------------------------------------------------------
// Scanning helpers
// ---------------------------------------------------------------------------

function redactSecret(match: string): string {
  if (match.length <= 8) return "[REDACTED]";
  return match.slice(0, 4) + "..." + match.slice(-4);
}

function lineMatchesKeywords(line: string, keywords: string[]): boolean {
  const lower = line.toLowerCase();
  return keywords.some((kw) => lower.includes(kw.toLowerCase()));
}

function scanFile(
  filePath: string,
  relativeBase: string
): SecretFindingBuiltin[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const relativePath = path.relative(relativeBase, filePath);
  const lines = content.split("\n");
  const findings: SecretFindingBuiltin[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0) continue;

    for (const rule of SECRET_RULES) {
      if (!lineMatchesKeywords(line, rule.keywords)) continue;

      const m = rule.regex.exec(line);
      if (!m) continue;

      const captured = m[1] ?? m[0];

      if (rule.entropyCheck) {
        if (shannonEntropy(captured) < ENTROPY_THRESHOLD) continue;
      }

      findings.push({
        rule_id: rule.id,
        file: relativePath,
        line: i + 1,
        match: redactSecret(captured),
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

export function runBuiltinSecretScan(targetDir: string): SecretScanResult {
  const timestamp = new Date().toISOString();
  const safeDir = path.resolve(targetDir);

  if (!fs.existsSync(safeDir)) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-secrets",
      target_directory: safeDir,
      files_scanned: 0,
      files_skipped: 0,
      results: [],
      summary: { total: 0, by_severity: {} },
    };
  }

  const { scanned, skipped } = collectFiles(safeDir);
  const allFindings: SecretFindingBuiltin[] = [];

  for (const filePath of scanned) {
    const findings = scanFile(filePath, safeDir);
    allFindings.push(...findings);
  }

  const bySeverity: Record<string, number> = {};
  for (const f of allFindings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  return {
    scan_timestamp: timestamp,
    scanner: "complyt-secrets",
    target_directory: safeDir,
    files_scanned: scanned.length,
    files_skipped: skipped,
    results: allFindings,
    summary: {
      total: allFindings.length,
      by_severity: bySeverity,
    },
  };
}
