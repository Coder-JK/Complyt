import fs from "fs";
import path from "path";

interface DockerfileRule {
  id: string;
  severity: "error" | "warning" | "info";
  title: string;
}

const RULES: DockerfileRule[] = [
  { id: "DL3000", severity: "error", title: "Use absolute WORKDIR" },
  { id: "DL3002", severity: "warning", title: "Last USER should not be root" },
  { id: "DL3004", severity: "error", title: "Do not use sudo" },
  { id: "DL3005", severity: "warning", title: "Do not use apt-get upgrade" },
  { id: "DL3006", severity: "warning", title: "Always tag image version" },
  { id: "DL3007", severity: "warning", title: "Do not use :latest tag" },
  { id: "DL3008", severity: "warning", title: "Pin versions in apt-get install" },
  { id: "DL3009", severity: "info", title: "Delete apt lists after install" },
  { id: "DL3015", severity: "info", title: "Use --no-install-recommends" },
  { id: "DL3020", severity: "error", title: "Use COPY instead of ADD" },
  { id: "DL3045", severity: "warning", title: "COPY to relative dest without WORKDIR" },
  { id: "DL3055", severity: "warning", title: "Missing HEALTHCHECK" },
  { id: "DL4000", severity: "error", title: "MAINTAINER is deprecated" },
  { id: "DL4003", severity: "warning", title: "Multiple CMD instructions" },
  { id: "DL4006", severity: "warning", title: "Set pipefail before pipe in RUN" },
  { id: "DL-SEC1", severity: "error", title: "Secrets in ENV/ARG" },
  { id: "DL-SEC2", severity: "error", title: "Invalid EXPOSE port" },
  { id: "DL-SEC3", severity: "warning", title: "Missing .dockerignore" },
];

const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

export interface DockerfileFinding {
  rule_id: string;
  title: string;
  severity: "error" | "warning" | "info";
  file: string;
  line: number;
  detail: string;
}

export interface DockerfileLintResult {
  scan_timestamp: string;
  scanner: "complyt-dockerfile";
  dockerfiles_found: number;
  results: DockerfileFinding[];
  summary: {
    total_findings: number;
    by_severity: Record<string, number>;
  };
  note?: string;
}

interface ParsedLine {
  lineNumber: number;
  instruction: string;
  args: string;
  raw: string;
}

function findDockerfiles(targetDir: string): string[] {
  const files: string[] = [];
  const searchDirs = [
    targetDir,
    path.join(targetDir, "docker"),
    path.join(targetDir, ".docker"),
    path.join(targetDir, "deploy"),
  ];

  for (const dir of searchDirs) {
    try {
      if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) continue;
      const entries = fs.readdirSync(dir);
      for (const entry of entries) {
        if (isDockerfile(entry)) {
          files.push(path.join(dir, entry));
        }
      }
    } catch {
      // Permission denied or similar — skip silently
    }
  }

  return files;
}

function isDockerfile(filename: string): boolean {
  const lower = filename.toLowerCase();
  if (lower === "dockerfile") return true;
  if (lower.startsWith("dockerfile.")) return true;
  if (lower.endsWith(".dockerfile")) return true;
  return false;
}

function parseDockerfile(content: string): ParsedLine[] {
  const rawLines = content.split(/\r?\n/);
  const parsed: ParsedLine[] = [];
  let continued = "";
  let continuedStartLine = 0;

  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i];
    const trimmed = line.trimEnd();

    if (trimmed.endsWith("\\")) {
      if (!continued) {
        continuedStartLine = i + 1;
      }
      continued += trimmed.slice(0, -1) + " ";
      continue;
    }

    const fullLine = continued ? continued + line : line;
    const lineNumber = continued ? continuedStartLine : i + 1;
    continued = "";

    const stripped = fullLine.trim();
    if (!stripped || stripped.startsWith("#")) continue;

    const match = stripped.match(/^(\w+)\s+([\s\S]*)/);
    if (match) {
      parsed.push({
        lineNumber,
        instruction: match[1].toUpperCase(),
        args: match[2],
        raw: stripped,
      });
    } else {
      parsed.push({
        lineNumber,
        instruction: stripped.toUpperCase(),
        args: "",
        raw: stripped,
      });
    }
  }

  return parsed;
}

function emit(
  findings: DockerfileFinding[],
  ruleId: string,
  file: string,
  line: number,
  detail: string,
): void {
  const rule = RULES_BY_ID.get(ruleId);
  if (!rule) return;
  findings.push({
    rule_id: ruleId,
    title: rule.title,
    severity: rule.severity,
    file,
    line,
    detail,
  });
}

const SECRETS_PATTERN = /\b(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\b/i;

function lintDockerfile(filePath: string, findings: DockerfileFinding[], targetDir: string): void {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return;
  }

  const relativePath = path.relative(targetDir, filePath);
  const lines = parseDockerfile(content);

  let workdirSet = false;
  let lastUser: { value: string; line: number } | null = null;
  let cmdCount = 0;
  let hasHealthcheck = false;
  let isMultistage = false;
  let stageCount = 0;

  for (const line of lines) {
    switch (line.instruction) {
      case "FROM": {
        stageCount++;
        if (stageCount > 1) isMultistage = true;

        workdirSet = false;
        lastUser = null;

        const imageRef = line.args.split(/\s+/)[0];
        if (imageRef.toLowerCase() === "scratch") break;

        if (!imageRef.includes(":")) {
          emit(findings, "DL3006", relativePath, line.lineNumber, `Image "${imageRef}" has no version tag`);
        } else if (imageRef.endsWith(":latest")) {
          emit(findings, "DL3007", relativePath, line.lineNumber, `Avoid using :latest tag on "${imageRef}"`);
        }
        break;
      }

      case "WORKDIR": {
        workdirSet = true;
        if (!line.args.startsWith("/") && !line.args.startsWith("$")) {
          emit(findings, "DL3000", relativePath, line.lineNumber, `WORKDIR "${line.args}" is not an absolute path`);
        }
        break;
      }

      case "USER": {
        lastUser = { value: line.args.trim(), line: line.lineNumber };
        break;
      }

      case "RUN": {
        if (/\bsudo\b/.test(line.args)) {
          emit(findings, "DL3004", relativePath, line.lineNumber, "Do not use sudo in RUN instructions");
        }

        if (/apt-get\s+(upgrade|dist-upgrade)\b/.test(line.args)) {
          emit(findings, "DL3005", relativePath, line.lineNumber, "Do not use apt-get upgrade/dist-upgrade");
        }

        if (/apt-get\s+install\b/.test(line.args)) {
          const installArgs = line.args.slice(line.args.indexOf("install"));
          const packages = installArgs
            .replace(/install/, "")
            .split(/\s+/)
            .filter((p) => p && !p.startsWith("-") && !p.startsWith("$"));
          const unpinned = packages.filter((p) => !p.includes("=") && p.length > 0);
          if (unpinned.length > 0) {
            emit(findings, "DL3008", relativePath, line.lineNumber,
              `Packages without version pins: ${unpinned.join(", ")}`);
          }

          if (!/rm\s+-rf\s+\/var\/lib\/apt\/lists/.test(line.args)) {
            emit(findings, "DL3009", relativePath, line.lineNumber,
              "apt-get install without cleaning /var/lib/apt/lists");
          }

          if (!line.args.includes("--no-install-recommends")) {
            emit(findings, "DL3015", relativePath, line.lineNumber,
              "apt-get install without --no-install-recommends");
          }
        }

        if (line.args.includes("|") && !/set\s+-o\s+pipefail/.test(line.args)) {
          emit(findings, "DL4006", relativePath, line.lineNumber,
            "RUN with pipe but no `set -o pipefail`");
        }
        break;
      }

      case "ADD": {
        const addArgs = line.args.trim().split(/\s+/);
        if (addArgs.length >= 2) {
          const src = addArgs[0];
          const isUrl = /^https?:\/\//.test(src);
          const isArchive = /\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$/i.test(src);
          if (!isUrl && !isArchive) {
            emit(findings, "DL3020", relativePath, line.lineNumber,
              `Use COPY instead of ADD for local file "${src}"`);
          }
        }
        break;
      }

      case "COPY": {
        const copyArgs = line.args.replace(/--\S+\s+/g, "").trim().split(/\s+/);
        if (copyArgs.length >= 2) {
          const dest = copyArgs[copyArgs.length - 1];
          if (!dest.startsWith("/") && !dest.startsWith("$") && !workdirSet) {
            emit(findings, "DL3045", relativePath, line.lineNumber,
              `COPY destination "${dest}" is relative but no WORKDIR is set`);
          }
        }
        break;
      }

      case "MAINTAINER": {
        emit(findings, "DL4000", relativePath, line.lineNumber,
          "MAINTAINER is deprecated — use LABEL maintainer instead");
        break;
      }

      case "CMD": {
        cmdCount++;
        break;
      }

      case "HEALTHCHECK": {
        hasHealthcheck = true;
        break;
      }

      case "EXPOSE": {
        const ports = line.args.trim().split(/\s+/);
        for (const portSpec of ports) {
          const portNum = parseInt(portSpec.replace(/\/(tcp|udp)/i, ""), 10);
          if (!isNaN(portNum) && (portNum < 0 || portNum > 65535)) {
            emit(findings, "DL-SEC2", relativePath, line.lineNumber,
              `Invalid port number: ${portSpec}`);
          }
        }
        break;
      }

      case "ENV":
      case "ARG": {
        if (SECRETS_PATTERN.test(line.args)) {
          emit(findings, "DL-SEC1", relativePath, line.lineNumber,
            `${line.instruction} may contain secrets: "${line.args.split("=")[0].trim()}"`);
        }
        break;
      }

      default:
        break;
    }
  }

  if (cmdCount > 1) {
    emit(findings, "DL4003", relativePath, 0,
      `Found ${cmdCount} CMD instructions — only the last one takes effect`);
  }

  if (!hasHealthcheck && !isMultistage) {
    emit(findings, "DL3055", relativePath, 0, "No HEALTHCHECK instruction found");
  }

  if (!lastUser || /^root$/i.test(lastUser.value)) {
    emit(findings, "DL3002", relativePath, lastUser?.line ?? 0,
      lastUser ? "Last USER instruction is root" : "No USER instruction found");
  }
}

export function runDockerfileLint(targetDir: string): DockerfileLintResult {
  const timestamp = new Date().toISOString();
  const safeDir = path.resolve(targetDir);

  if (!fs.existsSync(safeDir)) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-dockerfile",
      dockerfiles_found: 0,
      results: [],
      summary: { total_findings: 0, by_severity: {} },
      note: `Target directory does not exist: ${safeDir}`,
    };
  }

  const dockerfiles = findDockerfiles(safeDir);

  if (dockerfiles.length === 0) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-dockerfile",
      dockerfiles_found: 0,
      results: [],
      summary: { total_findings: 0, by_severity: {} },
      note: "No Dockerfile found",
    };
  }

  const findings: DockerfileFinding[] = [];

  for (const df of dockerfiles) {
    lintDockerfile(df, findings, safeDir);
  }

  const hasDockerignore = fs.existsSync(path.join(safeDir, ".dockerignore"));
  if (!hasDockerignore) {
    emit(findings, "DL-SEC3", "", 0, "No .dockerignore file found in the project root");
  }

  const bySeverity: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  return {
    scan_timestamp: timestamp,
    scanner: "complyt-dockerfile",
    dockerfiles_found: dockerfiles.length,
    results: findings,
    summary: {
      total_findings: findings.length,
      by_severity: bySeverity,
    },
  };
}
