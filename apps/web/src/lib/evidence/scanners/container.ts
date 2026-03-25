import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { resilientFetch } from "@/lib/evidence/http";

const OSV_API = "https://api.osv.dev/v1/query";
const CONCURRENCY_LIMIT = 5;

const EOL_IMAGES: Record<string, string> = {
  "node:14": "Node.js 14 EOL April 2023",
  "node:16": "Node.js 16 EOL September 2023",
  "node:18": "Node.js 18 EOL April 2025",
  "python:3.6": "Python 3.6 EOL December 2021",
  "python:3.7": "Python 3.7 EOL June 2023",
  "python:3.8": "Python 3.8 EOL October 2024",
  "ubuntu:18.04": "Ubuntu 18.04 EOL May 2023",
  "ubuntu:20.04": "Ubuntu 20.04 EOL April 2025",
  "debian:stretch": "Debian 9 EOL June 2022",
  "debian:buster": "Debian 10 EOL June 2024",
  "alpine:3.14": "Alpine 3.14 EOL May 2023",
  "alpine:3.15": "Alpine 3.15 EOL November 2023",
  "alpine:3.16": "Alpine 3.16 EOL May 2024",
  "centos:7": "CentOS 7 EOL June 2024",
  "centos:8": "CentOS 8 EOL December 2021",
};

interface OsPackage {
  name: string;
  version: string;
  ecosystem: string;
}

interface OsvVulnReference {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
}

interface ImageVulnerability {
  vuln_id: string;
  package_name: string;
  package_version: string;
  severity: string;
  summary: string;
}

interface ImageResult {
  image: string;
  tag: string;
  eol_status: string | null;
  os_packages_scanned: number;
  vulnerabilities: ImageVulnerability[];
}

export interface ContainerScanResult {
  scan_timestamp: string;
  scanner: "complyt-container";
  images: ImageResult[];
  summary: {
    images_scanned: number;
    eol_images: number;
    total_os_vulns: number;
    by_severity: Record<string, number>;
    docker_available: boolean;
    trivy_available: boolean;
  };
  errors: string[];
}

function isDockerAvailable(): boolean {
  try {
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], {
      timeout: 5000,
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

export function isTrivyAvailable(): boolean {
  try {
    execFileSync("trivy", ["--version"], { timeout: 5000, stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

function findDockerfiles(targetDir: string): string[] {
  const results: string[] = [];
  const safeDir = path.resolve(targetDir);

  function walk(dir: string, depth: number): void {
    if (depth > 5) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else if (
        entry.name === "Dockerfile" ||
        entry.name.startsWith("Dockerfile.") ||
        entry.name.endsWith(".Dockerfile")
      ) {
        results.push(full);
      }
    }
  }

  walk(safeDir, 0);
  return results;
}

interface ParsedImage {
  raw: string;
  image: string;
  tag: string;
}

function parseFromDirectives(dockerfilePath: string): ParsedImage[] {
  let content: string;
  try {
    content = fs.readFileSync(dockerfilePath, "utf-8");
  } catch {
    return [];
  }

  const images: ParsedImage[] = [];
  const seen = new Set<string>();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    const match = trimmed.match(/^FROM\s+(\S+)/i);
    if (!match) continue;

    let ref = match[1];
    if (ref.startsWith("--platform=")) {
      const parts = trimmed.match(/^FROM\s+\S+\s+(\S+)/i);
      if (parts) ref = parts[1];
      else continue;
    }
    if (ref === "scratch" || ref.startsWith("$")) continue;

    const [imagePart, tagPart] = ref.includes(":")
      ? [ref.slice(0, ref.lastIndexOf(":")), ref.slice(ref.lastIndexOf(":") + 1)]
      : [ref, "latest"];

    const key = `${imagePart}:${tagPart}`;
    if (seen.has(key)) continue;
    seen.add(key);

    images.push({ raw: ref, image: imagePart, tag: tagPart });
  }

  return images;
}

function checkEol(image: string, tag: string): string | null {
  const shortImage = image.includes("/") ? image.split("/").pop()! : image;
  const key = `${shortImage}:${tag}`;
  return EOL_IMAGES[key] ?? null;
}

function detectDistro(imageRef: string): "debian" | "alpine" | "unknown" {
  const lower = imageRef.toLowerCase();
  if (lower.includes("alpine")) return "alpine";
  if (
    lower.includes("debian") ||
    lower.includes("ubuntu") ||
    lower.includes("node") ||
    lower.includes("python")
  ) {
    return "debian";
  }
  return "unknown";
}

function extractOsPackages(imageRef: string): OsPackage[] {
  const distro = detectDistro(imageRef);
  const packages: OsPackage[] = [];

  try {
    if (distro === "debian") {
      const output = execFileSync(
        "docker",
        ["run", "--rm", imageRef, "dpkg", "-l"],
        { timeout: 60000, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 }
      );
      for (const line of output.split("\n")) {
        const match = line.match(/^ii\s+(\S+)\s+(\S+)/);
        if (match) {
          packages.push({ name: match[1], version: match[2], ecosystem: "Debian" });
        }
      }
    } else if (distro === "alpine") {
      const output = execFileSync(
        "docker",
        ["run", "--rm", imageRef, "apk", "list", "-I"],
        { timeout: 60000, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 }
      );
      for (const line of output.split("\n")) {
        const match = line.match(/^(\S+)-(\d\S*)\s/);
        if (match) {
          packages.push({ name: match[1], version: match[2], ecosystem: "Alpine" });
        }
      }
    } else {
      // Try debian first, fall back to alpine
      try {
        const output = execFileSync(
          "docker",
          ["run", "--rm", imageRef, "dpkg", "-l"],
          { timeout: 30000, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 }
        );
        for (const line of output.split("\n")) {
          const match = line.match(/^ii\s+(\S+)\s+(\S+)/);
          if (match) {
            packages.push({ name: match[1], version: match[2], ecosystem: "Debian" });
          }
        }
      } catch {
        try {
          const output = execFileSync(
            "docker",
            ["run", "--rm", imageRef, "apk", "list", "-I"],
            { timeout: 30000, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 }
          );
          for (const line of output.split("\n")) {
            const match = line.match(/^(\S+)-(\d\S*)\s/);
            if (match) {
              packages.push({ name: match[1], version: match[2], ecosystem: "Alpine" });
            }
          }
        } catch {
          // neither package manager available
        }
      }
    }
  } catch {
    // Docker command failed — image may not exist locally or daemon issue
  }

  return packages;
}

async function queryOsvForPackage(
  pkg: OsPackage
): Promise<OsvVulnReference[]> {
  try {
    const response = await resilientFetch(OSV_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
        version: pkg.version,
      }),
      maxRetries: 1,
      timeoutMs: 8000,
    });

    const data = (await response.json()) as { vulns?: OsvVulnReference[] };
    return data.vulns ?? [];
  } catch {
    return [];
  }
}

function chunk<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

async function queryOsvBatch(
  packages: OsPackage[]
): Promise<ImageVulnerability[]> {
  const vulns: ImageVulnerability[] = [];
  const batches = chunk(packages, CONCURRENCY_LIMIT);

  for (const batch of batches) {
    const results = await Promise.allSettled(
      batch.map((pkg) => queryOsvForPackage(pkg))
    );

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const pkg = batch[i];
      if (result.status === "fulfilled") {
        for (const vuln of result.value) {
          const severity = extractSeverity(vuln);
          vulns.push({
            vuln_id: vuln.id,
            package_name: pkg.name,
            package_version: pkg.version,
            severity,
            summary: vuln.summary ?? "No summary available",
          });
        }
      }
    }
  }

  return vulns;
}

function extractSeverity(vuln: OsvVulnReference): string {
  if (!vuln.severity?.length) return "unknown";
  const cvss = vuln.severity.find((s) => s.type === "CVSS_V3");
  if (!cvss) return "unknown";
  const score = parseFloat(cvss.score);
  if (Number.isNaN(score)) return "unknown";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

interface TrivyVuln {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  Severity: string;
  Title?: string;
}

interface TrivyTarget {
  Vulnerabilities?: TrivyVuln[];
}

interface TrivyOutput {
  Results?: TrivyTarget[];
}

function runTrivyScan(imageRef: string): ImageVulnerability[] {
  try {
    const output = execFileSync(
      "trivy",
      ["image", "--format", "json", "--quiet", "--no-progress", imageRef],
      { timeout: 120000, encoding: "utf-8", maxBuffer: 50 * 1024 * 1024 }
    );

    const parsed: TrivyOutput = JSON.parse(output);
    const vulns: ImageVulnerability[] = [];

    for (const target of parsed.Results ?? []) {
      for (const v of target.Vulnerabilities ?? []) {
        vulns.push({
          vuln_id: v.VulnerabilityID,
          package_name: v.PkgName,
          package_version: v.InstalledVersion,
          severity: v.Severity.toLowerCase(),
          summary: v.Title ?? "No summary available",
        });
      }
    }

    return vulns;
  } catch {
    return [];
  }
}

export async function runContainerScan(
  targetDir: string
): Promise<ContainerScanResult> {
  const timestamp = new Date().toISOString();
  const errors: string[] = [];
  const dockerAvailable = isDockerAvailable();
  const trivyAvailable = isTrivyAvailable();

  const safeDir = path.resolve(targetDir);
  if (!fs.existsSync(safeDir)) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-container",
      images: [],
      summary: {
        images_scanned: 0,
        eol_images: 0,
        total_os_vulns: 0,
        by_severity: {},
        docker_available: dockerAvailable,
        trivy_available: trivyAvailable,
      },
      errors: [`Target directory does not exist: ${safeDir}`],
    };
  }

  const dockerfiles = findDockerfiles(safeDir);
  if (dockerfiles.length === 0) {
    return {
      scan_timestamp: timestamp,
      scanner: "complyt-container",
      images: [],
      summary: {
        images_scanned: 0,
        eol_images: 0,
        total_os_vulns: 0,
        by_severity: {},
        docker_available: dockerAvailable,
        trivy_available: trivyAvailable,
      },
      errors: [],
    };
  }

  const allParsed: ParsedImage[] = [];
  for (const df of dockerfiles) {
    const parsed = parseFromDirectives(df);
    allParsed.push(...parsed);
  }

  const uniqueImages = new Map<string, ParsedImage>();
  for (const p of allParsed) {
    const key = `${p.image}:${p.tag}`;
    if (!uniqueImages.has(key)) uniqueImages.set(key, p);
  }

  const imageResults: ImageResult[] = [];
  let eolCount = 0;
  const bySeverity: Record<string, number> = {};
  let totalOsVulns = 0;

  for (const [, parsed] of uniqueImages) {
    const eolStatus = checkEol(parsed.image, parsed.tag);
    if (eolStatus) eolCount++;

    let vulns: ImageVulnerability[] = [];
    let osPackagesScanned = 0;

    if (trivyAvailable) {
      vulns = runTrivyScan(parsed.raw);
    } else if (dockerAvailable) {
      const packages = extractOsPackages(parsed.raw);
      osPackagesScanned = packages.length;
      if (packages.length > 0) {
        vulns = await queryOsvBatch(packages);
      }
    } else {
      errors.push(
        `Neither Docker nor Trivy available — only EOL check performed for ${parsed.raw}`
      );
    }

    for (const v of vulns) {
      bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
    }
    totalOsVulns += vulns.length;

    imageResults.push({
      image: parsed.image,
      tag: parsed.tag,
      eol_status: eolStatus,
      os_packages_scanned: osPackagesScanned,
      vulnerabilities: vulns,
    });
  }

  return {
    scan_timestamp: timestamp,
    scanner: "complyt-container",
    images: imageResults,
    summary: {
      images_scanned: imageResults.length,
      eol_images: eolCount,
      total_os_vulns: totalOsVulns,
      by_severity: bySeverity,
      docker_available: dockerAvailable,
      trivy_available: trivyAvailable,
    },
    errors,
  };
}
