import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execFileSync } from "child_process";

interface CycloneDxComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
  "bom-ref": string;
}

interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: { name: string; version: string }[];
    component?: { type: string; name: string; version: string };
  };
  components: CycloneDxComponent[];
}

export async function generateSbom(targetDir: string): Promise<CycloneDxBom> {
  const syftPath = process.env.SYFT_PATH;

  if (syftPath && fs.existsSync(syftPath)) {
    return generateWithSyft(syftPath, targetDir);
  }

  return generateFromPackageJson(targetDir);
}

async function generateWithSyft(
  syftPath: string,
  targetDir: string
): Promise<CycloneDxBom> {
  const safeDir = path.resolve(targetDir);
  if (!fs.existsSync(safeDir)) {
    throw new Error(`Target directory does not exist: ${safeDir}`);
  }

  const output = execFileSync(
    syftPath,
    ["dir:" + safeDir, "-o", "cyclonedx-json"],
    {
      timeout: 60000,
      maxBuffer: 50 * 1024 * 1024,
      encoding: "utf-8",
    }
  );

  return JSON.parse(output);
}

function generateFromPackageJson(targetDir: string): CycloneDxBom {
  const pkgPath = path.join(targetDir, "package.json");
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`No package.json found at ${pkgPath}`);
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  const allDeps: Record<string, string> = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
  };

  const lockPath = findLockfile(targetDir);
  const resolvedVersions = lockPath
    ? extractVersionsFromLock(lockPath)
    : new Map<string, string>();

  const components: CycloneDxComponent[] = Object.entries(allDeps).map(
    ([name, versionRange]) => {
      const version =
        resolvedVersions.get(name) ?? cleanVersion(versionRange);
      return {
        type: "library" as const,
        name,
        version,
        purl: `pkg:npm/${encodeURIComponent(name)}@${version}`,
        "bom-ref": `pkg:npm/${encodeURIComponent(name)}@${version}`,
      };
    }
  );

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: "complyt", version: "0.1.0" }],
      component: {
        type: "application",
        name: pkg.name ?? "unknown",
        version: pkg.version ?? "0.0.0",
      },
    },
    components,
  };
}

function findLockfile(dir: string): string | null {
  const candidates = [
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
  ];
  for (const name of candidates) {
    const p = path.join(dir, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function extractVersionsFromLock(lockPath: string): Map<string, string> {
  const versions = new Map<string, string>();
  const filename = path.basename(lockPath);

  if (filename === "package-lock.json") {
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));
      const packages = lock.packages ?? {};
      for (const [key, value] of Object.entries(packages)) {
        if (key.startsWith("node_modules/")) {
          const name = key.replace("node_modules/", "");
          versions.set(name, (value as { version?: string }).version ?? "");
        }
      }
    } catch {
      // Malformed lock file
    }
  } else if (filename === "pnpm-lock.yaml") {
    try {
      const content = fs.readFileSync(lockPath, "utf-8");
      const lines = content.split("\n");
      for (const line of lines) {
        const match = line.match(
          /^\s+\/?(@?[^@\s]+(?:\/[^@\s]+)?)@(\d+\.\d+\.\d+[^:\s]*?):/
        );
        if (match) {
          versions.set(match[1], match[2]);
        }
      }
    } catch {
      // Malformed lock file
    }
  } else if (filename === "yarn.lock") {
    try {
      const content = fs.readFileSync(lockPath, "utf-8");
      const lines = content.split("\n");
      let currentPackage: string | null = null;
      for (const line of lines) {
        const headerMatch = line.match(/^"?(@?[^@\s"]+)@[^:]+:?\s*$/);
        if (headerMatch) {
          currentPackage = headerMatch[1];
          continue;
        }
        if (currentPackage) {
          const versionMatch = line.match(/^\s+version\s+"([^"]+)"/);
          if (versionMatch) {
            versions.set(currentPackage, versionMatch[1]);
            currentPackage = null;
          }
        }
        if (line.trim() === "") {
          currentPackage = null;
        }
      }
    } catch {
      // Malformed lock file
    }
  }

  return versions;
}

function cleanVersion(v: string): string {
  return v.replace(/^[\^~>=<]+/, "");
}
