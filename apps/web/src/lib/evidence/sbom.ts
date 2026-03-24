import fs from "fs";
import path from "path";
import crypto from "crypto";

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
  const { execSync } = await import("child_process");

  const safeDir = path.resolve(targetDir);
  if (!fs.existsSync(safeDir)) {
    throw new Error(`Target directory does not exist: ${safeDir}`);
  }

  const output = execSync(
    `"${syftPath}" dir:"${safeDir}" -o cyclonedx-json`,
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
  const ext = path.basename(lockPath);

  if (ext === "package-lock.json") {
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
  }

  return versions;
}

function cleanVersion(v: string): string {
  return v.replace(/^[\^~>=<]+/, "");
}
