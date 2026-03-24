import crypto from "crypto";
import { getDb } from "@/lib/db";
import { workspaces } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

interface ManifestArtifact {
  filename: string;
  type: string;
  content_type: string;
  size_bytes: number;
  hash: { algo: string; value: string };
  collected_at: string;
  description: string;
}

interface EvidenceManifest {
  version: string;
  generated_at: string;
  generator: { name: string; version: string };
  workspace: { id: string; name: string };
  artifacts: ManifestArtifact[];
}

const ARTIFACT_DESCRIPTIONS: Record<string, string> = {
  "sbom.json":
    "CycloneDX 1.5 Software Bill of Materials listing all software components and their versions.",
  "osv.json":
    "OSV vulnerability scan results from querying osv.dev API for known vulnerabilities in SBOM components.",
  "osv_enriched.json":
    "Vulnerability scan results enriched with CISA KEV (Known Exploited Vulnerabilities) and EPSS (Exploitation Prediction Scoring System) data.",
  "control-matrix.csv":
    "Compliance control status matrix showing all tracked controls and their current assessment status.",
  "evidence-manifest.json":
    "This file. Machine-readable manifest of all artifacts in this evidence pack with integrity hashes.",
};

export function generateManifest(
  workspaceId: string,
  files: Array<{ filename: string; type: string; content: string }>
): EvidenceManifest {
  const db = getDb();
  const ws = db
    .select()
    .from(workspaces)
    .where(eq(workspaces.id, workspaceId))
    .get();

  const artifacts: ManifestArtifact[] = files.map(
    ({ filename, type, content }) => ({
      filename,
      type,
      content_type: filename.endsWith(".csv") ? "text/csv" : "application/json",
      size_bytes: Buffer.byteLength(content, "utf-8"),
      hash: {
        algo: "sha256",
        value: crypto.createHash("sha256").update(content).digest("hex"),
      },
      collected_at: new Date().toISOString(),
      description: ARTIFACT_DESCRIPTIONS[filename] ?? "",
    })
  );

  return {
    version: "1.0.0",
    generated_at: new Date().toISOString(),
    generator: { name: "complyt", version: "0.1.0" },
    workspace: { id: workspaceId, name: ws?.name ?? "Unknown" },
    artifacts,
  };
}
