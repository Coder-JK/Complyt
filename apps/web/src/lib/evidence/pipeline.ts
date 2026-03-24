import fs from "fs";
import path from "path";
import crypto from "crypto";
import { getDb } from "@/lib/db";
import { evidenceRuns, evidenceArtifacts } from "@/lib/db/schema";
import { eq } from "drizzle-orm";
import { generateSbom } from "./sbom";
import { scanWithOsv } from "./osv";
import { fetchKev } from "./kev";
import { fetchEpssScores } from "./epss";
import { enrichOsvResults } from "./enrich";
import { OfflineError } from "./http";
import { isOffline } from "./http";

interface PipelineResult {
  runId: string;
  status: "completed" | "failed";
  error?: string;
  artifactCount: number;
  offline: boolean;
}

export async function runEvidencePipeline(
  workspaceId: string,
  targetDir?: string
): Promise<PipelineResult> {
  const db = getDb();
  const runId = crypto.randomUUID();
  const now = new Date().toISOString();
  let offline = isOffline();

  db.insert(evidenceRuns)
    .values({
      id: runId,
      workspaceId,
      type: "full_pack",
      status: "running",
      startedAt: now,
      createdAt: now,
    })
    .run();

  const artifactsDir = path.resolve(
    process.cwd(),
    "data",
    "artifacts",
    runId
  );
  fs.mkdirSync(artifactsDir, { recursive: true });

  let artifactCount = 0;

  try {
    const scanDir = targetDir || process.cwd();

    // Step 1: Generate SBOM
    const sbom = await generateSbom(scanDir);
    artifactCount += await saveArtifact(
      db,
      runId,
      workspaceId,
      "sbom",
      "sbom.json",
      sbom,
      artifactsDir
    );

    if (offline) {
      db.update(evidenceRuns)
        .set({
          status: "completed",
          completedAt: new Date().toISOString(),
          metadata: JSON.stringify({ offline: true, artifactCount }),
        })
        .where(eq(evidenceRuns.id, runId))
        .run();

      return { runId, status: "completed", artifactCount, offline: true };
    }

    // Step 2: OSV Scan
    let osvScan;
    try {
      osvScan = await scanWithOsv(sbom.components);
      artifactCount += await saveArtifact(
        db,
        runId,
        workspaceId,
        "osv_scan",
        "osv.json",
        osvScan,
        artifactsDir
      );
    } catch (error) {
      if (error instanceof OfflineError) {
        offline = true;
        osvScan = null;
      } else {
        throw error;
      }
    }

    if (!osvScan || osvScan.summary.total_vulnerabilities === 0) {
      db.update(evidenceRuns)
        .set({
          status: "completed",
          completedAt: new Date().toISOString(),
          metadata: JSON.stringify({ offline, artifactCount }),
        })
        .where(eq(evidenceRuns.id, runId))
        .run();

      return { runId, status: "completed", artifactCount, offline };
    }

    // Step 3: KEV + EPSS Enrichment
    const allCves = extractCves(osvScan);

    let kevMap = new Map();
    try {
      kevMap = await fetchKev();
    } catch (error) {
      if (error instanceof OfflineError) offline = true;
    }

    let epssMap = new Map();
    try {
      epssMap = await fetchEpssScores(allCves);
    } catch (error) {
      if (error instanceof OfflineError) offline = true;
    }

    const enriched = enrichOsvResults(osvScan, kevMap, epssMap);
    artifactCount += await saveArtifact(
      db,
      runId,
      workspaceId,
      "osv_enriched",
      "osv_enriched.json",
      enriched,
      artifactsDir
    );

    db.update(evidenceRuns)
      .set({
        status: "completed",
        completedAt: new Date().toISOString(),
        metadata: JSON.stringify({
          offline,
          artifactCount,
          summary: enriched.summary,
        }),
      })
      .where(eq(evidenceRuns.id, runId))
      .run();

    return { runId, status: "completed", artifactCount, offline };
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : String(error);

    db.update(evidenceRuns)
      .set({
        status: "failed",
        completedAt: new Date().toISOString(),
        error: errorMessage,
      })
      .where(eq(evidenceRuns.id, runId))
      .run();

    return {
      runId,
      status: "failed",
      error: errorMessage,
      artifactCount,
      offline,
    };
  }
}

type ArtifactType = "sbom" | "osv_scan" | "osv_enriched" | "kev_data" | "epss_data" | "control_matrix" | "evidence_manifest";

async function saveArtifact(
  db: ReturnType<typeof getDb>,
  runId: string,
  workspaceId: string,
  type: ArtifactType,
  filename: string,
  data: unknown,
  artifactsDir: string
): Promise<number> {
  const json = JSON.stringify(data, null, 2);
  const filePath = path.join(artifactsDir, filename);
  fs.writeFileSync(filePath, json, "utf-8");

  const hash = crypto.createHash("sha256").update(json).digest("hex");
  const stat = fs.statSync(filePath);
  const storagePath = path.relative(
    path.resolve(process.cwd(), "data"),
    filePath
  );

  db.insert(evidenceArtifacts)
    .values({
      id: crypto.randomUUID(),
      runId,
      workspaceId,
      type,
      filename,
      contentType: "application/json",
      sizeBytes: stat.size,
      hashAlgo: "sha256",
      hashValue: hash,
      storagePath,
      collectedAt: new Date().toISOString(),
    })
    .run();

  return 1;
}

function extractCves(osvScan: {
  results: Array<{
    vulnerabilities: Array<{ id: string; aliases?: string[] }>;
  }>;
}): string[] {
  const cves = new Set<string>();
  for (const result of osvScan.results) {
    for (const vuln of result.vulnerabilities) {
      const allIds = [vuln.id, ...(vuln.aliases ?? [])];
      for (const id of allIds) {
        if (id.startsWith("CVE-")) cves.add(id);
      }
    }
  }
  return [...cves];
}
