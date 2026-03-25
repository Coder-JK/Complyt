import fs from "fs";
import path from "path";
import crypto from "crypto";
import { getDb } from "@/lib/db";
import {
  evidenceRuns,
  evidenceArtifacts,
  cloudCredentials,
} from "@/lib/db/schema";
import { eq } from "drizzle-orm";
import { generateSbom } from "./sbom";
import { scanWithOsv } from "./osv";
import { fetchKev } from "./kev";
import { fetchEpssScores } from "./epss";
import { enrichOsvResults } from "./enrich";
import { OfflineError, isOffline } from "./http";
import { isSemgrepAvailable, runSemgrepScan } from "./sast";
import { isGitleaksAvailable, runGitleaksScan } from "./secrets";
import { runBuiltinSecretScan } from "./scanners/secrets-builtin";
import { runBuiltinSastScan } from "./scanners/sast-builtin";
import { runLicenseScan } from "./scanners/license";
import { runDockerfileLint } from "./scanners/dockerfile";
import { runContainerScan } from "./scanners/container";
import { runCspmAwsScan } from "./scanners/cspm-aws";
import { runBuiltinDastScan } from "./scanners/dast-builtin";
import { decrypt } from "./crypto";

interface StepStatus {
  status: "completed" | "skipped" | "failed" | "not_configured";
  reason?: string;
  summary?: Record<string, unknown>;
  duration_ms?: number;
}

interface PipelineResult {
  runId: string;
  status: "completed" | "failed";
  error?: string;
  artifactCount: number;
  offline: boolean;
  steps: Record<string, StepStatus>;
}

type ArtifactType =
  | "sbom"
  | "osv_scan"
  | "osv_enriched"
  | "kev_data"
  | "epss_data"
  | "control_matrix"
  | "evidence_manifest"
  | "sast"
  | "secrets"
  | "license_audit"
  | "dockerfile_lint"
  | "container_scan"
  | "cspm"
  | "dast";

export async function runEvidencePipeline(
  workspaceId: string,
  targetDir?: string,
  dastTargetUrl?: string,
): Promise<PipelineResult> {
  const db = getDb();
  const runId = crypto.randomUUID();
  const now = new Date().toISOString();
  let offline = isOffline();
  let artifactCount = 0;
  const steps: Record<string, StepStatus> = {};

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

  const artifactsDir = path.resolve(process.cwd(), "data", "artifacts", runId);
  fs.mkdirSync(artifactsDir, { recursive: true });

  const scanDir = targetDir || process.cwd();
  const pkgJsonPath = path.join(scanDir, "package.json");

  if (!fs.existsSync(scanDir)) {
    const msg = `Target directory does not exist: ${scanDir}\n\nGo to Settings and set a valid project directory for this workspace.`;
    db.update(evidenceRuns)
      .set({ status: "failed", completedAt: new Date().toISOString(), error: msg })
      .where(eq(evidenceRuns.id, runId))
      .run();
    return { runId, status: "failed", error: msg, artifactCount: 0, offline, steps };
  }

  if (!fs.existsSync(pkgJsonPath)) {
    const msg = `No package.json found at ${pkgJsonPath}\n\nComplyt needs a package.json to generate an SBOM. Make sure the workspace target directory points to your project root.`;
    db.update(evidenceRuns)
      .set({ status: "failed", completedAt: new Date().toISOString(), error: msg })
      .where(eq(evidenceRuns.id, runId))
      .run();
    return { runId, status: "failed", error: msg, artifactCount: 0, offline, steps };
  }

  // -------------------------------------------------------------------------
  // Step 1: SBOM (always — local operation)
  // -------------------------------------------------------------------------
  let sbom: Awaited<ReturnType<typeof generateSbom>> | null = null;
  {
    const t0 = Date.now();
    try {
      sbom = await generateSbom(scanDir);
      artifactCount += await saveArtifact(db, runId, workspaceId, "sbom", "sbom.json", sbom, artifactsDir);
      steps.sbom = {
        status: "completed",
        duration_ms: Date.now() - t0,
        summary: { components: sbom.components.length },
      };
    } catch (err) {
      steps.sbom = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t0,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 2: SCA / OSV (skip if offline)
  // -------------------------------------------------------------------------
  let osvScan: Awaited<ReturnType<typeof scanWithOsv>> | null = null;
  let enriched: ReturnType<typeof enrichOsvResults> | null = null;
  {
    const t0 = Date.now();
    if (offline) {
      steps.osv = { status: "skipped", reason: "Offline mode", duration_ms: 0 };
    } else if (!sbom) {
      steps.osv = { status: "skipped", reason: "SBOM generation failed", duration_ms: 0 };
    } else {
      try {
        osvScan = await scanWithOsv(sbom.components);
        artifactCount += await saveArtifact(db, runId, workspaceId, "osv_scan", "osv.json", osvScan, artifactsDir);

        if (osvScan.summary.total_vulnerabilities > 0) {
          const allCves = extractCves(osvScan);
          let kevMap = new Map<string, import("./kev").KevEntry>();
          try {
            kevMap = await fetchKev();
          } catch (e) {
            if (e instanceof OfflineError) offline = true;
          }

          let epssMap = new Map<string, import("./epss").EpssEntry>();
          try {
            epssMap = await fetchEpssScores(allCves);
          } catch (e) {
            if (e instanceof OfflineError) offline = true;
          }

          enriched = enrichOsvResults(osvScan, kevMap, epssMap);
          artifactCount += await saveArtifact(db, runId, workspaceId, "osv_enriched", "osv_enriched.json", enriched, artifactsDir);
        }

        steps.osv = {
          status: "completed",
          duration_ms: Date.now() - t0,
          summary: {
            total_vulnerabilities: osvScan.summary.total_vulnerabilities,
            kev_matches: enriched?.summary.kev_matches ?? 0,
          },
        };
      } catch (err) {
        if (err instanceof OfflineError) {
          offline = true;
          steps.osv = { status: "skipped", reason: "Network unavailable", duration_ms: Date.now() - t0 };
        } else {
          steps.osv = {
            status: "failed",
            reason: err instanceof Error ? err.message : String(err),
            duration_ms: Date.now() - t0,
          };
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 3: Built-in Secret Scan (always — local)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    try {
      const secretsResult = runBuiltinSecretScan(scanDir);
      artifactCount += await saveArtifact(db, runId, workspaceId, "secrets", "secrets.json", secretsResult, artifactsDir);
      steps.secrets = {
        status: "completed",
        duration_ms: Date.now() - t0,
        summary: { total: secretsResult.summary.total, by_severity: secretsResult.summary.by_severity },
      };
    } catch (err) {
      steps.secrets = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t0,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 4: Built-in SAST Scan (always — local)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    try {
      const sastResult = runBuiltinSastScan(scanDir);
      artifactCount += await saveArtifact(db, runId, workspaceId, "sast", "sast.json", sastResult, artifactsDir);
      steps.sast = {
        status: "completed",
        duration_ms: Date.now() - t0,
        summary: { total_findings: sastResult.summary.total_findings, by_severity: sastResult.summary.by_severity },
      };
    } catch (err) {
      steps.sast = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t0,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 5: License Compliance (always — needs SBOM)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    if (!sbom) {
      steps.license = { status: "skipped", reason: "SBOM generation failed", duration_ms: 0 };
    } else {
      try {
        const licenseResult = runLicenseScan(sbom, scanDir);
        artifactCount += await saveArtifact(db, runId, workspaceId, "license_audit", "license-audit.json", licenseResult, artifactsDir);
        steps.license = {
          status: "completed",
          duration_ms: Date.now() - t0,
          summary: {
            total_packages: licenseResult.total_packages,
            blocked: licenseResult.summary.blocked,
            unknown: licenseResult.summary.unknown,
          },
        };
      } catch (err) {
        steps.license = {
          status: "failed",
          reason: err instanceof Error ? err.message : String(err),
          duration_ms: Date.now() - t0,
        };
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 6: Dockerfile Lint (always — local)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    try {
      const dockerResult = runDockerfileLint(scanDir);
      artifactCount += await saveArtifact(db, runId, workspaceId, "dockerfile_lint", "dockerfile-lint.json", dockerResult, artifactsDir);
      steps.dockerfile = {
        status: "completed",
        duration_ms: Date.now() - t0,
        summary: { total_findings: dockerResult.summary.total_findings, dockerfiles_found: dockerResult.dockerfiles_found },
      };
    } catch (err) {
      steps.dockerfile = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t0,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 7: Container Scan (always — local)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    try {
      const containerResult = await runContainerScan(scanDir);
      artifactCount += await saveArtifact(db, runId, workspaceId, "container_scan", "container-scan.json", containerResult, artifactsDir);
      steps.container = {
        status: "completed",
        duration_ms: Date.now() - t0,
        summary: {
          images_scanned: containerResult.summary.images_scanned,
          total_os_vulns: containerResult.summary.total_os_vulns,
        },
      };
    } catch (err) {
      steps.container = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t0,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 8: AWS CSPM (only if credentials configured)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    try {
      const cred = db
        .select()
        .from(cloudCredentials)
        .where(eq(cloudCredentials.workspaceId, workspaceId))
        .get();

      if (!cred) {
        const statusArtifact = { status: "not_configured", message: "Add AWS credentials in Settings" };
        artifactCount += await saveArtifact(db, runId, workspaceId, "cspm", "cspm-aws.json", statusArtifact, artifactsDir);
        steps.cspm = { status: "not_configured", reason: "No AWS credentials configured", duration_ms: Date.now() - t0 };
      } else {
        const decrypted = JSON.parse(decrypt(cred.credentials));
        const cspmResult = await runCspmAwsScan(decrypted);
        artifactCount += await saveArtifact(db, runId, workspaceId, "cspm", "cspm-aws.json", cspmResult, artifactsDir);
        steps.cspm = {
          status: "completed",
          duration_ms: Date.now() - t0,
          summary: {
            total_checks: cspmResult.summary.total_checks,
            passed: cspmResult.summary.passed,
            failed: cspmResult.summary.failed,
          },
        };
      }
    } catch (err) {
      steps.cspm = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t0,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 9: DAST (only if target URL configured)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    if (!dastTargetUrl) {
      const statusArtifact = { status: "not_configured", message: "Set a DAST target URL in workspace settings" };
      artifactCount += await saveArtifact(db, runId, workspaceId, "dast", "dast.json", statusArtifact, artifactsDir);
      steps.dast = { status: "not_configured", reason: "No DAST target URL configured", duration_ms: Date.now() - t0 };
    } else {
      try {
        const dastResult = await runBuiltinDastScan(dastTargetUrl);
        artifactCount += await saveArtifact(db, runId, workspaceId, "dast", "dast.json", dastResult, artifactsDir);
        steps.dast = {
          status: "completed",
          duration_ms: Date.now() - t0,
          summary: { total: dastResult.summary.total, passed: dastResult.summary.passed, failed: dastResult.summary.failed },
        };
      } catch (err) {
        steps.dast = {
          status: "failed",
          reason: err instanceof Error ? err.message : String(err),
          duration_ms: Date.now() - t0,
        };
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 10: Enhanced scanners (Semgrep + Gitleaks merge)
  // -------------------------------------------------------------------------
  {
    const t0 = Date.now();
    try {
      if (isSemgrepAvailable()) {
        const semgrepResult = runSemgrepScan(scanDir);
        artifactCount += await saveArtifact(db, runId, workspaceId, "sast", "sast-semgrep.json", semgrepResult, artifactsDir);
        steps.sast_semgrep = {
          status: "completed",
          duration_ms: Date.now() - t0,
          summary: { findings: semgrepResult.summary.total_findings, by_severity: semgrepResult.summary.by_severity },
        };
      } else {
        steps.sast_semgrep = { status: "skipped", reason: "Semgrep not installed", duration_ms: Date.now() - t0 };
      }
    } catch (err) {
      steps.sast_semgrep = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t0,
      };
    }

    const t1 = Date.now();
    try {
      if (isGitleaksAvailable()) {
        const gitleaksResult = runGitleaksScan(scanDir);
        artifactCount += await saveArtifact(db, runId, workspaceId, "secrets", "secrets-gitleaks.json", gitleaksResult, artifactsDir);
        steps.secrets_gitleaks = {
          status: "completed",
          duration_ms: Date.now() - t1,
          summary: { findings: gitleaksResult.summary.total_findings, by_rule: gitleaksResult.summary.by_rule },
        };
      } else {
        steps.secrets_gitleaks = { status: "skipped", reason: "Gitleaks not installed", duration_ms: Date.now() - t1 };
      }
    } catch (err) {
      steps.secrets_gitleaks = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - t1,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Complete run
  // -------------------------------------------------------------------------
  db.update(evidenceRuns)
    .set({
      status: "completed",
      completedAt: new Date().toISOString(),
      metadata: JSON.stringify({ offline, artifactCount, steps }),
    })
    .where(eq(evidenceRuns.id, runId))
    .run();

  return { runId, status: "completed", artifactCount, offline, steps };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function saveArtifact(
  db: ReturnType<typeof getDb>,
  runId: string,
  workspaceId: string,
  type: ArtifactType,
  filename: string,
  data: unknown,
  artifactsDir: string,
): Promise<number> {
  const json = JSON.stringify(data, null, 2);
  const filePath = path.join(artifactsDir, filename);
  fs.writeFileSync(filePath, json, "utf-8");

  const hash = crypto.createHash("sha256").update(json).digest("hex");
  const stat = fs.statSync(filePath);
  const storagePath = path.relative(
    path.resolve(process.cwd(), "data"),
    filePath,
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
