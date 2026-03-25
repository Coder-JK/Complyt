import { z } from "zod";

export const controlStatusEnum = z.enum([
  "not_started",
  "in_progress",
  "met",
  "not_met",
]);
export type ControlStatus = z.infer<typeof controlStatusEnum>;

export const evidenceRunTypeEnum = z.enum([
  "sbom",
  "osv_scan",
  "kev_enrichment",
  "epss_enrichment",
  "full_pack",
]);
export type EvidenceRunType = z.infer<typeof evidenceRunTypeEnum>;

export const evidenceRunStatusEnum = z.enum([
  "pending",
  "running",
  "completed",
  "failed",
]);
export type EvidenceRunStatus = z.infer<typeof evidenceRunStatusEnum>;

export const artifactTypeEnum = z.enum([
  "sbom",
  "osv_scan",
  "osv_enriched",
  "kev_data",
  "epss_data",
  "control_matrix",
  "evidence_manifest",
  "sast",
  "secrets",
  "license_audit",
  "dockerfile_lint",
  "container_scan",
  "cspm",
  "dast",
]);
export type ArtifactType = z.infer<typeof artifactTypeEnum>;

export const createWorkspaceSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  targetDir: z.string().max(500).optional(),
  dastTargetUrl: z.string().optional(),
});

export const updateWorkspaceSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).optional(),
  targetDir: z.string().max(500).optional(),
  dastTargetUrl: z.string().optional(),
});

export const createControlSchema = z.object({
  controlId: z.string().min(1).max(50),
  title: z.string().min(1).max(255),
  description: z.string().max(2000).optional(),
  category: z.string().max(100).optional(),
  frequency: z.string().max(50).optional(),
  status: controlStatusEnum.optional(),
});

export const updateControlStatusSchema = z.object({
  status: controlStatusEnum,
});

export const startEvidenceRunSchema = z.object({
  workspaceId: z.string().min(1),
  type: evidenceRunTypeEnum,
});

export const createExportSchema = z.object({
  workspaceId: z.string().min(1),
  name: z.string().min(1).max(255).optional(),
});
