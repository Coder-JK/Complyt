import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { sql } from "drizzle-orm";

export const workspaces = sqliteTable("workspaces", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  targetDir: text("target_dir"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
  updatedAt: text("updated_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const controls = sqliteTable("controls", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id")
    .notNull()
    .references(() => workspaces.id, { onDelete: "cascade" }),
  controlId: text("control_id").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  category: text("category"),
  frequency: text("frequency"),
  status: text("status", {
    enum: ["not_started", "in_progress", "met", "not_met"],
  })
    .notNull()
    .default("not_started"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const evidenceRuns = sqliteTable("evidence_runs", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id")
    .notNull()
    .references(() => workspaces.id, { onDelete: "cascade" }),
  type: text("type", {
    enum: ["sbom", "osv_scan", "kev_enrichment", "epss_enrichment", "full_pack"],
  }).notNull(),
  status: text("status", {
    enum: ["pending", "running", "completed", "failed"],
  })
    .notNull()
    .default("pending"),
  startedAt: text("started_at"),
  completedAt: text("completed_at"),
  error: text("error"),
  metadata: text("metadata"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const evidenceArtifacts = sqliteTable("evidence_artifacts", {
  id: text("id").primaryKey(),
  runId: text("run_id")
    .notNull()
    .references(() => evidenceRuns.id, { onDelete: "cascade" }),
  workspaceId: text("workspace_id")
    .notNull()
    .references(() => workspaces.id, { onDelete: "cascade" }),
  type: text("type", {
    enum: [
      "sbom",
      "osv_scan",
      "osv_enriched",
      "kev_data",
      "epss_data",
      "control_matrix",
      "evidence_manifest",
    ],
  }).notNull(),
  filename: text("filename").notNull(),
  contentType: text("content_type").notNull().default("application/json"),
  sizeBytes: integer("size_bytes"),
  hashAlgo: text("hash_algo").default("sha256"),
  hashValue: text("hash_value"),
  storagePath: text("storage_path").notNull(),
  collectedAt: text("collected_at").notNull(),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const exports = sqliteTable("exports", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id")
    .notNull()
    .references(() => workspaces.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  filename: text("filename").notNull(),
  format: text("format").notNull().default("zip"),
  storagePath: text("storage_path").notNull(),
  sizeBytes: integer("size_bytes"),
  artifactIds: text("artifact_ids"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export type Workspace = typeof workspaces.$inferSelect;
export type NewWorkspace = typeof workspaces.$inferInsert;
export type Control = typeof controls.$inferSelect;
export type NewControl = typeof controls.$inferInsert;
export type EvidenceRun = typeof evidenceRuns.$inferSelect;
export type NewEvidenceRun = typeof evidenceRuns.$inferInsert;
export type EvidenceArtifact = typeof evidenceArtifacts.$inferSelect;
export type NewEvidenceArtifact = typeof evidenceArtifacts.$inferInsert;
export type Export = typeof exports.$inferSelect;
export type NewExport = typeof exports.$inferInsert;
