import { NextRequest, NextResponse } from "next/server";
import { startEvidenceRunSchema } from "@/lib/db/validation";
import { getDb } from "@/lib/db";
import { workspaces } from "@/lib/db/schema";
import { eq } from "drizzle-orm";
import { runEvidencePipeline } from "@/lib/evidence/pipeline";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const parsed = startEvidenceRunSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Validation failed", details: parsed.error.flatten() },
      { status: 400 }
    );
  }

  const db = getDb();
  const workspace = db
    .select()
    .from(workspaces)
    .where(eq(workspaces.id, parsed.data.workspaceId))
    .get();

  if (!workspace) {
    return NextResponse.json(
      { error: "Workspace not found" },
      { status: 404 }
    );
  }

  const scanDir = workspace.targetDir ?? undefined;

  const result = await runEvidencePipeline(workspace.id, scanDir);

  return NextResponse.json(
    { ...result, scannedDirectory: scanDir || "(Complyt project itself)" },
    { status: result.status === "completed" ? 200 : 500 }
  );
}
