import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { evidenceRuns, evidenceArtifacts } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const db = getDb();

  const run = db
    .select()
    .from(evidenceRuns)
    .where(eq(evidenceRuns.id, id))
    .get();

  if (!run) {
    return NextResponse.json({ error: "Run not found" }, { status: 404 });
  }

  const artifacts = db
    .select()
    .from(evidenceArtifacts)
    .where(eq(evidenceArtifacts.runId, id))
    .all();

  return NextResponse.json({ ...run, artifacts });
}
