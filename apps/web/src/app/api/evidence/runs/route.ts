import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { evidenceRuns } from "@/lib/db/schema";
import { eq, desc } from "drizzle-orm";

export async function GET(request: NextRequest) {
  const workspaceId = request.nextUrl.searchParams.get("workspaceId");

  if (!workspaceId) {
    return NextResponse.json(
      { error: "workspaceId query parameter is required" },
      { status: 400 }
    );
  }

  const db = getDb();
  const runs = db
    .select()
    .from(evidenceRuns)
    .where(eq(evidenceRuns.workspaceId, workspaceId))
    .orderBy(desc(evidenceRuns.createdAt))
    .all();

  return NextResponse.json(runs);
}
