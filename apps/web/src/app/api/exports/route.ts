import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { exports as exportsTable } from "@/lib/db/schema";
import { eq, desc } from "drizzle-orm";
import { createExportSchema } from "@/lib/db/validation";
import { generateExportZip } from "@/lib/export/zip";

export async function GET(request: NextRequest) {
  const workspaceId = request.nextUrl.searchParams.get("workspaceId");

  if (!workspaceId) {
    return NextResponse.json(
      { error: "workspaceId query parameter is required" },
      { status: 400 }
    );
  }

  const db = getDb();
  const all = db
    .select()
    .from(exportsTable)
    .where(eq(exportsTable.workspaceId, workspaceId))
    .orderBy(desc(exportsTable.createdAt))
    .all();

  return NextResponse.json(all);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const parsed = createExportSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Validation failed", details: parsed.error.flatten() },
      { status: 400 }
    );
  }

  const result = await generateExportZip(
    parsed.data.workspaceId,
    parsed.data.name ?? undefined
  );

  return NextResponse.json(result, { status: 201 });
}
