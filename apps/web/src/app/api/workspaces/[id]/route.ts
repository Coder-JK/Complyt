import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { workspaces } from "@/lib/db/schema";
import { updateWorkspaceSchema } from "@/lib/db/validation";
import { eq } from "drizzle-orm";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const db = getDb();
  const workspace = db
    .select()
    .from(workspaces)
    .where(eq(workspaces.id, id))
    .get();

  if (!workspace) {
    return NextResponse.json({ error: "Workspace not found" }, { status: 404 });
  }

  return NextResponse.json(workspace);
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json();
  const parsed = updateWorkspaceSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Validation failed", details: parsed.error.flatten() },
      { status: 400 }
    );
  }

  const db = getDb();
  const existing = db
    .select()
    .from(workspaces)
    .where(eq(workspaces.id, id))
    .get();

  if (!existing) {
    return NextResponse.json({ error: "Workspace not found" }, { status: 404 });
  }

  const updates: Record<string, string> = {
    updatedAt: new Date().toISOString(),
  };
  if (parsed.data.name !== undefined) updates.name = parsed.data.name;
  if (parsed.data.description !== undefined)
    updates.description = parsed.data.description;
  if (parsed.data.targetDir !== undefined)
    updates.targetDir = parsed.data.targetDir;

  db.update(workspaces).set(updates).where(eq(workspaces.id, id)).run();

  const updated = db
    .select()
    .from(workspaces)
    .where(eq(workspaces.id, id))
    .get();

  return NextResponse.json(updated);
}
