import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { workspaces, controls } from "@/lib/db/schema";
import { createWorkspaceSchema } from "@/lib/db/validation";
import { getStarterControls } from "@/lib/db/seed-controls";
import { desc } from "drizzle-orm";

export async function GET() {
  const db = getDb();
  const all = db.select().from(workspaces).orderBy(desc(workspaces.createdAt)).all();
  return NextResponse.json(all);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const parsed = createWorkspaceSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Validation failed", details: parsed.error.flatten() },
      { status: 400 }
    );
  }

  const db = getDb();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const workspace = {
    id,
    name: parsed.data.name,
    description: parsed.data.description ?? null,
    targetDir: parsed.data.targetDir ?? null,
    createdAt: now,
    updatedAt: now,
  };

  db.insert(workspaces).values(workspace).run();

  const starterControls = getStarterControls(id);
  if (starterControls.length > 0) {
    db.insert(controls).values(starterControls).run();
  }

  return NextResponse.json(workspace, { status: 201 });
}
