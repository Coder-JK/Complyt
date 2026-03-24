import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { controls } from "@/lib/db/schema";
import { updateControlStatusSchema } from "@/lib/db/validation";
import { eq } from "drizzle-orm";

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
    .from(controls)
    .where(eq(controls.workspaceId, workspaceId))
    .all();

  return NextResponse.json(all);
}

export async function PATCH(request: NextRequest) {
  const body = await request.json();
  const { id, ...rest } = body;

  if (!id) {
    return NextResponse.json({ error: "id is required" }, { status: 400 });
  }

  const parsed = updateControlStatusSchema.safeParse(rest);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Validation failed", details: parsed.error.flatten() },
      { status: 400 }
    );
  }

  const db = getDb();
  db.update(controls)
    .set({ status: parsed.data.status })
    .where(eq(controls.id, id))
    .run();

  const updated = db.select().from(controls).where(eq(controls.id, id)).get();

  return NextResponse.json(updated);
}
