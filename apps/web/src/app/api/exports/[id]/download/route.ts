import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { exports as exportsTable } from "@/lib/db/schema";
import { eq } from "drizzle-orm";
import fs from "fs";
import path from "path";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const db = getDb();

  const exp = db
    .select()
    .from(exportsTable)
    .where(eq(exportsTable.id, id))
    .get();

  if (!exp) {
    return NextResponse.json({ error: "Export not found" }, { status: 404 });
  }

  const fullPath = path.resolve(process.cwd(), "data", exp.storagePath);

  if (!fs.existsSync(fullPath)) {
    return NextResponse.json(
      { error: "Export file not found on disk" },
      { status: 404 }
    );
  }

  const fileBuffer = fs.readFileSync(fullPath);

  return new NextResponse(fileBuffer, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${exp.filename}"`,
      "Content-Length": String(fileBuffer.length),
    },
  });
}
