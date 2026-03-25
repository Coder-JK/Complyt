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

  const stat = fs.statSync(fullPath);
  const stream = fs.createReadStream(fullPath);
  const readable = new ReadableStream({
    start(controller) {
      stream.on("data", (chunk: Buffer | string) => {
        const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        controller.enqueue(new Uint8Array(buf));
      });
      stream.on("end", () => controller.close());
      stream.on("error", (err) => controller.error(err));
    },
  });

  return new NextResponse(readable, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${exp.filename}"`,
      "Content-Length": String(stat.size),
    },
  });
}
