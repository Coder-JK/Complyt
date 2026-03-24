import { getDb } from "@/lib/db";
import { controls } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

export function generateControlMatrixCsv(workspaceId: string): string {
  const db = getDb();
  const rows = db
    .select()
    .from(controls)
    .where(eq(controls.workspaceId, workspaceId))
    .all();

  const headers = [
    "Control ID",
    "Title",
    "Category",
    "Description",
    "Frequency",
    "Status",
  ];

  const csvRows = rows.map((row) =>
    [
      escapeCsv(row.controlId),
      escapeCsv(row.title),
      escapeCsv(row.category ?? ""),
      escapeCsv(row.description ?? ""),
      escapeCsv(row.frequency ?? ""),
      escapeCsv(row.status),
    ].join(",")
  );

  return [headers.join(","), ...csvRows].join("\n");
}

function escapeCsv(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
