import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { getDb } from "@/lib/db";
import { cloudCredentials, workspaces } from "@/lib/db/schema";
import { eq, and } from "drizzle-orm";
import { encrypt } from "@/lib/evidence/crypto";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(
  _request: NextRequest,
  { params }: RouteContext,
) {
  const { id } = await params;
  const db = getDb();

  const workspace = db.select().from(workspaces).where(eq(workspaces.id, id)).get();
  if (!workspace) {
    return NextResponse.json({ error: "Workspace not found" }, { status: 404 });
  }

  const cred = db
    .select()
    .from(cloudCredentials)
    .where(eq(cloudCredentials.workspaceId, id))
    .get();

  if (!cred) {
    return NextResponse.json({ has_credentials: false });
  }

  return NextResponse.json({
    has_credentials: true,
    provider: cred.provider,
    region: cred.region,
    validated_at: cred.validatedAt,
  });
}

export async function POST(
  request: NextRequest,
  { params }: RouteContext,
) {
  const { id } = await params;
  const db = getDb();

  const workspace = db.select().from(workspaces).where(eq(workspaces.id, id)).get();
  if (!workspace) {
    return NextResponse.json({ error: "Workspace not found" }, { status: 404 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 });
  }

  const { provider, accessKeyId, secretAccessKey, region } = body as {
    provider?: string;
    accessKeyId?: string;
    secretAccessKey?: string;
    region?: string;
  };

  if (provider !== "aws") {
    return NextResponse.json({ error: "Only 'aws' provider is supported" }, { status: 400 });
  }

  if (!accessKeyId || !secretAccessKey || !region) {
    return NextResponse.json(
      { error: "accessKeyId, secretAccessKey, and region are required" },
      { status: 400 },
    );
  }

  const sts = new STSClient({
    region,
    credentials: { accessKeyId, secretAccessKey },
  });

  try {
    await sts.send(new GetCallerIdentityCommand({}));
  } catch (err) {
    return NextResponse.json(
      { error: "AWS credential validation failed", detail: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }

  const validatedAt = new Date().toISOString();
  const encryptedCredentials = encrypt(
    JSON.stringify({ accessKeyId, secretAccessKey, region }),
  );

  const existing = db
    .select()
    .from(cloudCredentials)
    .where(and(eq(cloudCredentials.workspaceId, id), eq(cloudCredentials.provider, "aws")))
    .get();

  if (existing) {
    db.update(cloudCredentials)
      .set({
        credentials: encryptedCredentials,
        region,
        validatedAt,
      })
      .where(eq(cloudCredentials.id, existing.id))
      .run();
  } else {
    db.insert(cloudCredentials)
      .values({
        id: crypto.randomUUID(),
        workspaceId: id,
        provider: "aws",
        credentials: encryptedCredentials,
        region,
        validatedAt,
      })
      .run();
  }

  return NextResponse.json({
    provider: "aws",
    region,
    validated_at: validatedAt,
    has_credentials: true,
  });
}

export async function DELETE(
  _request: NextRequest,
  { params }: RouteContext,
) {
  const { id } = await params;
  const db = getDb();

  const workspace = db.select().from(workspaces).where(eq(workspaces.id, id)).get();
  if (!workspace) {
    return NextResponse.json({ error: "Workspace not found" }, { status: 404 });
  }

  db.delete(cloudCredentials)
    .where(eq(cloudCredentials.workspaceId, id))
    .run();

  return NextResponse.json({ deleted: true });
}
