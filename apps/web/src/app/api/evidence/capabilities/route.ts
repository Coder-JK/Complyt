import { NextResponse } from "next/server";
import { isSemgrepAvailable } from "@/lib/evidence/sast";
import { isGitleaksAvailable } from "@/lib/evidence/secrets";
import { isTrivyAvailable } from "@/lib/evidence/scanners/container";

let cachedResult: Record<string, unknown> | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60_000;

export async function GET() {
  const now = Date.now();
  if (cachedResult && now - cacheTimestamp < CACHE_TTL_MS) {
    return NextResponse.json(cachedResult);
  }

  const result = {
    scanners: {
      sca: {
        name: "Dependency Scan (SCA)",
        description: "SBOM + OSV + KEV + EPSS",
        available: true,
        builtin: true,
      },
      sast: {
        name: "Code Security (SAST)",
        description: "14 built-in rules + optional Semgrep",
        available: true,
        builtin: true,
        enhanced: isSemgrepAvailable(),
      },
      secrets: {
        name: "Secret Scanning",
        description: "30 built-in rules + optional Gitleaks",
        available: true,
        builtin: true,
        enhanced: isGitleaksAvailable(),
      },
      license: {
        name: "License Compliance",
        description: "SPDX license taxonomy",
        available: true,
        builtin: true,
      },
      dockerfile: {
        name: "Dockerfile Security",
        description: "18 Dockerfile lint rules",
        available: true,
        builtin: true,
      },
      container: {
        name: "Container Scanning",
        description: "Base image + OS package CVEs",
        available: true,
        builtin: true,
        enhanced: isTrivyAvailable(),
      },
      cspm: {
        name: "Cloud Security (AWS)",
        description: "25 AWS infrastructure checks",
        available: true,
        builtin: true,
        requiresConfig: "aws_credentials",
      },
      dast: {
        name: "HTTP Security Audit",
        description: "15 header/TLS/cookie checks",
        available: true,
        builtin: true,
        requiresConfig: "dast_target_url",
      },
    },
  };

  cachedResult = result;
  cacheTimestamp = now;
  return NextResponse.json(result);
}
