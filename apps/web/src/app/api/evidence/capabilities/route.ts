import { NextResponse } from "next/server";
import { isSemgrepAvailable } from "@/lib/evidence/sast";
import { isGitleaksAvailable } from "@/lib/evidence/secrets";

export async function GET() {
  return NextResponse.json({
    scanners: {
      sca: {
        name: "Dependency Scan (SCA)",
        description: "Scans package.json dependencies against OSV.dev, enriches with CISA KEV and EPSS",
        available: true,
        builtin: true,
      },
      sast: {
        name: "Code Scan (SAST)",
        description: "Static analysis for security bugs in your code (SQL injection, XSS, insecure patterns)",
        available: isSemgrepAvailable(),
        tool: "Semgrep",
        installUrl: "https://semgrep.dev/docs/getting-started/cli-oss",
      },
      secrets: {
        name: "Secret Scan",
        description: "Detects hardcoded API keys, passwords, and tokens in source code",
        available: isGitleaksAvailable(),
        tool: "Gitleaks",
        installUrl: "https://github.com/gitleaks/gitleaks#installing",
      },
    },
  });
}
