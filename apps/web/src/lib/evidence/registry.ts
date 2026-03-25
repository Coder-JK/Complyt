export interface ScanContext {
  workspaceId: string;
  targetDir: string;
  artifactsDir: string;
  runId: string;
}

export interface ScanResult {
  filename: string;
  artifactType: string;
  data: unknown;
  summary: Record<string, unknown>;
  errors: string[];
}

export interface ScannerDef {
  id: string;
  name: string;
  layer: "sca" | "sast" | "secrets" | "license" | "dockerfile" | "container" | "cspm" | "dast";
  builtin: boolean;
  requiresConfig?: "aws_credentials" | "dast_target_url";
  check: () => boolean;
  run: (ctx: ScanContext) => Promise<ScanResult>;
}

export interface ScannerStatus {
  id: string;
  name: string;
  layer: string;
  builtin: boolean;
  available: boolean;
  requiresConfig?: string;
  description: string;
}

const scanners: ScannerDef[] = [];

export function registerScanner(scanner: ScannerDef): void {
  scanners.push(scanner);
}

export function getAllScanners(): ScannerDef[] {
  return [...scanners];
}

export function getScannerStatuses(): ScannerStatus[] {
  return scanners.map((s) => ({
    id: s.id,
    name: s.name,
    layer: s.layer,
    builtin: s.builtin,
    available: s.check(),
    requiresConfig: s.requiresConfig,
    description: `${s.name} (${s.builtin ? "built-in" : "external tool"})`,
  }));
}
