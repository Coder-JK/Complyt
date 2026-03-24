"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Loader2, Play, ChevronDown, ChevronUp, AlertTriangle, FolderOpen } from "lucide-react";
import Link from "next/link";

interface Workspace {
  id: string;
  name: string;
  targetDir: string | null;
}

interface Artifact {
  id: string;
  type: string;
  filename: string;
  sizeBytes: number | null;
  hashValue: string | null;
  collectedAt: string;
}

interface EvidenceRun {
  id: string;
  type: string;
  status: string;
  startedAt: string | null;
  completedAt: string | null;
  error: string | null;
  metadata: string | null;
  createdAt: string;
  artifacts?: Artifact[];
}

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  completed: "default",
  running: "outline",
  pending: "secondary",
  failed: "destructive",
};

interface ScannerCapability {
  name: string;
  description: string;
  available: boolean;
  builtin?: boolean;
  tool?: string;
  installUrl?: string;
}

export default function EvidencePage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWs, setSelectedWs] = useState("");
  const [runs, setRuns] = useState<EvidenceRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [expandedRun, setExpandedRun] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState<Record<string, ScannerCapability>>({});

  const fetchCapabilities = useCallback(async () => {
    try {
      const res = await fetch("/api/evidence/capabilities");
      const data = await res.json();
      setCapabilities(data.scanners || {});
    } catch {
      // non-critical
    }
  }, []);

  const fetchWorkspaces = useCallback(async () => {
    const res = await fetch("/api/workspaces");
    const data = await res.json();
    setWorkspaces(data);
    if (data.length > 0 && !selectedWs) setSelectedWs(data[0].id);
    setLoading(false);
  }, [selectedWs]);

  const fetchRuns = useCallback(async () => {
    if (!selectedWs) return;
    const res = await fetch(`/api/evidence/runs?workspaceId=${selectedWs}`);
    const data = await res.json();
    setRuns(Array.isArray(data) ? data : []);
  }, [selectedWs]);

  useEffect(() => {
    fetchWorkspaces();
    fetchCapabilities();
  }, [fetchWorkspaces, fetchCapabilities]);

  useEffect(() => {
    if (selectedWs) fetchRuns();
  }, [selectedWs, fetchRuns]);

  async function startRun() {
    if (!selectedWs) return;
    setRunning(true);
    await fetch("/api/evidence/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ workspaceId: selectedWs, type: "full_pack" }),
    });
    await fetchRuns();
    setRunning(false);
  }

  async function toggleExpand(runId: string) {
    if (expandedRun === runId) {
      setExpandedRun(null);
      return;
    }
    const res = await fetch(`/api/evidence/runs/${runId}`);
    const data = await res.json();
    setRuns((prev) =>
      prev.map((r) => (r.id === runId ? { ...r, artifacts: data.artifacts } : r))
    );
    setExpandedRun(runId);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">
            Evidence Runs
          </h2>
          <p className="text-muted-foreground">
            Run evidence collection pipelines and view results.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {workspaces.length > 1 && (
            <select
              value={selectedWs}
              onChange={(e) => setSelectedWs(e.target.value)}
              className="rounded-md border bg-background px-3 py-1.5 text-sm"
              aria-label="Select workspace"
            >
              {workspaces.map((ws) => (
                <option key={ws.id} value={ws.id}>
                  {ws.name}
                </option>
              ))}
            </select>
          )}
          <Button
            onClick={startRun}
            disabled={running || !selectedWs}
          >
            {running ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Play className="mr-2 h-4 w-4" />
            )}
            Run Evidence Pack
          </Button>
        </div>
      </div>

      {selectedWs && (() => {
        const activeWs = workspaces.find((w) => w.id === selectedWs);
        const hasDir = activeWs?.targetDir && activeWs.targetDir.trim().length > 0;
        return hasDir ? (
          <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/50 px-4 py-2.5 text-sm">
            <FolderOpen className="h-4 w-4 text-muted-foreground shrink-0" />
            <span className="text-muted-foreground">Scanning:</span>
            <code className="rounded bg-background px-1.5 py-0.5 text-xs font-mono">
              {activeWs.targetDir}
            </code>
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2.5 text-sm text-amber-800">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>
              No project directory configured. Scans will target Complyt&apos;s
              own dependencies.{" "}
              <Link href="/settings" className="font-medium underline">
                Set a directory in Settings
              </Link>
            </span>
          </div>
        );
      })()}

      {Object.keys(capabilities).length > 0 && (
        <div className="grid gap-2 sm:grid-cols-3">
          {Object.entries(capabilities).map(([key, cap]) => (
            <div
              key={key}
              className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs ${
                cap.available
                  ? "border-green-200 bg-green-50 text-green-800"
                  : "border-border bg-muted/30 text-muted-foreground"
              }`}
            >
              <span
                className={`inline-block h-2 w-2 rounded-full ${
                  cap.available ? "bg-green-500" : "bg-gray-300"
                }`}
              />
              <span className="font-medium">{cap.name}</span>
              {!cap.available && cap.tool && (
                <a
                  href={cap.installUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ml-auto underline"
                >
                  Install {cap.tool}
                </a>
              )}
              {cap.available && (
                <span className="ml-auto">Active</span>
              )}
            </div>
          ))}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      ) : workspaces.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No workspace found. Create one in Settings first.
          </CardContent>
        </Card>
      ) : runs.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">No Runs Yet</CardTitle>
            <CardDescription>
              Click &quot;Run Evidence Pack&quot; to generate SBOM, scan for
              vulnerabilities, and enrich with KEV + EPSS data.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="space-y-3">
          {runs.map((run) => {
            const meta = run.metadata ? JSON.parse(run.metadata) : null;
            const isExpanded = expandedRun === run.id;

            return (
              <Card key={run.id}>
                <div
                  className="flex cursor-pointer items-center justify-between p-4"
                  onClick={() => toggleExpand(run.id)}
                  role="button"
                  tabIndex={0}
                  aria-expanded={isExpanded}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") toggleExpand(run.id);
                  }}
                >
                  <div className="flex items-center gap-3">
                    <Badge variant={STATUS_VARIANT[run.status] ?? "secondary"}>
                      {run.status}
                    </Badge>
                    <span className="text-sm font-medium">{run.type}</span>
                    {meta?.offline && (
                      <Badge variant="outline" className="text-xs">
                        offline
                      </Badge>
                    )}
                    {meta?.summary && (
                      <span className="text-xs text-muted-foreground">
                        {meta.summary.total_vulnerabilities ?? 0} vulns,{" "}
                        {meta.summary.kev_matches ?? 0} KEV
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">
                      {new Date(run.createdAt).toLocaleString()}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4" />
                    ) : (
                      <ChevronDown className="h-4 w-4" />
                    )}
                  </div>
                </div>
                {isExpanded && (
                  <CardContent className="border-t pt-4">
                    {run.error && (
                      <p className="mb-3 text-sm text-destructive">
                        Error: {run.error}
                      </p>
                    )}
                    {run.artifacts && run.artifacts.length > 0 ? (
                      <div className="space-y-2">
                        <p className="text-sm font-medium">Artifacts:</p>
                        {run.artifacts.map((a) => (
                          <div
                            key={a.id}
                            className="flex items-center justify-between rounded border px-3 py-2 text-sm"
                          >
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="text-xs">
                                {a.type}
                              </Badge>
                              <span className="font-mono text-xs">
                                {a.filename}
                              </span>
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {a.sizeBytes
                                ? `${(a.sizeBytes / 1024).toFixed(1)} KB`
                                : ""}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No artifacts produced.
                      </p>
                    )}
                  </CardContent>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
