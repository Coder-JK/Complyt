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
import { Loader2, Download, PackageOpen } from "lucide-react";

interface Workspace {
  id: string;
  name: string;
}

interface ExportRecord {
  id: string;
  name: string;
  filename: string;
  format: string;
  sizeBytes: number | null;
  createdAt: string;
}

export default function ExportsPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWs, setSelectedWs] = useState("");
  const [exports, setExports] = useState<ExportRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const fetchWorkspaces = useCallback(async () => {
    const res = await fetch("/api/workspaces");
    const data = await res.json();
    setWorkspaces(data);
    if (data.length > 0 && !selectedWs) setSelectedWs(data[0].id);
    setLoading(false);
  }, [selectedWs]);

  const fetchExports = useCallback(async () => {
    if (!selectedWs) return;
    const res = await fetch(`/api/exports?workspaceId=${selectedWs}`);
    const data = await res.json();
    setExports(Array.isArray(data) ? data : []);
  }, [selectedWs]);

  useEffect(() => {
    fetchWorkspaces();
  }, [fetchWorkspaces]);

  useEffect(() => {
    if (selectedWs) fetchExports();
  }, [selectedWs, fetchExports]);

  async function generateExport() {
    if (!selectedWs) return;
    setGenerating(true);
    await fetch("/api/exports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ workspaceId: selectedWs }),
    });
    await fetchExports();
    setGenerating(false);
  }

  function downloadExport(id: string) {
    window.open(`/api/exports/${id}/download`, "_blank");
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">Exports</h2>
          <p className="text-muted-foreground">
            Generate and download audit-ready evidence packs.
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
            onClick={generateExport}
            disabled={generating || !selectedWs}
          >
            {generating ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <PackageOpen className="mr-2 h-4 w-4" />
            )}
            Generate Audit Pack
          </Button>
        </div>
      </div>

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
      ) : exports.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">No Exports Yet</CardTitle>
            <CardDescription>
              Run an evidence pack first, then click &quot;Generate Audit
              Pack&quot; to create a downloadable ZIP.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="space-y-3">
          {exports.map((exp) => (
            <Card key={exp.id}>
              <div className="flex items-center justify-between p-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{exp.name}</span>
                    <Badge variant="outline" className="text-xs">
                      {exp.format.toUpperCase()}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="font-mono">{exp.filename}</span>
                    {exp.sizeBytes && (
                      <span>{(exp.sizeBytes / 1024).toFixed(1)} KB</span>
                    )}
                    <span>{new Date(exp.createdAt).toLocaleString()}</span>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadExport(exp.id)}
                >
                  <Download className="mr-2 h-4 w-4" />
                  Download
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
