"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ShieldCheck,
  FileSearch,
  PackageOpen,
  AlertTriangle,
  Loader2,
} from "lucide-react";

interface Workspace {
  id: string;
  name: string;
}

interface Control {
  id: string;
  controlId: string;
  title: string;
  status: string;
  category: string | null;
}

interface EvidenceRun {
  id: string;
  type: string;
  status: string;
  createdAt: string;
}

const STATUS_LABEL: Record<string, string> = {
  not_started: "Not Started",
  in_progress: "In Progress",
  met: "Met",
  not_met: "Not Met",
};

export default function DashboardPage() {
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [runs, setRuns] = useState<EvidenceRun[]>([]);
  const [exportCount, setExportCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    const wsRes = await fetch("/api/workspaces");
    const workspaces = await wsRes.json();

    if (workspaces.length > 0) {
      const ws = workspaces[0];
      setWorkspace(ws);

      const [ctrlRes, runsRes, exportsRes] = await Promise.all([
        fetch(`/api/controls?workspaceId=${ws.id}`),
        fetch(`/api/evidence/runs?workspaceId=${ws.id}`),
        fetch(`/api/exports?workspaceId=${ws.id}`),
      ]);

      setControls(await ctrlRes.json().catch(() => []));
      setRuns(await runsRes.json().catch(() => []));
      const exportsData = await exportsRes.json().catch(() => []);
      setExportCount(Array.isArray(exportsData) ? exportsData.length : 0);
    }

    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const completedRuns = runs.filter((r) => r.status === "completed").length;
  const metControls = controls.filter((c) => c.status === "met").length;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">
          {workspace
            ? `Workspace: ${workspace.name}`
            : "Create a workspace in Settings to get started."}
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Controls"
          value={workspace ? `${metControls}/${controls.length}` : "--"}
          description={workspace ? "Controls met" : "No workspace"}
          icon={<ShieldCheck className="h-4 w-4 text-muted-foreground" />}
        />
        <StatCard
          title="Evidence Runs"
          value={workspace ? String(completedRuns) : "--"}
          description="Completed runs"
          icon={<FileSearch className="h-4 w-4 text-muted-foreground" />}
        />
        <StatCard
          title="Exports"
          value={workspace ? String(exportCount) : "--"}
          description="Audit packs generated"
          icon={<PackageOpen className="h-4 w-4 text-muted-foreground" />}
        />
        <StatCard
          title="Open Findings"
          value={workspace ? String(controls.filter((c) => c.status === "not_met").length) : "--"}
          description="Controls not met"
          icon={<AlertTriangle className="h-4 w-4 text-muted-foreground" />}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Evidence Runs</CardTitle>
            <CardDescription>Last 5 evidence collection runs</CardDescription>
          </CardHeader>
          <CardContent>
            {runs.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No evidence runs yet.
              </p>
            ) : (
              <div className="space-y-2">
                {runs.slice(0, 5).map((run) => (
                  <div
                    key={run.id}
                    className="flex items-center justify-between rounded border px-3 py-2"
                  >
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          run.status === "completed"
                            ? "default"
                            : run.status === "failed"
                              ? "destructive"
                              : "secondary"
                        }
                      >
                        {run.status}
                      </Badge>
                      <span className="text-sm">{run.type}</span>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {new Date(run.createdAt).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Control Coverage</CardTitle>
            <CardDescription>Status breakdown</CardDescription>
          </CardHeader>
          <CardContent>
            {controls.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No controls loaded.
              </p>
            ) : (
              <div className="space-y-3">
                {Object.entries(
                  controls.reduce(
                    (acc, c) => {
                      acc[c.status] = (acc[c.status] || 0) + 1;
                      return acc;
                    },
                    {} as Record<string, number>
                  )
                ).map(([status, count]) => (
                  <div key={status} className="flex items-center justify-between">
                    <span className="text-sm">
                      {STATUS_LABEL[status] ?? status}
                    </span>
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-24 rounded-full bg-muted">
                        <div
                          className={`h-2 rounded-full ${
                            status === "met"
                              ? "bg-green-500"
                              : status === "not_met"
                                ? "bg-red-500"
                                : status === "in_progress"
                                  ? "bg-yellow-500"
                                  : "bg-gray-400"
                          }`}
                          style={{
                            width: `${(count / controls.length) * 100}%`,
                          }}
                        />
                      </div>
                      <span className="text-sm font-medium">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatCard({
  title,
  value,
  description,
  icon,
}: {
  title: string;
  value: string;
  description: string;
  icon: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <p className="text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
