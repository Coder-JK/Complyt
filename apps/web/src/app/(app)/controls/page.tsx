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
import { Button } from "@/components/ui/button";
import { Loader2 } from "lucide-react";

interface Workspace {
  id: string;
  name: string;
}

interface Control {
  id: string;
  controlId: string;
  title: string;
  description: string | null;
  category: string | null;
  frequency: string | null;
  status: string;
}

const STATUS_STYLES: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
  not_started: { label: "Not Started", variant: "secondary" },
  in_progress: { label: "In Progress", variant: "outline" },
  met: { label: "Met", variant: "default" },
  not_met: { label: "Not Met", variant: "destructive" },
};

const STATUS_CYCLE: string[] = ["not_started", "in_progress", "met", "not_met"];

export default function ControlsPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWs, setSelectedWs] = useState<string>("");
  const [controls, setControls] = useState<Control[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchWorkspaces = useCallback(async () => {
    const res = await fetch("/api/workspaces");
    const data = await res.json();
    setWorkspaces(data);
    if (data.length > 0 && !selectedWs) {
      setSelectedWs(data[0].id);
    }
    setLoading(false);
  }, [selectedWs]);

  const fetchControls = useCallback(async () => {
    if (!selectedWs) return;
    const res = await fetch(`/api/controls?workspaceId=${selectedWs}`);
    const data = await res.json();
    setControls(data);
  }, [selectedWs]);

  useEffect(() => {
    fetchWorkspaces();
  }, [fetchWorkspaces]);

  useEffect(() => {
    if (selectedWs) fetchControls();
  }, [selectedWs, fetchControls]);

  async function cycleStatus(control: Control) {
    const currentIdx = STATUS_CYCLE.indexOf(control.status);
    const nextStatus = STATUS_CYCLE[(currentIdx + 1) % STATUS_CYCLE.length];

    await fetch("/api/controls", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: control.id, status: nextStatus }),
    });
    await fetchControls();
  }

  const categories = [...new Set(controls.map((c) => c.category).filter(Boolean))];
  const statusCounts = controls.reduce(
    (acc, c) => {
      acc[c.status] = (acc[c.status] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">Controls</h2>
          <p className="text-muted-foreground">
            Manage compliance controls and track their status.
          </p>
        </div>
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
      ) : (
        <>
          <div className="flex gap-3">
            {Object.entries(statusCounts).map(([status, count]) => {
              const style = STATUS_STYLES[status];
              return (
                <Badge key={status} variant={style?.variant ?? "secondary"}>
                  {style?.label ?? status}: {count}
                </Badge>
              );
            })}
            <Badge variant="outline">Total: {controls.length}</Badge>
          </div>

          {categories.map((category) => (
            <Card key={category}>
              <CardHeader>
                <CardTitle className="text-base">{category}</CardTitle>
                <CardDescription>
                  {controls.filter((c) => c.category === category).length}{" "}
                  controls
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {controls
                    .filter((c) => c.category === category)
                    .map((control) => {
                      const style = STATUS_STYLES[control.status];
                      return (
                        <div
                          key={control.id}
                          className="flex items-start justify-between gap-4 rounded-lg border p-3"
                        >
                          <div className="min-w-0 flex-1 space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs text-muted-foreground">
                                {control.controlId}
                              </span>
                              <span className="text-sm font-medium">
                                {control.title}
                              </span>
                            </div>
                            {control.description && (
                              <p className="text-xs text-muted-foreground">
                                {control.description}
                              </p>
                            )}
                            {control.frequency && (
                              <span className="text-xs text-muted-foreground">
                                Frequency: {control.frequency}
                              </span>
                            )}
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => cycleStatus(control)}
                            className="shrink-0"
                          >
                            <Badge variant={style?.variant ?? "secondary"}>
                              {style?.label ?? control.status}
                            </Badge>
                          </Button>
                        </div>
                      );
                    })}
                </div>
              </CardContent>
            </Card>
          ))}
        </>
      )}
    </div>
  );
}
