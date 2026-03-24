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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Plus, Loader2, FolderOpen, AlertTriangle } from "lucide-react";

interface Workspace {
  id: string;
  name: string;
  description: string | null;
  targetDir: string | null;
  createdAt: string;
}

export default function SettingsPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetDir, setTargetDir] = useState("");

  const fetchWorkspaces = useCallback(async () => {
    const res = await fetch("/api/workspaces");
    const data = await res.json();
    setWorkspaces(data);
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchWorkspaces();
  }, [fetchWorkspaces]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    const res = await fetch("/api/workspaces", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: name.trim(),
        description: description.trim() || undefined,
        targetDir: targetDir.trim() || undefined,
      }),
    });

    if (res.ok) {
      setName("");
      setDescription("");
      setTargetDir("");
      await fetchWorkspaces();
    }
    setCreating(false);
  }

  async function handleUpdateTargetDir(wsId: string, newDir: string) {
    await fetch(`/api/workspaces/${wsId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targetDir: newDir.trim() }),
    });
    await fetchWorkspaces();
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight">Settings</h2>
        <p className="text-muted-foreground">
          Configure your workspace and evidence collection settings.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Create Workspace</CardTitle>
          <CardDescription>
            A workspace scopes your controls, evidence runs, and exports to one
            project. Point it at your project folder so Complyt knows what to
            scan.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleCreate} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="ws-name">Project Name</Label>
              <Input
                id="ws-name"
                placeholder="e.g. My SaaS Product"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="ws-dir" className="flex items-center gap-1.5">
                <FolderOpen className="h-3.5 w-3.5" />
                Project Directory
              </Label>
              <Input
                id="ws-dir"
                placeholder="e.g. C:\Users\you\projects\my-app"
                value={targetDir}
                onChange={(e) => setTargetDir(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Absolute path to your project root (must contain a{" "}
                <code className="rounded bg-muted px-1">package.json</code>).
                This is the directory Complyt will scan for dependencies and
                vulnerabilities. If left blank, Complyt scans its own
                dependencies (not useful for your audit).
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="ws-desc">
                Description{" "}
                <span className="text-muted-foreground">(optional)</span>
              </Label>
              <Input
                id="ws-desc"
                placeholder="Brief description of this workspace"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <Button type="submit" disabled={creating || !name.trim()}>
              {creating ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Plus className="mr-2 h-4 w-4" />
              )}
              Create Workspace
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Workspaces</CardTitle>
          <CardDescription>Your existing compliance workspaces</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : workspaces.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No workspaces yet. Create one above.
            </p>
          ) : (
            <div className="space-y-4">
              {workspaces.map((ws) => (
                <WorkspaceCard
                  key={ws.id}
                  workspace={ws}
                  onUpdateTargetDir={handleUpdateTargetDir}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function WorkspaceCard({
  workspace,
  onUpdateTargetDir,
}: {
  workspace: {
    id: string;
    name: string;
    description: string | null;
    targetDir: string | null;
    createdAt: string;
  };
  onUpdateTargetDir: (id: string, dir: string) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [dirValue, setDirValue] = useState(workspace.targetDir ?? "");

  async function handleSave() {
    await onUpdateTargetDir(workspace.id, dirValue);
    setEditing(false);
  }

  const hasDir = workspace.targetDir && workspace.targetDir.trim().length > 0;

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-medium">{workspace.name}</span>
          <Badge variant="secondary" className="text-xs">
            {workspace.id.slice(0, 8)}
          </Badge>
        </div>
        <span className="text-xs text-muted-foreground">
          {new Date(workspace.createdAt).toLocaleDateString()}
        </span>
      </div>

      {workspace.description && (
        <p className="text-sm text-muted-foreground">
          {workspace.description}
        </p>
      )}

      <div className="space-y-1.5">
        <div className="flex items-center gap-2 text-sm">
          <FolderOpen className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="font-medium text-muted-foreground">
            Scan target:
          </span>
          {hasDir ? (
            <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
              {workspace.targetDir}
            </code>
          ) : (
            <span className="flex items-center gap-1 text-amber-600 text-xs">
              <AlertTriangle className="h-3 w-3" />
              Not configured — will scan Complyt&apos;s own dependencies
            </span>
          )}
        </div>

        {editing ? (
          <div className="flex gap-2">
            <Input
              value={dirValue}
              onChange={(e) => setDirValue(e.target.value)}
              placeholder="C:\Users\you\projects\my-app"
              className="text-sm"
            />
            <Button size="sm" onClick={handleSave}>
              Save
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setEditing(false)}
            >
              Cancel
            </Button>
          </div>
        ) : (
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setDirValue(workspace.targetDir ?? "");
              setEditing(true);
            }}
          >
            {hasDir ? "Change directory" : "Set project directory"}
          </Button>
        )}
      </div>
    </div>
  );
}
