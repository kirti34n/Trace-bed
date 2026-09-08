import { useMemo } from "react";
import { useSession } from "../auth/session";
import { useProjectConfig, useScope } from "../api/hooks";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { Table, type ColumnDef } from "../components/Table";
import { truncateId } from "../lib/format";

type Layer = "project" | "agent_type";

interface ConfigOverrideRow {
  key: string;
  layer: Layer;
  value: unknown;
  shadowedProjectValue?: unknown;
}

function renderValue(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function SessionPanel() {
  const session = useSession();
  if (session.phase === "loading") {
    return <div role="status" aria-label="Checking BFF session" className="h-20 max-w-lg animate-pulse rounded-lg border border-border bg-surface" />;
  }
  if (session.phase === "error") return <ErrorState error={session.error} onRetry={session.reload} title="Could not check the BFF session" />;
  if (session.phase === "anonymous") {
    return (
      <EmptyState
        title="No active operator session"
        description="Sign in through the same-origin identity flow. The dashboard never accepts, stores, or sends bearer tokens, API keys, or session identifiers."
        action={{ label: "Sign in", onClick: session.login }}
      />
    );
  }
  return (
    <div className="flex max-w-lg items-center justify-between rounded-lg border border-border bg-surface p-4 text-sm">
      <p className="text-text-muted">Signed in through the same-origin BFF session.</p>
      <button type="button" onClick={() => void session.logout()} className="font-medium text-text-muted hover:text-danger">
        Sign out
      </button>
    </div>
  );
}

function ScopePanel() {
  const query = useScope();
  if (query.status === "error") return <ErrorState error={query.error} onRetry={query.reload} />;
  if (query.status !== "success" || query.data === undefined) {
    return <div role="status" aria-label="Resolving scope" className="h-24 max-w-lg animate-pulse rounded-lg border border-border bg-surface" />;
  }
  const scope = query.data;
  return (
    <dl className="grid max-w-lg grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 rounded-lg border border-border bg-surface p-4 text-sm">
      <dt className="text-text-muted">Project</dt><dd className="font-mono text-xs text-text">{scope.project_id}</dd>
      <dt className="text-text-muted">Agent type</dt><dd className="font-mono text-xs text-text">{scope.agent_type_id}</dd>
      <dt className="text-text-muted">Principal</dt><dd className="font-mono text-xs text-text">{scope.principal_id}</dd>
    </dl>
  );
}

function ConfigPanel() {
  const query = useProjectConfig();
  const rows = useMemo((): ConfigOverrideRow[] => {
    if (query.data === undefined) return [];
    const out: ConfigOverrideRow[] = [];
    for (const [key, value] of Object.entries(query.data.agent_type)) {
      out.push({ key, layer: "agent_type", value, shadowedProjectValue: query.data.project[key] });
    }
    for (const [key, value] of Object.entries(query.data.project)) {
      if (!(key in query.data.agent_type)) out.push({ key, layer: "project", value });
    }
    return out;
  }, [query.data]);
  const columns: ColumnDef<ConfigOverrideRow>[] = [
    { key: "key", header: "Config key", width: "34ch", render: (row) => <span className="font-mono text-xs text-text">{row.key}</span>, sortValue: (row) => row.key },
    { key: "layer", header: "Override layer", width: "20ch", render: (row) => <span className="text-xs text-text-muted">{row.layer === "agent_type" ? "This agent type" : "Whole project"}</span>, sortValue: (row) => row.layer },
    { key: "value", header: "Stored value", render: (row) => <div className="min-w-0"><span className="font-mono text-xs text-text">{renderValue(row.value)}</span>{row.shadowedProjectValue !== undefined && <p className="mt-0.5 text-xs text-text-muted">Other agent types resolve <span className="font-mono">{renderValue(row.shadowedProjectValue)}</span> from the project override.</p>}</div>, sortValue: (row) => renderValue(row.value) },
  ];
  if (query.status === "error") return <ErrorState error={query.error} onRetry={query.reload} />;
  return (
    <>
      <p className="mb-2 max-w-3xl text-xs text-text-muted"><strong className="font-semibold text-text">Overrides only.</strong> Process defaults are deployment configuration, not project data. {query.data !== undefined && <>The agent-type layer is <span className="font-mono">{truncateId(query.data.agent_type_id)}</span>.</>}</p>
      {query.status === "success" && rows.length === 0 ? <EmptyState title="No config overrides stored" description="This resolved scope uses the API process defaults." /> : <Table caption="Stored config overrides for the resolved scope" columns={columns} rows={rows} getRowId={(row) => `${row.layer}:${row.key}`} loading={query.status === "loading"} initialSort={{ key: "key", direction: "asc" }} />}
    </>
  );
}

export default function Settings() {
  return (
    <div className="space-y-8">
      <div><h1 className="text-lg font-semibold text-text">Settings</h1><p className="mt-1 max-w-3xl text-sm text-text-muted">BFF session state, server-derived identity, and stored config overrides.</p></div>
      <section><h2 className="mb-2 text-sm font-semibold text-text">Session</h2><SessionPanel /></section>
      <section><h2 className="mb-2 text-sm font-semibold text-text">Resolved scope</h2><p className="mb-3 max-w-3xl text-sm text-text-muted">The API derives this from the authenticated BFF session with <code className="font-mono text-xs">GET /admin/whoami</code>; the browser cannot choose a project.</p><ScopePanel /></section>
      <section><h2 className="mb-2 text-sm font-semibold text-text">Config overrides</h2><ConfigPanel /></section>
    </div>
  );
}
