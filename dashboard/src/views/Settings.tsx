import { useMemo, useState, type FormEvent } from "react";
import { credentials, type PrincipalAuthMode } from "../api/client";
import { useProjectConfig, useScope } from "../api/hooks";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { Table, type ColumnDef } from "../components/Table";
import { formatDateTime, truncateId } from "../lib/format";

// Two real concerns share this route.
//
// 1. CREDENTIALS. No login route exists anywhere in the contract — PLAN.md §3
//    and §9.3 name none — because Tracebed authenticates callers, not humans:
//    an operator holds either an OIDC bearer token their IdP issued or a
//    `tb_sk_...` API key `POST /admin/agents/register` minted exactly once.
//    This form is where that credential is pasted, and `api/client.ts` is the
//    only reader or writer of it. It never leaves this browser except as an
//    Authorization / X-Api-Key / X-Admin-Key header.
//
// 2. RESOLVED SCOPE AND STORED CONFIG OVERRIDES. `GET /admin/whoami` reports
//    the project and agent type the server derived for the pasted credential —
//    which is the only way this dashboard can name the project it is looking
//    at, since it can never ask for one. `GET /admin/config` returns the two
//    STORED override layers of PLAN.md §6's resolution order.
//
// The config table shows overrides ONLY, and says so in the heading rather
// than in a footnote. Process defaults live in the API server's environment
// and are not this project's data; a table that merged them would report a
// server-wide value as a project setting, and an operator would tune the
// wrong thing.

type Layer = "project" | "agent_type";

interface ConfigOverrideRow {
  key: string;
  layer: Layer;
  value: unknown;
  /** Set when the same key is overridden at BOTH layers — the agent-type row
   * wins for THIS agent type only, and the operator needs to know the project
   * row is still in force for every other agent type in the project. */
  shadowedProjectValue?: unknown;
}

function renderValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function CredentialForm() {
  const [mode, setMode] = useState<PrincipalAuthMode>(
    () => credentials.getPrincipal()?.mode ?? "bearer"
  );
  const [value, setValue] = useState(() => credentials.getPrincipal()?.value ?? "");
  const [adminKey, setAdminKey] = useState(() => credentials.getAdminKey() ?? "");
  const [savedAt, setSavedAt] = useState<Date | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const hasSomething = credentials.getPrincipal() !== null || credentials.getAdminKey() !== null;

  function save(event: FormEvent) {
    event.preventDefault();
    credentials.setPrincipal(value.trim().length > 0 ? { mode, value: value.trim() } : null);
    credentials.setAdminKey(adminKey.trim().length > 0 ? adminKey.trim() : null);
    setSavedAt(new Date());
    // A saved credential changes which project every other view resolves to,
    // and nothing else in the app subscribes to localStorage. Reload rather
    // than leave stale reads on screen under a new identity.
    window.location.reload();
  }

  function doClear() {
    credentials.setPrincipal(null);
    credentials.setAdminKey(null);
    setValue("");
    setAdminKey("");
    setConfirmClear(false);
    setSavedAt(new Date());
    window.location.reload();
  }

  return (
    <>
      <form onSubmit={save} className="max-w-lg space-y-4 rounded-lg border border-border bg-surface p-4">
        <fieldset className="space-y-2">
          <legend className="text-xs font-semibold uppercase tracking-wide text-text-muted">
            Credential type
          </legend>
          <div className="flex gap-4">
            {(["bearer", "api_key"] as const).map((m) => (
              <label key={m} className="inline-flex items-center gap-1.5 text-sm text-text">
                <input
                  type="radio"
                  name="auth-mode"
                  checked={mode === m}
                  onChange={() => setMode(m)}
                  className="h-3.5 w-3.5 accent-accent"
                />
                {m === "bearer" ? "OIDC bearer token" : "API key"}
              </label>
            ))}
          </div>
        </fieldset>

        <label className="block space-y-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">
            {mode === "bearer" ? "Bearer token" : "API key"}
          </span>
          <input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={mode === "bearer" ? "eyJhbGciOi..." : "tb_sk_..."}
            className="w-full rounded-md border border-border-strong bg-bg px-3 py-1.5 text-sm text-text placeholder:text-text-faint"
            autoComplete="off"
          />
        </label>

        <label className="block space-y-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">
            Admin bootstrap key (optional)
          </span>
          <input
            type="password"
            value={adminKey}
            onChange={(e) => setAdminKey(e.target.value)}
            placeholder="TB_ADMIN_KEY value"
            className="w-full rounded-md border border-border-strong bg-bg px-3 py-1.5 text-sm text-text placeholder:text-text-faint"
            autoComplete="off"
          />
          <span className="block text-xs text-text-faint">
            A separate credential plane. It authorises project creation and agent registration only
            — it grants no read scope, and presenting it never widens what any other route returns.
          </span>
        </label>

        <div className="flex items-center justify-between pt-1">
          <button
            type="submit"
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
          >
            Save and reload
          </button>
          <button
            type="button"
            disabled={!hasSomething}
            onClick={() => setConfirmClear(true)}
            title={hasSomething ? undefined : "Nothing is stored in this browser"}
            className="text-sm font-medium text-text-muted hover:text-danger disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear all credentials
          </button>
        </div>
        {savedAt !== null && (
          <p role="status" className="text-xs text-text-faint">
            Saved at {formatDateTime(savedAt)}.
          </p>
        )}
      </form>

      <ConfirmDialog
        open={confirmClear}
        tone="danger"
        title="Clear the credentials stored in this browser?"
        description="POST /admin/agents/register returns a tb_sk_ key exactly once and Tracebed stores only its hash. If this browser holds the only copy, clearing it destroys a credential that cannot be re-issued — the agent has to be registered again under a new principal."
        impact={[
          { label: "Principal credential removed", value: credentials.getPrincipal() === null ? "none stored" : "yes" },
          { label: "Admin bootstrap key removed", value: credentials.getAdminKey() === null ? "none stored" : "yes" },
          { label: "Revoked server-side", value: "no — this only forgets them locally" },
          { label: "Recoverable from Tracebed", value: "no" },
        ]}
        confirmLabel="Clear credentials"
        onConfirm={doClear}
        onCancel={() => setConfirmClear(false)}
      />
    </>
  );
}

function ScopePanel() {
  const query = useScope();
  if (query.status === "error") return <ErrorState error={query.error} onRetry={query.reload} />;
  if (query.status !== "success") {
    return (
      <div
        role="status"
        aria-label="Resolving scope"
        className="h-24 max-w-lg animate-pulse rounded-lg border border-border bg-surface"
      />
    );
  }
  const scope = query.data;
  if (scope === undefined) return null;
  return (
    <dl className="grid max-w-lg grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 rounded-lg border border-border bg-surface p-4 text-sm">
      <dt className="text-text-muted">Project</dt>
      <dd className="font-mono text-xs text-text" title={scope.project_id}>
        {scope.project_id}
      </dd>
      <dt className="text-text-muted">Agent type</dt>
      <dd className="font-mono text-xs text-text" title={scope.agent_type_id}>
        {scope.agent_type_id}
      </dd>
      <dt className="text-text-muted">Principal</dt>
      <dd className="font-mono text-xs text-text" title={scope.principal_id}>
        {scope.principal_id}
      </dd>
    </dl>
  );
}

function ConfigPanel() {
  const query = useProjectConfig();

  const rows = useMemo((): ConfigOverrideRow[] => {
    const data = query.data;
    if (data === undefined) return [];
    const out: ConfigOverrideRow[] = [];
    for (const [key, value] of Object.entries(data.agent_type)) {
      const row: ConfigOverrideRow = { key, layer: "agent_type", value };
      if (key in data.project) row.shadowedProjectValue = data.project[key];
      out.push(row);
    }
    for (const [key, value] of Object.entries(data.project)) {
      if (key in data.agent_type) continue;
      out.push({ key, layer: "project", value });
    }
    return out;
  }, [query.data]);

  const columns: ColumnDef<ConfigOverrideRow>[] = [
    {
      key: "key",
      header: "Config key",
      width: "34ch",
      render: (row) => <span className="font-mono text-xs text-text">{row.key}</span>,
      sortValue: (row) => row.key,
    },
    {
      key: "layer",
      header: "Override layer",
      width: "20ch",
      render: (row) => (
        <span className="text-xs text-text-muted">
          {row.layer === "agent_type" ? "This agent type" : "Whole project"}
        </span>
      ),
      sortValue: (row) => (row.layer === "agent_type" ? 0 : 1),
    },
    {
      key: "value",
      header: "Stored value",
      render: (row) => (
        <div className="min-w-0">
          <span className="font-mono text-xs text-text">{renderValue(row.value)}</span>
          {/* Layering is per-(project, agent_type). An agent-type override
              shown alone would tell the operator the wrong number for every
              OTHER agent type in the same project. */}
          {row.shadowedProjectValue !== undefined && (
            <p className="mt-0.5 text-xs text-text-muted">
              Every other agent type in this project resolves{" "}
              <span className="font-mono">{renderValue(row.shadowedProjectValue)}</span> from the
              project-level override.
            </p>
          )}
        </div>
      ),
      sortValue: (row) => renderValue(row.value),
    },
  ];

  if (query.status === "error") return <ErrorState error={query.error} onRetry={query.reload} />;

  return (
    <>
      <p className="mb-2 max-w-3xl text-xs text-text-muted">
        <strong className="font-semibold text-text">Overrides only.</strong> PLAN.md §6 resolves
        config as process defaults → <code className="font-mono">project_config</code> →{" "}
        <code className="font-mono">agent_type_config</code> → kill-switch overlay. Only the middle
        two are rows in this project&rsquo;s own tables and therefore readable here. A key absent
        from this table is running on the API server&rsquo;s process default, whose value is not
        this project&rsquo;s data and is not reported by any route.
        {query.data !== undefined && (
          <>
            {" "}
            The agent-type layer shown is{" "}
            <span className="font-mono" title={query.data.agent_type_id}>
              {truncateId(query.data.agent_type_id)}
            </span>{" "}
            — the one this credential resolves to.
          </>
        )}
      </p>
      {query.status === "success" && rows.length === 0 ? (
        <EmptyState
          title="No config overrides stored"
          description="Neither project_config nor agent_type_config has a row for this scope, so every value is running on the API server's process default. That is the normal state for a project that has not been tuned — nothing here is missing."
        />
      ) : (
        <Table
          caption="Stored project_config and agent_type_config overrides for the resolved scope"
          columns={columns}
          rows={rows}
          getRowId={(row) => `${row.layer}:${row.key}`}
          loading={query.status === "loading"}
          initialSort={{ key: "key", direction: "asc" }}
        />
      )}
    </>
  );
}

export default function Settings() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-text">Settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          The credential this browser presents, the scope the server derives from it, and the
          config overrides stored for that scope.
        </p>
      </div>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-text">Credentials</h2>
        <p className="mb-3 max-w-3xl text-sm text-text-muted">
          Tracebed has no login route — it authenticates callers, not humans. Paste the OIDC bearer
          token or <code className="font-mono text-xs">tb_sk_...</code> API key the registration
          minted; it is kept only in this browser&rsquo;s local storage and attached as an{" "}
          <code className="font-mono text-xs">Authorization</code> or{" "}
          <code className="font-mono text-xs">X-Api-Key</code> header.
        </p>
        <CredentialForm />
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-text">Resolved scope</h2>
        <p className="mb-3 max-w-3xl text-sm text-text-muted">
          Derived server-side from the credential above via{" "}
          <code className="font-mono text-xs">GET /admin/whoami</code>. The dashboard cannot ask for
          a project; this is how it learns which one it is looking at. A 403 here means the
          credential authenticates but has no{" "}
          <code className="font-mono text-xs">agent_registration</code> row — it is a valid identity
          bound to no project.
        </p>
        <ScopePanel />
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-text">Config overrides</h2>
        <ConfigPanel />
      </section>
    </div>
  );
}
