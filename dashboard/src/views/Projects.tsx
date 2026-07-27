import { useCallback, useEffect, useState, type FormEvent } from "react";
import { credentials } from "../api/client";
import { useCreateProject, useRegisterAgent, useScope } from "../api/hooks";
import type { AgentPrincipalIn } from "../api/types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorState } from "../components/ErrorState";

// The registry plane, and the only page here that is not project-scoped.
// `POST /admin/projects` and `POST /admin/agents/register` authenticate with
// the bootstrap `X-Admin-Key` (contract C-20) precisely because no
// `agent_registration` row exists yet for the principal they are about to
// create. Both are irreversible from this dashboard and both are gated behind
// a confirmation that names what they will provision.
//
// There is deliberately NO project list, no principal list, and no agent
// registration list here. `Repo.list_project_ids` exists but is unscoped and
// cross-project by definition; exposing it over HTTP would hand any holder of
// the bootstrap key an enumeration of every tenant on the instance, which is
// not a thing this console needs in order to create the next one. What the
// page shows instead is the ONE scope the current credential resolves to,
// read from `GET /admin/whoami` — enough to answer "did the registration I
// just made actually bind?" without enumerating anything.
//
// Also absent, and named rather than faked: the embedding pin
// (`embedding_model`), the current scoring epoch (`scoring_epoch`) and
// partition headroom. All three are real tables or real operational limits
// with no read route; they used to be rendered here from constants, which
// meant an operator could read "dim 768, gemini-embedding-2" off a screen that
// had never spoken to their deployment.

/** Re-reads the admin key on mount and whenever the window regains focus, so
 * setting one on Settings in another tab stops this page claiming the call
 * will 401 when it no longer will. */
function useAdminKeyPresent(): boolean {
  const [present, setPresent] = useState(() => credentials.getAdminKey() !== null);
  useEffect(() => {
    function refresh() {
      setPresent(credentials.getAdminKey() !== null);
    }
    refresh();
    window.addEventListener("focus", refresh);
    return () => window.removeEventListener("focus", refresh);
  }, []);
  return present;
}

function AdminKeyWarning() {
  return (
    <p className="rounded-md border border-status-quarantined-border/60 bg-status-quarantined-bg/40 px-2.5 py-1.5 text-xs text-status-quarantined-fg">
      No admin key set — this call will fail with 401. Set one on the Settings view.
    </p>
  );
}

function CreateProjectForm() {
  const [name, setName] = useState("");
  const [confirming, setConfirming] = useState(false);
  const create = useCreateProject();
  const hasAdminKey = useAdminKeyPresent();
  const trimmedName = name.trim();

  function submit(event: FormEvent) {
    event.preventDefault();
    if (trimmedName.length === 0) return;
    setConfirming(true);
  }

  function confirmCreate() {
    create
      .mutate({ name: trimmedName })
      .then(() => {
        setName("");
      })
      .catch(() => {
        // `create.error` already carries the typed failure and renders below;
        // swallowing here only stops an unhandled rejection.
      })
      .finally(() => setConfirming(false));
  }

  return (
    <form onSubmit={submit} className="space-y-3 rounded-lg border border-border bg-surface p-4">
      <h3 className="text-sm font-semibold text-text">Create project</h3>
      <p className="text-xs text-text-muted">
        Calls the real <code className="font-mono">POST /admin/projects</code>. One call provisions three things at
        once: the registry row, a partition of every one of PLAN.md §5's LIST-partitioned tables, and the project's{" "}
        <code className="font-mono">__project__</code> KEK.
      </p>
      {!hasAdminKey && <AdminKeyWarning />}
      <label className="block space-y-1">
        <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">Project name</span>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="billing-support-prod"
          className="w-full rounded-md border border-border-strong bg-bg px-3 py-1.5 text-sm text-text placeholder:text-text-faint"
        />
      </label>
      <button
        type="submit"
        disabled={create.status === "pending" || trimmedName.length === 0}
        className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
      >
        {create.status === "pending" ? "Creating…" : "Create project…"}
      </button>
      {create.status === "success" && create.data !== undefined && (
        <p role="status" className="rounded-md border border-status-validated-border/60 bg-status-validated-bg/40 px-2.5 py-1.5 text-xs text-status-validated-fg">
          Created. project_id: <span className="select-all font-mono">{create.data.project_id}</span>
        </p>
      )}
      {create.status === "error" && <ErrorState error={create.error} title="Could not create project" />}

      {/* Creating a project allocates partitions across every partitioned
          table and mints a project KEK. No route deletes a project — the
          contract exposes `drop_project` to migrations only — so from this
          dashboard the action cannot be undone. */}
      <ConfirmDialog
        open={confirming}
        title={`Create project "${trimmedName}"?`}
        description="This writes the registry row, creates a partition of every partitioned table for the new project_id, and provisions its __project__ KEK. No route deletes a project: partitions.drop_project is a migration-time operation with no HTTP surface, so this dashboard cannot undo it."
        impact={[
          { label: "Project name", value: trimmedName },
          { label: "Partitions created", value: "One per partitioned table (PLAN.md §5)" },
          { label: "Crypto material", value: "New per-project KEK (__project__)" },
          { label: "Undo from this dashboard", value: "Not possible" },
        ]}
        confirmLabel="Create project"
        busy={create.status === "pending"}
        onConfirm={confirmCreate}
        onCancel={() => setConfirming(false)}
      />
    </form>
  );
}

function OneTimeApiKey({ apiKey }: { apiKey: string }) {
  const [copied, setCopied] = useState<"idle" | "ok" | "failed">("idle");
  const copy = useCallback(() => {
    navigator.clipboard
      .writeText(apiKey)
      .then(() => setCopied("ok"))
      .catch(() => setCopied("failed"));
  }, [apiKey]);

  return (
    <div className="rounded border border-status-quarantined-border bg-status-quarantined-bg px-2 py-1.5 text-status-quarantined-fg">
      <p className="font-semibold">Shown once. Tracebed stores only its hash and can never display it again.</p>
      <p className="mt-1 break-all">
        <span className="select-all font-mono">{apiKey}</span>
      </p>
      <div className="mt-1.5 flex items-center gap-2">
        <button
          type="button"
          onClick={copy}
          className="rounded border border-status-quarantined-border px-2 py-0.5 text-[11px] font-semibold hover:bg-status-quarantined-bg"
        >
          Copy key
        </button>
        {copied === "ok" && (
          <span role="status" className="text-[11px]">
            Copied to clipboard.
          </span>
        )}
        {copied === "failed" && (
          <span role="status" className="text-[11px]">
            Clipboard unavailable — select the key above and copy it manually.
          </span>
        )}
      </div>
    </div>
  );
}

function RegisterAgentForm() {
  const [projectId, setProjectId] = useState("");
  const [agentType, setAgentType] = useState("");
  const [principalKind, setPrincipalKind] = useState<"oidc_sub" | "api_key">("api_key");
  const [sub, setSub] = useState("");
  const [confirming, setConfirming] = useState(false);
  const register = useRegisterAgent();
  const hasAdminKey = useAdminKeyPresent();

  const trimmedProjectId = projectId.trim();
  const trimmedAgentType = agentType.trim();
  const trimmedSub = sub.trim();
  // An OIDC registration with an empty `sub` would bind a principal nobody can
  // ever authenticate as, and agent_registration is UNIQUE(principal_id) with
  // no delete route — so it is blocked here rather than left to a 4xx.
  const complete =
    trimmedProjectId.length > 0 &&
    trimmedAgentType.length > 0 &&
    (principalKind === "api_key" || trimmedSub.length > 0);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!complete) return;
    setConfirming(true);
  }

  function confirmRegister() {
    const principal: AgentPrincipalIn =
      principalKind === "oidc_sub" ? { kind: "oidc_sub", sub: trimmedSub } : { kind: "api_key" };
    register
      .mutate({ project_id: trimmedProjectId, agent_type: trimmedAgentType, principal })
      .catch(() => {
        // Typed failure is rendered from `register.error` below.
      })
      .finally(() => setConfirming(false));
  }

  return (
    <form onSubmit={submit} className="space-y-3 rounded-lg border border-border bg-surface p-4">
      <h3 className="text-sm font-semibold text-text">Register agent</h3>
      <p className="text-xs text-text-muted">
        Calls the real <code className="font-mono">POST /admin/agents/register</code> — the one route allowed to
        name a project_id (the admin is naming the project being provisioned, not asserting scope for a data read).
        The registration row it writes is what makes server-side scope derivation possible at all; invariant 4 rests
        on it.
      </p>
      {!hasAdminKey && <AdminKeyWarning />}
      <label className="block space-y-1">
        <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">Project id (uuid)</span>
        <input
          type="text"
          value={projectId}
          onChange={(e) => setProjectId(e.target.value)}
          placeholder="0193c1a0-0000-7000-8000-000000000000"
          className="w-full rounded-md border border-border-strong bg-bg px-3 py-1.5 font-mono text-sm text-text placeholder:text-text-faint"
        />
      </label>
      <label className="block space-y-1">
        <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">Agent type name</span>
        <input
          type="text"
          value={agentType}
          onChange={(e) => setAgentType(e.target.value)}
          placeholder="support_triage"
          className="w-full rounded-md border border-border-strong bg-bg px-3 py-1.5 text-sm text-text placeholder:text-text-faint"
        />
      </label>
      <fieldset className="space-y-2">
        <legend className="text-xs font-semibold uppercase tracking-wide text-text-muted">Principal kind</legend>
        <div className="flex gap-4">
          {(["api_key", "oidc_sub"] as const).map((k) => (
            <label key={k} className="inline-flex items-center gap-1.5 text-sm text-text">
              <input
                type="radio"
                name="principal-kind"
                checked={principalKind === k}
                onChange={() => setPrincipalKind(k)}
                className="h-3.5 w-3.5 accent-accent"
              />
              {k === "api_key" ? "API key (server-minted)" : "OIDC subject"}
            </label>
          ))}
        </div>
      </fieldset>
      {principalKind === "oidc_sub" && (
        <label className="block space-y-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">OIDC sub</span>
          <input
            type="text"
            value={sub}
            onChange={(e) => setSub(e.target.value)}
            placeholder="svc-support-triage@platform.internal"
            className="w-full rounded-md border border-border-strong bg-bg px-3 py-1.5 text-sm text-text placeholder:text-text-faint"
          />
        </label>
      )}
      <button
        type="submit"
        disabled={register.status === "pending" || !complete}
        className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
      >
        {register.status === "pending" ? "Registering…" : "Register agent…"}
      </button>
      {register.status === "success" && register.data !== undefined && (
        <div className="space-y-1.5 rounded-md border border-status-validated-border/60 bg-status-validated-bg/40 px-2.5 py-1.5 text-xs text-status-validated-fg">
          <p>
            Registered. principal_id: <span className="select-all font-mono">{register.data.principal_id}</span>
          </p>
          <p>
            agent_type_id: <span className="select-all font-mono">{register.data.agent_type_id}</span>
          </p>
          {register.data.api_key !== null && <OneTimeApiKey apiKey={register.data.api_key} />}
        </div>
      )}
      {register.status === "error" && <ErrorState error={register.error} title="Could not register agent" />}

      {/* Registration is one-way from here: agent_registration is
          UNIQUE(principal_id), no route deletes or revokes a registration, and
          an api_key principal's plaintext key is returned exactly once. */}
      <ConfirmDialog
        open={confirming}
        title="Register this agent?"
        description={
          principalKind === "api_key"
            ? "This binds a new principal to the named project and agent_type, and mints an API key that is returned exactly once. Tracebed stores only its hash — if the key is not captured from the next screen it cannot be recovered, and no route revokes or deletes a registration."
            : "This binds the named OIDC subject to the project and agent_type. agent_registration is UNIQUE(principal_id) and no route deletes or revokes one, so this binding cannot be changed from this dashboard."
        }
        impact={[
          { label: "Project id", value: trimmedProjectId },
          { label: "Agent type", value: trimmedAgentType },
          { label: "Principal", value: principalKind === "api_key" ? "New server-minted API key" : trimmedSub },
          {
            label: "Credential shown",
            value: principalKind === "api_key" ? "Once, never again" : "None (IdP-held)",
          },
          { label: "Undo from this dashboard", value: "Not possible" },
        ]}
        tone="danger"
        confirmLabel="Register agent"
        busy={register.status === "pending"}
        onConfirm={confirmRegister}
        onCancel={() => setConfirming(false)}
      />
    </form>
  );
}

function CurrentScopeCard() {
  const query = useScope();
  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <h2 className="text-sm font-semibold text-text">This credential&rsquo;s scope</h2>
      <p className="mt-1 text-xs text-text-muted">
        From <code className="font-mono">GET /admin/whoami</code>. This is the project every other
        view in this dashboard is reading; it is derived from the principal credential set on
        Settings, never chosen here.
      </p>
      {query.status === "error" ? (
        <div className="mt-3">
          <ErrorState
            error={query.error}
            onRetry={query.reload}
            title="No scope resolves for the current credential"
          />
        </div>
      ) : query.status === "success" && query.data !== undefined ? (
        <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs">
          <dt className="text-text-muted">Project</dt>
          <dd className="select-all font-mono text-text">{query.data.project_id}</dd>
          <dt className="text-text-muted">Agent type</dt>
          <dd className="select-all font-mono text-text">{query.data.agent_type_id}</dd>
          <dt className="text-text-muted">Principal</dt>
          <dd className="select-all font-mono text-text">{query.data.principal_id}</dd>
        </dl>
      ) : (
        <div
          role="status"
          aria-label="Resolving scope"
          className="mt-3 h-16 animate-pulse rounded-md border border-border bg-bg"
        />
      )}
    </div>
  );
}

export default function Projects() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-text">Registry</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          Creating a project and binding a principal to it — the two writes that make server-side
          scope derivation possible at all. Both authenticate with the bootstrap admin key, a
          separate credential plane from the one every read on this dashboard uses.
        </p>
      </div>

      <CurrentScopeCard />

      <section>
        <h2 className="mb-3 text-sm font-semibold text-text">Registry actions</h2>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <CreateProjectForm />
          <RegisterAgentForm />
        </div>
      </section>

      <section className="rounded-lg border border-border bg-surface p-4">
        <h2 className="text-sm font-semibold text-text">What this page deliberately does not list</h2>
        <ul className="mt-2 space-y-1.5 text-xs text-text-muted">
          <li>
            <strong className="font-medium text-text">Other projects, principals or agent types.</strong>{" "}
            No route lists them, and none should: an enumeration of every tenant is not needed to
            create the next one, and PLAN.md §10 keeps this console single-project everywhere else.
          </li>
          <li>
            <strong className="font-medium text-text">The embedding pin and scoring epoch.</strong>{" "}
            <code className="font-mono">embedding_model</code> and{" "}
            <code className="font-mono">scoring_epoch</code> are unpartitioned registry tables with
            no read route. Both matter — a silent embedding swap invalidates the whole vault, and
            cross-epoch Q comparison is rejected — which is exactly why they are named here rather
            than rendered from a constant that never touched this deployment.
          </li>
          <li>
            <strong className="font-medium text-text">Partition headroom.</strong> PLAN.md §5 puts
            the ceiling at ~1,000 projects per instance. Counting partitions is an instance-wide
            question, not a project-scoped one, so it belongs to operational monitoring rather than
            to a route this dashboard can call.
          </li>
        </ul>
      </section>
    </div>
  );
}
