import { useScope } from "../api/hooks";
import { ErrorState } from "../components/ErrorState";

function CurrentScopeCard() {
  const query = useScope();
  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <h2 className="text-sm font-semibold text-text">This session&rsquo;s scope</h2>
      <p className="mt-1 text-xs text-text-muted">
        From <code className="font-mono">GET /admin/whoami</code>. The API derives this scope from
        the authenticated BFF session; it is never selected by the browser.
      </p>
      {query.status === "error" ? (
        <div className="mt-3">
          <ErrorState error={query.error} onRetry={query.reload} title="No scope resolves for this credential" />
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
          The API is intentionally project-scoped and has no owner onboarding routes. Create projects
          and agents through the owner-side one-shot onboarding operation, then sign in through
          the approved identity flow to reach the resulting scope.
        </p>
      </div>

      <CurrentScopeCard />

      <section className="rounded-lg border border-border bg-surface p-4">
        <h2 className="text-sm font-semibold text-text">Onboarding boundary</h2>
        <p className="mt-2 max-w-3xl text-xs text-text-muted">
          This dashboard cannot create a project, register an agent, mint a principal, or choose a
          project. Those owner operations do not share the normal API&rsquo;s database identity or HTTP
          surface, so a browser session cannot accidentally acquire registry-wide authority.
        </p>
      </section>
    </div>
  );
}
