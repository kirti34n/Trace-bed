import { lazy, Suspense } from "react";
import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { SessionProvider, useSession } from "./auth/session";

// Every route here renders a real view against a real route. There is no
// scaffold panel and no fixture page left in this tree: a view whose data has
// no source was deleted rather than stubbed (D-094).
//
// Lift & Q, Staleness and Consolidation are back, because the routes that feed
// them now exist (api/reports.py's four D-093 aggregate reads). Each of the
// three renders only what its route actually returns and states, on the page,
// what the underlying tables cannot answer — a view that is unreachable is
// indistinguishable from one that was never built, and these three had been
// left built-but-unrouted, which is the worst of both.
//
// Lazy-loaded per route. The views are large and independent — an operator
// opening the Overview should not pay to parse the Forensics blast-radius
// scanner — and code-splitting here costs one Suspense boundary rather than a
// bundler config.

const Overview = lazy(() => import("./views/Overview"));
const Injections = lazy(() => import("./views/Injections"));
const MemoryVault = lazy(() => import("./views/MemoryVault"));
const MemoryDetail = lazy(() => import("./views/MemoryDetail"));
const ReviewQueue = lazy(() => import("./views/ReviewQueue"));
const Abstention = lazy(() => import("./views/Abstention"));
const VaultTrend = lazy(() => import("./views/VaultTrend"));
const Forensics = lazy(() => import("./views/Forensics"));
const KillSwitch = lazy(() => import("./views/KillSwitch"));
const LiftAndQ = lazy(() => import("./views/LiftAndQ"));
const Staleness = lazy(() => import("./views/Staleness"));
const Consolidation = lazy(() => import("./views/Consolidation"));
const Spend = lazy(() => import("./views/Spend"));
const Health = lazy(() => import("./views/Health"));
const Projects = lazy(() => import("./views/Projects"));
const Settings = lazy(() => import("./views/Settings"));
const ValidationRuns = lazy(() => import("./views/ValidationRuns"));

/** Route-level loading. Fixed height and the same border/surface as a real
 * panel so the page does not reflow when the chunk lands — a view that jumps
 * on arrival reads as a bug on a console whose tables are the instrument. */
function RouteFallback() {
  return (
    <div
      role="status"
      aria-label="Loading view"
      className="h-64 animate-pulse rounded-lg border border-border bg-surface"
    />
  );
}

/** Do not mount data views until the BFF session is known to be authenticated.
 * This makes logout and auth loss clear rendered project state synchronously,
 * even if the subsequent `/auth/session` probe is slow or fails. */
function ProtectedOutlet() {
  const { phase, login, error, reload } = useSession();
  if (phase === "authenticated") return <Outlet />;
  if (phase === "anonymous") {
    return (
      <div className="rounded-lg border border-border bg-surface p-6">
        <h1 className="text-lg font-semibold text-text">Sign in required</h1>
        <p className="mt-1 text-sm text-text-muted">Use the same-origin identity flow to access project-scoped views.</p>
        <button type="button" onClick={login} className="mt-4 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast">Sign in</button>
      </div>
    );
  }
  if (phase === "error") {
    return <div role="alert" className="rounded-lg border border-status-quarantined-border bg-status-quarantined-bg p-6 text-sm text-status-quarantined-fg">Could not verify the session{error?.message ? ": " + error.message : "."}<button type="button" onClick={reload} className="ml-3 underline">Retry</button></div>;
  }
  return <RouteFallback />;
}

function RoutedApp() {
  // There is no client query cache, but pages do retain local data/filter
  // state. An authentication transition remounts the route tree so no result,
  // selection, or filter survives under a different BFF identity.
  const { epoch } = useSession();
  return (
    <Routes key={epoch}>
      <Route element={<Layout />}>
        <Route element={<ProtectedOutlet />}>
          <Route element={<Suspense fallback={<RouteFallback />}><Outlet /></Suspense>}>
          <Route index element={<Overview />} />
          <Route path="injections" element={<Injections />} />
          <Route path="memory-vault" element={<MemoryVault />} />
          {/* The vault table and the review queue both link here by id; the
              detail view is the only place a memory's provenance is readable,
              which is what makes a row governable rather than just visible. */}
          <Route path="memory-vault/:memoryId" element={<MemoryDetail />} />
          <Route path="review-queue" element={<ReviewQueue />} />
          <Route path="abstention" element={<Abstention />} />
          <Route path="vault-trend" element={<VaultTrend />} />
          <Route path="forensics" element={<Forensics />} />
          <Route path="kill-switch" element={<KillSwitch />} />
          <Route path="lift-and-q" element={<LiftAndQ />} />
          <Route path="staleness" element={<Staleness />} />
          <Route path="consolidation" element={<Consolidation />} />
          <Route path="spend" element={<Spend />} />
          <Route path="health" element={<Health />} />
          <Route path="registry" element={<Projects />} />
          <Route path="settings" element={<Settings />} />
          <Route path="validation-runs" element={<ValidationRuns />} />
          <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Route>
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <SessionProvider>
      <RoutedApp />
    </SessionProvider>
  );
}
