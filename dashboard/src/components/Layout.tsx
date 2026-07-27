import { useEffect, useState, type SVGProps } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { credentials } from "../api/client";
import { getResolvedTheme, toggleTheme } from "../lib/theme";

// The shell: sidebar nav for every view group PLAN.md §7 assigns across the
// five phases, plus the top bar (theme toggle, credential status). Route
// CONTENT for each nav item is out of this chunk's file list — App.tsx wires
// each path to its (for now, scaffolded) panel; a later agent replaces each
// panel with the real view without touching this file.

type IconProps = SVGProps<SVGSVGElement>;

function icon(path: string) {
  return function Icon(props: IconProps) {
    return (
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" {...props}>
        <path strokeLinecap="round" strokeLinejoin="round" d={path} />
      </svg>
    );
  };
}

const Icons = {
  overview: icon("M3 10.5 10 4l7 6.5M5 9v7h10V9"),
  injections: icon("M4 6h12M4 10h12M4 14h7"),
  vault: icon("M4 6.5C4 5 6.7 4 10 4s6 1 6 2.5-2.7 2.5-6 2.5-6-1-6-2.5Zm0 0V14c0 1.5 2.7 2.5 6 2.5s6-1 6-2.5V6.5M4 10.25c0 1.5 2.7 2.5 6 2.5s6-1 6-2.5"),
  reviewQueue: icon("M4 4h9l3 3v9H4V4Zm9 0v3h3M7 10h6M7 13h4"),
  lift: icon("M4 15 8 9l3.5 3L16 5M16 5h-3.5M16 5v3.5"),
  staleness: icon("M10 5.5v4.7l3 2M10 17a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z"),
  consolidation: icon("M6 5v6a4 4 0 0 0 4 4h4M14 5v10M6 5 3.5 7.5M6 5l2.5 2.5"),
  vaultTrend: icon("M4 16V6m4 10v-4m4 4V9m4 7V4"),
  forensics: icon("M9 9a5 5 0 1 1 0 10 5 5 0 0 1 0-10Zm5.5 8.5L17 20"),
  killSwitch: icon("M10 4v6M6 6.3a6 6 0 1 0 8 0"),
  spend: icon("M10 3.5v13M13.5 6.8c0-1.3-1.6-2.3-3.5-2.3s-3.5 1-3.5 2.3S8.1 9 10 9s3.5 1 3.5 2.3-1.6 2.3-3.5 2.3-3.5-1-3.5-2.3"),
  abstention: icon("M4 10h12M10 4v12M15.5 4.5l-11 11"),
  registry: icon("M3 17h14M5 17V7l5-3 5 3v10M8 10h4M8 13h4"),
  health: icon("M3 11h3l2-5 3 9 2-4h4"),
  settings: icon("M10 12.7a2.7 2.7 0 1 0 0-5.4 2.7 2.7 0 0 0 0 5.4Zm7-2.7c0 .4 0 .8-.1 1.2l1.6 1.2-1.5 2.6-1.9-.6c-.6.5-1.3.9-2 1.1L12.7 18H7.3l-.4-2.6c-.7-.2-1.4-.6-2-1.1l-1.9.6-1.5-2.6 1.6-1.2C3 10.8 3 10.4 3 10s0-.8.1-1.2L1.5 7.6l1.5-2.6 1.9.6c.6-.5 1.3-.9 2-1.1L7.3 2h5.4l.4 2.6c.7.2 1.4.6 2 1.1l1.9-.6 1.5 2.6-1.6 1.2c.1.4.1.8.1 1.2Z"),
};

interface NavItem {
  to: string;
  label: string;
  Icon: (p: IconProps) => JSX.Element;
}

// Grouped by the question an operator is holding, not by the table each view
// reads. "Is memory helping" and "what is in the vault" are different jobs and
// an undifferentiated list of twelve makes the reader do the sorting.
//
// Every entry routes to a view backed by a real route. Lift & Q, Staleness and
// Consolidation were removed when nothing fed them (D-094) and are back now
// that api/reports.py's D-093 aggregate reads exist. Each still states on its
// own page what its tables cannot answer — which is the honest version of the
// rule that removed them, not a reversal of it: a nav entry must lead to a
// page that reads real data, and all three now do.
const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Activity",
    items: [
      { to: "/", label: "Overview", Icon: Icons.overview },
      { to: "/injections", label: "Injections", Icon: Icons.injections },
      { to: "/abstention", label: "Abstention", Icon: Icons.abstention },
      { to: "/health", label: "Health", Icon: Icons.health },
    ],
  },
  {
    label: "The vault",
    items: [
      { to: "/memory-vault", label: "Memory Vault", Icon: Icons.vault },
      { to: "/vault-trend", label: "Vault Trend", Icon: Icons.vaultTrend },
      { to: "/staleness", label: "Staleness", Icon: Icons.staleness },
      { to: "/consolidation", label: "Consolidation", Icon: Icons.consolidation },
    ],
  },
  {
    label: "Govern",
    items: [
      { to: "/review-queue", label: "Review Queue", Icon: Icons.reviewQueue },
      { to: "/forensics", label: "Forensics", Icon: Icons.forensics },
      { to: "/lift-and-q", label: "Lift & Q", Icon: Icons.lift },
      { to: "/kill-switch", label: "Kill Switch", Icon: Icons.killSwitch },
    ],
  },
  {
    label: "Operate",
    items: [
      { to: "/spend", label: "Spend", Icon: Icons.spend },
      { to: "/registry", label: "Registry", Icon: Icons.registry },
      { to: "/settings", label: "Settings", Icon: Icons.settings },
    ],
  },
];

function ThemeToggle() {
  const [resolved, setResolved] = useState<"light" | "dark">("light");
  useEffect(() => setResolved(getResolvedTheme()), []);
  return (
    <button
      type="button"
      onClick={() => {
        toggleTheme();
        setResolved(getResolvedTheme());
      }}
      aria-label={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      title={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      className="rounded-md border border-border-strong p-1.5 text-text-muted transition-colors hover:bg-surface-raised hover:text-text"
    >
      {resolved === "dark" ? (
        <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
          <path d="M10 2.5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 10 2.5Zm4.53 2.22a.75.75 0 0 1 1.06 1.06l-1.06 1.06a.75.75 0 1 1-1.06-1.06l1.06-1.06Zm-9.06 0 1.06 1.06a.75.75 0 1 1-1.06 1.06L4.41 5.78A.75.75 0 1 1 5.47 4.72ZM10 6.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7ZM2.5 10a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 0 1.5h-1.5A.75.75 0 0 1 2.5 10Zm12.75-.75h1.5a.75.75 0 0 1 0 1.5h-1.5a.75.75 0 0 1 0-1.5Zm-9.53 5.03 1.06 1.06a.75.75 0 1 1-1.06 1.06L4.65 15.34a.75.75 0 0 1 1.06-1.06Zm7.6 0a.75.75 0 0 1 1.06 1.06l-1.06 1.06a.75.75 0 1 1-1.06-1.06l1.06-1.06ZM10 15.75a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5a.75.75 0 0 1 .75-.75Z" />
        </svg>
      ) : (
        <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
          <path d="M17.5 12.6a7.5 7.5 0 0 1-9.6-9.9.75.75 0 0 0-.9-1A8.97 8.97 0 0 0 2 10a9 9 0 0 0 16.4 5.15.75.75 0 0 0-.9-.98 7.46 7.46 0 0 1-.99-.57Z" />
        </svg>
      )}
    </button>
  );
}

function CredentialStatus() {
  const [principal, setPrincipal] = useState(() => credentials.getPrincipal());
  const [adminKey, setAdminKey] = useState(() => credentials.getAdminKey() !== null);

  // Settings (a route this shell scaffolds but does not itself implement)
  // writes to the same localStorage keys via `api/client.ts`'s `credentials`
  // module — poll on focus so a credential entered there shows up here
  // without wiring a cross-component event bus for two booleans.
  useEffect(() => {
    function refresh() {
      setPrincipal(credentials.getPrincipal());
      setAdminKey(credentials.getAdminKey() !== null);
    }
    window.addEventListener("focus", refresh);
    return () => window.removeEventListener("focus", refresh);
  }, []);

  return (
    <div className="flex items-center gap-3 text-xs text-text-muted">
      <span className="inline-flex items-center gap-1.5">
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 rounded-full ${principal !== null ? "bg-status-validated-fg" : "bg-status-quarantined-fg"}`}
        />
        {principal !== null ? `Signed in (${principal.mode})` : "No credential"}
      </span>
      {adminKey && (
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-tier-a" />
          Admin key set
        </span>
      )}
    </div>
  );
}

export function Layout() {
  return (
    <div className="flex min-h-screen bg-bg text-text">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-contrast"
      >
        Skip to content
      </a>
      <nav
        aria-label="Primary"
        className="flex w-60 shrink-0 flex-col border-r border-border bg-surface"
      >
        <div className="flex items-center gap-2 px-4 py-4">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-accent text-sm font-semibold text-accent-contrast">
            T
          </span>
          <span className="text-sm font-semibold tracking-tight">Tracebed</span>
        </div>
        <div className="flex-1 space-y-4 overflow-y-auto px-2 pb-4">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              <h2 className="px-2.5 pb-1 text-[10px] font-semibold uppercase tracking-widest text-text-faint">
                {group.label}
              </h2>
              <ul className="space-y-0.5">
                {group.items.map(({ to, label, Icon }) => (
                  <li key={to}>
                    <NavLink
                      to={to}
                      end={to === "/"}
                      className={({ isActive }) =>
                        // The left rule, not the tint, is what survives a
                        // colour-vision deficiency; aria-current carries it
                        // for assistive tech (NavLink sets it on active).
                        `flex items-center gap-2.5 rounded-md border-l-2 px-2.5 py-2 text-sm font-medium transition-colors ${
                          isActive
                            ? "border-accent bg-accent/10 text-accent"
                            : "border-transparent text-text-muted hover:bg-surface-raised hover:text-text"
                        }`
                      }
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      {label}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-border bg-surface px-6 py-3">
          <CredentialStatus />
          <ThemeToggle />
        </header>
        <main id="main-content" className="min-w-0 flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
