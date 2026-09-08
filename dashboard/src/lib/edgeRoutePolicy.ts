/** Exact browser routes that may reach the local edge in development. This is
 * deliberately a deny-by-default mirror of the production BFF surface. */
export const EDGE_EXACT_PATHS = [
  "/auth/login", "/auth/callback", "/auth/csrf", "/auth/session", "/auth/logout", "/auth/demo-manifest",
  "/v1/retrieve", "/v1/trace", "/v1/trace/batch", "/v1/feedback", "/v1/propose_memory", "/v1/invalidation",
  "/admin/whoami", "/admin/memory", "/admin/injections", "/admin/review_queue", "/admin/killswitch_state", "/admin/invalidations", "/admin/spend", "/admin/config", "/admin/lift/report", "/admin/staleness/report", "/admin/consolidation/diffs",
  "/export/project", "/healthz",
] as const;

const EXACT = new Set<string>(EDGE_EXACT_PATHS);
const MEMORY_ID_PATTERN = "/admin/memory/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const MEMORY_ID = new RegExp(`^${MEMORY_ID_PATTERN}$`);

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function isApprovedEdgePath(path: string): boolean {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\") || path.includes("%") || path.includes("/./") || path.includes("/../")) return false;
  return EXACT.has(path) || MEMORY_ID.test(path);
}

function proxyContextForApprovedPath(path: string): string {
  if (!isApprovedEdgePath(path)) throw new Error(`refusing an unapproved proxy context: ${path}`);
  return `^${escapeRegex(path)}(?:\\?.*)?$`;
}

/** Vite's proxy accepts string contexts, which prefix-match unless the context
 * starts with `^`. These anchored contexts are generated from the same policy
 * that decides whether a browser route is allowed at all. Query strings stay
 * permitted because the policy is about a request pathname, not query values. */
export const EDGE_PROXY_CONTEXTS = [
  ...EDGE_EXACT_PATHS.map(proxyContextForApprovedPath),
  `^${MEMORY_ID_PATTERN}(?:\\?.*)?$`,
] as const;
