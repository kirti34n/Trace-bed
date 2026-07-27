// THE one place that talks HTTP (task brief, rule 3). Every hook in
// api/hooks.ts goes through the functions exported here; no component or
// hook is allowed to call `fetch` directly.
//
// Two independent guarantees live here, both load-bearing for invariant 4:
//   1. `assertNoProjectId` — a body or query object containing a `project_id`
//      key throws in development, UNLESS the call site explicitly opted in
//      via `{ allowProjectId: true }`. Exactly one route may do that:
//      `POST /admin/agents/register`, where the ADMIN names the project
//      being provisioned (contract §9.3's own parenthetical). Every other
//      route derives scope from the authenticated principal server-side.
//   2. Typed errors distinguish 401/403/404/409/422/5xx so a hook can render
//      "you're not signed in" differently from "that memory isn't yours (or
//      doesn't exist)" differently from "the server broke" — collapsing
//      these into one generic Error is exactly what makes an ErrorState
//      useless to an operator deciding what to do next.

// --------------------------------------------------------------------- //
// Credentials. The dashboard has no login route of its own to call (none
// exists in the contract — see README's contract gaps): an operator pastes
// in the bearer token or `tb_sk_...` API key their registration minted, plus
// the bootstrap admin key if they hold one, and this module is the only
// reader/writer of where those live (localStorage, never sent anywhere but
// the Authorization/X-Api-Key/X-Admin-Key headers below).
// --------------------------------------------------------------------- //

export type PrincipalAuthMode = "bearer" | "api_key";

export interface PrincipalCredential {
  mode: PrincipalAuthMode;
  value: string;
}

const PRINCIPAL_KEY = "tb:auth:principal";
const ADMIN_KEY = "tb:auth:admin_key";

function readJson<T>(key: string): T | null {
  const raw = window.localStorage.getItem(key);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export const credentials = {
  getPrincipal(): PrincipalCredential | null {
    return readJson<PrincipalCredential>(PRINCIPAL_KEY);
  },
  setPrincipal(cred: PrincipalCredential | null): void {
    if (cred === null) window.localStorage.removeItem(PRINCIPAL_KEY);
    else window.localStorage.setItem(PRINCIPAL_KEY, JSON.stringify(cred));
  },
  getAdminKey(): string | null {
    return window.localStorage.getItem(ADMIN_KEY);
  },
  setAdminKey(key: string | null): void {
    if (key === null) window.localStorage.removeItem(ADMIN_KEY);
    else window.localStorage.setItem(ADMIN_KEY, key);
  },
};

// --------------------------------------------------------------------- //
// Typed errors (api/main.py §9.4's exact mapping, plus the client-side
// states it has no opinion about: network failure and cancellation).
// --------------------------------------------------------------------- //

export type ApiErrorKind =
  | "unauthorized" // 401 — AuthenticationFailed
  | "forbidden" // 403 — ScopeResolutionFailed (no agent_registration row)
  | "not_found" // 404 — NotFound (uniform for "absent" and "not your project")
  | "conflict" // 409 — DuplicateRegistration
  | "validation" // 422 — pydantic extra="forbid" / field errors
  | "server" // 5xx or any TracebedError with no specific mapping
  | "network" // fetch itself rejected (offline, DNS, CORS, refused)
  | "cancelled"; // the caller's AbortSignal fired

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;
  readonly detail: unknown;

  constructor(kind: ApiErrorKind, message: string, status?: number, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.detail = detail;
  }
}

function kindForStatus(status: number): ApiErrorKind {
  switch (status) {
    case 401:
      return "unauthorized";
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 422:
      return "validation";
    default:
      return "server";
  }
}

// --------------------------------------------------------------------- //
// The project_id guard (invariant 4). Recursive and depth-bounded: a nested
// payload (e.g. `retention_policy` jsonb) hiding a `project_id` key would
// otherwise slip past a shallow check.
// --------------------------------------------------------------------- //

function containsProjectId(value: unknown, depth = 0): boolean {
  if (depth > 8 || value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((v) => containsProjectId(v, depth + 1));
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
    if (key === "project_id") return true;
    if (containsProjectId(v, depth + 1)) return true;
  }
  return false;
}

function assertNoProjectId(body: unknown, allowProjectId: boolean): void {
  if (import.meta.env.DEV && !allowProjectId && containsProjectId(body)) {
    throw new Error(
      "invariant 4 violation: request body carries a project_id — the server " +
        "derives scope from the authenticated principal; no data route may send one " +
        "(the one legitimate exception, POST /admin/agents/register, must pass " +
        "{ allowProjectId: true } explicitly)."
    );
  }
}

// --------------------------------------------------------------------- //
// The fetch wrapper. `API_BASE` is empty by default (same-origin — works
// against vite.config.ts's dev proxy and nginx.conf's prod reverse proxy
// identically); VITE_API_BASE overrides it for a build that talks to a
// non-same-origin API.
// --------------------------------------------------------------------- //

const API_BASE: string = import.meta.env.VITE_API_BASE ?? "";

interface RequestOptions {
  signal?: AbortSignal;
  /** See `assertNoProjectId` — do not set this anywhere but the one route
   * the contract names. */
  allowProjectId?: boolean;
}

function principalAuthHeaders(): HeadersInit {
  const cred = credentials.getPrincipal();
  if (cred === null) return {};
  return cred.mode === "bearer"
    ? { Authorization: `Bearer ${cred.value}` }
    : { "X-Api-Key": cred.value };
}

function adminAuthHeaders(): HeadersInit {
  const key = credentials.getAdminKey();
  return key === null ? {} : { "X-Admin-Key": key };
}

async function parseErrorDetail(res: Response): Promise<unknown> {
  try {
    return await res.clone().json();
  } catch {
    try {
      return await res.text();
    } catch {
      return undefined;
    }
  }
}

async function execute<T>(
  path: string,
  init: RequestInit,
  opts: RequestOptions
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, signal: opts.signal });
  } catch (err) {
    if (opts.signal?.aborted || (err instanceof DOMException && err.name === "AbortError")) {
      throw new ApiError("cancelled", "request was cancelled");
    }
    throw new ApiError("network", err instanceof Error ? err.message : "network error");
  }
  if (!res.ok) {
    const detail = await parseErrorDetail(res);
    throw new ApiError(kindForStatus(res.status), `${res.status} ${res.statusText}`, res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return text.length === 0 ? (undefined as T) : (JSON.parse(text) as T);
}

/** GET against a principal-scoped route (`/v1/*` reads, `/admin/memory/{id}`). */
export function get<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  return execute<T>(path, { method: "GET", headers: { ...principalAuthHeaders() } }, opts);
}

/** POST against a principal-scoped route (`/v1/*`). */
export function postJson<T>(
  path: string,
  body: unknown,
  opts: RequestOptions = {}
): Promise<T> {
  assertNoProjectId(body, opts.allowProjectId ?? false);
  return execute<T>(
    path,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", ...principalAuthHeaders() },
      body: JSON.stringify(body),
    },
    opts
  );
}

/** POST against the bootstrap admin-key routes (`/admin/projects`,
 * `/admin/agents/register`) — a distinct auth plane on purpose (contract
 * §9.3/C-20): no `agent_registration` row can exist yet for a caller these
 * routes are about to create one for. */
export function postAdmin<T>(
  path: string,
  body: unknown,
  opts: RequestOptions = {}
): Promise<T> {
  assertNoProjectId(body, opts.allowProjectId ?? false);
  return execute<T>(
    path,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", ...adminAuthHeaders() },
      body: JSON.stringify(body),
    },
    opts
  );
}

/**
 * Streams `GET /export/project`'s `application/x-ndjson` body (contract
 * §9.3) one parsed line at a time, so a huge project export never sits fully
 * materialised in a JS string before the first row is usable. The connection
 * stays open for the caller's `for await` — abort `opts.signal` to stop early
 * without waiting for the server to finish streaming.
 */
export async function* streamNdjson<T>(
  path: string,
  opts: RequestOptions = {}
): AsyncGenerator<T, void, unknown> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "GET",
      headers: { ...principalAuthHeaders() },
      signal: opts.signal,
    });
  } catch (err) {
    if (opts.signal?.aborted || (err instanceof DOMException && err.name === "AbortError")) {
      throw new ApiError("cancelled", "request was cancelled");
    }
    throw new ApiError("network", err instanceof Error ? err.message : "network error");
  }
  if (!res.ok) {
    const detail = await parseErrorDetail(res);
    throw new ApiError(kindForStatus(res.status), `${res.status} ${res.statusText}`, res.status, detail);
  }
  const body = res.body;
  if (body === null) return;
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let newlineIndex: number;
      while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newlineIndex);
        buffer = buffer.slice(newlineIndex + 1);
        if (line.trim().length > 0) yield JSON.parse(line) as T;
      }
    }
    if (buffer.trim().length > 0) yield JSON.parse(buffer) as T;
  } finally {
    reader.releaseLock();
  }
}
