// The only module that performs HTTP. The dashboard intentionally speaks only
// to its own origin: the reverse proxy/BFF owns upstream identity credentials
// and browser code never sees, stores, or forwards them.
import type { SessionStatusOut } from "./types";

export type ApiErrorKind =
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "validation"
  | "server"
  | "network"
  | "cancelled";

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

const AUTH_CHANGED_EVENT = "tracebed:auth-changed";
let synchronizerCsrfToken: string | null = null;
const EXPORT_MAX_BYTES_HEADER = "X-Tracebed-Export-Max-Bytes";
const EXPORT_COMPLETENESS_HEADER = "X-Tracebed-Export-Completeness";

/** Kept in module memory only. It is deliberately neither a credential nor a
 * session identifier; refresh/navigate drops it and status fetches mint/read it
 * again from the BFF's authenticated cookie session. */
export function setSynchronizerCsrfToken(token: string | null): void {
  synchronizerCsrfToken = token;
}

export function notifyAuthenticationChanged(): void {
  synchronizerCsrfToken = null;
  window.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
}

export function onAuthenticationChanged(listener: () => void): () => void {
  window.addEventListener(AUTH_CHANGED_EVENT, listener);
  return () => window.removeEventListener(AUTH_CHANGED_EVENT, listener);
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

/** Refuse accidental cross-origin, protocol-relative, or relative URL use at
 * the one transport boundary. All application routes are absolute paths. */
function sameOriginPath(path: string): string {
  if (!path.startsWith("/") || path.startsWith("//") || /[\r\n]/.test(path)) {
    throw new Error("dashboard API paths must be same-origin absolute paths");
  }
  return path;
}

function containsProjectId(value: unknown, depth = 0): boolean {
  if (depth > 8 || value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((entry) => containsProjectId(entry, depth + 1));
  return Object.entries(value as Record<string, unknown>).some(
    ([key, entry]) => key === "project_id" || containsProjectId(entry, depth + 1)
  );
}

function assertNoProjectId(body: unknown): void {
  if (import.meta.env.DEV && containsProjectId(body)) {
    throw new Error("request body must not carry project_id; scope is server-derived");
  }
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

interface RequestOptions {
  signal?: AbortSignal;
  csrf?: boolean;
}

async function execute<T>(path: string, init: RequestInit, opts: RequestOptions = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (opts.csrf) {
    if (synchronizerCsrfToken === null) {
      throw new ApiError("unauthorized", "no active session synchronizer token");
    }
    headers.set("X-CSRF-Token", synchronizerCsrfToken);
  }

  let res: Response;
  try {
    res = await fetch(sameOriginPath(path), {
      ...init,
      headers,
      credentials: "same-origin",
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
    if (res.status === 401) notifyAuthenticationChanged();
    throw new ApiError(kindForStatus(res.status), `${res.status} ${res.statusText}`, res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return text.length === 0 ? (undefined as T) : (JSON.parse(text) as T);
}

export function get<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  return execute<T>(path, { method: "GET" }, opts);
}

export function postJson<T>(path: string, body: unknown, opts: RequestOptions = {}): Promise<T> {
  assertNoProjectId(body);
  return execute<T>(
    path,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
    { ...opts, csrf: true }
  );
}

/** BFF session status contains no bearer/API token or session identifier. */
export function getSessionStatus(signal?: AbortSignal): Promise<SessionStatusOut> {
  return get<SessionStatusOut>("/auth/session", { signal });
}

/** Login is an IdP/BFF navigation, never a credential form or XHR exchange. */
export function beginLogin(): void {
  window.location.assign("/auth/login");
}

export async function logout(signal?: AbortSignal): Promise<void> {
  await postJson<void>("/auth/logout", {}, { signal });
  notifyAuthenticationChanged();
}

/** An export is safe to render only when the BFF committed to a complete,
 * bounded relay before sending bytes. A chunked relay marked `bounded` may be
 * cut at the edge limit, leaving an EOF indistinguishable from a full export.
 * Reject it before exposing any rows rather than presenting a partial project
 * snapshot as a successful query. */
function completeExportLimit(res: Response): number {
  const max = Number(res.headers.get(EXPORT_MAX_BYTES_HEADER));
  if (!Number.isSafeInteger(max) || max <= 0) {
    throw new ApiError("server", "export response omitted a valid maximum-byte bound");
  }
  if (res.headers.get(EXPORT_COMPLETENESS_HEADER) !== "complete") {
    throw new ApiError("server", "export stream completeness cannot be established");
  }
  const contentLength = res.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > max) {
      throw new ApiError("server", "export response exceeds its declared maximum-byte bound");
    }
  }
  return max;
}

export async function* streamNdjson<T>(path: string, opts: RequestOptions = {}): AsyncGenerator<T, void, unknown> {
  let res: Response;
  try {
    res = await fetch(sameOriginPath(path), { method: "GET", credentials: "same-origin", signal: opts.signal });
  } catch (err) {
    if (opts.signal?.aborted || (err instanceof DOMException && err.name === "AbortError")) {
      throw new ApiError("cancelled", "request was cancelled");
    }
    throw new ApiError("network", err instanceof Error ? err.message : "network error");
  }
  if (!res.ok) {
    const detail = await parseErrorDetail(res);
    if (res.status === 401) notifyAuthenticationChanged();
    throw new ApiError(kindForStatus(res.status), `${res.status} ${res.statusText}`, res.status, detail);
  }
  let maxBytes: number | undefined;
  if (path === "/export/project") {
    try {
      maxBytes = completeExportLimit(res);
    } catch (err) {
      await res.body?.cancel().catch(() => undefined);
      throw err;
    }
  }
  if (res.body === null) return;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let completed = false;
  let observedBytes = 0;
  const cancelReader = () => void reader.cancel().catch(() => undefined);
  if (opts.signal?.aborted) cancelReader();
  else opts.signal?.addEventListener("abort", cancelReader, { once: true });
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        completed = true;
        break;
      }
      observedBytes += value.byteLength;
      if (maxBytes !== undefined && observedBytes > maxBytes) {
        throw new ApiError("server", "export stream exceeded its maximum-byte bound");
      }
      buffer += decoder.decode(value, { stream: true });
      let newline: number;
      while ((newline = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line.trim()) yield JSON.parse(line) as T;
      }
    }
    if (buffer.trim()) yield JSON.parse(buffer) as T;
  } finally {
    // `for await` calls this path on a row cap; effect cleanup reaches it via
    // AbortController. Both explicitly cancel the network reader rather than
    // relying on garbage collection to stop an upstream export.
    if (!completed) await reader.cancel().catch(() => undefined);
    opts.signal?.removeEventListener("abort", cancelReader);
    reader.releaseLock();
  }
}
