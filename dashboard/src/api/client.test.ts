import { afterEach, describe, expect, it, vi } from "vitest";
import { get, getSessionStatus, postJson, setSynchronizerCsrfToken } from "./client";
import { authenticatedSession } from "../test/fixtures";

function response(body: unknown, status = 200): Response {
  return new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    statusText: status === 200 ? "OK" : "Failure",
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  setSynchronizerCsrfToken(null);
});

describe("same-origin BFF client", () => {
  it("uses only same-origin cookie requests and never storage-backed auth", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response(authenticatedSession));
    vi.stubGlobal("fetch", fetchMock);
    await expect(getSessionStatus()).resolves.toEqual(authenticatedSession);
    expect(fetchMock).toHaveBeenCalledWith("/auth/session", expect.objectContaining({ credentials: "same-origin" }));
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("attaches the synchronizer header to every JSON mutation", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response(undefined, 204));
    vi.stubGlobal("fetch", fetchMock);
    setSynchronizerCsrfToken("csrf-value");
    await postJson("/v1/trace", { run_id: "run-1" });
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("csrf-value");
    expect(new Headers(init.headers).get("Authorization")).toBeNull();
    expect(new Headers(init.headers).get("X-Api-Key")).toBeNull();
  });

  it("fails closed before a mutation if there is no session synchronizer", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(postJson("/v1/trace", {})).rejects.toMatchObject({ kind: "unauthorized" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([[401, "unauthorized"], [403, "forbidden"], [404, "not_found"], [500, "server"]] as const)("maps %s to %s", async (status, kind) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response({ detail: "opaque" }, status)));
    await expect(get("/admin/whoami")).rejects.toEqual(expect.objectContaining({ kind, status }));
  });

  it("rejects non-same-origin paths before sending a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(get("https://example.invalid/admin/whoami")).rejects.toThrow("same-origin");
    await expect(get("//example.invalid/admin/whoami")).rejects.toThrow("same-origin");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
