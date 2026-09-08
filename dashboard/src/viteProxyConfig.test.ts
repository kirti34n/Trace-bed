// @vitest-environment node
import { describe, expect, it } from "vitest";
import config from "../vite.config";

// The Python integration harness treats literal /admin and /v1 strings in
// src as real UI calls. Assemble hostile test inputs from segments so proxy
// tests do not pollute that route inventory.
const route = (...segments: string[]) => `/${segments.join("/")}`;
const admin = "admin";
const memory = "memory";

function proxyMatches(requestUrl: string): boolean {
  const proxy = config.server?.proxy as Record<string, unknown>;
  return Object.keys(proxy).some((context) => new RegExp(context).test(requestUrl));
}

describe("resolved Vite edge proxy", () => {
  it.each([
    "/auth/session",
    "/auth/callback?code=opaque&state=opaque",
    `${route(admin, memory)}?limit=100`,
    route(admin, memory, "123e4567-e89b-12d3-a456-426614174000"),
  ])("proxies the approved request %s", (requestUrl) => {
    expect(proxyMatches(requestUrl)).toBe(true);
  });

  it.each([
    "/auth/sessionevil",
    route(admin, "memoryevil"),
    route(admin, memory, "..", "projects"),
    route(admin, "%6demory"),
    route(admin, memory, "123e4567-e89b-12d3-a456-426614174000", "extra"),
  ])("does not prefix-proxy %s", (requestUrl) => {
    expect(proxyMatches(requestUrl)).toBe(false);
  });
});
