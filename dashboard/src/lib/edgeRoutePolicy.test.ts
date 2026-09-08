import { describe, expect, it } from "vitest";
import { isApprovedEdgePath } from "./edgeRoutePolicy";

// Build adversarial paths from segments. The Python integration harness
// deliberately extracts literal /admin and /v1 strings from dashboard/src as
// real browser calls; keeping rejection probes non-literal prevents its route
// inventory from mistaking test inputs for application transport paths.
const route = (...segments: string[]) => `/${segments.join("/")}`;
const admin = "admin";
const memory = "memory";

describe("development edge route policy", () => {
  it("allows the BFF status route and approved data routes", () => {
    expect(isApprovedEdgePath("/auth/session")).toBe(true);
    expect(isApprovedEdgePath(route(admin, memory))).toBe(true);
    expect(isApprovedEdgePath(route(admin, memory, "123e4567-e89b-12d3-a456-426614174000"))).toBe(true);
  });

  it.each([
    route(admin, "projects"),
    route(admin, "agents", "register"),
    route("v1", "erasure-requests"),
    route(admin, "", memory),
    route(admin, "%6demory"),
    route(admin, ".", memory),
    route(admin, memory, "..", "projects"),
    route("", admin, memory),
  ])("rejects %s", (path) => {
    expect(isApprovedEdgePath(path)).toBe(false);
  });
});
