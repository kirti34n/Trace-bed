import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useExportRows } from "./hooks";

const encoder = new TextEncoder();
const EXPORT_MAX = 16 * 1024 * 1024;

function exportResponse(stream: ReadableStream<Uint8Array>, headers: Record<string, string> = {}) {
  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson",
      "X-Tracebed-Export-Completeness": "complete",
      "X-Tracebed-Export-Max-Bytes": String(EXPORT_MAX),
      ...headers,
    },
  });
}

function Probe({ maxRows = 5_000 }: { maxRows?: number }) {
  const query = useExportRows(["memory_item"], maxRows);
  return <p>{query.status}:{query.rows.length}:{String(query.truncated)}:{query.error?.kind ?? "none"}</p>;
}

afterEach(() => vi.unstubAllGlobals());

describe("useExportRows bounded export contract", () => {
  it("accepts a complete export body larger than the ordinary 1 MiB BFF limit", async () => {
    const line = encoder.encode(`${JSON.stringify({ table: "memory_item", row: { text: "x".repeat(1_100_000) } })}\n`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse(new ReadableStream({ start(c) { c.enqueue(line); c.close(); } }), { "Content-Length": String(line.byteLength) })));
    render(<Probe />);
    await screen.findByText("success:1:false:none");
  });

  it("rejects an over-16 MiB stream and never renders its partial rows", async () => {
    const first = encoder.encode(`${JSON.stringify({ table: "memory_item", row: { id: "partial" } })}\n`);
    const excess = new Uint8Array(EXPORT_MAX);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse(new ReadableStream({ start(c) { c.enqueue(first); c.enqueue(excess); c.close(); } }))));
    render(<Probe />);
    await screen.findByText("error:0:false:server");
    expect(screen.queryByText(/success:1/)).toBeNull();
  });

  it("rejects a bounded chunked export before it can render a partial snapshot", async () => {
    const line = encoder.encode(`${JSON.stringify({ table: "memory_item", row: { id: "partial" } })}\n`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse(new ReadableStream({ start(c) { c.enqueue(line); } }), { "X-Tracebed-Export-Completeness": "bounded" })));
    render(<Probe />);
    await screen.findByText("error:0:false:server");
  });

  it("cancels the reader when the local row cap stops traversal", async () => {
    const cancel = vi.fn();
    const lines = encoder.encode(`${JSON.stringify({ table: "memory_item", row: { id: "one" } })}\n${JSON.stringify({ table: "memory_item", row: { id: "two" } })}\n`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse(new ReadableStream({ start(c) { c.enqueue(lines); }, cancel }))));
    render(<Probe maxRows={1} />);
    await screen.findByText("success:1:true:none");
    await waitFor(() => expect(cancel).toHaveBeenCalled());
  });

  it("cancels a pending reader when the view unmounts", async () => {
    const cancel = vi.fn();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse(new ReadableStream({ cancel }))));
    const view = render(<Probe />);
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    view.unmount();
    await waitFor(() => expect(cancel).toHaveBeenCalled());
  });
});
