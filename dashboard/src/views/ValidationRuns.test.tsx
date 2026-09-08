import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ValidationRuns from "./ValidationRuns";

const { useDemoManifest, useExportRows } = vi.hoisted(() => ({
  useDemoManifest: vi.fn(),
  useExportRows: vi.fn(),
}));

vi.mock("../api/hooks", () => ({ useDemoManifest, useExportRows }));

describe("ValidationRuns", () => {
  beforeEach(() => {
    useDemoManifest.mockReturnValue({
      status: "success",
      data: {
        mode: "local_demo", title: "Evidence", schema_version: 1,
        provenance: "Imported after execution.",
        runs: [{ run_id: "11111111-1111-1111-1111-111111111111", label: "Python suite", status: "passed", facts: "5,189 passed." }],
      },
    });
    useExportRows.mockReturnValue({
      status: "success", truncated: false, error: undefined, reload: vi.fn(), rows: [{ table: "trace_index", row: {
        run_id: "11111111-1111-1111-1111-111111111111", outcome_status: "ok", ended_at: "2026-08-27T12:00:00Z",
      } }],
    });
  });

  it("joins checked-in evidence labels to authoritative trace export rows", () => {
    render(<ValidationRuns />);
    expect(screen.getByRole("heading", { name: "Validation Runs" })).toBeInTheDocument();
    expect(screen.getByText("Local demo")).toBeInTheDocument();
    expect(screen.getByText("Python suite")).toBeInTheDocument();
    expect(screen.getByText("5,189 passed.")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(screen.getByText("Imported after execution.")).toBeInTheDocument();
  });
});
