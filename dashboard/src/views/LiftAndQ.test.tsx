import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import LiftAndQ from "./LiftAndQ";

const { useLiftReport } = vi.hoisted(() => ({ useLiftReport: vi.fn() }));

vi.mock("../api/hooks", () => ({ useLiftReport }));

describe("LiftAndQ", () => {
  beforeEach(() => {
    useLiftReport.mockReturnValue({
      status: "success",
      error: undefined,
      reload: vi.fn(),
      data: {
        window: { since: "2026-08-01T00:00:00Z", days: 14, observations_considered: 0, observations_truncated: false, observations_cap: 1000 },
        methodology: { min_cell_n: 200, killswitch_window_days: 14, correction: "BH", confidence: 0.95, bh_alpha: 0.05, bh_hypotheses: 0, source: "project" },
        cells: [],
        q_trajectory: { limit: 100, offset: 0, returned: 1, items: [{ memory_id: "memory-1", agent_type_id: "agent-1", mem_type: "lesson", q_value: 0.7, confidence: 0.8, scored_use_count: 3, observed_at: "2026-08-27T00:00:00Z", scoring_epoch_id: 4 }] },
      },
    });
  });

  it("describes the scoring epoch as persisted rather than inferred", () => {
    render(<LiftAndQ />);
    const snapshotNote = screen.getByText(/this is a snapshot, not a history/i).parentElement;
    expect(snapshotNote).not.toBeNull();
    expect(snapshotNote).toHaveTextContent(/persisted epoch_id/i);
    expect(snapshotNote).not.toHaveTextContent(/inferred/i);
    expect(screen.getByText("4")).toBeInTheDocument();
  });
});
