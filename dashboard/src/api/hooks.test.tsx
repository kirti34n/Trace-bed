import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useQuery } from "./hooks";

function Probe({ page, resolve }: { page: string; resolve: (page: string) => Promise<string> }) {
  const query = useQuery(() => resolve(page), page);
  return <p>{query.status}:{query.data ?? "none"}</p>;
}

describe("useQuery page changes", () => {
  it("clears a prior cursor page while the next page is pending", async () => {
    let resolveSecond: ((value: string) => void) | undefined;
    const resolve = (page: string) => page === "first"
      ? Promise.resolve("first-row")
      : new Promise<string>((done) => { resolveSecond = done; });
    const view = render(<Probe page="first" resolve={resolve} />);
    await screen.findByText("success:first-row");
    view.rerender(<Probe page="second" resolve={resolve} />);
    expect(screen.getByText("loading:none")).toBeInTheDocument();
    resolveSecond?.("second-row");
    await screen.findByText("success:second-row");
  });
});
