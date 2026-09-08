import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { memoryFixture } from "../test/fixtures";
import type { QueryState } from "../api/hooks";
import type { MemoryListOut } from "../api/types";
import MemoryVault from "./MemoryVault";

const useMemoryListMock = vi.hoisted(() => vi.fn());
let state: QueryState<MemoryListOut>;
vi.mock("../api/hooks", () => ({ useMemoryList: useMemoryListMock }));

function queryState(data: MemoryListOut | undefined, status: QueryState<MemoryListOut>["status"]): QueryState<MemoryListOut> {
  return { status, data, error: undefined, reload: vi.fn() };
}

function renderVault() {
  return render(<MemoryRouter><MemoryVault /></MemoryRouter>);
}

describe("Memory Vault bounded list states", () => {
  beforeEach(() => {
    useMemoryListMock.mockImplementation(() => state);
  });

  it("passes the opaque next cursor back only for page traversal", async () => {
    state = queryState({ items: [memoryFixture], next_cursor: "opaque-next" }, "success");
    renderVault();
    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await waitFor(() => expect(useMemoryListMock).toHaveBeenLastCalledWith(null, "opaque-next", 100));
  });

  it("renders loading without claiming a zero count", () => {
    state = queryState(undefined, "loading");
    renderVault();
    expect(screen.getAllByText("—")).toHaveLength(4);
  });

  it("renders a deliberate empty state", () => {
    state = queryState({ items: [], next_cursor: null }, "success");
    renderVault();
    expect(screen.getByText("No memories in this vault yet")).toBeInTheDocument();
  });

  it("renders one cursor page and escapes content", () => {
    state = queryState({ items: [{ ...memoryFixture, content: "<img src=x>" }], next_cursor: "opaque-next" }, "success");
    renderVault();
    expect(screen.getByRole("navigation", { name: "Memory vault pages" })).toHaveTextContent("Older");
    expect(screen.getByText("<img src=x>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it.each([[401, "unauthorized", "same-origin BFF session"], [403, "forbidden", "no agent registration"], [404, "not_found", "Nothing at this id"], [500, "server", "internal error"]] as const)("renders %s failures semantically", (status, kind, label) => {
    state = { status: "error", data: undefined, error: new ApiError(kind, "failure", status), reload: vi.fn() };
    renderVault();
    expect(screen.getByRole("alert")).toHaveTextContent(label);
  });
});
