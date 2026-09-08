import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Table } from "./Table";

describe("Table", () => {
  it("renders semantic table markup and row content from stable server ids", () => {
    render(<Table caption="Stable row ids" columns={[{ key: "name", header: "Name", render: (row: { id: string; name: string }) => row.name }]} rows={[{ id: "server-id-1", name: "First" }, { id: "server-id-2", name: "Second" }]} getRowId={(row) => row.id} />);
    expect(screen.getByRole("table", { name: "Stable row ids" })).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(3);
    expect(screen.getByText("First")).toBeInTheDocument();
  });
});
