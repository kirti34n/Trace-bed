import { useCallback, useMemo, useRef, useState, type ReactNode } from "react";

// The primary instrument (task brief: "get this right and half the UI is
// right"). Deliberately generic over one row type at a time — every column
// definition supplies its own `render`, so the table itself never needs to
// know a memory row from a spend row.

export interface ColumnDef<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  /** Omit to make the column unsortable. Return `null` to sort that row last
   * regardless of direction (e.g. a genuinely-missing value). */
  sortValue?: (row: T) => string | number | null;
  align?: "left" | "right" | "center";
  /** CSS width (e.g. "12ch", "160px") — set on every numeric/id/status
   * column so the table doesn't reflow as data of varying length streams in. */
  width?: string;
  /** Right-aligns and applies tabular-nums; the default for anything that
   * looks like a count, a score, or money. */
  numeric?: boolean;
}

export interface TableProps<T> {
  columns: ColumnDef<T>[];
  rows: T[];
  getRowId: (row: T) => string;
  loading?: boolean;
  loadingRowCount?: number;
  onRowClick?: (row: T) => void;
  density?: "comfortable" | "compact";
  /** Screen-reader-only summary of what this table shows — every instance
   * needs one; there is no visual caption element competing for space. */
  caption: string;
  initialSort?: { key: string; direction: "asc" | "desc" };
  /** Caps the scrollable body height (e.g. "60vh") so the sticky header has
   * a scrolling ancestor to stick within on pages with several tables. */
  maxHeight?: string;
}

type SortDirection = "asc" | "desc";

function compareValues(a: string | number | null, b: string | number | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1; // nulls sort last regardless of direction
  if (b === null) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

export function Table<T>({
  columns,
  rows,
  getRowId,
  loading = false,
  loadingRowCount = 8,
  onRowClick,
  density = "comfortable",
  caption,
  initialSort,
  maxHeight,
}: TableProps<T>) {
  const [sort, setSort] = useState<{ key: string; direction: SortDirection } | undefined>(
    initialSort
  );
  const [focusedIndex, setFocusedIndex] = useState(0);
  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([]);

  const sortedRows = useMemo(() => {
    if (sort === undefined) return rows;
    const column = columns.find((c) => c.key === sort.key);
    if (column?.sortValue === undefined) return rows;
    const sortValue = column.sortValue;
    const sign = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => sign * compareValues(sortValue(a), sortValue(b)));
  }, [rows, sort, columns]);

  const toggleSort = useCallback((key: string) => {
    setSort((current) => {
      if (current?.key !== key) return { key, direction: "asc" };
      return current.direction === "asc" ? { key, direction: "desc" } : undefined;
    });
  }, []);

  const cellPadding = density === "compact" ? "px-3 py-1.5" : "px-4 py-2.5";
  const rowCount = loading ? loadingRowCount : sortedRows.length;

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLTableRowElement>, index: number) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        const next = Math.min(index + 1, rowCount - 1);
        setFocusedIndex(next);
        rowRefs.current[next]?.focus();
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        const prev = Math.max(index - 1, 0);
        setFocusedIndex(prev);
        rowRefs.current[prev]?.focus();
      } else if (event.key === "Home") {
        event.preventDefault();
        setFocusedIndex(0);
        rowRefs.current[0]?.focus();
      } else if (event.key === "End") {
        event.preventDefault();
        setFocusedIndex(rowCount - 1);
        rowRefs.current[rowCount - 1]?.focus();
      } else if ((event.key === "Enter" || event.key === " ") && onRowClick !== undefined) {
        event.preventDefault();
        const row = sortedRows[index];
        if (row !== undefined) onRowClick(row);
      }
    },
    [rowCount, onRowClick, sortedRows]
  );

  return (
    <div
      className="tb-scroll overflow-auto rounded-lg border border-border bg-surface"
      style={maxHeight !== undefined ? { maxHeight } : undefined}
    >
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="sticky top-0 z-10 bg-surface-raised">
            {columns.map((col) => {
              const isSorted = sort?.key === col.key;
              const alignClass =
                col.align === "right" || col.numeric === true
                  ? "text-right"
                  : col.align === "center"
                    ? "text-center"
                    : "text-left";
              return (
                <th
                  key={col.key}
                  scope="col"
                  style={col.width !== undefined ? { width: col.width } : undefined}
                  className={`${cellPadding} border-b border-border text-xs font-semibold uppercase tracking-wide text-text-muted ${alignClass}`}
                  aria-sort={
                    isSorted ? (sort?.direction === "asc" ? "ascending" : "descending") : undefined
                  }
                >
                  {col.sortValue !== undefined ? (
                    <button
                      type="button"
                      onClick={() => toggleSort(col.key)}
                      className={`inline-flex items-center gap-1 ${col.numeric === true ? "flex-row-reverse" : ""} hover:text-text`}
                    >
                      {col.header}
                      <SortIndicator active={isSorted} direction={sort?.direction} />
                    </button>
                  ) : (
                    col.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {loading
            ? Array.from({ length: loadingRowCount }, (_, i) => (
                <tr key={`skeleton-${i}`} className="border-b border-border last:border-0">
                  {columns.map((col) => (
                    <td key={col.key} className={cellPadding}>
                      <div className="h-3.5 w-full max-w-[12rem] animate-pulse rounded bg-border" />
                    </td>
                  ))}
                </tr>
              ))
            : sortedRows.map((row, index) => {
                const id = getRowId(row);
                return (
                  <tr
                    key={id}
                    ref={(el) => {
                      rowRefs.current[index] = el;
                    }}
                    tabIndex={focusedIndex === index ? 0 : -1}
                    onFocus={() => setFocusedIndex(index)}
                    onKeyDown={(e) => handleKeyDown(e, index)}
                    onClick={onRowClick !== undefined ? () => onRowClick(row) : undefined}
                    className={
                      "border-b border-border last:border-0 outline-none" +
                      (onRowClick !== undefined
                        ? " cursor-pointer hover:bg-surface-raised focus-visible:bg-surface-raised"
                        : "")
                    }
                  >
                    {columns.map((col) => {
                      const alignClass =
                        col.align === "right" || col.numeric === true
                          ? "text-right"
                          : col.align === "center"
                            ? "text-center"
                            : "text-left";
                      return (
                        <td
                          key={col.key}
                          className={`${cellPadding} ${alignClass} ${col.numeric === true ? "tabular-nums" : ""}`}
                        >
                          {col.render(row)}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
        </tbody>
      </table>
    </div>
  );
}

function SortIndicator({ active, direction }: { active: boolean; direction: SortDirection | undefined }) {
  return (
    <svg viewBox="0 0 12 12" className={`h-3 w-3 shrink-0 ${active ? "text-accent" : "text-text-faint"}`} aria-hidden="true">
      {(!active || direction === "asc") && <path d="M6 3.5 3 7h6L6 3.5Z" fill="currentColor" opacity={active ? 1 : 0.6} />}
      {(!active || direction === "desc") && <path d="M6 8.5 3 5h6L6 8.5Z" fill="currentColor" opacity={active ? 1 : 0.6} />}
    </svg>
  );
}
