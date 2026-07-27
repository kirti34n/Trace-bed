import type { ReactNode } from "react";

export interface EmptyStateAction {
  label: string;
  onClick: () => void;
}

export interface EmptyStateProps {
  /** Short, specific — "No memories in this vault yet", not "No data". */
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: EmptyStateAction;
  /** Renders inside a bordered panel matching Table's frame, so an empty
   * table and its "empty" message occupy the same visual footprint (task
   * brief: "empty is the common case for a young project and it must look
   * deliberate, not broken"). Set false when embedding inline (e.g. below a
   * chart) instead of as a page's whole content. */
  bordered?: boolean;
}

export function EmptyState({
  title,
  description,
  icon,
  action,
  bordered = true,
}: EmptyStateProps) {
  return (
    <div
      role="status"
      className={
        "flex flex-col items-center justify-center gap-3 px-6 py-16 text-center" +
        (bordered ? " rounded-lg border border-dashed border-border bg-surface" : "")
      }
    >
      {icon !== undefined && (
        <div aria-hidden="true" className="text-text-faint">
          {icon}
        </div>
      )}
      <div className="space-y-1">
        <p className="text-sm font-medium text-text">{title}</p>
        {description !== undefined && (
          <p className="max-w-sm text-sm text-text-muted">{description}</p>
        )}
      </div>
      {action !== undefined && (
        <button
          type="button"
          onClick={action.onClick}
          className="mt-1 rounded-md border border-border-strong bg-surface px-3 py-1.5 text-sm font-medium text-text transition-colors hover:bg-surface-raised focus-visible:outline-none"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
