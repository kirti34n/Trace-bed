import { ApiError, type ApiErrorKind } from "../api/client";

export interface ErrorStateProps {
  error: unknown;
  onRetry?: () => void;
  /** Overrides the kind-derived title — use when the surrounding view has
   * more specific language than the generic per-kind copy below. */
  title?: string;
}

const KIND_COPY: Record<ApiErrorKind, { title: string; description: string }> = {
  unauthorized: {
    title: "Not signed in",
    description:
      "Your credential is missing or no longer valid. Enter an API key or bearer token in Settings.",
  },
  forbidden: {
    title: "No project access",
    description:
      "This credential authenticates but has no agent registration bound to a project — it cannot be scoped to any data.",
  },
  not_found: {
    title: "Not found",
    description:
      "Nothing at this id, in this project. Tracebed returns the same response whether it never existed or belongs to someone else — that is deliberate isolation, not a bug in this view.",
  },
  conflict: {
    title: "Already exists",
    description: "That registration already exists and cannot be created twice.",
  },
  validation: {
    title: "Rejected by the server",
    description: "The request did not match the API's schema.",
  },
  server: {
    title: "Server error",
    description: "Tracebed's API returned an internal error. Nothing here can be inferred as your project's actual state.",
  },
  network: {
    title: "Can't reach the API",
    description: "Check that the API at :8110 is running and reachable.",
  },
  cancelled: {
    title: "Request cancelled",
    description: "This request was cancelled before it completed.",
  },
};

function describe(error: unknown): { title: string; description: string; detail?: string } {
  if (error instanceof ApiError) {
    const copy = KIND_COPY[error.kind];
    const detail =
      typeof error.detail === "string"
        ? error.detail
        : error.detail !== undefined
          ? JSON.stringify(error.detail)
          : undefined;
    return { ...copy, detail };
  }
  return {
    title: "Something went wrong",
    description: error instanceof Error ? error.message : "An unexpected error occurred.",
  };
}

/** Every non-success query/mutation state renders through here — one shape
 * for "what happened" + "what can you do about it", never a raw stack trace
 * or a bare "Error" string an operator can't act on. */
export function ErrorState({ error, onRetry, title }: ErrorStateProps) {
  const { title: derivedTitle, description, detail } = describe(error);
  return (
    <div
      role="alert"
      className="flex flex-col items-center gap-3 rounded-lg border border-status-quarantined-border/60 bg-status-quarantined-bg/40 px-6 py-12 text-center"
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 20 20"
        className="h-6 w-6 text-status-quarantined-fg"
        fill="currentColor"
      >
        <path
          fillRule="evenodd"
          d="M8.257 3.099c.765-1.36 2.72-1.36 3.486 0l6.28 11.18c.75 1.334-.213 2.98-1.742 2.98H3.72c-1.53 0-2.492-1.646-1.743-2.98l6.28-11.18ZM11 13a1 1 0 1 1-2 0 1 1 0 0 1 2 0Zm-1-8a1 1 0 0 0-1 1v3a1 1 0 1 0 2 0V6a1 1 0 0 0-1-1Z"
          clipRule="evenodd"
        />
      </svg>
      <div className="space-y-1">
        <p className="text-sm font-medium text-text">{title ?? derivedTitle}</p>
        <p className="max-w-md text-sm text-text-muted">{description}</p>
        {detail !== undefined && (
          <p className="max-w-md truncate font-mono text-xs text-text-faint" title={detail}>
            {detail}
          </p>
        )}
      </div>
      {onRetry !== undefined && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-1 rounded-md border border-border-strong bg-surface px-3 py-1.5 text-sm font-medium text-text transition-colors hover:bg-surface-raised"
        >
          Retry
        </button>
      )}
    </div>
  );
}
