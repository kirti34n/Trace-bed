import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

// For governing/destructive actions only (kill switch, quarantine, delete-by-
// subject, retire). The task brief is explicit: these "need confirmation and
// must show what they will affect first" — `impact` is required, not
// optional, so a call site cannot ship a confirm dialog that just repeats
// the action's name back at the operator.

export interface ConfirmDialogImpact {
  label: string;
  value: string | number;
}

export interface ConfirmDialogReasonField {
  label: string;
  placeholder?: string;
  /** When true, Confirm stays disabled until the operator has typed
   * something — for a governing override (e.g. a kill-switch reversal)
   * where the reason IS the audit trail, not an optional comment. */
  required?: boolean;
}

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description?: string;
  /** What this action will affect, shown as a labelled list before the
   * confirm button — e.g. [{label: "Memories affected", value: 14},
   * {label: "Runs touched", value: 812}] for a blast-radius quarantine. */
  impact: ConfirmDialogImpact[];
  confirmLabel?: string;
  cancelLabel?: string;
  /** "danger" for anything irreversible or trust-reducing; "default" for a
   * governing action that is still reversible (e.g. pin/unpin). */
  tone?: "danger" | "default";
  /** Disables both buttons and marks the dialog busy while the action's
   * request is in flight — prevents a double-submit on a network hiccup. */
  busy?: boolean;
  /** Renders a free-text rationale field above the buttons when present. A
   * governing override recorded with no operator-authored reason is
   * indistinguishable later from one nobody thought about — this is the one
   * place that gap can be closed, since the dialog is the only UI a
   * destructive/governing action passes through. Omit for an action with no
   * meaningful "why" to capture (e.g. dismissing a stale toast). */
  reasonField?: ConfirmDialogReasonField;
  /** Receives the trimmed reason text (or `undefined` if the field was
   * empty and not required) — existing call sites that ignore the
   * parameter keep working unchanged. */
  onConfirm: (reason: string | undefined) => void;
  onCancel: () => void;
}

const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function ConfirmDialog({
  open,
  title,
  description,
  impact,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "default",
  busy = false,
  reasonField,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  const [reason, setReason] = useState("");

  // The field is per-open-instance state, not per-mount: a dialog reused
  // across two different governed actions (open -> cancel -> open again for
  // a different row) must not leak the previous action's typed rationale
  // into the next one's confirm call.
  useEffect(() => {
    if (open) setReason("");
  }, [open]);

  const trimmedReason = reason.trim();
  const reasonSatisfied =
    reasonField === undefined || reasonField.required !== true || trimmedReason.length > 0;

  // Focus management: move focus into the dialog on open, trap Tab within
  // it, and restore the operator's place in the page on close — a modal
  // that leaves keyboard focus behind on the page underneath it is not
  // actually modal for a keyboard-only operator.
  useEffect(() => {
    if (!open) return;
    previouslyFocused.current = document.activeElement as HTMLElement | null;
    const panel = panelRef.current;
    const firstFocusable = panel?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
    firstFocusable?.focus();

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !busy) {
        event.preventDefault();
        onCancel();
        return;
      }
      if (event.key !== "Tab" || panel === null || panel === undefined) return;
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previouslyFocused.current?.focus();
    };
  }, [open, busy, onCancel]);

  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop is pointer-only convenience (click outside to dismiss);
          Escape (handled above) and the Cancel button are the keyboard and
          screen-reader paths, so the overlay itself carries no interactive
          role — jsx-a11y's static-element-interactions check is for
          elements that ARE a control with no keyboard equivalent, which
          this deliberately is not. */}
      <div
        aria-hidden="true"
        onMouseDown={() => {
          if (!busy) onCancel();
        }}
        className="absolute inset-0 bg-black/40"
      />
      <div
        ref={panelRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby={description !== undefined ? "confirm-dialog-description" : undefined}
        className="relative z-10 w-full max-w-md rounded-lg border border-border bg-surface p-5 shadow-popover"
      >
        <h2 id="confirm-dialog-title" className="text-sm font-semibold text-text">
          {title}
        </h2>
        {description !== undefined && (
          <p id="confirm-dialog-description" className="mt-1.5 text-sm text-text-muted">
            {description}
          </p>
        )}

        {impact.length > 0 && (
          <dl className="mt-4 space-y-1.5 rounded-md border border-border bg-bg px-3 py-2.5">
            {impact.map((item) => (
              <div key={item.label} className="flex items-center justify-between gap-4 text-sm">
                <dt className="text-text-muted">{item.label}</dt>
                <dd className="font-medium tabular-nums text-text">{item.value}</dd>
              </div>
            ))}
          </dl>
        )}

        {reasonField !== undefined && (
          <div className="mt-4">
            <label
              htmlFor="confirm-dialog-reason"
              className="text-xs font-medium text-text-muted"
            >
              {reasonField.label}
              {reasonField.required === true && <span aria-hidden="true"> *</span>}
            </label>
            <textarea
              id="confirm-dialog-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={reasonField.placeholder}
              required={reasonField.required}
              disabled={busy}
              rows={2}
              className="mt-1 w-full resize-none rounded-md border border-border bg-bg px-2.5 py-1.5 text-sm text-text placeholder:text-text-faint focus-visible:outline-none disabled:opacity-50"
            />
          </div>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded-md border border-border-strong px-3 py-1.5 text-sm font-medium text-text transition-colors hover:bg-surface-raised disabled:opacity-50"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={() => onConfirm(trimmedReason.length > 0 ? trimmedReason : undefined)}
            disabled={busy || !reasonSatisfied}
            className={
              "rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:opacity-50 " +
              (tone === "danger"
                ? "bg-danger text-danger-contrast hover:opacity-90"
                : "bg-accent text-accent-contrast hover:opacity-90")
            }
          >
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
