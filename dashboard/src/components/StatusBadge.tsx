import type { SVGProps } from "react";
import type { Status, TrustTier } from "../api/types";

// Every status/tier gets a fixed label AND a fixed shape, never colour alone
// (task brief: "operators with colour-vision deficiency read these same
// screens"). The colour classes below (bg-status-*, text-status-*,
// border-status-*) resolve through tailwind.config.ts to index.css's design
// tokens — this file is the ONLY place that decides which icon+label pairs
// with which status; nothing else in the dashboard should invent another
// rendering of "validated".

type IconProps = SVGProps<SVGSVGElement>;

function TriangleWarningIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" {...props}>
      <path
        fillRule="evenodd"
        d="M8.257 3.099c.765-1.36 2.72-1.36 3.486 0l6.28 11.18c.75 1.334-.213 2.98-1.742 2.98H3.72c-1.53 0-2.492-1.646-1.743-2.98l6.28-11.18ZM11 13a1 1 0 1 1-2 0 1 1 0 0 1 2 0Zm-1-8a1 1 0 0 0-1 1v3a1 1 0 1 0 2 0V6a1 1 0 0 0-1-1Z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function DashedCircleIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" aria-hidden="true" {...props}>
      <circle
        cx="10"
        cy="10"
        r="7"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeDasharray="3.2 3"
      />
    </svg>
  );
}

function CheckCircleIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" {...props}>
      <path
        fillRule="evenodd"
        d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.68-1.68a.75.75 0 0 0-1.06 1.061l2.32 2.32a.75.75 0 0 0 1.137-.089l4-5.52Z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function ArrowsRightLeftIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true" {...props}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 7h10l-2.5-2.5M16 13H6l2.5 2.5" />
    </svg>
  );
}

function ClockAlertIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" {...props}>
      <circle cx="10" cy="10.8" r="6.3" />
      <path strokeLinecap="round" d="M10 7.6v3.2l2 1.4" />
      <path strokeLinecap="round" d="M8.6 2.4h2.8" />
    </svg>
  );
}

function StopSquareIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" {...props}>
      <rect x="5" y="5" width="10" height="10" rx="1.5" />
    </svg>
  );
}

function ArchiveBoxIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" {...props}>
      <rect x="3" y="4" width="14" height="3.2" rx="0.8" />
      <path d="M4.2 7.2v7.4a1.4 1.4 0 0 0 1.4 1.4h8.8a1.4 1.4 0 0 0 1.4-1.4V7.2" />
      <path strokeLinecap="round" d="M8.2 10.4h3.6" />
    </svg>
  );
}

function PinIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M11.5 2.5a1.5 1.5 0 0 0-3 0v5.2L6 10.2v1.6h3.25L10 18l.75-6.2H14v-1.6l-2.5-2.5V2.5Z" />
    </svg>
  );
}

function TombstoneIcon(props: IconProps) {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" {...props}>
      <path d="M5.5 17V9a4.5 4.5 0 1 1 9 0v8" />
      <path strokeLinecap="round" d="M4 17h12" />
      <path strokeLinecap="round" d="M8.3 8.7h3.4" />
    </svg>
  );
}

interface StatusMeta {
  label: string;
  Icon: (props: IconProps) => JSX.Element;
  classes: string;
}

const STATUS_META: Record<Status, StatusMeta> = {
  quarantined: {
    label: "Quarantined",
    Icon: TriangleWarningIcon,
    classes: "bg-status-quarantined-bg text-status-quarantined-fg border-status-quarantined-border",
  },
  candidate: {
    label: "Candidate",
    Icon: DashedCircleIcon,
    classes: "bg-status-candidate-bg text-status-candidate-fg border-status-candidate-border",
  },
  validated: {
    label: "Validated",
    Icon: CheckCircleIcon,
    classes: "bg-status-validated-bg text-status-validated-fg border-status-validated-border",
  },
  superseded: {
    label: "Superseded",
    Icon: ArrowsRightLeftIcon,
    classes: "bg-status-superseded-bg text-status-superseded-fg border-status-superseded-border",
  },
  stale: {
    label: "Stale",
    Icon: ClockAlertIcon,
    classes: "bg-status-stale-bg text-status-stale-fg border-status-stale-border",
  },
  retired: {
    label: "Retired",
    Icon: StopSquareIcon,
    classes: "bg-status-retired-bg text-status-retired-fg border-status-retired-border",
  },
  archived: {
    label: "Archived",
    Icon: ArchiveBoxIcon,
    classes: "bg-status-archived-bg text-status-archived-fg border-status-archived-border",
  },
  pinned: {
    label: "Pinned",
    Icon: PinIcon,
    classes: "bg-status-pinned-bg text-status-pinned-fg border-status-pinned-border",
  },
  tombstoned: {
    label: "Tombstoned",
    Icon: TombstoneIcon,
    classes: "bg-status-tombstoned-bg text-status-tombstoned-fg border-status-tombstoned-border",
  },
};

export interface StatusBadgeProps {
  status: Status;
  className?: string;
}

export function StatusBadge({ status, className = "" }: StatusBadgeProps) {
  const meta = STATUS_META[status];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium tabular-nums ${meta.classes} ${className}`}
    >
      <meta.Icon className="h-3 w-3 shrink-0" />
      {meta.label}
    </span>
  );
}

const TIER_META: Record<TrustTier, { label: string; description: string }> = {
  A: {
    label: "Tier A",
    description: "Structurally derived (parser output) — enters as candidate.",
  },
  B: {
    label: "Tier B",
    description: "Content-derived (distiller/proposal) — enters quarantined until corroborated.",
  },
};

export interface TrustTierBadgeProps {
  tier: TrustTier;
  className?: string;
}

/** Kept in this file rather than a second component file (not in the owning
 * agent's file list) — tier and status are shown side by side everywhere a
 * memory row appears, so one import covers both. Tier is rendered as
 * lettered text ("Tier A"/"Tier B"), never colour-only, and the border
 * style itself differs (solid vs dashed) as a second, non-colour signal. */
export function TrustTierBadge({ tier, className = "" }: TrustTierBadgeProps) {
  const meta = TIER_META[tier];
  return (
    <span
      title={meta.description}
      className={
        `inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold tabular-nums ` +
        (tier === "A"
          ? "border-tier-a/50 bg-tier-a/10 text-tier-a"
          : "border-tier-b/50 border-dashed bg-tier-b/10 text-tier-b") +
        ` ${className}`
      }
    >
      {meta.label}
    </span>
  );
}
