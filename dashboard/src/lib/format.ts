// Formatting helpers shared by every view. Centralised so "how do we show a
// timestamp" / "how do we show a confidence interval" has one answer instead
// of N slightly-different ones scattered across table cells.

const numberFormatter = new Intl.NumberFormat("en-US");
const percentFormatter = new Intl.NumberFormat("en-US", {
  style: "percent",
  maximumFractionDigits: 1,
});
const costFormatter = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  maximumFractionDigits: 2,
});
const dateTimeFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "medium",
});

export function formatInt(value: number): string {
  return numberFormatter.format(Math.round(value));
}

export function formatFloat(value: number, digits = 2): string {
  return value.toFixed(digits);
}

export function formatPercent(fraction: number): string {
  return percentFormatter.format(fraction);
}

export function formatCostUsd(value: number): string {
  return costFormatter.format(value);
}

export function formatDateTime(iso: string | Date): string {
  const d = typeof iso === "string" ? new Date(iso) : iso;
  return Number.isNaN(d.getTime()) ? "—" : dateTimeFormatter.format(d);
}

/** "3m ago", "2h ago", "5d ago" — coarse on purpose; the exact timestamp is
 * always available in a title attribute alongside this, never replaced by it. */
export function formatRelativeTime(iso: string | Date, now: Date = new Date()): string {
  const d = typeof iso === "string" ? new Date(iso) : iso;
  if (Number.isNaN(d.getTime())) return "—";
  const diffMs = now.getTime() - d.getTime();
  const diffSec = Math.round(diffMs / 1000);
  const abs = Math.abs(diffSec);
  const suffix = diffSec >= 0 ? "ago" : "from now";
  if (abs < 60) return `${abs}s ${suffix}`;
  if (abs < 3600) return `${Math.round(abs / 60)}m ${suffix}`;
  if (abs < 86_400) return `${Math.round(abs / 3600)}h ${suffix}`;
  if (abs < 2_592_000) return `${Math.round(abs / 86_400)}d ${suffix}`;
  return `${Math.round(abs / 2_592_000)}mo ${suffix}`;
}

export function formatDurationMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

/** A lift/confidence figure MUST carry its interval and its N — this is the
 * one call site that renders that trio, so a view cannot accidentally drop
 * the interval and show a bare, misleading point estimate (task brief:
 * "a lift figure without a confidence interval is the single most misleading
 * thing this UI could display"). */
export function formatEstimateWithCI(
  point: number,
  ciLow: number,
  ciHigh: number,
  n: number,
  opts: { percent?: boolean; confidence?: number } = {}
): string {
  const fmt = opts.percent ? formatPercent : (v: number) => formatFloat(v, 3);
  // The confidence LEVEL is part of the figure, not decoration. It used to be
  // hard-coded to "95% CI" here while the server sends the level it actually
  // used (workers/lift.py's `confidence`, overridable per call site) — so an
  // interval computed at 0.99 rendered with a 95% label, which is a wrong
  // claim about how much evidence the bound represents, not a typo. Callers
  // that genuinely have no level to pass fall back to the module default 0.95,
  // which is what workers/lift.py's DEFAULT_CONFIDENCE is.
  const level = opts.confidence ?? 0.95;
  // One decimal, then strip a trailing ".0" — 0.95 * 100 is 95.00000000000001
  // in IEEE 754, so testing the product for integrality renders the common
  // case as "95.0%". Rounding first and trimming after is exact for every
  // level anyone configures.
  const levelLabel = `${formatFloat(level * 100, 1).replace(/\.0$/, "")}%`;
  // "to", never an en dash: an en-dash-joined range collapses into one
  // unreadable token the instant either bound is negative
  // ("-5.0%–7.0%" reads as a single hyphenated run, not a range). KillSwitch
  // worked around this locally; this is the one fix, for every call site.
  return `${fmt(point)} (${levelLabel} CI ${fmt(ciLow)} to ${fmt(ciHigh)}, n=${formatInt(n)})`;
}

/** Shortens a UUID/hash for table display; the full value always still lives
 * in the DOM (title attribute) for copy/inspection — never lost, just not
 * given column width it doesn't need. */
export function truncateId(value: string, head = 8, tail = 4): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function formatTokens(count: number): string {
  return `${formatInt(count)} tok`;
}
