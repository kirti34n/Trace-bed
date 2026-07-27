import type { Config } from "tailwindcss";

// Every colour a component may reach for is named here once (README documents
// the meaning of each). Call sites pick `bg-status-validated` etc., never a raw
// `bg-green-500` — that is what keeps "validated never reads like quarantined"
// a property of the token, not of each author's memory.
function hslVar(variable: string) {
  return `hsl(var(${variable}) / <alpha-value>)`;
}

const statusTokens = [
  "quarantined",
  "candidate",
  "validated",
  "superseded",
  "stale",
  "retired",
  "archived",
  "pinned",
  "tombstoned",
] as const;

const statusColors = Object.fromEntries(
  statusTokens.map((name) => [
    name,
    {
      bg: hslVar(`--status-${name}-bg`),
      fg: hslVar(`--status-${name}-fg`),
      border: hslVar(`--status-${name}-border`),
    },
  ])
);

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: hslVar("--tb-bg"),
        surface: hslVar("--tb-surface"),
        "surface-raised": hslVar("--tb-surface-raised"),
        border: hslVar("--tb-border"),
        "border-strong": hslVar("--tb-border-strong"),
        text: hslVar("--tb-text"),
        "text-muted": hslVar("--tb-text-muted"),
        "text-faint": hslVar("--tb-text-faint"),
        accent: hslVar("--tb-accent"),
        "accent-contrast": hslVar("--tb-accent-contrast"),
        danger: hslVar("--tb-danger"),
        "danger-contrast": hslVar("--tb-danger-contrast"),
        focus: hslVar("--tb-focus-ring"),
        status: statusColors,
        tier: {
          a: hslVar("--tier-a"),
          b: hslVar("--tier-b"),
        },
        risk: {
          low: hslVar("--risk-low"),
          med: hslVar("--risk-med"),
          high: hslVar("--risk-high"),
        },
        chart: {
          line: hslVar("--chart-line"),
          band: hslVar("--chart-band"),
          grid: hslVar("--chart-grid"),
          axis: hslVar("--chart-axis"),
        },
      },
      fontFamily: {
        sans: [
          "InterVariable",
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        panel: "0 1px 2px 0 hsl(var(--tb-shadow) / 0.06), 0 1px 1px 0 hsl(var(--tb-shadow) / 0.04)",
        popover: "0 12px 32px -8px hsl(var(--tb-shadow) / 0.35)",
      },
      borderRadius: {
        sm: "4px",
        md: "6px",
        lg: "10px",
      },
    },
  },
  plugins: [],
} satisfies Config;
