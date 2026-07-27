import { useMemo } from "react";

// Hand-rolled SVG — no charting dependency (task brief: "do NOT pull a
// heavyweight dependency for three line charts"). The one feature that is
// not optional: a confidence-interval band, because a lift figure with no
// interval is, per the task brief, "the single most misleading thing this
// UI could display" — `band` is a first-class prop, not an afterthought.

export interface ChartPoint {
  x: number;
  y: number;
}

export type ChartMarkerShape = "circle" | "square" | "diamond" | "none";

export interface ChartSeries {
  label: string;
  points: ChartPoint[];
  /** One of the `chart-*` tokens by default; override only for a second
   * series that must be visually distinct from the CI band's own hue. */
  colorClassName?: string;
  /** SVG `stroke-dasharray`, e.g. `"6 3"` (dashed) or `"1.5 2.5"` (dotted).
   * Undefined draws a solid line. This — together with `marker` — is the
   * non-colour channel a series MUST carry when colour is the only other
   * thing separating it from a sibling series (e.g. one line per
   * scoring_epoch): colour alone distinguishing data series is an
   * accessibility failure the task brief calls out by name. */
  strokeDasharray?: string;
  /** Draws this shape at every point in addition to (or instead of) the
   * line. Required for a series with fewer than two points — a line needs
   * two points to exist at all, so a single-window estimate would otherwise
   * render as nothing, which is worse than showing an unqualified number:
   * it hides that the observation exists. Defaults to "none" for a normal
   * multi-point line to avoid cluttering long series with a mark per day. */
  marker?: ChartMarkerShape;
  /** `"points"` suppresses the connecting path entirely, however many points
   * the series has.
   *
   * A line between two points is a claim that the thing being measured moved
   * continuously from one to the other. That claim is false for a population
   * scatter — one point per memory, ordered by when each was last scored — no
   * matter how tempting the shape is, because consecutive points belong to
   * DIFFERENT memories. Drawing it anyway produces a "Q is trending up" read
   * from data that contains no trend at all. Series that are scatters say so
   * here rather than relying on every caller to remember. */
  mode?: "line" | "points";
}

export interface ChartBandPoint {
  x: number;
  yLow: number;
  yHigh: number;
}

export interface ChartBand {
  label: string;
  points: ChartBandPoint[];
}

export interface ChartProps {
  series: ChartSeries[];
  band?: ChartBand;
  width?: number;
  height?: number;
  xTickFormat?: (x: number) => string;
  yTickFormat?: (y: number) => string;
  /** Override the auto-computed [min, max] — use for a fixed 0..1 axis (Q
   * values, lift fractions) so the scale doesn't jump as new points arrive. */
  yDomain?: [number, number];
  /** Screen-reader summary; visible chart content is otherwise decorative
   * to assistive tech (aria-hidden on the SVG itself). */
  ariaLabel: string;
}

const PADDING = { top: 12, right: 16, bottom: 28, left: 48 };
const TICK_COUNT = 4;

function scaleLinear(domain: [number, number], range: [number, number]) {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const span = d1 - d0;
  return (v: number) => (span === 0 ? (r0 + r1) / 2 : r0 + ((v - d0) / span) * (r1 - r0));
}

function niceTicks(min: number, max: number, count: number): number[] {
  if (min === max) return [min];
  const step = (max - min) / count;
  return Array.from({ length: count + 1 }, (_, i) => min + step * i);
}

const MARKER_RADIUS = 3.5;

/** One shape per marker kind so a series with no room for a colour
 * difference (or none assigned) is still identifiable by form alone. */
function ChartMarker({
  x,
  y,
  shape,
  className,
}: {
  x: number;
  y: number;
  shape: ChartMarkerShape;
  className: string;
}) {
  if (shape === "none") return null;
  if (shape === "circle") return <circle cx={x} cy={y} r={MARKER_RADIUS} className={className} />;
  if (shape === "square") {
    return (
      <rect
        x={x - MARKER_RADIUS}
        y={y - MARKER_RADIUS}
        width={MARKER_RADIUS * 2}
        height={MARKER_RADIUS * 2}
        className={className}
      />
    );
  }
  const r = MARKER_RADIUS * 1.3;
  return (
    <polygon points={`${x},${y - r} ${x + r},${y} ${x},${y + r} ${x - r},${y}`} className={className} />
  );
}

function markerFillClass(colorClassName: string | undefined): string {
  return colorClassName?.replace("stroke-", "fill-") ?? "fill-chart-line";
}

export function Chart({
  series,
  band,
  width = 640,
  height = 240,
  xTickFormat = (x) => String(Math.round(x)),
  yTickFormat = (y) => y.toFixed(2),
  yDomain,
  ariaLabel,
}: ChartProps) {
  const innerWidth = width - PADDING.left - PADDING.right;
  const innerHeight = height - PADDING.top - PADDING.bottom;

  const { xScale, yScale, yTicks, xTicks } = useMemo(() => {
    const allX = [
      ...series.flatMap((s) => s.points.map((p) => p.x)),
      ...(band?.points.map((p) => p.x) ?? []),
    ];
    const allY = [
      ...series.flatMap((s) => s.points.map((p) => p.y)),
      ...(band?.points.flatMap((p) => [p.yLow, p.yHigh]) ?? []),
    ];
    const xMin = allX.length > 0 ? Math.min(...allX) : 0;
    const xMax = allX.length > 0 ? Math.max(...allX) : 1;
    const [yMin, yMax] = yDomain ?? [
      allY.length > 0 ? Math.min(...allY) : 0,
      allY.length > 0 ? Math.max(...allY) : 1,
    ];
    const xS = scaleLinear([xMin, xMax], [0, innerWidth]);
    const yS = scaleLinear([yMin, yMax], [innerHeight, 0]);
    return {
      xScale: xS,
      yScale: yS,
      yTicks: niceTicks(yMin, yMax, TICK_COUNT),
      xTicks: niceTicks(xMin, xMax, Math.min(TICK_COUNT, Math.max(1, allX.length - 1))),
    };
  }, [series, band, innerWidth, innerHeight, yDomain]);

  const bandPath = useMemo(() => {
    if (band === undefined || band.points.length === 0) return null;
    const sorted = [...band.points].sort((a, b) => a.x - b.x);
    const top = sorted.map((p) => `${xScale(p.x)},${yScale(p.yHigh)}`).join(" L ");
    const bottom = sorted
      .slice()
      .reverse()
      .map((p) => `${xScale(p.x)},${yScale(p.yLow)}`)
      .join(" L ");
    return `M ${top} L ${bottom} Z`;
  }, [band, xScale, yScale]);

  return (
    <figure className="w-full">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        role="img"
        aria-label={ariaLabel}
        preserveAspectRatio="xMidYMid meet"
      >
        <g transform={`translate(${PADDING.left},${PADDING.top})`}>
          {yTicks.map((t) => (
            <g key={`y-${t}`}>
              <line
                x1={0}
                x2={innerWidth}
                y1={yScale(t)}
                y2={yScale(t)}
                className="stroke-chart-grid"
                strokeWidth={1}
              />
              <text
                x={-8}
                y={yScale(t)}
                dy="0.32em"
                textAnchor="end"
                className="fill-chart-axis text-[10px] tabular-nums"
              >
                {yTickFormat(t)}
              </text>
            </g>
          ))}
          {xTicks.map((t) => (
            <text
              key={`x-${t}`}
              x={xScale(t)}
              y={innerHeight + 18}
              textAnchor="middle"
              className="fill-chart-axis text-[10px] tabular-nums"
            >
              {xTickFormat(t)}
            </text>
          ))}

          {bandPath !== null && (
            <path d={bandPath} className="fill-chart-band/15" stroke="none" />
          )}

          {series.map((s) => {
            const sortedPoints = s.points.slice().sort((a, b) => a.x - b.x);
            const path = sortedPoints
              .map((p, i) => `${i === 0 ? "M" : "L"} ${xScale(p.x)},${yScale(p.y)}`)
              .join(" ");
            const fillClass = markerFillClass(s.colorClassName);
            // Hoisted out of the JSX so the narrowing survives into the
            // `.map` callback below — a property read inside a closure is
            // re-widened by TypeScript, and the alternative there was an
            // `as` cast, which would silently keep compiling if `marker`'s
            // type ever changed underneath it.
            const marker: ChartMarkerShape = s.marker ?? "none";
            const drawLine = (s.mode ?? "line") === "line" && sortedPoints.length > 1;
            return (
              <g key={s.label}>
                {drawLine && (
                  <path
                    d={path}
                    fill="none"
                    strokeWidth={2}
                    strokeDasharray={s.strokeDasharray}
                    className={s.colorClassName ?? "stroke-chart-line"}
                  />
                )}
                {marker !== "none" &&
                  sortedPoints.map((p, i) => (
                    <ChartMarker
                      key={`${s.label}-pt-${i}`}
                      x={xScale(p.x)}
                      y={yScale(p.y)}
                      shape={marker}
                      className={fillClass}
                    />
                  ))}
              </g>
            );
          })}

          <line
            x1={0}
            x2={innerWidth}
            y1={innerHeight}
            y2={innerHeight}
            className="stroke-border-strong"
            strokeWidth={1}
          />
        </g>
      </svg>
      <figcaption className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
        {series.map((s) => (
          <span key={s.label} className="inline-flex items-center gap-1.5">
            {/* The dash pattern and marker shape are reproduced here, not just
                the colour swatch — a legend that only shows colour would
                itself fail the "not colour alone" rule the series encoding
                exists to satisfy. */}
            <svg aria-hidden="true" width="16" height="8" viewBox="0 0 16 8" className="shrink-0">
              {(s.mode ?? "line") === "line" && (
                <line
                  x1={0}
                  y1={4}
                  x2={16}
                  y2={4}
                  strokeWidth={2}
                  strokeDasharray={s.strokeDasharray}
                  className={s.colorClassName ?? "stroke-chart-line"}
                />
              )}
              {s.marker !== undefined && s.marker !== "none" && (
                <ChartMarker x={8} y={4} shape={s.marker} className={markerFillClass(s.colorClassName)} />
              )}
            </svg>
            {s.label}
          </span>
        ))}
        {band !== undefined && (
          <span className="inline-flex items-center gap-1.5">
            <span aria-hidden="true" className="inline-block h-2.5 w-3 rounded-sm bg-chart-band/25" />
            {band.label}
          </span>
        )}
      </figcaption>
    </figure>
  );
}
