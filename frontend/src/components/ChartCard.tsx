import type { ReactNode } from "react";

/**
 * Chart container + pure-CSS distribution bar (no charting library: the
 * API exposes simple counts, and CSS bars stay accessible and theme-aware).
 *
 * `segments` values are real API numbers — the caller never synthesizes
 * them. The bar is decorative (`aria-hidden`); the legend below carries
 * the accessible text.
 */
export interface Segment {
  label: string;
  value: number;
  /** Tailwind bg class from the token palette (bg-ok, bg-warn, …). */
  colorClass: string;
  href?: string;
}

export function ChartCard({
  title,
  description,
  segments,
  emptyMessage = "No data yet.",
  action,
  legendColumns = 3,
}: {
  title: string;
  description?: string;
  segments: Segment[];
  emptyMessage?: string;
  action?: ReactNode;
  legendColumns?: number;
}) {
  const visible = segments.filter((s) => s.value > 0);
  const sum = segments.reduce((acc, s) => acc + s.value, 0);

  return (
    <section
      aria-label={title}
      className="flex flex-col rounded-lg border border-line bg-surface p-4 shadow-card"
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="text-sm font-medium text-ink">{title}</h3>
          {description && (
            <p className="mt-0.5 text-xs text-faint">{description}</p>
          )}
        </div>
        {action}
      </div>

      {sum === 0 ? (
        <p className="mt-4 text-sm text-faint">{emptyMessage}</p>
      ) : (
        <>
          <div
            aria-hidden
            className="mt-4 flex h-2 w-full overflow-hidden rounded-full bg-raised"
          >
            {segments
              .filter((s) => s.value > 0)
              .map((segment) => (
                <span
                  key={segment.label}
                  className={`${segment.colorClass} h-full`}
                  style={{ width: `${(segment.value / sum) * 100}%` }}
                  title={`${segment.label}: ${segment.value}`}
                />
              ))}
          </div>
          <ul
            className="mt-3 grid gap-x-3 gap-y-1.5 text-xs"
            style={{
              gridTemplateColumns: `repeat(${legendColumns}, minmax(0, 1fr))`,
            }}
          >
            {visible.map((segment) => {
              const inner = (
                <>
                  <span
                    aria-hidden
                    className={`inline-block h-2 w-2 rounded-full ${segment.colorClass}`}
                  />
                  <span className="text-muted">{segment.label}</span>
                  <span className="ml-auto font-medium tabular-nums text-ink">
                    {segment.value}
                  </span>
                </>
              );
              const className = "flex items-center gap-1.5";
              return (
                <li key={segment.label}>
                  {segment.href ? (
                    <a href={segment.href} className={`${className} hover:underline`}>
                      {inner}
                    </a>
                  ) : (
                    <span className={className}>{inner}</span>
                  )}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}

/** Single-value progress bar (e.g. inventory coverage). */
export function ProgressBar({
  label,
  value,
  max,
  hint,
  colorClass = "bg-accent",
}: {
  label: string;
  value: number;
  max: number;
  hint?: string;
  colorClass?: string;
}) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <section
      aria-label={label}
      className="flex flex-col rounded-lg border border-line bg-surface p-4 shadow-card"
    >
      <h3 className="text-sm font-medium text-ink">{label}</h3>
      <p className="mt-2 text-2xl font-semibold tabular-nums text-ink">
        {value}
        <span className="text-sm font-normal text-faint"> / {max}</span>
      </p>
      <div
        aria-hidden
        className="mt-2 h-2 w-full overflow-hidden rounded-full bg-raised"
      >
        <span
          className={`${colorClass} h-full rounded-full`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-faint" aria-live="polite">
        {hint ?? `${pct}% coverage`}
      </p>
    </section>
  );
}
