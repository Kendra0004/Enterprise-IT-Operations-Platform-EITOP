import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export type StatTone = "neutral" | "ok" | "warn" | "danger";

const TONE_TEXT: Record<StatTone, string> = {
  neutral: "text-ink",
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
};

/**
 * KPI card. Values always come from the API — the component only renders.
 * When `href` is set the whole card becomes a link (metric → filtered view).
 *
 * DOM shape: label and value are direct children of the card root so the
 * label's parent element always contains the metric (keeps text assertions
 * stable and helps screen readers announce the pair).
 */
export function StatCard({
  label,
  value,
  icon: Icon,
  tone = "neutral",
  href,
  sub,
  ariaLabel,
}: {
  label: string;
  value: ReactNode;
  icon?: LucideIcon;
  tone?: StatTone;
  href?: string;
  sub?: string;
  ariaLabel?: string;
}) {
  const body = (
    <>
      <p className="pr-6 text-[11px] font-medium uppercase tracking-wider text-faint">
        {label}
      </p>
      {Icon && (
        <Icon
          size={15}
          aria-hidden
          className="absolute right-3 top-3 text-faint"
        />
      )}
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${TONE_TEXT[tone]}`}>
        {value}
      </p>
      {sub && <p className="mt-0.5 truncate text-xs text-faint">{sub}</p>}
    </>
  );

  const className =
    "relative block rounded-lg border border-line bg-surface p-4 shadow-card transition-colors";

  if (href) {
    return (
      <Link
        to={href}
        aria-label={ariaLabel ?? `${label}: ${String(value)}`}
        className={`${className} hover:border-line-strong hover:bg-raised`}
      >
        {body}
      </Link>
    );
  }
  return (
    <div aria-label={ariaLabel} className={className}>
      {body}
    </div>
  );
}
