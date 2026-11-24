/**
 * Shared primitives for the Directory Insights tabs (Phase 3.2.3).
 *
 * Every badge renders its text label — state is never conveyed by color
 * alone. Evidence rendering only pretty-prints the sanitized `detail`
 * dict the API returns: it never logs, never fetches, and never invents
 * fields the backend did not send.
 */

import type { ReactNode } from "react";
import { ApiError } from "../../api/client";

// --- Labels ------------------------------------------------------------------

/** snake_case / dotted key → readable label ("last_logon_at" → "Last logon at"). */
export function humanize(key: string): string {
  const words = key.replace(/[._]/g, " ").split(/\s+/).filter(Boolean);
  return words
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// --- Badges ------------------------------------------------------------------

const SEVERITY_CLS: Record<string, string> = {
  critical: "bg-danger/10 text-danger ring-danger/40",
  high: "bg-danger/10 text-danger ring-danger/40",
  medium: "bg-warn/10 text-warn ring-warn/40",
  low: "bg-accent/10 text-accent ring-accent/40",
  info: "bg-raised text-muted ring-line-strong",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_CLS[severity] ?? "bg-raised text-muted ring-line-strong";
  return (
    <span
      data-testid={`severity-${severity}`}
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${cls}`}
    >
      {severity}
    </span>
  );
}

const FINDING_STATUS_CLS: Record<string, string> = {
  open: "bg-warn/10 text-warn ring-warn/40",
  acknowledged: "bg-accent/10 text-accent ring-accent/40",
  suppressed: "bg-raised text-muted ring-line-strong",
  resolved: "bg-ok/10 text-ok ring-ok/40",
};

export function FindingStatusBadge({ status }: { status: string }) {
  const cls =
    FINDING_STATUS_CLS[status] ?? "bg-raised text-muted ring-line-strong";
  return (
    <span
      data-testid={`finding-status-${status}`}
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${cls}`}
    >
      {status}
    </span>
  );
}

const VISIBILITY: Record<string, { cls: string; label: string }> = {
  full: { cls: "bg-ok/10 text-ok ring-ok/40", label: "Full visibility" },
  partial: { cls: "bg-warn/10 text-warn ring-warn/40", label: "Partial visibility" },
  insufficient: {
    cls: "bg-danger/10 text-danger ring-danger/40",
    label: "Insufficient visibility",
  },
};

export function VisibilityBadge({ value }: { value: string }) {
  const known = VISIBILITY[value] ?? {
    cls: "bg-raised text-muted ring-line-strong",
    label: humanize(value),
  };
  return (
    <span
      data-testid={`visibility-${value}`}
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${known.cls}`}
    >
      {known.label}
    </span>
  );
}

// --- Errors ------------------------------------------------------------------

/**
 * Accurate, secret-free message for lifecycle/API failures. The backend's
 * RFC 9457 title + detail are shown verbatim for validation failures (400)
 * so the operator sees the real reason; auth/permission/missing cases get
 * a clear standing explanation.
 */
export function apiErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const { status, title, detail } = err.problem;
    if (status === 401) return "Your session expired — sign in again.";
    if (status === 403) {
      return "You do not have permission to change findings (directory:write required).";
    }
    if (status === 404) {
      return "This finding no longer exists in this connection.";
    }
    if (status >= 500) {
      return "The server could not complete the request — try again.";
    }
    if (status === 0) return detail ?? "Could not reach the API server.";
    return detail ? `${title} — ${detail}` : title;
  }
  return err instanceof Error ? err.message : "Unexpected error.";
}

// --- Evidence ----------------------------------------------------------------

const MAX_DEPTH = 4;

function renderEvidence(value: unknown, depth: number): ReactNode {
  if (value === null || value === undefined) {
    return <span className="text-faint">—</span>;
  }
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") {
    return <span className="tabular-nums">{value}</span>;
  }
  if (typeof value === "string") return <span className="break-all">{value}</span>;

  const oversized = depth >= MAX_DEPTH;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-faint">—</span>;
    if (oversized) {
      return (
        <span className="break-all font-mono text-xs">{JSON.stringify(value)}</span>
      );
    }
    return (
      <ul className="mt-1 space-y-1 border-l border-line pl-3">
        {value.map((item, index) => (
          <li key={index}>{renderEvidence(item, depth + 1)}</li>
        ))}
      </ul>
    );
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <span className="text-faint">—</span>;
    if (oversized) {
      return (
        <span className="break-all font-mono text-xs">{JSON.stringify(value)}</span>
      );
    }
    return (
      <dl className="mt-1 space-y-1 border-l border-line pl-3">
        {entries.map(([key, child]) => (
          <div key={key} className="text-sm">
            <dt className="inline text-faint">{humanize(key)}: </dt>
            <dd className="inline text-muted">{renderEvidence(child, depth + 1)}</dd>
          </div>
        ))}
      </dl>
    );
  }
  return <span>{String(value)}</span>;
}

/**
 * Structured evidence view: nested dicts render as indented key/value
 * groups, lists as indented items. Pure rendering of API data.
 */
export function EvidenceBlock({
  detail,
}: {
  detail: Record<string, unknown>;
}) {
  const entries = Object.entries(detail);
  if (entries.length === 0) {
    return <p className="text-sm text-faint">No additional evidence recorded.</p>;
  }
  return (
    <dl className="space-y-1.5">
      {entries.map(([key, value]) => (
        <div key={key} className="text-sm">
          <dt className="inline text-faint">{humanize(key)}: </dt>
          <dd className="inline text-muted">{renderEvidence(value, 0)}</dd>
        </div>
      ))}
    </dl>
  );
}
