/** Shared async-state components: loading, empty and error. */

import { ApiError } from "../api/client";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      role="status"
      className="flex items-center gap-3 rounded-lg border border-line bg-surface p-4 text-sm text-muted shadow-card"
    >
      <span
        className="h-4 w-4 animate-spin rounded-full border-2 border-line-strong border-t-accent"
        aria-hidden
      />
      {label}
    </div>
  );
}

export function Empty({ message }: { message: string }) {
  return (
    <p
      data-testid="empty-state"
      className="rounded-lg border border-dashed border-line-strong p-6 text-center text-sm text-faint"
    >
      {message}
    </p>
  );
}

export function ErrorState({
  error,
  onRetry,
  inline = false,
}: {
  error: unknown;
  onRetry?: () => void;
  /**
   * Inline variant for page sections: same role="alert" but no
   * `error-state` testid, so it never collides with main query states.
   */
  inline?: boolean;
}) {
  const detail =
    error instanceof ApiError
      ? `${error.problem.title}${error.problem.detail ? ` — ${error.problem.detail}` : ""}`
      : "An unexpected error occurred.";

  return (
    <div
      role="alert"
      data-testid={inline ? undefined : "error-state"}
      className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm"
    >
      <p className="font-medium text-danger">Could not load data</p>
      <p className="mt-1 text-muted">{detail}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded-md border border-danger/60 px-3 py-1 text-danger hover:bg-danger/10"
        >
          Retry
        </button>
      )}
    </div>
  );
}
