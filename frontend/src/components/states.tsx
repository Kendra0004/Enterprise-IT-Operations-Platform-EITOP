/** Shared async-state components: loading, empty and error. */

import { ApiError } from "../api/client";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      role="status"
      className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm text-slate-400"
    >
      <span
        className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-slate-300"
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
      className="rounded-lg border border-dashed border-slate-700 p-6 text-center text-sm text-slate-500"
    >
      {message}
    </p>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  const detail =
    error instanceof ApiError
      ? `${error.problem.title}${error.problem.detail ? ` — ${error.problem.detail}` : ""}`
      : "An unexpected error occurred.";

  return (
    <div
      role="alert"
      data-testid="error-state"
      className="rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-200"
    >
      <p className="font-medium">Could not load data</p>
      <p className="mt-1 text-red-300/90">{detail}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded border border-red-400/60 px-3 py-1 text-red-100 hover:bg-red-500/20"
        >
          Retry
        </button>
      )}
    </div>
  );
}
