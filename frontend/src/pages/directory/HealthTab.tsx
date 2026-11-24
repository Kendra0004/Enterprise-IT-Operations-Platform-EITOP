/**
 * Directory Health tab (Phase 3.2.3): newest-run status, the nine
 * required inventory categories, privilege visibility and sync freshness.
 *
 * Everything derives from `GET /directory/health`, whose `newest_run` is
 * ALWAYS the newest run regardless of status — this view never falls back
 * to an older successful run. Five honest states are distinguished:
 * healthy, partial, failed, stale and unknown (no run yet).
 */

import {
  useDirectoryHealth,
  type CategoryResult,
} from "../../api/directory";
import { Empty, ErrorState, Loading } from "../../components/states";
import { StatCard } from "../../components/StatCard";
import { formatUtc, formatUtcShort } from "../../utils/datetime";
import { VisibilityBadge, humanize } from "./shared";

type Tone = "ok" | "warn" | "danger" | "neutral";

interface Verdict {
  label: string;
  hint: string;
  tone: Tone;
}

const TONE_TEXT: Record<Tone, string> = {
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
  neutral: "text-ink",
};

const TONE_CARD: Record<Tone, string> = {
  ok: "border-ok/40 bg-ok/5",
  warn: "border-warn/40 bg-warn/5",
  danger: "border-danger/40 bg-danger/5",
  neutral: "border-line bg-surface",
};

/** The five spec states, in evaluation order (facts by precedence). */
function verdictOf(
  hasRun: boolean,
  runStatus: string,
  inventoryComplete: boolean,
  overdue: boolean,
): Verdict {
  if (!hasRun) {
    return {
      label: "Unknown — no synchronization run yet",
      hint: "No run has ever completed for this connection; health cannot be asserted.",
      tone: "neutral",
    };
  }
  if (runStatus === "failed") {
    return {
      label: "Failed synchronization",
      hint: "The newest run failed. An older successful run is never presented as current.",
      tone: "danger",
    };
  }
  if (runStatus === "running") {
    return {
      label: "Synchronization running",
      hint: "The newest run is still executing; results are not final.",
      tone: "neutral",
    };
  }
  if (!inventoryComplete) {
    return {
      label: "Partial inventory",
      hint: "The newest run succeeded but did not prove every required category.",
      tone: "warn",
    };
  }
  if (overdue) {
    return {
      label: "Stale synchronization",
      hint: "The last successful sync is older than this connection's sync cadence.",
      tone: "warn",
    };
  }
  return {
    label: "Healthy inventory",
    hint: "Newest run succeeded, all required categories are complete, within cadence.",
    tone: "ok",
  };
}

const CATEGORY_STATUS_CLS: Record<string, string> = {
  success: "bg-ok/10 text-ok ring-ok/40",
  failed: "bg-danger/10 text-danger ring-danger/40",
  running: "bg-accent/10 text-accent ring-accent/40",
  pending: "bg-warn/10 text-warn ring-warn/40",
  skipped: "bg-raised text-muted ring-line-strong",
};

export function HealthTab({ connectionId }: { connectionId: string }) {
  const health = useDirectoryHealth(connectionId);

  if (!connectionId) {
    return (
      <Empty message="No directory connection configured yet — add one in Connections." />
    );
  }
  if (health.isLoading) return <Loading label="Loading directory health…" />;
  if (health.isError) {
    return (
      <ErrorState error={health.error} onRetry={() => void health.refetch()} />
    );
  }

  const h = health.data!;
  const run = h.newest_run;
  const overdue = h.sync_freshness.sync_overdue;
  const verdict = verdictOf(
    run !== null,
    run?.status ?? "",
    h.inventory_complete,
    overdue,
  );

  // Category order follows the newest run's own result keys (the engine
  // emits them in PIPELINE order); without a run, the backend already
  // lists all nine required categories as missing.
  const categories: string[] = run
    ? [
        ...new Set([
          ...Object.keys(run.category_results),
          ...h.missing_categories,
        ]),
      ]
    : h.missing_categories;

  const runStatusCls =
    run?.status === "success"
      ? "bg-ok/10 text-ok ring-ok/40"
      : run?.status === "failed"
        ? "bg-danger/10 text-danger ring-danger/40"
        : "bg-raised text-muted ring-line-strong";

  return (
    <div className="space-y-4">
      <section
        aria-label="Inventory verdict"
        data-testid="health-verdict"
        className={`rounded-lg border p-4 shadow-card ${TONE_CARD[verdict.tone]}`}
      >
        <p className="text-[11px] font-medium uppercase tracking-wider text-faint">
          Directory health
        </p>
        <p className={`mt-1 text-lg font-semibold ${TONE_TEXT[verdict.tone]}`}>
          {verdict.label}
        </p>
        <p className="mt-1 text-sm text-muted">{verdict.hint}</p>
      </section>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Newest run"
          value={run ? run.status : "none"}
          tone={
            run?.status === "success"
              ? "ok"
              : run?.status === "failed"
                ? "danger"
                : "neutral"
          }
          sub={
            run
              ? `started ${formatUtcShort(run.started_at)}`
              : "no run recorded"
          }
        />
        <StatCard
          label="Last success"
          value={
            h.sync_freshness.last_success_at
              ? formatUtcShort(h.sync_freshness.last_success_at)
              : "never"
          }
          sub={overdue ? "overdue" : "within cadence"}
          tone={overdue ? "warn" : "ok"}
        />
        <StatCard
          label="Missing categories"
          value={h.missing_categories.length}
          tone={h.missing_categories.length > 0 ? "warn" : "ok"}
          sub={h.inventory_complete ? "inventory complete" : "inventory incomplete"}
        />
        <StatCard
          label="Sync cadence"
          value={`${h.sync_freshness.sync_interval_minutes} min`}
          sub={overdue ? "stale" : "fresh"}
          tone={overdue ? "warn" : "neutral"}
        />
      </div>

      <section
        aria-label="Newest synchronization run"
        className="rounded-lg border border-line bg-surface p-4 shadow-card"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
            Newest synchronization run
          </h3>
          <p className="text-xs text-faint">
            Always the newest run regardless of status — older successes never
            backfill a newer failure.
          </p>
        </div>
        {run ? (
          <div className="mt-3">
            <div className="flex flex-wrap items-center gap-2">
              <span
                data-testid={`run-status-${run.status}`}
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${runStatusCls}`}
              >
                {run.status}
              </span>
              <span className="text-sm capitalize text-muted">
                trigger: {run.trigger}
              </span>
              <span className="text-sm text-muted">
                {run.duration_ms !== null ? `${run.duration_ms} ms` : "duration n/a"}
              </span>
            </div>
            <dl className="mt-2 space-y-1 text-sm">
              <div>
                <dt className="inline text-faint">Started: </dt>
                <dd className="inline text-muted">{formatUtc(run.started_at)}</dd>
              </div>
              <div>
                <dt className="inline text-faint">Finished: </dt>
                <dd className="inline text-muted">
                  {run.finished_at ? formatUtc(run.finished_at) : "not finished"}
                </dd>
              </div>
            </dl>
          </div>
        ) : (
          <Empty message="No synchronization run recorded yet." />
        )}
      </section>

      <section
        aria-label="Required category completeness"
        className="rounded-lg border border-line bg-surface p-4 shadow-card"
      >
        <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
          Required categories ({categories.length}/9)
        </h3>
        <ul className="mt-3 grid gap-2 sm:grid-cols-3">
          {categories.map((name) => {
            const entry: CategoryResult | undefined =
              run?.category_results[name];
            const state = entry?.status ?? "missing";
            const cls =
              CATEGORY_STATUS_CLS[state] ??
              "bg-warn/10 text-warn ring-warn/40";
            return (
              <li
                key={name}
                className="flex items-center justify-between gap-2 rounded-md border border-line bg-raised/40 px-3 py-2 text-sm"
              >
                <span className="truncate capitalize text-ink" title={name}>
                  {humanize(name)}
                </span>
                <span
                  data-testid={`category-${name}`}
                  className={`inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}
                >
                  {entry?.label ?? state}
                </span>
              </li>
            );
          })}
        </ul>
        {h.missing_categories.length > 0 ? (
          <p className="mt-3 text-sm text-muted">
            Missing or unsuccessful:{" "}
            <span className="capitalize text-warn">
              {h.missing_categories.map(humanize).join(", ")}
            </span>
          </p>
        ) : (
          <p className="mt-3 text-sm text-ok">
            All required categories reported success.
          </p>
        )}
      </section>

      <div className="grid gap-3 lg:grid-cols-2">
        <section
          aria-label="Privilege visibility"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <div className="flex flex-wrap items-center gap-3">
            <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
              Privilege visibility
            </h3>
            <VisibilityBadge value={h.privilege_visibility} />
          </div>
          {h.visibility_reasons.length > 0 && (
            <ul className="mt-2 list-inside list-disc text-sm text-muted">
              {h.visibility_reasons.map((reason) => (
                <li key={reason}>{humanize(reason)}</li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-xs text-faint">
            Shared engine helper — the same verdict the findings engine uses.
            Distribution anomalies are reported but never downgrade it here.
          </p>
        </section>

        <section
          aria-label="Sync freshness"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
            Sync freshness
          </h3>
          <dl className="mt-2 space-y-1 text-sm">
            <div>
              <dt className="inline text-faint">Last successful sync: </dt>
              <dd className="inline text-muted">
                {h.sync_freshness.last_success_at
                  ? formatUtc(h.sync_freshness.last_success_at)
                  : "never"}
              </dd>
            </div>
            <div>
              <dt className="inline text-faint">Newest run started: </dt>
              <dd className="inline text-muted">
                {h.sync_freshness.newest_run_started_at
                  ? formatUtc(h.sync_freshness.newest_run_started_at)
                  : "never"}
              </dd>
            </div>
            <div>
              <dt className="inline text-faint">Cadence: </dt>
              <dd className="inline text-muted">
                every {h.sync_freshness.sync_interval_minutes} minutes
              </dd>
            </div>
          </dl>
          <p
            data-testid="freshness-state"
            className={`mt-3 text-sm font-medium ${overdue ? "text-warn" : "text-ok"}`}
          >
            {overdue
              ? "Overdue — last success is older than the cadence."
              : "Fresh — last success is within the cadence."}
          </p>
        </section>
      </div>
    </div>
  );
}
