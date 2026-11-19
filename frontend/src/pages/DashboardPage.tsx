/**
 * Platform dashboard.
 *
 * Shows ONLY real backend data:
 * - session info (from /auth/me)
 * - platform readiness (from /health/ready)
 * - endpoint KPIs (from /endpoints/overview) for endpoints:read holders
 * - recent audit events (from /audit-logs) for audit:read holders
 */

import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  Clock,
  Database,
  MonitorSmartphone,
  Server,
  ShieldAlert,
} from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useOverview } from "../api/endpoints";
import { PageHeader } from "../components/PageHeader";
import { StatCard } from "../components/StatCard";
import { ErrorState, Loading } from "../components/states";
import { formatUtcShort } from "../utils/datetime";

interface ReadyResponse {
  status: string;
  checks: Record<string, string>;
}

interface AuditPage {
  items: {
    id: string;
    event_type: string;
    actor_email: string | null;
    outcome: string;
    created_at: string;
  }[];
  total: number;
}

export function DashboardPage() {
  const { user, hasPermission } = useAuth();

  const ready = useQuery({
    queryKey: ["ready"],
    queryFn: () => fetch("/health/ready").then((r) => r.json() as Promise<ReadyResponse>),
    refetchInterval: 30_000,
    retry: 1,
  });

  const overview = useOverview();
  const stats = overview.data;

  const audit = useQuery({
    queryKey: ["audit-recent"],
    queryFn: () => api.get<AuditPage>("/audit-logs", { query: { page_size: 8 } }),
    enabled: hasPermission("audit:read"),
  });

  const canSeeEndpoints = hasPermission("endpoints:read");

  return (
    <div className="space-y-5">
      <PageHeader
        title="Dashboard"
        description={`Signed in as ${user?.email} — roles: ${user?.roles.join(", ") || "none"}`}
      />

      {/* --- Platform readiness --- */}
      <section aria-labelledby="platform-status" className="grid gap-3 sm:grid-cols-3">
        <h2 id="platform-status" className="sr-only">
          Platform status
        </h2>

        <StatusCard
          title="API health"
          icon={<Server size={15} aria-hidden />}
          loading={ready.isLoading}
        >
          <StatusLine label="API" value={ready.data?.status ?? "unknown"} />
        </StatusCard>

        <StatusCard
          title="Database"
          icon={<Database size={15} aria-hidden />}
          loading={ready.isLoading}
        >
          <StatusLine
            label="PostgreSQL"
            value={ready.data?.checks?.database ?? "unknown"}
          />
        </StatusCard>

        <StatusCard
          title="Cache / jobs"
          icon={<Activity size={15} aria-hidden />}
          loading={ready.isLoading}
        >
          <StatusLine label="Redis" value={ready.data?.checks?.redis ?? "unknown"} />
        </StatusCard>
      </section>

      {/* --- Endpoint KPIs (real overview data) --- */}
      {canSeeEndpoints && (
        <section aria-label="Endpoint statistics">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-medium text-ink">Endpoints</h2>
            <Link to="/endpoints" className="text-xs text-accent hover:underline">
              Open endpoint management →
            </Link>
          </div>
          {overview.isLoading && <Loading label="Loading overview…" />}
          {overview.isError && (
            <ErrorState
              inline
              error={overview.error}
              onRetry={() => void overview.refetch()}
            />
          )}
          {stats && (
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <StatCard
                label="Total"
                value={stats.total}
                icon={Server}
                href="/endpoints"
                ariaLabel={`${stats.total} endpoints — view all`}
              />
              <StatCard
                label="Active"
                value={stats.active}
                icon={MonitorSmartphone}
                tone="ok"
                href="/endpoints?status=active"
                ariaLabel={`${stats.active} active endpoints — view`}
              />
              <StatCard
                label="Offline"
                value={stats.offline}
                icon={Clock}
                tone={stats.offline > 0 ? "warn" : "neutral"}
                href="/endpoints?status=offline"
                ariaLabel={`${stats.offline} offline endpoints — view`}
              />
              <StatCard
                label="Revoked"
                value={stats.revoked}
                icon={ShieldAlert}
                tone={stats.revoked > 0 ? "danger" : "neutral"}
                href="/endpoints?status=revoked"
                ariaLabel={`${stats.revoked} revoked endpoints — view`}
              />
            </div>
          )}
        </section>
      )}

      {/* --- Session + recent activity --- */}
      <div className="grid gap-3 lg:grid-cols-2">
        <section
          aria-labelledby="session-heading"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h2 id="session-heading" className="text-sm font-medium text-ink">
            Your permissions
          </h2>
          <ul className="mt-3 flex flex-wrap gap-2">
            {user?.permissions.map((p) => (
              <li
                key={p}
                className="rounded bg-accent-soft px-2 py-0.5 font-mono text-xs text-accent"
              >
                {p}
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-faint">
            Endpoint management and groups are live. Sidebar modules marked
            “soon” are honest previews — not operational features.
          </p>
        </section>

        {hasPermission("audit:read") && (
          <section
            aria-labelledby="recent-activity"
            className="rounded-lg border border-line bg-surface p-4 shadow-card"
          >
            <h2 id="recent-activity" className="text-sm font-medium text-ink">
              Recent audit events
            </h2>
            <div className="mt-1">
              {audit.isLoading && <Loading label="Loading audit events…" />}
              {audit.isError && (
                <ErrorState
                  inline
                  error={audit.error}
                  onRetry={() => void audit.refetch()}
                />
              )}
              {audit.data && audit.data.items.length === 0 && (
                <p className="py-3 text-sm text-faint">No audit events yet.</p>
              )}
              {audit.data && audit.data.items.length > 0 && (
                <ul className="divide-y divide-line">
                  {audit.data.items.map((e) => (
                    <li key={e.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                      <span className="truncate font-mono text-xs text-ink">
                        {e.event_type}
                      </span>
                      <span className="truncate text-xs text-muted">
                        {e.actor_email ?? "—"}
                      </span>
                      <span
                        className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${
                          e.outcome === "success"
                            ? "bg-ok/10 text-ok"
                            : "bg-danger/10 text-danger"
                        }`}
                      >
                        {e.outcome}
                      </span>
                      <time
                        dateTime={e.created_at}
                        className="hidden shrink-0 text-xs tabular-nums text-faint sm:block"
                      >
                        {formatUtcShort(e.created_at)}
                      </time>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

function StatusCard({
  title,
  icon,
  loading,
  children,
}: {
  title: string;
  icon: ReactNode;
  loading: boolean;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4 shadow-card">
      <h3 className="flex items-center gap-1.5 text-sm font-medium text-ink">
        <span className="text-faint">{icon}</span>
        {title}
      </h3>
      <div className="mt-2">
        {loading ? (
          <div
            className="h-4 w-2/3 animate-pulse rounded bg-raised"
            aria-hidden
          />
        ) : (
          children
        )}
      </div>
    </div>
  );
}

function StatusLine({ label, value }: { label: string; value: string }) {
  // /health/ready reports "ready"; /health checks report "ok". Both healthy.
  const ok = value === "ok" || value === "ready";
  return (
    <p className="flex items-center gap-2 text-sm">
      <span
        className={`inline-block h-2.5 w-2.5 rounded-full ${
          ok ? "bg-ok" : value === "unknown" ? "bg-line-strong" : "bg-warn"
        }`}
        aria-hidden
      />
      <span className="text-muted">{label}</span>
      <span className={ok ? "text-ok" : "text-warn"}>{value}</span>
    </p>
  );
}
