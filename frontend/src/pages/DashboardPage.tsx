import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";

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

/**
 * Dashboard shows ONLY real backend data:
 * - session info (from /auth/me)
 * - platform readiness (from /health/ready)
 * - recent audit events (admin/audit holders only)
 */
export function DashboardPage() {
  const { user, hasPermission } = useAuth();

  const ready = useQuery({
    queryKey: ["ready"],
    queryFn: () => fetch("/health/ready").then((r) => r.json() as Promise<ReadyResponse>),
    refetchInterval: 30_000,
    retry: 1,
  });

  const audit = useQuery({
    queryKey: ["audit-recent"],
    queryFn: () => api.get<AuditPage>("/audit-logs", { query: { page_size: 5 } }),
    enabled: hasPermission("audit:read"),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-sm text-slate-400">
          Signed in as {user?.email} — roles: {user?.roles.join(", ") || "none"}
        </p>
      </div>

      <section aria-labelledby="platform-status" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <h2 id="platform-status" className="sr-only">
          Platform status
        </h2>

        <Card title="API health">
          {ready.isLoading ? (
            <Skeleton />
          ) : (
            <StatusLine label="API" value={ready.data?.status ?? "unknown"} />
          )}
        </Card>

        <Card title="Database">
          {ready.isLoading ? (
            <Skeleton />
          ) : (
            <StatusLine
              label="PostgreSQL"
              value={ready.data?.checks?.database ?? "unknown"}
            />
          )}
        </Card>

        <Card title="Cache / jobs">
          {ready.isLoading ? (
            <Skeleton />
          ) : (
            <StatusLine label="Redis" value={ready.data?.checks?.redis ?? "unknown"} />
          )}
        </Card>
      </section>

      <section aria-labelledby="session-heading" className="grid gap-4 sm:grid-cols-2">
        <h2 id="session-heading" className="sr-only">
          Session
        </h2>
        <Card title="Your permissions">
          <ul className="flex flex-wrap gap-2">
            {user?.permissions.map((p) => (
              <li
                key={p}
                className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-emerald-300"
              >
                {p}
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Modules">
          <p className="text-sm text-slate-400">
            10 feature modules are listed in the sidebar. Everything except
            Dashboard and Administration is <em>under development</em> in Phase 1.
          </p>
        </Card>
      </section>

      {hasPermission("audit:read") && (
        <section aria-labelledby="recent-activity">
          <h2 id="recent-activity" className="mb-2 text-lg font-medium">
            Recent audit events
          </h2>
          {audit.isLoading && (
            <Card title="">
              <Skeleton />
            </Card>
          )}
          {audit.data && audit.data.items.length > 0 && (
            <ul className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-slate-900">
              {audit.data.items.map((e) => (
                <li key={e.id} className="flex items-center justify-between px-4 py-2 text-sm">
                  <span className="font-mono text-slate-300">{e.event_type}</span>
                  <span className="text-slate-400">{e.actor_email ?? "—"}</span>
                  <span
                    className={
                      e.outcome === "success" ? "text-emerald-400" : "text-red-400"
                    }
                  >
                    {e.outcome}
                  </span>
                  <span className="text-xs text-slate-500">
                    {new Date(e.created_at).toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {audit.data && audit.data.items.length === 0 && (
            <p className="text-sm text-slate-500">No audit events yet.</p>
          )}
          {audit.isError && audit.error instanceof ApiError && (
            <p className="text-sm text-amber-400">
              Could not load audit events: {audit.error.problem.title}
            </p>
          )}
        </section>
      )}
    </div>
  );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      {title && <h3 className="mb-2 text-sm font-medium text-slate-400">{title}</h3>}
      {children}
    </div>
  );
}

function StatusLine({ label, value }: { label: string; value: string }) {
  const ok = value === "ok";
  return (
    <p className="flex items-center gap-2 text-sm">
      <span
        className={`inline-block h-2.5 w-2.5 rounded-full ${
          ok ? "bg-emerald-500" : value === "unknown" ? "bg-slate-600" : "bg-amber-500"
        }`}
        aria-hidden
      />
      <span className="text-slate-300">{label}</span>
      <span className={ok ? "text-emerald-400" : "text-amber-400"}>{value}</span>
    </p>
  );
}

function Skeleton() {
  return <div className="h-4 w-2/3 animate-pulse rounded bg-slate-800" aria-hidden />;
}
