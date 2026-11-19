/**
 * Endpoint overview + inventory table (Phases 2.5–2.8).
 *
 * Every number comes from GET /endpoints/overview; rows from GET /endpoints;
 * activity from GET /audit-logs (real lifecycle events). Nothing is
 * synthesized client-side. Server-side pagination, sorting (allowlisted)
 * and filters; debounced search; UTC timestamps everywhere.
 */

import { Link, useSearchParams } from "react-router-dom";
import {
  Activity,
  Clock,
  Monitor,
  MonitorSmartphone,
  RefreshCw,
  Server,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import {
  useEndpointActivity,
  useEndpoints,
  useGroups,
  useOverview,
  type EndpointListParams,
  type EndpointRow,
  type EndpointStatus,
} from "../api/endpoints";
import { ActivityList } from "../components/ActivityList";
import { ChartCard, ProgressBar } from "../components/ChartCard";
import { DataTable, type Column } from "../components/DataTable";
import { FilterBar, FilterSelect } from "../components/FilterBar";
import { PageHeader } from "../components/PageHeader";
import { Pagination } from "../components/Pagination";
import { SearchInput } from "../components/SearchInput";
import { StatCard } from "../components/StatCard";
import { StatusBadge } from "../components/StatusBadge";
import { Empty, ErrorState, Loading } from "../components/states";
import { useAuth } from "../auth/AuthContext";
import { ageLabel, formatUtcShort } from "../utils/datetime";
import { OsIcon } from "../components/OsIcon";

const SORTABLE = [
  "hostname",
  "status",
  "os",
  "agent_version",
  "enrolled_at",
  "last_heartbeat_at",
] as const;
type SortField = (typeof SORTABLE)[number];

export function EndpointListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { hasPermission } = useAuth();

  const page = Number(searchParams.get("page") ?? 1);
  const pageSize = Number(searchParams.get("page_size") ?? 20);
  const sort = (searchParams.get("sort") ?? "enrolled_at") as SortField;
  const order = (searchParams.get("order") ?? "desc") as "asc" | "desc";
  const status = (searchParams.get("status") ?? "") as EndpointStatus | "";
  const q = searchParams.get("q") ?? "";
  const os = searchParams.get("os") ?? "";
  const agentVersion = searchParams.get("agent_version") ?? "";
  const groupId = searchParams.get("group_id") ?? "";

  const params: EndpointListParams = {
    page,
    page_size: pageSize,
    status,
    q,
    os,
    agent_version: agentVersion,
    group_id: groupId,
    sort,
    order,
  };

  const overview = useOverview();
  const groups = useGroups();
  const endpoints = useEndpoints(params);
  const stats = overview.data;

  // Operational sections: real queries, each with its own state.
  const recentActive = useEndpoints({
    page: 1,
    page_size: 5,
    sort: "last_heartbeat_at",
    order: "desc",
  });
  const offlineAlerts = useEndpoints({
    page: 1,
    page_size: 5,
    status: "offline",
  });
  const activity = useEndpointActivity({
    enabled: hasPermission("audit:read"),
    limit: 8,
  });

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "page") next.delete("page");
    setSearchParams(next, { replace: true });
  }

  function clearFilters() {
    const next = new URLSearchParams(searchParams);
    for (const key of ["q", "status", "os", "agent_version", "group_id", "page"]) {
      next.delete(key);
    }
    setSearchParams(next, { replace: true });
  }

  function toggleSort(field: SortField) {
    const next = new URLSearchParams(searchParams);
    if (sort === field) {
      next.set("order", order === "asc" ? "desc" : "asc");
    } else {
      next.set("sort", field);
      next.set("order", "asc");
    }
    next.delete("page");
    setSearchParams(next, { replace: true });
  }

  const hasFilters = Boolean(q || status || os || agentVersion || groupId);

  const columns: Column<EndpointRow>[] = [
    {
      key: "hostname",
      header: "Endpoint",
      sortField: "hostname",
      sortLabel: "hostname",
      render: (ep) => (
        <>
          <Link
            to={`/endpoints/${ep.id}`}
            className="font-medium text-accent hover:underline"
          >
            {ep.hostname}
          </Link>
          {ep.groups.length > 0 && (
            <p className="mt-0.5 text-xs text-faint">{ep.groups.join(", ")}</p>
          )}
        </>
      ),
    },
    {
      key: "os",
      header: "OS",
      sortField: "os",
      render: (ep) => (
        <span className="flex items-center gap-1.5 text-muted">
          <OsIcon os={ep.os} />
          <span className="capitalize">{ep.os}</span>
          {ep.os_version && (
            <span className="text-faint">{ep.os_version}</span>
          )}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      sortField: "status",
      render: (ep) => <StatusBadge status={ep.status} />,
    },
    {
      key: "ips",
      header: "IP addresses",
      render: (ep) => (
        <span className="font-mono text-xs text-muted">
          {ep.ip_addresses.length > 0 ? ep.ip_addresses.join(", ") : "—"}
        </span>
      ),
    },
    {
      key: "agent",
      header: "Agent",
      sortField: "agent_version",
      render: (ep) => (
        <span className="text-muted">{ep.agent_version ?? "—"}</span>
      ),
    },
    {
      key: "heartbeat",
      header: "Last heartbeat",
      sortField: "last_heartbeat_at",
      render: (ep) => (
        <span className="whitespace-nowrap text-muted">
          {formatUtcShort(ep.last_heartbeat_at)}
          {ep.last_heartbeat_at && (
            <span className="ml-1 text-faint">({ageLabel(ep.last_heartbeat_at)})</span>
          )}
        </span>
      ),
    },
    {
      key: "inventory",
      header: "Last inventory",
      render: (ep) => (
        <span className="whitespace-nowrap text-muted">
          {formatUtcShort(ep.last_inventory_at)}
        </span>
      ),
    },
    {
      key: "enrolled",
      header: "Enrolled",
      sortField: "enrolled_at",
      className: "hidden xl:table-cell",
      render: (ep) => (
        <span className="whitespace-nowrap text-muted">
          {formatUtcShort(ep.enrolled_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      render: (ep) => (
        <span className="flex gap-3 text-xs">
          <Link
            to={`/endpoints/${ep.id}`}
            aria-label={`View ${ep.hostname} details`}
            className="text-accent hover:underline"
          >
            Details
          </Link>
          <Link
            to={`/endpoints/${ep.id}/history`}
            aria-label={`${ep.hostname} inventory history`}
            className="text-accent hover:underline"
          >
            History
          </Link>
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Endpoints"
        description="Enrolled collectors, heartbeat health and inventory coverage."
        actions={
          <button
            type="button"
            onClick={() => {
              void endpoints.refetch();
              void overview.refetch();
            }}
            className="flex items-center gap-1.5 rounded-md border border-line px-3 py-1.5 text-sm text-muted transition-colors hover:bg-raised hover:text-ink"
          >
            <RefreshCw size={14} aria-hidden />
            Refresh
          </button>
        }
      />

      {/* --- KPI cards (real overview aggregates) --- */}
      {overview.isLoading && <Loading label="Loading overview…" />}
      {overview.isError && (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      )}
      {stats && (
        <section
          aria-label="Endpoint statistics"
          className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6"
        >
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
          <StatCard
            label="Windows"
            value={stats.windows}
            icon={Monitor}
            href="/endpoints?os=windows"
            ariaLabel={`${stats.windows} Windows endpoints — view`}
          />
          <StatCard
            label="Linux"
            value={stats.linux}
            icon={Terminal}
            href="/endpoints?os=linux"
            ariaLabel={`${stats.linux} Linux endpoints — view`}
          />
        </section>
      )}

      {/* --- Distribution charts (overview numbers only) --- */}
      {stats && (
        <div className="grid gap-3 lg:grid-cols-3">
          <ChartCard
            title="Status distribution"
            description="Lifecycle state of all enrolled endpoints"
            segments={[
              { label: "Active", value: stats.active, colorClass: "bg-ok", href: "/endpoints?status=active" },
              { label: "Offline", value: stats.offline, colorClass: "bg-warn", href: "/endpoints?status=offline" },
              { label: "Revoked", value: stats.revoked, colorClass: "bg-danger", href: "/endpoints?status=revoked" },
            ]}
            emptyMessage="No endpoints enrolled yet."
          />
          <ChartCard
            title="Operating systems"
            description="Reported OS family per endpoint"
            segments={[
              { label: "Windows", value: stats.windows, colorClass: "bg-accent", href: "/endpoints?os=windows" },
              { label: "Linux", value: stats.linux, colorClass: "bg-ok", href: "/endpoints?os=linux" },
              { label: "Other", value: stats.other_os, colorClass: "bg-line-strong" },
            ]}
            emptyMessage="No endpoints enrolled yet."
          />
          <ProgressBar
            label="Inventory collection health"
            value={stats.inventory_reported}
            max={stats.total}
            hint={
              stats.total === 0
                ? "No endpoints enrolled yet."
                : `${stats.inventory_reported} of ${stats.total} endpoints have submitted inventory`
            }
            colorClass="bg-ok"
          />
        </div>
      )}

      {/* --- Operational sections --- */}
      <div className="grid gap-3 lg:grid-cols-3">
        <section
          aria-label="Recently enrolled"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h3 className="text-sm font-medium text-ink">Recently enrolled</h3>
          {overview.isLoading && (
            <div className="mt-3">
              <Loading label="Loading enrollments…" />
            </div>
          )}
          {stats && stats.latest_enrollments.length === 0 && (
            <p className="mt-3 text-sm text-faint">No enrollments yet.</p>
          )}
          {stats && stats.latest_enrollments.length > 0 && (
            <ul className="mt-2 divide-y divide-line">
              {stats.latest_enrollments.map((ep) => (
                <li key={ep.id} className="flex items-center justify-between gap-2 py-2 text-sm">
                  <div className="min-w-0">
                    <Link
                      to={`/endpoints/${ep.id}`}
                      className="truncate font-medium text-accent hover:underline"
                    >
                      {ep.hostname}
                    </Link>
                    <p className="text-xs text-faint">{ep.os}</p>
                  </div>
                  <time
                    dateTime={ep.enrolled_at}
                    className="shrink-0 text-xs tabular-nums text-faint"
                  >
                    {formatUtcShort(ep.enrolled_at)}
                  </time>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section
          aria-label="Recently active"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h3 className="text-sm font-medium text-ink">Recently active</h3>
          {recentActive.isLoading && (
            <div className="mt-3">
              <Loading label="Loading recent endpoints…" />
            </div>
          )}
          {recentActive.isError && (
            <div className="mt-3">
              <ErrorState
                inline
                error={recentActive.error}
                onRetry={() => void recentActive.refetch()}
              />
            </div>
          )}
          {recentActive.data && recentActive.data.items.length === 0 && (
            <p className="mt-3 text-sm text-faint">No endpoints have heartbeated yet.</p>
          )}
          {recentActive.data && recentActive.data.items.length > 0 && (
            <ul className="mt-2 divide-y divide-line">
              {recentActive.data.items.map((ep) => (
                <li key={ep.id} className="flex items-center justify-between gap-2 py-2 text-sm">
                  <Link
                    to={`/endpoints/${ep.id}`}
                    className="truncate font-medium text-accent hover:underline"
                  >
                    {ep.hostname}
                  </Link>
                  <span className="shrink-0 text-xs tabular-nums text-faint">
                    {ep.last_heartbeat_at
                      ? `${ageLabel(ep.last_heartbeat_at)} ago`
                      : "never"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section
          aria-label="Offline alerts"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h3 className="flex items-center gap-1.5 text-sm font-medium text-ink">
            <ShieldAlert size={14} aria-hidden className="text-warn" />
            Offline alerts
          </h3>
          {stats && stats.offline === 0 && (
            <p className="mt-3 text-sm text-faint">All enrolled endpoints are online.</p>
          )}
          {stats && stats.offline > 0 && (
            <>
              {offlineAlerts.isLoading && (
                <div className="mt-3">
                  <Loading label="Loading offline alerts…" />
                </div>
              )}
              {offlineAlerts.isError && (
                <div className="mt-3">
                  <ErrorState
                    inline
                    error={offlineAlerts.error}
                    onRetry={() => void offlineAlerts.refetch()}
                  />
                </div>
              )}
              {offlineAlerts.data && offlineAlerts.data.items.length === 0 && (
                <p className="mt-3 text-sm text-faint">
                  Status changed since the last refresh.
                </p>
              )}
              {offlineAlerts.data && offlineAlerts.data.items.length > 0 && (
                <ul className="mt-2 divide-y divide-line">
                  {offlineAlerts.data.items.map((ep) => (
                    <li key={ep.id} className="flex items-center justify-between gap-2 py-2 text-sm">
                      <Link
                        to={`/endpoints/${ep.id}`}
                        className="truncate font-medium text-accent hover:underline"
                      >
                        {ep.hostname}
                      </Link>
                      <span className="shrink-0 text-xs text-faint">
                        {ep.last_heartbeat_at
                          ? `last seen ${ageLabel(ep.last_heartbeat_at)} ago`
                          : "never heartbeated"}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-2 text-xs text-faint">
                <Link to="/endpoints?status=offline" className="text-accent hover:underline">
                  View all offline endpoints
                </Link>
              </p>
            </>
          )}
        </section>
      </div>

      {/* --- Lifecycle activity (audit:read only; real audit rows) --- */}
      {hasPermission("audit:read") && (
        <section
          aria-label="Recent endpoint activity"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h3 className="flex items-center gap-1.5 text-sm font-medium text-ink">
            <Activity size={14} aria-hidden className="text-accent" />
            Recent endpoint activity
          </h3>
          <div className="mt-1">
            {activity.isLoading && <Loading label="Loading activity…" />}
            {activity.isError && (
              <ErrorState
                inline
                error={activity.error}
                onRetry={() => void activity.refetch()}
              />
            )}
            {activity.data && (
              <ActivityList
                events={activity.data}
                emptyMessage="No lifecycle events recorded yet (enrollments, state transitions and rotations appear here)."
              />
            )}
          </div>
        </section>
      )}

      {/* --- Filters --- */}
      <FilterBar
        showClear={hasFilters}
        onClear={clearFilters}
        label="Endpoint filters"
      >
        <SearchInput
          label="Search hostname"
          value={q}
          onSearch={(value) => setParam("q", value)}
          placeholder="hostname…"
        />
        <FilterSelect
          label="Status"
          value={status}
          onChange={(value) => setParam("status", value)}
          options={[
            { value: "", label: "All" },
            { value: "active", label: "Active" },
            { value: "offline", label: "Offline" },
            { value: "revoked", label: "Revoked" },
          ]}
        />
        <FilterSelect
          label="OS"
          value={os}
          onChange={(value) => setParam("os", value)}
          options={[
            { value: "", label: "All" },
            { value: "windows", label: "Windows" },
            { value: "linux", label: "Linux" },
          ]}
        />
        <FilterSelect
          label="Group"
          value={groupId}
          onChange={(value) => setParam("group_id", value)}
          options={[
            { value: "", label: "All" },
            ...(groups.data ?? []).map((g) => ({ value: g.id, label: g.name })),
          ]}
        />
        <label className="flex flex-col gap-1 text-xs text-muted">
          Agent version
          <input
            value={agentVersion}
            onChange={(e) => setParam("agent_version", e.target.value.trim())}
            placeholder="e.g. 0.2.0"
            className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink placeholder:text-faint focus:border-accent"
          />
        </label>
      </FilterBar>

      {/* --- Table --- */}
      {endpoints.isLoading && <Loading label="Loading endpoints…" />}
      {endpoints.isError && (
        <ErrorState error={endpoints.error} onRetry={() => void endpoints.refetch()} />
      )}

      {endpoints.data && endpoints.data.items.length === 0 && (
        <Empty message="No endpoints match the current view. Enroll an endpoint to get started." />
      )}

      {endpoints.data && endpoints.data.items.length > 0 && (
        <DataTable
          caption="Enrolled endpoints"
          columns={columns}
          rows={endpoints.data.items}
          rowKey={(ep) => ep.id}
          sort={{ field: sort, order }}
          onSort={(field) => toggleSort(field as SortField)}
        />
      )}

      {endpoints.data && endpoints.data.items.length > 0 && (
        <Pagination
          page={endpoints.data.page}
          pageSize={endpoints.data.page_size}
          total={endpoints.data.total}
          onPageSizeChange={(size) => setParam("page_size", String(size))}
          onPageChange={(next) => setParam("page", String(next))}
        />
      )}
    </div>
  );
}
