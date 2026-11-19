/**
 * Endpoint overview + inventory table (Phase 2.7).
 *
 * All numbers come from GET /endpoints/overview; rows from GET /endpoints.
 * Nothing is synthesized client-side. Server-side pagination, sorting
 * (allowlisted fields) and filters; UTC timestamps everywhere.
 */

import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  useEndpoints,
  useGroups,
  useOverview,
  type EndpointListParams,
  type EndpointStatus,
} from "../api/endpoints";
import { Pagination } from "../components/Pagination";
import { StatusBadge } from "../components/StatusBadge";
import { Empty, ErrorState, Loading } from "../components/states";
import { formatUtcShort } from "../utils/datetime";

const SORTABLE = ["hostname", "status", "os", "agent_version", "enrolled_at", "last_heartbeat_at"] as const;
type SortField = (typeof SORTABLE)[number];

export function EndpointListPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  const page = Number(searchParams.get("page") ?? 1);
  const pageSize = Number(searchParams.get("page_size") ?? 20);
  const sort = (searchParams.get("sort") ?? "enrolled_at") as SortField;
  const order = (searchParams.get("order") ?? "desc") as "asc" | "desc";
  const status = (searchParams.get("status") ?? "") as EndpointStatus | "";
  const q = searchParams.get("q") ?? "";
  const os = searchParams.get("os") ?? "";
  const agentVersion = searchParams.get("agent_version") ?? "";
  const groupId = searchParams.get("group_id") ?? "";

  const [searchDraft, setSearchDraft] = useState(q);

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

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "page") next.delete("page");
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

  const stats = overview.data;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Endpoints</h1>
          <p className="text-sm text-slate-400">
            Enrolled collectors, their heartbeat health and inventory.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            void endpoints.refetch();
            void overview.refetch();
          }}
          className="rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
        >
          Refresh
        </button>
      </header>

      {overview.isLoading && <Loading label="Loading overview…" />}
      {overview.isError && <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />}
      {stats && (
        <section aria-label="Endpoint statistics" className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <Stat label="Total" value={stats.total} />
          <Stat label="Active" value={stats.active} tone="text-emerald-300" />
          <Stat label="Offline" value={stats.offline} tone="text-amber-300" />
          <Stat label="Revoked" value={stats.revoked} tone="text-red-300" />
          <Stat label="Windows" value={stats.windows} />
          <Stat label="Linux" value={stats.linux} />
        </section>
      )}

      <section aria-label="Filters" className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            setParam("q", searchDraft.trim());
          }}
        >
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Search hostname
            <input
              value={searchDraft}
              onChange={(e) => setSearchDraft(e.target.value)}
              placeholder="hostname…"
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Status
            <select
              value={status}
              onChange={(e) => setParam("status", e.target.value)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            >
              <option value="">All</option>
              <option value="active">Active</option>
              <option value="offline">Offline</option>
              <option value="revoked">Revoked</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            OS
            <select
              value={os}
              onChange={(e) => setParam("os", e.target.value)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            >
              <option value="">All</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Agent version
            <input
              value={agentVersion}
              onChange={(e) => setParam("agent_version", e.target.value.trim())}
              placeholder="e.g. 0.2.0"
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Group
            <select
              value={groupId}
              onChange={(e) => setParam("group_id", e.target.value)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            >
              <option value="">All</option>
              {groups.data?.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            className="rounded bg-slate-700 px-3 py-1.5 text-sm text-white hover:bg-slate-600"
          >
            Apply
          </button>
        </form>
      </section>

      {endpoints.isLoading && <Loading label="Loading endpoints…" />}
      {endpoints.isError && (
        <ErrorState error={endpoints.error} onRetry={() => void endpoints.refetch()} />
      )}

      {endpoints.data && endpoints.data.items.length === 0 && (
        <Empty message="No endpoints match the current filters." />
      )}

      {endpoints.data && endpoints.data.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <Th field="hostname" sort={sort} order={order} onSort={toggleSort} />
                <Th label="OS" field="os" sort={sort} order={order} onSort={toggleSort} />
                <th scope="col" className="px-4 py-3">
                  Status
                </th>
                <th scope="col" className="px-4 py-3">
                  IP addresses
                </th>
                <Th
                  label="Agent version"
                  field="agent_version"
                  sort={sort}
                  order={order}
                  onSort={toggleSort}
                />
                <Th
                  label="Last heartbeat"
                  field="last_heartbeat_at"
                  sort={sort}
                  order={order}
                  onSort={toggleSort}
                />
                <Th
                  label="Enrolled"
                  field="enrolled_at"
                  sort={sort}
                  order={order}
                  onSort={toggleSort}
                />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-950">
              {endpoints.data.items.map((ep) => (
                <tr key={ep.id} className="hover:bg-slate-900/60">
                  <td className="px-4 py-3">
                    <Link
                      to={`/endpoints/${ep.id}`}
                      className="font-medium text-sky-300 hover:underline"
                    >
                      {ep.hostname}
                    </Link>
                    {ep.groups.length > 0 && (
                      <p className="mt-0.5 text-xs text-slate-500">
                        {ep.groups.join(", ")}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {ep.os}
                    {ep.os_version ? (
                      <span className="text-slate-500"> {ep.os_version}</span>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={ep.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">
                    {ep.ip_addresses.length > 0 ? ep.ip_addresses.join(", ") : "—"}
                  </td>
                  <td className="px-4 py-3 text-slate-300">{ep.agent_version ?? "—"}</td>
                  <td className="px-4 py-3 text-slate-300">
                    {formatUtcShort(ep.last_heartbeat_at)}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {formatUtcShort(ep.enrolled_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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

function Stat({ label, value, tone = "text-slate-100" }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${tone}`}>{value}</p>
    </div>
  );
}

function Th({
  label,
  field,
  sort,
  order,
  onSort,
}: {
  label?: string;
  field: SortField;
  sort: SortField;
  order: "asc" | "desc";
  onSort: (f: SortField) => void;
}) {
  const active = sort === field;
  return (
    <th scope="col" className="px-4 py-3">
      <button
        type="button"
        onClick={() => onSort(field)}
        className="flex items-center gap-1 uppercase tracking-wide hover:text-slate-300"
        aria-label={`Sort by ${label ?? field}`}
      >
        {label ?? field}
        <span aria-hidden className={active ? "text-sky-300" : "text-slate-600"}>
          {active ? (order === "asc" ? "▲" : "▼") : "↕"}
        </span>
      </button>
    </th>
  );
}
