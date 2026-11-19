/**
 * Inventory history (Phase 2.6/2.7): immutable snapshots with timestamps,
 * side-by-side comparison (software installed/removed/changed + hardware
 * changes) and per-snapshot detail. Date range filters are optional and
 * bounded server-side.
 */

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  useEndpoint,
  useEndpointNetwork,
  useSnapshot,
  useSnapshots,
  type SnapshotDiff,
  type SnapshotDetail,
  type SnapshotSoftware,
} from "../api/endpoints";
import { Pagination } from "../components/Pagination";
import { Empty, ErrorState, Loading } from "../components/states";
import { formatUtc } from "../utils/datetime";

export function EndpointHistoryPage() {
  const { id } = useParams();

  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const [compareTo, setCompareTo] = useState<string | null>(null);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const detail = useEndpoint(id);
  const snapshots = useSnapshots(id, {
    page,
    page_size: 20,
    from: from ? `${from}T00:00:00Z` : undefined,
    to: to ? `${to}T23:59:59Z` : undefined,
  });
  const snapshotDetail = useSnapshot(id, selected ?? undefined, compareTo ?? undefined);
  const network = useEndpointNetwork(id, { page_size: 5 });

  const items = snapshots.data?.items ?? [];
  // Selecting a row as target auto-designates the previous snapshot as base.
  function selectSnapshot(snapshotId: string) {
    if (selected === snapshotId) {
      setSelected(null);
      setCompareTo(null);
      return;
    }
    const index = items.findIndex((s) => s.id === snapshotId);
    const previous = items[index + 1]; // list is newest-first
    setSelected(snapshotId);
    setCompareTo(previous && previous.id !== snapshotId ? previous.id : null);
  }

  if (detail.isLoading) return <Loading label="Loading history…" />;
  if (detail.isError) {
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  }

  return (
    <div className="space-y-6">
      <header>
        <nav aria-label="Breadcrumb" className="text-xs text-slate-500">
          <Link to="/endpoints" className="hover:text-slate-300">
            Endpoints
          </Link>{" "}
          /{" "}
          <Link to={`/endpoints/${id}`} className="hover:text-slate-300">
            {detail.data?.hostname ?? "endpoint"}
          </Link>{" "}
          / <span className="text-slate-300">Inventory history</span>
        </nav>
        <h1 className="mt-1 text-2xl font-semibold text-slate-100">
          Inventory history — {detail.data?.hostname}
        </h1>
        <p className="text-sm text-slate-400">
          Immutable snapshots submitted by the agent. Identical submissions are
          deduplicated server-side.
        </p>
      </header>

      <form
        aria-label="Date range filter"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-slate-800 bg-slate-900 p-4"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(1);
          void snapshots.refetch();
        }}
      >
        <label className="flex flex-col gap-1 text-xs text-slate-400">
          From
          <input
            type="date"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-slate-400">
          To
          <input
            type="date"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
          />
        </label>
        <button type="submit" className="rounded bg-slate-700 px-3 py-1.5 text-sm text-white hover:bg-slate-600">
          Apply
        </button>
        {(from || to) && (
          <button
            type="button"
            onClick={() => {
              setFrom("");
              setTo("");
              setPage(1);
            }}
            className="rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800"
          >
            Clear
          </button>
        )}
      </form>

      {snapshots.isLoading && <Loading label="Loading snapshots…" />}
      {snapshots.isError && (
        <ErrorState error={snapshots.error} onRetry={() => void snapshots.refetch()} />
      )}
      {snapshots.data && items.length === 0 && (
        <Empty message="No snapshots in the selected range." />
      )}

      {items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th scope="col" className="px-4 py-3">
                  Compare
                </th>
                <th scope="col" className="px-4 py-3">
                  Received (UTC)
                </th>
                <th scope="col" className="px-4 py-3">
                  Collected (UTC)
                </th>
                <th scope="col" className="px-4 py-3">
                  Packages
                </th>
                <th scope="col" className="px-4 py-3">
                  Facts
                </th>
                <th scope="col" className="px-4 py-3">
                  Sections
                </th>
                <th scope="col" className="px-4 py-3">
                  Schema
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-950">
              {items.map((s) => (
                <tr
                  key={s.id}
                  className={selected === s.id ? "bg-sky-500/10" : "hover:bg-slate-900/60"}
                >
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      aria-label={`Select snapshot ${formatUtc(s.received_at)} for comparison`}
                      checked={selected === s.id}
                      onChange={() => selectSnapshot(s.id)}
                      className="h-4 w-4"
                    />
                  </td>
                  <td className="px-4 py-3 text-slate-300">{formatUtc(s.received_at)}</td>
                  <td className="px-4 py-3 text-slate-300">{formatUtc(s.collected_at)}</td>
                  <td className="px-4 py-3 tabular-nums text-slate-300">{s.package_count}</td>
                  <td className="px-4 py-3 tabular-nums text-slate-300">{s.fact_count}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {[s.has_hardware && "hardware", s.has_network && "network"]
                      .filter(Boolean)
                      .join(", ") || "system only"}
                  </td>
                  <td className="px-4 py-3 text-slate-400">{s.schema_version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {snapshots.data && items.length > 0 && (
        <Pagination
          page={snapshots.data.page}
          pageSize={snapshots.data.page_size}
          total={snapshots.data.total}
          onPageChange={setPage}
          label="snapshot pagination"
        />
      )}

      {snapshotDetail.isLoading && <Loading label="Loading snapshot…" />}
      {snapshotDetail.isError && (
        <ErrorState error={snapshotDetail.error} onRetry={() => void snapshotDetail.refetch()} />
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <section
          aria-label="Snapshot detail"
          className="rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <h2 className="text-sm font-medium text-slate-300">
            {snapshotDetail.data
              ? `Snapshot — ${formatUtc(snapshotDetail.data.received_at)}`
              : "Snapshot detail"}
          </h2>
          {!snapshotDetail.data && (
            <p className="mt-2 text-sm text-slate-500">
              Select a snapshot to inspect its packages and facts.
            </p>
          )}
          {snapshotDetail.data && <SnapshotDetailBody data={snapshotDetail.data} />}
        </section>

        <section aria-label="Comparison" className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 className="text-sm font-medium text-slate-300">Comparison</h2>
          {snapshotDetail.data?.changes ? (
            <DiffPanel diff={snapshotDetail.data.changes} />
          ) : (
            <p className="mt-2 text-sm text-slate-500">
              Select a snapshot to compare it with the previous one (newest
              first).
            </p>
          )}
        </section>
      </div>

      <section aria-label="Network history" className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-300">Network history</h2>
        {network.isLoading && <div className="mt-2"><Loading /></div>}
        {network.isError && (
          <div className="mt-2">
            <ErrorState error={network.error} />
          </div>
        )}
        {network.data && network.data.items.length === 0 && (
          <div className="mt-2">
            <Empty message="No network sections reported yet." />
          </div>
        )}
        {network.data && network.data.items.length > 0 && (
          <ul className="mt-2 divide-y divide-slate-800">
            {network.data.items.map((row) => {
              const ips = (row.network?.ip_addresses as string[] | undefined) ?? [];
              return (
                <li key={row.snapshot_id} className="flex items-center justify-between py-2 text-sm">
                  <span className="text-slate-300">{formatUtc(row.collected_at)}</span>
                  <span className="font-mono text-xs text-slate-400">
                    {ips.length > 0 ? ips.join(", ") : "no IPs"}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
}

function SnapshotDetailBody({ data }: { data: SnapshotDetail }) {
  return (
    <>
      <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-500">Agent</dt>
        <dd className="text-slate-200">{data.agent_version ?? "—"}</dd>
        <dt className="text-slate-500">Schema version</dt>
        <dd className="text-slate-200">{data.schema_version}</dd>
      </dl>
      <h3 className="mt-3 text-xs uppercase tracking-wide text-slate-500">
        Packages ({data.packages.length})
      </h3>
      <ul className="mt-1 max-h-56 divide-y divide-slate-800 overflow-y-auto">
        {data.packages.map((p) => (
          <li key={`${p.name}-${p.package_manager}`} className="flex justify-between py-1.5 text-sm">
            <span className="text-slate-200">{p.name}</span>
            <span className="font-mono text-xs text-slate-400">{p.version}</span>
          </li>
        ))}
      </ul>
      {Object.keys(data.facts).length > 0 && (
        <>
          <h3 className="mt-3 text-xs uppercase tracking-wide text-slate-500">Facts</h3>
          <ul className="mt-1 grid grid-cols-2 gap-1 text-xs text-slate-400">
            {Object.entries(data.facts).map(([k, v]) => (
              <li key={k}>
                <span className="text-slate-500">{k}</span>: {v}
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

function DiffPanel({ diff }: { diff: SnapshotDiff }) {
  return (
    <div className="mt-2 space-y-3 text-sm">
      <PackageDiff title="Installed since base" rows={diff.added_packages} tone="text-emerald-300" />
      <PackageDiff title="Removed since base" rows={diff.removed_packages} tone="text-red-300" />
      <PackageDiff title="Version changed" rows={diff.changed_packages} tone="text-amber-300" showPrevious />
      <div>
        <h3 className="text-xs uppercase tracking-wide text-slate-500">Hardware changes</h3>
        {diff.hardware_changes.length === 0 ? (
          <p className="mt-1 text-slate-500">No hardware changes.</p>
        ) : (
          <ul className="mt-1 space-y-1">
            {diff.hardware_changes.map((c) => (
              <li key={c.field} className="text-slate-300">
                <span className="text-slate-400">{c.field}</span>:{" "}
                <span className="text-red-300">{String(c.before ?? "—")}</span> →{" "}
                <span className="text-emerald-300">{String(c.after ?? "—")}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function PackageDiff({
  title,
  rows,
  tone,
  showPrevious = false,
}: {
  title: string;
  rows: SnapshotSoftware[];
  tone: string;
  showPrevious?: boolean;
}) {
  return (
    <div>
      <h3 className={`text-xs uppercase tracking-wide ${tone}`}>
        {title} ({rows.length})
      </h3>
      {rows.length === 0 ? (
        <p className="mt-1 text-slate-500">None.</p>
      ) : (
        <ul className="mt-1 max-h-40 space-y-0.5 overflow-y-auto">
          {rows.map((p) => (
            <li key={`${p.name}-${p.package_manager}`} className="text-slate-300">
              {p.name}{" "}
              <span className="font-mono text-xs">
                {showPrevious && p.previous_version
                  ? `${p.previous_version} → ${p.version}`
                  : p.version}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
