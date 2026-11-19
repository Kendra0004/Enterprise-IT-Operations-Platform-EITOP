/**
 * Inventory history (Phases 2.6–2.8): immutable snapshots with distinct
 * collection/receipt timestamps, date filtering, side-by-side comparison
 * (software installed/removed/changed + hardware changes) and per-snapshot
 * detail. Date ranges are optional and bounded server-side.
 */

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  GitCompareArrows,
  Inbox,
  ListTree,
  Network,
  Package,
} from "lucide-react";
import {
  useEndpoint,
  useEndpointNetwork,
  useSnapshot,
  useSnapshots,
  type SnapshotDetail,
  type SnapshotDiff,
  type SnapshotSoftware,
} from "../api/endpoints";
import { PageHeader } from "../components/PageHeader";
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
    <div className="space-y-5">
      <PageHeader
        title={`Inventory history — ${detail.data?.hostname ?? "endpoint"}`}
        description="Immutable snapshots submitted by the agent. Identical submissions are deduplicated server-side; collected is the agent-side time, received is the server-side time."
        actions={
          <Link
            to={`/endpoints/${id}`}
            className="rounded-md border border-line px-3 py-1.5 text-sm text-muted transition-colors hover:bg-raised hover:text-ink"
          >
            ← Endpoint details
          </Link>
        }
      />

      <form
        aria-label="Date range filter"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-line bg-surface p-3 shadow-card"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(1);
          void snapshots.refetch();
        }}
      >
        <label className="flex flex-col gap-1 text-xs text-muted">
          From
          <input
            type="date"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted">
          To
          <input
            type="date"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
          />
        </label>
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
        >
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
            className="rounded-md border border-line px-3 py-1.5 text-sm text-muted hover:bg-raised hover:text-ink"
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
        <div className="overflow-x-auto rounded-lg border border-line bg-surface shadow-card">
          <table className="min-w-full text-sm">
            <caption className="sr-only">Inventory snapshots, newest first</caption>
            <thead className="border-b border-line bg-raised text-left text-[11px] uppercase tracking-wider text-faint">
              <tr>
                <th scope="col" className="px-4 py-2.5">
                  Compare
                </th>
                <th scope="col" className="px-4 py-2.5">
                  Received (UTC)
                </th>
                <th scope="col" className="px-4 py-2.5">
                  Collected (UTC)
                </th>
                <th scope="col" className="px-4 py-2.5">
                  Packages
                </th>
                <th scope="col" className="px-4 py-2.5">
                  Facts
                </th>
                <th scope="col" className="px-4 py-2.5">
                  Sections
                </th>
                <th scope="col" className="px-4 py-2.5">
                  Schema
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {items.map((s) => (
                <tr
                  key={s.id}
                  className={selected === s.id ? "bg-accent-soft" : "hover:bg-raised/70"}
                >
                  <td className="px-4 py-2.5">
                    <input
                      type="checkbox"
                      aria-label={`Select snapshot ${formatUtc(s.received_at)} for comparison`}
                      checked={selected === s.id}
                      onChange={() => selectSnapshot(s.id)}
                      className="h-4 w-4 accent-accent"
                    />
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-ink">
                    {formatUtc(s.received_at)}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-muted">
                    {formatUtc(s.collected_at)}
                  </td>
                  <td className="px-4 py-2.5 tabular-nums text-muted">{s.package_count}</td>
                  <td className="px-4 py-2.5 tabular-nums text-muted">{s.fact_count}</td>
                  <td className="px-4 py-2.5 text-xs text-faint">
                    {[s.has_hardware && "hardware", s.has_network && "network"]
                      .filter(Boolean)
                      .join(", ") || "system only"}
                  </td>
                  <td className="px-4 py-2.5 text-faint">{s.schema_version}</td>
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

      <div className="grid gap-3 lg:grid-cols-2">
        <section
          aria-label="Snapshot detail"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h2 className="flex items-center gap-1.5 text-sm font-medium text-ink">
            <Inbox size={14} aria-hidden className="text-faint" />
            {snapshotDetail.data
              ? `Snapshot — ${formatUtc(snapshotDetail.data.received_at)}`
              : "Snapshot detail"}
          </h2>
          {!snapshotDetail.data && (
            <p className="mt-2 text-sm text-faint">
              Select a snapshot to inspect its packages and facts.
            </p>
          )}
          {snapshotDetail.data && <SnapshotDetailBody data={snapshotDetail.data} />}
        </section>

        <section
          aria-label="Comparison"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h2 className="flex items-center gap-1.5 text-sm font-medium text-ink">
            <GitCompareArrows size={14} aria-hidden className="text-faint" />
            Comparison
          </h2>
          {snapshotDetail.data?.changes ? (
            <DiffPanel diff={snapshotDetail.data.changes} />
          ) : (
            <p className="mt-2 text-sm text-faint">
              Select a snapshot to compare it with the previous one (newest
              first). Snapshots missing a section report that gap explicitly —
              missing data is never shown as “unchanged”.
            </p>
          )}
        </section>
      </div>

      <section
        aria-label="Network history"
        className="rounded-lg border border-line bg-surface p-4 shadow-card"
      >
        <h2 className="flex items-center gap-1.5 text-sm font-medium text-ink">
          <Network size={14} aria-hidden className="text-faint" />
          Network history
        </h2>
        {network.isLoading && (
          <div className="mt-2">
            <Loading />
          </div>
        )}
        {network.isError && (
          <div className="mt-2">
            <ErrorState inline error={network.error} />
          </div>
        )}
        {network.data && network.data.items.length === 0 && (
          <div className="mt-2">
            <Empty message="No network sections reported yet." />
          </div>
        )}
        {network.data && network.data.items.length > 0 && (
          <ul className="mt-2 divide-y divide-line">
            {network.data.items.map((row) => {
              const ips = (row.network?.ip_addresses as string[] | undefined) ?? [];
              return (
                <li
                  key={row.snapshot_id}
                  className="flex items-center justify-between gap-3 py-2 text-sm"
                >
                  <span className="text-muted">{formatUtc(row.collected_at)}</span>
                  <span className="truncate font-mono text-xs text-faint">
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
        <dt className="text-faint">Agent</dt>
        <dd className="text-ink">{data.agent_version ?? "—"}</dd>
        <dt className="text-faint">Schema version</dt>
        <dd className="text-ink">{data.schema_version}</dd>
      </dl>
      <h3 className="mt-3 flex items-center gap-1 text-xs uppercase tracking-wider text-faint">
        <Package size={12} aria-hidden />
        Packages ({data.packages.length})
      </h3>
      <ul className="mt-1 max-h-56 divide-y divide-line overflow-y-auto">
        {data.packages.map((p) => (
          <li
            key={`${p.name}-${p.package_manager}`}
            className="flex justify-between py-1.5 text-sm"
          >
            <span className="text-ink">{p.name}</span>
            <span className="font-mono text-xs text-muted">{p.version}</span>
          </li>
        ))}
      </ul>
      {Object.keys(data.facts).length > 0 && (
        <>
          <h3 className="mt-3 flex items-center gap-1 text-xs uppercase tracking-wider text-faint">
            <ListTree size={12} aria-hidden />
            Facts
          </h3>
          <ul className="mt-1 grid grid-cols-2 gap-1 text-xs text-muted">
            {Object.entries(data.facts).map(([k, v]) => (
              <li key={k}>
                <span className="text-faint">{k}</span>: {v}
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
    <div className="mt-3 space-y-3 text-sm">
      <PackageDiff
        title="Installed since base"
        rows={diff.added_packages}
        tone="text-ok"
      />
      <PackageDiff
        title="Removed since base"
        rows={diff.removed_packages}
        tone="text-danger"
      />
      <PackageDiff
        title="Version changed"
        rows={diff.changed_packages}
        tone="text-warn"
        showPrevious
      />
      <div>
        <h3 className="text-xs uppercase tracking-wider text-faint">
          Hardware changes
        </h3>
        {diff.hardware_changes.length === 0 ? (
          <p className="mt-1 text-faint">
            No hardware changes (or a hardware section was missing on one side —
            see snapshot sections above).
          </p>
        ) : (
          <ul className="mt-1 space-y-1">
            {diff.hardware_changes.map((c) => (
              <li key={c.field} className="text-muted">
                <span className="text-faint">{c.field}</span>:{" "}
                <span className="text-danger">{String(c.before ?? "—")}</span> →{" "}
                <span className="text-ok">{String(c.after ?? "—")}</span>
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
      <h3 className={`text-xs uppercase tracking-wider ${tone}`}>
        {title} ({rows.length})
      </h3>
      {rows.length === 0 ? (
        <p className="mt-1 text-faint">None.</p>
      ) : (
        <ul className="mt-1 max-h-40 space-y-0.5 overflow-y-auto">
          {rows.map((p) => (
            <li key={`${p.name}-${p.package_manager}`} className="text-muted">
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
