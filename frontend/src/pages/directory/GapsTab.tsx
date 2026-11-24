/**
 * Correlation Gaps tab (Phase 3.2.3): directory computers without a
 * resolved endpoint correlation, from `GET /directory/correlation/gaps`.
 *
 * The backend returns ONLY the three honest gap states — matched and
 * rejected records are deliberate decisions and never appear. The copy
 * never implies a candidate match is confirmed: ambiguous means leads
 * that require review, nothing more. Filtering and pagination are
 * server-side.
 */

import { useMemo, useState } from "react";
import {
  useCorrelationGaps,
  type CorrelationGap,
} from "../../api/directory";
import { DataTable, type Column } from "../../components/DataTable";
import { FilterBar, FilterSelect } from "../../components/FilterBar";
import { Pagination } from "../../components/Pagination";
import { Empty, ErrorState, Loading } from "../../components/states";
import { formatUtcShort } from "../../utils/datetime";

const GAP_TONES: Record<string, string> = {
  never_reconciled: "bg-warn/10 text-warn ring-warn/40",
  unmatched: "bg-danger/10 text-danger ring-danger/40",
  ambiguous: "bg-accent/10 text-accent ring-accent/40",
};

function GapBadge({ gapType }: { gapType: string }) {
  const cls = GAP_TONES[gapType] ?? "bg-raised text-muted ring-line-strong";
  return (
    <span
      data-testid={`gap-${gapType}`}
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}
    >
      {gapType.replace(/_/g, " ")}
    </span>
  );
}

/** Honest one-line explanations — a candidate is never a confirmed match. */
const GAP_EXPLANATIONS: { key: string; title: string; text: string }[] = [
  {
    key: "never_reconciled",
    title: "Never reconciled",
    text: "No reconciliation record exists — this computer has never been evaluated against endpoints.",
  },
  {
    key: "unmatched",
    title: "Unmatched",
    text: "Reconciliation ran and found no endpoint for this computer.",
  },
  {
    key: "ambiguous",
    title: "Ambiguous",
    text: "Candidate endpoints exist but none is confirmed. Candidates are leads for review, not matches.",
  },
];

export function GapsTab({ connectionId }: { connectionId: string }) {
  const [gapType, setGapType] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [sort, setSort] = useState("name");
  const [order, setOrder] = useState<"asc" | "desc">("asc");

  const params = useMemo(
    () => ({
      connection_id: connectionId,
      gap_type: gapType || undefined,
      page,
      page_size: pageSize,
      sort,
      order,
    }),
    [connectionId, gapType, page, pageSize, sort, order],
  );
  const gaps = useCorrelationGaps(params);

  function toggleSort(field: string) {
    if (sort === field) setOrder((o) => (o === "asc" ? "desc" : "asc"));
    else {
      setSort(field);
      setOrder("asc");
    }
    setPage(1);
  }

  if (!connectionId) {
    return (
      <Empty message="No directory connection configured yet — add one in Connections." />
    );
  }

  const columns: Column<CorrelationGap>[] = [
    {
      key: "name",
      header: "Computer",
      sortField: "name",
      sortLabel: "computer name",
      render: (r) => (
        <div className="min-w-0">
          <p className="font-medium text-ink">{r.computer_name}</p>
          <p className="break-all text-xs text-faint">
            {r.distinguished_name}
          </p>
        </div>
      ),
    },
    {
      key: "dns",
      header: "DNS hostname",
      render: (r) => <span className="break-all">{r.dns_hostname ?? "—"}</span>,
    },
    {
      key: "gap",
      header: "Gap type",
      render: (r) => <GapBadge gapType={r.gap_type} />,
    },
    {
      key: "recon",
      header: "Reconciliation",
      render: (r) => (
        <span className="capitalize text-muted">
          {r.recon_status ?? "none"}
          {r.recon_method ? ` · ${r.recon_method}` : ""}
        </span>
      ),
    },
    {
      key: "confidence",
      header: "Confidence",
      render: (r) => <span className="capitalize">{r.recon_confidence ?? "—"}</span>,
    },
    {
      key: "candidates",
      header: "Candidates",
      render: (r) =>
        r.candidates.length > 0 ? (
          <span className="tabular-nums text-muted">
            {r.candidates.length} (unconfirmed)
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      key: "reviewed",
      header: "Reviewed",
      render: (r) => formatUtcShort(r.reviewed_at),
    },
  ];

  return (
    <div className="space-y-4">
      <section
        aria-label="Gap type explanations"
        className="grid gap-3 sm:grid-cols-3"
      >
        {GAP_EXPLANATIONS.map((item) => (
          <article
            key={item.key}
            className="rounded-lg border border-line bg-surface p-4 shadow-card"
          >
            <h3 className="text-sm font-semibold text-ink">{item.title}</h3>
            <p className="mt-1 text-sm text-muted">{item.text}</p>
          </article>
        ))}
      </section>
      <p className="text-xs text-faint">
        Matched and rejected records are deliberate decisions and never appear
        here as gaps.
      </p>

      <FilterBar label="Gap filters">
        <FilterSelect
          label="Gap type"
          value={gapType}
          onChange={(v) => {
            setGapType(v);
            setPage(1);
          }}
          options={[
            { value: "", label: "All gap types" },
            { value: "never_reconciled", label: "Never reconciled" },
            { value: "unmatched", label: "Unmatched" },
            { value: "ambiguous", label: "Ambiguous" },
          ]}
        />
      </FilterBar>

      {gaps.isLoading ? (
        <Loading label="Loading correlation gaps…" />
      ) : gaps.isError ? (
        <ErrorState error={gaps.error} onRetry={() => void gaps.refetch()} />
      ) : (
        <>
          <DataTable
            columns={columns}
            rows={gaps.data!.items}
            rowKey={(r) => r.computer_id}
            caption="Directory computers without a resolved endpoint correlation"
            sort={{ field: sort, order }}
            onSort={toggleSort}
          />
          {gaps.data!.items.length === 0 && (
            <Empty message="No correlation gaps of this type — every computer is matched or deliberately rejected." />
          )}
          <Pagination
            page={page}
            pageSize={pageSize}
            total={gaps.data!.total}
            onPageChange={setPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setPage(1);
            }}
            label="correlation gaps pagination"
          />
        </>
      )}
    </div>
  );
}
