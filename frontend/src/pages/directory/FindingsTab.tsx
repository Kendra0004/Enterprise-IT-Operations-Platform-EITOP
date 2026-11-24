/**
 * Directory Insights tab (Phase 3.2.3): findings summary, paginated
 * findings table and the finding detail drawer with lifecycle actions.
 *
 * All data comes from the Phase 3.2.2 API — filtering, sorting and
 * pagination are SERVER-SIDE (never client-side over a partial page).
 * Lifecycle buttons are shown only for `directory:write` holders and only
 * for transitions the backend accepts for the current status; the backend
 * stays authoritative (403/400 surface as errors). Success is displayed
 * only after the API confirms it — no optimistic transitions.
 */

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Ban, Check, RotateCcw, X } from "lucide-react";
import {
  useFinding,
  useFindingSummary,
  useFindingTransition,
  useFindings,
  type Finding,
} from "../../api/directory";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { DataTable, type Column } from "../../components/DataTable";
import { FilterBar, FilterSelect } from "../../components/FilterBar";
import { Pagination } from "../../components/Pagination";
import { StatCard } from "../../components/StatCard";
import { Empty, ErrorState, Loading } from "../../components/states";
import { formatUtcShort, formatUtc } from "../../utils/datetime";
import {
  EvidenceBlock,
  FindingStatusBadge,
  SeverityBadge,
  VisibilityBadge,
  apiErrorMessage,
  humanize,
} from "./shared";

// --- Filter option catalogs (mirror the backend enums) -----------------------

const SUBJECT_TYPES = ["user", "group", "computer", "unknown", "connection"];
const ACCESSES = ["direct", "transitive"];
const STATUSES = ["open", "acknowledged", "suppressed", "resolved"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const RULE_KEYS = [
  "privileged.direct_member",
  "privileged.transitive_member",
  "privileged.unknown_member",
  "privileged.disabled_member",
  "privileged.distribution_member_anomaly",
  "computer.disabled_persist",
  "computer.missing_after_grace",
  "user.inactive",
  "user.no_logon_data",
  "computer.stale",
  "connection.sync_freshness",
  "connection.inventory_empty",
];

const all = (label: string) => ({ value: "", label: `All ${label}` });
const opts = (values: string[]) =>
  values.map((v) => ({ value: v, label: humanize(v) }));

// Which transitions the backend accepts, per current status.
const canSuppress = (status: string) => status === "open" || status === "acknowledged";
const canReopen = (status: string) =>
  status === "acknowledged" || status === "suppressed" || status === "resolved";

// --- Tab root ----------------------------------------------------------------

export function FindingsTab({
  connectionId,
  canWrite,
}: {
  connectionId: string;
  canWrite: boolean;
}) {
  const [subjectType, setSubjectType] = useState("");
  const [access, setAccess] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [ruleKey, setRuleKey] = useState("");
  const [sort, setSort] = useState("updated_at");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const params = useMemo(
    () => ({
      connection_id: connectionId,
      subject_type: subjectType || undefined,
      access: access || undefined,
      status: status || undefined,
      severity: severity || undefined,
      rule_key: ruleKey || undefined,
      page,
      page_size: pageSize,
      sort,
      order,
    }),
    [
      connectionId,
      subjectType,
      access,
      status,
      severity,
      ruleKey,
      page,
      pageSize,
      sort,
      order,
    ],
  );
  const findings = useFindings(params);

  const hasFilters = Boolean(
    subjectType || access || status || severity || ruleKey,
  );
  function clearFilters() {
    setSubjectType("");
    setAccess("");
    setStatus("");
    setSeverity("");
    setRuleKey("");
    setPage(1);
  }
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

  const columns: Column<Finding>[] = [
    {
      key: "severity",
      header: "Severity",
      sortField: "severity",
      sortLabel: "severity",
      render: (r) => <SeverityBadge severity={r.severity} />,
    },
    {
      key: "finding",
      header: "Finding",
      sortField: "rule_key",
      sortLabel: "rule",
      render: (r) => (
        <div className="min-w-0">
          <p className="font-medium text-ink">{r.title}</p>
          <p className="font-mono text-xs text-faint">{r.rule_key}</p>
        </div>
      ),
    },
    {
      key: "subject",
      header: "Subject",
      render: (r) => (
        <div className="min-w-0">
          <p className="text-ink">{r.subject_name ?? r.subject_dn ?? "—"}</p>
          <p className="text-xs capitalize text-faint">{r.subject_type}</p>
        </div>
      ),
    },
    {
      key: "access",
      header: "Access",
      render: (r) => <span className="capitalize">{r.access ?? "—"}</span>,
    },
    {
      key: "status",
      header: "Status",
      sortField: "status",
      sortLabel: "status",
      render: (r) => <FindingStatusBadge status={r.status} />,
    },
    {
      key: "first_seen",
      header: "First seen",
      sortField: "first_seen_at",
      sortLabel: "first seen",
      render: (r) => formatUtcShort(r.first_seen_at),
    },
    {
      key: "last_seen",
      header: "Last seen",
      sortField: "last_seen_at",
      sortLabel: "last seen",
      render: (r) => formatUtcShort(r.last_seen_at),
    },
    {
      key: "details",
      header: "Details",
      render: (r) => (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setSelectedId(r.id);
          }}
          className="rounded-md border border-line px-2 py-1 text-xs text-muted transition-colors hover:bg-raised hover:text-ink"
        >
          Details
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <SummaryPanel connectionId={connectionId} />

      <FilterBar
        onClear={clearFilters}
        showClear={hasFilters}
        label="Finding filters"
      >
        <FilterSelect
          label="Subject type"
          value={subjectType}
          onChange={(v) => {
            setSubjectType(v);
            setPage(1);
          }}
          options={[all("subject types"), ...opts(SUBJECT_TYPES)]}
        />
        <FilterSelect
          label="Access"
          value={access}
          onChange={(v) => {
            setAccess(v);
            setPage(1);
          }}
          options={[all("access classes"), ...opts(ACCESSES)]}
        />
        <FilterSelect
          label="Status"
          value={status}
          onChange={(v) => {
            setStatus(v);
            setPage(1);
          }}
          options={[all("statuses"), ...opts(STATUSES)]}
        />
        <FilterSelect
          label="Severity"
          value={severity}
          onChange={(v) => {
            setSeverity(v);
            setPage(1);
          }}
          options={[all("severities"), ...opts(SEVERITIES)]}
        />
        <FilterSelect
          label="Rule"
          value={ruleKey}
          onChange={(v) => {
            setRuleKey(v);
            setPage(1);
          }}
          options={[
            all("rules"),
            ...RULE_KEYS.map((k) => ({ value: k, label: k })),
          ]}
        />
      </FilterBar>

      {findings.isLoading ? (
        <Loading label="Loading findings…" />
      ) : findings.isError ? (
        <ErrorState
          error={findings.error}
          onRetry={() => void findings.refetch()}
        />
      ) : (
        <>
          <DataTable
            columns={columns}
            rows={findings.data!.items}
            rowKey={(r) => r.id}
            caption="Directory security findings"
            sort={{ field: sort, order }}
            onSort={toggleSort}
            onRowClick={(r) => setSelectedId(r.id)}
          />
          {findings.data!.items.length === 0 && (
            <Empty
              message={
                hasFilters
                  ? "No findings match the current filters."
                  : "No findings recorded for this connection yet."
              }
            />
          )}
          <Pagination
            page={page}
            pageSize={pageSize}
            total={findings.data!.total}
            onPageChange={setPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setPage(1);
            }}
            label="findings pagination"
          />
        </>
      )}

      {selectedId && (
        <FindingDrawer
          findingId={selectedId}
          connectionId={connectionId}
          canWrite={canWrite}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

// --- Summary -----------------------------------------------------------------

function SummaryPanel({ connectionId }: { connectionId: string }) {
  const summary = useFindingSummary(connectionId);

  if (summary.isLoading) return <Loading label="Loading findings summary…" />;
  if (summary.isError) {
    return (
      <ErrorState
        inline
        error={summary.error}
        onRetry={() => void summary.refetch()}
      />
    );
  }
  const s = summary.data!;

  const severityEntries = SEVERITIES
    .filter((k) => (s.by_severity[k] ?? 0) > 0)
    .map((k) => [k, s.by_severity[k]] as [string, number]);
  const ruleEntries = Object.entries(s.by_rule).sort((a, b) => b[1] - a[1]);
  const subjectEntries = Object.entries(s.by_subject_type).sort(
    (a, b) => b[1] - a[1],
  );

  return (
    <div className="space-y-4" data-testid="findings-summary">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Open"
          value={s.open}
          tone={s.open > 0 ? "warn" : "neutral"}
          sub={`${s.total} finding(s) total`}
        />
        <StatCard label="Acknowledged" value={s.acknowledged} />
        <StatCard label="Suppressed" value={s.suppressed} />
        <StatCard
          label="Resolved"
          value={s.resolved}
          tone={s.resolved > 0 ? "ok" : "neutral"}
        />
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <Distribution title="Severity" entries={severityEntries} />
        <Distribution title="Rule" entries={ruleEntries} mono />
        <Distribution title="Subject type" entries={subjectEntries} />
      </div>

      <section
        aria-label="Privilege visibility"
        className="rounded-lg border border-line bg-surface p-4 shadow-card"
      >
        <div className="flex flex-wrap items-center gap-3">
          <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
            Privilege visibility
          </h3>
          <VisibilityBadge value={s.privilege_visibility} />
          <span className="text-xs text-faint">
            Inventory {s.inventory_complete ? "complete" : "incomplete"}
          </span>
        </div>
        {s.visibility_reasons.length > 0 && (
          <ul className="mt-2 list-inside list-disc text-sm text-muted">
            {s.visibility_reasons.map((reason) => (
              <li key={reason}>{humanize(reason)}</li>
            ))}
          </ul>
        )}
        <p className="mt-2 text-xs text-faint">
          Verdict computed by the findings engine from the newest sync run.
        </p>
      </section>
    </div>
  );
}

function Distribution({
  title,
  entries,
  mono = false,
}: {
  title: string;
  entries: [string, number][];
  mono?: boolean;
}) {
  const max = Math.max(1, ...entries.map(([, count]) => count));
  return (
    <section
      aria-label={`${title} distribution`}
      className="rounded-lg border border-line bg-surface p-4 shadow-card"
    >
      <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
        {title}
      </h3>
      {entries.length === 0 ? (
        <p className="mt-2 text-sm text-faint">None.</p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {entries.map(([key, count]) => (
            <li key={key} className="flex items-center gap-2 text-sm">
              <span
                className={`w-44 truncate text-muted ${mono ? "font-mono text-xs" : "capitalize"}`}
                title={key}
              >
                {mono ? key : humanize(key)}
              </span>
              <span className="h-2 flex-1 overflow-hidden rounded bg-raised">
                <span
                  aria-hidden
                  className="block h-full rounded bg-accent/70"
                  style={{ width: `${Math.round((count / max) * 100)}%` }}
                />
              </span>
              <span className="tabular-nums text-ink">{count}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// --- Detail drawer ------------------------------------------------------------

function FindingDrawer({
  findingId,
  connectionId,
  canWrite,
  onClose,
}: {
  findingId: string;
  connectionId: string;
  canWrite: boolean;
  onClose: () => void;
}) {
  const detail = useFinding(findingId, connectionId);
  const transition = useFindingTransition();
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionOk, setActionOk] = useState<string | null>(null);
  const [confirmSuppress, setConfirmSuppress] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
  }, [findingId]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  /** Runs one transition; resolves true only after the API confirms it. */
  async function run(
    action: "ack" | "suppress" | "reopen",
  ): Promise<boolean> {
    if (transition.isPending) return false;
    setActionError(null);
    setActionOk(null);
    try {
      await transition.mutateAsync({ id: findingId, connectionId, action });
      setActionOk(
        action === "ack"
          ? "Finding acknowledged."
          : action === "suppress"
            ? "Finding suppressed."
            : "Finding reopened.",
      );
      return true;
    } catch (err) {
      setActionError(apiErrorMessage(err));
      return false;
    }
  }

  const finding = detail.data;
  const status = finding?.status ?? "";

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/40"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-drawer-title"
        className="h-full w-full max-w-xl overflow-y-auto border-l border-line bg-overlay p-5 shadow-pop"
      >
        <div className="flex items-start justify-between gap-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-faint">
            Finding details
          </p>
          <button
            ref={closeRef}
            type="button"
            aria-label="Close finding details"
            onClick={onClose}
            className="rounded-md border border-line px-2 py-1 text-muted transition-colors hover:bg-raised hover:text-ink"
          >
            <X size={14} aria-hidden />
          </button>
        </div>

        {detail.isLoading && <div className="mt-4"><Loading label="Loading finding…" /></div>}
        {detail.isError && (
          <div className="mt-4">
            <ErrorState
              inline
              error={detail.error}
              onRetry={() => void detail.refetch()}
            />
          </div>
        )}

        {finding && (
          <div className="mt-3 space-y-4">
            <div>
              <h2
                id="finding-drawer-title"
                className="text-lg font-semibold text-ink"
              >
                {finding.title}
              </h2>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <FindingStatusBadge status={finding.status} />
                <span className="font-mono text-xs text-faint">
                  {finding.rule_key}
                </span>
                {finding.access && (
                  <span className="rounded-full bg-raised px-2 py-0.5 text-xs capitalize text-muted ring-1 ring-inset ring-line-strong">
                    {finding.access} access
                  </span>
                )}
              </div>
            </div>

            {actionOk && (
              <p
                role="status"
                className="rounded-md bg-ok/10 p-2 text-sm text-ok"
              >
                {actionOk}
              </p>
            )}
            {actionError && (
              <p
                role="alert"
                className="rounded-md border border-danger/40 bg-danger/10 p-2 text-sm text-danger"
              >
                {actionError}
              </p>
            )}

            <section aria-label="Subject" className="rounded-lg border border-line bg-surface p-4">
              <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
                Subject
              </h3>
              <dl className="mt-2 space-y-1 text-sm">
                <Row label="Type" value={<span className="capitalize">{finding.subject_type}</span>} />
                <Row label="Name" value={finding.subject_name ?? "—"} />
                <Row label="Distinguished name" value={<span className="break-all">{finding.subject_dn ?? "—"}</span>} />
                <Row label="Object GUID" value={<span className="break-all">{finding.subject_guid ?? "—"}</span>} />
              </dl>
            </section>

            <section aria-label="Lifecycle" className="rounded-lg border border-line bg-surface p-4">
              <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
                Lifecycle
              </h3>
              <dl className="mt-2 space-y-1 text-sm">
                <Row label="First seen" value={formatUtc(finding.first_seen_at)} />
                <Row label="Last seen" value={formatUtc(finding.last_seen_at)} />
                <Row
                  label="Acknowledged"
                  value={
                    finding.acknowledged_at
                      ? `${formatUtc(finding.acknowledged_at)}${
                          finding.acknowledged_by
                            ? ` · by ${finding.acknowledged_by}`
                            : ""
                        }`
                      : "—"
                  }
                />
                <Row
                  label="Suppressed"
                  value={
                    finding.suppressed_at ? formatUtc(finding.suppressed_at) : "—"
                  }
                />
                <Row
                  label="Resolved"
                  value={
                    finding.resolved_at ? formatUtc(finding.resolved_at) : "—"
                  }
                />
                <Row label="Reopen count" value={String(finding.reopen_count)} />
              </dl>
            </section>

            <section aria-label="Evidence" className="rounded-lg border border-line bg-surface p-4">
              <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
                Evidence
              </h3>
              <div className="mt-2">
                <EvidenceBlock detail={finding.detail} />
              </div>
            </section>

            <section aria-label="Actions" className="rounded-lg border border-line bg-surface p-4">
              <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">
                Actions
              </h3>
              {!canWrite ? (
                <p className="mt-2 text-sm text-muted">
                  Lifecycle actions require the directory:write permission.
                </p>
              ) : (
                <div className="mt-3 flex flex-wrap gap-2">
                  {status === "open" && (
                    <ActionButton
                      label="Acknowledge"
                      icon={Check}
                      busy={transition.isPending}
                      onClick={() => void run("ack")}
                    />
                  )}
                  {canSuppress(status) && (
                    <ActionButton
                      label="Suppress…"
                      icon={Ban}
                      busy={transition.isPending}
                      onClick={() => setConfirmSuppress(true)}
                    />
                  )}
                  {canReopen(status) && (
                    <ActionButton
                      label="Reopen"
                      icon={RotateCcw}
                      busy={transition.isPending}
                      onClick={() => void run("reopen")}
                    />
                  )}
                </div>
              )}
            </section>
          </div>
        )}

        <ConfirmDialog
          open={confirmSuppress}
          title="Suppress this finding?"
          description={
            <>
              The finding moves to <strong>suppressed</strong> and future syncs
              stop updating it. The transition is recorded in the audit log
              with your account as actor.
            </>
          }
          confirmLabel="Suppress"
          busy={transition.isPending}
          onConfirm={() => {
            void run("suppress").then(() => setConfirmSuppress(false));
          }}
          onCancel={() => setConfirmSuppress(false)}
        />
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt className="inline text-faint">{label}: </dt>
      <dd className="inline text-muted">{value}</dd>
    </div>
  );
}

function ActionButton({
  label,
  icon: Icon,
  busy,
  onClick,
}: {
  label: string;
  icon: typeof Check;
  busy: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={busy}
      onClick={onClick}
      className="flex items-center gap-1 rounded-md border border-line px-3 py-1.5 text-sm text-muted transition-colors hover:bg-raised hover:text-ink disabled:cursor-not-allowed disabled:opacity-50"
    >
      <Icon size={13} aria-hidden />
      {label}
    </button>
  );
}
