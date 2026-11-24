/**
 * Active Directory (Phase 3.1, extended 3.2.3): one page with in-page
 * tabs — Overview · Connections · Users · Groups · Computers · OUs ·
 * Insights · Health · Correlation Gaps · Sync History.
 *
 * Everything rendered here is read-only mirrored directory data plus the
 * connection lifecycle actions. Writes are gated on `directory:write` /
 * `directory:sync` client-side for affordance only — the backend enforces
 * the same matrix independently (403), and the bind password is entered
 * here but never displayed (the API never returns it).
 */

import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  FileSearch,
  History,
  Monitor,
  Network,
  RefreshCw,
  Server,
  ShieldCheck,
  TestTube2,
  Trash2,
  Users,
} from "lucide-react";
import {
  useCreateConnection,
  useDeleteConnection,
  useDirectoryComputers,
  useDirectoryConnections,
  useDirectoryGroups,
  useDirectoryOverview,
  useDirectoryUsers,
  useDomains,
  useOus,
  useSyncRuns,
  useTestConnection,
  useTriggerSync,
  type ConnectionCreate,
  type DirectoryComputerRow,
  type DirectoryGroupRow,
  type DirectoryUserRow,
  type ObjectListParams,
  type OuRow,
} from "../api/directory";
import { useAuth } from "../auth/AuthContext";
import { PageHeader } from "../components/PageHeader";
import { FindingsTab } from "./directory/FindingsTab";
import { GapsTab } from "./directory/GapsTab";
import { HealthTab } from "./directory/HealthTab";
import { SectionNav } from "../components/SectionNav";
import { SearchInput } from "../components/SearchInput";
import { StatCard } from "../components/StatCard";
import { DataTable, type Column } from "../components/DataTable";
import { Empty, ErrorState, Loading } from "../components/states";
import { formatUtcShort } from "../utils/datetime";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "connections", label: "Connections" },
  { id: "users", label: "Users" },
  { id: "groups", label: "Groups" },
  { id: "computers", label: "Computers" },
  { id: "ous", label: "OUs" },
  { id: "insights", label: "Insights" },
  { id: "health", label: "Health" },
  { id: "gaps", label: "Correlation Gaps" },
  { id: "history", label: "Sync History" },
];

export function DirectoryPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = searchParams.get("tab") ?? "overview";
  const { hasPermission } = useAuth();
  const canRead = hasPermission("directory:read");
  const canWrite = hasPermission("directory:write");
  const canSync = hasPermission("directory:sync");

  const connections = useDirectoryConnections();
  const [selectedId, setSelectedId] = useState<string>(
    () => searchParams.get("connection") ?? "",
  );
  const activeId = selectedId || connections.data?.items[0]?.id || "";

  if (!canRead) {
    return (
      <div className="space-y-5">
        <PageHeader title="Active Directory" />
        <p
          role="alert"
          className="rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger"
        >
          Missing permission(s): directory:read
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-5" data-testid="directory-page">
      <PageHeader
        title="Active Directory"
        description="Read-only mirror of Active Directory: connections, directory objects, memberships and sync history. No write path touches the directory itself."
        actions={<ConnectionPicker
          connections={connections.data?.items ?? []}
          value={activeId}
          onChange={setSelectedId}
        />}
      />

      <SectionNav
        sections={TABS}
        active={tab}
        onSelect={(id) =>
          setSearchParams(
            activeId ? { tab: id, connection: activeId } : { tab: id },
          )
        }
        label="Directory sections"
      />

      {/* Sections need a resolved connection id; while the connections
          query loads (or fails) show the honest state instead of flashing
          "No directory connection configured yet". */}
      {connections.isLoading ? (
        <Loading label="Loading directory connection…" />
      ) : connections.isError ? (
        <ErrorState
          error={connections.error}
          onRetry={() => void connections.refetch()}
        />
      ) : (
        <>
          {tab === "overview" && <OverviewSection />}
          {tab === "connections" && <ConnectionsSection canWrite={canWrite} canSync={canSync} />}
          {tab === "users" && <UsersSection connectionId={activeId} />}
          {tab === "groups" && <GroupsSection connectionId={activeId} />}
          {tab === "computers" && <ComputersSection connectionId={activeId} />}
          {tab === "ous" && <OusSection connectionId={activeId} />}
          {tab === "insights" && (
            <FindingsTab connectionId={activeId} canWrite={canWrite} />
          )}
          {tab === "health" && <HealthTab connectionId={activeId} />}
          {tab === "gaps" && <GapsTab connectionId={activeId} />}
          {tab === "history" && <HistorySection connectionId={activeId} />}
        </>
      )}
    </div>
  );
}

function ConnectionPicker({
  connections,
  value,
  onChange,
}: {
  connections: { id: string; name: string }[];
  value: string;
  onChange: (id: string) => void;
}) {
  if (connections.length === 0) return null;
  return (
    <label className="flex flex-col gap-1 text-xs text-muted">
      Connection
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
      >
        {connections.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name}
          </option>
        ))}
      </select>
    </label>
  );
}

function NeedsConnection() {
  return <Empty message="No directory connection configured yet — add one in Connections." />;
}

// --- Overview ----------------------------------------------------------------

function OverviewSection() {
  const overview = useDirectoryOverview();
  if (overview.isLoading) return <Loading label="Loading directory overview…" />;
  if (overview.isError) {
    return <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />;
  }
  const o = overview.data!;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Connections" value={o.connections_total} icon={Server} sub={`${o.connections_enabled} enabled`} />
        <StatCard label="Domains" value={o.domains} icon={Network} />
        <StatCard label="Users" value={o.users_total} icon={Users} sub={`${o.users_enabled} enabled · ${o.users_disabled} disabled`} />
        <StatCard label="Groups" value={o.groups} icon={ShieldCheck} />
        <StatCard label="Computers" value={o.computers} icon={Monitor} />
        <StatCard label="Missing objects" value={o.missing_objects} icon={FileSearch} />
        <StatCard
          label="Needs review"
          value={o.reconciliation_needs_review}
          icon={TestTube2}
          tone={o.reconciliation_needs_review > 0 ? "warn" : "neutral"}
          sub={`${o.reconciliation_matched} matched · ${o.reconciliation_unmatched} unmatched`}
        />
        <StatCard
          label="Failed runs (24h)"
          value={o.failed_runs_24h}
          icon={History}
          tone={o.failed_runs_24h > 0 ? "danger" : "ok"}
          sub={o.running_syncs > 0 ? `${o.running_syncs} running` : "idle"}
        />
      </div>
      <p className="text-xs text-faint">
        Last successful sync:{" "}
        {o.last_sync_success_at ? formatUtcShort(o.last_sync_success_at) : "never"}
        {o.last_sync_failure_at && (
          <> · Last failure: {formatUtcShort(o.last_sync_failure_at)}</>
        )}
      </p>
    </div>
  );
}

// --- Connections ---------------------------------------------------------------

function ConnectionsSection({ canWrite, canSync }: { canWrite: boolean; canSync: boolean }) {
  const connections = useDirectoryConnections();
  const [showForm, setShowForm] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ id: string; name: string } | null>(null);

  const create = useCreateConnection();
  const remove = useDeleteConnection();
  const test = useTestConnection();
  const trigger = useTriggerSync();

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    const form = new FormData(e.currentTarget);
    const payload: ConnectionCreate = {
      name: String(form.get("name") ?? ""),
      domain_dns: String(form.get("domain_dns") ?? ""),
      host: String(form.get("host") ?? ""),
      port: Number(form.get("port") || 636),
      tls_mode: form.get("tls_mode") === "starttls" ? "starttls" : "ldaps",
      tls_ca_pem: String(form.get("tls_ca_pem") ?? "").trim() || null,
      search_base: String(form.get("search_base") ?? ""),
      bind_username: String(form.get("bind_username") ?? ""),
      // Write-only field: sent once, never echoed back by the API.
      bind_password: String(form.get("bind_password") ?? ""),
      auto_sync: form.get("auto_sync") === "on",
    };
    try {
      await create.mutateAsync(payload);
      setShowForm(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not create connection.");
    }
  }

  async function runTest(id: string) {
    setTestResult(null);
    try {
      const res = await test.mutateAsync(id);
      setTestResult({ id, ok: res.ok, message: res.message ?? res.label ?? "Unknown result" });
    } catch (err) {
      setTestResult({ id, ok: false, message: err instanceof Error ? err.message : "Test failed." });
    }
  }

  async function runSync(id: string) {
    setTestResult(null);
    try {
      await trigger.mutateAsync(id);
    } catch (err) {
      setTestResult({ id, ok: false, message: err instanceof Error ? err.message : "Sync could not be queued." });
    }
  }

  if (connections.isLoading) return <Loading label="Loading connections…" />;
  if (connections.isError) {
    return <ErrorState error={connections.error} onRetry={() => void connections.refetch()} />;
  }

  const rows = connections.data?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted">
          {rows.length} connection(s). TLS validation is always on — there is no plaintext mode.
        </p>
        {canWrite && (
          <button
            type="button"
            onClick={() => setShowForm((v) => !v)}
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
          >
            {showForm ? "Cancel" : "Add connection"}
          </button>
        )}
      </div>

      {formError && (
        <p role="alert" className="rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
          {formError}
        </p>
      )}

      {showForm && canWrite && (
        <section aria-label="New connection" className="rounded-lg border border-line bg-surface p-4 shadow-card">
          <form className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" onSubmit={submit}>
            <Field label="Name" name="name" required />
            <Field label="Domain (DNS)" name="domain_dns" required />
            <Field label="DC host" name="host" required />
            <Field label="Port" name="port" type="number" defaultValue={636} />
            <label className="flex flex-col gap-1 text-xs text-muted">
              TLS mode
              <select
                name="tls_mode"
                defaultValue="ldaps"
                className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
              >
                <option value="ldaps">LDAPS (636)</option>
                <option value="starttls">StartTLS (389 → encrypted)</option>
              </select>
            </label>
            <Field label="Search base (DN)" name="search_base" required />
            <Field label="Bind username (DN)" name="bind_username" required />
            <label className="flex flex-col gap-1 text-xs text-muted">
              Bind password
              <input
                name="bind_password"
                type="password"
                required
                autoComplete="new-password"
                className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-muted sm:col-span-2">
              CA certificate (PEM, optional — system roots used when empty)
              <textarea
                name="tls_ca_pem"
                rows={3}
                className="rounded-md border border-line-strong bg-surface px-2 py-1.5 font-mono text-xs text-ink"
              />
            </label>
            <label className="flex items-center gap-2 text-sm text-muted">
              <input name="auto_sync" type="checkbox" defaultChecked />
              Scheduled sync
            </label>
            <div className="sm:col-span-2 lg:col-span-3">
              <button
                type="submit"
                disabled={create.isPending}
                className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
              >
                {create.isPending ? "Creating…" : "Create connection"}
              </button>
            </div>
          </form>
        </section>
      )}

      {rows.length === 0 ? (
        <Empty message="No directory connections yet." />
      ) : (
        <ul className="divide-y divide-line rounded-lg border border-line bg-surface shadow-card">
          {rows.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
              <div className="min-w-0">
                <p className="text-sm font-medium text-ink">
                  {c.name} <span className="text-faint">· {c.host}:{c.port}</span>
                </p>
                <p className="text-xs text-muted">
                  {c.domain_dns} · {String(c.tls_mode).toUpperCase()} · {c.search_base}
                </p>
                <p className="text-xs text-faint">
                  Last run: {c.last_run_status ?? "never"}
                  {c.last_success_at && <> · success {formatUtcShort(c.last_success_at)}</>}
                  {c.auto_sync && <> · every {c.sync_interval_minutes} min</>}
                  {!c.enabled && " · disabled"}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <ActionButton
                  label="Test"
                  icon={TestTube2}
                  disabled={!canSync}
                  busy={test.isPending && test.variables === c.id}
                  onClick={() => void runTest(c.id)}
                />
                <ActionButton
                  label="Sync now"
                  icon={RefreshCw}
                  disabled={!canSync}
                  busy={trigger.isPending && trigger.variables === c.id}
                  onClick={() => void runSync(c.id)}
                />
                {canWrite && (
                  <button
                    type="button"
                    aria-label={`Delete connection ${c.name}`}
                    onClick={() => setConfirmDelete({ id: c.id, name: c.name })}
                    className="flex items-center gap-1 rounded-md border border-danger/50 px-2 py-1 text-xs text-danger transition-colors hover:bg-danger/10"
                  >
                    <Trash2 size={12} aria-hidden />
                    Delete
                  </button>
                )}
              </div>
              {testResult?.id === c.id && (
                <p
                  role="status"
                  className={`w-full rounded-md p-2 text-xs ${
                    testResult.ok ? "bg-ok/10 text-ok" : "bg-warn/10 text-warn"
                  }`}
                >
                  {testResult.message}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}

      {confirmDelete && (
        <div
          role="dialog"
          aria-label="Delete connection"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
        >
          <div className="w-full max-w-md rounded-lg border border-line bg-surface p-4 shadow-card">
            <h3 className="text-base font-semibold text-ink">Delete connection?</h3>
            <p className="mt-2 text-sm text-muted">
              Removes <strong>{confirmDelete.name}</strong> and its mirrored directory data.
              Nothing in Active Directory is affected.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmDelete(null)}
                className="rounded-md border border-line px-3 py-1.5 text-sm text-muted hover:bg-raised"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={remove.isPending}
                onClick={async () => {
                  await remove.mutateAsync(confirmDelete.id).catch(() => undefined);
                  setConfirmDelete(null);
                }}
                className="rounded-md bg-danger px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  name,
  type = "text",
  required,
  defaultValue,
}: {
  label: string;
  name: string;
  type?: string;
  required?: boolean;
  defaultValue?: string | number;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted">
      {label}
      <input
        name={name}
        type={type}
        required={required}
        defaultValue={defaultValue}
        className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
      />
    </label>
  );
}

function ActionButton({
  label,
  icon: Icon,
  disabled,
  busy,
  onClick,
}: {
  label: string;
  icon: typeof RefreshCw;
  disabled?: boolean;
  busy?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled || busy}
      onClick={onClick}
      title={disabled ? "Missing directory:sync permission" : undefined}
      className="flex items-center gap-1 rounded-md border border-line px-2 py-1 text-xs text-muted transition-colors hover:bg-raised hover:text-ink disabled:cursor-not-allowed disabled:opacity-40"
    >
      <Icon size={12} aria-hidden />
      {busy ? "…" : label}
    </button>
  );
}

// --- Object tabs ---------------------------------------------------------------

/** Shared list state for the object tabs (hooks run unconditionally). */
function useObjectList(connectionId: string) {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const params: ObjectListParams = useMemo(
    () => ({ connection_id: connectionId, page, page_size: 50, q: q || undefined }),
    [connectionId, page, q],
  );
  return { q, setQ, page, setPage, params };
}

function SearchRow({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <SearchInput
      label={label}
      value={value}
      onSearch={onChange}
      placeholder={`${label.toLowerCase()}…`}
    />
  );
}

function TotalLine({ total, noun }: { total: number; noun: string }) {
  return <p className="text-xs text-faint">{total} {noun}(s)</p>;
}

function UsersSection({ connectionId }: { connectionId: string }) {
  const { q, setQ, setPage, params } = useObjectList(connectionId);
  const users = useDirectoryUsers(params);

  if (!connectionId) return <NeedsConnection />;
  if (users.isLoading) return <Loading label="Loading users…" />;
  if (users.isError) return <ErrorState error={users.error} onRetry={() => void users.refetch()} />;

  const columns: Column<DirectoryUserRow>[] = [
    { key: "sam", header: "sAMAccountName", render: (r) => r.sam_account_name },
    { key: "name", header: "Display name", render: (r) => r.display_name ?? "—" },
    { key: "email", header: "Email", render: (r) => r.email ?? "—" },
    { key: "dept", header: "Department", render: (r) => r.department ?? "—" },
    {
      key: "enabled",
      header: "Enabled",
      render: (r) => (r.enabled === null ? "—" : r.enabled ? "Yes" : "No"),
    },
    { key: "state", header: "State", render: (r) => (r.missing_since ? "Missing" : "Present") },
    { key: "logon", header: "Last logon", render: (r) => formatUtcShort(r.last_logon_at) },
  ];
  return (
    <div className="space-y-3">
      <SearchRow label="Search users" value={q} onChange={(v) => { setQ(v); setPage(1); }} />
      <DataTable columns={columns} rows={users.data!.items} rowKey={(r) => r.id} caption="Directory users" />
      <TotalLine total={users.data!.total} noun="user" />
    </div>
  );
}

function GroupsSection({ connectionId }: { connectionId: string }) {
  const { q, setQ, setPage, params } = useObjectList(connectionId);
  const groups = useDirectoryGroups(params);

  if (!connectionId) return <NeedsConnection />;
  if (groups.isLoading) return <Loading label="Loading groups…" />;
  if (groups.isError) return <ErrorState error={groups.error} onRetry={() => void groups.refetch()} />;

  const columns: Column<DirectoryGroupRow>[] = [
    { key: "name", header: "Name", render: (r) => r.name },
    { key: "scope", header: "Scope", render: (r) => r.scope ?? "—" },
    { key: "category", header: "Category", render: (r) => r.category ?? "—" },
    { key: "dn", header: "Distinguished name", render: (r) => r.distinguished_name },
    { key: "state", header: "State", render: (r) => (r.missing_since ? "Missing" : "Present") },
  ];
  return (
    <div className="space-y-3">
      <SearchRow label="Search groups" value={q} onChange={(v) => { setQ(v); setPage(1); }} />
      <DataTable columns={columns} rows={groups.data!.items} rowKey={(r) => r.id} caption="Directory groups" />
      <TotalLine total={groups.data!.total} noun="group" />
    </div>
  );
}

function ComputersSection({ connectionId }: { connectionId: string }) {
  const { q, setQ, setPage, params } = useObjectList(connectionId);
  const computers = useDirectoryComputers(params);

  if (!connectionId) return <NeedsConnection />;
  if (computers.isLoading) return <Loading label="Loading computers…" />;
  if (computers.isError) {
    return <ErrorState error={computers.error} onRetry={() => void computers.refetch()} />;
  }

  const columns: Column<DirectoryComputerRow>[] = [
    { key: "name", header: "Name", render: (r) => r.name },
    { key: "fqdn", header: "DNS hostname", render: (r) => r.dns_hostname ?? "—" },
    {
      key: "os",
      header: "OS",
      render: (r) => (r.os ? `${r.os} ${r.os_version ?? ""}`.trim() : "—"),
    },
    { key: "recon", header: "Reconciliation", render: (r) => r.recon_status ?? "unmatched" },
    { key: "state", header: "State", render: (r) => (r.missing_since ? "Missing" : "Present") },
  ];
  return (
    <div className="space-y-3">
      <SearchRow label="Search computers" value={q} onChange={(v) => { setQ(v); setPage(1); }} />
      <DataTable columns={columns} rows={computers.data!.items} rowKey={(r) => r.id} caption="Directory computers" />
      <TotalLine total={computers.data!.total} noun="computer" />
    </div>
  );
}

function OusSection({ connectionId }: { connectionId: string }) {
  const { q, setQ, setPage, params } = useObjectList(connectionId);
  const ous = useOus(params);

  if (!connectionId) return <NeedsConnection />;
  if (ous.isLoading) return <Loading label="Loading OUs…" />;
  if (ous.isError) return <ErrorState error={ous.error} onRetry={() => void ous.refetch()} />;

  const columns: Column<OuRow>[] = [
    { key: "name", header: "Name", render: (r) => r.name },
    { key: "dn", header: "Distinguished name", render: (r) => r.distinguished_name },
    { key: "state", header: "State", render: (r) => (r.missing_since ? "Missing" : "Present") },
  ];
  return (
    <div className="space-y-3">
      <SearchRow label="Search OUs" value={q} onChange={(v) => { setQ(v); setPage(1); }} />
      <DataTable columns={columns} rows={ous.data!.items} rowKey={(r) => r.id} caption="Organizational units" />
      <TotalLine total={ous.data!.total} noun="OU" />
    </div>
  );
}

// --- Sync history ---------------------------------------------------------------

function HistorySection({ connectionId }: { connectionId: string }) {
  const runs = useSyncRuns({ connection_id: connectionId || undefined, page_size: 50 });
  const domains = useDomains({ connection_id: connectionId, page_size: 1 });

  if (!connectionId) return <NeedsConnection />;
  if (runs.isLoading) return <Loading label="Loading sync history…" />;
  if (runs.isError) return <ErrorState error={runs.error} onRetry={() => void runs.refetch()} />;

  const rows = runs.data?.items ?? [];
  const columns: Column<(typeof rows)[0]>[] = [
    { key: "started", header: "Started", render: (r) => formatUtcShort(r.started_at) },
    { key: "status", header: "Status", render: (r) => r.status },
    { key: "trigger", header: "Trigger", render: (r) => r.trigger },
    { key: "found", header: "Discovered", render: (r) => String(r.objects_discovered) },
    { key: "created", header: "Created", render: (r) => String(r.objects_created) },
    { key: "updated", header: "Updated", render: (r) => String(r.objects_updated) },
    { key: "missing", header: "Marked missing", render: (r) => String(r.objects_marked_missing) },
    { key: "duration", header: "Duration", render: (r) => (r.duration_ms ? `${r.duration_ms} ms` : "—") },
  ];

  return (
    <div className="space-y-3">
      {domains.isError && <ErrorState inline error={domains.error} />}
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} caption="Directory sync runs" />
      {rows.length === 0 && <Empty message="No sync runs yet." />}
      <p className="text-xs text-faint">
        Errors are stored as fixed labels (for example <code>timeout</code>,{" "}
        <code>invalid_credentials</code>) — never raw exception text or credentials.
      </p>
    </div>
  );
}
