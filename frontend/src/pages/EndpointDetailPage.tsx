/**
 * Endpoint detail (Phases 2.5–2.8): identity, OS, hardware, network,
 * software, activity/health, group membership and the management actions
 * (revoke, rotate) gated by RBAC. Sections stay mounted — the section nav
 * scrolls rather than hides, so deep links and tests see everything.
 */

import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Activity,
  Cpu,
  Fingerprint,
  HardDrive,
  History,
  KeyRound,
  Network,
  Package,
  Power,
  ShieldCheck,
} from "lucide-react";
import {
  useAddGroupMember,
  useEndpoint,
  useEndpointActivity,
  useEndpointHealth,
  useEndpointSoftware,
  useGroups,
  useRemoveGroupMember,
  useRevokeEndpoint,
  useRotateCredential,
} from "../api/endpoints";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ActivityList } from "../components/ActivityList";
import { ErrorState, Loading, Empty } from "../components/states";
import { PageHeader } from "../components/PageHeader";
import { SectionNav } from "../components/SectionNav";
import { StatusBadge } from "../components/StatusBadge";
import { useAuth } from "../auth/AuthContext";
import { ageLabel, formatBytes, formatUtc } from "../utils/datetime";

const SECTIONS = [
  { id: "overview", label: "Overview" },
  { id: "hardware", label: "Hardware" },
  { id: "software", label: "Software" },
  { id: "network", label: "Network" },
  { id: "activity", label: "Activity & health" },
];

export function EndpointDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const canWrite = hasPermission("endpoints:write");

  const detail = useEndpoint(id);
  const health = useEndpointHealth(id);
  const groups = useGroups();
  const activity = useEndpointActivity({
    enabled: hasPermission("audit:read"),
    target: id,
    limit: 10,
  });

  const [activeSection, setActiveSection] = useState("overview");
  const [confirm, setConfirm] = useState<"revoke" | "rotate" | null>(null);
  const [rotatedCredential, setRotatedCredential] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [assignGroup, setAssignGroup] = useState("");

  const revoke = useRevokeEndpoint();
  const rotate = useRotateCredential();
  const addMember = useAddGroupMember();
  const removeMember = useRemoveGroupMember();

  const ep = detail.data;
  const meta = ep?.metadata ?? null;

  if (detail.isLoading || health.isLoading) return <Loading label="Loading endpoint…" />;
  if (detail.isError) {
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  }
  if (!ep) return <Empty message="Endpoint not found." />;

  const notInGroups = (groups.data ?? []).filter((g) => !ep.groups.includes(g.name));

  function scrollTo(sectionId: string) {
    setActiveSection(sectionId);
    document.getElementById(`section-${sectionId}`)?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }

  async function runRevoke() {
    if (!id) return;
    setActionError(null);
    try {
      await revoke.mutateAsync(id);
      setConfirm(null);
      await detail.refetch();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Revocation failed.");
      setConfirm(null);
    }
  }

  async function runRotate() {
    if (!id) return;
    setActionError(null);
    try {
      const res = await rotate.mutateAsync(id);
      setRotatedCredential(res.credential);
      setConfirm(null);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Rotation failed.");
      setConfirm(null);
    }
  }

  async function assign() {
    if (!id || !assignGroup) return;
    setActionError(null);
    try {
      await addMember.mutateAsync({ endpointId: id, groupId: assignGroup });
      setAssignGroup("");
      await detail.refetch();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Could not assign group.");
    }
  }

  async function unassign(groupId: string) {
    if (!id) return;
    setActionError(null);
    try {
      await removeMember.mutateAsync({ endpointId: id, groupId });
      await detail.refetch();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Could not remove group.");
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title={ep.hostname}
        description={`${ep.fqdn ?? "No FQDN"} · ${ep.os} ${ep.os_version ?? ""} · agent ${ep.agent_version ?? "unknown"}`}
        actions={
          <>
            <Link
              to={`/endpoints/${ep.id}/history`}
              className="flex items-center gap-1.5 rounded-md border border-line px-3 py-1.5 text-sm text-muted transition-colors hover:bg-raised hover:text-ink"
            >
              <History size={14} aria-hidden />
              Inventory history
            </Link>
            {canWrite && (
              <>
                <button
                  type="button"
                  onClick={() => setConfirm("rotate")}
                  className="flex items-center gap-1.5 rounded-md border border-line px-3 py-1.5 text-sm text-muted transition-colors hover:bg-raised hover:text-ink"
                >
                  <KeyRound size={14} aria-hidden />
                  Rotate credential
                </button>
                <button
                  type="button"
                  onClick={() => setConfirm("revoke")}
                  disabled={ep.status === "revoked"}
                  className="flex items-center gap-1.5 rounded-md bg-danger px-3 py-1.5 text-sm font-medium text-accent-contrast transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Power size={14} aria-hidden />
                  Revoke endpoint
                </button>
              </>
            )}
          </>
        }
      />

      {actionError && (
        <p
          role="alert"
          className="rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger"
        >
          {actionError}
        </p>
      )}

      {rotatedCredential && (
        <section
          aria-label="New credential"
          className="rounded-lg border border-warn/40 bg-warn/10 p-4 text-sm"
        >
          <p className="font-medium text-warn">
            New credential — shown exactly once. Update the agent now.
          </p>
          <code className="mt-2 block break-all rounded bg-canvas p-2 font-mono text-xs text-ink">
            {rotatedCredential}
          </code>
          <button
            type="button"
            onClick={() => setRotatedCredential(null)}
            className="mt-2 rounded-md border border-warn/60 px-3 py-1 text-warn hover:bg-warn/10"
          >
            Dismiss
          </button>
        </section>
      )}

      {/* --- Health strip --- */}
      <section
        aria-label="Endpoint health"
        className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"
      >
        <InfoCard label="Lifecycle status">
          <span className="flex items-center gap-2">
            <StatusBadge status={ep.status} />
            <span className="text-xs text-faint">
              {health.data?.collector_status ?? "—"}
            </span>
          </span>
        </InfoCard>
        <InfoCard label="Last heartbeat">
          {formatUtc(ep.last_heartbeat_at)}
          {ep.last_heartbeat_at && (
            <span className="ml-2 text-xs text-faint">
              {ageLabel(ep.last_heartbeat_at)} ago
            </span>
          )}
        </InfoCard>
        <InfoCard label="Last inventory">{formatUtc(ep.last_inventory_at)}</InfoCard>
        <InfoCard label="Enrolled">{formatUtc(ep.enrolled_at)}</InfoCard>
      </section>

      {health.data && (
        <p className="text-xs text-faint">
          Expected heartbeat every {health.data.heartbeat_interval_seconds}s ·
          offline after {health.data.offline_threshold_seconds}s · server time{" "}
          {formatUtc(health.data.server_time)}
        </p>
      )}

      {/* --- Section nav --- */}
      <SectionNav
        sections={SECTIONS}
        active={activeSection}
        onSelect={scrollTo}
      />

      {/* --- Overview --- */}
      <section
        id="section-overview"
        aria-label="Overview"
        className="grid gap-3 lg:grid-cols-2"
        style={{ scrollMarginTop: "1rem" }}
      >
        <Card title="Identity" icon={<Fingerprint size={14} aria-hidden />}>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <Dt>Hostname</Dt>
            <Dd>{ep.hostname}</Dd>
            <Dt>FQDN</Dt>
            <Dd>{ep.fqdn ?? "—"}</Dd>
            <Dt>Endpoint ID</Dt>
            <Dd className="break-all font-mono text-xs">{ep.id}</Dd>
            <Dt>Groups</Dt>
            <Dd>{ep.groups.length > 0 ? ep.groups.join(", ") : "—"}</Dd>
          </dl>
        </Card>

        <Card title="Operating system" icon={<ShieldCheck size={14} aria-hidden />}>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <Dt>OS</Dt>
            <Dd>{ep.os}</Dd>
            <Dt>Version</Dt>
            <Dd>{ep.os_version ?? "—"}</Dd>
            <Dt>Architecture</Dt>
            <Dd>{ep.os_arch ?? "—"}</Dd>
            <Dt>Kernel</Dt>
            <Dd>{ep.kernel_version ?? "—"}</Dd>
            <Dt>Agent version</Dt>
            <Dd>{ep.agent_version ?? "—"}</Dd>
          </dl>
        </Card>
      </section>

      {/* --- Hardware --- */}
      <section
        id="section-hardware"
        aria-label="Hardware"
        style={{ scrollMarginTop: "1rem" }}
      >
        <Card title="Hardware" icon={<Cpu size={14} aria-hidden />}>
          {meta ? (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm md:grid-cols-3">
              <div>
                <dt className="text-xs uppercase tracking-wide text-faint">
                  Manufacturer
                </dt>
                <dd className="text-ink">{meta.manufacturer ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wide text-faint">Model</dt>
                <dd className="text-ink">{meta.model ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wide text-faint">Serial</dt>
                <dd className="text-ink">{meta.serial_number ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wide text-faint">CPU</dt>
                <dd className="text-ink">
                  {meta.cpu_model ?? "—"}
                  {meta.cpu_cores ? ` · ${meta.cpu_cores} cores` : ""}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wide text-faint">Memory</dt>
                <dd className="text-ink">{formatBytes(meta.memory_bytes)}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wide text-faint">Storage</dt>
                <dd className="text-ink">{formatBytes(meta.disk_bytes)}</dd>
              </div>
            </dl>
          ) : (
            <p className="text-sm text-faint">No inventory reported yet.</p>
          )}
        </Card>
      </section>

      {/* --- Software --- */}
      <section
        id="section-software"
        aria-label="Software"
        style={{ scrollMarginTop: "1rem" }}
      >
        <SoftwareSection endpointId={ep.id} />
      </section>

      {/* --- Network --- */}
      <section
        id="section-network"
        aria-label="Network"
        style={{ scrollMarginTop: "1rem" }}
      >
        <Card title="Network" icon={<Network size={14} aria-hidden />}>
          {meta && meta.ip_addresses.length + meta.mac_addresses.length > 0 ? (
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
              <Dt>IP addresses</Dt>
              <Dd className="font-mono text-xs">
                {meta.ip_addresses.length > 0 ? meta.ip_addresses.join(", ") : "—"}
              </Dd>
              <Dt>MAC addresses</Dt>
              <Dd className="font-mono text-xs">
                {meta.mac_addresses.length > 0 ? meta.mac_addresses.join(", ") : "—"}
              </Dd>
            </dl>
          ) : (
            <p className="text-sm text-faint">No network data reported yet.</p>
          )}
        </Card>
      </section>

      {/* --- Activity & health --- */}
      <section
        id="section-activity"
        aria-label="Activity and health"
        className="grid gap-3 lg:grid-cols-2"
        style={{ scrollMarginTop: "1rem" }}
      >
        <Card title="Endpoint activity" icon={<Activity size={14} aria-hidden />}>
          {!hasPermission("audit:read") ? (
            <p className="text-sm text-faint">
              Requires the audit:read permission.
            </p>
          ) : (
            <>
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
                  emptyMessage="No lifecycle events recorded for this endpoint."
                />
              )}
            </>
          )}
        </Card>

        <Card title="Inventory collection" icon={<HardDrive size={14} aria-hidden />}>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <Dt>Last inventory</Dt>
            <Dd>{formatUtc(ep.last_inventory_at)}</Dd>
            <Dt>Packages reported</Dt>
            <Dd>{ep.software_count}</Dd>
            <Dt>Collector status</Dt>
            <Dd>
              <StatusBadge status={health.data?.collector_status ?? "pending"} />
            </Dd>
          </dl>
        </Card>
      </section>

      {/* --- Groups --- */}
      <section
        aria-labelledby="groups-heading"
        className="rounded-lg border border-line bg-surface p-4 shadow-card"
      >
        <h2 id="groups-heading" className="text-sm font-medium text-ink">
          Groups
        </h2>
        {ep.groups.length === 0 ? (
          <p className="mt-2 text-sm text-faint">Not assigned to any group.</p>
        ) : (
          <ul className="mt-2 flex flex-wrap gap-2">
            {ep.groups.map((name) => {
              const group = groups.data?.find((g) => g.name === name);
              return (
                <li
                  key={name}
                  className="flex items-center gap-2 rounded bg-raised px-2 py-1 text-sm text-ink"
                >
                  {group ? (
                    <Link to={`/groups?group=${group.id}`} className="hover:underline">
                      {name}
                    </Link>
                  ) : (
                    name
                  )}
                  {canWrite && (
                    <button
                      type="button"
                      aria-label={`Remove ${name} from group`}
                      onClick={() => group && void unassign(group.id)}
                      className="text-faint hover:text-danger"
                    >
                      ✕
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {canWrite && (
          <form
            className="mt-3 flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void assign();
            }}
          >
            <label htmlFor="assign-group" className="text-xs text-muted">
              Assign to group
            </label>
            <select
              id="assign-group"
              value={assignGroup}
              onChange={(e) => setAssignGroup(e.target.value)}
              className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
            >
              <option value="">Choose a group…</option>
              {notInGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
            <button
              type="submit"
              disabled={!assignGroup || addMember.isPending}
              className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
            >
              Add
            </button>
          </form>
        )}
      </section>

      <ConfirmDialog
        open={confirm === "revoke"}
        title="Revoke endpoint?"
        description={
          <>
            <strong>{ep.hostname}</strong> will be permanently revoked: its agent
            credential stops working immediately and the endpoint can never
            return to active status. This cannot be undone.
          </>
        }
        confirmLabel="Revoke"
        destructive
        busy={revoke.isPending}
        onConfirm={() => void runRevoke()}
        onCancel={() => setConfirm(null)}
      />

      <ConfirmDialog
        open={confirm === "rotate"}
        title="Rotate credential?"
        description={
          <>
            A new credential is issued for <strong>{ep.hostname}</strong> and the
            current one stops working. The new value is displayed exactly once.
          </>
        }
        confirmLabel="Rotate"
        busy={rotate.isPending}
        onConfirm={() => void runRotate()}
        onCancel={() => setConfirm(null)}
      />

      <button
        type="button"
        onClick={() => navigate("/endpoints")}
        className="text-sm text-muted hover:text-ink"
      >
        ← Back to endpoints
      </button>
    </div>
  );
}

function SoftwareSection({ endpointId }: { endpointId: string }) {
  const [name, setName] = useState("");
  const [applied, setApplied] = useState("");
  const software = useEndpointSoftware(endpointId, {
    view: "current",
    name: applied,
    page_size: 50,
  });

  return (
    <div className="rounded-lg border border-line bg-surface p-4 shadow-card">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-1.5 text-sm font-medium text-ink">
          <Package size={14} aria-hidden className="text-faint" />
          Installed software
        </h2>
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setApplied(name.trim());
          }}
        >
          <label htmlFor="sw-filter" className="sr-only">
            Filter by package name
          </label>
          <input
            id="sw-filter"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Filter package…"
            className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink placeholder:text-faint focus:border-accent"
          />
          <button
            type="submit"
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
          >
            Filter
          </button>
        </form>
      </div>

      {software.isLoading && (
        <div className="mt-3">
          <Loading label="Loading packages…" />
        </div>
      )}
      {software.isError && (
        <div className="mt-3">
          <ErrorState error={software.error} onRetry={() => void software.refetch()} />
        </div>
      )}
      {software.data && software.data.items.length === 0 && (
        <div className="mt-3">
          <Empty message="No software reported for this endpoint yet." />
        </div>
      )}
      {software.data && software.data.items.length > 0 && (
        <>
          <ul className="mt-3 max-h-72 divide-y divide-line overflow-y-auto">
            {software.data.items.map((pkg) => (
              <li
                key={`${pkg.name}-${pkg.package_manager}`}
                className="flex items-center justify-between py-2 text-sm"
              >
                <span className="text-ink">{pkg.name}</span>
                <span className="font-mono text-xs text-muted">
                  {pkg.version} · {pkg.package_manager}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-faint">
            {software.data.total} package(s) ·{" "}
            <Link
              to={`/endpoints/${endpointId}/history`}
              className="text-accent hover:underline"
            >
              view install/remove history
            </Link>
          </p>
        </>
      )}
    </div>
  );
}

function Card({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4 shadow-card">
      <h3 className="flex items-center gap-1.5 text-sm font-medium text-ink">
        {icon && <span className="text-faint">{icon}</span>}
        {title}
      </h3>
      <div className="mt-3">{children}</div>
    </div>
  );
}

function InfoCard({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4 shadow-card">
      <p className="text-[11px] font-medium uppercase tracking-wider text-faint">
        {label}
      </p>
      <div className="mt-1 text-sm text-ink">{children}</div>
    </div>
  );
}

function Dt({ children }: { children: ReactNode }) {
  return <dt className="text-faint">{children}</dt>;
}

function Dd({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <dd className={`text-ink ${className}`}>{children}</dd>;
}
