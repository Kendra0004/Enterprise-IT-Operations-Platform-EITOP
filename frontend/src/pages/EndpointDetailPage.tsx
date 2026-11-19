/**
 * Endpoint detail (Phase 2.7): identity, OS, hardware, network, software,
 * agent/heartbeat health, and the management actions (health, history,
 * revoke, rotate, group membership) gated by RBAC.
 */

import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  useAddGroupMember,
  useEndpoint,
  useEndpointHealth,
  useEndpointSoftware,
  useGroups,
  useRemoveGroupMember,
  useRevokeEndpoint,
  useRotateCredential,
} from "../api/endpoints";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { StatusBadge } from "../components/StatusBadge";
import { Empty, ErrorState, Loading } from "../components/states";
import { useAuth } from "../auth/AuthContext";
import { ageLabel, formatBytes, formatUtc } from "../utils/datetime";

export function EndpointDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const canWrite = hasPermission("endpoints:write");

  const detail = useEndpoint(id);
  const health = useEndpointHealth(id);
  const groups = useGroups();

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
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <nav aria-label="Breadcrumb" className="text-xs text-slate-500">
            <Link to="/endpoints" className="hover:text-slate-300">
              Endpoints
            </Link>{" "}
            / <span className="text-slate-300">{ep.hostname}</span>
          </nav>
          <h1 className="mt-1 flex flex-wrap items-center gap-3 text-2xl font-semibold text-slate-100">
            {ep.hostname}
            <StatusBadge status={health.data?.collector_status ?? ep.status} />
          </h1>
          <p className="text-sm text-slate-400">
            {ep.fqdn ?? "No FQDN"} · {ep.os} {ep.os_version ?? ""} · agent{" "}
            {ep.agent_version ?? "unknown"}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link
            to={`/endpoints/${ep.id}/history`}
            className="rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
          >
            Inventory history
          </Link>
          {canWrite && (
            <>
              <button
                type="button"
                onClick={() => setConfirm("rotate")}
                className="rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
              >
                Rotate credential
              </button>
              <button
                type="button"
                onClick={() => setConfirm("revoke")}
                disabled={ep.status === "revoked"}
                className="rounded bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Revoke endpoint
              </button>
            </>
          )}
        </div>
      </header>

      {actionError && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
          {actionError}
        </p>
      )}

      {rotatedCredential && (
        <section
          aria-label="New credential"
          className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-100"
        >
          <p className="font-medium">
            New credential — shown exactly once. Update the agent now.
          </p>
          <code className="mt-2 block break-all rounded bg-slate-950 p-2 font-mono text-xs text-amber-200">
            {rotatedCredential}
          </code>
          <button
            type="button"
            onClick={() => setRotatedCredential(null)}
            className="mt-2 rounded border border-amber-400/60 px-3 py-1"
          >
            Dismiss
          </button>
        </section>
      )}

      <section aria-label="Health" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <InfoCard label="Lifecycle status">
          <StatusBadge status={ep.status} />{" "}
          <span className="text-slate-400">({health.data?.collector_status ?? "—"})</span>
        </InfoCard>
        <InfoCard label="Last heartbeat">
          {formatUtc(ep.last_heartbeat_at)}
          {health.data?.seconds_since_heartbeat !== null &&
            health.data?.seconds_since_heartbeat !== undefined && (
              <span className="ml-2 text-slate-500">{ageLabel(ep.last_heartbeat_at)} ago</span>
            )}
        </InfoCard>
        <InfoCard label="Last inventory">{formatUtc(ep.last_inventory_at)}</InfoCard>
        <InfoCard label="Enrolled">{formatUtc(ep.enrolled_at)}</InfoCard>
      </section>

      {health.data && (
        <p className="text-xs text-slate-500">
          Expected heartbeat every {health.data.heartbeat_interval_seconds}s · offline after{" "}
          {health.data.offline_threshold_seconds}s · server time{" "}
          {formatUtc(health.data.server_time)}
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <InfoCard title="Identity">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <Dt>Hostname</Dt>
            <Dd>{ep.hostname}</Dd>
            <Dt>FQDN</Dt>
            <Dd>{ep.fqdn ?? "—"}</Dd>
            <Dt>Endpoint ID</Dt>
            <Dd className="break-all font-mono text-xs">{ep.id}</Dd>
            <Dt>Groups</Dt>
            <Dd>{ep.groups.length > 0 ? ep.groups.join(", ") : "—"}</Dd>
          </dl>
        </InfoCard>

        <InfoCard title="Operating system">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <Dt>OS</Dt>
            <Dd>{ep.os}</Dd>
            <Dt>Version</Dt>
            <Dd>{ep.os_version ?? "—"}</Dd>
            <Dt>Architecture</Dt>
            <Dd>{ep.os_arch ?? "—"}</Dd>
            <Dt>Kernel</Dt>
            <Dd>{ep.kernel_version ?? "—"}</Dd>
          </dl>
        </InfoCard>

        <InfoCard title="Hardware">
          {meta ? (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <Dt>Manufacturer</Dt>
              <Dd>{meta.manufacturer ?? "—"}</Dd>
              <Dt>Model</Dt>
              <Dd>{meta.model ?? "—"}</Dd>
              <Dt>Serial</Dt>
              <Dd>{meta.serial_number ?? "—"}</Dd>
              <Dt>CPU</Dt>
              <Dd>
                {meta.cpu_model ?? "—"}
                {meta.cpu_cores ? ` · ${meta.cpu_cores} cores` : ""}
              </Dd>
              <Dt>Memory</Dt>
              <Dd>{formatBytes(meta.memory_bytes)}</Dd>
              <Dt>Storage</Dt>
              <Dd>{formatBytes(meta.disk_bytes)}</Dd>
            </dl>
          ) : (
            <p className="text-sm text-slate-500">No inventory reported yet.</p>
          )}
        </InfoCard>

        <InfoCard title="Network">
          {meta && meta.ip_addresses.length + meta.mac_addresses.length > 0 ? (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
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
            <p className="text-sm text-slate-500">No network data reported yet.</p>
          )}
        </InfoCard>
      </div>

      <SoftwareSection endpointId={ep.id} />

      <section aria-labelledby="groups-heading" className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 id="groups-heading" className="text-sm font-medium text-slate-300">
          Groups
        </h2>
        {ep.groups.length === 0 ? (
          <p className="mt-2 text-sm text-slate-500">Not assigned to any group.</p>
        ) : (
          <ul className="mt-2 flex flex-wrap gap-2">
            {ep.groups.map((name) => {
              const group = groups.data?.find((g) => g.name === name);
              return (
                <li key={name} className="flex items-center gap-2 rounded bg-slate-800 px-2 py-1 text-sm text-slate-200">
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
                      className="text-slate-500 hover:text-red-300"
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
            <label htmlFor="assign-group" className="text-xs text-slate-400">
              Assign to group
            </label>
            <select
              id="assign-group"
              value={assignGroup}
              onChange={(e) => setAssignGroup(e.target.value)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
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
              className="rounded bg-slate-700 px-3 py-1.5 text-sm text-white hover:bg-slate-600 disabled:opacity-50"
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
            credential stops working immediately and the endpoint can never return
            to active status. This cannot be undone.
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
        className="text-sm text-slate-400 hover:text-slate-200"
      >
        ← Back to endpoints
      </button>
    </div>
  );
}

function SoftwareSection({ endpointId }: { endpointId: string }) {
  const [name, setName] = useState("");
  const [applied, setApplied] = useState("");
  const software = useEndpointSoftware(endpointId, { view: "current", name: applied, page_size: 50 });

  return (
    <section aria-labelledby="software-heading" className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="software-heading" className="text-sm font-medium text-slate-300">
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
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200"
          />
          <button type="submit" className="rounded bg-slate-700 px-3 py-1 text-sm text-white hover:bg-slate-600">
            Filter
          </button>
        </form>
      </div>

      {software.isLoading && <div className="mt-3"><Loading label="Loading packages…" /></div>}
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
          <ul className="mt-3 max-h-72 divide-y divide-slate-800 overflow-y-auto">
            {software.data.items.map((pkg) => (
              <li key={`${pkg.name}-${pkg.package_manager}`} className="flex items-center justify-between py-2 text-sm">
                <span className="text-slate-200">{pkg.name}</span>
                <span className="font-mono text-xs text-slate-400">
                  {pkg.version} · {pkg.package_manager}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-slate-500">
            {software.data.total} package(s) ·{" "}
            <Link to={`/endpoints/${endpointId}/history`} className="text-sky-400 hover:underline">
              view install/remove history
            </Link>
          </p>
        </>
      )}
    </section>
  );
}

function InfoCard({
  title,
  label,
  children,
}: {
  title?: string;
  label?: string;
  children: ReactNode;
}) {
  if (label) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
        <div className="mt-1 text-sm text-slate-200">{children}</div>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-300">{title}</h2>
      <div className="mt-2">{children}</div>
    </div>
  );
}

function Dt({ children }: { children: ReactNode }) {
  return <dt className="text-slate-500">{children}</dt>;
}
function Dd({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <dd className={`text-slate-200 ${className}`}>{children}</dd>;
}
