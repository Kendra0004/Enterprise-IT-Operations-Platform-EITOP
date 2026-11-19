/**
 * Endpoint groups (Phase 2.7): list, create, detail with members, and
 * assign/remove membership. Mutations require endpoints:write — the
 * backend enforces the same rule independently (403).
 */

import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  useAddGroupMember,
  useCreateGroup,
  useEndpoints,
  useGroup,
  useGroups,
  useRemoveGroupMember,
} from "../api/endpoints";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { StatusBadge } from "../components/StatusBadge";
import { Empty, ErrorState, Loading } from "../components/states";
import { useAuth } from "../auth/AuthContext";
import { formatUtcShort } from "../utils/datetime";

export function GroupsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get("group");
  const { hasPermission } = useAuth();
  const canWrite = hasPermission("endpoints:write");

  const groups = useGroups();
  const group = useGroup(selectedId);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const create = useCreateGroup();

  async function submitCreate(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    try {
      const created = await create.mutateAsync({ name: name.trim(), description });
      setName("");
      setDescription("");
      setSearchParams({ group: created.id });
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not create group.");
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-100">Endpoint groups</h1>
        <p className="text-sm text-slate-400">
          Logical groupings used for filtering and future policy scoping.
        </p>
      </header>

      {formError && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
          {formError}
        </p>
      )}

      {canWrite && (
        <section aria-labelledby="create-group" className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 id="create-group" className="text-sm font-medium text-slate-300">
            Create group
          </h2>
          <form className="mt-3 flex flex-wrap items-end gap-3" onSubmit={submitCreate}>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              Name
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={128}
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              Description
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={512}
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
              />
            </label>
            <button
              type="submit"
              disabled={create.isPending || name.trim().length === 0}
              className="rounded bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {create.isPending ? "Creating…" : "Create"}
            </button>
          </form>
        </section>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <section aria-labelledby="group-list" className="lg:col-span-1">
          <h2 id="group-list" className="mb-2 text-sm font-medium text-slate-300">
            All groups
          </h2>
          {groups.isLoading && <Loading label="Loading groups…" />}
          {groups.isError && (
            <ErrorState error={groups.error} onRetry={() => void groups.refetch()} />
          )}
          {groups.data && groups.data.length === 0 && (
            <Empty message="No groups yet." />
          )}
          {groups.data && groups.data.length > 0 && (
            <ul className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-slate-900">
              {groups.data.map((g) => (
                <li key={g.id}>
                  <button
                    type="button"
                    onClick={() => setSearchParams({ group: g.id })}
                    className={`flex w-full items-center justify-between px-4 py-3 text-left text-sm hover:bg-slate-800 ${
                      selectedId === g.id ? "bg-slate-800" : ""
                    }`}
                  >
                    <span className="text-slate-200">{g.name}</span>
                    <span className="text-xs tabular-nums text-slate-500">
                      {g.endpoint_count} endpoint(s)
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section aria-labelledby="group-detail" className="lg:col-span-2">
          <h2 id="group-detail" className="mb-2 text-sm font-medium text-slate-300">
            Group detail
          </h2>
          {!selectedId && <Empty message="Select a group to view its members." />}
          {selectedId && group.isLoading && <Loading label="Loading group…" />}
          {selectedId && group.isError && (
            <ErrorState error={group.error} onRetry={() => void group.refetch()} />
          )}
          {group.data && <GroupMembers groupId={group.data.id} onChanged={() => void group.refetch()} />}
        </section>
      </div>
    </div>
  );
}

function GroupMembers({ groupId, onChanged }: { groupId: string; onChanged: () => void }) {
  const { hasPermission } = useAuth();
  const canWrite = hasPermission("endpoints:write");
  const group = useGroup(groupId);
  const removeMember = useRemoveGroupMember();
  const addMember = useAddGroupMember();
  const endpoints = useEndpoints({ page_size: 100, status: "active" });

  const [assignId, setAssignId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<{ id: string; hostname: string } | null>(null);

  const data = group.data;
  if (!data) return <Loading label="Loading members…" />;

  const memberIds = new Set(data.members.map((m) => m.id));
  const candidates = (endpoints.data?.items ?? []).filter((e) => !memberIds.has(e.id));

  async function assign(e: FormEvent) {
    e.preventDefault();
    if (!assignId) return;
    setError(null);
    try {
      await addMember.mutateAsync({ endpointId: assignId, groupId });
      setAssignId("");
      onChanged();
      void endpoints.refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not assign endpoint.");
    }
  }

  async function remove() {
    if (!confirmRemove) return;
    setError(null);
    try {
      await removeMember.mutateAsync({ endpointId: confirmRemove.id, groupId });
      setConfirmRemove(null);
      onChanged();
      void endpoints.refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove endpoint.");
      setConfirmRemove(null);
    }
  }

  return (
    <div className="space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div>
        <h3 className="text-base font-semibold text-slate-100">{data.name}</h3>
        <p className="text-sm text-slate-400">{data.description || "No description."}</p>
        <p className="mt-1 text-xs text-slate-500">
          Created {formatUtcShort(data.created_at)} · {data.endpoint_count} member(s)
        </p>
      </div>

      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
          {error}
        </p>
      )}

      {data.members.length === 0 ? (
        <Empty message="No endpoints in this group." />
      ) : (
        <ul className="divide-y divide-slate-800">
          {data.members.map((m) => (
            <li key={m.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <div className="flex items-center gap-3">
                <Link to={`/endpoints/${m.id}`} className="text-sm font-medium text-sky-300 hover:underline">
                  {m.hostname}
                </Link>
                <StatusBadge status={m.status} />
                <span className="text-xs text-slate-500">{m.os}</span>
              </div>
              {canWrite && (
                <button
                  type="button"
                  onClick={() => setConfirmRemove({ id: m.id, hostname: m.hostname })}
                  className="rounded border border-red-500/50 px-2 py-1 text-xs text-red-300 hover:bg-red-500/10"
                >
                  Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <form className="flex flex-wrap items-end gap-2" onSubmit={assign}>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Add endpoint
            <select
              value={assignId}
              onChange={(e) => setAssignId(e.target.value)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            >
              <option value="">Choose an endpoint…</option>
              {candidates.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.hostname}
                </option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            disabled={!assignId || addMember.isPending}
            className="rounded bg-slate-700 px-3 py-1.5 text-sm text-white hover:bg-slate-600 disabled:opacity-50"
          >
            Add
          </button>
        </form>
      )}

      <ConfirmDialog
        open={confirmRemove !== null}
        title="Remove from group?"
        description={
          <>
            Remove <strong>{confirmRemove?.hostname}</strong> from{" "}
            <strong>{data.name}</strong>? The endpoint itself is not affected.
          </>
        }
        confirmLabel="Remove"
        destructive
        busy={removeMember.isPending}
        onConfirm={() => void remove()}
        onCancel={() => setConfirmRemove(null)}
      />
    </div>
  );
}
