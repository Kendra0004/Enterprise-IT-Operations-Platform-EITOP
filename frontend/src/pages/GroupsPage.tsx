/**
 * Endpoint groups (Phases 2.7–2.8): list with search, create, detail with
 * members, and assign/remove membership. Mutations require endpoints:write —
 * the backend enforces the same rule independently (403).
 */

import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FolderTree, UserMinus, UserPlus } from "lucide-react";
import {
  useAddGroupMember,
  useCreateGroup,
  useEndpoints,
  useGroup,
  useGroups,
  useRemoveGroupMember,
} from "../api/endpoints";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { PageHeader } from "../components/PageHeader";
import { SearchInput } from "../components/SearchInput";
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

  const [search, setSearch] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const create = useCreateGroup();

  const filteredGroups = (groups.data ?? []).filter((g) =>
    g.name.toLowerCase().includes(search.toLowerCase()),
  );

  async function submitCreate(e: React.FormEvent) {
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
    <div className="space-y-5">
      <PageHeader
        title="Endpoint groups"
        description="Logical groupings used for filtering and future policy scoping."
      />

      {formError && (
        <p
          role="alert"
          className="rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger"
        >
          {formError}
        </p>
      )}

      {canWrite && (
        <section
          aria-labelledby="create-group"
          className="rounded-lg border border-line bg-surface p-4 shadow-card"
        >
          <h2 id="create-group" className="text-sm font-medium text-ink">
            Create group
          </h2>
          <form className="mt-3 flex flex-wrap items-end gap-3" onSubmit={submitCreate}>
            <label className="flex flex-col gap-1 text-xs text-muted">
              Name
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={128}
                className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink focus:border-accent"
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-muted">
              Description
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={512}
                className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink focus:border-accent"
              />
            </label>
            <button
              type="submit"
              disabled={create.isPending || name.trim().length === 0}
              className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
            >
              {create.isPending ? "Creating…" : "Create"}
            </button>
          </form>
        </section>
      )}

      <div className="grid gap-3 lg:grid-cols-3">
        <section aria-label="All groups" className="lg:col-span-1">
          <div className="mb-2 flex items-center justify-between gap-2">
            <h2 className="text-sm font-medium text-ink">All groups</h2>
            <span className="text-xs text-faint">
              {groups.data ? `${groups.data.length} total` : ""}
            </span>
          </div>
          {groups.data && groups.data.length > 0 && (
            <SearchInput
              label="Search groups"
              value={search}
              onSearch={setSearch}
              placeholder="group name…"
              delay={200}
            />
          )}
          <div className="mt-2">
            {groups.isLoading && <Loading label="Loading groups…" />}
            {groups.isError && (
              <ErrorState error={groups.error} onRetry={() => void groups.refetch()} />
            )}
            {groups.data && groups.data.length === 0 && (
              <Empty message="No groups yet." />
            )}
            {groups.data && groups.data.length > 0 && filteredGroups.length === 0 && (
              <Empty message="No groups match your search." />
            )}
            {filteredGroups.length > 0 && (
              <ul className="divide-y divide-line rounded-lg border border-line bg-surface shadow-card">
                {filteredGroups.map((g) => (
                  <li key={g.id}>
                    <button
                      type="button"
                      onClick={() => setSearchParams({ group: g.id })}
                      className={`flex w-full items-center justify-between px-4 py-3 text-left text-sm transition-colors hover:bg-raised ${
                        selectedId === g.id ? "bg-accent-soft" : ""
                      }`}
                    >
                      <span className="flex items-center gap-2 text-ink">
                        <FolderTree size={14} aria-hidden className="text-faint" />
                        {g.name}
                      </span>
                      <span className="text-xs tabular-nums text-faint">
                        {g.endpoint_count} endpoint(s)
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        <section aria-label="Group detail" className="lg:col-span-2">
          <h2 className="mb-2 text-sm font-medium text-ink">Group detail</h2>
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

  async function assign(e: React.FormEvent) {
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
    <div className="space-y-4 rounded-lg border border-line bg-surface p-4 shadow-card">
      <div>
        <h3 className="text-base font-semibold text-ink">{data.name}</h3>
        <p className="text-sm text-muted">{data.description || "No description."}</p>
        <p className="mt-1 text-xs text-faint">
          Created {formatUtcShort(data.created_at)} · {data.endpoint_count} member(s)
        </p>
      </div>

      {error && (
        <p
          role="alert"
          className="rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger"
        >
          {error}
        </p>
      )}

      {data.members.length === 0 ? (
        <Empty message="No endpoints in this group." />
      ) : (
        <ul className="divide-y divide-line">
          {data.members.map((m) => (
            <li
              key={m.id}
              className="flex flex-wrap items-center justify-between gap-2 py-2"
            >
              <div className="flex flex-wrap items-center gap-3">
                <Link
                  to={`/endpoints/${m.id}`}
                  className="text-sm font-medium text-accent hover:underline"
                >
                  {m.hostname}
                </Link>
                <StatusBadge status={m.status} />
                <span className="text-xs text-faint">{m.os}</span>
              </div>
              {canWrite && (
                <button
                  type="button"
                  onClick={() => setConfirmRemove({ id: m.id, hostname: m.hostname })}
                  className="flex items-center gap-1 rounded-md border border-danger/50 px-2 py-1 text-xs text-danger transition-colors hover:bg-danger/10"
                >
                  <UserMinus size={12} aria-hidden />
                  Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <form className="flex flex-wrap items-end gap-2" onSubmit={assign}>
          <label className="flex flex-col gap-1 text-xs text-muted">
            Add endpoint
            <select
              value={assignId}
              onChange={(e) => setAssignId(e.target.value)}
              className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink"
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
            className="flex items-center gap-1 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90 disabled:opacity-50"
          >
            <UserPlus size={13} aria-hidden />
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
