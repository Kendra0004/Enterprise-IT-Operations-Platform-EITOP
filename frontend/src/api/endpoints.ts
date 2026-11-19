/**
 * Endpoint management API (Phases 2.5–2.7): typed models + React Query hooks.
 *
 * Every hook delegates to the shared `api` client (auth header, single
 * refresh retry, problem+json errors). No request bypasses the client, so
 * RBAC failures surface as `ApiError` with the backend's status.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";

// --- Models (mirror the backend schemas) ----------------------------------

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export type EndpointStatus = "active" | "offline" | "revoked";
export type CollectorStatus = "healthy" | "late" | "offline" | "pending" | "revoked";

export interface EndpointRow {
  id: string;
  hostname: string;
  fqdn: string | null;
  os: string;
  os_version: string | null;
  os_arch: string | null;
  kernel_version: string | null;
  status: EndpointStatus;
  agent_version: string | null;
  enrolled_at: string;
  last_heartbeat_at: string | null;
  created_at: string;
  updated_at: string;
  groups: string[];
  ip_addresses: string[];
  last_inventory_at: string | null;
}

export interface EndpointMetadata {
  manufacturer: string | null;
  model: string | null;
  serial_number: string | null;
  cpu_model: string | null;
  cpu_cores: number | null;
  memory_bytes: number | null;
  disk_bytes: number | null;
  ip_addresses: string[];
  mac_addresses: string[];
  updated_at: string | null;
}

export interface FactRow {
  key: string;
  value: string;
  source: string;
  collected_at: string;
}

export interface EndpointDetail extends EndpointRow {
  metadata: EndpointMetadata | null;
  facts: FactRow[];
  software_count: number;
  last_inventory_at: string | null;
}

export interface EndpointHealth {
  endpoint_id: string;
  status: EndpointStatus;
  collector_status: CollectorStatus;
  last_heartbeat_at: string | null;
  last_inventory_at: string | null;
  seconds_since_heartbeat: number | null;
  agent_version: string | null;
  heartbeat_interval_seconds: number;
  offline_threshold_seconds: number;
  server_time: string;
}

export interface OverviewStats {
  total: number;
  active: number;
  offline: number;
  revoked: number;
  windows: number;
  linux: number;
  other_os: number;
  /** Endpoints that submitted at least one inventory (API-computed). */
  inventory_reported: number;
  latest_enrollments: EndpointRow[];
}

export interface SnapshotRow {
  id: string;
  endpoint_id: string;
  collected_at: string;
  received_at: string;
  agent_version: string | null;
  schema_version: number;
  package_count: number;
  fact_count: number;
  has_hardware: boolean;
  has_network: boolean;
}

export interface SnapshotSoftware {
  name: string;
  version: string;
  package_manager: string;
  previous_version?: string | null;
}

export interface HardwareChange {
  field: string;
  before: unknown;
  after: unknown;
}

export interface SnapshotDiff {
  base_snapshot_id: string;
  target_snapshot_id: string;
  added_packages: SnapshotSoftware[];
  removed_packages: SnapshotSoftware[];
  changed_packages: SnapshotSoftware[];
  hardware_changes: HardwareChange[];
}

export interface SnapshotDetail extends SnapshotRow {
  system: Record<string, unknown>;
  hardware: Record<string, unknown> | null;
  network: Record<string, unknown> | null;
  filesystems: Record<string, unknown>[];
  facts: Record<string, string>;
  packages: SnapshotSoftware[];
  changes: SnapshotDiff | null;
}

export interface SoftwareRow {
  name: string;
  version: string;
  package_manager: string;
  collected_at?: string;
}

export interface SoftwareHistoryRow {
  snapshot_id: string;
  collected_at: string;
  name: string;
  version: string;
  package_manager: string;
}

export interface NetworkHistoryRow {
  snapshot_id: string;
  collected_at: string;
  network: Record<string, unknown> | null;
}

export interface GroupRow {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  endpoint_count: number;
}

export interface GroupDetail extends GroupRow {
  members: EndpointRow[];
}

export interface EndpointListParams {
  page?: number;
  page_size?: number;
  status?: EndpointStatus | "";
  group_id?: string;
  q?: string;
  os?: string;
  agent_version?: string;
  heartbeat_from?: string;
  sort?: string;
  order?: "asc" | "desc";
}

// --- Queries ---------------------------------------------------------------

export function useEndpoints(params: EndpointListParams) {
  return useQuery({
    queryKey: ["endpoints", "list", params],
    queryFn: () =>
      api.get<Page<EndpointRow>>("/endpoints", {
        query: {
          page: params.page,
          page_size: params.page_size,
          status: params.status || undefined,
          group_id: params.group_id,
          q: params.q,
          os: params.os,
          agent_version: params.agent_version,
          heartbeat_from: params.heartbeat_from,
          sort: params.sort,
          order: params.order,
        },
      }),
  });
}

export function useOverview() {
  return useQuery({
    queryKey: ["endpoints", "overview"],
    queryFn: () => api.get<OverviewStats>("/endpoints/overview"),
  });
}

// --- Endpoint activity (real audit events, Phase 2.8) ----------------------

export interface AuditEvent {
  id: string;
  event_type: string;
  actor_email: string | null;
  target: string | null;
  outcome: string;
  created_at: string;
}

/**
 * Recent lifecycle audit events (`endpoint.*`). The audit API filters by
 * exact event_type only, so one page is fetched and narrowed client-side —
 * still real API data, one request, no per-event polling. Requires
 * `audit:read`; callers gate with `enabled`.
 */
export function useEndpointActivity({
  enabled = true,
  target,
  limit = 8,
}: { enabled?: boolean; target?: string; limit?: number } = {}) {
  return useQuery({
    queryKey: ["audit", "endpoint-activity", target ?? "all", limit],
    enabled,
    queryFn: async () => {
      const page = await api.get<Page<AuditEvent>>("/audit-logs", {
        query: { page_size: 100 },
      });
      return page.items
        .filter(
          (event) =>
            event.event_type.startsWith("endpoint.") &&
            (target === undefined || event.target === target),
        )
        .slice(0, limit);
    },
  });
}

export function useEndpoint(id: string | undefined) {
  return useQuery({
    queryKey: ["endpoints", "detail", id],
    enabled: Boolean(id),
    queryFn: () => api.get<EndpointDetail>(`/endpoints/${id}`),
  });
}

export function useEndpointHealth(id: string | undefined) {
  return useQuery({
    queryKey: ["endpoints", "health", id],
    enabled: Boolean(id),
    refetchInterval: 30_000,
    queryFn: () => api.get<EndpointHealth>(`/endpoints/${id}/health`),
  });
}

export interface SnapshotListParams {
  page?: number;
  page_size?: number;
  from?: string;
  to?: string;
}

export function useSnapshots(endpointId: string | undefined, params: SnapshotListParams) {
  return useQuery({
    queryKey: ["endpoints", "snapshots", endpointId, params],
    enabled: Boolean(endpointId),
    queryFn: () =>
      api.get<Page<SnapshotRow>>(`/endpoints/${endpointId}/snapshots`, {
        query: { page: params.page, page_size: params.page_size, from: params.from, to: params.to },
      }),
  });
}

export function useSnapshot(
  endpointId: string | undefined,
  snapshotId: string | undefined,
  compareTo?: string,
) {
  return useQuery({
    queryKey: ["endpoints", "snapshot", endpointId, snapshotId, compareTo ?? null],
    enabled: Boolean(endpointId && snapshotId),
    queryFn: () =>
      api.get<SnapshotDetail>(`/endpoints/${endpointId}/snapshots/${snapshotId}`, {
        query: { compare_to: compareTo },
      }),
  });
}

export interface SoftwareParams {
  view?: "current" | "history";
  name?: string;
  page?: number;
  page_size?: number;
}

export function useEndpointSoftware(endpointId: string | undefined, params: SoftwareParams) {
  return useQuery({
    queryKey: ["endpoints", "software", endpointId, params],
    enabled: Boolean(endpointId),
    queryFn: () =>
      api.get<Page<SoftwareRow | SoftwareHistoryRow>>(`/endpoints/${endpointId}/software`, {
        query: {
          view: params.view,
          name: params.name,
          page: params.page,
          page_size: params.page_size,
        },
      }),
  });
}

export function useEndpointNetwork(
  endpointId: string | undefined,
  params: { page?: number; page_size?: number; from?: string; to?: string },
) {
  return useQuery({
    queryKey: ["endpoints", "network", endpointId, params],
    enabled: Boolean(endpointId),
    queryFn: () =>
      api.get<Page<NetworkHistoryRow>>(`/endpoints/${endpointId}/network`, {
        query: { page: params.page, page_size: params.page_size, from: params.from, to: params.to },
      }),
  });
}

export function useGroups() {
  return useQuery({
    queryKey: ["groups"],
    queryFn: () => api.get<GroupRow[]>("/endpoints/groups"),
  });
}

export function useGroup(groupId: string | null | undefined) {
  return useQuery({
    queryKey: ["groups", "detail", groupId],
    enabled: Boolean(groupId),
    queryFn: () => api.get<GroupDetail>(`/endpoints/groups/${groupId}`),
  });
}

// --- Mutations -------------------------------------------------------------

function useInvalidate(...keys: string[][]) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: keys[0] });
    for (const key of keys.slice(1)) void qc.invalidateQueries({ queryKey: key });
  };
}

/** Admin action: revoke an endpoint (terminal — blocked at authentication). */
export function useRevokeEndpoint() {
  const invalidate = useInvalidate(["endpoints"]);
  return useMutation({
    mutationFn: (endpointId: string) =>
      api.post<{ id: string; status: string; revoked_credentials: number }>(
        `/endpoints/${endpointId}/revoke`,
      ),
    onSuccess: invalidate,
  });
}

/** Admin action: rotate the agent credential (raw value returned once). */
export function useRotateCredential() {
  const invalidate = useInvalidate(["endpoints"]);
  return useMutation({
    mutationFn: (endpointId: string) =>
      api.post<{ endpoint_id: string; credential: string; issued_at: string }>(
        `/endpoints/${endpointId}/rotate-credential`,
      ),
    onSuccess: invalidate,
  });
}

export function useCreateGroup() {
  const invalidate = useInvalidate(["groups"], ["endpoints"]);
  return useMutation({
    mutationFn: (input: { name: string; description?: string }) =>
      api.post<GroupRow>("/endpoints/groups", input),
    onSuccess: invalidate,
  });
}

export function useAddGroupMember() {
  const invalidate = useInvalidate(["groups"], ["endpoints"]);
  return useMutation({
    mutationFn: ({ endpointId, groupId }: { endpointId: string; groupId: string }) =>
      api.post<GroupDetail>(`/endpoints/${endpointId}/groups/${groupId}`),
    onSuccess: invalidate,
  });
}

export function useRemoveGroupMember() {
  const invalidate = useInvalidate(["groups"], ["endpoints"]);
  return useMutation({
    mutationFn: ({ endpointId, groupId }: { endpointId: string; groupId: string }) =>
      api.delete<GroupDetail>(`/endpoints/${endpointId}/groups/${groupId}`),
    onSuccess: invalidate,
  });
}
