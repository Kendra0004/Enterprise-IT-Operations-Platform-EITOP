/**
 * Active Directory API (Phase 3.1): typed models + React Query hooks.
 *
 * Mirrors the backend `/api/v1/directory` router. Notes that matter:
 * - the bind password is WRITE-ONLY: it appears only in create/update
 *   payloads and is never part of any response type;
 * - every object list is scoped by `connection_id` (the backend 404s an
 *   unknown connection and never returns another connection's rows);
 * - mutations carry the matching `directory:*` permission, but the backend
 *   enforces RBAC independently (403) — this is display logic only.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";

// --- Shared shapes ----------------------------------------------------------

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface DirectoryOverview {
  domains: number;
  users_total: number;
  users_enabled: number;
  users_disabled: number;
  groups: number;
  computers: number;
  missing_objects: number;
  connections_total: number;
  connections_enabled: number;
  reconciliation_matched: number;
  reconciliation_needs_review: number;
  reconciliation_unmatched: number;
  reconciliation_rejected: number;
  running_syncs: number;
  failed_runs_24h: number;
  last_sync_success_at: string | null;
  last_sync_failure_at: string | null;
}

// --- Connections -------------------------------------------------------------

export type TlsMode = "ldaps" | "starttls";

export interface ConnectionSummary {
  id: string;
  name: string;
  domain_dns: string;
  host: string;
  port: number;
  tls_mode: TlsMode | string;
  search_base: string;
  bind_username: string;
  connect_timeout_seconds: number;
  search_timeout_seconds: number;
  page_size: number;
  enabled: boolean;
  auto_sync: boolean;
  sync_interval_minutes: number;
  has_custom_ca: boolean;
  last_run_status: string | null;
  last_run_started_at: string | null;
  last_success_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ConnectionDetail extends ConnectionSummary {
  /** Non-secret CA bundle for editing — never a credential. */
  tls_ca_pem: string | null;
}

/** Create payload: `bind_password` is accepted here and never returned. */
export interface ConnectionCreate {
  name: string;
  domain_dns: string;
  host: string;
  port?: number;
  tls_mode?: TlsMode;
  tls_ca_pem?: string | null;
  search_base: string;
  bind_username: string;
  bind_password: string;
  connect_timeout_seconds?: number;
  search_timeout_seconds?: number;
  page_size?: number;
  enabled?: boolean;
  auto_sync?: boolean;
  sync_interval_minutes?: number;
}

/** Update payload: `bind_password` rotates the stored secret when present. */
export type ConnectionUpdate = Partial<Omit<ConnectionCreate, "bind_password">> & {
  bind_password?: string;
};

export interface ConnectionTestResult {
  ok: boolean;
  label: string | null;
  message: string | null;
  duration_ms: number;
  default_naming_context: string | null;
  dns_hostname: string | null;
}

// --- Sync runs ---------------------------------------------------------------

export interface SyncRun {
  id: string;
  connection_id: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  trigger: string;
  objects_discovered: number;
  objects_created: number;
  objects_updated: number;
  objects_marked_missing: number;
  duration_ms: number | null;
}

export interface SyncRunDetail extends SyncRun {
  /** Sanitized fixed labels — never raw exception text. */
  errors: { category?: string; label: string; error_count?: number }[] | null;
  category_results: Record<string, { status?: string; label?: string; error_count?: number }>;
}

// --- Directory objects -------------------------------------------------------

export interface DomainRow {
  id: string;
  connection_id: string;
  domain_dns: string;
  distinguished_name: string;
  sid: string | null;
  functional_level: string | null;
  last_synced_at: string | null;
  last_seen_at: string;
}

export interface OuRow {
  id: string;
  connection_id: string;
  object_guid: string;
  distinguished_name: string;
  name: string;
  parent_dn: string | null;
  last_seen_at: string;
  missing_since: string | null;
}

export interface OuDetail extends OuRow {
  child_ous: number;
  users: number;
  groups: number;
  computers: number;
}

export interface DirectoryUserRow {
  id: string;
  connection_id: string;
  object_guid: string;
  distinguished_name: string;
  sid: string | null;
  sam_account_name: string;
  user_principal_name: string | null;
  display_name: string | null;
  email: string | null;
  enabled: boolean | null;
  department: string | null;
  title: string | null;
  manager_dn: string | null;
  last_logon_at: string | null;
  ad_created_at: string | null;
  ad_changed_at: string | null;
  last_seen_at: string;
  missing_since: string | null;
}

export interface DirectoryGroupRow {
  id: string;
  connection_id: string;
  object_guid: string;
  distinguished_name: string;
  sid: string | null;
  name: string;
  description: string | null;
  scope: string | null;
  category: string | null;
  last_seen_at: string;
  missing_since: string | null;
}

export interface DirectoryGroupDetail extends DirectoryGroupRow {
  member_count: number;
}

export interface GroupMemberRow {
  member_type: string;
  member_dn: string;
  member_object_guid: string | null;
  resolved: boolean;
  local_id: string | null;
  display_name: string | null;
}

export interface DirectoryComputerRow {
  id: string;
  connection_id: string;
  object_guid: string;
  distinguished_name: string;
  sid: string | null;
  name: string;
  dns_hostname: string | null;
  os: string | null;
  os_version: string | null;
  enabled: boolean | null;
  last_logon_at: string | null;
  ad_changed_at: string | null;
  last_seen_at: string;
  missing_since: string | null;
  recon_status: string | null;
  recon_method: string | null;
  recon_confidence: string | null;
  recon_endpoint_id: string | null;
}

export interface DirectoryComputerDetail extends DirectoryComputerRow {
  recon_candidates: string[];
  recon_reviewed_at: string | null;
}

export interface ReconciliationRow {
  id: string;
  connection_id: string;
  computer_id: string;
  endpoint_id: string | null;
  method: string;
  confidence: string;
  status: string;
  candidates: string[];
  reviewed_by: string | null;
  reviewed_at: string | null;
  updated_at: string;
  computer_name?: string | null;
  endpoint_hostname?: string | null;
}

export interface MatchDecision {
  decision: "match" | "reject";
  endpoint_id?: string | null;
}

// --- List parameters ----------------------------------------------------------

export interface ObjectListParams {
  connection_id: string;
  page?: number;
  page_size?: number;
  q?: string;
  include_missing?: boolean;
  sort?: string;
  order?: "asc" | "desc";
}

function objectQuery(params: ObjectListParams) {
  return {
    connection_id: params.connection_id,
    page: params.page,
    page_size: params.page_size,
    q: params.q,
    include_missing: params.include_missing ? "true" : undefined,
    sort: params.sort,
    order: params.order,
  };
}

// --- Queries ------------------------------------------------------------------

export function useDirectoryOverview() {
  return useQuery({
    queryKey: ["directory", "overview"],
    queryFn: () => api.get<DirectoryOverview>("/directory/overview"),
  });
}

export function useDirectoryConnections() {
  return useQuery({
    queryKey: ["directory", "connections"],
    queryFn: () => api.get<Page<ConnectionSummary>>("/directory/connections", {
      query: { page_size: 100 },
    }),
  });
}

export function useDirectoryConnection(id: string | null) {
  return useQuery({
    queryKey: ["directory", "connections", id],
    queryFn: () => api.get<ConnectionDetail>(`/directory/connections/${id}`),
    enabled: Boolean(id),
  });
}

export function useDomains(params: ObjectListParams) {
  return useQuery({
    queryKey: ["directory", "domains", params],
    queryFn: () => api.get<Page<DomainRow>>("/directory/domains", { query: objectQuery(params) }),
    enabled: Boolean(params.connection_id),
  });
}

export function useOus(params: ObjectListParams) {
  return useQuery({
    queryKey: ["directory", "ous", params],
    queryFn: () => api.get<Page<OuRow>>("/directory/ous", { query: objectQuery(params) }),
    enabled: Boolean(params.connection_id),
  });
}

export function useOu(id: string | null, connectionId: string) {
  return useQuery({
    queryKey: ["directory", "ous", id, connectionId],
    queryFn: () =>
      api.get<OuDetail>(`/directory/ous/${id}`, { query: { connection_id: connectionId } }),
    enabled: Boolean(id) && Boolean(connectionId),
  });
}

export function useDirectoryUsers(params: ObjectListParams) {
  return useQuery({
    queryKey: ["directory", "users", params],
    queryFn: () => api.get<Page<DirectoryUserRow>>("/directory/users", {
      query: objectQuery(params),
    }),
    enabled: Boolean(params.connection_id),
  });
}

export function useDirectoryGroups(params: ObjectListParams) {
  return useQuery({
    queryKey: ["directory", "groups", params],
    queryFn: () => api.get<Page<DirectoryGroupRow>>("/directory/groups", {
      query: objectQuery(params),
    }),
    enabled: Boolean(params.connection_id),
  });
}

export function useDirectoryGroup(id: string | null, connectionId: string) {
  return useQuery({
    queryKey: ["directory", "groups", id, connectionId],
    queryFn: () =>
      api.get<DirectoryGroupDetail>(`/directory/groups/${id}`, {
        query: { connection_id: connectionId },
      }),
    enabled: Boolean(id) && Boolean(connectionId),
  });
}

export function useGroupMembers(id: string | null, connectionId: string) {
  return useQuery({
    queryKey: ["directory", "groups", id, "members", connectionId],
    queryFn: () =>
      api.get<Page<GroupMemberRow>>(`/directory/groups/${id}/members`, {
        query: { connection_id: connectionId, page_size: 200 },
      }),
    enabled: Boolean(id) && Boolean(connectionId),
  });
}

export function useDirectoryComputers(params: ObjectListParams) {
  return useQuery({
    queryKey: ["directory", "computers", params],
    queryFn: () => api.get<Page<DirectoryComputerRow>>("/directory/computers", {
      query: objectQuery(params),
    }),
    enabled: Boolean(params.connection_id),
  });
}

export interface SyncRunListParams {
  connection_id?: string;
  status?: string;
  page?: number;
  page_size?: number;
}

export function useSyncRuns(params: SyncRunListParams = {}) {
  return useQuery({
    queryKey: ["directory", "sync-runs", params],
    queryFn: () => api.get<Page<SyncRun>>("/directory/sync-runs", {
      query: {
        connection_id: params.connection_id,
        status: params.status,
        page: params.page,
        page_size: params.page_size ?? 50,
      },
    }),
  });
}

export function useSyncRun(id: string | null) {
  return useQuery({
    queryKey: ["directory", "sync-runs", id],
    queryFn: () => api.get<SyncRunDetail>(`/directory/sync-runs/${id}`),
    enabled: Boolean(id),
  });
}

export function useReconciliations(connectionId: string, status?: string) {
  return useQuery({
    queryKey: ["directory", "reconciliations", connectionId, status],
    queryFn: () =>
      api.get<Page<ReconciliationRow>>("/directory/reconciliations", {
        query: { connection_id: connectionId, status, page_size: 100 },
      }),
    enabled: Boolean(connectionId),
  });
}

// --- Mutations ----------------------------------------------------------------

function useDirectoryInvalidation() {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ queryKey: ["directory"] });
  };
}

export function useCreateConnection() {
  const invalidate = useDirectoryInvalidation();
  return useMutation({
    mutationFn: (payload: ConnectionCreate) =>
      api.post<ConnectionDetail>("/directory/connections", payload),
    onSuccess: invalidate,
  });
}

export function useUpdateConnection() {
  const invalidate = useDirectoryInvalidation();
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: ConnectionUpdate }) =>
      api.patch<ConnectionDetail>(`/directory/connections/${id}`, payload),
    onSuccess: invalidate,
  });
}

export function useDeleteConnection() {
  const invalidate = useDirectoryInvalidation();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/directory/connections/${id}`),
    onSuccess: invalidate,
  });
}

/** Connectivity test: resolves 200 with {ok:false,label} on failure. */
export function useTestConnection() {
  return useMutation({
    mutationFn: (id: string) =>
      api.post<ConnectionTestResult>(`/directory/connections/${id}/test`),
  });
}

/** Manual sync: 202 with the queued run; 409 when one is already running. */
export function useTriggerSync() {
  const invalidate = useDirectoryInvalidation();
  return useMutation({
    mutationFn: (id: string) => api.post<SyncRun>(`/directory/connections/${id}/sync`),
    onSuccess: invalidate,
  });
}

export function useDecideMatch(computerId: string) {
  const invalidate = useDirectoryInvalidation();
  return useMutation({
    mutationFn: (payload: MatchDecision) =>
      api.post<ReconciliationRow>(`/directory/computers/${computerId}/match`, payload),
    onSuccess: invalidate,
  });
}
