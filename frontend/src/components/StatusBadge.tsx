/** Lifecycle/health status badge. Colors are semantic; the text is always
 * present so the state is not conveyed by color alone (accessibility). */

export type BadgeStatus =
  | "active"
  | "offline"
  | "revoked"
  | "healthy"
  | "late"
  | "pending";

const STYLES: Record<BadgeStatus, { cls: string; label: string }> = {
  active: { cls: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40", label: "Active" },
  offline: { cls: "bg-amber-500/15 text-amber-300 ring-amber-500/40", label: "Offline" },
  revoked: { cls: "bg-red-500/15 text-red-300 ring-red-500/40", label: "Revoked" },
  healthy: { cls: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40", label: "Healthy" },
  late: { cls: "bg-amber-500/15 text-amber-300 ring-amber-500/40", label: "Late" },
  pending: { cls: "bg-slate-500/15 text-slate-300 ring-slate-500/40", label: "Pending" },
};

export function StatusBadge({ status }: { status: string }) {
  const known = (status in STYLES ? status : "pending") as BadgeStatus;
  const { cls, label } = STYLES[known];
  return (
    <span
      data-testid={`status-${known}`}
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}
    >
      {label}
    </span>
  );
}
