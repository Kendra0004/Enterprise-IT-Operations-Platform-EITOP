/** Lifecycle/health status badge. Colors are semantic tokens that follow the
 * active theme; the text label is always present so the state is never
 * conveyed by color alone (accessibility). */

export type BadgeStatus =
  | "active"
  | "offline"
  | "revoked"
  | "healthy"
  | "late"
  | "pending";

const STYLES: Record<BadgeStatus, { cls: string; label: string }> = {
  active: {
    cls: "bg-ok/10 text-ok ring-ok/40",
    label: "Active",
  },
  offline: {
    cls: "bg-warn/10 text-warn ring-warn/40",
    label: "Offline",
  },
  revoked: {
    cls: "bg-danger/10 text-danger ring-danger/40",
    label: "Revoked",
  },
  healthy: {
    cls: "bg-ok/10 text-ok ring-ok/40",
    label: "Healthy",
  },
  late: {
    cls: "bg-warn/10 text-warn ring-warn/40",
    label: "Late",
  },
  pending: {
    cls: "bg-raised text-muted ring-line-strong",
    label: "Pending",
  },
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
