import { Link } from "react-router-dom";
import { Activity } from "lucide-react";
import type { AuditEvent } from "../api/endpoints";
import { formatUtcShort } from "../utils/datetime";

/** Human label for lifecycle audit event types. */
const EVENT_LABELS: Record<string, string> = {
  "endpoint.enrolled": "Endpoint enrolled",
  "endpoint.offline": "Went offline",
  "endpoint.online": "Recovered online",
  "endpoint.revoked": "Endpoint revoked",
  "endpoint.credential.rotated": "Credential rotated",
  "endpoint.group.member.added": "Added to group",
  "endpoint.group.member.removed": "Removed from group",
};

/**
 * Recent endpoint lifecycle activity — real audit rows only. Renders a
 * compact list with event, actor, outcome and UTC timestamp.
 */
export function ActivityList({
  events,
  emptyMessage = "No endpoint activity recorded yet.",
  showTargetLink = false,
}: {
  events: AuditEvent[];
  emptyMessage?: string;
  showTargetLink?: boolean;
}) {
  if (events.length === 0) {
    return <p className="py-3 text-sm text-faint">{emptyMessage}</p>;
  }
  return (
    <ul className="divide-y divide-line">
      {events.map((event) => (
        <li key={event.id} className="flex items-center gap-3 py-2.5 text-sm">
          <Activity
            size={14}
            aria-hidden
            className={
              event.outcome === "success" ? "shrink-0 text-ok" : "shrink-0 text-danger"
            }
          />
          <div className="min-w-0 flex-1">
            <p className="truncate text-ink">
              {EVENT_LABELS[event.event_type] ?? event.event_type}
            </p>
            <p className="truncate text-xs text-faint">
              {event.actor_email ?? "system"}
              {showTargetLink && event.target && (
                <>
                  {" · "}
                  <Link
                    to={`/endpoints/${event.target}`}
                    className="text-accent hover:underline"
                  >
                    view endpoint
                  </Link>
                </>
              )}
            </p>
          </div>
          <span
            className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${
              event.outcome === "success"
                ? "bg-ok/10 text-ok"
                : "bg-danger/10 text-danger"
            }`}
          >
            {event.outcome}
          </span>
          <time
            dateTime={event.created_at}
            className="hidden shrink-0 text-xs tabular-nums text-faint sm:block"
          >
            {formatUtcShort(event.created_at)}
          </time>
        </li>
      ))}
    </ul>
  );
}
