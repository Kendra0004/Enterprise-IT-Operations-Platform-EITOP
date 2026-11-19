import { NavLink } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { NAV_ITEMS } from "./nav";

interface Props {
  open: boolean;
  onClose: () => void;
  collapsed: boolean;
}

/**
 * Persistent application sidebar (Phase 2.8).
 *
 * Desktop: collapsible rail (icons + tooltips) or expanded list with labels.
 * Mobile: overlay drawer. Unimplemented modules render muted under a
 * "Preview" heading so they never read as operational features.
 */
export function Sidebar({ open, onClose, collapsed }: Props) {
  const { hasPermission, user } = useAuth();

  const visible = NAV_ITEMS.filter(
    (item) => !item.permission || hasPermission(item.permission),
  );
  const live = visible.filter((item) => !item.preview);
  const preview = visible.filter((item) => item.preview);

  const width = collapsed ? "lg:w-16" : "lg:w-60";

  return (
    <>
      {/* Mobile scrim */}
      {open && (
        <button
          className="fixed inset-0 z-20 bg-black/50 lg:hidden"
          aria-label="Close navigation"
          onClick={onClose}
        />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r border-line bg-surface transition-transform lg:static lg:translate-x-0 lg:transition-[width] ${width} ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
        aria-label="Main navigation"
      >
        {/* Brand */}
        <div
          className={`flex h-14 shrink-0 items-center gap-2 border-b border-line px-4 ${
            collapsed ? "lg:justify-center lg:px-0" : ""
          }`}
        >
          <span className="rounded bg-accent px-2 py-0.5 text-sm font-bold text-accent-contrast">
            E
          </span>
          {!collapsed && (
            <span className="text-sm font-semibold tracking-wide text-ink">
              EITOP
            </span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto p-2" aria-label="Modules">
          {!collapsed && (
            <p className="px-2 pb-1 pt-3 text-[11px] font-medium uppercase tracking-wider text-faint">
              Platform
            </p>
          )}
          <ul className="space-y-0.5">
            {live.map((item) => (
              <NavItemLink
                key={item.path}
                item={item}
                collapsed={collapsed}
                onNavigate={onClose}
              />
            ))}
          </ul>

          {preview.length > 0 && (
            <>
              <p
                className={`px-2 pb-1 pt-4 text-[11px] font-medium uppercase tracking-wider text-faint ${
                  collapsed ? "lg:hidden" : ""
                }`}
              >
                Preview
              </p>
              <ul className="space-y-0.5">
                {preview.map((item) => (
                  <NavItemLink
                    key={item.path}
                    item={item}
                    collapsed={collapsed}
                    onNavigate={onClose}
                    muted
                  />
                ))}
              </ul>
            </>
          )}
        </nav>

        {/* User block */}
        <div
          className={`border-t border-line p-3 ${collapsed ? "lg:px-2" : ""}`}
        >
          <div
            className={`flex items-center gap-2 ${
              collapsed ? "lg:justify-center" : ""
            }`}
          >
            <span
              aria-hidden
              className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent-soft text-xs font-bold text-accent"
            >
              {(user?.full_name || user?.email || "?").charAt(0).toUpperCase()}
            </span>
            {!collapsed && (
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-ink">
                  {user?.full_name || user?.email}
                </p>
                <p className="truncate text-[11px] text-faint">
                  {user?.roles.join(", ") || "no roles"}
                </p>
              </div>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}

function NavItemLink({
  item,
  collapsed,
  onNavigate,
  muted = false,
}: {
  item: (typeof NAV_ITEMS)[number];
  collapsed: boolean;
  onNavigate: () => void;
  muted?: boolean;
}) {
  const Icon = item.icon;
  return (
    <li>
      <NavLink
        to={item.path}
        end={item.path === "/"}
        onClick={onNavigate}
        title={collapsed ? item.label : undefined}
        className={({ isActive }) =>
          `group flex items-center gap-3 rounded-md px-2.5 py-2 text-sm transition-colors ${
            collapsed ? "lg:justify-center lg:px-0" : ""
          } ${
            isActive
              ? "bg-accent-soft font-medium text-accent"
              : muted
                ? "text-faint hover:bg-raised hover:text-muted"
                : "text-muted hover:bg-raised hover:text-ink"
          }`
        }
      >
        <Icon size={16} aria-hidden className="shrink-0" />
        {!collapsed && <span className="truncate">{item.label}</span>}
        {collapsed && <span className="sr-only">{item.label}</span>}
        {muted && !collapsed && (
          <span className="ml-auto rounded bg-raised px-1 text-[10px] uppercase text-faint group-hover:text-muted">
            soon
          </span>
        )}
      </NavLink>
    </li>
  );
}
