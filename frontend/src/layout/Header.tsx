import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, LogOut, Menu } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { ThemeToggle } from "../components/ThemeToggle";
import { useEndpoint } from "../api/endpoints";
import { usePageMeta } from "./pageMeta";

interface Props {
  onMenuClick: () => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

/**
 * Compact application header: navigation controls, breadcrumb + page title
 * (endpoint hostname when addressing a specific endpoint — served from the
 * same query cache the page uses, so no extra request), theme switcher and
 * the account menu.
 */
export function Header({ onMenuClick, collapsed, onToggleCollapse }: Props) {
  const { user, logout } = useAuth();
  const meta = usePageMeta();
  const endpoint = useEndpoint(meta.endpointId);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  // Endpoint hostname replaces the last breadcrumb crumb (text, not a
  // heading — the page itself owns the <h1>). Served from the same query
  // cache the page uses, so no extra request.
  const crumbs = meta.crumbs.map((crumb, index) =>
    index === meta.crumbs.length - 1 && endpoint.data
      ? { ...crumb, label: endpoint.data.hostname }
      : crumb,
  );

  // Close the account menu on outside click / Escape.
  useEffect(() => {
    if (!menuOpen) return;
    function onPointer(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setMenuOpen(false);
    }
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-surface px-4">
      <button
        type="button"
        className="rounded-md border border-line p-1.5 text-muted hover:bg-raised hover:text-ink lg:hidden"
        onClick={onMenuClick}
        aria-label="Open navigation menu"
      >
        <Menu size={16} aria-hidden />
      </button>
      <button
        type="button"
        className="hidden rounded-md border border-line p-1.5 text-muted hover:bg-raised hover:text-ink lg:block"
        onClick={onToggleCollapse}
        aria-expanded={!collapsed}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {collapsed ? (
          <ChevronRight size={16} aria-hidden />
        ) : (
          <ChevronLeft size={16} aria-hidden />
        )}
      </button>

      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-semibold leading-tight text-ink">
          {meta.title}
        </p>
        <Breadcrumbs crumbs={crumbs} />
      </div>

      <ThemeToggle />

      <div className="relative" ref={menuRef}>
        <button
          type="button"
          className="flex items-center gap-2 rounded-md border border-line px-2 py-1.5 text-sm text-muted hover:bg-raised hover:text-ink"
          onClick={() => setMenuOpen((v) => !v)}
          aria-expanded={menuOpen}
          aria-haspopup="menu"
          aria-label="Account menu"
        >
          <span
            aria-hidden
            className="flex h-6 w-6 items-center justify-center rounded-full bg-accent-soft text-xs font-bold text-accent"
          >
            {(user?.full_name || user?.email || "?").charAt(0).toUpperCase()}
          </span>
          <span className="hidden max-w-40 truncate sm:block">
            {user?.full_name || user?.email}
          </span>
        </button>

        {menuOpen && (
          <div
            role="menu"
            aria-label="Account"
            className="absolute right-0 z-40 mt-2 w-60 rounded-lg border border-line bg-overlay p-1 shadow-pop"
          >
            <div className="border-b border-line px-3 py-2">
              <p className="truncate text-sm font-medium text-ink">{user?.email}</p>
              <p className="text-xs text-faint">
                Roles: {user?.roles.join(", ") || "none"}
              </p>
            </div>
            <button
              type="button"
              role="menuitem"
              className="mt-1 flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm text-danger hover:bg-raised"
              onClick={handleLogout}
            >
              <LogOut size={14} aria-hidden />
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
