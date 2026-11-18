import { NavLink } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { NAV_ITEMS } from "./nav";

interface Props {
  open: boolean;
  onClose: () => void;
}

export function Sidebar({ open, onClose }: Props) {
  const { hasPermission } = useAuth();

  const visible = NAV_ITEMS.filter(
    (item) => !item.permission || hasPermission(item.permission),
  );

  return (
    <>
      {/* Mobile scrim */}
      {open && (
        <button
          className="fixed inset-0 z-20 bg-black/60 lg:hidden"
          aria-label="Close navigation"
          onClick={onClose}
        />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-30 w-64 transform border-r border-slate-800 bg-slate-900 transition-transform lg:static lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
        aria-label="Main navigation"
      >
        <div className="flex h-14 items-center gap-2 border-b border-slate-800 px-4">
          <span className="rounded bg-emerald-500 px-2 py-0.5 font-bold text-slate-950">
            EITOP
          </span>
          <span className="text-xs text-slate-400">v0.1.0</span>
        </div>
        <nav className="flex flex-col gap-1 p-3">
          {visible.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === "/"}
              onClick={onClose}
              className={({ isActive }) =>
                `rounded px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-emerald-600/20 text-emerald-400"
                    : "text-slate-300 hover:bg-slate-800 hover:text-white"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
    </>
  );
}
