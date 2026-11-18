import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

interface Props {
  onMenuClick: () => void;
}

export function Header({ onMenuClick }: Props) {
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <header className="flex h-14 items-center justify-between border-b border-slate-800 bg-slate-900 px-4">
      <button
        className="rounded p-2 text-slate-300 hover:bg-slate-800 lg:hidden"
        onClick={onMenuClick}
        aria-label="Open navigation menu"
      >
        ☰
      </button>
      <div className="hidden text-sm text-slate-400 lg:block">
        Enterprise IT Operations Platform
      </div>

      <div className="relative">
        <button
          className="flex items-center gap-2 rounded px-3 py-1.5 text-sm hover:bg-slate-800"
          onClick={() => setMenuOpen((v) => !v)}
          aria-expanded={menuOpen}
          aria-haspopup="menu"
        >
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-emerald-600 text-xs font-bold">
            {(user?.full_name || user?.email || "?").charAt(0).toUpperCase()}
          </span>
          <span className="max-w-40 truncate">{user?.full_name || user?.email}</span>
        </button>

        {menuOpen && (
          <div
            role="menu"
            className="absolute right-0 z-40 mt-2 w-56 rounded border border-slate-700 bg-slate-900 py-1 shadow-xl"
            onMouseLeave={() => setMenuOpen(false)}
          >
            <div className="border-b border-slate-800 px-4 py-2">
              <p className="truncate text-sm font-medium">{user?.email}</p>
              <p className="text-xs text-slate-400">
                Roles: {user?.roles.join(", ") || "none"}
              </p>
            </div>
            <button
              role="menuitem"
              className="w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-slate-800"
              onClick={handleLogout}
            >
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
