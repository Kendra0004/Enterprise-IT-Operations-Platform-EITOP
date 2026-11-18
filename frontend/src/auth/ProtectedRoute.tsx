import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "./AuthContext";

/** Gate a route subtree behind authentication. */
export function ProtectedRoute() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div
        className="flex h-screen items-center justify-center"
        role="status"
        aria-label="Loading session"
      >
        <span className="animate-pulse text-slate-400">Restoring session…</span>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <Outlet />;
}
