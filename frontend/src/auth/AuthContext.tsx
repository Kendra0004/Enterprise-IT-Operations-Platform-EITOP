import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, clearTokens, getStoredRefreshToken, setTokens } from "../api/client";

export interface UserInfo {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  roles: string[];
  permissions: string[];
  created_at: string;
}

interface AuthState {
  user: UserInfo | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (perm: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);

  // On mount: try to restore the session from the stored refresh token.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!getStoredRefreshToken()) {
        if (!cancelled) setLoading(false);
        return;
      }
      try {
        const me = await api.get<UserInfo>("/auth/me");
        if (!cancelled) setUser(me);
      } catch {
        clearTokens();
        if (!cancelled) setUser(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const pair = await api.post<{
      access_token: string;
      refresh_token: string;
    }>("/auth/login", { email, password }, { auth: false });
    setTokens(pair.access_token, pair.refresh_token);
    const me = await api.get<UserInfo>("/auth/me");
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    const stored = getStoredRefreshToken();
    try {
      if (stored) {
        await api.post<void>("/auth/logout", { refresh_token: stored });
      }
    } catch {
      // Even if the server call fails, drop local session state.
    }
    clearTokens();
    setUser(null);
  }, []);

  const hasPermission = useCallback(
    (perm: string) => user?.permissions.includes(perm) ?? false,
    [user],
  );

  const value = useMemo(
    () => ({ user, loading, login, logout, hasPermission }),
    [user, loading, login, logout, hasPermission],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
