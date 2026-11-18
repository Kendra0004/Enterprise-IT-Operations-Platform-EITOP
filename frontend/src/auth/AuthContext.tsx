import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  api,
  clearTokens,
  hasSessionHint,
  setAccessToken,
  setSessionHint,
  type TokenPair,
} from "../api/client";

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

  // On mount: when a session hint exists, restore via /auth/me — the API
  // client transparently rotates the HttpOnly refresh cookie on 401.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!hasSessionHint()) {
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
    const pair = await api.post<TokenPair>(
      "/auth/login",
      { email, password },
      { auth: false },
    );
    // Access token → memory only. Refresh token → HttpOnly cookie (server).
    setAccessToken(pair.access_token);
    setSessionHint(true);
    const me = await api.get<UserInfo>("/auth/me");
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    try {
      // Server revokes the refresh family from the cookie and clears it.
      await api.post<void>("/auth/logout");
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
