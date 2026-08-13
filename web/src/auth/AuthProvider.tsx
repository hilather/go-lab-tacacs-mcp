import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { createSession, deleteSession, getStatus, readCsrfCookie } from "../api/client";
import type { Session } from "../generated/api";

type AuthState =
  | { status: "loading" }
  | { status: "anonymous" }
  | { status: "signed_in"; session: Session };

type AuthContextValue = {
  state: AuthState;
  hasScope: (scope: string) => boolean;
  login: (token: string) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

function sessionFromProbe(revision: number): Session {
  return {
    token_id: "",
    scopes: ["state:read"],
    expires_at: "",
    csrf_token: readCsrfCookie(),
    cookie_name: "taclab_session",
    cookie_secure: false,
    same_site: "strict",
    cookie_path: "/",
    cookie_max_age: 0,
    revision,
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<AuthState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const env = await getStatus();
        if (!cancelled) {
          setState({ status: "signed_in", session: sessionFromProbe(env.revision) });
        }
      } catch {
        if (!cancelled) {
          setState({ status: "anonymous" });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(
    async (token: string) => {
      const env = await createSession(token);
      setState({ status: "signed_in", session: env.data });
      await queryClient.invalidateQueries();
    },
    [queryClient],
  );

  const logout = useCallback(async () => {
    try {
      await deleteSession();
    } finally {
      queryClient.clear();
      setState({ status: "anonymous" });
    }
  }, [queryClient]);

  useEffect(() => {
    if (state.status !== "signed_in") {
      return;
    }
    const exp = Date.parse(state.session.expires_at);
    if (!Number.isFinite(exp) || exp <= 0) {
      return;
    }
    const wait = exp - Date.now();
    if (wait <= 0) {
      void logout();
      return;
    }
    const timer = window.setTimeout(() => {
      void logout();
    }, wait);
    return () => {
      window.clearTimeout(timer);
    };
  }, [state, logout]);

  const hasScope = useCallback(
    (scope: string) => {
      if (state.status !== "signed_in") {
        return false;
      }
      return state.session.scopes.includes(scope);
    },
    [state],
  );

  const value = useMemo(
    () => ({ state, hasScope, login, logout }),
    [state, hasScope, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth requires AuthProvider");
  }
  return ctx;
}
