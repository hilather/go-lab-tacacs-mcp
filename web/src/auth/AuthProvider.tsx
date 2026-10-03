import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createSession, deleteSession, getSession, readCsrfCookie } from "../api/client";
import type { Session } from "../generated/api";
import { clearSessionMeta, saveSessionMeta } from "./sessionMeta";

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

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<AuthState>({ status: "loading" });
  const authGen = useRef(0);

  useEffect(() => {
    const gen = authGen.current;
    let cancelled = false;
    void (async () => {
      try {
        const sess = await getSession();
        if (cancelled || authGen.current !== gen) {
          return;
        }
        saveSessionMeta({
          token_id: sess.data.token_id,
          scopes: sess.data.scopes,
          expires_at: sess.data.expires_at,
        });
        setState((prev) => {
          if (prev.status !== "loading") {
            return prev;
          }
          return {
            status: "signed_in",
            session: {
              ...sess.data,
              csrf_token: readCsrfCookie() || sess.data.csrf_token,
              revision: sess.revision,
            },
          };
        });
      } catch {
        if (cancelled || authGen.current !== gen) {
          return;
        }
        clearSessionMeta();
        setState((prev) => (prev.status === "loading" ? { status: "anonymous" } : prev));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(
    async (token: string) => {
      authGen.current += 1;
      const env = await createSession(token);
      saveSessionMeta({
        token_id: env.data.token_id,
        scopes: env.data.scopes,
        expires_at: env.data.expires_at,
      });
      setState({ status: "signed_in", session: env.data });
      await queryClient.invalidateQueries();
    },
    [queryClient],
  );

  const logout = useCallback(async () => {
    authGen.current += 1;
    try {
      await deleteSession();
    } finally {
      clearSessionMeta();
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
