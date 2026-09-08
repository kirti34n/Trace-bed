/* eslint-disable react-refresh/only-export-components -- provider and its consumer hook share one private context. */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { beginLogin, getSessionStatus, logout, onAuthenticationChanged, setSynchronizerCsrfToken } from "../api/client";
import type { ApiError } from "../api/client";
import type { SessionStatusOut } from "../api/types";

type SessionPhase = "loading" | "authenticated" | "anonymous" | "error";

interface SessionContextValue {
  phase: SessionPhase;
  session: SessionStatusOut | undefined;
  error: ApiError | undefined;
  /** Changes whenever identity becomes unknown, anonymous, or authenticated.
   * Consumers use it as a key to discard view-local/query state. */
  epoch: number;
  reload: () => void;
  login: () => void;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<SessionPhase>("loading");
  const [session, setSession] = useState<SessionStatusOut | undefined>();
  const [error, setError] = useState<ApiError | undefined>();
  const [generation, setGeneration] = useState(0);
  const [epoch, setEpoch] = useState(0);
  const sessionRequestId = useRef(0);

  const reload = useCallback(() => setGeneration((current) => current + 1), []);
  const clearRenderedSession = useCallback(() => {
    // Do this before any follow-up status request: a delayed/failed probe must
    // never leave the previous project's rows or selection visible.
    setSynchronizerCsrfToken(null);
    sessionRequestId.current += 1;
    setSession(undefined);
    setError(undefined);
    setPhase("loading");
    setEpoch((current) => current + 1);
  }, []);

  // An ordinary protected-route 401 while already anonymous must not remount
  // the whole tree and immediately issue the same request again. Only a loss
  // of an authenticated session is an identity transition worth refreshing.
  useEffect(() => onAuthenticationChanged(() => {
    if (phase === "authenticated") {
      clearRenderedSession();
      reload();
    }
  }), [clearRenderedSession, phase, reload]);

  useEffect(() => {
    const controller = new AbortController();
    const requestId = ++sessionRequestId.current;
    setPhase("loading");
    setError(undefined);
    setSynchronizerCsrfToken(null);
    getSessionStatus(controller.signal)
      .then((next) => {
        if (requestId !== sessionRequestId.current) return;
        setSession(next);
        setSynchronizerCsrfToken(next.authenticated ? (next.csrf_token ?? null) : null);
        setPhase(next.authenticated ? "authenticated" : "anonymous");
        setEpoch((current) => current + 1);
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted || requestId !== sessionRequestId.current) return;
        setSession(undefined);
        setSynchronizerCsrfToken(null);
        setError(reason as ApiError);
        setPhase("error");
        setEpoch((current) => current + 1);
      });
    return () => controller.abort();
  }, [generation]);

  const logoutCurrent = useCallback(async () => {
    // `logout()` constructs the CSRF-protected request synchronously; clear
    // the rendered identity immediately after that construction, not after
    // its network response.
    const pending = logout();
    clearRenderedSession();
    try {
      await pending;
    } catch {
      // The local rendered identity has already been cleared. A status probe
      // decides the follow-up UX; never restore stale project state here.
    } finally {
      reload();
    }
  }, [clearRenderedSession, reload]);

  const value = useMemo<SessionContextValue>(
    () => ({ phase, session, error, epoch, reload, login: beginLogin, logout: logoutCurrent }),
    [epoch, error, logoutCurrent, phase, reload, session]
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (value === null) throw new Error("useSession must be rendered inside SessionProvider");
  return value;
}
