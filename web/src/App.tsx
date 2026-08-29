import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense, useState } from "react";
import { BrowserRouter, NavLink, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthProvider";
import { EventStreamProvider } from "./hooks/EventStreamProvider";
import { useEventStream } from "./hooks/useEventStream";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { NAV_GROUPS, visibleNavItems } from "./ui/nav";

const UsersPage = lazy(async () => ({ default: (await import("./pages/UsersPage")).UsersPage }));
const GroupsPage = lazy(async () => ({ default: (await import("./pages/GroupsPage")).GroupsPage }));
const ClientsPage = lazy(async () => ({ default: (await import("./pages/ClientsPage")).ClientsPage }));
const TokensPage = lazy(async () => ({ default: (await import("./pages/TokensPage")).TokensPage }));
const EventsPage = lazy(async () => ({ default: (await import("./pages/EventsPage")).EventsPage }));
const AuthTestPage = lazy(async () => ({ default: (await import("./pages/AuthTestPage")).AuthTestPage }));
const RadiusAuthTestPage = lazy(async () => ({ default: (await import("./pages/RadiusAuthTestPage")).RadiusAuthTestPage }));
const RadiusSessionsPage = lazy(async () => ({ default: (await import("./pages/RadiusSessionsPage")).RadiusSessionsPage }));
const RadiusAttributesPage = lazy(async () => ({ default: (await import("./pages/RadiusAttributesPage")).RadiusAttributesPage }));
const PolicyExplainPage = lazy(async () => ({ default: (await import("./pages/PolicyExplainPage")).PolicyExplainPage }));
const RadiusExplainPage = lazy(async () => ({ default: (await import("./pages/RadiusExplainPage")).RadiusExplainPage }));
const ConfigPage = lazy(async () => ({ default: (await import("./pages/ConfigPage")).ConfigPage }));
const AboutPage = lazy(async () => ({ default: (await import("./pages/AboutPage")).AboutPage }));

function queryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 5_000 },
    },
  });
}

function SkipLink() {
  return (
    <a className="skip-link" href="#app-main">
      Skip to main content
    </a>
  );
}

function StreamPill() {
  const { hasScope } = useAuth();
  const stream = useEventStream();
  if (!hasScope("events:read")) {
    return (
      <span className="stream-pill stream-pill--off" role="status">
        stream off
      </span>
    );
  }
  const live = stream.connected;
  const wait = stream.reconnecting;
  return (
    <span
      className={`stream-pill ${live ? "stream-pill--live" : wait ? "stream-pill--wait" : "stream-pill--off"}`}
      role="status"
    >
      {live ? "stream live" : wait ? "stream reconnecting" : "stream off"}
    </span>
  );
}

function HeaderTools() {
  const { state, logout } = useAuth();
  if (state.status !== "signed_in") {
    return null;
  }
  return (
    <div className="chrome-tools">
      <StreamPill />
      {state.session.token_id !== "" ? <span className="operator-pill">{state.session.token_id}</span> : null}
      <button type="button" className="sign-out" onClick={() => void logout()}>
        Sign out
      </button>
    </div>
  );
}

function NavRail() {
  const { hasScope } = useAuth();
  return (
    <aside className="rail">
      {NAV_GROUPS.map((group) => {
        const items = visibleNavItems(group, hasScope);
        if (items.length === 0) {
          return null;
        }
        return (
          <nav key={group.id} className="rail__group" aria-label={group.label}>
            <h2 className="rail__heading">{group.label}</h2>
            <ul className="rail__list">
              {items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end ?? item.to === "/"}
                    className={({ isActive }) => (isActive ? "nav-active" : undefined)}
                    aria-label={item.accessibleName}
                  >
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        );
      })}
    </aside>
  );
}

export function Shell() {
  const { state } = useAuth();
  const signedIn = state.status === "signed_in";
  const frame = (
    <div className={signedIn ? "app app--signed" : "app"}>
      <SkipLink />
      <header className="topbar">
        <NavLink className="brand" to={signedIn ? "/" : "/login"}>
          <span className="brand__dot" aria-hidden="true" />
          TacLab
        </NavLink>
        {signedIn ? <HeaderTools /> : null}
      </header>
      {signedIn ? <NavRail /> : null}
      <div id="app-main">
        <Suspense
          fallback={
            <main className="page">
              <p role="status">Loading page…</p>
            </main>
          }
        >
          <Outlet />
        </Suspense>
      </div>
    </div>
  );
  if (!signedIn) {
    return frame;
  }
  return <EventStreamProvider>{frame}</EventStreamProvider>;
}

function RequireSession() {
  const { state } = useAuth();
  if (state.status === "loading") {
    return (
      <main className="page">
        <p role="status">Checking session…</p>
      </main>
    );
  }
  if (state.status !== "signed_in") {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}

function RedirectIfSignedIn() {
  const { state } = useAuth();
  if (state.status === "loading") {
    return (
      <main className="page">
        <p role="status">Checking session…</p>
      </main>
    );
  }
  if (state.status === "signed_in") {
    return <Navigate to="/" replace />;
  }
  return <Outlet />;
}

export function App() {
  const [client] = useState(queryClient);
  return (
    <QueryClientProvider client={client}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route element={<Shell />}>
              <Route element={<RedirectIfSignedIn />}>
                <Route path="/login" element={<LoginPage />} />
              </Route>
              <Route element={<RequireSession />}>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/groups" element={<GroupsPage />} />
                <Route path="/clients" element={<ClientsPage />} />
                <Route path="/radius-sessions" element={<RadiusSessionsPage />} />
                <Route path="/radius-attributes" element={<RadiusAttributesPage />} />
                <Route path="/tokens" element={<TokensPage />} />
                <Route path="/events" element={<EventsPage />} />
                <Route path="/auth-test" element={<AuthTestPage />} />
                <Route path="/radius-auth-test" element={<RadiusAuthTestPage />} />
                <Route path="/explain" element={<PolicyExplainPage />} />
                <Route path="/radius-explain" element={<RadiusExplainPage />} />
                <Route path="/config" element={<ConfigPage />} />
                <Route path="/about" element={<AboutPage />} />
              </Route>
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
