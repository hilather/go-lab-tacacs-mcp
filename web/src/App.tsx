import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense, useState, type ReactNode } from "react";
import { BrowserRouter, NavLink, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthProvider";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";

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

function NavItem({ to, children }: { to: string; children: ReactNode }) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? "nav-active" : undefined)} end={to === "/"}>
      {children}
    </NavLink>
  );
}

function Shell() {
  const { state, hasScope, logout } = useAuth();
  const signedIn = state.status === "signed_in";
  return (
    <div className="app">
      <SkipLink />
      <header className="topbar">
        <NavLink className="brand" to="/">
          TacLab
        </NavLink>
        <nav aria-label="Primary">
          {signedIn ? (
            <>
              <NavItem to="/">Status</NavItem>
              {hasScope("state:read") ? <NavItem to="/users">Users</NavItem> : null}
              {hasScope("state:read") ? <NavItem to="/groups">Groups</NavItem> : null}
              {hasScope("state:read") ? <NavItem to="/clients">Clients</NavItem> : null}
              {hasScope("state:read") ? <NavItem to="/radius-sessions">RADIUS sessions</NavItem> : null}
              {hasScope("state:read") ? <NavItem to="/radius-attributes">RADIUS attributes</NavItem> : null}
              {hasScope("tokens:manage") ? <NavItem to="/tokens">Tokens</NavItem> : null}
              {hasScope("events:read") ? <NavItem to="/events">Events</NavItem> : null}
              {hasScope("policy:test") ? <NavItem to="/auth-test">Auth test</NavItem> : null}
              {hasScope("policy:test") ? <NavItem to="/radius-auth-test">RADIUS test</NavItem> : null}
              {hasScope("policy:test") ? <NavItem to="/explain">Explain</NavItem> : null}
              {hasScope("policy:test") ? <NavItem to="/radius-explain">RADIUS explain</NavItem> : null}
              {hasScope("state:read") ? <NavItem to="/config">Config</NavItem> : null}
              {hasScope("state:read") ? <NavItem to="/about">About</NavItem> : null}
              <button type="button" className="linkish" onClick={() => void logout()}>
                Sign out
              </button>
            </>
          ) : null}
        </nav>
      </header>
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
