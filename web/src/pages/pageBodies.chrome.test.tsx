import type { ReactElement } from "react";
import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { AboutPage } from "./AboutPage";
import { AuthTestPage } from "./AuthTestPage";
import { ClientsPage } from "./ClientsPage";
import { ConfigPage } from "./ConfigPage";
import { DashboardPage } from "./DashboardPage";
import { GroupsPage } from "./GroupsPage";
import { LoginPage } from "./LoginPage";
import { PolicyExplainPage } from "./PolicyExplainPage";
import { RadiusAttributesPage } from "./RadiusAttributesPage";
import { RadiusAuthTestPage } from "./RadiusAuthTestPage";
import { RadiusExplainPage } from "./RadiusExplainPage";
import { RadiusSessionsPage } from "./RadiusSessionsPage";
import { TokensPage } from "./TokensPage";
import { UsersPage } from "./UsersPage";

function ok() {
  return json(
    200,
    envelope({
      instance_id: "lab",
      revision: 3,
      baseline_hash: "a",
      overlay_hash: "b",
      compiled_at: "2026-08-12T00:00:00Z",
      listeners: [],
      colocated_topology: false,
      users: 0,
      groups: 0,
      clients: 0,
      tokens: 0,
      version: "dev",
      commit: "abc",
      build_time: "now",
      go_version: "go1.24.5",
      ui_version: "0.0.0",
      schema_version: 2,
      tacacs_conformance: "RFC 8907",
      mcp_specification: "2026-07-28",
      protocols: {},
      items: [],
      view: "effective",
      yaml: "schema_version: 1\n",
      format: "yaml",
    }),
  );
}

const leftover: Array<{ name: string; route: string; ui: ReactElement; heading: string; signIn: boolean }> = [
  { name: "login", route: "/login", ui: <LoginPage />, heading: "Sign in to TacLab", signIn: false },
  { name: "status", route: "/", ui: <DashboardPage />, heading: "Status", signIn: true },
  { name: "users", route: "/users", ui: <UsersPage />, heading: "Users", signIn: true },
  { name: "groups", route: "/groups", ui: <GroupsPage />, heading: "Groups", signIn: true },
  { name: "clients", route: "/clients", ui: <ClientsPage />, heading: "Clients", signIn: true },
  { name: "radius-sessions", route: "/radius-sessions", ui: <RadiusSessionsPage />, heading: "RADIUS sessions", signIn: true },
  { name: "radius-attributes", route: "/radius-attributes", ui: <RadiusAttributesPage />, heading: "RADIUS attributes", signIn: true },
  { name: "tokens", route: "/tokens", ui: <TokensPage />, heading: "API tokens", signIn: true },
  { name: "auth-test", route: "/auth-test", ui: <AuthTestPage />, heading: "Authentication test", signIn: true },
  { name: "radius-auth-test", route: "/radius-auth-test", ui: <RadiusAuthTestPage />, heading: "RADIUS authentication test", signIn: true },
  { name: "explain", route: "/explain", ui: <PolicyExplainPage />, heading: "Policy explain", signIn: true },
  { name: "radius-explain", route: "/radius-explain", ui: <RadiusExplainPage />, heading: "RADIUS policy explain", signIn: true },
  { name: "config", route: "/config", ui: <ConfigPage />, heading: "Config and runtime", signIn: true },
  { name: "about", route: "/about", ui: <AboutPage />, heading: "About", signIn: true },
];

describe("leftover page-body chrome", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it.each(leftover)("$name ($route) uses a muted lede on the page body", async ({ route, ui, heading, signIn }) => {
    if (signIn) {
      seedSession();
    }
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ok()),
    );
    renderApp(ui, { route });
    expect(await screen.findByRole("heading", { name: heading })).toBeInTheDocument();
    await waitFor(() => {
      expect(document.querySelector("main .lede")).toBeTruthy();
    });
  });
});
