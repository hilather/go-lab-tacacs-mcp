export type NavItem = {
  to: string;
  label: string;
  accessibleName?: string;
  scope?: string;
  end?: boolean;
};

export type NavGroup = {
  id: string;
  label: string;
  items: readonly NavItem[];
};

export const NAV_GROUPS: readonly NavGroup[] = [
  {
    id: "lab",
    label: "Lab",
    items: [
      { to: "/", label: "Status", end: true },
      { to: "/events", label: "Events", scope: "events:read" },
      { to: "/config", label: "Config", scope: "state:read" },
      { to: "/tokens", label: "Tokens", scope: "tokens:manage" },
      { to: "/about", label: "About", scope: "state:read" },
    ],
  },
  {
    id: "directory",
    label: "Directory",
    items: [
      { to: "/users", label: "Users", scope: "state:read" },
      { to: "/groups", label: "Groups", scope: "state:read" },
      { to: "/clients", label: "Clients", scope: "state:read" },
    ],
  },
  {
    id: "tacacs",
    label: "TACACS+",
    items: [
      { to: "/auth-test", label: "Auth test", scope: "policy:test" },
      { to: "/explain", label: "Explain", accessibleName: "TACACS+ explain", scope: "policy:test" },
    ],
  },
  {
    id: "radius",
    label: "RADIUS",
    items: [
      { to: "/radius-sessions", label: "Sessions", scope: "state:read" },
      { to: "/radius-auth-test", label: "Test", accessibleName: "RADIUS test", scope: "policy:test" },
      { to: "/radius-explain", label: "Explain", accessibleName: "RADIUS explain", scope: "policy:test" },
      { to: "/radius-attributes", label: "Attributes", scope: "state:read" },
    ],
  },
];

export function visibleNavItems(group: NavGroup, hasScope: (scope: string) => boolean): NavItem[] {
  return group.items.filter((item) => item.scope === undefined || hasScope(item.scope));
}
