export interface NavItem {
  label: string;
  path: string;
  /** Permission required to see the item (undefined = always visible). */
  permission?: string;
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", path: "/" },
  { label: "Endpoints", path: "/endpoints", permission: "endpoints:read" },
  { label: "Active Directory", path: "/active-directory", permission: "endpoints:read" },
  { label: "Security & Compliance", path: "/security", permission: "security:read" },
  { label: "Vulnerabilities", path: "/vulnerabilities", permission: "vulns:read" },
  { label: "Network", path: "/network", permission: "network:read" },
  { label: "DNS Security", path: "/dns", permission: "network:read" },
  { label: "Automation", path: "/automation", permission: "automation:read" },
  { label: "Assets", path: "/assets", permission: "assets:read" },
  { label: "Reports", path: "/reports", permission: "reports:read" },
  { label: "Administration", path: "/admin", permission: "admin:read" },
];
