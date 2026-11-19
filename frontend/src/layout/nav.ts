import {
  Activity,
  AppWindow,
  BarChart3,
  Bot,
  FolderTree,
  LayoutDashboard,
  Network,
  ScanSearch,
  Server,
  ShieldCheck,
  ShieldAlert,
  Users,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
  /** Permission required to see the item (undefined = always visible). */
  permission?: string;
  /**
   * True for modules that route to an honest "under development" page —
   * rendered muted so they are never mistaken for operational features.
   */
  preview?: boolean;
}

/** Modules that exist as routes today. Live features first, previews after. */
export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", path: "/", icon: LayoutDashboard },
  {
    label: "Endpoints",
    path: "/endpoints",
    icon: Server,
    permission: "endpoints:read",
  },
  {
    label: "Endpoint Groups",
    path: "/groups",
    icon: FolderTree,
    permission: "endpoints:read",
  },
  { label: "Administration", path: "/admin", icon: Users, permission: "admin:read", preview: true },

  // --- Preview modules (Phase 1 placeholders; not operational features) ---
  { label: "Active Directory", path: "/active-directory", icon: ShieldCheck, permission: "endpoints:read", preview: true },
  { label: "Security & Compliance", path: "/security", icon: ShieldAlert, permission: "security:read", preview: true },
  { label: "Vulnerabilities", path: "/vulnerabilities", icon: ScanSearch, permission: "vulns:read", preview: true },
  { label: "Network", path: "/network", icon: Network, permission: "network:read", preview: true },
  { label: "DNS Security", path: "/dns", icon: Activity, permission: "network:read", preview: true },
  { label: "Automation", path: "/automation", icon: Bot, permission: "automation:read", preview: true },
  { label: "Assets", path: "/assets", icon: AppWindow, permission: "assets:read", preview: true },
  { label: "Reports", path: "/reports", icon: BarChart3, permission: "reports:read", preview: true },
];
