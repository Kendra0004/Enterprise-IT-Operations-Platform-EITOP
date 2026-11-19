/** Route → page title/breadcrumb metadata for the app header. */

import { useLocation } from "react-router-dom";

export interface Crumb {
  label: string;
  path?: string; // undefined = current page (no link)
}

export interface PageMeta {
  title: string;
  crumbs: Crumb[];
  /** Endpoint id when the route addresses a specific endpoint. */
  endpointId?: string;
}

const MODULE_TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/endpoints": "Endpoints",
  "/groups": "Endpoint Groups",
  "/active-directory": "Active Directory",
  "/security": "Security & Compliance",
  "/vulnerabilities": "Vulnerabilities",
  "/network": "Network",
  "/dns": "DNS Security",
  "/automation": "Automation",
  "/assets": "Assets",
  "/reports": "Reports",
  "/admin": "Administration",
};

export function usePageMeta(): PageMeta {
  const { pathname } = useLocation();

  const endpointMatch = pathname.match(
    /^\/endpoints\/([0-9a-fA-F-]{36})(\/history)?$/,
  );
  if (endpointMatch) {
    const isHistory = Boolean(endpointMatch[2]);
    return {
      title: isHistory ? "Inventory History" : "Endpoint Details",
      crumbs: isHistory
        ? [
            { label: "Endpoints", path: "/endpoints" },
            { label: "Endpoint", path: `/endpoints/${endpointMatch[1]}` },
            { label: "Inventory History" },
          ]
        : [{ label: "Endpoints", path: "/endpoints" }, { label: "Endpoint Details" }],
      endpointId: endpointMatch[1],
    };
  }

  const title = MODULE_TITLES[pathname] ?? "EITOP";
  return {
    title,
    crumbs:
      pathname === "/"
        ? [{ label: "Dashboard" }]
        : [{ label: "Dashboard", path: "/" }, { label: title }],
  };
}
