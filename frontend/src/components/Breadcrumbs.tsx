import { Link } from "react-router-dom";
import type { Crumb } from "../layout/pageMeta";

/** Breadcrumb trail rendered in the app header. */
export function Breadcrumbs({ crumbs }: { crumbs: Crumb[] }) {
  if (crumbs.length === 0) return null;
  return (
    <nav aria-label="Breadcrumbs" className="min-w-0">
      <ol className="flex flex-wrap items-center gap-1 text-xs text-faint">
        {crumbs.map((crumb, index) => {
          const isLast = index === crumbs.length - 1;
          return (
            <li key={`${crumb.label}-${index}`} className="flex items-center gap-1">
              {index > 0 && (
                <span aria-hidden className="text-line-strong">
                  /
                </span>
              )}
              {crumb.path && !isLast ? (
                <Link
                  to={crumb.path}
                  className="hover:text-accent hover:underline"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span aria-current={isLast ? "page" : undefined} className="text-muted">
                  {crumb.label}
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
