import type { ReactNode } from "react";

/** Consistent page heading: title, description and optional actions. */
export function PageHeader({
  title,
  description,
  actions,
  testId,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  testId?: string;
}) {
  return (
    <header
      className="flex flex-wrap items-start justify-between gap-3"
      data-testid={testId}
    >
      <div className="min-w-0">
        <h2 className="text-xl font-semibold tracking-tight text-ink">{title}</h2>
        {description && (
          <p className="mt-0.5 max-w-3xl text-sm text-muted">{description}</p>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}
