/**
 * Placeholder for modules not yet implemented.
 *
 * Deliberately shows NO fake data or invented statistics — only an honest
 * "under development" state, per project quality rules.
 */
import { Construction } from "lucide-react";

interface Props {
  moduleName: string;
}

export function UnderDevelopment({ moduleName }: Props) {
  return (
    <div className="mx-auto max-w-2xl" data-testid="under-development">
      <h1 className="mb-2 text-2xl font-semibold text-ink">{moduleName}</h1>
      <div className="mt-6 rounded-lg border border-dashed border-line-strong bg-surface p-8 text-center shadow-card">
        <Construction
          size={22}
          aria-hidden
          className="mx-auto text-warn"
        />
        <p className="mt-2 text-lg font-medium text-warn">Under development</p>
        <p className="mt-2 text-sm text-muted">
          This module has not been implemented yet. No data is shown because
          there is no real backend integration for it in this release.
        </p>
        <p className="mt-4 text-xs text-faint">
          See the project roadmap for planned delivery phases.
        </p>
      </div>
    </div>
  );
}
