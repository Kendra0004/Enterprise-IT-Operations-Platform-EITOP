/**
 * Placeholder for modules not yet implemented.
 *
 * Deliberately shows NO fake data or invented statistics — only an honest
 * "under development" state, per project quality rules.
 */
interface Props {
  moduleName: string;
}

export function UnderDevelopment({ moduleName }: Props) {
  return (
    <div className="mx-auto max-w-2xl" data-testid="under-development">
      <h1 className="mb-2 text-2xl font-semibold">{moduleName}</h1>
      <div className="mt-6 rounded-lg border border-dashed border-slate-700 bg-slate-900 p-8 text-center">
        <p className="text-lg font-medium text-amber-400">Under development</p>
        <p className="mt-2 text-sm text-slate-400">
          This module has not been implemented yet. No data is shown because
          there is no real backend integration for it in this release.
        </p>
        <p className="mt-4 text-xs text-slate-500">
          See the project roadmap for planned delivery phases.
        </p>
      </div>
    </div>
  );
}
