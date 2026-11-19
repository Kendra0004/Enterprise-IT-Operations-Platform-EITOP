import type { ReactNode } from "react";

/** Consistent toolbar wrapper for list-page filters. */
export function FilterBar({
  children,
  onClear,
  showClear,
  label = "Filters",
}: {
  children: ReactNode;
  onClear?: () => void;
  showClear?: boolean;
  label?: string;
}) {
  return (
    <section
      aria-label={label}
      className="rounded-lg border border-line bg-surface p-3 shadow-card"
    >
      <div className="flex flex-wrap items-end gap-3">
        {children}
        {showClear && onClear && (
          <button
            type="button"
            onClick={onClear}
            className="rounded-md border border-line px-3 py-1.5 text-sm text-muted hover:bg-raised hover:text-ink"
          >
            Clear filters
          </button>
        )}
      </div>
    </section>
  );
}

/** Labeled select used inside FilterBar (label text is the accessible name). */
export function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink focus:border-accent"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}
