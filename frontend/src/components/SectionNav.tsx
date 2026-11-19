/**
 * In-page section navigation (tab styling, anchor semantics).
 *
 * The endpoint detail page keeps every section mounted — tests and deep
 * links see all content — while this control gives a compact tab bar that
 * scrolls to the section.
 */

const LINK =
  "rounded-md px-3 py-1.5 text-sm transition-colors border border-transparent";

export function SectionNav({
  sections,
  active,
  onSelect,
  label = "Page sections",
}: {
  sections: { id: string; label: string }[];
  active: string;
  onSelect: (id: string) => void;
  label?: string;
}) {
  return (
    <nav aria-label={label} className="flex flex-wrap gap-1 border-b border-line">
      {sections.map((section) => {
        const isActive = section.id === active;
        return (
          <button
            key={section.id}
            type="button"
            aria-current={isActive ? "true" : undefined}
            onClick={() => onSelect(section.id)}
            className={`${LINK} -mb-px rounded-b-none ${
              isActive
                ? "border-line bg-surface font-medium text-accent"
                : "text-muted hover:bg-raised hover:text-ink"
            }`}
          >
            {section.label}
          </button>
        );
      })}
    </nav>
  );
}
