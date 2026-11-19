import { useEffect, useRef, useState } from "react";
import { Search, X } from "lucide-react";

/**
 * Debounced search box. The value reaches the consumer `delay` ms after the
 * user stops typing (default 350 ms) — one API request per pause, not per
 * keystroke. An explicit Enter/submit flushes immediately.
 */
export function SearchInput({
  value,
  onSearch,
  label = "Search",
  placeholder = "Search…",
  delay = 350,
  testId,
}: {
  value: string;
  onSearch: (value: string) => void;
  label?: string;
  placeholder?: string;
  delay?: number;
  testId?: string;
}) {
  const [draft, setDraft] = useState(value);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const latest = useRef(onSearch);
  latest.current = onSearch;

  // External resets (e.g. Clear filters) sync into the draft.
  useEffect(() => setDraft(value), [value]);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  function push(next: string, immediate = false) {
    setDraft(next);
    if (timer.current) clearTimeout(timer.current);
    if (immediate) {
      latest.current(next.trim());
      return;
    }
    timer.current = setTimeout(() => latest.current(next.trim()), delay);
  }

  return (
    <form
      role="search"
      className="flex items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        push(draft, true);
      }}
    >
      <label className="flex flex-col gap-1 text-xs text-muted">
        {label}
        <span className="relative block">
          <Search
            size={14}
            aria-hidden
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint"
          />
          <input
            type="search"
            value={draft}
            onChange={(e) => push(e.target.value)}
            placeholder={placeholder}
            data-testid={testId}
            className="w-full rounded-md border border-line-strong bg-surface py-1.5 pl-8 pr-8 text-sm text-ink placeholder:text-faint focus:border-accent"
          />
          {draft && (
            <button
              type="button"
              aria-label={`Clear ${label.toLowerCase()}`}
              onClick={() => push("", true)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-faint hover:text-ink"
            >
              <X size={13} aria-hidden />
            </button>
          )}
        </span>
      </label>
    </form>
  );
}
