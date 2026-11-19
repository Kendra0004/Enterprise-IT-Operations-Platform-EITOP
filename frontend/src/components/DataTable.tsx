import type { ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  /** Query-param field name when this column is sortable. */
  sortField?: string;
  /** Accessible sort label (defaults to header) — keeps "Sort by hostname". */
  sortLabel?: string;
  className?: string;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  /** Accessible caption (screen readers; visually hidden). */
  caption: string;
  sort?: { field: string; order: "asc" | "desc" };
  onSort?: (field: string) => void;
  onRowClick?: (row: T) => void;
}

/**
 * Reusable table shell: semantic markup, sortable header buttons with
 * stable accessible names, hover/focus states, horizontal scroll wrapper.
 * Data, sorting and pagination stay server-side — this only renders.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  sort,
  onSort,
  onRowClick,
}: DataTableProps<T>) {
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface shadow-card">
      <table className="min-w-full text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="border-b border-line bg-raised text-left text-[11px] uppercase tracking-wider text-faint">
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col" className={`px-4 py-2.5 ${column.className ?? ""}`}>
                {column.sortField && onSort ? (
                  <button
                    type="button"
                    onClick={() => onSort(column.sortField!)}
                    aria-label={`Sort by ${column.sortLabel ?? column.header}`}
                    className="flex items-center gap-1 uppercase tracking-wider hover:text-ink"
                  >
                    {column.header}
                    <span
                      aria-hidden
                      className={
                        sort?.field === column.sortField
                          ? "text-accent"
                          : "text-line-strong"
                      }
                    >
                      {sort?.field === column.sortField
                        ? sort.order === "asc"
                          ? "▲"
                          : "▼"
                        : "↕"}
                    </span>
                  </button>
                ) : (
                  column.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rows.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={
                onRowClick
                  ? "cursor-pointer hover:bg-raised/70 focus-within:bg-raised/70"
                  : "hover:bg-raised/70"
              }
            >
              {columns.map((column) => (
                <td key={column.key} className={`px-4 py-2.5 ${column.className ?? ""}`}>
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
