import { HelpCircle, Monitor, Terminal } from "lucide-react";
import type { LucideIcon } from "lucide-react";

/**
 * OS glyph. lucide-react ships no vendor logos, so we use neutral device
 * metaphors — paired with the OS text in tables, never color-only.
 */
const ICONS: Record<string, { icon: LucideIcon; label: string }> = {
  windows: { icon: Monitor, label: "Windows" },
  linux: { icon: Terminal, label: "Linux" },
  macos: { icon: Monitor, label: "macOS" },
  other: { icon: HelpCircle, label: "Other OS" },
};

export function OsIcon({ os }: { os: string }) {
  const entry = ICONS[os] ?? ICONS.other;
  const Icon = entry.icon;
  return (
    <span
      role="img"
      aria-label={entry.label}
      title={entry.label}
      className="inline-flex items-center"
    >
      <Icon size={15} aria-hidden className="text-faint" />
    </span>
  );
}
