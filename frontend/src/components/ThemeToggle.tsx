import { Moon, Sun } from "lucide-react";
import { useTheme } from "../theme/ThemeProvider";

/** Dark/light switch. Accessible name reflects the action, not the state. */
export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className="rounded-md border border-line p-2 text-muted transition-colors hover:bg-raised hover:text-ink"
    >
      {theme === "dark" ? <Sun size={15} aria-hidden /> : <Moon size={15} aria-hidden />}
    </button>
  );
}
