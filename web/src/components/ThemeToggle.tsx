import { theme, setTheme, type Theme } from "~/utils/theme";

const CYCLE: Theme[] = ["dark", "system", "light"];

export default function ThemeToggle() {
  const next = () => {
    const idx = CYCLE.indexOf(theme());
    setTheme(CYCLE[(idx + 1) % CYCLE.length]);
  };

  const label = () => {
    switch (theme()) {
      case "dark":
        return "Dark";
      case "light":
        return "Light";
      case "system":
        return "System";
    }
  };

  return (
    <button
      onClick={next}
      aria-label={`Theme: ${label()}. Click to switch.`}
      class="theme-toggle"
    >
      {/* Moon icon */}
      <svg
        class="theme-icon"
        classList={{ active: theme() === "dark" }}
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <path d="M14 8.5A6 6 0 117.5 2a4.5 4.5 0 006.5 6.5z" />
      </svg>
      {/* Monitor icon */}
      <svg
        class="theme-icon"
        classList={{ active: theme() === "system" }}
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <rect x="1.5" y="2" width="13" height="9" rx="1.5" />
        <path d="M5.5 14h5M8 11v3" />
      </svg>
      {/* Sun icon */}
      <svg
        class="theme-icon"
        classList={{ active: theme() === "light" }}
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <circle cx="8" cy="8" r="3" />
        <path d="M8 1.5v1M8 13.5v1M2.75 2.75l.7.7M12.55 12.55l.7.7M1.5 8h1M13.5 8h1M2.75 13.25l.7-.7M12.55 3.45l.7-.7" />
      </svg>
    </button>
  );
}
