import { createSignal } from "solid-js";

export type Theme = "light" | "dark" | "system";

const STORAGE_KEY = "ocidex-theme";

function getSystemTheme(): "light" | "dark" {
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function getInitialTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
  return stored ?? "system";
}

function applyTheme(pref: Theme) {
  const resolved = pref === "system" ? getSystemTheme() : pref;
  document.documentElement.classList.toggle("light", resolved === "light");
  document.documentElement.classList.toggle("dark", resolved === "dark");
}

const [theme, setThemeInternal] = createSignal<Theme>(getInitialTheme());

// Apply on load
applyTheme(theme());

// Listen for system theme changes
window
  .matchMedia("(prefers-color-scheme: dark)")
  .addEventListener("change", () => {
    if (theme() === "system") {
      applyTheme("system");
    }
  });

export function setTheme(t: Theme) {
  setThemeInternal(t);
  localStorage.setItem(STORAGE_KEY, t);
  applyTheme(t);
}

export { theme };

export function resolvedTheme(): "light" | "dark" {
  const t = theme();
  return t === "system" ? getSystemTheme() : t;
}
