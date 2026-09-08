// Theme persistence + toggle. The same-origin `theme-bootstrap.ts` module runs
// before the React entrypoint, so CSP can stay free of `unsafe-inline`.
const STORAGE_KEY = "tb:theme";

export type ThemePreference = "light" | "dark" | "system";

function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

/** What's actually painted right now — never "system", always resolved. */
export function getResolvedTheme(): "light" | "dark" {
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

/** The stored preference, defaulting to "system" when nothing was ever set. */
export function getStoredPreference(): ThemePreference {
  const raw = window.localStorage.getItem(STORAGE_KEY);
  return raw === "light" || raw === "dark" ? raw : "system";
}

/** Applies the saved preference without mutating storage. Kept separate from
 * `applyTheme` so the CSP-safe bootstrap can run before React mounts. */
export function initializeTheme(): void {
  try {
    const preference = getStoredPreference();
    const dark = preference === "dark" || (preference === "system" && systemPrefersDark());
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.classList.toggle("light", !dark);
  } catch {
    // Storage can be unavailable; CSS media defaults remain safe.
  }
}

export function applyTheme(preference: ThemePreference): void {
  if (preference === "system") {
    window.localStorage.removeItem(STORAGE_KEY);
  } else {
    window.localStorage.setItem(STORAGE_KEY, preference);
  }
  const dark = preference === "dark" || (preference === "system" && systemPrefersDark());
  document.documentElement.classList.toggle("dark", dark);
  document.documentElement.classList.toggle("light", !dark);
}

export function toggleTheme(): void {
  applyTheme(getResolvedTheme() === "dark" ? "light" : "dark");
}
