// Theme persistence + toggle. `index.html`'s inline script makes the *first
// paint* match this; everything after that (a user clicking the toggle) goes
// through here so the two never disagree about the storage key or its values.
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
