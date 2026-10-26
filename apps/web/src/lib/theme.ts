export type Theme = "light" | "dark";

const KEY = "phish-check:theme";

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "light" ? "#f2f2ef" : "#0b0b0c");
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Private windows can block storage; the choice still applies to this visit.
  }
}
