import { useEffect, useState } from "react";

export type Theme = "dark" | "light";
const KEY = "nettriage.theme";

function stored(): Theme {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === "dark" ? "dark" : "light";
  } catch {
    return "light"; // storage blocked (private window, strict settings): light is the default anyway
  }
}

export function applyStoredTheme() {
  document.documentElement.dataset.theme = stored();
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(stored);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem(KEY, theme);
    } catch {
      /* preference just won't persist */
    }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}
