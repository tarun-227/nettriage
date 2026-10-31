import { useEffect, useState } from "react";

export type Theme = "dark" | "light";
const KEY = "nettriage.theme";

function stored(): Theme {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === "light" ? "light" : "dark";
  } catch {
    return "dark"; // storage blocked (private window, strict settings): dark is the default anyway
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
