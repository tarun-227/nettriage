import { useSyncExternalStore } from "react";

// A tiny hash router: #/ , #/a/<job>/<tab>, #/a/<job>/findings/<finding>.
// Hash routes need no server configuration and keep the app a single static page.

function subscribe(cb: () => void) {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
}

const current = () => window.location.hash.replace(/^#/, "") || "/";

export function useRoute(): string[] {
  const path = useSyncExternalStore(subscribe, current);
  return path.split("/").filter(Boolean).map((p) => decodeURIComponent(p));
}

export function navigate(path: string) {
  if (current() !== path) window.location.hash = path;
}

export const href = (path: string) => `#${path}`;
