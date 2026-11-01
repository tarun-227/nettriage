import type { ReactNode } from "react";
import { useNow } from "../lib/live";
import { href, navigate } from "../lib/router";
import { WifiOff } from "./icons";

const SECTIONS = [
  { id: "samples", label: "Samples" },
  { id: "detects", label: "Catches" },
  { id: "security", label: "Security" },
  { id: "capture", label: "Capture" },
];

export function scrollToSection(id: string) {
  if (window.location.hash.replace(/^#/, "") !== "/" && window.location.hash !== "") {
    navigate("/");
    setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" }), 80);
    return;
  }
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}

export function TopBar({ children, home = false }: { children?: ReactNode; home?: boolean }) {
  const now = useNow();
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-bg/90 font-mono backdrop-blur">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-5 px-4 sm:px-6">
        <a href={href("/")} className="flex shrink-0 items-center gap-2.5 text-[13px] font-bold tracking-[0.22em] text-neon"
          onClick={() => window.scrollTo({ top: 0 })}>
          <span className="h-2 w-2 animate-pulse rounded-full bg-neon shadow-glow" />
          NETTRIAGE
        </a>
        {home ? (
          <nav className="hidden flex-1 items-center justify-center gap-1 lg:flex" aria-label="Sections">
            {SECTIONS.map((s) => (
              <button key={s.id} type="button" onClick={() => scrollToSection(s.id)}
                className="rounded px-3 py-1.5 text-[12px] uppercase tracking-[0.16em] text-muted transition-colors hover:bg-neon/10 hover:text-neon">
                {s.label}
              </button>
            ))}
          </nav>
        ) : (
          <div className="flex min-w-0 flex-1 items-center gap-3">{children}</div>
        )}
        <span className="hidden text-[12px] tabular-nums tracking-[0.12em] text-muted xl:inline" title="Local time in UTC">
          {now.toISOString().slice(11, 19)} UTC
        </span>
        <span className="hidden items-center gap-1.5 rounded border border-neon/40 px-2 py-0.5 text-[11px] tracking-[0.16em] text-neon md:inline-flex"
          title="NetTriage makes no outbound connections">
          <WifiOff size={12} /> OFFLINE
        </span>
        {home && (
          <button type="button" className="btn btn-primary hidden sm:inline-flex" onClick={() => scrollToSection("analyse")}>
            Analyse <kbd className="kbd text-[10px]">U</kbd>
          </button>
        )}
      </div>
    </header>
  );
}
