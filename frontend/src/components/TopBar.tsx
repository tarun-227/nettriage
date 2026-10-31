import type { ReactNode } from "react";
import { href, navigate } from "../lib/router";
import { useTheme } from "../lib/theme";
import { Logo, Moon, Sun, WifiOff } from "./icons";

const SECTIONS = [
  { id: "how", label: "How it works" },
  { id: "detects", label: "What it finds" },
  { id: "samples", label: "Samples" },
  { id: "security", label: "Security" },
  { id: "capture", label: "Make a capture" },
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
  const [theme, toggle] = useTheme();
  return (
    <header className="sticky top-0 z-30 border-b border-white/10 bg-navy text-white shadow-[0_1px_0_rgba(201,162,39,0.25)]">
      <div className="mx-auto flex h-16 max-w-[1400px] items-center gap-5 px-4 sm:px-6">
        <a href={href("/")} className="flex shrink-0 items-center gap-2.5" onClick={() => window.scrollTo({ top: 0 })}>
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-white/10 text-gold ring-1 ring-gold/40">
            <Logo size={20} />
          </span>
          <span className="leading-tight">
            <span className="display block text-[18px] font-semibold">NetTriage</span>
            <span className="hidden text-[10.5px] uppercase tracking-[0.18em] text-white/60 sm:block">Network diagnosis</span>
          </span>
        </a>
        {home ? (
          <nav className="hidden flex-1 items-center justify-center gap-1 lg:flex" aria-label="Sections">
            {SECTIONS.map((s) => (
              <button key={s.id} type="button" onClick={() => scrollToSection(s.id)}
                className="rounded-lg px-3 py-1.5 text-[13px] font-medium text-white/75 transition-colors hover:bg-white/10 hover:text-white">
                {s.label}
              </button>
            ))}
          </nav>
        ) : (
          <div className="flex min-w-0 flex-1 items-center gap-3">{children}</div>
        )}
        <span className="hidden items-center gap-1.5 rounded-full border border-gold/40 bg-gold/10 px-2.5 py-1 text-[12px]
          font-medium text-[#f0d88a] md:inline-flex" title="NetTriage makes no outbound connections">
          <WifiOff size={13} /> Offline
        </span>
        <button type="button" onClick={toggle}
          className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/20 text-white/80 transition-colors hover:border-gold/60 hover:text-gold"
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
          {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        {home && (
          <button type="button" className="btn btn-gold hidden sm:inline-flex" onClick={() => scrollToSection("analyse")}>
            Analyse a capture
          </button>
        )}
      </div>
    </header>
  );
}
