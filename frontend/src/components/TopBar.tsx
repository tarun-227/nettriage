import type { ReactNode } from "react";
import { href } from "../lib/router";
import { useTheme } from "../lib/theme";
import { Logo, Moon, Sun, WifiOff } from "./icons";

export function TopBar({ children }: { children?: ReactNode }) {
  const [theme, toggle] = useTheme();
  return (
    <header className="sticky top-0 z-20 border-b border-line bg-bg/85 backdrop-blur">
      <div className="flex h-14 items-center gap-4 px-4 sm:px-6">
        <a href={href("/")} className="flex shrink-0 items-center gap-2 font-semibold tracking-tight">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <Logo size={18} />
          </span>
          <span className="text-[15px]">NetTriage</span>
        </a>
        <div className="flex min-w-0 flex-1 items-center gap-3">{children}</div>
        <span className="hidden items-center gap-1.5 rounded-full border border-benign/30 bg-benign/10 px-2.5 py-1
          text-[12px] font-medium text-benign sm:inline-flex" title="NetTriage makes no outbound connections">
          <WifiOff size={13} /> Offline
        </span>
        <button type="button" className="btn px-2" onClick={toggle}
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
          {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
        </button>
      </div>
    </header>
  );
}
