import type { ReactNode } from "react";
import { useNow } from "../lib/live";
import { href } from "../lib/router";
import { WifiOff } from "./icons";

// The plain console header used while an analysis is loading, running or has failed.
export function TopBar({ children }: { children?: ReactNode }) {
  const now = useNow();
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-bg/90 font-mono backdrop-blur">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-5 px-4 sm:px-6">
        <a href={href("/app")} className="flex shrink-0 items-center gap-2.5 text-[13px] font-bold tracking-[0.22em] text-neon">
          <span className="h-2 w-2 animate-pulse rounded-full bg-neon shadow-glow" />
          NETTRIAGE
        </a>
        <div className="flex min-w-0 flex-1 items-center gap-3">{children}</div>
        <span className="hidden text-[12px] tabular-nums tracking-[0.12em] text-muted xl:inline" title="Local time in UTC">
          {now.toISOString().slice(11, 19)} UTC
        </span>
        <span className="hidden items-center gap-1.5 rounded border border-neon/40 px-2 py-0.5 text-[11px] tracking-[0.16em] text-neon md:inline-flex"
          title="NetTriage makes no outbound connections">
          <WifiOff size={12} /> OFFLINE
        </span>
      </div>
    </header>
  );
}
