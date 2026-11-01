// The console's signature pieces: a 3D radar dish (also the drop target), a tilted CRT that types out
// a log, keyboard-key buttons and a scrolling ticker. Plain CSS 3D, no libraries, nothing from the network.
import type { ReactNode } from "react";
import { useTyped } from "../lib/live";

type Tone = "neon" | "attack" | "fault";
type Blip = { x: number; y: number; d: number; tone?: Tone };

const BLIPS: Blip[] = [
  { x: 68, y: 30, d: 0.4, tone: "attack" }, { x: 30, y: 38, d: 1.6 }, { x: 58, y: 72, d: 2.3, tone: "fault" },
  { x: 22, y: 64, d: 1.1, tone: "attack" }, { x: 78, y: 58, d: 0.9 },
];

const rgb = (tone: Tone, a = 1) => `rgb(var(--${tone}) / ${a})`;

export function RadarDish({ tone = "neon", blips = BLIPS, active = false, className = "", children }: {
  tone?: Tone; blips?: Blip[]; active?: boolean; className?: string; children?: ReactNode;
}) {
  return (
    <div className={`relative aspect-square [perspective:900px] ${className}`}>
      <div className="preserve-3d absolute inset-0" style={{ transform: "rotateX(56deg)" }}>
        {[100, 76, 52, 28].map((s, i) => (
          <div key={s} className="absolute left-1/2 top-1/2 rounded-full border transition-colors"
            style={{
              width: `${s}%`, height: `${s}%`, transform: `translate(-50%, -50%) translateZ(${i * 10}px)`,
              borderColor: rgb(tone, active ? 1 : 0.32),
              boxShadow: i === 0 ? `0 0 60px ${rgb(tone, 0.25)}, inset 0 0 60px ${rgb(tone, 0.12)}` : undefined,
            }} />
        ))}
        <div className="absolute inset-0 rounded-full"
          style={{ background: `conic-gradient(from 0deg, ${rgb(tone, 0.55)}, ${rgb(tone, 0)} 22%)`, animation: "dc-spin 3.2s linear infinite" }} />
        <div className="absolute left-1/2 top-0 h-full w-px" style={{ background: rgb(tone, 0.2) }} />
        <div className="absolute left-0 top-1/2 h-px w-full" style={{ background: rgb(tone, 0.2) }} />
        {blips.map((b, i) => (
          <span key={i} className="absolute h-[3.2%] w-[3.2%] rounded-full"
            style={{ left: `${b.x}%`, top: `${b.y}%`, background: rgb(b.tone ?? tone), boxShadow: `0 0 16px ${rgb(b.tone ?? tone)}`,
              animation: `dc-blip 3.2s ease-out ${b.d}s infinite` }} />
        ))}
      </div>
      {children}
    </div>
  );
}

export type LogLine = { t: string; c: string };

// A CRT monitor, turned slightly in 3D, that types `lines` out and loops.
export function CrtLog({ lines, texts, className = "" }: { lines: LogLine[]; texts: readonly string[]; className?: string }) {
  const { line, chars } = useTyped(texts);
  return (
    <div className={`[perspective:1400px] ${className}`} aria-hidden="true">
      <div className="relative rounded-[22px] border-[10px] border-[#132320] bg-[#060E0A] p-4 sm:p-5
        shadow-[0_40px_80px_-30px_rgba(0,0,0,0.95),0_0_70px_-10px_rgba(43,255,136,0.18)]"
        style={{ transform: "rotateY(9deg) rotateX(4deg)", animation: "dc-flicker 4s infinite" }}>
        <div className="mb-3 flex gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-attack/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-neon/80" />
        </div>
        <div className="h-[10.5em] overflow-hidden font-mono text-[clamp(10.5px,1.15vw,13.5px)] leading-[1.75] [text-shadow:0_0_8px_currentColor]">
          {lines.slice(0, line).map((l) => <p key={l.t} className={`truncate ${l.c}`}>{l.t}</p>)}
          {line < lines.length && (
            <p className={`truncate ${lines[line].c}`}>
              {lines[line].t.slice(0, chars)}
              <span className="ml-0.5 inline-block h-[1em] w-[0.55em] translate-y-[2px] bg-neon" style={{ animation: "dc-caret 1s steps(1) infinite" }} />
            </p>
          )}
        </div>
        <div className="scanlines pointer-events-none absolute inset-0 rounded-xl" />
      </div>
    </div>
  );
}

export function KeyButton({ k, title, sub, onClick, disabled }: {
  k: string; title: string; sub: string; onClick: () => void; disabled?: boolean;
}) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} aria-keyshortcuts={k}
      className="group flex items-center gap-4 rounded-lg border border-neon/35 bg-surface/80 px-5 py-4 text-left font-mono transition-all
        hover:-translate-y-0.5 hover:border-neon hover:bg-neon/10 hover:shadow-glow disabled:cursor-wait disabled:opacity-60">
      <kbd className="kbd text-[17px] text-neon">{k}</kbd>
      <span className="min-w-0">
        <span className="block text-[16px] font-bold text-white">{title}</span>
        <span className="block truncate text-[12px] text-muted">{sub}</span>
      </span>
    </button>
  );
}

export type Tick = { t: string; v: string; c: string };

export function Ticker({ items, label }: { items: Tick[]; label: string }) {
  const loop = [...items, ...items];
  return (
    <div className="flex items-stretch overflow-hidden border-y border-line bg-surface/80 font-mono text-[12px] tracking-[0.14em]">
      <span className="z-10 flex shrink-0 items-center gap-2 border-r border-line bg-surface px-4 text-neon">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-neon" /> {label}
      </span>
      <div className="min-w-0 flex-1 overflow-hidden" aria-hidden="true">
        <div className="flex w-max gap-10 py-2.5 pl-6" style={{ animation: "dc-marquee 45s linear infinite" }}>
          {loop.map((x, i) => (
            <span key={i} className="flex items-center gap-2 whitespace-nowrap">
              <span className="text-ink/80">{x.t}</span>
              <span className="text-muted">▸</span>
              <span className={`font-bold ${x.c}`}>{x.v}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// "Section header" in console style: `> name` with an optional count.
export function Prompt({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <h2 className="font-mono text-[clamp(22px,3vw,30px)] font-bold tracking-tight text-white">
        <span className="text-neon">&gt;</span> {children}
        <span className="ml-1 inline-block h-[0.9em] w-[0.5em] translate-y-[3px] bg-neon/80" style={{ animation: "dc-caret 1.1s steps(1) infinite" }} />
      </h2>
      {right}
    </div>
  );
}
