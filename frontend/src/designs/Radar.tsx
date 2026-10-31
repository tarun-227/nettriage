// Concept 1 · Radar: mission control. Black, neon green, one big target to drop on.
import { ErrorToast, GalleryLink, useAnalyse, useCycle, useNow } from "./shared";

const TICKER = [
  { t: "ARP SPOOFING", v: "ATTACK", c: "text-[#FF3B5C]" },
  { t: "DNS TIMEOUTS", v: "FAULT", c: "text-[#FFC145]" },
  { t: "ROUTER FAILOVER", v: "RULED OUT", c: "text-[#2BFF88]" },
  { t: "PORT SCAN", v: "ATTACK", c: "text-[#FF3B5C]" },
  { t: "PACKET LOSS", v: "FAULT", c: "text-[#FFC145]" },
];
const BLIPS = [
  { x: 68, y: 30, d: 0.4, red: true }, { x: 30, y: 38, d: 1.6 }, { x: 58, y: 72, d: 2.3 },
  { x: 22, y: 64, d: 1.1, red: true }, { x: 78, y: 58, d: 0.9 },
];

export function RadarConcept() {
  const a = useAnalyse();
  const now = useNow();
  const tick = TICKER[useCycle(TICKER.length, 1700)];
  return (
    <div className="min-h-full bg-[#05080A] font-mono text-[#C8FFE0]">
      <header className="flex items-center justify-between px-6 py-4 text-[12px] tracking-[0.2em]">
        <span className="flex items-center gap-2 text-[#2BFF88]"><span className="h-2 w-2 animate-pulse rounded-full bg-[#2BFF88]" /> NETTRIAGE / RADAR</span>
        <span className="flex items-center gap-5 text-[#2BFF88]/70">
          <span>{now.toISOString().slice(11, 19)} UTC</span>
          <span className="rounded border border-[#2BFF88]/40 px-2 py-0.5">OFFLINE</span>
          <GalleryLink className="hover:text-[#2BFF88]" />
        </span>
      </header>

      <main className="flex flex-col items-center px-6 pb-16">
        <h1 className="mt-2 text-center text-[clamp(34px,6vw,64px)] font-bold tracking-[0.12em] text-white">DROP A CAPTURE</h1>
        <p className="mt-2 text-[13px] tracking-[0.35em] text-[#2BFF88]/80">FAULTS · ATTACKS · PROOF</p>

        <button type="button" onClick={a.pickFile} {...a.dropProps} disabled={a.busy} aria-label="Drop or choose a capture file"
          className="relative mt-6 aspect-square w-[min(520px,88vw)] [perspective:900px]">
          <div className="preserve-3d absolute inset-0" style={{ transform: "rotateX(56deg)" }}>
            {[100, 76, 52, 28].map((s, i) => (
              <div key={s} className={`absolute left-1/2 top-1/2 rounded-full border ${a.over ? "border-[#2BFF88]" : "border-[#2BFF88]/30"}`}
                style={{ width: `${s}%`, height: `${s}%`, transform: `translate(-50%, -50%) translateZ(${i * 10}px)`,
                  boxShadow: i === 0 ? "0 0 60px rgba(43,255,136,0.25), inset 0 0 60px rgba(43,255,136,0.12)" : undefined }} />
            ))}
            <div className="absolute inset-0 rounded-full"
              style={{ background: "conic-gradient(from 0deg, rgba(43,255,136,0.55), rgba(43,255,136,0) 22%)",
                animation: "dc-spin 3.2s linear infinite" }} />
            <div className="absolute left-1/2 top-0 h-full w-px bg-[#2BFF88]/20" />
            <div className="absolute left-0 top-1/2 h-px w-full bg-[#2BFF88]/20" />
            {BLIPS.map((b, i) => (
              <span key={i} className={`absolute h-3.5 w-3.5 rounded-full ${b.red ? "bg-[#FF3B5C] shadow-[0_0_16px_#FF3B5C]" : "bg-[#2BFF88] shadow-[0_0_14px_#2BFF88]"}`}
                style={{ left: `${b.x}%`, top: `${b.y}%`, animation: `dc-blip 3.2s ease-out ${b.d}s infinite` }} />
            ))}
          </div>
          <span className="absolute inset-x-0 bottom-[18%] text-center text-[13px] tracking-[0.3em] text-[#2BFF88]">
            {a.busy ? "ANALYSING..." : a.over ? "RELEASE TO SCAN" : "CLICK OR DROP .PCAP"}
          </span>
        </button>

        <div className="mt-6 flex h-10 items-center gap-3 rounded border border-[#2BFF88]/25 bg-[#0B1215] px-4 text-[13px] tracking-[0.15em]">
          <span className="text-[#2BFF88]/60">LIVE</span>
          <span key={tick.t} className="animate-[dc-caret_0.4s_steps(1)_1]">{tick.t}</span>
          <span className="text-[#2BFF88]/40">▸</span>
          <span className={`font-bold ${tick.c}`}>{tick.v}</span>
        </div>

        <div className="mt-10 flex flex-wrap justify-center gap-2">
          {a.featured.map((s) => (
            <button key={s.name} type="button" disabled={a.busy} onClick={() => a.sample(s.name)}
              className="rounded border border-[#2BFF88]/30 px-3 py-1.5 text-[12px] tracking-[0.12em] text-[#C8FFE0]/80 transition-colors hover:border-[#2BFF88] hover:bg-[#2BFF88]/10 hover:text-[#2BFF88]">
              {s.title.toUpperCase()}
            </button>
          ))}
        </div>
      </main>
      {a.fileInput}
      <ErrorToast text={a.error} onClose={a.clearError} className="rounded border border-[#FF3B5C] bg-[#0B1215] text-[#FFB3C0]" />
    </div>
  );
}
