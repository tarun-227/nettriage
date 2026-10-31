// Concept 4 · Amber terminal: a keyboard-first tool for power users. Amber on dark, a tilted 3D CRT, a live log.
import { useEffect, useState } from "react";
import { ErrorToast, GalleryLink, useAnalyse } from "./shared";

const LOG = [
  { t: "$ nettriage analyze office.pcap", c: "text-[#FFB000]" },
  { t: "  2,891 packets · 60 s · 8 devices", c: "text-[#B98A2E]" },
  { t: "[ATTACK 100%] 08:00:27:3e:5a:11 impersonating router", c: "text-[#FF5A3C]" },
  { t: "[FAULT   99%] DNS failing at 192.168.1.1", c: "text-[#FFD27A]" },
  { t: "[OK      94%] router failover ruled out", c: "text-[#9BE37A]" },
  { t: "  evidence.pcap written · 78 frames", c: "text-[#B98A2E]" },
];

function useTyped() {
  const [line, setLine] = useState(0);
  const [chars, setChars] = useState(0);
  useEffect(() => {
    if (line >= LOG.length) {
      const id = setTimeout(() => { setLine(0); setChars(0); }, 2600);
      return () => clearTimeout(id);
    }
    const full = LOG[line].t.length;
    const id = setTimeout(() => {
      if (chars < full) setChars(chars + 1);
      else { setLine(line + 1); setChars(0); }
    }, chars < full ? 22 : 420);
    return () => clearTimeout(id);
  }, [line, chars]);
  return { line, chars };
}

export function TerminalConcept() {
  const a = useAnalyse();
  const { line, chars } = useTyped();
  const { pickFile, randomSample } = a;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key.toLowerCase() === "u") pickFile();
      if (e.key.toLowerCase() === "s") randomSample();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pickFile, randomSample]);

  return (
    <div {...a.dropProps} className="min-h-full bg-[#120C02] font-mono text-[#FFB000]">
      <header className="flex items-center justify-between px-6 py-4 text-[12px]">
        <span>nettriage@localhost:~</span>
        <GalleryLink className="text-[#B98A2E] hover:text-[#FFB000]" />
      </header>
      <main className="mx-auto flex max-w-5xl flex-col items-center px-6 pb-16">
        <div className="mt-6 w-full [perspective:1400px]">
          <div className="relative mx-auto aspect-[16/10] w-full max-w-3xl rounded-[28px] border-[14px] border-[#2A1F0C] bg-[#1A1105] p-6
            shadow-[0_40px_80px_-30px_rgba(0,0,0,0.9),0_0_80px_rgba(255,176,0,0.12)]"
            style={{ transform: "rotateY(-12deg) rotateX(5deg)", animation: "dc-flicker 4s infinite" }}>
            <div className="h-full overflow-hidden rounded-xl text-[clamp(11px,1.6vw,15px)] leading-relaxed [text-shadow:0_0_8px_rgba(255,176,0,0.55)]">
              {LOG.slice(0, line).map((l) => <p key={l.t} className={l.c}>{l.t}</p>)}
              {line < LOG.length && (
                <p className={LOG[line].c}>
                  {LOG[line].t.slice(0, chars)}
                  <span className="ml-0.5 inline-block h-[1em] w-[0.6em] translate-y-[2px] bg-[#FFB000]" style={{ animation: "dc-caret 1s steps(1) infinite" }} />
                </p>
              )}
            </div>
            <div className="dc-scanlines pointer-events-none absolute inset-6 rounded-xl" />
          </div>
        </div>

        <div className={`mt-12 grid w-full max-w-3xl gap-3 sm:grid-cols-2 ${a.over ? "opacity-60" : ""}`}>
          <button type="button" onClick={pickFile} disabled={a.busy}
            className="flex items-center gap-4 rounded-lg border border-[#FFB000]/40 px-5 py-4 text-left hover:bg-[#FFB000]/10">
            <kbd className="rounded border border-[#FFB000] px-2.5 py-1 text-[16px] font-bold">U</kbd>
            <span><span className="block text-[16px] font-bold">{a.busy ? "running..." : "upload"}</span>
              <span className="text-[12px] text-[#B98A2E]">or drop a .pcap</span></span>
          </button>
          <button type="button" onClick={() => randomSample()} disabled={a.busy}
            className="flex items-center gap-4 rounded-lg border border-[#FFB000]/40 px-5 py-4 text-left hover:bg-[#FFB000]/10">
            <kbd className="rounded border border-[#FFB000] px-2.5 py-1 text-[16px] font-bold">S</kbd>
            <span><span className="block text-[16px] font-bold">sample</span>
              <span className="text-[12px] text-[#B98A2E]">random demo capture</span></span>
          </button>
        </div>
      </main>
      {a.fileInput}
      <ErrorToast text={a.error} onClose={a.clearError} className="rounded-lg border border-[#FF5A3C] bg-[#1A1105] font-mono text-[#FF8A70]" />
    </div>
  );
}
