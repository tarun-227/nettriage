// Concept 5 · Toy town: friendly for beginners. Pastels, chunky shapes, an isometric town where
// houses are devices and cars are packets.
import type { CSSProperties } from "react";
import { Box, type Faces } from "../components/Scene3D";
import { CheckCircle, ShieldAlert, Upload, Wrench } from "../components/icons";
import { ErrorToast, GalleryLink, useAnalyse } from "./shared";

const MINT: Faces = { top: "#7FEFC0", light: "#3DDC97", dark: "#25B377" };
const CORAL: Faces = { top: "#FF9A9A", light: "#FF6B6B", dark: "#E04848" };
const SKY: Faces = { top: "#8DBBFF", light: "#4D96FF", dark: "#2F74DB" };
const SUN: Faces = { top: "#FFE680", light: "#FFD93D", dark: "#E9B90E" };
const CREAM: Faces = { top: "#FFFFFF", light: "#F1E9DA", dark: "#DDD1BA" };

const HOUSES = [
  { id: "hub", x: 185, y: 185, w: 80, h: 56, c: SKY, label: "Router" },
  { id: "a", x: 50, y: 60, w: 54, h: 40, c: CREAM },
  { id: "b", x: 330, y: 50, w: 58, h: 70, c: MINT, label: "Server" },
  { id: "c", x: 40, y: 320, w: 54, h: 36, c: SUN, bubble: "Oops", tone: "bg-[#FFD93D] text-[#2D3142]" },
  { id: "d", x: 330, y: 320, w: 54, h: 44, c: CORAL, bubble: "Uh-oh!", tone: "bg-[#FF6B6B] text-white" },
];
const mid = (id: string) => {
  const h = HOUSES.find((x) => x.id === id)!;
  return { x: h.x + h.w / 2, y: h.y + h.w / 2 };
};
const CARS = [
  { a: "a", b: "hub", d: 2.6, delay: 0, c: CORAL }, { a: "hub", b: "b", d: 2.4, delay: 0.8, c: SUN },
  { a: "c", b: "hub", d: 3, delay: 0.4, c: SKY }, { a: "hub", b: "d", d: 2.2, delay: 1.3, c: MINT },
  { a: "d", b: "hub", d: 1.8, delay: 0.2, c: CORAL },
];

export function ToytownConcept() {
  const a = useAnalyse();
  return (
    <div className="min-h-full bg-gradient-to-b from-[#DFF1FF] to-[#FFF6E5] text-[#2D3142]">
      <header className="flex items-center justify-between px-8 py-5">
        <span className="flex items-center gap-2 text-[20px] font-black">
          <span className="h-7 w-7 rounded-xl bg-[#4D96FF] shadow-[0_4px_0_#2F74DB]" /> NetTriage
        </span>
        <GalleryLink className="rounded-full bg-white px-4 py-2 text-[13px] font-bold shadow-[0_3px_0_#E5DCCB] hover:-translate-y-0.5" />
      </header>

      <main className="mx-auto grid max-w-6xl items-center gap-6 px-8 pb-16 lg:grid-cols-2">
        <div>
          <h1 className="text-[clamp(40px,6vw,68px)] font-black leading-[1.02] tracking-tight">
            Your network,<br /><span className="text-[#4D96FF]">explained.</span>
          </h1>
          <p className="mt-4 text-[18px] font-semibold text-[#2D3142]/70">No jargon. Just what's wrong.</p>

          <div {...a.dropProps} className="mt-8 flex flex-wrap gap-3">
            <button type="button" onClick={a.pickFile} disabled={a.busy}
              className={`flex items-center gap-3 rounded-2xl px-7 py-4 text-[17px] font-black text-white transition-transform hover:-translate-y-1 ${a.over
                ? "bg-[#25B377] shadow-[0_6px_0_#1A8A5A]" : "bg-[#3DDC97] shadow-[0_6px_0_#25B377]"}`}>
              <Upload size={20} /> {a.busy ? "Looking..." : a.over ? "Let go!" : "Drop a capture"}
            </button>
            <button type="button" onClick={() => a.randomSample()} disabled={a.busy}
              className="rounded-2xl bg-white px-6 py-4 text-[17px] font-black shadow-[0_6px_0_#E5DCCB] transition-transform hover:-translate-y-1">
              Show me one
            </button>
          </div>

          <div className="mt-8 flex flex-wrap gap-2.5">
            {[
              { Icon: ShieldAlert, t: "Attack", c: "bg-[#FF6B6B] text-white" },
              { Icon: Wrench, t: "Fault", c: "bg-[#FFD93D]" },
              { Icon: CheckCircle, t: "All good", c: "bg-[#3DDC97] text-white" },
            ].map(({ Icon, t, c }) => (
              <span key={t} className={`flex items-center gap-1.5 rounded-full px-4 py-2 text-[14px] font-bold ${c}`}>
                <Icon size={16} /> {t}
              </span>
            ))}
          </div>
        </div>

        <div className="relative h-[440px] select-none [perspective:1300px]" aria-hidden="true">
          <div className="preserve-3d absolute left-1/2 top-1/2 h-[440px] w-[440px] -translate-x-1/2 -translate-y-1/2"
            style={{ transform: "translate(-50%, -50%) rotateX(58deg) rotateZ(-38deg)" }}>
            <div className="absolute inset-0 rounded-[48px] bg-[#9BE3B0] shadow-[0_30px_0_#6FC98B,0_50px_60px_-20px_rgba(45,49,66,0.35)]" />
            <svg className="absolute inset-0" width="440" height="440" viewBox="0 0 440 440">
              {["a", "b", "c", "d"].map((id) => {
                const p = mid("hub");
                const q = mid(id);
                return (
                  <g key={id}>
                    <line x1={p.x} y1={p.y} x2={q.x} y2={q.y} stroke="#6B7A8F" strokeWidth="18" strokeLinecap="round" />
                    <line x1={p.x} y1={p.y} x2={q.x} y2={q.y} stroke="#FFFFFF" strokeWidth="2" strokeDasharray="8 10" />
                  </g>
                );
              })}
            </svg>
            {HOUSES.map((h) => (
              <Box key={h.id} x={h.x} y={h.y} w={h.w} d={h.w} h={h.h} c={h.c}>
                {(h.label || h.bubble) && (
                  <div className="preserve-3d absolute left-1/2 top-1/2"
                    style={{ transform: `translate(-50%, -50%) translateZ(${h.h + 36}px) rotateZ(38deg) rotateX(-58deg)` }}>
                    <span className={`block whitespace-nowrap rounded-full px-3 py-1 text-[13px] font-black shadow-[0_3px_0_rgba(0,0,0,0.15)] ${h.tone ?? "bg-white"}`}
                      style={h.bubble ? { animation: "dc-bob 1.6s ease-in-out infinite" } : undefined}>
                      {h.bubble ?? h.label}
                    </span>
                  </div>
                )}
              </Box>
            ))}
            {/* A siren on the suspicious house */}
            <div className="absolute h-6 w-6 rounded-full bg-[#FF3B3B] shadow-[0_0_30px_#FF3B3B]"
              style={{ left: mid("d").x - 12, top: mid("d").y - 12, transform: "translateZ(50px)", animation: "dc-siren 0.8s infinite" }} />
            {CARS.map((car, i) => {
              const p = mid(car.a);
              const q = mid(car.b);
              return (
                <div key={i} className="preserve-3d absolute left-0 top-0 animate-hop"
                  style={{ ["--x1" as string]: `${p.x - 9}px`, ["--y1" as string]: `${p.y - 9}px`, ["--x2" as string]: `${q.x - 9}px`,
                    ["--y2" as string]: `${q.y - 9}px`, ["--dur" as string]: `${car.d}s`, animationDelay: `${car.delay}s` } as CSSProperties}>
                  <Box x={0} y={0} w={18} d={18} h={12} c={car.c} />
                </div>
              );
            })}
          </div>
        </div>
      </main>
      {a.fileInput}
      <ErrorToast text={a.error} onClose={a.clearError} className="rounded-2xl bg-[#FF6B6B] font-bold text-white shadow-[0_5px_0_#E04848]" />
    </div>
  );
}
