// Side-by-side picker for the five early design concepts. The live app mixes Radar and Terminal.
import { href } from "../lib/router";
import { AuroraConcept } from "./Aurora";
import { EditorialConcept } from "./Editorial";
import { RadarConcept } from "./Radar";
import { TerminalConcept } from "./Terminal";
import { ToytownConcept } from "./Toytown";

export const CONCEPTS = [
  { id: "radar", name: "Radar", idea: "Mission control", colours: ["#05080A", "#2BFF88", "#FF3B5C"], View: RadarConcept,
    preview: "bg-[radial-gradient(circle_at_50%_60%,#0f3d27,#05080A_60%)]" },
  { id: "aurora", name: "Aurora", idea: "Calm and glassy", colours: ["#0E0B2A", "#7C3AED", "#EC4899", "#06B6D4"], View: AuroraConcept,
    preview: "bg-[linear-gradient(135deg,#4c1d95,#be185d_55%,#0e7490)]" },
  { id: "editorial", name: "Editorial", idea: "Big type, few words", colours: ["#F4EFE6", "#111111", "#E4572E"], View: EditorialConcept,
    preview: "bg-[linear-gradient(135deg,#F4EFE6_60%,#E4572E_60%)]" },
  { id: "terminal", name: "Terminal", idea: "Keyboard first", colours: ["#120C02", "#FFB000", "#FF5A3C"], View: TerminalConcept,
    preview: "bg-[repeating-linear-gradient(#1A1105_0_3px,#2a1c06_3px_4px)]" },
  { id: "toytown", name: "Toy town", idea: "Friendly, no jargon", colours: ["#FFF6E5", "#3DDC97", "#4D96FF", "#FF6B6B", "#FFD93D"],
    View: ToytownConcept, preview: "bg-[linear-gradient(135deg,#DFF1FF,#9BE3B0_55%,#FFD93D)]" },
] as const;

export function DesignGallery() {
  return (
    <div className="min-h-full bg-[#F8F7F4] px-6 py-12 text-[#2B2B2B]">
      <div className="mx-auto max-w-6xl">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <h1 className="text-[40px] font-black tracking-tight">5 design concepts</h1>
          <a href={href("/")} className="rounded-xl bg-[#1B2A4A] px-4 py-2 text-[13px] font-semibold text-white">Current design</a>
        </div>
        <div className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {CONCEPTS.map((c, i) => (
            <a key={c.id} href={href(`/designs/${c.id}`)}
              className="group overflow-hidden rounded-3xl border border-[#E2DED4] bg-white shadow-sm transition-transform hover:-translate-y-1 hover:shadow-xl">
              <div className={`relative h-40 ${c.preview}`}>
                <span className="absolute left-4 top-3 text-[44px] font-black text-white/90 mix-blend-difference">{i + 1}</span>
              </div>
              <div className="flex items-center justify-between p-5">
                <div>
                  <p className="text-[18px] font-bold">{c.name}</p>
                  <p className="text-[13px] text-[#6B6A66]">{c.idea}</p>
                </div>
                <div className="flex -space-x-1.5">
                  {c.colours.map((col) => (
                    <span key={col} className="h-6 w-6 rounded-full border-2 border-white" style={{ background: col }} title={col} />
                  ))}
                </div>
              </div>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
