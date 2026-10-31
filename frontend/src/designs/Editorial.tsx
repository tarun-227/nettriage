// Concept 3 · Editorial: Swiss poster. Cream, black, one vermilion accent. Huge type, almost no words.
import { ErrorToast, GalleryLink, useAnalyse } from "./shared";

const CARDS = [
  { front: "ARP 192.168.1.1", back: "Attack", tone: "bg-[#E4572E] text-[#F4EFE6]" },
  { front: "DNS 192.168.1.1", back: "Fault", tone: "bg-[#111] text-[#F4EFE6]" },
  { front: "VRRP 192.168.1.2", back: "Fine", tone: "bg-[#F4EFE6] text-[#111] border-2 border-[#111]" },
];

export function EditorialConcept() {
  const a = useAnalyse();
  return (
    <div {...a.dropProps} className={`min-h-full bg-[#F4EFE6] text-[#111] transition-colors ${a.over ? "bg-[#F9E3D9]" : ""}`}>
      <header className="flex items-baseline justify-between border-b-2 border-[#111] px-8 py-5">
        <span className="text-[15px] font-black uppercase tracking-tight">NetTriage<span className="text-[#E4572E]">.</span></span>
        <span className="flex gap-6 text-[13px] font-semibold uppercase">
          <span>Offline</span>
          <GalleryLink className="underline decoration-2 underline-offset-4 hover:text-[#E4572E]" />
        </span>
      </header>

      <main className="grid gap-10 overflow-hidden px-8 pb-16 pt-10 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <div className="min-w-0">
          <h1 className="text-[clamp(56px,8.5vw,140px)] font-black uppercase leading-[0.85] tracking-[-0.04em]">
            Broken<br /><span className="text-[0.45em] align-middle tracking-normal">or</span><br />
            <span className="text-[#E4572E]">breached?</span>
          </h1>
          <div className="mt-10 flex flex-wrap items-center gap-4">
            <button type="button" onClick={a.pickFile} disabled={a.busy}
              className="bg-[#111] px-7 py-4 text-[15px] font-bold uppercase tracking-wide text-[#F4EFE6] transition-transform hover:-translate-y-0.5">
              {a.busy ? "Reading..." : "Choose capture →"}
            </button>
            <button type="button" onClick={() => a.randomSample()} disabled={a.busy}
              className="border-2 border-[#111] px-6 py-[14px] text-[15px] font-bold uppercase tracking-wide hover:bg-[#111] hover:text-[#F4EFE6]">
              Sample
            </button>
            <span className="text-[13px] font-semibold uppercase text-[#111]/60">or drop it anywhere</span>
          </div>
        </div>

        <div className="flex min-w-0 flex-col justify-between gap-10">
          <div className="flex justify-center gap-3 [perspective:1000px]">
            {CARDS.map((c, i) => (
              <div key={c.back} className="preserve-3d relative h-52 w-32 shrink-0"
                style={{ animation: `dc-flip 6s ease-in-out ${i * 0.7}s infinite` }}>
                <div className="dc-face absolute inset-0 flex flex-col justify-between border-2 border-[#111] bg-white p-3">
                  <span className="text-[11px] font-bold uppercase">Packet</span>
                  <span className="font-mono text-[12px]">{c.front}</span>
                </div>
                <div className={`dc-face absolute inset-0 flex items-end p-3 ${c.tone}`} style={{ transform: "rotateY(180deg)" }}>
                  <span className="text-[30px] font-black uppercase leading-none">{c.back}</span>
                </div>
              </div>
            ))}
          </div>
          <ol className="grid grid-cols-3 border-t-2 border-[#111]">
            {["Drop", "Read", "Fix"].map((w, i) => (
              <li key={w} className="border-r-2 border-[#111] pt-3 last:border-r-0">
                <span className="block text-[13px] font-bold text-[#E4572E]">0{i + 1}</span>
                <span className="text-[clamp(20px,2.4vw,32px)] font-black uppercase">{w}</span>
              </li>
            ))}
          </ol>
        </div>
      </main>
      {a.fileInput}
      <ErrorToast text={a.error} onClose={a.clearError} className="border-2 border-[#111] bg-[#E4572E] font-semibold text-[#F4EFE6]" />
    </div>
  );
}
