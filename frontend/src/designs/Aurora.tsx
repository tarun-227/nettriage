// Concept 2 · Aurora glass: calm consumer app. Deep violet, drifting colour, frosted glass, a spinning 3D cube.
import { CheckCircle, HelpCircle, Lock, ShieldAlert, Upload, WifiOff, Wrench } from "../components/icons";
import { ErrorToast, GalleryLink, useAnalyse, useCountUp } from "./shared";

const FACES = [
  { Icon: ShieldAlert, t: "Attack", c: "text-[#FF7AB6]" },
  { Icon: Wrench, t: "Fault", c: "text-[#FFD37A]" },
  { Icon: CheckCircle, t: "All good", c: "text-[#6EF2C6]" },
  { Icon: HelpCircle, t: "Review", c: "text-[#8FB8FF]" },
  { Icon: WifiOff, t: "Offline", c: "text-white" },
  { Icon: Lock, t: "Private", c: "text-white" },
];
const SIZE = 170;
const TRANSFORMS = [
  `translateZ(${SIZE / 2}px)`, `rotateY(90deg) translateZ(${SIZE / 2}px)`, `rotateY(180deg) translateZ(${SIZE / 2}px)`,
  `rotateY(-90deg) translateZ(${SIZE / 2}px)`, `rotateX(90deg) translateZ(${SIZE / 2}px)`, `rotateX(-90deg) translateZ(${SIZE / 2}px)`,
];

function Stat({ n, suffix, label }: { n: number; suffix?: string; label: string }) {
  const v = useCountUp(n);
  return (
    <div className="rounded-2xl border border-white/15 bg-white/10 px-5 py-3 text-center backdrop-blur-xl">
      <p className="text-[28px] font-semibold tabular-nums text-white">{v}{suffix}</p>
      <p className="text-[12px] text-white/70">{label}</p>
    </div>
  );
}

export function AuroraConcept() {
  const a = useAnalyse();
  return (
    <div className="relative min-h-full overflow-hidden bg-[#0E0B2A] text-white">
      {[["#7C3AED", "-10%", "-10%", 0], ["#EC4899", "55%", "5%", 3], ["#06B6D4", "20%", "60%", 6]].map(([c, l, t, d]) => (
        <div key={String(c)} className="pointer-events-none absolute h-[520px] w-[520px] rounded-full opacity-50 blur-[110px]"
          style={{ background: String(c), left: String(l), top: String(t), animation: `dc-blob 14s ease-in-out ${d}s infinite alternate` }} />
      ))}

      <header className="relative flex items-center justify-between px-8 py-6">
        <span className="text-[18px] font-semibold tracking-tight">nettriage</span>
        <GalleryLink className="rounded-full border border-white/20 bg-white/10 px-4 py-1.5 text-[13px] backdrop-blur hover:bg-white/20" />
      </header>

      <main className="relative mx-auto grid max-w-6xl items-center gap-12 px-8 pb-20 pt-6 lg:grid-cols-2">
        <div>
          <h1 className="text-[clamp(40px,6vw,72px)] font-semibold leading-[1.02] tracking-tight">
            Know what<br />
            <span className="bg-gradient-to-r from-[#C4B5FD] via-[#F9A8D4] to-[#67E8F9] bg-clip-text text-transparent">broke.</span>
          </h1>
          <p className="mt-4 text-[17px] text-white/75">Fault or attack. In seconds. Offline.</p>

          <div {...a.dropProps}
            className={`mt-8 flex items-center gap-4 rounded-3xl border p-4 backdrop-blur-xl transition-colors ${a.over ? "border-white/60 bg-white/20" : "border-white/15 bg-white/10"}`}>
            <button type="button" onClick={a.pickFile} disabled={a.busy}
              className="flex h-14 w-14 items-center justify-center rounded-2xl bg-white text-[#4C1D95] shadow-[0_10px_30px_-8px_rgba(236,72,153,0.7)]">
              <Upload size={22} />
            </button>
            <div className="flex-1">
              <p className="font-semibold">{a.busy ? "Analysing..." : "Drop your .pcap"}</p>
              <p className="text-[13px] text-white/60">or click the button</p>
            </div>
            <button type="button" onClick={() => a.randomSample()} disabled={a.busy}
              className="rounded-full bg-white/15 px-4 py-2 text-[13px] font-semibold hover:bg-white/25">Try a sample</button>
          </div>

          <div className="mt-6 grid grid-cols-3 gap-3">
            <Stat n={14} label="problem types" />
            <Stat n={0} suffix=" B" label="sent to cloud" />
            <Stat n={100} suffix="%" label="explained" />
          </div>
        </div>

        <div className="flex h-[360px] items-center justify-center [perspective:900px]">
          <div className="preserve-3d relative" style={{ width: SIZE, height: SIZE, animation: "dc-cube 16s linear infinite" }}>
            {FACES.map(({ Icon, t, c }, i) => (
              <div key={t} className="absolute inset-0 flex flex-col items-center justify-center gap-2 rounded-[28px] border border-white/30 bg-white/10 backdrop-blur-md"
                style={{ transform: TRANSFORMS[i], boxShadow: "inset 0 0 40px rgba(255,255,255,0.15)" }}>
                <Icon size={38} className={c} />
                <span className="text-[15px] font-semibold">{t}</span>
              </div>
            ))}
          </div>
        </div>
      </main>
      {a.fileInput}
      <ErrorToast text={a.error} onClose={a.clearError} className="rounded-2xl border border-white/20 bg-[#2A1B52]/90 text-white backdrop-blur" />
    </div>
  );
}
